package server

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"nfqws2strategy/internal/services/dnsserver"
)

func (s *Server) dnsServerStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.app.DNSServer().Status())
}

type dnsServerConfigRequest struct {
	dnsserver.Config
	CacheTTLSeconds  *int    `json:"cache_ttl_seconds"`
	FastDNS          *bool   `json:"fast_dns"`
	SchedulerEnabled *bool   `json:"scheduler_enabled"`
	RouteMode        *string `json:"route_mode"`
}

func (in dnsServerConfigRequest) merge(current dnsserver.Config) dnsserver.Config {
	cfg := in.Config
	// The port belongs to System settings. A stale DNS form must not reset it.
	cfg.DNSPort = current.DNSPort
	cfg.LoggingEnabled = current.LoggingEnabled
	// Method switches belong to the scheduler. Saving a stale DNS form must
	// never turn a disabled route/provider pair back on, even if it sent [].
	cfg.DisabledMethods = current.DisabledMethods
	cfg.CacheTTLSeconds = current.CacheTTLSeconds
	if in.CacheTTLSeconds != nil {
		cfg.CacheTTLSeconds = *in.CacheTTLSeconds
	}
	// Older tabs must not reset the independently introduced fast-dns option.
	cfg.FastDNS = current.FastDNS
	if in.FastDNS != nil {
		cfg.FastDNS = *in.FastDNS
	}
	cfg.SchedulerEnabled = current.SchedulerEnabled
	if in.SchedulerEnabled != nil {
		cfg.SchedulerEnabled = *in.SchedulerEnabled
	}
	// Saving a tab opened before VPN-only existed must not reopen the WAN path.
	cfg.RouteMode = current.RouteMode
	if in.RouteMode != nil {
		cfg.RouteMode = *in.RouteMode
	}
	// Forms opened before DNS filtering existed must preserve the saved rules.
	if cfg.Filtering == nil {
		cfg.Filtering = current.Filtering
	}
	if cfg.ShadowDNS == nil {
		cfg.ShadowDNS = current.ShadowDNS
	}
	// Older open tabs do not know about pools. Only an explicit empty array
	// removes additional providers; unrelated edits must keep the saved pool.
	if cfg.DefaultPool == nil {
		cfg.DefaultPool = current.DefaultPool
	}
	for i := range cfg.Rules {
		if cfg.Rules[i].Pool != nil {
			continue
		}
		for _, previous := range current.Rules {
			if previous.ID == cfg.Rules[i].ID {
				cfg.Rules[i].Pool = previous.Pool
				break
			}
		}
	}
	return cfg
}

func (s *Server) dnsServerConfig(w http.ResponseWriter, r *http.Request) {
	s.portsMu.Lock()
	defer s.portsMu.Unlock()
	var in dnsServerConfigRequest
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err)
		return
	}
	cfg := in.merge(s.app.DNSServer().Config())
	if err := s.app.DNSServer().SetConfig(cfg); err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, s.app.DNSServer().Status())
}

func (s *Server) dnsServerClearCache(w http.ResponseWriter, r *http.Request) {
	s.app.DNSServer().ClearCache()
	writeJSON(w, 200, s.app.DNSServer().Status())
}

func (s *Server) dnsServerUpdateFiltering(w http.ResponseWriter, r *http.Request) {
	if err := s.app.DNSServer().UpdateFiltering(); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, s.app.DNSServer().Status())
}

func (s *Server) dnsServerLogs(w http.ResponseWriter, r *http.Request) {
	var after uint64
	if cursor := r.URL.Query().Get("after"); cursor != "" {
		var err error
		after, err = strconv.ParseUint(cursor, 10, 64)
		if err != nil {
			httpErr(w, 400, fmt.Errorf("неверный курсор журнала"))
			return
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, s.app.DNSServer().Logs(after))
}

func (s *Server) dnsServerClearLogs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.app.DNSServer().ClearLogs())
}

func (s *Server) dnsServerLogging(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled *bool `json:"enabled"`
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err)
		return
	}
	if in.Enabled == nil {
		httpErr(w, 400, fmt.Errorf("укажите enabled"))
		return
	}
	s.portsMu.Lock()
	defer s.portsMu.Unlock()
	if err := s.app.DNSServer().SetLoggingEnabled(*in.Enabled); err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, s.app.DNSServer().Logs(0))
}

func (s *Server) dnsServerScheduler(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	snapshot, err := s.app.DNSServer().SchedulerSnapshot(domain)
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, snapshot)
}

func (s *Server) dnsServerMethod(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Upstream string `json:"upstream"`
		Route    string `json:"route"`
		Enabled  *bool  `json:"enabled"`
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	if in.Enabled == nil {
		httpErr(w, http.StatusBadRequest, fmt.Errorf("укажите enabled"))
		return
	}
	s.portsMu.Lock()
	defer s.portsMu.Unlock()
	service := s.app.DNSServer()
	if err := service.SetMethodEnabled(in.Upstream, in.Route, *in.Enabled); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, service.Config())
}

func (s *Server) dnsServerStart(w http.ResponseWriter, r *http.Request) {
	s.portsMu.Lock()
	defer s.portsMu.Unlock()
	if err := s.app.DNSServer().SetEnabled(true); err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, s.app.DNSServer().Status())
}
func (s *Server) dnsServerStop(w http.ResponseWriter, r *http.Request) {
	s.portsMu.Lock()
	defer s.portsMu.Unlock()
	if err := s.app.DNSServer().SetEnabled(false); err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, s.app.DNSServer().Status())
}
func (s *Server) dnsServerTest(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Domain string `json:"domain"`
		Type   string `json:"type"`
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 28*time.Second)
	defer cancel()
	writeJSON(w, 200, s.app.DNSServer().Test(ctx, in.Domain, in.Type))
}
