package server

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"nfqws2strategy/internal/services/pihole"
)

func (s *Server) piholeStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.app.Pihole().Status())
}

func (s *Server) piholeStats(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	writeJSON(w, 200, s.app.Pihole().Stats(ctx))
}

func (s *Server) piholeSaveConfig(w http.ResponseWriter, r *http.Request) {
	var in pihole.Config
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err)
		return
	}
	if err := s.app.SavePiholeConfig(in); err != nil {
		httpErr(w, 500, err)
		return
	}
	writeJSON(w, 200, s.app.Pihole().Status())
}

// piholeInstall runs `docker pull` + `docker run`; takes up to ~5 min on a slow
// link, so we use a long context.
func (s *Server) piholeInstall(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Minute)
	defer cancel()
	log, err := s.app.Pihole().Install(ctx)
	if err != nil {
		writeJSON(w, 500, map[string]any{"ok": false, "error": err.Error(), "log": log})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "log": log, "status": s.app.Pihole().Status()})
}

func (s *Server) piholeStart(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	out, err := s.app.Pihole().Start(ctx)
	piholeRespond(w, out, err, s)
}

func (s *Server) piholeStop(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	out, err := s.app.Pihole().Stop(ctx)
	piholeRespond(w, out, err, s)
}

func (s *Server) piholeRestart(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	out, err := s.app.Pihole().Restart(ctx)
	piholeRespond(w, out, err, s)
}

func (s *Server) piholeUpgrade(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Minute)
	defer cancel()
	out, err := s.app.Pihole().Upgrade(ctx)
	if err != nil {
		writeJSON(w, 500, map[string]any{"ok": false, "error": err.Error(), "log": out})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "log": out, "status": s.app.Pihole().Status()})
}

func (s *Server) piholeRemove(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	out, err := s.app.Pihole().Remove(ctx)
	piholeRespond(w, out, err, s)
}

func (s *Server) piholeLogs(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	lines := 200
	if v := r.URL.Query().Get("lines"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			lines = n
		}
	}
	out, err := s.app.Pihole().Logs(ctx, lines)
	if err != nil {
		httpErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"log": out})
}

// piholeSetChain toggles the DNS chain flag (AWG2 proxy upstream → pi-hole)
// and persists the resulting config so the choice survives reboot.
func (s *Server) piholeSetChain(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err)
		return
	}
	s.app.Pihole().SetDNSChain(in.Enabled)
	cfg := s.app.Pihole().Config()
	if err := s.app.SavePiholeConfig(cfg); err != nil {
		httpErr(w, 500, err)
		return
	}
	writeJSON(w, 200, s.app.Pihole().Status())
}

func piholeRespond(w http.ResponseWriter, out string, err error, s *Server) {
	if err != nil {
		writeJSON(w, 500, map[string]any{"ok": false, "error": err.Error(), "log": out})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "log": out, "status": s.app.Pihole().Status()})
}
