package dnsserver

import (
	"context"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
	"nfqws2strategy/internal/services/dnsroute"
	"nfqws2strategy/internal/tools/logbuf"
	"nfqws2strategy/internal/tools/store"
)

const configFile = "dnsserver.json"

type Stats struct {
	Queries      uint64 `json:"queries"`
	CacheHits    uint64 `json:"cache_hits"`
	NFQWSSuccess uint64 `json:"nfqws_success"`
	AWGSuccess   uint64 `json:"awg_success"`
	Failures     uint64 `json:"failures"`
	LastDomain   string `json:"last_domain"`
	LastRoute    string `json:"last_route"`
	LastUpstream string `json:"last_upstream"`
	LastError    string `json:"last_error"`
}
type Endpoints struct {
	DNS string `json:"dns"`
}
type Status struct {
	Config     Config           `json:"config"`
	Running    bool             `json:"running"`
	ListenHost string           `json:"listen_host"`
	Endpoints  Endpoints        `json:"endpoints"`
	LastError  string           `json:"last_error"`
	Stats      Stats            `json:"stats"`
	Cache      CacheStatus      `json:"cache"`
	FastDNS    FastDNSStatus    `json:"fast_dns"`
	Routes     []dnsroute.Route `json:"routes"`
}
type serviceRun struct {
	cancel    context.CancelFunc
	listeners *Listeners
	resolver  *Resolver
	failure   chan error
}

type Service struct {
	opMu          sync.Mutex
	mu            sync.RWMutex
	store         *store.Store
	backend       Backend
	resolveHost   func(string) (string, error)
	cfg           Config
	host          string
	lastError     string
	stats         Stats
	logs          *LogBuffer
	scheduler     *Scheduler
	active        *serviceRun
	controlCancel context.CancelFunc
}

func New(st *store.Store, backend Backend, resolveHost func(string) (string, error)) *Service {
	cfg := Default()
	loaded := Config{LoggingEnabled: true, CacheTTLSeconds: cfg.CacheTTLSeconds, FastDNS: cfg.FastDNS}
	s := &Service{store: st, backend: backend, resolveHost: resolveHost, cfg: cfg, logs: NewLogBuffer(), scheduler: NewScheduler()}
	if err := st.Load(configFile, &loaded); err == nil {
		legacy := loaded.DNSPort == 0
		if legacy {
			loaded.DNSPort = cfg.DNSPort
		}
		if err := loaded.NormalizeValidate(); err == nil {
			s.cfg = loaded
			if legacy {
				if err := st.Save(configFile, loaded); err != nil {
					s.lastError = err.Error()
				}
			}
		} else {
			s.lastError = "неверная сохранённая конфигурация: " + err.Error()
		}
	} else if os.IsNotExist(err) {
		if err := st.Save(configFile, cfg); err != nil {
			s.lastError = err.Error()
		}
	} else {
		s.lastError = err.Error()
	}
	s.host, _ = s.resolveHost(s.cfg.ListenHost)
	s.logs.SetEnabled(s.cfg.LoggingEnabled)
	if s.lastError != "" {
		s.logs.Append(LogEntry{Level: "error", Event: "config", Message: s.lastError})
	}
	return s
}

func (s *Service) Config() Config { s.mu.RLock(); defer s.mu.RUnlock(); return cloneConfig(s.cfg) }

func (s *Service) Status() Status {
	s.mu.RLock()
	st := Status{Config: cloneConfig(s.cfg), Running: s.active != nil, ListenHost: s.host, LastError: s.lastError, Stats: s.stats}
	st.Cache = s.cacheStatusLocked()
	st.FastDNS.Enabled = s.cfg.FastDNS
	if s.active != nil && s.active.resolver.fastDNS != nil {
		st.FastDNS = s.active.resolver.fastDNS.Snapshot()
		st.FastDNS.Enabled = s.cfg.FastDNS
	}
	s.mu.RUnlock()
	st.Routes = s.backend.Routes()
	if st.Routes == nil {
		st.Routes = []dnsroute.Route{}
	}
	host := st.ListenHost
	if host != "" {
		st.Endpoints.DNS = net.JoinHostPort(host, strconv.Itoa(st.Config.DNSPort))
	}
	return st
}

func (s *Service) SetConfig(cfg Config) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	return s.setConfigLocked(cfg)
}

func (s *Service) setConfigLocked(cfg Config) error {
	if err := cfg.NormalizeValidate(); err != nil {
		return err
	}
	host, err := s.resolveHost(cfg.ListenHost)
	if err != nil {
		return err
	}
	if err := validateNoSelfUpstream(cfg, host); err != nil {
		return err
	}
	if err := s.store.Save(configFile, cfg); err != nil {
		return err
	}
	s.stopLocked()
	s.mu.Lock()
	s.cfg = cloneConfig(cfg)
	s.host = host
	s.lastError = ""
	s.mu.Unlock()
	s.logs.SetEnabled(cfg.LoggingEnabled)
	if cfg.Enabled {
		s.startControlLocked()
	}
	return nil
}

func (s *Service) SetEnabled(enabled bool) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	cfg := s.Config()
	cfg.Enabled = enabled
	return s.setConfigLocked(cfg)
}

func (s *Service) StartEnabled() {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if s.Config().Enabled && s.controlCancel == nil {
		s.startControlLocked()
	}
}

func (s *Service) startControlLocked() {
	ctx, cancel := context.WithCancel(context.Background())
	s.controlCancel = cancel
	if err := s.startRunLocked(ctx); err != nil {
		s.setError(err)
	}
	go s.supervise(ctx)
}

func (s *Service) supervise(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		s.mu.RLock()
		run := s.active
		s.mu.RUnlock()
		var failures <-chan error
		if run != nil {
			failures = run.failure
		}
		var cause error
		select {
		case <-ctx.Done():
			return
		case cause = <-failures:
		case <-ticker.C:
		}
		s.opMu.Lock()
		if ctx.Err() != nil {
			s.opMu.Unlock()
			return
		}
		if cause != nil {
			s.setError(cause)
			s.stopRunLocked()
		}
		s.mu.RLock()
		running := s.active != nil
		s.mu.RUnlock()
		if !running {
			if err := s.startRunLocked(ctx); err != nil {
				s.setError(err)
			}
		}
		s.opMu.Unlock()
	}
}

func (s *Service) startRunLocked(parent context.Context) error {
	cfg := s.Config()
	host, err := s.resolveHost(cfg.ListenHost)
	if err != nil {
		return err
	}
	if err := validateNoSelfUpstream(cfg, host); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	run := &serviceRun{cancel: cancel, failure: make(chan error, 1)}
	cfg.ListenHost = host // concrete bind address also protects upstream dialing from loops
	run.resolver = NewResolver(cfg, s.backend)
	run.resolver.SetScheduler(s.scheduler)
	run.resolver.SetAttemptObserver(s.recordAttempt)
	run.resolver.SetCancellationObserver(s.recordCancellations)
	opts := ListenerOptions{BindHost: host, DNSPort: cfg.DNSPort, RequestTimeout: 27 * time.Second,
		AllowClient: allowLANClients(host), Exchange: func(ctx context.Context, q []byte) ([]byte, error) {
			b, _, err := s.exchange(ctx, run, q)
			return b, err
		},
		OnError: func(err error) {
			if ctx.Err() == nil {
				select {
				case run.failure <- err:
				default:
				}
			}
		}}
	// Bind before opening firewall access; a conflict cannot leave a partial
	// listener service or redirect the router's existing DNS/HTTPS service.
	run.listeners, err = StartListeners(ctx, opts)
	if err == nil {
		err = s.backend.Prepare(ctx, dnsroute.ListenOptions{Host: host, DNSPort: cfg.DNSPort})
	}
	if err != nil {
		cancel()
		if run.listeners != nil {
			run.listeners.Close()
		}
		run.resolver.Close()
		_ = s.backend.Close()
		return err
	}
	s.mu.Lock()
	s.active = run
	s.host = host
	s.lastError = ""
	s.stats = Stats{}
	s.mu.Unlock()
	logbuf.Append("dnsserver", "info", "DNS Server запущен на "+host)
	s.logs.Append(LogEntry{Level: "info", Event: "start", Message: "DNS запущен на " + net.JoinHostPort(host, strconv.Itoa(cfg.DNSPort))})
	run.resolver.StartMaintenance()
	return nil
}

func allowLANClients(host string) func(net.IP) bool {
	ip := net.ParseIP(host)
	var subnet *net.IPNet
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				a, n, e := net.ParseCIDR(addr.String())
				if e == nil && a.Equal(ip) {
					subnet = n
				}
			}
		}
	}
	return func(peer net.IP) bool {
		return peer != nil && (peer.IsLoopback() || peer.Equal(ip) || subnet != nil && subnet.Contains(peer))
	}
}

func (s *Service) exchange(ctx context.Context, run *serviceRun, q []byte) ([]byte, Outcome, error) {
	started := time.Now()
	resp, out, err := run.resolver.Resolve(ctx, q)
	if err == nil {
		resp, err = s.backend.ObserveAnswer(ctx, out.Domain, resp, ContextClientIP(ctx))
	}
	if err != nil {
		out.Error = err.Error()
		resp = errorReply(q, mdns.RcodeServerFailure)
	}
	s.mu.Lock()
	if s.active == run {
		s.stats.Queries++
		s.stats.LastDomain = out.Domain
		s.stats.LastRoute = out.Route
		s.stats.LastUpstream = out.Upstream
		s.stats.LastError = out.Error
		if err != nil {
			s.stats.Failures++
		} else if out.Cached {
			s.stats.CacheHits++
		} else if out.Route == "nfqws" {
			s.stats.NFQWSSuccess++
		} else {
			s.stats.AWGSuccess++
		}
	}
	s.mu.Unlock()
	entry := LogEntry{Level: "info", Event: "answer", Domain: out.Domain, Upstream: out.Upstream, Route: out.Route, DurationMS: time.Since(started).Milliseconds()}
	if parsed, _, e := parseQuery(q); e == nil {
		entry.QType = mdns.TypeToString[parsed.Question[0].Qtype]
	}
	if err != nil {
		entry.Level, entry.Event, entry.Message = "error", "error", err.Error()
	} else if out.Cached {
		entry.Event = "cache"
	}
	s.logs.Append(entry)
	// Transport succeeded even for SERVFAIL: clients receive a DNS error, and
	// the next query continues recovery instead of losing the listener.
	return resp, out, nil
}

func (s *Service) setError(err error) {
	s.mu.Lock()
	s.lastError = err.Error()
	s.mu.Unlock()
	logbuf.Append("dnsserver", "warn", err.Error())
	s.logs.Append(LogEntry{Level: "error", Event: "service", Message: err.Error()})
}

func (s *Service) stopRunLocked() {
	s.mu.Lock()
	run := s.active
	s.active = nil
	s.mu.Unlock()
	if run != nil {
		run.cancel()
		run.listeners.Close()
		run.resolver.Close()
		s.logs.Append(LogEntry{Level: "info", Event: "stop", Message: "DNS остановлен"})
	}
	_ = s.backend.Close()
}
func (s *Service) stopLocked() {
	if s.controlCancel != nil {
		s.controlCancel()
		s.controlCancel = nil
	}
	s.stopRunLocked()
}
func (s *Service) Close() { s.opMu.Lock(); defer s.opMu.Unlock(); s.stopLocked() }

type TestResult struct {
	OK         bool     `json:"ok"`
	Domain     string   `json:"domain"`
	Type       string   `json:"type"`
	Route      string   `json:"route"`
	Upstream   string   `json:"upstream"`
	Answers    []string `json:"answers"`
	DurationMS int64    `json:"duration_ms"`
	Error      string   `json:"error,omitempty"`
}

func (s *Service) Test(ctx context.Context, domain, kind string) TestResult {
	started := time.Now()
	result := TestResult{Domain: domain, Type: kind, Answers: []string{}}
	name, err := normalizeDomain(domain)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	typeCode := mdns.TypeA
	if kind == "AAAA" {
		typeCode = mdns.TypeAAAA
	} else if kind != "A" && kind != "" {
		result.Error = "тип должен быть A или AAAA"
		return result
	}
	s.mu.RLock()
	run := s.active
	s.mu.RUnlock()
	if run == nil {
		result.Error = "DNS-сервис выключен или запускается"
		return result
	}
	q := new(mdns.Msg)
	q.SetQuestion(mdns.Fqdn(name), typeCode)
	raw, _ := q.Pack()
	resp, out, err := s.exchange(ctx, run, raw)
	result.Domain = name
	result.Type = mdns.TypeToString[typeCode]
	result.Route = out.Route
	result.Upstream = out.Upstream
	result.Error = out.Error
	result.DurationMS = time.Since(started).Milliseconds()
	if err != nil {
		result.Error = err.Error()
		return result
	}
	var msg mdns.Msg
	if err := msg.Unpack(resp); err != nil {
		result.Error = err.Error()
		return result
	}
	for _, rr := range msg.Answer {
		result.Answers = append(result.Answers, rr.String())
	}
	result.OK = result.Error == "" && (msg.Rcode == mdns.RcodeSuccess || msg.Rcode == mdns.RcodeNameError)
	return result
}
