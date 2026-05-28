package tgws

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// Manager owns the proxy lifecycle: it is held by the host app and driven from
// the web tab. Start/Stop/Restart are safe to call concurrently.
type Manager struct {
	mu      sync.Mutex
	cfg     *Config
	stats   *Stats
	running bool

	ln     net.Listener
	ctx    context.Context
	cancel context.CancelFunc
	pool   *wsPool
	conns  *connSet
	wg     sync.WaitGroup
}

// NewManager creates a manager around an initial config (normalized in place).
func NewManager(cfg *Config) *Manager {
	cfg.Normalize()
	return &Manager{cfg: cfg, stats: &Stats{}}
}

func (m *Manager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

// Config returns a copy of the current config.
func (m *Manager) Config() Config {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := *m.cfg
	c.DCRedirects = copyDC(m.cfg.DCRedirects)
	return c
}

func (m *Manager) Stats() Snapshot { return m.stats.snapshot() }

func (m *Manager) Link(hostOverride string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return TGLink(m.cfg, hostOverride)
}

// SetConfig replaces the config and, if the proxy is running, restarts it so
// the change takes effect.
func (m *Manager) SetConfig(cfg *Config) error {
	cfg.Normalize()
	if errs := cfg.Validate(); len(errs) > 0 {
		return fmt.Errorf("%s", joinErrs(errs))
	}
	m.mu.Lock()
	wasRunning := m.running
	m.cfg = cfg
	m.mu.Unlock()

	if wasRunning {
		m.Stop()
	}
	if cfg.Enabled {
		return m.Start()
	}
	return nil
}

// Start begins listening if enabled and not already running.
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		return nil
	}
	cfg := m.cfg

	secret, err := hex.DecodeString(cfg.Secret)
	if err != nil || len(secret) == 0 {
		return fmt.Errorf("неверный secret")
	}

	bal := newDomainBalancer()
	if cfg.CFProxy && cfg.CFProxyUserDomain == "" {
		bal.updatePool(cfg.cfproxyDefaultPool())
	} else if cfg.CFProxyUserDomain != "" {
		bal.updatePool([]string{cfg.CFProxyUserDomain})
	}

	ctx, cancel := context.WithCancel(context.Background())
	pool := newWSPool(ctx, cfg.PoolSize, cfg.BufferSize, m.stats)
	settings := handlerSettings{
		secret:        secret,
		dcRedirects:   copyDC(cfg.DCRedirects),
		bufferSize:    cfg.BufferSize,
		fakeTLSDomain: cfg.FakeTLSDomain,
		proxyProtocol: cfg.ProxyProtocol,
		fallback:      fallbackConfig{cfproxyEnabled: cfg.CFProxy, cfproxyWorkerDomain: cfg.CFProxyWorkerDomain},
	}
	conns := newConnSet()
	handler := newClientHandler(ctx, settings, pool, m.stats, bal)

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Port))
	if err != nil {
		cancel()
		return fmt.Errorf("не удалось открыть порт %d: %w", cfg.Port, err)
	}

	m.ln = ln
	m.ctx = ctx
	m.cancel = cancel
	m.pool = pool
	m.conns = conns
	m.running = true
	m.stats.startedAt.Store(time.Now().Unix())

	m.wg.Add(1)
	go m.acceptLoop(ln, handler, conns)
	pool.warmup(settings.dcRedirects)

	log.Printf("tgws: listening on :%d (fake-tls=%q, pool=%d)", cfg.Port, cfg.FakeTLSDomain, cfg.PoolSize)
	return nil
}

func (m *Manager) acceptLoop(ln net.Listener, h *clientHandler, conns *connSet) {
	defer m.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed on Stop
		}
		conns.add(conn)
		go func() {
			defer conns.remove(conn)
			h.handle(conn)
		}()
	}
}

// Stop shuts the listener, aborts in-flight dials and drops active clients.
func (m *Manager) Stop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	m.running = false
	cancel, ln, pool, conns := m.cancel, m.ln, m.pool, m.conns
	m.cancel, m.ln, m.pool, m.conns = nil, nil, nil, nil
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if ln != nil {
		_ = ln.Close()
	}
	if conns != nil {
		conns.closeAll()
	}
	if pool != nil {
		pool.reset()
	}
	m.wg.Wait()
	log.Printf("tgws: stopped. stats: %s", m.stats.summary())
}

func (m *Manager) Restart() error {
	m.Stop()
	return m.Start()
}

// connSet tracks live client connections so Stop can drop them all.
type connSet struct {
	mu sync.Mutex
	m  map[net.Conn]struct{}
}

func newConnSet() *connSet { return &connSet{m: map[net.Conn]struct{}{}} }

func (cs *connSet) add(c net.Conn) {
	cs.mu.Lock()
	cs.m[c] = struct{}{}
	cs.mu.Unlock()
}
func (cs *connSet) remove(c net.Conn) {
	cs.mu.Lock()
	delete(cs.m, c)
	cs.mu.Unlock()
}
func (cs *connSet) closeAll() {
	cs.mu.Lock()
	for c := range cs.m {
		_ = c.Close()
	}
	cs.m = map[net.Conn]struct{}{}
	cs.mu.Unlock()
}

func copyDC(in map[int]string) map[int]string {
	out := make(map[int]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func joinErrs(errs []string) string {
	out := ""
	for i, e := range errs {
		if i > 0 {
			out += "; "
		}
		out += e
	}
	return out
}
