package tgws

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Manager owns the proxy lifecycle: it is held by the host app and driven from
// the web tab. Start/Stop/Restart are safe to call concurrently.
type Manager struct {
	opMu    sync.Mutex // serializes complete lifecycle operations, including waits
	mu      sync.Mutex
	cfg     *Config
	stats   *Stats
	running bool

	ln         net.Listener
	ctx        context.Context
	cancel     context.CancelFunc
	pool       *wsPool
	workerPool *cfWorkerPool
	conns      *connSet
	wg         sync.WaitGroup

	// awgUp is an optional live probe injected by the host app: "is the AWG2
	// tunnel up?" Read per connection (atomic, settable after Start) to route the
	// otherwise-unreachable DCs (1/3/5) through the tunnel only while it is up.
	awgUp atomic.Pointer[func() bool]
}

// SetAWGUp injects the live AWG2-tunnel-up probe (safe to call after Start; reads
// are lock-free). A nil or unset probe means "tunnel down" (normal fallback).
func (m *Manager) SetAWGUp(f func() bool) { m.awgUp.Store(&f) }

func (m *Manager) awgAvailable() bool {
	if p := m.awgUp.Load(); p != nil && *p != nil {
		return (*p)()
	}
	return false
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
	c.CFProxyUserDomains = append([]string{}, m.cfg.CFProxyUserDomains...)
	c.CFProxyWorkerDomains = append([]string{}, m.cfg.CFProxyWorkerDomains...)
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
	m.opMu.Lock()
	defer m.opMu.Unlock()
	cfg.Normalize()
	if errs := cfg.Validate(); len(errs) > 0 {
		return fmt.Errorf("%s", joinErrs(errs))
	}
	m.mu.Lock()
	wasRunning := m.running
	m.cfg = cfg
	m.mu.Unlock()

	if wasRunning {
		m.stop()
	}
	if cfg.Enabled {
		return m.start()
	}
	return nil
}

// Start begins listening if enabled and not already running.
func (m *Manager) Start() error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	return m.start()
}

func (m *Manager) start() error {
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
	if cfg.CFProxy && len(cfg.CFProxyUserDomains) == 0 {
		bal.updatePool(cfg.cfproxyDefaultPool())
	} else if len(cfg.CFProxyUserDomains) > 0 {
		bal.updatePool(cfg.CFProxyUserDomains)
	}

	ctx, cancel := context.WithCancel(context.Background())
	pool := newWSPool(ctx, cfg.PoolSize, cfg.BufferSize, m.stats, cfg.SNIFronting)
	workerPool := newCFWorkerPool(ctx, cfg.PoolSize, cfg.BufferSize, m.stats)
	settings := handlerSettings{
		secret:        secret,
		dcRedirects:   copyDC(cfg.DCRedirects),
		bufferSize:    cfg.BufferSize,
		fakeTLSDomain: cfg.FakeTLSDomain,
		proxyProtocol: cfg.ProxyProtocol,
		forceTestDC:   cfg.ForceTestDC,
		fallback:      fallbackConfig{cfproxyEnabled: cfg.CFProxy, cfproxyWorkerDomains: append([]string{}, cfg.CFProxyWorkerDomains...), workerPool: workerPool},
		awgAvailable:  m.awgAvailable,
	}
	conns := newConnSet()
	handler := newClientHandler(ctx, settings, pool, m.stats, bal)

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Port))
	if err != nil {
		cancel()
		pool.reset()
		workerPool.reset()
		return fmt.Errorf("не удалось открыть порт %d: %w", cfg.Port, err)
	}

	m.ln = ln
	m.ctx = ctx
	m.cancel = cancel
	m.pool = pool
	m.workerPool = workerPool
	m.conns = conns
	m.running = true
	m.stats.startedAt.Store(time.Now().Unix())

	m.wg.Add(1)
	go m.acceptLoop(ln, handler, conns)
	if !cfg.ForceTestDC {
		pool.warmup(settings.dcRedirects)
		cfTargets := make(map[int]string)
		for dc, ip := range dcDefaultIPs {
			if settings.dcRedirects[dc] == "" {
				cfTargets[dc] = ip
			}
		}
		workerPool.warmup(cfTargets, cfg.CFProxyWorkerDomains)
	}
	if cfg.CFProxy && len(cfg.CFProxyUserDomains) == 0 {
		m.wg.Add(1)
		go func() { defer m.wg.Done(); runCFDomainRefresh(ctx, bal) }()
	}

	log.Printf("tgws: upstream %s listening on :%d (fake-tls=%q, pool=%d)", UpstreamVersion, cfg.Port, censorDomains(cfg.FakeTLSDomain), cfg.PoolSize)
	return nil
}

func (m *Manager) acceptLoop(ln net.Listener, h *clientHandler, conns *connSet) {
	defer m.wg.Done()
	address := ln.Addr().String()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if h.ctx.Err() != nil {
				return
			}
			_ = ln.Close()
			log.Printf("tgws: listener failed; reopening %s: %s", address, censorDomains(err.Error()))
			for {
				select {
				case <-h.ctx.Done():
					return
				case <-time.After(time.Second):
				}
				reopened, err := net.Listen("tcp", address)
				if err != nil {
					continue
				}
				m.mu.Lock()
				if h.ctx.Err() != nil {
					m.mu.Unlock()
					_ = reopened.Close()
					return
				}
				m.ln = reopened
				m.mu.Unlock()
				ln = reopened
				log.Printf("tgws: listener restored on %s", address)
				break
			}
			continue
		}
		if !conns.add(conn) {
			continue
		}
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			defer conns.remove(conn)
			h.handle(conn)
		}()
	}
}

// Stop shuts the listener, aborts in-flight dials and drops active clients.
func (m *Manager) Stop() {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.stop()
}

func (m *Manager) stop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	m.running = false
	cancel, ln, pool, conns := m.cancel, m.ln, m.pool, m.conns
	workerPool := m.workerPool
	m.workerPool = nil
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
	if workerPool != nil {
		workerPool.reset()
	}
	m.wg.Wait()
	log.Printf("tgws: stopped. stats: %s", m.stats.summary())
}

func (m *Manager) Restart() error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.stop()
	return m.start()
}

// connSet tracks live client connections so Stop can drop them all.
type connSet struct {
	mu     sync.Mutex
	m      map[net.Conn]struct{}
	closed bool
}

func newConnSet() *connSet { return &connSet{m: map[net.Conn]struct{}{}} }

func (cs *connSet) add(c net.Conn) bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.closed {
		_ = c.Close()
		return false
	}
	cs.m[c] = struct{}{}
	return true
}
func (cs *connSet) remove(c net.Conn) {
	cs.mu.Lock()
	delete(cs.m, c)
	cs.mu.Unlock()
}
func (cs *connSet) closeAll() {
	cs.mu.Lock()
	cs.closed = true
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
