package tgws

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// Socks5Manager owns the SOCKS5 proxy lifecycle (mirrors Manager). Start/Stop/
// Restart are safe to call concurrently; it is held by the host app.
type Socks5Manager struct {
	mu      sync.Mutex
	cfg     *Socks5Config
	stats   *Socks5Stats
	running bool

	ln     net.Listener
	ctx    context.Context
	cancel context.CancelFunc
	conns  *connSet
	wg     sync.WaitGroup
}

func NewSocks5Manager(cfg *Socks5Config) *Socks5Manager {
	cfg.Normalize()
	return &Socks5Manager{cfg: cfg, stats: &Socks5Stats{}}
}

func (m *Socks5Manager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

func (m *Socks5Manager) Config() Socks5Config {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := *m.cfg
	c.DCRedirects = copyDC(m.cfg.DCRedirects)
	return c
}

func (m *Socks5Manager) Stats() Socks5Snapshot { return m.stats.snapshot() }

func (m *Socks5Manager) Link(hostOverride string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Socks5LinkFor(m.cfg, hostOverride)
}

// SetConfig replaces the config and restarts the proxy if it was running.
func (m *Socks5Manager) SetConfig(cfg *Socks5Config) error {
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

func (m *Socks5Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		return nil
	}
	cfg := m.cfg
	ctx, cancel := context.WithCancel(context.Background())
	settings := socks5Settings{
		user:        cfg.User,
		pass:        cfg.Pass,
		bufferSize:  cfg.BufferSize,
		dcRedirects: copyDC(cfg.DCRedirects),
	}
	conns := newConnSet()
	handler := newSocks5Handler(ctx, settings, m.stats)

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Port))
	if err != nil {
		cancel()
		return fmt.Errorf("не удалось открыть порт %d: %w", cfg.Port, err)
	}

	m.ln, m.ctx, m.cancel, m.conns = ln, ctx, cancel, conns
	m.running = true
	m.stats.startedAt.Store(time.Now().Unix())

	m.wg.Add(1)
	go m.acceptLoop(ln, handler, conns)
	log.Printf("socks5: listening on :%d (auth=%v)", cfg.Port, cfg.User != "")
	return nil
}

func (m *Socks5Manager) acceptLoop(ln net.Listener, h *socks5Handler, conns *connSet) {
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

func (m *Socks5Manager) Stop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	m.running = false
	cancel, ln, conns := m.cancel, m.ln, m.conns
	m.cancel, m.ln, m.conns = nil, nil, nil
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
	m.wg.Wait()
	log.Printf("socks5: stopped")
}

func (m *Socks5Manager) Restart() error {
	m.Stop()
	return m.Start()
}
