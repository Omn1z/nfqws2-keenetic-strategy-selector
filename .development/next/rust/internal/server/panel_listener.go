package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// PanelListener replaces only the web listener when the user changes its port.
// All service managers and authenticated sessions remain in the same process.
type PanelListener struct {
	mu      sync.Mutex
	host    string
	address string
	handler http.Handler
	current *http.Server
	servers map[*http.Server]struct{}
	errors  chan error
	closed  bool
	grace   time.Duration
}

func NewPanelListener(address string, handler http.Handler) (*PanelListener, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	m := &PanelListener{
		host: host, address: ln.Addr().String(), handler: handler,
		servers: make(map[*http.Server]struct{}), errors: make(chan error, 1),
		grace: 5 * time.Second,
	}
	m.startLocked(ln)
	return m, nil
}

func (m *PanelListener) startLocked(ln net.Listener) {
	srv := &http.Server{Addr: ln.Addr().String(), Handler: m.handler, ReadHeaderTimeout: 10 * time.Second}
	m.current = srv
	m.servers[srv] = struct{}{}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			select {
			case m.errors <- err:
			default:
			}
		}
	}()
}

func (m *PanelListener) Address() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.address
}

func (m *PanelListener) Errors() <-chan error { return m.errors }

// ChangePort reserves the new port before persisting it. A bind or save failure
// leaves the existing listener untouched; it cannot strand the current client.
func (m *PanelListener) ChangePort(port int, persist func() error) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("порт панели должен быть от 1 до 65535")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return fmt.Errorf("HTTP-сервер останавливается")
	}
	_, oldPort, _ := net.SplitHostPort(m.address)
	if oldPort == strconv.Itoa(port) {
		return persist()
	}
	address := net.JoinHostPort(m.host, strconv.Itoa(port))
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("не удалось открыть порт панели %d: %w", port, err)
	}
	if err := persist(); err != nil {
		_ = ln.Close()
		return err
	}
	old := m.current
	m.address = ln.Addr().String()
	m.startLocked(ln)
	log.Printf("web panel now listening on %s", m.address)
	// Keep the old port alive briefly so the save response can reach the browser
	// before it follows the new URL. Shut it down even if a request is stuck.
	go func() {
		time.Sleep(m.grace)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = old.Shutdown(ctx)
		_ = old.Close()
		m.mu.Lock()
		delete(m.servers, old)
		m.mu.Unlock()
	}()
	return nil
}

func (m *PanelListener) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	m.closed = true
	servers := make([]*http.Server, 0, len(m.servers))
	for srv := range m.servers {
		servers = append(servers, srv)
	}
	m.mu.Unlock()
	var wg sync.WaitGroup
	for _, srv := range servers {
		wg.Add(1)
		go func(srv *http.Server) {
			defer wg.Done()
			_ = srv.Shutdown(ctx)
			_ = srv.Close()
		}(srv)
	}
	wg.Wait()
	return ctx.Err()
}
