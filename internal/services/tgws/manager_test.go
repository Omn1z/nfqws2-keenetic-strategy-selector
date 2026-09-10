package tgws

import (
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

func localTestManager(t *testing.T) (*Manager, string) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	cfg := Default()
	cfg.Port = port
	cfg.CFProxy = false
	cfg.PoolSize = 0
	cfg.Enabled = true
	m := NewManager(cfg)
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Stop)
	return m, net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

func TestListenerRestoresAndStopClosesPendingHandshakes(t *testing.T) {
	m, address := localTestManager(t)
	m.mu.Lock()
	original := m.ln
	m.mu.Unlock()
	_ = original.Close() // emulate unexpected listener loss while service is enabled
	deadline := time.Now().Add(4 * time.Second)
	var conn net.Conn
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if err == nil {
			conn = c
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if conn == nil {
		t.Fatal("listener never recovered")
	}
	defer conn.Close()
	m.Stop()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("pending handshake survived Stop")
	}
	if m.Running() {
		t.Fatal("still running after Stop")
	}
	if c, err := net.DialTimeout("tcp", address, 100*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("listener survived Stop")
	}
}

func TestConcurrentLifecycleDoesNotLeaveOldListener(t *testing.T) {
	m, address := localTestManager(t)
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 3; n++ {
				if err := m.Restart(); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	m.Stop()
	if conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond); err == nil {
		conn.Close()
		t.Fatal("leaked listener")
	}
}
