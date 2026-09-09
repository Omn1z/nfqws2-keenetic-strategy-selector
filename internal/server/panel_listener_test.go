package server

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func panelTestPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func panelTestGet(address string) (string, error) {
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: time.Second}
	resp, err := client.Get("http://" + address)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func panelTestServer(t *testing.T) *PanelListener {
	t.Helper()
	m, err := NewPanelListener("127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "panel")
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = m.Shutdown(ctx)
	})
	return m
}

func TestPanelListenerOccupiedPortKeepsExistingListener(t *testing.T) {
	m := panelTestServer(t)
	old := m.Address()
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	saved := false
	err = m.ChangePort(occupied.Addr().(*net.TCPAddr).Port, func() error { saved = true; return nil })
	if err == nil || saved || m.Address() != old {
		t.Fatalf("bind failure changed state: err=%v saved=%v address=%s", err, saved, m.Address())
	}
	if body, err := panelTestGet(old); err != nil || body != "panel" {
		t.Fatalf("old panel unavailable: %q %v", body, err)
	}
}

func TestPanelListenerSaveFailureReleasesReplacement(t *testing.T) {
	m := panelTestServer(t)
	old := m.Address()
	port := panelTestPort(t)
	want := errors.New("disk full")
	if err := m.ChangePort(port, func() error { return want }); !errors.Is(err, want) {
		t.Fatalf("persistence failure: %v", err)
	}
	if m.Address() != old {
		t.Fatal("persistence failure switched address")
	}
	if body, err := panelTestGet(old); err != nil || body != "panel" {
		t.Fatalf("old panel unavailable: %q %v", body, err)
	}
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("failed replacement socket leaked: %v", err)
	}
	_ = ln.Close()
}

func TestPanelListenerSwitchPreservesResponseAndClosesOldPort(t *testing.T) {
	var m *PanelListener
	newPort := panelTestPort(t)
	var err error
	m, err = NewPanelListener("127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/switch" {
			if err := m.ChangePort(newPort, func() error { return nil }); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			time.Sleep(60 * time.Millisecond)
		}
		_, _ = io.WriteString(w, "panel")
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Shutdown(context.Background())
	m.grace = 20 * time.Millisecond
	old := m.Address()
	if body, err := panelTestGet(old + "/switch"); err != nil || body != "panel" {
		t.Fatalf("save response was interrupted: %q %v", body, err)
	}
	if body, err := panelTestGet(m.Address()); err != nil || body != "panel" {
		t.Fatalf("new panel unavailable: %q %v", body, err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := panelTestGet(old); err != nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("old port still accepts connections after grace period")
}

func TestPanelListenerShutdownDuringPortChangeClosesBothPorts(t *testing.T) {
	m := panelTestServer(t)
	old := m.Address()
	port := panelTestPort(t)
	saving := make(chan struct{})
	resume := make(chan struct{})
	changed := make(chan error, 1)
	go func() {
		changed <- m.ChangePort(port, func() error {
			close(saving)
			<-resume
			return nil
		})
	}()
	<-saving
	stopped := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		stopped <- m.Shutdown(ctx)
	}()
	close(resume)
	if err := <-changed; err != nil {
		t.Fatalf("reserved port change failed: %v", err)
	}
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("shutdown failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown deadlocked with port change")
	}
	for _, address := range []string{old, m.Address()} {
		if _, err := panelTestGet(address); err == nil {
			t.Fatalf("server still accepts requests on %s after shutdown", address)
		}
	}
	saved := false
	if err := m.ChangePort(port, func() error { saved = true; return nil }); err == nil || saved {
		t.Fatalf("changed port after shutdown: err=%v saved=%v", err, saved)
	}
}
