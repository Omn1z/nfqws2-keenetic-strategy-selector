//go:build linux

package awgroute

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testWgetScript(t *testing.T, script string) awgWgetCommand {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wget")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return awgWgetCommand{path: path}
}

func TestAWGDownloadFallsBackToWgetAfterHTTPFailure(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "unavailable", http.StatusBadGateway)
	}))
	defer server.Close()

	wget := testWgetScript(t, "printf 'engine archive'")
	got, err := downloadAWGAsset(context.Background(), server.URL+"/archive", 64, false, []awgWgetCommand{wget})
	if err != nil || string(got) != "engine archive" {
		t.Fatalf("wget fallback failed: data=%q, err=%v", got, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected one Go HTTP attempt, got %d", calls.Load())
	}
}

func TestAWGKeeneticDownloadPrefersWget(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte("HTTP archive"))
	}))
	defer server.Close()

	wget := testWgetScript(t, "printf 'wget archive'")
	got, err := downloadAWGAsset(context.Background(), server.URL+"/archive", 64, true, []awgWgetCommand{wget})
	if err != nil || string(got) != "wget archive" {
		t.Fatalf("Keenetic wget download failed: data=%q, err=%v", got, err)
	}
	if calls.Load() != 0 {
		t.Fatalf("Go HTTP was attempted before working wget: %d calls", calls.Load())
	}
}

func TestAWGKeeneticDownloadFallsBackToHTTP(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte("HTTP archive"))
	}))
	defer server.Close()

	wget := testWgetScript(t, "exit 1")
	got, err := downloadAWGAsset(context.Background(), server.URL+"/archive", 64, true, []awgWgetCommand{wget})
	if err != nil || string(got) != "HTTP archive" {
		t.Fatalf("Go HTTP fallback failed: data=%q, err=%v", got, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected one Go HTTP attempt, got %d", calls.Load())
	}
}

func TestAWGEmptyWgetResponseFallsBackToHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("HTTP archive"))
	}))
	defer server.Close()
	wget := testWgetScript(t, "exit 0")
	got, err := downloadAWGAsset(context.Background(), server.URL+"/archive", 64, true, []awgWgetCommand{wget})
	if err != nil || string(got) != "HTTP archive" {
		t.Fatalf("empty wget response did not fall back: data=%q, err=%v", got, err)
	}
}

func TestAWGDownloadRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("1234567890"))
	}))
	defer server.Close()
	if _, err := httpGetBytes(context.Background(), server.URL, time.Second, 4); err == nil || !strings.Contains(err.Error(), "лимита") {
		t.Fatalf("Go HTTP accepted oversized response: %v", err)
	}
	wget := testWgetScript(t, "printf '1234567890'")
	if _, err := wgetGetBytes(context.Background(), server.URL, 4, []awgWgetCommand{wget}); err == nil || !strings.Contains(err.Error(), "лимита") {
		t.Fatalf("wget accepted oversized response: %v", err)
	}
}

func TestAWGFailedDownloadPreservesInstalledEngine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "amneziawg-go")
	if err := os.WriteFile(path, []byte("working engine"), 0o755); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "missing", http.StatusNotFound)
	}))
	defer server.Close()
	wget := testWgetScript(t, "exit 1")
	if err := installAWGEngineFromRelease(context.Background(), server.URL+"/archive", dir, false, []awgWgetCommand{wget}); err == nil {
		t.Fatal("expected failed download")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "working engine" {
		t.Fatalf("working engine changed: data=%q, err=%v", got, err)
	}
}

func TestAWGBadChecksumPreservesInstalledEngine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "amneziawg-go")
	if err := os.WriteFile(path, []byte("working engine"), 0o755); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sha256") {
			_, _ = w.Write([]byte(strings.Repeat("0", 64)))
			return
		}
		_, _ = w.Write([]byte("archive with wrong checksum"))
	}))
	defer server.Close()
	if err := installAWGEngineFromRelease(context.Background(), server.URL+"/archive", dir, false, nil); err == nil || !strings.Contains(err.Error(), "контрольная сумма") {
		t.Fatalf("expected checksum failure, got %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "working engine" {
		t.Fatalf("working engine changed: data=%q, err=%v", got, err)
	}
}
