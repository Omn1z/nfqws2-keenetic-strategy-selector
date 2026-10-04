//go:build linux

package dnsroute

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestShadowDiagnosticsDiscoveryCacheAndNativeOutputPrivacy(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "ndmc"), []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	previous := command
	t.Cleanup(func() { command = previous })
	calls := 0
	command = func(context.Context, string, ...string) (string, error) {
		calls++
		return "private native log: vpn-password-secret", errors.New("output: vpn-password-secret")
	}
	a := New(nil, nil)
	a.cfg.DataDir = t.TempDir()
	if servers, err := a.ShadowDNSServers(context.Background()); err == nil || len(servers) != 0 {
		t.Fatalf("unexpected discovery result: %v %v", servers, err)
	}
	first := a.ShadowDiagnostics()
	if first.InProgress || len(first.Attempts) != 1 || first.Attempts[0].FinishedAt == nil || first.Attempts[0].NextRetryAt == nil || first.Attempts[0].Error == "" {
		t.Fatalf("missing failed attempt: %+v", first)
	}
	count := calls
	_, _ = a.ShadowDNSServers(context.Background())
	second := a.ShadowDiagnostics()
	if calls != count || len(second.Attempts) != 1 || !first.Attempts[0].StartedAt.Equal(second.Attempts[0].StartedAt) || len(first.Attempts[0].Events) != len(second.Attempts[0].Events) {
		t.Fatal("negative cache hit reset diagnostics or re-ran discovery")
	}
	raw, err := json.Marshal(second)
	if err != nil || strings.Contains(string(raw), "vpn-password-secret") || strings.Contains(string(raw), "private native log") {
		t.Fatalf("diagnostics leaked native output: %s (%v)", raw, err)
	}
	a.shadow.discoveryUntil = time.Time{}
	_, _ = a.ShadowDNSServers(context.Background())
	if got := a.ShadowDiagnostics(); len(got.Attempts) != 2 || got.Attempts[1].ID != first.Attempts[0].ID+1 {
		t.Fatalf("next real discovery did not append an attempt: %+v", got)
	}
}
