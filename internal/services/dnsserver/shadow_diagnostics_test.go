package dnsserver

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"nfqws2strategy/internal/services/dnsroute"
	"nfqws2strategy/internal/tools/store"
)

type diagnosticShadowBackend struct {
	resolverTestBackend
	snapshot func() dnsroute.ShadowDiagnostics
	queries  int
	set      func(bool)
}

func (b *diagnosticShadowBackend) SetShadowDiagnostics(enabled bool) { b.set(enabled) }

func (b *diagnosticShadowBackend) ShadowDiagnostics() dnsroute.ShadowDiagnostics {
	return b.snapshot()
}

func (b *diagnosticShadowBackend) ShadowDNSServers(context.Context) ([]string, error) {
	b.queries++
	return []string{"192.0.2.53:53"}, nil
}

func TestShadowDiagnosticsStatusIsPassiveAndOutsideServiceLock(t *testing.T) {
	backend := &diagnosticShadowBackend{}
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := New(st, backend, func(string) (string, error) { return "192.0.2.1", nil })
	backend.snapshot = func() dnsroute.ShadowDiagnostics {
		if !s.mu.TryLock() {
			t.Fatal("service status held service mutex while obtaining diagnostics")
		}
		s.mu.Unlock()
		return dnsroute.ShadowDiagnostics{Version: 1, Attempts: []dnsroute.ShadowDiagnosticAttempt{{ID: 7, Error: "probe timeout"}}}
	}
	status := s.Status()
	if status.ShadowDNS.Diagnostics == nil || status.ShadowDNS.Diagnostics.Attempts[0].ID != 7 || backend.queries != 0 || backend.prepareCount != 0 {
		t.Fatalf("missing or active diagnostics: %+v", status.ShadowDNS)
	}
	raw, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Status
	if err := json.Unmarshal(raw, &decoded); err != nil || decoded.ShadowDNS.Diagnostics == nil || decoded.ShadowDNS.Diagnostics.Version != 1 {
		t.Fatalf("missing diagnostics in status JSON: %v", err)
	}
	s.backend = &resolverTestBackend{}
	if s.Status().ShadowDNS.Diagnostics != nil {
		t.Fatal("unsupported backend returned stale diagnostics")
	}
}

func TestShadowDiagnosticsTogglePreservesDNSRunCacheAndConfig(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	state := false
	backend := &diagnosticShadowBackend{set: func(enabled bool) { state = enabled }}
	backend.snapshot = func() dnsroute.ShadowDiagnostics { return dnsroute.ShadowDiagnostics{Version: 1, Enabled: state} }
	cfg := Default()
	cfg.Enabled, cfg.FastDNS = true, false
	if err := st.Save(configFile, cfg); err != nil {
		t.Fatal(err)
	}
	s := New(st, backend, func(string) (string, error) { return "127.0.0.1", nil })
	resolver := NewResolver(cfg, backend)
	s.active = &serviceRun{resolver: resolver}
	t.Cleanup(resolver.Close)
	before := s.Config()
	beforeFile, err := os.ReadFile(s.store.Path(configFile))
	if err != nil {
		t.Fatal(err)
	}
	run := s.active
	cacheGeneration := run.resolver.cacheGeneration
	for _, enabled := range []bool{true, false, true, false} {
		if err := s.SetShadowDiagnostics(enabled); err != nil {
			t.Fatal(err)
		}
		if s.Status().ShadowDNS.Diagnostics.Enabled != enabled {
			t.Fatal("toggle state not exposed")
		}
		if s.active != run || run.resolver.lifetime.Err() != nil || run.resolver.cacheGeneration != cacheGeneration {
			t.Fatal("diagnostics restarted DNS or discarded its cache")
		}
	}
	afterFile, err := os.ReadFile(s.store.Path(configFile))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, s.Config()) || !bytes.Equal(beforeFile, afterFile) || backend.prepareCount != 0 || backend.queries != 0 {
		t.Fatal("diagnostic toggle affected DNS settings/network")
	}
	s.backend = &resolverTestBackend{}
	if err := s.SetShadowDiagnostics(true); err == nil {
		t.Fatal("unsupported backend accepted toggle")
	}
}
