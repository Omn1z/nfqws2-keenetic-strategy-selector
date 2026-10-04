package dnsserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"nfqws2strategy/internal/services/dnsroute"
	"nfqws2strategy/internal/tools/store"
)

type diagnosticShadowBackend struct {
	resolverTestBackend
	snapshot func() dnsroute.ShadowDiagnostics
	queries  int
}

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
	if err != nil || !strings.Contains(string(raw), `"diagnostics":{"version":1`) {
		t.Fatalf("missing status JSON: %v %s", err, raw)
	}
	s.backend = &resolverTestBackend{}
	if s.Status().ShadowDNS.Diagnostics != nil {
		t.Fatal("unsupported backend returned stale diagnostics")
	}
}
