package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"nfqws2strategy/internal/services/dnsserver"
)

func TestDNSServerSettingsExportPreservesCompleteSavedConfig(t *testing.T) {
	cfg := dnsserver.Default()
	cfg.Enabled = true
	cfg.ShadowDNS.Enabled = true
	cfg.ShadowDNS.Servers = []string{"192.0.2.53:53"}
	cfg.ListenHost = "192.168.3.1"
	cfg.DNSPort = 5356
	cfg.LoggingEnabled = false
	cfg.FastDNS = false
	cfg.AWGFallback = "saved-warp-connection"
	cfg.RouteMode = dnsserver.RouteModeVPNOnly
	cfg.TimeoutSeconds, cfg.CacheSize, cfg.CacheTTLSeconds = 7, 123, 456
	cfg.DefaultUpstream = dnsserver.Upstream{Address: "https://cloudflare-dns.com/dns-query", BootstrapIPs: []string{"1.1.1.1", "2606:4700:4700::1111"}}
	cfg.DefaultPool = []dnsserver.Upstream{{Address: "https://dns.quad9.net/dns-query", BootstrapIPs: []string{"9.9.9.9"}}}
	cfg.Rules = []dnsserver.Rule{
		{ID: "group-a", Enabled: true, Domain: "example.com", IncludeSubdomains: true, Upstream: cfg.DefaultUpstream, Pool: cfg.DefaultPool},
		{ID: "group-b", Enabled: false, Domain: "exact.example", IncludeSubdomains: false, Upstream: cfg.DefaultPool[0], Pool: []dnsserver.Upstream{}},
	}
	cfg.Filtering = &dnsserver.FilteringConfig{Enabled: true, Lists: []string{"adguard"}, Allowlist: []string{"allowed.example"}, CustomRules: []dnsserver.BlockingRule{{Domain: "ads.example", Category: "ads"}, {Domain: "tracker.example", Category: "trackers"}}}
	cfg.DisabledMethods = []dnsserver.DisabledMethod{{Upstream: cfg.DefaultUpstream.Address, Route: "nfqws"}, {Upstream: cfg.DefaultPool[0].Address, Route: "awg:saved-warp-connection"}}
	before, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 2, 17, 4, 5, 0, time.FixedZone("MSK", 3*60*60))
	w := httptest.NewRecorder()
	writeDNSServerSettingsExport(w, cfg, now)
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("invalid response: %d %v", w.Code, w.Header())
	}
	if got := w.Header().Get("Content-Disposition"); got != `attachment; filename="dns-server-settings-20261002-140405.json"` {
		t.Fatalf("unsafe or incorrect download filename: %q", got)
	}
	var doc dnsServerSettingsExport
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Format != dnsServerExportFormat || doc.Version != 1 || !doc.ExportedAt.Equal(now) || doc.ExportedAt.Location() != time.UTC {
		t.Fatalf("invalid versioned UTC envelope: %+v", doc)
	}
	if !reflect.DeepEqual(doc.Config, cfg) {
		t.Fatalf("export omitted or changed saved settings:\nwant: %+v\ngot: %+v", cfg, doc.Config)
	}
	after, err := json.Marshal(cfg)
	if err != nil || string(after) != string(before) {
		t.Fatal("export modified its saved configuration snapshot")
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil || len(envelope) != 4 {
		t.Fatalf("export included runtime state: %v %v", envelope, err)
	}
	for _, field := range []string{"format", "version", "exported_at", "config"} {
		if _, exists := envelope[field]; !exists {
			t.Fatalf("missing envelope field %s", field)
		}
	}
}

func TestDNSServerSettingsExportKeepsDisabledAndEmptySettings(t *testing.T) {
	cfg := dnsserver.Default()
	cfg.Enabled, cfg.LoggingEnabled, cfg.FastDNS = false, false, false
	cfg.CacheSize = 0
	cfg.Rules = []dnsserver.Rule{}
	cfg.DefaultPool = []dnsserver.Upstream{}
	cfg.DisabledMethods = []dnsserver.DisabledMethod{}
	cfg.Filtering = &dnsserver.FilteringConfig{Enabled: false, Lists: []string{}, CustomRules: []dnsserver.BlockingRule{}, Allowlist: []string{}}
	w := httptest.NewRecorder()
	writeDNSServerSettingsExport(w, cfg, time.Now())
	var doc dnsServerSettingsExport
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil || !reflect.DeepEqual(doc.Config, cfg) {
		t.Fatalf("export changed disabled or empty settings: %+v %v", doc.Config, err)
	}
}

func TestDNSServerSettingsExportIsReadOnlyAndProtected(t *testing.T) {
	if publicAPI("/api/dnsserver/export") {
		t.Fatal("settings export must remain behind the API authentication gate")
	}
	// Inspect the real mux without starting an App or any router service.
	s := New(nil)
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		_, pattern := s.mux.Handler(httptest.NewRequest(method, "/api/dnsserver/export", nil))
		if pattern != "GET /api/dnsserver/export" {
			t.Fatalf("export not registered for %s: %q", method, pattern)
		}
	}
	_, pattern := s.mux.Handler(httptest.NewRequest(http.MethodPost, "/api/dnsserver/export", strings.NewReader(`{"enabled":true}`)))
	if pattern == "GET /api/dnsserver/export" {
		t.Fatal("a mutation method reached the settings export handler")
	}
}
