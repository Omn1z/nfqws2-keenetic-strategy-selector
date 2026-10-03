package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"nfqws2strategy/internal/services/dnsserver"
)

func dnsConfigPayload(t *testing.T, cfg dnsserver.Config) map[string]any {
	t.Helper()
	wire, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(wire, &payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

func decodeDNSConfigRequest(t *testing.T, payload map[string]any) dnsServerConfigRequest {
	t.Helper()
	wire, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/dnsserver/config", strings.NewReader(string(wire)))
	var in dnsServerConfigRequest
	if err := readJSON(r, &in); err != nil {
		t.Fatal(err)
	}
	return in
}

func TestDNSConfigOldPOSTPreservesIndependentSettings(t *testing.T) {
	current := dnsserver.Default()
	current.RouteMode = dnsserver.RouteModeVPNOnly
	current.SchedulerEnabled = false
	current.Filtering.Enabled = true
	current.ShadowDNS.Enabled = true
	current.ShadowDNS.Servers = []string{"192.0.2.53:53"}
	current.Filtering.Allowlist = []string{"allowed.example"}
	current.CacheTTLSeconds = 1234
	current.DefaultPool = []dnsserver.Upstream{{Address: "https://9.9.9.9/dns-query"}}
	current.Rules[0].Pool = []dnsserver.Upstream{{Address: "https://8.8.8.8/dns-query"}}
	current.DisabledMethods = []dnsserver.DisabledMethod{{Upstream: current.DefaultUpstream.Address, Route: "nfqws"}}
	payload := dnsConfigPayload(t, current)
	delete(payload, "route_mode")
	delete(payload, "filtering")
	delete(payload, "shadow_dns")
	delete(payload, "fast_dns")
	delete(payload, "scheduler_enabled")
	delete(payload, "cache_ttl_seconds")
	delete(payload, "default_pool")
	delete(payload["rules"].([]any)[0].(map[string]any), "pool")
	payload["dns_port"] = 9999
	payload["logging_enabled"] = false
	payload["disabled_methods"] = []any{}

	in := decodeDNSConfigRequest(t, payload)
	if in.RouteMode != nil {
		t.Fatal("old request unexpectedly supplied route mode")
	}
	merged := in.merge(current)
	if merged.SchedulerEnabled {
		t.Fatal("old tab re-enabled the saved disabled scheduler")
	}
	if merged.RouteMode != dnsserver.RouteModeVPNOnly || merged.DNSPort != current.DNSPort || merged.LoggingEnabled != current.LoggingEnabled || merged.FastDNS != current.FastDNS || merged.CacheTTLSeconds != current.CacheTTLSeconds {
		t.Fatalf("old request reset current settings: %+v", merged)
	}
	if !reflect.DeepEqual(merged.DisabledMethods, current.DisabledMethods) || !reflect.DeepEqual(merged.DefaultPool, current.DefaultPool) || !reflect.DeepEqual(merged.Rules[0].Pool, current.Rules[0].Pool) {
		t.Fatalf("old request reset methods or pools: %+v", merged)
	}
	if !reflect.DeepEqual(merged.Filtering, current.Filtering) {
		t.Fatalf("old request reset filtering: %+v", merged.Filtering)
	}
	if !reflect.DeepEqual(merged.ShadowDNS, current.ShadowDNS) {
		t.Fatalf("old request reset Shadow DNS: %+v", merged.ShadowDNS)
	}
	if err := merged.NormalizeValidate(); err != nil {
		t.Fatalf("merged old request should remain valid: %v", err)
	}
}

func TestDNSConfigExplicitSchedulerSwitch(t *testing.T) {
	current := dnsserver.Default()
	for _, enabled := range []bool{false, true} {
		payload := dnsConfigPayload(t, current)
		payload["scheduler_enabled"] = enabled
		merged := decodeDNSConfigRequest(t, payload).merge(current)
		if merged.SchedulerEnabled != enabled {
			t.Fatalf("explicit scheduler switch = %v, want %v", merged.SchedulerEnabled, enabled)
		}
	}
}

func TestDNSConfigExplicitRouteModeAndInvalidCombination(t *testing.T) {
	current := dnsserver.Default()
	current.RouteMode = dnsserver.RouteModeVPNOnly
	for _, tc := range []struct {
		name        string
		routeMode   *string
		awgFallback string
		wantMode    string
		wantError   bool
	}{
		{name: "explicit auto switch", routeMode: ptrString(dnsserver.RouteModeAuto), awgFallback: "off", wantMode: dnsserver.RouteModeAuto},
		{name: "unknown route mode", routeMode: ptrString("direct"), awgFallback: "auto", wantMode: "direct", wantError: true},
		{name: "stale tab disables AWG", awgFallback: "off", wantMode: dnsserver.RouteModeVPNOnly, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := dnsConfigPayload(t, current)
			delete(payload, "route_mode")
			if tc.routeMode != nil {
				payload["route_mode"] = *tc.routeMode
			}
			payload["awg_fallback"] = tc.awgFallback
			merged := decodeDNSConfigRequest(t, payload).merge(current)
			if merged.RouteMode != tc.wantMode {
				t.Fatalf("merged route mode = %q, want %q", merged.RouteMode, tc.wantMode)
			}
			if err := merged.NormalizeValidate(); (err != nil) != tc.wantError {
				t.Fatalf("route mode %q with AWG %q validation = %v; want error %v", tc.wantMode, tc.awgFallback, err, tc.wantError)
			}
		})
	}
}

func ptrString(value string) *string { return &value }
