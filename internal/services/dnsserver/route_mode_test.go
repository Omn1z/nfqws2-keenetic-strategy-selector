package dnsserver

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"

	mdns "github.com/miekg/dns"
	"nfqws2strategy/internal/services/dnsroute"
	"nfqws2strategy/internal/tools/store"
)

type routeModeRecordingBackend struct {
	resolverTestBackend
	prepared []dnsroute.ListenOptions
}

func (b *routeModeRecordingBackend) Prepare(ctx context.Context, opts dnsroute.ListenOptions) error {
	b.mu.Lock()
	b.prepared = append(b.prepared, opts)
	b.mu.Unlock()
	return b.resolverTestBackend.Prepare(ctx, opts)
}

func TestRouteModeNormalizesOldConfigAndRejectsContradiction(t *testing.T) {
	if got := Default().RouteMode; got != "auto" {
		t.Fatalf("default route mode = %q, want auto", got)
	}
	old := Default()
	encoded, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "route_mode")
	encoded, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	var loaded Config
	if err = json.Unmarshal(encoded, &loaded); err != nil {
		t.Fatal(err)
	}
	if err = loaded.NormalizeValidate(); err != nil || loaded.RouteMode != "auto" {
		t.Fatalf("old config route mode = %q, error %v", loaded.RouteMode, err)
	}
	loaded.RouteMode = "vpn_only"
	loaded.AWGFallback = "off"
	if err = loaded.NormalizeValidate(); err == nil || !strings.Contains(err.Error(), "AWG") {
		t.Fatalf("vpn_only with AWG off accepted: %v", err)
	}
	loaded.AWGFallback = "auto"
	if err = loaded.NormalizeValidate(); err != nil {
		t.Fatalf("vpn_only with AWG enabled rejected: %v", err)
	}
	loaded.RouteMode = "direct"
	if err = loaded.NormalizeValidate(); err == nil || !strings.Contains(err.Error(), "route") && !strings.Contains(err.Error(), "маршрутизации") {
		t.Fatalf("unknown route mode accepted: %v", err)
	}
}

func TestVPNOnlyFiltersQueriesFastDNSAndProbes(t *testing.T) {
	cfg := Default()
	cfg.RouteMode = "vpn_only"
	cfg.Rules = nil
	cfg.DefaultUpstream = Upstream{Address: "https://resolver.example/dns-query"}
	routes := []dnsroute.Route{{ID: "nfqws", Available: true}, {ID: "awg:warp", Available: true}, {ID: "awg:down", Available: false}}
	if got := eligibleRoutes(cfg, routes); len(got) != 2 || got[0].ID != "awg:warp" || got[1].ID != "awg:down" {
		t.Fatalf("VPN-only eligible routes: %+v", got)
	}
	ordered := NewScheduler().order(cfg, routes, "example.com")
	if len(ordered) != 1 || ordered[0].route.ID != "awg:warp" {
		t.Fatalf("VPN-only query candidates: %+v", ordered)
	}
	if got := fastDNSTargets(cfg, routes); !reflect.DeepEqual(got, []FastDNSTarget{{Route: "awg:warp", Host: "resolver.example"}}) {
		t.Fatalf("VPN-only bootstrap targets: %+v", got)
	}
	if got := schedulerProbeCandidates(cfg, routes); len(got) != 1 || got[0].route.ID != "awg:warp" {
		t.Fatalf("VPN-only probes: %+v", got)
	}
	cfg.AWGFallback = "down"
	if got := NewScheduler().order(cfg, routes, "example.com"); len(got) != 0 {
		t.Fatalf("unavailable selected VPN created query attempts: %+v", got)
	}
	if got := fastDNSTargets(cfg, routes); len(got) != 0 {
		t.Fatalf("unavailable selected VPN created bootstrap targets: %+v", got)
	}
	if got := schedulerProbeCandidates(cfg, routes); len(got) != 0 {
		t.Fatalf("unavailable selected VPN created probes: %+v", got)
	}
}

func TestVPNOnlyNoWANAttemptWhenTunnelUnavailable(t *testing.T) {
	cfg := Default()
	cfg.RouteMode = "vpn_only"
	cfg.Rules = nil
	cfg.CacheSize = 0
	backend := &resolverTestBackend{routes: []dnsroute.Route{{ID: "nfqws", Available: true}, {ID: "awg:warp", Available: false}}}
	r := NewResolver(cfg, backend)
	defer r.Close()
	_, _, err := r.Resolve(context.Background(), resolverWire(t, "example.com", 1, mdns.TypeA))
	if err == nil || !strings.Contains(err.Error(), "только VPN") {
		t.Fatalf("missing fail-closed VPN error: %v", err)
	}
	if calls := backend.dialCalls(); len(calls) != 0 {
		t.Fatalf("VPN unavailable but attempted route(s): %v", calls)
	}
}

func TestVPNOnlyServiceReturnsSERVFAILWithoutTunnel(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := Default()
	cfg.RouteMode = RouteModeVPNOnly
	cfg.ListenHost = "127.0.0.1"
	cfg.DNSPort = protocolTestPort(t)
	cfg.Rules = nil
	if err := st.Save(configFile, cfg); err != nil {
		t.Fatal(err)
	}
	b := &routeModeRecordingBackend{resolverTestBackend: resolverTestBackend{routes: []dnsroute.Route{{ID: "nfqws", Available: true}}}}
	s := New(st, b, func(string) (string, error) { return "127.0.0.1", nil })
	t.Cleanup(s.Close)
	if err := s.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
	if status := s.Status(); !status.Running {
		t.Fatalf("VPN-only service failed to start: %s", status.LastError)
	}
	msg := queryDNSService(t, &mdns.Client{Net: "udp"}, s.Status().Endpoints.DNS, 3)
	if msg.Rcode != mdns.RcodeServerFailure {
		t.Fatalf("no tunnel response = %s, want SERVFAIL", mdns.RcodeToString[msg.Rcode])
	}
	if calls := b.dialCalls(); len(calls) != 0 {
		t.Fatalf("VPN-only service tried WAN route: %v", calls)
	}
	if lastErr := s.Status().Stats.LastError; !strings.Contains(lastErr, "только VPN") {
		t.Fatalf("missing VPN-only failure reason: %q", lastErr)
	}
}

func TestVPNOnlyBootstrapNeverDialsNFQWS(t *testing.T) {
	cfg := Default()
	cfg.RouteMode = "vpn_only"
	cfg.Rules = nil
	cfg.FastDNS = false
	cfg.CacheSize = 0
	cfg.DefaultUpstream = Upstream{Address: "https://resolver.example/dns-query"}
	backend := &resolverTestBackend{routes: []dnsroute.Route{{ID: "nfqws", Available: true}, {ID: "awg:warp", Available: true}}}
	backend.dialHook = func(_ context.Context, _, _, address string) (net.Conn, error) {
		return nil, errors.New("test endpoint unavailable: " + address)
	}
	r := NewResolver(cfg, backend)
	defer r.Close()
	_, _, err := r.Resolve(context.Background(), resolverWire(t, "example.com", 2, mdns.TypeA))
	if err == nil || !strings.Contains(err.Error(), "bootstrap") {
		t.Fatalf("expected failed same-route bootstrap: %v", err)
	}
	calls := backend.dialCalls()
	if len(calls) != 2 || calls[0] != "awg:warp" || calls[1] != "awg:warp" {
		t.Fatalf("bootstrap escaped VPN route: %v", calls)
	}
}

func TestRouteModeSwitchRepreparesBackendAndClearsCache(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := Default()
	cfg.Enabled = false
	cfg.ListenHost = "127.0.0.1"
	cfg.DNSPort = protocolTestPort(t)
	cfg.Rules = nil
	if err := st.Save(configFile, cfg); err != nil {
		t.Fatal(err)
	}
	b := &routeModeRecordingBackend{}
	s := New(st, b, func(string) (string, error) { return "127.0.0.1", nil })
	t.Cleanup(s.Close)
	if err := s.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
	if status := s.Status(); !status.Running {
		t.Fatalf("auto mode failed to start: %s", status.LastError)
	}
	s.mu.RLock()
	oldResolver := s.active.resolver
	s.mu.RUnlock()
	oldResolver.mu.Lock()
	oldResolver.cache["stale.example/A"] = dnsCacheEntry{}
	oldResolver.mu.Unlock()

	cfg = s.Config()
	cfg.RouteMode = RouteModeVPNOnly
	if err := s.SetConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if status := s.Status(); !status.Running || status.Cache.Entries != 0 {
		t.Fatalf("VPN-only mode did not restart with empty cache: %+v", status)
	}
	s.mu.RLock()
	newResolver := s.active.resolver
	s.mu.RUnlock()
	if newResolver == oldResolver {
		t.Fatal("mode switch reused answer cache")
	}
	b.mu.Lock()
	prepared := append([]dnsroute.ListenOptions(nil), b.prepared...)
	b.mu.Unlock()
	if len(prepared) != 2 || prepared[0].DisableNFQWS || !prepared[1].DisableNFQWS {
		t.Fatalf("firewall options across route mode switch: %+v", prepared)
	}
}
