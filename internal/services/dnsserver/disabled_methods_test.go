package dnsserver

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"nfqws2strategy/internal/services/dnsroute"
)

func TestDisabledMethodsCanonicalizeExactProviderProfilesAndClone(t *testing.T) {
	cfg := Default()
	cfg.DisabledMethods = []DisabledMethod{
		{Upstream: " https://DNS.EXAMPLE:443 ", Route: "nfqws"},
		{Upstream: "https://dns.example/dns-query", Route: "nfqws"},
		{Upstream: "https://dns.example/profile-a?device=one", Route: "nfqws"},
		{Upstream: "https://dns.example/profile-b?device=one", Route: "nfqws"},
		{Upstream: "https://dns.example/profile-a?device=two", Route: "nfqws"},
		{Upstream: "https://dns.example/profile-a?device=one", Route: "awg:warp-1"},
	}
	if err := cfg.NormalizeValidate(); err != nil {
		t.Fatal(err)
	}
	want := []DisabledMethod{
		{Upstream: "https://dns.example/dns-query", Route: "nfqws"},
		{Upstream: "https://dns.example/profile-a?device=one", Route: "nfqws"},
		{Upstream: "https://dns.example/profile-b?device=one", Route: "nfqws"},
		{Upstream: "https://dns.example/profile-a?device=two", Route: "nfqws"},
		{Upstream: "https://dns.example/profile-a?device=one", Route: "awg:warp-1"},
	}
	if !reflect.DeepEqual(cfg.DisabledMethods, want) {
		t.Fatalf("method identity collapsed distinct profile/route or retained duplicate: %+v", cfg.DisabledMethods)
	}
	copy := cloneConfig(cfg)
	copy.DisabledMethods[0].Route = "awg:other"
	copy.DisabledMethods[1].Upstream = "https://other.example/dns-query"
	if !reflect.DeepEqual(cfg.DisabledMethods, want) {
		t.Fatal("cloning configuration shares mutable disabled methods")
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var reopened Config
	if err := json.Unmarshal(encoded, &reopened); err != nil {
		t.Fatal(err)
	}
	if err := reopened.NormalizeValidate(); err != nil || !reflect.DeepEqual(reopened.DisabledMethods, want) {
		t.Fatalf("disabled methods did not survive JSON round trip: %+v, %v", reopened.DisabledMethods, err)
	}
}

func TestDisabledMethodsValidateRoutesUpstreamsAndCapacity(t *testing.T) {
	for _, route := range []string{"", "direct", "awg:", "awg:bad route", "awg:bad;name", "awg:bad/name", "awg:тест", strings.Repeat("a", 200)} {
		t.Run("route_"+route, func(t *testing.T) {
			cfg := Default()
			cfg.DisabledMethods = []DisabledMethod{{Upstream: cfg.DefaultUpstream.Address, Route: route}}
			if err := cfg.NormalizeValidate(); err == nil {
				t.Fatalf("invalid route accepted: %q", route)
			}
		})
	}
	for _, upstream := range []string{"", "http://dns.example/dns-query", "https://user:pass@dns.example/dns-query", "https://dns.example/dns-query#fragment", "https://dns.example:0/dns-query"} {
		t.Run("upstream_"+upstream, func(t *testing.T) {
			cfg := Default()
			cfg.DisabledMethods = []DisabledMethod{{Upstream: upstream, Route: "nfqws"}}
			if err := cfg.NormalizeValidate(); err == nil {
				t.Fatalf("invalid DoH address accepted: %q", upstream)
			}
		})
	}
	cfg := Default()
	for i := range 2048 {
		cfg.DisabledMethods = append(cfg.DisabledMethods, DisabledMethod{Upstream: fmt.Sprintf("https://dns.example/profile-%d", i), Route: "nfqws"})
	}
	if err := cfg.NormalizeValidate(); err != nil {
		t.Fatalf("documented capacity rejected: %v", err)
	}
	cfg.DisabledMethods = append(cfg.DisabledMethods, DisabledMethod{Upstream: "https://dns.example/one-too-many", Route: "nfqws"})
	if err := cfg.NormalizeValidate(); err == nil {
		t.Fatal("unbounded disabled-method configuration accepted")
	}
	legacy := Default()
	encoded, _ := json.Marshal(legacy)
	var saved map[string]any
	if err := json.Unmarshal(encoded, &saved); err != nil {
		t.Fatal(err)
	}
	delete(saved, "disabled_methods")
	encoded, _ = json.Marshal(saved)
	var loaded Config
	if err := json.Unmarshal(encoded, &loaded); err != nil {
		t.Fatal(err)
	}
	if err := loaded.NormalizeValidate(); err != nil || len(loaded.DisabledMethods) != 0 {
		t.Fatalf("legacy configuration gained disabled methods: %+v, %v", loaded.DisabledMethods, err)
	}
}

func TestDisabledMethodsSchedulerKeepsVisibleHistoryButNeverSchedulesPair(t *testing.T) {
	cfg := Default()
	cfg.Rules = nil
	cfg.DefaultUpstream = Upstream{Address: "https://dns.example/profile-a?device=one"}
	cfg.DefaultPool = []Upstream{{Address: "https://dns.example/profile-b?device=one"}, {Address: "https://dns.example/profile-a?device=two"}}
	cfg.DisabledMethods = []DisabledMethod{{Upstream: cfg.DefaultUpstream.Address, Route: "nfqws"}}
	s := NewScheduler()
	now := time.Unix(1700000000, 0)
	s.now = func() time.Time { return now }
	s.started("nfqws", cfg.DefaultUpstream.Address)
	s.record(AttemptEvent{Route: "nfqws", Upstream: cfg.DefaultUpstream.Address, Success: true, DurationMS: 1})
	routes := schedulerTestRoutes()[:2]
	view := s.Snapshot(cfg, routes, "")
	if len(view.Candidates) != 6 {
		t.Fatalf("disabled method disappeared from the table: %+v", view)
	}
	for index, candidate := range view.Candidates {
		wantDisabled := candidate.Route == "nfqws" && candidate.Upstream == cfg.DefaultUpstream.Address
		if candidate.Disabled != wantDisabled {
			t.Fatalf("disable leaked to another profile/query/route: %+v", candidate)
		}
		if wantDisabled {
			if candidate.Position != 0 || index != len(view.Candidates)-1 || candidate.Successes != 1 || candidate.LatencyMS != 1 || candidate.LastResultAt == "" {
				t.Fatalf("disabled method lost measurements or retained queue priority: %+v", candidate)
			}
		} else if candidate.Position < 1 {
			t.Fatalf("active method lost queue position: %+v", candidate)
		}
	}
	for range 16 { // Also cover foreground exploration races 8 and 16.
		ordered := s.order(cfg, routes, "example.com")
		if len(ordered) != 5 {
			t.Fatalf("disabled method still counted in request order: %d", len(ordered))
		}
		for _, candidate := range ordered {
			if candidate.route.ID == "nfqws" && candidate.upstream.Address == cfg.DefaultUpstream.Address {
				t.Fatal("foreground exploration revived a disabled method")
			}
		}
	}
	seen := map[string]bool{}
	for range 5 {
		probe, ok := s.nextProbe(cfg, routes)
		if !ok {
			t.Fatal("enabled unmeasured pair was not probed")
		}
		key := schedulerKey(probe.route.ID, probe.upstream.Address)
		if probe.route.ID == "nfqws" && probe.upstream.Address == cfg.DefaultUpstream.Address || seen[key] {
			t.Fatalf("background check retried disabled/duplicate pair: %+v", probe)
		}
		seen[key] = true
		s.finishProbe(probe, AttemptEvent{Success: true, DurationMS: 20})
		now = now.Add(schedulerProbeInterval)
	}
	cfg.DisabledMethods = nil
	reenabled := s.Snapshot(cfg, routes, "").Candidates[0]
	if reenabled.Disabled || reenabled.Upstream != cfg.DefaultUpstream.Address || reenabled.Route != "nfqws" || reenabled.Successes != 1 || reenabled.LatencyMS != 1 {
		t.Fatalf("reenabling erased original best measurement: %+v", reenabled)
	}
}

func TestDisabledMethodsAllSpecialPairsStayInsideTheirPool(t *testing.T) {
	cfg := Default()
	routes := schedulerTestRoutes()[:2]
	special := cfg.Rules[0].Upstream.Address
	for _, route := range routes {
		cfg.DisabledMethods = append(cfg.DisabledMethods, DisabledMethod{Upstream: special, Route: route.ID})
	}
	s := NewScheduler()
	if ordered := s.order(cfg, routes, "api.claude.com"); len(ordered) != 0 {
		t.Fatalf("all-disabled special pool fell through to another method: %+v", ordered)
	}
	view := s.Snapshot(cfg, routes, "api.claude.com")
	if view.PoolSource != "claude.com" || len(view.Candidates) != len(routes) {
		t.Fatalf("all-disabled pool lost its own rows: %+v", view)
	}
	for _, candidate := range view.Candidates {
		if candidate.Upstream != special || !candidate.Disabled || candidate.Position != 0 {
			t.Fatalf("disabled special pool leaked a default provider: %+v", candidate)
		}
	}
	for _, probe := range schedulerProbeCandidates(cfg, routes) {
		if probe.domain != "." || probe.upstream.Address == special {
			t.Fatalf("disabled special domain was sent through another pool: %+v", probe)
		}
	}
}

func TestDisabledMethodsHotTogglePreservesServiceCacheStatisticsAndHistory(t *testing.T) {
	s, backend, client := newDNSServiceFixture(t, 8)
	backend.mu.Lock()
	backend.routes = []dnsroute.Route{{ID: "nfqws", Name: "NFQWS", Available: true}}
	backend.mu.Unlock()
	if queryDNSService(t, client, s.Status().Endpoints.DNS, 701).Rcode != mdns.RcodeSuccess {
		t.Fatal("failed to populate the answer cache")
	}
	run := activeDNSRun(s)
	runtimeConfig := cloneConfig(run.resolver.cfg)
	before := s.Status()
	history, err := s.SchedulerSnapshot("example.com")
	if err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	prepares, closes := backend.prepareCount, backend.closeCount
	backend.mu.Unlock()
	upstream := before.Config.DefaultUpstream.Address
	for range 2 { // An already disabled switch must be idempotent.
		if err := s.SetMethodEnabled(upstream, "nfqws", false); err != nil {
			t.Fatal(err)
		}
	}
	after := s.Status()
	if len(after.Config.DisabledMethods) != 1 || after.Config.DisabledMethods[0] != (DisabledMethod{Upstream: upstream, Route: "nfqws"}) {
		t.Fatalf("disabled pair was lost or duplicated: %+v", after.Config.DisabledMethods)
	}
	unrelated := cloneConfig(after.Config)
	unrelated.DisabledMethods = before.Config.DisabledMethods
	if !reflect.DeepEqual(unrelated, before.Config) || !reflect.DeepEqual(after.Cache, before.Cache) || !reflect.DeepEqual(after.Stats, before.Stats) || activeDNSRun(s) != run || !after.Running || !reflect.DeepEqual(run.resolver.cfg, runtimeConfig) {
		t.Fatal("hot method toggle restarted service or changed cache/statistics/immutable resolver configuration")
	}
	var saved Config
	if err := s.store.Load(configFile, &saved); err != nil || !reflect.DeepEqual(saved.DisabledMethods, after.Config.DisabledMethods) {
		t.Fatalf("disabled method was not persisted: %+v, %v", saved.DisabledMethods, err)
	}
	reopened := New(s.store, &resolverTestBackend{}, func(string) (string, error) { return "127.0.0.1", nil })
	defer reopened.Close()
	if !reflect.DeepEqual(reopened.Config().DisabledMethods, after.Config.DisabledMethods) {
		t.Fatal("disabled method disappeared after loading saved configuration")
	}
	disabledHistory, err := s.SchedulerSnapshot("example.com")
	if err != nil || len(disabledHistory.Candidates) != 1 || !disabledHistory.Candidates[0].Disabled || disabledHistory.Candidates[0].Successes != history.Candidates[0].Successes || disabledHistory.Candidates[0].LastResultAt != history.Candidates[0].LastResultAt {
		t.Fatalf("hot disable erased scheduler measurements: %+v, %v", disabledHistory, err)
	}
	if err := s.SetMethodEnabled(upstream, "nfqws", true); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMethodEnabled(upstream, "nfqws", true); err != nil {
		t.Fatal(err)
	}
	if len(s.Config().DisabledMethods) != 0 {
		t.Fatal("reenabling did not remove disabled pair")
	}
	reenabled, err := s.SchedulerSnapshot("example.com")
	if err != nil || !reflect.DeepEqual(reenabled, history) {
		t.Fatalf("reenabling did not restore exact scheduler history: before=%+v after=%+v, %v", history, reenabled, err)
	}
	if queryDNSService(t, client, after.Endpoints.DNS, 702).Rcode != mdns.RcodeSuccess || s.Status().Stats.CacheHits != before.Stats.CacheHits+1 {
		t.Fatal("method toggles discarded the previously cached answer")
	}
	backend.mu.Lock()
	preparesAfter, closesAfter := backend.prepareCount, backend.closeCount
	backend.mu.Unlock()
	if preparesAfter != prepares || closesAfter != closes || activeDNSRun(s) != run {
		t.Fatal("method toggle rebuilt router rules or listeners")
	}
}

func TestDisabledMethodsFailedSaveLeavesRuntimeAndPersistedPolicyUntouched(t *testing.T) {
	s, backend, client := newDNSServiceFixture(t, 8)
	backend.mu.Lock()
	backend.routes = []dnsroute.Route{{ID: "nfqws", Name: "NFQWS", Available: true}}
	backend.mu.Unlock()
	if queryDNSService(t, client, s.Status().Endpoints.DNS, 710).Rcode != mdns.RcodeSuccess {
		t.Fatal("failed to warm cache")
	}
	run := activeDNSRun(s)
	before := s.Status()
	history, err := s.SchedulerSnapshot("example.com")
	if err != nil {
		t.Fatal(err)
	}
	// A directory at the store's temporary-file path makes saving fail on all
	// platforms without changing permissions or the valid configuration file.
	blockedTemp := s.store.Path(configFile + ".tmp")
	if err := os.Mkdir(blockedTemp, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(blockedTemp)
	if err := s.SetMethodEnabled(before.Config.DefaultUpstream.Address, "nfqws", false); err == nil {
		t.Fatal("method change succeeded despite failed persistence")
	}
	after := s.Status()
	if activeDNSRun(s) != run || !reflect.DeepEqual(after.Config, before.Config) || !reflect.DeepEqual(after.Stats, before.Stats) || !reflect.DeepEqual(after.Cache, before.Cache) {
		t.Fatal("failed save changed runtime policy, listeners, statistics or cache")
	}
	nextHistory, err := s.SchedulerSnapshot("example.com")
	if err != nil || !reflect.DeepEqual(nextHistory, history) {
		t.Fatalf("failed save changed scheduler policy: %+v, %v", nextHistory, err)
	}
	var saved Config
	if err := s.store.Load(configFile, &saved); err != nil || !reflect.DeepEqual(saved, before.Config) {
		t.Fatalf("failed save replaced persisted configuration: %+v, %v", saved, err)
	}
}
