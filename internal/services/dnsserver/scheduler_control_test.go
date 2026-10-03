package dnsserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"nfqws2strategy/internal/tools/store"
)

func TestSchedulerConfigDefaultLegacyLoadAndExplicitFalsePersist(t *testing.T) {
	if !Default().SchedulerEnabled {
		t.Fatal("new DNS configurations unexpectedly disable existing scheduling")
	}
	for _, tc := range []struct {
		name    string
		missing bool
		enabled bool
	}{
		{"legacy_missing", true, true},
		{"explicit_enabled", false, true},
		{"explicit_disabled", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, err := store.New(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			cfg := Default()
			cfg.SchedulerEnabled = tc.enabled
			cfg.FastDNS = true
			encoded, _ := json.Marshal(cfg)
			var saved map[string]any
			if err := json.Unmarshal(encoded, &saved); err != nil {
				t.Fatal(err)
			}
			if tc.missing {
				delete(saved, "scheduler_enabled")
			}
			if err := st.Save(configFile, saved); err != nil {
				t.Fatal(err)
			}
			s := New(st, &resolverTestBackend{}, func(string) (string, error) { return "127.0.0.1", nil })
			defer s.Close()
			got := s.Config()
			if got.SchedulerEnabled != tc.enabled || !got.FastDNS {
				t.Fatalf("legacy/default/explicit disabled changed: scheduler=%v fastdns=%v", got.SchedulerEnabled, got.FastDNS)
			}
			if err := got.NormalizeValidate(); err != nil || got.SchedulerEnabled != tc.enabled {
				t.Fatalf("normalization lost explicit scheduler choice: %v %+v", err, got)
			}
			if err := s.SetConfig(got); err != nil {
				t.Fatal(err)
			}
			var disk map[string]any
			if err := st.Load(configFile, &disk); err != nil || disk["scheduler_enabled"] != tc.enabled {
				t.Fatalf("scheduler choice was not explicitly persisted: %v %#v", err, disk["scheduler_enabled"])
			}
		})
	}
}

func TestSchedulerDisabledIgnoresOldRankingAndKeepsConfiguredOrder(t *testing.T) {
	cfg := Default()
	cfg.SchedulerEnabled, cfg.Rules = false, nil
	cfg.DefaultPool = []Upstream{{Address: "https://8.8.8.8/dns-query"}}
	cfg.DisabledMethods = []DisabledMethod{{Route: "nfqws", Upstream: cfg.DefaultPool[0].Address}}
	routes := schedulerTestRoutes()
	routes[2].Available = false
	s := NewScheduler()
	s.record(AttemptEvent{Route: "awg:warp", Upstream: cfg.DefaultUpstream.Address, Success: true, DurationMS: 1})
	s.record(AttemptEvent{Route: "nfqws", Upstream: cfg.DefaultUpstream.Address, Error: "prior ranking would prefer WARP"})
	priorEntries := len(s.entries)
	wanted := []string{"nfqws|https://1.1.1.1/dns-query", "awg:warp|https://1.1.1.1/dns-query", "awg:warp|https://8.8.8.8/dns-query"}
	for i := 0; i < 24; i++ {
		var keys []string
		for _, candidate := range s.order(cfg, routes, "example.com") {
			keys = append(keys, schedulerKey(candidate.route.ID, candidate.upstream.Address))
			if candidate.view.Score != 0 || candidate.view.Exploration || candidate.view.Attempts != 0 {
				t.Fatal("disabled scheduler still ranked or counted a pair")
			}
		}
		if !reflect.DeepEqual(keys, wanted) {
			t.Fatalf("disabled scheduler reordered configured race: %v", keys)
		}
	}
	view := s.Snapshot(cfg, routes, "example.com")
	if view.Enabled || view.Effective || view.Reason != "disabled" || view.EffectiveCandidateCount != 3 || view.TrackedPairs != 0 || view.ActiveProbes != 0 || s.races != 0 || len(s.entries) != priorEntries {
		t.Fatalf("disabled scheduler exposed/updated adaptive history: %+v", view)
	}
	for _, candidate := range view.Candidates {
		if candidate.Successes != 0 || candidate.Failures != 0 || candidate.LastResultAt != "" || candidate.ProbeAttempts != 0 {
			t.Fatal("disabled snapshot retained misleading ranking statistics")
		}
	}
	if _, ok := s.nextProbe(cfg, routes); ok || len(schedulerProbeCandidates(cfg, routes)) != 0 || s.probeKey != "" {
		t.Fatal("disabled scheduler allocated a background probe")
	}
}

func TestSchedulerSingleUsableCandidateSkipsBackgroundAndResumesWhenCompetitorReturns(t *testing.T) {
	cfg := Default()
	cfg.Rules, cfg.DefaultPool = nil, nil
	cfg.RouteMode = RouteModeVPNOnly
	routes := schedulerTestRoutes()
	routes[2].Available = false
	s := NewScheduler()
	view := s.Snapshot(cfg, routes, "")
	if !view.Enabled || view.Effective || view.Reason != "single_candidate" || view.EffectiveCandidateCount != 1 {
		t.Fatalf("sole allowed live VPN is not explained: %+v", view)
	}
	for i := 0; i < 12; i++ {
		ordered := s.order(cfg, routes, "ordinary.example")
		if len(ordered) != 1 || ordered[0].view.Score != 0 || ordered[0].view.Exploration {
			t.Fatal("single-candidate foreground order still applied adaptive ranking")
		}
		if _, ok := s.nextProbe(cfg, routes); ok {
			t.Fatal("single-candidate pool allocated pointless background work")
		}
	}
	if len(s.entries) != 0 || s.races != 0 || s.probeToken != 0 || s.probeKey != "" {
		t.Fatal("single-candidate suppression still created measurements")
	}
	// Config remains enabled. A recovering route automatically makes the
	// existing pool competitive; no second user toggle is required.
	routes[2].Available = true
	if view = s.Snapshot(cfg, routes, ""); !view.Effective || view.Reason != "" || view.EffectiveCandidateCount != 2 {
		t.Fatalf("recovered competitor did not restore effective scheduling: %+v", view)
	}
	probe, ok := s.nextProbe(cfg, routes)
	if !ok {
		t.Fatal("background probes did not resume after a competitor recovered")
	}
	s.finishProbe(probe, AttemptEvent{Canceled: true})
	cfg.DisabledMethods = []DisabledMethod{{Route: routes[2].ID, Upstream: cfg.DefaultUpstream.Address}}
	if _, ok := s.nextProbe(cfg, routes); ok || len(schedulerProbeCandidates(cfg, routes)) != 0 {
		t.Fatal("disabled competitor incorrectly made a sole path competitive")
	}
	cfg.DisabledMethods = append(cfg.DisabledMethods, DisabledMethod{Route: routes[1].ID, Upstream: cfg.DefaultUpstream.Address})
	if view = s.Snapshot(cfg, routes, ""); view.Effective || view.Reason != "no_candidates" || view.EffectiveCandidateCount != 0 {
		t.Fatalf("no runnable routes have an incorrect effective reason: %+v", view)
	}
}

func TestResolverSchedulerEnabledSoleCandidateDoesNotCollectHistory(t *testing.T) {
	r, _, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg { return resolverAnswer(q, 60) })
	r.cfg.SchedulerEnabled, r.cfg.CacheSize, r.cfg.AWGFallback = true, 0, "off"
	attempts := make(chan AttemptEvent, 2)
	r.SetAttemptObserver(func(event AttemptEvent) { attempts <- event })
	for i := 0; i < 2; i++ {
		if _, out, err := r.Resolve(context.Background(), resolverWire(t, "sole.example", uint16(i+1), mdns.TypeA)); err != nil || out.Cached {
			t.Fatalf("single enabled path failed to resolve normally: %+v %v", out, err)
		}
	}
	for i := 0; i < 2; i++ {
		select {
		case event := <-attempts:
			if !event.Success || event.Route != "nfqws" {
				t.Fatalf("skipping sole-candidate measurements lost actual attempt evidence: %+v", event)
			}
		case <-time.After(time.Second):
			t.Fatal("ordinary single-candidate request lost diagnostic evidence")
		}
	}
	if len(r.scheduler.entries) != 0 || r.scheduler.races != 0 {
		t.Fatal("enabled single-candidate resolver still counted/ranked pointless adaptive history")
	}
}

func TestSchedulerIndependentSingleCandidateDomainPoolsAreNotBackgroundCompetition(t *testing.T) {
	cfg := Default()
	cfg.AWGFallback, cfg.Rules = "off", nil
	cfg.Rules = []Rule{{ID: "special", Enabled: true, Domain: "special.example", Upstream: Upstream{Address: "https://8.8.8.8/dns-query"}}}
	routes := schedulerTestRoutes()[:1]
	if got := schedulerProbeCandidates(cfg, routes); len(got) != 0 {
		t.Fatalf("unrelated single-choice pools were treated as competing methods: %+v", got)
	}
	// Only this rule gets a competitor. Its representative must remain within
	// the configured group, even when the first provider is shared elsewhere.
	cfg.Rules[0].Pool = []Upstream{cfg.DefaultUpstream}
	probes := schedulerProbeCandidates(cfg, routes)
	if len(probes) != 2 {
		t.Fatalf("competitive rule did not receive its two probes: %+v", probes)
	}
	for _, probe := range probes {
		if probe.domain != "special.example" || probe.qtype != mdns.TypeA {
			t.Fatalf("competitive rule leaked into a default root probe: %+v", probe)
		}
	}
}

func TestResolverSchedulerDisabledKeepsParallelRaceWithoutMeasurements(t *testing.T) {
	entered, release := make(chan struct{}, 4), make(chan struct{})
	r, backend := newPoolResolverFixture(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		query := maintenanceQuestion(t, req)
		if query == nil {
			return
		}
		entered <- struct{}{}
		select {
		case <-release:
			maintenanceReply(t, w, query)
		case <-req.Context().Done():
		}
	}))
	backend.routes = backend.routes[:2]
	r.cfg.SchedulerEnabled, r.cfg.CacheSize, r.cfg.FastDNS = false, 0, false
	r.fastDNS = nil
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	done := startResolverFlightTest(r, context.Background(), resolverWire(t, "ordinary.example", 17, mdns.TypeA))
	for i := 0; i < 4; i++ {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("disabling scheduler serialized or skipped a foreground pool/route pair")
		}
	}
	unblock()
	if reply := resolverFlightTestReceive(t, done); reply.err != nil {
		t.Fatal(reply.err)
	}
	if len(r.scheduler.entries) != 0 || r.scheduler.races != 0 || len(backend.dialCalls()) != 4 {
		t.Fatal("disabled resolver created adaptive history or changed the parallel race")
	}
	r.StartMaintenance()
	for i := 0; i < 12; i++ {
		r.runSchedulerProbe()
	}
	if len(backend.dialCalls()) != 4 || r.scheduler.probeToken != 0 {
		t.Fatal("disabled maintenance sent extra DNS traffic")
	}
}

func TestResolverSchedulerDisabledStillStartsIndependentFastDNS(t *testing.T) {
	cfg := Default()
	cfg.SchedulerEnabled, cfg.FastDNS = false, true
	r := NewResolver(cfg, &resolverTestBackend{routes: schedulerTestRoutes()[:1]})
	defer r.Close()
	warmed := make(chan string, 1)
	r.fastDNS = NewFastDNSCache(r.lifetime, func(_ context.Context, route, host string) ([]string, error) {
		warmed <- fmt.Sprintf("%s|%s", route, host)
		return []string{"192.0.2.1"}, nil
	}, func() []FastDNSTarget { return []FastDNSTarget{{Route: "nfqws", Host: "configured-provider.example"}} })
	r.StartMaintenance()
	select {
	case target := <-warmed:
		if target != "nfqws|configured-provider.example" {
			t.Fatalf("FastDNS warmed an unrelated domain: %s", target)
		}
	case <-time.After(time.Second):
		t.Fatal("scheduler switch incorrectly disabled FastDNS maintenance")
	}
	if r.scheduler.probeToken != 0 || len(r.scheduler.entries) != 0 {
		t.Fatal("FastDNS independence accidentally restored scheduler work")
	}
}
