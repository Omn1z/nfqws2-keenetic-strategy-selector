package dnsserver

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"nfqws2strategy/internal/services/dnsroute"
)

func schedulerTestRoutes() []dnsroute.Route {
	return []dnsroute.Route{{ID: "nfqws", Name: "NFQWS", Available: true}, {ID: "awg:warp", Name: "WARP", Available: true}, {ID: "awg:other", Name: "Other AWG", Available: true}}
}

func TestSchedulerRanksRealOutcomesAndRecovers(t *testing.T) {
	s := NewScheduler()
	cfg := Default()
	routes := schedulerTestRoutes()
	for _, event := range []AttemptEvent{
		{Route: "nfqws", DurationMS: 500, Success: true},
		{Route: "awg:warp", DurationMS: 40, Success: true},
		{Route: "awg:other", DurationMS: 10, Error: "connection refused"},
	} {
		event.Upstream = cfg.DefaultUpstream.Address
		s.started(event.Route, event.Upstream)
		s.record(event)
	}
	view := s.Snapshot(cfg, routes, "example.com")
	if view.Candidates[0].Route != "awg:warp" || view.Candidates[2].Route != "awg:other" {
		t.Fatalf("unexpected rank: %+v", view.Candidates)
	}
	if view.Candidates[0].Score <= view.Candidates[1].Score || view.Candidates[2].FailurePenalty != 20 {
		t.Fatalf("score components: %+v", view.Candidates)
	}
	// A cancellation contributes an attempt, but no latency/error evidence.
	s.started("awg:warp", cfg.DefaultUpstream.Address)
	s.record(AttemptEvent{Route: "awg:warp", Upstream: cfg.DefaultUpstream.Address, Canceled: true, DurationMS: 9999, Error: "context canceled"})
	neutral := s.Snapshot(cfg, routes, "example.com").Candidates[0]
	if neutral.Score != view.Candidates[0].Score || neutral.Failures != 0 || neutral.Attempts != 2 || neutral.LatencyMS != 40 {
		t.Fatalf("loser cancellation was penalized: %+v", neutral)
	}
	for i := 0; i < 24; i++ {
		s.started("awg:other", cfg.DefaultUpstream.Address)
		s.record(AttemptEvent{Route: "awg:other", Upstream: cfg.DefaultUpstream.Address, Success: true, DurationMS: 15})
	}
	recovered := s.Snapshot(cfg, routes, "example.com").Candidates[0]
	if recovered.Route != "awg:other" || recovered.ConsecutiveFailures != 0 || recovered.LastError != "" || recovered.FailurePenalty != 0 {
		t.Fatalf("recovered path did not return to front: %+v", recovered)
	}
	if _, err := json.Marshal(s.Snapshot(cfg, routes, "example.com")); err != nil {
		t.Fatalf("invalid numeric JSON: %v", err)
	}
}

func TestSchedulerRulePoolIsolationAndUnavailableRoutes(t *testing.T) {
	cfg := Default()
	cfg.DefaultPool = []Upstream{{Address: "https://8.8.8.8/dns-query"}}
	cfg.Rules[2].Pool = []Upstream{{Address: "https://9.9.9.9/dns-query"}}
	routes := schedulerTestRoutes()
	routes[0].Available = false
	routes[0].Error = "queue is not bound"
	cfg.AWGFallback = "warp"
	s := NewScheduler()
	view := s.Snapshot(cfg, routes, "API.CLAUDE.AI.")
	if view.PoolSource != "claude.ai" || len(view.Candidates) != 4 {
		t.Fatalf("wrong rule pool: %+v", view)
	}
	for _, candidate := range view.Candidates {
		if strings.Contains(candidate.Upstream, "1.1.1.1") || strings.Contains(candidate.Upstream, "8.8.8.8") || candidate.Route == "awg:other" {
			t.Fatalf("leaked outside domain/route selection: %+v", candidate)
		}
		if !candidate.Available && candidate.LastError != "queue is not bound" {
			t.Fatalf("missing route reason: %+v", candidate)
		}
	}
	ordered := s.order(cfg, routes, "api.claude.ai")
	if len(ordered) != 2 || ordered[0].route.ID != "awg:warp" {
		t.Fatalf("unavailable route scheduled: %+v", ordered)
	}
}

func TestSchedulerExploresWaitingPairsAndBoundsMemory(t *testing.T) {
	s := NewScheduler()
	now := time.Unix(1700000000, 0)
	s.now = func() time.Time { return now }
	cfg := Default()
	routes := make([]dnsroute.Route, 40)
	for i := range routes {
		routes[i] = dnsroute.Route{ID: fmt.Sprintf("awg:%02d", i), Available: true}
		if i < 39 {
			s.started(routes[i].ID, cfg.DefaultUpstream.Address)
			s.record(AttemptEvent{Route: routes[i].ID, Upstream: cfg.DefaultUpstream.Address, Success: true, DurationMS: 20})
		}
	}
	for i := 1; i <= 8; i++ {
		view := s.Snapshot(cfg, routes, "example.com")
		ordered := s.order(cfg, routes, "example.com")
		if view.Candidates[0].Route != ordered[0].route.ID {
			t.Fatal("displayed queue differs from actual scheduler")
		}
		if i < 8 && ordered[0].route.ID == routes[39].ID {
			t.Fatal("unexpected exploration")
		}
		if i == 8 && (ordered[0].route.ID != routes[39].ID || !ordered[0].view.Exploration) {
			t.Fatalf("untried tail was starved: %+v", ordered[0])
		}
	}
	for i := 0; i < maxSchedulerPairs+20; i++ {
		now = now.Add(time.Second)
		s.started("nfqws", fmt.Sprintf("https://dns%d.example/dns-query", i))
	}
	if len(s.entries) != maxSchedulerPairs {
		t.Fatalf("unbounded history: %d", len(s.entries))
	}
	if _, ok := s.entries[schedulerKey("nfqws", "https://dns0.example/dns-query")]; ok {
		t.Fatal("least recently used entry was not evicted")
	}
}

func TestSchedulerSmallPoolAlsoExploresUnderSharedContention(t *testing.T) {
	s := NewScheduler()
	cfg := Default()
	routes := schedulerTestRoutes()[:2]
	s.started(routes[0].ID, cfg.DefaultUpstream.Address)
	s.record(AttemptEvent{Route: routes[0].ID, Upstream: cfg.DefaultUpstream.Address, Success: true, DurationMS: 5})
	for race := 1; race <= 8; race++ {
		ordered := s.order(cfg, routes, "example.com")
		if race < 8 && ordered[0].route.ID != routes[0].ID {
			t.Fatal("preferred route lost ordinary priority")
		}
		if race == 8 && (ordered[0].route.ID != routes[1].ID || !ordered[0].view.Exploration) {
			t.Fatal("small pool tail could starve while other requests occupy shared slots")
		}
	}
}

func TestPoolConfigMigrationValidationAndDeepCopy(t *testing.T) {
	legacy := Default()
	if err := json.Unmarshal([]byte(`{"default_upstream":{"address":"https://DNS.Example:443"},"rules":[{"id":"special","enabled":true,"domain":"claude.ai","include_subdomains":true,"upstream":{"address":"https://xbox-dns.ru/dns-query"}}]}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if err := legacy.NormalizeValidate(); err != nil {
		t.Fatal(err)
	}
	if legacy.DefaultUpstream.Address != "https://dns.example/dns-query" || len(legacy.DefaultPool) != 0 || !legacy.LoggingEnabled {
		t.Fatalf("legacy configuration changed: %+v", legacy)
	}
	legacy.DefaultPool = []Upstream{{Address: "https://DNS.EXAMPLE:443/dns-query"}, {Address: "https://other.example", BootstrapIPs: []string{"192.0.2.1"}}}
	legacy.Rules[0].Pool = []Upstream{{Address: "https://rule.example", BootstrapIPs: []string{"192.0.2.2"}}}
	if err := legacy.NormalizeValidate(); err != nil {
		t.Fatal(err)
	}
	if len(legacy.DefaultPool) != 1 {
		t.Fatalf("equivalent endpoint not deduplicated: %+v", legacy.DefaultPool)
	}
	copy := cloneConfig(legacy)
	copy.DefaultPool[0].BootstrapIPs[0] = "192.0.2.3"
	copy.Rules[0].Pool[0].BootstrapIPs[0] = "192.0.2.4"
	if legacy.DefaultPool[0].BootstrapIPs[0] != "192.0.2.1" || legacy.Rules[0].Pool[0].BootstrapIPs[0] != "192.0.2.2" {
		t.Fatal("pool clone aliases caller state")
	}
	invalid := cloneConfig(legacy)
	invalid.DefaultPool = []Upstream{{Address: "http://bad.example/dns-query"}}
	if invalid.NormalizeValidate() == nil {
		t.Fatal("plaintext upstream accepted inside pool")
	}
	invalid = cloneConfig(legacy)
	invalid.DefaultPool = make([]Upstream, maxPoolUpstreams)
	if invalid.NormalizeValidate() == nil {
		t.Fatal("unbounded provider pool accepted")
	}
	invalid = cloneConfig(legacy)
	invalid.Rules[0].Pool = []Upstream{{Address: "https://192.168.3.1:5355/dns-query"}}
	if validateNoSelfUpstream(invalid, "192.168.3.1") == nil {
		t.Fatal("self upstream inside domain pool accepted")
	}
}
