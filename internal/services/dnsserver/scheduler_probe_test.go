package dnsserver

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"nfqws2strategy/internal/services/dnsroute"
)

func TestSchedulerProbeMeasuresContinuallyCanceledTail(t *testing.T) {
	s := NewScheduler()
	now := time.Unix(1700000000, 0)
	s.now = func() time.Time { return now }
	cfg := Default()
	cfg.Rules = nil
	routes := schedulerTestRoutes()
	for _, route := range routes[:2] {
		s.started(route.ID, cfg.DefaultUpstream.Address)
		s.record(AttemptEvent{Route: route.ID, Upstream: cfg.DefaultUpstream.Address, Success: true, DurationMS: 50})
	}
	for range 20 {
		now = now.Add(time.Second)
		s.started(routes[2].ID, cfg.DefaultUpstream.Address)
		s.record(AttemptEvent{Route: routes[2].ID, Upstream: cfg.DefaultUpstream.Address, Canceled: true, DurationMS: 9999})
	}
	before := s.Snapshot(cfg, routes, "")
	if before.Candidates[2].LastResultAt != "" || before.Candidates[2].LastAttemptAt == "" {
		t.Fatalf("cancellation became a measurement: %+v", before.Candidates[2])
	}
	probe, ok := s.nextProbe(cfg, routes)
	if !ok || probe.route.ID != routes[2].ID {
		t.Fatalf("frequently canceled route did not get independent measurement: %+v", probe)
	}
	during := s.Snapshot(cfg, routes, "")
	if during.ActiveProbes != 1 || !during.Candidates[2].Probing || during.Candidates[2].ProbeAttempts != 1 {
		t.Fatalf("missing active probe state: %+v", during)
	}
	// A background result has its own lifetime; the caller reports a completed
	// result even when the query race would already have returned another path.
	s.finishProbe(probe, AttemptEvent{Success: true, DurationMS: 5})
	after := s.Snapshot(cfg, routes, "")
	winner := after.Candidates[0]
	if winner.Route != routes[2].ID || winner.Reliability != 1 || winner.LatencyMS != 5 || winner.ProbeSuccesses != 1 || winner.Probing || after.ActiveProbes != 0 || winner.LastResultAt == "" {
		t.Fatalf("first genuine fast result did not restore ranking: %+v", after)
	}
}

func TestSchedulerProbeUsesOnlyMatchingActivePoolsAndRoutes(t *testing.T) {
	cfg := Default()
	cfg.DefaultUpstream = Upstream{Address: "https://default.example/dns-query"}
	cfg.DefaultPool = []Upstream{{Address: "https://default-extra.example/dns-query"}}
	cfg.Rules = []Rule{
		{Enabled: true, Domain: "claude.ai", IncludeSubdomains: true, Upstream: Upstream{Address: "https://special.example/dns-query"}, Pool: []Upstream{{Address: "https://special-extra.example/dns-query"}}},
		{Enabled: true, Domain: "api.claude.ai", Upstream: Upstream{Address: "https://nested.example/dns-query"}},
		{Enabled: true, Domain: "grok.com", Upstream: Upstream{Address: "https://special.example/dns-query"}},
		{Enabled: false, Domain: "disabled.example", Upstream: Upstream{Address: "https://disabled.example/dns-query"}},
	}
	cfg.AWGFallback = "warp"
	routes := schedulerTestRoutes()
	routes[0].Available = false
	candidates := schedulerProbeCandidates(cfg, append(routes, routes[1]))
	if len(candidates) != 5 {
		t.Fatalf("wrong active unique pair count: %+v", candidates)
	}
	seen := map[string]bool{}
	for _, probe := range candidates {
		if probe.route.ID != "awg:warp" || !probe.route.Available || seen[probe.upstream.Address] {
			t.Fatalf("unavailable, excluded or duplicated route: %+v", probe)
		}
		seen[probe.upstream.Address] = true
		pool, source := cfg.upstreamsFor(probe.domain)
		found := false
		for _, upstream := range pool {
			found = found || upstream.Address == probe.upstream.Address
		}
		if !found {
			t.Fatalf("probe leaked domain outside assigned provider pool: %+v", probe)
		}
		if source == "default" && (probe.domain != "." || probe.qtype != mdns.TypeNS) || source != "default" && (probe.domain != source || probe.qtype != mdns.TypeA) {
			t.Fatalf("wrong representative question: %+v, source %q", probe, source)
		}
	}
	if seen[cfg.Rules[3].Upstream.Address] {
		t.Fatal("disabled rule was probed")
	}
	cfg.AWGFallback = "off"
	if got := schedulerProbeCandidates(cfg, routes); len(got) != 0 {
		t.Fatalf("unavailable NFQWS and disabled AWG still scheduled: %+v", got)
	}
}

func TestSchedulerProbeCadencePrioritizesMissingThenOldestResult(t *testing.T) {
	s := NewScheduler()
	now := time.Unix(1700000000, 0)
	s.now = func() time.Time { return now }
	cfg := Default()
	cfg.Rules = nil
	routes := schedulerTestRoutes()
	s.record(AttemptEvent{Route: routes[0].ID, Upstream: cfg.DefaultUpstream.Address, Success: true, DurationMS: 30})
	now = now.Add(50 * time.Second)
	s.record(AttemptEvent{Route: routes[1].ID, Upstream: cfg.DefaultUpstream.Address, Success: true, DurationMS: 30})
	now = now.Add(70 * time.Second)
	for index, wanted := range []string{routes[2].ID, routes[0].ID, routes[1].ID} {
		probe, ok := s.nextProbe(cfg, routes)
		if !ok || probe.route.ID != wanted {
			t.Fatalf("probe %d should measure %s: %+v, %v", index, wanted, probe, ok)
		}
		if _, ok := s.nextProbe(cfg, routes); ok {
			t.Fatal("parallel probe exceeded one-active limit")
		}
		s.finishProbe(probe, AttemptEvent{Success: true, DurationMS: 20})
		if _, ok := s.nextProbe(cfg, routes); ok {
			t.Fatal("probe started before cadence interval")
		}
		now = now.Add(schedulerProbeInterval)
	}
	if _, ok := s.nextProbe(cfg, routes); ok {
		t.Fatal("freshly measured pair was unnecessarily probed")
	}
	now = now.Add(schedulerProbeRecheck)
	probe, ok := s.nextProbe(cfg, routes)
	if !ok || probe.route.ID != routes[2].ID {
		t.Fatalf("oldest result was not revisited: %+v, %v", probe, ok)
	}
}

func TestSchedulerProbePollingAndCancellationAreNeutral(t *testing.T) {
	s := NewScheduler()
	now := time.Unix(1700000000, 0)
	s.now = func() time.Time { return now }
	cfg := Default()
	cfg.Rules = nil
	routes := schedulerTestRoutes()
	before := s.Snapshot(cfg, routes, "")
	for range 30 {
		if got := s.Snapshot(cfg, routes, ""); !reflect.DeepEqual(got, before) {
			t.Fatal("polling mutated scheduler state")
		}
	}
	if s.races != 0 || s.probeCursor != 0 || len(s.entries) != 0 {
		t.Fatal("polling consumed exploration or history")
	}
	probe, ok := s.nextProbe(cfg, routes)
	if !ok {
		t.Fatal("missing initial probe")
	}
	s.finishProbe(probe, AttemptEvent{Canceled: true, Error: "shutdown"})
	after := s.Snapshot(cfg, routes, "")
	first := after.Candidates[0]
	if first.LastResultAt != "" || first.Score != 25 || first.Failures != 0 || first.ProbeFailures != 0 || first.Probing || after.ActiveProbes != 0 {
		t.Fatalf("shutdown cancellation became negative evidence: %+v", after)
	}
	now = now.Add(schedulerProbeInterval)
	other, ok := s.nextProbe(cfg, routes)
	if !ok || other.route.ID == probe.route.ID {
		t.Fatalf("canceled probe starved other never-measured paths: %+v", other)
	}
	s.finishProbe(probe, AttemptEvent{Success: true, DurationMS: 1})
	if s.Snapshot(cfg, routes, "").ActiveProbes != 1 {
		t.Fatal("obsolete finish released a newer probe")
	}
	s.finishProbe(other, AttemptEvent{Error: "timeout"})
	s.finishProbe(other, AttemptEvent{Success: true, DurationMS: 1})
	entry := s.entries[schedulerKey(other.route.ID, other.upstream.Address)]
	if entry.probeFailures != 1 || entry.probeSuccesses != 0 || entry.failures != 1 {
		t.Fatalf("duplicate finish changed evidence: %+v", entry)
	}
}

func TestSchedulerProbeRefreshDropsStaleFailureAndLatencyHistory(t *testing.T) {
	s := NewScheduler()
	now := time.Unix(1700000000, 0)
	s.now = func() time.Time { return now }
	cfg := Default()
	cfg.Rules = nil
	routes := schedulerTestRoutes()[:1]
	s.record(AttemptEvent{Route: routes[0].ID, Upstream: cfg.DefaultUpstream.Address, Success: true, DurationMS: 2500})
	for range 5 {
		s.record(AttemptEvent{Route: routes[0].ID, Upstream: cfg.DefaultUpstream.Address, Error: "old failure"})
	}
	now = now.Add(schedulerStaleAfter)
	probe, ok := s.nextProbe(cfg, routes)
	if !ok {
		t.Fatal("stale failed path was not scheduled")
	}
	s.finishProbe(probe, AttemptEvent{Success: true, DurationMS: 10})
	fresh := s.Snapshot(cfg, routes, "").Candidates[0]
	if fresh.Reliability != 1 || fresh.LatencyMS != 10 || fresh.ConsecutiveFailures != 0 || fresh.FailurePenalty != 0 || fresh.LastError != "" || fresh.Failures != 5 {
		t.Fatalf("stale scoring prevented recovery or erased historical counters: %+v", fresh)
	}
}

func TestSchedulerProbeBoundedHistoryRetainsActiveLease(t *testing.T) {
	s := NewScheduler()
	now := time.Unix(1700000000, 0)
	s.now = func() time.Time { return now }
	cfg := Default()
	cfg.Rules = nil
	probe, ok := s.nextProbe(cfg, schedulerTestRoutes()[:1])
	if !ok {
		t.Fatal("missing probe")
	}
	for i := range maxSchedulerPairs + 20 {
		now = now.Add(time.Second)
		s.started("nfqws", fmt.Sprintf("https://history%d.example/dns-query", i))
	}
	key := schedulerKey(probe.route.ID, probe.upstream.Address)
	if len(s.entries) != maxSchedulerPairs || s.entries[key] == nil || !s.entries[key].probing {
		t.Fatal("bounded history evicted its active lease")
	}
	s.finishProbe(probe, AttemptEvent{Success: true, DurationMS: 10})
	if s.entries[key].probeSuccesses != 1 || s.entries[key].probing {
		t.Fatal("active probe did not safely finish after eviction pressure")
	}
}

func TestSchedulerProbeRotatesBeyondHistoryCapacity(t *testing.T) {
	s := NewScheduler()
	now := time.Unix(1700000000, 0)
	s.now = func() time.Time { return now }
	cfg := Default()
	cfg.Rules = nil
	routes := make([]dnsroute.Route, maxSchedulerPairs+5)
	for i := range routes {
		routes[i] = dnsroute.Route{ID: fmt.Sprintf("awg:%04d", i), Available: true}
	}
	seen := make(map[string]bool, len(routes))
	for range routes {
		probe, ok := s.nextProbe(cfg, routes)
		if !ok || seen[probe.route.ID] {
			t.Fatalf("history eviction starved an unmeasured tail: %+v, %v", probe, ok)
		}
		seen[probe.route.ID] = true
		s.finishProbe(probe, AttemptEvent{Success: true, DurationMS: 20})
		now = now.Add(schedulerProbeInterval)
	}
	if len(s.entries) != maxSchedulerPairs || len(seen) != len(routes) {
		t.Fatalf("unbounded or incomplete exploration: history=%d visited=%d", len(s.entries), len(seen))
	}
}
