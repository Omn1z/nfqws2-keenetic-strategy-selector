package awgroute

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	"nfqws2strategy/internal/services/awg"
)

func TestRoutingDiscoveryWaitsForSuccessfulInstall(t *testing.T) {
	svc := new(Service)
	entered, resume := make(chan struct{}), make(chan struct{})
	observed := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- svc.confirmRoutingDNSLearning(context.Background(), 0, func() error {
			close(entered)
			<-resume
			return nil
		}, func() { observed <- struct{}{} })
	}()
	<-entered
	select {
	case <-observed:
		t.Fatal("history published before address installation finished")
	default:
	}
	close(resume)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case <-observed:
	default:
		t.Fatal("successful address installation was not observed")
	}
}

func TestRoutingDiscoveryRejectsFailureCancellationAndObsoletePolicy(t *testing.T) {
	failure := errors.New("kernel rejected destination")
	for _, kind := range []string{"install failure", "canceled", "generation changed", "kernel epoch changed"} {
		t.Run(kind, func(t *testing.T) {
			svc := new(Service)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			observed := false
			err := svc.confirmRoutingDNSLearning(ctx, 0, func() error {
				switch kind {
				case "install failure":
					return failure
				case "canceled":
					cancel()
				case "generation changed", "kernel epoch changed":
					finish := svc.routingDNSGate.begin(kind == "generation changed")
					finish(nil)
				}
				return nil
			}, func() { observed = true })
			if err == nil || observed {
				t.Fatalf("unconfirmed address observed=%v err=%v", observed, err)
			}
			if kind == "install failure" && !errors.Is(err, failure) {
				t.Fatalf("installation failure hidden: %v", err)
			}
		})
	}
	svc := new(Service)
	finish := svc.routingDNSGate.begin(true)
	finish(nil)
	if err := svc.confirmRoutingDNSLearning(context.Background(), 0, func() error {
		t.Fatal("obsolete learner attempted an installation")
		return nil
	}, func() { t.Fatal("obsolete learner was observed") }); err == nil {
		t.Fatal("obsolete generation accepted")
	}
}

func rememberRoutingDiscoveryFixture(svc *Service, z awg.Zone, names ...string) {
	for _, name := range names {
		svc.discovered.Record(AWGRoutingLearnedRuleKey(z), name, "192.168.3.10", []string{"192.0.2.17"}, "dns", true, 0, 0, time.Now())
	}
}

func TestRoutingDiscoveryWarmupNamesStayWithinCurrentExpandedScope(t *testing.T) {
	on, off := true, false
	for _, tc := range []struct {
		name   string
		policy *bool
		want   []string
	}{
		{"subdomains", &on, []string{"api.example.com", "video.example.com"}},
		{"exact", &off, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := &Service{expandCache: map[string]expandCacheEntry{
				"list:sites": {rev: 0, domains: []string{"example.com"}},
			}}
			z := awg.Zone{Enabled: true, Domains: []string{"list:sites"}, IncludeSubdomains: tc.policy}
			rememberRoutingDiscoveryFixture(svc, z, "example.com", "api.example.com", "video.example.com", "other.example", "example.com.evil.example")
			expanded, _ := svc.expandZoneEntries(z)
			got := svc.routingDiscoverySeedNames(z, expanded)
			sort.Strings(got)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("seed names=%v want=%v", got, tc.want)
			}
			if !reflect.DeepEqual(z.Domains, []string{"list:sites"}) || !reflect.DeepEqual(svc.expandCache["list:sites"].domains, []string{"example.com"}) {
				t.Fatal("observed names modified the user's list or rule")
			}
		})
	}
	for _, z := range []awg.Zone{{Domains: []string{"*"}}, {IPs: []string{"0.0.0.0/0"}, Domains: []string{"example.com"}}, {IPs: []string{"192.0.2.1"}}} {
		svc := new(Service)
		rememberRoutingDiscoveryFixture(svc, z, "api.example.com")
		expanded, _ := svc.expandZoneEntries(z)
		if got := svc.routingDiscoverySeedNames(z, expanded); len(got) != 0 {
			t.Fatalf("catch-all or IP-only rule seeded names: %v", got)
		}
	}
}

func TestRoutingDiscoveryWarmupUsesCallerLookupAndCacheOnlyMaintenance(t *testing.T) {
	svc := new(Service)
	on := true
	z := awg.Zone{Enabled: true, Domains: []string{"example.com"}, IncludeSubdomains: &on}
	rememberRoutingDiscoveryFixture(svc, z, "api.example.com", "unrelated.example")
	queries := []string{}
	entries, catchAll, staticOK := svc.awgMultiRuleEntriesWithLookup(z, svc.policyDNSLookup(true, func(name string) []string {
		queries = append(queries, name)
		if name == "api.example.com" {
			return []string{"192.0.2.18"}
		}
		return []string{"192.0.2.17"}
	}))
	if catchAll || !staticOK || !reflect.DeepEqual(queries, []string{"example.com", "api.example.com"}) || !reflect.DeepEqual(entries, []string{"192.0.2.17/32", "192.0.2.18/32"}) {
		t.Fatalf("wrong scoped warmup: queries=%v entries=%v catchAll=%v static=%v", queries, entries, catchAll, staticOK)
	}
	cached, _, _ := svc.awgMultiRuleEntriesWithLookup(z, svc.policyDNSLookup(false, func(string) []string {
		t.Fatal("cached maintenance started a new DNS query")
		return nil
	}))
	if !reflect.DeepEqual(cached, entries) {
		t.Fatalf("cached warmup=%v want=%v", cached, entries)
	}
}

func TestRoutingDiscoveryWarmupSeedsEveryCurrentMatchingPriority(t *testing.T) {
	svc := new(Service)
	old := awg.Zone{Name: "Previously visited", TunnelID: "old", Enabled: true, Route: "tunnel", Domains: []string{"*.example.com"}}
	rememberRoutingDiscoveryFixture(svc, old, "api.example.com", "unrelated.other")
	// These rules have no same-key history. A cached client still needs its
	// known address in the new earlier set for firewall priority to work.
	earlier := awg.Zone{Name: "New earlier wildcard", TunnelID: "first", Enabled: true, Route: "tunnel", Domains: []string{"*.example.com"}}
	later := awg.Zone{Name: "Later specific rule", TunnelID: "second", Enabled: true, Route: "tunnel", Domains: []string{"api.example.com"}}
	candidates := svc.routingDiscoveryWarmupCandidates()
	for _, z := range []awg.Zone{earlier, later} {
		queries := []string{}
		entries, _, ok := svc.awgMultiRuleEntriesWithLookupAndSeeds(z, func(name string) []string {
			queries = append(queries, name)
			return []string{"192.0.2.19"}
		}, candidates)
		if !ok || !reflect.DeepEqual(queries, []string{"api.example.com"}) || !reflect.DeepEqual(entries, []string{"192.0.2.19/32"}) {
			t.Fatalf("current matching rule %q was not prepared: queries=%v entries=%v", z.Name, queries, entries)
		}
		if names := svc.discovered.Names(AWGRoutingLearnedRuleKey(z)); len(names) != 0 {
			t.Fatalf("candidate warmup manufactured rule observations: %v", names)
		}
	}
	outside := awg.Zone{Domains: []string{"*.other.example"}}
	if names := svc.routingDiscoverySeedNamesFrom(outside, outside.Domains, candidates); len(names) != 0 {
		t.Fatalf("cross-rule history expanded the current scope: %v", names)
	}
}

func TestRoutingDiscoveryWarmupFreezesOneCommonBoundedWindow(t *testing.T) {
	svc := new(Service)
	old := awg.Zone{Enabled: true, Domains: []string{"*.example.com"}}
	at := time.Now()
	for i := 0; i < routingLearnedNamesLimit+1; i++ {
		svc.discovered.Record(AWGRoutingLearnedRuleKey(old), fmt.Sprintf("host%03d.example.com", i), "", []string{"192.0.2.19"}, "dns", true, 0, 0, at.Add(time.Duration(i)*time.Second))
	}
	candidates := svc.routingDiscoveryWarmupCandidates()
	if len(candidates) != routingLearnedNamesLimit {
		t.Fatalf("candidate bound=%d", len(candidates))
	}
	// A query racing rule preparation cannot change this build's candidate
	// window. Both old and new scopes receive exactly the frozen candidates.
	svc.discovered.Record(AWGRoutingLearnedRuleKey(old), "newest.example.com", "", []string{"192.0.2.20"}, "dns", true, 0, 0, at.Add(time.Hour))
	broad := awg.Zone{Domains: []string{"*.example.com"}}
	accepted := svc.routingDiscoverySeedNamesFrom(broad, broad.Domains, candidates)
	if len(accepted) != routingLearnedNamesLimit {
		t.Fatalf("broad rule did not share complete frozen window: %d", len(accepted))
	}
	for _, name := range accepted {
		narrow := awg.Zone{Domains: []string{"[re]^" + name + "$"}}
		if names := svc.routingDiscoverySeedNamesFrom(narrow, narrow.Domains, candidates); !reflect.DeepEqual(names, []string{name}) {
			t.Fatalf("matching rule used a different candidate window: %v want=%s", names, name)
		}
	}
	excluded := awg.Zone{Domains: []string{"[re]^host000\\.example\\.com$"}}
	if names := svc.routingDiscoverySeedNamesFrom(excluded, excluded.Domains, candidates); len(names) != 0 {
		t.Fatalf("later specific rule warmed a name beyond the shared budget: %v", names)
	}
}

func TestLegacyRoutingDiscoverySnapshotPreservesRuleIdentityAcrossReorder(t *testing.T) {
	svc := new(Service)
	on := true
	scoped := awg.Zone{Name: "Device", TunnelID: "vpn-a", Enabled: true, Route: "tunnel", Domains: []string{"example.com"}, IncludeSubdomains: &on, SourceIPs: []string{"192.168.3.10"}}
	global := awg.Zone{Name: "Everyone", TunnelID: "vpn-a", Enabled: true, Route: "direct", Domains: []string{"example.com"}, IncludeSubdomains: &on}
	first := svc.legacyRoutingDiscoverySnapshot([]awg.Zone{scoped, global})
	z, ok := svc.legacyRoutingDiscoveryRule(first, RouteDecision{RuleIdx: 1, Route: RouteTunnel, SourceBound: true}, "video.example.com", "192.168.3.10")
	if !ok || AWGRoutingLearnedRuleKey(z) != AWGRoutingLearnedRuleKey(scoped) {
		t.Fatal("source-matched rule lost its identity")
	}
	second := svc.legacyRoutingDiscoverySnapshot([]awg.Zone{global, scoped})
	z, ok = svc.legacyRoutingDiscoveryRule(second, RouteDecision{RuleIdx: 2, Route: RouteTunnel, SourceBound: true}, "video.example.com", "192.168.3.10")
	if !ok || AWGRoutingLearnedRuleKey(z) != AWGRoutingLearnedRuleKey(scoped) {
		t.Fatal("reordering moved history to another rule")
	}
	for _, tc := range []struct {
		decision       RouteDecision
		domain, source string
	}{
		{RouteDecision{RuleIdx: 1, Route: RouteTunnel, SourceBound: true}, "video.example.com", "192.168.3.11"},
		{RouteDecision{RuleIdx: 1, Route: RouteTunnel, SourceBound: true}, "unrelated.example", "192.168.3.10"},
		{RouteDecision{RuleIdx: 1, Route: RouteDirect, SourceBound: true}, "video.example.com", "192.168.3.10"},
		{RouteDecision{RuleIdx: 1, Route: RouteTunnel}, "video.example.com", "192.168.3.10"},
		{RouteDecision{RuleIdx: 0, Route: RouteTunnel}, "video.example.com", "192.168.3.10"},
	} {
		if _, ok := svc.legacyRoutingDiscoveryRule(first, tc.decision, tc.domain, tc.source); ok {
			t.Fatalf("attributed a mismatched decision: %+v", tc)
		}
	}
	// Mutation after registration cannot alter its source/domain policy.
	scoped.Domains[0] = "changed.example"
	scoped.SourceIPs[0] = "192.168.3.11"
	if _, ok := svc.legacyRoutingDiscoveryRule(first, RouteDecision{RuleIdx: 1, Route: RouteTunnel, SourceBound: true}, "video.example.com", "192.168.3.10"); !ok {
		t.Fatal("callback snapshot shared caller slices")
	}
}
