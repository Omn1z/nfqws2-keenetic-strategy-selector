//go:build linux

package awgroute

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"nfqws2strategy/internal/services/awg"
)

func routingDiscoveryMultiFixture(t *testing.T, z awg.Zone, set string, index int) awgMultiRule {
	t.Helper()
	svc := new(Service)
	domains, _ := svc.expandZoneEntries(z)
	ms, bad := awg.CompileMatcherSet(awgDropCatchAll(domains))
	if len(bad) > 0 {
		t.Fatal(bad)
	}
	return awgMultiRule{Zone: z, SetName: set, HasDst: true, CatchAll: z.IsCatchAll(), Sources: z.SourceIPs, Dynamic: ms.Len() > 0, Matchers: &ms, RuleIndex: index}
}

func TestMultiDNSDiscoveryBelongsToConfirmedSourceMatchedWinner(t *testing.T) {
	on := true
	scoped := awg.Zone{Name: "Device", TunnelID: "first", Enabled: true, Route: "tunnel", Domains: []string{"example.com"}, IncludeSubdomains: &on, SourceIPs: []string{"192.168.3.10"}}
	global := awg.Zone{Name: "Everyone", TunnelID: "second", Enabled: true, Route: "tunnel", Domains: []string{"example.com"}, IncludeSubdomains: &on}
	for _, tc := range []struct {
		name    string
		reverse bool
		client  string
		winner  awg.Zone
	}{
		{"scoped first", false, "192.168.3.10", scoped},
		{"different client", false, "192.168.3.11", global},
		{"global first", true, "192.168.3.10", global},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := new(Service)
			rules := []awgMultiRule{routingDiscoveryMultiFixture(t, scoped, "awgm_001", 0), routingDiscoveryMultiFixture(t, global, "awgm_002", 1)}
			if tc.reverse {
				rules[0], rules[1] = rules[1], rules[0]
			}
			learned := []ipsetAddReq{}
			err := svc.awgMultiLearnDNSAnswerWith(context.Background(), rules, "video.example.com", tc.client, []string{"192.0.2.17", "2001:db8::17"}, 0, func(_ context.Context, requests []ipsetAddReq) error {
				if len(svc.discovered.Names(AWGRoutingLearnedRuleKey(tc.winner))) != 0 {
					t.Fatal("discovery recorded before kernel acceptance")
				}
				learned = append(learned, requests...)
				return nil
			})
			if err != nil || len(learned) != 1 || learned[0].ip != "192.0.2.17" {
				t.Fatalf("route install=%v err=%v", learned, err)
			}
			if names := svc.discovered.Names(AWGRoutingLearnedRuleKey(tc.winner)); !reflect.DeepEqual(names, []string{"video.example.com"}) {
				t.Fatalf("winning rule history=%v", names)
			}
			loser := global
			if AWGRoutingLearnedRuleKey(tc.winner) == AWGRoutingLearnedRuleKey(global) {
				loser = scoped
			}
			if names := svc.discovered.Names(AWGRoutingLearnedRuleKey(loser)); len(names) != 0 {
				t.Fatalf("nonwinning rule acquired discovery: %v", names)
			}
		})
	}
}

func TestMultiDNSDiscoveryRejectsFailureReplayCatchAllAndOldGeneration(t *testing.T) {
	on := true
	z := awg.Zone{Name: "Sites", Enabled: true, Route: "tunnel", Domains: []string{"example.com"}, IncludeSubdomains: &on}
	for _, kind := range []string{"failure", "replay", "catch-all", "old generation", "outside scope"} {
		t.Run(kind, func(t *testing.T) {
			svc := new(Service)
			rule := routingDiscoveryMultiFixture(t, z, "awgm_001", 0)
			name := "video.example.com"
			if kind == "catch-all" {
				rule.CatchAll = true
			}
			if kind == "old generation" {
				finish := svc.routingDNSGate.begin(true)
				finish(nil)
			}
			if kind == "outside scope" {
				name = "unrelated.example"
			}
			failure := errors.New("install failed")
			err := svc.awgMultiLearnDNSAnswerWithDiscovery(context.Background(), []awgMultiRule{rule}, name, "192.168.3.10", []string{"192.0.2.17"}, 0, kind != "replay", func(context.Context, []ipsetAddReq) error {
				if kind == "failure" {
					return failure
				}
				if kind == "old generation" || kind == "outside scope" {
					t.Fatal("ineligible answer attempted installation")
				}
				return nil
			})
			if (kind == "failure" || kind == "old generation") != (err != nil) {
				t.Fatalf("unexpected install error: %v", err)
			}
			if names := svc.discovered.Names(AWGRoutingLearnedRuleKey(z)); len(names) != 0 {
				t.Fatalf("ineligible answer acquired history: %v", names)
			}
		})
	}
}

func TestLegacyDNSDiscoveryUsesClientWinnerAndInstalledSourceSet(t *testing.T) {
	on := true
	z := awg.Zone{Name: "Device", TunnelID: "vpn", Enabled: true, Route: "tunnel", Domains: []string{"example.com"}, IncludeSubdomains: &on, SourceIPs: []string{"192.168.3.10"}}
	svc := new(Service)
	cfg := &awg.ServerConfig{Routing: awg.RoutingConfig{Mode: "zones", Zones: []awg.Zone{z}}}
	svc.route.routeTable.Store(svc.buildRouteTable(cfg, false))
	snapshot := svc.legacyRoutingDiscoverySnapshot(cfg.Routing.Zones)
	if err := svc.awgLearnLegacyDNSAnswerWithSnapshot(context.Background(), "video.example.com", "192.168.3.10", []string{"192.0.2.17"}, 0, snapshot, func(_ context.Context, requests []ipsetAddReq) error {
		if len(requests) != 1 || requests[0].set != sourceZoneSetName(0) {
			t.Fatalf("unexpected source destination: %v", requests)
		}
		if len(svc.discovered.Names(AWGRoutingLearnedRuleKey(z))) != 0 {
			t.Fatal("legacy discovery recorded before install")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if names := svc.discovered.Names(AWGRoutingLearnedRuleKey(z)); !reflect.DeepEqual(names, []string{"video.example.com"}) {
		t.Fatalf("source-bound legacy winner was not recorded: %v", names)
	}
}
