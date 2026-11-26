package awgroute

import (
	"testing"

	"nfqws2strategy/internal/services/awg"
)

func TestSourceOnlyLegacyModesPersistAsExplicitMultiRules(t *testing.T) {
	for _, mode := range []string{"include", "exclude", "full"} {
		svc, _, entries := failoverTestService(t)
		owner := entries[0]
		owner.Manager.SetEnabled(true)
		owner.Manager.SetClientEnabled(true)
		rc := awg.RoutingConfig{Mode: mode, Zones: []awg.Zone{
			{Enabled: true, SourceIPs: []string{"192.168.1.17"}},
		}}
		rc.Normalize()
		owner.Manager.SetRoutingState(rc, true)
		rules := svc.awgPolicyRoutingRules()
		if len(rules) != 1 || rules[0].TunnelID != owner.ID || len(rules[0].SourceIPs) != 1 {
			t.Fatalf("%s lost its source-only multi rule", mode)
		}
		want := "tunnel"
		if mode == "exclude" {
			want = "direct"
		}
		if rules[0].RouteValue() != want {
			t.Fatalf("%s selected %s", mode, rules[0].RouteValue())
		}
		dsts, _, keep := svc.awgMultiRuleEntriesWithLookupAndSeeds(rules[0], func(string) []string {
			t.Fatal("source-only rule attempted a DNS lookup")
			return nil
		}, nil)
		if !keep || len(dsts) != 0 {
			t.Fatalf("%s source-only rule acquired a destination restriction", mode)
		}
	}
}

func TestFullWatchdogIPv6OnlyGlobalZonesProduceNoMultiRule(t *testing.T) {
	svc, _, _ := failoverTestService(t)
	z := awg.Zone{Enabled: true, IPs: []string{"2001:db8:7::/48", "2001:db8:8::1"}}
	dst, blanket, keep := svc.awgMultiRuleEntriesWithLookupAndSeeds(z, nil, nil)
	if len(dst) > 0 || blanket || keep || len(sourceBoundZones([]awg.Zone{z})) != 0 ||
		awgEffectiveMode(awg.RoutingConfig{Mode: "full", Zones: []awg.Zone{z}}) != "full" {
		t.Fatal("global IPv6-only zones no longer fall back to the full watchdog blanket")
	}
}

// These are the actual rule and ownership selectors used by Linux multi-policy
// compilation and legacy full-tunnel recovery. They need no running interface.
func TestSavedSNIFlagDoesNotChooseLegacyRoutingForExplicitZones(t *testing.T) {
	for _, sni := range []bool{false, true} {
		svc, _, entries := failoverTestService(t)
		owner := entries[0]
		owner.Manager.SetEnabled(true)
		owner.Manager.SetClientEnabled(true)
		setTestFailover(t, owner.Manager, false)
		rc := awg.RoutingConfig{Mode: "zones", SNIRouting: sni, Zones: []awg.Zone{
			{Route: "tunnel", Enabled: true, Domains: []string{"*.corp.test"}},
		}}
		owner.Manager.SetRoutingState(rc, true)
		rules := svc.awgPolicyRoutingRules()
		if len(rules) != 1 || rules[0].TunnelID != owner.ID || !svc.connectionRoutingEnabled(owner) || svc.legacyFullRoutingOwner() != nil {
			t.Fatalf("explicit domain rule did not select its own multi-policy tunnel (SNI=%t)", sni)
		}
		rc.Zones = nil
		owner.Manager.SetRoutingState(rc, true)
		if len(svc.awgPolicyRoutingRules()) != 0 || svc.legacyFullRoutingOwner() != nil {
			t.Fatalf("empty zones became a blanket tunnel (SNI=%t)", sni)
		}
		rc.Mode = "full"
		owner.Manager.SetRoutingState(rc, true)
		if len(svc.awgPolicyRoutingRules()) != 0 || svc.legacyFullRoutingOwner() != owner {
			t.Fatalf("full mode without reserves lost its legacy owner (SNI=%t)", sni)
		}
	}
}
