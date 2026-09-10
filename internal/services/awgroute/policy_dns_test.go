package awgroute

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"nfqws2strategy/internal/services/awg"
)

func TestRecoveryPolicyEntriesNeverResolveDNS(t *testing.T) {
	svc := &Service{}
	svc.rememberPolicyDNS("cached.example", []string{"192.0.2.10"})
	live := func(string) []string { t.Fatal("recovery called live DNS resolver"); return nil }
	z := awg.Zone{Domains: []string{"cold.example", "cached.example", "*.mask.example"}, IPs: []string{"198.51.100.0/24"}}
	entries, catchAll, static := svc.awgMultiRuleEntriesWithLookup(z, svc.policyDNSLookup(false, live))
	if catchAll || !static || !reflect.DeepEqual(entries, []string{"192.0.2.10/32", "198.51.100.0/24"}) {
		t.Fatalf("unexpected recovery entries: %v catchAll=%v static=%v", entries, catchAll, static)
	}
	if got := svc.cachedPolicyHostIP("cold.example"); got != "" {
		t.Fatal("uncached endpoint invented an address")
	}
	if got := svc.cachedPolicyHostIP("cached.example"); got != "192.0.2.10" {
		t.Fatal("cached endpoint missing")
	}
}

func TestExplicitPolicyResolutionSeedsRecoveryCache(t *testing.T) {
	svc := &Service{}
	lookups := 0
	live := func(string) []string { lookups++; return []string{"192.0.2.11"} }
	z := awg.Zone{Domains: []string{"host.example"}}
	svc.awgMultiRuleEntriesWithLookup(z, svc.policyDNSLookup(true, live))
	entries, _, _ := svc.awgMultiRuleEntriesWithLookup(z, svc.policyDNSLookup(false, live))
	if lookups != 1 || !reflect.DeepEqual(entries, []string{"192.0.2.11/32"}) {
		t.Fatalf("cache did not preserve result: %v lookups=%d", entries, lookups)
	}
}

func TestPolicyDNSCacheBoundedAndExpires(t *testing.T) {
	svc := &Service{}
	for i := 0; i < policyDNSCacheLimit+100; i++ {
		svc.rememberPolicyDNS(fmt.Sprintf("host%d.example", i), []string{"192.0.2.11"})
	}
	if len(svc.policyDNS) != policyDNSCacheLimit {
		t.Fatalf("unbounded cache: %d", len(svc.policyDNS))
	}
	svc.policyDNS["expired.example"] = policyDNSAnswer{ips: []string{"192.0.2.12"}, expires: time.Now().Add(-time.Second)}
	if ips := svc.policyDNSLookup(false, nil)("expired.example"); len(ips) != 0 {
		t.Fatal("expired answer was reused")
	}
}
