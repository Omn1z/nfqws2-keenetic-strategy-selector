package awgroute

import (
	"reflect"
	"testing"

	"nfqws2strategy/internal/services/awg"
)

func TestDomainSubdomainPolicy(t *testing.T) {
	cases := []struct {
		raw  string
		on   bool
		want string
	}{
		{" EXAMPLE.COM. ", true, "example.com"},
		{" EXAMPLE.COM. ", false, "full:example.com"},
		{"domain:example.com", true, "example.com"},
		{"full:example.com", true, "example.com"},
		{"domain:example.com", false, "full:example.com"},
		{"*.example.com", true, "example.com"},
		{"*.example.com", false, "*.example.com"},
		{".example.com", false, "full:example.com"},
		{"xn--e1afmkfd.xn--p1ai", false, "full:xn--e1afmkfd.xn--p1ai"},
		{"[re]^example\\.com$", true, "[re]^example\\.com$"},
		{"test##.com", true, "test##.com"},
		{"*example.com", true, "*example.com"},
		{"*", false, "*"},
		{"192.0.2.1", false, "192.0.2.1"},
		{"192.0.2.0/24", true, "192.0.2.0/24"},
		{"2001:db8::1", true, "2001:db8::1"},
	}
	for _, c := range cases {
		if got := domainSubdomainPolicy(c.raw, c.on); got != c.want {
			t.Errorf("policy(%q, %v)=%q, want %q", c.raw, c.on, got, c.want)
		}
	}
}

func TestRuleSubdomainPoliciesDoNotMutateSharedListExpansion(t *testing.T) {
	// This is a cache fixture; no real list files or OS DNS are consulted.
	original := []string{"example.com", "*.cdn.example"}
	ipEntries := []string{"192.0.2.0/24"}
	svc := &Service{expandCache: map[string]expandCacheEntry{
		"list:sites": {rev: 0, domains: original, ips: ipEntries},
	}}
	on, off := true, false
	base := awg.Zone{Enabled: true, Domains: []string{"list:sites"}}
	legacy, legacyIPs := svc.expandZoneEntries(base)
	base.IncludeSubdomains = &on
	all, _ := svc.expandZoneEntries(base)
	base.IncludeSubdomains = &off
	exact, _ := svc.expandZoneEntries(base)
	if !reflect.DeepEqual(legacy, []string{"example.com", "*.cdn.example"}) ||
		!reflect.DeepEqual(all, []string{"example.com", "cdn.example"}) ||
		!reflect.DeepEqual(exact, []string{"full:example.com", "*.cdn.example"}) ||
		!reflect.DeepEqual(legacyIPs, ipEntries) {
		t.Fatalf("wrong per-rule expansion: legacy=%v all=%v exact=%v ips=%v", legacy, all, exact, legacyIPs)
	}
	all[0] = "changed.example"
	exact[0] = "full:changed.example"
	if !reflect.DeepEqual(original, []string{"example.com", "*.cdn.example"}) {
		t.Fatalf("policy mutated the shared expansion: %v", original)
	}
}

func TestSubdomainPolicyReachesDNSMatcherAndStaticLookup(t *testing.T) {
	svc := &Service{}
	on, off := true, false
	for _, policy := range []*bool{nil, &on, &off} {
		z := awg.Zone{Enabled: true, Domains: []string{"example.com"}, IncludeSubdomains: policy}
		domains, _ := svc.expandZoneEntries(z)
		ms, bad := awg.CompileMatcherSet(domains)
		if len(bad) != 0 || !ms.MatchAny("example.com") || ms.MatchAny("notexample.com") || ms.MatchAny("a.example.com") != (policy == nil || *policy) {
			t.Fatalf("wrong matching for policy %v: %v bad=%v", policy, domains, bad)
		}
		queries := []string{}
		entries, _, ok := svc.awgMultiRuleEntriesWithLookup(z, func(name string) []string {
			queries = append(queries, name)
			return []string{"192.0.2.1"}
		})
		if !ok || !reflect.DeepEqual(queries, []string{"example.com"}) || !reflect.DeepEqual(entries, []string{"192.0.2.1/32"}) {
			t.Fatalf("full marker reached DNS lookup: queries=%v entries=%v ok=%v", queries, entries, ok)
		}
		cfg := &awg.ServerConfig{Routing: awg.RoutingConfig{Mode: "zones", DomainSource: "resolve", Zones: []awg.Zone{z}}}
		if got := awgUsesDNSProxy(cfg); got != (policy != nil && *policy) {
			t.Fatalf("subdomain discovery gate=%v for policy %v", got, policy)
		}
	}
}

func TestSubdomainFlagInvalidatesRuleFingerprint(t *testing.T) {
	on, off := true, false
	cfg := &awg.ServerConfig{Routing: awg.RoutingConfig{Zones: []awg.Zone{{Enabled: true, Domains: []string{"example.com"}}}}}
	legacy := routeTableInputHash(cfg, false)
	cfg.Routing.Zones[0].IncludeSubdomains = &on
	all := routeTableInputHash(cfg, false)
	cfg.Routing.Zones[0].IncludeSubdomains = &off
	exact := routeTableInputHash(cfg, false)
	if legacy == all || all == exact || legacy == exact {
		t.Fatal("subdomain policy change did not invalidate the compiled rules")
	}
}
