package awgroute

import (
	"strings"
	"testing"
	"time"
)

func TestEndpointRouteAuditUsesExactFamilyHostPrefixAndNativeMainTable(t *testing.T) {
	const saved = "default via fe80::1 dev eth4\n2001:db8::20 via fe80::1 dev eth4 proto static\n"
	if !awgEndpointRouteIntact(saved, "2001:db8::20", "fe80::1", "eth4") || !awgEndpointRouteIntact(strings.ReplaceAll(saved, "2001:db8::20 ", "2001:db8::20/128 "), "2001:db8::20", "fe80::1", "eth4") {
		t.Fatal("valid native IPv6 escape rejected")
	}
	for _, broken := range []string{"2001:db8::20/32 via fe80::1 dev eth4", "2001:db8::20 via fe80::1 dev awg1", "2001:db8::20 via fe80::2 dev eth4", "2001:db8::20 via fe80::1 dev eth4 table 901", "blackhole 2001:db8::20/128"} {
		if awgEndpointRouteIntact(broken, "2001:db8::20", "fe80::1", "eth4") {
			t.Fatalf("incorrect endpoint escape accepted: %s", broken)
		}
	}
}

func TestMultiRouteAuditRequiresEveryIPv4CandidateWithoutMisclassifyingIPv6(t *testing.T) {
	want := []awgMultiRouteExpectation{{Table: 901, Iface: "awg0", EndpointIP: "2001:db8::20", EndpointIPs: []string{"198.51.100.10", "198.51.100.11", "2001:db8::20"}, Online: true}}
	const saved = "default dev awg0 table 901\n198.51.100.10 via 192.0.2.1 dev eth3\n198.51.100.11/32 via 192.0.2.1 dev eth3\n"
	if !awgMultiRoutesIntact(saved, "192.0.2.1", "eth3", want) {
		t.Fatal("complete IPv4 escapes rejected because current endpoint is IPv6")
	}
	if awgMultiRoutesIntact(strings.ReplaceAll(saved, "198.51.100.11/32 via 192.0.2.1 dev eth3\n", ""), "192.0.2.1", "eth3", want) {
		t.Fatal("missing backup IPv4 escape was accepted")
	}
}

func TestPolicyEndpointIPv6HintsSurviveDNSExpiryAndKeepIPv4Preference(t *testing.T) {
	svc := &Service{}
	svc.rememberPolicyEndpointIP("v6.example", "2001:0db8::20")
	svc.rememberPolicyDNS("v6.example", []string{"2001:db8::21"})
	answer := svc.policyDNS["v6.example"]
	answer.expires = time.Now().Add(-time.Second)
	svc.policyDNS["v6.example"] = answer
	if got := svc.cachedPolicyEndpointIP("v6.example"); got != "2001:db8::20" {
		t.Fatalf("running IPv6 escape lost after DNS expiry: %s", got)
	}
	if got := svc.cachedPolicyEndpointIP("2001:0db8::30"); got != "2001:db8::30" {
		t.Fatalf("literal IPv6 missing: %s", got)
	}
	svc.rememberPolicyDNS("dual.example", []string{"2001:db8::21", "198.51.100.10"})
	if got := svc.cachedPolicyHostIP("dual.example"); got != "198.51.100.10" {
		t.Fatalf("existing primary IPv4 preference changed: %s", got)
	}
}
