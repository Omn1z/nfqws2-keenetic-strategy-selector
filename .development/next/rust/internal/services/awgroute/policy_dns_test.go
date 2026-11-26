package awgroute

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

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

func TestCachedPolicyEndpointRetainsWANEscapeAfterDNSHintExpires(t *testing.T) {
	svc := &Service{}
	if got := svc.policyHostIPWithLookup("Endpoint.Example.", func(string) string { return "198.51.100.31" }); got != "198.51.100.31" {
		t.Fatal("endpoint resolution failed")
	}
	svc.policyDNSMu.Lock()
	answer := svc.policyDNS["endpoint.example"]
	answer.expires = time.Now().Add(-time.Second)
	svc.policyDNS["endpoint.example"] = answer
	svc.policyDNSMu.Unlock()
	if svc.cachedPolicyHostIP("endpoint.example") != "" {
		t.Fatal("DNS answer expiry was changed")
	}
	if svc.cachedPolicyEndpointIP("endpoint.example") != "198.51.100.31" {
		t.Fatal("periodic refresh lost the running endpoint's WAN escape")
	}
	if svc.cachedPolicyEndpointIP("other-endpoint.example") != "" {
		t.Fatal("an edited endpoint inherited an unrelated escape")
	}
	svc.rememberPolicyDNS("endpoint.example", []string{"198.51.100.32"})
	if svc.cachedPolicyEndpointIP("endpoint.example") != "198.51.100.31" {
		t.Fatal("background DNS overrode the running engine endpoint")
	}
	svc.policyHostIPWithLookup("endpoint.example", func(string) string { return "198.51.100.33" })
	if svc.cachedPolicyEndpointIP("endpoint.example") != "198.51.100.33" {
		t.Fatal("explicit endpoint resolution did not update the WAN escape")
	}
}

func policyDNSWire(t *testing.T, name, address string) []byte {
	t.Helper()
	query := new(mdns.Msg)
	query.SetQuestion(mdns.Fqdn(name), mdns.TypeA)
	answer := new(mdns.Msg)
	answer.SetReply(query)
	answer.Answer = []mdns.RR{&mdns.A{Hdr: mdns.RR_Header{Name: mdns.Fqdn(name), Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60}, A: net.ParseIP(address)}}
	wire, err := answer.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestFailedPolicyPreparationUsesUpstreamHintWithoutDeliveringAnswer(t *testing.T) {
	svc := new(Service)
	failure := errors.New("kernel apply failed")
	finish := svc.routingDNSGate.begin(true)
	finish(failure)
	wire := policyDNSWire(t, "cold.example", "192.0.2.21")
	before := append([]byte(nil), wire...)
	live := func(name string) []string {
		// Model resolver :53 forwarding to this DNS service: the upstream
		// answer exists, but the native lookup observes our SERVFAIL.
		out, err := svc.ObserveDNSAnswer(context.Background(), name, wire, net.IPv4(127, 0, 0, 1))
		if out != nil || !errors.Is(err, failure) {
			t.Fatalf("broken policy delivered an address: %x, %v", out, err)
		}
		return nil
	}
	got := svc.policyDNSLookup(true, live)("cold.example")
	if !reflect.DeepEqual(got, []string{"192.0.2.21"}) || !bytes.Equal(wire, before) || svc.RoutingDNSReadiness().Ready {
		t.Fatalf("retry did not preserve fail-closed preparation: hints=%v ready=%v", got, svc.RoutingDNSReadiness().Ready)
	}
	endpoint := svc.policyHostIPWithLookup("endpoint.example", func(name string) string {
		if out, err := svc.ObserveDNSAnswer(context.Background(), name, policyDNSWire(t, name, "198.51.100.23"), nil); out != nil || !errors.Is(err, failure) {
			t.Fatalf("endpoint retry leaked an answer: %x, %v", out, err)
		}
		return ""
	})
	if endpoint != "198.51.100.23" || svc.RoutingDNSReadiness().Ready {
		t.Fatalf("failed policy endpoint preparation=%q ready=%v", endpoint, svc.RoutingDNSReadiness().Ready)
	}
	finish = svc.routingDNSGate.begin(false)
	finish(nil) // Simulate confirmed installation, not just successful resolution.
	if out, err := svc.ObserveDNSAnswer(context.Background(), "cold.example", wire, nil); err != nil || !bytes.Equal(out, wire) || !svc.RoutingDNSReadiness().Ready {
		t.Fatalf("confirmed retry did not release DNS: %v ready=%v", err, svc.RoutingDNSReadiness().Ready)
	}
}

func TestFailedPolicyPreparationRejectsUnusableUpstreamHints(t *testing.T) {
	good := policyDNSWire(t, "cold.example", "192.0.2.21")
	query := append([]byte(nil), good...)
	query[2] &^= 0x80
	negative := append([]byte(nil), good...)
	negative[3] = negative[3]&0xf0 | byte(mdns.RcodeNameError)
	truncated := append([]byte(nil), good...)
	truncated[2] |= 0x02
	for name, wire := range map[string][]byte{
		"mismatched": policyDNSWire(t, "another.example", "192.0.2.21"),
		"query":      query, "negative": negative, "truncated": truncated,
		"null route": policyDNSWire(t, "cold.example", "0.0.0.0"),
		"malformed":  good[:len(good)-1], "short": {0, 1},
	} {
		t.Run(name, func(t *testing.T) {
			svc := new(Service)
			finish := svc.routingDNSGate.begin(true)
			finish(errors.New("kernel apply failed"))
			if out, err := svc.ObserveDNSAnswer(context.Background(), "cold.example", wire, nil); out != nil || err == nil {
				t.Fatal("broken policy accepted an answer")
			}
			if hints := svc.policyDNSLookup(false, nil)("cold.example"); len(hints) != 0 {
				t.Fatalf("unusable answer seeded recovery: %v", hints)
			}
		})
	}
}

func TestPolicyPreparationNeverReusesExpiredOrHealthyNegativeLookup(t *testing.T) {
	svc := new(Service)
	svc.rememberPolicyDNS("healthy.example", []string{"192.0.2.21"})
	if got := svc.policyDNSLookup(true, func(string) []string { return nil })("healthy.example"); len(got) != 0 {
		t.Fatalf("healthy negative lookup revived old addresses: %v", got)
	}
	finish := svc.routingDNSGate.begin(true)
	finish(errors.New("kernel apply failed"))
	svc.policyDNS["expired.example"] = policyDNSAnswer{ips: []string{"192.0.2.22"}, expires: time.Now().Add(-time.Second)}
	if got := svc.policyDNSLookup(true, func(string) []string { return nil })("expired.example"); len(got) != 0 {
		t.Fatalf("failed-policy retry reused an expired address: %v", got)
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
