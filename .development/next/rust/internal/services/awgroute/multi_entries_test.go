package awgroute

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"nfqws2strategy/internal/services/awg"
)

func TestMultiRuleResolutionIsBoundedParallelAndSeedsCache(t *testing.T) {
	svc := &Service{}
	domains := make([]string, 64)
	for i := range domains {
		domains[i] = fmt.Sprintf("host%d.example", i)
	}
	domains = append(domains, "*.mask.example")
	var active, peak, called atomic.Int32
	live := func(name string) []string {
		called.Add(1)
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		time.Sleep(5 * time.Millisecond)
		index, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(name, "host"), ".example"))
		if err != nil {
			return nil
		}
		return []string{fmt.Sprintf("198.51.100.%d", index+1)}
	}
	z := awg.Zone{Domains: domains}
	entries, catchAll, static := svc.awgMultiRuleEntriesWithLookup(z, svc.policyDNSLookup(true, live))
	if catchAll || !static || len(entries) != 64 || called.Load() != 64 {
		t.Fatalf("unexpected result: entries=%d catchAll=%v static=%v calls=%d", len(entries), catchAll, static, called.Load())
	}
	if peak.Load() < 2 || peak.Load() > 32 {
		t.Fatalf("lookup concurrency=%d, want 2..32", peak.Load())
	}
	cached, _, _ := svc.awgMultiRuleEntriesWithLookup(z, svc.policyDNSLookup(false, live))
	if !reflect.DeepEqual(cached, entries) || called.Load() != 64 {
		t.Fatal("recovery did not reuse complete DNS cache")
	}
}

func TestMultiCDNTunnelWarmupAndCachedRefresh(t *testing.T) {
	for _, tc := range []struct {
		name, route string
		sources     []string
		want        []string
	}{
		{"tunnel", "tunnel", nil, []string{"188.114.96.3/32", "188.114.97.3/32"}},
		{"direct remains protected", "direct", nil, []string{}},
		{"scoped tunnel", "tunnel", []string{"192.168.3.152"}, []string{"188.114.96.3/32", "188.114.97.3/32"}},
		{"scoped direct keeps conservative warmup", "direct", []string{"192.168.3.152"}, []string{}},
		{"unsupported IPv6 scope cannot seed global bypass", "direct", []string{"2001:db8::152"}, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := new(Service)
			z := awg.Zone{Route: tc.route, Domains: []string{"notletters.com"}, SourceIPs: tc.sources}
			live := func(name string) []string {
				if name != "notletters.com" {
					t.Fatalf("unexpected lookup %q", name)
				}
				return []string{"188.114.96.3", "188.114.97.3"}
			}
			entries, catchAll, _ := svc.awgMultiRuleEntriesWithLookup(z, svc.policyDNSLookup(true, live))
			if catchAll || !reflect.DeepEqual(entries, tc.want) {
				t.Fatalf("initial domain routes = %v, want %v", entries, tc.want)
			}
			entries, _, _ = svc.awgMultiRuleEntriesWithLookup(z, svc.policyDNSLookup(false, func(string) []string {
				t.Fatal("maintenance queried DNS instead of reusing hints")
				return nil
			}))
			if !reflect.DeepEqual(entries, tc.want) {
				t.Fatalf("cached maintenance changed CDN policy: %v", entries)
			}
		})
	}
}

func TestMultiCDNDirectGuardDoesNotRemoveExplicitIP(t *testing.T) {
	svc := new(Service)
	z := awg.Zone{Route: "direct", Domains: []string{"notletters.com"}, IPs: []string{"188.114.96.3"}}
	entries, _, _ := svc.awgMultiRuleEntriesWithLookup(z, func(string) []string { return []string{"188.114.96.3", "188.114.97.3"} })
	if !reflect.DeepEqual(entries, []string{"188.114.96.3/32"}) {
		t.Fatalf("explicit IP changed or domain-derived direct exception leaked: %v", entries)
	}
}
