//go:build linux

package awgroute

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"nfqws2strategy/internal/services/awg"
)

func cdnTestMultiRule(t *testing.T, route string, sources []string, set string) awgMultiRule {
	t.Helper()
	ms, err := awg.CompileMatcherSet([]string{"notletters.com"})
	if err != nil {
		t.Fatal(err)
	}
	return awgMultiRule{Zone: awg.Zone{Route: route, Domains: []string{"notletters.com"}}, Sources: sources, SetName: set, HasDst: true, Dynamic: true, Matchers: &ms}
}

func TestMultiCDNBeforeReplyHonorsTunnelAndDirectPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, route string
		sources     []string
		want        []ipsetAddReq
	}{
		{"tunnel", "tunnel", nil, []ipsetAddReq{{set: "awgm_000", ip: "188.114.96.3"}}},
		{"global direct stays guarded", "direct", nil, nil},
		{"scoped direct stays supported", "direct", []string{"192.168.3.152"}, []ipsetAddReq{{set: "awgm_000", ip: "188.114.96.3"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := new(Service)
			rules := []awgMultiRule{cdnTestMultiRule(t, tc.route, tc.sources, "awgm_000"), cdnTestMultiRule(t, "tunnel", nil, "awgm_001")}
			p := awg.NewDNSProxy("", "", nil)
			p.SetMatchers(awgMultiRulesMatcherSet(rules))
			var got []ipsetAddReq
			p.SetBeforeReply(func(ctx context.Context, src, name string, ips []string) error {
				return svc.awgMultiLearnDNSAnswerWith(ctx, rules, name, src, ips, 0, func(_ context.Context, requests []ipsetAddReq) error {
					got = append(got, requests...)
					return nil
				})
			})
			wire := policyDNSWire(t, "notletters.com", "188.114.96.3")
			answer, err := p.ObserveAnswerContext(context.Background(), "192.168.3.152", "notletters.com", wire)
			if err != nil || !bytes.Equal(answer, wire) || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("before-reply routing = %v err=%v, want %v and unchanged DNS answer", got, err, tc.want)
			}
			// Replay uses no source IP and must retain a global tunnel binding.
			if tc.route == "tunnel" {
				got = nil
				if err := svc.awgMultiLearnDNSAnswerWith(context.Background(), rules, "notletters.com", "", []string{"188.114.97.3"}, 0, func(_ context.Context, requests []ipsetAddReq) error {
					got = requests
					return nil
				}); err != nil || !reflect.DeepEqual(got, []ipsetAddReq{{set: "awgm_000", ip: "188.114.97.3"}}) {
					t.Fatalf("replay lost shared-CDN tunnel route: %v %v", got, err)
				}
			}
		})
	}
}

func TestMultiCDNReplyWaitsForKernelAndPropagatesFailure(t *testing.T) {
	svc := new(Service)
	rules := []awgMultiRule{cdnTestMultiRule(t, "tunnel", nil, "awgm_000")}
	p := awg.NewDNSProxy("", "", nil)
	p.SetMatchers(awgMultiRulesMatcherSet(rules))
	entered, release := make(chan struct{}), make(chan struct{})
	failure := errors.New("test kernel refused CDN route")
	p.SetBeforeReply(func(ctx context.Context, src, name string, ips []string) error {
		return svc.awgMultiLearnDNSAnswerWith(ctx, rules, name, src, ips, 0, func(context.Context, []ipsetAddReq) error {
			close(entered)
			<-release
			return failure
		})
	})
	defer close(release)
	wire := policyDNSWire(t, "notletters.com", "188.114.96.3")
	done := make(chan error, 1)
	go func() {
		answer, err := p.ObserveAnswerContext(context.Background(), "192.168.3.152", "notletters.com", wire)
		if answer != nil {
			err = errors.New("DNS answer escaped before a confirmed CDN route")
		}
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("CDN address never reached route installation")
	}
	select {
	case err := <-done:
		t.Fatalf("reply did not wait for kernel installation: %v", err)
	default:
	}
	release <- struct{}{}
	select {
	case err := <-done:
		if !errors.Is(err, failure) {
			t.Fatalf("kernel failure was hidden: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("failed route installation did not release the reply")
	}
}

func TestLegacyCDNTunnelStaticAndLivePreserveDirectGuard(t *testing.T) {
	for _, tc := range []struct {
		name, route, set string
		sources          []string
		allowed          bool
	}{
		{"tunnel", "tunnel", awgSetInc, nil, true},
		{"direct", "direct", awgSetExc, nil, false},
		{"scoped tunnel", "tunnel", "awg2_z0", []string{"192.168.3.152"}, true},
		{"scoped direct", "direct", "awg2_z0", []string{"192.168.3.152"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := new(Service)
			cfg := &awg.ServerConfig{Routing: awg.RoutingConfig{Mode: "zones", Zones: []awg.Zone{{Enabled: true, Route: tc.route, Domains: []string{"notletters.com"}, SourceIPs: tc.sources}}}}
			svc.rememberPolicyDNS("notletters.com", []string{"188.114.96.3", "188.114.97.3"})
			plan := svc.awgPrepareSetPlan(cfg, true)
			for _, ip := range []string{"188.114.96.3", "188.114.97.3"} {
				wantWarmup := tc.route == "tunnel"
				if got := strings.Contains(plan.globalScript+plan.sourceScript, "add "+tc.set+" "+ip+"/32\n"); got != wantWarmup {
					t.Fatalf("warmup allow=%v, want %v for %s", got, wantWarmup, ip)
				}
			}
			svc.route.routeTable.Store(svc.buildRouteTable(cfg, false))
			var got []ipsetAddReq
			if err := svc.awgLearnLegacyDNSAnswerWith(context.Background(), "notletters.com", "192.168.3.152", []string{"188.114.96.3"}, 0, func(_ context.Context, requests []ipsetAddReq) error {
				got = requests
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if tc.allowed && !reflect.DeepEqual(got, []ipsetAddReq{{set: tc.set, ip: "188.114.96.3"}}) || !tc.allowed && len(got) != 0 {
				t.Fatalf("live CDN policy changed: %v", got)
			}
		})
	}
}

func TestMultiCDNTraceMatchesLearnedDecision(t *testing.T) {
	wasEnabled := traceEnabled()
	traceSetEnabled(true)
	defer traceSetEnabled(wasEnabled)
	defer traceClear()
	for _, route := range []string{"tunnel", "direct"} {
		traceClear()
		svc := new(Service)
		svc.awgTraceMultiDNSQuery([]awgMultiRule{cdnTestMultiRule(t, route, nil, "awgm_000")}, "192.168.3.152", "notletters.com", "A", []string{"188.114.96.3", "188.114.97.3"}, false)
		entries := traceSnapshot(0)
		want := route
		if route == "direct" {
			want = "cdn-skip"
		}
		if len(entries) != 2 {
			t.Fatalf("trace entries = %d, want two answers", len(entries))
		}
		for _, entry := range entries {
			if entry.Decision != want {
				t.Fatalf("trace claimed %q after %q rule, want %q", entry.Decision, route, want)
			}
		}
	}
}
