package awgroute

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nfqws2strategy/internal/services/awg"
)

func TestPolicyWarmupReusesHintsAcrossRulesWithoutChangingFreshLookup(t *testing.T) {
	svc := new(Service)
	calls := 0
	live := func(string) []string { calls++; return []string{"192.0.2.10", "bad", "192.0.2.10"} }
	lookup := func(name string) []string { return svc.policyDNSWarmupWithLookup(context.Background(), name, live) }
	for _, z := range []awg.Zone{{Domains: []string{"Example.Test"}}, {Domains: []string{"example.test"}}, {Domains: []string{"second.test", "example.test"}}} {
		entries, _, _ := svc.awgMultiRuleEntriesWithLookup(z, lookup)
		if !reflect.DeepEqual(entries, []string{"192.0.2.10/32"}) {
			t.Fatalf("warmup changed rule entries: %v", entries)
		}
	}
	if calls != 2 {
		t.Fatalf("repeated same-name list resolution: %d", calls)
	}
	first := lookup("EXAMPLE.TEST.")
	first[0] = "198.51.100.20"
	if lookup("example.test")[0] != "192.0.2.10" {
		t.Fatal("caller mutated cached routing hints")
	}
	svc.policyDNSLookup(true, live)("example.test")
	svc.policyDNSLookup(true, live)("example.test")
	if calls != 4 {
		t.Fatal("explicit fresh lookup silently became cached")
	}
}

func TestPolicyWarmupSharesConcurrentColdLookupAndCancelsWaiter(t *testing.T) {
	svc := new(Service)
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	live := func(string) []string {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return []string{"192.0.2.10"}
	}
	leader := make(chan []string, 1)
	go func() { leader <- svc.policyDNSWarmupWithLookup(context.Background(), "example.test", live) }()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	waiter := make(chan []string, 1)
	go func() { waiter <- svc.policyDNSWarmupWithLookup(ctx, "example.test", live) }()
	cancel()
	select {
	case got := <-waiter:
		if len(got) != 0 {
			t.Fatal("canceled waiter got a fresh reply")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled waiter waited for leader network lookup")
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := svc.policyDNSWarmupWithLookup(context.Background(), "example.test", live); !reflect.DeepEqual(got, []string{"192.0.2.10"}) {
				t.Errorf("shared reply %v", got)
			}
		}()
	}
	close(release)
	wg.Wait()
	if got := <-leader; !reflect.DeepEqual(got, []string{"192.0.2.10"}) || calls.Load() != 1 {
		t.Fatalf("cold query duplicated: %v calls=%d", got, calls.Load())
	}
	if len(svc.policyDNSWarmups) != 0 {
		t.Fatal("successful flights accumulated")
	}
}

func TestPolicyWarmupFailedRetryAndExpiredHints(t *testing.T) {
	svc := new(Service)
	calls := 0
	live := func(string) []string { calls++; return nil }
	lookup := func(name string) []string { return svc.policyDNSWarmupWithLookup(context.Background(), name, live) }
	for range 10 {
		lookup("failure.test")
	}
	if calls != 1 {
		t.Fatalf("failure repeated during backoff: %d", calls)
	}
	svc.policyDNSMu.Lock()
	svc.policyDNSWarmups["failure.test"].retryAfter = time.Now().Add(-time.Second)
	svc.policyDNS = make(map[string]policyDNSAnswer)
	svc.policyDNS["expired.test"] = policyDNSAnswer{ips: []string{"192.0.2.99"}, expires: time.Now().Add(-time.Second)}
	svc.policyDNSMu.Unlock()
	lookup("failure.test")
	if got := lookup("expired.test"); len(got) != 0 || calls != 3 {
		t.Fatalf("retry/expiry contract changed: %v calls=%d", got, calls)
	}
	if svc.routingDNSGate.failed() {
		t.Fatal("optional unsuccessful warmup changed route readiness")
	}
}

func TestPolicyWarmupBudgetSharesContextAndPreservesCachedEntriesAfterCancel(t *testing.T) {
	svc := new(Service)
	svc.rememberPolicyDNS("cached.test", []string{"192.0.2.10"})
	_, unlock := svc.lockClientOps(false)
	defer unlock()
	calls := 0
	var seen context.Context
	lookup, cancel := svc.policyDNSWarmupLookup(func(ctx context.Context, name string) []string {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > policyDNSWarmupBudget || time.Until(deadline) <= 0 {
			t.Fatal("bulk warmup has no bounded total deadline")
		}
		if seen != nil && seen != ctx {
			t.Fatal("list names got independent unbounded budgets")
		}
		seen = ctx
		return []string{"192.0.2.11"}
	})
	defer cancel()
	lookup("first.test")
	lookup("second.test")
	cancel()
	if len(lookup("cold.test")) > 0 || calls != 2 {
		t.Fatal("canceled bulk budget launched another cold lookup")
	}
	if got := lookup("cached.test"); !reflect.DeepEqual(got, []string{"192.0.2.10"}) {
		t.Fatal("expired warmup budget discarded known usable addresses")
	}
}

func TestPolicyWarmupNegativeMapBoundedWithoutEvictingInflight(t *testing.T) {
	svc := new(Service)
	for i := 0; i < policyDNSCacheLimit+10; i++ {
		svc.policyDNSWarmupWithLookup(context.Background(), fmt.Sprintf("host%d.test", i), func(string) []string { return nil })
	}
	if len(svc.policyDNSWarmups) != policyDNSCacheLimit {
		t.Fatalf("warmup failures grow without bound: %d", len(svc.policyDNSWarmups))
	}
	for name := range svc.policyDNSWarmups {
		svc.policyDNSWarmups[name] = &policyDNSWarmup{done: make(chan struct{})}
	}
	if got := svc.policyDNSWarmupWithLookup(context.Background(), "extra.test", func(string) []string { t.Fatal("saturated warmup duplicated active work"); return nil }); len(got) > 0 || len(svc.policyDNSWarmups) != policyDNSCacheLimit {
		t.Fatal("in-flight coordination was evicted")
	}
}

func TestPolicyWarmupFailedReadinessUsesValidatedUpstreamHint(t *testing.T) {
	svc := new(Service)
	failure := errors.New("kernel apply failed")
	finish := svc.routingDNSGate.begin(true)
	finish(failure)
	got := svc.policyDNSWarmupWithLookup(context.Background(), "recover.test", func(name string) []string {
		wire := policyDNSWire(t, name, "192.0.2.21")
		if answer, err := svc.ObserveDNSAnswer(context.Background(), name, wire, nil); answer != nil || !errors.Is(err, failure) {
			t.Fatal("failed readiness delivered client address")
		}
		return nil
	})
	if !reflect.DeepEqual(got, []string{"192.0.2.21"}) || svc.RoutingDNSReadiness().Ready {
		t.Fatalf("warmup lost validated fail-closed recovery hint: %v", got)
	}
}
