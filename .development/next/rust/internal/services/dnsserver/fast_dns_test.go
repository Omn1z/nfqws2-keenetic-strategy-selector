package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nfqws2strategy/internal/services/dnsroute"
)

type fastDNSTestClock struct{ nanos atomic.Int64 }

func newFastDNSTestClock() *fastDNSTestClock {
	c := new(fastDNSTestClock)
	c.nanos.Store(time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC).UnixNano())
	return c
}
func (c *fastDNSTestClock) now() time.Time          { return time.Unix(0, c.nanos.Load()).UTC() }
func (c *fastDNSTestClock) advance(d time.Duration) { c.nanos.Add(int64(d)) }

func waitFastDNS(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !condition() {
		select {
		case <-deadline.C:
			t.Fatal("timed out waiting for fast-dns workers")
		case <-tick.C:
		}
	}
}

func TestFastDNSCacheHourlyRefreshAndRouteScope(t *testing.T) {
	lifetime, stop := context.WithCancel(context.Background())
	defer stop()
	clock := newFastDNSTestClock()
	var calls atomic.Int32
	var generation atomic.Int32
	generation.Store(1)
	cache := NewFastDNSCache(lifetime, func(_ context.Context, route, host string) ([]string, error) {
		calls.Add(1)
		if host != "resolver.example" {
			t.Errorf("bootstrap hostname was not normalized: %s", host)
		}
		last := 1
		if route == "awg:warp" {
			last = 2
		}
		return []string{fmt.Sprintf("192.0.%d.%d", generation.Load(), last)}, nil
	}, nil)
	cache.now = clock.now
	for _, route := range []string{"nfqws", "awg:warp"} {
		ips, err := cache.Lookup(context.Background(), route, "RESOLVER.example.")
		if err != nil || len(ips) != 1 {
			t.Fatalf("initial %s lookup: %v %v", route, ips, err)
		}
		ips[0] = "198.51.100.255"
	}
	clock.advance(time.Hour - time.Second)
	cache.maintain()
	ips, err := cache.Lookup(context.Background(), "nfqws", "resolver.example")
	if err != nil || !reflect.DeepEqual(ips, []string{"192.0.1.1"}) || calls.Load() != 2 {
		t.Fatalf("hour cache was bypassed or aliased: %v %v calls=%d", ips, err, calls.Load())
	}
	generation.Store(2)
	clock.advance(time.Second)
	cache.maintain()
	waitFastDNS(t, func() bool { return calls.Load() == 4 && cache.Snapshot().Refreshing == 0 })
	ips, err = cache.Lookup(context.Background(), "awg:warp", "resolver.example")
	if err != nil || !reflect.DeepEqual(ips, []string{"192.0.2.2"}) {
		t.Fatalf("hourly same-route refresh missing: %v %v", ips, err)
	}
	status := cache.Snapshot()
	if status.Entries != 2 || status.Ready != 2 || status.LastRefreshAt != clock.now().Format(time.RFC3339Nano) || status.NextRefreshAt != clock.now().Add(time.Hour).Format(time.RFC3339Nano) {
		t.Fatalf("incorrect snapshot: %+v", status)
	}
}

func TestFastDNSConcurrentMissesSurviveCanceledWaiter(t *testing.T) {
	lifetime, stop := context.WithCancel(context.Background())
	defer stop()
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	cache := NewFastDNSCache(lifetime, func(ctx context.Context, _, _ string) ([]string, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		select {
		case <-release:
			return []string{"192.0.2.1"}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}, nil)
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() {
		_, err := cache.Lookup(firstCtx, "nfqws", "resolver.example")
		firstDone <- err
	}()
	<-started
	const waiters = 20
	var waiting sync.WaitGroup
	waiting.Add(waiters)
	errorsOut := make(chan error, waiters)
	for range waiters {
		go func() {
			defer waiting.Done()
			ips, err := cache.Lookup(context.Background(), "nfqws", "resolver.example")
			if err == nil && !reflect.DeepEqual(ips, []string{"192.0.2.1"}) {
				err = fmt.Errorf("incorrect shared result: %v", ips)
			}
			errorsOut <- err
		}()
	}
	cancelFirst()
	if err := <-firstDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter: %v", err)
	}
	close(release)
	waiting.Wait()
	close(errorsOut)
	for err := range errorsOut {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("concurrent misses triggered %d bootstraps", calls.Load())
	}
}

func TestFastDNSStaleRetryAndRecovery(t *testing.T) {
	lifetime, stop := context.WithCancel(context.Background())
	defer stop()
	clock := newFastDNSTestClock()
	var fail atomic.Bool
	var calls atomic.Int32
	cache := NewFastDNSCache(lifetime, func(context.Context, string, string) ([]string, error) {
		call := calls.Add(1)
		if fail.Load() {
			return nil, errors.New("bootstrap temporarily blocked")
		}
		return []string{fmt.Sprintf("192.0.2.%d", call)}, nil
	}, nil)
	cache.now = clock.now
	if _, err := cache.Lookup(context.Background(), "nfqws", "resolver.example"); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	clock.advance(time.Hour)
	cache.maintain()
	waitFastDNS(t, func() bool { return calls.Load() == 2 && cache.Snapshot().Refreshing == 0 })
	for range 10 {
		ips, err := cache.Lookup(context.Background(), "nfqws", "resolver.example")
		if err != nil || !reflect.DeepEqual(ips, []string{"192.0.2.1"}) {
			t.Fatalf("failed refresh discarded usable IP: %v %v", ips, err)
		}
	}
	if calls.Load() != 2 || !strings.Contains(cache.Snapshot().LastError, "blocked") {
		t.Fatalf("failed retry was not cached: calls=%d status=%+v", calls.Load(), cache.Snapshot())
	}
	clock.advance(time.Minute - time.Second)
	cache.maintain()
	if calls.Load() != 2 {
		t.Fatal("retry started before its cooldown")
	}
	fail.Store(false)
	clock.advance(time.Second)
	cache.maintain()
	waitFastDNS(t, func() bool { return calls.Load() == 3 && cache.Snapshot().Refreshing == 0 })
	ips, err := cache.Lookup(context.Background(), "nfqws", "resolver.example")
	if err != nil || !reflect.DeepEqual(ips, []string{"192.0.2.3"}) || cache.Snapshot().LastError != "" {
		t.Fatalf("refresh did not recover: %v %v %+v", ips, err, cache.Snapshot())
	}
	// A later outage must not extend stale addresses indefinitely.
	fail.Store(true)
	clock.advance(2 * time.Hour)
	if ips, err := cache.Lookup(context.Background(), "nfqws", "resolver.example"); err == nil || len(ips) != 0 {
		t.Fatalf("addresses survived the two-hour hard expiry: %v %v", ips, err)
	}
	if cache.Snapshot().Ready != 0 {
		t.Fatalf("expired entries reported ready: %+v", cache.Snapshot())
	}
}

func TestFastDNSWarmStaleLookupDoesNotWaitForRefresh(t *testing.T) {
	lifetime, stop := context.WithCancel(context.Background())
	defer stop()
	clock := newFastDNSTestClock()
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	cache := NewFastDNSCache(lifetime, func(ctx context.Context, _, _ string) ([]string, error) {
		if calls.Add(1) > 1 {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return []string{"192.0.2.1"}, nil
	}, nil)
	cache.now = clock.now
	if _, err := cache.Lookup(context.Background(), "nfqws", "resolver.example"); err != nil {
		t.Fatal(err)
	}
	clock.advance(time.Hour)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ips, err := cache.Lookup(ctx, "nfqws", "resolver.example")
	if err != nil || len(ips) != 1 {
		t.Fatalf("stale lookup waited for asynchronous refresh: %v %v", ips, err)
	}
	<-started
	close(release)
}

func TestFastDNSTransportRefreshHasCooldownAndRetries(t *testing.T) {
	lifetime, stop := context.WithCancel(context.Background())
	defer stop()
	clock := newFastDNSTestClock()
	var calls atomic.Int32
	cache := NewFastDNSCache(lifetime, func(context.Context, string, string) ([]string, error) {
		if calls.Add(1) == 2 {
			return nil, errors.New("refresh failed")
		}
		return []string{"192.0.2.1"}, nil
	}, nil)
	cache.now = clock.now
	if _, err := cache.Lookup(context.Background(), "nfqws", "resolver.example"); err != nil {
		t.Fatal(err)
	}
	cache.RefreshSoon("nfqws", "resolver.example")
	if calls.Load() != 1 {
		t.Fatal("transport refresh ignored successful-lookup cooldown")
	}
	if got := cache.Snapshot().NextRefreshAt; got != clock.now().Add(time.Minute).Format(time.RFC3339Nano) {
		t.Fatalf("single transport failure during cooldown was forgotten: %s", got)
	}
	clock.advance(time.Minute)
	cache.maintain()
	waitFastDNS(t, func() bool { return calls.Load() == 2 && cache.Snapshot().Refreshing == 0 })
	for range 10 {
		cache.RefreshSoon("nfqws", "resolver.example")
	}
	if got := cache.Snapshot().NextRefreshAt; got != clock.now().Add(time.Minute).Format(time.RFC3339Nano) {
		t.Fatalf("transport failure did not schedule an early retry: %s", got)
	}
	clock.advance(time.Minute)
	cache.maintain()
	waitFastDNS(t, func() bool { return calls.Load() == 3 && cache.Snapshot().Refreshing == 0 })
	if cache.Snapshot().LastError != "" {
		t.Fatal("early retry did not clear the transport refresh failure")
	}
}

func TestFastDNSWorkersBoundedAndForegroundPrioritized(t *testing.T) {
	lifetime, stop := context.WithCancel(context.Background())
	defer stop()
	started := make(chan string, fastDNSCapacity+1)
	permit := make(chan struct{})
	var active, maxActive atomic.Int32
	cache := NewFastDNSCache(lifetime, func(ctx context.Context, _, host string) ([]string, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for prev := maxActive.Load(); n > prev && !maxActive.CompareAndSwap(prev, n); prev = maxActive.Load() {
		}
		started <- host
		select {
		case <-permit:
			return []string{"192.0.2.1"}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}, func() []FastDNSTarget {
		targets := make([]FastDNSTarget, 1024)
		for i := range targets {
			targets[i] = FastDNSTarget{Route: "nfqws", Host: fmt.Sprintf("warm-%d.example", i)}
		}
		return targets
	})
	cache.Start()
	<-started
	<-started
	requestDone := make(chan error, 1)
	go func() {
		_, err := cache.Lookup(context.Background(), "nfqws", "foreground.example")
		requestDone <- err
	}()
	waitFastDNS(t, func() bool {
		cache.mu.Lock()
		defer cache.mu.Unlock()
		e := cache.entries[fastDNSKey("nfqws", "foreground.example")]
		return e != nil && e.flight != nil && e.flight.foreground
	})
	permit <- struct{}{}
	if host := <-started; host != "foreground.example" {
		t.Fatalf("foreground DNS miss waited behind warm-up: %s", host)
	}
	if cache.Snapshot().Entries != fastDNSCapacity || maxActive.Load() != fastDNSWorkers {
		t.Fatalf("bounds not enforced: %+v maxworkers=%d", cache.Snapshot(), maxActive.Load())
	}
	stop()
	if err := <-requestDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("foreground waiter survived cache shutdown: %v", err)
	}
}

func TestFastDNSShutdownDoesNotPublishResults(t *testing.T) {
	lifetime, stop := context.WithCancel(context.Background())
	defer stop()
	started, returned := make(chan struct{}), make(chan struct{})
	cache := NewFastDNSCache(lifetime, func(ctx context.Context, _, _ string) ([]string, error) {
		close(started)
		<-ctx.Done()
		defer close(returned)
		// A backend returning a late success must not warm a closed service.
		return []string{"192.0.2.1"}, nil
	}, nil)
	done := make(chan error, 1)
	go func() {
		_, err := cache.Lookup(context.Background(), "nfqws", "resolver.example")
		done <- err
	}()
	<-started
	stop()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("waiter did not stop: %v", err)
	}
	<-returned
	cache.mu.Lock()
	e := cache.entries[fastDNSKey("nfqws", "resolver.example")]
	flightDone := e.flight.done
	cache.mu.Unlock()
	<-flightDone
	if status := cache.Snapshot(); status.Ready != 0 || status.LastRefreshAt != "" {
		t.Fatalf("closed cache published late success: %+v", status)
	}
	if _, err := cache.Lookup(context.Background(), "nfqws", "new.example"); !errors.Is(err, context.Canceled) {
		t.Fatalf("closed cache accepted a new lookup: %v", err)
	}
}

func TestFastDNSCacheBoundAndIPValidation(t *testing.T) {
	lifetime, stop := context.WithCancel(context.Background())
	defer stop()
	clock := newFastDNSTestClock()
	cache := NewFastDNSCache(lifetime, func(context.Context, string, string) ([]string, error) {
		ips := []string{"not-an-ip", "0.0.0.0", "224.0.0.1", "192.0.2.1", "192.0.2.1"}
		for i := 2; i <= 30; i++ {
			ips = append(ips, fmt.Sprintf("192.0.2.%d", i))
		}
		return ips, nil
	}, nil)
	cache.now = clock.now
	for i := 0; i <= fastDNSCapacity; i++ {
		clock.advance(time.Second)
		ips, err := cache.Lookup(context.Background(), "nfqws", fmt.Sprintf("resolver-%d.example", i))
		if err != nil || len(ips) != 16 || ips[0] != "192.0.2.1" || ips[15] != "192.0.2.16" {
			t.Fatalf("unbounded/unvalidated IP result: %v %v", ips, err)
		}
	}
	cache.mu.Lock()
	_, oldestPresent := cache.entries[fastDNSKey("nfqws", "resolver-0.example")]
	count := len(cache.entries)
	cache.mu.Unlock()
	if oldestPresent || count != fastDNSCapacity {
		t.Fatalf("LRU bound was not respected: oldest=%v entries=%d", oldestPresent, count)
	}
}

func TestFastDNSTargetsOnlyConfiguredNamesAndRoutes(t *testing.T) {
	cfg := Default()
	cfg.DefaultUpstream = Upstream{Address: "https://manual.example/dns-query", BootstrapIPs: []string{"192.0.2.1"}}
	cfg.DefaultPool = []Upstream{{Address: "https://1.1.1.1/dns-query"}, {Address: "https://DEFAULT.example/dns-query"}}
	cfg.Rules = []Rule{
		{Enabled: true, Domain: "private-query.example", Upstream: Upstream{Address: "https://special.example/dns-query"}, Pool: []Upstream{{Address: "https://default.example/another-query"}}},
		{Enabled: false, Domain: "disabled-query.example", Upstream: Upstream{Address: "https://disabled-provider.example/dns-query"}},
	}
	routes := []dnsroute.Route{{ID: "nfqws", Available: true}, {ID: "awg:warp", Available: true}, {ID: "awg:down", Available: false}, {ID: "direct", Available: true}}
	want := []FastDNSTarget{{Route: "nfqws", Host: "default.example"}, {Route: "awg:warp", Host: "default.example"}, {Route: "nfqws", Host: "special.example"}, {Route: "awg:warp", Host: "special.example"}}
	if got := fastDNSTargets(cfg, routes); !reflect.DeepEqual(got, want) {
		t.Fatalf("wrong warm-up scope: got %v want %v", got, want)
	}
	cfg.AWGFallback = "off"
	if got := fastDNSTargets(cfg, routes); !reflect.DeepEqual(got, []FastDNSTarget{want[0], want[2]}) {
		t.Fatalf("AWG-off warm-up used disallowed routes: %v", got)
	}
	for i := 0; i < 512; i++ {
		cfg.Rules = append(cfg.Rules, Rule{Enabled: true, Upstream: Upstream{Address: fmt.Sprintf("https://provider-%d.example/dns-query", i)}})
	}
	if got := fastDNSTargets(cfg, routes); len(got) != fastDNSCapacity {
		t.Fatalf("warm-up target enumeration is unbounded: %d", len(got))
	}
}
