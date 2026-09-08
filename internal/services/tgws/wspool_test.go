package tgws

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func testWSPool(t *testing.T, target int) *wsPool {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	p := newWSPool(ctx, target, 4096, &Stats{}, true)
	t.Cleanup(cancel)
	return p
}

func waitForPool(t *testing.T, p *wsPool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		p.mu.Lock()
		active := len(p.refilling)
		p.mu.Unlock()
		if active == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("pool refill did not finish")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestWSPoolRotationRefillsPartialAndExpiresOldConnections(t *testing.T) {
	p := testWSPool(t, 4)
	var calls atomic.Int32
	p.dial = func(context.Context, string, string, time.Duration, string, int, string) (*rawWebSocket, error) {
		calls.Add(1)
		ws, _ := newMemoryWS(nil)
		return ws, nil
	}
	key := poolKey{dc: 2, targetIP: "149.154.167.220"}
	ready, _ := newMemoryWS(nil)
	old, oldConn := newMemoryWS(nil)
	p.mu.Lock()
	p.idle[key] = []pooledWS{{ws: ready, created: time.Now()}, {ws: old, created: time.Now().Add(-poolMaxAge)}}
	p.domains[key] = []string{"example.com"}
	p.mu.Unlock()
	p.rotate(time.Now())
	waitForPool(t, p)
	p.mu.Lock()
	count := len(p.idle[key])
	p.mu.Unlock()
	if count != 4 || calls.Load() != 3 {
		t.Fatalf("ready=%d connections=%d", count, calls.Load())
	}
	deadline := time.Now().Add(time.Second)
	for !oldConn.closed.Load() {
		if time.Now().After(deadline) {
			t.Fatal("expired socket left open")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestWSPoolWarmupBoundsDialsAndRetainsEachBucketSize(t *testing.T) {
	p := testWSPool(t, 4)
	started := make(chan struct{}, 16)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	var current, peak, calls atomic.Int32
	p.dial = func(context.Context, string, string, time.Duration, string, int, string) (*rawWebSocket, error) {
		n := current.Add(1)
		defer current.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		calls.Add(1)
		started <- struct{}{}
		<-release
		ws, _ := newMemoryWS(nil)
		return ws, nil
	}
	p.warmup(map[int]string{2: "192.0.2.2", 4: "192.0.2.4"})
	for i := 0; i < poolDialConcurrency; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("warmup did not fill available dial slots")
		}
	}
	select {
	case <-started:
		unblock()
		t.Fatal("warmup exceeded its background dial limit")
	case <-time.After(20 * time.Millisecond):
	}
	unblock()
	waitForPool(t, p)
	if peak.Load() != poolDialConcurrency || calls.Load() != 16 {
		t.Fatalf("peak=%d calls=%d", peak.Load(), calls.Load())
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, dc := range []int{2, 4} {
		for _, media := range []bool{false, true} {
			key := poolKey{dc: dc, media: media, targetIP: "192.0.2." + itoa(dc)}
			if n := len(p.idle[key]); n != 4 {
				t.Errorf("DC%d media=%t ready=%d, want 4", dc, media, n)
			}
		}
	}
}

func TestWSPoolCancellationStopsQueuedDials(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := newWSPool(ctx, 0, 4096, &Stats{})
	started := make(chan struct{}, 16)
	var calls atomic.Int32
	p.dial = func(ctx context.Context, _, _ string, _ time.Duration, _ string, _ int, _ string) (*rawWebSocket, error) {
		calls.Add(1)
		started <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = p.connectOne("192.0.2.2", []string{"kws2.web.telegram.org"}) }()
	}
	for i := 0; i < poolDialConcurrency; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("dial did not start")
		}
	}
	cancel()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation left background dial waiters blocked")
	}
	if calls.Load() != poolDialConcurrency || len(p.dialSlots) != 0 {
		t.Fatalf("calls=%d occupied slots=%d", calls.Load(), len(p.dialSlots))
	}
}

func TestWSPoolBackoffAndSuccessfulFreshConnectionReset(t *testing.T) {
	p := testWSPool(t, 1)
	var calls atomic.Int32
	p.tryFrontingFirst.Store(false)
	p.dial = func(context.Context, string, string, time.Duration, string, int, string) (*rawWebSocket, error) {
		calls.Add(1)
		return nil, errors.New("unavailable")
	}
	key := poolKey{dc: 2, targetIP: "149.154.167.220"}
	p.scheduleRefill(key, key.targetIP, []string{"example.com"})
	waitForPool(t, p)
	p.mu.Lock()
	failures, after := p.failures[key], p.refillAfter[key]
	p.mu.Unlock()
	if failures != 1 || !after.After(time.Now()) {
		t.Fatalf("failures=%d after=%v", failures, after)
	}
	p.scheduleRefill(key, key.targetIP, []string{"example.com"})
	if calls.Load() != 1 {
		t.Fatal("refill ignored backoff")
	}
	p.reportSuccess(2, false)
	p.mu.Lock()
	_, blocked := p.refillAfter[key]
	p.mu.Unlock()
	if blocked {
		t.Fatal("successful connection did not clear refill cooldown")
	}
	p.scheduleRefill(key, key.targetIP, []string{"example.com"})
	waitForPool(t, p)
	if calls.Load() != 2 {
		t.Fatal("pool did not retry after success")
	}
	if poolRefillBackoff(1) != time.Second || poolRefillBackoff(2) != 2*time.Second || poolRefillBackoff(1000) != time.Hour {
		t.Fatal("incorrect capped exponential backoff")
	}
}

func TestWSPoolResetDiscardsInflightRefill(t *testing.T) {
	p := testWSPool(t, 1)
	started, release := make(chan struct{}), make(chan struct{})
	ws, c := newMemoryWS(nil)
	p.dial = func(context.Context, string, string, time.Duration, string, int, string) (*rawWebSocket, error) {
		close(started)
		<-release
		return ws, nil
	}
	key := poolKey{dc: 2, targetIP: "149.154.167.220"}
	p.scheduleRefill(key, key.targetIP, []string{"example.com"})
	<-started
	p.reset()
	close(release)
	deadline := time.Now().Add(time.Second)
	for !c.closed.Load() {
		if time.Now().After(deadline) {
			t.Fatal("reset leaked pending connection")
		}
		time.Sleep(time.Millisecond)
	}
	p.mu.Lock()
	n := len(p.idle)
	p.mu.Unlock()
	if n != 0 {
		t.Fatal("inflight refill repopulated reset pool")
	}
}

func TestWSPoolNeverReturnsConnectionForPreviousRoute(t *testing.T) {
	p := testWSPool(t, 0)
	ws, _ := newMemoryWS(nil)
	p.idle[poolKey{dc: 2, targetIP: "192.0.2.1"}] = []pooledWS{{ws: ws, created: time.Now()}}
	if got := p.acquire(2, false, "192.0.2.2", []string{"example.com"}); got != nil {
		t.Fatal("returned connection for a different target")
	}
	p.reset()
}

func TestWSPoolFrontingKeepsHostAndSNISeparate(t *testing.T) {
	p := testWSPool(t, 0)
	p.tryFrontingFirst.Store(true)
	var gotHost, gotDomain, gotSNI string
	p.dial = func(_ context.Context, host, domain string, _ time.Duration, _ string, _ int, sni string) (*rawWebSocket, error) {
		gotHost, gotDomain, gotSNI = host, domain, sni
		ws, _ := newMemoryWS(nil)
		return ws, nil
	}
	ws := p.connectOne("192.0.2.1", []string{"kws2.web.telegram.org"})
	if ws == nil || gotHost != "192.0.2.1" || gotDomain != "kws2.web.telegram.org" || gotSNI != frontingSNI {
		t.Fatalf("host=%q domain=%q sni=%q", gotHost, gotDomain, gotSNI)
	}
	if p.stats.connectionsFronting.Load() != 1 {
		t.Fatal("fronted connection was not counted")
	}
	_ = ws.close()
}

func TestWSPoolTriesFrontingAfterDirectTimeout(t *testing.T) {
	p := testWSPool(t, 0)
	var calls []string
	p.dial = func(_ context.Context, _, domain string, _ time.Duration, _ string, _ int, sni string) (*rawWebSocket, error) {
		calls = append(calls, sni)
		if sni == domain {
			return nil, context.DeadlineExceeded
		}
		ws, _ := newMemoryWS(nil)
		return ws, nil
	}
	ws := p.connectOne("192.0.2.1", []string{"kws2.web.telegram.org"})
	if ws == nil || !reflect.DeepEqual(calls, []string{"kws2.web.telegram.org", frontingSNI}) {
		t.Fatalf("fronting fallback calls=%v connection=%v", calls, ws)
	}
	if !p.tryFrontingFirst.Load() {
		t.Fatal("successful fronting did not update preference")
	}
	_ = ws.close()
}

func TestWSFrontingErrorClassificationMatchesUpstream(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"EOF", io.EOF, false},
		{"wrapped EOF", fmt.Errorf("TLS handshake: %w", io.EOF), false},
		{"unexpected EOF", io.ErrUnexpectedEOF, false},
		{"timeout", context.DeadlineExceeded, true},
		{"connection reset", syscall.ECONNRESET, true},
		{"wrapped reset", fmt.Errorf("read: %w", syscall.ECONNRESET), true},
		{"HTTP redirect", &wsHandshakeError{statusCode: 302}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldTryFronting(tc.err); got != tc.want {
				t.Fatalf("shouldTryFronting(%v)=%t, want %t", tc.err, got, tc.want)
			}
		})
	}
}

func TestWSPoolDoesNotAcceptFrontedUpgradeAfterDirectEOF(t *testing.T) {
	p := testWSPool(t, 0)
	calls := 0
	p.dial = func(_ context.Context, _, domain string, _ time.Duration, _ string, _ int, sni string) (*rawWebSocket, error) {
		calls++
		if sni == domain {
			return nil, io.EOF
		}
		ws, _ := newMemoryWS(nil)
		return ws, nil
	}
	if ws := p.connectOne("192.0.2.1", []string{"kws2.web.telegram.org"}); ws != nil {
		_ = ws.close()
		t.Fatal("accepted fronted upgrade after EOF from the original endpoint")
	}
	if calls != 1 || p.stats.connectionsFronting.Load() != 0 {
		t.Fatalf("dial calls=%d fronting=%d", calls, p.stats.connectionsFronting.Load())
	}
}

func TestWSPoolFrontingDisabledPreservesOrdinaryDial(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"timeout", context.DeadlineExceeded},
		{"reset", syscall.ECONNRESET},
		{"success", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newWSPool(context.Background(), 0, 4096, &Stats{}, false)
			// Even a previously successful preference cannot override the option.
			p.tryFrontingFirst.Store(true)
			calls := 0
			p.dial = func(_ context.Context, _, domain string, _ time.Duration, _ string, _ int, sni string) (*rawWebSocket, error) {
				calls++
				if sni != domain {
					t.Error("disabled fronting changed TLS SNI")
				}
				if tc.err != nil {
					return nil, tc.err
				}
				ws, _ := newMemoryWS(nil)
				return ws, nil
			}
			ws := p.connectOne("192.0.2.2", []string{"kws2.web.telegram.org"})
			if (ws != nil) != (tc.err == nil) {
				t.Fatalf("connection=%v direct error=%v", ws, tc.err)
			}
			if ws != nil {
				_ = ws.close()
			}
			if p.connectFronted("192.0.2.2", "kws2.web.telegram.org") != nil {
				t.Fatal("direct fronting helper ignored disabled option")
			}
			if calls != 1 || p.stats.connectionsFronting.Load() != 0 {
				t.Fatalf("calls=%d fronting=%d", calls, p.stats.connectionsFronting.Load())
			}
		})
	}
}

func TestWSPoolFrontingRequiresExplicitOptIn(t *testing.T) {
	if p := newWSPool(context.Background(), 0, 4096, &Stats{}); p.frontingEnabled {
		t.Fatal("omitted fronting option enabled fronting")
	}
}

func TestCFWorkerPoolKeepsProductionAndTestDestinationsSeparate(t *testing.T) {
	p := newCFWorkerPool(context.Background(), 0, 4096, &Stats{})
	ws, _ := newMemoryWS(serverFrame(wsOpPing, nil, true))
	p.idle[cfPoolKey{dc: 2, targetIP: "149.154.167.51"}] = []pooledWorkerWS{{pooledWS: pooledWS{ws: ws, created: time.Now()}, domain: "worker.example"}}
	if got, _ := p.acquire(2, "149.154.167.40", []string{"worker.example"}); got != nil {
		t.Fatal("test DC got a production connection")
	}
	got, domain := p.acquire(2, "149.154.167.51", []string{"worker.example"})
	if got != ws || domain != "worker.example" {
		t.Fatal("production pool miss")
	}
	_ = ws.close()
}

func TestBothWSPoolsDiscardClosedIdleSocketsBeforeCountingHits(t *testing.T) {
	for _, worker := range []bool{false, true} {
		client, server := net.Pipe()
		_ = server.Close()
		ws := &rawWebSocket{conn: client, r: bufio.NewReader(client)}
		stats := &Stats{}
		if worker {
			p := newCFWorkerPool(context.Background(), 0, 4096, stats)
			p.idle[cfPoolKey{dc: 2, targetIP: "192.0.2.2"}] = []pooledWorkerWS{{pooledWS: pooledWS{ws: ws, created: time.Now()}, domain: "worker.example"}}
			if got, _ := p.acquire(2, "192.0.2.2", []string{"worker.example"}); got != nil {
				t.Error("worker pool returned closed socket")
			}
			if stats.cfPoolHits.Load() != 0 || stats.cfPoolMisses.Load() != 1 {
				t.Error("worker closed socket counted as a hit")
			}
		} else {
			p := newWSPool(context.Background(), 0, 4096, stats)
			p.idle[poolKey{dc: 2, targetIP: "192.0.2.2"}] = []pooledWS{{ws: ws, created: time.Now()}}
			if got := p.acquire(2, false, "192.0.2.2", []string{"kws2.web.telegram.org"}); got != nil {
				t.Error("native pool returned closed socket")
			}
			if stats.poolHits.Load() != 0 || stats.poolMisses.Load() != 1 {
				t.Error("native closed socket counted as a hit")
			}
		}
		_ = client.Close()
	}
}

func TestCFWorkerDomainsAndEscapedQuery(t *testing.T) {
	p := newCFWorkerPool(context.Background(), 4, 4096, &Stats{})
	if p.target != 1 {
		t.Fatal("worker pool exceeds per-DC quota")
	}
	domains := p.availableDomains([]string{"b.example", "a.example", "b.example", ""})
	sort.Strings(domains)
	if !reflect.DeepEqual(domains, []string{"a.example", "b.example"}) {
		t.Fatalf("domains=%v", domains)
	}
	u, err := url.Parse(cfWorkerPath(2, "2001:db8::1"))
	if err != nil || u.Path != "/apiws" || u.Query().Get("dst") != "2001:db8::1" || u.Query().Get("dc") != "2" {
		t.Fatalf("worker url=%v %v", u, err)
	}
}

func TestCFWorkerPoolResetDiscardsInflightRefill(t *testing.T) {
	p := newCFWorkerPool(context.Background(), 4, 4096, &Stats{})
	started, release := make(chan struct{}), make(chan struct{})
	ws, conn := newMemoryWS(nil)
	p.dial = func(context.Context, string, string, time.Duration, string, int, string) (*rawWebSocket, error) {
		close(started)
		<-release
		return ws, nil
	}
	p.warmup(map[int]string{2: "149.154.167.51"}, []string{"worker.example"})
	<-started
	p.reset()
	close(release)
	deadline := time.Now().Add(time.Second)
	for !conn.closed.Load() {
		if time.Now().After(deadline) {
			t.Fatal("reset leaked pending worker connection")
		}
		time.Sleep(time.Millisecond)
	}
	p.mu.Lock()
	n := len(p.idle)
	p.mu.Unlock()
	if n != 0 {
		t.Fatal("inflight refill repopulated reset worker pool")
	}
}
