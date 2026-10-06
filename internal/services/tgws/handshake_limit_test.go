package tgws

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestWSHandshakeLimiterBoundsConcurrentSetups(t *testing.T) {
	const limit, attempts = 4, 24
	l := newWSHandshakeLimiter(limit)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := make(chan struct{}, attempts)
	unblock := make(chan struct{})
	var unblockOnce sync.Once
	finish := func() { unblockOnce.Do(func() { close(unblock) }) }
	defer finish()
	var wg sync.WaitGroup
	var active, peak, completed atomic.Int32
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := l.acquire(ctx)
			if err != nil {
				t.Errorf("acquire: %v", err)
				return
			}
			defer release()
			n := active.Add(1)
			defer active.Add(-1)
			for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
			}
			started <- struct{}{}
			select {
			case <-unblock:
			case <-ctx.Done():
			}
			completed.Add(1)
		}()
	}
	for i := 0; i < limit; i++ {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("setups did not fill available slots")
		}
	}
	select {
	case <-started:
		t.Fatal("setup started while every slot was occupied")
	case <-time.After(20 * time.Millisecond):
	}
	finish()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("queued setups did not finish after releasing slots")
	}
	if peak.Load() != limit || completed.Load() != attempts || len(l.slots) != 0 {
		t.Fatalf("peak=%d completed=%d occupied=%d", peak.Load(), completed.Load(), len(l.slots))
	}
}

func TestWSHandshakeLimiterQueuedContextCancellation(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			l := newWSHandshakeLimiter(1)
			release, err := l.acquire(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			var ctx context.Context
			var cancel context.CancelFunc
			want := context.Canceled
			if mode == "deadline" {
				ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
				want = context.DeadlineExceeded
			} else {
				ctx, cancel = context.WithCancel(context.Background())
			}
			defer cancel()
			waiting := make(chan struct{})
			result := make(chan error, 1)
			go func() {
				close(waiting)
				r, err := l.acquire(ctx)
				if r != nil {
					r()
				}
				result <- err
			}()
			<-waiting
			if mode == "cancel" {
				cancel()
			}
			select {
			case err := <-result:
				if !errors.Is(err, want) {
					t.Fatalf("acquire error=%v, want %v", err, want)
				}
			case <-time.After(time.Second):
				t.Fatal("canceled setup remained queued")
			}
			if len(l.slots) != 1 {
				t.Fatalf("canceled waiter changed occupied slots: %d", len(l.slots))
			}
			release()
			checkCtx, checkCancel := context.WithTimeout(context.Background(), time.Second)
			defer checkCancel()
			nextRelease, err := l.acquire(checkCtx)
			if err != nil {
				t.Fatalf("released slot unavailable: %v", err)
			}
			nextRelease()
		})
	}
}

func TestWSHandshakeLimiterPreCanceledContextDoesNotOccupySlot(t *testing.T) {
	l := newWSHandshakeLimiter(1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 100; i++ {
		release, err := l.acquire(ctx)
		if release != nil || !errors.Is(err, context.Canceled) || len(l.slots) != 0 {
			t.Fatalf("release=%t error=%v occupied=%d", release != nil, err, len(l.slots))
		}
	}
}

// Cancel on the post-acquisition check to reproduce cancellation becoming
// ready together with a free slot without depending on goroutine timing.
type cancelOnAcquisitionContext struct {
	context.Context
	cancel context.CancelFunc
	checks int
}

func (c *cancelOnAcquisitionContext) Err() error {
	c.checks++
	if c.checks == 2 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestWSHandshakeLimiterCancellationAfterTakingSlotReleasesIt(t *testing.T) {
	l := newWSHandshakeLimiter(1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	release, err := l.acquire(&cancelOnAcquisitionContext{Context: ctx, cancel: cancel})
	if release != nil || !errors.Is(err, context.Canceled) || len(l.slots) != 0 {
		t.Fatalf("release=%t error=%v occupied=%d", release != nil, err, len(l.slots))
	}
}

func TestWSHandshakeLimiterReleaseIsIdempotent(t *testing.T) {
	l := newWSHandshakeLimiter(1)
	release, err := l.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	release()
	nextRelease, err := l.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer nextRelease()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); release() }()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("duplicate release blocked")
	}
	if len(l.slots) != 1 {
		t.Fatalf("duplicate release released another setup's slot: %d", len(l.slots))
	}
}

func TestWSHandshakeQueueErrorsPreserveCauseAndClassification(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		err := fmt.Errorf("WS setup: %w", &wsHandshakeQueueError{cause: cause})
		if !errors.Is(err, cause) || !isWSHandshakeQueueError(err) {
			t.Fatalf("queue error lost its classification or cause: %v", err)
		}
	}
	if isWSHandshakeQueueError(context.DeadlineExceeded) {
		t.Fatal("ordinary network timeout lost its classification")
	}
}

func TestQueuedWSSetupDoesNotDialAndAllowsRetry(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			var hits atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				conn, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Errorf("upgrade server: %v", err)
					return
				}
				defer conn.Close()
				_, _ = io.WriteString(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
				_ = rw.Flush()
			}))
			defer server.Close()
			target := strings.TrimPrefix(server.URL, "http://")
			var held []func()
			for i := 0; i < cap(wsHandshakes.slots); i++ {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				release, err := wsHandshakes.acquire(ctx)
				cancel()
				if err != nil {
					t.Fatalf("fill handshake budget: %v", err)
				}
				held = append(held, release)
				defer release()
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel" {
				stop := time.AfterFunc(10*time.Millisecond, cancel)
				defer stop.Stop()
			}
			ws, gotError := connectWSWithTLSConfig(ctx, target, "kws2.web.telegram.org", 20*time.Millisecond, wsPath, 4096, "kws2.web.telegram.org", false, nil)
			if ws != nil {
				_ = ws.close()
				t.Fatal("setup passed a fully occupied handshake budget")
			}
			cause := context.Canceled
			if mode == "deadline" {
				cause = context.DeadlineExceeded
			}
			if !isWSHandshakeQueueError(gotError) || !errors.Is(gotError, cause) {
				t.Fatalf("wrong queued failure: %v", gotError)
			}
			if hits.Load() != 0 {
				t.Fatalf("local queue failure reached the network: hits=%d", hits.Load())
			}
			for _, release := range held {
				release()
			}
			ws, gotError = connectWSWithTLSConfig(context.Background(), target, "kws2.web.telegram.org", time.Second, wsPath, 4096, "kws2.web.telegram.org", false, nil)
			if ws == nil {
				t.Fatalf("healthy endpoint unavailable after releasing budget: %v", gotError)
			}
			_ = ws.close()
			if hits.Load() != 1 || len(wsHandshakes.slots) != 0 {
				t.Fatalf("retry hits=%d occupied slots=%d", hits.Load(), len(wsHandshakes.slots))
			}
		})
	}
}

func TestWSPoolLocalQueueFailureKeepsShortRetry(t *testing.T) {
	for _, frontedFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("fronted_first=%t", frontedFirst), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := newWSPool(ctx, 1, 4096, &Stats{}, true)
			key := poolKey{dc: 2, targetIP: "192.0.2.2"}
			p.failures[key] = 3 // Earlier real failures remain recorded separately.
			var calls atomic.Int32
			p.dial = func(context.Context, string, string, time.Duration, string, int, string) (*rawWebSocket, error) {
				calls.Add(1)
				return nil, &wsHandshakeQueueError{cause: context.DeadlineExceeded}
			}
			for i := 0; i < 5; i++ {
				p.tryFrontingFirst.Store(frontedFirst)
				p.refill(key, key.targetIP, wsDomainsFor(2, false), 0)
				p.mu.Lock()
				failures, wait := p.failures[key], time.Until(p.refillAfter[key])
				p.mu.Unlock()
				if failures != 3 || wait <= 0 || wait > time.Second {
					t.Fatalf("local pressure changed network backoff: failures=%d wait=%s", failures, wait)
				}
			}
			if calls.Load() != 5 || p.stats.connectionsFronting.Load() != 0 {
				t.Fatalf("queue failure retried another SNI: dials=%d fronted=%d", calls.Load(), p.stats.connectionsFronting.Load())
			}
		})
	}
}

func TestWSPoolMixedQueueAndNetworkFailuresRetainNetworkBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := newWSPool(ctx, 2, 4096, &Stats{})
	key := poolKey{dc: 2, targetIP: "192.0.2.2"}
	p.failures[key] = 3
	var calls atomic.Int32
	p.dial = func(context.Context, string, string, time.Duration, string, int, string) (*rawWebSocket, error) {
		if calls.Add(1) == 1 {
			return nil, &wsHandshakeQueueError{cause: context.DeadlineExceeded}
		}
		return nil, errors.New("upstream refused connection")
	}
	p.refill(key, key.targetIP, wsDomainsFor(2, false), 0)
	p.mu.Lock()
	defer p.mu.Unlock()
	wait := time.Until(p.refillAfter[key])
	if p.failures[key] != 4 || wait <= 7*time.Second || wait > 8*time.Second || calls.Load() != 2 {
		t.Fatalf("real failure lost its backoff: failures=%d wait=%s dials=%d", p.failures[key], wait, calls.Load())
	}
}

func TestWSPoolNetworkFailureBeforeQueuedFrontingRetainsNetworkBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := newWSPool(ctx, 1, 4096, &Stats{}, true)
	key := poolKey{dc: 2, targetIP: "192.0.2.2"}
	p.failures[key] = 3
	var calls atomic.Int32
	p.dial = func(context.Context, string, string, time.Duration, string, int, string) (*rawWebSocket, error) {
		if calls.Add(1) == 1 {
			return nil, context.DeadlineExceeded // This attempt actually dialed.
		}
		return nil, &wsHandshakeQueueError{cause: context.DeadlineExceeded}
	}
	p.refill(key, key.targetIP, wsDomainsFor(2, false), 0)
	p.mu.Lock()
	defer p.mu.Unlock()
	wait := time.Until(p.refillAfter[key])
	if p.failures[key] != 4 || wait <= 7*time.Second || wait > 8*time.Second || calls.Load() != 2 {
		t.Fatalf("queued retry hid original network failure: failures=%d wait=%s dials=%d", p.failures[key], wait, calls.Load())
	}
}

func TestCFWorkerPoolQueueFailureStopsDomainRetries(t *testing.T) {
	p := newCFWorkerPool(context.Background(), 1, 4096, &Stats{})
	var calls atomic.Int32
	p.dial = func(context.Context, string, string, time.Duration, string, int, string) (*rawWebSocket, error) {
		calls.Add(1)
		return nil, &wsHandshakeQueueError{cause: context.DeadlineExceeded}
	}
	key := cfPoolKey{dc: 2, targetIP: "192.0.2.2"}
	p.refill(key, []string{"one.example", "two.example", "three.example"}, 0)
	if calls.Load() != 1 || len(p.idle[key]) != 0 {
		t.Fatalf("local pressure retried Worker domains: dials=%d ready=%d", calls.Load(), len(p.idle[key]))
	}
}

func TestWSQueueWaitDoesNotConsumeNetworkUpgradeTimeout(t *testing.T) {
	const timeout = 200 * time.Millisecond
	const queueWait = 150 * time.Millisecond
	const responseDelay = 120 * time.Millisecond
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("upgrade server: %v", err)
			return
		}
		defer conn.Close()
		timer := time.NewTimer(responseDelay)
		defer timer.Stop()
		<-timer.C
		_, _ = io.WriteString(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = rw.Flush()
	}))
	defer server.Close()
	var held []func()
	for i := 0; i < cap(wsHandshakes.slots); i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		release, err := wsHandshakes.acquire(ctx)
		cancel()
		if err != nil {
			t.Fatalf("fill handshake budget: %v", err)
		}
		held = append(held, release)
		defer release()
	}
	started := time.Now()
	releaseTimer := time.AfterFunc(queueWait, func() {
		for _, release := range held {
			release()
		}
	})
	defer releaseTimer.Stop()
	target := strings.TrimPrefix(server.URL, "http://")
	ws, gotError := connectWSWithTLSConfig(context.Background(), target, "kws2.web.telegram.org", timeout, wsPath, 4096, "kws2.web.telegram.org", false, nil)
	if ws == nil {
		t.Fatalf("local queue exhausted a healthy endpoint's network timeout: %v", gotError)
	}
	defer ws.close()
	if elapsed := time.Since(started); elapsed <= timeout {
		t.Fatalf("fixture did not consume the former shared timeout: elapsed=%s", elapsed)
	}
	if hits.Load() != 1 || len(wsHandshakes.slots) != 0 {
		t.Fatalf("hits=%d occupied slots=%d", hits.Load(), len(wsHandshakes.slots))
	}
}
