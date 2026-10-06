package tgws

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func cfH2PoolFixture(t *testing.T, handler http.HandlerFunc) *cfH2Pool {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	bal := newDomainBalancer()
	bal.updatePool([]string{"test.invalid"})
	p := newCFH2Pool(context.Background(), bal, &Stats{})
	p.newLane = func(string) *cfH2Lane {
		return newCFH2Lane(p.ctx, strings.TrimPrefix(server.URL, "https://"), p.stats, &tls.Config{RootCAs: roots})
	}
	t.Cleanup(p.close)
	return p
}

func TestCFH2PoolConcurrentSetupAndShutdown(t *testing.T) {
	var preflights atomic.Int64
	p := cfH2PoolFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			preflights.Add(1)
			return
		}
		<-r.Context().Done()
	})
	var wg sync.WaitGroup
	channels := make(chan *cfH2Channel, 16)
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := p.open(context.Background(), 2, "test")
			if err != nil || c == nil {
				t.Errorf("open=%v %v", c, err)
				return
			}
			channels <- c
		}()
	}
	wg.Wait()
	close(channels)
	for c := range channels {
		if err := c.send(context.Background(), cfH2Packet(1), false); err != nil {
			t.Fatal(err)
		}
	}
	if preflights.Load() != 1 || p.stats.h2TCPConnections.Load() != 1 {
		t.Fatalf("setup was duplicated %d/%d", preflights.Load(), p.stats.h2TCPConnections.Load())
	}
	done := make(chan struct{})
	go func() { p.close(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pool close hung with pending HTTP streams")
	}
	if _, err := p.open(context.Background(), 2, "after close"); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("pool reopened: %v", err)
	}
}

func TestCFH2PoolFailedPreflightCooldownAndWSFallback(t *testing.T) {
	var preflights atomic.Int64
	p := cfH2PoolFixture(t, func(w http.ResponseWriter, r *http.Request) { preflights.Add(1); w.WriteHeader(502) })
	for range 2 {
		if c, err := p.open(context.Background(), 2, "test"); c != nil || err != nil {
			t.Fatalf("expected WS fallback, got %v %v", c, err)
		}
	}
	if preflights.Load() != 1 {
		t.Fatal("failed endpoint repeatedly handshaken")
	}
	if c, err := p.open(context.Background(), 999, "unsupported"); c != nil || err != nil {
		t.Fatal("unsupported DC did not fall back")
	}
	p.mu.Lock()
	p.failedUntil["kws2.test.invalid"] = time.Now().Add(-time.Second)
	p.mu.Unlock()
	if _, err := p.open(context.Background(), 2, "retry"); err != nil {
		t.Fatal(err)
	}
	if preflights.Load() != 2 {
		t.Fatal("expired cooldown never retried")
	}
}

func TestCFH2PoolCancellationDuringPreflight(t *testing.T) {
	started := make(chan struct{})
	p := cfH2PoolFixture(t, func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() })
	done := make(chan error, 1)
	go func() { _, err := p.open(context.Background(), 2, "pending"); done <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("preflight not started")
	}
	p.close()
	select {
	case err := <-done:
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("pending open=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not cancel preflight")
	}
}

func TestCFH2UsesSharedHandshakeLimitWithoutCoolingHealthyLane(t *testing.T) {
	p := cfH2PoolFixture(t, func(w http.ResponseWriter, r *http.Request) {})
	old := wsHandshakes
	wsHandshakes = newWSHandshakeLimiter(1)
	t.Cleanup(func() { wsHandshakes = old })
	release, err := wsHandshakes.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	c, err := p.open(ctx, 2, "queued")
	cancel()
	release()
	if c != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("occupied handshake bypassed: %v %v", c, err)
	}
	p.mu.Lock()
	failures, retries := len(p.failedUntil), len(p.setupRetry)
	p.mu.Unlock()
	if failures != 0 || retries != 0 {
		t.Fatal("local queue pressure cooled healthy endpoint")
	}
	c, err = p.open(context.Background(), 2, "free")
	if c == nil || err != nil {
		t.Fatalf("released handshake still blocked: %v %v", c, err)
	}
}

func TestCFH2PrunesObsoleteIdleDomainsWithoutDroppingActiveChannels(t *testing.T) {
	p := cfH2PoolFixture(t, func(w http.ResponseWriter, r *http.Request) {})
	c, err := p.open(context.Background(), 2, "live")
	if err != nil || c == nil {
		t.Fatalf("open: %v", err)
	}
	p.prune([]string{"new.invalid"})
	p.mu.Lock()
	count := len(p.lanes)
	p.mu.Unlock()
	if count != 1 {
		t.Fatal("active old domain was removed")
	}
	c.close()
	p.prune([]string{"new.invalid"})
	p.mu.Lock()
	count = len(p.lanes)
	p.mu.Unlock()
	if count != 0 {
		t.Fatal("idle old domain remained in pool")
	}
}

func TestCFH2Preflight404IsEndpointFailureNotNativeTransportError(t *testing.T) {
	p := cfH2PoolFixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })
	lane := p.newLane("test.invalid")
	defer lane.close()
	err := lane.preflight(context.Background())
	var native *mtprotoTransportError
	if err == nil || errors.As(err, &native) {
		t.Fatalf("HEAD 404 incorrectly delivered to native client: %v", err)
	}
	c, err := p.open(context.Background(), 2, "HEAD 404")
	if c != nil || err != nil {
		t.Fatalf("HEAD 404 did not select WS fallback: %v %v", c, err)
	}
}

func TestCFH2PreflightCompletionDoesNotRestoreRemovedDomain(t *testing.T) {
	started, finish := make(chan struct{}), make(chan struct{})
	p := cfH2PoolFixture(t, func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-finish:
		case <-r.Context().Done():
		}
	})
	result := make(chan *cfH2Channel, 1)
	go func() {
		c, err := p.open(context.Background(), 2, "rotating")
		if err != nil {
			t.Errorf("open: %v", err)
		}
		result <- c
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("preflight not started")
	}
	p.bal.updatePool([]string{"replacement.invalid"})
	close(finish)
	var c *cfH2Channel
	select {
	case c = <-result:
	case <-time.After(time.Second):
		t.Fatal("preflight stuck")
	}
	if c == nil {
		t.Fatal("valid established channel was lost during refresh")
	}
	if domains := p.bal.candidatesFor(2); len(domains) != 1 || domains[0] != "replacement.invalid" {
		t.Fatalf("old domain restored: %v", domains)
	}
	c.close()
	p.prune(p.bal.candidatesFor(2))
	p.mu.Lock()
	count := len(p.lanes)
	p.mu.Unlock()
	if count != 0 {
		t.Fatal("completed old origin was not pruned after disconnect")
	}
}

func TestCFH2ConcurrentCloseWaitsForFirstShutdown(t *testing.T) {
	p := cfH2PoolFixture(t, func(w http.ResponseWriter, r *http.Request) {})
	c, err := p.open(context.Background(), 2, "closing")
	if err != nil || c == nil {
		t.Fatalf("open: %v", err)
	}
	// Hold one worker so both close callers must wait for its completion.
	c.wg.Add(1)
	var release sync.Once
	finish := func() { release.Do(c.wg.Done) }
	defer finish()
	first, second := make(chan struct{}), make(chan struct{})
	go func() { p.close(); close(first) }()
	select {
	case <-c.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("first shutdown not started")
	}
	go func() { p.close(); close(second) }()
	select {
	case <-second:
		t.Fatal("second close returned with live worker")
	case <-time.After(20 * time.Millisecond):
	}
	finish()
	for _, done := range []chan struct{}{first, second} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("shutdown did not join worker")
		}
	}
}

func TestCFH2CanceledLookupDoesNotReuseLiveLane(t *testing.T) {
	p := cfH2PoolFixture(t, func(w http.ResponseWriter, r *http.Request) {})
	c, err := p.open(context.Background(), 2, "ready")
	if err != nil || c == nil {
		t.Fatalf("open: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if lane, err := p.getLane(ctx, "kws2.test.invalid"); lane != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled lookup reused live lane: %v %v", lane, err)
	}
}

func TestCFH2LaneShutdownCancelsHandshakeQueue(t *testing.T) {
	old := wsHandshakes
	wsHandshakes = newWSHandshakeLimiter(1)
	defer func() { wsHandshakes = old }()
	release, err := wsHandshakes.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	lane := newCFH2Lane(context.Background(), "unused.invalid", &Stats{}, nil)
	defer lane.close()
	done := make(chan error, 1)
	go func() {
		_, err := lane.transport.DialTLSContext(context.Background(), "tcp", "unused.invalid:443")
		done <- err
	}()
	lane.close()
	select {
	case err := <-done:
		if !isWSHandshakeQueueError(err) || !errors.Is(err, context.Canceled) {
			t.Fatalf("queue close = %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("lane shutdown left the TLS dial waiting for a handshake slot")
	}
}
