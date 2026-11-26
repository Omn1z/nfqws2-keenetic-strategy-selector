package tgws

import (
	"bufio"
	"context"
	"errors"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestWSPoolHitKeepsFailedRefillBackoff(t *testing.T) {
	p := testWSPool(t, 1)
	key := poolKey{dc: 2, targetIP: "192.0.2.2"}
	ws, _ := newMemoryWS(serverFrame(wsOpPing, nil, true))
	after := time.Now().Add(time.Minute)
	p.idle[key] = []pooledWS{{ws: ws, created: time.Now()}}
	p.failures[key], p.refillAfter[key] = 4, after
	if got := p.acquire(2, false, key.targetIP, wsDomainsFor(2, false)); got != ws {
		t.Fatal("expected warm socket")
	}
	_ = ws.close()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failures[key] != 4 || !p.refillAfter[key].Equal(after) || len(p.refilling) != 0 {
		t.Fatal("an old warm socket reset failed refill backoff")
	}
}

func TestWSPoolRotationRefillsPeerClosedIdleSocket(t *testing.T) {
	p := testWSPool(t, 1)
	key := poolKey{dc: 2, targetIP: "192.0.2.2"}
	client, server := net.Pipe()
	defer client.Close()
	_ = server.Close()
	stale := &rawWebSocket{conn: client, r: bufio.NewReader(client)}
	p.idle[key] = []pooledWS{{ws: stale, created: time.Now()}}
	p.domains[key] = wsDomainsFor(2, false)
	var calls atomic.Int32
	p.dial = func(context.Context, string, string, time.Duration, string, int, string) (*rawWebSocket, error) {
		calls.Add(1)
		ws, _ := newMemoryWS(serverFrame(wsOpPing, nil, true))
		return ws, nil
	}
	p.rotate(time.Now())
	waitForPool(t, p)
	p.mu.Lock()
	defer p.mu.Unlock()
	if calls.Load() != 1 || len(p.idle[key]) != 1 || p.idle[key][0].ws == stale || !stale.isClosed() {
		t.Fatal("peer-closed idle socket was retained until the next client")
	}
}

type heldIdleProbeConn struct {
	net.Conn
	once    sync.Once
	started chan struct{}
	release chan struct{}
}

func (c *heldIdleProbeConn) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.started); <-c.release })
	return c.Conn.Read(p)
}

func TestWSPoolBackgroundProbeDoesNotHoldMutexOrRaceBorrow(t *testing.T) {
	p := testWSPool(t, 1)
	key := poolKey{dc: 2, targetIP: "192.0.2.2"}
	other := poolKey{dc: 4, targetIP: "192.0.2.4"}
	client, server := net.Pipe()
	defer server.Close()
	conn := &heldIdleProbeConn{Conn: client, started: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(conn.release) }) }
	defer release()
	ws := &rawWebSocket{conn: conn, r: bufio.NewReader(conn)}
	ready, _ := newMemoryWS(serverFrame(wsOpPing, nil, true))
	p.idle[key] = []pooledWS{{ws: ws, created: time.Now()}}
	p.idle[other] = []pooledWS{{ws: ready, created: time.Now()}}
	p.domains[key], p.domains[other] = wsDomainsFor(2, false), wsDomainsFor(4, false)
	p.refillAfter[key], p.refillAfter[other] = time.Now().Add(time.Minute), time.Now().Add(time.Minute)
	rotated := make(chan struct{})
	go func() { p.rotate(time.Now()); close(rotated) }()
	select {
	case <-conn.started:
	case <-time.After(time.Second):
		t.Fatal("probe did not start")
	}
	if !p.mu.TryLock() {
		t.Fatal("background network probe held pool mutex")
	}
	p.mu.Unlock()
	if got := p.acquire(4, false, other.targetIP, p.domains[other]); got != ready {
		t.Fatal("unrelated ready bucket blocked by background probe")
	}
	_ = ready.close()
	borrowed := make(chan *rawWebSocket, 1)
	go func() { borrowed <- p.acquire(2, false, key.targetIP, wsDomainsFor(2, false)) }()
	select {
	case <-borrowed:
		t.Fatal("socket escaped while background reader owned it")
	case <-time.After(10 * time.Millisecond):
	}
	release()
	select {
	case got := <-borrowed:
		if got != ws {
			t.Fatal("healthy socket lost after probe")
		}
		_ = got.close()
	case <-time.After(time.Second):
		t.Fatal("borrow did not resume after probe")
	}
	<-rotated
}

func TestWSPoolMaintenanceWakesAtRefillBackoffDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := newWSPool(ctx, 1, 4096, &Stats{})
	key := poolKey{dc: 2, targetIP: "192.0.2.2"}
	var calls atomic.Int32
	ready := make(chan struct{})
	p.dial = func(context.Context, string, string, time.Duration, string, int, string) (*rawWebSocket, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("temporary outage")
		}
		close(ready)
		ws, _ := newMemoryWS(serverFrame(wsOpPing, nil, true))
		return ws, nil
	}
	p.scheduleRefill(key, key.targetIP, wsDomainsFor(2, false))
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("one-second refill cooldown waited for five-second rotation tick")
	}
	waitForPool(t, p)
}

func TestWSPoolDisabledNeverBorrowsOrRefills(t *testing.T) {
	p := testWSPool(t, 0)
	key := poolKey{dc: 2, targetIP: "192.0.2.2"}
	ws, _ := newMemoryWS(serverFrame(wsOpPing, nil, true))
	p.idle[key] = []pooledWS{{ws: ws, created: time.Now()}}
	var calls atomic.Int32
	p.dial = func(context.Context, string, string, time.Duration, string, int, string) (*rawWebSocket, error) {
		calls.Add(1)
		return nil, errors.New("unexpected dial")
	}
	if p.acquire(2, false, key.targetIP, wsDomainsFor(2, false)) != nil {
		t.Fatal("disabled pool returned an old socket")
	}
	p.warmup(map[int]string{2: key.targetIP})
	if calls.Load() != 0 || len(p.refilling) != 0 {
		t.Fatal("disabled pool dialed")
	}
	p.reset()
}

func TestWSPoolTestEndpointGetsSeparateBucketAndPath(t *testing.T) {
	p := testWSPool(t, 1)
	key := poolKey{dc: 2, targetIP: "192.0.2.2"}
	production, _ := newMemoryWS(serverFrame(wsOpPing, nil, true))
	p.idle[key] = []pooledWS{{ws: production, created: time.Now()}}
	p.refillAfter[key] = time.Now().Add(time.Hour)
	paths := make(chan string, 2)
	p.dial = func(_ context.Context, _, _ string, _ time.Duration, path string, _ int, _ string) (*rawWebSocket, error) {
		paths <- path
		ws, _ := newMemoryWS(serverFrame(wsOpPing, nil, true))
		return ws, nil
	}
	if p.acquire(2, false, key.targetIP, wsDomainsFor(2, false), true) != nil {
		t.Fatal("test connection consumed production socket")
	}
	waitForPool(t, p)
	if path := <-paths; path != wsTestPath {
		t.Fatalf("test path=%q", path)
	}
	key.test = true
	p.mu.Lock()
	p.refillAfter[key] = time.Now().Add(time.Hour)
	p.mu.Unlock()
	testWS := p.acquire(2, false, key.targetIP, wsDomainsFor(2, false), true)
	if testWS == nil || testWS == production {
		t.Fatal("missing separate test socket")
	}
	_ = testWS.close()
	if p.acquire(2, false, key.targetIP, wsDomainsFor(2, false)) != production {
		t.Fatal("test refill altered production bucket")
	}
	_ = production.close()
}

func TestWSPoolPublishesFastResultBeforeSlowSibling(t *testing.T) {
	p := testWSPool(t, 2)
	key := poolKey{dc: 2, targetIP: "192.0.2.2"}
	release := make(chan struct{})
	var calls atomic.Int32
	p.dial = func(ctx context.Context, _, _ string, _ time.Duration, _ string, _ int, _ string) (*rawWebSocket, error) {
		if calls.Add(1) == 2 {
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		ws, _ := newMemoryWS(serverFrame(wsOpPing, nil, true))
		return ws, nil
	}
	p.scheduleRefill(key, key.targetIP, wsDomainsFor(2, false))
	deadline := time.Now().Add(time.Second)
	for {
		p.mu.Lock()
		n := len(p.idle[key])
		p.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			close(release)
			t.Fatal("ready socket was held until all dials completed")
		}
		time.Sleep(time.Millisecond)
	}
	ws := p.acquire(2, false, key.targetIP, wsDomainsFor(2, false))
	if ws == nil {
		close(release)
		t.Fatal("ready result was not borrowable")
	}
	_ = ws.close()
	close(release)
	waitForPool(t, p)
	p.reset()
}

func TestWSPoolTriesEveryConfiguredModeAndMediaEndpoint(t *testing.T) {
	for _, frontedFirst := range []bool{false, true} {
		p := testWSPool(t, 0)
		p.tryFrontingFirst.Store(frontedFirst)
		var calls []string
		p.dial = func(_ context.Context, _, domain string, _ time.Duration, _ string, _ int, sni string) (*rawWebSocket, error) {
			calls = append(calls, domain+"|"+sni)
			if len(calls) == 4 {
				ws, _ := newMemoryWS(nil)
				return ws, nil
			}
			return nil, errors.New("failed handshake")
		}
		domains := wsDomainsFor(2, true)
		ws := p.connectOne("192.0.2.2", domains)
		if ws == nil {
			t.Fatal("did not try all endpoints")
		}
		_ = ws.close()
		var want []string
		for _, domain := range domains {
			if frontedFirst {
				want = append(want, domain+"|"+frontingSNI, domain+"|"+domain)
			} else {
				want = append(want, domain+"|"+domain, domain+"|"+frontingSNI)
			}
		}
		if !reflect.DeepEqual(calls, want) {
			t.Fatalf("calls=%v want=%v", calls, want)
		}
	}
	if got := wsDomainsFor(2, false); !reflect.DeepEqual(got, []string{"kws2.web.telegram.org"}) {
		t.Fatalf("ordinary connection should avoid media endpoint: %v", got)
	}
}
