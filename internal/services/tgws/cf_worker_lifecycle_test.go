package tgws

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func waitCFWorkerSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatal(description)
	}
}

func TestCFWorkerPoolCloseCancelsAndJoinsLateDialResults(t *testing.T) {
	p := newCFWorkerPool(context.Background(), 1, 4096, &Stats{})
	defer p.close()
	idle, idleConn := newMemoryWS(nil)
	late, lateConn := newMemoryWS(nil)
	p.idle[cfPoolKey{dc: 2, targetIP: "192.0.2.2"}] = []pooledWorkerWS{{pooledWS: pooledWS{ws: idle, created: time.Now()}, domain: "idle.example"}}
	started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	var calls atomic.Int32
	p.dial = func(ctx context.Context, _, _ string, _ time.Duration, _ string, _ int, _ string) (*rawWebSocket, error) {
		calls.Add(1)
		close(started)
		<-ctx.Done()
		close(canceled)
		<-release // emulate a dial returning a socket despite cancellation
		return late, nil
	}
	p.warmup(map[int]string{4: "192.0.2.4"}, []string{"late.example"})
	waitCFWorkerSignal(t, started, "worker refill did not start")
	first, second := make(chan struct{}), make(chan struct{})
	go func() { p.close(); close(first) }()
	waitCFWorkerSignal(t, canceled, "pool close did not cancel worker refill")
	go func() { p.close(); close(second) }()
	select {
	case <-first:
		t.Fatal("first close returned before late dial cleanup")
	case <-second:
		t.Fatal("concurrent close returned before first shutdown completed")
	default:
	}
	close(release)
	waitCFWorkerSignal(t, first, "first close did not finish")
	waitCFWorkerSignal(t, second, "concurrent close did not join shutdown")
	if !idleConn.closed.Load() || !lateConn.closed.Load() {
		t.Fatal("shutdown leaked idle or late-returned socket")
	}
	p.mu.Lock()
	idleCount, refillCount, cancelCount := len(p.idle), len(p.refilling), len(p.refillCancels)
	p.mu.Unlock()
	if idleCount != 0 || refillCount != 0 || cancelCount != 0 {
		t.Fatalf("shutdown retained work: idle=%d refill=%d cancel=%d", idleCount, refillCount, cancelCount)
	}
	p.reset()
	p.warmup(map[int]string{4: "192.0.2.4"}, []string{"late.example"})
	if ws, _ := p.acquire(4, "192.0.2.4", []string{"late.example"}); ws != nil || calls.Load() != 1 {
		t.Fatal("closed worker pool reopened")
	}
}

func TestCFWorkerPoolResetCancelsOnlyOldGenerationAndRemainsReusable(t *testing.T) {
	p := newCFWorkerPool(context.Background(), 1, 4096, &Stats{})
	defer p.close()
	old, oldConn := newMemoryWS(nil)
	ready, _ := newMemoryWS(serverFrame(wsOpBinary, []byte("ready"), true))
	defer ready.close()
	idle, idleConn := newMemoryWS(nil)
	p.idle[cfPoolKey{dc: 4, targetIP: "192.0.2.4"}] = []pooledWorkerWS{{pooledWS: pooledWS{ws: idle, created: time.Now()}, domain: "idle.example"}}
	started, canceled, releaseOld, startedNew, releaseNew := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-releaseOld:
		default:
			close(releaseOld)
		}
		select {
		case <-releaseNew:
		default:
			close(releaseNew)
		}
	}()
	var calls atomic.Int32
	p.dial = func(ctx context.Context, _, _ string, _ time.Duration, _ string, _ int, _ string) (*rawWebSocket, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-ctx.Done()
			close(canceled)
			<-releaseOld
			return old, nil
		}
		close(startedNew)
		<-releaseNew
		return ready, nil
	}
	key := cfPoolKey{dc: 2, targetIP: "192.0.2.2"}
	p.scheduleRefill(key, []string{"worker.example"})
	waitCFWorkerSignal(t, started, "initial worker refill did not start")
	p.reset()
	waitCFWorkerSignal(t, canceled, "reset did not cancel the old refill")
	if !idleConn.closed.Load() {
		t.Fatal("reset returned before closing the idle socket")
	}
	p.scheduleRefill(key, []string{"worker.example"})
	waitCFWorkerSignal(t, startedNew, "reset permanently disabled worker refill")
	close(releaseOld)
	deadline := time.Now().Add(time.Second)
	for !oldConn.closed.Load() {
		if time.Now().After(deadline) {
			t.Fatal("old refill leaked a late socket")
		}
		time.Sleep(time.Millisecond)
	}
	p.mu.Lock()
	active, present := p.refilling[key]
	current := p.generation
	p.mu.Unlock()
	if !present || active != current {
		t.Fatal("old refill erased replacement generation's tracking")
	}
	close(releaseNew)
	deadline = time.Now().Add(time.Second)
	for {
		p.mu.Lock()
		published := len(p.idle[key]) == 1 && len(p.refilling) == 0
		p.mu.Unlock()
		if published {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("replacement refill did not publish")
		}
		time.Sleep(time.Millisecond)
	}
	// Avoid another background refill while checking ownership transfer.
	p.mu.Lock()
	p.target = 0
	p.mu.Unlock()
	if ws, domain := p.acquire(2, "192.0.2.2", []string{"worker.example"}); ws != ready || domain != "worker.example" {
		t.Fatal("new generation's idle socket was lost")
	}
}

func TestManagerStopWaitsForCFWorkerPoolShutdown(t *testing.T) {
	m, _ := localTestManager(t)
	p := newCFWorkerPool(context.Background(), 1, 4096, &Stats{})
	started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	late, conn := newMemoryWS(nil)
	p.dial = func(ctx context.Context, _, _ string, _ time.Duration, _ string, _ int, _ string) (*rawWebSocket, error) {
		close(started)
		<-ctx.Done()
		close(canceled)
		<-release
		return late, nil
	}
	m.mu.Lock()
	original := m.workerPool
	m.workerPool = p
	m.mu.Unlock()
	original.close()
	p.scheduleRefill(cfPoolKey{dc: 2, targetIP: "192.0.2.2"}, []string{"worker.example"})
	waitCFWorkerSignal(t, started, "manager fixture refill did not start")
	stopped := make(chan struct{})
	go func() { m.Stop(); close(stopped) }()
	waitCFWorkerSignal(t, canceled, "manager did not close its worker pool")
	select {
	case <-stopped:
		t.Fatal("manager stop returned while pool cleanup remained pending")
	default:
	}
	close(release)
	waitCFWorkerSignal(t, stopped, "manager stop did not join worker cleanup")
	if !conn.closed.Load() {
		t.Fatal("manager shutdown leaked late worker socket")
	}
}
