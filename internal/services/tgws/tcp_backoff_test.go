package tgws

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestTCPFallbackFailureBackoffCapsAndSeparatesEndpoints(t *testing.T) {
	b := newTCPFallbackBackoff()
	now := time.Now()
	b.now = func() time.Time { return now }
	var calls int
	b.dial = func(context.Context, string, string) (net.Conn, error) {
		calls++
		return nil, errors.New("unavailable")
	}
	for i := 1; i <= 10; i++ {
		if _, err := prepareTCPFallback(context.Background(), "192.0.2.2:443", nil, b); err == nil || errors.Is(err, errTCPFallbackDeferred) {
			t.Fatalf("probe %d error=%v", i, err)
		}
		state := b.endpoints["192.0.2.2:443"]
		want := min(30*time.Second*time.Duration(1<<min(i-1, 7)), time.Hour)
		if state.retryAfter.Sub(now) != want || state.connecting {
			t.Fatalf("probe %d state=%+v", i, state)
		}
		if _, err := prepareTCPFallback(context.Background(), "192.0.2.2:443", nil, b); !errors.Is(err, errTCPFallbackDeferred) {
			t.Fatalf("backoff bypassed: %v", err)
		}
		if calls != i {
			t.Fatalf("unexpected dial during backoff: %d", calls)
		}
		now = state.retryAfter
	}
	if _, err := prepareTCPFallback(context.Background(), "192.0.2.2:80", nil, b); errors.Is(err, errTCPFallbackDeferred) {
		t.Fatal("backoff crossed port")
	}
	if _, err := prepareTCPFallback(context.Background(), "192.0.2.3:443", nil, b); errors.Is(err, errTCPFallbackDeferred) {
		t.Fatal("backoff crossed destination")
	}
}

func TestTCPFallbackSuccessClearsBackoffAndReleasesSetupSlot(t *testing.T) {
	b := newTCPFallbackBackoff()
	endpoint := "192.0.2.2:443"
	b.endpoints[endpoint] = tcpFallbackEndpoint{failures: 5, retryAfter: time.Now().Add(-time.Second)}
	var connections []*memoryWSConn
	b.dial = func(context.Context, string, string) (net.Conn, error) {
		_, conn := newMemoryWS(nil)
		connections = append(connections, conn)
		return conn, nil
	}
	for i := 0; i < 2; i++ {
		conn, err := prepareTCPFallback(context.Background(), endpoint, []byte("init"), b)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if !bytes.Equal(connections[i].output.Bytes(), []byte("init")) || connections[i].closed.Load() {
			t.Fatal("initializer lost or successful connection closed")
		}
		if _, exists := b.endpoints[endpoint]; exists {
			t.Fatal("successful setup left backoff or active probe marker")
		}
	}
}

func TestTCPFallbackOnlyOneProbeAndCancellationIsNotFailure(t *testing.T) {
	b := newTCPFallbackBackoff()
	endpoint := "192.0.2.2:443"
	started := make(chan struct{})
	var calls atomic.Int32
	b.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		calls.Add(1)
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := prepareTCPFallback(ctx, endpoint, nil, b); done <- err }()
	<-started
	if _, err := prepareTCPFallback(context.Background(), endpoint, nil, b); !errors.Is(err, errTCPFallbackDeferred) {
		t.Fatalf("parallel probe wasn't skipped: %v", err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if calls.Load() != 1 || len(b.endpoints) != 0 {
		t.Fatal("cancellation left a failure or dialed twice")
	}
	if _, err := prepareTCPFallback(ctx, endpoint, nil, b); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("already canceled caller dialed")
	}
}

type failingTCPInitConn struct {
	*memoryWSConn
	short bool
}

func (c *failingTCPInitConn) Write(p []byte) (int, error) {
	if c.short {
		return len(p) - 1, nil
	}
	return 0, io.ErrClosedPipe
}

func TestTCPFallbackInitializationFailureClosesSocketAndBacksOff(t *testing.T) {
	for _, short := range []bool{false, true} {
		b := newTCPFallbackBackoff()
		_, base := newMemoryWS(nil)
		conn := &failingTCPInitConn{memoryWSConn: base, short: short}
		b.dial = func(context.Context, string, string) (net.Conn, error) { return conn, nil }
		if remote, err := prepareTCPFallback(context.Background(), "192.0.2.2:443", []byte("init"), b); remote != nil || err == nil {
			t.Fatal("invalid initializer write accepted")
		}
		if !base.closed.Load() || b.endpoints["192.0.2.2:443"].failures != 1 {
			t.Fatal("initialization failure not counted or transport leaked")
		}
	}
}

func TestTCPFallbackCancellationUnblocksInitializationAndKeepsPriorBackoff(t *testing.T) {
	b := newTCPFallbackBackoff()
	endpoint := "192.0.2.2:443"
	previous := time.Now().Add(-time.Minute)
	b.endpoints[endpoint] = tcpFallbackEndpoint{failures: 3, retryAfter: previous}
	client, server := net.Pipe()
	defer server.Close()
	started := make(chan struct{})
	b.dial = func(context.Context, string, string) (net.Conn, error) { close(started); return client, nil }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := prepareTCPFallback(ctx, endpoint, []byte("init"), b); done <- err }()
	<-started
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled initialization succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("initialization stayed blocked after cancellation")
	}
	state := b.endpoints[endpoint]
	if state.failures != 3 || state.connecting || !state.retryAfter.Equal(previous) {
		t.Fatalf("cancellation changed upstream backoff: %+v", state)
	}
}
