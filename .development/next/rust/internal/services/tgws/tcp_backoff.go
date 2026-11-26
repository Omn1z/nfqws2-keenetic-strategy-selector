package tgws

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

const tcpFallbackInitialBackoff = 30 * time.Second
const tcpFallbackMaxBackoff = time.Hour

var errTCPFallbackDeferred = errors.New("TCP fallback is cooling down or connecting")

type tcpFallbackEndpoint struct {
	failures   int
	retryAfter time.Time
	connecting bool
}

// One instance belongs to one proxy run. A failed endpoint is probed by at
// most one client at a time; established bridges do not hold that probe slot.
type tcpFallbackBackoff struct {
	mu        sync.Mutex
	endpoints map[string]tcpFallbackEndpoint
	now       func() time.Time
	dial      func(context.Context, string, string) (net.Conn, error)
}

func newTCPFallbackBackoff() *tcpFallbackBackoff {
	return &tcpFallbackBackoff{endpoints: make(map[string]tcpFallbackEndpoint), now: time.Now,
		dial: (&net.Dialer{Timeout: 10 * time.Second}).DialContext}
}

func tcpFallbackDelay(failures int) time.Duration {
	shift := max(0, min(failures-1, 7))
	return min(tcpFallbackInitialBackoff*time.Duration(1<<shift), tcpFallbackMaxBackoff)
}

func (b *tcpFallbackBackoff) begin(endpoint string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	state := b.endpoints[endpoint]
	if state.connecting || b.now().Before(state.retryAfter) {
		return false
	}
	state.connecting = true
	b.endpoints[endpoint] = state
	return true
}

func (b *tcpFallbackBackoff) finish(endpoint string, err error, canceled bool) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	state := b.endpoints[endpoint]
	state.connecting = false
	if canceled {
		if state.failures == 0 {
			delete(b.endpoints, endpoint)
		} else {
			b.endpoints[endpoint] = state
		}
		return 0
	}
	if err == nil {
		delete(b.endpoints, endpoint)
		return 0
	}
	state.failures = min(state.failures+1, 8)
	delay := tcpFallbackDelay(state.failures)
	state.retryAfter = b.now().Add(delay)
	b.endpoints[endpoint] = state
	return delay
}

func prepareTCPFallback(ctx context.Context, endpoint string, relayInit []byte, backoff *tcpFallbackBackoff) (remote net.Conn, err error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if backoff == nil {
		backoff = newTCPFallbackBackoff()
	}
	if !backoff.begin(endpoint) {
		return nil, errTCPFallbackDeferred
	}
	defer func() {
		delay := backoff.finish(endpoint, err, ctx.Err() != nil)
		if delay > 0 {
			log.Printf("tgws: TCP fallback %s failed: %s; retry in %s", endpoint, censorDomains(err.Error()), delay)
		}
	}()
	setupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	remote, err = backoff.dial(setupCtx, "tcp", endpoint)
	if err != nil {
		return nil, err
	}
	conn := remote
	stopClose := context.AfterFunc(setupCtx, func() { _ = conn.Close() })
	defer stopClose()
	defer func() {
		if err != nil {
			_ = conn.Close()
		}
	}()
	deadline, _ := setupCtx.Deadline()
	if err = conn.SetWriteDeadline(deadline); err != nil {
		return nil, err
	}
	var n int
	n, err = conn.Write(relayInit)
	if err == nil && n != len(relayInit) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = setupCtx.Err()
	}
	if err != nil {
		return nil, err
	}
	if !stopClose() {
		return nil, setupCtx.Err()
	}
	if err = conn.SetWriteDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return conn, nil
}
