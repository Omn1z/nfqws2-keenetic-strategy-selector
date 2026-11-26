package tgws

import (
	"context"
	"errors"
	"sync"
)

// Share the setup budget across native, CF and Worker connections, including
// foreground clients. Established streams release their slot after upgrading.
var wsHandshakes = newWSHandshakeLimiter(4)

type wsHandshakeLimiter struct {
	slots chan struct{}
}

// Queue pressure is local and says nothing about the upstream endpoint. Keep
// the context cause available to callers without treating it as a dial failure.
type wsHandshakeQueueError struct {
	cause error
}

func (e *wsHandshakeQueueError) Error() string {
	return "waiting for WebSocket handshake slot: " + e.cause.Error()
}

func (e *wsHandshakeQueueError) Unwrap() error { return e.cause }

func isWSHandshakeQueueError(err error) bool {
	var queued *wsHandshakeQueueError
	return errors.As(err, &queued)
}

func newWSHandshakeLimiter(limit int) *wsHandshakeLimiter {
	if limit < 1 {
		limit = 1
	}
	return &wsHandshakeLimiter{slots: make(chan struct{}, limit)}
}

func (l *wsHandshakeLimiter) acquire(ctx context.Context) (release func(), err error) {
	if err := ctx.Err(); err != nil {
		return nil, &wsHandshakeQueueError{cause: err}
	}
	select {
	case l.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, &wsHandshakeQueueError{cause: ctx.Err()}
	}
	// A slot and cancellation can become ready together. Do not start another
	// handshake or retain the slot if select happened to choose the slot.
	if err := ctx.Err(); err != nil {
		<-l.slots
		return nil, &wsHandshakeQueueError{cause: err}
	}
	var once sync.Once
	return func() { once.Do(func() { <-l.slots }) }, nil
}
