package dnsroute

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestShadowRenewalGuardPersistsAfterAmbiguousCommand(t *testing.T) {
	var s shadowRenewalState
	if err := s.begin(time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.begin(time.Now()); err == nil {
		t.Fatal("concurrent renewal allowed")
	}
	s.sent()
	s.finish()
	if err := s.begin(time.Now().Add(4 * time.Minute)); err == nil {
		t.Fatal("possibly executed command retried")
	}
	if err := s.begin(time.Now().Add(6 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	s.finish()
}

func TestShadowRenewalPreflightDoesNotConsumeCooldown(t *testing.T) {
	var s shadowRenewalState
	if err := s.begin(time.Now()); err != nil {
		t.Fatal(err)
	}
	s.finish()
	if err := s.begin(time.Now()); err != nil {
		t.Fatal(err)
	}
	s.finish()
}

func TestShadowRenewalLockCancellation(t *testing.T) {
	var mu sync.Mutex
	mu.Lock()
	defer mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if err := lockShadowContext(ctx, &mu); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

func TestShadowRenewalUnavailableAndCancelled(t *testing.T) {
	a := New(nil, nil)
	a.shadowRenewal.platformOnce.Do(func() { a.shadowRenewal.supported = false })
	if _, err := a.RenewShadowDNS(context.Background()); err == nil {
		t.Fatal("unsupported platform renewed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.RenewShadowDNS(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
