package dnsroute

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type ShadowRenewalResult struct {
	Status    string   `json:"status"`
	Interface string   `json:"interface"`
	Device    string   `json:"device"`
	Servers   []string `json:"servers,omitempty"`
	Message   string   `json:"message"`
}

// This guard survives capture replacement and service restarts. A failed or
// cancelled command may already have reached firmware and must not be retried.
type shadowRenewalState struct {
	mu           sync.Mutex
	active       bool
	next         time.Time
	platformOnce sync.Once
	supported    bool
}

func (s *shadowRenewalState) begin(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active {
		return fmt.Errorf("обновление DNS провайдера уже выполняется")
	}
	if now.Before(s.next) {
		return fmt.Errorf("повторное обновление DNS провайдера доступно через %d с", int(s.next.Sub(now).Seconds())+1)
	}
	s.active = true
	return nil
}
func (s *shadowRenewalState) finish() { s.mu.Lock(); s.active = false; s.mu.Unlock() }
func (s *shadowRenewalState) sent() {
	s.mu.Lock()
	s.next = time.Now().Add(5 * time.Minute)
	s.mu.Unlock()
}

// Status polling performs no native commands or network discovery.
func (a *Adapter) ShadowRenewalAvailable() bool {
	a.shadowRenewal.platformOnce.Do(func() { a.shadowRenewal.supported = shadowRenewalPlatform() })
	return a.shadowRenewal.supported
}

func (a *Adapter) RenewShadowDNS(ctx context.Context) (ShadowRenewalResult, error) {
	if err := ctx.Err(); err != nil {
		return ShadowRenewalResult{}, err
	}
	if !a.ShadowRenewalAvailable() {
		return ShadowRenewalResult{}, fmt.Errorf("обновление DHCP для Shadow DNS доступно только на Keenetic")
	}
	if err := a.shadowRenewal.begin(time.Now()); err != nil {
		return ShadowRenewalResult{}, err
	}
	defer a.shadowRenewal.finish()
	ctx, cancel := context.WithTimeout(ctx, 16*time.Second)
	defer cancel()
	return a.renewShadowDNSOS(ctx)
}

func lockShadowContext(ctx context.Context, mu *sync.Mutex) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if mu.TryLock() {
		return nil
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if mu.TryLock() {
				return nil
			}
		}
	}
}
