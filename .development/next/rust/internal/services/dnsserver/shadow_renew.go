package dnsserver

import (
	"context"
	"fmt"
	"time"

	"nfqws2strategy/internal/services/dnsroute"
)

type shadowRenewBackend interface {
	ShadowRenewalAvailable() bool
	RenewShadowDNS(context.Context) (dnsroute.ShadowRenewalResult, error)
}

// Renew is an explicit WAN action. It is never called by resolution, status
// polling, import or startup. Stopping/replacing the resolver cancels its wait.
func (s *Service) RenewShadowDNS(ctx context.Context, confirmed bool) (dnsroute.ShadowRenewalResult, error) {
	var empty dnsroute.ShadowRenewalResult
	if !confirmed {
		return empty, fmt.Errorf("подтвердите обновление DHCP WAN: возможно краткое прерывание интернета")
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	backend, ok := s.backend.(shadowRenewBackend)
	if !ok || !backend.ShadowRenewalAvailable() {
		return empty, fmt.Errorf("обновление DHCP для Shadow DNS доступно только на Keenetic")
	}
	s.mu.RLock()
	run := s.active
	enabled := s.cfg.Enabled && s.cfg.ShadowDNS != nil && s.cfg.ShadowDNS.Enabled
	s.mu.RUnlock()
	if !enabled || run == nil {
		return empty, fmt.Errorf("сначала включите DNS Server и сохраните включённый Shadow DNS")
	}
	ctx, cancel := context.WithTimeout(ctx, 18*time.Second)
	defer cancel()
	stop := context.AfterFunc(run.resolver.lifetime, cancel)
	defer stop()
	if err := run.resolver.lifetime.Err(); err != nil {
		return empty, err
	}
	result, err := backend.RenewShadowDNS(ctx)
	if err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.active != run || !s.cfg.Enabled || s.cfg.ShadowDNS == nil || !s.cfg.ShadowDNS.Enabled {
		return result, fmt.Errorf("DNS Server перенастроен во время проверки; обновите состояние")
	}
	run.resolver.mu.Lock()
	run.resolver.shadowStatus.Servers = append([]string{}, result.Servers...)
	if result.Status != "resolved" {
		run.resolver.shadowStatus.Error = result.Message
	} else if run.resolver.shadowStatus.FallbackActive {
		// Newly learned addresses deserve a fresh query, but discovery alone
		// does not prove reachability. Keep fallback until a DNS reply succeeds.
		run.resolver.shadowFallback.generation++
		run.resolver.shadowFallback.probing = false
		run.resolver.shadowFallback.retryAt = run.resolver.now()
		run.resolver.shadowStatus.NextProbeAt = run.resolver.shadowFallback.retryAt.UTC().Format(time.RFC3339)
	} else {
		run.resolver.shadowStatus.Error = ""
	}
	run.resolver.mu.Unlock()
	return result, nil
}
