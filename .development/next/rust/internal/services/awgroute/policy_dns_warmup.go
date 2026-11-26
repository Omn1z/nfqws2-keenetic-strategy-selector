package awgroute

import (
	"context"
	"net"
	"strings"
	"time"
)

const (
	policyDNSWarmupRetry  = time.Minute
	policyDNSWarmupBudget = 30 * time.Second
)

type policyDNSWarmup struct {
	done       chan struct{}
	complete   bool
	ips        []string
	retryAfter time.Time
}

// Static list preparation may repeat the same domain across many rules. Reuse
// the existing routing hints, share a cold lookup, and briefly defer repeated
// failed warmups. This never changes resolver/client answer TTL semantics;
// policyDNSLookup(true) remains the explicit fresh-lookup primitive.
func (svc *Service) policyDNSWarmupLookup(live func(context.Context, string) []string) (func(string) []string, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(svc.clientOpContext(), policyDNSWarmupBudget)
	lookup := func(name string) []string {
		return svc.policyDNSWarmupWithLookup(ctx, name, func(name string) []string { return live(ctx, name) })
	}
	return lookup, cancel
}

func (svc *Service) policyDNSWarmupWithLookup(ctx context.Context, name string, live func(string) []string) []string {
	key := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if key == "" {
		return nil
	}
	now := time.Now()
	svc.policyDNSMu.Lock()
	if hint, ok := svc.policyDNS[key]; ok && now.Before(hint.expires) {
		ips := append([]string(nil), hint.ips...)
		svc.policyDNSMu.Unlock()
		return ips
	}
	if ctx.Err() != nil {
		svc.policyDNSMu.Unlock()
		return nil
	}
	if flight := svc.policyDNSWarmups[key]; flight != nil {
		if !flight.complete {
			svc.policyDNSMu.Unlock()
			select {
			case <-ctx.Done():
				return nil
			case <-flight.done:
				return append([]string(nil), flight.ips...)
			}
		}
		if now.Before(flight.retryAfter) {
			svc.policyDNSMu.Unlock()
			return nil
		}
		delete(svc.policyDNSWarmups, key)
	}
	if svc.policyDNSWarmups == nil {
		svc.policyDNSWarmups = map[string]*policyDNSWarmup{}
	}
	if len(svc.policyDNSWarmups) >= policyDNSCacheLimit {
		// Never evict an in-flight name: doing so starts duplicate network work.
		removed := false
		for old, flight := range svc.policyDNSWarmups {
			if flight.complete {
				delete(svc.policyDNSWarmups, old)
				removed = true
				break
			}
		}
		if !removed {
			svc.policyDNSMu.Unlock()
			return nil
		}
	}
	flight := &policyDNSWarmup{done: make(chan struct{})}
	svc.policyDNSWarmups[key] = flight
	svc.policyDNSMu.Unlock()
	// Fresh fallback preserves validated upstream hints when the native
	// resolver forwards through our currently failed readiness gate.
	resolved := svc.policyDNSLookup(true, live)(name)
	var ips []string
	seen := map[string]bool{}
	for _, raw := range resolved {
		if ip := net.ParseIP(raw); ip != nil && !seen[ip.String()] {
			ips = append(ips, ip.String())
			seen[ip.String()] = true
		}
	}
	if ctx.Err() != nil {
		ips = nil
	}
	svc.policyDNSMu.Lock()
	flight.ips, flight.complete = ips, true
	if len(ips) > 0 || ctx.Err() != nil {
		delete(svc.policyDNSWarmups, key)
	} else {
		flight.retryAfter = time.Now().Add(policyDNSWarmupRetry)
	}
	close(flight.done)
	svc.policyDNSMu.Unlock()
	return append([]string(nil), ips...)
}
