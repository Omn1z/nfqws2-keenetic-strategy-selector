package dnsserver

import (
	"context"
	"fmt"
	"time"

	mdns "github.com/miekg/dns"
)

const shadowRetryInterval = 30 * time.Second

type shadowFallbackState struct {
	generation uint64
	retryAt    time.Time
	probing    bool
}

func (r *Resolver) resolveShadow(ctx context.Context, query *mdns.Msg, wire []byte, domain string) (*mdns.Msg, Outcome, error) {
	// Shared flights outlive an individual caller, but never get an unlimited
	// budget. The provider child timeout leaves time for configured DNS routes.
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	stop := context.AfterFunc(r.lifetime, cancel)
	defer stop()
	if err := ctx.Err(); err != nil {
		return nil, Outcome{Domain: domain, Route: shadowRoute, Error: err.Error()}, err
	}
	tryProvider, generation, providerError := r.beginShadowAttempt()
	if tryProvider {
		response, out, servers, err := r.queryShadow(ctx, query, domain)
		// A canceled client or stopped service is not a provider outage.
		r.finishShadowAttempt(generation, servers, err, ctx.Err() != nil || r.lifetime.Err() != nil)
		if err == nil {
			return response, out, nil
		}
		providerError = err.Error()
	}
	if err := ctx.Err(); err != nil {
		return nil, Outcome{Domain: domain, Route: shadowRoute, Error: err.Error()}, err
	}
	if err := r.lifetime.Err(); err != nil {
		return nil, Outcome{Domain: domain, Route: shadowRoute, Error: err.Error()}, err
	}
	response, out, err := r.resolveConfigured(ctx, query, wire, domain)
	if err != nil {
		err = fmt.Errorf("%s; резерв DNS Server: %w", providerError, err)
		out.Error = err.Error()
		return nil, out, err
	}
	// Bound both our cache and downstream client caches, including negative
	// answers. A long upstream TTL must not postpone retrying the provider.
	clipShadowFallbackTTL(response)
	return response, out, nil
}

func (r *Resolver) beginShadowAttempt() (bool, uint64, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := &r.shadowFallback
	if r.shadowStatus.FallbackActive {
		if r.now().Before(s.retryAt) || s.probing {
			return false, s.generation, r.shadowStatus.Error
		}
		// Only one cache miss tests recovery; other domains keep using the
		// configured routes without waiting for another provider timeout.
		s.probing = true
	}
	return true, s.generation, r.shadowStatus.Error
}

func (r *Resolver) finishShadowAttempt(generation uint64, servers []string, err error, canceled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := &r.shadowFallback
	if generation != s.generation {
		return // a late result must not undo a newer outage/recovery decision
	}
	s.probing = false
	if canceled {
		return
	}
	r.shadowStatus.Servers = append([]string{}, servers...)
	if err == nil {
		if r.shadowStatus.FallbackActive {
			s.generation++
		}
		s.retryAt = time.Time{}
		r.shadowStatus.FallbackActive = false
		r.shadowStatus.NextProbeAt = ""
		r.shadowStatus.Error = ""
		return
	}
	s.generation++
	s.retryAt = r.now().Add(shadowRetryInterval)
	r.shadowStatus.FallbackActive = true
	r.shadowStatus.NextProbeAt = s.retryAt.UTC().Format(time.RFC3339)
	r.shadowStatus.Error = err.Error()
}

func clipShadowFallbackTTL(msg *mdns.Msg) {
	limit := uint32(shadowRetryInterval / time.Second)
	for _, section := range [][]mdns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			h := rr.Header()
			// OPT's TTL field contains EDNS flags/version, not a lifetime.
			if h.Rrtype == mdns.TypeOPT {
				continue
			}
			if h.Ttl > limit {
				h.Ttl = limit
			}
			// Negative TTL is min(SOA TTL, SOA.MINIMUM). Cap only the header:
			// changing MINIMUM would alter signed RDATA and invalidate DNSSEC.
		}
	}
}
