package dnsserver

import (
	"time"

	mdns "github.com/miekg/dns"
	"nfqws2strategy/internal/services/dnsroute"
)

const (
	schedulerProbeInterval = 5 * time.Second
	schedulerProbeRecheck  = time.Minute
)

// A probe is a lease on one route/provider pair. The caller takes an existing
// shared attempt slot first, then always calls finishProbe, even on shutdown.
// Its context belongs to the resolver lifetime, never to a racing DNS request.
type schedulerProbe struct {
	route    dnsroute.Route
	upstream Upstream
	domain   string
	qtype    uint16
	token    uint64
}

func schedulerProbeCandidates(cfg Config, routes []dnsroute.Route) []schedulerProbe {
	eligible := eligibleRoutes(cfg, routes)
	result := make([]schedulerProbe, 0)
	seen := make(map[string]bool)
	addPool := func(domain string, qtype uint16) {
		pool, _ := cfg.upstreamsFor(domain)
		for _, upstream := range pool {
			for _, route := range eligible {
				key := schedulerKey(route.ID, upstream.Address)
				if !route.Available || seen[key] {
					continue
				}
				seen[key] = true
				result = append(result, schedulerProbe{route: route, upstream: upstream, domain: domain, qtype: qtype})
			}
		}
	}
	// The root NS question is public and cannot be assigned to a domain rule.
	// Never send one rule's representative domain to a different provider pool.
	addPool(".", mdns.TypeNS)
	for _, rule := range cfg.Rules {
		if rule.Enabled {
			addPool(rule.Domain, mdns.TypeA)
		}
	}
	return result
}

// nextProbe selects by completed measurements, not by starts. A pair that is
// continually canceled by faster competitors therefore remains due. Equal
// candidates rotate, including configurations larger than the bounded history.
func (s *Scheduler) nextProbe(cfg Config, routes []dnsroute.Route) (schedulerProbe, bool) {
	candidates := schedulerProbeCandidates(cfg, routes)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.probeKey != "" || len(candidates) == 0 || !s.lastProbe.IsZero() && now.Sub(s.lastProbe) < schedulerProbeInterval {
		return schedulerProbe{}, false
	}
	best := -1
	var oldestResult, oldestProbe time.Time
	for offset := range candidates {
		index := (s.probeCursor + offset) % len(candidates)
		candidate := candidates[index]
		var resultAt, probeAt time.Time
		if entry := s.entries[schedulerKey(candidate.route.ID, candidate.upstream.Address)]; entry != nil {
			resultAt, probeAt = entry.lastResult, entry.lastProbe
		}
		if !resultAt.IsZero() && now.Sub(resultAt) < schedulerProbeRecheck {
			continue
		}
		if best == -1 || resultAt.Before(oldestResult) || resultAt.Equal(oldestResult) && probeAt.Before(oldestProbe) {
			best, oldestResult, oldestProbe = index, resultAt, probeAt
		}
	}
	if best == -1 {
		return schedulerProbe{}, false
	}
	probe := candidates[best]
	key := schedulerKey(probe.route.ID, probe.upstream.Address)
	entry := s.entryLocked(key, now)
	entry.probing = true
	entry.probeAttempts++
	entry.attempts++
	entry.lastProbe, entry.lastAttempt = now, now
	s.probeToken++
	probe.token = s.probeToken
	s.probeKey, s.lastProbe, s.probeCursor = key, now, (best+1)%len(candidates)
	return probe, true
}

func (s *Scheduler) finishProbe(probe schedulerProbe, event AttemptEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := schedulerKey(probe.route.ID, probe.upstream.Address)
	if probe.token != s.probeToken || key != s.probeKey {
		return
	}
	s.probeKey = ""
	entry := s.entries[key]
	entry.probing = false
	if event.Canceled {
		return
	}
	// The lease determines which pair receives evidence, even if a caller left
	// the display fields empty. Duplicate or obsolete finishes are harmless.
	event.Route, event.Upstream = probe.route.ID, probe.upstream.Address
	s.recordLocked(event, s.now())
	if event.Success {
		entry.probeSuccesses++
	} else {
		entry.probeFailures++
	}
}
