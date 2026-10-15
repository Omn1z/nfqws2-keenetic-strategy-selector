package awgroute

import (
	"errors"
	"os"
	"strings"
	"time"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/logbuf"
)

type AWGRoutingDiscoveredRule struct {
	RuleIndex int                      `json:"rule_index"`
	RuleKey   string                   `json:"rule_key"`
	Rule      awg.Zone                 `json:"rule"`
	Entries   []AWGRoutingLearnedEntry `json:"entries"`
}

type AWGRoutingDiscoveredSnapshot struct {
	Revision     uint64                     `json:"revision"`
	Active       bool                       `json:"active"`
	Ready        bool                       `json:"ready"`
	DomainSource string                     `json:"domain_source"`
	Error        string                     `json:"error,omitempty"`
	Rules        []AWGRoutingDiscoveredRule `json:"rules"`
	Limit        int                        `json:"limit"`
}

type routingDiscoveryScope struct {
	revision int64
	matchers *awg.MatcherSet
	explicit map[string]bool
}

func (svc *Service) loadRoutingDiscoveries() {
	if svc.store == nil {
		return
	}
	if err := svc.discovered.Load(svc.store); err != nil && !errors.Is(err, os.ErrNotExist) {
		logbuf.Append("awg2", "warn", "история обнаруженных маршрутов: "+err.Error())
	}
}

// RestoreRoutingDiscoveries replaces only observational history around a
// backup write. Active routing, DNS listeners and policy epochs stay unchanged.
func (svc *Service) RestoreRoutingDiscoveries(restore func() (int, error)) (int, error) {
	return svc.discovered.Restore(svc.store, restore)
}

// Flush at most once per batch, outside the DNS reply path and lifecycle lock.
// Reading the list never schedules writes or DNS queries.
func (svc *Service) scheduleRoutingDiscoveriesSave() {
	if svc.store == nil {
		return
	}
	svc.discoveryPersistMu.Lock()
	defer svc.discoveryPersistMu.Unlock()
	if svc.discoveryClosed || svc.discoveryPersistTimer != nil {
		return
	}
	svc.discoveryPersistTimer = time.AfterFunc(30*time.Second, func() {
		svc.discoveryPersistMu.Lock()
		closed := svc.discoveryClosed
		svc.discoveryPersistTimer = nil
		svc.discoveryPersistMu.Unlock()
		if !closed {
			svc.flushRoutingDiscoveries()
		}
	})
}

func (svc *Service) flushRoutingDiscoveries() {
	if svc.store == nil {
		return
	}
	if err := svc.discovered.Flush(svc.store); err != nil {
		logbuf.Append("awg2", "warn", "сохранение обнаруженных маршрутов: "+err.Error())
	}
}

// Stop delayed persistence after DNS listeners and routing have stopped, then
// synchronously save the final bounded history for the next panel start.
func (svc *Service) CloseRoutingDiscoveries() {
	svc.discoveryPersistMu.Lock()
	svc.discoveryClosed = true
	if svc.discoveryPersistTimer != nil {
		svc.discoveryPersistTimer.Stop()
		svc.discoveryPersistTimer = nil
	}
	svc.discoveryPersistMu.Unlock()
	svc.flushRoutingDiscoveries()
}

func (svc *Service) routingDiscoveryMatchers(z awg.Zone) (*awg.MatcherSet, map[string]bool) {
	key := AWGRoutingLearnedRuleKey(z)
	revision := svc.zonesRevision.Load()
	svc.discoveryScopeMu.Lock()
	if scope, ok := svc.discoveryScopes[key]; ok && scope.revision == revision {
		svc.discoveryScopeMu.Unlock()
		return scope.matchers, scope.explicit
	}
	svc.discoveryScopeMu.Unlock()
	domains, _ := svc.expandZoneEntries(z)
	ms, _ := awg.CompileMatcherSet(awgDropCatchAll(domains))
	explicit := make(map[string]bool)
	for _, entry := range domains {
		entry = strings.TrimSpace(strings.ToLower(entry))
		for _, prefix := range []string{"full:", "domain:"} {
			entry = strings.TrimPrefix(entry, prefix)
		}
		entry = strings.TrimSuffix(entry, ".")
		if routingHostname(entry) {
			explicit[entry] = true
		}
	}
	svc.discoveryScopeMu.Lock()
	if svc.zonesRevision.Load() == revision {
		if svc.discoveryScopes == nil || len(svc.discoveryScopes) >= 128 {
			svc.discoveryScopes = make(map[string]routingDiscoveryScope)
		}
		svc.discoveryScopes[key] = routingDiscoveryScope{revision: revision, matchers: &ms, explicit: explicit}
	}
	svc.discoveryScopeMu.Unlock()
	return &ms, explicit
}

// Called only after a synchronous, successful kernel insertion. Keep the
// epoch check and the in-memory confirmation atomic with policy replacement.
func (svc *Service) recordRoutingDiscovery(z awg.Zone, domain, sourceIP string, ips []string, source string, generation uint64) {
	if !z.Enabled || z.WaitingForConnection || z.IsCatchAll() || len(ips) == 0 {
		return
	}
	if len(z.SourceIPs) > 0 && !srcIPMatches(sourceIP, z.SourceIPs) {
		return
	}
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	ms, explicit := svc.routingDiscoveryMatchers(z)
	if ms.Len() == 0 || !ms.MatchAny(domain) {
		return
	}
	g := &svc.routingDNSGate
	g.mu.Lock()
	if g.applying || g.err != nil || g.generation != generation {
		g.mu.Unlock()
		return
	}
	svc.discovered.Record(AWGRoutingLearnedRuleKey(z), domain, sourceIP, ips, source, !explicit[domain], generation, g.writeEpoch, time.Now())
	g.mu.Unlock()
	svc.scheduleRoutingDiscoveriesSave()
}

// A semantic fingerprint keeps observations attached through rename/reorder,
// while changed match scope, route or connection gets an independent bucket.
func (svc *Service) AWG2DiscoveredRoutes() AWGRoutingDiscoveredSnapshot {
	zones := svc.awgRoutingRules()
	routing := svc.globalRoutingConfig(zones)
	g := &svc.routingDNSGate
	g.mu.Lock()
	generation, epoch := g.generation, g.writeEpoch
	ready := !g.applying && g.err == nil
	message := ""
	if g.err != nil {
		message = g.err.Error()
	}
	g.mu.Unlock()
	out := AWGRoutingDiscoveredSnapshot{Revision: generation, Active: routing.Active, Ready: ready && routing.Active, DomainSource: routing.DomainSource, Error: message, Rules: []AWGRoutingDiscoveredRule{}, Limit: 4096}
	for i, z := range zones {
		key := AWGRoutingLearnedRuleKey(z)
		entries := svc.discovered.Snapshot(key, generation, epoch, out.Ready && z.Enabled && !z.WaitingForConnection)
		filtered := make([]AWGRoutingLearnedEntry, 0, len(entries))
		if len(entries) > 0 && !z.IsCatchAll() {
			ms, explicit := svc.routingDiscoveryMatchers(z)
			for _, entry := range entries {
				if ms.MatchAny(entry.Domain) {
					entry.Additional = !explicit[entry.Domain]
					filtered = append(filtered, entry)
				}
			}
		}
		out.Rules = append(out.Rules, AWGRoutingDiscoveredRule{RuleIndex: i, RuleKey: key, Rule: z, Entries: filtered})
	}
	return out
}
