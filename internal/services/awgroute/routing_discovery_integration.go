package awgroute

import (
	"context"
	"fmt"
	"strings"

	"nfqws2strategy/internal/services/awg"
)

// confirmRoutingDNSLearning keeps address installation ahead of observation.
// OS-specific learners call it while holding their DNS reader guard; tests can
// exercise the same failure/cancellation/replacement barrier without a kernel.
func (svc *Service) confirmRoutingDNSLearning(ctx context.Context, generation uint64, install func() error, observe func()) error {
	g := &svc.routingDNSGate
	g.mu.Lock()
	epoch := g.writeEpoch
	g.mu.Unlock()
	verify := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		g.mu.Lock()
		defer g.mu.Unlock()
		if g.applying || generation != g.generation || epoch != g.writeEpoch {
			return fmt.Errorf("DNS routing policy changed; retry the query")
		}
		if g.err != nil {
			return fmt.Errorf("DNS routing policy is not ready: %w", g.err)
		}
		return nil
	}
	if err := verify(); err != nil {
		return err
	}
	if err := install(); err != nil {
		return err
	}
	if err := verify(); err != nil {
		return err
	}
	if observe != nil {
		observe()
	}
	return verify()
}

// All rules in a policy build share this same bounded name window. Otherwise a
// broad earlier rule could exhaust its budget before seeing a name warmed only
// into a later rule, defeating first-match priority for a cached DNS client.
func (svc *Service) routingDiscoveryWarmupCandidates() []string {
	names := svc.discovered.AllNames()
	if len(names) > routingLearnedNamesLimit {
		names = names[:routingLearnedNamesLimit]
	}
	return names
}

// Candidate history grants no routing scope. Every current rule revalidates
// the same window against its own expanded matcher and source firewall guard.
func (svc *Service) routingDiscoverySeedNames(z awg.Zone, expanded []string) []string {
	return svc.routingDiscoverySeedNamesFrom(z, expanded, svc.routingDiscoveryWarmupCandidates())
}

func (svc *Service) routingDiscoverySeedNamesFrom(z awg.Zone, expanded, candidates []string) []string {
	if z.IsCatchAll() || len(expanded) == 0 {
		return nil
	}
	ms, _ := awg.CompileMatcherSet(awgDropCatchAll(expanded))
	if ms.Len() == 0 {
		return nil
	}
	seen := make(map[string]bool, len(expanded))
	for _, entry := range expanded {
		if !isMaskEntry(entry) {
			seen[strings.ToLower(strings.TrimSuffix(routingResolveName(entry), "."))] = true
		}
	}
	out := []string{}
	for _, name := range candidates {
		name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
		if !routingHostname(name) || seen[name] || !ms.MatchAny(name) {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// A legacy DNS callback retains the exact rule order it was registered with.
// Verify its decision as well as the name/source scope before attributing an
// observation, so a catch-all or stale row index cannot acquire discovered names.
type routingDiscoveryRule struct {
	zone     awg.Zone
	matchers *awg.MatcherSet
}

func (svc *Service) legacyRoutingDiscoverySnapshot(rules []awg.Zone) []routingDiscoveryRule {
	rules = cloneAWGZones(rules)
	out := make([]routingDiscoveryRule, len(rules))
	for i, z := range rules {
		if !z.Enabled || z.WaitingForConnection || z.IsCatchAll() {
			continue
		}
		expanded, _ := svc.expandZoneEntries(z)
		ms, _ := awg.CompileMatcherSet(awgDropCatchAll(expanded))
		if ms.Len() > 0 {
			out[i] = routingDiscoveryRule{zone: z, matchers: &ms}
		}
	}
	return out
}

func (svc *Service) legacyRoutingDiscoveryRule(rules []routingDiscoveryRule, decision RouteDecision, domain, sourceIP string) (awg.Zone, bool) {
	index := decision.RuleIdx - 1
	if index < 0 || index >= len(rules) {
		return awg.Zone{}, false
	}
	z := rules[index].zone
	if rules[index].matchers == nil || z.RouteValue() != string(decision.Route) || decision.SourceBound != (len(z.SourceIPs) > 0) || len(z.SourceIPs) > 0 && !srcIPMatches(sourceIP, z.SourceIPs) {
		return awg.Zone{}, false
	}
	if !rules[index].matchers.MatchAny(domain) {
		return awg.Zone{}, false
	}
	return z, true
}
