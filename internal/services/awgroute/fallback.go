package awgroute

import (
	"fmt"
	"strconv"
	"strings"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/logbuf"
)

// fallbackCandidates returns a stable, de-duplicated priority list. The
// primary connection is always first, even when an old or hand-written config
// also contains it in the fallback array.
func fallbackCandidates(primary string, fallbacks []string) []string {
	seen := make(map[string]struct{}, len(fallbacks)+1)
	out := make([]string, 0, len(fallbacks)+1)
	add := func(raw string) {
		id := strings.TrimSpace(raw)
		if id == "" {
			return
		}
		if _, ok := seen[id]; ok {
			return
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	add(primary)
	for _, id := range fallbacks {
		add(id)
	}
	return out
}

// normalizeFallbackTunnelIDs validates and canonicalizes a rule's backup list.
// It deliberately keeps the user's order because that order is the failover
// priority shown in the panel.
func normalizeFallbackTunnelIDs(primary string, fallbacks []string, exists func(string) bool) ([]string, error) {
	primary = strings.TrimSpace(primary)
	seen := map[string]struct{}{primary: {}}
	out := make([]string, 0, len(fallbacks))
	for _, raw := range fallbacks {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		if id == primary {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		if exists != nil && !exists(id) {
			return nil, fmt.Errorf("резервный туннель не найден: %s", id)
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out, nil
}

// selectFallbackTunnelID chooses the first connected usable connection. If
// none is connected it returns the first usable connection (normally the
// primary), preserving that tunnel's killswitch instead of falling back to
// the WAN. An empty result means every configured candidate is disabled or
// invalid and the rule must not install a direct route.
func selectFallbackTunnelID(primary string, fallbacks []string, usable, connected func(string) bool) string {
	return selectOrderedFallbackTunnelID(fallbackCandidates(primary, fallbacks), primary, usable, connected)
}

func selectOrderedFallbackTunnelID(candidates []string, primary string, usable, connected func(string) bool) string {
	for _, id := range candidates {
		if usable == nil || usable(id) {
			if connected != nil && connected(id) {
				return id
			}
		}
	}
	// A preference can put a connected reserve first, but the primary's
	// policy is still the correct place for traffic when nothing is healthy.
	if len(candidates) != 0 && candidates[0] != primary && (usable == nil || usable(primary)) {
		return primary
	}
	for _, id := range candidates {
		if usable == nil || usable(id) {
			return id
		}
	}
	return ""
}

func (svc *Service) blocksOrdinaryReserves(am *awg.Manager) bool {
	svc.clients.mu.Lock()
	state := svc.clients.doubleTunnels[am]
	svc.clients.mu.Unlock()
	return state.prioritizesDouble() && !state.trialStarted.IsZero() && !state.ordinaryAllowed
}

func (svc *Service) orderedFallbackCandidates(primary string, fallbacks []string) []string {
	candidates := fallbackCandidates(primary, fallbacks)
	if len(candidates) < 2 {
		return candidates
	}
	svc.mu.RLock()
	owner := svc.servers[primary]
	svc.mu.RUnlock()
	if owner == nil {
		return candidates
	}
	svc.clients.mu.Lock()
	state := svc.clients.doubleTunnels[owner.Manager]
	svc.clients.mu.Unlock()
	if state.mode == awg.DoubleTunnelAutomatic && state.ordinaryAllowed && state.outer != nil && state.wanted == state.outer {
		copy(candidates, candidates[1:])
		candidates[len(candidates)-1] = primary
	}
	return candidates
}

func (svc *Service) selectRoutingFallback(primary string, fallbacks []string, usable, connected func(string) bool) string {
	return selectOrderedFallbackTunnelID(svc.orderedFallbackCandidates(primary, fallbacks), primary, usable, connected)
}

// fallbackRoutingSignature describes both LAN rule targets and logical
// connections used by DNS/proxies. The latter also exist with LAN routing off:
// their Telegram front host routes still need updating when the peer changes.
func (svc *Service) fallbackRoutingSignature() (string, bool) {
	servers := make(map[string]*managedServer)
	ordered := svc.serverSnapshot()
	for _, srv := range ordered {
		if srv != nil {
			servers[srv.ID] = srv
		}
	}
	connected := make(map[string]bool)
	routingEnabled := svc.connectionRoutingEligibility()
	known := make(map[string]bool)
	isConnected := func(id string) bool {
		if !known[id] {
			connected[id] = svc.tunnelUpForManagedServer(servers[id])
			known[id] = true
		}
		return connected[id]
	}
	usable := func(id string) bool {
		srv := servers[id]
		if srv == nil {
			return false
		}
		return routingEnabled[srv.ID]
	}
	var b strings.Builder
	hasFallback := false
	ruleFailovers := svc.awgRuleFailovers()
	for _, srv := range ordered {
		if srv == nil {
			continue
		}
		identity := srv.Manager.RuntimeLocalClientIdentity()
		groups := ruleFailovers[srv.ID]
		if len(groups) == 0 && identity.RoutingActive && identity.RoutingMode == "full" {
			groups = [][]string{nil}
		}
		for i, backups := range groups {
			fallbacks := svc.endpointFallbackTunnelIDs(srv.ID, backups)
			if len(fallbacks) == 0 {
				continue
			}
			hasFallback = true
			selected := svc.selectRoutingFallback(srv.ID, fallbacks, usable, isConnected)
			b.WriteString("rule:")
			b.WriteString(strconv.Quote(srv.ID))
			b.WriteByte(':')
			b.WriteString(strconv.Itoa(i))
			b.WriteByte('=')
			b.WriteString(strconv.Quote(selected))
			b.WriteByte(';')
		}
		if len(identity.FallbackTunnelIDs) == 0 && identity.DoubleTunnelID == "" && identity.DoubleTunnelMode != awg.DoubleTunnelPermanent {
			continue
		}
		hasFallback = true
		selected := ""
		if identity.Enabled && identity.ClientEnabled {
			for _, id := range svc.orderedFallbackCandidates(srv.ID, svc.endpointFallbackTunnelIDs(srv.ID, nil)) {
				if isConnected(id) {
					selected = id
					break
				}
			}
		}
		b.WriteString("connection:")
		b.WriteString(strconv.Quote(srv.ID))
		b.WriteByte('=')
		b.WriteString(strconv.Quote(selected))
		b.WriteByte(';')
	}
	return b.String(), hasFallback
}

// refreshFallbackRoutingIfNeeded applies the current policy once when a
// fallback rule's selected connection changes. The first observation only
// establishes the baseline and does not cause startup churn.
func (svc *Service) refreshFallbackRoutingIfNeeded() bool {
	signature, hasFallback := svc.fallbackRoutingSignature()
	return svc.refreshFallbackRouting(signature, hasFallback, svc.awgApplyFallbackPolicyOSErr)
}

func (svc *Service) refreshFallbackRouting(signature string, hasFallback bool, apply func() error) bool {
	svc.clients.mu.Lock()
	if !hasFallback {
		svc.clients.fallbackSignature = ""
		svc.clients.fallbackSignatureSeen = false
		svc.clients.mu.Unlock()
		return false
	}
	if !svc.clients.fallbackSignatureSeen {
		svc.clients.fallbackSignature = signature
		svc.clients.fallbackSignatureSeen = true
		svc.clients.mu.Unlock()
		return false
	}
	changed := svc.clients.fallbackSignature != signature
	svc.clients.mu.Unlock()
	if !changed {
		return false
	}
	unlock, ok := svc.tryClientOps()
	if !ok {
		return false
	}
	err := apply()
	if err != nil {
		unlock()
		logbuf.Append("awg2", "warn", "fallback-маршрутизация: "+err.Error())
		return false
	}
	// A busy lifecycle or failed kernel write must not consume the change.
	// The next supervisor pass retries with cached policy preparation.
	svc.clients.mu.Lock()
	svc.clients.fallbackSignature = signature
	hook := svc.clients.onRecovered
	svc.clients.mu.Unlock()
	// The selected reserve may have been healthy all along, so its recovery
	// callback will never fire. Notify the app to move the Telegram /32 routes
	// after the policy was installed, without holding lifecycle serialization.
	unlock()
	if hook != nil {
		hook()
	}
	return true
}
