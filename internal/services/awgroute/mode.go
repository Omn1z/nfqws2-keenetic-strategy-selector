package awgroute

import (
	"strings"

	"nfqws2strategy/internal/services/awg"
)

// orderedZoneMatcher is one entry in the first-match-wins ordered list the
// DNS proxy + SNI sniffer walk per query/connection. Route is "tunnel" or
// "direct" (awg vocabulary). Index is the position in cfg.Routing.Zones so
// traces can show "matched rule #3". Build-tag-free so it can sit in
// awgRouteState which is referenced by build-tag-free client.go.
type orderedZoneMatcher struct {
	Matchers *awg.MatcherSet
	Route    string // "tunnel" | "direct"
	Index    int    // position in cfg.Routing.Zones
}

// Pure split-routing mode logic (no OS calls) — kept build-tag-free so it is
// unit-testable on any platform. The linux files (sets/dnsproxy/snisniff/
// routing) call these to decide chain shape and matcher composition.
//
// Routing model: FIRST-MATCH-WINS. Zones walk in cfg.Routing.Zones order; the
// first enabled, non-source-bound zone whose Domains/IPs match the (name, dst)
// decides tunnel-or-direct. A zone with "*" (or "0.0.0.0/0" / "::/0") is a
// catch-all — every rule AFTER it in the array is dead code and ignored by
// the ipset builder, the DNS proxy, the SNI sniffer, and the firewall hook.

// isMaskEntry reports whether a zone domain entry is a glob/regex mask
// (resolved on the fly by the DNS proxy) rather than a plain hostname.
func isMaskEntry(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.ContainsAny(s, "*#") || strings.HasPrefix(s, "[re]")
}

// awgIsCatchAll reports whether an entry matches everything: bare "*" for
// Domains, or "0.0.0.0/0" / "::/0" for IPs. A "*" DNS mask alone could only
// tunnel a site AFTER its name was freshly resolved through our :53 proxy (so
// cached lookups and DoH/DoT clients would slip past); honoring it at the
// firewall has no such gap.
func awgIsCatchAll(s string) bool {
	switch strings.TrimSpace(s) {
	case "*", "0.0.0.0/0", "::/0":
		return true
	}
	return false
}

// zoneHasCatchAll reports whether the zone contains any catch-all entry.
// Equivalent to awg.Zone.IsCatchAll() — kept as a package-local for
// existing callers; new code can use the schema-level method.
func zoneHasCatchAll(z awg.Zone) bool { return z.IsCatchAll() }

// awgDropCatchAll returns entries with the bare "*" / CIDR catch-all removed —
// catch-all is handled by the effective mode / set membership, not by feeding
// every resolved IP into a domain matcher (pointless under full-marking,
// unboundedly large under everything else).
func awgDropCatchAll(entries []string) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if !awgIsCatchAll(e) {
			out = append(out, e)
		}
	}
	return out
}

// firstCatchAllZoneIndex returns the array index of the first enabled,
// NON-source-bound zone that contains a catch-all entry. Returns -1 when no
// catch-all exists. Source-bound zones can have their own catch-all per
// device — those are evaluated separately by the per-source firewall block
// and don't participate in the global walk.
func firstCatchAllZoneIndex(r awg.RoutingConfig) int {
	for i, z := range r.Zones {
		if !z.Enabled || len(z.SourceIPs) > 0 {
			continue
		}
		if z.IsCatchAll() {
			return i
		}
	}
	return -1
}

// effectiveZones returns r.Zones with everything AFTER the first global
// catch-all stripped out — those zones are dead code under first-match-wins
// and must not contribute to ipsets, matchers, or firewall rules. Source-
// bound zones placed after the catch-all are kept (they're per-device and
// have their own walk).
//
// Callers downstream consume this instead of cfg.Routing.Zones directly, so
// the "drop dead zones" rule is enforced in exactly one place.
func effectiveZones(r awg.RoutingConfig) []awg.Zone {
	idx := firstCatchAllZoneIndex(r)
	if idx < 0 {
		return r.Zones
	}
	// Keep all zones up to and including the catch-all, then APPEND every
	// source-bound zone from the tail (they remain alive — see comment above).
	out := make([]awg.Zone, 0, len(r.Zones))
	out = append(out, r.Zones[:idx+1]...)
	for _, z := range r.Zones[idx+1:] {
		if len(z.SourceIPs) > 0 {
			out = append(out, z)
		}
	}
	return out
}

// awgZonesHaveMask reports whether any enabled effective zone has a REAL DNS
// mask/regex entry (glob like "*.com"/"*ip*", or "[re]…") — excluding the
// bare "*" catch-all. Such masks REQUIRE the DNS proxy: the plain "resolve"
// path can't resolve "*.com" to an IP, so without interception they silently
// do nothing.
func awgZonesHaveMask(cfg *awg.ServerConfig) bool {
	for _, z := range effectiveZones(cfg.Routing) {
		if !z.Enabled {
			continue
		}
		for _, d := range z.Domains {
			if !awgIsCatchAll(d) && isMaskEntry(d) {
				return true
			}
		}
	}
	return false
}

// awgUsesDNSProxy reports whether split-routing needs the domain-mask DNS
// proxy: either the user explicitly chose DNS interception, OR a zone
// contains a real mask that can only work via interception, OR a source-bound
// zone has any domain entry (per-device CDN tracking).
func awgUsesDNSProxy(cfg *awg.ServerConfig) bool {
	if cfg.Routing.DomainSource == "dnsproxy" || awgZonesHaveMask(cfg) {
		return true
	}
	for _, z := range effectiveZones(cfg.Routing) {
		if !z.Enabled || len(z.SourceIPs) == 0 {
			continue
		}
		if len(z.Domains) > 0 {
			return true
		}
	}
	return false
}

// awgEffectiveMode returns the firewall chain shape under first-match-wins.
// Output vocabulary kept compatible with existing callers (firewall_linux.go
// switches on these strings; routing_linux.go hashes them):
//
//	"off"     → routing disabled
//	"full"    → catch-all=tunnel with no carve-out before it → mark everything
//	"include" → at least one tunnel rule, no catch-all (whitelist)
//	"exclude" → catch-all=tunnel WITH at least one direct rule before it,
//	            OR no catch-all and at least one direct rule (blacklist)
//	""        → catch-all=direct, OR no enabled zones with entries → nothing marked
//
// The collapse is driven by the FIRST catch-all's position:
//   - no catch-all  → look at direction mix (any tunnel → "include", direct → "exclude", neither → "")
//   - catch-all=tunnel at index 0 → "full" (every dst marks, no carve-out)
//   - catch-all=tunnel at index N>0 with any earlier direct zone → "exclude"
//     (everything tunnels except the earlier carve-outs)
//   - catch-all=tunnel at index N>0 with NO earlier direct zone → "full"
//     (earlier zones are all tunnel-direction → still everything marks)
//   - catch-all=direct → "" (chain stays no-op: ipsets built for earlier zones
//     still RETURN/MARK packets for them; everything else stays direct)
//
// This drops the old "incAll && hasExc → exclude" inversion bug where a
// catch-all=tunnel at array index 0 was downgraded to "exclude" because a
// LATER direct zone existed — which contradicted the user's stated priority.
func awgEffectiveMode(r awg.RoutingConfig) string {
	switch r.Mode {
	case "off":
		return "off"
	case "full":
		return "full"
	}
	idx := firstCatchAllZoneIndex(r)
	if idx >= 0 {
		caRoute := r.Zones[idx].RouteValue()
		// Look for any earlier non-source-bound, enabled, non-empty zone with
		// the OPPOSITE direction — those are real carve-outs under FMW.
		earlierOpposite := false
		for i := 0; i < idx; i++ {
			z := r.Zones[i]
			if !z.Enabled || len(z.SourceIPs) > 0 {
				continue
			}
			if len(z.Domains) == 0 && len(z.IPs) == 0 {
				continue
			}
			if z.RouteValue() != caRoute {
				earlierOpposite = true
				break
			}
		}
		switch caRoute {
		case "tunnel":
			if earlierOpposite {
				return "exclude"
			}
			return "full"
		default: // "direct"
			if earlierOpposite {
				// Catch-all=direct shadows nothing useful for the global chain:
				// later rules are dead, and earlier tunnel rules are realized
				// via awg2_inc membership (chain="include").
				return "include"
			}
			return ""
		}
	}
	// No catch-all: classic direction mix.
	hasInc, hasExc := false, false
	for _, z := range r.Zones {
		if !z.Enabled || (len(z.Domains) == 0 && len(z.IPs) == 0) {
			continue
		}
		if len(z.SourceIPs) > 0 {
			continue
		}
		if z.RouteValue() == "direct" {
			hasExc = true
		} else {
			hasInc = true
		}
	}
	switch {
	case hasInc:
		return "include"
	case hasExc:
		return "exclude"
	default:
		return ""
	}
}
