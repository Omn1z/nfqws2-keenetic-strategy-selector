package awgroute

import (
	"strings"

	"nfqws2strategy/internal/services/awg"
)

// Pure split-routing mode logic (no OS calls) — kept build-tag-free so it is unit-
// testable on any platform. The linux files (sets/dnsproxy/routing_linux.go) call
// these to decide the firewall chain shape and whether the domain-mask DNS proxy
// must run.

// isMaskEntry reports whether a zone domain entry is a glob/regex mask (resolved on
// the fly by the DNS proxy) rather than a plain resolvable hostname.
func isMaskEntry(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.ContainsAny(s, "*#") || strings.HasPrefix(s, "[re]")
}

// awgIsCatchAll reports whether an entry is the bare "*" wildcard. The user means it
// as "everything" — we honor that at the firewall (mark ALL traffic, via the full/
// exclude effective mode) instead of as a DNS mask. A "*" DNS mask could only tunnel
// a site AFTER its name was freshly resolved through our :53 proxy (so cached lookups
// and DoH/DoT clients would slip past); marking everything has no such gap.
func awgIsCatchAll(s string) bool { return strings.TrimSpace(s) == "*" }

// zoneHasCatchAll reports whether the zone contains a bare "*" entry.
func zoneHasCatchAll(z awg.Zone) bool {
	for _, d := range z.Domains {
		if awgIsCatchAll(d) {
			return true
		}
	}
	return false
}

// awgDropCatchAll returns entries with the bare "*" catch-all removed — it is handled
// by the effective mode, not by the DNS proxy (a "*" matcher would dump every resolved
// IP into the set, pointless under full-marking and unboundedly large).
func awgDropCatchAll(entries []string) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if !awgIsCatchAll(e) {
			out = append(out, e)
		}
	}
	return out
}

// awgZonesHaveMask reports whether any enabled zone has a REAL DNS mask/regex entry
// (glob like "*.com"/"*ip*", or "[re]…") — excluding the bare "*" catch-all. Such
// masks REQUIRE the DNS proxy: the plain "resolve" path skips them (you can't resolve
// "*.com" to an IP), so without interception they silently do nothing.
func awgZonesHaveMask(cfg *awg.ServerConfig) bool {
	for _, z := range cfg.Routing.Zones {
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

// awgUsesDNSProxy reports whether split-routing needs the domain-mask DNS proxy:
// either the user explicitly chose DNS interception (domain_source=="dnsproxy", which
// also catches plain-domain subdomains and live IP changes), OR a zone contains a real
// mask that can only work via interception. The second arm makes masks "just work"
// even when the toggle is off — otherwise typing "*.com" in the default resolve mode
// is silently ignored.
func awgUsesDNSProxy(cfg *awg.ServerConfig) bool {
	return cfg.Routing.DomainSource == "dnsproxy" || awgZonesHaveMask(cfg)
}

// awgEffectiveMode collapses the per-zone directions + global mode into the chain
// shape the firewall hook renders:
//
//	"full"    → mark everything (route all traffic)
//	"include" → whitelist: only include-zones tunnel; exclude-zones carve out
//	"exclude" → blacklist: everything tunnels except exclude-zones
//	""        → "zones" but no enabled zones with entries → nothing marked (all direct)
//	"off"     → routing disabled
//
// Rules:
//   - A bare "*" in an enabled include-zone means "route everything": alone → "full";
//     with exclude-zones present → "exclude" (everything via VPN except them). This is
//     firewall-level so it covers every site regardless of DNS (cache, DoH/DoT).
//   - Otherwise: any enabled include-zone with entries → whitelist ("include"); only
//     exclude-zones → blacklist ("exclude").
func awgEffectiveMode(r awg.RoutingConfig) string {
	switch r.Mode {
	case "off":
		return "off"
	case "full":
		return "full"
	}
	hasInc, hasExc, incAll := false, false, false
	for _, z := range r.Zones {
		if !z.Enabled || (len(z.Domains) == 0 && len(z.IPs) == 0) {
			continue
		}
		if z.Mode == "exclude" {
			hasExc = true
		} else {
			hasInc = true
			if zoneHasCatchAll(z) {
				incAll = true
			}
		}
	}
	switch {
	case incAll && hasExc:
		return "exclude"
	case incAll:
		return "full"
	case hasInc:
		return "include"
	case hasExc:
		return "exclude"
	default:
		return ""
	}
}
