package awgroute

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync/atomic"

	"nfqws2strategy/internal/services/awg"
)

// Single source of truth for "what should we do with this name?". All hot-path
// consumers — DNS proxy onMatch, DNS proxy onQuery (trace), SNI sniffer onHello,
// DNS proxy AAAA blocker — call routeFor and consume the same answer.
//
// Before this consolidation each consumer walked cfg.Routing.Zones (or its
// derived orderedMatchers) inline with subtly different logic. Symptoms:
//
//   1. The AAAA blocker used a unified MatcherSet which matched every name
//      once the user had a catch-all "*" rule → AAAA blocked for every name,
//      RU sites lost v6 even though their direct-route rule wanted it.
//
//   2. tunnelV6 was probed live via awgTunnelV6Reaches() on every DNS query
//      (cached for 90s, so cheap, but a hot-path cross-package call).
//
//   3. Source-bound zones were considered only by onMatch's per-source ipset
//      push, never by the AAAA decision — a per-device "all via VPN" rule
//      didn't strip AAAA for that client even though the tunnel can't carry
//      v6 for that client.
//
// routeFor fixes (1) by walking the per-zone matchers in array order (FMW),
// (2) by reading a snapshot of tunnelV6 captured at zones-edit time, and (3)
// by checking source-bound zones BEFORE the global walk.

// Route is the binary routing direction in the awg vocabulary.
type Route string

const (
	RouteUnknown Route = ""        // no rule matched (caller falls back to effective mode)
	RouteTunnel  Route = "tunnel"  // packet marked → table 998 → awg0
	RouteDirect  Route = "direct"  // unmarked → main → wandev
)

// RouteDecision is the result of one first-match-wins lookup. Callers never
// look at internals of zones / matchers / tunnelV6 — they just consume this.
type RouteDecision struct {
	Route       Route // tunnel / direct / unknown (no match)
	RuleIdx     int   // 1-based rule position for traces ("правило #3"); 0 = no match
	BlockAAAA   bool  // pre-computed: true if AAAA must be stripped for this name
	SourceBound bool  // matched via a source-bound rule (per-device)
	SourceSet   string // per-zone ipset name when SourceBound (e.g. "awg2_z0")
}

// routeTable is the immutable snapshot the hot path reads via atomic.Pointer.
// Built once per zones edit (apply / watchdog / source-bound change) and
// swapped atomically. Readers never block.
//
// `hash` is the sha256 of the inputs that drove this build (zones + tunnelV6
// + expand-cache version). republishRouteTable uses it to short-circuit a
// rebuild when nothing changed — saving the 4-6× duplicate expandEntries +
// matcher compilation per apply that the audit found.
type routeTable struct {
	ordered  []orderedZoneMatcher // global FMW zones in array order
	source   []sourceZoneDecision // source-bound zones (per-device pre-resolved)
	tunnelV6 bool                 // snapshotted at build time
	hash     string               // input fingerprint for cache short-circuit
}

// sourceZoneDecision augments sourceZoneMatchers with the route + ipset name
// + raw source-IP/CIDR list, so routeFor can decide in one pass without
// re-resolving the source membership per query.
type sourceZoneDecision struct {
	Matchers *awg.MatcherSet
	SetName  string   // per-zone ipset (e.g. "awg2_z3")
	Route    string   // "tunnel" | "direct" (from zone.RouteValue())
	Index    int      // position in cfg.Routing.Zones
	Sources  []string // raw source IP/CIDR strings (membership check at lookup time)
}

// Service.routeTable holds the current snapshot. Hot path reads via Load().
// Builders call buildRouteTable to swap atomically.

// routeFor returns the decision for one (qname, srcIP) pair. Safe for
// concurrent use; no allocations on the hot path beyond what MatcherSet does.
//
// Algorithm: walk ALL zones (global + source-bound) in cfg.Routing.Zones
// order — i.e. the order the user sees in the UI — and return the FIRST that
// matches. This is true first-match-wins: a "All clients via VPN" rule at
// row #2 wins over a "device:X" rule at row #4 (the UI promises «приоритет
// сверху вниз»). Previously source-bound zones were walked first and always
// beat global rules regardless of UI order, which contradicted that promise.
func (svc *Service) routeFor(qname, srcIP string) RouteDecision {
	tbl := svc.route.routeTable.Load()
	if tbl == nil {
		return RouteDecision{}
	}

	// Two-pointer merge by Index — both slices are already sorted by
	// cfg.Routing.Zones position, so we never re-sort. At each step pick the
	// entry with the smaller Index (= higher UI priority).
	oi, si := 0, 0
	for oi < len(tbl.ordered) || si < len(tbl.source) {
		pickOrdered := si >= len(tbl.source) ||
			(oi < len(tbl.ordered) && tbl.ordered[oi].Index <= tbl.source[si].Index)
		if pickOrdered {
			zm := tbl.ordered[oi]
			oi++
			if zm.Matchers.MatchAny(qname) {
				return RouteDecision{
					Route:     Route(zm.Route),
					RuleIdx:   zm.Index + 1,
					BlockAAAA: zm.Route == "tunnel" && !tbl.tunnelV6,
				}
			}
			continue
		}
		sb := tbl.source[si]
		si++
		if !srcIPMatches(srcIP, sb.Sources) {
			continue
		}
		if sb.Matchers != nil && sb.Matchers.Len() > 0 && !sb.Matchers.MatchAny(qname) {
			continue
		}
		return RouteDecision{
			Route:       Route(sb.Route),
			RuleIdx:     sb.Index + 1,
			BlockAAAA:   sb.Route == "tunnel" && !tbl.tunnelV6,
			SourceBound: true,
			SourceSet:   sb.SetName,
		}
	}
	return RouteDecision{}
}

// awgZoneMatchersOrdered compiles per-zone matchers in cfg.Routing.Zones array
// order, returning one entry per enabled, non-source-bound zone. Source-bound
// zones live in their own per-device pipeline (buildSourceZoneDecisions) and
// are not part of the global first-match-wins walk.
//
// Zones AFTER the first catch-all are dropped (effectiveZones takes care of
// that). The catch-all itself IS included in the returned list as a real
// matcher entry — routeFor sees it as "matches everything" and short-circuits.
//
// A catch-all is modelled as a regex matcher "[re]^" (always-true) rather
// than letting awgDropCatchAll strip it — the legacy strip made catch-all
// invisible to MatcherSet.MatchAny, which is exactly what broke the AAAA
// blocker (it then matched every name via the bare matcher).
func (svc *Service) awgZoneMatchersOrdered(cfg *awg.ServerConfig) []orderedZoneMatcher {
	ez := effectiveZones(cfg.Routing)
	out := make([]orderedZoneMatcher, 0, len(ez))
	for i, z := range ez {
		if !z.Enabled || len(z.SourceIPs) > 0 {
			continue
		}
		var ms awg.MatcherSet
		if z.IsCatchAll() {
			ms, _ = awg.CompileMatcherSet([]string{"[re]^"})
		} else {
			exp, _ := svc.expandEntries(z.Domains)
			ms, _ = awg.CompileMatcherSet(awgDropCatchAll(exp))
		}
		out = append(out, orderedZoneMatcher{
			Matchers: &ms,
			Route:    z.RouteValue(),
			Index:    i,
		})
	}
	return out
}

// awgZoneSourceMatchers builds the per-source-zone matcher list in the same
// order as awgBuildSourceSets so each entry's SetName matches its zone's ipset.
// Kept for the legacy dnsproxy onMatch path that pushes per-device IPs into
// awg2_z<idx> sets; the new routeFor consumes buildSourceZoneDecisions which
// carries the same info plus the route + source membership list.
func (svc *Service) awgZoneSourceMatchers(cfg *awg.ServerConfig) []sourceZoneMatchers {
	sb := sourceBoundZones(cfg.Routing.Zones)
	out := make([]sourceZoneMatchers, 0, len(sb))
	for i, z := range sb {
		exp, _ := svc.expandEntries(z.Domains)
		ms, _ := awg.CompileMatcherSet(awgDropCatchAll(exp))
		out = append(out, sourceZoneMatchers{Matchers: &ms, SetName: sourceZoneSetName(i)})
	}
	return out
}

// buildRouteTable composes a fresh immutable snapshot for the given config +
// tunnel-v6 reachability state. Callers (awgEnsureDNSProxy, awgEnsureSNISniff,
// the watchdog) invoke this once per zones edit and store the result via
// svc.route.routeTable.Store(&tbl). The hot path never builds — it just reads.
//
// tunnelV6 is sampled by the caller (not here) because routeFor must be
// build-tag-free for unit-testing on macOS, but awgTunnelV6Reaches is a Linux
// helper. The caller passes the bool it computed.
func (svc *Service) buildRouteTable(cfg *awg.ServerConfig, tunnelV6 bool) *routeTable {
	ordered := svc.awgZoneMatchersOrdered(cfg)
	source := svc.buildSourceZoneDecisions(cfg)
	return &routeTable{
		ordered:  ordered,
		source:   source,
		tunnelV6: tunnelV6,
		hash:     routeTableInputHash(cfg, tunnelV6),
	}
}

// routeTableInputHash digests the inputs that affect a routeTable build, so
// republishRouteTable can detect "same inputs as last build → reuse" without
// re-running expandEntries / matcher compilation. Keep this cheap and
// COMPLETE — missing a relevant input means stale matchers in production.
func routeTableInputHash(cfg *awg.ServerConfig, tunnelV6 bool) string {
	h := sha256.New()
	for _, z := range cfg.Routing.Zones {
		fmt.Fprintf(h, "z|%t|%s|%s|", z.Enabled, z.Mode, z.Route)
		for _, d := range z.Domains {
			h.Write([]byte("d:"))
			h.Write([]byte(d))
			h.Write([]byte{0})
		}
		for _, ip := range z.IPs {
			h.Write([]byte("i:"))
			h.Write([]byte(ip))
			h.Write([]byte{0})
		}
		for _, s := range z.SourceIPs {
			h.Write([]byte("s:"))
			h.Write([]byte(s))
			h.Write([]byte{0})
		}
	}
	if tunnelV6 {
		h.Write([]byte("v6:1"))
	} else {
		h.Write([]byte("v6:0"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// republishRouteTable rebuilds + stores the snapshot ONLY when the input
// fingerprint differs from the currently-published table. Returns the
// (possibly re-used) snapshot so the caller can pass it to downstream
// builders without an extra Load(). Both awgEnsureDNSProxy and
// awgEnsureSNISniff call this; on apply both fire back-to-back so the second
// call returns the cached snapshot for free.
func (svc *Service) republishRouteTable(cfg *awg.ServerConfig, tunnelV6 bool) *routeTable {
	want := routeTableInputHash(cfg, tunnelV6)
	if cur := svc.route.routeTable.Load(); cur != nil && cur.hash == want {
		return cur
	}
	tbl := svc.buildRouteTable(cfg, tunnelV6)
	svc.route.routeTable.Store(tbl)
	return tbl
}

// buildSourceZoneDecisions converts each source-bound zone into a
// sourceZoneDecision (pre-resolved matchers + source list + ipset name). The
// returned slice is in cfg.Routing.Zones array order so source-bound rules
// also walk first-match-wins per device.
//
// Source-bound zones get their per-zone ipset awg2_z<idx> built separately
// by awgBuildSourceSets — we only carry the SetName here so routeFor can tell
// onMatch which set to populate when a name matches per-device.
func (svc *Service) buildSourceZoneDecisions(cfg *awg.ServerConfig) []sourceZoneDecision {
	// We walk cfg.Routing.Zones in its ORIGINAL order so Index reflects the
	// position the user sees in the UI ("правило #3"). sourceZoneSetName uses
	// a separate per-source-bound counter because the firewall hook + ipset
	// builder both index ipsets that way (awg2_z0, awg2_z1, ...).
	out := make([]sourceZoneDecision, 0)
	sbCounter := 0
	for i, z := range cfg.Routing.Zones {
		if !z.Enabled || len(z.SourceIPs) == 0 {
			continue
		}
		var ms awg.MatcherSet
		if z.IsCatchAll() {
			// "All traffic from this device" — model as always-match. The
			// global FMW walk doesn't include this zone (source-bound zones
			// are not in the global ordered list), so we keep its semantics
			// here and let routeFor short-circuit on a per-device match.
			ms, _ = awg.CompileMatcherSet([]string{"[re]^"})
		} else if len(z.Domains) > 0 {
			exp, _ := svc.expandEntries(z.Domains)
			ms, _ = awg.CompileMatcherSet(awgDropCatchAll(exp))
		}
		out = append(out, sourceZoneDecision{
			Matchers: &ms,
			SetName:  sourceZoneSetName(sbCounter),
			Route:    z.RouteValue(),
			Index:    i, // ORIGINAL position in cfg.Routing.Zones (1-based at lookup)
			Sources:  append([]string(nil), z.SourceIPs...),
		})
		sbCounter++
	}
	return out
}

// awgRouteState.routeTable is the live snapshot pointer. Defined here so the
// build-tag-free file can reference it; Service embeds awgRouteState (see
// client.go) so svc.route.routeTable is the lookup path.
type routeStateAtomic = atomic.Pointer[routeTable]

// srcIPMatches reports whether srcIP belongs to any entry in cidrs. Entries
// may be bare IPs ("192.168.1.50"), CIDRs ("192.168.1.0/24"), or v6 forms.
// Empty cidrs → false (no match).
func srcIPMatches(srcIP string, cidrs []string) bool {
	if srcIP == "" || len(cidrs) == 0 {
		return false
	}
	ip := net.ParseIP(srcIP)
	if ip == nil {
		return false
	}
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if strings.Contains(c, "/") {
			_, n, err := net.ParseCIDR(c)
			if err == nil && n.Contains(ip) {
				return true
			}
			continue
		}
		// Bare IP — exact match (the firewall hook treats source_ips of bare
		// IPs as single-host iptables -s rules; we mirror that here).
		if c == srcIP {
			return true
		}
		if other := net.ParseIP(c); other != nil && other.Equal(ip) {
			return true
		}
	}
	return false
}
