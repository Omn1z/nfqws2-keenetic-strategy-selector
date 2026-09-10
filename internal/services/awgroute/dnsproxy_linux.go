//go:build linux

package awgroute

import (
	"fmt"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/logbuf"
)

// Lifecycle of the domain-mask DNS proxy: it transparently intercepts LAN :53
// (via the hook's REDIRECT), and for every answer whose name matches a zone
// entry it adds the IPs to the routing ipset. Started/refreshed/stopped together
// with split-routing when domain_source=="dnsproxy".

// awgZoneMatchers compiles a flat matcher of every enabled zone's domains —
// used by the proxy's MatcherSet (the np.SetMatchers gate) to decide whether
// a query is RELEVANT at all. The decision (tunnel vs direct) is made by the
// onMatch callback walking the ORDERED list (awgZoneMatchersOrdered) below.
func (svc *Service) awgZoneMatchers(cfg *awg.ServerConfig) *awg.MatcherSet {
	var entries []string
	for _, z := range effectiveZones(cfg.Routing) {
		if !z.Enabled {
			continue
		}
		exp, _ := svc.expandEntries(z.Domains)
		entries = append(entries, exp...)
	}
	ms, _ := awg.CompileMatcherSet(awgDropCatchAll(entries))
	return &ms
}

// awgZoneMatchersOrdered + awgZoneSourceMatchers moved to decision.go so the
// build-tag-free routeFor / buildRouteTable can call them.

// awgEnsureDNSProxy starts/updates the domain-mask DNS proxy when
// domain_source=="dnsproxy" with at least one matcher, otherwise stops it. It
// returns true when the proxy is (now) running, so the firewall hook installs
// the LAN :53 REDIRECT only while the proxy is actually up (never blackhole DNS).
func (svc *Service) awgEnsureDNSProxy(cfg *awg.ServerConfig) bool {
	ms := svc.awgZoneMatchers(cfg)
	// Run the proxy only when the routing selects a SUBSET (include/exclude) and that
	// subset needs DNS interception — either the user turned it on, or a real mask is
	// present (a "*.com"/"*ip*" mask can ONLY be matched via interception). Skip it for
	// "full" (everything is marked at the firewall — no per-name decision needed), and
	// for "off"/"" (nothing to route).
	eff := awgEffectiveMode(cfg.Routing)
	// Source-bound zones don't affect eff (they're per-device, see mode.go), but
	// they still need DNS interception to track CDN-served destinations live.
	hasSrc := false
	for _, z := range cfg.Routing.Zones {
		if z.Enabled && len(z.SourceIPs) > 0 && len(z.Domains) > 0 {
			hasSrc = true
			break
		}
	}
	want := (eff == "include" || eff == "exclude" || hasSrc) && ms.Len() > 0 && awgUsesDNSProxy(cfg)
	svc.route.mu.Lock()
	p := svc.route.dnsProxy
	svc.route.mu.Unlock()
	if !want {
		if p != nil {
			svc.awgStopDNSProxy()
		}
		return false
	}
	// Publish a fresh routeTable snapshot — single source of truth for every
	// hot-path decision. republishRouteTable short-circuits when the inputs
	// match the last build (the SNI ensure that fires right after this one
	// hits the cached snapshot for free instead of re-running expandEntries
	// + matcher compilation).
	tbl := svc.republishRouteTable(cfg, awgTunnelV6Reaches())
	ordered := tbl.ordered
	svc.route.orderedMatchers.Store(&ordered)
	if p != nil {
		p.SetMatchers(ms) // refresh on zone change
		return true
	}
	np := awg.NewDNSProxy(awgDNSAddr, svc.awgEffectiveDNSUpstream(), func(name string, ips []string) {
		// Per-NAME decisions computed ONCE per query. Per-IP work below
		// shrinks to just family-pick + ipsetAddAsync. Before this hoist,
		// the same routeFor walk + sourceZoneMatchers walk ran per IP, so
		// a CDN answer with 8 IPs cost 8× the matcher work for an
		// identical result.
		dec := svc.routeFor(name, "")
		tbl := svc.route.routeTable.Load()
		// Pre-compute which source-bound zones matched this name. Source-
		// bound zones are evaluated per-device but the MATCHER itself is
		// per-NAME — hoisting the walk is correct.
		var matchedSrc []sourceZoneDecision
		if tbl != nil {
			for _, sb := range tbl.source {
				if sb.Matchers != nil && sb.Matchers.Len() > 0 && sb.Matchers.MatchAny(name) {
					matchedSrc = append(matchedSrc, sb)
				}
			}
		}
		for _, ip := range ips {
			v6Suffix := ""
			if isIPv6(ip) {
				v6Suffix = "_6"
			}
			// Source-bound zones first, BEFORE the shared-CDN skip: the user
			// explicitly opted that device into this zone, so a Cloudflare/
			// Akamai destination is what they asked for. Skipping it for "shared
			// CDN" reasoning is correct for LAN-wide global sets (a stray vk.com
			// → 104.16.0.0/13 routed everything-else-on-that-/13 through the
			// tunnel) but wrong for a per-device carve-out.
			for _, sb := range matchedSrc {
				ipsetAddAsync(sb.SetName+v6Suffix, ip)
			}
			if _, ok := sharedCDNProvider(ip); ok {
				svc.awgNoteSharedCDNSkip("dnsproxy", ip)
				continue
			}
			switch dec.Route {
			case RouteDirect:
				ipsetAddAsync(awgSetExc+v6Suffix, ip)
			case RouteTunnel:
				ipsetAddAsync(awgSetInc+v6Suffix, ip)
			}
		}
	})
	// Trace hooks for the per-flow debug log. Both are no-ops when trace is off
	// (the ring's atomic enabled-check kicks the hot path out in ~5ns).
	//
	// Decision logic mirrors what the firewall actually does. The DNS-proxy
	// match alone can't tell — when the user picks a global catch-all "*" the
	// include zone is empty AFTER awgDropCatchAll, but the firewall still
	// marks everything-not-in-exclude → all those queries DO go via the
	// tunnel. The trace has to know the effective mode to label them right.
	traceMode := eff
	np.SetOnQuery(func(srcIP, qname, qtype string, ips []string, sinkholed bool) {
		// Don't gate on traceEnabled() here — the lifetime counters that the
		// dashboard's "запросов в минуту" reads from must keep ticking even
		// when ring recording is off ("trace_mode=off"). traceAppend itself
		// always increments counters and only skips the ring write.
		//
		// Pi-hole sinkhole short-circuit: when the upstream returned a
		// no-destination answer (NXDOMAIN / NOERROR-empty / 0.0.0.0|::), the
		// FMW routing decision is moot — the client got an "address not
		// found". Label the row "blocked" so the user sees the real outcome
		// instead of the misleading "tunnel"/"direct" that would have applied
		// to a real answer. CDN-skip + ipset logic are also moot here (no IP
		// to add); fall through to a single TraceEntry with Dst="" + 0.0.0.0
		// for the NXDOMAIN/empty case so the trace doesn't say "ждём
		// трафика…" for a query that already completed.
		if sinkholed {
			if len(ips) == 0 {
				traceAppend(TraceEntry{Src: srcIP, Kind: "dns", Name: qname, Qtype: qtype, Decision: "blocked", Reason: "pi-hole: домен в блок-листе"})
				return
			}
			for _, ip := range ips {
				traceAppend(TraceEntry{Src: srcIP, Kind: "dns", Name: qname, Qtype: qtype, Dst: ip, Decision: "blocked", Reason: "pi-hole: домен в блок-листе (null-route)"})
			}
			return
		}
		dec := svc.routeFor(qname, srcIP)
		var decision, reason string
		rule := dec.RuleIdx
		switch dec.Route {
		case RouteDirect:
			decision = "direct"
			reason = fmt.Sprintf("правило #%d (direct)", rule)
		case RouteTunnel:
			decision = "tunnel"
			reason = fmt.Sprintf("правило #%d (tunnel)", rule)
		default:
			switch traceMode {
			case "exclude", "full":
				decision, reason = "tunnel", "маршрут по умолчанию через VPN (режим="+traceMode+")"
			default:
				decision, reason = "direct", "нет совпадения"
			}
		}
		if len(ips) == 0 {
			traceAppend(TraceEntry{Src: srcIP, Kind: "dns", Name: qname, Qtype: qtype, Decision: decision, Rule: rule, Reason: reason})
			return
		}
		for _, ip := range ips {
			d, r := decision, reason
			rl := rule
			if decision == "tunnel" {
				if _, ok := sharedCDNProvider(ip); ok {
					d, r, rl = "cdn-skip", "общий CDN — IP не добавлен в set", 0
				}
			}
			traceAppend(TraceEntry{Src: srcIP, Kind: "dns", Name: qname, Qtype: qtype, Dst: ip, Decision: d, Rule: rl, Reason: r})
		}
	})
	np.SetOnBlock(func(srcIP, qname string) {
		// Same as above — let traceAppend gate the ring write; counter ticks always.
		traceAppend(TraceEntry{Src: srcIP, Kind: "dns", Name: qname, Qtype: "AAAA", Decision: "blocked", Reason: "v6-noleak (FMW tunnel rule, AAAA suppressed → v4 fallback)"})
	})
	// AAAA blocker is just a one-line consumer of routeFor — the decision
	// (block or not) is pre-computed by buildRouteTable from the matched
	// rule's route + tunnelV6 snapshot, so the hot path never probes live
	// state and the logic stays consistent with onMatch/onQuery/onHello.
	// Pass the LAN client IP so source-bound zones evaluate per-device — a
	// {SourceIPs:[192.168.1.50], Route:tunnel} rule must only suppress AAAA
	// for THAT device, not the whole LAN.
	np.SetAAAABlocker(func(srcIP, name string) bool {
		return svc.routeFor(name, srcIP).BlockAAAA
	})
	svc.awgLoadRecent(np) // restore domains seen in a previous run (before matching)
	np.SetMatchers(ms)    // re-evaluates the loaded cache → re-adds matching domains
	if err := np.Start(); err != nil {
		logbuf.Append("awg2", "error", "DNS-прокси (маски доменов) не запустился: "+err.Error())
		return false
	}
	svc.route.mu.Lock()
	svc.route.dnsProxy = np
	svc.route.mu.Unlock()
	logbuf.Append("awg2", "info", "DNS-прокси запущен: перехват :53 → маски доменов идут в нужный набор (include/exclude)")
	return true
}

// awgStopDNSProxy stops the proxy and removes its LAN :53 REDIRECT rules so DNS
// falls straight back to the router's resolver.
func (svc *Service) awgStopDNSProxy() {
	svc.route.mu.Lock()
	p := svc.route.dnsProxy
	svc.route.dnsProxy = nil
	svc.route.mu.Unlock()
	if p != nil {
		p.Stop()
	}
	// Strip both possible REDIRECT targets — :5354 (legacy, proxy-first) and
	// :5353 (current, pi-hole-first) — so a chain-mode flip doesn't leave a
	// stale rule pointing at a dead port.
	_, _ = awgRun("for br in $(ls /sys/class/net/ 2>/dev/null | grep '^br'); do " +
		"for port in " + awgDNSPort + " " + awgPiholeDNSPort + "; do " +
		"iptables -t nat -D PREROUTING -i $br -p udp --dport 53 -j REDIRECT --to-ports $port 2>/dev/null; " +
		"iptables -t nat -D PREROUTING -i $br -p tcp --dport 53 -j REDIRECT --to-ports $port 2>/dev/null; " +
		"ip6tables -t nat -D PREROUTING -i $br -p udp --dport 53 -j REDIRECT --to-ports $port 2>/dev/null; " +
		"ip6tables -t nat -D PREROUTING -i $br -p tcp --dport 53 -j REDIRECT --to-ports $port 2>/dev/null; " +
		"done; done")
}
