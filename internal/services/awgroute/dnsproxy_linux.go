//go:build linux

package awgroute

import (
	"fmt"
	"strconv"

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
		exp, _ := svc.expandZoneEntries(z)
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
	want := awgDNSProxyWanted(cfg, ms)
	eff := awgEffectiveMode(cfg.Routing)
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
	// hot-path decision. republishRouteTable reuses unchanged inputs.
	tbl := svc.republishRouteTable(cfg, awgTunnelV6Reaches())
	ordered := tbl.ordered
	svc.route.orderedMatchers.Store(&ordered)
	identity := tbl.hash + ":" + strconv.FormatInt(tbl.revision, 10) + ":" + strconv.FormatUint(svc.routingDNSGate.version(), 10)
	if p != nil {
		if p.PolicyChanged(identity) {
			svc.awgSetLegacyDNSLearner(p)
			p.SetMatchers(ms)
		}
		return true
	}
	np := awg.NewDNSProxy(awgDNSAddr, awgDNSUpstream, nil)
	np.PolicyChanged(identity)
	svc.awgSetLegacyDNSLearner(np)
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
		// DNS sinkhole short-circuit: when the upstream returned a
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
				traceAppend(TraceEntry{Src: srcIP, Kind: "dns", Name: qname, Qtype: qtype, Decision: "blocked", Reason: "DNS upstream: пустой или отрицательный ответ"})
				return
			}
			for _, ip := range ips {
				traceAppend(TraceEntry{Src: srcIP, Kind: "dns", Name: qname, Qtype: qtype, Dst: ip, Decision: "blocked", Reason: "DNS upstream: null-route"})
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
			if skipSharedCDNDomainIP(string(dec.Route), dec.SourceBound, ip) {
				d, r, rl = "cdn-skip", "общий CDN — глобальное исключение direct не добавлено", 0
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

// Share the exact listener requirement with apply/recovery checks. A full
// tunnel with domain entries still needs no per-name learner unless source
// rules select a subset, so its deliberately absent proxy is not a failure.
func awgDNSProxyWanted(cfg *awg.ServerConfig, ms *awg.MatcherSet) bool {
	if cfg == nil || ms == nil || ms.Len() == 0 || !awgUsesDNSProxy(cfg) {
		return false
	}
	eff := awgEffectiveMode(cfg.Routing)
	hasSrc := false
	for _, z := range cfg.Routing.Zones {
		if z.Enabled && !z.WaitingForConnection && len(z.SourceIPs) > 0 && len(z.Domains) > 0 {
			hasSrc = true
			break
		}
	}
	return eff == "include" || eff == "exclude" || hasSrc
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
	// Also remove the old Pi-hole target on upgrades, so a retired DNS chain
	// cannot leave LAN clients pointing at an unused port.
	_, _ = awgRun("for br in $(ls /sys/class/net/ 2>/dev/null | grep '^br'); do " +
		"for port in " + awgDNSPort + " " + awgLegacyPiholeDNSPort + "; do " +
		"iptables -t nat -D PREROUTING -i $br -p udp --dport 53 -j REDIRECT --to-ports $port 2>/dev/null; " +
		"iptables -t nat -D PREROUTING -i $br -p tcp --dport 53 -j REDIRECT --to-ports $port 2>/dev/null; " +
		"ip6tables -t nat -D PREROUTING -i $br -p udp --dport 53 -j REDIRECT --to-ports $port 2>/dev/null; " +
		"ip6tables -t nat -D PREROUTING -i $br -p tcp --dport 53 -j REDIRECT --to-ports $port 2>/dev/null; " +
		"done; done")
}
