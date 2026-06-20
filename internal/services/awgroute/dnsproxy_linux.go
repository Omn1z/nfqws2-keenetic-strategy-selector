//go:build linux

package awgroute

import (
	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/logbuf"
)

// Lifecycle of the domain-mask DNS proxy: it transparently intercepts LAN :53
// (via the hook's REDIRECT), and for every answer whose name matches a zone
// entry it adds the IPs to the routing ipset. Started/refreshed/stopped together
// with split-routing when domain_source=="dnsproxy".

// awgZoneMatchers compiles domain matchers from ALL enabled zones (any direction).
// The proxy fires onMatch for a name matching any zone; the callback then routes
// the IP to the include or exclude set by which zone matched.
func (svc *Service) awgZoneMatchers(cfg *awg.ServerConfig) []awg.DomainMatcher {
	var entries []string
	for _, z := range cfg.Routing.Zones {
		if !z.Enabled {
			continue
		}
		exp, _ := svc.expandEntries(z.Domains)
		entries = append(entries, exp...)
	}
	ms, _ := awg.CompileMatchers(awgDropCatchAll(entries))
	return ms
}

// awgZoneMatchersByMode compiles matchers for the enabled GLOBAL zones of one
// direction ("include" or "exclude"). Source-bound zones are isolated to their
// own per-zone ipset (see awgZoneSourceMatchers) and excluded here so a domain
// scoped to one device never lands in the LAN-wide awg2_inc / awg2_exc sets.
func (svc *Service) awgZoneMatchersByMode(cfg *awg.ServerConfig, mode string) []awg.DomainMatcher {
	var entries []string
	for _, z := range cfg.Routing.Zones {
		if !z.Enabled || len(z.SourceIPs) > 0 {
			continue
		}
		zm := "include"
		if z.Mode == "exclude" {
			zm = "exclude"
		}
		if zm == mode {
			exp, _ := svc.expandEntries(z.Domains)
			entries = append(entries, exp...)
		}
	}
	ms, _ := awg.CompileMatchers(awgDropCatchAll(entries))
	return ms
}

// awgZoneSourceMatchers builds the per-source-zone matcher list in the same
// order as awgBuildSourceSets so each entry's SetName matches its zone's ipset.
func (svc *Service) awgZoneSourceMatchers(cfg *awg.ServerConfig) []sourceZoneMatchers {
	sb := sourceBoundZones(cfg.Routing.Zones)
	out := make([]sourceZoneMatchers, 0, len(sb))
	for i, z := range sb {
		exp, _ := svc.expandEntries(z.Domains)
		ms, _ := awg.CompileMatchers(awgDropCatchAll(exp))
		out = append(out, sourceZoneMatchers{Matchers: ms, SetName: sourceZoneSetName(i)})
	}
	return out
}

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
	want := (eff == "include" || eff == "exclude" || hasSrc) && len(ms) > 0 && awgUsesDNSProxy(cfg)
	svc.route.mu.Lock()
	p := svc.route.dnsProxy
	svc.route.mu.Unlock()
	if !want {
		if p != nil {
			svc.awgStopDNSProxy()
		}
		return false
	}
	// Publish the per-direction matchers the onMatch callback routes by (lock-free,
	// so it never contends with a routing op holding route.mu). Refreshed every call.
	inc := svc.awgZoneMatchersByMode(cfg, "include")
	exc := svc.awgZoneMatchersByMode(cfg, "exclude")
	src := svc.awgZoneSourceMatchers(cfg)
	svc.route.incMatchers.Store(&inc)
	svc.route.excMatchers.Store(&exc)
	svc.route.srcZoneMatchers.Store(&src)
	if p != nil {
		p.SetMatchers(ms) // refresh on zone change
		return true
	}
	np := awg.NewDNSProxy(awgDNSAddr, awgDNSUpstream, func(name, ip string) {
		if provider, ok := sharedCDNProvider(ip); ok {
			svc.awgNoteSharedCDNSkip("dnsproxy", name, ip, provider)
			return
		}
		// Per-source-bound zones first: a name landing in a device-scoped zone
		// must reach that zone's ipset regardless of any global include/exclude
		// overlap. v6 vs v4 picks the family-matching per-zone set.
		v6Suffix := ""
		if isIPv6(ip) {
			v6Suffix = "_6"
		}
		if szs := svc.route.srcZoneMatchers.Load(); szs != nil {
			for _, sz := range *szs {
				if awg.MatchAny(sz.Matchers, name) {
					_, _ = awgRun("ipset add " + sz.SetName + v6Suffix + " " + ip + " -exist")
				}
			}
		}
		// Route the matched IP to the exclude set when the name matched an exclude
		// zone (exclude wins on overlap), else the include set. Matchers are read live
		// so a zone edit takes effect without recreating the proxy. Idempotent -exist;
		// a zone edit flushes the sets so the next query re-learns cleanly.
		set := awgSetInc + v6Suffix
		if e := svc.route.excMatchers.Load(); e != nil && awg.MatchAny(*e, name) {
			set = awgSetExc + v6Suffix
		}
		_, _ = awgRun("ipset add " + set + " " + ip + " -exist")
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
	_, _ = awgRun("for br in $(ls /sys/class/net/ 2>/dev/null | grep '^br'); do " +
		"iptables -t nat -D PREROUTING -i $br -p udp --dport 53 -j REDIRECT --to-ports " + awgDNSPort + " 2>/dev/null; " +
		"iptables -t nat -D PREROUTING -i $br -p tcp --dport 53 -j REDIRECT --to-ports " + awgDNSPort + " 2>/dev/null; " +
		"ip6tables -t nat -D PREROUTING -i $br -p udp --dport 53 -j REDIRECT --to-ports " + awgDNSPort + " 2>/dev/null; " +
		"ip6tables -t nat -D PREROUTING -i $br -p tcp --dport 53 -j REDIRECT --to-ports " + awgDNSPort + " 2>/dev/null; done")
}
