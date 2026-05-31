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
func awgZoneMatchers(cfg *awg.ServerConfig) []awg.DomainMatcher {
	var entries []string
	for _, z := range cfg.Routing.Zones {
		if z.Enabled {
			entries = append(entries, z.Domains...)
		}
	}
	ms, _ := awg.CompileMatchers(entries)
	return ms
}

// awgZoneMatchersByMode compiles matchers for the enabled zones of one direction
// ("include" or "exclude"), so a matched mask's IPs land in the right set.
func awgZoneMatchersByMode(cfg *awg.ServerConfig, mode string) []awg.DomainMatcher {
	var entries []string
	for _, z := range cfg.Routing.Zones {
		if !z.Enabled {
			continue
		}
		zm := "include"
		if z.Mode == "exclude" {
			zm = "exclude"
		}
		if zm == mode {
			entries = append(entries, z.Domains...)
		}
	}
	ms, _ := awg.CompileMatchers(entries)
	return ms
}

// awgEnsureDNSProxy starts/updates the domain-mask DNS proxy when
// domain_source=="dnsproxy" with at least one matcher, otherwise stops it. It
// returns true when the proxy is (now) running, so the firewall hook installs
// the LAN :53 REDIRECT only while the proxy is actually up (never blackhole DNS).
func (svc *Service) awgEnsureDNSProxy(cfg *awg.ServerConfig) bool {
	ms := awgZoneMatchers(cfg)
	want := cfg.Routing.Mode != "off" && cfg.Routing.Mode != "full" && cfg.Routing.DomainSource == "dnsproxy" && len(ms) > 0
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
	inc := awgZoneMatchersByMode(cfg, "include")
	exc := awgZoneMatchersByMode(cfg, "exclude")
	svc.route.incMatchers.Store(&inc)
	svc.route.excMatchers.Store(&exc)
	if p != nil {
		p.SetMatchers(ms) // refresh on zone change
		return true
	}
	np := awg.NewDNSProxy(awgDNSAddr, awgDNSUpstream, func(name, ip string) {
		// Route the matched IP to the exclude set when the name matched an exclude
		// zone (exclude wins on overlap), else the include set. Matchers are read live
		// so a zone edit takes effect without recreating the proxy. Idempotent -exist;
		// a zone edit flushes the sets so the next query re-learns cleanly.
		set := awgSetInc
		if e := svc.route.excMatchers.Load(); e != nil && awg.MatchAny(*e, name) {
			set = awgSetExc
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
		"iptables -t nat -D PREROUTING -i $br -p tcp --dport 53 -j REDIRECT --to-ports " + awgDNSPort + " 2>/dev/null; done")
}
