//go:build linux

package app

import (
	"nfqws2strategy/internal/awg"
	"nfqws2strategy/internal/logbuf"
)

// Lifecycle of the domain-mask DNS proxy: it transparently intercepts LAN :53
// (via the hook's REDIRECT), and for every answer whose name matches a zone
// entry it adds the IPs to the routing ipset. Started/refreshed/stopped together
// with split-routing when domain_source=="dnsproxy".

// awgZoneMatchers compiles domain matchers from all enabled zones' domain lists.
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

// awgEnsureDNSProxy starts/updates the domain-mask DNS proxy when
// domain_source=="dnsproxy" with at least one matcher, otherwise stops it. It
// returns true when the proxy is (now) running, so the firewall hook installs
// the LAN :53 REDIRECT only while the proxy is actually up (never blackhole DNS).
func (a *App) awgEnsureDNSProxy(cfg *awg.ServerConfig, targetSet string) bool {
	ms := awgZoneMatchers(cfg)
	want := cfg.Routing.Mode != "off" && cfg.Routing.DomainSource == "dnsproxy" && len(ms) > 0
	a.awgRoute.mu.Lock()
	p := a.awgRoute.dnsProxy
	a.awgRoute.mu.Unlock()
	if !want {
		if p != nil {
			a.awgStopDNSProxy()
		}
		return false
	}
	if p != nil {
		p.SetMatchers(ms) // refresh on zone change
		return true
	}
	np := awg.NewDNSProxy(awgDNSAddr, awgDNSUpstream, func(ip string) {
		// Add every matched answer IP (idempotent -exist). No dedup cache on purpose:
		// a zone edit flushes the set, and the next DNS query must re-learn cleanly.
		// The target set is read live so a mode switch routes new hits correctly.
		_, _ = awgRun("ipset add " + awgTargetSet(a.awg.Config().Routing.Mode) + " " + ip + " -exist")
	})
	a.awgLoadRecent(np) // restore domains seen in a previous run (before matching)
	np.SetMatchers(ms)  // re-evaluates the loaded cache → re-adds matching domains
	if err := np.Start(); err != nil {
		logbuf.Append("awg2", "error", "DNS-прокси (маски доменов) не запустился: "+err.Error())
		return false
	}
	a.awgRoute.mu.Lock()
	a.awgRoute.dnsProxy = np
	a.awgRoute.mu.Unlock()
	logbuf.Append("awg2", "info", "DNS-прокси запущен: перехват :53 → домены/поддомены/маски идут в туннель")
	return true
}

// awgStopDNSProxy stops the proxy and removes its LAN :53 REDIRECT rules so DNS
// falls straight back to the router's resolver.
func (a *App) awgStopDNSProxy() {
	a.awgRoute.mu.Lock()
	p := a.awgRoute.dnsProxy
	a.awgRoute.dnsProxy = nil
	a.awgRoute.mu.Unlock()
	if p != nil {
		p.Stop()
	}
	_, _ = awgRun("for br in $(ls /sys/class/net/ 2>/dev/null | grep '^br'); do " +
		"iptables -t nat -D PREROUTING -i $br -p udp --dport 53 -j REDIRECT --to-ports " + awgDNSPort + " 2>/dev/null; " +
		"iptables -t nat -D PREROUTING -i $br -p tcp --dport 53 -j REDIRECT --to-ports " + awgDNSPort + " 2>/dev/null; done")
}
