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
func (svc *Service) awgEnsureDNSProxy(cfg *awg.ServerConfig, targetSet string) bool {
	ms := awgZoneMatchers(cfg)
	want := cfg.Routing.Mode != "off" && cfg.Routing.DomainSource == "dnsproxy" && len(ms) > 0
	svc.route.mu.Lock()
	p := svc.route.dnsProxy
	svc.route.mu.Unlock()
	if !want {
		if p != nil {
			svc.awgStopDNSProxy()
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
		_, _ = awgRun("ipset add " + awgTargetSet(svc.awg.Config().Routing.Mode) + " " + ip + " -exist")
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
	logbuf.Append("awg2", "info", "DNS-прокси запущен: перехват :53 → домены/поддомены/маски идут в туннель")
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
