//go:build linux

package awgroute

// awgEffectiveDNSUpstream returns the addr the DNS proxy should forward to.
// Currently always awgDNSUpstream — the chain toggle works by moving the
// iptables REDIRECT target between :5353 (pi-hole-first) and :5354 (proxy-
// direct), NOT by rewiring the proxy's upstream. Kept as a helper so future
// non-REDIRECT chain topologies can splice in without touching every caller.
func (svc *Service) awgEffectiveDNSUpstream() string { return awgDNSUpstream }

// DNSProxyUpstreamAddr returns the proxy's listening address in pi-hole/dnsmasq
// "IP#PORT" upstream syntax. Pi-hole points its upstream here when the chain is
// inverted (pi-hole first → proxy as its upstream), so the proxy still sees and
// classifies every query while pi-hole logs the real client IP.
func DNSProxyUpstreamAddr() string { return "127.0.0.1#" + awgDNSPort }

// SetDNSChainEnabled flips the chain mode and rewrites the firewall hook so the
// REDIRECT target moves to pi-hole (:5353) when on or back to the proxy (:5354)
// when off. No-op when routing isn't currently applied — the hook will pick up
// the new state on the next routing apply. The CAS on the atomic.Bool gives
// us "already in that state → no-op" without a mutex round-trip.
func (svc *Service) SetDNSChainEnabled(enabled bool) {
	if svc.route.dnsChainEnabledFlag.Load() == enabled {
		return
	}
	_, unlock := svc.lockClientOps(false)
	defer unlock()
	if svc.route.dnsChainEnabledFlag.Swap(enabled) == enabled {
		return
	}
	svc.route.mu.Lock()
	initialized := svc.route.multiStopRefresh != nil || svc.route.stopRefresh != nil || svc.route.dnsProxy != nil
	svc.route.mu.Unlock()
	if !initialized {
		return
	} // Startup: supervisor applies the chosen chain after initialization.
	svc.awgApplyMultiHostRoutesOS()
}

// dnsChainEnabled returns the current chain mode for the firewall hook generator.
// Called on every watchdog tick + every DNS-proxy ensure — lock-free read.
func (svc *Service) dnsChainEnabled() bool {
	return svc.route.dnsChainEnabledFlag.Load()
}
