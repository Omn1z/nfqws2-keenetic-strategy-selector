//go:build linux

package awgroute

// External services (currently the Pi-hole chain toggle) can swap the DNS
// proxy's upstream resolver — the AWG2 zone-routing logic doesn't change, only
// where the proxy forwards unmatched queries.

// awgEffectiveDNSUpstream returns the addr the DNS proxy should forward to.
// Default is awgDNSUpstream (the system resolver); an override set by
// SetDNSUpstream wins so the Pi-hole chain can splice into the path.
func (svc *Service) awgEffectiveDNSUpstream() string {
	svc.route.mu.Lock()
	defer svc.route.mu.Unlock()
	if svc.route.dnsUpstreamOverride != "" {
		return svc.route.dnsUpstreamOverride
	}
	return awgDNSUpstream
}

// DNSProxyUpstreamAddr returns the proxy's listening address in pi-hole/dnsmasq
// "IP#PORT" upstream syntax. Pi-hole points its upstream here when the chain is
// inverted (pi-hole first → proxy as its upstream), so the proxy still sees and
// classifies every query while pi-hole logs the real client IP.
func DNSProxyUpstreamAddr() string { return "127.0.0.1#" + awgDNSPort }

// SetDNSUpstream records an override (or clears it with "") and pushes it into
// the running DNS proxy, if one exists. Cheap atomic swap on the proxy side —
// in-flight queries finish on the old upstream; new ones use the new addr.
func (svc *Service) SetDNSUpstream(addr string) {
	svc.route.mu.Lock()
	svc.route.dnsUpstreamOverride = addr
	p := svc.route.dnsProxy
	svc.route.mu.Unlock()
	if p != nil {
		if addr == "" {
			p.SetUpstream(awgDNSUpstream)
		} else {
			p.SetUpstream(addr)
		}
	}
}
