package awgroute

import (
	"context"
	"net"
	"strings"
)

// DNSRouteInfo deliberately contains no endpoint credentials or key material.
type DNSRouteInfo struct {
	ID, Name, Interface string
	Available           bool
}

// DNSRouteCandidates includes every enabled local client, including WARP and
// clients without split-routing rules. A stale handshake alone does not exclude
// an idle tunnel: the DNS connection can trigger its next handshake.
func (svc *Service) DNSRouteCandidates() []DNSRouteInfo {
	out := []DNSRouteInfo{}
	for _, srv := range svc.serverSnapshot() {
		cfg := srv.Manager.RuntimeConfig()
		if !cfg.Enabled || !cfg.Client.Enabled || strings.TrimSpace(cfg.Endpoint) == "" {
			continue
		}
		iface := awgClientIfaceName(cfg)
		out = append(out, DNSRouteInfo{ID: srv.ID, Name: awgServerLabel(srv, cfg), Interface: iface, Available: awgDNSRunningOS(iface)})
	}
	return out
}

// ObserveDNSAnswer uses the live learner's immutable callback snapshot. This
// preserves per-device policy, recent-answer replay, and AAAA suppression for
// encrypted DNS clients which bypass the transparent port-53 proxy.
func (svc *Service) ObserveDNSAnswer(ctx context.Context, domain string, response []byte, clientIP net.IP) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	svc.route.mu.Lock()
	p := svc.route.dnsProxy
	svc.route.mu.Unlock()
	if p == nil {
		return response, nil
	}
	src := ""
	if clientIP != nil {
		src = clientIP.String()
	}
	filtered, err := p.ObserveAnswer(src, domain, response)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return filtered, nil
}
