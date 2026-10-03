package awgroute

import (
	"context"
	"net"
	"strings"

	"nfqws2strategy/internal/services/awg"
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
		identity := srv.Manager.RuntimeLocalClientIdentity()
		if !identity.Enabled || !identity.ClientEnabled || strings.TrimSpace(identity.Endpoint) == "" {
			continue
		}
		cfg := awg.ServerConfig{Endpoint: identity.Endpoint, ClientIface: identity.ClientIface}
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
	release, err := svc.routingDNSGate.acquire(ctx, 0, false)
	if err != nil {
		if ctx.Err() == nil && svc.routingDNSGate.failed() {
			// Preserve only a validated, unfiltered upstream address hint. Do
			// not deliver the answer or install routes while policy is broken.
			// This lets a later apply prepare endpoints/static sets even when
			// the native resolver feeds back into this DNS service.
			if ips, validationErr := awg.ValidatedDNSAnswerIPs(domain, response); validationErr == nil {
				svc.rememberPolicyDNS(domain, ips)
			}
		}
		return nil, err
	}
	svc.route.mu.Lock()
	p := svc.route.dnsProxy
	svc.route.mu.Unlock()
	generation := svc.routingDNSGate.version()
	if p == nil {
		defer release()
		return response, svc.routingDNSGate.verify(generation)
	}
	release()
	src := ""
	if clientIP != nil {
		src = clientIP.String()
	}
	filtered, err := p.ObserveAnswerContext(ctx, src, domain, response)
	if err != nil {
		return nil, err
	}
	if err := svc.routingDNSGate.verify(generation); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return filtered, nil
}
