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
	return svc.dnsRouteCandidates(awgDNSRunningOS)
}

func (svc *Service) dnsRouteCandidates(running func(string) bool) []DNSRouteInfo {
	servers := svc.serverSnapshot()
	identities := make(map[string]awg.LocalClientIdentity, len(servers))
	for _, srv := range servers {
		identities[srv.ID] = srv.Manager.RuntimeLocalClientIdentity()
	}
	svc.clients.mu.Lock()
	activated := make(map[string]bool, len(servers))
	for _, srv := range servers {
		activated[srv.ID] = svc.clients.standbyActive[srv.Manager]
	}
	svc.clients.mu.Unlock()
	usable := func(id string) bool {
		identity, ok := identities[id]
		return ok && identity.Enabled && identity.ClientEnabled && strings.TrimSpace(identity.Endpoint) != "" && (!identity.Standby || activated[id])
	}
	statuses := make(map[string]*ClientStatus, len(servers))
	known := make(map[string]bool, len(servers))
	byID := make(map[string]*managedServer, len(servers))
	for _, srv := range servers {
		byID[srv.ID] = srv
	}
	driver := svc.clientLifecycleDriver()
	connected := func(id string) bool {
		if !usable(id) {
			return false
		}
		if !known[id] {
			statuses[id] = driver.status(byID[id].Manager)
			known[id] = true
		}
		st := statuses[id]
		return st != nil && st.Connected
	}
	// Keep logical IDs stable: an explicitly selected DNS profile follows its
	// connection reserves without forcing users to edit DNS settings as well.
	// Read each physical UAPI status at most once per candidates snapshot.
	out := []DNSRouteInfo{}
	for _, srv := range servers {
		identity := identities[srv.ID]
		if !identity.Enabled || !identity.ClientEnabled || strings.TrimSpace(identity.Endpoint) == "" {
			continue
		}
		cfg := awg.ServerConfig{Endpoint: identity.Endpoint, ClientIface: identity.ClientIface}
		iface := awgClientIfaceName(cfg)
		if usable(srv.ID) && len(identity.FallbackTunnelIDs) > 0 {
			seen := map[string]bool{}
			var selectConnected func(string) string
			selectConnected = func(id string) string {
				if seen[id] {
					return ""
				}
				seen[id] = true
				if connected(id) {
					return id
				}
				for _, fallback := range identities[id].FallbackTunnelIDs {
					if selected := selectConnected(fallback); selected != "" {
						return selected
					}
				}
				return ""
			}
			if selected := selectConnected(srv.ID); selected != "" {
				iface = awgClientIfaceName(awg.ServerConfig{ClientIface: identities[selected].ClientIface})
			}
		}
		out = append(out, DNSRouteInfo{ID: srv.ID, Name: awgServerLabel(srv, cfg), Interface: iface, Available: usable(srv.ID) && running(iface)})
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
