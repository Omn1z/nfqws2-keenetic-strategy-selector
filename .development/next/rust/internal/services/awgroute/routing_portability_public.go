package awgroute

import (
	"fmt"

	"nfqws2strategy/internal/services/awg"
)

// ValidateAWGConnectionReference applies the same public identity validation
// as routing-file import, including the canonical fingerprint. Empty identity
// fields remain valid for an explicit missing/blank connection reference.
func ValidateAWGConnectionReference(ref AWG2ConnectionRef) error {
	return awgValidateRoutingDocument(AWGRoutingDocument{
		Format: awgRoutingFormat, Version: 1,
		Routing:     awg.RoutingConfig{Mode: "off"},
		Connections: []AWG2ConnectionRef{ref},
	})
}

// AWG2PublicConnections returns current configured connection identities,
// without status probes, kernel reads, secret copies or detached references.
func (svc *Service) AWG2PublicConnections() []AWG2ConnectionRef {
	svc.mu.RLock()
	servers := make([]managedServer, 0, len(svc.order))
	for _, id := range svc.order {
		if server := svc.servers[id]; server != nil && server.Manager != nil {
			servers = append(servers, *server)
		}
	}
	svc.mu.RUnlock()
	refs := make([]AWG2ConnectionRef, 0, len(servers))
	for i := range servers {
		refs = append(refs, awgConnectionReference(&servers[i]))
	}
	return refs
}

// WithAWG2PublicConnections keeps configured VPN identities stable while a
// dependent service validates and commits its references. The callback may
// read AWG state, but must not call an AWG lifecycle mutator or reacquire
// client operations. No service/manager read lock is held across the callback.
func (svc *Service) WithAWG2PublicConnections(fn func([]AWG2ConnectionRef) error) error {
	if fn == nil {
		return fmt.Errorf("AWG connection callback is required")
	}
	_, unlock := svc.lockClientOps(false)
	defer unlock()
	return fn(svc.AWG2PublicConnections())
}
