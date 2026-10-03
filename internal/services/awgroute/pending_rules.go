package awgroute

import (
	"strings"

	"nfqws2strategy/internal/services/awg"
)

// AWG2ConnectionRef contains only a connection's public identity. It can stay
// with detached rules after the manager (including all its secrets) is deleted.
type AWG2ConnectionRef struct {
	Ref             string `json:"ref"`
	Label           string `json:"label"`
	Endpoint        string `json:"endpoint"`
	ClientIface     string `json:"client_iface"`
	Protocol        string `json:"protocol"`
	ServerPublicKey string `json:"server_public_key,omitempty"`
	Fingerprint     string `json:"fingerprint"`
}

func cloneAWGConnectionRefs(in map[string]AWG2ConnectionRef) map[string]AWG2ConnectionRef {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]AWG2ConnectionRef, len(in))
	for id, ref := range in {
		out[id] = ref
	}
	return out
}

func cloneAWGZones(in []awg.Zone) []awg.Zone {
	if in == nil {
		return nil
	}
	out := make([]awg.Zone, len(in))
	for i, z := range in {
		z.Domains = cloneAWGStrings(z.Domains)
		z.IPs = cloneAWGStrings(z.IPs)
		z.SourceIPs = cloneAWGStrings(z.SourceIPs)
		z.FallbackTunnelIDs = cloneAWGStrings(z.FallbackTunnelIDs)
		if z.IncludeSubdomains != nil {
			value := *z.IncludeSubdomains
			z.IncludeSubdomains = &value
		}
		out[i] = z
	}
	return out
}

func cloneAWGStrings(in []string) []string {
	if in == nil {
		return nil
	}
	return append([]string{}, in...)
}

// normalizeAWGPendingRules never attaches a waiting rule automatically, even
// if its old ID exists again. Empty IDs on ordinary legacy rules still belong
// to their owning manager; only explicit waiting or a missing primary detaches.
func normalizeAWGPendingRules(st *awgPersisted) {
	live := make(map[string]bool, len(st.Servers))
	for _, server := range st.Servers {
		live[server.ID] = true
	}
	pending := cloneAWGZones(st.PendingRules)
	for i := range pending {
		pending[i].WaitingForConnection = true
	}
	for i := range st.Servers {
		server := &st.Servers[i]
		zones := make([]awg.Zone, 0, len(server.Config.Routing.Zones))
		for _, z := range server.Config.Routing.Zones {
			primary := strings.TrimSpace(z.TunnelID)
			if z.WaitingForConnection || primary != "" && !live[primary] {
				z.WaitingForConnection = true
				pending = append(pending, z)
				continue
			}
			zones = append(zones, z)
		}
		server.Config.Routing.Zones = zones
	}
	st.PendingRules = cloneAWGZones(pending)
	st.ConnectionRefs = awgRetainedConnectionRefs(st.ConnectionRefs, st.PendingRules, st.Servers)
}

// Retain only missing identities still referenced by a primary or fallback.
// Live descriptors are generated from their managers, and unrelated deleted
// profiles must not accumulate after the user removes/reassigns their rules.
func awgRetainedConnectionRefs(refs map[string]AWG2ConnectionRef, pending []awg.Zone, servers []awgPersistedServer) map[string]AWG2ConnectionRef {
	live := make(map[string]bool, len(servers))
	for _, server := range servers {
		live[server.ID] = true
	}
	var retained map[string]AWG2ConnectionRef
	retainMissing := func(id string) {
		id = strings.TrimSpace(id)
		if id == "" || live[id] {
			return
		}
		ref, known := refs[id]
		if !known {
			// Legacy dangling IDs have no recoverable public wire identity.
			// Keep an explicit label-only reference; it cannot auto-match.
			ref = AWG2ConnectionRef{Ref: id, Label: id}
		}
		ref.Ref = id
		if retained == nil {
			retained = map[string]AWG2ConnectionRef{}
		}
		retained[id] = ref
	}
	for _, z := range pending {
		retainMissing(z.TunnelID)
		for _, fallback := range z.FallbackTunnelIDs {
			retainMissing(fallback)
		}
	}
	for _, server := range servers {
		for _, z := range server.Config.Routing.Zones {
			for _, fallback := range z.FallbackTunnelIDs {
				retainMissing(fallback)
			}
		}
	}
	return retained
}

func awgPendingReferencesID(rules []awg.Zone, id string) bool {
	for _, z := range rules {
		if strings.TrimSpace(z.TunnelID) == id {
			return true
		}
		for _, fallback := range z.FallbackTunnelIDs {
			if strings.TrimSpace(fallback) == id {
				return true
			}
		}
	}
	return false
}

// connectionRefSnapshot combines retained identities with current public
// identities, without holding Service.mu while taking a Manager lock.
func (svc *Service) connectionRefSnapshot() map[string]AWG2ConnectionRef {
	svc.mu.RLock()
	refs := cloneAWGConnectionRefs(svc.connectionRefs)
	svc.mu.RUnlock()
	if refs == nil {
		refs = map[string]AWG2ConnectionRef{}
	}
	for _, server := range svc.serverSnapshot() {
		refs[server.ID] = awgConnectionReference(server)
	}
	return refs
}

func (svc *Service) rememberConnectionRefs(refs map[string]AWG2ConnectionRef) {
	svc.mu.Lock()
	defer svc.mu.Unlock()
	if svc.connectionRefs == nil {
		svc.connectionRefs = map[string]AWG2ConnectionRef{}
	}
	for id, ref := range refs {
		svc.connectionRefs[id] = ref
	}
}
