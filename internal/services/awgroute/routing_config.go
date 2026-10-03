package awgroute

import (
	"strings"

	"nfqws2strategy/internal/services/awg"
)

// awgRoutingSettings belongs to the router rather than to the connection that
// happens to be selected in the editor. Rules and their committed state remain
// on their owning managers for compatibility with the multi-tunnel datapath.
type awgRoutingSettings struct {
	Mode         string `json:"mode"`
	MTU          int    `json:"mtu"`
	Killswitch   bool   `json:"killswitch"`
	DomainSource string `json:"domain_source"`
	SNIRouting   bool   `json:"sni_routing"`
	TraceEnabled bool   `json:"trace_enabled"`
}

func routingSettingsFrom(rc awg.RoutingConfig) awgRoutingSettings {
	// Do not normalize the caller's zones: their slices can belong to a manager
	// snapshot, and settings normalization must not mutate rule content.
	rc.Zones = nil
	rc.Normalize()
	return awgRoutingSettings{
		Mode:         rc.Mode,
		MTU:          rc.MTU,
		Killswitch:   rc.Killswitch,
		DomainSource: rc.DomainSource,
		SNIRouting:   rc.SNIRouting,
		TraceEnabled: rc.TraceEnabled,
	}
}

func (s awgRoutingSettings) apply(rc awg.RoutingConfig) awg.RoutingConfig {
	rc.Mode = s.Mode
	rc.MTU = s.MTU
	rc.Killswitch = s.Killswitch
	rc.DomainSource = s.DomainSource
	rc.SNIRouting = s.SNIRouting
	rc.TraceEnabled = s.TraceEnabled
	return rc
}

func legacyRoutingSettings(entries []awgPersistedServer, activeID string) awgRoutingSettings {
	selected := -1
	for i, entry := range entries {
		if entry.ID == activeID {
			selected = i
			break
		}
	}
	// A newly added, selected profile can have untouched defaults while another
	// connection is still routing traffic. Prefer that committed policy to the
	// empty profile that caused the original UI reset.
	if selected >= 0 && entries[selected].Config.Routing.Active && entries[selected].Config.Routing.Mode != "off" {
		return routingSettingsFrom(entries[selected].Config.Routing)
	}
	for _, entry := range entries {
		if entry.Config.Routing.Active && entry.Config.Routing.Mode != "off" {
			return routingSettingsFrom(entry.Config.Routing)
		}
	}
	defaults := routingSettingsFrom(awg.RoutingConfig{})
	configured := func(rc awg.RoutingConfig) bool {
		return len(rc.Zones) > 0 || routingSettingsFrom(rc) != defaults
	}
	if selected >= 0 && configured(entries[selected].Config.Routing) {
		return routingSettingsFrom(entries[selected].Config.Routing)
	}
	for _, entry := range entries {
		if configured(entry.Config.Routing) {
			return routingSettingsFrom(entry.Config.Routing)
		}
	}
	if selected >= 0 {
		return routingSettingsFrom(entries[selected].Config.Routing)
	}
	return defaults
}

func (svc *Service) currentRoutingSettings() awgRoutingSettings {
	svc.mu.RLock()
	if svc.routing != nil {
		settings := *svc.routing
		svc.mu.RUnlock()
		return settings
	}
	activeID := svc.activeID
	entries := make([]awgPersistedServer, 0, len(svc.order))
	managers := make([]*managedServer, 0, len(svc.order))
	for _, id := range svc.order {
		if srv := svc.servers[id]; srv != nil {
			managers = append(managers, srv)
		}
	}
	selected := svc.awg
	svc.mu.RUnlock()
	// The fallback also keeps services made by older callers or test fixtures
	// compatible until their first persisted routing edit.
	for _, srv := range managers {
		entries = append(entries, awgPersistedServer{ID: srv.ID, Config: srv.Manager.Config()})
	}
	if len(entries) == 0 && selected != nil {
		entries = append(entries, awgPersistedServer{ID: activeID, Config: selected.Config()})
	}
	return legacyRoutingSettings(entries, activeID)
}

func (svc *Service) rememberRoutingSettings(settings awgRoutingSettings) {
	svc.mu.Lock()
	svc.routing = &settings
	svc.mu.Unlock()
}

func (svc *Service) globalRoutingConfig(rules []awg.Zone) awg.RoutingConfig {
	routing := svc.currentRoutingSettings().apply(awg.RoutingConfig{Zones: rules})
	if routing.Mode == "off" {
		return routing
	}
	usable := map[string]bool{}
	for _, srv := range svc.serverSnapshot() {
		cfg := srv.Manager.Config()
		if cfg.Enabled && cfg.Client.Enabled && cfg.Routing.Active && cfg.Routing.Mode != "off" {
			usable[srv.ID] = true
			if routing.Mode == "full" {
				routing.Active = true // retain the legacy zone-less full-mode view
			}
		}
	}
	for _, z := range rules {
		if !z.Enabled || z.WaitingForConnection {
			continue
		}
		primary := strings.TrimSpace(z.TunnelID)
		if z.RouteValue() == "tunnel" {
			for _, id := range fallbackCandidates(primary, z.FallbackTunnelIDs) {
				if usable[id] {
					routing.Active = true
					return routing
				}
			}
		} else if usable[primary] {
			routing.Active = true
			return routing
		}
	}
	return routing
}
