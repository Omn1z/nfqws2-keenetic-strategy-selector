package awg

import "strings"

// ConnectionOverview is the read-only profile metadata returned to status
// views. Peer keys, credentials and rule match lists stay in the manager.
type ConnectionOverview struct {
	ConfiguredEndpoint string
	Endpoint           string
	Host               string
	ClientIface        string
	Install            string
	RuntimeInstall     string
	Protocol           string
	ProtocolVersion    string
	ServerPublicKey    string
	Enabled            bool
	Deployed           bool
	DeploymentPending  bool
	TrafficObfuscation bool
	HasPassword        bool
	HasKey             bool
	HasServerKey       bool
}

func (m *Manager) ConnectionOverview() ConnectionOverview {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg, wire := m.cfg, m.cfg
	if m.applied != nil {
		wire = m.applied
	}
	return ConnectionOverview{
		ConfiguredEndpoint: cfg.Endpoint,
		Endpoint:           m.selectedClientEndpointLocked(wire.Endpoint),
		Host:               strings.TrimSpace(cfg.Conn.Host),
		ClientIface:        cfg.ClientIface,
		Install:            cfg.Install,
		RuntimeInstall:     wire.Install,
		Protocol:           wire.Protocol,
		ProtocolVersion:    wire.EffectiveProtocolVersion(),
		ServerPublicKey:    wire.PublicKey,
		Enabled:            cfg.Enabled,
		Deployed:           cfg.DeployedAt > 0,
		DeploymentPending:  m.applied != nil,
		TrafficObfuscation: wire.UseObfuscation(),
		HasPassword:        strings.TrimSpace(cfg.Conn.Password) != "",
		HasKey:             strings.TrimSpace(cfg.Conn.KeyPEM) != "",
		HasServerKey:       strings.TrimSpace(cfg.PrivateKey) != "",
	}
}

// LocalClientStatus contains the local interface and peer fields needed to poll
// or probe the tunnel. Polling never needs the private keys or routing lists.
type LocalClientStatus struct {
	Endpoint    string
	Host        string
	ClientIface string
	Address     string
	MTU         int
	AllowedIPs  string
	HasPeer     bool
}

func (m *Manager) RuntimeClientStatus() LocalClientStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg := m.runtimeConfigLocked()
	status := LocalClientStatus{
		Endpoint:    m.selectedClientEndpointLocked(cfg.Endpoint),
		Host:        cfg.Conn.Host,
		ClientIface: cfg.ClientIface,
		MTU:         cfg.MTU,
	}
	if status.MTU <= 0 {
		status.MTU = cfg.Routing.MTU
	}
	if status.MTU <= 0 {
		status.MTU = 1280
	}
	addressFound := false
	for _, peer := range cfg.Peers {
		if !status.HasPeer && (peer.IsRouter || cfg.Client.PeerID != "" && peer.ID == cfg.Client.PeerID) {
			status.AllowedIPs, status.HasPeer = peer.AllowedIPs, true
		}
		if !addressFound && peer.IsRouter {
			status.Address, addressFound = peer.Address, true
		}
		if status.HasPeer && addressFound {
			break
		}
	}
	return status
}

func (m *Manager) RoutingZones() []Zone {
	m.mu.Lock()
	defer m.mu.Unlock()
	return cloneRoutingZones(m.cfg.Routing.Zones)
}

type RuleFailover struct {
	PrimaryID string
	BackupIDs []string
}

func (m *Manager) RuleFailovers() []RuleFailover {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []RuleFailover
	var defaultTargets map[string]bool
	for _, zone := range m.cfg.Routing.Zones {
		if !zone.Enabled || zone.WaitingForConnection || zone.RouteValue() != "tunnel" {
			continue
		}
		id := strings.TrimSpace(zone.TunnelID)
		if len(zone.FallbackTunnelIDs) == 0 {
			// Rules without overrides use the same connection-level order;
			// one marker is sufficient for the runtime change signature.
			if defaultTargets[id] {
				continue
			}
			if defaultTargets == nil {
				defaultTargets = make(map[string]bool)
			}
			defaultTargets[id] = true
		}
		out = append(out, RuleFailover{PrimaryID: id, BackupIDs: append([]string(nil), zone.FallbackTunnelIDs...)})
	}
	return out
}
