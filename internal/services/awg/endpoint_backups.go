package awg

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const MaxEndpointBackups = 8

type clientEndpointIdentity struct {
	endpoint, serverKey, iface, peerKey, protocol string
	obfuscation                                   Obfuscation
	obfuscated                                    bool
}

func (m *Manager) clientEndpointIdentityLocked() clientEndpointIdentity {
	wire := m.cfg
	if m.applied != nil {
		wire = m.applied
	}
	identity := clientEndpointIdentity{endpoint: wire.Endpoint, serverKey: wire.PublicKey, iface: m.cfg.ClientIface, protocol: wire.EffectiveProtocolVersion(), obfuscated: wire.UseObfuscation(), obfuscation: wire.Obf}
	identity.obfuscation.HasHeaderProtectionKey = false
	for _, p := range wire.Peers {
		if p.IsRouter || m.cfg.Client.PeerID != "" && p.ID == m.cfg.Client.PeerID {
			identity.peerKey = p.PublicKey
			break
		}
	}
	return identity
}

// NormalizeEndpointBackups validates local addresses of one server. Bare IPs
// inherit the primary port; every result is an unambiguous canonical IP:port.
// DNS is reserved for the configured primary, so changing DNS cannot reorder
// the explicit reserve pool or create unbounded endpoint discovery.
func NormalizeEndpointBackups(primary string, inputs []string) ([]string, error) {
	if len(inputs) == 0 {
		return nil, nil
	}
	if len(inputs) > MaxEndpointBackups {
		return nil, fmt.Errorf("резервных IP сервера должно быть не больше %d", MaxEndpointBackups)
	}
	primaryHost, portText, err := net.SplitHostPort(strings.TrimSpace(primary))
	port, portErr := strconv.Atoi(portText)
	if err != nil || portErr != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("для резервных IP укажите основной endpoint с портом 1–65535")
	}
	seen := map[string]bool{}
	if ip, e := netip.ParseAddr(primaryHost); e == nil {
		seen[net.JoinHostPort(ip.Unmap().String(), strconv.Itoa(port))] = true
	}
	var out []string
	for i, raw := range inputs {
		text := strings.TrimSpace(raw)
		if text == "" {
			continue
		}
		host := text
		candidatePort := port
		if _, e := netip.ParseAddr(text); e != nil {
			var p string
			host, p, err = net.SplitHostPort(text)
			if err != nil {
				return nil, fmt.Errorf("резервный IP %d: ожидается IPv4/IPv6 или IP:порт", i+1)
			}
			candidatePort, err = strconv.Atoi(p)
			if err != nil || candidatePort < 1 || candidatePort > 65535 {
				return nil, fmt.Errorf("резервный IP %d: порт должен быть 1–65535", i+1)
			}
		}
		ip, e := netip.ParseAddr(host)
		if e != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, fmt.Errorf("резервный IP %d: укажите literal IPv4/IPv6 без имени хоста", i+1)
		}
		endpoint := net.JoinHostPort(ip.Unmap().String(), strconv.Itoa(candidatePort))
		if !seen[endpoint] {
			seen[endpoint] = true
			out = append(out, endpoint)
		}
	}
	return out, nil
}

func (m *Manager) clientEndpointCandidatesLocked() []string {
	if m.cfg == nil {
		return nil
	}
	primary := m.cfg.Endpoint
	if m.applied != nil {
		primary = m.applied.Endpoint
	}
	backups, err := NormalizeEndpointBackups(primary, m.cfg.Client.EndpointBackups)
	if err != nil {
		backups = nil
	} // invalid saved policy never supplies a dial target
	return append([]string{strings.TrimSpace(primary)}, backups...)
}

func (m *Manager) selectedClientEndpointLocked(primary string) string {
	if m.clientEndpointIdentity != m.clientEndpointIdentityLocked() {
		return primary
	}
	for _, candidate := range m.clientEndpointCandidatesLocked() {
		if m.clientEndpoint != "" && candidate == m.clientEndpoint {
			return candidate
		}
	}
	return primary
}

// ClientEndpointCandidates always begins with the configured/applied primary,
// independently of the transient RuntimeConfig selection.
func (m *Manager) ClientEndpointCandidates() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.clientEndpointCandidatesLocked()
}

func (m *Manager) SelectClientEndpoint(index int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	pool := m.clientEndpointCandidatesLocked()
	if index < 0 || index >= len(pool) {
		return false
	}
	m.clientEndpoint = pool[index]
	m.clientEndpointIdentity = m.clientEndpointIdentityLocked()
	return true
}

func (m *Manager) ResetClientEndpoint() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clientEndpoint = ""
}

// SetEndpointBackups changes only local policy, including imported profiles
// without SSH credentials. It never marks the remote wire config pending.
func (m *Manager) SetEndpointBackups(inputs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	primary := m.cfg.Endpoint
	if m.applied != nil {
		primary = m.applied.Endpoint
	}
	normalized, err := NormalizeEndpointBackups(primary, inputs)
	if err != nil {
		return err
	}
	m.cfg.Client.EndpointBackups = normalized
	keep := false
	for _, endpoint := range m.clientEndpointCandidatesLocked() {
		if endpoint == m.clientEndpoint {
			keep = true
		}
	}
	if !keep {
		m.clientEndpoint = ""
	}
	return nil
}
