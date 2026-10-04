//go:build linux

package dnsroute

import (
	"context"
	"fmt"
	"net"
	"sort"
	"time"
)

func hasShadowInformTarget(state *shadowInformState, key string, wanIPs []net.IP, devices map[string]string, verify func(string, net.IP) bool) bool {
	for iface, target := range state.targets {
		if target.valid(key, wanIPs) && validShadowWAN(devices[target.clientIP.String()]) && verify(iface, target.clientIP) {
			return true
		}
	}
	return false
}

func dueShadowInformBroadcastTargets(state *shadowInformState, key string, wanIPs []net.IP, devices map[string]string, verify func(string, net.IP) bool) []string {
	now := time.Now()
	var aliases []string
	for iface, target := range state.targets {
		answer := state.answers[iface]
		if !answer.refresh && now.Before(answer.expires.Add(-time.Minute)) {
			continue
		}
		if target.preferBroadcast && !now.Before(state.retryAfter[iface]) && target.valid(key, wanIPs) && validShadowWAN(devices[target.clientIP.String()]) && verify(iface, target.clientIP) {
			aliases = append(aliases, iface)
		}
	}
	sort.Strings(aliases)
	return aliases
}

// Candidates have already passed physical/default-WAN checks. Keep the known
// native alias (for example ISP rather than GigabitEthernet1) so fallback cannot
// create a second target and leave the unreachable peer active beside it.
func shadowBroadcastFallbackWANs(state *shadowInformState, key string, candidates []shadowBroadcastWAN, aliases []string) []shadowBroadcastWAN {
	var result []shadowBroadcastWAN
	for _, iface := range aliases {
		target := state.targets[iface]
		for _, wan := range candidates {
			if target.wanKey == key && target.clientIP.Equal(wan.client) {
				wan.native = iface
				result = append(result, wan)
				break
			}
		}
	}
	return result
}

// RFC 2131 sections 4.4.3-4.4.4 permit limited broadcast DHCPINFORM when the
// server is unknown or did not answer unicast. It obtains options, never a lease.
// The caller must first exhaust authoritative DNS and known-peer discovery.
func discoverShadowBroadcast(ctx context.Context, state *shadowInformState, key string, candidates []shadowBroadcastWAN, local []net.IP) ([]string, error) {
	if err := shadowDiscoveryContextErr(ctx); err != nil {
		return nil, err
	}
	if key == "" || len(candidates) == 0 {
		return nil, nil
	}
	// Probe at most one active WAN per pass; the outer discovery deadline also
	// bounds native CLI inspection and prevents a DNS request multiplying work.
	wan := candidates[0]
	retryKey := key + "|" + wan.native + "|" + wan.device + "|" + wan.client.String()
	if state.broadcastKey == retryKey && time.Now().Before(state.broadcastRetry) {
		return nil, fmt.Errorf("ожидается повторное обнаружение DNS через DHCP активного WAN")
	}
	probe := state.probeDiscover
	if probe == nil {
		probe = shadowDHCPInformDiscover
	}
	server, servers, err := probe(ctx, wan.device, wan.client)
	if contextErr := shadowDiscoveryContextErr(ctx); contextErr != nil {
		return nil, contextErr
	}
	state.broadcastKey, state.broadcastRetry = retryKey, time.Now().Add(30*time.Second)
	if previous, exists := state.targets[wan.native]; exists && previous.wanKey == key && previous.clientIP.Equal(wan.client) {
		if state.retryAfter == nil {
			state.retryAfter = map[string]time.Time{}
		}
		state.retryAfter[wan.native] = state.broadcastRetry
	}
	if err != nil {
		return nil, err
	}
	servers = filterShadowServers(servers, local)
	if server.To4() == nil || len(filterShadowServers([]string{server.String()}, local)) != 1 || len(servers) == 0 {
		return nil, fmt.Errorf("DHCP-сервер не сообщил допустимые DNS")
	}
	if _, exists := state.targets[wan.native]; !exists && len(state.targets) >= 8 {
		return nil, fmt.Errorf("достигнут предел проверенных DHCP-интерфейсов")
	}
	if state.targets == nil {
		state.targets = map[string]shadowDHCPTarget{}
	}
	if state.answers == nil {
		state.answers = map[string]shadowInformAnswer{}
	}
	if state.retryAfter == nil {
		state.retryAfter = map[string]time.Time{}
	}
	target := shadowDHCPTarget{wanKey: key, clientIP: append(net.IP(nil), wan.client...), serverIP: append(net.IP(nil), server...)}
	if previous, exists := state.targets[wan.native]; exists && previous.wanKey == key && previous.clientIP.Equal(wan.client) {
		target.stamp = previous.stamp
		target.preferBroadcast = previous.preferBroadcast
	}
	state.targets[wan.native] = target
	state.answers[wan.native] = shadowInformAnswer{servers: append([]string(nil), servers...), expires: time.Now().Add(5 * time.Minute)}
	state.retryAfter[wan.native] = time.Now().Add(30 * time.Second)
	return servers, nil
}
