//go:build linux

package dnsroute

import (
	"context"
	"fmt"
	"net"
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

// RFC 2131 section 4.4.3 permits a limited broadcast DHCPINFORM when the
// server is unknown. It obtains options for an existing address, never a lease.
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
	state.targets[wan.native] = shadowDHCPTarget{wanKey: key, clientIP: append(net.IP(nil), wan.client...), serverIP: append(net.IP(nil), server...)}
	state.answers[wan.native] = shadowInformAnswer{servers: append([]string(nil), servers...), expires: time.Now().Add(5 * time.Minute)}
	state.retryAfter[wan.native] = time.Now().Add(30 * time.Second)
	return servers, nil
}
