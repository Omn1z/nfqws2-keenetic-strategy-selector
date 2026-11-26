package dnsroute

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"
)

type shadowPPPWAN struct {
	shadowBroadcastWAN
	sessionID uint64
	uptime    time.Duration
}

func parseShadowPPPWANs(output, routes string, configured []string, devices map[string]string) []shadowPPPWAN {
	var result []shadowPPPWAN
	parseShadowNativeWANs(output, routes, configured, devices, func(values map[string]string, wan shadowBroadcastWAN) bool {
		if values["type"] != "PPPoE" || !shadowPPPDevice(wan.device) {
			return false
		}
		sessionID, sessionErr := strconv.ParseUint(values["session-id"], 10, 16)
		uptime, uptimeErr := strconv.ParseUint(values["uptime"], 10, 32)
		if sessionErr != nil || sessionID == 0 || uptimeErr != nil {
			return false
		}
		result = append(result, shadowPPPWAN{shadowBroadcastWAN: wan, sessionID: sessionID, uptime: time.Duration(uptime) * time.Second})
		return true
	})
	return result
}

// PPPoE has no DHCP lease lifetime. Read the current IPCP negotiation from
// pppd's log and revalidate it against native session state on every discovery.
// Never persist it as a DHCP lease or accept unattributed "ignored DNS" lines.
func discoverShadowPPPServers(ctx context.Context, log, before, interfaces, routes string, configured []string, devices map[string]string, local []net.IP, routerNow time.Time) []string {
	wans := parseShadowPPPWANs(interfaces, routes, configured, devices)
	previous := parseShadowPPPWANs(before, routes, configured, devices)
	sessions := parseKeeneticShadowPPPSessions(log)
	var candidates []string
	shadowDiagnosticEvent(ctx, "native.ppp", fmt.Sprintf("Подтверждённых PPPoE WAN: %d; сеансов pppd с DNS в журнале: %d", len(wans), len(sessions)), 0)
	for _, wan := range wans {
		accepted := false
		stable := false
		for _, prior := range previous {
			stable = stable || prior.native == wan.native && prior.device == wan.device && prior.client.Equal(wan.client) && prior.sessionID == wan.sessionID && wan.uptime >= prior.uptime
		}
		for _, session := range sessions {
			if !stable || session.device != wan.device || session.sessionID != wan.sessionID || !session.clientIP.Equal(wan.client) {
				continue
			}
			started := shadowLeaseObservedAt(session.stamp, routerNow)
			// Session IDs and client addresses can both be reused. Compare the
			// logged start with current native uptime as well. The small margin
			// covers authentication, integer-second logs and sequential CLI reads.
			delta := routerNow.Sub(started) - wan.uptime
			if started.IsZero() || delta < -30*time.Second || delta > 30*time.Second {
				continue
			}
			servers := filterShadowServers(session.servers, local)
			candidates = append(candidates, servers...)
			accepted = len(servers) > 0
		}
		shadowDiagnosticEvent(ctx, "native.ppp.session", fmt.Sprintf("%s/%s: session-id=%d; uptime=%d с; сеанс стабилен=%t; DNS текущего IPCP подтверждены=%t", wan.native, wan.device, wan.sessionID, int64(wan.uptime/time.Second), stable, accepted), 0)
	}
	return filterShadowServers(candidates, local)
}
