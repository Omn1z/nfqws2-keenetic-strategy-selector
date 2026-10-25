package dnsroute

import (
	"context"
	"encoding/json"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

const shadowPPPWANFixture = `Interface, name = "PPPoE0"
               id: PPPoE0
             type: PPPoE
        connected: yes
          address: 100.66.1.244
           global: yes
        defaultgw: yes
   security-level: public
             ipv6:
                  address: 2001:db8::1
                  uptime: 0
              session-id: 999
           uptime: 60
       session-id: 12650
`

func TestShadowPPPDiscoveryRequiresCurrentMainWANSession(t *testing.T) {
	log := shadowPPPLogFixture("30539", "ppp0", "12650", "100.66.1.244", "46.61.250.142", "46.61.250.143")
	routes := "default dev ppp0 metric 1000"
	devices := map[string]string{"100.66.1.244": "ppp0"}
	now := time.Date(2026, 10, 25, 18, 22, 6, 0, time.FixedZone("router", 3*60*60))
	parse := func(fixture, route, sessionLog string, clock time.Time, local []net.IP) []string {
		return discoverShadowPPPServers(context.Background(), sessionLog, fixture, fixture, route, []string{"ppp0"}, devices, local, clock)
	}
	want := []string{"46.61.250.142:53", "46.61.250.143:53"}
	if got := parse(shadowPPPWANFixture, routes, log, now, nil); !reflect.DeepEqual(got, want) {
		t.Fatalf("current IPCP DNS lost: %v", got)
	}
	for _, pair := range [][2]string{
		{"type: PPPoE", "type: PPTP"}, {"type: PPPoE", "type: L2TP"},
		{"type: PPPoE", "type: Wireguard"}, {"type: PPPoE", "type: GigabitEthernet"},
		{"connected: yes", "connected: no"}, {"global: yes", "global: no"},
		{"defaultgw: yes", "defaultgw: no"}, {"security-level: public", "security-level: private"},
		{"address: 100.66.1.244", "address: 100.66.1.245"}, {"address: 100.66.1.244", "address:"},
		{"session-id: 12650", "session-id: 12651"}, {"session-id: 12650", "session-id:"},
		{"session-id: 12650", "session-id: 65536"}, {"session-id: 12650", "session-id: 0"},
		{"uptime: 60", "uptime:"}, {"uptime: 60", "uptime: -1"},
		{"uptime: 60", "uptime: 4294967296"}, {"uptime: 60", "uptime: 3600"},
		{"id: PPPoE0", "id: Wireguard0"},
	} {
		if got := parse(strings.Replace(shadowPPPWANFixture, pair[0], pair[1], 1), routes, log, now, nil); len(got) != 0 {
			t.Errorf("unsafe or stale PPP status accepted: %v -> %v", pair, got)
		}
	}
	for _, route := range []string{"", "default dev ppp1", "default dev wg0", "100.66.0.0/16 dev ppp0"} {
		if got := parse(shadowPPPWANFixture, route, log, now, nil); len(got) != 0 {
			t.Errorf("non-main PPP WAN accepted: %s -> %v", route, got)
		}
	}
	for _, clock := range []time.Time{time.Time{}, now.Add(time.Hour), now.Add(-time.Hour)} {
		if got := parse(shadowPPPWANFixture, routes, log, clock, nil); len(got) != 0 {
			t.Errorf("stale/reused PPP session accepted with clock %s: %v", clock, got)
		}
	}
	if got := parse(shadowPPPWANFixture, routes, log, now, []net.IP{net.ParseIP("46.61.250.142")}); !reflect.DeepEqual(got, want[1:]) {
		t.Fatalf("router-local DNS not filtered: %v", got)
	}
	if got := parseShadowPPPWANs(shadowPPPWANFixture, routes, []string{"eth3"}, devices); len(got) != 0 {
		t.Fatal("unconfigured PPP accepted")
	}
	if got := parseShadowBroadcastWANs(shadowPPPWANFixture, routes, []string{"ppp0"}, devices); len(got) != 0 {
		t.Fatal("PPP promoted to DHCP broadcast")
	}
}

func TestShadowPPPDiscoveryRejectsDNSFromOtherSessionOrUnattributedLog(t *testing.T) {
	now := time.Date(2026, 10, 25, 18, 22, 6, 0, time.UTC)
	devices := map[string]string{"100.66.1.244": "ppp0"}
	for _, log := range []string{
		shadowPPPLogFixture("10", "ppp1", "12650", "100.66.1.244", "192.0.2.53", ""),
		shadowPPPLogFixture("10", "ppp0", "12651", "100.66.1.244", "192.0.2.53", ""),
		shadowPPPLogFixture("10", "ppp0", "12650", "100.66.1.245", "192.0.2.53", ""),
		"W [Oct 25 18:21:06] ndm: Dns::InterfaceSpecific: name server 192.0.2.53 is ignored.",
	} {
		if got := discoverShadowPPPServers(context.Background(), log, shadowPPPWANFixture, shadowPPPWANFixture, "default dev ppp0", []string{"ppp0"}, devices, nil, now); len(got) != 0 {
			t.Fatalf("unverified IPCP DNS accepted: %v", got)
		}
	}
}

func TestShadowPPPDiagnosticsExposeOnlyStructuredSessionEvidence(t *testing.T) {
	var state shadowDiagnosticState
	state.setEnabled(true)
	ctx, finish := state.begin(context.Background())
	log := shadowPPPLogFixture("30539", "ppp0", "12650", "100.66.1.244", "46.61.250.142", "46.61.250.143") +
		"I [Oct 25 18:21:06] pppd[30539]: private authentication password-secret\n"
	now := time.Date(2026, 10, 25, 18, 22, 6, 0, time.UTC)
	servers := discoverShadowPPPServers(ctx, log, shadowPPPWANFixture, shadowPPPWANFixture, "default dev ppp0", []string{"ppp0"}, map[string]string{"100.66.1.244": "ppp0"}, nil, now)
	finish(servers, nil, time.Time{})
	state.mu.Lock()
	raw, err := json.Marshal(state.attempts)
	state.mu.Unlock()
	if err != nil || strings.Contains(string(raw), "password-secret") || strings.Contains(string(raw), "authentication") {
		t.Fatalf("native PPP output leaked: %s (%v)", raw, err)
	}
	for _, expected := range []string{"native.ppp", "native.ppp.session", "session-id=12650", "IPCP подтверждены=true"} {
		if !strings.Contains(string(raw), expected) {
			t.Errorf("missing PPP evidence %q: %s", expected, raw)
		}
	}
}

func TestShadowPPPDiscoveryRejectsReconnectDuringLogRead(t *testing.T) {
	log := shadowPPPLogFixture("30539", "ppp0", "12650", "100.66.1.244", "46.61.250.142", "46.61.250.143")
	now := time.Date(2026, 10, 25, 18, 22, 6, 0, time.UTC)
	for _, before := range []string{
		"",
		strings.Replace(shadowPPPWANFixture, "uptime: 60", "uptime: 61", 1),
		strings.Replace(shadowPPPWANFixture, "session-id: 12650", "session-id: 123", 1),
		strings.Replace(shadowPPPWANFixture, "connected: yes", "connected: no", 1),
	} {
		got := discoverShadowPPPServers(context.Background(), log, before, shadowPPPWANFixture, "default dev ppp0", []string{"ppp0"}, map[string]string{"100.66.1.244": "ppp0"}, nil, now)
		if len(got) != 0 {
			t.Fatalf("changed PPP session accepted: %v", got)
		}
	}
}
