package dnsroute

import (
	"strings"
	"testing"
)

const shadowBroadcastFixture = `Interface, name = "GigabitEthernet1"
               id: GigabitEthernet1
             type: GigabitEthernet
        connected: yes
          address: 192.0.2.10
           global: yes
        defaultgw: yes
   security-level: public
             ipv6:
                  address: 2001:db8::1
            defaultgw: no
             port, name = 0:
                    id: GigabitEthernet1/0
                  type: Port
`

func TestShadowBroadcastRequiresNativePhysicalMainWAN(t *testing.T) {
	routes := "default via 192.0.2.1 dev eth3 metric 1000"
	devices := map[string]string{"192.0.2.10": "eth3"}
	parse := func(fixture, route string, configured []string) int {
		return len(parseShadowBroadcastWANs(fixture, route, configured, devices))
	}
	if got := parseShadowBroadcastWANs(shadowBroadcastFixture, routes, []string{"eth3"}, devices); len(got) != 1 || got[0].native != "GigabitEthernet1" || got[0].device != "eth3" || got[0].client.String() != "192.0.2.10" {
		t.Fatalf("native WAN rejected or nested status replaced it: %+v", got)
	}
	for _, pair := range [][2]string{
		{"connected: yes", "connected: no"}, {"global: yes", "global: no"},
		{"defaultgw: yes", "defaultgw: no"}, {"security-level: public", "security-level: private"},
		{"type: GigabitEthernet", "type: PPPoE"}, {"type: GigabitEthernet", "type: Wireguard"},
		{"type: GigabitEthernet", "type: Bridge"}, {"type: GigabitEthernet", "type: WifiMaster"},
		{"address: 192.0.2.10", "address: 192.0.2.11"}, {"address: 192.0.2.10", "address:"},
		{"address: 192.0.2.10", "address: 127.0.0.1"}, {"id: GigabitEthernet1", "id: Bridge0"},
		{"id: GigabitEthernet1", "id: Wireguard0"},
	} {
		if parse(strings.Replace(shadowBroadcastFixture, pair[0], pair[1], 1), routes, []string{"eth3"}) != 0 {
			t.Errorf("unsafe native state accepted: %v", pair)
		}
	}
	for _, route := range []string{"", "default via 192.0.2.1 dev eth2", "default dev wg0", "192.0.2.0/24 dev eth3"} {
		if parse(shadowBroadcastFixture, route, []string{"eth3"}) != 0 {
			t.Errorf("non-main WAN accepted: %s", route)
		}
	}
	if parse(shadowBroadcastFixture, routes, []string{"eth2"}) != 0 {
		t.Fatal("unconfigured kernel WAN accepted")
	}
	// A child's status cannot repair missing top-level authorization.
	malicious := strings.ReplaceAll(shadowBroadcastFixture, "security-level: public", "security-level:") + " security-level: public\n address: 192.0.2.10\n"
	if parse(malicious, routes, []string{"eth3"}) != 0 {
		t.Fatal("nested port promoted to WAN")
	}
	if parse(shadowBroadcastFixture+shadowBroadcastFixture, routes, []string{"eth3"}) != 1 {
		t.Fatal("duplicate native status multiplied broadcast probes")
	}
	if parse(strings.ReplaceAll(strings.ReplaceAll(shadowBroadcastFixture, "GigabitEthernet1", "GigabitEthernet1/Vlan2"), "type: GigabitEthernet", "type: Vlan"), routes, []string{"eth3"}) != 1 {
		t.Fatal("verified physical VLAN rejected")
	}
}
