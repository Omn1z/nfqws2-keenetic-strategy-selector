package dnsroute

import (
	"context"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestShadowEndpointRejectsRecursionAndInvalidDestinations(t *testing.T) {
	for _, address := range []string{"127.0.0.1:53", "[::1]:53", "0.0.0.0:53", "[::]:53", "224.0.0.1:53", "169.254.1.1:53", "[fe80::1]:53", "255.255.255.255:53", "dns.example:53", "192.0.2.2:0", "192.0.2.2:65536", "192.0.2.2", "192.0.2.2:http"} {
		if _, err := shadowEndpoint(address); err == nil {
			t.Errorf("accepted invalid endpoint %q", address)
		}
	}
	for _, address := range []string{"192.0.2.2:53", "192.168.0.1:5353", "[2001:db8::53]:53"} {
		if _, err := shadowEndpoint(address); err != nil {
			t.Errorf("rejected valid endpoint %q: %v", address, err)
		}
	}
	a := New(nil, nil)
	if _, err := a.DialShadowDNS(context.Background(), "unix", "192.0.2.1:53"); err == nil {
		t.Fatal("accepted non-DNS transport")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.DialShadowDNS(ctx, "udp", "192.0.2.1:53"); err != context.Canceled {
		t.Fatalf("cancellation: %v", err)
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err == nil && ip.IsGlobalUnicast() {
			if _, err := a.DialShadowDNS(context.Background(), "udp", net.JoinHostPort(ip.String(), "53")); err == nil {
				t.Errorf("accepted own address %s", ip)
			}
		}
	}
}

func TestShadowServerFilteringCanonicalizesAndExcludesAllLocalIPs(t *testing.T) {
	candidates := []string{"127.0.0.1", "192.168.3.1:5355", "192.0.2.1", "192.0.2.1:53", "::ffff:192.0.2.1", "2001:0db8::53", "[2001:db8::53]:53", "bad", "[fe80::53]:53"}
	got := filterShadowServers(candidates, []net.IP{net.ParseIP("192.168.3.1")})
	want := []string{"192.0.2.1:53", "[2001:db8::53]:53"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestKeeneticShadowDiscoveryOnlyPeerEntries(t *testing.T) {
	fixture := `
server:
  address: 192.168.3.1
  port: 5355
  service: Dns::Manager
  interface:
server:
  address: 192.0.2.53
  port: 0
  service: GigabitEthernet1 DHCP client
  interface: GigabitEthernet1
server:
  address: 198.51.100.53
  service: PPPoE0 IPCP
  interface: PPPoE0
server:
  address: 203.0.113.53
  service: DHCP client
  interface: Bridge0
server:
  address: 203.0.113.54
  service: DHCP client
  interface: ISP;system reboot
server-tls:
  address: 203.0.113.55
  service: DHCP client
  interface: GigabitEthernet1
server-https:
  address: 203.0.113.56
  service: DHCP client
  interface: GigabitEthernet1
`
	got := parseKeeneticShadowServers(fixture)
	if len(got) != 2 || got[0].address != "192.0.2.53" || got[1].iface != "PPPoE0" {
		t.Fatalf("unexpected candidates: %+v", got)
	}
}

func TestOpenWrtShadowDiscoveryOnlyConfiguredActiveWAN(t *testing.T) {
	fixture := `{"interface":[
{"interface":"lan","proto":"static","up":true,"l3_device":"br-lan","dns-server":["192.168.1.1"]},
{"interface":"wan","proto":"dhcp","up":true,"l3_device":"eth0.2","dns-server":["192.0.2.53"]},
{"interface":"wan6","proto":"dhcpv6","up":true,"device":"eth0.2","dns-server":["2001:db8::53"]},
{"interface":"vpn","proto":"wireguard","up":true,"device":"eth0.2","l3_device":"wg0","dns-server":["10.0.0.1"]},
{"interface":"backup","proto":"dhcp","up":false,"l3_device":"eth0.2","dns-server":["198.51.100.53"]}]}`
	got := parseOpenWrtShadowServers(fixture, []string{"eth0.2"})
	if !reflect.DeepEqual(got, []string{"192.0.2.53", "2001:db8::53"}) {
		t.Fatalf("unexpected servers %v", got)
	}
	if got := parseOpenWrtShadowServers("invalid JSON", []string{"eth0.2"}); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestShadowDiscoveryIgnoredPeerDNS(t *testing.T) {
	fixture := `{"interface":[{"interface":"wan","proto":"dhcp","up":true,"l3_device":"eth1","dns-server":["1.1.1.1"],"inactive":{"dns-server":["192.0.2.53"]}},{"interface":"vpn","proto":"wireguard","up":true,"l3_device":"wg0","inactive":{"dns-server":["10.0.0.53"]}}]}`
	if got := parseOpenWrtShadowServers(fixture, []string{"eth1"}); !reflect.DeepEqual(got, []string{"192.0.2.53"}) {
		t.Fatal(got)
	}
	log := `I [Oct  3 01:15:13] ndhcpc: GigabitEthernet1: received ACK for 192.168.0.10
                    from 192.168.0.1 lease 86400 sec.
I [Oct  3 01:15:13] ndm: Dhcp::Client: configuring interface ISP.
I [Oct  3 01:15:13] ndm: Dhcp::Client: obtained IP address 192.168.0.10/24.
W [Oct  3 01:15:13] ndm: Dns::InterfaceSpecific: name server 192.0.2.53 is
                    ignored.
W [Oct  3 01:15:13] ndm: Dns::InterfaceSpecific: name server 198.51.100.53 is ignored.
W [Oct  3 01:15:14] ndm: Dns::InterfaceSpecific: name server 203.0.113.53 is ignored.`
	got := parseKeeneticShadowLeases(log)
	if len(got) != 1 || got[0].iface != "GigabitEthernet1" || !got[0].clientIP.Equal(net.ParseIP("192.168.0.10")) || !reflect.DeepEqual(got[0].servers, []string{"192.0.2.53", "198.51.100.53"}) {
		t.Fatalf("lease: %+v", got)
	}
	for _, suffix := range []string{
		"\nI [Oct  3 02:00:00] ndhcpc: GigabitEthernet1: received ACK for 192.168.0.20 from 192.168.0.1 lease 86400 sec.",
		"\nI [Oct  3 02:00:00] ndhcpc: GigabitEthernet1: received ACK for 192.168.0.10 from 192.168.0.1 lease 86400 sec.",
	} {
		got := parseKeeneticShadowLeases(log + suffix)
		if len(got) != 1 || len(got[0].servers) != 0 {
			t.Fatalf("stale lease survived renewal: %+v", got)
		}
	}
}

func TestKeeneticShadowLeaseDoesNotTrustUnattributedOrWrongLease(t *testing.T) {
	for _, log := range []string{
		"W [Oct  3 01:15:13] ndm: Dns::InterfaceSpecific: name server 192.0.2.53 is ignored.",
		"I [Oct  3 01:15:13] ndhcpc: Bridge0: received ACK for 192.168.0.10 from 192.168.0.1 lease 86400 sec.\nI [Oct  3 01:15:13] ndm: Dhcp::Client: obtained IP address 192.168.0.10/24.\nW [Oct  3 01:15:13] ndm: Dns::InterfaceSpecific: name server 192.0.2.53 is ignored.",
		"I [Oct  3 01:15:13] ndhcpc: GigabitEthernet1: received ACK for 192.168.0.10 from 192.168.0.1 lease 86400 sec.\nI [Oct  3 01:15:13] ndm: Dhcp::Client: obtained IP address 192.168.0.20/24.\nW [Oct  3 01:15:13] ndm: Dns::InterfaceSpecific: name server 192.0.2.53 is ignored.",
	} {
		for _, lease := range parseKeeneticShadowLeases(log) {
			if len(lease.servers) != 0 {
				t.Fatal(lease)
			}
		}
	}
}

func TestShadowLeaseActualExpiryAndYearBoundary(t *testing.T) {
	zone := time.FixedZone("router", 3*60*60)
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, zone)
	lease := keeneticShadowLease{stamp: "Oct  3 01:15:13", leaseSeconds: 86400}
	if got := shadowLeaseRemaining(lease, now); got != 13*time.Hour+15*time.Minute+13*time.Second {
		t.Fatal(got)
	}
	lease = keeneticShadowLease{stamp: "Dec 31 23:55:00", leaseSeconds: 3600}
	if got := shadowLeaseRemaining(lease, time.Date(2027, 1, 1, 0, 5, 0, 0, zone)); got != 50*time.Minute {
		t.Fatal(got)
	}
	for _, lease := range []keeneticShadowLease{{stamp: "bad", leaseSeconds: 86400}, {stamp: "Oct  1 01:00:00", leaseSeconds: 3600}, {stamp: "Oct  3 01:00:00", leaseSeconds: 0}, {stamp: "Oct  3 01:00:00", leaseSeconds: 0xffffffff}, {stamp: "Oct  3 13:00:00", leaseSeconds: 3600}} {
		if got := shadowLeaseRemaining(lease, now); got != 0 {
			t.Fatalf("untrusted lease has lifetime: %+v %s", lease, got)
		}
	}
}

func TestShadowRememberedLeaseBoundToWANIdentity(t *testing.T) {
	wan := []string{"eth3"}
	ips := []net.IP{net.ParseIP("192.168.0.10")}
	key := shadowWANKey("default via 192.168.0.1 dev eth3 metric 1000\ndefault via 10.0.0.1 dev awg0", wan, ips)
	if key == "" || strings.Contains(key, "awg0") {
		t.Fatal(key)
	}
	now := time.Now()
	lease := shadowRememberedLease{wanKey: key, clientIP: ips[0], expires: now.Add(time.Hour)}
	if !lease.valid(key, ips, now) {
		t.Fatal("fresh same-WAN lease rejected")
	}
	for _, changed := range []string{"", shadowWANKey("default via 192.168.0.2 dev eth3", wan, ips), shadowWANKey("default via 192.168.0.1 dev eth4", []string{"eth4"}, ips), shadowWANKey("default via 192.168.0.1 dev eth3", wan, []net.IP{net.ParseIP("192.168.0.20")})} {
		if lease.valid(changed, ips, now) {
			t.Fatalf("lease reused after WAN change: %s", changed)
		}
	}
	if lease.valid(key, ips, lease.expires) || lease.valid(key, []net.IP{net.ParseIP("192.168.0.20")}, now) {
		t.Fatal("expired/different address lease accepted")
	}
}

func TestShadowPrivateSlotAndWANValidation(t *testing.T) {
	if shadowRouteSlot <= 0 || shadowRouteSlot >= maxRouteSlots {
		t.Fatal("Shadow slot outside owned cleanup range")
	}
	if routeSelector(shadowRouteSlot) == routeSelector(0) {
		t.Fatal("Shadow shares NFQUEUE routing identity")
	}
	for _, name := range []string{"awg0", "nwg1", "wg0", "tun0", "br0", "lo", "eth3;reboot"} {
		if validShadowWAN(name) {
			t.Errorf("accepted %s", name)
		}
	}
	for _, name := range []string{"eth3", "eth0.2", "ppp0", "pppoe-wan", "br-wan", "br-wan.100"} {
		if !validShadowWAN(name) {
			t.Errorf("rejected %s", name)
		}
	}
}

func TestOpenWrtShadowPPPoELogicalAndPhysicalMapping(t *testing.T) {
	fixture := `{"interface":[
{"interface":"wan","proto":"pppoe","up":true,"device":"eth1","l3_device":"pppoe-wan","dns-server":["192.0.2.53"]},
{"interface":"wan6","proto":"dhcpv6","up":true,"l3_device":"pppoe-wan","dns-server":["2001:db8::53"]},
{"interface":"vpn","proto":"pptp","up":true,"device":"eth1","l3_device":"ppp0","dns-server":["10.0.0.1"]},
{"interface":"other","proto":"dhcp","up":true,"l3_device":"eth4","dns-server":["203.0.113.53"]}]}`
	for _, configured := range [][]string{{"eth1"}, {"wan"}, {"pppoe-wan"}, {"eth3"}} {
		devices, servers := parseOpenWrtShadowWAN(fixture, configured, []string{"pppoe-wan"})
		if !reflect.DeepEqual(devices, []string{"pppoe-wan", "pppoe-wan"}) || !reflect.DeepEqual(servers, []string{"192.0.2.53", "2001:db8::53"}) {
			t.Fatalf("config%v => %v / %v", configured, devices, servers)
		}
	}
}

func TestOpenWrtShadowDoesNotTrustUnknownVPNDefault(t *testing.T) {
	for _, proto := range []string{"wireguardfoo", "vti", "xfrm", "tailscale", "unknown", ""} {
		fixture := `{"interface":[{"interface":"wan","proto":"` + proto + `","up":true,"device":"eth1","l3_device":"custom0","dns-server":["10.0.0.53"]}]}`
		devices, servers := parseOpenWrtShadowWAN(fixture, []string{"wan", "eth1", "custom0"}, []string{"custom0"})
		if len(devices) != 0 || len(servers) != 0 {
			t.Errorf("unknown protocol %q treated as direct WAN: %v %v", proto, devices, servers)
		}
	}
}

func TestOpenWrtShadowSupportsProviderTransitionProtocols(t *testing.T) {
	for _, proto := range []string{"6in4", "6rd", "dslite", "464xlat", "map"} {
		fixture := `{"interface":[{"interface":"wan","proto":"` + proto + `","up":true,"l3_device":"isp0","dns-server":["2001:db8::53"]}]}`
		devices, servers := parseOpenWrtShadowWAN(fixture, nil, []string{"isp0"})
		if !reflect.DeepEqual(devices, []string{"isp0"}) || !reflect.DeepEqual(servers, []string{"2001:db8::53"}) {
			t.Errorf("provider protocol %q rejected: %v %v", proto, devices, servers)
		}
	}
}
