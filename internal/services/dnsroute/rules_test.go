package dnsroute

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestDialRefusesImplicitBootstrap(t *testing.T) {
	a := New(nil, nil)
	for _, address := range []string{"dns.example:443", "localhost:443", "[fe80::1%eth3]:443", "1.1.1.1", "1.1.1.1:"} {
		if _, err := a.DialContext(context.Background(), "nfqws", "tcp", address); err == nil || !strings.Contains(err.Error(), "literal IP:port") {
			t.Errorf("%q: expected explicit-bootstrap rejection, got %v", address, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.DialContext(ctx, "nfqws", "tcp", "1.1.1.1:443"); err != context.Canceled {
		t.Fatalf("cancellation: %v", err)
	}
}

func TestListenerDoesNotAcceptWildcardsOrWAN(t *testing.T) {
	for _, host := range []string{"0.0.0.0", "::", "8.8.8.8", "not-a-host", "192.0.2.1"} {
		if _, err := ResolveLANHost(host, nil); err == nil {
			t.Errorf("unsafe listener %q accepted", host)
		}
	}
	for _, name := range []string{"awg1", "nwg0", "wg0", "tun0", "ppp0", "eth3"} {
		if lanInterface(net.Interface{Name: name, Flags: net.FlagUp}, []string{"eth3"}) {
			t.Errorf("non-LAN interface %q selected", name)
		}
	}
	for _, name := range []string{"br0", "eth2.1"} {
		if !lanInterface(net.Interface{Name: name, Flags: net.FlagUp}, []string{"eth3"}) {
			t.Errorf("LAN interface %q rejected", name)
		}
	}
}

func TestPrivateRouteMarksSurviveAWGClassification(t *testing.T) {
	const mask uint32 = 0x8000ffff
	for slot := 0; slot < maxRouteSlots; slot++ {
		mark := routeMarkBase + uint32(slot)
		for _, awg := range []uint32{0x10100000, 0x10200000, 0x14000000} {
			classified := (mark & ^uint32(0x1ff00000)) | awg
			if classified&mask != mark {
				t.Fatalf("AWG changed DNS route identity: slot%d", slot)
			}
			if (classified|0x40000000)&mask != mark {
				t.Fatalf("NFQWS changed DNS route identity: slot%d", slot)
			}
		}
		if table := routeTableBase + slot; table >= 901 || table < 1 {
			t.Fatalf("table%d overlaps AWG or exceeds Keenetic range", table)
		}
	}
}

func TestFirewallIsScopedAndLANOnly(t *testing.T) {
	script := firewallScript(300, ListenOptions{Host: "192.168.3.1", DNSPort: 5355}, "br0", "192.168.3.0/24")
	for _, expected := range []string{
		"-I POSTROUTING 1 -m mark --mark " + routeSelector(0) + " -j " + postChain,
		"-I PREROUTING 1 -m connmark --mark " + routeSelector(0) + " -j " + preChain,
		"-A " + postChain + " -m mark --mark 0x40000000/0x40000000 -j ACCEPT",
		"--connbytes-dir original -j NFQUEUE --queue-num 300",
		"--connbytes-dir reply -j NFQUEUE --queue-num 300",
		"-A " + inputChain + " -i br0 -s 192.168.3.0/24 -j ACCEPT",
		"-A " + inputChain + " -j DROP",
		"-I INPUT 1 -d 192.168.3.1 -p udp --dport 5355 -j " + inputChain,
		"-I INPUT 1 -d 192.168.3.1 -p tcp --dport 5355 -j " + inputChain,
	} {
		if !strings.Contains(script, expected) {
			t.Errorf("missing route safety condition: %s", expected)
		}
	}
	for _, unsafe := range []string{"-F OUTPUT", "-F POSTROUTING", "-F INPUT", "-t nat", "AWG2_MULTI", "-A FORWARD", "-j ACCEPT\niptables -w -t filter -A INPUT"} {
		if strings.Contains(script, unsafe) {
			t.Errorf("unexpected global firewall mutation: %s", unsafe)
		}
	}
}

func TestInterfaceValidationRejectsShellSyntax(t *testing.T) {
	for _, name := range []string{"eth3;true", "br0\ntrue", "$(id)", "a b", "eth3/../lo", "", strings.Repeat("a", 16)} {
		if validInterface(name) {
			t.Errorf("unsafe interface %q accepted", name)
		}
	}
}
