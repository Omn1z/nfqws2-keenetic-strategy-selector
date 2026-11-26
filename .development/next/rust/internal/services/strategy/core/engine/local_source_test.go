package engine

import (
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestLocalIPv4Snapshot(t *testing.T) {
	s := &Sandbox{localAddrs: func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("192.168.3.1"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)},
			&net.IPAddr{IP: net.ParseIP("10.0.0.2")},
			&net.IPAddr{IP: net.ParseIP("10.0.0.2")},
			&net.IPAddr{IP: net.IPv4zero},
		}, nil
	}}
	got, err := s.localIPv4()
	if err != nil || !reflect.DeepEqual(got, []string{"10.0.0.2", "192.168.3.1"}) {
		t.Fatalf("snapshot = %v, %v", got, err)
	}
}

func TestSandboxLocalAddressErrorsFailBeforeInstallingRules(t *testing.T) {
	for name, get := range map[string]func() ([]net.Addr, error){
		"permission": func() ([]net.Addr, error) { return nil, os.ErrPermission },
		"empty":      func() ([]net.Addr, error) { return nil, nil },
		"nil_entry":  func() ([]net.Addr, error) { return []net.Addr{nil}, nil },
		"only_ipv6": func() ([]net.Addr, error) {
			return []net.Addr{&net.IPAddr{IP: net.ParseIP("2001:db8::1")}}, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newSandboxFirewall(true)
			original := fmt.Sprint(f.chains)
			s := testSandbox(f, 0)
			s.localAddrs = get
			if err := s.RulesUp(); err == nil {
				t.Fatal("sandbox installed without a reliable local address snapshot")
			}
			if got := fmt.Sprint(f.chains); got != original {
				t.Fatalf("firewall changed despite invalid local addresses:\n%s", got)
			}
		})
	}
}

func TestSandboxRejectsLocalAddressChanges(t *testing.T) {
	f := newSandboxFirewall(true)
	s := testSandbox(f, 0)
	if err := s.RulesUp(); err != nil {
		t.Fatal(err)
	}
	defer s.RulesDown()
	s.localAddrs = func() ([]net.Addr, error) {
		return []net.Addr{&net.IPAddr{IP: net.ParseIP("10.0.0.3")}}, nil
	}
	if err := s.CheckRules(); err == nil || !strings.Contains(err.Error(), "local IPv4 addresses changed") {
		t.Fatalf("address change did not invalidate test: %v", err)
	}
	s.localAddrs = func() ([]net.Addr, error) { return nil, os.ErrPermission }
	if err := s.CheckRules(); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("address inspection failure did not invalidate test: %v", err)
	}
}

func TestSandboxDoesNotCaptureVendorMarkedForwardedConnections(t *testing.T) {
	for _, queue := range []bool{false, true} {
		t.Run(fmt.Sprintf("queue_%v", queue), func(t *testing.T) {
			f := newSandboxFirewall(true)
			s := testSandbox(f, 0)
			if err := s.rulesUp(queue); err != nil {
				t.Fatal(err)
			}
			defer s.RulesDown()
			for _, ifc := range []string{"eth3", "eth2.4"} {
				// Vendor policy can set the same connmark bit. This LAN client's
				// matching source port still must go through the vendor rules.
				p := sandboxPacket{out: ifc, originalSource: "192.168.3.42", sport: s.PortLo + 1, dport: 443, count: 1, connmark: 0x20001234}
				f.traverse("POSTROUTING", &p)
				if !reflect.DeepEqual(p.queues, []int{300}) || p.connmark != 0x20001234 {
					t.Fatalf("marked forwarded client captured/excluded: %+v", p)
				}
				// A NAT reply is addressed to the router WAN IP at PREROUTING,
				// but its conntrack original source remains the LAN client.
				reply := sandboxPacket{in: ifc, originalSource: "192.168.3.42", sport: 443, dport: p.sport, count: 1, connmark: p.connmark}
				f.traverse("PREROUTING", &reply)
				if !reflect.DeepEqual(reply.queues, []int{300}) {
					t.Fatalf("marked forwarded NAT reply captured/excluded: %+v", reply)
				}
			}
		})
	}
}

func TestSandboxIncludesRouterLocalOriginalSourceThroughNAT(t *testing.T) {
	f := newSandboxFirewall(true)
	s := testSandbox(f, 0)
	if err := s.RulesUp(); err != nil {
		t.Fatal(err)
	}
	defer s.RulesDown()
	// A local socket explicitly using the router LAN address may be SNATed to
	// WAN. Match its original source in both directions, not the current IPs.
	p := sandboxPacket{out: "eth3", originalSource: "192.168.3.1", sport: s.PortLo + 1, dport: 443, count: 1}
	f.traverse("OUTPUT", &p)
	f.traverse("POSTROUTING", &p)
	if !reflect.DeepEqual(p.queues, []int{200}) {
		t.Fatalf("router-local source did not reach sandbox: %+v", p)
	}
	reply := sandboxPacket{in: "eth3", originalSource: "192.168.3.1", sport: 443, dport: p.sport, count: 1, connmark: p.connmark}
	f.traverse("PREROUTING", &reply)
	if !reflect.DeepEqual(reply.queues, []int{200}) {
		t.Fatalf("router-local NAT reply did not reach sandbox: %+v", reply)
	}
}

func TestOwnedMainGuardRequiresCompleteExactStructure(t *testing.T) {
	s := testSandbox(newSandboxFirewall(true), 0)
	const real = "-A nfqws_post -p tcp -m tcp --sport 50000:50199 --dport 443 -m connmark --mark 0x20000000/0x20000000 -m conntrack --ctorigsrc 10.0.0.2/32 -j RETURN"
	if got := s.ownedMainGuard("nfqws_post", real); got == nil || strings.Join(got, " ") != strings.TrimPrefix(real, "-A nfqws_post ") {
		t.Fatalf("real iptables -S form not recognized: %v", got)
	}
	for _, foreign := range []string{
		strings.Replace(real, "50000:50199", "50200:50399", 1),
		strings.Replace(real, "0x20000000/0x20000000", "0x20000000/0xffffffff", 1),
		strings.Replace(real, "10.0.0.2/32", "10.0.0.0/24", 1),
		strings.Replace(real, "10.0.0.2/32", "0.0.0.0/32", 1),
		strings.Replace(real, "RETURN", "ACCEPT", 1),
		strings.Replace(real, "--dport 443", "--dport 80", 1),
		strings.Replace(real, "-p tcp", "-p udp", 1),
		strings.Replace(real, " -j RETURN", " -d 1.1.1.1/32 -j RETURN", 1),
		strings.Replace(real, " -j RETURN", " -m comment --comment user-rule -j RETURN", 1),
		strings.Replace(real, " -j RETURN", " -m tcp -j RETURN", 1),
	} {
		if got := s.ownedMainGuard("nfqws_post", foreign); got != nil {
			t.Fatalf("foreign rule matched cleanup: %s", foreign)
		}
	}
}

func TestSandboxCrashCleanupUsesSavedRuleAddressesNotCurrentLease(t *testing.T) {
	f := newSandboxFirewall(true)
	foreign := []string{"-p", "tcp", "--sport", "50000:50199", "--dport", "443", "-m", "connmark", "--mark", exclMark, "-m", "conntrack", "--ctorigsrc", "10.0.0.0/24", "-j", "RETURN"}
	f.chains["nfqws_post"] = append(f.chains["nfqws_post"], foreign)
	original := fmt.Sprint(f.chains)
	s := testSandbox(f, 0)
	if err := s.RulesUp(); err != nil {
		t.Fatal(err)
	}
	// Simulate process loss and a different or unavailable local-address view.
	fresh := testSandbox(f, 0)
	fresh.localAddrs = func() ([]net.Addr, error) { return nil, os.ErrPermission }
	fresh.RulesDown()
	if got := fmt.Sprint(f.chains); got != original {
		t.Fatalf("stale guards remained or foreign rule changed:\ngot %s\nwant %s", got, original)
	}
}
