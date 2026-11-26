//go:build linux

package awgroute

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"nfqws2strategy/internal/services/awg"
)

func TestDoubleTunnelSelectorAcceptsItsKeeneticState(t *testing.T) {
	selector, err := newDoubleTunnelSelector("awg7")
	if err != nil {
		t.Fatal(err)
	}
	state := &doubleTunnelTransport{OuterIface: "awg1", Endpoint: "192.0.2.20", MTU: 1220}
	run := func(command string) (string, error) {
		switch command {
		case "ip rule show":
			return "0: from all lookup local\n60: from all fwmark 0xa0000007 lookup 835\n61: from all fwmark 0xa0000007 lookup main reject\n", nil
		case "ip route show table 835":
			return "192.0.2.20 dev awg1  scope link src 172.16.0.2\nblackhole default  metric 1000\n", nil
		}
		return "", fmt.Errorf("unexpected command %q", command)
	}
	present, enabled, err := selector.inspect("ip", state, run)
	if err != nil || !enabled || !present["60:"] || !present["61:"] {
		t.Fatalf("inspect = %v, %t, %v", present, enabled, err)
	}
	if _, _, err := selector.inspect("ip", nil, run); err == nil {
		t.Fatal("accepted existing routes without ownership state")
	}
}

func TestDoubleTunnelSelectorRefusesCollisionAndGuardsBeforeLookup(t *testing.T) {
	selector, err := newDoubleTunnelSelector("awg7")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = selector.inspect("ip", nil, func(command string) (string, error) {
		if command == "ip rule show" {
			return "55: from all fwmark 0x80000000/0x80000000 lookup 104\n", nil
		}
		return "", nil
	})
	if err == nil {
		t.Fatal("accepted a higher-priority rule matching the transport mark")
	}
	var commands []string
	if err := selector.apply("ip", nil, "192.0.2.20/32 dev awg1 src 172.16.0.2", func(command string) (string, error) {
		commands = append(commands, command)
		return "", nil
	}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ip rule add pref 61 fwmark 0xa0000007 type prohibit",
		"ip route replace blackhole default table 835 protocol 99 metric 1000",
		"ip route replace 192.0.2.20/32 dev awg1 src 172.16.0.2 table 835 protocol 99",
		"ip rule add pref 60 fwmark 0xa0000007 table 835",
	}
	if !reflect.DeepEqual(commands, want) {
		t.Errorf("commands =\n%s\nwant\n%s", strings.Join(commands, "\n"), strings.Join(want, "\n"))
	}
}

func TestDoubleTunnelMTUAccountsForTransportAndObfuscation(t *testing.T) {
	cfg := awg.ServerConfig{MTU: 1420, Protocol: "awg", Obf: awg.Obfuscation{S4: 12, ContentPaddingAddition: "10-30"}}
	if got, err := doubleTunnelMTU(cfg, 1280, true); err != nil || got != 1178 {
		t.Fatalf("IPv4 MTU = %d, %v", got, err)
	}
	if got, err := doubleTunnelMTU(cfg, 1280, false); err != nil || got != 1158 {
		t.Fatalf("IPv6 transport MTU = %d, %v", got, err)
	}
	if _, err := doubleTunnelMTU(cfg, 600, true); err == nil {
		t.Fatal("accepted an MTU below 576")
	}
}
