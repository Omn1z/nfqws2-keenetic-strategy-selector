//go:build linux

package awgroute

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestPermanentLegacyRoutesKeepBothFamiliesFailClosed(t *testing.T) {
	const iface = "awg3"
	table := " table " + awgTable
	existing := fmt.Sprintf("32765: from all fwmark %s lookup %s\n", awgMarkRule, awgTable)
	for _, tc := range []struct {
		name  string
		ready bool
		route string
	}{
		{name: "waiting", route: "del"},
		{name: "ready", ready: true, route: "replace"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var commands []string
			run := func(command string) (string, error) {
				commands = append(commands, command)
				if strings.HasSuffix(command, " rule show") {
					return existing, nil
				}
				return "", nil
			}
			if err := applyPermanentLegacyRoutes(iface, tc.ready, run); err != nil {
				t.Fatal(err)
			}
			expected := []string{
				"ip rule show",
				"ip route replace blackhole default" + table + " metric 1000",
				"ip route " + tc.route + " default dev " + iface + table,
				"ip -6 rule show",
				"ip -6 route replace blackhole default" + table + " metric " + legacyPermanentIPv6Metric,
				"ip -6 route " + tc.route + " default dev " + iface + table,
			}
			if !slices.Equal(commands, expected) {
				t.Fatalf("unexpected route changes:\ngot  %q\nwant %q", commands, expected)
			}
		})
	}
}

func TestPermanentLegacyHookKeepsMarksAndWANEndpointExceptionsWhenLinkIsDown(t *testing.T) {
	hook := awgFirewallHookForInterface("awg3", "full", "192.0.2.42", "eth3", 1280, false, true, true, nil, "2001:db8::2")
	if strings.Contains(hook, "ip link show awg3 >/dev/null 2>&1 || exit 0") {
		t.Fatal("permanent hook would skip routing guards while the inner interface was down")
	}
	for _, rule := range []string{
		"-A " + awgChain + " -j MARK --set-xmark " + awgMarkRule,
		"-A " + awgChain + "6 -j MARK --set-xmark " + awgMarkRule,
		"-d 192.0.2.42/32 -j RETURN",
		"-d 2001:db8::2/128 -j RETURN",
	} {
		if !strings.Contains(hook, rule) {
			t.Fatalf("permanent hook omitted %q", rule)
		}
	}
}
