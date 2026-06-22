//go:build linux

package awgroute

import (
	"strings"
	"testing"
)

func TestMultiFirewallHookWaitsForXtablesLock(t *testing.T) {
	hook := awgMultiFirewallHook([]awgMultiTunnel{{
		Iface:      "awg0",
		EndpointIP: "138.124.229.182",
		Table:      901,
		Mark:       awgMultiMark(1),
		MTU:        1280,
	}}, []awgMultiRule{{
		Tunnel:  &awgMultiTunnel{Mark: awgMultiMark(1)},
		SetName: "awgm_000",
		HasDst:  true,
		Sources: []string{"192.168.3.151"},
	}})
	for _, want := range []string{
		"iptables -w -t mangle -D PREROUTING",
		"IPTABLES_RESTORE='iptables-restore --noflush'",
		"iptables-restore -w 5 --noflush",
		"$IPTABLES_RESTORE <<'AWGMV4'",
		"iptables -w -t mangle -I PREROUTING 1 -j AWG2_MULTI",
		"iptables -w -t nat -A POSTROUTING -o awg0 -j MASQUERADE",
		"iptables -w -t mangle -A FORWARD -o awg0",
		"-A AWG2_MULTI -s 192.168.3.151 -m set --match-set awgm_000 dst -j ACCEPT",
	} {
		if !strings.Contains(hook, want) {
			t.Fatalf("multi hook misses %q:\n%s", want, hook)
		}
	}
	for _, bad := range []string{
		"iptables -t mangle -D PREROUTING",
		"iptables-restore --noflush <<",
		"iptables -t nat -A POSTROUTING",
	} {
		if strings.Contains(hook, bad) {
			t.Fatalf("multi hook still has non-waiting command %q:\n%s", bad, hook)
		}
	}
}
