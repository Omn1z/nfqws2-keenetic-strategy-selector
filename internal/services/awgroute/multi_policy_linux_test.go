//go:build linux

package awgroute

import (
	"regexp"
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
	}}, false, false)
	for _, want := range []string{
		"iptables -w -t mangle -D PREROUTING",
		"IPTABLES_RESTORE='iptables-restore --noflush'",
		"iptables-restore -w --noflush",
		"$IPTABLES_RESTORE <<'AWGMV4'",
		"iptables -w -t mangle -I PREROUTING 1 -j AWG2_MULTI",
		"iptables -w -t nat -A POSTROUTING -o awg0 -j MASQUERADE",
		"iptables -w -t mangle -A FORWARD -o awg0",
		"-A AWG2_MULTI -s 192.168.3.151 -m set --match-set awgm_000 dst -j ACCEPT",
		"nft insert rule inet fw4 forward iifname \"$br\" oifname \"awg0\" accept comment \"nfqws2-awg2\"",
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
	// Some Keenetic builds accept -w but interpret the next token as the
	// command, rather than an optional timeout. A numeric argument breaks the
	// entire hook with "Bad argument `5'" before any routing rule is installed.
	numericWait := regexp.MustCompile(`-w[[:space:]]+[0-9]`)
	if numericWait.MatchString(hook) {
		t.Fatalf("multi hook uses an unsupported numeric xtables wait:\n%s", hook)
	}
	legacyHook := awgFirewallHook("full", "138.124.229.182", "eth3", 1280, false, false, false, nil)
	if numericWait.MatchString(legacyHook) {
		t.Fatalf("legacy hook uses an unsupported numeric xtables wait:\n%s", legacyHook)
	}
}

func TestMultiFirewallHookCanRedirectDNS(t *testing.T) {
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
	}}, true, false)
	for _, want := range []string{
		"grep -qi ':14EA ' /proc/net/udp /proc/net/udp6",
		"--dport 53 -j REDIRECT --to-ports 5354",
		"ip6tables -t nat -C PREROUTING",
	} {
		if !strings.Contains(hook, want) {
			t.Fatalf("multi hook misses DNS redirect %q:\n%s", want, hook)
		}
	}
}
