//go:build linux

package awgroute

import (
	"fmt"
	"strings"
	"testing"
)

func TestAWGNFQUEUEWindowRequiresBoundedPayloadOrTCPControl(t *testing.T) {
	const bounded = "-A nfqws_post -p tcp -m connbytes --connbytes 1:15 --connbytes-mode packets --connbytes-dir original -j NFQUEUE --queue-num 300"
	cases := []struct {
		name, rule string
		safe       bool
	}{
		{"initial original packets", bounded, true},
		{"initial reply packets", strings.ReplaceAll(strings.ReplaceAll(bounded, "1:15", "1:32"), "original", "reply"), true},
		{"bounded other queue", strings.ReplaceAll(bounded, "--queue-num 300", "--queue-num 301"), true},
		{"SYN", "-A nfqws_post -p tcp -m tcp --tcp-flags SYN SYN -j NFQUEUE --queue-num 300", true},
		{"FIN", "-A nfqws_post -p tcp -m tcp --tcp-flags FIN FIN -j NFQUEUE --queue-num 300", true},
		{"RST", "-A nfqws_post -p tcp -m tcp --tcp-flags 0x04 0x04 -j NFQUEUE --queue-num 300", true},
		{"unbounded", "-A nfqws_post -j NFQUEUE --queue-num 300", false},
		{"unbounded other queue", "-A nfqws_post -j NFQUEUE --queue-num 301", false},
		{"too many initial packets", strings.ReplaceAll(bounded, "1:15", "1:33"), false},
		{"no upper bound", strings.ReplaceAll(bounded, "1:15", "1:"), false},
		{"inverted range", strings.ReplaceAll(bounded, "1:15", "15:1"), false},
		{"nonpacket bytes", strings.ReplaceAll(bounded, "--connbytes-mode packets", "--connbytes-mode bytes"), false},
		{"both directions", strings.ReplaceAll(bounded, "--connbytes-dir original", "--connbytes-dir both"), false},
		{"negated window", strings.ReplaceAll(bounded, "--connbytes 1:15", "! --connbytes 1:15"), false},
		{"negated mode", strings.ReplaceAll(bounded, "--connbytes-mode packets", "! --connbytes-mode packets"), false},
		{"negated direction", strings.ReplaceAll(bounded, "--connbytes-dir original", "! --connbytes-dir original"), false},
		{"ACK bulk", "-A nfqws_post -p tcp --tcp-flags ACK ACK -j NFQUEUE --queue-num 300", false},
		{"negated SYN", "-A nfqws_post -p tcp ! --tcp-flags SYN SYN -j NFQUEUE --queue-num 300", false},
		{"negated TCP", "-A nfqws_post ! -p tcp --tcp-flags SYN SYN -j NFQUEUE --queue-num 300", false},
		{"missing queue", strings.ReplaceAll(bounded, " --queue-num 300", ""), false},
		{"queue balance", strings.ReplaceAll(bounded, "--queue-num 300", "--queue-balance 300:301"), false},
		{"nonnumeric queue", strings.ReplaceAll(bounded, "--queue-num 300", "--queue-num unknown"), false},
		{"invalid queue", strings.ReplaceAll(bounded, "--queue-num 300", "--queue-num 65536"), false},
		{"comment cannot provide a window", `-A nfqws_post -m comment --comment "--connbytes 1:15 --connbytes-mode packets --connbytes-dir original" -j NFQUEUE --queue-num 300`, false},
		{"quoted comments preserve real window", bounded + ` -m comment --comment "a quoted 'note' --tcp-flags ACK ACK"`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := awgNFQUEUEWindowSafe("*mangle\n"+tc.rule+"\nCOMMIT\n", 300); got != tc.safe {
				t.Fatalf("queue coverage safety = %v, want %v", got, tc.safe)
			}
		})
	}
	if awgNFQUEUEWindowSafe("*mangle\n"+bounded+"\nCOMMIT\n*filter\n-A unrelated -j NFQUEUE --queue-num 400\nCOMMIT\n", 300) {
		t.Fatal("unbounded NFQUEUE in another table escaped the audit")
	}
	for _, queue := range []int{-1, 65536} {
		if awgNFQUEUEWindowSafe("*mangle\nCOMMIT\n", queue) {
			t.Fatal("invalid configured queue accepted")
		}
	}
}

// A fixed contract fixture keeps changes to generator and auditor from agreeing
// with each other while silently losing a packet direction or interface guard.
func awgPPEContractDocument() string {
	var b strings.Builder
	b.WriteString("*mangle\n:N2S_AWGPPE_IN - [0:0]\n:N2S_AWGPPE_FWD - [0:0]\n:N2S_AWGPPE_OUT - [0:0]\n")
	for _, chain := range []string{"N2S_AWGPPE_IN", "N2S_AWGPPE_FWD", "N2S_AWGPPE_OUT"} {
		fmt.Fprintf(&b, "-A %s -m connbytes --connbytes 1:32 --connbytes-mode packets --connbytes-dir original -j PPE\n", chain)
		fmt.Fprintf(&b, "-A %s -m connbytes --connbytes 1:32 --connbytes-mode packets --connbytes-dir reply -j PPE\n", chain)
		fmt.Fprintf(&b, "-A %s -p tcp -m tcp --tcp-flags SYN SYN -j PPE\n-A %s -p tcp -m tcp --tcp-flags FIN FIN -j PPE\n-A %s -p tcp -m tcp --tcp-flags RST RST -j PPE\n", chain, chain, chain)
	}
	b.WriteString("-A N2S_AWGPPE_IN -i awg0 -j PPE\n-A N2S_AWGPPE_FWD -i awg0 -j PPE\n-A N2S_AWGPPE_FWD -o awg0 -j PPE\n-A N2S_AWGPPE_OUT -o awg0 -j PPE\n")
	b.WriteString("-A N2S_AWGPPE_IN -i awg7 -j PPE\n-A N2S_AWGPPE_FWD -i awg7 -j PPE\n-A N2S_AWGPPE_FWD -o awg7 -j PPE\n-A N2S_AWGPPE_OUT -o awg7 -j PPE\nCOMMIT\n")
	return b.String()
}

func TestAWGPPEGuardDocumentCoversHandshakeControlAndTunnelDirections(t *testing.T) {
	if got, want := awgPPEGuardDocument([]string{"awg0", "awg7"}), awgPPEContractDocument(); got != want {
		t.Fatalf("PPE guards lost the initial 32 packets, TCP control, or a tunnel direction:\n%s", got)
	}
}

func TestAWGPPEGuardsAuditRequiresExactScopedRulesAndParentOrder(t *testing.T) {
	const parents = "-A PREROUTING -j N2S_AWGPPE_IN\n-A FORWARD -j N2S_AWGPPE_FWD\n-A POSTROUTING -j N2S_AWGPPE_OUT\n"
	plain := strings.Replace(awgPPEContractDocument(), "COMMIT\n", parents+"COMMIT\n", 1)
	composed := strings.Replace(plain, "-A PREROUTING -j N2S_AWGPPE_IN", "-A PREROUTING -j AWG2_MULTI\n-A PREROUTING -j N2S_AWGPPE_IN", 1)
	for name, snapshot := range map[string]string{
		"IPv4 composed policy":                  composed,
		"unprefixed policy":                     plain,
		"hexadecimal TCP flags":                 strings.ReplaceAll(composed, "--tcp-flags SYN SYN", "--tcp-flags 0x02 0x02"),
		"raw table parent rules are irrelevant": "*raw\n-A PREROUTING -j ACCEPT\nCOMMIT\n" + composed,
		"real save footer and later tables":     "# Generated by iptables-save v1.8.10\n" + composed + "# Completed on Mon Nov 16 2026\n*nat\n-A POSTROUTING -j ACCEPT\nCOMMIT\n# Completed on Mon Nov 16 2026\n",
	} {
		t.Run(name, func(t *testing.T) {
			if !awgPPEGuardsIntact(snapshot, []string{"awg0", "awg7"}, true) {
				t.Fatal("complete ordered PPE protection rejected")
			}
		})
	}
	if !awgPPEGuardsIntact(plain, []string{"awg0", "awg7"}, false) {
		t.Fatal("IPv6 PPE-first layout rejected")
	}
	if awgPPEGuardsIntact(composed, []string{"awg0", "awg7"}, false) {
		t.Fatal("IPv6 audit allowed another chain ahead of PPE")
	}
	orig := "-A N2S_AWGPPE_IN -m connbytes --connbytes 1:32 --connbytes-mode packets --connbytes-dir original -j PPE\n"
	reply := strings.ReplaceAll(orig, "original", "reply")
	for name, broken := range map[string]string{
		"missing original window":     strings.Replace(composed, orig, "", 1),
		"missing reply window":        strings.Replace(composed, reply, "", 1),
		"reordered windows":           strings.Replace(composed, orig+reply, reply+orig, 1),
		"short window":                strings.Replace(composed, "--connbytes 1:32", "--connbytes 1:15", 1),
		"missing control":             strings.Replace(composed, "-A N2S_AWGPPE_OUT -p tcp -m tcp --tcp-flags RST RST -j PPE\n", "", 1),
		"missing tunnel reply":        strings.Replace(composed, "-A N2S_AWGPPE_FWD -o awg7 -j PPE\n", "", 1),
		"unscoped tunnel guard":       strings.Replace(composed, "-A N2S_AWGPPE_FWD -o awg7 -j PPE", "-A N2S_AWGPPE_FWD -j PPE", 1),
		"wrong tunnel":                strings.Replace(composed, "-A N2S_AWGPPE_IN -i awg7", "-A N2S_AWGPPE_IN -i awg8", 1),
		"reordered tunnel directions": strings.Replace(composed, "-A N2S_AWGPPE_FWD -i awg0 -j PPE\n-A N2S_AWGPPE_FWD -o awg0 -j PPE", "-A N2S_AWGPPE_FWD -o awg0 -j PPE\n-A N2S_AWGPPE_FWD -i awg0 -j PPE", 1),
		"missing parent":              strings.Replace(composed, "-A FORWARD -j N2S_AWGPPE_FWD\n", "", 1),
		"forward guard displaced":     strings.Replace(composed, "-A FORWARD -j N2S_AWGPPE_FWD", "-A FORWARD -j ACCEPT\n-A FORWARD -j N2S_AWGPPE_FWD", 1),
		"policy prefix displaced":     strings.Replace(composed, "-A PREROUTING -j AWG2_MULTI", "-A PREROUTING -j ACCEPT\n-A PREROUTING -j AWG2_MULTI", 1),
		"missing commit":              strings.TrimSuffix(composed, "COMMIT\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if awgPPEGuardsIntact(broken, []string{"awg0", "awg7"}, true) {
				t.Fatal("missing, broadened, or reordered PPE protection accepted")
			}
		})
	}
	if awgPPEGuardsIntact(composed, nil, true) || awgPPEGuardsIntact(composed, []string{"awg0", "awg7", "awg8"}, true) {
		t.Fatal("audit accepted absent expected interfaces")
	}
}
