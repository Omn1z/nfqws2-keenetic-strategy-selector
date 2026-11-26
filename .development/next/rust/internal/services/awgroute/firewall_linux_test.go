//go:build linux

package awgroute

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestFirewallHookKeepsCriticalRestoreFreeOfOptionalTargets(t *testing.T) {
	hook := awgFirewallHook("full", "138.124.229.182", "eth3", 1280, false, false, nil)
	start := strings.Index(hook, "$IPTABLES_RESTORE <<'AWGV4' 2>&1\n")
	end := strings.Index(hook, "\nAWGV4\n")
	if start < 0 || end < 0 || end <= start {
		t.Fatalf("v4 restore document not found:\n%s", hook)
	}
	doc := hook[start:end]
	for _, bad := range []string{"TCPMSS", "-m comment", "*nat", "*filter"} {
		if strings.Contains(doc, bad) {
			t.Fatalf("critical v4 restore contains optional target %q:\n%s", bad, doc)
		}
	}
	for _, want := range []string{"-A AWG2_MARK -j MARK --set-xmark 0x10000000/0x10000000", "-A PREROUTING -j AWG2_MARK", "-A OUTPUT -j AWG2_MARK"} {
		if !strings.Contains(doc, want) {
			t.Fatalf("critical v4 restore misses %q:\n%s", want, doc)
		}
	}
	if !strings.Contains(hook[end:], "TCPMSS") || !strings.Contains(hook[end:], "MASQUERADE") {
		t.Fatalf("best-effort shared rules were not emitted after critical restore:\n%s", hook[end:])
	}
}

func TestFirewallHooksRestoreFunctionsHaveValidShellSyntax(t *testing.T) {
	for name, hook := range map[string]string{
		"legacy": awgFirewallHook("full", "192.0.2.10", "eth0", 1280, true, false, nil),
		"multi":  awgMultiFirewallHook([]awgMultiTunnel{{Iface: "awg0", EndpointIP: "192.0.2.10", Table: 901, Mark: awgMultiMark(1), MTU: 1280}}, nil, true),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name+".sh")
			if err := os.WriteFile(path, []byte(hook), 0o600); err != nil {
				t.Fatal(err)
			}
			// Parse only: no generated firewall or interface action is executed.
			if out, err := exec.Command("sh", "-n", path).CombinedOutput(); err != nil {
				t.Fatalf("hook syntax: %v: %s", err, out)
			}
		})
	}
}

func TestFirewallHooksRedirectDNSOnlyToRouteLearner(t *testing.T) {
	for name, hook := range map[string]string{
		"legacy": awgFirewallHook("include", "192.0.2.10", "eth0", 1280, true, false, nil),
		"multi": awgMultiFirewallHook([]awgMultiTunnel{{
			Iface: "awg0", EndpointIP: "192.0.2.10", Table: 901, Mark: awgMultiMark(1), MTU: 1280,
		}}, nil, true),
	} {
		t.Run(name, func(t *testing.T) {
			for _, family := range []string{"iptables", "ip6tables"} {
				for _, protocol := range []string{"udp", "tcp"} {
					want := family + " -w -t nat -A PREROUTING -i $br -p " + protocol + " --dport 53 -j REDIRECT --to-ports " + awgDNSPort
					if !strings.Contains(hook, want) {
						t.Fatalf("missing route learner redirect %q", want)
					}
				}
			}
			if strings.Contains(hook, "--to-ports "+awgLegacyPiholeDNSPort) {
				t.Fatal("firewall still redirects DNS to the retired Pi-hole port")
			}
		})
	}
}
