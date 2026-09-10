//go:build linux

package awgroute

import (
	"strings"
	"testing"
)

func TestFirewallHookKeepsCriticalRestoreFreeOfOptionalTargets(t *testing.T) {
	hook := awgFirewallHook("full", "138.124.229.182", "eth3", 1280, false, false, false, nil)
	start := strings.Index(hook, "iptables-restore --noflush <<'AWGV4'\n")
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
