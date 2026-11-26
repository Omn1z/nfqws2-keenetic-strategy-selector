package nfqws2

import (
	"strings"
	"testing"
)

func TestNFQWS2InstallCommandSelectsOpenWrtNFTProviders(t *testing.T) {
	script, label := nfqws2InstallCommand("apk", "nfqws2-keenetic", true)
	steps := strings.Split(script, " && ")
	if len(steps) != 3 || steps[0] != "'apk' update" ||
		!strings.HasPrefix(steps[1], "'apk' add ") ||
		steps[2] != "'apk' add --upgrade 'nfqws2-keenetic'" {
		t.Fatalf("apk must install dependencies before NFQWS2: %q", script)
	}
	deps := strings.Fields(strings.TrimPrefix(steps[1], "'apk' add "))
	for _, required := range []string{
		"iptables-nft", "ip6tables-nft", "iptables-mod-nfqueue",
		"iptables-mod-conntrack-extra", "iptables-mod-ipopt", "ipset", "kmod-ipt-ipset",
	} {
		found := false
		for _, dep := range deps {
			found = found || dep == required
		}
		if !found {
			t.Fatalf("apk runtime dependency %q missing: %q", required, script)
		}
	}
	for _, dep := range deps {
		if dep == "iptables" || dep == "ip6tables" {
			t.Fatalf("apk command requests virtual package %q: %q", dep, script)
		}
	}
	if label != "apk install/upgrade nfqws2-keenetic" {
		t.Fatalf("wrong apk label: %q", label)
	}
	script, label = nfqws2InstallCommand("opkg", "nfqws2-keenetic", false)
	if script != "'opkg' update && 'opkg' install 'nfqws2-keenetic'" || label != "opkg install/upgrade nfqws2-keenetic" {
		t.Fatalf("opkg command changed: %q, %q", script, label)
	}
}

func TestNFQWS2BypassApplyInitializesBothFamilies(t *testing.T) {
	script := nfqws2BypassApplyCommand("/etc/init.d/nfqws2-keenetic", "/etc/nfqws2/nfqws-strategy-bypass.sh")
	want := []string{
		"'/etc/init.d/nfqws2-keenetic' firewall_iptables",
		"'/etc/init.d/nfqws2-keenetic' firewall_ip6tables",
		"'/etc/nfqws2/nfqws-strategy-bypass.sh' iptables",
		"'/etc/nfqws2/nfqws-strategy-bypass.sh' ip6tables",
	}
	previous := -1
	for _, step := range want {
		index := strings.Index(script, step)
		if index <= previous {
			t.Fatalf("missing or out-of-order bypass step %q: %q", step, script)
		}
		previous = index
	}
}

func TestParseAPKPackageVersion(t *testing.T) {
	const pkg = "nfqws2-keenetic"
	t.Run("policy", func(t *testing.T) {
		got := parseAPKPackageVersion("nfqws2-keenetic policy:\n  1.2.8:\n    lib/apk/db/installed\n", pkg)
		if got != "1.2.8" {
			t.Fatalf("version = %q, want 1.2.8", got)
		}
	})
	t.Run("installed wins over repository candidate", func(t *testing.T) {
		output := "nfqws2-keenetic policy:\n  1.3.0:\n    https://example.invalid/packages.adb\n  1.2.8:\n    lib/apk/db/installed\n"
		if got := parseAPKPackageVersion(output, pkg); got != "1.2.8" {
			t.Fatalf("version = %q, want installed 1.2.8", got)
		}
	})
	t.Run("info fallback", func(t *testing.T) {
		got := parseAPKPackageVersion("nfqws2-keenetic policy:\n  1.2.8:\n    lib/apk/db/installed\n", pkg)
		if got != "1.2.8" {
			t.Fatalf("version = %q, want 1.2.8", got)
		}
	})
	t.Run("candidate without local database is not installed", func(t *testing.T) {
		output := "nfqws2-keenetic policy:\n  1.3.0:\n    https://example.invalid/packages.adb\n"
		if got := parseAPKInstalledVersion(output); got != "" {
			t.Fatalf("candidate version = %q, want empty", got)
		}
	})
}
