package nfqws2

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEnsureBypassScriptCreatesExecutableFallback(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "nfqws2", "nfqws-bypass.sh")
	if err := ensureBypassScript(name); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o111 == 0 {
		t.Fatalf("fallback is not executable: %v", st.Mode())
	}
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"nfqws2_bypass", "nfqws_post", "nfqws_pre", "nfqueue_bypass_domains.list", "-j ACCEPT"} {
		if !strings.Contains(string(data), needle) {
			t.Errorf("fallback script missing %q", needle)
		}
	}
}

func TestEnsureBypassScriptPreservesVendorHelper(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "nfqws-bypass.sh")
	const vendor = "#!/bin/sh\necho vendor\n"
	if err := os.WriteFile(name, []byte(vendor), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureBypassScript(name); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != vendor {
		t.Fatalf("vendor helper overwritten: %q", data)
	}
	if st, err := os.Stat(name); err != nil || (runtime.GOOS != "windows" && st.Mode().Perm()&0o111 == 0) {
		t.Fatalf("vendor helper was not made executable: %v", err)
	}
}

func TestEnsureBypassInitHookIsIdempotentAndPostSystemConfig(t *testing.T) {
	dir := t.TempDir()
	init := filepath.Join(dir, "nfqws2-keenetic")
	bypass := filepath.Join(dir, "nfqws-bypass.sh")
	const source = "#!/bin/sh\nstart_service() {\n  firewall_iptables\n  system_config\n}\n"
	if err := os.WriteFile(init, []byte(source), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ensureBypassInitHookOn(init, bypass, true); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(init)
	if err != nil {
		t.Fatal(err)
	}
	text := string(first)
	marker := "# nfqws2-strategy: reapply NFQUEUE bypass"
	if strings.Count(text, marker) != 1 || strings.Index(text, marker) <= strings.Index(text, "system_config") {
		t.Fatalf("hook placement is wrong: %q", text)
	}
	backup, err := os.ReadFile(init + ".n2s-bak")
	if err != nil {
		t.Fatalf("original init backup missing: %v", err)
	}
	if string(backup) != source {
		t.Fatalf("init backup was not pristine: %q", backup)
	}
	if err := ensureBypassInitHookOn(init, bypass, true); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(init)
	if err != nil {
		t.Fatal(err)
	}
	if string(second) != text {
		t.Fatal("second application changed an already patched init script")
	}
}

func TestEnsureBypassInitHookLeavesUnsupportedPlatformUntouched(t *testing.T) {
	dir := t.TempDir()
	init := filepath.Join(dir, "nfqws2-keenetic")
	const source = "#!/bin/sh\nsystem_config\n"
	if err := os.WriteFile(init, []byte(source), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ensureBypassInitHookOn(init, filepath.Join(dir, "bypass"), false); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(init)
	if string(got) != source {
		t.Fatal("non-OpenWrt init script was modified")
	}
}
