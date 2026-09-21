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
