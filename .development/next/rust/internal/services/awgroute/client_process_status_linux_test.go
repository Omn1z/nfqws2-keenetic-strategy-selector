//go:build linux

package awgroute

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientProcessIdentityRejectsReplacementAndMissingDaemon(t *testing.T) {
	root := t.TempDir()
	iface := "awg987"
	t.Cleanup(func() { clientEnginePIDs.Delete(iface) })
	pid := "42"
	dir := filepath.Join(root, pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, value string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stat := func(state, start string) string {
		return pid + " (amneziawg-go) " + state + " " + strings.Repeat("0 ", 18) + start
	}
	write("cmdline", "/opt/usr/bin/amneziawg-go\x00"+iface+"\x00")
	write("stat", stat("S", "1234"))
	if got := awgClientProcessIdentity(root, iface); got != "42/1234" {
		t.Fatalf("live daemon identity: %q", got)
	}
	write("stat", stat("S", "5678"))
	if got := awgClientProcessIdentity(root, iface); got != "42/5678" {
		t.Fatalf("reused PID retained old generation: %q", got)
	}
	write("cmdline", "/opt/usr/bin/amneziawg-go\x00awg0\x00")
	if got := awgClientProcessIdentity(root, iface); got != "" {
		t.Fatalf("different interface daemon accepted: %q", got)
	}
	write("cmdline", "/opt/usr/bin/amneziawg-go\x00"+iface+"\x00")
	write("stat", stat("Z", "5678"))
	if got := awgClientProcessIdentity(root, iface); got != "" {
		t.Fatalf("zombie daemon accepted: %q", got)
	}
	if err := os.Remove(filepath.Join(dir, "cmdline")); err != nil {
		t.Fatal(err)
	}
	if got := awgClientProcessIdentity(root, iface); got != "" {
		t.Fatalf("missing daemon accepted: %q", got)
	}
}
