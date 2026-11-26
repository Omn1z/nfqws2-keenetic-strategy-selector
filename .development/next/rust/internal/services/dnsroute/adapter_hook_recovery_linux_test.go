//go:build linux

package dnsroute

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"nfqws2strategy/internal/tools/config"
)

type hookRecoveryIntegration struct {
	adapter    *Adapter
	hook       string
	dataDir    string
	cleanupLog string
	mu         sync.Mutex
	calls      []string
	failHook   bool
}

func newHookRecoveryIntegration(t *testing.T) *hookRecoveryIntegration {
	t.Helper()
	root := t.TempDir()
	f := &hookRecoveryIntegration{
		hook:       filepath.Join(root, "netfilter.d", "93-nfqws-dns.sh"),
		dataDir:    filepath.Join(root, "data"),
		cleanupLog: filepath.Join(root, "cleanup.log"),
	}
	if err := os.MkdirAll(filepath.Dir(f.hook), 0755); err != nil {
		t.Fatal(err)
	}
	// cleanupLocked invokes runCommandContext directly. Drain that script in
	// a no-op shell wrapper so even the cleanup path cannot reach a host's
	// real iptables executable. All commands use shell builtins.
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0755); err != nil {
		t.Fatal(err)
	}
	stub := "#!/bin/sh\nprintf '%s\\n' cleanup >> \"$N2S_DNS_HOOK_TEST_LOG\"\nwhile IFS= read -r line; do :; done\n"
	if err := os.WriteFile(filepath.Join(bin, "sh"), []byte(stub), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("N2S_DNS_HOOK_TEST_LOG", f.cleanupLog)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	priorCommand, priorHook := command, hookPath
	t.Cleanup(func() { command, hookPath = priorCommand, priorHook })
	hookPath = f.hook
	command = func(_ context.Context, name string, args ...string) (string, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, name+" "+strings.Join(args, " "))
		if name == "ip" && len(args) == 3 && args[1] == "rule" && args[2] == "show" {
			return "", nil
		}
		if name == "sh" && len(args) == 1 && args[0] == f.hook {
			if f.failHook {
				f.failHook = false
				return "", errors.New("fixture hook installation failed")
			}
			return "", nil
		}
		return "", errors.New("unexpected command in isolated hook test")
	}
	cfg := config.Default()
	cfg.DataDir = f.dataDir
	f.adapter = New(cfg, nil)
	t.Cleanup(func() { _ = f.adapter.Close() })
	return f
}

func (f *hookRecoveryIntegration) prepare() error {
	return f.adapter.Prepare(context.Background(), ListenOptions{
		Host: "127.0.0.1", DNSPort: 5355, DisableNFQWS: true,
	})
}

func (f *hookRecoveryIntegration) requireNoCommands(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) != 0 {
		t.Fatalf("unrecognized hook triggered commands: %v", f.calls)
	}
	if _, err := os.Stat(f.cleanupLog); !os.IsNotExist(err) {
		t.Fatalf("unrecognized hook triggered firewall cleanup: %v", err)
	}
}

func (f *hookRecoveryIntegration) requireDamageBackup(t *testing.T, original []byte) string {
	t.Helper()
	backupRoot := filepath.Join(f.dataDir, "recovery", "dns-hooks")
	var matches []string
	err := filepath.WalkDir(backupRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Equal(data, original) {
			matches = append(matches, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("exact damage backups = %d, want 1", len(matches))
	}
	relative, err := filepath.Rel(filepath.Dir(f.hook), matches[0])
	if err != nil || !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		t.Fatalf("backup remained in active hook directory: %q, %v", relative, err)
	}
	return matches[0]
}

func TestAdapterPrepareRecoversDamagedHookWithoutLeavingExecutableBackup(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "empty", data: []byte{}},
		{name: "zero-filled", data: bytes.Repeat([]byte{0}, 128)},
		{name: "truncated own header", data: []byte("#!/bin/sh\n# NFQWS DNS Server: managed private sock")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newHookRecoveryIntegration(t)
			if err := os.WriteFile(f.hook, tc.data, 0755); err != nil {
				t.Fatal(err)
			}
			if err := f.prepare(); err != nil {
				t.Fatalf("recover damaged hook: %v", err)
			}
			if !f.adapter.started || !f.adapter.hookReady {
				t.Fatal("successful recovery did not prepare routing")
			}
			installed, err := os.ReadFile(f.hook)
			if err != nil || !bytes.Contains(installed, []byte(hookSignature)) {
				t.Fatalf("recovery did not install an owned hook: %v", err)
			}
			backup := f.requireDamageBackup(t, tc.data)
			entries, err := os.ReadDir(filepath.Dir(f.hook))
			if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(f.hook) {
				t.Fatalf("active hook directory contains recovery artifacts: entries=%v err=%v", entries, err)
			}
			if err := f.adapter.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(f.hook); !os.IsNotExist(err) {
				t.Fatalf("Close left recovered hook installed: %v", err)
			}
			if data, err := os.ReadFile(backup); err != nil || !bytes.Equal(data, tc.data) {
				t.Fatalf("Close damaged recovery backup: %v", err)
			}
		})
	}
}

func TestAdapterPrepareDoesNotCleanUpForeignOrSymlinkHook(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		name := "foreign file"
		if symlink {
			name = "symlink to owned content"
		}
		t.Run(name, func(t *testing.T) {
			f := newHookRecoveryIntegration(t)
			original := []byte("#!/bin/sh\n# User firewall hook\nexit 0\n")
			target := f.hook
			if symlink {
				original = []byte("#!/bin/sh\n" + hookSignature + "\nexit 0\n")
				target = filepath.Join(t.TempDir(), "owned-target.sh")
			}
			if err := os.WriteFile(target, original, 0755); err != nil {
				t.Fatal(err)
			}
			if symlink {
				if err := os.Symlink(target, f.hook); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.prepare(); err == nil {
				t.Fatal("unrecognized hook was replaced")
			}
			f.requireNoCommands(t)
			if err := f.adapter.Close(); err == nil {
				t.Fatal("Close accepted an unrecognized hook")
			}
			f.requireNoCommands(t)
			if data, err := os.ReadFile(target); err != nil || !bytes.Equal(data, original) {
				t.Fatalf("unrecognized hook content changed: %v", err)
			}
			if symlink {
				if got, err := os.Readlink(f.hook); err != nil || got != target {
					t.Fatalf("hook symlink changed: %q, %v", got, err)
				}
			}
		})
	}
}

func TestAdapterRecoveredHookInstallFailureCanRetryWithoutLosingBackup(t *testing.T) {
	f := newHookRecoveryIntegration(t)
	damage := []byte("#!/bin/sh\n# NFQWS DNS Server: managed private sock")
	if err := os.WriteFile(f.hook, damage, 0755); err != nil {
		t.Fatal(err)
	}
	f.failHook = true
	if err := f.prepare(); err == nil || !strings.Contains(err.Error(), "fixture hook installation failed") {
		t.Fatalf("hook installation failure was lost: %v", err)
	}
	if f.adapter.started || f.adapter.hookReady {
		t.Fatal("failed installation advertised prepared routing")
	}
	backup := f.requireDamageBackup(t, damage)
	if err := f.prepare(); err != nil {
		t.Fatalf("retry after failed recovery: %v", err)
	}
	if !f.adapter.started || !f.adapter.hookReady {
		t.Fatal("retry did not restore routing")
	}
	if f.requireDamageBackup(t, damage) != backup {
		t.Fatal("retry replaced the original damage backup")
	}
}
