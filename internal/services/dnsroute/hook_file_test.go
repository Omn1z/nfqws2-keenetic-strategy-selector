package dnsroute

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func dnsHookFixture(t *testing.T, data []byte) (string, string) {
	t.Helper()
	dir := t.TempDir()
	hooks := filepath.Join(dir, "netfilter.d")
	if err := os.Mkdir(hooks, 0755); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(hooks, "93-nfqws-dns.sh")
	if data != nil {
		if err := os.WriteFile(filename, data, 0755); err != nil {
			t.Fatal(err)
		}
	}
	return filename, filepath.Join(dir, "data", "recovery", "dns-hooks")
}

func TestDNSHookRecoversInterruptedFiles(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"zeroed", make([]byte, 128)},
		{"own_header_prefix", []byte("#!/bin/sh\n# NFQWS DNS Server: managed private sock")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			filename, recovery := dnsHookFixture(t, tc.data)
			script := "#!/bin/sh\n" + hookSignature + "\nset -e\n"
			if err := installDNSHook(filename, recovery, script); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(filename)
			if err != nil || string(got) != script {
				t.Fatalf("recovered hook = %q, %v", got, err)
			}
			files, err := filepath.Glob(filepath.Join(recovery, "93-nfqws-dns.sh.damaged-*"))
			if err != nil || len(files) != 1 {
				t.Fatalf("recovery backups = %v, %v", files, err)
			}
			backup, err := os.ReadFile(files[0])
			if err != nil || !bytes.Equal(backup, tc.data) {
				t.Fatalf("backup changed damaged bytes: %q, %v", backup, err)
			}
			info, err := os.Stat(files[0])
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm()&0111 != 0 || runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
				t.Fatalf("backup permissions = %v", info.Mode())
			}
			leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(filename), ".nfqws-dns-*"))
			if len(leftovers) != 0 {
				t.Fatalf("staging hooks left among active hooks: %v", leftovers)
			}
		})
	}
}

func TestDNSHookRejectsForeignAndUnrecognisedCorruption(t *testing.T) {
	for _, data := range [][]byte{
		[]byte("#!/bin/sh\necho custom firewall\n"),
		[]byte("#!/bin/sh\n# NFQWS DNS Server: another service\n"),
		[]byte("#!/bin/sh\n# NFQWS DNS"),
		[]byte("#!/bin/sh\n# NFQWS DNS Server: managed\x00"),
		append([]byte(hookSignature), make([]byte, maxDNSHookBytes)...),
	} {
		filename, recovery := dnsHookFixture(t, data)
		if err := installDNSHook(filename, recovery, "replacement"); err == nil {
			t.Fatalf("unrecognised hook was replaced: %q", data[:min(len(data), 80)])
		}
		if err := removeDNSHook(filename, recovery); err == nil {
			t.Fatal("unrecognised hook was removed")
		}
		got, err := os.ReadFile(filename)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("foreign bytes changed: %v", err)
		}
		if _, err := os.Stat(recovery); !os.IsNotExist(err) {
			t.Fatalf("foreign hook created a recovery directory: %v", err)
		}
	}
}

func TestDNSHookMissingAndOwnedFilesNeedNoRecoveryDirectory(t *testing.T) {
	for _, initial := range [][]byte{nil, []byte("#!/bin/sh\n" + hookSignature + "\nold content\n")} {
		filename, _ := dnsHookFixture(t, initial)
		if err := installDNSHook(filename, "", hookSignature+"\nnew content\n"); err != nil {
			t.Fatal(err)
		}
		if err := removeDNSHook(filename, ""); err != nil {
			t.Fatal(err)
		}
		if err := removeDNSHook(filename, ""); err != nil {
			t.Fatalf("repeated removal: %v", err)
		}
	}
}

func TestDNSHookRejectsNonregularFiles(t *testing.T) {
	filename, recovery := dnsHookFixture(t, nil)
	if err := os.Mkdir(filename, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectDNSHook(filename, "replace"); err == nil {
		t.Fatal("directory accepted as hook")
	}
	if err := os.Remove(filename); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(filepath.Dir(filepath.Dir(filename)), "target")
	if err := os.WriteFile(target, []byte(hookSignature), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filename); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := installDNSHook(filename, recovery, hookSignature); err == nil {
		t.Fatal("symlink accepted as hook")
	}
	if err := removeDNSHook(filename, recovery); err == nil {
		t.Fatal("symlink removed as owned hook")
	}
	if info, err := os.Lstat(filename); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink changed: %v", err)
	}
}

func TestDNSHookRecoveryCannotCreateBackupsAmongLiveHooks(t *testing.T) {
	filename, _ := dnsHookFixture(t, []byte{})
	inside := filepath.Join(filepath.Dir(filename), "backups")
	if err := installDNSHook(filename, inside, hookSignature); err == nil {
		t.Fatal("recovery inside active hook directory accepted")
	}
	if _, err := os.Stat(inside); !os.IsNotExist(err) {
		t.Fatalf("created directory among live hooks: %v", err)
	}
	alias := filepath.Join(filepath.Dir(filepath.Dir(filename)), "alias")
	if err := os.Symlink(filepath.Dir(filename), alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := installDNSHook(filename, filepath.Join(alias, "backups"), hookSignature); err == nil {
		t.Fatal("recovery alias into active hooks accepted")
	}
	if _, err := os.Stat(inside); !os.IsNotExist(err) {
		t.Fatalf("created directory through live-hook alias: %v", err)
	}
}

type failingDNSHookFile struct {
	*os.File
	fail string
	err  error
	sync func()
}

func (f *failingDNSHookFile) Write(data []byte) (int, error) {
	if f.fail == "write" {
		return 0, f.err
	}
	return f.File.Write(data)
}

func (f *failingDNSHookFile) Chmod(mode os.FileMode) error {
	if f.fail == "chmod" {
		return f.err
	}
	return f.File.Chmod(mode)
}

func (f *failingDNSHookFile) Sync() error {
	if f.fail == "sync" {
		return f.err
	}
	err := f.File.Sync()
	if err == nil && f.sync != nil {
		f.sync()
	}
	return err
}

func (f *failingDNSHookFile) Close() error {
	err := f.File.Close()
	if f.fail == "close" {
		return f.err
	}
	return err
}

func TestDNSHookPrecommitFailuresKeepExistingHook(t *testing.T) {
	for _, stage := range []string{"create", "write", "chmod", "sync", "close", "rename"} {
		t.Run(stage, func(t *testing.T) {
			original := []byte(hookSignature + "\noriginal\n")
			filename, recovery := dnsHookFixture(t, original)
			fault := errors.New("injected " + stage + " failure")
			ops := defaultDNSHookFileOps()
			ops.createTemp = func(dir, pattern string) (dnsHookWritableFile, error) {
				if stage == "create" {
					return nil, fault
				}
				f, err := os.CreateTemp(dir, pattern)
				if err != nil {
					return nil, err
				}
				return &failingDNSHookFile{File: f, fail: stage, err: fault}, nil
			}
			if stage == "rename" {
				ops.rename = func(string, string) error { return fault }
			}
			if err := installDNSHookWithOps(filename, recovery, hookSignature+"\nnew\n", ops); !errors.Is(err, fault) {
				t.Fatalf("error = %v, want injected failure", err)
			}
			got, err := os.ReadFile(filename)
			if err != nil || !bytes.Equal(got, original) {
				t.Fatalf("failed update damaged original hook: %q, %v", got, err)
			}
			leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(filename), ".nfqws-dns-*"))
			if len(leftovers) != 0 {
				t.Fatalf("failed staging files not cleaned: %v", leftovers)
			}
		})
	}
}

func TestDNSHookFileSyncPrecedesReplacementAndDirectorySync(t *testing.T) {
	filename, recovery := dnsHookFixture(t, []byte(hookSignature+"\nold\n"))
	ops := defaultDNSHookFileOps()
	synced, renamed := false, false
	ops.createTemp = func(dir, pattern string) (dnsHookWritableFile, error) {
		f, err := os.CreateTemp(dir, pattern)
		if err != nil {
			return nil, err
		}
		return &failingDNSHookFile{File: f, sync: func() { synced = true }}, nil
	}
	ops.rename = func(old, new string) error {
		if !synced {
			t.Error("unsynced file reached rename")
		}
		renamed = true
		return os.Rename(old, new)
	}
	ops.syncDir = func(string) error {
		if !renamed {
			t.Error("hook directory synced before replacement")
		}
		return nil
	}
	if err := installDNSHookWithOps(filename, recovery, hookSignature+"\nnew\n", ops); err != nil {
		t.Fatal(err)
	}
	if !synced || !renamed {
		t.Fatal("file sync or replacement did not run")
	}
}

func TestDNSHookPostcommitSyncFailureIsReported(t *testing.T) {
	filename, recovery := dnsHookFixture(t, []byte(hookSignature+"\nold\n"))
	ops := defaultDNSHookFileOps()
	fault := errors.New("directory I/O failure")
	ops.syncDir = func(string) error { return fault }
	script := hookSignature + "\nnew\n"
	if err := installDNSHookWithOps(filename, recovery, script, ops); !errors.Is(err, fault) {
		t.Fatalf("directory sync error hidden: %v", err)
	}
	got, err := os.ReadFile(filename)
	if err != nil || string(got) != script {
		t.Fatalf("a post-rename error must leave a complete replacement: %q, %v", got, err)
	}
}

func TestDNSHookBackupMustBeDurableBeforeReplacement(t *testing.T) {
	filename, recovery := dnsHookFixture(t, []byte{})
	if err := os.MkdirAll(recovery, 0700); err != nil {
		t.Fatal(err)
	}
	ops := defaultDNSHookFileOps()
	fault := errors.New("backup directory I/O failure")
	ops.syncDir = func(directory string) error {
		if directory == recovery {
			return fault
		}
		return nil
	}
	ops.rename = func(string, string) error {
		t.Fatal("replacement attempted without a durable backup")
		return nil
	}
	if err := installDNSHookWithOps(filename, recovery, hookSignature, ops); !errors.Is(err, fault) {
		t.Fatalf("backup sync error = %v", err)
	}
	if got, err := os.ReadFile(filename); err != nil || len(got) != 0 {
		t.Fatalf("damaged original changed before backup durability: %q, %v", got, err)
	}
}

func TestDNSHookNewDirectoryLinksAreSynced(t *testing.T) {
	dir := t.TempDir()
	hooks := filepath.Join(dir, "new", "ndm", "netfilter.d")
	filename := filepath.Join(hooks, "93-nfqws-dns.sh")
	ops := defaultDNSHookFileOps()
	var synced []string
	ops.syncDir = func(directory string) error { synced = append(synced, directory); return nil }
	if err := installDNSHookWithOps(filename, "", hookSignature, ops); err != nil {
		t.Fatal(err)
	}
	for _, needed := range []string{dir, filepath.Join(dir, "new"), filepath.Join(dir, "new", "ndm"), hooks} {
		found := false
		for _, actual := range synced {
			found = found || actual == needed
		}
		if !found {
			t.Errorf("new directory link was not synced: %s (got %v)", needed, synced)
		}
	}
}

func TestDNSHookRemovalPreservesInterruptedBytes(t *testing.T) {
	damaged := []byte("#!/bin/sh\n# NFQWS DNS Server:")
	filename, recovery := dnsHookFixture(t, damaged)
	if err := removeDNSHook(filename, recovery); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filename); !os.IsNotExist(err) {
		t.Fatalf("damaged hook still exists: %v", err)
	}
	files, _ := filepath.Glob(filepath.Join(recovery, "*"))
	if len(files) != 1 {
		t.Fatalf("removal backup count = %d", len(files))
	}
	got, err := os.ReadFile(files[0])
	if err != nil || !bytes.Equal(got, damaged) {
		t.Fatalf("removal changed backup bytes: %q, %v", got, err)
	}
}

func TestDNSHookDefaultRecoveryDirectoryStaysOutsideHooks(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "ndm", "netfilter.d", "93-nfqws-dns.sh")
	got := dnsHookRecoveryDir("", filename)
	if pathWithinDirectory(filepath.Dir(filename), got) || !strings.HasSuffix(got, "nfqws2-dns-hook-recovery") {
		t.Fatalf("unsafe fallback recovery directory: %s", got)
	}
}
