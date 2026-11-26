package backup

import (
	"archive/zip"
	"bytes"
	"crypto/md5"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type archiveEntry struct {
	path string
	data string
	mode os.FileMode
}

func sealedTestArchive(t *testing.T, entries ...archiveEntry) []byte {
	t.Helper()
	var plain bytes.Buffer
	zw := zip.NewWriter(&plain)
	for _, entry := range entries {
		name, err := archiveName(entry.path)
		if err != nil {
			t.Fatal(err)
		}
		h := &zip.FileHeader{Name: name, Method: zip.Store}
		h.SetMode(entry.mode)
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(entry.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return sealTestZIP(t, plain.Bytes())
}

func sealTestZIP(t *testing.T, plain []byte) []byte {
	t.Helper()
	gcm, err := newGCM()
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, nonceLen)
	body := make([]byte, saltLen+nonceLen)
	body = append(body, gcm.Seal(nil, nonce, plain, []byte(magicV1))...)
	sum := md5.Sum(body)
	out := append([]byte(magicV1), sum[:]...)
	return append(out, body...)
}

func assertRestoreTempsRemoved(t *testing.T, dir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, ".n2s-restore-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("restore temporaries remain: %v (%v)", matches, err)
	}
}

func TestRestoreFailureBeforeRenamePreservesOriginal(t *testing.T) {
	boom := errors.New("injected persistence failure")
	for _, stage := range []string{"file-sync", "file-close", "rename"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "settings.json")
			if err := os.WriteFile(path, []byte("old-complete"), 0o600); err != nil {
				t.Fatal(err)
			}
			archive := sealedTestArchive(t, archiveEntry{path, "new-complete", 0o600})
			ops := restoreFileOps{}
			switch stage {
			case "file-sync":
				ops.syncFile = func(*os.File) error { return boom }
			case "file-close":
				ops.closeFile = func(f *os.File) error { return errors.Join(f.Close(), boom) }
			case "rename":
				ops.rename = func(string, string) error { return boom }
			}
			n, err := restoreWithOps([]string{dir}, bytes.NewReader(archive), ops)
			if n != 0 || !errors.Is(err, boom) {
				t.Fatalf("n=%d error=%v", n, err)
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != "old-complete" {
				t.Fatalf("old file was changed: %q %v", got, err)
			}
			assertRestoreTempsRemoved(t, dir)
		})
	}
}

func TestRestoreDirectorySyncFailureReportsCommittedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := sealedTestArchive(t, archiveEntry{path, "new-complete", 0o600})
	boom := errors.New("directory sync failed")
	n, err := restoreWithOps([]string{dir}, bytes.NewReader(archive), restoreFileOps{syncDir: func(string) error { return boom }})
	if n != 1 || !errors.Is(err, boom) {
		t.Fatalf("committed count not reported: n=%d error=%v", n, err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "new-complete" {
		t.Fatalf("committed file incomplete: %q %v", got, err)
	}
	assertRestoreTempsRemoved(t, dir)
}

func TestRestoreLaterRenameFailureReportsPartialCommit(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")
	for _, path := range []string{a, b} {
		if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	archive := sealedTestArchive(t, archiveEntry{a, "new-a", 0o600}, archiveEntry{b, "new-b", 0o600})
	boom := errors.New("second rename failed")
	n, err := restoreWithOps([]string{dir}, bytes.NewReader(archive), restoreFileOps{rename: func(src, dst string) error {
		if dst == b {
			return boom
		}
		return os.Rename(src, dst)
	}})
	if n != 1 || !errors.Is(err, boom) {
		t.Fatalf("n=%d error=%v", n, err)
	}
	for path, want := range map[string]string{a: "new-a", b: "old"} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatalf("unexpected commit %s: %q %v", filepath.Base(path), got, err)
		}
	}
	assertRestoreTempsRemoved(t, dir)
}

func TestRestoreNewDirectorySyncFailurePreventsCommit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new", "nested", "settings.json")
	archive := sealedTestArchive(t, archiveEntry{path, "settings", 0o600})
	boom := errors.New("parent directory sync failed")
	n, err := restoreWithOps([]string{dir}, bytes.NewReader(archive), restoreFileOps{syncDir: func(string) error { return boom }})
	if n != 0 || !errors.Is(err, boom) {
		t.Fatalf("n=%d error=%v", n, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("target published without durable parent: %v", err)
	}
}

func TestRestoreRejectsOversizedUncompressedMember(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	name, err := archiveName(path)
	if err != nil {
		t.Fatal(err)
	}
	var plain bytes.Buffer
	zw := zip.NewWriter(&plain)
	header := &zip.FileHeader{Name: name, Method: zip.Store, UncompressedSize64: maxArchive + 1}
	header.SetMode(0o600)
	if _, err := zw.CreateRaw(header); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	n, err := Restore([]string{dir}, bytes.NewReader(sealTestZIP(t, plain.Bytes())))
	if n != 0 || err == nil || !strings.Contains(err.Error(), "256MB") {
		t.Fatalf("oversized member accepted: %d %v", n, err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "old" {
		t.Fatal("oversized archive replaced target")
	}
	assertRestoreTempsRemoved(t, dir)
}

func TestRestoreStagesEntireArchiveBeforeCommit(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")
	for _, path := range []string{a, b} {
		if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	archive := sealedTestArchive(t, archiveEntry{a, "new-a", 0o600}, archiveEntry{b, "unique-crc-payload", 0o600})
	gcm, err := newGCM()
	if err != nil {
		t.Fatal(err)
	}
	body := archive[len(magicV1)+md5Len:]
	plain, err := gcm.Open(nil, body[saltLen:saltLen+nonceLen], body[saltLen+nonceLen:], []byte(magicV1))
	if err != nil {
		t.Fatal(err)
	}
	// Re-authenticate a ZIP with a damaged second member: its CRC, rather
	// than the outer envelope, must reject it before either target changes.
	plain = bytes.Replace(plain, []byte("unique-crc-payload"), []byte("broken-crc-payload"), 1)
	n, err := Restore([]string{dir}, bytes.NewReader(sealTestZIP(t, plain)))
	if n != 0 || !errors.Is(err, zip.ErrChecksum) {
		t.Fatalf("n=%d error=%v", n, err)
	}
	for _, path := range []string{a, b} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != "old" {
			t.Fatalf("changed target %s: %q %v", filepath.Base(path), got, err)
		}
	}
	assertRestoreTempsRemoved(t, dir)
}

func TestStoreMetadataNeverEntersOrLeavesArchive(t *testing.T) {
	dir := t.TempDir()
	metadata := filepath.Join(dir, ".store", "lock")
	if err := os.MkdirAll(filepath.Dir(metadata), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metadata, []byte("current-lock"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte("settings"), 0o600); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	if n, err := Build([]string{dir, metadata}, &archive); err != nil || n != 1 {
		t.Fatalf("metadata was backed up: n=%d %v", n, err)
	}
	gcm, err := newGCM()
	if err != nil {
		t.Fatal(err)
	}
	body := archive.Bytes()[len(magicV1)+md5Len:]
	plain, err := gcm.Open(nil, body[saltLen:saltLen+nonceLen], body[saltLen+nonceLen:], []byte(magicV1))
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(plain), int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range zr.File {
		if strings.Contains(f.Name, ".store") {
			t.Fatal("archive contains internal store metadata")
		}
	}
	forged := sealedTestArchive(t, archiveEntry{metadata, "foreign-lock", 0o600}, archiveEntry{path, "restored", 0o600})
	if n, err := Restore([]string{dir}, bytes.NewReader(forged)); err != nil || n != 1 {
		t.Fatalf("n=%d error=%v", n, err)
	}
	got, err := os.ReadFile(metadata)
	if err != nil || string(got) != "current-lock" {
		t.Fatalf("metadata replaced: %q %v", got, err)
	}
}

func TestRestoreKeepsSecretsPrivateAndHooksExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission semantics")
	}
	dir := t.TempDir()
	secret, private, hook := filepath.Join(dir, "awg.json"), filepath.Join(dir, "private.json"), filepath.Join(dir, "hook.sh")
	if err := os.WriteFile(private, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := sealedTestArchive(t, archiveEntry{secret, "settings", 0o644}, archiveEntry{private, "settings", 0o644}, archiveEntry{hook, "script", 0o755})
	if n, err := Restore([]string{dir}, bytes.NewReader(archive)); err != nil || n != 3 {
		t.Fatalf("n=%d error=%v", n, err)
	}
	for path, want := range map[string]os.FileMode{secret: 0o600, private: 0o600, hook: 0o755} {
		st, err := os.Stat(path)
		if err != nil || st.Mode().Perm() != want {
			t.Fatalf("%s mode: %v %v", filepath.Base(path), st, err)
		}
	}
}

func TestRestoreLegacySymlinkEntryAsPrivateRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.conf")
	archive := sealedTestArchive(t, archiveEntry{path, "captured file contents", os.ModeSymlink | 0o777})
	if n, err := Restore([]string{dir}, bytes.NewReader(archive)); err != nil || n != 1 {
		t.Fatalf("legacy entry restore: %d %v", n, err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("legacy entry did not become a regular file: %v %v", info, err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("legacy content exposed with mode %v", info.Mode().Perm())
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "captured file contents" {
		t.Fatalf("legacy payload lost: %q %v", got, err)
	}
	// An existing destination link must never redirect the archived bytes
	// into its target, even when the ZIP itself has legacy symlink metadata.
	outside := filepath.Join(t.TempDir(), "outside.conf")
	if err := os.WriteFile(outside, []byte("outside untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "existing-link.conf")
	if err := os.Symlink(outside, link); err != nil {
		t.Logf("destination-link subcase unavailable: %v", err)
		return
	}
	archive = sealedTestArchive(t, archiveEntry{link, "replacement", os.ModeSymlink | 0o777})
	if n, err := Restore([]string{dir}, bytes.NewReader(archive)); n != 0 || err == nil {
		t.Fatalf("existing link accepted: %d %v", n, err)
	}
	info, err = os.Lstat(link)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("destination symlink was replaced")
	}
	got, err = os.ReadFile(outside)
	if err != nil || string(got) != "outside untouched" {
		t.Fatalf("outside target changed: %q %v", got, err)
	}
	assertRestoreTempsRemoved(t, dir)
}

func TestRestoreRejectsDuplicateAndSymlinkParentBeforeCommit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := sealedTestArchive(t, archiveEntry{path, "first", 0o600}, archiveEntry{path, "second", 0o600})
	if n, err := Restore([]string{dir}, bytes.NewReader(archive)); n != 0 || err == nil {
		t.Fatalf("duplicate accepted: %d %v", n, err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "old" {
		t.Fatal("duplicate committed its first entry")
	}
	assertRestoreTempsRemoved(t, dir)
	outside := t.TempDir()
	link := filepath.Join(dir, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	archive = sealedTestArchive(t, archiveEntry{filepath.Join(link, "outside.json"), "outside", 0o600})
	if n, err := Restore([]string{dir}, bytes.NewReader(archive)); n != 0 || err == nil {
		t.Fatalf("symlink parent accepted: %d %v", n, err)
	}
	if _, err := os.Stat(filepath.Join(outside, "outside.json")); !os.IsNotExist(err) {
		t.Fatal("restore escaped allowed root")
	}
}
