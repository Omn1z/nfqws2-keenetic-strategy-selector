package nfqws2

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nfqws2strategy/internal/tools/config"
)

func archiveTestManager(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	return New(&config.Config{Nfqws2Conf: filepath.ToSlash(filepath.Join(dir, "nfqws2", "nfqws2.conf")), SystemBlobsDir: filepath.ToSlash(filepath.Join(dir, "nfqws2", "blobs")), LuaDir: filepath.ToSlash(filepath.Join(dir, "nfqws2", "lua")), DataDir: filepath.ToSlash(filepath.Join(dir, "state"))})
}
func putTestAsset(t *testing.T, m *Manager, name string, data []byte) {
	t.Helper()
	if err := m.SaveAsset(name, data, true); err != nil {
		t.Fatal(err)
	}
}
func testZIP(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	entries := make(archiveFiles, len(files))
	for name, data := range files {
		entries[name] = archiveEntry{data: data, mode: 0644}
	}
	b, err := encodeStrategyArchive(entries)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func readTestAsset(t *testing.T, m *Manager, name string) []byte {
	t.Helper()
	b, err := m.AssetBytes(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestStrategyExportBinaryAndScriptsRoundTrip(t *testing.T) {
	m := archiveTestManager(t)
	want := map[string][]byte{"nfqws2.conf": []byte("NFQWS_ARGS=\"--filter-tcp=443\"\n"), "lists/user.list": []byte("example.org\n"), "lists/deep/other.txt": []byte("example.net\n"), "blobs/tls.bin": {0, 1, 255, 0, 2, 13, 10}, "lua/lib.lua.gz": {31, 139, 8, 0}, "scripts/custom.sh": []byte("#!/bin/sh\necho custom\n"), "configs/other.conf": []byte("CUSTOM=1\n")}
	for name, data := range want {
		putTestAsset(t, m, name, data)
	}
	data, err := m.StrategyExport()
	if err != nil {
		t.Fatal(err)
	}
	other := archiveTestManager(t)
	preview, err := other.StrategyPreview(data, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Files) != len(want) || len(preview.ProtectedLists) != 1 {
		t.Fatalf("preview: %+v", preview)
	}
	result, err := other.StrategyImport(data, "", ArchiveImportOptions{Digest: preview.Digest, Lists: "replace", Overwrite: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Imported) != len(want) || !validSnapshotID(result.Snapshot.ID) {
		t.Fatalf("result: %+v", result)
	}
	for name, data := range want {
		if got := readTestAsset(t, other, name); !bytes.Equal(got, data) {
			t.Errorf("%s bytes changed: %x != %x", name, got, data)
		}
	}
}

func TestStrategyImportRequiresPreviewAndConflictChoices(t *testing.T) {
	m := archiveTestManager(t)
	putTestAsset(t, m, "nfqws2.conf", []byte("OLD=1\n"))
	putTestAsset(t, m, "lists/user.list", []byte("mine.test\n"))
	data := testZIP(t, map[string][]byte{"nfqws2.conf": []byte("NEW=1\n"), "lists/user.list": []byte("incoming.test\n")})
	preview, err := m.StrategyPreview(data, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.StrategyImport(data, "", ArchiveImportOptions{}); !errors.Is(err, ErrArchiveChanged) {
		t.Fatalf("missing preview = %v", err)
	}
	if _, err = m.StrategyImport(data, "", ArchiveImportOptions{Digest: preview.Digest, Overwrite: true}); err == nil {
		t.Fatal("no explicit user list decision")
	}
	if _, err = m.StrategyImport(data, "", ArchiveImportOptions{Digest: preview.Digest, Lists: "keep"}); !errors.Is(err, ErrAssetConflict) {
		t.Fatalf("overwrite conflict = %v", err)
	}
	result, err := m.StrategyImport(data, "", ArchiveImportOptions{Digest: preview.Digest, Lists: "keep", Overwrite: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Kept) != 1 || string(readTestAsset(t, m, "lists/user.list")) != "mine.test\n" {
		t.Fatal("personal list was replaced")
	}
	if string(readTestAsset(t, m, "nfqws2.conf")) != "NEW=1\n" {
		t.Fatal("config not imported")
	}
	// A valid preview cannot authorize subsequent on-disk changes.
	preview, err = m.StrategyPreview(data, "")
	if err != nil {
		t.Fatal(err)
	}
	putTestAsset(t, m, "nfqws2.conf", []byte("CHANGED=1\n"))
	if _, err = m.StrategyImport(data, "", ArchiveImportOptions{Digest: preview.Digest, Lists: "replace", Overwrite: true}); !errors.Is(err, ErrArchiveChanged) {
		t.Fatalf("stale preview = %v", err)
	}
}

func TestStrategySnapshotRestoreRemovesNewAssetsAndKeepsChosenLists(t *testing.T) {
	m := archiveTestManager(t)
	putTestAsset(t, m, "nfqws2.conf", []byte("OLD=1\n"))
	putTestAsset(t, m, "lists/user.list", []byte("old.test\n"))
	putTestAsset(t, m, "blobs/a.bin", []byte{0, 99})
	snapshot, err := m.StrategySnapshotCreate("Рабочая стратегия")
	if err != nil {
		t.Fatal(err)
	}
	putTestAsset(t, m, "nfqws2.conf", []byte("NEW=1\n"))
	putTestAsset(t, m, "blobs/new.bin", []byte{1, 2})
	putTestAsset(t, m, "lists/user.list", []byte("my.new.test\n"))
	putTestAsset(t, m, "lists/autolist.txt", []byte("learned.test\n"))
	preview, err := m.StrategyPreview(nil, snapshot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Removed) != 2 {
		t.Fatalf("removed=%v", preview.Removed)
	}
	result, err := m.StrategyImport(nil, snapshot.ID, ArchiveImportOptions{Digest: preview.Digest, Lists: "keep", Overwrite: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Removed) != 1 || result.Removed[0] != "blobs/new.bin" {
		t.Fatalf("removed=%v", result.Removed)
	}
	if _, err = m.AssetBytes("blobs/new.bin"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("leftover blob: %v", err)
	}
	if string(readTestAsset(t, m, "nfqws2.conf")) != "OLD=1\n" || string(readTestAsset(t, m, "lists/user.list")) != "my.new.test\n" || string(readTestAsset(t, m, "lists/autolist.txt")) != "learned.test\n" {
		t.Fatal("restore/preserve result incorrect")
	}
	list, err := m.StrategySnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("snapshots=%+v", list)
	}
	if err = m.StrategySnapshotDelete(snapshot.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = m.StrategySnapshotBytes(snapshot.ID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("snapshot not deleted: %v", err)
	}
}

func TestStrategyImportRollsBackAfterPartialWrite(t *testing.T) {
	m := archiveTestManager(t)
	putTestAsset(t, m, "nfqws2.conf", []byte("OLD=1\n"))
	putTestAsset(t, m, "blobs/a.bin", []byte{1})
	putTestAsset(t, m, "lists/blocked", []byte("not a directory"))
	data := testZIP(t, map[string][]byte{"nfqws2.conf": []byte("NEW=1\n"), "blobs/a.bin": {2}, "blobs/new.bin": {3}, "lists/blocked/child.list": []byte("fail.test\n")})
	preview, err := m.StrategyPreview(data, "")
	if err != nil {
		t.Fatal(err)
	}
	result, err := m.StrategyImport(data, "", ArchiveImportOptions{Digest: preview.Digest, Overwrite: true})
	if err == nil || !strings.Contains(err.Error(), "исходные файлы восстановлены") {
		t.Fatalf("rollback error: %v", err)
	}
	if !validSnapshotID(result.Snapshot.ID) {
		t.Fatal("no durable rollback snapshot")
	}
	if string(readTestAsset(t, m, "nfqws2.conf")) != "OLD=1\n" || !bytes.Equal(readTestAsset(t, m, "blobs/a.bin"), []byte{1}) {
		t.Fatal("originals not restored")
	}
	if _, err = m.AssetBytes("blobs/new.bin"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("new blob survived rollback: %v", err)
	}
}

func TestStrategyArchiveRejectsTraversalLinksAndDuplicates(t *testing.T) {
	m := archiveTestManager(t)
	for _, name := range []string{"../escape", "lists/../../escape", "/etc/passwd", "lists\\evil", "lists/./bad", "C:/evil", "scripts/../../evil.sh", "configs/nfqws2.conf", "unmanaged/file.txt"} {
		t.Run(name, func(t *testing.T) {
			data := testZIP(t, map[string][]byte{"nfqws2.conf": []byte("X=1\n"), name: []byte("bad")})
			if _, err := m.StrategyPreview(data, ""); err == nil {
				t.Fatalf("accepted %q", name)
			}
		})
	}
	for _, link := range []bool{false, true} {
		var b bytes.Buffer
		zw := zip.NewWriter(&b)
		w, _ := zw.Create("nfqws2.conf")
		w.Write([]byte("X=1\n"))
		h := &zip.FileHeader{Name: "lists/user.list", Method: zip.Deflate}
		h.SetMode(0644)
		if link {
			h.SetMode(os.ModeSymlink | 0777)
		}
		w, _ = zw.CreateHeader(h)
		w.Write([]byte("/etc/passwd"))
		if !link {
			w, _ = zw.Create("lits/user.list")
			w.Write([]byte("duplicate"))
		}
		zw.Close()
		if _, err := m.StrategyPreview(b.Bytes(), ""); err == nil {
			t.Fatalf("accepted link=%v", link)
		}
	}
}

func TestStrategyArchiveLimitsAndCRC(t *testing.T) {
	m := archiveTestManager(t)
	// A highly compressible expansion must fail before allocating its contents.
	data := testZIP(t, map[string][]byte{"nfqws2.conf": []byte("X=1\n"), "blobs/bomb.bin": bytes.Repeat([]byte{0}, AssetMaxBytes+1)})
	if _, err := m.StrategyPreview(data, ""); err == nil {
		t.Fatal("accepted oversized expansion")
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.CreateHeader(&zip.FileHeader{Name: "nfqws2.conf", Method: zip.Store})
	w.Write([]byte("UNCHANGED=1\n"))
	zw.Close()
	broken := buf.Bytes()
	i := bytes.Index(broken, []byte("UNCHANGED=1"))
	broken[i] = 'X'
	if _, err := m.StrategyPreview(broken, ""); err == nil {
		t.Fatal("accepted bad checksum")
	}
	if _, err := m.StrategyPreview(testZIP(t, map[string][]byte{"lists/a.list": []byte("example.org")}), ""); err == nil {
		t.Fatal("accepted missing config")
	}
}

func TestAssetPathsConflictAndBinaryDelete(t *testing.T) {
	m := archiveTestManager(t)
	data := []byte{0, 255, 13, 10, 42}
	if err := m.SaveAsset("blobs/test.bin", data, false); err != nil {
		t.Fatal(err)
	}
	if err := m.SaveAsset("blobs/test.bin", []byte{3}, false); !errors.Is(err, ErrAssetConflict) {
		t.Fatalf("conflict=%v", err)
	}
	if !bytes.Equal(readTestAsset(t, m, "blobs/test.bin"), data) {
		t.Fatal("conflicting upload changed file")
	}
	putTestAsset(t, m, "nfqws2.conf", []byte("X=1\n"))
	putTestAsset(t, m, "lists/user.list", []byte("my.test\n"))
	if err := m.DeleteAsset("nfqws2.conf"); err == nil {
		t.Fatal("deleted live config")
	}
	if err := m.DeleteAsset("lists/user.list"); err != nil {
		t.Fatalf("cannot delete user list in explorer: %v", err)
	}
	if err := m.DeleteAsset("blobs/test.bin"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"blobs/../nfqws2.conf", "blobs\\other.bin", "blobs/.hidden", "/etc/passwd", "scripts/no-extension", "configs/nfqws2.conf"} {
		if err := m.SaveAsset(name, []byte{1}, true); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
}

func TestAssetSymlinksRejected(t *testing.T) {
	m := archiveTestManager(t)
	putTestAsset(t, m, "nfqws2.conf", []byte("X=1\n"))
	putTestAsset(t, m, "lists/ordinary.list", []byte("mine"))
	outside := filepath.Join(t.TempDir(), "target.list")
	if err := os.WriteFile(outside, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(m.assetRoots()["list"], "link.list")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("host symlink privileges unavailable: %v", err)
	}
	if err := m.SaveAsset("lists/link.list", []byte("changed"), true); err == nil {
		t.Fatal("followed symlink while saving")
	}
	if _, err := m.AssetBytes("lists/link.list"); err == nil {
		t.Fatal("followed symlink while reading")
	}
	if err := m.DeleteAsset("lists/link.list"); err == nil {
		t.Fatal("followed symlink while deleting")
	}
	got, err := os.ReadFile(outside)
	if err != nil || string(got) != "outside" {
		t.Fatalf("outside changed: %q %v", got, err)
	}
}

func TestSnapshotRetentionPreservesNamedSnapshots(t *testing.T) {
	m := archiveTestManager(t)
	putTestAsset(t, m, "nfqws2.conf", []byte("X=1\n"))
	named, err := m.StrategySnapshotCreate("Named")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		data := testZIP(t, map[string][]byte{"nfqws2.conf": []byte("X=2\n")})
		p, e := m.StrategyPreview(data, "")
		if e != nil {
			t.Fatal(e)
		}
		if _, e = m.StrategyImport(data, "", ArchiveImportOptions{Digest: p.Digest, Overwrite: true}); e != nil {
			t.Fatal(e)
		}
	}
	list, err := m.StrategySnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 4 {
		t.Fatalf("snapshot count=%d", len(list))
	}
	if _, err = m.StrategySnapshotBytes(named.ID); err != nil {
		t.Fatal("named snapshot pruned", err)
	}
}

func TestStrategyPreviewAllowsLiveAutolistAppends(t *testing.T) {
	m := archiveTestManager(t)
	putTestAsset(t, m, "nfqws2.conf", []byte("OLD=1\n"))
	putTestAsset(t, m, "lists/auto.list", []byte("old.test\n"))
	data := testZIP(t, map[string][]byte{"nfqws2.conf": []byte("NEW=1\n"), "lists/auto.list": []byte("incoming.test\n")})
	p, err := m.StrategyPreview(data, "")
	if err != nil {
		t.Fatal(err)
	}
	putTestAsset(t, m, "lists/auto.list", []byte("old.test\nlearned.test\n"))
	if _, err = m.StrategyImport(data, "", ArchiveImportOptions{Digest: p.Digest, Overwrite: true, Lists: "keep"}); err != nil {
		t.Fatal(err)
	}
	if string(readTestAsset(t, m, "lists/auto.list")) != "old.test\nlearned.test\n" {
		t.Fatal("newly learned autolist entries lost")
	}
}

func TestConfiguredRootSymlinkIsAllowed(t *testing.T) {
	m := archiveTestManager(t)
	physical := t.TempDir()
	if err := os.MkdirAll(filepath.Dir(m.cfg.Nfqws2Conf), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(physical, m.cfg.SystemBlobsDir); err != nil {
		t.Skipf("host symlink privileges unavailable: %v", err)
	}
	putTestAsset(t, m, "blobs/blob.bin", []byte{0, 7, 255})
	if got, err := os.ReadFile(filepath.Join(physical, "blob.bin")); err != nil || !bytes.Equal(got, []byte{0, 7, 255}) {
		t.Fatalf("trusted configured root did not work: %x %v", got, err)
	}
}

func TestIncomingWindowsTextIsPortableWithoutChangingBinaryAssets(t *testing.T) {
	m := archiveTestManager(t)
	windows := []byte("\xef\xbb\xbfFIRST=1\r\nSECOND=2\r\n")
	plain := []byte("FIRST=1\nSECOND=2\n")
	for _, name := range []string{"nfqws2.conf", "configs/windows.conf", "scripts/windows.sh", "lists/windows.list"} {
		putTestAsset(t, m, name, windows)
		if got := readTestAsset(t, m, name); !bytes.Equal(got, plain) {
			t.Fatalf("%s not normalized: %q", name, got)
		}
	}
	for _, name := range []string{"blobs/windows.bin", "lists/windows.list.gz", "lua/windows.lua"} {
		putTestAsset(t, m, name, windows)
		if got := readTestAsset(t, m, name); !bytes.Equal(got, windows) {
			t.Fatalf("%s was unexpectedly normalized: %q", name, got)
		}
	}
	if err := m.SaveAsset("lists/not-utf8.list", []byte{0xff, 0xfe, 0x61}, false); err == nil {
		t.Fatal("accepted non-UTF8 text list")
	}
	data := testZIP(t, map[string][]byte{"nfqws2.conf": windows, "scripts/windows.sh": windows, "lists/windows.list": windows, "blobs/windows.bin": windows, "lists/windows.list.gz": windows})
	other := archiveTestManager(t)
	p, err := other.StrategyPreview(data, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(p.Warnings, " "), "BOM") {
		t.Fatalf("missing normalization notice: %v", p.Warnings)
	}
	if _, err = other.StrategyImport(data, "", ArchiveImportOptions{Digest: p.Digest}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"nfqws2.conf", "scripts/windows.sh", "lists/windows.list"} {
		if !bytes.Equal(readTestAsset(t, other, name), plain) {
			t.Fatalf("import %s was not normalized", name)
		}
	}
	for _, name := range []string{"blobs/windows.bin", "lists/windows.list.gz"} {
		if !bytes.Equal(readTestAsset(t, other, name), windows) {
			t.Fatalf("binary %s changed", name)
		}
	}
	bad := testZIP(t, map[string][]byte{"nfqws2.conf": plain, "lists/non-utf8.list": {0xff, 0xfe}})
	if _, err = other.StrategyPreview(bad, ""); err == nil {
		t.Fatal("archive with a non-UTF8 text list accepted")
	}
}

func TestExportPreservesExistingWindowsBytes(t *testing.T) {
	m := archiveTestManager(t)
	putTestAsset(t, m, "nfqws2.conf", []byte("X=1\n"))
	original := []byte("\xef\xbb\xbfX=1\r\n")
	if err := os.WriteFile(m.cfg.Nfqws2Conf, original, 0644); err != nil {
		t.Fatal(err)
	}
	data, err := m.StrategyExport()
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	f, err := zr.Open("nfqws2.conf")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var got bytes.Buffer
	if _, err = got.ReadFrom(f); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), original) {
		t.Fatalf("export changed bytes: %q", got.Bytes())
	}
}

func TestStrategyKeepImportsMissingPersonalLists(t *testing.T) {
	m := archiveTestManager(t)
	putTestAsset(t, m, "nfqws2.conf", []byte("OLD=1\n"))
	data := testZIP(t, map[string][]byte{"nfqws2.conf": []byte("NEW=1\n"), "lists/user.list": []byte("user.test\n"), "lists/auto.list": []byte("auto.test\n")})
	p, err := m.StrategyPreview(data, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(p.Warnings, " "), "отсутствующие") {
		t.Fatalf("missing keep semantics warning: %v", p.Warnings)
	}
	result, err := m.StrategyImport(data, "", ArchiveImportOptions{Digest: p.Digest, Overwrite: true, Lists: "keep"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Kept) != 0 || len(result.Imported) != 3 {
		t.Fatalf("result: %+v", result)
	}
	if string(readTestAsset(t, m, "lists/user.list")) != "user.test\n" || string(readTestAsset(t, m, "lists/auto.list")) != "auto.test\n" {
		t.Fatal("missing personal lists were not imported")
	}
}

func TestStrategyKeepProtectsAlternateCompressedList(t *testing.T) {
	for _, compressedCurrent := range []bool{false, true} {
		t.Run(map[bool]string{false: "current plain", true: "current gzip"}[compressedCurrent], func(t *testing.T) {
			m := archiveTestManager(t)
			putTestAsset(t, m, "nfqws2.conf", []byte("OLD=1\n"))
			current, incoming := "lists/user.list", "lists/user.list.gz"
			if compressedCurrent {
				current, incoming = incoming, current
			}
			putTestAsset(t, m, current, []byte("own.test\n"))
			data := testZIP(t, map[string][]byte{"nfqws2.conf": []byte("NEW=1\n"), incoming: []byte("incoming.test\n")})
			p, err := m.StrategyPreview(data, "")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(strings.Join(p.Warnings, " "), "другом формате") {
				t.Fatalf("missing alternate format notice: %v", p.Warnings)
			}
			result, err := m.StrategyImport(data, "", ArchiveImportOptions{Digest: p.Digest, Overwrite: true, Lists: "keep"})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Kept) != 1 || result.Kept[0] != incoming {
				t.Fatalf("did not keep alternate list: %+v", result)
			}
			if string(readTestAsset(t, m, current)) != "own.test\n" {
				t.Fatal("own alternate format list changed")
			}
			if _, err = m.AssetBytes(incoming); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("incoming file shadows existing personal list: %v", err)
			}
		})
	}
}
