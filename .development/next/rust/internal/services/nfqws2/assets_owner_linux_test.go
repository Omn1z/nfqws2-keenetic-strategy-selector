//go:build linux

package nfqws2

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestAssetReplacementPreservesEngineOwnership(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("ownership change requires root in the isolated test directory")
	}
	m := archiveTestManager(t)
	putTestAsset(t, m, "nfqws2.conf", []byte("USER=nobody\n"))
	putTestAsset(t, m, "lists/auto.list", []byte("old.test\n"))
	file := filepath.Join(m.assetRoots()["list"], "auto.list")
	if err := os.Chown(file, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0600); err != nil {
		t.Fatal(err)
	}
	check := func() {
		st, err := os.Stat(file)
		if err != nil {
			t.Fatal(err)
		}
		sys := st.Sys().(*syscall.Stat_t)
		if sys.Uid != 65534 || sys.Gid != 65534 || st.Mode().Perm() != 0600 {
			t.Fatalf("ownership/mode changed: uid=%d gid=%d mode=%o", sys.Uid, sys.Gid, st.Mode().Perm())
		}
	}
	putTestAsset(t, m, "lists/auto.list", []byte("explorer.test\n"))
	check()
	if err := m.Save("list", "auto.list", "editor.test\n"); err != nil {
		t.Fatal(err)
	}
	check()
	data := testZIP(t, map[string][]byte{"nfqws2.conf": []byte("USER=nobody\n"), "lists/auto.list": []byte("archive.test\n")})
	p, err := m.StrategyPreview(data, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.StrategyImport(data, "", ArchiveImportOptions{Digest: p.Digest, Overwrite: true, Lists: "replace"}); err != nil {
		t.Fatal(err)
	}
	check()
}

func TestNewAutolistOwnershipForUploadsAndArchives(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("ownership test requires root in isolated directory")
	}
	m := archiveTestManager(t)
	putTestAsset(t, m, "nfqws2.conf", []byte("USER=65534:65533\n"))
	putTestAsset(t, m, "lists/auto.list", []byte("uploaded.test\n"))
	check := func(name string) {
		st, err := os.Stat(filepath.Join(m.assetRoots()["list"], name))
		if err != nil {
			t.Fatal(err)
		}
		owner := st.Sys().(*syscall.Stat_t)
		if owner.Uid != 65534 || owner.Gid != 65533 {
			t.Fatalf("new %s has wrong owner: %d:%d", name, owner.Uid, owner.Gid)
		}
	}
	check("auto.list")
	data := testZIP(t, map[string][]byte{"nfqws2.conf": []byte("\xef\xbb\xbfUSER='65534:65533'\r\n"), "lists/autolist.txt": []byte("imported.test\r\n")})
	p, err := m.StrategyPreview(data, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.StrategyImport(data, "", ArchiveImportOptions{Digest: p.Digest, Overwrite: true, Lists: "replace"}); err != nil {
		t.Fatal(err)
	}
	check("autolist.txt")
	if err = m.DeleteAsset("lists/auto.list"); err != nil {
		t.Fatal(err)
	}
	if err = m.Create("list", "auto.list"); err != nil {
		t.Fatal(err)
	}
	check("auto.list")
	if err = m.DeleteAsset("lists/auto.list"); err != nil {
		t.Fatal(err)
	}
	if err = m.Save("list", "auto.list", "legacy.test\n"); err != nil {
		t.Fatal(err)
	}
	check("auto.list")
	if err = m.DeleteAsset("lists/auto.list"); err != nil {
		t.Fatal(err)
	}
	missingData := testZIP(t, map[string][]byte{"nfqws2.conf": []byte("USER=65534:65533\n"), "lists/auto.list": []byte("new-kept.test\n")})
	p, err = m.StrategyPreview(missingData, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.StrategyImport(missingData, "", ArchiveImportOptions{Digest: p.Digest, Overwrite: true, Lists: "keep"}); err != nil {
		t.Fatal(err)
	}
	check("auto.list")
}
