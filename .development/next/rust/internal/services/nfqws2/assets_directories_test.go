package nfqws2

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestExplorerLongDirectoryDoesNotHideExportableFile(t *testing.T) {
	m := archiveTestManager(t)
	putTestAsset(t, m, "nfqws2.conf", []byte("NFQWS_ARGS=''\n"))
	directory := "lists/" + strings.Repeat("a", 170) + "/" + strings.Repeat("b", 170) + "/" + strings.Repeat("c", 160)
	name := directory + "/x"
	putTestAsset(t, m, name, []byte("example.org\n"))
	assets, err := m.Assets()
	if err != nil || len(assets.Files) != 2 || assets.Files[0].Path != name {
		t.Fatalf("valid long path missing from explorer: %+v, %v", assets, err)
	}
	data, err := m.StrategyExport()
	if err != nil {
		t.Fatal(err)
	}
	preview, err := archiveTestManager(t).StrategyPreview(data, "")
	if err != nil || len(preview.Files) != 2 || preview.Files[0].Path != name {
		t.Fatalf("valid long path missing from export: %+v, %v", preview, err)
	}
}

func TestExplorerDirectoriesPersistAfterLastFileDeletion(t *testing.T) {
	m := archiveTestManager(t)
	putTestAsset(t, m, "lists/strategy/nested/example.txt", []byte("example.org\n"))
	putTestAsset(t, m, "blobs/strategy/tls.bin", []byte{0, 1, 2})
	putTestAsset(t, m, "lua/strategy/example.lua", []byte("return true\n"))
	if err := m.DeleteAsset("lists/strategy/nested/example.txt"); err != nil {
		t.Fatal(err)
	}
	assets, err := m.Assets()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"blobs/strategy", "lists/strategy", "lists/strategy/nested", "lua/strategy"}
	if !reflect.DeepEqual(assets.Directories, want) {
		t.Fatalf("directories = %v, want %v", assets.Directories, want)
	}
	if len(assets.Files) != 2 {
		t.Fatalf("deleted file remains listed: %+v", assets.Files)
	}
	// The empty folder stays usable as an upload destination.
	if err := m.SaveAsset("lists/strategy/nested/new.txt", []byte("example.net\n"), false); err != nil {
		t.Fatal(err)
	}
}

func TestExplorerDirectoriesExcludeUnsupportedPaths(t *testing.T) {
	m := archiveTestManager(t)
	root := m.assetRoots()["list"]
	for _, relative := range []string{"visible", ".hidden/nested", "has space/nested", "a/b/c/d/e/f/g/h/i"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(relative)), 0755); err != nil {
			t.Fatal(err)
		}
	}
	assets, err := m.Assets()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"lists/a", "lists/a/b", "lists/a/b/c", "lists/a/b/c/d", "lists/a/b/c/d/e", "lists/a/b/c/d/e/f", "lists/a/b/c/d/e/f/g", "lists/a/b/c/d/e/f/g/h", "lists/visible"}
	if !reflect.DeepEqual(assets.Directories, want) {
		t.Fatalf("unsupported directory leaked into navigation: %v", assets.Directories)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Logf("directory symlink unavailable: %v", err)
		return
	}
	assets, err = m.Assets()
	if err != nil || !reflect.DeepEqual(assets.Directories, want) {
		t.Fatalf("symlink leaked into navigation: %v (%v)", assets.Directories, err)
	}
}
