package nfqws2

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestExplorerDirectoryCapacityPreservesImportableStrategy(t *testing.T) {
	m := archiveTestManager(t)
	const branches = 513
	const depth = 8
	want := map[string][]byte{"nfqws2.conf": []byte("NFQWS_ARGS=''\n")}
	for i := 0; i < branches; i++ {
		// Every branch owns eight directories: paths accepted by the archive
		// importer can exceed 4096 directories while using only 514 files.
		name := fmt.Sprintf("lists/branch-%03d/a/b/c/d/e/f/g/domains.list", i)
		want[name] = []byte(fmt.Sprintf("domain-%03d.example\n", i))
	}
	for name, data := range want {
		loc, err := m.assetLocation(name)
		if err != nil {
			t.Fatalf("fixture must be importable (%s): %v", name, err)
		}
		filename := filepath.Join(loc.root, loc.name)
		if err = os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
			t.Fatal(err)
		}
		// These are fresh, private test files; skip the production writer's
		// fsync per fixture so this capacity regression stays inexpensive.
		if err = os.WriteFile(filename, data, 0644); err != nil {
			t.Fatal(err)
		}
	}

	assets, err := m.Assets()
	if err != nil {
		t.Fatalf("importable strategy cannot be listed: %v", err)
	}
	if len(assets.Directories) != branches*depth || len(assets.Files) != len(want) {
		t.Fatalf("listing lost entries: %d directories, %d files; want %d, %d", len(assets.Directories), len(assets.Files), branches*depth, len(want))
	}
	for _, file := range assets.Files {
		if _, ok := want[file.Path]; !ok {
			t.Fatalf("unexpected listing entry: %s", file.Path)
		}
	}

	data, err := m.StrategyExport()
	if err != nil {
		t.Fatalf("importable strategy cannot be exported: %v", err)
	}
	files, err := m.decodeStrategyArchive(data)
	if err != nil {
		t.Fatalf("export no longer satisfies import limits: %v", err)
	}
	if len(files) != len(want) {
		t.Fatalf("export contains %d files, want %d", len(files), len(want))
	}
	for name, expected := range want {
		if actual, ok := files[name]; !ok || !bytes.Equal(actual.data, expected) {
			t.Fatalf("file missing or changed in export: %s", name)
		}
	}
}
