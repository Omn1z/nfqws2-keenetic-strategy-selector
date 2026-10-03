package nfqws2

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestExplorerModificationTimesComeFromEachFilesystemEntry(t *testing.T) {
	m := archiveTestManager(t)
	for _, name := range []string{"nfqws2.conf", "configs/other.conf", "scripts/custom.sh", "lists/nested/example.txt", "blobs/example.bin", "lua/example.lua"} {
		putTestAsset(t, m, name, []byte("example\n"))
	}
	roots := m.assetRoots()
	if err := os.MkdirAll(filepath.Join(roots["list"], "empty"), 0755); err != nil {
		t.Fatal(err)
	}

	// Set the child's mtime newer than its parent: a folder must retain its
	// own stat time, rather than inherit the maximum of descendants.
	want := map[string]time.Time{}
	paths := map[string]string{
		"nfqws2.conf":              m.cfg.Nfqws2Conf,
		"configs/other.conf":       filepath.Join(roots["conf"], "other.conf"),
		"scripts/custom.sh":        filepath.Join(roots["script"], "custom.sh"),
		"lists/nested/example.txt": filepath.Join(roots["list"], "nested", "example.txt"),
		"blobs/example.bin":        filepath.Join(roots["blob"], "example.bin"),
		"lua/example.lua":          filepath.Join(roots["lua"], "example.lua"),
		"lists/nested":             filepath.Join(roots["list"], "nested"),
		"lists/empty":              filepath.Join(roots["list"], "empty"),
		"configs":                  roots["conf"],
		"lists":                    roots["list"],
		"blobs":                    roots["blob"],
		"lua":                      roots["lua"],
	}
	for name, path := range paths {
		stamp := time.Date(2024, 7, 6, 8, 9, 10, 123456700, time.FixedZone("source", 3*3600))
		if name == "lists/nested/example.txt" {
			stamp = stamp.Add(24 * time.Hour)
		}
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			t.Fatal(err)
		}
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		// Compare with the filesystem result, which may round nanoseconds.
		want[name] = st.ModTime()
	}
	want["scripts"] = want["configs"]
	assets, err := m.Assets()
	if err != nil {
		t.Fatal(err)
	}
	if len(assets.Files) != 6 || len(assets.DirectoryModified) != 7 {
		t.Fatalf("missing file or directory metadata: %+v", assets)
	}
	for _, file := range assets.Files {
		if !file.ModifiedAt.Equal(want[file.Path]) || file.ModifiedAt.Location() != time.UTC {
			t.Errorf("%s time = %v, want %v in UTC", file.Path, file.ModifiedAt, want[file.Path])
		}
	}
	for name, stamp := range assets.DirectoryModified {
		if !stamp.Equal(want[name]) || stamp.Location() != time.UTC {
			t.Errorf("directory %s time = %v, want %v in UTC", name, stamp, want[name])
		}
	}
	if !reflect.DeepEqual(assets.Directories, []string{"lists/empty", "lists/nested"}) {
		t.Fatalf("legacy directory list changed: %v", assets.Directories)
	}
	encoded, err := json.Marshal(assets)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Files []struct {
			Path       string `json:"path"`
			ModifiedAt string `json:"modified_at"`
		} `json:"files"`
		DirectoryModified map[string]string `json:"directory_modified"`
	}
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatal(err)
	}
	for _, file := range payload.Files {
		stamp, err := time.Parse(time.RFC3339Nano, file.ModifiedAt)
		if err != nil || !stamp.Equal(want[file.Path]) {
			t.Fatalf("invalid JSON file timestamp %q: %v", file.ModifiedAt, err)
		}
	}
	if payload.DirectoryModified["lists/nested"] != assets.DirectoryModified["lists/nested"].Format(time.RFC3339Nano) {
		t.Fatal("directory timestamp missing from JSON")
	}
}

func TestExplorerMissingRootsDoNotInventModificationTimes(t *testing.T) {
	m := archiveTestManager(t)
	assets, err := m.Assets()
	if err != nil || len(assets.DirectoryModified) != 0 || len(assets.Files) != 0 {
		t.Fatalf("missing roots have synthetic metadata: %+v, %v", assets, err)
	}
	putTestAsset(t, m, "nfqws2.conf", []byte("NFQWS_ARGS=''\n"))
	assets, err = m.Assets()
	if err != nil {
		t.Fatal(err)
	}
	if len(assets.DirectoryModified) != 2 || assets.DirectoryModified["configs"].IsZero() || !assets.DirectoryModified["scripts"].Equal(assets.DirectoryModified["configs"]) {
		t.Fatalf("virtual sections must share their existing physical root timestamp: %+v", assets.DirectoryModified)
	}
}
