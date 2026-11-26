package app

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"nfqws2strategy/internal/tools/geo"
	"nfqws2strategy/internal/tools/modules"
	"nfqws2strategy/internal/tools/store"
)

func geoTestApp(t *testing.T) *App {
	t.Helper()
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &App{store: st}
}

func TestGeoPanelFileAndList(t *testing.T) {
	if modules.Compact {
		source := os.Getenv("NFQWS2_GEO_BIN")
		if source == "" {
			t.Skip("set NFQWS2_GEO_BIN to run panel integration with the Rust helper")
		}
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		root := t.TempDir()
		t.Setenv("N2S_MODULE_DIR", root)
		if err := os.Mkdir(filepath.Join(root, "geo"), 0755); err != nil {
			t.Fatal(err)
		}
		name := "nfqws2-geo"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		if err := os.WriteFile(filepath.Join(root, "geo", name), data, 0755); err != nil {
			t.Fatal(err)
		}
	}
	a := geoTestApp(t)
	if err := a.SaveGeoFile("hosts.txt", "text", []byte(" # comment\nexample.test\n192.0.2.0/24\nexample.test\n")); err != nil {
		t.Fatal(err)
	}
	files := a.GeoFiles()
	if len(files) != 1 || !reflect.DeepEqual(files[0].Categories, []geo.Category{{Name: "all", Count: 3}}) {
		t.Fatalf("files: %+v", files)
	}
	got, err := a.ResolveGeo("hosts.txt", "ALL", 2)
	if err != nil || !reflect.DeepEqual(got, []string{"example.test", "192.0.2.0/24"}) {
		t.Fatalf("limited resolution: %v, %v", got, err)
	}
	if _, err := a.ResolveGeo("hosts.txt", "missing", 0); err == nil {
		t.Fatal("missing category accepted")
	}
	l, err := a.ImportGeo("hosts.txt", "All", 0, "", "geo test")
	if err != nil || !reflect.DeepEqual(l.Domains, []string{"example.test"}) || !reflect.DeepEqual(l.IPs, []string{"192.0.2.0/24"}) {
		t.Fatalf("import: %+v, %v", l, err)
	}
}

func TestGeoFileNames(t *testing.T) {
	a := geoTestApp(t)
	for _, name := range []string{"", ".", "..", "../other", "..\\other", "C:file", "a/b.txt", "nul\x00.dat"} {
		if validGeoName(name) {
			t.Fatalf("accepted filename %q", name)
		}
		if a.SaveGeoFile(name, "text", nil) == nil || a.DeleteGeoFile(name) == nil {
			t.Fatalf("accepted file operation on %q", name)
		}
		if _, err := a.ResolveGeo(name, "all", 0); err == nil {
			t.Fatalf("accepted file lookup for %q", name)
		}
	}
}
