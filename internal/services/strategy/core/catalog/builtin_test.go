package catalog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"nfqws2strategy/internal/tools/modules"
)

func TestBuiltinCatalogMatchesPackageAndPreservesOrder(t *testing.T) {
	root := t.TempDir()
	t.Setenv("N2S_MODULE_DIR", root)
	data, err := os.ReadFile("builtin.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "strategies"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "strategies", "catalog.json"), data, 0644); err != nil {
		t.Fatal(err)
	}
	var want []Strategy
	if err := json.Unmarshal(data, &want); err != nil || len(want) != 8 {
		t.Fatalf("catalog size = %d, err = %v", len(want), err)
	}
	got, err := Builtin()
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("loaded catalog differs from packaged catalog: %v", err)
	}
	got[0].Name = "modified by caller"
	got, err = Builtin()
	if err != nil || !slices.Equal(got, want) {
		t.Fatal("callers share mutable catalog entries")
	}
}

func TestOptionalCatalogInstallationAndRemovalDuringServiceLifetime(t *testing.T) {
	if !modules.Compact {
		t.Skip("the full build embeds the catalog")
	}
	root := t.TempDir()
	t.Setenv("N2S_MODULE_DIR", root)
	dir := filepath.Join(root, "strategies")
	path := filepath.Join(dir, "catalog.json")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	check := func(n int, wantErr bool) {
		t.Helper()
		got, err := Builtin()
		if (err != nil) != wantErr || len(got) != n || (!wantErr && got == nil) {
			t.Fatalf("got %d entries, err %v", len(got), err)
		}
	}
	check(0, false)
	data, err := os.ReadFile("builtin.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"[", "null", "[]", "[{}]", strings.Replace(string(data), `"builtin"`, `"custom"`, 1), strings.Replace(string(data), `"tls-fake-ack-multisplit"`, `"tls-fake-multisplit-google"`, 1), strings.Repeat(" ", (64<<10)+1)} {
		if err := os.WriteFile(path, []byte(invalid), 0644); err != nil {
			t.Fatal(err)
		}
		check(0, true)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	check(8, false)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	check(0, false)
}
