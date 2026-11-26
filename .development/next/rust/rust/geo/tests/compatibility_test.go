package geocompat_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"nfqws2strategy/internal/tools/geo"
)

// Set NFQWS2_GEO_BIN to the built Rust executable for differential checks.
func TestRustMatchesGo(t *testing.T) {
	bin := os.Getenv("NFQWS2_GEO_BIN")
	if bin == "" {
		t.Skip("set NFQWS2_GEO_BIN to the built nfqws2-geo executable")
	}
	dir := t.TempDir()
	textPath := filepath.Join(dir, "hosts.txt")
	if err := os.WriteFile(textPath, []byte(" # comment\nEXAMPLE.org\n::1\nEXAMPLE.org\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// Tiny wire-format fixtures exercise both .dat formats on clean CI runners.
	sitePath := filepath.Join(dir, "geosite.dat")
	ipPath := filepath.Join(dir, "geoip.dat")
	for path, content := range map[string]string{
		sitePath: "\x0a\x0b\x0a\x02RU\x12\x05\x12\x03abc",
		ipPath:   "\x0a\x0e\x0a\x02RU\x12\x08\x0a\x04\xc0\x00\x02\x00\x10\x18",
	} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ kind, file, category string }{
		{"text", textPath, "all"},
		{"geosite", sitePath, "ru"},
		{"geoip", ipPath, "ru"},
		{"geosite", "../../../dev/testdata/geosite.dat", "google"},
		{"geoip", "../../../dev/testdata/geoip.dat", "cn"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			data, err := os.ReadFile(tc.file)
			if os.IsNotExist(err) && tc.kind != "text" {
				t.Skip("local real database fixture unavailable")
			}
			if err != nil {
				t.Fatal(err)
			}
			parsed := geo.Parse(tc.kind, data)
			var categories []geo.Category
			runJSON(t, bin, &categories, "list", tc.kind, tc.file)
			if !reflect.DeepEqual(categories, geo.Categories(parsed)) {
				t.Fatalf("category names or counts differ (Rust %d, Go %d)", len(categories), len(parsed))
			}
			var items []string
			runJSON(t, bin, &items, "extract", tc.kind, tc.file, tc.category)
			expected := parsed[tc.category]
			if !reflect.DeepEqual(items, expected) {
				t.Fatalf("entries or ordering differ (Rust %d, Go %d)", len(items), len(expected))
			}
			t.Logf("matched %d categories and all %d entries from %s", len(parsed), len(expected), tc.category)
		})
	}
}

func runJSON(t *testing.T, bin string, dest any, args ...string) {
	t.Helper()
	output, err := exec.Command(bin, args...).Output()
	if err != nil {
		t.Fatalf("running geo helper: %v", err)
	}
	if err := json.Unmarshal(output, dest); err != nil {
		t.Fatalf("reading geo JSON: %v", err)
	}
}
