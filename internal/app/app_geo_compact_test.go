//go:build n2s_compact

package app

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompactGeoAutoHonorsHotInstall(t *testing.T) {
	t.Setenv("N2S_MODULE_DIR", t.TempDir())
	var requests int
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	http.DefaultTransport = selfUpdateRoundTripper(func(r *http.Request) (*http.Response, error) {
		requests++
		body := io.NopCloser(bytes.NewReader([]byte{10, 3, 10, 1, 'A'}))
		return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
	})
	a := geoTestApp(t)
	saved := &GeoAutoConfig{Enabled: true, GeoSiteURL: "https://example.test/site.dat", GeoIPURL: "https://example.test/ip.dat"}
	if err := a.SetGeoAuto(saved); err != nil {
		t.Fatal(err)
	}
	a.checkGeoAuto()
	if _, err := a.FetchGeoNow(); err == nil {
		t.Fatal("manual fetch available without Geo")
	}
	if requests != 0 || *a.GeoAuto() != *saved {
		t.Fatal("fetch or settings mutation without Geo")
	}
	path := geoHelper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0755); err != nil {
		t.Fatal(err)
	}
	a.checkGeoAuto()
	a.checkGeoAuto()
	if requests != 2 || a.GeoAuto().LastGeoIPLen != 5 {
		t.Fatalf("requests=%d config=%+v", requests, a.GeoAuto())
	}
}

func TestGeoModuleArrayRejectsPartialResults(t *testing.T) {
	for _, input := range []string{"{}", "[1]", "[\"example.test\"", "[] []", "[]garbage"} {
		if items, err := readGeoArray[string](strings.NewReader(input)); err == nil || items != nil {
			t.Fatalf("accepted %q: %+v %v", input, items, err)
		}
	}
}
