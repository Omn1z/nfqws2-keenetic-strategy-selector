//go:build n2s_compact

package server

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompactPagePackages(t *testing.T) {
	root := t.TempDir()
	t.Setenv("N2S_MODULE_DIR", root)
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	_, _ = gz.Write([]byte("export default 42"))
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"runs", "blockcheck", "strategies", "geo"} {
		url := "/" + moduleAssets[id]
		get := func(url, encoding string) *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, url, nil)
			r.Header.Set("Accept-Encoding", encoding)
			(&Server{}).serveIndex(w, r)
			return w
		}
		if got := get(url, "").Code; got != 404 {
			t.Fatalf("%s before install: %d", id, got)
		}
		file := filepath.Join(root, strings.TrimPrefix(url, "/modules/")+".gz")
		if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, compressed.Bytes(), 0644); err != nil {
			t.Fatal(err)
		}
		for _, encoding := range []string{"gzip", "*", "identity", "gzip;q=0, *;q=1", ""} {
			w := get(url, encoding)
			if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/javascript") {
				t.Fatalf("%s: %d %v", url, w.Code, w.Header())
			}
			if encoding == "gzip" || encoding == "*" {
				if w.Header().Get("Content-Encoding") != "gzip" || !bytes.Equal(w.Body.Bytes(), compressed.Bytes()) {
					t.Fatal("gzip response differs")
				}
			} else if w.Body.String() != "export default 42" {
				t.Fatal("identity response differs")
			}
		}
		for _, other := range []string{"/modules/" + id + "/nfqws2-geo", url + ".gz", "/ui/missing.js", "/modules/unknown/file.js"} {
			if got := get(other, "").Code; got != 404 {
				t.Fatalf("%s: %d", other, got)
			}
		}
		if err := os.Remove(file); err != nil {
			t.Fatal(err)
		}
		if got := get(url, "").Code; got != 404 {
			t.Fatalf("%s after removal: %d", url, got)
		}
	}
}
