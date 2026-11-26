//go:build n2s_compact

package server

import (
	"compress/gzip"
	"embed"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"nfqws2strategy/internal/tools/modules"
)

//go:embed compactweb
var compactAssets embed.FS

// The build manifest pins imports to this panel build; the directory also
// contains executables that must never be exposed through the HTTP handler.
var moduleAssets = func() map[string]string {
	raw, err := compactAssets.ReadFile("compactweb/modules.json")
	if err != nil {
		panic(err)
	}
	var files map[string]string
	if err := json.Unmarshal(raw, &files); err != nil {
		panic(err)
	}
	return files
}()

func servePanelAsset(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/")
	var file fs.File
	var err error
	switch {
	case strings.HasPrefix(name, "modules/"):
		id, _, _ := strings.Cut(strings.TrimPrefix(name, "modules/"), "/")
		if moduleAssets[id] != name {
			http.NotFound(w, r)
			return
		}
		file, err = os.Open(filepath.Join(modules.Dir(), filepath.FromSlash(strings.TrimPrefix(name, "modules/")+".gz")))
	case strings.HasPrefix(name, "ui/"):
		if !fs.ValidPath(name) || !(strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".css")) {
			http.NotFound(w, r)
			return
		}
		file, err = compactAssets.Open("compactweb/" + name + ".gz")
	default:
		name = "index.html"
		file, err = compactAssets.Open("compactweb/index.html.gz")
	}
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	w.Header().Set("Vary", "Accept-Encoding")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	switch path.Ext(name) {
	case ".js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	case ".css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
	}
	if acceptsGzip(r.Header.Get("Accept-Encoding")) {
		w.Header().Set("Content-Encoding", "gzip")
		if st, err := file.Stat(); err == nil {
			w.Header().Set("Content-Length", strconv.FormatInt(st.Size(), 10))
		}
		if r.Method != http.MethodHead {
			_, _ = io.Copy(w, file)
		}
		return
	}
	gz, err := gzip.NewReader(file)
	if err != nil {
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "invalid panel asset", http.StatusInternalServerError)
		return
	}
	defer gz.Close()
	if r.Method != http.MethodHead {
		_, _ = io.Copy(w, gz)
	}
}

func acceptsGzip(header string) bool {
	star := false
	for _, part := range strings.Split(header, ",") {
		encoding, param, _ := strings.Cut(strings.TrimSpace(part), ";")
		q := 1.0
		if k, v, ok := strings.Cut(strings.TrimSpace(param), "="); ok && strings.EqualFold(strings.TrimSpace(k), "q") {
			q, _ = strconv.ParseFloat(strings.TrimSpace(v), 64)
		}
		switch strings.ToLower(strings.TrimSpace(encoding)) {
		case "gzip":
			return q > 0
		case "*":
			star = q > 0
		}
	}
	return star
}
