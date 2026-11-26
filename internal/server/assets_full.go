//go:build !n2s_compact

package server

import (
	"compress/gzip"
	_ "embed"
	"net/http"
	"strings"
)

//go:embed web/index.html
var fullIndex []byte

func servePanelAsset(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzipWriterPool.Get().(*gzip.Writer)
		gz.Reset(w)
		defer func() { _ = gz.Close(); gzipWriterPool.Put(gz) }()
		_, _ = gz.Write(fullIndex)
		return
	}
	_, _ = w.Write(fullIndex)
}
