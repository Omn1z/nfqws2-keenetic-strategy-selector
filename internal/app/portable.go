package app

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"nfqws2strategy/internal/services/strategy/core/catalog"
)

const maxBlobBytes = 8 << 20

// reBlobPath matches a blob DEFINITION carrying a file path: --blob=NAME:@PATH.
var reBlobPath = regexp.MustCompile(`--blob=([^:\s]+):@(\S+)`)

// ExportBlobsZip writes a zip of blobs to w. With no names it exports all custom
// blobs; with names it exports exactly those (custom or system, resolved like a
// run does), so system blobs can be exported too.
func (a *App) ExportBlobsZip(w io.Writer, names []string) error {
	zw := zip.NewWriter(w)
	add := func(zipName, path string) {
		if data, err := os.ReadFile(path); err == nil {
			if f, e := zw.Create(zipName); e == nil {
				_, _ = f.Write(data)
			}
		}
	}
	if len(names) == 0 {
		blobNames, _ := a.store.ListFiles("blobs")
		for _, n := range blobNames {
			add(n, filepath.Join(a.blobsDir(), n))
		}
	} else {
		for _, n := range names {
			base := filepath.Base(n)
			if _, path, ok := a.resolveBlob(base); ok {
				add(base, path)
			}
		}
	}
	return zw.Close()
}

// ImportBlobsZip extracts every file in the zip as a custom blob.
func (a *App) ImportBlobsZip(data []byte) (int, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return 0, fmt.Errorf("not a valid zip")
	}
	count := 0
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		b, err := readZipFile(f)
		if err != nil {
			continue
		}
		if _, err := a.SaveBlob(filepath.Base(f.Name), b); err == nil {
			count++
		}
	}
	return count, nil
}

// ExportStrategyZip writes a shareable zip: strategy.json plus any custom blob
// files the strategy references. Blob paths in the args are rewritten to bare
// filenames so they re-resolve on import.
func (a *App) ExportStrategyZip(name, l7, args string, w io.Writer) error {
	zw := zip.NewWriter(w)
	portableArgs := reBlobPath.ReplaceAllStringFunc(args, func(m string) string {
		sub := reBlobPath.FindStringSubmatch(m)
		blobName, path := sub[1], sub[2]
		base := filepath.Base(path)
		if data, err := os.ReadFile(path); err == nil {
			if f, e := zw.Create(base); e == nil {
				_, _ = f.Write(data)
			}
		}
		return "--blob=" + blobName + ":@" + base
	})
	meta, _ := json.Marshal(map[string]string{"name": name, "l7": l7, "args": portableArgs})
	if f, err := zw.Create("strategy.json"); err == nil {
		_, _ = f.Write(meta)
	}
	return zw.Close()
}

// ImportStrategyZip restores a shared strategy: it saves the bundled blobs as
// custom blobs and adds the strategy with its blob paths pointed at the local
// blob directory.
func (a *App) ImportStrategyZip(data []byte) (catalog.Strategy, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return catalog.Strategy{}, fmt.Errorf("not a valid zip")
	}
	var meta struct {
		Name string `json:"name"`
		L7   string `json:"l7"`
		Args string `json:"args"`
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		b, err := readZipFile(f)
		if err != nil {
			continue
		}
		if filepath.Base(f.Name) == "strategy.json" {
			_ = json.Unmarshal(b, &meta)
			continue
		}
		_, _ = a.SaveBlob(filepath.Base(f.Name), b)
	}
	if strings.TrimSpace(meta.Args) == "" {
		return catalog.Strategy{}, fmt.Errorf("strategy.json missing or empty")
	}
	// Re-point bare blob filenames to this install's blob directory.
	args := reBlobPath.ReplaceAllStringFunc(meta.Args, func(m string) string {
		sub := reBlobPath.FindStringSubmatch(m)
		blobName, path := sub[1], sub[2]
		if !strings.ContainsAny(path, "/\\") {
			path = filepath.Join(a.blobsDir(), filepath.Base(path))
		}
		return "--blob=" + blobName + ":@" + path
	})
	return a.SaveCustomStrategy(catalog.Strategy{Name: meta.Name, L7: meta.L7, ArgLine: args, Source: "custom"})
}

func readZipFile(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, maxBlobBytes))
}
