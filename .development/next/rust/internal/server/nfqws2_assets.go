package server

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path"

	"nfqws2strategy/internal/services/nfqws2"
)

func (s *Server) nfqws2AssetRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/nfqws2/assets", s.nfqws2Assets)
	m.HandleFunc("GET /api/nfqws2/assets/file", s.nfqws2AssetDownload)
	m.HandleFunc("POST /api/nfqws2/assets/file", s.nfqws2AssetUpload)
	m.HandleFunc("DELETE /api/nfqws2/assets/file", s.nfqws2AssetDelete)
	m.HandleFunc("GET /api/nfqws2/strategy/export", s.nfqws2StrategyExport)
	m.HandleFunc("POST /api/nfqws2/strategy/preview", s.nfqws2StrategyPreview)
	m.HandleFunc("POST /api/nfqws2/strategy/import", s.nfqws2StrategyImport)
	m.HandleFunc("GET /api/nfqws2/strategy/snapshots", s.nfqws2StrategySnapshots)
	m.HandleFunc("POST /api/nfqws2/strategy/snapshots", s.nfqws2StrategySnapshotCreate)
	m.HandleFunc("GET /api/nfqws2/strategy/snapshot", s.nfqws2StrategySnapshotDownload)
	m.HandleFunc("DELETE /api/nfqws2/strategy/snapshot", s.nfqws2StrategySnapshotDelete)
}

func assetHTTPError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	if errors.Is(err, nfqws2.ErrAssetConflict) || errors.Is(err, nfqws2.ErrArchiveChanged) {
		status = http.StatusConflict
	}
	if errors.Is(err, os.ErrNotExist) {
		status = http.StatusNotFound
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		status = http.StatusRequestEntityTooLarge
	}
	httpErr(w, status, err)
}

func (s *Server) nfqws2Assets(w http.ResponseWriter, r *http.Request) {
	data, err := s.app.Nfqws2Assets()
	if err != nil {
		assetHTTPError(w, err)
		return
	}
	writeJSON(w, 200, data)
}
func serveAssetBytes(w http.ResponseWriter, name, contentType string, data []byte) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": path.Base(name)}))
	w.Write(data)
}
func (s *Server) nfqws2AssetDownload(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("path")
	data, err := s.app.Nfqws2AssetBytes(name)
	if err != nil {
		assetHTTPError(w, err)
		return
	}
	serveAssetBytes(w, name, "application/octet-stream", data)
}
func parseAssetMultipart(w http.ResponseWriter, r *http.Request, limit int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit+(1<<20))
	return r.ParseMultipartForm(1 << 20)
}
func multipartFileBytes(r *http.Request, limit int64) ([]byte, error) {
	f, _, err := r.FormFile("file")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, &http.MaxBytesError{Limit: limit}
	}
	return data, nil
}
func (s *Server) nfqws2AssetUpload(w http.ResponseWriter, r *http.Request) {
	if err := parseAssetMultipart(w, r, nfqws2.AssetMaxBytes); err != nil {
		assetHTTPError(w, err)
		return
	}
	defer r.MultipartForm.RemoveAll()
	data, err := multipartFileBytes(r, nfqws2.AssetMaxBytes)
	if err != nil {
		assetHTTPError(w, err)
		return
	}
	name := r.FormValue("path")
	if err = s.app.Nfqws2SaveAsset(name, data, r.FormValue("overwrite") == "true"); err != nil {
		assetHTTPError(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"path": name, "status": "saved"})
}
func (s *Server) nfqws2AssetDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.app.Nfqws2DeleteAsset(r.URL.Query().Get("path")); err != nil {
		assetHTTPError(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "deleted"})
}
func (s *Server) nfqws2StrategyExport(w http.ResponseWriter, r *http.Request) {
	data, err := s.app.Nfqws2StrategyExport()
	if err != nil {
		assetHTTPError(w, err)
		return
	}
	serveAssetBytes(w, "nfqws2-strategy.zip", "application/zip", data)
}
func strategyArchiveInput(w http.ResponseWriter, r *http.Request) ([]byte, string, error) {
	if err := parseAssetMultipart(w, r, nfqws2.ArchiveMaxBytes); err != nil {
		return nil, "", err
	}
	id := r.FormValue("snapshot")
	if id != "" {
		if len(r.MultipartForm.File["file"]) > 0 {
			return nil, "", fmt.Errorf("выберите файл или снимок, не оба сразу")
		}
		return nil, id, nil
	}
	data, err := multipartFileBytes(r, nfqws2.ArchiveMaxBytes)
	return data, "", err
}
func (s *Server) nfqws2StrategyPreview(w http.ResponseWriter, r *http.Request) {
	data, id, err := strategyArchiveInput(w, r)
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	if err != nil {
		assetHTTPError(w, err)
		return
	}
	preview, err := s.app.Nfqws2StrategyPreview(data, id)
	if err != nil {
		assetHTTPError(w, err)
		return
	}
	writeJSON(w, 200, preview)
}
func (s *Server) nfqws2StrategyImport(w http.ResponseWriter, r *http.Request) {
	data, id, err := strategyArchiveInput(w, r)
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	if err != nil {
		assetHTTPError(w, err)
		return
	}
	opts := nfqws2.ArchiveImportOptions{Digest: r.FormValue("digest"), Overwrite: r.FormValue("overwrite") == "true", Lists: r.FormValue("lists")}
	result, err := s.app.Nfqws2StrategyImport(data, id, opts)
	if err != nil {
		assetHTTPError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) nfqws2StrategySnapshots(w http.ResponseWriter, r *http.Request) {
	items, err := s.app.Nfqws2StrategySnapshots()
	if err != nil {
		assetHTTPError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"snapshots": items})
}
func (s *Server) nfqws2StrategySnapshotCreate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if err := readJSON(r, &in); err != nil {
		assetHTTPError(w, err)
		return
	}
	item, err := s.app.Nfqws2StrategySnapshotCreate(in.Name)
	if err != nil {
		assetHTTPError(w, err)
		return
	}
	writeJSON(w, 200, item)
}
func (s *Server) nfqws2StrategySnapshotDownload(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	data, err := s.app.Nfqws2StrategySnapshotBytes(id)
	if err != nil {
		assetHTTPError(w, err)
		return
	}
	serveAssetBytes(w, id, "application/zip", data)
}
func (s *Server) nfqws2StrategySnapshotDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.app.Nfqws2StrategySnapshotDelete(r.URL.Query().Get("id")); err != nil {
		assetHTTPError(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "deleted"})
}
