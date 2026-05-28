// Package server exposes the REST API and the embedded web UI.
package server

import (
	"embed"
	"encoding/json"
	"io"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"

	"nfqws2strategy/internal/app"
	"nfqws2strategy/internal/catalog"
)

//go:embed all:web
var webAssets embed.FS

type Server struct {
	app *app.App
	mux *http.ServeMux
}

func New(a *app.App) *Server {
	s := &Server{app: a, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler { return logging(s.mux) }

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /api/config", s.getConfig)

	m.HandleFunc("GET /api/strategies", s.getStrategies)
	m.HandleFunc("POST /api/strategies", s.saveStrategy)
	m.HandleFunc("DELETE /api/strategies/{id}", s.deleteStrategy)

	m.HandleFunc("GET /api/lists", s.getLists)
	m.HandleFunc("POST /api/lists", s.saveList)
	m.HandleFunc("GET /api/lists/{id}", s.getList)
	m.HandleFunc("DELETE /api/lists/{id}", s.deleteList)

	m.HandleFunc("GET /api/blobs", s.getBlobs)
	m.HandleFunc("POST /api/blobs", s.uploadBlob)

	m.HandleFunc("POST /api/runs", s.startRun)
	m.HandleFunc("GET /api/runs", s.getRuns)
	m.HandleFunc("GET /api/runs/{id}", s.getRun)
	m.HandleFunc("POST /api/runs/{id}/cancel", s.cancelRun)

	m.HandleFunc("POST /api/apply", s.applyStrategy)

	m.HandleFunc("GET /api/update/check", s.checkUpdate)
	m.HandleFunc("POST /api/update", s.doUpdate)

	sub, _ := fs.Sub(webAssets, "web")
	m.HandleFunc("GET /{$}", s.serveIndex)
	m.HandleFunc("GET /index.html", s.serveIndex)
	m.Handle("/", noStore(http.FileServerFS(sub)))
}

// ---------- handlers ----------

// serveIndex serves index.html with version-stamped asset URLs so a self-update
// busts the browser cache for style.css / app.js.
func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	b, err := fs.ReadFile(webAssets, "web/index.html")
	if err != nil {
		http.Error(w, "index missing", 500)
		return
	}
	v := s.app.Cfg.Version
	if v == "" {
		v = "0"
	}
	html := strings.ReplaceAll(string(b), "style.css", "style.css?v="+v)
	html = strings.ReplaceAll(html, "app.js", "app.js?v="+v)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(html))
}

func (s *Server) getConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.app.Cfg)
}

func (s *Server) getStrategies(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.app.Strategies())
}

func (s *Server) saveStrategy(w http.ResponseWriter, r *http.Request) {
	var in catalog.Strategy
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err)
		return
	}
	out, err := s.app.SaveCustomStrategy(in)
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, out)
}

func (s *Server) deleteStrategy(w http.ResponseWriter, r *http.Request) {
	if err := s.app.DeleteCustomStrategy(r.PathValue("id")); err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (s *Server) getLists(w http.ResponseWriter, r *http.Request) {
	lists, err := s.app.Lists()
	if err != nil {
		httpErr(w, 500, err)
		return
	}
	writeJSON(w, 200, lists)
}

func (s *Server) getList(w http.ResponseWriter, r *http.Request) {
	l, err := s.app.GetList(r.PathValue("id"))
	if err != nil {
		httpErr(w, 404, err)
		return
	}
	writeJSON(w, 200, l)
}

func (s *Server) saveList(w http.ResponseWriter, r *http.Request) {
	var in app.List
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err)
		return
	}
	out, err := s.app.SaveList(&in)
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, out)
}

func (s *Server) deleteList(w http.ResponseWriter, r *http.Request) {
	if err := s.app.DeleteList(r.PathValue("id")); err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (s *Server) getBlobs(w http.ResponseWriter, r *http.Request) {
	sys, custom := s.app.Blobs()
	writeJSON(w, 200, map[string]any{"system": sys, "custom": custom})
}

func (s *Server) uploadBlob(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(4 << 20); err != nil {
		httpErr(w, 400, err)
		return
	}
	f, hdr, err := r.FormFile("file")
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4<<20))
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	path, err := s.app.SaveBlob(hdr.Filename, data)
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]string{"name": hdr.Filename, "path": path})
}

func (s *Server) startRun(w http.ResponseWriter, r *http.Request) {
	var req app.RunRequest
	if err := readJSON(r, &req); err != nil {
		httpErr(w, 400, err)
		return
	}
	run, err := s.app.StartRun(req)
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, run)
}

func (s *Server) getRuns(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.app.Runs())
}

func (s *Server) getRun(w http.ResponseWriter, r *http.Request) {
	run, ok := s.app.GetRun(r.PathValue("id"))
	if !ok {
		httpErr(w, 404, errNotFound)
		return
	}
	writeJSON(w, 200, run)
}

func (s *Server) cancelRun(w http.ResponseWriter, r *http.Request) {
	if err := s.app.CancelRun(r.PathValue("id")); err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "cancelling"})
}

func (s *Server) applyStrategy(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Args    string `json:"args"`
		Restart bool   `json:"restart"`
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err)
		return
	}
	if err := s.app.ApplyStrategyToConfig(in.Args, in.Restart); err != nil {
		httpErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "applied"})
}

func (s *Server) checkUpdate(w http.ResponseWriter, r *http.Request) {
	info, err := s.app.CheckUpdate()
	if err != nil {
		writeJSON(w, 200, map[string]any{"current": info.Current, "latest": info.Latest, "available": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, info)
}

func (s *Server) doUpdate(w http.ResponseWriter, r *http.Request) {
	info, err := s.app.SelfUpdate()
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]any{"status": "updating", "from": info.Current, "to": info.Latest})
}

// ---------- helpers ----------

type apiError struct{ Error string `json:"error"` }

var errNotFound = &simpleErr{"not found"}

type simpleErr struct{ s string }

func (e *simpleErr) Error() string { return e.s }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, apiError{Error: err.Error()})
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(io.LimitReader(r.Body, 8<<20)).Decode(v)
}

// noStore stops browsers from heuristically caching the embedded web assets, so
// a self-update is reflected immediately instead of serving a stale UI.
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Del("If-Modified-Since")
		r.Header.Del("If-None-Match")
		w.Header().Set("Cache-Control", "no-store, must-revalidate")
		next.ServeHTTP(w, r)
	})
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		if r.URL.Path != "/" && len(r.URL.Path) >= 4 && r.URL.Path[:4] == "/api" {
			log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
		}
	})
}
