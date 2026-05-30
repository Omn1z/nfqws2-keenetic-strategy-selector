// Package server exposes the REST API and the embedded web UI.
package server

import (
	"compress/gzip"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"nfqws2strategy/internal/app"
	"nfqws2strategy/internal/catalog"
	"nfqws2strategy/internal/dns"
	"nfqws2strategy/internal/logbuf"
	"nfqws2strategy/internal/tgws"
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

func (s *Server) Handler() http.Handler { return s.logging(s.authGate(s.mux)) }

const sessionCookie = "n2s_sess"

// authGate blocks protected /api/* endpoints unless a valid session cookie is
// present. Static assets and the login/status endpoints stay public.
func (s *Server) authGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.app.AuthEnabled() && strings.HasPrefix(r.URL.Path, "/api/") && !publicAPI(r.URL.Path) {
			c, _ := r.Cookie(sessionCookie)
			if c == nil || !s.app.ValidSession(c.Value) {
				writeJSON(w, http.StatusUnauthorized, apiError{Error: "unauthorized"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func publicAPI(p string) bool {
	return p == "/api/auth/status" || p == "/api/auth/login"
}

func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	authed := false
	if c, _ := r.Cookie(sessionCookie); c != nil {
		authed = s.app.ValidSession(c.Value)
	}
	writeJSON(w, 200, map[string]any{"enabled": s.app.AuthEnabled(), "authed": authed, "version": s.app.Cfg.Version})
}

func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err)
		return
	}
	tok, ok := s.app.Login(in.User, in.Password)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, apiError{Error: "неверный логин или пароль"})
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 7 * 24 * 3600})
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (s *Server) authLogout(w http.ResponseWriter, r *http.Request) {
	if c, _ := r.Cookie(sessionCookie); c != nil {
		s.app.Logout(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (s *Server) authConfig(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err)
		return
	}
	if err := s.app.SetAuthEnabled(in.Enabled); err != nil {
		httpErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"enabled": in.Enabled})
}

func (s *Server) restartServices(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Services []string `json:"services"`
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]any{"results": s.app.RestartServices(in.Services)})
}

func (s *Server) getSystemSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"auth_enabled":      s.app.AuthEnabled(),
		"auth_forced_off":   s.app.AuthForcedOff(),
		"logging_enabled":   s.app.LoggingEnabled(),
		"http_logs_enabled": s.app.HTTPLogsEnabled(),
	})
}

func (s *Server) setSystemSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AuthEnabled     *bool `json:"auth_enabled"`
		LoggingEnabled  *bool `json:"logging_enabled"`
		HTTPLogsEnabled *bool `json:"http_logs_enabled"`
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err)
		return
	}
	if in.AuthEnabled != nil && !s.app.AuthForcedOff() {
		if err := s.app.SetAuthEnabled(*in.AuthEnabled); err != nil {
			httpErr(w, 500, err)
			return
		}
	}
	if in.LoggingEnabled != nil {
		if err := s.app.SetLoggingEnabled(*in.LoggingEnabled); err != nil {
			httpErr(w, 500, err)
			return
		}
	}
	if in.HTTPLogsEnabled != nil {
		if err := s.app.SetHTTPLogsEnabled(*in.HTTPLogsEnabled); err != nil {
			httpErr(w, 500, err)
			return
		}
	}
	s.getSystemSettings(w, r)
}

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /api/config", s.getConfig)

	m.HandleFunc("GET /api/dashboard", s.getDashboard)
	m.HandleFunc("GET /api/connections", s.getConnections)
	m.HandleFunc("GET /api/devices", s.getDevices)
	m.HandleFunc("POST /api/devices/{ip}/trace", s.startDeviceTrace)
	m.HandleFunc("GET /api/trace/{id}", s.getTrace)
	m.HandleFunc("POST /api/devices/{ip}/pcap", s.startPcap)
	m.HandleFunc("GET /api/pcap/{id}", s.getPcap)
	m.HandleFunc("GET /api/pcap/{id}/download", s.downloadPcap)
	m.HandleFunc("POST /api/devices/{ip}/blobcap", s.startBlobCapture)
	m.HandleFunc("GET /api/blobcap/{id}", s.getBlobCapture)
	m.HandleFunc("POST /api/blobcap/{id}/save", s.saveCapturedBlob)
	m.HandleFunc("POST /api/system/install", s.installPackage)
	m.HandleFunc("GET /api/system/settings", s.getSystemSettings)
	m.HandleFunc("POST /api/system/settings", s.setSystemSettings)
	m.HandleFunc("POST /api/services/restart", s.restartServices)

	m.HandleFunc("GET /api/logs", s.getLogs)
	m.HandleFunc("POST /api/logs/clear", s.clearLogs)

	m.HandleFunc("GET /api/strategies", s.getStrategies)
	m.HandleFunc("POST /api/strategies", s.saveStrategy)
	m.HandleFunc("GET /api/strategies/sni", s.getSNI)
	m.HandleFunc("POST /api/strategies/sni", s.setSNI)
	m.HandleFunc("POST /api/strategies/export", s.exportStrategy)
	m.HandleFunc("POST /api/strategies/import", s.importStrategy)
	m.HandleFunc("DELETE /api/strategies/{id}", s.deleteStrategy)

	m.HandleFunc("GET /api/lists", s.getLists)
	m.HandleFunc("POST /api/lists", s.saveList)
	m.HandleFunc("GET /api/lists/{id}", s.getList)
	m.HandleFunc("DELETE /api/lists/{id}", s.deleteList)

	m.HandleFunc("GET /api/blobs", s.getBlobs)
	m.HandleFunc("POST /api/blobs", s.uploadBlob)
	m.HandleFunc("POST /api/blobs/generate", s.generateBlob)
	m.HandleFunc("GET /api/blobs/export", s.exportBlobs)
	m.HandleFunc("POST /api/blobs/export", s.exportBlobsSel)
	m.HandleFunc("POST /api/blobs/zip", s.importBlobsZip)
	m.HandleFunc("POST /api/blobs/trash/empty", s.emptyTrash)
	m.HandleFunc("DELETE /api/blobs/trash/{name}", s.purgeBlob)
	m.HandleFunc("POST /api/blobs/{name}/restore", s.restoreBlob)
	m.HandleFunc("GET /api/blobs/{name}/validate", s.validateBlob)
	m.HandleFunc("DELETE /api/blobs/{name}", s.deleteBlob)

	m.HandleFunc("POST /api/runs", s.startRun)
	m.HandleFunc("GET /api/runs", s.getRuns)
	m.HandleFunc("GET /api/runs/{id}", s.getRun)
	m.HandleFunc("POST /api/runs/{id}/cancel", s.cancelRun)
	m.HandleFunc("POST /api/runs/{id}/threads", s.addRunThreads)

	m.HandleFunc("POST /api/blockcheck", s.startBlockCheck)
	m.HandleFunc("GET /api/blockcheck/{id}", s.getBlockCheck)
	m.HandleFunc("POST /api/blockcheck/{id}/cancel", s.cancelBlockCheck)

	m.HandleFunc("GET /api/dns", s.getDNS)
	m.HandleFunc("POST /api/dns", s.saveDNS)
	m.HandleFunc("POST /api/dns/reset", s.resetDNS)
	m.HandleFunc("DELETE /api/dns/{id}", s.deleteDNS)

	m.HandleFunc("GET /api/tgws", s.tgwsStatus)
	m.HandleFunc("POST /api/tgws/config", s.tgwsConfig)
	m.HandleFunc("POST /api/tgws/start", s.tgwsStart)
	m.HandleFunc("POST /api/tgws/stop", s.tgwsStop)
	m.HandleFunc("POST /api/tgws/secret", s.tgwsSecret)

	m.HandleFunc("GET /api/socks5", s.socks5Status)
	m.HandleFunc("POST /api/socks5/config", s.socks5Config)
	m.HandleFunc("POST /api/socks5/start", s.socks5Start)
	m.HandleFunc("POST /api/socks5/stop", s.socks5Stop)

	m.HandleFunc("POST /api/apply", s.applyStrategy)

	m.HandleFunc("GET /api/update/check", s.checkUpdate)
	m.HandleFunc("POST /api/update", s.doUpdate)

	m.HandleFunc("GET /api/auth/status", s.authStatus)
	m.HandleFunc("POST /api/auth/login", s.authLogin)
	m.HandleFunc("POST /api/auth/logout", s.authLogout)
	m.HandleFunc("POST /api/auth/config", s.authConfig)

	m.HandleFunc("GET /api/geo", s.getGeo)
	m.HandleFunc("POST /api/geo", s.uploadGeo)
	m.HandleFunc("DELETE /api/geo/{name}", s.deleteGeo)
	m.HandleFunc("POST /api/geo/import", s.importGeo)
	m.HandleFunc("POST /api/geo/resolve", s.resolveGeo)

	// NFQWS2 engine: file management (conf/list/lua) + version/update/reload.
	m.HandleFunc("GET /api/nfqws2/version", s.nfqws2Version)
	m.HandleFunc("GET /api/nfqws2/update/check", s.nfqws2CheckUpdate)
	m.HandleFunc("POST /api/nfqws2/update", s.nfqws2Update)
	m.HandleFunc("POST /api/nfqws2/reload", s.nfqws2Reload)
	m.HandleFunc("POST /api/nfqws2/start", s.nfqws2StartSvc)
	m.HandleFunc("POST /api/nfqws2/stop", s.nfqws2StopSvc)
	m.HandleFunc("GET /api/nfqws2/files", s.nfqws2Files)
	m.HandleFunc("GET /api/nfqws2/file", s.nfqws2GetFile)
	m.HandleFunc("POST /api/nfqws2/file", s.nfqws2SaveFile)
	m.HandleFunc("POST /api/nfqws2/file/create", s.nfqws2CreateFile)
	m.HandleFunc("POST /api/nfqws2/file/upload", s.nfqws2UploadFile)
	m.HandleFunc("DELETE /api/nfqws2/file", s.nfqws2DeleteFile)
	m.HandleFunc("GET /api/nfqws2/file/download", s.nfqws2DownloadFile)

	// Single-file React app: any non-/api path serves the inlined index.html, so
	// History-API routes (/lists, /runs, …) deep-link and refresh cleanly. /api/*
	// patterns are more specific and take precedence.
	m.HandleFunc("/", s.serveIndex)
}

// ---------- handlers ----------

// serveIndex serves the single inlined index.html (JS+CSS embedded by the Vite
// build). It is served with no-store — the whole UI is one file, so there are no
// sub-assets to cache-bust, and a self-update is reflected immediately. The
// response is gzipped when the client accepts it (the inlined file is ~280 KB
// → ~84 KB on the wire).
func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	b, err := fs.ReadFile(webAssets, "web/index.html")
	if err != nil {
		http.Error(w, "index missing", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		defer gz.Close()
		_, _ = gz.Write(b)
		return
	}
	_, _ = w.Write(b)
}

func (s *Server) getConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.app.Cfg)
}

// ---------- monitoring (dashboard / connections / devices) ----------

func (s *Server) getDashboard(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.app.Dashboard(hostFromHeader(r.Host)))
}

func (s *Server) getConnections(w http.ResponseWriter, r *http.Request) {
	v, err := s.app.Connections()
	if err != nil {
		httpErr(w, 500, err)
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) getDevices(w http.ResponseWriter, r *http.Request) {
	v, err := s.app.DeviceActivity()
	if err != nil {
		httpErr(w, 500, err)
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) startDeviceTrace(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Seconds int `json:"seconds"`
	}
	_ = readJSON(r, &in) // body optional; defaults to 30s
	t, err := s.app.StartDeviceTrace(r.PathValue("ip"), in.Seconds)
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, t)
}

func (s *Server) getTrace(w http.ResponseWriter, r *http.Request) {
	t, ok := s.app.GetTrace(r.PathValue("id"))
	if !ok {
		httpErr(w, 404, errNotFound)
		return
	}
	writeJSON(w, 200, t)
}

func (s *Server) startPcap(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Seconds int `json:"seconds"`
	}
	_ = readJSON(r, &in) // body optional; defaults to 30s
	p, err := s.app.StartPcap(r.PathValue("ip"), in.Seconds)
	if err != nil {
		if errors.Is(err, app.ErrNeedTcpdump) {
			writeJSON(w, 200, map[string]any{"need_install": true, "package": "tcpdump"})
			return
		}
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, p)
}

func (s *Server) getPcap(w http.ResponseWriter, r *http.Request) {
	p, ok := s.app.GetPcap(r.PathValue("id"))
	if !ok {
		httpErr(w, 404, errNotFound)
		return
	}
	writeJSON(w, 200, p)
}

func (s *Server) downloadPcap(w http.ResponseWriter, r *http.Request) {
	path, name, ok := s.app.PcapFile(r.PathValue("id"))
	if !ok {
		httpErr(w, 404, errNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	http.ServeFile(w, r, path)
}

func (s *Server) installPackage(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Package string `json:"package"`
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err)
		return
	}
	out, err := s.app.InstallPackage(in.Package)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "output": out, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "output": out})
}

// ---------- logs (in-memory ring, UI "Логи" tab) ----------

func (s *Server) getLogs(w http.ResponseWriter, r *http.Request) {
	module := r.URL.Query().Get("module")
	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		limit, _ = strconv.Atoi(v)
	}
	writeJSON(w, 200, map[string]any{"entries": logbuf.Snapshot(module, limit), "modules": logbuf.Modules()})
}

func (s *Server) clearLogs(w http.ResponseWriter, r *http.Request) {
	logbuf.Clear()
	writeJSON(w, 200, map[string]string{"status": "ok"})
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

func (s *Server) exportStrategy(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
		L7   string `json:"l7"`
		Args string `json:"args"`
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err)
		return
	}
	if strings.TrimSpace(in.Args) == "" {
		httpErr(w, 400, &simpleErr{"empty strategy args"})
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+safeFile(in.Name)+`.zip"`)
	_ = s.app.ExportStrategyZip(in.Name, in.L7, in.Args, w)
}

func (s *Server) importStrategy(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		httpErr(w, 400, err)
		return
	}
	f, _, err := r.FormFile("file")
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 32<<20))
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	st, err := s.app.ImportStrategyZip(data)
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, st)
}

// safeFile sanitizes a user-provided name for use in a Content-Disposition filename.
func safeFile(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		out = "strategy"
	}
	if len(out) > 60 {
		out = out[:60]
	}
	return out
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

func (s *Server) getSNI(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"domains": s.app.SNIDomains()})
}

func (s *Server) setSNI(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Domains []string `json:"domains"`
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err)
		return
	}
	out, err := s.app.SetSNIDomains(in.Domains)
	if err != nil {
		httpErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"domains": out})
}

func (s *Server) getBlobs(w http.ResponseWriter, r *http.Request) {
	sys, custom := s.app.Blobs()
	writeJSON(w, 200, map[string]any{"system": sys, "custom": custom, "trash": s.app.TrashedBlobs()})
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

func (s *Server) exportBlobs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="blobs.zip"`)
	_ = s.app.ExportBlobsZip(w, nil)
}

func (s *Server) exportBlobsSel(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Names []string `json:"names"`
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="blobs.zip"`)
	_ = s.app.ExportBlobsZip(w, in.Names)
}

func (s *Server) deleteBlob(w http.ResponseWriter, r *http.Request) {
	if err := s.app.DeleteBlob(r.PathValue("name")); err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (s *Server) importBlobsZip(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		httpErr(w, 400, err)
		return
	}
	f, _, err := r.FormFile("file")
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 32<<20))
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	n, err := s.app.ImportBlobsZip(data)
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]int{"imported": n})
}

func (s *Server) generateBlob(w http.ResponseWriter, r *http.Request) {
	var in struct {
		SNI        string   `json:"sni"`
		ALPN       []string `json:"alpn"`
		MinVersion int      `json:"min_version"`
		Name       string   `json:"name"`
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err)
		return
	}
	path, err := s.app.GenerateBlob(in.SNI, in.ALPN, uint16(in.MinVersion), in.Name)
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]string{"name": in.Name, "path": path})
}

func (s *Server) validateBlob(w http.ResponseWriter, r *http.Request) {
	valid, detail, err := s.app.ValidateBlob(r.PathValue("name"))
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]any{"valid": valid, "detail": detail})
}

func (s *Server) restoreBlob(w http.ResponseWriter, r *http.Request) {
	if err := s.app.RestoreBlob(r.PathValue("name")); err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (s *Server) purgeBlob(w http.ResponseWriter, r *http.Request) {
	if err := s.app.PurgeBlob(r.PathValue("name")); err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (s *Server) emptyTrash(w http.ResponseWriter, r *http.Request) {
	if err := s.app.EmptyTrash(); err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (s *Server) startBlobCapture(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Seconds int `json:"seconds"`
	}
	_ = readJSON(r, &in) // body optional; defaults to 20s
	c, err := s.app.StartBlobCapture(r.PathValue("ip"), in.Seconds)
	if err != nil {
		if errors.Is(err, app.ErrNeedTcpdump) {
			writeJSON(w, 200, map[string]any{"need_install": true, "package": "tcpdump"})
			return
		}
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, c)
}

func (s *Server) getBlobCapture(w http.ResponseWriter, r *http.Request) {
	c, ok := s.app.GetBlobCapture(r.PathValue("id"))
	if !ok {
		httpErr(w, 404, errNotFound)
		return
	}
	writeJSON(w, 200, c)
}

func (s *Server) saveCapturedBlob(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Index int    `json:"index"`
		Name  string `json:"name"`
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err)
		return
	}
	path, err := s.app.SaveCapturedBlob(r.PathValue("id"), in.Index, in.Name)
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]string{"name": in.Name, "path": path})
}

func (s *Server) getGeo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.app.GeoFiles())
}

func (s *Server) uploadGeo(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(16 << 20); err != nil {
		httpErr(w, 400, err)
		return
	}
	kind := r.FormValue("kind")
	f, hdr, err := r.FormFile("file")
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 48<<20))
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	if err := s.app.SaveGeoFile(hdr.Filename, kind, data); err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]string{"name": hdr.Filename, "kind": kind})
}

func (s *Server) deleteGeo(w http.ResponseWriter, r *http.Request) {
	if err := s.app.DeleteGeoFile(r.PathValue("name")); err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (s *Server) importGeo(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Geo      string `json:"geo"`
		Category string `json:"category"`
		Limit    int    `json:"limit"`
		ListID   string `json:"list_id"`
		ListName string `json:"list_name"`
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err)
		return
	}
	list, err := s.app.ImportGeo(in.Geo, in.Category, in.Limit, in.ListID, in.ListName)
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, list)
}

func (s *Server) resolveGeo(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Geo      string `json:"geo"`
		Category string `json:"category"`
		Limit    int    `json:"limit"`
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err)
		return
	}
	targets, err := s.app.ResolveGeo(in.Geo, in.Category, in.Limit)
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]any{"targets": targets})
}

// ---------- NFQWS2 engine file management + version/update/reload ----------

func (s *Server) nfqws2Version(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.app.Nfqws2Version())
}

func (s *Server) nfqws2CheckUpdate(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.app.Nfqws2CheckUpdate())
}

func (s *Server) nfqws2Update(w http.ResponseWriter, r *http.Request) {
	out, err := s.app.Nfqws2Update()
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "output": out, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "output": out})
}

func (s *Server) nfqws2Reload(w http.ResponseWriter, r *http.Request) {
	if err := s.app.Nfqws2Reload(); err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "reloaded"})
}

func (s *Server) nfqws2Files(w http.ResponseWriter, r *http.Request) {
	files, err := s.app.ListNfqws2Files(r.URL.Query().Get("kind"))
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]any{"files": files})
}

func (s *Server) nfqws2GetFile(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	kind, name := q.Get("kind"), q.Get("name")
	content, err := s.app.ReadNfqws2File(kind, name)
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]any{"kind": kind, "name": name, "content": content})
}

func (s *Server) nfqws2SaveFile(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Kind    string `json:"kind"`
		Name    string `json:"name"`
		Content string `json:"content"`
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err)
		return
	}
	if err := s.app.SaveNfqws2File(in.Kind, in.Name, in.Content); err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "saved"})
}

func (s *Server) nfqws2CreateFile(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err)
		return
	}
	if err := s.app.CreateNfqws2File(in.Kind, in.Name); err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "created"})
}

func (s *Server) nfqws2UploadFile(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(16 << 20); err != nil {
		httpErr(w, 400, err)
		return
	}
	kind := r.FormValue("kind")
	f, hdr, err := r.FormFile("file")
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 16<<20))
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	if err := s.app.SaveNfqws2Upload(kind, hdr.Filename, data); err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]string{"name": hdr.Filename, "kind": kind})
}

func (s *Server) nfqws2DeleteFile(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if err := s.app.DeleteNfqws2File(q.Get("kind"), q.Get("name")); err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (s *Server) nfqws2DownloadFile(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	data, name, err := s.app.Nfqws2FileBytes(q.Get("kind"), q.Get("name"))
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+safeDispoName(name)+`"`)
	_, _ = w.Write(data)
}

// safeDispoName sanitizes a filename for a Content-Disposition header while
// PRESERVING dots — unlike safeFile, which maps "." to "_" (mangling user.list).
func safeDispoName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		out = "file"
	}
	if len(out) > 80 {
		out = out[:80]
	}
	return out
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

func (s *Server) addRunThreads(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Threads int `json:"threads"`
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err)
		return
	}
	threads, err := s.app.AddRunThreads(r.PathValue("id"), in.Threads)
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]int{"threads": threads})
}

func (s *Server) startBlockCheck(w http.ResponseWriter, r *http.Request) {
	var req app.BlockCheckRequest
	if err := readJSON(r, &req); err != nil {
		httpErr(w, 400, err)
		return
	}
	bc, err := s.app.StartBlockCheck(req)
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, bc)
}

func (s *Server) getBlockCheck(w http.ResponseWriter, r *http.Request) {
	bc, ok := s.app.GetBlockCheck(r.PathValue("id"))
	if !ok {
		httpErr(w, 404, errNotFound)
		return
	}
	writeJSON(w, 200, bc)
}

func (s *Server) cancelBlockCheck(w http.ResponseWriter, r *http.Request) {
	if err := s.app.CancelBlockCheck(r.PathValue("id")); err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "cancelling"})
}

// ---------- DNS (DoH/DoT servers) ----------

func (s *Server) getDNS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.app.DNSServers())
}

func (s *Server) saveDNS(w http.ResponseWriter, r *http.Request) {
	var in dns.Server
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err)
		return
	}
	out, err := s.app.SaveDNSServer(in)
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, out)
}

func (s *Server) deleteDNS(w http.ResponseWriter, r *http.Request) {
	if err := s.app.DeleteDNSServer(r.PathValue("id")); err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (s *Server) resetDNS(w http.ResponseWriter, r *http.Request) {
	out, err := s.app.ResetDNSServers()
	if err != nil {
		httpErr(w, 500, err)
		return
	}
	writeJSON(w, 200, out)
}

// ---------- TG WS Proxy ----------

func (s *Server) tgwsStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.app.TGWSStatusFor(hostFromHeader(r.Host)))
}

func (s *Server) tgwsConfig(w http.ResponseWriter, r *http.Request) {
	var in tgws.Config
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err)
		return
	}
	if err := s.app.TGWSSetConfig(&in); err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, s.app.TGWSStatusFor(hostFromHeader(r.Host)))
}

func (s *Server) tgwsStart(w http.ResponseWriter, r *http.Request) {
	if err := s.app.TGWSStart(); err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, s.app.TGWSStatusFor(hostFromHeader(r.Host)))
}

func (s *Server) tgwsStop(w http.ResponseWriter, r *http.Request) {
	if err := s.app.TGWSStop(); err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, s.app.TGWSStatusFor(hostFromHeader(r.Host)))
}

func (s *Server) tgwsSecret(w http.ResponseWriter, r *http.Request) {
	secret, err := s.app.TGWSNewSecret()
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]string{"secret": secret})
}

// ---------- SOCKS5 Telegram proxy (TGLock-adapted) ----------

func (s *Server) socks5Status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.app.Socks5StatusFor(hostFromHeader(r.Host)))
}

func (s *Server) socks5Config(w http.ResponseWriter, r *http.Request) {
	var in tgws.Socks5Config
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err)
		return
	}
	if err := s.app.Socks5SetConfig(&in); err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, s.app.Socks5StatusFor(hostFromHeader(r.Host)))
}

func (s *Server) socks5Start(w http.ResponseWriter, r *http.Request) {
	if err := s.app.Socks5Start(); err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, s.app.Socks5StatusFor(hostFromHeader(r.Host)))
}

func (s *Server) socks5Stop(w http.ResponseWriter, r *http.Request) {
	if err := s.app.Socks5Stop(); err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, 200, s.app.Socks5StatusFor(hostFromHeader(r.Host)))
}

func (s *Server) nfqws2StartSvc(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.app.Nfqws2Start())
}

func (s *Server) nfqws2StopSvc(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.app.Nfqws2Stop())
}

// hostFromHeader strips the port from a Host header so the tg:// link points at
// whatever address the user reached the UI on.
func hostFromHeader(host string) string {
	if host == "" {
		return ""
	}
	if strings.HasPrefix(host, "[") { // IPv6 literal: [::1]:8090
		if i := strings.Index(host, "]"); i > 0 {
			return host[:i+1]
		}
		return host
	}
	if i := strings.Index(host, ":"); i >= 0 {
		return host[:i]
	}
	return host
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

type apiError struct {
	Error string `json:"error"`
}

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

func (s *Server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		if s.app.HTTPLogsEnabled() && r.URL.Path != "/" && len(r.URL.Path) >= 4 && r.URL.Path[:4] == "/api" {
			log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
		}
	})
}
