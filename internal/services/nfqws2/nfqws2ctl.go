// Package nfqws2 ports the file-management + version/update surface of the
// upstream nfqws-keenetic-web (the lighttpd+PHP UI on port 90) into our panel:
// editing the live nfqws2 engine's config, Lua DPI scripts and domain/IP lists,
// plus showing/updating the engine package version and reloading it (SIGHUP).
// The on-disk layout mirrors the upstream PHP (dev/router-nfqws-web-index.php):
// conf in /opt/etc/nfqws2, lists in /opt/etc/nfqws2/lists, lua in the configured
// lua dir (all .lua.gz here).
//
// SECURITY: this runs as root on the router, so the path model is deliberately
// strict — the client only picks a KIND ("conf"|"list"|"lua"); the server owns
// the directory. Names are reduced to a basename and validated against a
// per-kind anchored regex (stem + allowed extension). No client-supplied value
// can redirect the directory or escape it.
package nfqws2

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"nfqws2strategy/internal/tools/config"
	"nfqws2strategy/internal/tools/logbuf"
)

// Manager owns the nfqws2 engine's on-disk files + package version/update/reload.
type Manager struct {
	cfg *config.Config
}

// New builds a Manager reading the live app config (router paths + package name).
func New(cfg *config.Config) *Manager { return &Manager{cfg: cfg} }

// File is one managed file (collapsed to its base name; a .gz variant is surfaced
// via Gz, not as a second entry).
type File struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Size      int64  `json:"size"`
	Gz        bool   `json:"gz"`        // stored gzipped (read transparently gunzips)
	Protected bool   `json:"protected"` // cannot be deleted (engine relies on it)
}

// VersionInfo reports the installed engine version and (optionally) the latest
// available release.
type VersionInfo struct {
	Package   string `json:"package"`         // opkg package version, e.g. "1.1.5"
	Engine    string `json:"engine"`          // binary --version, e.g. "v0.9.5.1"
	Latest    string `json:"latest"`          // newest release (v-stripped)
	Available bool   `json:"available"`       // Latest newer than Package
	URL       string `json:"url"`             // release page
	Error     string `json:"error,omitempty"` // soft network error
}

const (
	readCap   = 8 << 20  // cap a single in-editor read
	uploadCap = 16 << 20 // cap an upload
	pidFile   = "/opt/var/run/nfqws2.pid"
)

// allowed base extensions per kind (without the leading dot, .gz already stripped).
var exts = map[string][]string{
	"conf": {"conf", "conf-opkg", "conf-old", "apk-new"},
	"list": {"list", "list-opkg", "list-old"},
	"lua":  {"lua"},
}

// anchored per-kind validators: stem [A-Za-z0-9_-]+ then one allowed extension.
var nameRe = func() map[string]*regexp.Regexp {
	m := map[string]*regexp.Regexp{}
	for kind, ex := range exts {
		m[kind] = regexp.MustCompile(`^[A-Za-z0-9_-]+\.(` + strings.Join(ex, "|") + `)$`)
	}
	return m
}()

var reEngineVer = regexp.MustCompile(`version\s+(v?[0-9][0-9A-Za-z._-]*)`)

// dir maps a kind to its server-owned directory (always forward-slash so it's
// correct regardless of the build OS — these are router paths).
func (m *Manager) dir(kind string) (string, bool) {
	confDir := path.Dir(m.cfg.Nfqws2Conf) // /opt/etc/nfqws2
	switch kind {
	case "conf":
		return confDir, true
	case "list":
		return confDir + "/lists", true
	case "lua":
		return m.cfg.LuaDir, true
	}
	return "", false
}

// resolve validates (kind, name) and returns the absolute base path (the non-.gz
// path inside the kind dir) plus the validated base name.
func (m *Manager) resolve(kind, name string) (basePath, base string, err error) {
	dir, ok := m.dir(kind)
	if !ok {
		return "", "", fmt.Errorf("неизвестный тип файла: %q", kind)
	}
	base = path.Base(strings.TrimSpace(name))
	base = strings.TrimSuffix(base, ".gz")
	re := nameRe[kind]
	if re == nil || !re.MatchString(base) {
		return "", "", fmt.Errorf("недопустимое имя файла: %q", name)
	}
	return dir + "/" + base, base, nil
}

func isProtected(kind, base string) bool {
	switch kind {
	case "conf":
		return base == "nfqws2.conf"
	case "list":
		switch base {
		case "user.list", "auto.list", "exclude.list", "ipset.list", "ipset_exclude.list":
			return true
		}
	}
	return false
}

// List returns the managed files of a kind, collapsing x.lua + x.lua.gz to a
// single base entry (a plain file shadows its .gz), sorted like the upstream.
func (m *Manager) List(kind string) ([]File, error) {
	dir, ok := m.dir(kind)
	if !ok {
		return nil, fmt.Errorf("неизвестный тип файла: %q", kind)
	}
	re := nameRe[kind]
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	type acc struct {
		plain *int64
		gz    *int64
	}
	byBase := map[string]*acc{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		isGz := strings.HasSuffix(name, ".gz")
		base := strings.TrimSuffix(name, ".gz")
		if !re.MatchString(base) {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		sz := info.Size()
		a2 := byBase[base]
		if a2 == nil {
			a2 = &acc{}
			byBase[base] = a2
		}
		if isGz {
			a2.gz = &sz
		} else {
			a2.plain = &sz
		}
	}
	out := make([]File, 0, len(byBase))
	for base, a2 := range byBase {
		f := File{Name: base, Kind: kind, Protected: isProtected(kind, base)}
		if a2.plain != nil {
			f.Size = *a2.plain
		} else if a2.gz != nil {
			f.Size = *a2.gz
			f.Gz = true
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		pi, pj := sortPriority(out[i].Name), sortPriority(out[j].Name)
		if pi != pj {
			return pi < pj
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// sortPriority mirrors the upstream ordering (router-nfqws-web-index.php).
func sortPriority(name string) int {
	switch name {
	case "nfqws2.conf":
		return -81
	case "user.list":
		return -64
	case "exclude.list":
		return -63
	case "auto.list":
		return -62
	case "ipset.list":
		return -61
	case "ipset_exclude.list":
		return -60
	}
	switch {
	case strings.HasSuffix(name, ".conf"):
		return -70
	case strings.HasSuffix(name, ".list"):
		return -50
	case strings.HasSuffix(name, ".lua"):
		return -30
	}
	return 10
}

func readCapped(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, readCap))
}

// Read returns the file content, transparently gunzipping a .gz variant. A
// missing file yields "" (upstream parity), not an error.
func (m *Manager) Read(kind, name string) (string, error) {
	basePath, _, err := m.resolve(kind, name)
	if err != nil {
		return "", err
	}
	if _, e := os.Stat(basePath); e == nil {
		b, rerr := readCapped(basePath)
		return string(b), rerr
	}
	gzPath := basePath + ".gz"
	if _, e := os.Stat(gzPath); e == nil {
		f, oerr := os.Open(gzPath)
		if oerr != nil {
			return "", oerr
		}
		defer f.Close()
		zr, zerr := gzip.NewReader(f)
		if zerr != nil {
			return "", zerr
		}
		defer zr.Close()
		b, rerr := io.ReadAll(io.LimitReader(zr, readCap))
		return string(b), rerr
	}
	return "", nil
}

// normalize mirrors the upstream normalizeString: LF endings, no runaway blank
// lines, single trailing newline.
func normalize(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = regexp.MustCompile(`\n{3,}`).ReplaceAllString(s, "\n\n")
	if s != "" && !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	return s
}

// Save writes content to the uncompressed base path (mirrors the PHP: a pre-
// existing .gz is left in place and now shadowed by the plain file). Write goes
// via a temp file + rename in the same dir so a partial write can't corrupt a
// live config.
func (m *Manager) Save(kind, name, content string) error {
	basePath, base, err := m.resolve(kind, name)
	if err != nil {
		return err
	}
	data := []byte(normalize(content))
	tmp := basePath + ".n2s-tmp"
	if werr := os.WriteFile(tmp, data, 0o644); werr != nil {
		return werr
	}
	if rerr := os.Rename(tmp, basePath); rerr != nil {
		_ = os.Remove(tmp)
		return rerr
	}
	logbuf.Append("nfqws2", "info", "сохранён "+kind+"/"+base)
	return nil
}

// Create creates an empty file; fails if a plain or .gz variant exists.
func (m *Manager) Create(kind, name string) error {
	basePath, base, err := m.resolve(kind, name)
	if err != nil {
		return err
	}
	if _, e := os.Stat(basePath); e == nil {
		return fmt.Errorf("файл уже существует: %s", base)
	}
	if _, e := os.Stat(basePath + ".gz"); e == nil {
		return fmt.Errorf("файл уже существует: %s", base)
	}
	if werr := os.WriteFile(basePath, nil, 0o644); werr != nil {
		return werr
	}
	logbuf.Append("nfqws2", "info", "создан "+kind+"/"+base)
	return nil
}

// Delete removes the base AND its .gz variant (so a deleted lua can't resurrect
// from its .gz). Protected files are refused.
func (m *Manager) Delete(kind, name string) error {
	basePath, base, err := m.resolve(kind, name)
	if err != nil {
		return err
	}
	if isProtected(kind, base) {
		return fmt.Errorf("файл защищён от удаления: %s", base)
	}
	existed := false
	if err := os.Remove(basePath); err == nil {
		existed = true
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Remove(basePath + ".gz"); err == nil {
		existed = true
	} else if !os.IsNotExist(err) {
		return err
	}
	if !existed {
		return fmt.Errorf("файл не найден: %s", base)
	}
	logbuf.Append("nfqws2", "info", "удалён "+kind+"/"+base)
	return nil
}

// Upload stores an uploaded file. Gzipped uploads are auto-decompressed (by
// magic, regardless of name) so the result is editable plain text.
func (m *Manager) Upload(kind, filename string, data []byte) error {
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err == nil {
			if dec, derr := io.ReadAll(io.LimitReader(zr, readCap)); derr == nil {
				data = dec
			}
			_ = zr.Close()
		}
	}
	return m.Save(kind, filename, string(data))
}

// Bytes returns the file as stored for download (a .gz with no plain sibling is
// returned raw, named ".gz"); otherwise the plain bytes.
func (m *Manager) Bytes(kind, name string) (data []byte, dlName string, err error) {
	basePath, base, rerr := m.resolve(kind, name)
	if rerr != nil {
		return nil, "", rerr
	}
	if b, e := readCapped(basePath); e == nil {
		return b, base, nil
	}
	if b, e := readCapped(basePath + ".gz"); e == nil {
		return b, base + ".gz", nil
	}
	return nil, "", fmt.Errorf("файл не найден: %s", base)
}

func opkgBin() string {
	if _, err := os.Stat("/opt/bin/opkg"); err == nil {
		return "/opt/bin/opkg"
	}
	return "opkg"
}

// Version reports the installed package + engine versions (fast, local).
func (m *Manager) Version() VersionInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	info := VersionInfo{}
	if out, err := exec.CommandContext(ctx, "sh", "-c",
		opkgBin()+" status "+m.cfg.Nfqws2Pkg+" | awk -F': ' '/^Version:/{print $2}'").Output(); err == nil {
		info.Package = strings.TrimSpace(string(out))
	}
	if out, err := exec.CommandContext(ctx, m.cfg.NfqwsBin, "--version").CombinedOutput(); err == nil {
		if mm := reEngineVer.FindStringSubmatch(string(out)); mm != nil {
			info.Engine = mm[1]
		}
	}
	return info
}

// CheckUpdate adds the latest GitHub release to the local version info and flags
// whether it is newer than the installed package (mirrors selfupdate).
func (m *Manager) CheckUpdate() VersionInfo {
	info := m.Version()
	if m.cfg.Nfqws2Repo == "" {
		info.Error = "repo not configured"
		return info
	}
	req, _ := http.NewRequest("GET", "https://api.github.com/repos/"+m.cfg.Nfqws2Repo+"/releases/latest", nil)
	req.Header.Set("User-Agent", "nfqws2-strategy")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := (&http.Client{Timeout: 12 * time.Second}).Do(req)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		info.Error = fmt.Sprintf("github api status %d", resp.StatusCode)
		return info
	}
	var rel struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
	}
	if derr := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel); derr != nil {
		info.Error = derr.Error()
		return info
	}
	info.Latest = strings.TrimPrefix(rel.TagName, "v")
	info.URL = rel.HTMLURL
	info.Available = info.Latest != "" && info.Package != "" && info.Latest != info.Package
	return info
}

// Update upgrades ONLY the engine package via opkg (never the abandoned web
// package, never a router reboot). It briefly bounces nfqws2. Returns trimmed
// command output.
func (m *Manager) Update() (string, error) {
	opkg := opkgBin()
	script := opkg + " update && " + opkg + " upgrade " + m.cfg.Nfqws2Pkg
	logbuf.Append("nfqws2", "info", "opkg upgrade "+m.cfg.Nfqws2Pkg+"…")
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "sh", "-c", script).CombinedOutput()
	detail := lastLines(strings.TrimSpace(string(out)), 20)
	if err != nil {
		logbuf.Append("nfqws2", "error", "opkg upgrade: "+err.Error())
		return detail, fmt.Errorf("%s (%v)", lastLines(detail, 4), err)
	}
	logbuf.Append("nfqws2", "info", "opkg upgrade: готово")
	return detail, nil
}

// Reload sends SIGHUP to the live nfqws2 daemon so it re-reads its config and
// lists WITHOUT dropping NFQUEUE 300 (no DPI blip). It refuses to signal unless
// the pid in the pidfile is verified to be the real engine and NOT our own
// nfqws2-strategy (guards the S51 pgrep-collision bug).
func (m *Manager) Reload() error {
	pid, err := readPid()
	if err != nil {
		return fmt.Errorf("не удалось прочитать pid nfqws2: %w", err)
	}
	if err := verifyPid(pid); err != nil {
		return err
	}
	if err := sighup(pid); err != nil {
		return err
	}
	logbuf.Append("nfqws2", "info", fmt.Sprintf("reload (SIGHUP pid %d)", pid))
	return nil
}

// readPid reads the engine pidfile (portable: file read only).
func readPid() (int, error) {
	b, err := os.ReadFile(pidFile)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("некорректный pid в %s", pidFile)
	}
	return pid, nil
}

// lastLines keeps at most the final n lines, for compact UI display.
func lastLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return s
	}
	return strings.Join(lines[len(lines)-n:], "\n")
}
