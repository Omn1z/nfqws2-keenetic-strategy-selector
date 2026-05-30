package app

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

	"nfqws2strategy/internal/logbuf"
)

// This file ports the file-management surface of the upstream nfqws-keenetic-web
// (the lighttpd+PHP UI on port 90) into our panel: editing the live nfqws2
// engine's config, Lua DPI scripts and domain/IP lists, plus showing/updating the
// engine package version. The on-disk layout mirrors the upstream PHP
// (dev/router-nfqws-web-index.php): conf in /opt/etc/nfqws2, lists in
// /opt/etc/nfqws2/lists, lua in /opt/etc/nfqws2/lua (all .lua.gz here).
//
// SECURITY: this runs as root on the router, so the path model is deliberately
// strict — the client only picks a KIND ("conf"|"list"|"lua"); the server owns
// the directory. Names are reduced to a basename and validated against a
// per-kind anchored regex (stem + allowed extension). No client-supplied value
// can redirect the directory or escape it.

// Nfqws2File is one managed file (collapsed to its base name; a .gz variant is
// surfaced via Gz, not as a second entry).
type Nfqws2File struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Size      int64  `json:"size"`
	Gz        bool   `json:"gz"`        // stored gzipped (read transparently gunzips)
	Protected bool   `json:"protected"` // cannot be deleted (engine relies on it)
}

// Nfqws2VersionInfo reports the installed engine version and (optionally) the
// latest available release.
type Nfqws2VersionInfo struct {
	Package   string `json:"package"`         // opkg package version, e.g. "1.1.5"
	Engine    string `json:"engine"`          // binary --version, e.g. "v0.9.5.1"
	Latest    string `json:"latest"`          // newest release (v-stripped)
	Available bool   `json:"available"`       // Latest newer than Package
	URL       string `json:"url"`             // release page
	Error     string `json:"error,omitempty"` // soft network error
}

const (
	nfqws2ReadCap   = 8 << 20  // cap a single in-editor read
	nfqws2UploadCap = 16 << 20 // cap an upload
	nfqws2PidFile   = "/opt/var/run/nfqws2.pid"
)

// allowed base extensions per kind (without the leading dot, .gz already stripped).
var nfqws2Exts = map[string][]string{
	"conf": {"conf", "conf-opkg", "conf-old", "apk-new"},
	"list": {"list", "list-opkg", "list-old"},
	"lua":  {"lua"},
}

// anchored per-kind validators: stem [A-Za-z0-9_-]+ then one allowed extension.
var nfqws2NameRe = func() map[string]*regexp.Regexp {
	m := map[string]*regexp.Regexp{}
	for kind, exts := range nfqws2Exts {
		m[kind] = regexp.MustCompile(`^[A-Za-z0-9_-]+\.(` + strings.Join(exts, "|") + `)$`)
	}
	return m
}()

var reEngineVer = regexp.MustCompile(`version\s+(v?[0-9][0-9A-Za-z._-]*)`)

// nfqws2Dir maps a kind to its server-owned directory (always forward-slash so
// it's correct regardless of the build OS — these are router paths).
func (a *App) nfqws2Dir(kind string) (string, bool) {
	confDir := path.Dir(a.Cfg.Nfqws2Conf) // /opt/etc/nfqws2
	switch kind {
	case "conf":
		return confDir, true
	case "list":
		return confDir + "/lists", true
	case "lua":
		return a.Cfg.LuaDir, true
	}
	return "", false
}

// resolveNfqws2 validates (kind, name) and returns the absolute base path (the
// non-.gz path inside the kind dir) plus the validated base name.
func (a *App) resolveNfqws2(kind, name string) (basePath, base string, err error) {
	dir, ok := a.nfqws2Dir(kind)
	if !ok {
		return "", "", fmt.Errorf("неизвестный тип файла: %q", kind)
	}
	base = path.Base(strings.TrimSpace(name))
	base = strings.TrimSuffix(base, ".gz")
	re := nfqws2NameRe[kind]
	if re == nil || !re.MatchString(base) {
		return "", "", fmt.Errorf("недопустимое имя файла: %q", name)
	}
	return dir + "/" + base, base, nil
}

func isProtectedNfqws2(kind, base string) bool {
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

// ListNfqws2Files returns the managed files of a kind, collapsing x.lua + x.lua.gz
// to a single base entry (a plain file shadows its .gz), sorted like the upstream.
func (a *App) ListNfqws2Files(kind string) ([]Nfqws2File, error) {
	dir, ok := a.nfqws2Dir(kind)
	if !ok {
		return nil, fmt.Errorf("неизвестный тип файла: %q", kind)
	}
	re := nfqws2NameRe[kind]
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
	out := make([]Nfqws2File, 0, len(byBase))
	for base, a2 := range byBase {
		f := Nfqws2File{Name: base, Kind: kind, Protected: isProtectedNfqws2(kind, base)}
		if a2.plain != nil {
			f.Size = *a2.plain
		} else if a2.gz != nil {
			f.Size = *a2.gz
			f.Gz = true
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		pi, pj := sortPriorityNfqws2(out[i].Name), sortPriorityNfqws2(out[j].Name)
		if pi != pj {
			return pi < pj
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// sortPriorityNfqws2 mirrors the upstream ordering (router-nfqws-web-index.php).
func sortPriorityNfqws2(name string) int {
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

func readCappedFile(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, nfqws2ReadCap))
}

// ReadNfqws2File returns the file content, transparently gunzipping a .gz variant.
// A missing file yields "" (upstream parity), not an error.
func (a *App) ReadNfqws2File(kind, name string) (string, error) {
	basePath, _, err := a.resolveNfqws2(kind, name)
	if err != nil {
		return "", err
	}
	if _, e := os.Stat(basePath); e == nil {
		b, rerr := readCappedFile(basePath)
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
		b, rerr := io.ReadAll(io.LimitReader(zr, nfqws2ReadCap))
		return string(b), rerr
	}
	return "", nil
}

// normalizeNfqws2 mirrors the upstream normalizeString: LF endings, no runaway
// blank lines, single trailing newline.
func normalizeNfqws2(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = regexp.MustCompile(`\n{3,}`).ReplaceAllString(s, "\n\n")
	if s != "" && !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	return s
}

// SaveNfqws2File writes content to the uncompressed base path (mirrors the PHP:
// a pre-existing .gz is left in place and now shadowed by the plain file). Write
// goes via a temp file + rename in the same dir so a partial write can't corrupt
// a live config.
func (a *App) SaveNfqws2File(kind, name, content string) error {
	basePath, base, err := a.resolveNfqws2(kind, name)
	if err != nil {
		return err
	}
	data := []byte(normalizeNfqws2(content))
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

// CreateNfqws2File creates an empty file; fails if a plain or .gz variant exists.
func (a *App) CreateNfqws2File(kind, name string) error {
	basePath, base, err := a.resolveNfqws2(kind, name)
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

// DeleteNfqws2File removes the base AND its .gz variant (so a deleted lua can't
// resurrect from its .gz). Protected files are refused.
func (a *App) DeleteNfqws2File(kind, name string) error {
	basePath, base, err := a.resolveNfqws2(kind, name)
	if err != nil {
		return err
	}
	if isProtectedNfqws2(kind, base) {
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

// SaveNfqws2Upload stores an uploaded file. Gzipped uploads are auto-decompressed
// (by magic, regardless of name) so the result is editable plain text.
func (a *App) SaveNfqws2Upload(kind, filename string, data []byte) error {
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err == nil {
			if dec, derr := io.ReadAll(io.LimitReader(zr, nfqws2ReadCap)); derr == nil {
				data = dec
			}
			_ = zr.Close()
		}
	}
	return a.SaveNfqws2File(kind, filename, string(data))
}

// Nfqws2FileBytes returns the file as stored for download (a .gz with no plain
// sibling is returned raw, named ".gz"); otherwise the plain bytes.
func (a *App) Nfqws2FileBytes(kind, name string) (data []byte, dlName string, err error) {
	basePath, base, rerr := a.resolveNfqws2(kind, name)
	if rerr != nil {
		return nil, "", rerr
	}
	if b, e := readCappedFile(basePath); e == nil {
		return b, base, nil
	}
	if b, e := readCappedFile(basePath + ".gz"); e == nil {
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

// Nfqws2Version reports the installed package + engine versions (fast, local).
func (a *App) Nfqws2Version() Nfqws2VersionInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	info := Nfqws2VersionInfo{}
	if out, err := exec.CommandContext(ctx, "sh", "-c",
		opkgBin()+" status "+a.Cfg.Nfqws2Pkg+" | awk -F': ' '/^Version:/{print $2}'").Output(); err == nil {
		info.Package = strings.TrimSpace(string(out))
	}
	if out, err := exec.CommandContext(ctx, a.Cfg.NfqwsBin, "--version").CombinedOutput(); err == nil {
		if m := reEngineVer.FindStringSubmatch(string(out)); m != nil {
			info.Engine = m[1]
		}
	}
	return info
}

// Nfqws2CheckUpdate adds the latest GitHub release to the local version info and
// flags whether it is newer than the installed package (mirrors selfupdate.go).
func (a *App) Nfqws2CheckUpdate() Nfqws2VersionInfo {
	info := a.Nfqws2Version()
	if a.Cfg.Nfqws2Repo == "" {
		info.Error = "repo not configured"
		return info
	}
	req, _ := http.NewRequest("GET", "https://api.github.com/repos/"+a.Cfg.Nfqws2Repo+"/releases/latest", nil)
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

// Nfqws2Update upgrades ONLY the engine package via opkg (never the abandoned web
// package, never a router reboot). It briefly bounces nfqws2. Returns trimmed
// command output.
func (a *App) Nfqws2Update() (string, error) {
	opkg := opkgBin()
	script := opkg + " update && " + opkg + " upgrade " + a.Cfg.Nfqws2Pkg
	logbuf.Append("nfqws2", "info", "opkg upgrade "+a.Cfg.Nfqws2Pkg+"…")
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

// Nfqws2Reload sends SIGHUP to the live nfqws2 daemon so it re-reads its config
// and lists WITHOUT dropping NFQUEUE 300 (no DPI blip). It refuses to signal
// unless the pid in the pidfile is verified to be the real engine and NOT our
// own nfqws2-strategy (guards the S51 pgrep-collision bug).
func (a *App) Nfqws2Reload() error {
	pid, err := readNfqws2Pid()
	if err != nil {
		return fmt.Errorf("не удалось прочитать pid nfqws2: %w", err)
	}
	if err := verifyNfqws2Pid(pid); err != nil {
		return err
	}
	if err := sighupNfqws2(pid); err != nil {
		return err
	}
	logbuf.Append("nfqws2", "info", fmt.Sprintf("reload (SIGHUP pid %d)", pid))
	return nil
}

// readNfqws2Pid reads the engine pidfile (portable: file read only).
func readNfqws2Pid() (int, error) {
	b, err := os.ReadFile(nfqws2PidFile)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("некорректный pid в %s", nfqws2PidFile)
	}
	return pid, nil
}
