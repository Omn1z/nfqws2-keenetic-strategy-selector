// Package app holds the application state and business logic: lists, the
// strategy catalog (builtin + custom), custom blobs, runs, and applying a found
// strategy back into the live nfqws2 config.
package app

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"nfqws2strategy/internal/auth"
	"nfqws2strategy/internal/catalog"
	"nfqws2strategy/internal/config"
	"nfqws2strategy/internal/store"
)

type App struct {
	Cfg   *config.Config
	store *store.Store

	mu       sync.Mutex
	custom   []catalog.Strategy // custom strategies
	runs     map[string]*Run    // in-memory runs (id -> run)
	runOrder []string           // run ids, newest last
	active         *Run      // currently running, if any
	cancel         func()    // cancel for the active run
	addWorker      func(int) // raises the active run's worker count (add threads live)
	pendingThreads int       // a thread target requested before the worker pool was up (auto baseline phase)

	activeBC *BlockCheck // currently running block check, if any
	cancelBC func()      // cancel for the active block check
	lastBC   *BlockCheck // most recently finished block check (for the final poll)

	sessions    *auth.Sessions
	authEnabled bool
}

const (
	customStrategiesFile = "strategies_custom.json"
	maxStoredRuns        = 30
)

func New(cfg *config.Config) (*App, error) {
	st, err := store.New(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	a := &App{Cfg: cfg, store: st, runs: map[string]*Run{}, sessions: auth.NewSessions(sessionTTL)}
	_ = a.store.Load(customStrategiesFile, &a.custom)
	if err := os.MkdirAll(a.blobsDir(), 0o755); err != nil {
		return nil, err
	}
	a.initAuth()
	a.loadRuns()
	return a, nil
}

func (a *App) blobsDir() string { return a.store.Path("blobs") }

// ---------- Lists ----------

func (a *App) Lists() ([]List, error) {
	names, err := a.store.ListFiles("lists")
	if err != nil {
		return nil, err
	}
	out := make([]List, 0, len(names))
	for _, n := range names {
		if !strings.HasSuffix(n, ".json") {
			continue
		}
		var l List
		if err := a.store.Load(filepath.Join("lists", n), &l); err == nil {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out, nil
}

func (a *App) GetList(id string) (*List, error) {
	var l List
	if err := a.store.Load(filepath.Join("lists", id+".json"), &l); err != nil {
		return nil, err
	}
	return &l, nil
}

// SaveList creates (empty id) or updates a list.
func (a *App) SaveList(l *List) (*List, error) {
	now := time.Now().Unix()
	if l.ID == "" {
		l.ID = store.NewID()
		l.CreatedAt = now
	} else if existing, err := a.GetList(l.ID); err == nil {
		l.CreatedAt = existing.CreatedAt
		if l.SuccessfulStrategies == nil {
			l.SuccessfulStrategies = existing.SuccessfulStrategies
		}
	}
	l.Domains = cleanLines(l.Domains)
	l.IPs = cleanLines(l.IPs)
	l.UpdatedAt = now
	if err := a.store.Save(filepath.Join("lists", l.ID+".json"), l); err != nil {
		return nil, err
	}
	return l, nil
}

func (a *App) DeleteList(id string) error {
	return a.store.Delete(filepath.Join("lists", id+".json"))
}

// ---------- Strategies (builtin + custom) ----------

func (a *App) Strategies() []catalog.Strategy {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := append([]catalog.Strategy{}, catalog.Builtin()...)
	out = append(out, a.custom...)
	return out
}

func (a *App) GetStrategy(id string) (catalog.Strategy, bool) {
	for _, s := range a.Strategies() {
		if s.ID == id {
			return s, true
		}
	}
	return catalog.Strategy{}, false
}

func (a *App) SaveCustomStrategy(s catalog.Strategy) (catalog.Strategy, error) {
	s.Source = "custom"
	if err := catalog.Validate(s.ArgLine); err != nil {
		return s, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if s.ID == "" {
		s.ID = "custom-" + store.NewID()
		a.custom = append(a.custom, s)
	} else {
		found := false
		for i := range a.custom {
			if a.custom[i].ID == s.ID {
				a.custom[i] = s
				found = true
				break
			}
		}
		if !found {
			a.custom = append(a.custom, s)
		}
	}
	return s, a.store.Save(customStrategiesFile, a.custom)
}

func (a *App) DeleteCustomStrategy(id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := a.custom[:0]
	for _, s := range a.custom {
		if s.ID != id {
			out = append(out, s)
		}
	}
	a.custom = out
	return a.store.Save(customStrategiesFile, a.custom)
}

// ---------- Blobs ----------

// Blobs lists available blob names: system blobs plus user-uploaded ones.
func (a *App) Blobs() (system []string, custom []string) {
	if entries, err := os.ReadDir(a.Cfg.SystemBlobsDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				system = append(system, e.Name())
			}
		}
	}
	if names, err := a.store.ListFiles("blobs"); err == nil {
		custom = names
	}
	sort.Strings(system)
	sort.Strings(custom)
	return
}

// resolveBlob maps a selected blob filename to its lua name and absolute path,
// preferring a custom upload over a system blob of the same name. The lua name is
// the filename without extension.
func (a *App) resolveBlob(name string) (luaName, path string, ok bool) {
	name = filepath.Base(name)
	if name == "" || name == "." {
		return "", "", false
	}
	path = filepath.Join(a.blobsDir(), name)
	if _, err := os.Stat(path); err != nil {
		path = filepath.Join(a.Cfg.SystemBlobsDir, name)
		if _, err := os.Stat(path); err != nil {
			return "", "", false
		}
	}
	return strings.TrimSuffix(name, filepath.Ext(name)), path, true
}

// reFakeBlobRef matches a fake-payload blob reference inside a desync directive
// (e.g. ":blob=tls_clienthello"), but not the "--blob=" definition flag.
var reFakeBlobRef = regexp.MustCompile(`([\s:])blob=[^\s:]+`)

// buildRunStrategies expands the base set across the selected blobs: every
// strategy that uses a fake blob is tested once per selected blob (with that blob
// substituted as the fake payload — "свой прогон на каждый блоб"); strategies
// without a fake blob are tested once. With no blobs selected the set is returned
// unchanged.
func (a *App) buildRunStrategies(base []catalog.Strategy, blobNames []string) []catalog.Strategy {
	type rb struct{ lua, path string }
	var blobs []rb
	for _, n := range blobNames {
		if lua, path, ok := a.resolveBlob(n); ok {
			blobs = append(blobs, rb{lua, path})
		}
	}
	if len(blobs) == 0 {
		return base
	}
	out := make([]catalog.Strategy, 0, len(base))
	for _, s := range base {
		if !reFakeBlobRef.MatchString(s.ArgLine) {
			out = append(out, s) // blob-independent — test once
			continue
		}
		for _, b := range blobs {
			v := s
			v.ID = s.ID + "/" + b.lua
			v.Name = "[" + b.lua + "] " + s.Name
			v.ArgLine = "--blob=" + b.lua + ":@" + b.path + " " + reFakeBlobRef.ReplaceAllString(s.ArgLine, "${1}blob="+b.lua)
			out = append(out, v)
		}
	}
	return out
}

// SaveBlob stores an uploaded blob and returns the absolute path to reference
// it in a strategy via --blob=name:@<path>.
func (a *App) SaveBlob(name string, data []byte) (string, error) {
	name = filepath.Base(name)
	if name == "" || name == "." || strings.ContainsAny(name, "/\\") {
		return "", fmt.Errorf("invalid blob name")
	}
	if err := a.store.WriteBytes(filepath.Join("blobs", name), data); err != nil {
		return "", err
	}
	return filepath.Join(a.blobsDir(), name), nil
}

// DeleteBlob removes a custom (user-uploaded) blob. System blobs live outside the
// data dir and are never touched.
func (a *App) DeleteBlob(name string) error {
	name = filepath.Base(name)
	if name == "" || name == "." || strings.ContainsAny(name, "/\\") {
		return fmt.Errorf("invalid blob name")
	}
	return a.store.Delete(filepath.Join("blobs", name))
}

// ---------- Apply strategy to live config ----------

var reArgsBlock = regexp.MustCompile(`(?s)(NFQWS_ARGS=")[^"]*(")`)

// ApplyStrategyToConfig backs up nfqws2.conf and replaces the NFQWS_ARGS block
// with the chosen single strategy. Optionally restarts the service. This affects
// the whole network, so callers must make it an explicit user action.
func (a *App) ApplyStrategyToConfig(argLine string, restart bool) error {
	conf := a.Cfg.Nfqws2Conf
	b, err := os.ReadFile(conf)
	if err != nil {
		return err
	}
	backup := conf + ".n2s.bak"
	if err := os.WriteFile(backup, b, 0o644); err != nil {
		return err
	}
	replacement := "${1}" + escapeRepl(argLine) + "${2}"
	out := reArgsBlock.ReplaceAll(b, []byte(replacement))
	if err := os.WriteFile(conf, out, 0o644); err != nil {
		return err
	}
	if restart {
		c := exec.Command("/opt/etc/init.d/S51nfqws2", "restart")
		if o, err := c.CombinedOutput(); err != nil {
			return fmt.Errorf("restart failed: %v: %s", err, strings.TrimSpace(string(o)))
		}
	}
	return nil
}

func escapeRepl(s string) string {
	// protect $ in the replacement string from regexp expansion
	return strings.ReplaceAll(s, "$", "$$")
}

// ---------- helpers ----------

func cleanLines(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
