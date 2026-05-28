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
	active   *Run               // currently running, if any
	cancel   func()             // cancel for the active run

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
	if strings.TrimSpace(s.ArgLine) == "" {
		return s, fmt.Errorf("strategy args are empty")
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

// blobArgs resolves blob filenames to nfqws2 `--blob=<name>:@<path>` arguments.
// Custom (uploaded) blobs take precedence over system blobs with the same name.
// The lua variable name is the filename without extension.
func (a *App) blobArgs(names []string) []string {
	var out []string
	for _, n := range names {
		n = filepath.Base(n)
		if n == "" || n == "." {
			continue
		}
		path := filepath.Join(a.blobsDir(), n)
		if _, err := os.Stat(path); err != nil {
			path = filepath.Join(a.Cfg.SystemBlobsDir, n)
			if _, err := os.Stat(path); err != nil {
				continue
			}
		}
		name := strings.TrimSuffix(n, filepath.Ext(n))
		out = append(out, "--blob="+name+":@"+path)
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
