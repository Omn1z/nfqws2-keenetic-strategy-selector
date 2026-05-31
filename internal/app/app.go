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

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/services/nfqws2"
	"nfqws2strategy/internal/services/strategy/core/catalog"
	"nfqws2strategy/internal/services/strategy/core/engine"
	"nfqws2strategy/internal/services/tgws"
	"nfqws2strategy/internal/tools/auth"
	"nfqws2strategy/internal/tools/config"
	"nfqws2strategy/internal/tools/dns"
	"nfqws2strategy/internal/tools/store"
)

type App struct {
	Cfg   *config.Config
	store *store.Store

	mu             sync.Mutex
	custom         []catalog.Strategy // custom strategies
	sniDomains     []string           // SNI domains to iterate in runs (Strategies tab)
	runs           map[string]*Run    // in-memory runs (id -> run)
	runOrder       []string           // run ids, newest last
	active         *Run               // currently running, if any
	cancel         func()             // cancel for the active run
	addWorker      func(int)          // raises the active run's worker count (add threads live)
	pendingThreads int                // a thread target requested before the worker pool was up (auto baseline phase)

	activeBC *BlockCheck // currently running block check, if any
	cancelBC func()      // cancel for the active block check
	lastBC   *BlockCheck // most recently finished block check (for the final poll)

	sessions         *auth.Sessions
	authEnabled      bool
	loggingDisabled  bool
	httpLogsDisabled bool // suppress the per-request HTTP access log line

	tgws     *tgws.Manager       // Telegram MTProto->WS proxy (Telegram tab)
	socks5   *tgws.Socks5Manager // Telegram SOCKS5 proxy, TGLock-adapted (Telegram tab)
	nfqws2   *nfqws2.Manager     // nfqws2 engine file/version/update/reload (nfqws2 tab)
	awg      *awg.Manager        // AmneziaWG 2.0 server/client manager (AWG2 tab)
	awgRoute awgRouteState       // AWG2 split-routing runtime (dead-man's switch)

	dnsMu      sync.Mutex
	dnsServers []dns.Server // configured DoH/DoT servers (DNS tab + run matrix)

	traceMu    sync.Mutex
	traces     map[string]*Trace // recent device network traces (id -> trace)
	traceOrder []string

	pcapMu    sync.Mutex
	pcaps     map[string]*Pcap // recent tcpdump captures (id -> pcap)
	pcapOrder []string

	blobCapMu    sync.Mutex
	blobCaps     map[string]*BlobCapture // recent ClientHello captures (id -> capture)
	blobCapOrder []string
}

const (
	customStrategiesFile = "strategies_custom.json"
	sniDomainsFile       = "sni_domains.json"
	maxStoredRuns        = 30
)

func New(cfg *config.Config) (*App, error) {
	st, err := store.New(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	a := &App{Cfg: cfg, store: st, runs: map[string]*Run{}, traces: map[string]*Trace{}, pcaps: map[string]*Pcap{}, blobCaps: map[string]*BlobCapture{}, sessions: auth.NewSessions(sessionTTL)}
	a.nfqws2 = nfqws2.New(cfg)
	_ = a.store.Load(customStrategiesFile, &a.custom)
	_ = a.store.Load(sniDomainsFile, &a.sniDomains)
	if err := os.MkdirAll(a.blobsDir(), 0o755); err != nil {
		return nil, err
	}
	a.initAuth()
	a.loadRuns()
	a.initTGWS()
	a.initSocks5()
	a.initAWG() // creates a.awg; may autostart the tunnel + (after a delay) re-apply committed routing
	a.initDNS()
	// Repair any sandbox state leaked by a previous unclean exit (stale STRAT_*
	// iptables chains / orphaned test nfqws2 children). Without this a killed run
	// leaves an exclude-connmark rule that makes the MAIN nfqws2 skip connections.
	engine.CleanupSandboxes(cfg, maxThreads)
	// Clear any leaked AWG2 routing state from an unclean exit. Runs AFTER initAWG
	// (needs a.awg) but BEFORE the autostart goroutine's delayed routing re-apply.
	a.awgRepairRouting()
	return a, nil
}

// Shutdown cancels any active run/block check, tears down every test sandbox
// (iptables chains + orphaned nfqws2 children) and stops the TG WS proxy. It is
// called on SIGTERM so a service stop/restart/update never leaves the main
// nfqws2 service skipping connections. Idempotent.
func (a *App) Shutdown() {
	a.mu.Lock()
	cancel, cancelBC := a.cancel, a.cancelBC
	a.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if cancelBC != nil {
		cancelBC()
	}
	// Give the worker goroutines a moment to run their own teardown, then force a
	// full cleanup in case they were killed before their defers ran.
	time.Sleep(300 * time.Millisecond)
	engine.CleanupSandboxes(a.Cfg, maxThreads)
	a.StopTGWS()
	a.StopSocks5()
	a.StopAWG()
	a.awgTeardownRouting()
}

func (a *App) blobsDir() string { return a.store.Path("blobs") }

// opkgBin returns the Entware opkg path (used by the AWG2 engine install).
func opkgBin() string {
	if _, err := os.Stat("/opt/bin/opkg"); err == nil {
		return "/opt/bin/opkg"
	}
	return "opkg"
}

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
	return luaIdent(strings.TrimSuffix(name, filepath.Ext(name))), path, true
}

// reNonIdent matches characters not allowed in an nfqws2 blob (Lua) identifier.
var reNonIdent = regexp.MustCompile(`[^A-Za-z0-9_]`)

// luaIdent turns a blob filename stem into a valid nfqws2 --blob=NAME identifier.
// Captured/generated blobs are named after the SNI (e.g. clienthello_edge.microsoft.com),
// and nfqws2 rejects dots/dashes as a "bad identifier", so they're folded to '_'.
func luaIdent(s string) string {
	s = reNonIdent.ReplaceAllString(s, "_")
	if s == "" || (s[0] >= '0' && s[0] <= '9') {
		s = "b_" + s
	}
	return s
}

// reFakeBlobRef matches a fake-payload blob reference inside a desync directive
// (e.g. ":blob=tls_clienthello"), but not the "--blob=" definition flag.
var reFakeBlobRef = regexp.MustCompile(`([\s:])blob=[^\s:]+`)

// reSNIRef matches the fake-hello SNI (e.g. "sni=www.google.com") that some
// strategies inject via tls_mod; the value runs to the next ':' or space.
var reSNIRef = regexp.MustCompile(`(sni=)[^\s:]+`)

// SNIDomains returns the user's SNI list (Strategies tab) for run iteration.
func (a *App) SNIDomains() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string{}, a.sniDomains...)
}

// SetSNIDomains persists the SNI domain list used to iterate strategies in runs.
func (a *App) SetSNIDomains(domains []string) ([]string, error) {
	clean := cleanLines(domains)
	a.mu.Lock()
	a.sniDomains = clean
	a.mu.Unlock()
	return clean, a.store.Save(sniDomainsFile, clean)
}

// expandSNIs tests each strategy that injects a fake SNI (sni=) once per domain
// in the list (the user's chosen SNIs first, then the strategy's own SNI as a
// fallback). Strategies without sni= are unchanged; an empty list is a no-op.
func (a *App) expandSNIs(base []catalog.Strategy, domains []string) []catalog.Strategy {
	if len(domains) == 0 {
		return base
	}
	out := make([]catalog.Strategy, 0, len(base)*(len(domains)+1))
	for _, s := range base {
		if !reSNIRef.MatchString(s.ArgLine) {
			out = append(out, s)
			continue
		}
		for _, d := range domains {
			v := s
			v.ID = s.ID + "/sni=" + d
			v.Name = "(sni " + d + ") " + s.Name
			v.ArgLine = reSNIRef.ReplaceAllString(s.ArgLine, "${1}"+d)
			out = append(out, v)
		}
		out = append(out, s) // strategy's own SNI, tested last
	}
	return out
}

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
	out := make([]catalog.Strategy, 0, len(base)*(len(blobs)+1))
	for _, s := range base {
		if !reFakeBlobRef.MatchString(s.ArgLine) {
			out = append(out, s) // blob-independent — test once
			continue
		}
		// Selected blobs first (the user's chosen payloads), then the strategy's
		// own default (tls_clienthello) as a fallback pass.
		for _, b := range blobs {
			v := s
			v.ID = s.ID + "/" + b.lua
			v.Name = "[" + b.lua + "] " + s.Name
			v.ArgLine = "--blob=" + b.lua + ":@" + b.path + " " + reFakeBlobRef.ReplaceAllString(s.ArgLine, "${1}blob="+b.lua)
			out = append(out, v)
		}
		out = append(out, s) // default payload, tested last
	}
	return out
}

// SaveBlob stores an uploaded blob and returns the absolute path to reference
// it in a strategy via --blob=name:@<path>.
func (a *App) SaveBlob(name string, data []byte) (string, error) {
	name, err := sanitizeBlobName(name)
	if err != nil {
		return "", err
	}
	if err := a.store.WriteBytes(filepath.Join("blobs", name), data); err != nil {
		return "", err
	}
	return filepath.Join(a.blobsDir(), name), nil
}

// DeleteBlob soft-deletes a custom (user-uploaded) blob by moving it to the
// recycle bin (TrashedBlobs / RestoreBlob / PurgeBlob). System blobs live
// outside the data dir and are never touched.
func (a *App) DeleteBlob(name string) error {
	name, err := sanitizeBlobName(name)
	if err != nil {
		return err
	}
	return a.trashBlob(name)
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
	out := []string{} // non-nil so an empty list marshals as [] not null (the UI joins it)
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
