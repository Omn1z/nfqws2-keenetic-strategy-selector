// Package awgroute owns the AWG2 capability end-to-end: the remote AmneziaWG 2.0
// server manager (SSH deploy / peers / status) plus the router-side client and
// split-routing runtime — engine install, awg0 tunnel up/down, and the policy
// routing (fwmark → table → awg0) guarded by a server-side dead-man's switch.
// The OS-specific work lives in the *_linux.go / *_other.go files; this package
// was extracted from internal/app, which now keeps thin delegators.
package awgroute

import (
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/config"
	"nfqws2strategy/internal/tools/store"
)

// Service owns the AWG2 server manager + the router-side client/split-routing
// runtime (dead-man's-switch state).
type Service struct {
	cfg   *config.Config
	store *store.Store

	mu       sync.RWMutex
	activeID string
	order    []string
	servers  map[string]*managedServer

	// awg is the currently selected server manager. Low-level client/routing code
	// still operates on one local awg0 tunnel, so it always reads this active one.
	awg   *awg.Manager
	route awgRouteState

	// statusCache memoises the last AWG server Status() result. Status() can
	// hang for up to 25 s when the VPS is slow (SSH, v6 timeouts) — without
	// this the HTTP handler blocks, fronted is forced into ~minute-long
	// retries, and xmir-init's watchdog kills the selector for being
	// unresponsive on :8090. The handler now always returns the cached value
	// instantly and kicks off a background refresh; UI sees fresh data
	// within ~25 s of any refresh request.
	statusMu     sync.Mutex
	statusCached awg.Status
	statusErr    error
	statusBusy   bool
	statusTs     time.Time

	// zonesRevision is bumped every time a server's Routing.Zones is mutated.
	// The watchdog reads it instead of re-hashing zones on every 60s tick, and
	// expandEntries uses it as the cache-validity tag (drop the cached
	// expansion when the revision moves). One monotonic counter saves both
	// hot-paths.
	zonesRevision atomic.Int64
	// expandCache memoises svc.expandEntries by (zone-text, revision). A single
	// apply runs expandEntries ~6× (sets v4/v6, decision build, dnsproxy ensure,
	// source-zone matchers); without this cache each call re-walks the geosite/
	// geoip/list expansion which can be MBs of work per call.
	expandMu    sync.RWMutex
	expandCache map[string]expandCacheEntry
}

type expandCacheEntry struct {
	rev     int64
	domains []string
	ips     []string
}

// BumpZonesRevision invalidates the expand-entries cache and tells the watchdog
// that the zones config has changed. Cheap; safe from any goroutine.
func (svc *Service) BumpZonesRevision() { svc.zonesRevision.Add(1) }

// expandEntriesMemo wraps expandEntriesUncached with a revision-tagged cache.
// Hot caller (apply / refresh / watchdog) calls expandEntries which delegates here.
func (svc *Service) expandEntriesMemo(in []string) ([]string, []string) {
	if len(in) == 0 {
		return nil, nil
	}
	key := strings.Join(in, "\x1f")
	rev := svc.zonesRevision.Load()
	svc.expandMu.RLock()
	if e, ok := svc.expandCache[key]; ok && e.rev == rev {
		d, i := e.domains, e.ips
		svc.expandMu.RUnlock()
		return d, i
	}
	svc.expandMu.RUnlock()
	d, i := svc.expandEntriesUncached(in)
	svc.expandMu.Lock()
	if svc.expandCache == nil {
		svc.expandCache = map[string]expandCacheEntry{}
	}
	// If the revision moved while we computed, drop the now-stale older entries.
	if cur := svc.zonesRevision.Load(); cur != rev {
		svc.expandCache = map[string]expandCacheEntry{}
		rev = cur
	}
	svc.expandCache[key] = expandCacheEntry{rev: rev, domains: d, ips: i}
	svc.expandMu.Unlock()
	return d, i
}

type managedServer struct {
	ID      string
	Name    string
	Manager *awg.Manager
}

// New loads the persisted AWG2 config, creates the server manager, and — if the
// client tunnel was enabled — autostarts it and re-applies committed routing. It
// NEVER auto-deploys the remote VPS (that is always an explicit user action).
func New(cfg *config.Config, st *store.Store) *Service {
	svc := &Service{cfg: cfg, store: st}
	svc.initAWG()
	go svc.awgRouteCacheSweeper()
	go svc.awgFlowTraceLoop()
	return svc
}

// awgRouteCacheSweeper trims TTL-aged entries from caches that the hot path
// only updates lazily: sniSeen (one entry per learned dst-IP) and
// sharedCDNSkips (one per "src:host:ip:provider" tuple). Without this, a long
// uptime accumulates entries that the Load+Delete on re-sight pattern never
// reaches. Runs forever — paired with the Service lifetime.
func (svc *Service) awgRouteCacheSweeper() {
	defer func() { _ = recover() }()
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().Unix() - int64(awgSNITTL)
		svc.route.sniSeen.Range(func(k, v any) bool {
			if ts, _ := v.(int64); ts < cutoff {
				svc.route.sniSeen.Delete(k)
			}
			return true
		})
		// sharedCDNSkips never stores a timestamp (just a presence marker), so
		// TTL pruning isn't possible. Nuke unconditionally — re-learning is
		// cheap (every miss logs once per unique key) and the 10-min cadence
		// keeps the working set bounded without a count pass.
		svc.route.sharedCDNSkips.Range(func(k, _ any) bool {
			svc.route.sharedCDNSkips.Delete(k)
			return true
		})
	}
}

// awgActive returns a stable pointer to the currently-selected AWG manager.
// Callers MUST use this instead of reading svc.awg directly: a concurrent
// AWG2AddServer/SelectServer/DeleteServer can swap svc.awg mid-handler, and
// an unprotected read torns the pointer (or returns nil during the swap).
//
// The returned *awg.Manager remains valid for the lifetime of the handler:
// even if the swap happens immediately after this call, the old Manager is
// still GC-rooted by the caller's local variable and its internal state
// stays consistent (the new active manager is a different object).
func (svc *Service) awgActive() *awg.Manager {
	svc.mu.RLock()
	defer svc.mu.RUnlock()
	return svc.awg
}

// RepairRouting clears any AWG2 routing state leaked by an unclean exit. Called
// at startup, after the manager exists.
func (svc *Service) RepairRouting() { svc.awgRepairRouting() }

// TeardownRouting removes the live split-routing without clearing the committed
// flag (so it restores when the tunnel returns). Called on shutdown.
func (svc *Service) TeardownRouting() { svc.awgTeardownRouting() }

// opkgBin returns the Entware opkg path (used by the AWG2 engine install).
func opkgBin() string {
	if _, err := os.Stat("/opt/bin/opkg"); err == nil {
		return "/opt/bin/opkg"
	}
	return "opkg"
}
