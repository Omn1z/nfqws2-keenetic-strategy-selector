package awgroute

// Router-side AWG2 client: install OUR self-built engine (amneziawg-go + awg)
// and bring up the local awg0 tunnel as a client of the deployed server. The
// OS-specific work lives in awgclient_{linux,other}.go.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/logbuf"
)

// EngineInfo reports the installed userspace AmneziaWG engine on the router.
type EngineInfo struct {
	Installed  bool   `json:"installed"`
	AwgVersion string `json:"awg_version"`
	Arch       string `json:"arch"`
	Supported  bool   `json:"supported"` // an engine asset exists for this arch
	TunOK      bool   `json:"tun_ok"`    // /dev/net/tun present
	Error      string `json:"error,omitempty"`
}

// ClientStatus is one local awgN tunnel state (from the userspace UAPI socket).
type ClientStatus struct {
	Running       bool   `json:"running"`
	IfacePresent  bool   `json:"iface_present"`
	LastHandshake int64  `json:"last_handshake"`
	RxBytes       int64  `json:"rx_bytes"`
	TxBytes       int64  `json:"tx_bytes"`
	Endpoint      string `json:"endpoint"`
	Address       string `json:"address"`
	MTU           int    `json:"mtu"`
	Connected     bool   `json:"connected"` // handshake within ~180s
	Error         string `json:"error,omitempty"`
}

// AWGConn is one AWG2 tunnel's live state, shaped for the dashboard (state +
// transfer + stats).
type AWGConn struct {
	ID            string `json:"id"`
	Label         string `json:"label"`
	Endpoint      string `json:"endpoint"`
	State         string `json:"state"` // "connected" | "stale" | "down" | "off"
	Connected     bool   `json:"connected"`
	Running       bool   `json:"running"`
	LastHandshake int64  `json:"last_handshake"`
	RxBytes       int64  `json:"rx_bytes"`
	TxBytes       int64  `json:"tx_bytes"`
	MTU           int    `json:"mtu"`
	Address       string `json:"address"`
}

// DashboardConns returns the AWG2 tunnel(s) for the dashboard. Empty (non-nil) when
// no server is configured and nothing is running, so the dashboard hides the card.
func (svc *Service) DashboardConns() []AWGConn {
	out := []AWGConn{}
	svc.mu.RLock()
	entries := make([]*managedServer, 0, len(svc.order))
	for _, id := range svc.order {
		if srv := svc.servers[id]; srv != nil {
			entries = append(entries, srv)
		}
	}
	svc.mu.RUnlock()

	for _, srv := range entries {
		cfg := srv.Manager.Config()
		endpoint := strings.TrimSpace(cfg.Endpoint)
		cs := svc.awgClientStatusManagerOS(srv.Manager) // nil off-router
		if endpoint == "" && (cs == nil || !cs.Running) {
			continue
		}
		c := AWGConn{ID: srv.ID, Label: awgServerLabel(srv, cfg), Endpoint: endpoint, State: "off"}
		if cs != nil {
			c.Connected, c.Running = cs.Connected, cs.Running
			c.LastHandshake, c.RxBytes, c.TxBytes = cs.LastHandshake, cs.RxBytes, cs.TxBytes
			c.MTU, c.Address = cs.MTU, cs.Address
			switch {
			case cs.Connected:
				c.State = "connected"
			case cs.Running:
				c.State = "stale" // iface up but the handshake is old (>~180s)
			default:
				c.State = "down"
			}
		}
		if c.MTU == 0 {
			c.MTU = awgTunnelMTU(cfg)
		}
		if c.Address == "" {
			for _, p := range cfg.Peers {
				if p.IsRouter {
					c.Address = p.Address
					break
				}
			}
		}
		out = append(out, c)
	}
	return out
}

func awgTunnelMTU(cfg awg.ServerConfig) int {
	if cfg.MTU > 0 {
		return cfg.MTU
	}
	if cfg.Routing.MTU > 0 {
		return cfg.Routing.MTU
	}
	return 1280
}

// Public app methods (delegating to the OS impl) used by the server handlers.
func (svc *Service) AWG2EngineInfo() EngineInfo         { return svc.awgEngineInfoOS() }
func (svc *Service) AWG2InstallEngine() (string, error) { return svc.awgInstallEngineOS() }
func (svc *Service) awgClientStatus() *ClientStatus     { return svc.awgClientStatusOS() }

// AWG2ClientUp brings up the local tunnel and persists Client.Enabled=true so it
// autostarts after a panel restart.
func (svc *Service) AWG2ClientUp() error {
	if err := svc.awgEnsureClientUpForRouting("ручного включения"); err != nil {
		return err
	}
	svc.awgRestoreCommittedRoutingAsync("поднятия туннеля")
	return nil
}

func (svc *Service) awgEnsureClientUpForRouting(reason string) error {
	am := svc.awgActive()
	if am == nil {
		return fmt.Errorf("AWG2-сервер не выбран")
	}
	if !am.Enabled() {
		return fmt.Errorf("AWG2-сервер выключен")
	}
	iface := awgClientIfaceName(am.Config())
	if cs := svc.awgClientStatusManagerOS(am); cs != nil && cs.Running {
		if !am.ClientEnabled() {
			am.SetClientEnabled(true)
			svc.route.tunnelUpAt.Store(0)
			svc.awgSave()
		}
		return nil
	} else if cs != nil && cs.IfacePresent {
		logbuf.Append("awg2", "warn", "найден "+iface+" без живого UAPI — пересоздаю туннель для "+reason)
		_ = svc.awgClientDownManagerOS(am)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if _, changed, err := am.EnsureRouterPeer(ctx); err != nil {
		return err
	} else if changed {
		svc.awgSave()
	}
	logbuf.Append("awg2", "info", "туннель "+iface+" не поднят — поднимаю автоматически для "+reason)
	if err := svc.awgClientUpManagerOS(am); err != nil {
		return err
	}
	am.SetClientEnabled(true)
	svc.route.tunnelUpAt.Store(0)
	svc.awgSave()
	return nil
}

// AWG2ClientDown tears down split-routing first (the table points at awg0, which
// is about to disappear), clears the autostart flag, then drops the tunnel.
func (svc *Service) AWG2ClientDown() error {
	svc.awgTeardownRouting()
	var am *awg.Manager
	if active := svc.awgActive(); active != nil {
		am = active
		am.SetClientEnabled(false)
	}
	svc.route.tunnelUpAt.Store(0)
	svc.awgSave()
	return svc.awgClientDownManagerOS(am)
}

// awgRouteState holds the split-routing runtime (dead-man's-switch + refresher
// + the optional domain-mask DNS proxy).
type awgRouteState struct {
	mu          sync.Mutex
	rollback    *time.Timer
	stopRefresh chan struct{}
	active      bool
	dnsProxy    *awg.DNSProxy
	// dnsChainEnabledFlag (atomic.Bool) tracks whether pi-hole sits in front of
	// our proxy. Read on every firewall-hook re-render (watchdog tick) and on
	// every DNS-proxy ensure call, so a lock here would contend with apply
	// paths. Mirror of the bool the pi-hole toggle sets.
	dnsChainEnabledFlag atomic.Bool
	// lastHookHash + hookSkipsSinceFull let the watchdog skip the expensive
	// hook-rerun/route/killswitch/accel/sniff block when the config hasn't
	// changed. We still force a full re-assertion every 4th tick so a Keenetic
	// firewall rebuild can't silently strand us without rules for longer than
	// ~4 minutes. Hot-path reads on the watchdog go through these atomics so
	// the tick doesn't take route.mu just to read a hash + a counter.
	lastHookHash       atomic.Pointer[string]
	hookSkipsSinceFull atomic.Int32
	// refreshWG tracks the refresh goroutine spawned by awgStartRefresh so
	// awgTeardownRoutingOS can wait for it to actually exit before removing
	// firewall rules. Without this, the refresh's pending awgRun calls could
	// re-install the rules immediately after teardown removed them.
	refreshWG sync.WaitGroup
	// First-match-wins ordered zone matchers — single list shared by the DNS
	// proxy's onMatch and onQuery callbacks AND the SNI sniffer's onHello
	// callback. Hot-path readers walk this in array order and the FIRST hit
	// decides tunnel-or-direct. Refreshed atomically on every zones edit; old
	// subscribers keep their snapshot pointer until the next dereference.
	//
	// Replaces the legacy incMatchers/excMatchers/sniMatchers triple — those
	// pre-bucketed by mode and so lost the per-rule array-order signal, which
	// is exactly what first-match-wins relies on.
	orderedMatchers atomic.Pointer[[]orderedZoneMatcher]
	// routeTable is the unified FMW snapshot consumed by Service.routeFor —
	// the single decision point for DNS proxy onMatch/onQuery/AAAA-block and
	// SNI sniffer onHello. Bundles orderedMatchers + source-bound zones +
	// tunnelV6 snapshot so the hot path doesn't probe live state per query.
	// The per-source ipset push in onMatch reads source zones from routeTable
	// too — no parallel srcZoneMatchers atomic anymore.
	routeTable atomic.Pointer[routeTable]

	// Optional SNI-routing sniffer (reads TLS ClientHellos off the LAN bridges and
	// routes matched domains' server IPs via the tunnel — beats DoH + CDN rotation).
	sni *sniSniffer
	// Hot-path cache: dst IPs we've already routed (either by a static ipset rule
	// or a previous SNI match) — skip the regex/glob matcher loop for them on the
	// next ClientHello. unix-seconds of insertion; pruned lazily.
	sniSeen sync.Map // map[string]int64
	// One-shot log suppression for learned domain-to-IP skips on shared CDN edges.
	sharedCDNSkips sync.Map

	// Cached TunnelUp() result: the Telegram proxies call it per connection, so we
	// avoid a UAPI round-trip more than ~once per 5s.
	tunnelUpVal atomic.Bool
	tunnelUpAt  atomic.Int64 // unix nanos of the last probe

	// Hash of the last zones config the watchdog actually built ipsets for. The
	// 15-min refresh ticks compare against this to skip a full re-resolve when
	// the user hasn't touched the zones — which avoids re-warming the geo cache
	// (~150 MB) and re-running thousands of nslookups for no reason.
	lastZonesHash atomic.Pointer[string]

	// Multi-tunnel policy has its own lightweight watchdog. The legacy refresh
	// loop only reasserts AWG2_MARK/table 998 for the active profile; after the
	// multi-server routing switch the live datapath is AWG2_MULTI + table 901+,
	// so it must keep its own hook/routes/fastnat state alive.
	multiStopRefresh chan struct{}
	multiRefreshWG   sync.WaitGroup
}

// TunnelUp reports whether the local AWG2 client tunnel is enabled AND connected
// (a handshake within ~180s). Used by the Telegram proxies to decide whether to
// route the ISP-blocked DCs (1/3/5) through the tunnel. Cached ~5s so per-connection
// callers don't hammer the UAPI socket. Always false on non-router (non-linux) OSes.
func (svc *Service) TunnelUp() bool {
	const ttl = int64(5 * time.Second)
	now := time.Now().UnixNano()
	if at := svc.route.tunnelUpAt.Load(); at != 0 && now-at < ttl {
		return svc.route.tunnelUpVal.Load()
	}
	up := false
	// Hot path: TunnelUp() runs per Telegram blocked-DC dial. Must go through
	// awgActive() — a direct svc.awg read torns on a concurrent server swap.
	if am := svc.awgActive(); am != nil && am.ClientEnabled() {
		if cs := svc.awgClientStatusManagerOS(am); cs != nil && cs.Connected {
			up = true
		}
	}
	svc.route.tunnelUpVal.Store(up)
	svc.route.tunnelUpAt.Store(now)
	return up
}

func (svc *Service) tunnelUpForManagedServer(srv *managedServer) bool {
	if srv == nil || !srv.Manager.Enabled() || !srv.Manager.ClientEnabled() {
		return false
	}
	cs := svc.awgClientStatusManagerOS(srv.Manager)
	return cs != nil && cs.Connected
}

func (svc *Service) TunnelUpForServer(id string) bool {
	id = strings.TrimSpace(id)
	svc.mu.RLock()
	srv := svc.servers[id]
	svc.mu.RUnlock()
	return svc.tunnelUpForManagedServer(srv)
}

// ServerInfo describes one selectable AWG2 server for the Telegram-proxy fallback
// select. The architecture currently has a single server (the awg0 tunnel); the
// list has one entry when a server endpoint is configured, otherwise none.
type ServerInfo struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	ClientIface string `json:"client_iface,omitempty"`
	Connected   bool   `json:"connected"`
}

// Servers lists the AWG2 servers available as a Telegram-proxy fallback target
// (non-nil so it marshals as [] not null).
func (svc *Service) Servers() []ServerInfo {
	svc.mu.RLock()
	entries := make([]*managedServer, 0, len(svc.order))
	for _, id := range svc.order {
		if srv := svc.servers[id]; srv != nil {
			entries = append(entries, srv)
		}
	}
	svc.mu.RUnlock()
	out := make([]ServerInfo, 0, len(entries))
	for _, srv := range entries {
		cfg := srv.Manager.Config()
		if !cfg.Enabled {
			continue
		}
		if strings.TrimSpace(cfg.Endpoint) == "" {
			continue
		}
		out = append(out, ServerInfo{
			ID:          srv.ID,
			Label:       awgServerLabel(srv, cfg),
			ClientIface: awgClientIfaceName(cfg),
			Connected:   svc.tunnelUpForManagedServer(srv),
		})
	}
	return out
}

func (svc *Service) ClientIfaces() []string {
	seen := map[string]bool{}
	out := []string{}
	for _, srv := range svc.serverSnapshot() {
		iface := awgClientIfaceName(srv.Manager.Config())
		if iface == "" || seen[iface] {
			continue
		}
		seen[iface] = true
		out = append(out, iface)
	}
	if !seen["awg0"] {
		out = append(out, "awg0")
	}
	return out
}

// FallbackUp reports whether the AWG2 fallback selected by sel is usable now (its
// tunnel up+connected). sel: ""/"off" → false; "auto" → first available server up;
// "<id>" → that specific server up. Currently a single server (awg0) backs both.
func (svc *Service) FallbackUp(sel string) bool {
	switch sel {
	case "", "off":
		return false
	case "auto":
		for _, srv := range svc.serverSnapshot() {
			if svc.tunnelUpForManagedServer(srv) {
				return true
			}
		}
		return false
	default:
		return svc.TunnelUpForServer(sel)
	}
}

func (svc *Service) FallbackIface(sel string) string {
	switch sel {
	case "", "off":
		return ""
	case "auto":
		for _, srv := range svc.serverSnapshot() {
			if svc.tunnelUpForManagedServer(srv) {
				return awgClientIfaceName(srv.Manager.Config())
			}
		}
		return ""
	default:
		svc.mu.RLock()
		srv := svc.servers[strings.TrimSpace(sel)]
		svc.mu.RUnlock()
		if !svc.tunnelUpForManagedServer(srv) {
			return ""
		}
		return awgClientIfaceName(srv.Manager.Config())
	}
}

func (svc *Service) serverSnapshot() []*managedServer {
	svc.mu.RLock()
	defer svc.mu.RUnlock()
	entries := make([]*managedServer, 0, len(svc.order))
	for _, id := range svc.order {
		if srv := svc.servers[id]; srv != nil {
			entries = append(entries, srv)
		}
	}
	return entries
}

func (svc *Service) AWG2ApplyRouting() error {
	if err := svc.awgApplyRoutingOS(); err != nil {
		return err
	}
	am := svc.awgActive()
	if am == nil {
		return fmt.Errorf("AWG2-сервер не выбран")
	}
	cfg := am.Config()
	am.SetRoutingActive(cfg.Routing.Mode != "off")
	svc.awgSave()
	svc.awgApplyMultiHostRoutesOS()
	return nil
}

// AWG2CommitRouting disarms the dead-man's switch and marks routing committed so
// it auto-applies after a restart/reboot.
func (svc *Service) AWG2CommitRouting() error {
	if err := svc.awgCommitRoutingOS(); err != nil {
		return err
	}
	if am := svc.awgActive(); am != nil {
		am.SetRoutingActive(true)
	}
	svc.awgSave()
	svc.awgApplyMultiHostRoutesOS()
	return nil
}

// AWG2TeardownRouting is the explicit "снять маршрутизацию" action — it clears
// the committed flag so routing does NOT come back on the next boot.
func (svc *Service) AWG2TeardownRouting() error {
	if am := svc.awgActive(); am != nil {
		am.SetRoutingActive(false)
	}
	svc.awgSave()
	svc.awgApplyMultiHostRoutesOS()
	return svc.awgTeardownRoutingOS()
}

func (svc *Service) awgRepairRouting() { svc.awgRepairRoutingOS() }

// awgTeardownRouting is the internal teardown (e.g. on client-down/shutdown). It
// does NOT clear the committed flag, so routing restores when the tunnel returns.
func (svc *Service) awgTeardownRouting() { _ = svc.awgTeardownRoutingOS() }

func (svc *Service) awgRestoreCommittedRoutingAsync(reason string) {
	am := svc.awgActive()
	if am == nil {
		return
	}
	cfg := am.Config()
	if !awgShouldRestoreRouting(cfg) {
		return
	}
	go svc.awgRestoreCommittedRouting(reason)
}

func (svc *Service) awgRestoreCommittedRouting(reason string) {
	am := svc.awgActive()
	if am == nil {
		return
	}
	cfg := am.Config()
	if !awgShouldRestoreRouting(cfg) {
		return
	}
	if err := svc.awgRefreshRoutingOS(); err != nil {
		logbuf.Append("awg2", "warn", "автовосстановление маршрутизации после "+reason+": "+err.Error())
		return
	}
	am.SetRoutingActive(true)
	svc.awgSave()
	svc.awgApplyMultiHostRoutesOS()
	logbuf.Append("awg2", "info", "маршрутизация восстановлена после "+reason)
}

func (svc *Service) awgReconnectActiveClientAfterDeploy(id string) {
	if svc.activeServerID() != id {
		return
	}
	am := svc.awgActive()
	if am == nil {
		return
	}
	cfg := am.Config()
	if !cfg.Client.Enabled {
		return
	}
	if err := svc.awgClientUpOS(); err != nil {
		logbuf.Append("awg2", "warn", "клиент после деплоя не переподнят: "+err.Error())
		return
	}
	svc.route.tunnelUpAt.Store(0)
	svc.awgRestoreCommittedRouting("деплоя сервера")
}
