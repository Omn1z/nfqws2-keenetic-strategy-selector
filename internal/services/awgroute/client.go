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

// ClientStatus is the local awg0 tunnel state (from `awg show awg0`).
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
// transfer + stats). Modelled as a list (DashboardConns) so multiple AWG2 servers
// render uniformly later; today there is the single router client tunnel awg0.
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
	cs := svc.awgClientStatus() // nil off-router
	svc.mu.RLock()
	activeID := svc.activeID
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
		isActive := srv.ID == activeID
		if endpoint == "" && (!isActive || cs == nil || !cs.Running) {
			continue
		}
		c := AWGConn{ID: srv.ID, Label: awgServerLabel(srv, cfg), Endpoint: endpoint, State: "off"}
		if isActive && cs != nil {
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
			c.MTU = cfg.Routing.MTU
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

// Public app methods (delegating to the OS impl) used by the server handlers.
func (svc *Service) AWG2EngineInfo() EngineInfo         { return svc.awgEngineInfoOS() }
func (svc *Service) AWG2InstallEngine() (string, error) { return svc.awgInstallEngineOS() }
func (svc *Service) awgClientStatus() *ClientStatus     { return svc.awgClientStatusOS() }

// AWG2ClientUp brings up the local tunnel and persists Client.Enabled=true so it
// autostarts after a panel restart.
func (svc *Service) AWG2ClientUp() error {
	if !svc.awg.Config().Enabled {
		return fmt.Errorf("AWG2-сервер выключен")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if _, changed, err := svc.awg.EnsureRouterPeer(ctx); err != nil {
		return err
	} else if changed {
		svc.awgSave()
	}
	if err := svc.awgClientUpOS(); err != nil {
		return err
	}
	svc.awg.SetClientEnabled(true)
	svc.route.tunnelUpAt.Store(0)
	svc.awgSave()
	return nil
}

// AWG2ClientDown tears down split-routing first (the table points at awg0, which
// is about to disappear), clears the autostart flag, then drops the tunnel.
func (svc *Service) AWG2ClientDown() error {
	svc.awgTeardownRouting()
	svc.awg.SetClientEnabled(false)
	svc.route.tunnelUpAt.Store(0)
	svc.awgSave()
	return svc.awgClientDownOS()
}

// awgRouteState holds the split-routing runtime (dead-man's-switch + refresher
// + the optional domain-mask DNS proxy).
type awgRouteState struct {
	mu          sync.Mutex
	rollback    *time.Timer
	stopRefresh chan struct{}
	active      bool
	dnsProxy    *awg.DNSProxy
	// dnsUpstreamOverride is set when an external service (Pi-hole chain) wants
	// the DNS proxy to forward elsewhere than awgDNSUpstream. Empty = use default.
	// The pi-hole module calls SetDNSUpstream() which both updates this and pushes
	// the new addr into the live DNSProxy without restarting it.
	dnsUpstreamOverride string
	// Per-direction domain matchers for the DNS proxy's onMatch callback (lock-free
	// reads so a DNS answer never blocks on a routing op holding mu). Linux-only use.
	incMatchers atomic.Pointer[[]awg.DomainMatcher]
	excMatchers atomic.Pointer[[]awg.DomainMatcher]
	// Per-source-bound-zone matchers + their per-zone ipset name. The DNS proxy
	// iterates these per query and routes matched IPs to the right awg2_z<idx>
	// so CDN destinations tracked for a specific device stay isolated.
	srcZoneMatchers atomic.Pointer[[]sourceZoneMatchers]

	// Optional SNI-routing sniffer (reads TLS ClientHellos off the LAN bridges and
	// routes matched domains' server IPs via the tunnel — beats DoH + CDN rotation).
	sni         *sniSniffer
	sniMatchers atomic.Pointer[[]awg.DomainMatcher]
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
	if svc.awg.Config().Client.Enabled {
		if cs := svc.awgClientStatusOS(); cs != nil && cs.Connected {
			up = true
		}
	}
	svc.route.tunnelUpVal.Store(up)
	svc.route.tunnelUpAt.Store(now)
	return up
}

// ServerInfo describes one selectable AWG2 server for the Telegram-proxy fallback
// select. The architecture currently has a single server (the awg0 tunnel); the
// list has one entry when a server endpoint is configured, otherwise none.
type ServerInfo struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Connected bool   `json:"connected"`
}

// Servers lists the AWG2 servers available as a Telegram-proxy fallback target
// (non-nil so it marshals as [] not null).
func (svc *Service) Servers() []ServerInfo {
	svc.mu.RLock()
	activeID := svc.activeID
	entries := make([]*managedServer, 0, len(svc.order))
	for _, id := range svc.order {
		if srv := svc.servers[id]; srv != nil {
			entries = append(entries, srv)
		}
	}
	svc.mu.RUnlock()
	up := svc.TunnelUp()
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
			ID:        srv.ID,
			Label:     awgServerLabel(srv, cfg),
			Connected: srv.ID == activeID && up,
		})
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
		return svc.TunnelUp()
	default:
		return sel == svc.activeServerID() && svc.TunnelUp()
	}
}

func (svc *Service) AWG2ApplyRouting() error {
	if err := svc.awgApplyRoutingOS(); err != nil {
		return err
	}
	cfg := svc.awg.Config()
	svc.awg.SetRoutingActive(cfg.Routing.Mode != "off")
	svc.awgSave()
	return nil
}

// AWG2CommitRouting disarms the dead-man's switch and marks routing committed so
// it auto-applies after a restart/reboot.
func (svc *Service) AWG2CommitRouting() error {
	if err := svc.awgCommitRoutingOS(); err != nil {
		return err
	}
	svc.awg.SetRoutingActive(true)
	svc.awgSave()
	return nil
}

// AWG2TeardownRouting is the explicit "снять маршрутизацию" action — it clears
// the committed flag so routing does NOT come back on the next boot.
func (svc *Service) AWG2TeardownRouting() error {
	svc.awg.SetRoutingActive(false)
	svc.awgSave()
	return svc.awgTeardownRoutingOS()
}

func (svc *Service) awgRepairRouting() { svc.awgRepairRoutingOS() }

// awgTeardownRouting is the internal teardown (e.g. on client-down/shutdown). It
// does NOT clear the committed flag, so routing restores when the tunnel returns.
func (svc *Service) awgTeardownRouting() { _ = svc.awgTeardownRoutingOS() }
