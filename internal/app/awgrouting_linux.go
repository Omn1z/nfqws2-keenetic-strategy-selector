//go:build linux

package app

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"nfqws2strategy/internal/logbuf"
)

// Split-routing lifecycle: mark selected traffic (by ipset membership) with a
// fwmark and policy-route it into the awg0 tunnel. SAFETY: private/LAN/self and
// the AWG endpoint are always excluded (RETURN) so the router and its management
// path are never pulled into the tunnel; a server-side dead-man's-switch tears the
// whole thing down if the panel doesn't commit in time.
//
// The pieces live in sibling files (all package app, build tag linux):
//   - awgfirewall_linux.go — the netfilter hook + NAT/MSS + accel + kill-switch
//   - awgsets_linux.go      — ipset membership + ipset/recent persistence
//   - awgdnsproxy_linux.go  — the domain-mask DNS proxy lifecycle
//   - awgutil_linux.go      — awgRun, route/mark inspection, host resolution
//
// PERSISTENCE: Keenetic's ndm periodically rebuilds the firewall and FLUSHES all
// foreign iptables chains — our marking chain + FORWARD/NAT/MSS rules vanish and
// nothing gets marked, so split-routing silently stops. We therefore install the
// iptables half as a Keenetic netfilter.d hook (re-run by ndm after every
// rebuild, exactly like nfqws2's 100-nfqws2.sh) and also re-assert it from a
// 60s watchdog. The ip rule / ip route table / ipset are NOT touched by Keenetic,
// so they live directly in the kernel.

const (
	awgTable = "998" // dedicated routing table for tunneled traffic
	// fwmark bit 28. MUST be clear of (a) Keenetic's own policy-routing marks,
	// which are 0x0FFFFxxx (bits 0–27) — an earlier 0x40000 (bit 18) collided with
	// them and our higher-priority ip rule hijacked ALL of Keenetic's policy traffic
	// → full outage — and (b) nfqws2's marks 0x40000000/0x20000000 (bits 30/29).
	awgMark     = "0x10000000"
	awgMarkRule = awgMark + "/" + awgMark
	awgChain    = "AWG2_MARK"
	awgSetInc   = "awg2_inc"
	awgSetExc   = "awg2_exc"
	// awgHookPath is the Keenetic ndm netfilter.d hook that re-installs our
	// iptables state after each firewall rebuild. Prefixed 90- to run after
	// Keenetic's own setup (and our nfqws2's 100- hook is independent).
	awgHookPath = "/opt/etc/ndm/netfilter.d/90-awg2.sh"

	// Domain-mask DNS proxy: transparently intercepts LAN :53 (via an iptables
	// REDIRECT in the hook) and adds the IPs of matching names to the ipset.
	awgDNSAddr     = "127.0.0.1:5354"
	awgDNSPort     = "5354"
	awgDNSUpstream = "127.0.0.1:53" // Keenetic ndnproxy — the real LAN resolver
)

func (a *App) awgApplyRoutingOS() error {
	cfg := a.awg.Config()
	r := cfg.Routing
	if r.Mode == "off" {
		return a.awgTeardownRoutingOS()
	}
	if cs := a.awgClientStatusOS(); cs == nil || !cs.IfacePresent {
		return fmt.Errorf("туннель awg0 не поднят — сначала «Поднять туннель»")
	}
	if other := awgMarkCollision(); other != "" {
		return fmt.Errorf("на роутере уже есть ip rule с пересекающейся fwmark (%s) — применение отменено во избежание конфликта с policy-routing роутера", other)
	}
	endpointIP := resolveHostIP(hostOf(cfg.Endpoint))
	gw, wandev := awgDefaultRoute()
	if endpointIP == "" {
		return fmt.Errorf("не удалось определить IP сервера (endpoint)")
	}
	if gw == "" || wandev == "" {
		return fmt.Errorf("не удалось определить маршрут по умолчанию")
	}
	// 1) pin the endpoint via the ORIGINAL gateway first (prevents the WG loop)
	_, _ = awgRun("ip route replace " + endpointIP + "/32 via " + gw + " dev " + wandev)
	// 2) ipset membership
	if err := a.awgBuildSets(&cfg); err != nil {
		return err
	}
	// 2b) restore the IPs the DNS proxy learned for masked domains in a previous
	// run so those domains stay in the tunnel across a panel restart / reboot
	// (the kernel set is recreated empty on restart; without this, every masked
	// domain falls out of the tunnel until the device happens to re-query it).
	if r.DomainSource == "dnsproxy" {
		awgRestoreSets()
	}
	// 3) tunnel table + fwmark rule (survive Keenetic reloads on their own)
	_, _ = awgRun("ip route replace default dev " + awgIface + " table " + awgTable)
	_, _ = awgRun("ip rule del fwmark " + awgMarkRule + " table " + awgTable + " 2>/dev/null")
	if _, err := awgRun("ip rule add fwmark " + awgMarkRule + " table " + awgTable); err != nil {
		return fmt.Errorf("ip rule: %w", err)
	}
	// 3b) killswitch (Эксклюзивный маршрут): a blackhole fallback in the tunnel table
	// so marked traffic is DROPPED (not leaked to the direct WAN) when awg0 is down.
	awgApplyKillswitch(r.Killswitch)
	// 4) domain-mask DNS proxy (optional, domain_source=="dnsproxy"). Start it
	// BEFORE the hook so the hook's DNS REDIRECT is only installed once the proxy
	// is actually listening (never blackhole LAN DNS).
	dnsOn := a.awgEnsureDNSProxy(&cfg, awgTargetSet(r.Mode))
	// 5) firewall hook (marking chain + FORWARD/NAT/MSS [+ DNS REDIRECT]) — a Keenetic
	// ndm netfilter.d hook so it survives the firewall rebuilds that flush foreign
	// iptables chains; awgWriteHook also applies it immediately.
	if err := awgWriteHook(r.Mode, endpointIP, r.MTU, dnsOn); err != nil {
		return fmt.Errorf("firewall-хук: %w", err)
	}
	// 6) disable Keenetic's NAT accelerators — their fast-path silently drops our
	// policy-routed tunnel segments (see awgSetAccel). Restored on teardown.
	awgSetAccel(false)
	// 7) arm the dead-man's switch + start the hook-watchdog / domain refresher
	a.awgArmRollback(90 * time.Second)
	a.awgStartRefresh()
	logbuf.Append("awg2", "info", "маршрутизация применена (режим "+r.Mode+") — подтвердите в течение 90с, иначе авто-откат")
	return nil
}

// awgRefreshRoutingOS re-applies the CURRENT (already-active) routing config to the
// live tunnel after a zone/mask/mode/killswitch edit — rebuilding ipset membership,
// refreshing the DNS-proxy matchers, re-writing the firewall hook and re-asserting
// the killswitch — WITHOUT arming the dead-man's switch. This is safe because a
// membership/matcher/mode change never affects panel reachability: LAN, private
// ranges, the router itself and the VPN endpoint are always excluded from the
// tunnel in every mode, so the panel stays reachable by its LAN IP throughout.
func (a *App) awgRefreshRoutingOS() error {
	cfg := a.awg.Config()
	r := cfg.Routing
	if r.Mode == "off" {
		return a.awgTeardownRoutingOS()
	}
	if cs := a.awgClientStatusOS(); cs == nil || !cs.IfacePresent {
		// Tunnel not up — nothing live to refresh; the config is already persisted
		// and will be applied when the tunnel comes up / on the next «Применить».
		logbuf.Append("awg2", "info", "зоны сохранены; туннель не поднят — применятся при поднятии")
		return nil
	}
	endpointIP := resolveHostIP(hostOf(cfg.Endpoint))
	if gw, wandev := awgDefaultRoute(); endpointIP != "" && gw != "" && wandev != "" {
		_, _ = awgRun("ip route replace " + endpointIP + "/32 via " + gw + " dev " + wandev)
	}
	// A zone/mask edit must drop the IPs learned for the OLD masks — otherwise a
	// removed domain stays tunneled ("старая зона не выгрузилась"). Flush the dynamic
	// set + its on-disk snapshot, then rebuild the explicit IP/CIDR entries; the DNS
	// proxy re-learns the (new) masks on the next query.
	if r.DomainSource == "dnsproxy" {
		_, _ = awgRun("ipset flush " + awgTargetSet(r.Mode))
		_ = os.Remove(awgSetDir + "/" + awgTargetSet(r.Mode) + ".ipset")
	}
	if err := a.awgBuildSets(&cfg); err != nil {
		return err
	}
	_, _ = awgRun("ip route replace default dev " + awgIface + " table " + awgTable)
	_, _ = awgRun("ip rule del fwmark " + awgMarkRule + " table " + awgTable + " 2>/dev/null")
	_, _ = awgRun("ip rule add fwmark " + awgMarkRule + " table " + awgTable + " 2>/dev/null")
	awgApplyKillswitch(r.Killswitch)
	dnsOn := a.awgEnsureDNSProxy(&cfg, awgTargetSet(r.Mode))
	if err := awgWriteHook(r.Mode, endpointIP, r.MTU, dnsOn); err != nil {
		return fmt.Errorf("firewall-хук: %w", err)
	}
	awgSetAccel(false)
	a.awgStartRefresh() // ensure the watchdog is running (idempotent)
	logbuf.Append("awg2", "info", "зоны применены к туннелю на лету (режим "+r.Mode+")")
	return nil
}

func (a *App) awgArmRollback(d time.Duration) {
	a.awgRoute.mu.Lock()
	defer a.awgRoute.mu.Unlock()
	if a.awgRoute.rollback != nil {
		a.awgRoute.rollback.Stop()
	}
	a.awgRoute.active = true
	a.awgRoute.rollback = time.AfterFunc(d, func() {
		logbuf.Append("awg2", "error", "маршрутизация не подтверждена вовремя — авто-откат")
		_ = a.awgTeardownRoutingOS()
	})
}

// awgStartRefresh runs a 60s watchdog while routing is active: it re-asserts the
// firewall hook (Keenetic may have flushed our chain between rebuilds, and not
// every table rebuild is guaranteed to trigger netfilter.d) and, every ~15 min,
// re-resolves the domain zones into the ipset. It stops when routing is torn down
// (the dead-man's switch / teardown closes stopRefresh), so a rollback is final.
func (a *App) awgStartRefresh() {
	a.awgRoute.mu.Lock()
	if a.awgRoute.stopRefresh != nil {
		close(a.awgRoute.stopRefresh)
	}
	stop := make(chan struct{})
	a.awgRoute.stopRefresh = stop
	a.awgRoute.mu.Unlock()
	go func() {
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		ticks := 0
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				c := a.awg.Config()
				if c.Routing.Mode == "off" {
					continue
				}
				// re-assert the firewall hook: rewrite the file if Keenetic/anything
				// removed it, otherwise just re-run it (fast, idempotent).
				if _, err := os.Stat(awgHookPath); err != nil {
					_ = awgWriteHook(c.Routing.Mode, resolveHostIP(hostOf(c.Endpoint)), c.Routing.MTU, a.awgEnsureDNSProxy(&c, awgTargetSet(c.Routing.Mode)))
				} else {
					_, _ = awgRun("sh " + awgHookPath)
				}
				// re-assert the tunnel default route + killswitch: if awg0 flapped, the
				// kernel drops routes on its device, so re-add the table-998 default and
				// keep the killswitch blackhole in the state the user chose.
				_, _ = awgRun("ip route replace default dev " + awgIface + " table " + awgTable)
				awgApplyKillswitch(c.Routing.Killswitch)
				awgSetAccel(false) // re-assert: Keenetic may re-enable accelerators on reconfig
				ticks++
				if ticks%15 == 0 && (c.Routing.Mode == "include" || c.Routing.Mode == "exclude") {
					_ = a.awgBuildSets(&c)
				}
				if ticks%5 == 0 && c.Routing.DomainSource == "dnsproxy" {
					awgSaveSets()     // persist proxy-learned IPs so they survive a restart/reboot
					a.awgSaveRecent() // persist seen domains so masks re-apply after a restart
				}
			}
		}
	}()
}

func (a *App) awgCommitRoutingOS() error {
	a.awgRoute.mu.Lock()
	if !a.awgRoute.active {
		a.awgRoute.mu.Unlock()
		return fmt.Errorf("маршрутизация не активна")
	}
	if a.awgRoute.rollback != nil {
		a.awgRoute.rollback.Stop()
		a.awgRoute.rollback = nil
	}
	a.awgRoute.mu.Unlock()
	logbuf.Append("awg2", "info", "маршрутизация подтверждена (авто-откат отменён)")
	// Persist OUTSIDE the lock: awgSaveRecent re-acquires a.awgRoute.mu, so calling it
	// while still holding the lock self-deadlocks — which would pin the mutex forever
	// and hang every subsequent routing operation (refresh/teardown/client-down).
	awgSaveSets()     // snapshot the current set members (incl. proxy-learned IPs)
	a.awgSaveRecent() // snapshot the seen-domains cache too
	return nil
}

func (a *App) awgTeardownRoutingOS() error {
	a.awgRoute.mu.Lock()
	if a.awgRoute.rollback != nil {
		a.awgRoute.rollback.Stop()
		a.awgRoute.rollback = nil
	}
	if a.awgRoute.stopRefresh != nil {
		close(a.awgRoute.stopRefresh)
		a.awgRoute.stopRefresh = nil
	}
	a.awgRoute.active = false
	a.awgRoute.mu.Unlock()

	a.awgStopDNSProxy()        // stop the domain-mask proxy + remove its LAN :53 REDIRECT
	awgSetAccel(true)          // restore Keenetic's NAT accelerators (off only while routing active)
	_ = os.Remove(awgHookPath) // stop Keenetic's ndm from re-adding our rules
	_, _ = awgRun("iptables -t mangle -D PREROUTING -j " + awgChain + " 2>/dev/null")
	_, _ = awgRun("iptables -t mangle -D OUTPUT -j " + awgChain + " 2>/dev/null")
	_, _ = awgRun("iptables -t mangle -F " + awgChain + " 2>/dev/null")
	_, _ = awgRun("iptables -t mangle -X " + awgChain + " 2>/dev/null")
	_, _ = awgRun("ip rule del fwmark " + awgMarkRule + " table " + awgTable + " 2>/dev/null")
	_, _ = awgRun("ip route flush table " + awgTable + " 2>/dev/null")
	_, _ = awgRun("iptables -t nat -D POSTROUTING -o " + awgIface + " -j MASQUERADE 2>/dev/null")
	mtu := a.awg.Config().Routing.MTU
	if mtu <= 0 {
		mtu = 1280
	}
	mss := strconv.Itoa(mtu - 40)
	for _, dir := range []string{"-o", "-i"} {
		_, _ = awgRun("iptables -t mangle -D FORWARD " + dir + " " + awgIface + " -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss " + mss + " 2>/dev/null")
		_, _ = awgRun("iptables -t mangle -D FORWARD " + dir + " " + awgIface + " -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null")
	}
	_, _ = awgRun("iptables -D FORWARD -i " + awgIface + " -j ACCEPT 2>/dev/null")
	_, _ = awgRun("iptables -D FORWARD -o " + awgIface + " -j ACCEPT 2>/dev/null")
	_, _ = awgRun("ipset destroy " + awgSetInc + " 2>/dev/null")
	_, _ = awgRun("ipset destroy " + awgSetExc + " 2>/dev/null")
	logbuf.Append("awg2", "info", "маршрутизация снята")
	return nil
}

// awgRepairRoutingOS removes any leaked AWG2 routing state on startup (idempotent).
func (a *App) awgRepairRoutingOS() { _ = a.awgTeardownRoutingOS() }
