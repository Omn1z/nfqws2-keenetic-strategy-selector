//go:build linux

package awgroute

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"nfqws2strategy/internal/tools/logbuf"
)

// Split-routing lifecycle: mark selected traffic (by ipset membership) with a
// fwmark and policy-route it into the awg0 tunnel. SAFETY: private/LAN/self and
// the AWG endpoint are always excluded (RETURN) so the router and its management
// path are never pulled into the tunnel; a server-side dead-man's-switch tears the
// whole thing down if the panel doesn't commit in time.
//
// The pieces live in sibling files (all package awgroute, build tag linux):
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
	// Bind 0.0.0.0 because iptables REDIRECT rewrites dst-IP to the primary IP
	// of the incoming interface (br-lan → 192.168.31.1, br-docker → 172.17.0.1,
	// etc.) — a 127.0.0.1-only socket would miss every redirected packet and
	// kernel would ICMP-unreachable the LAN client. WAN access stays closed via
	// fw3's default DROP on zone_wan_input.
	awgDNSAddr     = "0.0.0.0:5354"
	awgDNSPort     = "5354"
	awgDNSUpstream = "127.0.0.1:53" // Keenetic ndnproxy — the real LAN resolver

	// Pi-hole FTL port — iptables REDIRECT target so pi-hole receives queries
	// directly (preserving client src IP in its query log). Pi-hole then forwards
	// to our proxy on awgDNSPort as its upstream. Mirrors pihole.DefaultDNSPort.
	awgPiholeDNSPort = "5353"

	// awgV6LeakComment tags ip6tables FORWARD REJECT rules added by the firewall
	// hook to block native v6 leaks for "everything via VPN" sources (see the
	// catch-all-include block in awgFirewallHook). The teardown / re-render path
	// uses the comment to flush stale rules even after MAC changes.
	awgV6LeakComment = "awg2-v6-noleak"
)

func (svc *Service) awgApplyRoutingOS() error {
	am := svc.awgActive()
	if am == nil {
		return fmt.Errorf("AWG2-сервер не выбран")
	}
	cfg := am.Config()
	r := cfg.Routing
	if r.Mode == "off" {
		return svc.awgTeardownRoutingOS()
	}
	if err := svc.awgEnsureClientUpForRouting("применения маршрутизации"); err != nil {
		return fmt.Errorf("туннель awg0 не поднят — автоподнятие не удалось: %w", err)
	}
	if other := awgMarkCollision(); other != "" {
		return fmt.Errorf("на роутере уже есть ip rule с пересекающейся fwmark (%s) — применение отменено во избежание конфликта с policy-routing роутера", other)
	}
	endpointIP := resolveHostIP(hostOf(cfg.Endpoint))
	gw, wandev := awgDefaultRoute()
	if endpointIP == "" {
		return fmt.Errorf("не удалось определить IP сервера (endpoint)")
	}
	if wandev == "" {
		return fmt.Errorf("не удалось определить маршрут по умолчанию")
	}
	// 1) pin the endpoint via the ORIGINAL gateway first (prevents the WG loop)
	// 2) ipset membership — force=true so a user-triggered apply always rebuilds
	if err := svc.awgBuildSetsForce(&cfg, true); err != nil {
		return err
	}
	awgResetSNISet()
	// 2b) restore the IPs the DNS proxy learned for masked domains in a previous
	// run so those domains stay in the tunnel across a panel restart / reboot
	// (the kernel set is recreated empty on restart; without this, every masked
	// domain falls out of the tunnel until the device happens to re-query it).
	if awgUsesDNSProxy(&cfg) {
		awgRestoreSets()
	}
	// 1 + 3) endpoint pin + tunnel table + fwmark rule. Keep `rule del` out of
	// checked batches: on a fresh apply it legitimately returns "not found".
	// We do check the route/rule add path — a failed fwmark rule leaves packets
	// marked by iptables but still routed through the native WAN.
	if err := awgRunCheck(awgEndpointRouteCmd(endpointIP, gw, wandev)); err != nil {
		logbuf.Append("awg2", "warn", "не удалось закрепить маршрут до endpoint, продолжаем: "+err.Error())
	}
	if err := awgRunCheck("ip route replace default dev " + awgIface + " table " + awgTable); err != nil {
		return fmt.Errorf("ip tunnel route: %w", err)
	}
	_, _ = awgRun("while ip rule del fwmark " + awgMarkRule + " table " + awgTable + " 2>/dev/null; do :; done")
	if err := awgRunCheck("ip rule add fwmark " + awgMarkRule + " table " + awgTable); err != nil {
		return fmt.Errorf("ip rule: %w", err)
	}
	// 3-v6) IPv6 mirror: separate table state (same id is fine — v4 and v6 are
	// independent), default-route into awg0, fwmark rule. AmneziaWG tunnels both
	// families when MTU/peer allow, so this is enough for IPv6 sites to ride the
	// existing per-source MARK or just the global blanket. Failures here are
	// non-fatal (kernel may lack v6 forwarding), so we don't roll back v4.
	_, _ = awgRun("ip -6 route replace default dev " + awgIface + " table " + awgTable)
	_, _ = awgRun("ip -6 rule del fwmark " + awgMarkRule + " table " + awgTable + " 2>/dev/null")
	_, _ = awgRun("ip -6 rule add fwmark " + awgMarkRule + " table " + awgTable)
	// 3b) killswitch (Эксклюзивный маршрут): a blackhole fallback in the tunnel table
	// so marked traffic is DROPPED (not leaked to the direct WAN) when awg0 is down.
	awgApplyKillswitch(r.Killswitch)
	// 4) domain-mask DNS proxy (optional, domain_source=="dnsproxy"). Start it
	// BEFORE the hook so the hook's DNS REDIRECT is only installed once the proxy
	// is actually listening (never blackhole LAN DNS).
	traceSetEnabled(r.TraceEnabled)
	dnsOn := svc.awgEnsureDNSProxy(&cfg)
	// 4b) optional SNI-routing sniffer (no-op unless sni_routing is on + include mode):
	// learns matched domains' server IPs off the TLS handshake into awg2_sni.
	svc.awgEnsureSNISniff(&cfg)
	// 5) firewall hook (marking chain + FORWARD/NAT/MSS [+ DNS REDIRECT]) — a Keenetic
	// ndm netfilter.d hook so it survives the firewall rebuilds that flush foreign
	// iptables chains; awgWriteHook also applies it immediately.
	if err := awgWriteHook(awgEffectiveMode(r), endpointIP, wandev, r.MTU, dnsOn, svc.dnsChainEnabled(), awgTunnelV6Reaches(), r.Zones); err != nil {
		return fmt.Errorf("firewall-хук: %w", err)
	}
	// 6) disable Keenetic's NAT accelerators — their fast-path silently drops our
	// policy-routed tunnel segments (see awgSetAccel). Restored on teardown.
	awgSetAccel(false)
	// 7) arm the dead-man's switch + start the hook-watchdog / domain refresher
	svc.awgArmRollback(90 * time.Second)
	svc.awgStartRefresh()
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
func (svc *Service) awgRefreshRoutingOS() error {
	am := svc.awgActive()
	if am == nil {
		return fmt.Errorf("AWG2-сервер не выбран")
	}
	cfg := am.Config()
	r := cfg.Routing
	if r.Mode == "off" {
		return svc.awgTeardownRoutingOS()
	}
	if err := svc.awgEnsureClientUpForRouting("обновления зон"); err != nil {
		logbuf.Append("awg2", "warn", "зоны сохранены, но туннель не поднялся автоматически: "+err.Error())
		return err
	}
	endpointIP := resolveHostIP(hostOf(cfg.Endpoint))
	gw, wandev := awgDefaultRoute()
	if endpointIP != "" && wandev != "" {
		_, _ = awgRun(awgEndpointRouteCmd(endpointIP, gw, wandev))
	}
	// A zone/mask edit must drop the IPs learned for the OLD masks — otherwise a
	// removed domain stays tunneled ("старая зона не выгрузилась"). Flush the dynamic
	// set + its on-disk snapshot, then rebuild the explicit IP/CIDR entries; the DNS
	// proxy re-learns the (new) masks on the next query.
	if awgUsesDNSProxy(&cfg) {
		_, _ = awgRun("ipset flush " + awgSetInc)
		_, _ = awgRun("ipset flush " + awgSetExc)
		_ = os.Remove(awgSetDir + "/" + awgSetInc + ".ipset")
		_ = os.Remove(awgSetDir + "/" + awgSetExc + ".ipset")
	}
	// force=true: a config refresh triggered by SetRouting is a user edit (or
	// fresh apply on startup) so the zones may have changed even if their hash
	// happens to look the same after flushing the DNS-proxy-learned entries.
	if err := svc.awgBuildSetsForce(&cfg, true); err != nil {
		return err
	}
	awgResetSNISet()
	_, _ = awgRun("ip route replace default dev " + awgIface + " table " + awgTable)
	_, _ = awgRun("while ip rule del fwmark " + awgMarkRule + " table " + awgTable + " 2>/dev/null; do :; done")
	_, _ = awgRun("ip rule add fwmark " + awgMarkRule + " table " + awgTable)
	awgApplyKillswitch(r.Killswitch)
	traceSetEnabled(r.TraceEnabled)
	dnsOn := svc.awgEnsureDNSProxy(&cfg)
	svc.awgEnsureSNISniff(&cfg) // start/stop/refresh the SNI sniffer to match the new zones
	if err := awgWriteHook(awgEffectiveMode(r), endpointIP, wandev, r.MTU, dnsOn, svc.dnsChainEnabled(), awgTunnelV6Reaches(), r.Zones); err != nil {
		return fmt.Errorf("firewall-хук: %w", err)
	}
	awgSetAccel(false)
	svc.route.mu.Lock()
	svc.route.active = true
	svc.route.mu.Unlock()
	svc.awgStartRefresh() // ensure the watchdog is running (idempotent)
	logbuf.Append("awg2", "info", "зоны применены к туннелю на лету (режим "+r.Mode+")")
	return nil
}

func (svc *Service) awgArmRollback(d time.Duration) {
	svc.route.mu.Lock()
	defer svc.route.mu.Unlock()
	if svc.route.rollback != nil {
		svc.route.rollback.Stop()
	}
	svc.route.active = true
	svc.route.rollback = time.AfterFunc(d, func() {
		defer func() {
			if r := recover(); r != nil {
				logbuf.Append("awg2", "warn", fmt.Sprintf("rollback panic: %v", r))
			}
		}()
		logbuf.Append("awg2", "error", "маршрутизация не подтверждена вовремя — авто-откат")
		if am := svc.awgActive(); am != nil {
			am.SetRoutingActive(false)
		}
		svc.awgSave()
		_ = svc.awgTeardownRoutingOS()
	})
}

// awgStartRefresh runs a 60s watchdog while routing is active: it re-asserts the
// firewall hook (Keenetic may have flushed our chain between rebuilds, and not
// every table rebuild is guaranteed to trigger netfilter.d) and, every ~15 min,
// re-resolves the domain zones into the ipset. It stops when routing is torn down
// (the dead-man's switch / teardown closes stopRefresh), so a rollback is final.
func (svc *Service) awgStartRefresh() {
	svc.route.mu.Lock()
	if svc.route.stopRefresh != nil {
		close(svc.route.stopRefresh)
	}
	stop := make(chan struct{})
	svc.route.stopRefresh = stop
	svc.route.mu.Unlock()
	svc.route.refreshWG.Add(1)
	go func() {
		defer svc.route.refreshWG.Done()
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		ticks := 0
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				// Snapshot the active manager pointer once per tick so a
				// concurrent server-swap can't change svc.awg out from under us
				// mid-tick (would leave the hook + routes installed for the
				// old server's mode/endpoint/MTU).
				am := svc.awgActive()
				if am == nil {
					continue
				}
				c := am.Config()
				if c.Routing.Mode == "off" {
					continue
				}
				// Hash the inputs that drive the firewall hook. When unchanged AND we
				// did a full re-assert recently, skip the expensive block (hook + route
				// + killswitch + accel + sniff) — saves ~4 forks/tick on stable config.
				// Force a full re-assert every 4th tick (≈ every 4 min) anyway so a
				// Keenetic firewall rebuild can't strand us silently for long.
				endpointIP := resolveHostIP(hostOf(c.Endpoint))
				_, wandev := awgDefaultRoute()
				dnsOn := svc.awgEnsureDNSProxy(&c)
				chainOn := svc.dnsChainEnabled()
				h := awgHookInputsHash(awgEffectiveMode(c.Routing), endpointIP, wandev, c.Routing.MTU, dnsOn, chainOn, awgTunnelV6Reaches(), c.Routing.Killswitch, svc.zonesRevision.Load())
				_, hookMissing := os.Stat(awgHookPath)
				// Watchdog hot path: avoid route.mu entirely. lastHookHash is an
				// atomic.Pointer[string] swapped by the most recent re-assert;
				// hookSkipsSinceFull is an atomic.Int32 we tick or reset here.
				var prev string
				if p := svc.route.lastHookHash.Load(); p != nil {
					prev = *p
				}
				same := prev == h && hookMissing == nil
				if !same {
					svc.route.lastHookHash.Store(&h)
					svc.route.hookSkipsSinceFull.Store(0)
				}
				skips := int(svc.route.hookSkipsSinceFull.Load())
				if same && skips < 3 {
					// Cheap path: nothing changed and we re-asserted within the last
					// 3 ticks. Still advance the tick counter for the persistence cadence
					// below so seen domains/sets get snapshotted on schedule.
					svc.route.hookSkipsSinceFull.Add(1)
					ticks++
					if ticks%5 == 0 && awgUsesDNSProxy(&c) {
						awgSaveSets()
						svc.awgSaveRecent()
					}
					continue
				}
				// Full re-assertion (hash changed, hook missing, or backstop fired).
				// Reset the skip counter so the next 3 ticks take the cheap path
				// again — otherwise once skips hits 3 every subsequent tick falls
				// through here forever, defeating the whole skip cache.
				svc.route.hookSkipsSinceFull.Store(0)
				if hookMissing != nil {
					_ = awgWriteHook(awgEffectiveMode(c.Routing), endpointIP, wandev, c.Routing.MTU, dnsOn, chainOn, awgTunnelV6Reaches(), c.Routing.Zones)
				} else {
					_, _ = awgRun("sh " + awgHookPath)
				}
				// re-assert the tunnel default route + killswitch: if awg0 flapped, the
				// kernel drops routes on its device, so re-add the table-998 default and
				// keep the killswitch blackhole in the state the user chose.
				_, _ = awgRun("ip route replace default dev " + awgIface + " table " + awgTable)
				awgApplyKillswitch(c.Routing.Killswitch)
				awgSetAccel(false)        // re-assert: Keenetic may re-enable accelerators on reconfig
				svc.awgEnsureSNISniff(&c) // re-assert the SNI sniffer (idempotent; restarts if a socket died)
				ticks++
				// re-resolve plain domains into the ipset every ~15 min (their IPs drift).
				// Gate on the EFFECTIVE mode: a per-zone config stores Mode=="zones", so the
				// old Mode=="include"/"exclude" check never fired and plain domains went stale.
				weff := awgEffectiveMode(c.Routing)
				if ticks%15 == 0 && (weff == "include" || weff == "exclude") {
					_ = svc.awgBuildSets(&c)
				}
				if ticks%5 == 0 && awgUsesDNSProxy(&c) {
					awgSaveSets()       // persist proxy-learned IPs so they survive a restart/reboot
					svc.awgSaveRecent() // persist seen domains so masks re-apply after a restart
				}
			}
		}
	}()
}

func (svc *Service) awgCommitRoutingOS() error {
	svc.route.mu.Lock()
	if !svc.route.active {
		svc.route.mu.Unlock()
		return fmt.Errorf("маршрутизация не активна")
	}
	if svc.route.rollback != nil {
		svc.route.rollback.Stop()
		svc.route.rollback = nil
	}
	svc.route.mu.Unlock()
	logbuf.Append("awg2", "info", "маршрутизация подтверждена (авто-откат отменён)")
	// Persist OUTSIDE the lock: awgSaveRecent re-acquires svc.route.mu, so calling it
	// while still holding the lock self-deadlocks — which would pin the mutex forever
	// and hang every subsequent routing operation (refresh/teardown/client-down).
	awgSaveSets()       // snapshot the current set members (incl. proxy-learned IPs)
	svc.awgSaveRecent() // snapshot the seen-domains cache too
	return nil
}

func (svc *Service) awgTeardownRoutingOS() error {
	svc.route.mu.Lock()
	if svc.route.rollback != nil {
		svc.route.rollback.Stop()
		svc.route.rollback = nil
	}
	if svc.route.stopRefresh != nil {
		close(svc.route.stopRefresh)
		svc.route.stopRefresh = nil
	}
	svc.route.active = false
	svc.route.mu.Unlock()
	// Wait for any in-flight refresh goroutine to actually exit before we tear
	// the firewall rules down — without this its pending awgRun calls would
	// re-install the rules immediately after teardown removed them, leaving
	// us with a stale "off" state in svc.route but rules still on the host.
	svc.route.refreshWG.Wait()

	svc.awgStopDNSProxy()      // stop the domain-mask proxy + remove its LAN :53 REDIRECT
	svc.awgStopSNISniff()      // stop the SNI sniffer (closes its AF_PACKET sockets)
	awgSetAccel(true)          // restore Keenetic's NAT accelerators (off only while routing active)
	_ = os.Remove(awgHookPath) // stop Keenetic's ndm from re-adding our rules
	_, _ = awgRun("iptables -t mangle -D PREROUTING -j " + awgChain + " 2>/dev/null")
	_, _ = awgRun("iptables -t mangle -D OUTPUT -j " + awgChain + " 2>/dev/null")
	_, _ = awgRun("iptables -t mangle -F " + awgChain + " 2>/dev/null")
	_, _ = awgRun("iptables -t mangle -X " + awgChain + " 2>/dev/null")
	_, _ = awgRun("ip rule del fwmark " + awgMarkRule + " table " + awgTable + " 2>/dev/null")
	_, _ = awgRun("ip route flush table " + awgTable + " 2>/dev/null")
	_, _ = awgRun("iptables -t nat -D POSTROUTING -o " + awgIface + " -j MASQUERADE 2>/dev/null")
	mtu := 1280
	if am := svc.awgActive(); am != nil {
		if v := am.Config().Routing.MTU; v > 0 {
			mtu = v
		}
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
	_, _ = awgRun("ipset destroy " + awgSetSNI + " 2>/dev/null")
	// IPv6 teardown: mirror of the v4 cleanup above (chain detach + flush, ip -6
	// rule + route, per-zone v6 ipsets). Per-zone v4 sets persist across teardown
	// by design (they're rebuilt by awgBuildSourceSets on next apply), so we leave
	// the v6 counterparts alone the same way.
	_, _ = awgRun("ip6tables -t mangle -D PREROUTING -j " + awgChain + "6 2>/dev/null")
	_, _ = awgRun("ip6tables -t mangle -D OUTPUT -j " + awgChain + "6 2>/dev/null")
	_, _ = awgRun("ip6tables -t mangle -F " + awgChain + "6 2>/dev/null")
	_, _ = awgRun("ip6tables -t mangle -X " + awgChain + "6 2>/dev/null")
	_, _ = awgRun("ip -6 rule del fwmark " + awgMarkRule + " table " + awgTable + " 2>/dev/null")
	_, _ = awgRun("ip -6 route flush table " + awgTable + " 2>/dev/null")
	_, _ = awgRun("ip6tables -t nat -D POSTROUTING -o " + awgIface + " -j MASQUERADE 2>/dev/null")
	for _, dir := range []string{"-o", "-i"} {
		_, _ = awgRun("ip6tables -t mangle -D FORWARD " + dir + " " + awgIface + " -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss " + mss + " 2>/dev/null")
	}
	_, _ = awgRun("ip6tables -D FORWARD -i " + awgIface + " -j ACCEPT 2>/dev/null")
	_, _ = awgRun("ip6tables -D FORWARD -o " + awgIface + " -j ACCEPT 2>/dev/null")
	// Strip any leftover v6-noleak rules so disabling split-routing fully restores
	// native v6 for previously-tunneled devices. Comment-tagged rules vary in
	// shape (REJECT vs ACCEPT, with/without --match-set), so delete by line
	// number in reverse — comment-only -D would fail to find them.
	_, _ = awgRun("for n in $(ip6tables -L FORWARD --line-numbers 2>/dev/null | awk '/" + awgV6LeakComment + "/ {print $1}' | sort -rn); do ip6tables -D FORWARD \"$n\" 2>/dev/null; done")
	logbuf.Append("awg2", "info", "маршрутизация снята")
	return nil
}

// awgRepairRoutingOS removes any leaked AWG2 routing state on startup (idempotent).
func (svc *Service) awgRepairRoutingOS() { _ = svc.awgTeardownRoutingOS() }

// awgHookInputsHash fingerprints every input that the watchdog uses to decide
// whether the firewall hook + supporting state needs re-asserting. Zones are
// represented by the monotonic zonesRevision counter (bumped on every config
// edit via awgSave) instead of json.Marshal+sha256(zones) — at 30k entries the
// hash burned several MB of allocs every 60s for the same comparison a counter
// does in 16 bytes.
func awgHookInputsHash(mode, endpointIP, wandev string, mtu int, dnsRedirect, chainEnabled, tunnelV6, killswitch bool, zonesRev int64) string {
	return fmt.Sprintf("%s|%s|%s|%d|%t|%t|%t|%t|%d", mode, endpointIP, wandev, mtu, dnsRedirect, chainEnabled, tunnelV6, killswitch, zonesRev)
}
