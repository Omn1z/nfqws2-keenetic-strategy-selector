//go:build linux

package app

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"nfqws2strategy/internal/awg"
	"nfqws2strategy/internal/logbuf"
)

// Split-routing: mark selected traffic (by ipset membership) with a fwmark and
// policy-route it into the awg0 tunnel. SAFETY: private/LAN/self and the AWG
// endpoint are always excluded (RETURN) so the router and its management path
// are never pulled into the tunnel; a server-side dead-man's-switch tears the
// whole thing down if the panel doesn't commit in time.
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

// awgExcludes never enter the tunnel — loopback, private/LAN, CGNAT ranges. The
// AWG endpoint is excluded separately (its IP is only known at apply time).
var awgExcludes = []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"}

// awgAccelSysctls are Keenetic's NAT accelerators that cache a forwarded flow's
// path and bypass per-packet netfilter. They CANNOT honor our fwmark→table→awg0
// policy routing: the accelerated fast-path silently DROPS forwarded tunnel
// segments, causing heavy TCP retransmits + exponential backoff (1→2→4→8s) — the
// router's own traffic is fine but LAN devices crawl and Wi-Fi dies. We turn them
// off while routing is active and back on at teardown. The hardware PPE for
// normal LAN↔WAN traffic (net.hwnat.ppe_enabled) is left untouched.
var awgAccelSysctls = []string{
	"net.netfilter.nf_conntrack_fastnat",
	"net.netfilter.nf_conntrack_fastroute",
	"net.core.swnat",
	"net.hwnat.extif_offload",
}

// awgSetAccel toggles Keenetic's NAT accelerators (off while tunnel routing is
// active). Disabling also flushes already-accelerated flows so existing
// connections re-evaluate the route.
func awgSetAccel(on bool) {
	v := "0"
	if on {
		v = "1"
	}
	for _, s := range awgAccelSysctls {
		_, _ = awgRun("sysctl -w " + s + "=" + v + " 2>/dev/null")
	}
	if !on {
		_, _ = awgRun("sysctl -w net.core.swnat_reset=1 2>/dev/null")
	}
}

func awgRun(cmd string) (string, error) {
	ctx, cancel := contextTimeout(15 * time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "sh", "-c", cmd).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func awgDefaultRoute() (gw, dev string) {
	out, _ := awgRun("ip route show default")
	f := strings.Fields(out)
	for i := 0; i+1 < len(f); i++ {
		switch f[i] {
		case "via":
			gw = f[i+1]
		case "dev":
			dev = f[i+1]
		}
	}
	return
}

// awgMarkCollision returns a non-empty fwmark string if some EXISTING ip rule
// uses a fwmark whose bits overlap ours (0x10000000) — which would let our
// higher-priority rule hijack that traffic, or the router's policy routing grab
// ours. The router's own marks (e.g. Keenetic's 0x0FFFFxxx) must not overlap.
func awgMarkCollision() string {
	out, _ := awgRun("ip rule")
	const ourBit = 0x10000000
	for _, ln := range strings.Split(out, "\n") {
		i := strings.Index(ln, "fwmark ")
		if i < 0 {
			continue
		}
		fields := strings.Fields(ln[i+len("fwmark "):])
		if len(fields) == 0 {
			continue
		}
		mark := fields[0]
		if j := strings.IndexByte(mark, '/'); j >= 0 {
			mark = mark[:j]
		}
		v, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimPrefix(mark, "0x"), "0X"), 16, 64)
		if err != nil {
			continue
		}
		if v == ourBit {
			continue // our own rule from a prior run
		}
		if v&ourBit != 0 {
			return mark
		}
	}
	return ""
}

func hostOf(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if i := strings.LastIndex(endpoint, ":"); i > 0 {
		return endpoint[:i]
	}
	return endpoint
}

func resolveHostIP(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if net.ParseIP(host) != nil {
		return host
	}
	for _, ip := range resolveDomain(host) {
		return ip
	}
	return ""
}

// resolveDomain returns the IPv4 addresses for a domain (system resolver).
func resolveDomain(d string) []string {
	d = strings.TrimSpace(d)
	if d == "" {
		return nil
	}
	ips, err := net.LookupIP(d)
	if err != nil {
		return nil
	}
	var out []string
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, v4.String())
		}
	}
	return out
}

// awgZoneMatchers compiles domain matchers from all enabled zones' domain lists.
func awgZoneMatchers(cfg *awg.ServerConfig) []awg.DomainMatcher {
	var entries []string
	for _, z := range cfg.Routing.Zones {
		if z.Enabled {
			entries = append(entries, z.Domains...)
		}
	}
	ms, _ := awg.CompileMatchers(entries)
	return ms
}

// awgTargetSet is the ipset the active mode populates.
func awgTargetSet(mode string) string {
	if mode == "exclude" {
		return awgSetExc
	}
	return awgSetInc
}

// awgEnsureDNSProxy starts/updates the domain-mask DNS proxy when
// domain_source=="dnsproxy" with at least one matcher, otherwise stops it. It
// returns true when the proxy is (now) running, so the firewall hook installs
// the LAN :53 REDIRECT only while the proxy is actually up (never blackhole DNS).
func (a *App) awgEnsureDNSProxy(cfg *awg.ServerConfig, targetSet string) bool {
	ms := awgZoneMatchers(cfg)
	want := cfg.Routing.Mode != "off" && cfg.Routing.DomainSource == "dnsproxy" && len(ms) > 0
	a.awgRoute.mu.Lock()
	p := a.awgRoute.dnsProxy
	a.awgRoute.mu.Unlock()
	if !want {
		if p != nil {
			a.awgStopDNSProxy()
		}
		return false
	}
	if p != nil {
		p.SetMatchers(ms) // refresh on zone change
		return true
	}
	np := awg.NewDNSProxy(awgDNSAddr, awgDNSUpstream, func(ip string) {
		// Add every matched answer IP (idempotent -exist). No dedup cache on purpose:
		// a zone edit flushes the set, and the next DNS query must re-learn cleanly.
		// The target set is read live so a mode switch routes new hits correctly.
		_, _ = awgRun("ipset add " + awgTargetSet(a.awg.Config().Routing.Mode) + " " + ip + " -exist")
	})
	a.awgLoadRecent(np)  // restore domains seen in a previous run (before matching)
	np.SetMatchers(ms)   // re-evaluates the loaded cache → re-adds matching domains
	if err := np.Start(); err != nil {
		logbuf.Append("awg2", "error", "DNS-прокси (маски доменов) не запустился: "+err.Error())
		return false
	}
	a.awgRoute.mu.Lock()
	a.awgRoute.dnsProxy = np
	a.awgRoute.mu.Unlock()
	logbuf.Append("awg2", "info", "DNS-прокси запущен: перехват :53 → домены/поддомены/маски идут в туннель")
	return true
}

// awgStopDNSProxy stops the proxy and removes its LAN :53 REDIRECT rules so DNS
// falls straight back to the router's resolver.
func (a *App) awgStopDNSProxy() {
	a.awgRoute.mu.Lock()
	p := a.awgRoute.dnsProxy
	a.awgRoute.dnsProxy = nil
	a.awgRoute.mu.Unlock()
	if p != nil {
		p.Stop()
	}
	_, _ = awgRun("for br in $(ls /sys/class/net/ 2>/dev/null | grep '^br'); do " +
		"iptables -t nat -D PREROUTING -i $br -p udp --dport 53 -j REDIRECT --to-ports " + awgDNSPort + " 2>/dev/null; " +
		"iptables -t nat -D PREROUTING -i $br -p tcp --dport 53 -j REDIRECT --to-ports " + awgDNSPort + " 2>/dev/null; done")
}

// awgFirewallHook renders the netfilter.d hook that (re)installs the AWG2 marking
// chain + FORWARD/NAT/MSS rules. Every rule is -C-guarded (idempotent) and the
// script self-disables when the tunnel is down, so Keenetic's ndm can run it at
// any time and any number of times. It is also executed directly on apply and by
// the watchdog. mtu is the awg0 MTU; TCP MSS is pinned to mtu-40 in BOTH
// directions with an EXPLICIT value (not --clamp-mss-to-pmtu): on the return path
// (-i awg0) the PMTU clamp resolves to the LAN MTU (1500), not the tunnel, so it
// fails to shrink client→server segments and oversized uploads (large cookies,
// speed-test POSTs) blackhole → pages "load then stall/RESET".
func awgFirewallHook(mode, endpointIP string, mtu int, dnsRedirect bool) string {
	if mtu <= 0 {
		mtu = 1280
	}
	mss := strconv.Itoa(mtu - 40)
	dnsPortHex := "14EA" // 5354 in hex, for the /proc/net/udp listening check
	if p, err := strconv.Atoi(awgDNSPort); err == nil {
		dnsPortHex = fmt.Sprintf("%04X", p)
	}
	ap := func(table, chain, rule string) string {
		b := "iptables -t " + table + " "
		return b + "-C " + chain + " " + rule + " 2>/dev/null || " + b + "-A " + chain + " " + rule + "\n"
	}
	ins := func(table, chain, rule string) string {
		b := "iptables -t " + table + " "
		return b + "-C " + chain + " " + rule + " 2>/dev/null || " + b + "-I " + chain + " 1 " + rule + "\n"
	}
	var s strings.Builder
	s.WriteString("#!/bin/sh\n")
	s.WriteString("# AWG2 split-routing firewall hook — managed by nfqws2-strategy. DO NOT EDIT.\n")
	s.WriteString("# Keenetic re-runs netfilter.d/* after every firewall rebuild (which flushes\n")
	s.WriteString("# foreign iptables chains); this restores the AWG2 marking + FORWARD/NAT/MSS.\n")
	s.WriteString("[ \"$type\" = \"ip6tables\" ] && exit 0\n")
	s.WriteString("ip link show " + awgIface + " >/dev/null 2>&1 || exit 0\n")
	s.WriteString("ipset create " + awgSetInc + " hash:net family inet -exist 2>/dev/null\n")
	s.WriteString("ipset create " + awgSetExc + " hash:net family inet -exist 2>/dev/null\n")
	s.WriteString("iptables -t mangle -N " + awgChain + " 2>/dev/null\n")
	s.WriteString("iptables -t mangle -F " + awgChain + "\n")
	for _, ex := range awgExcludes {
		s.WriteString("iptables -t mangle -A " + awgChain + " -d " + ex + " -j RETURN\n")
	}
	if endpointIP != "" {
		s.WriteString("iptables -t mangle -A " + awgChain + " -d " + endpointIP + "/32 -j RETURN\n")
	}
	switch mode {
	case "include":
		s.WriteString("iptables -t mangle -A " + awgChain + " -m set --match-set " + awgSetInc + " dst -j MARK --set-xmark " + awgMarkRule + "\n")
	case "exclude":
		s.WriteString("iptables -t mangle -A " + awgChain + " -m set ! --match-set " + awgSetExc + " dst -j MARK --set-xmark " + awgMarkRule + "\n")
	case "full":
		s.WriteString("iptables -t mangle -A " + awgChain + " -j MARK --set-xmark " + awgMarkRule + "\n")
	}
	s.WriteString(ap("mangle", "PREROUTING", "-j "+awgChain))
	s.WriteString(ap("mangle", "OUTPUT", "-j "+awgChain))
	// NAT for LAN clients + MSS clamp + allow forwarding LAN<->tunnel. Keenetic's
	// FORWARD policy is DROP and doesn't know awg0, so the ACCEPTs go at the TOP.
	s.WriteString(ap("nat", "POSTROUTING", "-o "+awgIface+" -j MASQUERADE"))
	s.WriteString(ap("mangle", "FORWARD", "-o "+awgIface+" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "+mss))
	s.WriteString(ap("mangle", "FORWARD", "-i "+awgIface+" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "+mss))
	s.WriteString(ins("filter", "FORWARD", "-i "+awgIface+" -j ACCEPT"))
	s.WriteString(ins("filter", "FORWARD", "-o "+awgIface+" -j ACCEPT"))
	if dnsRedirect {
		// Domain-mask DNS interception: redirect LAN :53 to the panel DNS proxy,
		// but ONLY while the proxy is actually listening (so we never blackhole DNS
		// if the proxy is down). Applies to every LAN bridge (br*).
		// Check the proxy is listening via /proc/net/udp (hex port) rather than
		// netstat — busybox netstat can be slow enough on a busy router to stall
		// the hook (and the «Сохранить и применить» request that runs it).
		s.WriteString("if grep -qi ':" + dnsPortHex + " ' /proc/net/udp 2>/dev/null; then\n")
		s.WriteString("  for br in $(ls /sys/class/net/ 2>/dev/null | grep '^br'); do\n")
		for _, proto := range []string{"udp", "tcp"} {
			r := "-i $br -p " + proto + " --dport 53 -j REDIRECT --to-ports " + awgDNSPort
			s.WriteString("    iptables -t nat -C PREROUTING " + r + " 2>/dev/null || iptables -t nat -A PREROUTING " + r + "\n")
		}
		s.WriteString("  done\nfi\n")
	}
	return s.String()
}

// awgWriteHook writes the netfilter.d hook for the given mode/endpoint and runs
// it once immediately (applying the rules now, not just on the next ndm rebuild).
func awgWriteHook(mode, endpointIP string, mtu int, dnsRedirect bool) error {
	if err := os.MkdirAll(filepath.Dir(awgHookPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(awgHookPath, []byte(awgFirewallHook(mode, endpointIP, mtu, dnsRedirect)), 0o755); err != nil {
		return err
	}
	if out, err := awgRun("sh " + awgHookPath); err != nil {
		logbuf.Append("awg2", "warn", "firewall-хук: "+lastLines(out, 2))
	}
	return nil
}

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
	target := awgSetInc
	if r.Mode == "exclude" {
		target = awgSetExc
	}
	dnsOn := a.awgEnsureDNSProxy(&cfg, target)
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

// isMaskEntry reports whether a zone domain entry is a glob/regex mask (which the
// DNS proxy resolves on the fly) rather than a plain resolvable hostname.
func isMaskEntry(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.ContainsAny(s, "*#") || strings.HasPrefix(s, "[re]")
}

func (a *App) awgBuildSets(cfg *awg.ServerConfig) error {
	_, _ = awgRun("ipset create " + awgSetInc + " hash:net family inet -exist")
	_, _ = awgRun("ipset create " + awgSetExc + " hash:net family inet -exist")
	target := awgSetInc
	if cfg.Routing.Mode == "exclude" {
		target = awgSetExc
	}
	// In dnsproxy mode the proxy adds matched IPs dynamically — don't flush them.
	if cfg.Routing.DomainSource != "dnsproxy" {
		_, _ = awgRun("ipset flush " + target)
	}
	n := 0
	for _, z := range cfg.Routing.Zones {
		if !z.Enabled {
			continue
		}
		for _, ip := range z.IPs {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			if _, err := awgRun("ipset add " + target + " " + ip + " -exist"); err == nil {
				n++
			}
		}
		for _, d := range z.Domains {
			// Mask/regex entries (e.g. "2ip.*", "*ip*", "[re]…") can't be resolved as
			// a hostname — trying to (net.LookupHost on a bogus name) blocks on slow
			// DNS timeouts and would hang «Сохранить и применить». The DNS proxy is
			// what matches masks, so skip them here; only PLAIN domains get a direct
			// server-side resolve (which makes them tunnel immediately).
			if isMaskEntry(d) {
				continue
			}
			for _, ip := range resolveDomain(d) {
				_, _ = awgRun("ipset add " + target + " " + ip + "/32 -exist")
				n++
			}
		}
	}
	logbuf.Append("awg2", "info", fmt.Sprintf("ipset %s: %d записей", target, n))
	return nil
}

const awgSetDir = "/opt/etc/nfqws2-strategy"

// awgSaveSets persists the ipset members so the IPs the DNS proxy learned for
// masked domains survive a panel restart / reboot (otherwise those domains fall
// out of the tunnel until each is queried again).
func awgSaveSets() {
	for _, s := range []string{awgSetInc, awgSetExc} {
		_, _ = awgRun("ipset save " + s + " 2>/dev/null > " + awgSetDir + "/" + s + ".ipset 2>/dev/null")
	}
}

// awgRestoreSets re-adds the persisted members into the (already-created) sets.
func awgRestoreSets() {
	for _, s := range []string{awgSetInc, awgSetExc} {
		f := awgSetDir + "/" + s + ".ipset"
		_, _ = awgRun("[ -f " + f + " ] && grep '^add ' " + f + " 2>/dev/null | while read _a st ip _r; do ipset add \"$st\" \"$ip\" -exist 2>/dev/null; done; true")
	}
}

const awgRecentFile = awgSetDir + "/awg2_recent.json"

// awgSaveRecent persists the DNS proxy's recently-seen name→IPs cache so that after
// a panel restart / reboot the masks re-apply to every domain seen before, without
// waiting for the device to look it up again (its DNS cache wouldn't re-query it).
func (a *App) awgSaveRecent() {
	a.awgRoute.mu.Lock()
	p := a.awgRoute.dnsProxy
	a.awgRoute.mu.Unlock()
	if p == nil {
		return
	}
	m := p.SnapshotRecent()
	if len(m) == 0 {
		return
	}
	if b, err := json.Marshal(m); err == nil {
		_ = os.WriteFile(awgRecentFile, b, 0o644)
	}
}

// awgLoadRecent restores the persisted name→IPs cache into a freshly-created proxy.
func (a *App) awgLoadRecent(p *awg.DNSProxy) {
	b, err := os.ReadFile(awgRecentFile)
	if err != nil {
		return
	}
	var m map[string][]string
	if json.Unmarshal(b, &m) == nil && len(m) > 0 {
		p.LoadRecent(m)
	}
}

// awgApplyKillswitch toggles the "Эксклюзивный маршрут" blackhole in the tunnel
// table. ON: a blackhole default (high metric) sits below the awg0 default — while
// awg0 is up the tunnel route wins; the moment awg0 goes down (its route is auto-
// removed) the blackhole catches the marked traffic and DROPS it, so listed sites
// cannot leak to the direct WAN. OFF: no blackhole, so when awg0 is down the marked
// traffic falls through ip-rule to the main table (a normal direct connection).
func awgApplyKillswitch(on bool) {
	if on {
		_, _ = awgRun("ip route replace blackhole default table " + awgTable + " metric 1000")
	} else {
		_, _ = awgRun("ip route del blackhole default table " + awgTable + " metric 1000 2>/dev/null")
	}
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
