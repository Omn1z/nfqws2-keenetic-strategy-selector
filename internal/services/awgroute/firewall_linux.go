//go:build linux

package awgroute

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/logbuf"
	"nfqws2strategy/internal/tools/strs"
)

// The netfilter / iptables half of split-routing: the marking chain + FORWARD/NAT/
// MSS rules (installed as a Keenetic ndm netfilter.d hook so they survive firewall
// rebuilds), the NAT-accelerator toggle, and the kill-switch blackhole route.

// awgExcludes never enter the tunnel — loopback, private/LAN, CGNAT ranges. The
// AWG endpoint is excluded separately (its IP is only known at apply time).
var awgExcludes = []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"}

// awgAccelSysctls are Keenetic's NAT accelerators that cache a forwarded flow's
// path and bypass per-packet netfilter. They CANNOT honor our fwmark→table→awg0
// policy routing: the accelerated fast-path silently DROPS forwarded tunnel
// segments, causing heavy TCP retransmits + exponential backoff (1→2→4→8s) — the
// router's own traffic is fine but LAN devices crawl and Wi-Fi dies. We turn them
// off while routing is active and back on at teardown.
var awgAccelSysctls = []string{
	"net.netfilter.nf_conntrack_fastnat",
	"net.netfilter.nf_conntrack_fastroute",
	"net.netfilter.nf_conntrack_fastnat_xfrm",
	"net.netfilter.nf_conntrack_fastpath_esp",
	"net.core.swnat",
	"net.hwnat.extif_offload",
	"net.hwnat.ppe_enabled",
}

// awgSetAccel toggles Keenetic's NAT accelerators (off while tunnel routing is
// active). Disabling also flushes already-accelerated flows so existing
// connections re-evaluate the route.
//
// Batched into ONE sysctl -w invocation. The previous form forked 4-5 times
// per call — every watchdog tick (60s) on the IPQ9554 burned ~50-150 ms on
// idempotent writes. Single fork now.
func awgSetAccel(on bool) {
	v := "0"
	if on {
		v = "1"
	}
	if on {
		_, _ = awgRun("ndmc -c 'ppe hardware' >/dev/null 2>&1; ndmc -c 'ppe software' >/dev/null 2>&1; true")
	} else {
		_, _ = awgRun("ndmc -c 'no ppe hardware' >/dev/null 2>&1; ndmc -c 'no ppe software' >/dev/null 2>&1; true")
	}
	var args []string
	for _, s := range awgAccelSysctls {
		args = append(args, "-w", s+"="+v)
	}
	if !on {
		args = append(args, "-w", "net.core.swnat_reset=1")
	}
	_, _ = awgRun("sysctl " + strings.Join(args, " ") + " 2>/dev/null")
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

// awgFirewallHook renders the netfilter.d hook that (re)installs the AWG2 marking
// chain + FORWARD/NAT/MSS rules. Every rule is -C-guarded (idempotent) and the
// script self-disables when the tunnel is down, so Keenetic's ndm can run it at
// any time and any number of times. It is also executed directly on apply and by
// the watchdog. mtu is the awg0 MTU; TCP MSS is pinned to mtu-40 in BOTH
// directions with an EXPLICIT value (not --clamp-mss-to-pmtu): on the return path
// (-i awg0) the PMTU clamp resolves to the LAN MTU (1500), not the tunnel, so it
// fails to shrink client→server segments and oversized uploads (large cookies,
// speed-test POSTs) blackhole → pages "load then stall/RESET".
func awgFirewallHook(mode, endpointIP, wandev string, mtu int, dnsRedirect, chainEnabled, tunnelV6 bool, zones []awg.Zone) string {
	if mtu <= 0 {
		mtu = 1280
	}
	mss := strconv.Itoa(mtu - 40)
	dnsPortHex := "14EA" // 5354 in hex, for the /proc/net/udp listening check
	if p, err := strconv.Atoi(awgDNSPort); err == nil {
		dnsPortHex = fmt.Sprintf("%04X", p)
	}
	// Every iptables rule we install carries the `awg2-*` comment marker that
	// identifies it as ours. The cleanup loop at the top of the script wipes
	// any rule with such a comment from every shared chain we touch (mangle
	// PREROUTING/OUTPUT/FORWARD, nat PREROUTING/POSTROUTING, filter FORWARD)
	// in both v4 and v6, then the restore docs at the end re-create them.
	// Net: one fork per family for the restore + 12 cleanup forks per re-run
	// (most are no-op listings on a fresh ndm re-render), down from ~24 forks
	// of -C/-A pairs that did the same job.
	//
	// Comment markers (12 chars max — older Linux iptables truncated longer
	// strings):
	//
	//   awg2-jump      mangle PREROUTING/OUTPUT  → -j AWG2_MARK(6)
	//   awg2-mss       mangle FORWARD            → TCPMSS clamp
	//   awg2-nat       nat POSTROUTING           → -j MASQUERADE
	//   awg2-fwd       filter FORWARD            → -i/-o awg0 ACCEPT
	//   awg2-dns       nat PREROUTING            → :53 REDIRECT
	//   awg2-v6-noleak filter FORWARD            → v6 leak prevent (existing)
	cm := func(tag string) string { return ` -m comment --comment "` + tag + `"` }
	ap := func(fam, table, chain, rule string) string {
		b := fam + " -t " + table + " "
		return b + "-C " + chain + " " + rule + " 2>/dev/null || " + b + "-A " + chain + " " + rule + " 2>/dev/null || true\n"
	}
	ins := func(fam, table, chain, rule string) string {
		b := fam + " -t " + table + " "
		return b + "-C " + chain + " " + rule + " 2>/dev/null || " + b + "-I " + chain + " 1 " + rule + " 2>/dev/null || true\n"
	}
	restoreFallback := func(fam, doc string) string {
		var b strings.Builder
		for _, raw := range strings.Split(doc, "\n") {
			ln := strings.TrimSpace(raw)
			switch {
			case ln == "" || ln == "*mangle" || ln == "COMMIT":
				continue
			case strings.HasPrefix(ln, ":"):
				fields := strings.Fields(strings.TrimPrefix(ln, ":"))
				if len(fields) == 0 {
					continue
				}
				chain := fields[0]
				b.WriteString(fam + " -t mangle -N " + chain + " 2>/dev/null || true\n")
				b.WriteString(fam + " -t mangle -F " + chain + " 2>/dev/null || true\n")
			case strings.HasPrefix(ln, "-A "):
				b.WriteString(fam + " -t mangle " + ln + " 2>/dev/null || true\n")
			}
		}
		return b.String()
	}
	var s strings.Builder
	s.Grow(64 << 10)
	s.WriteString("#!/bin/sh\n")
	s.WriteString("# AWG2 split-routing firewall hook — managed by nfqws2-strategy. DO NOT EDIT.\n")
	s.WriteString("# Keenetic re-runs netfilter.d/* after every firewall rebuild (which flushes\n")
	s.WriteString("# foreign iptables chains); this restores the AWG2 marking + FORWARD/NAT/MSS.\n")
	s.WriteString("ip link show " + awgIface + " >/dev/null 2>&1 || exit 0\n")
	s.WriteString("ipset create " + awgSetInc + " hash:net family inet -exist 2>/dev/null\n")
	s.WriteString("ipset create " + awgSetExc + " hash:net family inet -exist 2>/dev/null\n")
	s.WriteString("ipset create " + awgSetSNI + " hash:ip family inet timeout " + strconv.Itoa(awgSNITTL) + " -exist 2>/dev/null\n")
	// Cleanup-by-comment: wipe any stale awg2-* rule from every shared chain
	// we'll re-populate below. Necessary because iptables-restore --noflush
	// APPENDS to shared chains (it does not deduplicate), so without this the
	// hook would pile up duplicate jumps/ACCEPTs on every ndm re-run.
	// Delete by line number in reverse so indexes don't shift mid-loop.
	s.WriteString("for fam in iptables ip6tables; do\n")
	s.WriteString("  for tc in 'mangle PREROUTING' 'mangle OUTPUT' 'mangle FORWARD' 'nat PREROUTING' 'nat POSTROUTING' 'filter FORWARD'; do\n")
	s.WriteString("    set -- $tc\n")
	s.WriteString("    tbl=$1; chn=$2\n")
	s.WriteString("    for n in $(\"$fam\" -t \"$tbl\" -L \"$chn\" --line-numbers 2>/dev/null | awk '/awg2-/ {print $1}' | sort -rn); do\n")
	s.WriteString("      \"$fam\" -t \"$tbl\" -D \"$chn\" \"$n\" 2>/dev/null\n")
	s.WriteString("    done\n")
	s.WriteString("  done\n")
	s.WriteString("done\n")
	// Older builds appended un-commented PREROUTING/OUTPUT jumps via
	// iptables-restore --noflush. Remove them explicitly so every hook run
	// leaves exactly one jump per chain instead of growing the hot path forever.
	s.WriteString("for chn in PREROUTING OUTPUT; do\n")
	s.WriteString("  while iptables -w -t mangle -D \"$chn\" -j " + awgChain + " 2>/dev/null; do :; done\n")
	s.WriteString("  while ip6tables -w -t mangle -D \"$chn\" -j " + awgChain + "6 2>/dev/null; do :; done\n")
	s.WriteString("done\n")

	// v4doc / v6doc are the critical *mangle table documents we'll feed to
	// iptables-restore --noflush. Keep them limited to MARK classification and
	// PREROUTING/OUTPUT jumps: optional targets such as TCPMSS/comment can be
	// missing on some Keenetic builds, and a single unsupported rule would abort
	// the whole restore at COMMIT, leaving full-routing with no MARK path at all.
	var v4doc, v6doc strings.Builder
	v4doc.WriteString("*mangle\n")
	v4doc.WriteString(":" + awgChain + " -\n")
	v4doc.WriteString("-A " + awgChain + " -m mark --mark 0x20000000/0x20000000 -j RETURN\n")
	v4doc.WriteString("-A " + awgChain + " -m mark --mark " + awgMarkRule + " -j RETURN\n")
	for _, ex := range awgExcludes {
		v4doc.WriteString("-A " + awgChain + " -d " + ex + " -j RETURN\n")
	}
	if endpointIP != "" {
		v4doc.WriteString("-A " + awgChain + " -d " + endpointIP + "/32 -j RETURN\n")
	}
	// Per-source-device routing. Zones with `source_ips` apply ONLY to packets
	// from those LAN IPs/CIDRs and are isolated from the global ipsets/mode (see
	// mode.go + sets_linux.go) so they never affect the rest of the LAN.
	//
	// Each source-bound zone owns a per-zone ipset awg2_z<idx> (built in
	// sets_linux.go awgBuildSourceSets) populated with the zone's destinations
	// (resolved domains + IPs/CIDRs). The rule shape depends on whether the
	// zone has destinations:
	//   tunnel + destinations  →  -s SRC -m set --match-set SET dst -j MARK
	//   tunnel + (no dests)    →  -s SRC -j MARK
	//   direct + destinations  →  -s SRC -m set --match-set SET dst -j RETURN
	//   direct + (no dests)    →  -s SRC -j RETURN
	//
	// First-match-wins: chain order = config order. Single pass over
	// sourceBoundZones in array order — the first source-bound zone whose
	// (SRC, dst set) matches a packet decides. The previous two-pass form
	// emitted RETURNs before MARKs unconditionally, which hard-coded "direct
	// always wins" and contradicted the user's stated array priority.
	// emitSrcRule writes one source-bound-zone rule into the given iptables doc.
	// Family-agnostic: the caller passes the chain name, the destination set name
	// (already family-suffixed), and the source-selector clause ("-s 1.2.3.4" for
	// v4, "-m mac --mac-source aa:bb:..." for v6) — that's the only thing that
	// differs between the v4 and v6 mirrors. Used by both passes below.
	emitSrcRule := func(doc *strings.Builder, chain, srcSel, dstSet, target string, hasDsts bool) {
		if hasDsts {
			doc.WriteString("-A " + chain + " " + srcSel +
				" -m set --match-set " + dstSet + " dst -j " + target + "\n")
		} else {
			doc.WriteString("-A " + chain + " " + srcSel + " -j " + target + "\n")
		}
	}
	sb := sourceBoundZones(zones)
	for i, z := range sb {
		target := "MARK --set-xmark " + awgMarkRule
		if z.RouteValue() == "direct" {
			target = "RETURN"
		}
		hasDsts := len(z.Domains) > 0 || len(z.IPs) > 0
		for _, src := range z.SourceIPs {
			src = strings.TrimSpace(src)
			if src == "" {
				continue
			}
			emitSrcRule(&v4doc, awgChain, "-s "+src, sourceZoneSetName(i), target, hasDsts)
		}
	}
	// IPv6 mirror of the per-source rules. Mangle chain AWG2_MARK6 has its own
	// excludes (loopback / ULA / link-local / multicast) so panel access to the
	// router and LAN-internal IPv6 traffic always go direct. Source matching is
	// by MAC (looked up from the IPv4 neighbour cache) because the device's
	// IPv6 source addresses rotate (SLAAC + temporary addresses) but its MAC
	// is stable. If a MAC can't be resolved (device offline at apply time), we
	// skip its v6 rule — the watchdog re-renders the hook so it comes back when
	// the device shows up.
	s.WriteString("ipset create " + awgSetInc + "_6 hash:net family inet6 -exist 2>/dev/null\n")
	s.WriteString("ipset create " + awgSetExc + "_6 hash:net family inet6 -exist 2>/dev/null\n")
	s.WriteString("ipset create " + awgSetSNI + "_6 hash:ip family inet6 timeout " + strconv.Itoa(awgSNITTL) + " -exist 2>/dev/null\n")

	v6doc.WriteString("*mangle\n")
	v6doc.WriteString(":" + awgChain + "6 -\n")
	v6doc.WriteString("-A " + awgChain + "6 -m mark --mark 0x20000000/0x20000000 -j RETURN\n")
	v6doc.WriteString("-A " + awgChain + "6 -m mark --mark " + awgMarkRule + " -j RETURN\n")
	for _, ex := range []string{"::1/128", "fc00::/7", "fe80::/10", "ff00::/8"} {
		v6doc.WriteString("-A " + awgChain + "6 -d " + ex + " -j RETURN\n")
	}
	// Read the neighbour table ONCE for all per-source IPv6 emits instead of
	// forking `ip neigh show <ip>` per source IP per zone. The previous form
	// could fork 20+ times per hook generation; now it's a single fork.
	macBatch := lookupMACBatch()
	// First-match-wins for v6: same single-pass over sb in array order. Reuses
	// emitSrcRule with the v6 chain name and a MAC-based source selector
	// (IPv6 source addresses rotate under SLAAC + temporary addresses; the MAC
	// is stable).
	for i, z := range sb {
		target := "MARK --set-xmark " + awgMarkRule
		if z.RouteValue() == "direct" {
			target = "RETURN"
		}
		hasDsts := len(z.Domains) > 0 || len(z.IPs) > 0
		for _, src := range z.SourceIPs {
			src = strings.TrimSpace(src)
			if src == "" {
				continue
			}
			mac := macBatch[src]
			if mac == "" {
				continue // MAC not in neighbour cache yet — watchdog re-renders
			}
			emitSrcRule(&v6doc, awgChain+"6", "-m mac --mac-source "+mac, sourceZoneSetName6(i), target, hasDsts)
		}
	}
	// IPv6 leak prevention — collected into v6FilterExtras and emitted into
	// the v6doc *filter section below (NOT *mangle — REJECT is a filter
	// target). The generic `awg2-*` cleanup loop at the top of the script
	// already wipes any prior copy of these rules.
	//
	// When the tunnel carries IPv6, all of this is skipped — the mark→table
	// 998 path moves v6 into the tunnel like v4 and there's no leak.
	var v6FilterExtras strings.Builder
	if !tunnelV6 {
		// Per-MAC REJECT for source-bound catch-all-include zones (per-device
		// "all via VPN"). Each goes into v6doc *filter as `-I FORWARD 1` so the
		// per-MAC REJECTs sit on top of the awg2_exc_6 carve-out (the device
		// wants EVERYTHING via VPN, no carve-out applies to it).
		for _, z := range sb {
			if z.RouteValue() != "tunnel" || !zoneHasCatchAll(z) {
				continue
			}
			for _, src := range z.SourceIPs {
				src = strings.TrimSpace(src)
				if src == "" {
					continue
				}
				mac := macBatch[src]
				if mac == "" {
					continue // MAC not in neighbour cache — watchdog re-renders
				}
				v6FilterExtras.WriteString("-I FORWARD 1 -m mac --mac-source " + mac + cm(awgV6LeakComment) +
					" -j REJECT --reject-with icmp6-adm-prohibited\n")
			}
		}
		// Global v6 leak prevention: when the effective mode is full or exclude (= all
		// traffic should ride the tunnel except specific carve-outs), every v6 packet
		// leaving via the WAN device must be REJECTed — the tunnel is v4-only, so v6
		// would otherwise go native WAN.
		//
		// EMISSION ORDER IS REVERSED on purpose: each `-I FORWARD 1` lands at
		// slot 1 and pushes previous rule 1 down to 2. To end up with chain
		// order ACCEPT@1 (carve-out, exclude mode only) then REJECT@2, we emit
		// REJECT FIRST (lands at 1) and ACCEPT SECOND (lands at 1, bumps REJECT
		// to 2). Do not "fix" this ordering — it is load-bearing.
		if wandev != "" && (mode == "full" || mode == "exclude") {
			v6FilterExtras.WriteString("-I FORWARD 1 -o " + wandev + cm(awgV6LeakComment) +
				" -j REJECT --reject-with icmp6-adm-prohibited\n")
			if mode == "exclude" {
				v6FilterExtras.WriteString("-I FORWARD 1 -o " + wandev + " -m set --match-set " + awgSetExc + "_6 dst" +
					cm(awgV6LeakComment) + " -j ACCEPT\n")
			}
		}
	} // end if !tunnelV6
	// mode here is the EFFECTIVE direction derived from the per-zone settings
	// (awgEffectiveMode): "include" = whitelist (only include-zones tunnel),
	// "exclude" = blacklist (everything except exclude-zones), "full" = everything,
	// "" = zones-on-but-empty → nothing marked (all direct).
	switch mode {
	case "include":
		// exclude-zones bypass FIRST (carve-out: they win over an overlapping include
		// CIDR), then include-zones go through the tunnel.
		v4doc.WriteString("-A " + awgChain + " -m set --match-set " + awgSetExc + " dst -j RETURN\n")
		v4doc.WriteString("-A " + awgChain + " -m set --match-set " + awgSetInc + " dst -j MARK --set-xmark " + awgMarkRule + "\n")
		// SNI-learned IPs (awg2_sni) ride the same whitelist as awg2_inc — placed after
		// the exclude RETURN so an excluded domain still wins even if SNI saw it.
		v4doc.WriteString("-A " + awgChain + " -m set --match-set " + awgSetSNI + " dst -j MARK --set-xmark " + awgMarkRule + "\n")
	case "exclude":
		v4doc.WriteString("-A " + awgChain + " -m set ! --match-set " + awgSetExc + " dst -j MARK --set-xmark " + awgMarkRule + "\n")
	case "full":
		v4doc.WriteString("-A " + awgChain + " -j MARK --set-xmark " + awgMarkRule + "\n")
	}
	// Global IPv6 mode rules — mirror of the v4 switch above, against the v6
	// ipsets. Without this an exclude/full mode covers only IPv4 traffic and
	// the LAN's v6 (which Linux prefers when AAAA exists) silently leaks out
	// the native WAN route. The v6 SNI sniffer / DNS proxy populate awg2_*_6.
	//
	// Gated on `tunnelV6`. When the tunnel CANNOT carry v6 (VPS-side v6 SNAT is
	// missing/broken, or the upstream provider blackholes), marking v6 packets
	// into the tunnel routes them via awg0, where they exit BEFORE the FORWARD
	// `-o eth3` leak-prevent REJECT can see them — they then silently blackhole
	// at the VPS. Skipping the global MARK keeps v6 on its native default
	// (eth3), where the REJECT block above ALREADY catches non-RU and the
	// awg2_exc_6 ACCEPT lets RU through → Happy Eyeballs falls back to v4 in
	// ~100ms instead of stalling on a tunnel that can't return.
	if tunnelV6 {
		switch mode {
		case "include":
			v6doc.WriteString("-A " + awgChain + "6 -m set --match-set " + awgSetExc + "_6 dst -j RETURN\n")
			v6doc.WriteString("-A " + awgChain + "6 -m set --match-set " + awgSetInc + "_6 dst -j MARK --set-xmark " + awgMarkRule + "\n")
			v6doc.WriteString("-A " + awgChain + "6 -m set --match-set " + awgSetSNI + "_6 dst -j MARK --set-xmark " + awgMarkRule + "\n")
		case "exclude":
			v6doc.WriteString("-A " + awgChain + "6 -m set ! --match-set " + awgSetExc + "_6 dst -j MARK --set-xmark " + awgMarkRule + "\n")
		case "full":
			v6doc.WriteString("-A " + awgChain + "6 -j MARK --set-xmark " + awgMarkRule + "\n")
		}
	}
	// Critical v4/v6 jumps. Shared-chain NAT/FORWARD/MSS rules are installed
	// below as best-effort one-liners so they cannot poison the mangle restore.
	v4doc.WriteString("-A PREROUTING -j " + awgChain + "\n")
	v4doc.WriteString("-A OUTPUT -j " + awgChain + "\n")
	v4doc.WriteString("COMMIT\n")
	v6doc.WriteString("-A PREROUTING -j " + awgChain + "6\n")
	v6doc.WriteString("-A OUTPUT -j " + awgChain + "6\n")
	v6doc.WriteString("COMMIT\n")
	s.WriteString("if ! iptables-restore --noflush <<'AWGV4'\n")
	s.WriteString(v4doc.String())
	s.WriteString("AWGV4\n")
	s.WriteString("then\n")
	s.WriteString(restoreFallback("iptables", v4doc.String()))
	s.WriteString("fi\n")
	s.WriteString("if ! ip6tables-restore --noflush <<'AWGV6'\n")
	s.WriteString(v6doc.String())
	s.WriteString("AWGV6\n")
	s.WriteString("then\n")
	s.WriteString(restoreFallback("ip6tables", v6doc.String()))
	s.WriteString("fi\n")
	mssRule := func(direction string) string {
		return "-" + direction + " " + awgIface + " -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss " + mss
	}
	s.WriteString(ap("iptables", "nat", "POSTROUTING", "-o "+awgIface+" -j MASQUERADE"))
	s.WriteString(ap("iptables", "mangle", "FORWARD", mssRule("o")))
	s.WriteString(ap("iptables", "mangle", "FORWARD", mssRule("i")))
	s.WriteString(ins("iptables", "filter", "FORWARD", "-i "+awgIface+" -j ACCEPT"))
	s.WriteString(ins("iptables", "filter", "FORWARD", "-o "+awgIface+" -j ACCEPT"))
	s.WriteString(ap("ip6tables", "nat", "POSTROUTING", "-o "+awgIface+" -j MASQUERADE"))
	s.WriteString(ap("ip6tables", "mangle", "FORWARD", mssRule("o")))
	s.WriteString(ap("ip6tables", "mangle", "FORWARD", mssRule("i")))
	s.WriteString(ins("ip6tables", "filter", "FORWARD", "-i "+awgIface+" -j ACCEPT"))
	s.WriteString(ins("ip6tables", "filter", "FORWARD", "-o "+awgIface+" -j ACCEPT"))
	for _, ln := range strings.Split(strings.TrimSpace(v6FilterExtras.String()), "\n") {
		if strings.TrimSpace(ln) != "" {
			s.WriteString("ip6tables -t filter " + ln + " 2>/dev/null || true\n")
		}
	}
	if dnsRedirect {
		// Domain-mask DNS interception: redirect LAN :53 to Pi-hole (:5353), which
		// then forwards to our DNS proxy (:5354) as its upstream. Pi-hole sees the
		// real client IP (not 127.0.0.1) so per-client query logs work. The proxy
		// classifies (SNI/zones) on what pi-hole forwards.
		//
		// We gate on the proxy port being up because pi-hole's upstream is the
		// proxy; if it's down, gating prevents a window where we redirect to
		// pi-hole and pi-hole then can't reach upstream. Check /proc/net/udp +
		// /proc/net/udp6 (Go's 0.0.0.0:5354 listener appears as ":::14EA" on this
		// kernel via dual-stack — invisible to a v4-only grep).
		// Port depends on chain mode. Chain on → pi-hole sits in front, REDIRECT
		// to its FTL port (clients visible in pi-hole's per-client log). Chain off
		// → REDIRECT straight to our proxy, pi-hole is out of the path entirely.
		redirectPort := awgDNSPort
		if chainEnabled {
			redirectPort = awgPiholeDNSPort
		}
		s.WriteString("if grep -qi ':" + dnsPortHex + " ' /proc/net/udp /proc/net/udp6 2>/dev/null; then\n")
		s.WriteString("  for br in $(ls /sys/class/net/ 2>/dev/null | grep '^br'); do\n")
		for _, proto := range []string{"udp", "tcp"} {
			r := "-i $br -p " + proto + " --dport 53 -j REDIRECT --to-ports " + redirectPort
			s.WriteString("    iptables -t nat -C PREROUTING " + r + " 2>/dev/null || iptables -t nat -A PREROUTING " + r + "\n")
			// iOS prefers IPv6 DNS when RA advertises RDNSS; without v6 REDIRECT
			// queries hit the host's native dnsmasq and bypass the chain.
			s.WriteString("    ip6tables -t nat -C PREROUTING " + r + " 2>/dev/null || ip6tables -t nat -A PREROUTING " + r + "\n")
		}
		s.WriteString("  done\nfi\n")
	}
	return s.String()
}

// awgWriteHook writes the netfilter.d hook for the given mode/endpoint and runs
// it once immediately (applying the rules now, not just on the next ndm rebuild).
func awgWriteHook(mode, endpointIP, wandev string, mtu int, dnsRedirect, chainEnabled, tunnelV6 bool, zones []awg.Zone) error {
	if err := os.MkdirAll(filepath.Dir(awgHookPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(awgHookPath, []byte(awgFirewallHook(mode, endpointIP, wandev, mtu, dnsRedirect, chainEnabled, tunnelV6, zones)), 0o755); err != nil {
		return err
	}
	if out, err := awgRun("sh " + awgHookPath); err != nil {
		logbuf.Append("awg2", "warn", "firewall-хук: "+strs.LastLines(out, 2))
	}
	return nil
}
