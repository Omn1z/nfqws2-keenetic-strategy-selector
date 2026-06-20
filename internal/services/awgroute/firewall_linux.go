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
func awgFirewallHook(mode, endpointIP string, mtu int, dnsRedirect bool, zones []awg.Zone) string {
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
	// The hook now installs BOTH iptables and ip6tables state in one run, so we no
	// longer bail out when ndm invokes it for the ip6tables family — that earlier
	// guard would have skipped the v6 chain entirely.
	s.WriteString("ip link show " + awgIface + " >/dev/null 2>&1 || exit 0\n")
	s.WriteString("ipset create " + awgSetInc + " hash:net family inet -exist 2>/dev/null\n")
	s.WriteString("ipset create " + awgSetExc + " hash:net family inet -exist 2>/dev/null\n")
	// SNI-learned server IPs (short-lived); always created so the include rule below
	// loads even when SNI-routing is off (then the set is simply empty = no matches).
	s.WriteString("ipset create " + awgSetSNI + " hash:ip family inet timeout " + strconv.Itoa(awgSNITTL) + " -exist 2>/dev/null\n")
	s.WriteString("iptables -t mangle -N " + awgChain + " 2>/dev/null\n")
	s.WriteString("iptables -t mangle -F " + awgChain + "\n")
	for _, ex := range awgExcludes {
		s.WriteString("iptables -t mangle -A " + awgChain + " -d " + ex + " -j RETURN\n")
	}
	if endpointIP != "" {
		s.WriteString("iptables -t mangle -A " + awgChain + " -d " + endpointIP + "/32 -j RETURN\n")
	}
	// Per-source-device routing. Zones with `source_ips` apply ONLY to packets
	// from those LAN IPs/CIDRs and are isolated from the global ipsets/mode (see
	// mode.go + sets_linux.go) so they never affect the rest of the LAN.
	//
	// Each source-bound zone owns a per-zone ipset awg2_z<idx> (built in
	// sets_linux.go awgBuildSourceSets) populated with the zone's destinations
	// (resolved domains + IPs/CIDRs). The rule shape depends on whether the zone
	// has destinations:
	//   include + destinations  →  -s SRC -m set --match-set SET dst -j MARK
	//                              (only those destinations tunnel for this source)
	//   include + (no dests)    →  -s SRC -j MARK
	//                              (whole-source tunnel; respects awg2_exc below)
	//   exclude + destinations  →  -s SRC -m set --match-set SET dst -j RETURN
	//                              (those destinations bypass for this source)
	//   exclude + (no dests)    →  -s SRC -j RETURN
	//                              (whole-source bypass; sources go direct)
	//
	// Order matters: exclude RETURNs come FIRST so a destination listed in an
	// exclude carve-out wins over the broader include MARK for the same source.
	emitSourceRule := func(z awg.Zone, idx int, target string) {
		hasDsts := len(z.Domains) > 0 || len(z.IPs) > 0
		for _, src := range z.SourceIPs {
			src = strings.TrimSpace(src)
			if src == "" {
				continue
			}
			if hasDsts {
				s.WriteString("iptables -t mangle -A " + awgChain + " -s " + src +
					" -m set --match-set " + sourceZoneSetName(idx) + " dst -j " + target + "\n")
			} else {
				s.WriteString("iptables -t mangle -A " + awgChain + " -s " + src + " -j " + target + "\n")
			}
		}
	}
	sb := sourceBoundZones(zones)
	for i, z := range sb {
		if z.Mode == "exclude" {
			emitSourceRule(z, i, "RETURN")
		}
	}
	for i, z := range sb {
		if z.Mode == "include" {
			emitSourceRule(z, i, "MARK --set-xmark "+awgMarkRule)
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
	s.WriteString("ip6tables -t mangle -N " + awgChain + "6 2>/dev/null\n")
	s.WriteString("ip6tables -t mangle -F " + awgChain + "6\n")
	for _, ex := range []string{"::1/128", "fc00::/7", "fe80::/10", "ff00::/8"} {
		s.WriteString("ip6tables -t mangle -A " + awgChain + "6 -d " + ex + " -j RETURN\n")
	}
	emitSourceRule6 := func(z awg.Zone, idx int, target string) {
		hasDsts := len(z.Domains) > 0 || len(z.IPs) > 0
		for _, src := range z.SourceIPs {
			src = strings.TrimSpace(src)
			if src == "" {
				continue
			}
			mac := lookupMAC(src)
			if mac == "" {
				continue // MAC not in neighbour cache yet — watchdog re-renders
			}
			if hasDsts {
				s.WriteString("ip6tables -t mangle -A " + awgChain + "6 -m mac --mac-source " + mac +
					" -m set --match-set " + sourceZoneSetName6(idx) + " dst -j " + target + "\n")
			} else {
				s.WriteString("ip6tables -t mangle -A " + awgChain + "6 -m mac --mac-source " + mac + " -j " + target + "\n")
			}
		}
	}
	for i, z := range sb {
		if z.Mode == "exclude" {
			emitSourceRule6(z, i, "RETURN")
		}
	}
	for i, z := range sb {
		if z.Mode == "include" {
			emitSourceRule6(z, i, "MARK --set-xmark "+awgMarkRule)
		}
	}
	// mode here is the EFFECTIVE direction derived from the per-zone settings
	// (awgEffectiveMode): "include" = whitelist (only include-zones tunnel),
	// "exclude" = blacklist (everything except exclude-zones), "full" = everything,
	// "" = zones-on-but-empty → nothing marked (all direct).
	switch mode {
	case "include":
		// exclude-zones bypass FIRST (carve-out: they win over an overlapping include
		// CIDR), then include-zones go through the tunnel.
		s.WriteString("iptables -t mangle -A " + awgChain + " -m set --match-set " + awgSetExc + " dst -j RETURN\n")
		s.WriteString("iptables -t mangle -A " + awgChain + " -m set --match-set " + awgSetInc + " dst -j MARK --set-xmark " + awgMarkRule + "\n")
		// SNI-learned IPs (awg2_sni) ride the same whitelist as awg2_inc — placed after
		// the exclude RETURN so an excluded domain still wins even if SNI saw it.
		s.WriteString("iptables -t mangle -A " + awgChain + " -m set --match-set " + awgSetSNI + " dst -j MARK --set-xmark " + awgMarkRule + "\n")
	case "exclude":
		s.WriteString("iptables -t mangle -A " + awgChain + " -m set ! --match-set " + awgSetExc + " dst -j MARK --set-xmark " + awgMarkRule + "\n")
	case "full":
		s.WriteString("iptables -t mangle -A " + awgChain + " -j MARK --set-xmark " + awgMarkRule + "\n")
	}
	// Global IPv6 mode rules — mirror of the v4 switch above, against the v6
	// ipsets. Without this an exclude/full mode covers only IPv4 traffic and
	// the LAN's v6 (which Linux prefers when AAAA exists) silently leaks out
	// the native WAN route. The v6 SNI sniffer / DNS proxy populate awg2_*_6.
	switch mode {
	case "include":
		s.WriteString("ip6tables -t mangle -A " + awgChain + "6 -m set --match-set " + awgSetExc + "_6 dst -j RETURN\n")
		s.WriteString("ip6tables -t mangle -A " + awgChain + "6 -m set --match-set " + awgSetInc + "_6 dst -j MARK --set-xmark " + awgMarkRule + "\n")
		s.WriteString("ip6tables -t mangle -A " + awgChain + "6 -m set --match-set " + awgSetSNI + "_6 dst -j MARK --set-xmark " + awgMarkRule + "\n")
	case "exclude":
		s.WriteString("ip6tables -t mangle -A " + awgChain + "6 -m set ! --match-set " + awgSetExc + "_6 dst -j MARK --set-xmark " + awgMarkRule + "\n")
	case "full":
		s.WriteString("ip6tables -t mangle -A " + awgChain + "6 -j MARK --set-xmark " + awgMarkRule + "\n")
	}
	s.WriteString(ap("mangle", "PREROUTING", "-j "+awgChain))
	s.WriteString(ap("mangle", "OUTPUT", "-j "+awgChain))
	// IPv6 jumps + FORWARD/NAT. Mirror of the v4 wiring above; ip6tables matches
	// on its own table even though the chain name AWG2_MARK6 differs.
	ap6 := func(table, chain, rule string) string {
		b := "ip6tables -t " + table + " "
		return b + "-C " + chain + " " + rule + " 2>/dev/null || " + b + "-A " + chain + " " + rule + "\n"
	}
	ins6 := func(table, chain, rule string) string {
		b := "ip6tables -t " + table + " "
		return b + "-C " + chain + " " + rule + " 2>/dev/null || " + b + "-I " + chain + " 1 " + rule + "\n"
	}
	s.WriteString(ap6("mangle", "PREROUTING", "-j "+awgChain+"6"))
	s.WriteString(ap6("mangle", "OUTPUT", "-j "+awgChain+"6"))
	s.WriteString(ap6("nat", "POSTROUTING", "-o "+awgIface+" -j MASQUERADE"))
	s.WriteString(ap6("mangle", "FORWARD", "-o "+awgIface+" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "+mss))
	s.WriteString(ap6("mangle", "FORWARD", "-i "+awgIface+" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "+mss))
	s.WriteString(ins6("filter", "FORWARD", "-i "+awgIface+" -j ACCEPT"))
	s.WriteString(ins6("filter", "FORWARD", "-o "+awgIface+" -j ACCEPT"))
	// NAT for LAN clients + MSS clamp + allow forwarding LAN<->tunnel. Keenetic's
	// FORWARD policy is DROP and doesn't know awg0, so the ACCEPTs go at the TOP.
	s.WriteString(ap("nat", "POSTROUTING", "-o "+awgIface+" -j MASQUERADE"))
	s.WriteString(ap("mangle", "FORWARD", "-o "+awgIface+" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "+mss))
	s.WriteString(ap("mangle", "FORWARD", "-i "+awgIface+" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "+mss))
	s.WriteString(ins("filter", "FORWARD", "-i "+awgIface+" -j ACCEPT"))
	s.WriteString(ins("filter", "FORWARD", "-o "+awgIface+" -j ACCEPT"))
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
		s.WriteString("if grep -qi ':" + dnsPortHex + " ' /proc/net/udp /proc/net/udp6 2>/dev/null; then\n")
		s.WriteString("  for br in $(ls /sys/class/net/ 2>/dev/null | grep '^br'); do\n")
		for _, proto := range []string{"udp", "tcp"} {
			r := "-i $br -p " + proto + " --dport 53 -j REDIRECT --to-ports " + awgPiholeDNSPort
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
func awgWriteHook(mode, endpointIP string, mtu int, dnsRedirect bool, zones []awg.Zone) error {
	if err := os.MkdirAll(filepath.Dir(awgHookPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(awgHookPath, []byte(awgFirewallHook(mode, endpointIP, mtu, dnsRedirect, zones)), 0o755); err != nil {
		return err
	}
	if out, err := awgRun("sh " + awgHookPath); err != nil {
		logbuf.Append("awg2", "warn", "firewall-хук: "+lastLines(out, 2))
	}
	return nil
}
