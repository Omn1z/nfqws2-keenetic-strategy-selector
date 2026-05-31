//go:build linux

package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"nfqws2strategy/internal/logbuf"
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
