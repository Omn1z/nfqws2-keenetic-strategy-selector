package dnsroute

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	hookPath      = "/opt/etc/ndm/netfilter.d/93-nfqws-dns.sh"
	hookSignature = "# NFQWS DNS Server: managed private socket routes"
	postChain     = "N2S_DNS_POST"
	preChain      = "N2S_DNS_PRE"
	inputChain    = "N2S_DNS_IN"
	// Bit31 plus a low-word service signature. AWG writes bits20..28; the
	// NFQWS engine writes bits29/30. Neither changes this routing identity.
	routeMarkBase uint32 = 0x8000d500
	routeMarkMask        = "0x8000ffff"
	// Keenetic's bundled ip rejects numeric table IDs above 1023. Keep this
	// range below that ceiling and below AWG's 901..964 and legacy 998.
	routeTableBase = 700
	routePriority  = 40
	maxRouteSlots  = 128
)

func routeMark(slot int) string     { return fmt.Sprintf("0x%08x", routeMarkBase+uint32(slot)) }
func routeSelector(slot int) string { return routeMark(slot) + "/" + routeMarkMask }

// All interpolated names/addresses come from validation or net.Interfaces.
// ACCEPT here is a mangle-table verdict, scoped to service-marked sockets; it
// prevents the main nfqws chain processing the same packet a second time. It
// does not bypass the filter table or forward any client traffic.
func firewallScript(queue int, listen ListenOptions, iface, subnet string) string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n" + hookSignature + "\nset -e\n")
	b.WriteString(familyFirewall("iptables", queue))
	b.WriteString("if command -v ip6tables >/dev/null 2>&1; then\n(\n")
	b.WriteString(familyFirewall("ip6tables", queue))
	b.WriteString(") || true\nfi\n")
	fam := "iptables"
	if net.ParseIP(listen.Host).To4() == nil {
		fam = "ip6tables"
	}
	ipt := func(args string) { b.WriteString(fam + " -w -t filter " + args + "\n") }
	b.WriteString(fam + " -w -t filter -N " + inputChain + " 2>/dev/null || true\n")
	ipt("-F " + inputChain)
	ipt("-A " + inputChain + " -i lo -j ACCEPT")
	ipt("-A " + inputChain + " -i " + iface + " -s " + subnet + " -j ACCEPT")
	ipt("-A " + inputChain + " -j DROP")
	for _, p := range listenerPorts(listen) {
		rule := "-d " + listen.Host + " -p " + p.protocol + " --dport " + strconv.Itoa(p.port) + " -j " + inputChain
		b.WriteString(fam + " -w -t filter -C INPUT " + rule + " 2>/dev/null || " + fam + " -w -t filter -I INPUT 1 " + rule + "\n")
	}
	return b.String()
}

func familyFirewall(fam string, queue int) string {
	var b strings.Builder
	ipt := func(args string) { b.WriteString(fam + " -w -t mangle " + args + "\n") }
	for _, ch := range []string{postChain, preChain} {
		b.WriteString(fam + " -w -t mangle -N " + ch + " 2>/dev/null || true\n")
		ipt("-F " + ch)
		ipt("-A " + ch + " -m mark --mark 0x40000000/0x40000000 -j ACCEPT")
	}
	ipt("-A " + postChain + " -j CONNMARK --set-xmark " + routeSelector(0))
	for _, x := range []struct{ chain, direction string }{{postChain, "original"}, {preChain, "reply"}} {
		ipt("-A " + x.chain + " -p tcp -m connbytes --connbytes 1:32 --connbytes-mode packets --connbytes-dir " + x.direction + " -j NFQUEUE --queue-num " + strconv.Itoa(queue) + " --queue-bypass")
		ipt("-A " + x.chain + " -j ACCEPT")
	}
	for _, x := range []struct{ parent, chain, match string }{{"POSTROUTING", postChain, "mark"}, {"PREROUTING", preChain, "connmark"}} {
		rule := "-m " + x.match + " --mark " + routeSelector(0) + " -j " + x.chain
		b.WriteString(fam + " -w -t mangle -C " + x.parent + " " + rule + " 2>/dev/null || " + fam + " -w -t mangle -I " + x.parent + " 1 " + rule + "\n")
	}
	return b.String()
}

type listenerPort struct {
	protocol string
	port     int
}

func listenerPorts(l ListenOptions) []listenerPort {
	return []listenerPort{{"tcp", l.DNSPort}, {"udp", l.DNSPort}}
}

// Remove jumps by their exact target, then remove only our own chains. This
// also removes old listening-port rules after a crash or configuration edit.
func cleanupFirewallScript() string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	for _, fam := range []string{"iptables", "ip6tables"} {
		for _, x := range []struct{ table, parent, chain string }{{"mangle", "POSTROUTING", postChain}, {"mangle", "PREROUTING", preChain}, {"filter", "INPUT", inputChain}} {
			// Rule numbers avoid eval or feeding arbitrary firewall text to sh.
			b.WriteString("while :; do\n n=$(" + fam + " -w -t " + x.table + " -L " + x.parent + " --line-numbers -n 2>/dev/null | awk '$2 == \"" + x.chain + "\" {print $1; exit}')\n [ -n \"$n\" ] || break\n " + fam + " -w -t " + x.table + " -D " + x.parent + " \"$n\" 2>/dev/null || break\ndone\n")
			b.WriteString(fam + " -w -t " + x.table + " -F " + x.chain + " 2>/dev/null || true\n")
			b.WriteString(fam + " -w -t " + x.table + " -X " + x.chain + " 2>/dev/null || true\n")
		}
	}
	return b.String()
}
