//go:build linux

package awgroute

import (
	"os"
	"path/filepath"
	"strings"

	"nfqws2strategy/internal/tools/logbuf"
	"nfqws2strategy/internal/tools/shell"
	"nfqws2strategy/internal/tools/strs"
)

// awgFW4ForwardRulesShell returns an idempotent OpenWrt firewall4 snippet.
//
// OpenWrt 25 uses fw4/nftables with a forward policy that only accepts the
// configured WAN zone. The iptables-nft compatibility rules used by the
// legacy/Keenetic path are not enough to permit LAN traffic to a dynamically
// created AWG interface, so insert the required accepts into fw4 itself.
func awgFW4ForwardRulesShell(ifaces []string) string {
	clean := make([]string, 0, len(ifaces))
	seen := make(map[string]struct{}, len(ifaces))
	for _, iface := range ifaces {
		iface = strings.TrimSpace(iface)
		if iface == "" || strings.ContainsAny(iface, " \t\r\n\"'") {
			continue
		}
		if _, ok := seen[iface]; ok {
			continue
		}
		seen[iface] = struct{}{}
		clean = append(clean, iface)
	}
	if len(clean) == 0 {
		return ""
	}

	var s strings.Builder
	s.WriteString("# OpenWrt firewall4 forward accepts for AWG2 (managed).\n")
	s.WriteString("if command -v nft >/dev/null 2>&1 && nft list chain inet fw4 forward >/dev/null 2>&1; then\n")
	s.WriteString("  for h in $(nft -a list chain inet fw4 forward 2>/dev/null | awk '/comment \"nfqws2-awg2\"/ {print $NF}'); do\n")
	s.WriteString("    nft delete rule inet fw4 forward handle \"$h\" 2>/dev/null || true\n")
	s.WriteString("  done\n")
	s.WriteString("  for brpath in /sys/class/net/br-*; do\n")
	s.WriteString("    [ -d \"$brpath\" ] || continue\n")
	s.WriteString("    br=${brpath##*/}\n")
	for _, iface := range clean {
		s.WriteString("    nft insert rule inet fw4 forward iifname \"$br\" oifname \"")
		s.WriteString(iface)
		s.WriteString("\" accept comment \"nfqws2-awg2\" 2>/dev/null || true\n")
		s.WriteString("    nft insert rule inet fw4 forward iifname \"")
		s.WriteString(iface)
		s.WriteString("\" oifname \"$br\" accept comment \"nfqws2-awg2\" 2>/dev/null || true\n")
	}
	s.WriteString("  done\n")
	s.WriteString("fi\n")
	return s.String()
}

// awgEnsureFW4IncludeOS makes the fw4 snippet run after every OpenWrt firewall
// reload. The direct invocation from the AWG hook covers the current process;
// the UCI include is what prevents a later `fw4 reload` from silently dropping
// the forward accepts.
func awgEnsureFW4IncludeOS(ifaces []string) {
	if !openWrtOS() {
		return
	}
	script := awgFW4ForwardRulesShell(ifaces)
	if script == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(awgFW4HookPath), 0o755); err != nil {
		logbuf.Append("awg2", "warn", "fw4-хук: каталог: "+err.Error())
		return
	}
	if err := os.WriteFile(awgFW4HookPath, []byte(script), 0o755); err != nil {
		logbuf.Append("awg2", "warn", "fw4-хук: запись: "+err.Error())
		return
	}
	qpath := shell.Quote(awgFW4HookPath)
	cmd := "if ! command -v uci >/dev/null 2>&1; then exit 0; fi; " +
		"if ! uci -q show firewall.nfqws2_awg2_fw4 >/dev/null 2>&1; then " +
		"uci set firewall.nfqws2_awg2_fw4=include; fi; " +
		"uci set firewall.nfqws2_awg2_fw4.type=script; " +
		"uci set firewall.nfqws2_awg2_fw4.path=" + qpath + "; " +
		"uci set firewall.nfqws2_awg2_fw4.fw4_compatible=1; " +
		"uci commit firewall"
	if out, err := awgRun(cmd); err != nil {
		logbuf.Append("awg2", "warn", "fw4-хук: UCI include: "+strs.LastLines(out, 2))
	}
}

func awgRemoveFW4IncludeOS() {
	if !openWrtOS() {
		return
	}
	_ = os.Remove(awgFW4HookPath)
	_, _ = awgRun("if command -v uci >/dev/null 2>&1; then uci -q delete firewall.nfqws2_awg2_fw4 2>/dev/null || true; uci commit firewall; fi")
}
