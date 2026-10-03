//go:build linux

package awgroute

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	routerpath "nfqws2strategy/internal/tools/path"
)

func (svc *Service) awgMultiPolicyIntact(rules []awgMultiRule, tunnels []awgMultiTunnel, dnsOn bool) bool {
	shared := map[string][]string{}
	for _, t := range tunnels {
		mss := t.MTU - 40
		if mss <= 0 {
			mss = 1240
		}
		shared["nat/POSTROUTING"] = append(shared["nat/POSTROUTING"], "-A POSTROUTING -o "+t.Iface+" -j MASQUERADE")
		shared["filter/FORWARD"] = append(shared["filter/FORWARD"], "-A FORWARD -i "+t.Iface+" -j ACCEPT", "-A FORWARD -o "+t.Iface+" -j ACCEPT")
		for _, dir := range []string{"-i", "-o"} {
			shared["mangle/FORWARD"] = append(shared["mangle/FORWARD"], "-A FORWARD "+dir+" "+t.Iface+" -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "+strconv.Itoa(mss))
		}
	}
	bridges, err := filepath.Glob("/sys/class/net/br*")
	if err != nil {
		return false
	}
	var redirects []string
	if dnsOn {
		port := awgDNSPort
		for _, bridge := range bridges {
			for _, proto := range []string{"udp", "tcp"} {
				redirects = append(redirects, "-A PREROUTING -i "+filepath.Base(bridge)+" -p "+proto+" -m "+proto+" --dport 53 -j REDIRECT --to-ports "+port)
			}
		}
		shared["nat/PREROUTING"] = redirects
	}
	var expected []string
	for _, line := range strings.Split(awgMultiPolicyDocument(tunnels, rules), "\n") {
		if strings.HasPrefix(line, "-A ") {
			expected = append(expected, line)
		}
	}
	snapshot, err := awgRun("iptables-save")
	if err != nil || !awgMultiFirewallIntact(snapshot, awgMultiChain, expected, shared) {
		return false
	}
	if len(redirects) > 0 {
		snapshot, err = awgRun("ip6tables-save -t nat")
		if err != nil || !awgMultiFirewallIntact(snapshot, "", nil, map[string][]string{"nat/PREROUTING": redirects}) {
			return false
		}
	}
	if routerpath.IsOpenWrt() {
		snapshot, err = awgRun("nft list chain inet fw4 forward")
		if err != nil {
			return false
		}
		normalized := strings.Join(strings.Fields(snapshot), " ")
		for _, bridge := range bridges {
			br := filepath.Base(bridge)
			if !strings.HasPrefix(br, "br-") {
				continue
			}
			for _, tunnel := range tunnels {
				for _, pair := range [][2]string{{br, tunnel.Iface}, {tunnel.Iface, br}} {
					want := fmt.Sprintf("iifname %q oifname %q accept comment %q", pair[0], pair[1], "nfqws2-awg2")
					if !strings.Contains(normalized, want) {
						return false
					}
				}
			}
		}
	}
	routeRules, err := awgRun("ip rule show")
	if err != nil {
		return false
	}
	var routeExpected []awgMultiRouteExpectation
	for _, t := range tunnels {
		if !awgMultiHasRouteRule(routeRules, t) {
			return false
		}
		_, linkErr := os.Stat("/sys/class/net/" + t.Iface)
		routeExpected = append(routeExpected, awgMultiRouteExpectation{Table: t.Table, Iface: t.Iface, EndpointIP: t.EndpointIP, Online: linkErr == nil, Killswitch: t.Killswitch})
	}
	routes, err := awgRun("ip -4 route show table all")
	if err != nil {
		return false
	}
	var defaults strings.Builder
	for _, line := range strings.Split(routes, "\n") {
		if strings.HasPrefix(line, "default ") && (!strings.Contains(line, " table ") || strings.Contains(line, " table main ") || strings.HasSuffix(line, " table main") || strings.Contains(line, " table 254 ")) {
			defaults.WriteString(line + "\n")
		}
	}
	gw, wan := selectDefaultRoute(defaults.String())
	if !awgMultiRoutesIntact(routes, gw, wan, routeExpected) {
		return false
	}
	setNames, err := awgRun("ipset list -name")
	if err != nil {
		return false
	}
	sets := map[string]bool{}
	for _, name := range strings.Fields(setNames) {
		sets[name] = true
	}
	for _, rule := range rules {
		if rule.HasDst && !sets[rule.SetName] {
			return false
		}
	}
	for _, sysctl := range awgAccelSysctls {
		value, err := os.ReadFile("/proc/sys/" + strings.ReplaceAll(sysctl, ".", "/"))
		if err == nil && strings.TrimSpace(string(value)) != "0" {
			return false
		}
	}
	return len(tunnels) > 0
}

func awgRefreshMultiSets(rules []awgMultiRule) error {
	var sets []awgMultiSetRefresh
	var save, cleanup strings.Builder
	save.WriteString("set -e\n")
	for _, rule := range rules {
		if !rule.HasDst {
			continue
		}
		sets = append(sets, awgMultiSetRefresh{Name: rule.SetName, Entries: rule.Entries})
		save.WriteString("ipset save " + rule.SetName + "\n")
		cleanup.WriteString("ipset destroy " + rule.SetName + "_r 2>/dev/null || true\n")
	}
	if len(sets) == 0 {
		return nil
	}
	saved, err := awgRun(save.String())
	if err != nil {
		return awgCmdErr("save multi sets", saved, err)
	}
	prepare, commit, err := awgMultiSetRefreshDocuments(sets, saved)
	if err != nil {
		return err
	}
	_, _ = awgRun(cleanup.String())
	defer func() { _, _ = awgRun(cleanup.String()) }()
	return awgCommitMultiSetRefresh(prepare, commit, func(document string) error {
		_, err := awgRunStdin("ipset restore -exist", document)
		return err
	})
}

// Recover missing sets without flushing surviving learned addresses. A real
// create/restore failure remains visible to the gate; do not replace a failed
// staging operation with a destructive flush of the live sets.
func awgEnsureMultiSets(rules []awgMultiRule) error {
	var document strings.Builder
	for _, rule := range rules {
		if rule.HasDst {
			document.WriteString("create " + rule.SetName + " hash:net family inet -exist\n")
		}
	}
	if document.Len() == 0 {
		return nil
	}
	_, err := awgRunStdin("ipset restore -exist", document.String())
	return err
}
