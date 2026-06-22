//go:build linux

package awgroute

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/logbuf"
)

const (
	awgMultiHookPath  = "/opt/etc/ndm/netfilter.d/91-awg2-multi.sh"
	awgMultiChain     = "AWG2_MULTI"
	awgMultiSetPrefix = "awgm"
	awgMultiTableBase = 900
	awgMultiPrefBase  = 70
	awgMultiMarkMask  = "0x1ff00000"
	awgMultiMax       = 64
)

type awgMultiTunnel struct {
	ID         string
	Iface      string
	EndpointIP string
	Table      int
	Mark       string
	MTU        int
	Killswitch bool
}

type awgMultiRule struct {
	Zone      awg.Zone
	Tunnel    *awgMultiTunnel
	SetName   string
	Entries   []string
	HasDst    bool
	CatchAll  bool
	Sources   []string
	StaticOK  bool
	RuleIndex int
}

func (svc *Service) awgApplyMultiPolicyOS() error {
	rules, tunnels := svc.awgBuildMultiPolicy()
	svc.awgClearLegacyPolicyOS()
	svc.awgClearMultiPolicyOS()
	if len(rules) == 0 || len(tunnels) == 0 {
		awgSetAccel(true)
		return nil
	}
	if err := awgWriteMultiSets(rules); err != nil {
		return err
	}
	if err := svc.awgInstallMultiRoutes(tunnels); err != nil {
		return err
	}
	if err := awgWriteMultiHook(tunnels, rules); err != nil {
		return err
	}
	awgSetAccel(false)
	svc.awgStartMultiPolicyRefresh()
	logbuf.Append("awg2", "info", "multi-routing: policy rules applied: "+strconv.Itoa(len(rules)))
	return nil
}

func (svc *Service) awgBuildMultiPolicy() ([]awgMultiRule, []awgMultiTunnel) {
	servers := map[string]*managedServer{}
	for _, srv := range svc.serverSnapshot() {
		servers[srv.ID] = srv
	}
	tunnelByID := map[string]*awgMultiTunnel{}
	tunnelOrder := []string{}
	getTunnel := func(srv *managedServer) *awgMultiTunnel {
		if srv == nil {
			return nil
		}
		if t := tunnelByID[srv.ID]; t != nil {
			return t
		}
		cfg := srv.Manager.Config()
		if !cfg.Enabled || cfg.Routing.Mode == "off" || !cfg.Routing.Active {
			return nil
		}
		iface := awgClientIfaceName(cfg)
		if !validAWGClientIfaceName(iface) || strings.TrimSpace(cfg.Endpoint) == "" {
			return nil
		}
		if cs := svc.awgClientStatusManagerOS(srv.Manager); cs == nil || !cs.Running {
			if awgCanStartLocalClient(cfg) {
				if err := svc.awgClientUpManagerOS(srv.Manager); err != nil {
					logbuf.Append("awg2", "warn", "multi-routing: tunnel "+iface+" is not up: "+err.Error())
					return nil
				}
				srv.Manager.SetClientEnabled(true)
				svc.awgSave()
			}
		} else if !cfg.Client.Enabled {
			srv.Manager.SetClientEnabled(true)
			svc.awgSave()
		}
		endpointIP := resolveHostIP(hostOf(cfg.Endpoint))
		if endpointIP == "" {
			logbuf.Append("awg2", "warn", "multi-routing: endpoint is not resolved for "+iface)
			return nil
		}
		if len(tunnelOrder) >= awgMultiMax {
			logbuf.Append("awg2", "warn", "multi-routing: too many tunnels, skipping "+iface)
			return nil
		}
		slot := len(tunnelOrder) + 1
		t := &awgMultiTunnel{
			ID:         srv.ID,
			Iface:      iface,
			EndpointIP: endpointIP,
			Table:      awgMultiTableBase + slot,
			Mark:       awgMultiMark(slot),
			MTU:        awgTunnelMTU(cfg),
			Killswitch: cfg.Routing.Killswitch,
		}
		tunnelByID[srv.ID] = t
		tunnelOrder = append(tunnelOrder, srv.ID)
		return t
	}

	out := []awgMultiRule{}
	for i, z := range svc.awgRoutingRules() {
		if !z.Enabled {
			continue
		}
		srv := servers[strings.TrimSpace(z.TunnelID)]
		if srv == nil {
			continue
		}
		cfg := srv.Manager.Config()
		if !cfg.Enabled || cfg.Routing.Mode == "off" || !cfg.Routing.Active {
			continue
		}
		route := z.RouteValue()
		var tun *awgMultiTunnel
		if route == "tunnel" {
			tun = getTunnel(srv)
			if tun == nil {
				continue
			}
		}
		r := awgMultiRule{
			Zone:      z,
			Tunnel:    tun,
			SetName:   awgMultiSetName(i),
			Sources:   awgCleanMultiSources(z.SourceIPs),
			RuleIndex: i,
		}
		r.Entries, r.CatchAll, r.StaticOK = svc.awgMultiRuleEntries(z)
		r.HasDst = len(r.Entries) > 0
		if !r.CatchAll && !r.HasDst && !r.StaticOK {
			logbuf.Append("awg2", "warn", "multi-routing: rule "+z.Name+" has only dynamic domain masks and was skipped")
			continue
		}
		out = append(out, r)
	}
	tunnels := make([]awgMultiTunnel, 0, len(tunnelOrder))
	for _, id := range tunnelOrder {
		if t := tunnelByID[id]; t != nil {
			tunnels = append(tunnels, *t)
		}
	}
	return out, tunnels
}

func (svc *Service) awgMultiRuleEntries(z awg.Zone) ([]string, bool, bool) {
	seen := map[string]bool{}
	out := []string{}
	add := func(raw string) {
		if ent, ok := awgNormalizeMultiEntry(raw); ok && !seen[ent] {
			seen[ent] = true
			out = append(out, ent)
		}
	}
	catchAll := z.IsCatchAll()
	staticOK := len(z.Domains) == 0 && len(z.IPs) == 0
	expDomains, expIPs := svc.expandEntries(z.Domains)
	for _, ip := range append(append([]string{}, z.IPs...), expIPs...) {
		if awgIsCatchAll(ip) {
			catchAll = true
			staticOK = true
			continue
		}
		before := len(out)
		add(ip)
		if len(out) > before {
			staticOK = true
		}
	}
	for _, d := range expDomains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if awgIsCatchAll(d) {
			catchAll = true
			staticOK = true
			continue
		}
		if isMaskEntry(d) {
			continue
		}
		for _, ip := range resolveDomainAll(d) {
			before := len(out)
			add(ip)
			if len(out) > before {
				staticOK = true
			}
		}
	}
	sort.Strings(out)
	return out, catchAll, staticOK
}

func awgNormalizeMultiEntry(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" || s == "*" {
		return "", false
	}
	if ip := net.ParseIP(s); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String() + "/32", true
		}
		return "", false
	}
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		return "", false
	}
	if v4 := ip.To4(); v4 != nil {
		n.IP = v4
		return n.String(), true
	}
	return "", false
}

func awgCleanMultiSources(in []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" || strings.Contains(s, ":") {
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				s = v4.String()
			} else {
				continue
			}
		} else if ip, n, err := net.ParseCIDR(s); err == nil {
			if v4 := ip.To4(); v4 != nil {
				n.IP = v4
				s = n.String()
			} else {
				continue
			}
		} else {
			continue
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func awgWriteMultiSets(rules []awgMultiRule) error {
	var b strings.Builder
	for _, r := range rules {
		if !r.HasDst {
			continue
		}
		b.WriteString("create " + r.SetName + " hash:net family inet -exist\n")
		b.WriteString("flush " + r.SetName + "\n")
		for _, ent := range r.Entries {
			b.WriteString("add " + r.SetName + " " + ent + " -exist\n")
		}
	}
	if b.Len() == 0 {
		return nil
	}
	if _, err := awgRunStdin("ipset restore -exist", b.String()); err != nil {
		return fmt.Errorf("ipset restore (multi): %w", err)
	}
	return nil
}

func (svc *Service) awgInstallMultiRoutes(tunnels []awgMultiTunnel) error {
	gw, wandev := awgDefaultRoute()
	var firstErr error
	for _, t := range tunnels {
		if t.EndpointIP != "" && wandev != "" {
			if err := awgRunCheck(awgEndpointRouteCmd(t.EndpointIP, gw, wandev)); err != nil {
				logbuf.Append("awg2", "warn", "multi-routing: endpoint route "+t.EndpointIP+": "+err.Error())
			}
		}
		if err := awgRunCheck("ip route replace default dev " + t.Iface + " table " + strconv.Itoa(t.Table)); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("ip tunnel route %s: %w", t.Iface, err)
		}
		_, _ = awgRun("ip rule add pref " + strconv.Itoa(awgMultiPref(t)) + " fwmark " + t.Mark + "/" + awgMultiMarkMask + " table " + strconv.Itoa(t.Table) + " 2>/dev/null")
		if t.Killswitch {
			_, _ = awgRun("ip route replace blackhole default table " + strconv.Itoa(t.Table) + " metric 1000")
		}
	}
	return firstErr
}

func awgWriteMultiHook(tunnels []awgMultiTunnel, rules []awgMultiRule) error {
	if err := os.MkdirAll(filepath.Dir(awgMultiHookPath), 0o755); err != nil {
		return err
	}
	hook := awgMultiFirewallHook(tunnels, rules)
	if err := os.WriteFile(awgMultiHookPath, []byte(hook), 0o755); err != nil {
		return err
	}
	if out, err := awgRun("sh " + awgMultiHookPath); err != nil {
		return fmt.Errorf("firewall hook: %v: %s", err, out)
	}
	return nil
}

func awgMultiFirewallHook(tunnels []awgMultiTunnel, rules []awgMultiRule) string {
	var s, doc strings.Builder
	s.WriteString("#!/bin/sh\n")
	s.WriteString("set -e\n")
	s.WriteString("# AWG2 multi-tunnel policy routing hook - managed by nfqws2-strategy.\n")
	s.WriteString("while iptables -w -t mangle -D PREROUTING -j " + awgMultiChain + " 2>/dev/null; do :; done\n")
	s.WriteString("while iptables -w -t mangle -D OUTPUT -j " + awgMultiChain + " 2>/dev/null; do :; done\n")
	s.WriteString("iptables -w -t mangle -N " + awgMultiChain + " 2>/dev/null || true\n")
	s.WriteString("iptables -w -t mangle -F " + awgMultiChain + " 2>/dev/null || true\n")
	s.WriteString(awgMultiSharedCleanupShell())
	s.WriteString("IPTABLES_RESTORE='iptables-restore --noflush'\n")
	s.WriteString("if iptables-restore --help 2>&1 | grep -q -- ' -w'; then IPTABLES_RESTORE='iptables-restore -w 5 --noflush'; fi\n")

	doc.WriteString("*mangle\n")
	doc.WriteString(":" + awgMultiChain + " -\n")
	for _, ex := range awgExcludes {
		doc.WriteString("-A " + awgMultiChain + " -d " + ex + " -j RETURN\n")
	}
	for _, t := range tunnels {
		if t.EndpointIP != "" {
			doc.WriteString("-A " + awgMultiChain + " -d " + t.EndpointIP + "/32 -j RETURN\n")
		}
	}
	for _, r := range rules {
		matches := awgMultiRuleMatches(r)
		for _, match := range matches {
			if r.Zone.RouteValue() == "direct" {
				doc.WriteString("-A " + awgMultiChain + match + " -j RETURN\n")
				continue
			}
			if r.Tunnel == nil {
				continue
			}
			doc.WriteString("-A " + awgMultiChain + match + " -j MARK --set-xmark " + r.Tunnel.Mark + "/" + awgMultiMarkMask + "\n")
			doc.WriteString("-A " + awgMultiChain + match + " -j ACCEPT\n")
		}
	}
	doc.WriteString("COMMIT\n")
	s.WriteString("$IPTABLES_RESTORE <<'AWGMV4'\n")
	s.WriteString(doc.String())
	s.WriteString("AWGMV4\n")
	s.WriteString("iptables -w -t mangle -I PREROUTING 1 -j " + awgMultiChain + "\n")
	s.WriteString("iptables -w -t mangle -I OUTPUT 1 -j " + awgMultiChain + "\n")
	for _, t := range tunnels {
		mss := t.MTU - 40
		if mss <= 0 {
			mss = 1240
		}
		ms := strconv.Itoa(mss)
		s.WriteString("iptables -w -t nat -A POSTROUTING -o " + t.Iface + " -j MASQUERADE 2>/dev/null || true\n")
		s.WriteString("iptables -w -A FORWARD -i " + t.Iface + " -j ACCEPT 2>/dev/null || true\n")
		s.WriteString("iptables -w -A FORWARD -o " + t.Iface + " -j ACCEPT 2>/dev/null || true\n")
		s.WriteString("iptables -w -t mangle -A FORWARD -o " + t.Iface + " -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss " + ms + " 2>/dev/null || true\n")
		s.WriteString("iptables -w -t mangle -A FORWARD -i " + t.Iface + " -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss " + ms + " 2>/dev/null || true\n")
	}
	return s.String()
}

func awgMultiSharedCleanupShell() string {
	return `cleanup_awg2_shared() {
  fam=$1; tbl=$2; chn=$3; target=$4
  for n in $("${fam}" -w -t "${tbl}" -L "${chn}" -v --line-numbers 2>/dev/null | awk -v target="${target}" '$4 == target && ($7 ~ /^awg[0-9][0-9]*$/ || $8 ~ /^awg[0-9][0-9]*$/) {print $1}' | sort -rn); do
    "${fam}" -w -t "${tbl}" -D "${chn}" "${n}" 2>/dev/null || true
  done
}
cleanup_awg2_shared iptables nat POSTROUTING MASQUERADE
cleanup_awg2_shared iptables filter FORWARD ACCEPT
cleanup_awg2_shared iptables mangle FORWARD TCPMSS
`
}

func awgMultiRuleMatches(r awgMultiRule) []string {
	srcs := r.Sources
	if len(srcs) == 0 {
		srcs = []string{""}
	}
	out := []string{}
	for _, src := range srcs {
		var b strings.Builder
		if src != "" {
			b.WriteString(" -s ")
			b.WriteString(src)
		}
		if r.HasDst {
			b.WriteString(" -m set --match-set ")
			b.WriteString(r.SetName)
			b.WriteString(" dst")
		}
		out = append(out, b.String())
	}
	return out
}

func (svc *Service) awgClearLegacyPolicyOS() {
	svc.awgStopLegacyRoutingRuntimeOS()
	svc.route.refreshWG.Wait()
	svc.awgStopDNSProxy()
	svc.awgStopSNISniff()
	_ = os.Remove(awgHookPath)
	_, _ = awgRun("while iptables -w -t mangle -D PREROUTING -j " + awgChain + " 2>/dev/null; do :; done")
	_, _ = awgRun("while iptables -w -t mangle -D OUTPUT -j " + awgChain + " 2>/dev/null; do :; done")
	_, _ = awgRun("while ip6tables -w -t mangle -D PREROUTING -j " + awgChain + "6 2>/dev/null; do :; done")
	_, _ = awgRun("while ip6tables -w -t mangle -D OUTPUT -j " + awgChain + "6 2>/dev/null; do :; done")
	_, _ = awgRun("iptables -t mangle -F " + awgChain + " 2>/dev/null")
	_, _ = awgRun("iptables -t mangle -X " + awgChain + " 2>/dev/null")
	_, _ = awgRun("ip6tables -t mangle -F " + awgChain + "6 2>/dev/null")
	_, _ = awgRun("ip6tables -t mangle -X " + awgChain + "6 2>/dev/null")
	_, _ = awgRun("ip rule del fwmark " + awgMarkRule + " table " + awgTable + " 2>/dev/null")
	_, _ = awgRun("ip route flush table " + awgTable + " 2>/dev/null")
}

func (svc *Service) awgClearMultiPolicyOS() {
	svc.awgStopMultiPolicyRefresh()
	_ = os.Remove(awgMultiHookPath)
	_, _ = awgRun("while iptables -w -t mangle -D PREROUTING -j " + awgMultiChain + " 2>/dev/null; do :; done")
	_, _ = awgRun("while iptables -w -t mangle -D OUTPUT -j " + awgMultiChain + " 2>/dev/null; do :; done")
	_, _ = awgRun("iptables -w -t mangle -F " + awgMultiChain + " 2>/dev/null")
	_, _ = awgRun("iptables -w -t mangle -X " + awgMultiChain + " 2>/dev/null")
	_, _ = awgRun(awgMultiSharedCleanupShell())
	for i := 1; i <= awgMultiMax; i++ {
		table := awgMultiTableBase + i
		mark := awgMultiMark(i)
		pref := awgMultiPrefBySlot(i)
		_, _ = awgRun("while ip rule del pref " + strconv.Itoa(pref) + " 2>/dev/null; do :; done")
		_, _ = awgRun("while ip rule del fwmark " + mark + "/" + awgMultiMarkMask + " table " + strconv.Itoa(table) + " 2>/dev/null; do :; done")
		_, _ = awgRun("ip route flush table " + strconv.Itoa(table) + " 2>/dev/null")
	}
	_, _ = awgRun("for s in $(ipset list -n 2>/dev/null | awk '/^" + awgMultiSetPrefix + "_[0-9][0-9][0-9]$/ {print $1}'); do ipset destroy \"$s\" 2>/dev/null; done")
}

func (svc *Service) awgStartMultiPolicyRefresh() {
	svc.awgStopMultiPolicyRefresh()
	svc.route.mu.Lock()
	stop := make(chan struct{})
	svc.route.multiStopRefresh = stop
	svc.route.mu.Unlock()

	svc.route.multiRefreshWG.Add(1)
	go func() {
		defer svc.route.multiRefreshWG.Done()
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		ticks := 0
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				ticks++
				if _, err := os.Stat(awgMultiHookPath); err != nil || ticks%15 == 0 {
					rules, tunnels := svc.awgBuildMultiPolicy()
					if len(rules) == 0 || len(tunnels) == 0 {
						continue
					}
					if err := awgWriteMultiSets(rules); err != nil {
						logbuf.Append("awg2", "warn", "multi-routing refresh: "+err.Error())
					}
					if err := svc.awgInstallMultiRoutes(tunnels); err != nil {
						logbuf.Append("awg2", "warn", "multi-routing refresh: "+err.Error())
					}
					if err := awgWriteMultiHook(tunnels, rules); err != nil {
						logbuf.Append("awg2", "warn", "multi-routing refresh: "+err.Error())
					}
				} else {
					tunnels := svc.awgBuildMultiTunnelsOnly()
					if len(tunnels) > 0 {
						if err := svc.awgInstallMultiRoutes(tunnels); err != nil {
							logbuf.Append("awg2", "warn", "multi-routing refresh: "+err.Error())
						}
					}
					_, _ = awgRun("sh " + awgMultiHookPath)
				}
				awgSetAccel(false)
			}
		}
	}()
}

func (svc *Service) awgStopMultiPolicyRefresh() {
	svc.route.mu.Lock()
	stop := svc.route.multiStopRefresh
	if stop != nil {
		close(stop)
		svc.route.multiStopRefresh = nil
	}
	svc.route.mu.Unlock()
	if stop != nil {
		svc.route.multiRefreshWG.Wait()
	}
}

func (svc *Service) awgBuildMultiTunnelsOnly() []awgMultiTunnel {
	servers := map[string]*managedServer{}
	for _, srv := range svc.serverSnapshot() {
		servers[srv.ID] = srv
	}
	tunnelByID := map[string]*awgMultiTunnel{}
	tunnelOrder := []string{}
	for _, z := range svc.awgRoutingRules() {
		if !z.Enabled || z.RouteValue() != "tunnel" {
			continue
		}
		srv := servers[strings.TrimSpace(z.TunnelID)]
		if srv == nil {
			continue
		}
		cfg := srv.Manager.Config()
		if !cfg.Enabled || cfg.Routing.Mode == "off" || !cfg.Routing.Active {
			continue
		}
		if tunnelByID[srv.ID] != nil {
			continue
		}
		iface := awgClientIfaceName(cfg)
		if !validAWGClientIfaceName(iface) || strings.TrimSpace(cfg.Endpoint) == "" {
			continue
		}
		endpointIP := resolveHostIP(hostOf(cfg.Endpoint))
		if endpointIP == "" || len(tunnelOrder) >= awgMultiMax {
			continue
		}
		slot := len(tunnelOrder) + 1
		tunnelByID[srv.ID] = &awgMultiTunnel{
			ID:         srv.ID,
			Iface:      iface,
			EndpointIP: endpointIP,
			Table:      awgMultiTableBase + slot,
			Mark:       awgMultiMark(slot),
			MTU:        awgTunnelMTU(cfg),
			Killswitch: cfg.Routing.Killswitch,
		}
		tunnelOrder = append(tunnelOrder, srv.ID)
	}
	out := make([]awgMultiTunnel, 0, len(tunnelOrder))
	for _, id := range tunnelOrder {
		if t := tunnelByID[id]; t != nil {
			out = append(out, *t)
		}
	}
	return out
}

func awgMultiMark(slot int) string {
	return fmt.Sprintf("0x%08x", 0x10000000|((slot&0xff)<<20))
}

func awgMultiPref(t awgMultiTunnel) int {
	return awgMultiPrefBase + (t.Table - awgMultiTableBase)
}

func awgMultiPrefBySlot(slot int) int {
	return awgMultiPrefBase + slot
}

func awgMultiSetName(i int) string {
	return fmt.Sprintf("%s_%03d", awgMultiSetPrefix, i)
}
