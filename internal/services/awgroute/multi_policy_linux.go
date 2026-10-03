//go:build linux

package awgroute

import (
	"context"
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
	Zone          awg.Zone
	Tunnel        *awgMultiTunnel
	SetName       string
	Entries       []string
	HasDst        bool
	CatchAll      bool
	Sources       []string
	StaticOK      bool
	Dynamic       bool
	DomainEntries []string
	Matchers      *awg.MatcherSet
	RuleIndex     int
}

func (svc *Service) awgApplyMultiPolicyOS() (applyErr error) {
	return svc.awgApplyMultiPolicyWithResolveOS(true)
}

func (svc *Service) awgApplyMultiPolicyCachedOS() error {
	return svc.awgApplyMultiPolicyWithResolveOS(false)
}

func (svc *Service) awgApplyMultiPolicyWithResolveOS(resolve bool) (applyErr error) {
	rules, tunnels := svc.awgBuildMultiPolicyWithResolve(resolve)
	finishDNS := svc.routingDNSGate.begin(true)
	defer func() { finishDNS(applyErr) }()
	svc.awgClearLegacyPolicyOS()
	svc.awgClearMultiPolicyOS()
	if len(rules) == 0 || len(tunnels) == 0 {
		awgSetAccel(true)
		return nil
	}
	if err := ensureAWGIPSetOS(svc.clientOpContext()); err != nil {
		return fmt.Errorf("multi-routing: %w", err)
	}
	if err := awgWriteMultiSets(rules); err != nil {
		return err
	}
	if err := svc.awgInstallMultiRoutes(tunnels); err != nil {
		return err
	}
	dnsOn := svc.awgEnsureMultiDNSProxy(rules)
	if awgMultiDynamicRuleCount(rules) > 0 && !dnsOn {
		return fmt.Errorf("multi-routing: DNS route learner failed to start")
	}
	if err := awgWriteMultiHook(tunnels, rules, dnsOn); err != nil {
		return err
	}
	awgSetAccel(false)
	svc.awgStartMultiPolicyRefresh(rules, tunnels)
	logbuf.Append("awg2", "info", "multi-routing: policy rules applied: "+strconv.Itoa(len(rules)))
	return nil
}

func (svc *Service) awgBuildMultiPolicy() ([]awgMultiRule, []awgMultiTunnel) {
	return svc.awgBuildMultiPolicyWithResolve(true)
}

func (svc *Service) awgBuildMultiPolicyCached() ([]awgMultiRule, []awgMultiTunnel) {
	return svc.awgBuildMultiPolicyWithResolve(false)
}

func (svc *Service) awgBuildMultiPolicyWithResolve(resolve bool) ([]awgMultiRule, []awgMultiTunnel) {
	lookup := svc.policyDNSLookup(false, nil)
	if resolve {
		var cancel context.CancelFunc
		lookup, cancel = svc.policyDNSWarmupLookup(resolveDomainAllContext)
		defer cancel()
	}
	servers := map[string]*managedServer{}
	for _, srv := range svc.serverSnapshot() {
		servers[srv.ID] = srv
	}
	tunnelByID := map[string]*awgMultiTunnel{}
	tunnelOrder := []string{}
	connected := map[string]bool{}
	connectedKnown := map[string]bool{}
	isConnected := func(srv *managedServer) bool {
		if srv == nil {
			return false
		}
		if !connectedKnown[srv.ID] {
			connected[srv.ID] = svc.tunnelUpForManagedServer(srv)
			connectedKnown[srv.ID] = true
		}
		return connected[srv.ID]
	}
	getTunnel := func(srv *managedServer) *awgMultiTunnel {
		if srv == nil {
			return nil
		}
		if t := tunnelByID[srv.ID]; t != nil {
			return t
		}
		cfg := srv.Manager.RuntimeConfig()
		if !cfg.Enabled || !cfg.Client.Enabled || cfg.Routing.Mode == "off" || !cfg.Routing.Active {
			return nil
		}
		iface := awgClientIfaceName(cfg)
		if !validAWGClientIfaceName(iface) || strings.TrimSpace(cfg.Endpoint) == "" {
			return nil
		}
		// Build desired policy without changing client intent. The supervisor
		// alone repairs absent interfaces; preserving the slot while down keeps
		// other tunnels' marks/tables stable and the configured killswitch intact.
		endpointIP := svc.cachedPolicyHostIP(hostOf(cfg.Endpoint))
		if !resolve {
			endpointIP = svc.cachedPolicyEndpointIP(hostOf(cfg.Endpoint))
		}
		if resolve && endpointIP == "" {
			endpointIP = svc.resolvePolicyHostIP(hostOf(cfg.Endpoint))
			svc.rememberPolicyDNS(hostOf(cfg.Endpoint), []string{endpointIP})
		}
		if endpointIP == "" && resolve {
			logbuf.Append("awg2", "warn", "multi-routing: endpoint is not resolved for "+iface)
			return nil
		}
		if resolve && endpointIP != "" {
			svc.rememberPolicyEndpointIP(hostOf(cfg.Endpoint), endpointIP)
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
	// Allocate slots in configured server order before resolving rules. A
	// failover must change only the selected interface, not every fwmark/table
	// number on the router.
	for _, srv := range svc.serverSnapshot() {
		if srv == nil {
			continue
		}
		cfg := srv.Manager.RuntimeConfig()
		if !cfg.Enabled || !cfg.Client.Enabled || cfg.Routing.Mode == "off" || !cfg.Routing.Active {
			continue
		}
		_ = getTunnel(srv)
	}

	out := []awgMultiRule{}
	for i, z := range svc.awgRoutingRules() {
		if !z.Enabled || z.WaitingForConnection {
			continue
		}
		primaryID := strings.TrimSpace(z.TunnelID)
		srv := servers[primaryID]
		if srv == nil {
			continue
		}
		route := z.RouteValue()
		var tun *awgMultiTunnel
		if route == "tunnel" {
			selectedID := primaryID
			if len(z.FallbackTunnelIDs) > 0 {
				selectedID = selectFallbackTunnelID(primaryID, z.FallbackTunnelIDs,
					func(id string) bool {
						candidate := servers[id]
						if candidate == nil {
							return false
						}
						cfg := candidate.Manager.RuntimeConfig()
						return cfg.Enabled && cfg.Client.Enabled && cfg.Routing.Mode != "off" && cfg.Routing.Active
					},
					func(id string) bool { return isConnected(servers[id]) },
				)
			}
			if selectedID != primaryID {
				srv = servers[selectedID]
			}
			tun = getTunnel(srv)
			if tun == nil {
				continue
			}
		} else {
			cfg := srv.Manager.RuntimeConfig()
			if !cfg.Enabled || !cfg.Client.Enabled || cfg.Routing.Mode == "off" || !cfg.Routing.Active {
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
		r.Entries, r.CatchAll, r.StaticOK = svc.awgMultiRuleEntriesWithLookup(z, lookup)
		r.DomainEntries = svc.awgMultiRuleDomainEntries(z)
		if len(r.DomainEntries) > 0 {
			ms, _ := awg.CompileMatcherSet(r.DomainEntries)
			if ms.Len() > 0 {
				r.Matchers = &ms
				r.Dynamic = true
			}
		}
		r.HasDst = len(r.Entries) > 0 || r.Dynamic
		if !r.CatchAll && !r.HasDst && !r.StaticOK {
			logbuf.Append("awg2", "warn", "multi-routing: rule "+z.Name+" has only dynamic domain masks and was skipped")
			continue
		}
		out = append(out, r)
	}
	// Multi-policy owns the shared firewall rules for every awgN interface while
	// any multi rule exists. Keep NAT/FORWARD/MSS alive for active tunnels even
	// when the current rule set happens to target a different tunnel; otherwise
	// the cleanup step below removes the legacy awg0 rules and LAN traffic through
	// the active server loses the exact fast-path/MTU guardrails the old datapath
	// installed.
	tunnels := make([]awgMultiTunnel, 0, len(tunnelOrder))
	for _, id := range tunnelOrder {
		if t := tunnelByID[id]; t != nil {
			tunnels = append(tunnels, *t)
		}
	}
	return out, tunnels
}

func (svc *Service) awgMultiRuleDomainEntries(z awg.Zone) []string {
	expDomains, _ := svc.expandZoneEntries(z)
	return awgDropCatchAll(expDomains)
}

func (svc *Service) awgMultiRuleEntries(z awg.Zone) ([]string, bool, bool) {
	lookup, cancel := svc.policyDNSWarmupLookup(resolveDomainAllContext)
	defer cancel()
	return svc.awgMultiRuleEntriesWithLookup(z, lookup)
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
	routeRules, err := awgRun("ip rule show")
	if err != nil {
		return awgCmdErr("ip rule show", routeRules, err)
	}
	var firstErr error
	for _, t := range tunnels {
		awgTuneClientKernelBuffers()
		_, _ = awgRun("ip link set " + t.Iface + " qlen " + strconv.Itoa(awgClientTxQueueLen) + " 2>/dev/null")
		if t.EndpointIP != "" && wandev != "" {
			if err := awgRunCheck(awgEndpointRouteCmd(t.EndpointIP, gw, wandev)); err != nil {
				logbuf.Append("awg2", "warn", "multi-routing: endpoint route "+t.EndpointIP+": "+err.Error())
			}
		}
		// A different enabled tunnel may still be offline or starting. Keep its
		// policy slot/killswitch, without making a healthy tunnel's restore fail.
		if _, err := os.Stat("/sys/class/net/" + t.Iface); err == nil {
			if err := awgRunCheck("ip route replace default dev " + t.Iface + " table " + strconv.Itoa(t.Table)); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("ip tunnel route %s: %w", t.Iface, err)
			}
		}
		if !awgMultiHasRouteRule(routeRules, t) {
			if err := awgRunCheck("ip rule add pref " + strconv.Itoa(awgMultiPref(t)) + " fwmark " + t.Mark + "/" + awgMultiMarkMask + " table " + strconv.Itoa(t.Table)); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("ip tunnel rule %s: %w", t.Iface, err)
			}
		}
		if t.Killswitch {
			if err := awgRunCheck("ip route replace blackhole default table " + strconv.Itoa(t.Table) + " metric 1000"); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("ip tunnel killswitch %s: %w", t.Iface, err)
			}
		}
	}
	return firstErr
}

// Existing rules are expected during a watchdog re-assertion. Recognize only
// our complete pref/mark/mask/table selector, rather than treating every failed
// add as harmless (which previously hid missing policy rules).
func awgMultiHasRouteRule(output string, tunnel awgMultiTunnel) bool {
	wantMark, markErr := strconv.ParseUint(tunnel.Mark, 0, 32)
	wantMask, maskErr := strconv.ParseUint(awgMultiMarkMask, 0, 32)
	if markErr != nil || maskErr != nil {
		return false
	}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		pref, err := strconv.Atoi(strings.TrimSuffix(fields[0], ":"))
		if err != nil || pref != awgMultiPref(tunnel) {
			continue
		}
		var mark, mask uint64
		var table int
		for i := 1; i+1 < len(fields); i++ {
			switch fields[i] {
			case "fwmark":
				parts := strings.SplitN(fields[i+1], "/", 2)
				mark, err = strconv.ParseUint(parts[0], 0, 32)
				if err != nil {
					continue
				}
				mask = 0xffffffff
				if len(parts) == 2 {
					mask, _ = strconv.ParseUint(parts[1], 0, 32)
				}
			case "lookup", "table":
				table, _ = strconv.Atoi(fields[i+1])
			}
		}
		if mark == wantMark && mask == wantMask && table == tunnel.Table {
			return true
		}
	}
	return false
}

func awgWriteMultiHook(tunnels []awgMultiTunnel, rules []awgMultiRule, dnsRedirect bool) error {
	if err := os.MkdirAll(filepath.Dir(awgMultiHookPath), 0o755); err != nil {
		return err
	}
	hook := awgMultiFirewallHook(tunnels, rules, dnsRedirect)
	if err := os.WriteFile(awgMultiHookPath, []byte(hook), 0o755); err != nil {
		return err
	}
	ifaces := make([]string, 0, len(tunnels))
	for _, t := range tunnels {
		ifaces = append(ifaces, t.Iface)
	}
	awgEnsureFW4IncludeOS(ifaces)
	if out, err := awgRun("sh " + awgMultiHookPath); err != nil {
		return fmt.Errorf("firewall hook: %v: %s", err, out)
	}
	return nil
}

func awgMultiPolicyDocument(tunnels []awgMultiTunnel, rules []awgMultiRule) string {
	var doc strings.Builder
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
		for _, match := range awgMultiRuleMatches(r) {
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
	return doc.String()
}

func awgMultiFirewallHook(tunnels []awgMultiTunnel, rules []awgMultiRule, dnsRedirect bool) string {
	var s strings.Builder
	dnsPortHex := "14EA"
	if p, err := strconv.Atoi(awgDNSPort); err == nil {
		dnsPortHex = fmt.Sprintf("%04X", p)
	}
	s.WriteString("#!/bin/sh\n")
	s.WriteString("set -e\n")
	s.WriteString("# AWG2 multi-tunnel policy routing hook - managed by nfqws2-strategy.\n")
	// --noflush rebuilds a declared user chain at COMMIT. Keep the live chain
	// and its jumps intact while preparing the replacement; separate -F/-D
	// calls otherwise let existing packets escape the policy during refresh.

	s.WriteString(awgFirewallRestoreShell("awg_restore_multi", "iptables-restore", "AWGMV4", awgMultiPolicyDocument(tunnels, rules)))
	s.WriteString("awg_restore_multi\n")
	for _, chain := range []string{"PREROUTING", "OUTPUT"} {
		// An existing jump below another marking chain must regain priority.
		// Insert the desired first jump without detaching the live one.
		s.WriteString("if ! iptables -w -t mangle -S " + chain + " | awk '$1 == \"-A\" { ok = ($3 == \"-j\" && $4 == \"" + awgMultiChain + "\"); exit } END { exit !ok }'; then\n")
		s.WriteString("  iptables -w -t mangle -I " + chain + " 1 -j " + awgMultiChain + "\nfi\n")
	}
	fw4Ifaces := make([]string, 0, len(tunnels))
	for _, t := range tunnels {
		mss := t.MTU - 40
		if mss <= 0 {
			mss = 1240
		}
		ms := strconv.Itoa(mss)
		fw4Ifaces = append(fw4Ifaces, t.Iface)
		for _, rule := range []struct{ table, chain, match string }{
			{"nat", "POSTROUTING", "-o " + t.Iface + " -j MASQUERADE"},
			{"filter", "FORWARD", "-i " + t.Iface + " -j ACCEPT"},
			{"filter", "FORWARD", "-o " + t.Iface + " -j ACCEPT"},
			{"mangle", "FORWARD", "-o " + t.Iface + " -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss " + ms},
			{"mangle", "FORWARD", "-i " + t.Iface + " -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss " + ms},
		} {
			base := "iptables -w -t " + rule.table
			s.WriteString(base + " -C " + rule.chain + " " + rule.match + " 2>/dev/null || " + base + " -A " + rule.chain + " " + rule.match + "\n")
		}
	}
	s.WriteString(awgFW4ForwardRulesShell(fw4Ifaces))
	if dnsRedirect {
		redirectPort := awgDNSPort
		s.WriteString("if grep -qi ':" + dnsPortHex + " ' /proc/net/udp /proc/net/udp6 2>/dev/null; then\n")
		s.WriteString("  for br in $(ls /sys/class/net/ 2>/dev/null | grep '^br'); do\n")
		for _, proto := range []string{"udp", "tcp"} {
			r := "-i $br -p " + proto + " --dport 53 -j REDIRECT --to-ports " + redirectPort
			s.WriteString("    iptables -w -t nat -C PREROUTING " + r + " 2>/dev/null || iptables -w -t nat -A PREROUTING " + r + "\n")
			s.WriteString("    ip6tables -w -t nat -C PREROUTING " + r + " 2>/dev/null || ip6tables -w -t nat -A PREROUTING " + r + "\n")
		}
		s.WriteString("  done\nfi\n")
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
	awgRemoveFW4IncludeOS()
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
	svc.awgStopDNSProxy()
	awgRemoveFW4IncludeOS()
	_ = os.Remove(awgMultiHookPath)
	_, _ = awgRun("while iptables -w -t mangle -D PREROUTING -j " + awgMultiChain + " 2>/dev/null; do :; done")
	_, _ = awgRun("while iptables -w -t mangle -D OUTPUT -j " + awgMultiChain + " 2>/dev/null; do :; done")
	_, _ = awgRun("iptables -w -t mangle -F " + awgMultiChain + " 2>/dev/null")
	_, _ = awgRun("iptables -w -t mangle -X " + awgMultiChain + " 2>/dev/null")
	_, _ = awgRun(awgMultiSharedCleanupShell())
	awgClearMultiRouteRules(awgRun)
	// Include unreferenced staging sets left by an interrupted periodic swap.
	_, _ = awgRun("for s in $(ipset list -n 2>/dev/null | awk '/^" + awgMultiSetPrefix + "_[0-9][0-9][0-9](_r)?$/ {print $1}'); do ipset destroy \"$s\" 2>/dev/null; done")
}

// Clear every reserved slot, including stale rules from removed tunnels. Run
// eight slots per shell: keeping the full range preserves restart cleanup,
// while 8 shells instead of 192 avoids repeated fork+pipe setup on routers.
func awgClearMultiRouteRules(run func(string) (string, error)) {
	const batchSlots = 8
	for first := 1; first <= awgMultiMax; first += batchSlots {
		var commands strings.Builder
		for i := first; i < first+batchSlots && i <= awgMultiMax; i++ {
			table := awgMultiTableBase + i
			mark := awgMultiMark(i)
			pref := awgMultiPrefBySlot(i)
			// Scope the pref-based delete to our own selector: a bare `ip rule del pref N`
			// removes ANY rule at that priority, and 71..134 overlaps the priorities
			// Keenetic uses for its own access-policy rules (100+).
			commands.WriteString("while ip rule del pref " + strconv.Itoa(pref) + " fwmark " + mark + "/" + awgMultiMarkMask + " table " + strconv.Itoa(table) + " 2>/dev/null; do :; done\n")
			commands.WriteString("while ip rule del fwmark " + mark + "/" + awgMultiMarkMask + " table " + strconv.Itoa(table) + " 2>/dev/null; do :; done\n")
			commands.WriteString("ip route flush table " + strconv.Itoa(table) + " 2>/dev/null\n")
		}
		_, _ = run(commands.String())
	}
}

func (svc *Service) awgStartMultiPolicyRefresh(rules []awgMultiRule, tunnels []awgMultiTunnel) {
	svc.awgStopMultiPolicyRefresh()
	// Capture the installed policy once. Re-expanding large domain lists on
	// every unchanged minute tick can itself create CPU/lock spikes. A real
	// config/fallback apply stops this loop and installs its new snapshot.
	rules = awgCloneMultiRules(rules)
	tunnels = append([]awgMultiTunnel(nil), tunnels...)
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
				unlock, ok := svc.tryClientOps()
				if !ok {
					continue
				}
				ticks++
				_, hookErr := os.Stat(awgMultiHookPath)
				if len(rules) == 0 || len(tunnels) == 0 {
					unlock()
					continue
				}
				wasReady := svc.RoutingDNSReadiness().Ready
				svc.route.mu.Lock()
				proxy := svc.route.dnsProxy
				svc.route.mu.Unlock()
				dnsOn := proxy != nil && proxy.Running()
				healthy := wasReady && hookErr == nil && (awgMultiDynamicRuleCount(rules) == 0 || dnsOn) && svc.awgMultiPolicyIntact(rules, tunnels, dnsOn)
				refreshRules := rules
				if !healthy || ticks%15 == 0 {
					// Prepare cached entries before blocking DNS readers. Never
					// resolve unused domains or alter the applied rule bindings.
					refreshRules = awgCloneMultiRules(rules)
					lookup := svc.policyDNSLookup(false, nil)
					for i := range refreshRules {
						refreshRules[i].Entries, _, _ = svc.awgMultiRuleEntriesWithLookup(refreshRules[i].Zone, lookup)
					}
				}
				err := svc.awgMaintainMultiPolicy(hookErr != nil, ticks, func() bool { return healthy }, func() error {
					// Same policy: stage and atomically swap sets while retaining
					// all learned addresses, their options, and the running proxy.
					return awgRefreshMultiSets(refreshRules)
				}, func() error {
					// Missing/reset kernel state and a previous failed install
					// still require a complete, synchronous recovery.
					if wasReady {
						if err := awgEnsureMultiSets(refreshRules); err != nil {
							return err
						}
						if err := awgRefreshMultiSets(refreshRules); err != nil {
							return err
						}
					} else if err := awgWriteMultiSets(refreshRules); err != nil {
						return err
					}
					if err := svc.awgInstallMultiRoutes(tunnels); err != nil {
						return err
					}
					if !wasReady || !dnsOn {
						dnsOn = svc.awgEnsureMultiDNSProxy(rules)
					}
					if awgMultiDynamicRuleCount(rules) > 0 && !dnsOn {
						return fmt.Errorf("multi-routing: DNS route learner failed to start")
					}
					if err := awgWriteMultiHook(tunnels, rules, dnsOn); err != nil {
						return err
					}
					awgSetAccel(false)
					return nil
				})
				if err != nil {
					logbuf.Append("awg2", "warn", "multi-routing refresh: "+err.Error())
				}
				unlock()
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
	tunnelByID := map[string]*awgMultiTunnel{}
	tunnelOrder := []string{}
	// Keep every active interface in the same deterministic order as the full
	// policy builder. A connection used only as a fallback still needs its route
	// table refreshed after an endpoint re-resolution.
	for _, srv := range svc.serverSnapshot() {
		if srv == nil {
			continue
		}
		cfg := srv.Manager.RuntimeConfig()
		if !cfg.Enabled || !cfg.Client.Enabled || cfg.Routing.Mode == "off" || !cfg.Routing.Active {
			continue
		}
		if tunnelByID[srv.ID] != nil {
			continue
		}
		iface := awgClientIfaceName(cfg)
		if !validAWGClientIfaceName(iface) || strings.TrimSpace(cfg.Endpoint) == "" {
			continue
		}
		endpointIP := svc.cachedPolicyEndpointIP(hostOf(cfg.Endpoint))
		if len(tunnelOrder) >= awgMultiMax {
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
