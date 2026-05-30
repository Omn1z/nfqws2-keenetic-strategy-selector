//go:build linux

package app

import (
	"fmt"
	"net"
	"os/exec"
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

const (
	awgTable    = "998"           // dedicated routing table for tunneled traffic
	awgMark     = "0x40000"       // distinctive fwmark bit (clear of nfqws2's marks)
	awgMarkRule = awgMark + "/" + awgMark
	awgChain    = "AWG2_MARK"
	awgSetInc   = "awg2_inc"
	awgSetExc   = "awg2_exc"
)

func awgRun(cmd string) (string, error) {
	ctx, cancel := contextTimeout(15 * time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "sh", "-c", cmd).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func awgEnsureRule(table, chain, rule string) {
	_, _ = awgRun("iptables -t " + table + " -C " + chain + " " + rule + " 2>/dev/null || iptables -t " + table + " -A " + chain + " " + rule)
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

func (a *App) awgApplyRoutingOS() error {
	cfg := a.awg.Config()
	r := cfg.Routing
	if r.Mode == "off" {
		return a.awgTeardownRoutingOS()
	}
	if cs := a.awgClientStatusOS(); cs == nil || !cs.IfacePresent {
		return fmt.Errorf("туннель awg0 не поднят — сначала «Поднять туннель»")
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
	// 3) tunnel table + fwmark rule
	_, _ = awgRun("ip route replace default dev " + awgIface + " table " + awgTable)
	_, _ = awgRun("ip rule del fwmark " + awgMarkRule + " table " + awgTable + " 2>/dev/null")
	if _, err := awgRun("ip rule add fwmark " + awgMarkRule + " table " + awgTable); err != nil {
		return fmt.Errorf("ip rule: %w", err)
	}
	// 4) mangle marking chain (exclusions first, then the mode rule)
	a.awgInstallChain(r.Mode, endpointIP)
	// 5) NAT + MSS clamp out the tunnel
	awgEnsureRule("nat", "POSTROUTING", "-o "+awgIface+" -j MASQUERADE")
	awgEnsureRule("mangle", "FORWARD", "-o "+awgIface+" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu")
	// 6) arm the dead-man's switch + start the domain refresher
	a.awgArmRollback(90 * time.Second)
	a.awgStartRefresh()
	logbuf.Append("awg2", "info", "маршрутизация применена (режим "+r.Mode+") — подтвердите в течение 90с, иначе авто-откат")
	return nil
}

func (a *App) awgInstallChain(mode, endpointIP string) {
	_, _ = awgRun("iptables -t mangle -N " + awgChain + " 2>/dev/null")
	_, _ = awgRun("iptables -t mangle -F " + awgChain)
	// mandatory exclusions — private/CGNAT/loopback and the AWG endpoint stay direct
	for _, ex := range []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"} {
		_, _ = awgRun("iptables -t mangle -A " + awgChain + " -d " + ex + " -j RETURN")
	}
	if endpointIP != "" {
		_, _ = awgRun("iptables -t mangle -A " + awgChain + " -d " + endpointIP + "/32 -j RETURN")
	}
	switch mode {
	case "include":
		_, _ = awgRun("iptables -t mangle -A " + awgChain + " -m set --match-set " + awgSetInc + " dst -j MARK --set-xmark " + awgMarkRule)
	case "exclude":
		_, _ = awgRun("iptables -t mangle -A " + awgChain + " -m set ! --match-set " + awgSetExc + " dst -j MARK --set-xmark " + awgMarkRule)
	case "full":
		_, _ = awgRun("iptables -t mangle -A " + awgChain + " -j MARK --set-xmark " + awgMarkRule)
	}
	awgEnsureRule("mangle", "PREROUTING", "-j "+awgChain)
	awgEnsureRule("mangle", "OUTPUT", "-j "+awgChain)
}

func (a *App) awgBuildSets(cfg *awg.ServerConfig) error {
	_, _ = awgRun("ipset create " + awgSetInc + " hash:net family inet -exist")
	_, _ = awgRun("ipset create " + awgSetExc + " hash:net family inet -exist")
	target := awgSetInc
	if cfg.Routing.Mode == "exclude" {
		target = awgSetExc
	}
	_, _ = awgRun("ipset flush " + target)
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
			for _, ip := range resolveDomain(d) {
				_, _ = awgRun("ipset add " + target + " " + ip + "/32 -exist")
				n++
			}
		}
	}
	logbuf.Append("awg2", "info", fmt.Sprintf("ipset %s: %d записей", target, n))
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

func (a *App) awgStartRefresh() {
	a.awgRoute.mu.Lock()
	if a.awgRoute.stopRefresh != nil {
		close(a.awgRoute.stopRefresh)
	}
	stop := make(chan struct{})
	a.awgRoute.stopRefresh = stop
	a.awgRoute.mu.Unlock()
	go func() {
		t := time.NewTicker(15 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				c := a.awg.Config()
				if c.Routing.Mode == "include" || c.Routing.Mode == "exclude" {
					_ = a.awgBuildSets(&c)
				}
			}
		}
	}()
}

func (a *App) awgCommitRoutingOS() error {
	a.awgRoute.mu.Lock()
	defer a.awgRoute.mu.Unlock()
	if !a.awgRoute.active {
		return fmt.Errorf("маршрутизация не активна")
	}
	if a.awgRoute.rollback != nil {
		a.awgRoute.rollback.Stop()
		a.awgRoute.rollback = nil
	}
	logbuf.Append("awg2", "info", "маршрутизация подтверждена (авто-откат отменён)")
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

	_, _ = awgRun("iptables -t mangle -D PREROUTING -j " + awgChain + " 2>/dev/null")
	_, _ = awgRun("iptables -t mangle -D OUTPUT -j " + awgChain + " 2>/dev/null")
	_, _ = awgRun("iptables -t mangle -F " + awgChain + " 2>/dev/null")
	_, _ = awgRun("iptables -t mangle -X " + awgChain + " 2>/dev/null")
	_, _ = awgRun("ip rule del fwmark " + awgMarkRule + " table " + awgTable + " 2>/dev/null")
	_, _ = awgRun("ip route flush table " + awgTable + " 2>/dev/null")
	_, _ = awgRun("iptables -t nat -D POSTROUTING -o " + awgIface + " -j MASQUERADE 2>/dev/null")
	_, _ = awgRun("iptables -t mangle -D FORWARD -o " + awgIface + " -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null")
	_, _ = awgRun("ipset destroy " + awgSetInc + " 2>/dev/null")
	_, _ = awgRun("ipset destroy " + awgSetExc + " 2>/dev/null")
	logbuf.Append("awg2", "info", "маршрутизация снята")
	return nil
}

// awgRepairRoutingOS removes any leaked AWG2 routing state on startup (idempotent).
func (a *App) awgRepairRoutingOS() { _ = a.awgTeardownRoutingOS() }
