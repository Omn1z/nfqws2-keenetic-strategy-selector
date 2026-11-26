//go:build linux

package awgroute

import (
	"strings"

	"nfqws2strategy/internal/services/awg"
)

const legacyPermanentIPv6Metric = "32760"

func (svc *Service) awgInstallLegacyPolicyRoutes(cfg awg.ServerConfig, includeIPv6 bool) error {
	if cfg.Client.DoubleTunnelMode == awg.DoubleTunnelPermanent {
		return svc.awgApplyPermanentLegacyRoutes(cfg)
	}
	iface := awgClientIfaceName(cfg)
	if err := awgRunCheck("ip route replace default dev " + iface + " table " + awgTable); err != nil {
		return err
	}
	_, _ = awgRun("while ip rule del fwmark " + awgMarkRule + " table " + awgTable + " 2>/dev/null; do :; done")
	if err := awgRunCheck("ip rule add fwmark " + awgMarkRule + " table " + awgTable); err != nil {
		return err
	}
	if includeIPv6 {
		_, _ = awgRun("ip -6 route replace default dev " + iface + " table " + awgTable)
		_, _ = awgRun("ip -6 rule del fwmark " + awgMarkRule + " table " + awgTable + " 2>/dev/null")
		_, _ = awgRun("ip -6 rule add fwmark " + awgMarkRule + " table " + awgTable)
	}
	awgApplyKillswitch(cfg.Routing.Killswitch)
	return nil
}

func (svc *Service) awgLegacyHookEndpoints(am *awg.Manager, cfg awg.ServerConfig) []string {
	ips := svc.awgClientEndpointIPs(am)
	svc.mu.RLock()
	outer := svc.servers[cfg.Client.DoubleTunnelID]
	svc.mu.RUnlock()
	if outer != nil {
		ips = append(ips, svc.awgClientEndpointIPs(outer.Manager)...)
	}
	return ips
}

func (svc *Service) awgApplyPermanentLegacyRoutes(cfg awg.ServerConfig) error {
	iface := awgClientIfaceName(cfg)
	svc.mu.RLock()
	outer := svc.servers[cfg.Client.DoubleTunnelID]
	svc.mu.RUnlock()
	ready := false
	if outer != nil {
		status := awgClientStatusIfaceContextOS(svc.clientOpContext(), iface)
		ready = status.transportMarked && status.transportOuterIface == clientIfaceName(outer.Manager.RuntimeClientStatus().ClientIface)
	}
	return applyPermanentLegacyRoutes(iface, ready, awgRun)
}

// Keep the legacy v4 and v6 policies on the same profile while it waits for
// its configured outer VPN. A previous, unmarked engine cannot receive the
// default routes during that time.
func applyPermanentLegacyRoutes(iface string, ready bool, run func(string) (string, error)) error {
	for _, family := range []struct{ ip, metric string }{
		{"ip", "1000"}, {"ip -6", legacyPermanentIPv6Metric},
	} {
		rules, err := run(family.ip + " rule show")
		if err != nil {
			if family.ip == "ip -6" && (strings.Contains(rules, "Address family not supported") || strings.Contains(rules, "Protocol not supported")) {
				continue
			}
			return awgCmdErr(family.ip+" rule show", rules, err)
		}
		table := " table " + awgTable
		guard := family.ip + " route replace blackhole default" + table + " metric " + family.metric
		route := " default dev " + iface + table
		if output, err := run(guard); err != nil {
			return awgCmdErr(guard, output, err)
		}
		if ready {
			cmd := family.ip + " route replace" + route
			if output, err := run(cmd); err != nil {
				return awgCmdErr(cmd, output, err)
			}
		} else {
			cmd := family.ip + " route del" + route
			if output, err := run(cmd); err != nil && !strings.Contains(output, "No such") &&
				!strings.Contains(strings.ToLower(output), "find device") {
				return awgCmdErr(cmd, output, err)
			}
		}
		if !strings.Contains(rules, "fwmark "+awgMarkRule+" lookup "+awgTable) {
			cmd := family.ip + " rule add fwmark " + awgMarkRule + table
			if output, err := run(cmd); err != nil {
				return awgCmdErr(cmd, output, err)
			}
		}
	}
	return nil
}
