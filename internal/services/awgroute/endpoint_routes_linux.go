//go:build linux

package awgroute

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"nfqws2strategy/internal/services/awg"
)

// Cached hostname hints suffice for unused candidates. The selected endpoint
// is resolved explicitly by the start path before configuring its UDP socket.
func (svc *Service) awgClientEndpointIPs(am *awg.Manager) []string {
	if am == nil {
		return nil
	}
	candidates := append(am.ClientEndpointCandidates(), am.RuntimeConfig().Endpoint)
	var ips []string
	for _, endpoint := range candidates {
		if ip := svc.cachedPolicyEndpointIP(hostOf(endpoint)); ip != "" {
			ips = append(ips, ip)
		}
	}
	return canonicalEndpointIPs(ips...)
}

func awgMultiEndpointIPs(tunnel awgMultiTunnel) []string {
	return canonicalEndpointIPs(append(append([]string(nil), tunnel.EndpointIPs...), tunnel.EndpointIP)...)
}

func awgEndpointDefaultRoute(ip string) (string, string) {
	if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
		out, _ := awgRun("ip -6 route show default table main")
		return selectDefaultRoute(out)
	}
	return awgDefaultRoute()
}

func (svc *Service) awgPinClientEndpoints(am *awg.Manager) error {
	if am == nil {
		return fmt.Errorf("AWG endpoint: connection unavailable")
	}
	ctx, cancel := context.WithTimeout(svc.clientOpContext(), 15*time.Second)
	defer cancel()
	host := hostOf(am.RuntimeConfig().Endpoint)
	selected := svc.cachedPolicyEndpointIP(host)
	if selected == "" {
		selected = svc.policyHostIPWithLookup(host, func(name string) string { return resolveHostIPContext(ctx, name) })
	}
	if selected == "" {
		return fmt.Errorf("AWG endpoint: address could not be resolved")
	}
	ips := canonicalEndpointIPs(append(svc.awgClientEndpointIPs(am), selected)...)
	return awgPinEndpointIPs(ips, selected, func(command string) (string, error) { return awgRunShell(ctx, command, "") })
}

func awgPinEndpointIPs(ips []string, selected string, run func(string) (string, error)) error {
	if selected != "" && net.ParseIP(selected) == nil {
		return fmt.Errorf("AWG endpoint: invalid selected address")
	}
	ips = canonicalEndpointIPs(append(ips, selected)...)
	for _, ipv6 := range []bool{false, true} {
		var family []string
		for _, raw := range ips {
			if (net.ParseIP(raw).To4() == nil) == ipv6 {
				family = append(family, raw)
			}
		}
		if len(family) == 0 {
			continue
		}
		query := "ip route show default"
		if ipv6 {
			query = "ip -6 route show default table main"
		}
		out, err := run(query)
		gw, dev := selectDefaultRoute(out)
		selectedFamily := net.ParseIP(selected) != nil && (net.ParseIP(selected).To4() == nil) == ipv6
		if err != nil || dev == "" {
			// A router without native IPv6 can still use its IPv4 candidates.
			// Selecting the unavailable family must fail before UAPI is changed.
			if selectedFamily {
				return fmt.Errorf("AWG endpoint: native WAN route unavailable for %s", selected)
			}
			continue
		}
		for _, ip := range family {
			if out, err := run(awgEndpointRouteCmd(ip, gw, dev)); err != nil {
				return awgCmdErr("AWG endpoint WAN route", out, err)
			}
		}
	}
	return awgEnsureEndpointExclusions(ips, run)
}

func awgEnsureEndpointExclusions(ips []string, run func(string) (string, error)) error {
	var script strings.Builder
	script.WriteString("set -e\n")
	for _, v6 := range []bool{false, true} {
		var addresses []string
		for _, raw := range canonicalEndpointIPs(ips...) {
			if (net.ParseIP(raw).To4() == nil) == v6 {
				addresses = append(addresses, raw)
			}
		}
		if len(addresses) == 0 {
			continue
		}
		family, prefix, chains := "iptables", "/32", []string{awgChain, awgMultiChain}
		if v6 {
			family, prefix, chains = "ip6tables", "/128", []string{awgChain + "6"}
		}
		// Read the whole table: a missing owned chain is normal, whereas a
		// lock/read failure must never be mistaken for an absent classifier.
		script.WriteString("if command -v " + family + " >/dev/null 2>&1; then\n  if N2S_ENDPOINT_SNAPSHOT=$(" + family + " -w -t mangle -S); then :; else\n    N2S_ENDPOINT_INSPECT_STATUS=$?\n    [ \"$N2S_ENDPOINT_INSPECT_STATUS\" -ne 4 ] || exit 4\n")
		tableNames := "/proc/net/ip_tables_names"
		if v6 {
			tableNames = "/proc/net/ip6_tables_names"
		}
		script.WriteString("    if { [ ! -e " + tableNames + " ] || { [ -r " + tableNames + " ] && ! grep -qx mangle " + tableNames + "; }; }; then N2S_ENDPOINT_SNAPSHOT=; else exit 1; fi\n")
		script.WriteString("  fi\nelse\n")
		script.WriteString("  if [ -e " + tableNames + " ] && { [ ! -r " + tableNames + " ] || grep -qx mangle " + tableNames + "; }; then exit 1; fi\n  N2S_ENDPOINT_SNAPSHOT=\n")
		script.WriteString("fi\n")
		for _, chain := range chains {
			base := family + " -w -t mangle "
			script.WriteString("case \"\n$N2S_ENDPOINT_SNAPSHOT\n\" in *'\n-N " + chain + "\n'*)\n")
			for _, raw := range addresses {
				rule := chain + " -d " + raw + prefix + " -j RETURN"
				script.WriteString("  " + base + "-C " + rule + " 2>/dev/null || " + base + "-I " + chain + " 1 -d " + raw + prefix + " -j RETURN\n")
			}
			script.WriteString(";; esac\n")
		}
	}
	if out, err := run(script.String()); err != nil {
		return awgCmdErr("AWG endpoint classification exclusion", out, err)
	}
	return nil
}
