package engine

import (
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
)

func (s *Sandbox) localIPv4() ([]string, error) {
	get := s.localAddrs
	if get == nil {
		get = net.InterfaceAddrs
	}
	addrs, err := get()
	if err != nil {
		return nil, fmt.Errorf("read local IPv4 addresses for sandbox isolation: %w", err)
	}
	seen := make(map[string]bool)
	for _, addr := range addrs {
		if addr == nil {
			return nil, fmt.Errorf("missing local address for sandbox isolation")
		}
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			ip = net.ParseIP(addr.String())
		}
		if ip == nil {
			return nil, fmt.Errorf("invalid local address for sandbox isolation: %q", addr.String())
		}
		if v4 := ip.To4(); v4 != nil && !v4.IsUnspecified() {
			seen[v4.String()] = true
		}
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("no local IPv4 addresses available for sandbox isolation")
	}
	ips := make([]string, 0, len(seen))
	for ip := range seen {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	return ips, nil
}

// ownedMainGuard recognizes only our complete worker-scoped rule shape. The
// source address may belong to a previous WAN lease: cleanup after a crash must
// not depend on today's addresses. No other rule in the vendor chain is edited.
func (s *Sandbox) ownedMainGuard(chain, line string) []string {
	fields := strings.Fields(line)
	if len(fields) < 3 || fields[0] != "-A" || fields[1] != chain {
		return nil
	}
	var normalized []string
	source := ""
	tcpMatcher := false
	for i := 2; i < len(fields); i++ {
		// iptables -S inserts the implicit TCP matcher when displaying ports.
		if fields[i] == "-m" && i+1 < len(fields) && fields[i+1] == "tcp" {
			if tcpMatcher {
				return nil
			}
			tcpMatcher = true
			i++
			continue
		}
		if fields[i] == "--ctorigsrc" && i+1 < len(fields) {
			raw := strings.TrimSuffix(fields[i+1], "/32")
			ip := net.ParseIP(raw)
			if ip == nil || ip.To4() == nil || ip.IsUnspecified() || source != "" {
				return nil
			}
			source = ip.To4().String()
			normalized = append(normalized, fields[i], source)
			i++
			continue
		}
		normalized = append(normalized, fields[i])
	}
	if source == "" || !slices.Equal(normalized, s.mainGuard(chain, source)) {
		return nil
	}
	return fields[2:]
}

func (s *Sandbox) removeMainGuards() {
	for _, chain := range []string{"nfqws_post", "nfqws_pre"} {
		// Also repair the exact pre-source-constraint guard left by an earlier
		// interrupted test. It has no dynamic IP, so no inspection is needed.
		s.iptQuiet(append([]string{"-t", "mangle", "-D", chain}, s.mainGuard(chain, "")...)...)
		out, err := s.iptOutput("-t", "mangle", "-S", chain)
		if err != nil {
			continue // stopped service or unavailable firewall; best-effort teardown
		}
		for _, line := range strings.Split(string(out), "\n") {
			if rule := s.ownedMainGuard(chain, line); rule != nil {
				s.iptQuiet(append([]string{"-t", "mangle", "-D", chain}, rule...)...)
			}
		}
	}
}
