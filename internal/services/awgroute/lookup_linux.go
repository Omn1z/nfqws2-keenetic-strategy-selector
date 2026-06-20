//go:build linux

package awgroute

import "strings"

// lookupMAC returns the LAN MAC address (lowercased aa:bb:cc:dd:ee:ff) for a
// given IPv4 source from the kernel ARP/neighbour cache; empty string if not
// learned yet. The firewall hook calls this to emit `-m mac --mac-source` rules
// in ip6tables for per-device routing — IPv6 source addresses rotate (SLAAC +
// privacy extensions), but the device MAC stays put.
func lookupMAC(ip string) string {
	out, err := awgRun("ip neigh show " + ip)
	if err != nil {
		return ""
	}
	// Format: "192.168.31.243 dev br-lan lladdr 84:a9:38:c9:d4:36 REACHABLE"
	for _, ln := range strings.Split(out, "\n") {
		fs := strings.Fields(ln)
		for i, f := range fs {
			if f == "lladdr" && i+1 < len(fs) {
				return strings.ToLower(fs[i+1])
			}
		}
	}
	return ""
}
