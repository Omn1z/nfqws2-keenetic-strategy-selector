//go:build linux

package netmon

import (
	"bufio"
	"os"
	"strings"
)

// Where to look for DHCP leases. Standard dnsmasq path first, then a couple of
// well-known alternates that ship on various OpenWrt forks (Keenetic / asuswrt-
// merlin / Padavan). The first readable file wins — best-effort, no panic on
// missing/odd formats.
var dhcpLeasesPaths = []string{
	"/tmp/dhcp.leases",
	"/var/dhcp.leases",
	"/var/lib/misc/dnsmasq.leases",
	"/tmp/dnsmasq.leases",
}

// HostnamesByMAC returns a lowercased mac → hostname map from the router's DHCP
// leases. Entries where dnsmasq did not learn a hostname (hostname field is "*")
// are omitted; the caller falls back to MAC display in that case. Safe to call
// repeatedly — it's just a few hundred bytes of /tmp on a router.
func HostnamesByMAC() map[string]string {
	out := map[string]string{}
	for _, p := range dhcpLeasesPaths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			// dnsmasq format: <expiry-unix> <mac> <ip> <hostname> <clientid>
			// (the hostname is "*" when the client didn't include one in DHCPREQUEST)
			fs := strings.Fields(sc.Text())
			if len(fs) < 4 {
				continue
			}
			mac := strings.ToLower(fs[1])
			name := fs[3]
			if name == "*" || name == "" {
				continue
			}
			out[mac] = name
		}
		_ = f.Close()
		break // first file with anything parseable is enough
	}
	return out
}
