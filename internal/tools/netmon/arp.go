package netmon

import (
	"bufio"
	"io"
	"net/netip"
	"strings"
)

// ParseARP parses /proc/net/arp. Columns:
// IP address   HW type   Flags   HW address   Mask   Device
func ParseARP(r io.Reader) ([]ARPEntry, error) {
	sc := bufio.NewScanner(r)
	var out []ARPEntry
	first := true
	for sc.Scan() {
		if first { // header row
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 6 {
			continue
		}
		ip, err := netip.ParseAddr(f[0])
		if err != nil {
			continue
		}
		out = append(out, ARPEntry{IP: ip, MAC: strings.ToLower(f[3]), Device: f[5]})
	}
	return out, sc.Err()
}
