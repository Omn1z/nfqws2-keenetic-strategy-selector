package netmon

import (
	"bufio"
	"io"
	"strings"
)

// ParseDev parses /proc/net/dev. Each data line is "iface: rx_bytes rx_packets
// rx_errs rx_drop fifo frame compressed multicast tx_bytes tx_packets ...".
// The two header lines have no early colon and are skipped.
func ParseDev(r io.Reader) ([]IfaceBytes, error) {
	sc := bufio.NewScanner(r)
	var out []IfaceBytes
	for sc.Scan() {
		line := sc.Text()
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		name := strings.TrimSpace(line[:colon])
		fields := strings.Fields(line[colon+1:])
		if name == "" || len(fields) < 16 {
			continue
		}
		out = append(out, IfaceBytes{
			Iface:     name,
			RxBytes:   atoi64(fields[0]),
			RxPackets: atoi64(fields[1]),
			TxBytes:   atoi64(fields[8]),
			TxPackets: atoi64(fields[9]),
		})
	}
	return out, sc.Err()
}
