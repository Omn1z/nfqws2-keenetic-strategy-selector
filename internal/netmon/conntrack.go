package netmon

import (
	"bufio"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// ParseConntrack parses /proc/net/nf_conntrack. Malformed lines are skipped so a
// single bad row never aborts the batch.
func ParseConntrack(r io.Reader) ([]Conn, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 256*1024) // rows are long on Keenetic
	var out []Conn
	for sc.Scan() {
		if c, ok := parseConntrackLine(sc.Text()); ok {
			out = append(out, c)
		}
	}
	return out, sc.Err()
}

// parseConntrackLine walks tokens rather than fixed offsets, because the layout
// shifts: tcp rows carry a STATE word after the TTL while udp/icmp rows do not,
// and the src/dst/sport/dport/packets/bytes keys repeat (first block = original
// tuple, second = reply).
func parseConntrackLine(line string) (Conn, bool) {
	f := strings.Fields(line)
	if len(f) < 5 {
		return Conn{}, false
	}
	var c Conn
	c.L3 = f[0]    // ipv4 | ipv6
	c.Proto = f[2] // tcp | udp | icmp | unknown
	ttl, err := strconv.Atoi(f[4])
	if err != nil {
		return Conn{}, false
	}
	c.TTL = ttl

	i := 5
	// tcp has a connection-state word before the key=val pairs; guard against a
	// malformed row where f[5] is already a key=val or a [flag].
	if c.Proto == "tcp" && i < len(f) && !strings.ContainsRune(f[i], '=') && !strings.HasPrefix(f[i], "[") {
		c.State = f[i]
		i++
	}

	var seenSrc, seenDst, seenSport, seenDport, seenPackets, seenBytes bool
	for ; i < len(f); i++ {
		tok := f[i]
		if strings.HasPrefix(tok, "[") {
			switch tok {
			case "[ASSURED]":
				c.Assured = true
			case "[UNREPLIED]":
				c.Unreplied = true
			case "[FASTNAT]":
				c.FastNAT = true
			}
			continue // ignore unknown brackets, incl. the two-token "[RTCACHE o33/r11]"
		}
		eq := strings.IndexByte(tok, '=')
		if eq < 0 {
			if tok == "slan" || tok == "swan" {
				c.Zone = tok
			}
			continue
		}
		key, val := tok[:eq], tok[eq+1:]
		switch key {
		case "src":
			if !seenSrc {
				c.Src, _ = netip.ParseAddr(val)
				seenSrc = true
			}
		case "dst":
			if !seenDst {
				c.Dst, _ = netip.ParseAddr(val)
				seenDst = true
			}
		case "sport":
			if !seenSport {
				c.SrcPort = atoi(val)
				seenSport = true
			}
		case "dport":
			if !seenDport {
				c.DstPort = atoi(val)
				seenDport = true
			}
		case "packets":
			if !seenPackets {
				c.Packets = atoi64(val)
				seenPackets = true
			}
		case "bytes":
			if !seenBytes {
				c.Bytes = atoi64(val)
				seenBytes = true
			} else {
				c.ReplyBytes = atoi64(val)
			}
		case "mac":
			c.MAC = strings.ToLower(val)
		}
	}
	return c, true
}
