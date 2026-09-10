// Package geo parses v2ray-format geosite.dat / geoip.dat (protobuf) and plain
// text lists into categories of domains or IP/CIDRs, for use as run targets.
package geo

import (
	"encoding/binary"
	"net"
	"sort"
	"strings"
)

// Kind of a geo file.
const (
	KindGeoSite = "geosite"
	KindGeoIP   = "geoip"
	KindText    = "text"
)

// Category is one named bucket of entries.
type Category struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// pbWalk iterates protobuf fields in data, calling fn(fieldNum, wireType,
// varintValue, lenDelimitedBytes). It is best-effort and stops on malformed
// input. Only wire types 0 (varint) and 2 (length-delimited) carry data we use.
func pbWalk(data []byte, fn func(num, wire int, v uint64, b []byte)) {
	i := 0
	for i < len(data) {
		key, n := binary.Uvarint(data[i:])
		if n <= 0 {
			return
		}
		i += n
		num, wire := int(key>>3), int(key&7)
		switch wire {
		case 0:
			v, n := binary.Uvarint(data[i:])
			if n <= 0 {
				return
			}
			i += n
			fn(num, 0, v, nil)
		case 2:
			l, n := binary.Uvarint(data[i:])
			if n <= 0 || i+n+int(l) > len(data) {
				return
			}
			i += n
			fn(num, 2, 0, data[i:i+int(l)])
			i += int(l)
		case 1:
			i += 8
		case 5:
			i += 4
		default:
			return
		}
	}
}

// ParseGeoSite returns category(lowercased) -> domains.
func ParseGeoSite(data []byte) map[string][]string {
	out := map[string][]string{}
	pbWalk(data, func(num, wire int, _ uint64, b []byte) {
		if num != 1 || wire != 2 { // repeated GeoSite entry
			return
		}
		var code string
		var domains []string
		pbWalk(b, func(n2, w2 int, _ uint64, b2 []byte) {
			switch {
			case n2 == 1 && w2 == 2:
				code = string(b2)
			case n2 == 2 && w2 == 2: // repeated Domain
				var typ uint64
				var val string
				pbWalk(b2, func(n3, w3 int, v3 uint64, b3 []byte) {
					switch {
					case n3 == 1 && w3 == 0:
						typ = v3
					case n3 == 2 && w3 == 2:
						val = string(b3)
					}
				})
				if val != "" && typ != 1 { // skip Regex(1); keep Plain/Domain/Full
					domains = append(domains, val)
				}
			}
		})
		if code != "" {
			c := strings.ToLower(code)
			out[c] = append(out[c], domains...)
		}
	})
	return out
}

// ParseGeoIP returns category(lowercased) -> CIDR strings.
func ParseGeoIP(data []byte) map[string][]string {
	out := map[string][]string{}
	pbWalk(data, func(num, wire int, _ uint64, b []byte) {
		if num != 1 || wire != 2 { // repeated GeoIP entry
			return
		}
		var code string
		var cidrs []string
		pbWalk(b, func(n2, w2 int, _ uint64, b2 []byte) {
			switch {
			case n2 == 1 && w2 == 2:
				code = string(b2)
			case n2 == 2 && w2 == 2: // repeated CIDR
				var ip net.IP
				var prefix uint64
				pbWalk(b2, func(n3, w3 int, v3 uint64, b3 []byte) {
					switch {
					case n3 == 1 && w3 == 2:
						ip = net.IP(append([]byte(nil), b3...))
					case n3 == 2 && w3 == 0:
						prefix = v3
					}
				})
				if len(ip) == 4 || len(ip) == 16 {
					bits := 32
					if len(ip) == 16 {
						bits = 128
					}
					p := int(prefix)
					if p == 0 || p > bits {
						p = bits
					}
					cidrs = append(cidrs, (&net.IPNet{IP: ip, Mask: net.CIDRMask(p, bits)}).String())
				}
			}
		})
		if code != "" {
			c := strings.ToLower(code)
			out[c] = append(out[c], cidrs...)
		}
	})
	return out
}

// ParseText treats the file as a single category "all" of one entry per line
// (comments starting with # and blank lines ignored).
func ParseText(data []byte) map[string][]string {
	var items []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		items = append(items, line)
	}
	return map[string][]string{"all": items}
}

// Parse dispatches on kind.
func Parse(kind string, data []byte) map[string][]string {
	switch kind {
	case KindGeoSite:
		return ParseGeoSite(data)
	case KindGeoIP:
		return ParseGeoIP(data)
	default:
		return ParseText(data)
	}
}

// Categories summarizes a parsed map as a sorted list with counts.
func Categories(m map[string][]string) []Category {
	out := make([]Category, 0, len(m))
	for name, items := range m {
		out = append(out, Category{Name: name, Count: len(items)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
