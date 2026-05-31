package dns

import (
	"crypto/rand"
	"errors"
	"net"
	"strings"
)

var (
	errShort   = errors.New("dns: short message")
	errNoA     = errors.New("dns: no A record")
	errBadName = errors.New("dns: bad name")
)

// buildQuery encodes a standard recursive query for the A record of host.
func buildQuery(host string) ([]byte, error) {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" {
		return nil, errBadName
	}
	labels := strings.Split(host, ".")
	size := 12 + 1 + 4 // header + root label + qtype/qclass
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 {
			return nil, errBadName
		}
		size += 1 + len(l)
	}
	b := make([]byte, 0, size)
	var id [2]byte
	_, _ = rand.Read(id[:])
	b = append(b, id[0], id[1]) // transaction id
	b = append(b, 0x01, 0x00)   // flags: RD=1
	b = append(b, 0x00, 0x01)   // QDCOUNT=1
	b = append(b, 0x00, 0x00)   // ANCOUNT
	b = append(b, 0x00, 0x00)   // NSCOUNT
	b = append(b, 0x00, 0x00)   // ARCOUNT
	for _, l := range labels {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0x00)       // root
	b = append(b, 0x00, 0x01) // QTYPE = A
	b = append(b, 0x00, 0x01) // QCLASS = IN
	return b, nil
}

// parseA returns the first IPv4 address from a DNS response message.
func parseA(msg []byte) (string, error) {
	if len(msg) < 12 {
		return "", errShort
	}
	if rcode := msg[3] & 0x0f; rcode != 0 {
		return "", &rcodeError{rcode}
	}
	qd := int(msg[4])<<8 | int(msg[5])
	an := int(msg[6])<<8 | int(msg[7])
	pos := 12
	for i := 0; i < qd; i++ {
		p, err := skipName(msg, pos)
		if err != nil {
			return "", err
		}
		pos = p + 4 // qtype + qclass
		if pos > len(msg) {
			return "", errShort
		}
	}
	for i := 0; i < an; i++ {
		p, err := skipName(msg, pos)
		if err != nil {
			return "", err
		}
		pos = p
		if pos+10 > len(msg) {
			return "", errShort
		}
		typ := int(msg[pos])<<8 | int(msg[pos+1])
		rdlen := int(msg[pos+8])<<8 | int(msg[pos+9])
		pos += 10
		if pos+rdlen > len(msg) {
			return "", errShort
		}
		if typ == 1 && rdlen == 4 { // A
			ip := net.IPv4(msg[pos], msg[pos+1], msg[pos+2], msg[pos+3])
			return ip.String(), nil
		}
		pos += rdlen
	}
	return "", errNoA
}

// skipName advances past a (possibly compressed) domain name and returns the
// position just after it. A compression pointer (top two bits set) ends the
// name in two bytes.
func skipName(msg []byte, pos int) (int, error) {
	for {
		if pos >= len(msg) {
			return 0, errShort
		}
		b := msg[pos]
		switch {
		case b == 0:
			return pos + 1, nil
		case b&0xc0 == 0xc0:
			if pos+2 > len(msg) {
				return 0, errShort
			}
			return pos + 2, nil
		default:
			pos += 1 + int(b)
		}
	}
}

type rcodeError struct{ code byte }

func (e *rcodeError) Error() string {
	switch e.code {
	case 1:
		return "dns: format error"
	case 2:
		return "dns: server failure"
	case 3:
		return "dns: NXDOMAIN"
	case 5:
		return "dns: refused"
	}
	return "dns: rcode error"
}
