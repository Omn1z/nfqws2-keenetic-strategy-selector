package awg

import (
	"errors"
	"net"
)

// DNS wire parsing + minimal response synthesis — pure, read-only, bounds-checked
// helpers over raw DNS messages. They never touch DNSProxy state, so they live
// apart from the proxy lifecycle in dnsproxy.go.

var errShortMsg = errors.New("dns: bad tcp message length")

// emptyNoErrorResponse turns a query into a NOERROR response with no answers
// (echoing the question), so the client sees "no AAAA record".
func emptyNoErrorResponse(query []byte) []byte {
	if len(query) < 12 {
		return query
	}
	resp := make([]byte, len(query))
	copy(resp, query)
	resp[2] |= 0x80           // QR=1 (response), keep RD/opcode
	resp[3] = 0x80            // RA=1, Z=0, RCODE=0 (NOERROR)
	resp[6], resp[7] = 0, 0   // ANCOUNT=0
	resp[8], resp[9] = 0, 0   // NSCOUNT=0
	resp[10], resp[11] = 0, 0 // ARCOUNT=0
	return resp
}

// questionInfo returns the first question's name (lowercased) and its qtype.
func questionInfo(msg []byte) (string, uint16, bool) {
	if len(msg) < 12 {
		return "", 0, false
	}
	if qd := int(msg[4])<<8 | int(msg[5]); qd < 1 {
		return "", 0, false
	}
	name, next, ok := readName(msg, 12)
	if !ok || next+2 > len(msg) {
		return "", 0, false
	}
	return name, uint16(msg[next])<<8 | uint16(msg[next+1]), true
}

// questionName returns the first question's name (dotted, lowercased) from a DNS
// message.
func questionName(msg []byte) (string, bool) {
	if len(msg) < 12 {
		return "", false
	}
	if qd := int(msg[4])<<8 | int(msg[5]); qd < 1 {
		return "", false
	}
	name, _, ok := readName(msg, 12)
	return name, ok
}

// answerIPs returns all A/AAAA addresses from a DNS response message.
func answerIPs(msg []byte) []string {
	if len(msg) < 12 {
		return nil
	}
	qd := int(msg[4])<<8 | int(msg[5])
	an := int(msg[6])<<8 | int(msg[7])
	pos := 12
	for i := 0; i < qd; i++ {
		_, np, ok := readName(msg, pos)
		if !ok {
			return nil
		}
		pos = np + 4 // qtype + qclass
		if pos > len(msg) {
			return nil
		}
	}
	var out []string
	for i := 0; i < an; i++ {
		_, np, ok := readName(msg, pos)
		if !ok {
			return out
		}
		pos = np
		if pos+10 > len(msg) {
			return out
		}
		typ := int(msg[pos])<<8 | int(msg[pos+1])
		rdlen := int(msg[pos+8])<<8 | int(msg[pos+9])
		pos += 10
		if pos+rdlen > len(msg) {
			return out
		}
		switch {
		case typ == 1 && rdlen == 4:
			out = append(out, net.IPv4(msg[pos], msg[pos+1], msg[pos+2], msg[pos+3]).String())
		case typ == 28 && rdlen == 16:
			ip := make(net.IP, 16)
			copy(ip, msg[pos:pos+16])
			out = append(out, ip.String())
		}
		pos += rdlen
	}
	return out
}

// readName decodes a (possibly compressed) domain name, returning the dotted
// lowercased name and the position just past the name in the ORIGINAL stream.
func readName(msg []byte, pos int) (string, int, bool) {
	var labels []string
	next := -1
	jumps := 0
	for {
		if pos < 0 || pos >= len(msg) {
			return "", 0, false
		}
		b := msg[pos]
		switch {
		case b == 0:
			if next < 0 {
				next = pos + 1
			}
			return joinLabels(labels), next, true
		case b&0xc0 == 0xc0:
			if pos+1 >= len(msg) {
				return "", 0, false
			}
			if next < 0 {
				next = pos + 2
			}
			pos = int(b&0x3f)<<8 | int(msg[pos+1])
			jumps++
			if jumps > 16 {
				return "", 0, false
			}
		default:
			l := int(b)
			if pos+1+l > len(msg) {
				return "", 0, false
			}
			labels = append(labels, string(msg[pos+1:pos+1+l]))
			pos += 1 + l
		}
	}
}

func joinLabels(labels []string) string {
	if len(labels) == 0 {
		return ""
	}
	out := labels[0]
	for _, l := range labels[1:] {
		out += "." + l
	}
	return toLower(out)
}

// toLower lowercases ASCII without importing strings (small + alloc-light).
func toLower(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			if b == nil {
				b = []byte(s)
			}
			b[i] = c + 32
		}
	}
	if b == nil {
		return s
	}
	return string(b)
}

func readTCPMsg(c net.Conn) ([]byte, error) {
	var l [2]byte
	if _, err := readFull(c, l[:]); err != nil {
		return nil, err
	}
	n := int(l[0])<<8 | int(l[1])
	if n == 0 || n > 65535 {
		return nil, errShortMsg
	}
	buf := make([]byte, n)
	if _, err := readFull(c, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeTCPMsg(c net.Conn, msg []byte) error {
	out := make([]byte, 2+len(msg))
	out[0] = byte(len(msg) >> 8)
	out[1] = byte(len(msg))
	copy(out[2:], msg)
	_, err := c.Write(out)
	return err
}

func readFull(c net.Conn, b []byte) (int, error) {
	got := 0
	for got < len(b) {
		n, err := c.Read(b[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}
