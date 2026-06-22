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
// isSinkholeResponse reports whether the upstream's reply is a "no destination"
// answer — Pi-hole / ad-blocker / domain-blocked-by-policy. Three shapes count:
//
//  1. RCODE = NXDOMAIN (rcode 3) — Pi-hole default reply for a blocked name.
//  2. RCODE = NOERROR (rcode 0) with ANCOUNT = 0 — "domain exists but no record
//     of this type" (also matches Pi-hole when the upstream returns an empty
//     NOERROR for a sinkholed domain via its `BLOCKINGMODE=NXDOMAIN-EMPTY`
//     fallback).
//  3. RCODE = NOERROR with every A == 0.0.0.0 and every AAAA == :: — Pi-hole's
//     `BLOCKINGMODE=NULL` mode where it answers with the null route.
//
// Header-only checks for (1) and (2) cost nothing; case (3) reuses the existing
// answerIPs walker. Used by the trace layer to label the row "blocked" rather
// than the misleading routing decision ("tunnel"/"direct") that would have
// applied if the answer wasn't a sinkhole.
func isSinkholeResponse(msg []byte) bool {
	if len(msg) < 12 {
		return false
	}
	rcode := msg[3] & 0x0F
	if rcode == 3 { // NXDOMAIN — case 1
		return true
	}
	if rcode != 0 {
		return false // SERVFAIL / REFUSED / etc. — not a sinkhole, propagate as-is
	}
	if msg[6] == 0 && msg[7] == 0 { // NOERROR + ANCOUNT=0 — case 2
		return true
	}
	ips := answerIPs(msg)
	if len(ips) == 0 {
		return false
	}
	for _, ip := range ips { // case 3 — all null-route
		if ip != "0.0.0.0" && ip != "::" {
			return false
		}
	}
	return true
}

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

// parseECSFromQuery walks the Additional section for an OPT pseudo-record
// (RFC 6891) and within it for the EDNS0 Client Subnet option (RFC 7871,
// code 8). Returns the client IP string when found.
//
// Why we need this: pi-hole sits in front of our proxy (LAN :53 → pi-hole →
// 127.0.0.1:5354). From the proxy's socket perspective every query arrives
// from localhost, so the trace log would show "src=127.0.0.1" for everything.
// Pi-hole, when configured with `add-subnet=32,128`, copies the original
// client IP into the OPT record's Client Subnet option, and this parser
// recovers it. When the option isn't present we return ("", false) and the
// caller falls back to the socket peer.
func parseECSFromQuery(msg []byte) (string, bool) {
	if len(msg) < 12 {
		return "", false
	}
	qd := int(msg[4])<<8 | int(msg[5])
	an := int(msg[6])<<8 | int(msg[7])
	ns := int(msg[8])<<8 | int(msg[9])
	ar := int(msg[10])<<8 | int(msg[11])
	if ar == 0 {
		return "", false
	}
	pos := 12
	// Skip QD entries (name + qtype + qclass).
	for i := 0; i < qd; i++ {
		_, np, ok := readName(msg, pos)
		if !ok {
			return "", false
		}
		pos = np + 4
		if pos > len(msg) {
			return "", false
		}
	}
	// Skip AN + NS RRs (name + 10-byte header + rdlength).
	for i := 0; i < an+ns; i++ {
		_, np, ok := readName(msg, pos)
		if !ok {
			return "", false
		}
		pos = np
		if pos+10 > len(msg) {
			return "", false
		}
		rdlen := int(msg[pos+8])<<8 | int(msg[pos+9])
		pos += 10 + rdlen
		if pos > len(msg) {
			return "", false
		}
	}
	// Walk AR looking for OPT (type 41).
	for i := 0; i < ar; i++ {
		_, np, ok := readName(msg, pos)
		if !ok {
			return "", false
		}
		pos = np
		if pos+10 > len(msg) {
			return "", false
		}
		rtype := int(msg[pos])<<8 | int(msg[pos+1])
		rdlen := int(msg[pos+8])<<8 | int(msg[pos+9])
		body := pos + 10
		next := body + rdlen
		if next > len(msg) {
			return "", false
		}
		if rtype == 41 {
			for op := body; op+4 <= next; {
				optCode := int(msg[op])<<8 | int(msg[op+1])
				optLen := int(msg[op+2])<<8 | int(msg[op+3])
				if op+4+optLen > next {
					break
				}
				if optCode == 8 && optLen >= 4 {
					family := int(msg[op+4])<<8 | int(msg[op+5])
					addrBytes := optLen - 4
					switch {
					case family == 1 && addrBytes >= 1 && addrBytes <= 4:
						ip := make(net.IP, 4)
						copy(ip, msg[op+8:op+8+addrBytes])
						return ip.String(), true
					case family == 2 && addrBytes >= 1 && addrBytes <= 16:
						ip := make(net.IP, 16)
						copy(ip, msg[op+8:op+8+addrBytes])
						return ip.String(), true
					}
				}
				op += 4 + optLen
			}
		}
		pos = next
	}
	return "", false
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
