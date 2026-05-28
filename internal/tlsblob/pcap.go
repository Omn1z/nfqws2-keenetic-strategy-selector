package tlsblob

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"
)

// Candidate is one TLS ClientHello extracted from a capture.
type Candidate struct {
	SrcIP   string `json:"src_ip"`
	DstIP   string `json:"dst_ip"`
	DstPort int    `json:"dst_port"`
	SNI     string `json:"sni"`
	Size    int    `json:"size"`
	Bytes   []byte `json:"-"` // raw TLS record; held server-side, saved as the blob
}

// link-layer (DLT) types we understand
const (
	dltEthernet = 1
	dltRaw      = 101
	dltLinuxSLL = 113
)

const maxCandidates = 50

// ParsePcapClientHellos parses a classic libpcap stream (what `tcpdump -w`
// writes) and returns every complete TLS ClientHello sent client→server, with
// its SNI, deduplicated by SNI. Best-effort: it reassembles a hello that spans
// the first couple of TCP segments and skips anything malformed or incomplete.
func ParsePcapClientHellos(data []byte) ([]Candidate, error) {
	if len(data) < 24 {
		return nil, errors.New("pcap слишком короткий")
	}
	var bo binary.ByteOrder
	switch {
	case data[0] == 0xd4 && data[1] == 0xc3 && data[2] == 0xb2 && data[3] == 0xa1, // µs, little-endian
		data[0] == 0x4d && data[1] == 0x3c && data[2] == 0xb2 && data[3] == 0xa1: // ns, little-endian
		bo = binary.LittleEndian
	case data[0] == 0xa1 && data[1] == 0xb2 && data[2] == 0xc3 && data[3] == 0xd4, // µs, big-endian
		data[0] == 0xa1 && data[1] == 0xb2 && data[2] == 0x3c && data[3] == 0x4d: // ns, big-endian
		bo = binary.BigEndian
	default:
		return nil, errors.New("не похоже на pcap-файл")
	}
	linkType := bo.Uint32(data[20:24])
	off := 24

	type flow struct {
		src, dst string
		dport    int
		baseSeq  uint32
		buf      []byte
		need     int
	}
	flows := map[string]*flow{}
	seen := map[string]bool{}
	var out []Candidate

	for off+16 <= len(data) {
		inclLen := int(bo.Uint32(data[off+8 : off+12]))
		off += 16
		if inclLen <= 0 || off+inclLen > len(data) {
			break
		}
		pkt := data[off : off+inclLen]
		off += inclLen

		src, dst, proto, l3pl, ok := parseL2L3(linkType, pkt)
		if !ok || proto != 6 { // TCP only
			continue
		}
		sport, dport, seq, tpl, ok := parseTCP(l3pl)
		if !ok || len(tpl) == 0 {
			continue
		}
		key := src + "|" + strconv.Itoa(sport) + ">" + dst + "|" + strconv.Itoa(dport)
		f := flows[key]
		if f == nil {
			// start a flow only on a TLS handshake record that begins a ClientHello
			if len(tpl) >= 6 && tpl[0] == 0x16 && tpl[1] == 0x03 && tpl[5] == 0x01 {
				recLen := int(tpl[3])<<8 | int(tpl[4])
				f = &flow{src: src, dst: dst, dport: dport, baseSeq: seq, buf: append([]byte(nil), tpl...), need: 5 + recLen}
				flows[key] = f
			} else {
				continue
			}
		} else if offset := int(seq - f.baseSeq); offset >= 0 && offset <= len(f.buf) {
			// contiguous append (extend only — overlapping retransmits are ignored)
			if offset+len(tpl) > len(f.buf) {
				f.buf = append(f.buf[:offset], tpl...)
			}
		}

		if len(f.buf) >= f.need {
			delete(flows, key)
			ch := f.buf[:f.need]
			sni := parseSNI(ch)
			if sni != "" {
				if seen[sni] {
					continue
				}
				seen[sni] = true
			}
			out = append(out, Candidate{
				SrcIP: f.src, DstIP: f.dst, DstPort: f.dport,
				SNI: sni, Size: len(ch), Bytes: append([]byte(nil), ch...),
			})
			if len(out) >= maxCandidates {
				break
			}
		}
	}
	return out, nil
}

// parseL2L3 strips the link layer + IP header, returning the L4 payload.
func parseL2L3(linkType uint32, pkt []byte) (src, dst string, proto int, payload []byte, ok bool) {
	switch linkType {
	case dltEthernet:
		if len(pkt) < 14 {
			return
		}
		et := int(pkt[12])<<8 | int(pkt[13])
		l := 14
		for et == 0x8100 || et == 0x88a8 { // 802.1Q / 802.1ad VLAN tag(s)
			if len(pkt) < l+4 {
				return
			}
			et = int(pkt[l+2])<<8 | int(pkt[l+3])
			l += 4
		}
		return parseIP(et, pkt[l:])
	case dltLinuxSLL:
		if len(pkt) < 16 {
			return
		}
		return parseIP(int(pkt[14])<<8|int(pkt[15]), pkt[16:])
	case dltRaw:
		if len(pkt) < 1 {
			return
		}
		switch pkt[0] >> 4 {
		case 4:
			return parseIPv4(pkt)
		case 6:
			return parseIPv6(pkt)
		}
	}
	return
}

func parseIP(etherType int, b []byte) (src, dst string, proto int, payload []byte, ok bool) {
	switch etherType {
	case 0x0800:
		return parseIPv4(b)
	case 0x86dd:
		return parseIPv6(b)
	}
	return
}

func parseIPv4(b []byte) (src, dst string, proto int, payload []byte, ok bool) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return
	}
	if fragOff := int(b[6]&0x1f)<<8 | int(b[7]); fragOff != 0 || b[6]&0x20 != 0 {
		return // fragmented — a ClientHello fits unfragmented, so skip
	}
	return net.IP(b[12:16]).String(), net.IP(b[16:20]).String(), int(b[9]), b[ihl:], true
}

func parseIPv6(b []byte) (src, dst string, proto int, payload []byte, ok bool) {
	if len(b) < 40 || b[0]>>4 != 6 {
		return
	}
	// assume no extension headers (ClientHello packets don't carry them)
	return net.IP(b[8:24]).String(), net.IP(b[24:40]).String(), int(b[6]), b[40:], true
}

func parseTCP(b []byte) (sport, dport int, seq uint32, payload []byte, ok bool) {
	if len(b) < 20 {
		return
	}
	dataOff := int(b[12]>>4) * 4
	if dataOff < 20 || len(b) < dataOff {
		return
	}
	return int(b[0])<<8 | int(b[1]), int(b[2])<<8 | int(b[3]), binary.BigEndian.Uint32(b[4:8]), b[dataOff:], true
}

// parseSNI reads the server_name from a full ClientHello record (starting at the
// 0x16 record header). Returns "" if absent or malformed.
func parseSNI(rec []byte) string {
	if len(rec) < 43 || rec[5] != 0x01 {
		return ""
	}
	body := rec[5+4:] // skip record header (5) + handshake header (4)
	p := 34           // client_version(2) + random(32)
	rd1 := func() (int, bool) { // length-prefixed-by-1-byte field: skip it
		if p >= len(body) {
			return 0, false
		}
		n := int(body[p])
		p += 1 + n
		return n, p <= len(body)
	}
	if _, ok := rd1(); !ok { // session_id
		return ""
	}
	if p+2 > len(body) { // cipher_suites (2-byte len)
		return ""
	}
	p += 2 + (int(body[p])<<8 | int(body[p+1]))
	if _, ok := rd1(); !ok { // compression_methods
		return ""
	}
	if p+2 > len(body) { // extensions (2-byte len)
		return ""
	}
	end := p + 2 + (int(body[p])<<8 | int(body[p+1]))
	p += 2
	if end > len(body) {
		end = len(body)
	}
	for p+4 <= end {
		etype := int(body[p])<<8 | int(body[p+1])
		elen := int(body[p+2])<<8 | int(body[p+3])
		p += 4
		if p+elen > end {
			return ""
		}
		if etype == 0x0000 {
			if sni := parseSNIExt(body[p : p+elen]); sni != "" {
				return sni
			}
		}
		p += elen
	}
	return ""
}

// parseSNIExt reads the first host_name from a server_name extension body.
func parseSNIExt(d []byte) string {
	if len(d) < 2 {
		return ""
	}
	listLen := int(d[0])<<8 | int(d[1])
	p := 2
	if 2+listLen > len(d) {
		return ""
	}
	for p+3 <= 2+listLen {
		nameType := d[p]
		nameLen := int(d[p+1])<<8 | int(d[p+2])
		p += 3
		if p+nameLen > len(d) {
			return ""
		}
		if nameType == 0x00 {
			return string(d[p : p+nameLen])
		}
		p += nameLen
	}
	return ""
}
