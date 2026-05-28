package tlsblob

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"net"
	"testing"
)

func TestGenerateClientHelloRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		alpn []string
		min  uint16
	}{
		{"default", nil, 0},
		{"h2-tls12", []string{"h2", "http/1.1"}, tls.VersionTLS12},
		{"tls13", nil, tls.VersionTLS13},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ch, err := GenerateClientHello("example.com", tc.alpn, tc.min)
			if err != nil {
				t.Fatal(err)
			}
			if len(ch) < 6 || ch[0] != 0x16 || ch[1] != 0x03 || ch[5] != 0x01 {
				t.Fatalf("bad record/handshake header: % x", ch[:6])
			}
			if recLen := int(ch[3])<<8 | int(ch[4]); len(ch) != 5+recLen {
				t.Fatalf("len %d != 5+recLen %d", len(ch), 5+recLen)
			}
			if sni := parseSNI(ch); sni != "example.com" {
				t.Fatalf("parsed SNI = %q, want example.com", sni)
			}
		})
	}
}

func TestGenerateRejectsIPAndEmpty(t *testing.T) {
	if _, err := GenerateClientHello("  ", nil, 0); err == nil {
		t.Fatal("want error for empty SNI")
	}
	if _, err := GenerateClientHello("1.2.3.4", nil, 0); err == nil {
		t.Fatal("want error for IP SNI")
	}
}

func TestParsePcapSingleSegment(t *testing.T) {
	ch, _ := GenerateClientHello("dump.example.org", []string{"h2"}, 0)
	pcap := buildPcap(dltEthernet, [][]byte{ethIPv4TCP("10.0.0.5", "93.184.216.34", 51000, 443, 1000, ch)})
	cands, err := ParsePcapClientHellos(pcap)
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 1 {
		t.Fatalf("got %d candidates, want 1", len(cands))
	}
	c := cands[0]
	if c.SNI != "dump.example.org" || c.DstPort != 443 || c.DstIP != "93.184.216.34" || c.SrcIP != "10.0.0.5" {
		t.Fatalf("candidate = %+v", c)
	}
	if !bytes.Equal(c.Bytes, ch) {
		t.Fatalf("captured bytes differ from original (%d vs %d)", len(c.Bytes), len(ch))
	}
}

func TestParsePcapReassembleTwoSegments(t *testing.T) {
	ch, _ := GenerateClientHello("split.example.net", nil, 0)
	split := 40
	seg1 := ethIPv4TCP("10.0.0.9", "1.1.1.1", 52000, 443, 5000, ch[:split])
	seg2 := ethIPv4TCP("10.0.0.9", "1.1.1.1", 52000, 443, 5000+uint32(split), ch[split:])
	pcap := buildPcap(dltEthernet, [][]byte{seg1, seg2})
	cands, err := ParsePcapClientHellos(pcap)
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 1 || cands[0].SNI != "split.example.net" {
		t.Fatalf("reassembly failed: %+v", cands)
	}
	if !bytes.Equal(cands[0].Bytes, ch) {
		t.Fatal("reassembled bytes differ from original")
	}
}

func TestParsePcapDedupAndIgnore(t *testing.T) {
	ch, _ := GenerateClientHello("dup.example.com", nil, 0)
	frames := [][]byte{
		ethIPv4TCP("10.0.0.1", "2.2.2.2", 5, 443, 1, []byte("GET / HTTP/1.1\r\n")),      // not a hello
		ethIPv4TCP("10.0.0.1", "8.8.8.8", 40000, 443, 100, ch),                          // hello #1
		ethIPv4TCP("10.0.0.2", "9.9.9.9", 40001, 443, 200, ch),                          // same SNI → deduped
	}
	cands, err := ParsePcapClientHellos(buildPcap(dltEthernet, frames))
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 1 || cands[0].SNI != "dup.example.com" {
		t.Fatalf("want 1 deduped candidate, got %+v", cands)
	}
}

func TestParsePcapRejectsNonPcap(t *testing.T) {
	if _, err := ParsePcapClientHellos([]byte("this is not a pcap file at all!!")); err == nil {
		t.Fatal("want error for non-pcap input")
	}
}

// --- pcap / frame builders for tests ---

func buildPcap(linkType uint32, frames [][]byte) []byte {
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:], 0xa1b2c3d4) // LE write → bytes d4 c3 b2 a1
	binary.LittleEndian.PutUint16(hdr[4:], 2)
	binary.LittleEndian.PutUint16(hdr[6:], 4)
	binary.LittleEndian.PutUint32(hdr[16:], 262144)
	binary.LittleEndian.PutUint32(hdr[20:], linkType)
	b := append([]byte(nil), hdr...)
	for _, f := range frames {
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[8:], uint32(len(f)))
		binary.LittleEndian.PutUint32(rec[12:], uint32(len(f)))
		b = append(b, rec...)
		b = append(b, f...)
	}
	return b
}

func ethIPv4TCP(src, dst string, sport, dport int, seq uint32, payload []byte) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], uint16(sport))
	binary.BigEndian.PutUint16(tcp[2:], uint16(dport))
	binary.BigEndian.PutUint32(tcp[4:], seq)
	tcp[12] = 5 << 4 // data offset = 5 words
	tcp[13] = 0x18   // PSH|ACK
	tcp = append(tcp, payload...)

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(tcp)))
	ip[8] = 64 // ttl
	ip[9] = 6  // TCP
	copy(ip[12:16], net.ParseIP(src).To4())
	copy(ip[16:20], net.ParseIP(dst).To4())
	ip = append(ip, tcp...)

	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:], 0x0800) // IPv4
	return append(eth, ip...)
}
