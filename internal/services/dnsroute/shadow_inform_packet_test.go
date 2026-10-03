package dnsroute

import (
	"bytes"
	"encoding/binary"
	"net"
	"reflect"
	"testing"
)

func shadowInformTestIdentity() shadowInformIdentity {
	return shadowInformIdentity{client: [4]byte{192, 168, 0, 10}, server: [4]byte{192, 168, 0, 1}, xid: [4]byte{1, 2, 3, 4}, mac: [6]byte{2, 0, 1, 2, 3, 4}}
}

func shadowInformACKFixture() []byte {
	id := shadowInformTestIdentity()
	packet := make([]byte, 20+8+300)
	packet[0], packet[9] = 0x45, 17
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], id.server[:])
	copy(packet[16:20], id.client[:])
	copy(packet[20:], makeShadowInformPacket(id))
	binary.BigEndian.PutUint16(packet[20:22], 67)
	binary.BigEndian.PutUint16(packet[22:24], 68)
	packet[28] = 2
	clear(packet[268:])
	copy(packet[268:], []byte{53, 1, 5, 54, 4, 192, 168, 0, 1, 6, 8, 77, 88, 8, 7, 1, 1, 1, 1, 255})
	return packet
}

func TestShadowInformRequestNeverRequestsLeaseOrAddress(t *testing.T) {
	id := shadowInformTestIdentity()
	p := makeShadowInformPacket(id)
	if len(p) != 308 || binary.BigEndian.Uint16(p[:2]) != 68 || binary.BigEndian.Uint16(p[2:4]) != 67 || binary.BigEndian.Uint16(p[4:6]) != uint16(len(p)) || p[6] != 0 || p[7] != 0 {
		t.Fatal("invalid UDP request")
	}
	d := p[8:]
	if d[0] != 1 || d[1] != 1 || d[2] != 6 || d[3] != 0 || !bytes.Equal(d[4:8], id.xid[:]) || !bytes.Equal(d[12:16], id.client[:]) || !bytes.Equal(d[28:34], id.mac[:]) || !bytes.Equal(d[236:240], shadowDHCPMagic) {
		t.Fatal("invalid BOOTP request")
	}
	if !bytes.Equal(d[8:12], make([]byte, 4)) || !bytes.Equal(d[16:28], make([]byte, 12)) {
		t.Fatal("INFORM must not request broadcast, a new address, or a relay")
	}
	if !bytes.Equal(d[240:247], []byte{53, 1, 8, 55, 1, 6, 255}) || !bytes.Equal(d[247:], make([]byte, len(d)-247)) {
		t.Fatal("request contains options other than INFORM and PRL DNS")
	}
}

func TestShadowInformACKStrictIdentity(t *testing.T) {
	id := shadowInformTestIdentity()
	packet := shadowInformACKFixture()
	servers, err := parseShadowInformReply(packet, id)
	if err != nil || !reflect.DeepEqual(servers, []string{"77.88.8.7", "1.1.1.1"}) {
		t.Fatalf("valid ACK: %v %v", servers, err)
	}
	for name, offset := range map[string]int{"version": 0, "protocol": 9, "source": 12, "destination": 16, "source_port": 21, "dest_port": 23, "op": 28, "htype": 29, "hlen": 30, "xid": 32, "mac": 56, "ciaddr": 40, "yiaddr": 44, "giaddr": 52, "cookie": 264, "type": 270, "server_id": 273} {
		t.Run(name, func(t *testing.T) {
			p := append([]byte(nil), packet...)
			p[offset] ^= 1
			if _, err := parseShadowInformReply(p, id); err == nil {
				t.Fatal("accepted changed reply identity")
			}
			if _, _, err := parseShadowInformDiscoverReply(p, id); err == nil {
				t.Fatal("discovery accepted changed reply identity")
			}
		})
	}
	for n := 0; n < len(packet); n++ {
		if _, err := parseShadowInformReply(packet[:n], id); err == nil {
			t.Fatalf("accepted truncated packet %d", n)
		}
		if _, _, err := parseShadowInformDiscoverReply(packet[:n], id); err == nil {
			t.Fatalf("discovery accepted truncated packet %d", n)
		}
	}
	zeroCI := append([]byte(nil), packet...)
	clear(zeroCI[40:44])
	if _, err := parseShadowInformReply(zeroCI, id); err != nil {
		t.Fatalf("permitted zero ACK ciaddr: %v", err)
	}
}

func TestShadowInformACKLengthsAndFragments(t *testing.T) {
	for name, alter := range map[string]func([]byte){
		"short_ihl":       func(p []byte) { p[0] = 0x44 },
		"oversized_ihl":   func(p []byte) { p[0] = 0x4f },
		"short_ip":        func(p []byte) { binary.BigEndian.PutUint16(p[2:4], 247) },
		"long_ip":         func(p []byte) { binary.BigEndian.PutUint16(p[2:4], 0xffff) },
		"more_fragments":  func(p []byte) { p[6] = 0x20 },
		"fragment_offset": func(p []byte) { p[7] = 1 },
		"short_udp":       func(p []byte) { binary.BigEndian.PutUint16(p[24:26], 247) },
		"long_udp":        func(p []byte) { binary.BigEndian.PutUint16(p[24:26], 0xffff) },
		"wrong_checksum":  func(p []byte) { p[26] = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			packet := shadowInformACKFixture()
			alter(packet)
			if _, err := parseShadowInformReply(packet, shadowInformTestIdentity()); err == nil {
				t.Fatal("accepted malformed datagram")
			}
			if _, _, err := parseShadowInformDiscoverReply(packet, shadowInformTestIdentity()); err == nil {
				t.Fatal("discovery accepted malformed datagram")
			}
		})
	}
	// IPv4 options move UDP to the header's actual IHL, not a hard-coded 20.
	p := shadowInformACKFixture()
	withOptions := append(append(append([]byte(nil), p[:20]...), 1, 1, 1, 1), p[20:]...)
	withOptions[0] = 0x46
	binary.BigEndian.PutUint16(withOptions[2:4], uint16(len(withOptions)))
	if _, err := parseShadowInformReply(withOptions, shadowInformTestIdentity()); err != nil {
		t.Fatalf("valid IP options: %v", err)
	}
	// RFC1071 example words plus their complement checksum, also exercise
	// an odd final octet using an explicit zero padding octet equivalence.
	if !shadowInformChecksumValid([]byte{0, 1, 0xf2, 3, 0xf4, 0xf5, 0xf6, 0xf7, 0x22, 0x0d}) || !shadowInformChecksumValid([]byte{0xff, 0xff, 0}) {
		t.Fatal("Internet checksum folding or odd-byte handling is incorrect")
	}
}

func TestShadowInformACKRejectsMalformedOptions(t *testing.T) {
	for name, options := range map[string][]byte{
		"truncated":          {53, 255},
		"duplicate_type":     {53, 1, 5, 53, 1, 5, 255},
		"empty_type":         {53, 0, 54, 4, 192, 168, 0, 1, 6, 4, 1, 1, 1, 1, 255},
		"empty_server":       {53, 1, 5, 54, 0, 6, 4, 1, 1, 1, 1, 255},
		"empty_overload":     {52, 0, 255},
		"duplicate_overload": {52, 1, 1, 52, 1, 1, 255},
		"duplicate_server":   {53, 1, 5, 54, 4, 192, 168, 0, 1, 54, 4, 192, 168, 0, 1, 255},
		"invalid_dns":        {53, 1, 5, 54, 4, 192, 168, 0, 1, 6, 3, 1, 1, 1, 255},
		"missing_dns":        {53, 1, 5, 54, 4, 192, 168, 0, 1, 255},
		"empty_dns":          {53, 1, 5, 54, 4, 192, 168, 0, 1, 6, 0, 255},
		"missing_end":        {53, 1, 5, 54, 4, 192, 168, 0, 1, 6, 4, 1, 1, 1, 1},
		"invalid_overload":   {52, 1, 4, 255},
	} {
		t.Run(name, func(t *testing.T) {
			p := shadowInformACKFixture()
			clear(p[268:])
			copy(p[268:], options)
			if _, err := parseShadowInformReply(p, shadowInformTestIdentity()); err == nil {
				t.Fatal("accepted malformed options")
			}
			if _, _, err := parseShadowInformDiscoverReply(p, shadowInformTestIdentity()); err == nil {
				t.Fatal("discovery accepted malformed options")
			}
		})
	}
}

func TestShadowInformDiscoveryLearnsOnlyFullyValidatedPeer(t *testing.T) {
	id := shadowInformTestIdentity()
	packet := shadowInformACKFixture()
	// The server is learned from a matching ACK, independently of any gateway
	// or previous peer. The known-server parser must remain just as strict.
	peer := net.IPv4(192, 0, 2, 41).To4()
	copy(packet[12:16], peer)
	copy(packet[273:277], peer)
	if _, err := parseShadowInformReply(packet, id); err == nil {
		t.Fatal("known-server exchange accepted an unrelated peer")
	}
	id.server = [4]byte{}
	got, servers, err := parseShadowInformDiscoverReply(packet, id)
	if err != nil || !got.Equal(peer) || !reflect.DeepEqual(servers, []string{"77.88.8.7", "1.1.1.1"}) {
		t.Fatalf("valid discovered peer: %v %v %v", got, servers, err)
	}
	packet[12] ^= 1
	if !got.Equal(peer) {
		t.Fatal("learned peer retained receive-buffer memory")
	}
	// Both modes request only INFORM and DNS, with the existing ciaddr and a
	// zero BOOTP broadcast flag: RFC2131 servers answer this INFORM unicast.
	if !bytes.Equal(makeShadowInformPacket(id), makeShadowInformPacket(shadowInformTestIdentity())) {
		t.Fatal("peer discovery changed DHCP request or introduced lease options")
	}
}

func TestShadowInformDiscoveryRejectsNonUnicastOrSelfPeer(t *testing.T) {
	for _, source := range []string{"0.0.0.0", "127.0.0.1", "169.254.1.1", "224.0.0.1", "255.255.255.255", "192.168.0.10"} {
		t.Run(source, func(t *testing.T) {
			packet := shadowInformACKFixture()
			ip := net.ParseIP(source).To4()
			copy(packet[12:16], ip)
			copy(packet[273:277], ip)
			peer, servers, err := parseShadowInformDiscoverReply(packet, shadowInformTestIdentity())
			if err == nil || peer != nil || servers != nil {
				t.Fatalf("unsafe discovered peer: %v %v %v", peer, servers, err)
			}
		})
	}
}

func TestShadowInformACKOverloadAndCallerFiltering(t *testing.T) {
	p := shadowInformACKFixture()
	clear(p[268:])
	copy(p[268:], []byte{53, 1, 5, 54, 4, 192, 168, 0, 1, 52, 1, 3, 6, 4, 77, 88, 8, 7, 255})
	copy(p[28+108:28+236], []byte{6, 4, 127, 0, 0, 1, 255})
	copy(p[28+44:28+108], []byte{6, 4, 192, 168, 0, 10, 255})
	servers, err := parseShadowInformReply(p, shadowInformTestIdentity())
	if err != nil || !reflect.DeepEqual(servers, []string{"77.88.8.7", "127.0.0.1", "192.168.0.10"}) {
		t.Fatalf("overload order/caller filter input: %v %v", servers, err)
	}
	copy(p[28+108:28+236], []byte{54, 4, 192, 168, 0, 1, 255})
	if _, err := parseShadowInformReply(p, shadowInformTestIdentity()); err == nil {
		t.Fatal("accepted duplicate server-ID hidden in overloaded file field")
	}
}
