package dnsroute

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

type shadowInformIdentity struct {
	client, server [4]byte
	xid            [4]byte
	mac            [6]byte
}

var shadowDHCPMagic = []byte{99, 130, 83, 99}

// The UDP header is included; Linux supplies the IPv4 header. DHCPINFORM
// requests parameters for the existing address, never an address or lease.
func makeShadowInformPacket(id shadowInformIdentity) []byte {
	packet := make([]byte, 8+300)
	binary.BigEndian.PutUint16(packet[0:2], 68)
	binary.BigEndian.PutUint16(packet[2:4], 67)
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)))
	// UDP checksum zero is permitted for IPv4.
	dhcp := packet[8:]
	dhcp[0], dhcp[1], dhcp[2] = 1, 1, 6
	copy(dhcp[4:8], id.xid[:])
	copy(dhcp[12:16], id.client[:])
	copy(dhcp[28:34], id.mac[:])
	copy(dhcp[236:240], shadowDHCPMagic)
	// No requested-address, lease-time, server-identifier, or client-id option.
	copy(dhcp[240:], []byte{53, 1, 8, 55, 1, 6, 255})
	return packet
}

func parseShadowInformOptions(data []byte, options map[byte][]byte) error {
	for i := 0; i < len(data); {
		code := data[i]
		i++
		switch code {
		case 0:
			continue
		case 255:
			return nil
		}
		if i >= len(data) || int(data[i]) > len(data)-i-1 {
			return fmt.Errorf("malformed DHCP option")
		}
		length := int(data[i])
		i++
		if _, duplicate := options[code]; duplicate && (code == 53 || code == 54 || code == 52) {
			return fmt.Errorf("duplicate DHCP control option")
		}
		// Retain only relevant options. Lease fields and any vendor/client data
		// are ignored; INFORM cannot extend a DHCP lease or establish its age.
		if code == 6 || code == 52 || code == 53 || code == 54 {
			options[code] = append(options[code], data[i:i+length]...)
		}
		i += length
	}
	return fmt.Errorf("DHCP option area lacks END")
}

func shadowInformChecksumValid(data []byte) bool {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) > 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum) == 0xffff
}

// parseShadowInformReply accepts only an unicast IPv4 ACK for this transaction.
// The returned literal DNS addresses still require caller-side loop filtering.
func parseShadowInformReply(packet []byte, id shadowInformIdentity) ([]string, error) {
	if len(packet) < 20 || packet[0]>>4 != 4 || packet[9] != 17 {
		return nil, fmt.Errorf("not IPv4 UDP")
	}
	iHL := int(packet[0]&15) * 4
	total := int(binary.BigEndian.Uint16(packet[2:4]))
	if iHL < 20 || total > len(packet) || total < iHL+8+240 || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
		return nil, fmt.Errorf("invalid IPv4 length or fragment")
	}
	if !bytes.Equal(packet[12:16], id.server[:]) || !bytes.Equal(packet[16:20], id.client[:]) {
		return nil, fmt.Errorf("wrong IPv4 endpoints")
	}
	udp := packet[iHL:total]
	length := int(binary.BigEndian.Uint16(udp[4:6]))
	if binary.BigEndian.Uint16(udp[0:2]) != 67 || binary.BigEndian.Uint16(udp[2:4]) != 68 || length < 8+240 || length > len(udp) {
		return nil, fmt.Errorf("wrong UDP endpoints or length")
	}
	udp = udp[:length]
	if binary.BigEndian.Uint16(udp[6:8]) != 0 {
		pseudo := make([]byte, 12+length)
		copy(pseudo[0:8], packet[12:20])
		pseudo[9] = 17
		binary.BigEndian.PutUint16(pseudo[10:12], uint16(length))
		copy(pseudo[12:], udp)
		if !shadowInformChecksumValid(pseudo) {
			return nil, fmt.Errorf("invalid UDP checksum")
		}
	}
	dhcp := udp[8:]
	if dhcp[0] != 2 || dhcp[1] != 1 || dhcp[2] != 6 || !bytes.Equal(dhcp[4:8], id.xid[:]) || !bytes.Equal(dhcp[28:34], id.mac[:]) {
		return nil, fmt.Errorf("wrong BOOTP reply identity")
	}
	if !bytes.Equal(dhcp[236:240], shadowDHCPMagic) {
		return nil, fmt.Errorf("wrong DHCP cookie")
	}
	zero := []byte{0, 0, 0, 0}
	// RFC2131 Table3 permits zero ciaddr in ACK. Reject another nonzero
	// address; destination, xid, hardware address, and server remain mandatory.
	if !bytes.Equal(dhcp[12:16], zero) && !bytes.Equal(dhcp[12:16], id.client[:]) {
		return nil, fmt.Errorf("wrong ACK ciaddr")
	}
	// This transport accepts only parameter-only INFORM replies. A yiaddr
	// assignment belongs to lease negotiation, which we never participate in.
	if !bytes.Equal(dhcp[16:20], zero) {
		return nil, fmt.Errorf("unexpected address assignment in INFORM ACK")
	}
	if !bytes.Equal(dhcp[24:28], zero) {
		return nil, fmt.Errorf("unexpected DHCP relay")
	}
	options := make(map[byte][]byte)
	if err := parseShadowInformOptions(dhcp[240:], options); err != nil {
		return nil, err
	}
	if overloaded, ok := options[52]; ok {
		if len(overloaded) != 1 || overloaded[0] < 1 || overloaded[0] > 3 {
			return nil, fmt.Errorf("invalid option overload")
		}
		if overloaded[0]&1 != 0 {
			if err := parseShadowInformOptions(dhcp[108:236], options); err != nil {
				return nil, err
			}
		}
		if overloaded[0]&2 != 0 {
			if err := parseShadowInformOptions(dhcp[44:108], options); err != nil {
				return nil, err
			}
		}
	}
	if !bytes.Equal(options[53], []byte{5}) || !bytes.Equal(options[54], id.server[:]) {
		return nil, fmt.Errorf("wrong DHCP type or server identifier")
	}
	dns := options[6]
	if len(dns) == 0 || len(dns)%4 != 0 {
		return nil, fmt.Errorf("DHCPACK has no valid DNS option")
	}
	servers := make([]string, 0, len(dns)/4)
	for i := 0; i < len(dns); i += 4 {
		servers = append(servers, net.IP(dns[i:i+4]).String())
	}
	return servers, nil
}
