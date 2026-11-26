package dnsroute

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const (
	shadowNativePendingLimit = 8
	shadowNativePendingTTL   = 2 * time.Minute
	shadowNativeMaxLease     = 7 * 24 * time.Hour
)

// This tracker observes the firmware DHCP client; it never creates a request.
// A tracker belongs to one verified WAN address/MAC and must be replaced when
// either changes. The owner serializes Observe calls.
type shadowNativeDHCPTracker struct {
	client   [4]byte
	mac      [6]byte
	pending  map[[4]byte]shadowNativePending
	sequence uint64
}

type shadowNativePending struct {
	started  time.Time
	sequence uint64
	server   [4]byte // Nonzero only when REQUEST explicitly selected option 54.
}

// Kind is empty for unrelated traffic, request, ack, ack_no_dns, nak, or
// rejected. Only ack supplies DNS with an expiry. ack_no_dns and nak are
// correlated native replies and let the owner withdraw a previous native lease.
// Returned fields never reference the reusable packet capture buffer.
type shadowNativeDHCPObservation struct {
	Kind         string
	XID          string
	ServerIP     net.IP
	Servers      []string
	LeaseSeconds uint64
	LeaseExpires time.Time
	Err          error
}

func newShadowNativeDHCPTracker(client net.IP, mac net.HardwareAddr) (*shadowNativeDHCPTracker, error) {
	ip := client.To4()
	if ip == nil || !shadowNativePeer(ip) || len(mac) != 6 || mac[0]&1 != 0 || bytes.Equal(mac, make([]byte, 6)) {
		return nil, fmt.Errorf("invalid native DHCP WAN identity")
	}
	t := &shadowNativeDHCPTracker{pending: make(map[[4]byte]shadowNativePending)}
	copy(t.client[:], ip)
	copy(t.mac[:], mac)
	return t, nil
}

func shadowNativePeer(ip net.IP) bool {
	return len(ip) == 4 && ip[0] != 0 && ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

func (t *shadowNativeDHCPTracker) prune(now time.Time) {
	for xid, request := range t.pending {
		if now.Before(request.started) || !now.Before(request.started.Add(shadowNativePendingTTL)) {
			delete(t.pending, xid)
		}
	}
}

func (t *shadowNativeDHCPTracker) complete(request shadowNativePending) {
	// A late ACK for an older transaction must not roll back a newer lease.
	// Consuming pending requests also rejects duplicate replies until another
	// validated outgoing REQUEST is seen. Keenetic reuses XID across renewals,
	// so completed XIDs themselves must not prevent a fresh native exchange.
	// DHCP carries no generation beyond XID: after reuse, an old matching ACK
	// cannot be distinguished from the new reply by passive observation alone.
	for id, pending := range t.pending {
		if pending.sequence <= request.sequence {
			delete(t.pending, id)
		}
	}
}

func (t *shadowNativeDHCPTracker) Observe(packet []byte, outgoing bool, now time.Time) shadowNativeDHCPObservation {
	t.prune(now)
	udp, dhcp, err := shadowNativeDatagram(packet, outgoing)
	if err != nil || dhcp[1] != 1 || dhcp[2] != 6 || !bytes.Equal(dhcp[28:34], t.mac[:]) {
		return shadowNativeDHCPObservation{}
	}
	var xid [4]byte
	copy(xid[:], dhcp[4:8])
	request, correlated := t.pending[xid]
	if !outgoing && !correlated {
		return shadowNativeDHCPObservation{}
	}
	observation := shadowNativeDHCPObservation{Kind: "rejected", XID: fmt.Sprintf("%x", xid)}
	reject := func(reason string) shadowNativeDHCPObservation {
		observation.Err = fmt.Errorf("%s", reason)
		return observation
	}
	if !bytes.Equal(dhcp[236:240], shadowDHCPMagic) {
		return reject("invalid DHCP cookie")
	}
	options, err := parseShadowNativeOptions(dhcp)
	if err != nil {
		return reject(err.Error())
	}
	typeOption := options[53]
	if len(typeOption) != 1 {
		return reject("missing or invalid DHCP message type")
	}
	zero := []byte{0, 0, 0, 0}
	broadcast := []byte{255, 255, 255, 255}
	ciaddr, yiaddr, giaddr := dhcp[12:16], dhcp[16:20], dhcp[24:28]
	if outgoing {
		// In particular, our own DHCPINFORMs never create native lease evidence.
		if typeOption[0] != 3 {
			return shadowNativeDHCPObservation{}
		}
		if !bytes.Equal(yiaddr, zero) || !bytes.Equal(giaddr, zero) || (!bytes.Equal(packet[16:20], broadcast) && !shadowNativePeer(net.IP(packet[16:20]))) || bytes.Equal(packet[16:20], t.client[:]) {
			return reject("invalid native REQUEST destination or address fields")
		}
		server, hasServer := options[54]
		requested, hasRequested := options[50]
		if hasServer && (!shadowNativePeer(net.IP(server)) || bytes.Equal(server, t.client[:])) {
			return reject("invalid REQUEST server identifier")
		}
		if bytes.Equal(ciaddr, t.client[:]) {
			// RFC2131 RENEWING/REBINDING use ciaddr, without options 50/54.
			if !bytes.Equal(packet[12:16], t.client[:]) || hasServer || hasRequested {
				return reject("invalid renewal REQUEST identity")
			}
		} else if !bytes.Equal(ciaddr, zero) || !bytes.Equal(packet[12:16], zero) || !hasRequested || !bytes.Equal(requested, t.client[:]) || !bytes.Equal(packet[16:20], broadcast) {
			return reject("REQUEST is not for this WAN address")
		}
		var selected [4]byte
		copy(selected[:], server)
		if correlated {
			if selected != request.server {
				return reject("REQUEST changed server within a transaction")
			}
			// Retransmits cannot keep a transaction alive indefinitely.
		} else {
			if len(t.pending) == shadowNativePendingLimit {
				var oldest [4]byte
				var sequence uint64
				for id, candidate := range t.pending {
					if sequence == 0 || candidate.sequence < sequence {
						oldest, sequence = id, candidate.sequence
					}
				}
				delete(t.pending, oldest)
			}
			t.sequence++
			t.pending[xid] = shadowNativePending{started: now, sequence: t.sequence, server: selected}
		}
		observation.Kind = "request"
		return observation
	}
	if typeOption[0] != 5 && typeOption[0] != 6 {
		return shadowNativeDHCPObservation{}
	}
	if !shadowNativePeer(net.IP(packet[12:16])) || bytes.Equal(packet[12:16], t.client[:]) || (!bytes.Equal(packet[16:20], t.client[:]) && !bytes.Equal(packet[16:20], broadcast)) {
		return reject("invalid native DHCP reply endpoints")
	}
	if !shadowInformChecksumValid(packet[:int(packet[0]&15)*4]) {
		return reject("invalid IPv4 checksum")
	}
	if binary.BigEndian.Uint16(udp[6:8]) != 0 {
		pseudo := make([]byte, 12+len(udp))
		copy(pseudo[:8], packet[12:20])
		pseudo[9] = 17
		binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(udp)))
		copy(pseudo[12:], udp)
		if !shadowInformChecksumValid(pseudo) {
			return reject("invalid UDP checksum")
		}
	}
	if !bytes.Equal(ciaddr, zero) && !bytes.Equal(ciaddr, t.client[:]) || !bytes.Equal(giaddr, zero) && (!shadowNativePeer(net.IP(giaddr)) || bytes.Equal(giaddr, t.client[:])) {
		return reject("invalid native DHCP reply client or relay address")
	}
	server := net.IP(options[54])
	if !shadowNativePeer(server) || server.Equal(net.IP(t.client[:])) || request.server != [4]byte{} && !bytes.Equal(server, request.server[:]) {
		return reject("invalid or unexpected native DHCP server identifier")
	}
	observation.ServerIP = append(net.IP(nil), server...)
	if typeOption[0] == 6 {
		if !bytes.Equal(yiaddr, zero) || !bytes.Equal(ciaddr, zero) {
			return reject("invalid DHCPNAK address fields")
		}
		t.complete(request)
		observation.Kind = "nak"
		return observation
	}
	// A lease ACK assigns/renews the current address. yiaddr=0 belongs to an
	// INFORM exchange, which must never be mistaken for a native DHCP lease.
	if !bytes.Equal(yiaddr, t.client[:]) {
		return reject("DHCPACK does not assign this WAN address")
	}
	lease := options[51]
	if len(lease) != 4 || binary.BigEndian.Uint32(lease) == 0 {
		return reject("DHCPACK has no valid lease time")
	}
	seconds := min(uint64(binary.BigEndian.Uint32(lease)), uint64(shadowNativeMaxLease/time.Second))
	observation.LeaseSeconds = seconds
	// RFC2131 measures the lease from sending DHCPREQUEST, not receiving ACK.
	// Keep the first observed transmission time through retries; network delay
	// must not extend the lease. The owner rejects an already-expired result.
	observation.LeaseExpires = request.started.Add(time.Duration(seconds) * time.Second)
	dns, hasDNS := options[6]
	if !hasDNS {
		t.complete(request)
		observation.Kind = "ack_no_dns"
		return observation
	}
	if len(dns) == 0 || len(dns)%4 != 0 {
		return reject("DHCPACK has malformed DNS option")
	}
	seen := make(map[string]bool)
	for offset := 0; offset < len(dns); offset += 4 {
		ip := net.IP(dns[offset : offset+4])
		if !shadowNativePeer(ip) || ip.Equal(net.IP(t.client[:])) {
			return reject("DHCPACK has invalid DNS server address")
		}
		address := ip.String()
		if !seen[address] && len(observation.Servers) < 8 {
			observation.Servers = append(observation.Servers, address)
			seen[address] = true
		}
	}
	t.complete(request)
	observation.Kind = "ack"
	return observation
}

func shadowNativeDatagram(packet []byte, outgoing bool) ([]byte, []byte, error) {
	if len(packet) < 20 || packet[0]>>4 != 4 || packet[9] != 17 {
		return nil, nil, fmt.Errorf("not IPv4 UDP")
	}
	ihl, total := int(packet[0]&15)*4, int(binary.BigEndian.Uint16(packet[2:4]))
	if ihl < 20 || total > len(packet) || total < ihl+8+240 || binary.BigEndian.Uint16(packet[6:8])&0xbfff != 0 {
		return nil, nil, fmt.Errorf("invalid IPv4 length or fragment")
	}
	udp := packet[ihl:total]
	length := int(binary.BigEndian.Uint16(udp[4:6]))
	source, destination, op := uint16(67), uint16(68), byte(2)
	if outgoing {
		source, destination, op = 68, 67, 1
	}
	if length != len(udp) || binary.BigEndian.Uint16(udp[:2]) != source || binary.BigEndian.Uint16(udp[2:4]) != destination || udp[8] != op {
		return nil, nil, fmt.Errorf("invalid native DHCP endpoints or lengths")
	}
	return udp, udp[8:], nil
}

func parseShadowNativeOptions(dhcp []byte) (map[byte][]byte, error) {
	options := make(map[byte][]byte)
	parse := func(data []byte) error {
		for offset := 0; offset < len(data); {
			code := data[offset]
			offset++
			if code == 0 {
				continue
			}
			if code == 255 {
				return nil
			}
			if offset == len(data) || int(data[offset]) > len(data)-offset-1 {
				return fmt.Errorf("malformed DHCP option")
			}
			length := int(data[offset])
			offset++
			switch code {
			case 50, 51, 52, 53, 54:
				if _, exists := options[code]; exists {
					return fmt.Errorf("duplicate DHCP control option")
				}
				options[code] = append([]byte{}, data[offset:offset+length]...)
			case 6:
				// RFC3396 permits concatenated DNS options, including overload.
				options[code] = append(options[code], data[offset:offset+length]...)
			}
			offset += length
		}
		return fmt.Errorf("DHCP option area lacks END")
	}
	if err := parse(dhcp[240:]); err != nil {
		return nil, err
	}
	if overload, exists := options[52]; exists {
		if len(overload) != 1 || overload[0] < 1 || overload[0] > 3 {
			return nil, fmt.Errorf("invalid DHCP option overload")
		}
		if overload[0]&1 != 0 {
			if err := parse(dhcp[108:236]); err != nil {
				return nil, err
			}
		}
		if overload[0]&2 != 0 {
			if err := parse(dhcp[44:108]); err != nil {
				return nil, err
			}
		}
	}
	return options, nil
}
