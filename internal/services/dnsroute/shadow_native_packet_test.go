package dnsroute

import (
	"encoding/binary"
	"net"
	"reflect"
	"testing"
	"time"
)

var (
	shadowNativeTestClient = net.IP{10, 101, 48, 55}
	shadowNativeTestServer = net.IP{1, 1, 1, 2}
	shadowNativeTestMAC    = net.HardwareAddr{0x50, 0xff, 0x20, 0xe1, 0x20, 0xba}
	shadowNativeTestNow    = time.Date(2026, 10, 4, 1, 2, 3, 0, time.UTC)
)

func shadowNativeTestTracker(t *testing.T) *shadowNativeDHCPTracker {
	t.Helper()
	tracker, err := newShadowNativeDHCPTracker(shadowNativeTestClient, shadowNativeTestMAC)
	if err != nil {
		t.Fatal(err)
	}
	return tracker
}

func shadowNativeTestIPChecksum(packet []byte) {
	clear(packet[10:12])
	var sum uint32
	for offset := 0; offset < int(packet[0]&15)*4; offset += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[offset : offset+2]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(packet[10:12], ^uint16(sum))
}

func shadowNativeTestOptions(packet []byte, options []byte) []byte {
	packet = append(append([]byte{}, packet[:268]...), options...)
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[24:26], uint16(len(packet)-20))
	shadowNativeTestIPChecksum(packet)
	return packet
}

func shadowNativeTestPacket(message byte, xid uint32) []byte {
	packet := make([]byte, 20+8+240)
	packet[0], packet[8], packet[9] = 0x45, 64, 17
	copy(packet[12:16], shadowNativeTestServer)
	copy(packet[16:20], shadowNativeTestClient)
	binary.BigEndian.PutUint16(packet[20:22], 67)
	binary.BigEndian.PutUint16(packet[22:24], 68)
	dhcp := packet[28:]
	dhcp[0], dhcp[1], dhcp[2] = 2, 1, 6
	binary.BigEndian.PutUint32(dhcp[4:8], xid)
	copy(dhcp[12:16], shadowNativeTestClient)
	copy(dhcp[28:34], shadowNativeTestMAC)
	copy(dhcp[236:240], shadowDHCPMagic)
	options := []byte{53, 1, message}
	if message == 3 || message == 8 {
		copy(packet[12:16], shadowNativeTestClient)
		copy(packet[16:20], shadowNativeTestServer)
		binary.BigEndian.PutUint16(packet[20:22], 68)
		binary.BigEndian.PutUint16(packet[22:24], 67)
		dhcp[0] = 1
	} else {
		options = append(options, 54, 4, 1, 1, 1, 2)
		if message == 5 {
			copy(dhcp[16:20], shadowNativeTestClient)
			options = append(options, 51, 4, 0, 0, 0x0e, 0x10, 6, 8, 77, 88, 8, 7, 192, 0, 2, 53)
		} else {
			clear(dhcp[12:16])
		}
	}
	return shadowNativeTestOptions(packet, append(options, 255))
}

func shadowNativeTestSelectingRequest(xid uint32, selectServer bool) []byte {
	request := shadowNativeTestPacket(3, xid)
	clear(request[12:16])
	copy(request[16:20], net.IPv4bcast.To4())
	clear(request[40:44])
	options := []byte{53, 1, 3, 50, 4, 10, 101, 48, 55}
	if selectServer {
		options = append(options, 54, 4, 1, 1, 1, 2)
	}
	return shadowNativeTestOptions(request, append(options, 255))
}

func TestShadowNativeDHCPRenewalLearnsBoundedLease(t *testing.T) {
	tracker := shadowNativeTestTracker(t)
	request := shadowNativeTestPacket(3, 0x12345678)
	// AF_PACKET can see a partial outbound transport/header checksum before
	// hardware offload has completed it. Identity comes from PACKET_OUTGOING.
	request[26], request[10] = 42, 0
	if got := tracker.Observe(request, true, shadowNativeTestNow); got.Kind != "request" || got.Err != nil {
		t.Fatalf("request: %+v", got)
	}
	ack := shadowNativeTestPacket(5, 0x12345678)
	now := shadowNativeTestNow.Add(time.Second)
	got := tracker.Observe(ack, false, now)
	if got.Kind != "ack" || got.Err != nil || got.XID != "12345678" || !got.ServerIP.Equal(shadowNativeTestServer) || !reflect.DeepEqual(got.Servers, []string{"77.88.8.7", "192.0.2.53"}) || got.LeaseSeconds != 3600 || !got.LeaseExpires.Equal(shadowNativeTestNow.Add(time.Hour)) {
		t.Fatalf("ack: %+v", got)
	}
	clear(ack)
	if !got.ServerIP.Equal(shadowNativeTestServer) || got.Servers[0] != "77.88.8.7" {
		t.Fatal("observation aliases capture buffer")
	}
	if got := tracker.Observe(shadowNativeTestPacket(5, 0x12345678), false, now); got.Kind != "" {
		t.Fatal("accepted duplicate ACK", got)
	}
}

func TestShadowNativeDHCPSelectingRebootAndRebinding(t *testing.T) {
	for _, mode := range []string{"selecting", "init-reboot", "rebinding", "relay"} {
		t.Run(mode, func(t *testing.T) {
			tracker := shadowNativeTestTracker(t)
			request := shadowNativeTestSelectingRequest(1, mode == "selecting" || mode == "relay")
			ack := shadowNativeTestPacket(5, 1)
			clear(ack[40:44]) // RFC permits zero ciaddr in an ACK.
			copy(ack[16:20], net.IPv4bcast.To4())
			if mode == "rebinding" {
				request = shadowNativeTestPacket(3, 1)
				copy(request[16:20], net.IPv4bcast.To4())
			}
			if mode == "relay" {
				copy(ack[12:16], []byte{10, 101, 48, 1})
				copy(ack[52:56], []byte{10, 101, 48, 1})
			}
			shadowNativeTestIPChecksum(request)
			shadowNativeTestIPChecksum(ack)
			if got := tracker.Observe(request, true, shadowNativeTestNow); got.Kind != "request" {
				t.Fatal("request rejected", got)
			}
			if got := tracker.Observe(ack, false, shadowNativeTestNow); got.Kind != "ack" {
				t.Fatal("ACK rejected", got)
			}
		})
	}
}

func TestShadowNativeDHCPRequiresNativeRequestIdentity(t *testing.T) {
	for name, alter := range map[string]func([]byte) []byte{
		"inform":              func(_ []byte) []byte { return shadowNativeTestPacket(8, 1) },
		"other_mac":           func(p []byte) []byte { p[56] ^= 2; return p },
		"wrong_ciaddr":        func(p []byte) []byte { p[43]++; return p },
		"wrong_source":        func(p []byte) []byte { p[15]++; return p },
		"invalid_destination": func(p []byte) []byte { p[16] = 127; return p },
		"own_destination":     func(p []byte) []byte { copy(p[16:20], shadowNativeTestClient); return p },
		"assignment":          func(p []byte) []byte { copy(p[44:48], shadowNativeTestClient); return p },
		"relay_request":       func(p []byte) []byte { p[52] = 1; return p },
		"renewal_server": func(p []byte) []byte {
			return shadowNativeTestOptions(p, []byte{53, 1, 3, 54, 4, 1, 1, 1, 2, 255})
		},
		"renewal_requested_ip": func(p []byte) []byte {
			return shadowNativeTestOptions(p, []byte{53, 1, 3, 50, 4, 10, 101, 48, 55, 255})
		},
		"selecting_other_address": func(_ []byte) []byte {
			p := shadowNativeTestSelectingRequest(1, true)
			p[276]++
			return p
		},
	} {
		t.Run(name, func(t *testing.T) {
			tracker := shadowNativeTestTracker(t)
			got := tracker.Observe(alter(shadowNativeTestPacket(3, 1)), true, shadowNativeTestNow)
			if got.Kind == "request" || len(tracker.pending) != 0 {
				t.Fatal("invalid request created pending transaction", got)
			}
			if got := tracker.Observe(shadowNativeTestPacket(5, 1), false, shadowNativeTestNow); got.Kind != "" {
				t.Fatal("uncorrelated ACK accepted", got)
			}
		})
	}
	tracker := shadowNativeTestTracker(t)
	if got := tracker.Observe(shadowNativeTestPacket(3, 1), false, shadowNativeTestNow); got.Kind != "" || len(tracker.pending) != 0 {
		t.Fatal("incoming forged REQUEST trusted", got)
	}
}

func TestShadowNativeDHCPRejectsUnrelatedOrSpoofedACK(t *testing.T) {
	for name, alter := range map[string]func([]byte){
		"xid":             func(p []byte) { p[35]++ },
		"mac":             func(p []byte) { p[56] ^= 2 },
		"op":              func(p []byte) { p[28] = 1 },
		"htype":           func(p []byte) { p[29] = 2 },
		"hlen":            func(p []byte) { p[30] = 5 },
		"ciaddr":          func(p []byte) { p[43]++ },
		"yiaddr":          func(p []byte) { p[47]++ },
		"inform_yiaddr":   func(p []byte) { clear(p[44:48]) },
		"relay":           func(p []byte) { p[52] = 127 },
		"destination":     func(p []byte) { p[19]++ },
		"source":          func(p []byte) { p[12] = 127 },
		"source_self":     func(p []byte) { copy(p[12:16], shadowNativeTestClient) },
		"server_mismatch": func(p []byte) { p[276]++ },
		"cookie":          func(p []byte) { p[264]++ },
		"checksum":        func(p []byte) { p[26] = 42 },
	} {
		t.Run(name, func(t *testing.T) {
			tracker := shadowNativeTestTracker(t)
			tracker.Observe(shadowNativeTestSelectingRequest(1, true), true, shadowNativeTestNow)
			ack := shadowNativeTestPacket(5, 1)
			alter(ack)
			shadowNativeTestIPChecksum(ack)
			if got := tracker.Observe(ack, false, shadowNativeTestNow); got.Kind == "ack" || got.Kind == "ack_no_dns" || got.Kind == "nak" || len(tracker.pending) != 1 {
				t.Fatal("invalid reply trusted or consumed legitimate transaction", got)
			}
			if got := tracker.Observe(shadowNativeTestPacket(5, 1), false, shadowNativeTestNow); got.Kind != "ack" {
				t.Fatal("legitimate reply rejected after unrelated packet", got)
			}
		})
	}
}

func TestShadowNativeDHCPMalformedDatagramsCannotPanicOrComplete(t *testing.T) {
	valid := shadowNativeTestPacket(5, 1)
	for n := 0; n < len(valid); n++ {
		tracker := shadowNativeTestTracker(t)
		tracker.Observe(shadowNativeTestPacket(3, 1), true, shadowNativeTestNow)
		if got := tracker.Observe(valid[:n], false, shadowNativeTestNow); got.Kind == "ack" || len(tracker.pending) != 1 {
			t.Fatalf("truncated packet %d completed: %+v", n, got)
		}
	}
	for name, alter := range map[string]func([]byte){
		"version":         func(p []byte) { p[0] = 0x65 },
		"protocol":        func(p []byte) { p[9] = 6 },
		"short_ihl":       func(p []byte) { p[0] = 0x44 },
		"long_ihl":        func(p []byte) { p[0] = 0x4f },
		"short_ip":        func(p []byte) { binary.BigEndian.PutUint16(p[2:4], 20) },
		"long_ip":         func(p []byte) { binary.BigEndian.PutUint16(p[2:4], 65535) },
		"fragment":        func(p []byte) { p[6] |= 0x20 },
		"fragment_offset": func(p []byte) { p[7] = 1 },
		"short_udp":       func(p []byte) { binary.BigEndian.PutUint16(p[24:26], 8) },
		"udp_ip_mismatch": func(p []byte) { binary.BigEndian.PutUint16(p[24:26], uint16(len(p)-21)) },
		"udp_port":        func(p []byte) { p[21]++ },
		"bad_ip_checksum": func(p []byte) { p[10]++ },
	} {
		t.Run(name, func(t *testing.T) {
			tracker := shadowNativeTestTracker(t)
			tracker.Observe(shadowNativeTestPacket(3, 1), true, shadowNativeTestNow)
			ack := append([]byte(nil), valid...)
			alter(ack)
			if got := tracker.Observe(ack, false, shadowNativeTestNow); got.Kind == "ack" || len(tracker.pending) != 1 {
				t.Fatal("malformed packet completed transaction", got)
			}
		})
	}
}

func TestShadowNativeDHCPOptionValidation(t *testing.T) {
	base := []byte{53, 1, 5, 54, 4, 1, 1, 1, 2, 51, 4, 0, 0, 0x0e, 0x10}
	for name, options := range map[string][]byte{
		"missing_type":     {54, 4, 1, 1, 1, 2, 255},
		"missing_lease":    {53, 1, 5, 54, 4, 1, 1, 1, 2, 6, 4, 8, 8, 8, 8, 255},
		"zero_lease":       {53, 1, 5, 54, 4, 1, 1, 1, 2, 51, 4, 0, 0, 0, 0, 6, 4, 8, 8, 8, 8, 255},
		"empty_lease":      {53, 1, 5, 54, 4, 1, 1, 1, 2, 51, 0, 6, 4, 8, 8, 8, 8, 255},
		"missing_server":   {53, 1, 5, 51, 4, 0, 0, 0x0e, 0x10, 6, 4, 8, 8, 8, 8, 255},
		"bad_server":       {53, 1, 5, 54, 3, 1, 1, 1, 51, 4, 0, 0, 0x0e, 0x10, 6, 4, 8, 8, 8, 8, 255},
		"short_dns":        append(append([]byte{}, base...), 6, 3, 8, 8, 8, 255),
		"empty_dns":        append(append([]byte{}, base...), 6, 0, 255),
		"local_dns":        append(append([]byte{}, base...), 6, 4, 127, 0, 0, 1, 255),
		"self_dns":         append(append([]byte{}, base...), 6, 4, 10, 101, 48, 55, 255),
		"multicast_dns":    append(append([]byte{}, base...), 6, 4, 224, 0, 0, 1, 255),
		"broadcast_dns":    append(append([]byte{}, base...), 6, 4, 255, 255, 255, 255, 255),
		"zeronet_dns":      append(append([]byte{}, base...), 6, 4, 0, 1, 2, 3, 255),
		"linklocal_dns":    append(append([]byte{}, base...), 6, 4, 169, 254, 1, 2, 255),
		"duplicate_type":   append(append([]byte{}, base...), 53, 1, 5, 255),
		"duplicate_lease":  append(append([]byte{}, base...), 51, 4, 0, 0, 0, 1, 255),
		"duplicate_server": append(append([]byte{}, base...), 54, 4, 1, 1, 1, 2, 255),
		"truncated":        append(append([]byte{}, base...), 6, 4, 8),
		"no_end":           append(append([]byte{}, base...), 6, 4, 8, 8, 8, 8),
		"bad_overload":     append(append([]byte{}, base...), 52, 1, 4, 255),
	} {
		t.Run(name, func(t *testing.T) {
			tracker := shadowNativeTestTracker(t)
			tracker.Observe(shadowNativeTestPacket(3, 1), true, shadowNativeTestNow)
			ack := shadowNativeTestOptions(shadowNativeTestPacket(5, 1), options)
			if got := tracker.Observe(ack, false, shadowNativeTestNow); got.Kind != "rejected" || got.Err == nil || len(tracker.pending) != 1 {
				t.Fatal("invalid options not rejected", got)
			}
		})
	}
}

func TestShadowNativeDHCPNoDNSAndNAKAreExplicitCorrelatedEvents(t *testing.T) {
	for _, kind := range []string{"ack_no_dns", "nak"} {
		t.Run(kind, func(t *testing.T) {
			tracker := shadowNativeTestTracker(t)
			tracker.Observe(shadowNativeTestSelectingRequest(1, true), true, shadowNativeTestNow)
			packet := shadowNativeTestPacket(6, 1)
			if kind == "ack_no_dns" {
				packet = shadowNativeTestOptions(shadowNativeTestPacket(5, 1), []byte{53, 1, 5, 54, 4, 1, 1, 1, 2, 51, 4, 0, 0, 0x0e, 0x10, 255})
			}
			got := tracker.Observe(packet, false, shadowNativeTestNow)
			if got.Kind != kind || got.Err != nil || len(got.Servers) != 0 || !got.ServerIP.Equal(shadowNativeTestServer) || len(tracker.pending) != 0 {
				t.Fatal("did not report correlated no-DNS/NAK", got)
			}
			if got := tracker.Observe(packet, false, shadowNativeTestNow); got.Kind != "" {
				t.Fatal("duplicate no-DNS/NAK reported", got)
			}
		})
	}
}

func TestShadowNativeDHCPTransactionsExpireAndStayBounded(t *testing.T) {
	tracker := shadowNativeTestTracker(t)
	for xid := uint32(1); xid <= 9; xid++ {
		tracker.Observe(shadowNativeTestPacket(3, xid), true, shadowNativeTestNow)
	}
	if len(tracker.pending) != shadowNativePendingLimit {
		t.Fatal("pending transactions are not bounded", len(tracker.pending))
	}
	if got := tracker.Observe(shadowNativeTestPacket(5, 1), false, shadowNativeTestNow); got.Kind != "" {
		t.Fatal("evicted transaction accepted", got)
	}
	// Repeated packets preserve the original pending timeout.
	tracker.Observe(shadowNativeTestPacket(3, 2), true, shadowNativeTestNow.Add(time.Minute))
	if got := tracker.Observe(shadowNativeTestPacket(5, 2), false, shadowNativeTestNow.Add(shadowNativePendingTTL)); got.Kind != "" || len(tracker.pending) != 0 {
		t.Fatal("expired/retransmitted transaction accepted", got)
	}
	tracker.Observe(shadowNativeTestPacket(3, 3), true, shadowNativeTestNow)
	if got := tracker.Observe(shadowNativeTestPacket(5, 3), false, shadowNativeTestNow.Add(-time.Second)); got.Kind != "" {
		t.Fatal("clock rollback revived stale pending request", got)
	}
	for xid := uint32(10); xid <= 20; xid++ {
		when := shadowNativeTestNow.Add(time.Duration(xid) * time.Second)
		tracker.Observe(shadowNativeTestPacket(3, xid), true, when)
		tracker.Observe(shadowNativeTestPacket(5, xid), false, when)
	}
	if len(tracker.pending) != 0 {
		t.Fatal("completed requests remained pending", len(tracker.pending))
	}
	if got := tracker.Observe(shadowNativeTestPacket(5, 20), false, shadowNativeTestNow.Add(3*time.Minute)); got.Kind != "" {
		t.Fatal("completed request accepted a replay after pending TTL", got)
	}
}

func TestShadowNativeDHCPReusesXIDOnlyAfterFreshValidatedRequest(t *testing.T) {
	tracker := shadowNativeTestTracker(t)
	request, ack := shadowNativeTestPacket(3, 1), shadowNativeTestPacket(5, 1)
	for renewal := 0; renewal < 4; renewal++ {
		started := shadowNativeTestNow.Add(time.Duration(renewal) * 30 * time.Second)
		if renewal > 0 {
			if got := tracker.Observe(ack, false, started); got.Kind != "" {
				t.Fatal("duplicate ACK reopened completed exchange", got)
			}
			bad := append([]byte(nil), request...)
			bad[15]++ // Wrong outgoing source must not make an old XID pending.
			if got := tracker.Observe(bad, true, started); got.Kind == "request" {
				t.Fatal("invalid REQUEST reopened completed XID", got)
			}
			if got := tracker.Observe(request, false, started); got.Kind != "" {
				t.Fatal("incoming forged REQUEST reopened completed XID", got)
			}
			tracker.Observe(shadowNativeTestPacket(8, 1), true, started)
			if got := tracker.Observe(ack, false, started); got.Kind != "" || len(tracker.pending) != 0 {
				t.Fatal("invalid/non-native request reopened XID", got)
			}
		}
		if got := tracker.Observe(request, true, started); got.Kind != "request" {
			t.Fatal("new native renewal with reused XID was suppressed", got)
		}
		got := tracker.Observe(ack, false, started.Add(time.Second))
		if got.Kind != "ack" || !got.LeaseExpires.Equal(started.Add(time.Hour)) || len(tracker.pending) != 0 {
			t.Fatal("renewed lease did not use the fresh request generation", got)
		}
	}
}

func TestShadowNativeDHCPXIDCanRenewAfterNoDNSOrNAK(t *testing.T) {
	for _, kind := range []string{"ack_no_dns", "nak"} {
		t.Run(kind, func(t *testing.T) {
			tracker := shadowNativeTestTracker(t)
			request := shadowNativeTestSelectingRequest(1, true)
			tracker.Observe(request, true, shadowNativeTestNow)
			reply := shadowNativeTestPacket(6, 1)
			if kind == "ack_no_dns" {
				reply = shadowNativeTestOptions(shadowNativeTestPacket(5, 1), []byte{53, 1, 5, 54, 4, 1, 1, 1, 2, 51, 4, 0, 0, 0x0e, 0x10, 255})
			}
			if got := tracker.Observe(reply, false, shadowNativeTestNow); got.Kind != kind {
				t.Fatal("fixture did not complete initial exchange", got)
			}
			if got := tracker.Observe(reply, false, shadowNativeTestNow.Add(time.Second)); got.Kind != "" {
				t.Fatal("duplicate negative reply accepted", got)
			}
			started := shadowNativeTestNow.Add(2 * time.Second)
			if got := tracker.Observe(request, true, started); got.Kind != "request" {
				t.Fatal("native client could not reuse XID after a negative reply", got)
			}
			if got := tracker.Observe(shadowNativeTestPacket(5, 1), false, started.Add(time.Second)); got.Kind != "ack" || !got.LeaseExpires.Equal(started.Add(time.Hour)) {
				t.Fatal("new exchange did not restore fresh DNS evidence", got)
			}
		})
	}
}

func TestShadowNativeDHCPDelayedACKDoesNotExtendLease(t *testing.T) {
	for _, delay := range []time.Duration{time.Second, time.Minute, 90 * time.Second} {
		t.Run(delay.String(), func(t *testing.T) {
			tracker := shadowNativeTestTracker(t)
			request := shadowNativeTestPacket(3, 1)
			tracker.Observe(request, true, shadowNativeTestNow)
			// Retransmission with the same XID must not move the lease origin.
			tracker.Observe(request, true, shadowNativeTestNow.Add(delay/2))
			ack := shadowNativeTestOptions(shadowNativeTestPacket(5, 1), []byte{53, 1, 5, 54, 4, 1, 1, 1, 2, 51, 4, 0, 0, 0, 60, 6, 4, 192, 0, 2, 53, 255})
			got := tracker.Observe(ack, false, shadowNativeTestNow.Add(delay))
			if got.Kind != "ack" || got.LeaseSeconds != 60 || !got.LeaseExpires.Equal(shadowNativeTestNow.Add(time.Minute)) {
				t.Fatal("delayed ACK or retransmit extended DHCP lease", got)
			}
			if delay >= time.Minute && shadowNativeTestNow.Add(delay).Before(got.LeaseExpires) {
				t.Fatal("expired lease appeared live at receipt", got)
			}
		})
	}
	tracker := shadowNativeTestTracker(t)
	tracker.Observe(shadowNativeTestPacket(3, 1), true, shadowNativeTestNow)
	options := []byte{53, 1, 5, 54, 4, 1, 1, 1, 2, 51, 4, 255, 255, 255, 255, 6, 4, 192, 0, 2, 53, 255}
	got := tracker.Observe(shadowNativeTestOptions(shadowNativeTestPacket(5, 1), options), false, shadowNativeTestNow.Add(time.Minute))
	if got.Kind != "ack" || !got.LeaseExpires.Equal(shadowNativeTestNow.Add(shadowNativeMaxLease)) {
		t.Fatal("delayed ACK extended seven-day safety bound", got)
	}
}

func TestShadowNativeDHCPLateACKCannotRollBackNewerLease(t *testing.T) {
	tracker := shadowNativeTestTracker(t)
	tracker.Observe(shadowNativeTestPacket(3, 1), true, shadowNativeTestNow)
	tracker.Observe(shadowNativeTestPacket(3, 2), true, shadowNativeTestNow)
	if got := tracker.Observe(shadowNativeTestPacket(5, 2), false, shadowNativeTestNow); got.Kind != "ack" {
		t.Fatal("newest ACK rejected", got)
	}
	if got := tracker.Observe(shadowNativeTestPacket(5, 1), false, shadowNativeTestNow); got.Kind != "" {
		t.Fatal("old ACK rolled back newer lease", got)
	}
}

func TestShadowNativeDHCPLeaseLimitAndDNSDeduplication(t *testing.T) {
	tracker := shadowNativeTestTracker(t)
	tracker.Observe(shadowNativeTestPacket(3, 1), true, shadowNativeTestNow)
	options := []byte{53, 1, 5, 54, 4, 1, 1, 1, 2, 51, 4, 255, 255, 255, 255, 6, 40}
	for last := byte(1); last <= 9; last++ {
		options = append(options, 192, 0, 2, last)
	}
	options = append(options, 192, 0, 2, 1, 255)
	got := tracker.Observe(shadowNativeTestOptions(shadowNativeTestPacket(5, 1), options), false, shadowNativeTestNow)
	if got.Kind != "ack" || got.LeaseSeconds != 7*24*3600 || !got.LeaseExpires.Equal(shadowNativeTestNow.Add(shadowNativeMaxLease)) || len(got.Servers) != 8 || got.Servers[0] != "192.0.2.1" || got.Servers[7] != "192.0.2.8" {
		t.Fatal("unbounded lease or DNS list", got)
	}
}

func TestShadowNativeDHCPOptionsOverloadAndConcatenation(t *testing.T) {
	tracker := shadowNativeTestTracker(t)
	tracker.Observe(shadowNativeTestPacket(3, 1), true, shadowNativeTestNow)
	ack := shadowNativeTestOptions(shadowNativeTestPacket(5, 1), []byte{53, 1, 5, 54, 4, 1, 1, 1, 2, 51, 4, 0, 0, 0x0e, 0x10, 52, 1, 3, 6, 2, 77, 88, 255})
	copy(ack[136:264], []byte{6, 2, 8, 7, 255}) // file is parsed before sname.
	copy(ack[72:136], []byte{6, 4, 192, 0, 2, 53, 255})
	got := tracker.Observe(ack, false, shadowNativeTestNow)
	if got.Kind != "ack" || !reflect.DeepEqual(got.Servers, []string{"77.88.8.7", "192.0.2.53"}) {
		t.Fatal("valid concatenated overload rejected", got)
	}
}

func TestShadowNativeDHCPAcceptsCheckedUDPWithIPv4Options(t *testing.T) {
	tracker := shadowNativeTestTracker(t)
	tracker.Observe(shadowNativeTestPacket(3, 1), true, shadowNativeTestNow)
	ack := shadowNativeTestPacket(5, 1)
	// Preserve an odd UDP length to exercise the pseudoheader checksum's final
	// byte padding. The four IPv4 option bytes move the transport header.
	ack = append(ack, 0)
	ack = append(append(append([]byte(nil), ack[:20]...), 1, 1, 1, 1), ack[20:]...)
	ack[0] = 0x46
	binary.BigEndian.PutUint16(ack[2:4], uint16(len(ack)))
	udp := ack[24:]
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	pseudo := make([]byte, 12+len(udp))
	copy(pseudo[:8], ack[12:20])
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(udp)))
	copy(pseudo[12:], udp)
	var sum uint32
	for offset := 0; offset < len(pseudo); offset += 2 {
		sum += uint32(pseudo[offset]) << 8
		if offset+1 < len(pseudo) {
			sum += uint32(pseudo[offset+1])
		}
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	checksum := ^uint16(sum)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], checksum)
	shadowNativeTestIPChecksum(ack)
	if got := tracker.Observe(ack, false, shadowNativeTestNow); got.Kind != "ack" {
		t.Fatal("valid UDP checksum/IPv4 options rejected", got)
	}
}

func TestShadowNativeDHCPNAKMustMatchSelectedServerAndHaveNoAssignment(t *testing.T) {
	for name, alter := range map[string]func([]byte){
		"wrong_server": func(p []byte) { p[276]++ },
		"assignment":   func(p []byte) { copy(p[44:48], shadowNativeTestClient) },
		"nonzero_ci":   func(p []byte) { copy(p[40:44], shadowNativeTestClient) },
	} {
		t.Run(name, func(t *testing.T) {
			tracker := shadowNativeTestTracker(t)
			tracker.Observe(shadowNativeTestSelectingRequest(1, true), true, shadowNativeTestNow)
			packet := shadowNativeTestPacket(6, 1)
			alter(packet)
			if got := tracker.Observe(packet, false, shadowNativeTestNow); got.Kind != "rejected" || got.Err == nil || len(tracker.pending) != 1 {
				t.Fatal("invalid NAK withdrew transaction", got)
			}
		})
	}
}

func TestShadowNativeDHCPRetransmitCannotChangeSelectedServer(t *testing.T) {
	tracker := shadowNativeTestTracker(t)
	request := shadowNativeTestSelectingRequest(1, true)
	tracker.Observe(request, true, shadowNativeTestNow)
	request[282]++
	if got := tracker.Observe(request, true, shadowNativeTestNow.Add(time.Second)); got.Kind != "rejected" {
		t.Fatal("retransmission changed selected server", got)
	}
	if got := tracker.Observe(shadowNativeTestPacket(5, 1), false, shadowNativeTestNow.Add(2*time.Second)); got.Kind != "ack" {
		t.Fatal("failed retransmission corrupted original transaction", got)
	}
}

func TestShadowNativeDHCPIdentityConstructorCopiesAndRejectsInvalid(t *testing.T) {
	for _, ip := range []net.IP{nil, net.ParseIP("::1"), net.IP{0, 1, 2, 3}, net.IP{127, 0, 0, 1}, net.IP{169, 254, 1, 2}} {
		if _, err := newShadowNativeDHCPTracker(ip, shadowNativeTestMAC); err == nil {
			t.Fatal("accepted invalid client", ip)
		}
	}
	for _, mac := range []net.HardwareAddr{nil, {0, 0, 0, 0, 0, 0}, {1, 2, 3, 4, 5, 6}, {2, 3, 4, 5, 6}} {
		if _, err := newShadowNativeDHCPTracker(shadowNativeTestClient, mac); err == nil {
			t.Fatal("accepted invalid MAC", mac)
		}
	}
	ip, mac := append(net.IP(nil), shadowNativeTestClient...), append(net.HardwareAddr(nil), shadowNativeTestMAC...)
	tracker, err := newShadowNativeDHCPTracker(ip, mac)
	if err != nil {
		t.Fatal(err)
	}
	clear(ip)
	clear(mac)
	if got := tracker.Observe(shadowNativeTestPacket(3, 1), true, shadowNativeTestNow); got.Kind != "request" {
		t.Fatal("constructor did not clone WAN identity", got)
	}
}
