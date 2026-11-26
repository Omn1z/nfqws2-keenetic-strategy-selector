package tlsblob

// Live SNI extraction from a single captured Ethernet frame — used by the AWG2
// SNI-routing sniffer to learn which server IP a TLS ClientHello is headed to,
// then route that IP through the tunnel. Reuses the same link/IP/TCP/SNI parsers
// as the pcap blob extractor; it only handles a ClientHello that fits in one frame
// (the common case — a multi-segment hello is rare and simply isn't matched).

// SNIFromEthernet parses one Ethernet frame and, if it carries a TCP segment whose
// payload begins a complete TLS ClientHello, returns the destination IP, the
// destination port, and the SNI host. ok is false for anything else (non-IP,
// non-TCP, no ClientHello, no SNI). Read-only and allocation-light.
func SNIFromEthernet(frame []byte) (dstIP string, dstPort int, sni string, ok bool) {
	_, dst, proto, l3pl, k := parseL2L3(dltEthernet, frame)
	if !k || proto != 6 { // TCP only
		return "", 0, "", false
	}
	_, dport, _, tpl, k := parseTCP(l3pl)
	if !k || len(tpl) < 6 || tpl[0] != 0x16 || tpl[1] != 0x03 || tpl[5] != 0x01 {
		return "", 0, "", false // not a TLS handshake / ClientHello
	}
	sni = parseSNI(tpl)
	if sni == "" {
		return "", 0, "", false
	}
	return dst, dport, sni, true
}
