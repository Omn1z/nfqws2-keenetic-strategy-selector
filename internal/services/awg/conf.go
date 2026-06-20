package awg

import (
	"fmt"
	"strings"
)

// ServerConf renders the server-side awg0.conf (AmneziaWG 2.0), including NAT
// PostUp/PostDown so awg-quick owns its own teardown.
func ServerConf(c *ServerConfig) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", c.PrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", c.Address)
	fmt.Fprintf(&b, "ListenPort = %d\n", c.ListenPort)
	if c.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", c.MTU)
	}
	if c.UseObfuscation() {
		b.WriteString(obfLines(c.Obf))
	}
	wan := strings.TrimSpace(c.WANIface)
	if wan == "" {
		wan = "eth0"
	}
	fmt.Fprintf(&b, "PostUp = %s\n", serverPostUpCommands(c.Subnet, wan, "%i"))
	fmt.Fprintf(&b, "PostDown = %s\n", serverPostDownCommands(c.Subnet, wan, "%i"))
	for _, p := range c.Peers {
		b.WriteString("\n")
		b.WriteString(serverPeerBlock(p))
	}
	return b.String()
}

// ClientConf renders the .conf the given peer uses to dial this server. The
// obfuscation block is byte-identical to the server's.
func ClientConf(c *ServerConfig, p Peer) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", p.PrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", p.Address)
	if strings.TrimSpace(c.DNS) != "" {
		fmt.Fprintf(&b, "DNS = %s\n", c.DNS)
	}
	if c.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", c.MTU)
	}
	if c.UseObfuscation() {
		b.WriteString(obfLines(c.Obf))
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", c.PublicKey)
	if strings.TrimSpace(p.PSK) != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", p.PSK)
	}
	fmt.Fprintf(&b, "Endpoint = %s\n", c.Endpoint)
	allowed := strings.TrimSpace(p.AllowedIPs)
	if allowed == "" {
		allowed = "0.0.0.0/0, ::/0"
	}
	fmt.Fprintf(&b, "AllowedIPs = %s\n", allowed)
	ka := p.Keepalive
	if ka == 0 {
		ka = 25
	}
	fmt.Fprintf(&b, "PersistentKeepalive = %d\n", ka)
	return b.String()
}

// obfLines renders the AmneziaWG 2.0 obfuscation block used VERBATIM by both
// server and client configs (they must match byte-for-byte).
func obfLines(o Obfuscation) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Jc = %d\n", o.Jc)
	fmt.Fprintf(&b, "Jmin = %d\n", o.Jmin)
	fmt.Fprintf(&b, "Jmax = %d\n", o.Jmax)
	fmt.Fprintf(&b, "S1 = %d\n", o.S1)
	fmt.Fprintf(&b, "S2 = %d\n", o.S2)
	// S3/S4 only when non-zero. AmneziaWG treats absent vs 0 as DIFFERENT — if
	// the server config has no S3/S4 line, the client MUST also omit it or the
	// handshake silently fails (server drops the auth-tagged packet).
	if o.S3 > 0 {
		fmt.Fprintf(&b, "S3 = %d\n", o.S3)
	}
	if o.S4 > 0 {
		fmt.Fprintf(&b, "S4 = %d\n", o.S4)
	}
	fmt.Fprintf(&b, "H1 = %s\n", hdr(o.H1, "1"))
	fmt.Fprintf(&b, "H2 = %s\n", hdr(o.H2, "2"))
	fmt.Fprintf(&b, "H3 = %s\n", hdr(o.H3, "3"))
	fmt.Fprintf(&b, "H4 = %s\n", hdr(o.H4, "4"))
	writeStrIf(&b, "I1", o.I1)
	writeStrIf(&b, "I2", o.I2)
	writeStrIf(&b, "I3", o.I3)
	writeStrIf(&b, "I4", o.I4)
	writeStrIf(&b, "I5", o.I5)
	return b.String()
}

// SetConfText renders the [Interface]+[Peer] form accepted by `awg setconf` on
// the client (WG + obfuscation settings only — Address/DNS/MTU are applied
// separately via `ip`, since awg setconf rejects them).
func SetConfText(c *ServerConfig, p Peer) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", p.PrivateKey)
	if c.UseObfuscation() {
		b.WriteString(obfLines(c.Obf))
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", c.PublicKey)
	if strings.TrimSpace(p.PSK) != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", p.PSK)
	}
	fmt.Fprintf(&b, "Endpoint = %s\n", c.Endpoint)
	allowed := strings.TrimSpace(p.AllowedIPs)
	if allowed == "" {
		allowed = "0.0.0.0/0, ::/0"
	}
	fmt.Fprintf(&b, "AllowedIPs = %s\n", allowed)
	if p.Keepalive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.Keepalive)
	}
	return b.String()
}

func serverPeerBlock(p Peer) string {
	var b strings.Builder
	b.WriteString("[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
	if strings.TrimSpace(p.PSK) != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", p.PSK)
	}
	fmt.Fprintf(&b, "AllowedIPs = %s\n", hostRoute(p.Address))
	return b.String()
}

func serverPostUpCommands(subnet, wan, iface string) string {
	if strings.TrimSpace(wan) == "" {
		wan = "eth0"
	}
	return fmt.Sprintf("sysctl -w net.ipv4.ip_forward=1; iptables -t nat -C POSTROUTING -s %[1]s -o %[2]s -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s %[1]s -o %[2]s -j MASQUERADE; iptables -C FORWARD -i %[3]s -j ACCEPT 2>/dev/null || iptables -A FORWARD -i %[3]s -j ACCEPT; iptables -C FORWARD -o %[3]s -j ACCEPT 2>/dev/null || iptables -A FORWARD -o %[3]s -j ACCEPT", subnet, wan, iface)
}

func serverPostDownCommands(subnet, wan, iface string) string {
	if strings.TrimSpace(wan) == "" {
		wan = "eth0"
	}
	return fmt.Sprintf("while iptables -t nat -D POSTROUTING -s %[1]s -o %[2]s -j MASQUERADE 2>/dev/null; do :; done; while iptables -D FORWARD -i %[3]s -j ACCEPT 2>/dev/null; do :; done; while iptables -D FORWARD -o %[3]s -j ACCEPT 2>/dev/null; do :; done", subnet, wan, iface)
}

func hdr(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return strings.TrimSpace(v)
}

func writeStrIf(b *strings.Builder, k, v string) {
	if strings.TrimSpace(v) != "" {
		fmt.Fprintf(b, "%s = %s\n", k, strings.TrimSpace(v))
	}
}

// hostRoute reduces a peer address to a host route the server uses in AllowedIPs
// (an IPv4 host becomes /32).
func hostRoute(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return addr
	}
	if i := strings.IndexByte(addr, '/'); i >= 0 {
		ip := addr[:i]
		if strings.Contains(ip, ".") {
			return ip + "/32"
		}
		return addr
	}
	if strings.Contains(addr, ".") {
		return addr + "/32"
	}
	return addr
}
