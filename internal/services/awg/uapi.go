package awg

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// UAPIStat is a peer's live state parsed from a UAPI `get=1` response.
type UAPIStat struct {
	LastHandshake int64
	RxBytes       int64
	TxBytes       int64
	Endpoint      string
}

func keyHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", fmt.Errorf("некорректный ключ: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("ключ должен быть 32 байта")
	}
	return hex.EncodeToString(raw), nil
}

// RenderUAPISet builds the WireGuard/AmneziaWG UAPI `set=1` request to configure
// the local client interface directly (no `awg` CLI): device identity + AWG 2.0
// obfuscation + the single server peer. Keys are hex (UAPI requirement) and the
// endpoint must be a resolved IP (UAPI does not resolve hostnames).
func RenderUAPISet(c *ServerConfig, p Peer, endpointIP string, port int) (string, error) {
	priv, err := keyHex(p.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("приватный ключ роутера: %w", err)
	}
	pub, err := keyHex(c.PublicKey)
	if err != nil {
		return "", fmt.Errorf("публичный ключ сервера: %w", err)
	}
	var b strings.Builder
	b.WriteString("set=1\n")
	fmt.Fprintf(&b, "private_key=%s\n", priv)
	o := c.Obf
	fmt.Fprintf(&b, "jc=%d\njmin=%d\njmax=%d\n", o.Jc, o.Jmin, o.Jmax)
	fmt.Fprintf(&b, "s1=%d\ns2=%d\ns3=%d\ns4=%d\n", o.S1, o.S2, o.S3, o.S4)
	fmt.Fprintf(&b, "h1=%s\nh2=%s\nh3=%s\nh4=%s\n", hdr(o.H1, "1"), hdr(o.H2, "2"), hdr(o.H3, "3"), hdr(o.H4, "4"))
	for i, v := range []string{o.I1, o.I2, o.I3, o.I4, o.I5} {
		if strings.TrimSpace(v) != "" {
			fmt.Fprintf(&b, "i%d=%s\n", i+1, strings.TrimSpace(v))
		}
	}
	b.WriteString("replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", pub)
	if strings.TrimSpace(p.PSK) != "" {
		if psk, err := keyHex(p.PSK); err == nil {
			fmt.Fprintf(&b, "preshared_key=%s\n", psk)
		}
	}
	fmt.Fprintf(&b, "endpoint=%s:%d\n", endpointIP, port)
	ka := p.Keepalive
	if ka == 0 {
		ka = 25
	}
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", ka)
	b.WriteString("replace_allowed_ips=true\n")
	for _, a := range splitAllowed(p.AllowedIPs) {
		fmt.Fprintf(&b, "allowed_ip=%s\n", a)
	}
	b.WriteString("\n")
	return b.String(), nil
}

func splitAllowed(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return []string{"0.0.0.0/0", "::/0"}
	}
	return out
}

// ParseUAPIGet extracts the (single) server peer's live stats from a `get=1`
// response.
func ParseUAPIGet(resp string) UAPIStat {
	var st UAPIStat
	for _, ln := range strings.Split(resp, "\n") {
		kv := strings.SplitN(strings.TrimSpace(ln), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "last_handshake_time_sec":
			st.LastHandshake = uapiInt(kv[1])
		case "rx_bytes":
			st.RxBytes = uapiInt(kv[1])
		case "tx_bytes":
			st.TxBytes = uapiInt(kv[1])
		case "endpoint":
			st.Endpoint = kv[1]
		}
	}
	return st
}

func uapiInt(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}
