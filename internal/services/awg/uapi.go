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
// the local client interface directly (no `awg` CLI): device identity + AWG
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
	if c.UseObfuscation() {
		o := c.Obf
		fmt.Fprintf(&b, "jc=%d\njmin=%d\njmax=%d\n", o.Jc, o.Jmin, o.Jmax)
		fmt.Fprintf(&b, "s1=%d\ns2=%d\n", o.S1, o.S2)
		// Omit unused extensions for legacy engines. This request initializes a
		// fresh device: omission on a running AWG3.1 device would retain its old
		// settings, so wire changes require an interface/daemon restart.
		if o.S3 > 0 {
			fmt.Fprintf(&b, "s3=%d\n", o.S3)
		}
		if o.S4 > 0 {
			fmt.Fprintf(&b, "s4=%d\n", o.S4)
		}
		fmt.Fprintf(&b, "h1=%s\nh2=%s\nh3=%s\nh4=%s\n", hdr(o.H1, "1"), hdr(o.H2, "2"), hdr(o.H3, "3"), hdr(o.H4, "4"))
		for i, v := range []string{o.I1, o.I2, o.I3, o.I4, o.I5} {
			if strings.TrimSpace(v) != "" {
				fmt.Fprintf(&b, "i%d=%s\n", i+1, strings.TrimSpace(v))
			}
		}
		if strings.TrimSpace(o.HeaderProtectionKey) != "" {
			key, err := keyHex(o.HeaderProtectionKey)
			if err != nil {
				return "", fmt.Errorf("HeaderProtectionKey: %w", err)
			}
			fmt.Fprintf(&b, "header_protection_key=%s\n", key)
		}
		for _, p := range o.awg31Strings() {
			if v := strings.TrimSpace(p.value); v != "" {
				fmt.Fprintf(&b, "%s=%s\n", p.uapi, v)
			}
		}
		if o.RandomTrailers {
			b.WriteString("random_trailers=true\n")
		}
		if o.DisableCookies {
			b.WriteString("disable_cookies=true\n")
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
	fmt.Fprintf(&b, "persistent_keepalive_interval=%s\n", c.PeerKeepaliveValue(p))
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
