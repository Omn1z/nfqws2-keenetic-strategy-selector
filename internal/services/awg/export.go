package awg

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

func ClientVPNPayload(c *ServerConfig, p Peer) (string, error) {
	root, err := clientAmneziaJSON(c, p)
	if err != nil {
		return "", err
	}
	var compressed bytes.Buffer
	var head [4]byte
	binary.BigEndian.PutUint32(head[:], uint32(len(root)))
	compressed.Write(head[:])
	zw := zlib.NewWriter(&compressed)
	if _, err := zw.Write(root); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(compressed.Bytes()), nil
}

func ClientVPNURI(c *ServerConfig, p Peer) (string, error) {
	payload, err := ClientVPNPayload(c, p)
	if err != nil {
		return "", err
	}
	return "vpn://" + payload, nil
}

func clientAmneziaJSON(c *ServerConfig, p Peer) ([]byte, error) {
	dns1, dns2 := splitDNS(c.DNS)
	mtu := c.MTU
	if mtu == 0 {
		mtu = c.Routing.MTU
	}
	if mtu == 0 {
		mtu = 1280
	}
	host := hostOnly(c.Endpoint)
	lastConfig := map[string]any{
		"config":                ClientConf(c, p),
		"hostName":              host,
		"port":                  c.ListenPort,
		"client_ip":             p.Address,
		"client_priv_key":       p.PrivateKey,
		"client_pub_key":        p.PublicKey,
		"server_pub_key":        c.PublicKey,
		"allowed_ips":           splitList(peerAllowedIPs(p)),
		"persistent_keep_alive": c.PeerKeepaliveValue(p),
		"mtu":                   strconv.Itoa(mtu),
	}
	if psk := strings.TrimSpace(p.PSK); psk != "" {
		lastConfig["psk_key"] = psk
	}
	if c.UseObfuscation() {
		addAmneziaObf(lastConfig, c.Obf)
		lastConfig["isObfuscationEnabled"] = true
	}
	last, err := json.Marshal(lastConfig)
	if err != nil {
		return nil, err
	}
	proto := map[string]any{
		"last_config":        string(last),
		"isThirdPartyConfig": true,
		"port":               strconv.Itoa(c.ListenPort),
		"transport_proto":    "udp",
	}
	container, protocol := "amnezia-awg", "awg"
	if c.UseObfuscation() {
		if v := c.EffectiveProtocolVersion(); v != "" && v != "1.0" {
			proto["protocol_version"] = v
		}
	} else {
		container, protocol = "amnezia-wireguard", "wireguard"
	}
	return json.Marshal(map[string]any{
		"description":      safeName(p.Name),
		"dns1":             dns1,
		"dns2":             dns2,
		"hostName":         host,
		"defaultContainer": container,
		"containers": []map[string]any{{
			"container": container,
			protocol:    proto,
		}},
	})
}

func addAmneziaObf(dst map[string]any, o Obfuscation) {
	dst["Jc"] = strconv.Itoa(o.Jc)
	dst["Jmin"] = strconv.Itoa(o.Jmin)
	dst["Jmax"] = strconv.Itoa(o.Jmax)
	dst["S1"] = strconv.Itoa(o.S1)
	dst["S2"] = strconv.Itoa(o.S2)
	if o.S3 > 0 {
		dst["S3"] = strconv.Itoa(o.S3)
	}
	if o.S4 > 0 {
		dst["S4"] = strconv.Itoa(o.S4)
	}
	dst["H1"] = hdr(o.H1, "1")
	dst["H2"] = hdr(o.H2, "2")
	dst["H3"] = hdr(o.H3, "3")
	dst["H4"] = hdr(o.H4, "4")
	for _, kv := range []struct {
		k string
		v string
	}{{"I1", o.I1}, {"I2", o.I2}, {"I3", o.I3}, {"I4", o.I4}, {"I5", o.I5}} {
		if v := strings.TrimSpace(kv.v); v != "" {
			dst[kv.k] = v
		}
	}
	if v := strings.TrimSpace(o.HeaderProtectionKey); v != "" {
		dst["HeaderProtectionKey"] = v
	}
	for _, p := range o.awg31Strings() {
		if v := strings.TrimSpace(p.value); v != "" {
			dst[p.conf] = v
		}
	}
	if o.RandomTrailers {
		dst["RandomTrailers"] = "on"
	}
	if o.DisableCookies {
		dst["DisableCookies"] = "on"
	}
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func peerKeepalive(p Peer) int {
	if p.Keepalive > 0 {
		return p.Keepalive
	}
	return 25
}

func peerAllowedIPs(p Peer) string {
	if allowed := strings.TrimSpace(p.AllowedIPs); allowed != "" {
		return allowed
	}
	return "0.0.0.0/0, ::/0"
}

func amneziaProtocolVersion(o Obfuscation) string {
	if o.hasAWG31() {
		return "3.1"
	}
	if o.S3 > 0 || o.S4 > 0 || strings.Contains(o.H1+o.H2+o.H3+o.H4, "-") {
		return "2"
	}
	if strings.TrimSpace(o.I1) != "" || strings.TrimSpace(o.I2) != "" || strings.TrimSpace(o.I3) != "" || strings.TrimSpace(o.I4) != "" || strings.TrimSpace(o.I5) != "" {
		return "1.5"
	}
	return ""
}

func splitDNS(s string) (string, string) {
	parts := strings.Split(s, ",")
	out := []string{}
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return "1.1.1.1", "1.0.0.1"
	}
	if len(out) == 1 {
		return out[0], out[0]
	}
	return out[0], out[1]
}

func hostOnly(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if i := strings.LastIndex(endpoint, ":"); i > 0 {
		return endpoint[:i]
	}
	return endpoint
}

func ClientExport(c *ServerConfig, p Peer, format string) (text, filename, contentType string, err error) {
	name := safeName(p.Name)
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "conf":
		return ClientConf(c, p), name + ".conf", "text/plain; charset=utf-8", nil
	case "vpn":
		uri, err := ClientVPNURI(c, p)
		if err != nil {
			return "", "", "", err
		}
		return uri, name + ".vpn", "text/plain; charset=utf-8", nil
	default:
		return "", "", "", fmt.Errorf("неизвестный формат экспорта")
	}
}
