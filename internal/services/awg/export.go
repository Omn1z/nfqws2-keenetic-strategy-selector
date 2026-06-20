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

func ClientVPNURI(c *ServerConfig, p Peer) (string, error) {
	conf := ClientConf(c, p)
	dns1, dns2 := splitDNS(c.DNS)
	mtu := c.MTU
	if mtu == 0 {
		mtu = c.Routing.MTU
	}
	if mtu == 0 {
		mtu = 1280
	}
	last, err := json.Marshal(map[string]any{
		"config": conf,
		"mtu":    strconv.Itoa(mtu),
		"port":   c.ListenPort,
	})
	if err != nil {
		return "", err
	}
	root, err := json.Marshal(map[string]any{
		"dns1":     dns1,
		"dns2":     dns2,
		"hostName": hostOnly(c.Endpoint),
		"containers": []map[string]any{{
			"awg": map[string]any{"last_config": string(last)},
		}},
	})
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
	return "vpn://" + base64.RawURLEncoding.EncodeToString(compressed.Bytes()), nil
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
