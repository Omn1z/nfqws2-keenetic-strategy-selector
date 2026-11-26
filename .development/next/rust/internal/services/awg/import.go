package awg

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// ImportClientConf parses an existing AmneziaWG client .conf file and produces a
// ServerConfig wired so the router can run as that client. The .conf MUST contain
// one [Interface] (the local client identity + obfuscation params) and one [Peer]
// (the remote server). The result is marked DeployedAt=now so the panel skips
// SSH-provisioning and lets the user go straight to "client up" + routing.
//
// Mapping:
//   - [Interface] PrivateKey/Address       -> Peer{IsRouter:true} on the server.
//   - [Interface] Jc/Jmin/Jmax/S1..4/H1..4/I1..5 -> ServerConfig.Obf (same on both ends).
//   - [Interface] DNS                       -> ServerConfig.DNS.
//   - [Peer]      PublicKey                 -> ServerConfig.PublicKey (server pub).
//   - [Peer]      PresharedKey              -> Peer.PSK.
//   - [Peer]      Endpoint                  -> ServerConfig.Endpoint + Conn.Host + ListenPort.
//   - [Peer]      AllowedIPs                -> Peer.AllowedIPs.
//   - [Peer]      PersistentKeepalive       -> Peer.Keepalive.
//
// The server's PrivateKey stays empty: we are a client, we don't have it, and
// nothing on the router-side path (client/up, routing) needs it.
func ImportClientConf(text string) (*ServerConfig, error) {
	confText, err := normalizeImportedConfig(text)
	if err != nil {
		return nil, err
	}
	iface, peer, err := parseConfSections(confText)
	if err != nil {
		return nil, err
	}

	priv := strings.TrimSpace(iface["PrivateKey"])
	if priv == "" {
		return nil, fmt.Errorf("в [Interface] нет PrivateKey")
	}
	srvPub := strings.TrimSpace(peer["PublicKey"])
	if srvPub == "" {
		return nil, fmt.Errorf("в [Peer] нет PublicKey")
	}
	endpoint := strings.TrimSpace(peer["Endpoint"])
	if endpoint == "" {
		return nil, fmt.Errorf("в [Peer] нет Endpoint")
	}
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("Endpoint %q невалиден: %v", endpoint, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("Endpoint порт %q невалиден", portStr)
	}

	clientPub, err := PubFromPriv(priv)
	if err != nil {
		return nil, fmt.Errorf("не удалось вывести публичный ключ из приватного: %v", err)
	}

	cfg := Default()
	// A newly imported profile inherits only the source's wire parameters.
	cfg.ProtocolVersion = ""
	cfg.TrafficObfuscation = nil
	cfg.Enabled = true
	cfg.Install = "imported" // ponytail: marker so UI knows there is no remote SSH to redeploy
	if hasAWGObfuscation(iface) {
		cfg.Protocol = "awg"
	} else {
		cfg.Protocol = "wireguard"
	}
	cfg.DeployedAt = time.Now().Unix()
	cfg.Interface = "awg0"

	cfg.PublicKey = srvPub
	cfg.PrivateKey = "" // we are the client; we don't have the server's private key
	cfg.Endpoint = endpoint
	cfg.Conn.Host = host
	cfg.ListenPort = port

	if v := strings.TrimSpace(iface["DNS"]); v != "" {
		cfg.DNS = v
	}
	if v := strings.TrimSpace(iface["MTU"]); v != "" {
		if mtu, _ := strconv.Atoi(v); mtu > 0 {
			cfg.MTU = mtu
		}
	}
	if a, s := deriveServerAddrs(iface["Address"]); a != "" {
		cfg.Address = a
		cfg.Subnet = s
	}

	cfg.Obf = Obfuscation{
		Jc:                     atoi(iface["Jc"]),
		Jmin:                   atoi(iface["Jmin"]),
		Jmax:                   atoi(iface["Jmax"]),
		S1:                     atoi(iface["S1"]),
		S2:                     atoi(iface["S2"]),
		S3:                     atoi(iface["S3"]),
		S4:                     atoi(iface["S4"]),
		H1:                     strings.TrimSpace(iface["H1"]),
		H2:                     strings.TrimSpace(iface["H2"]),
		H3:                     strings.TrimSpace(iface["H3"]),
		H4:                     strings.TrimSpace(iface["H4"]),
		I1:                     strings.TrimSpace(iface["I1"]),
		I2:                     strings.TrimSpace(iface["I2"]),
		I3:                     strings.TrimSpace(iface["I3"]),
		I4:                     strings.TrimSpace(iface["I4"]),
		I5:                     strings.TrimSpace(iface["I5"]),
		HeaderProtectionKey:    strings.TrimSpace(iface["HeaderProtectionKey"]),
		ContentPaddingAddition: strings.TrimSpace(iface["ContentPaddingAddition"]),
		RekeyAfterTime:         strings.TrimSpace(iface["RekeyAfterTime"]),
		RekeyTimeout:           strings.TrimSpace(iface["RekeyTimeout"]),
		RejectAfterTime:        strings.TrimSpace(iface["RejectAfterTime"]),
		KeepaliveTimeout:       strings.TrimSpace(iface["KeepaliveTimeout"]),
		MaxHandshakeAttempts:   strings.TrimSpace(iface["MaxHandshakeAttempts"]),
	}
	for _, field := range []struct {
		name  string
		value *bool
	}{{"RandomTrailers", &cfg.Obf.RandomTrailers}, {"DisableCookies", &cfg.Obf.DisableCookies}} {
		if v := strings.TrimSpace(iface[field.name]); v != "" {
			switch strings.ToLower(v) {
			case "on", "true", "1":
				*field.value = true
			case "off", "false", "0":
				*field.value = false
			default:
				return nil, fmt.Errorf("%s: ожидается on или off", field.name)
			}
		}
	}

	ka := atoi(peer["PersistentKeepalive"])
	if ka == 0 {
		ka = 25
	}
	allowed := strings.TrimSpace(peer["AllowedIPs"])
	if allowed == "" {
		allowed = "0.0.0.0/0, ::/0"
	}

	cfg.Peers = []Peer{{
		ID:         "router",
		Name:       "Router (imported)",
		PrivateKey: priv,
		PublicKey:  clientPub,
		PSK:        strings.TrimSpace(peer["PresharedKey"]),
		Address:    strings.TrimSpace(iface["Address"]),
		AllowedIPs: allowed,
		Keepalive:  ka,
		IsRouter:   true,
		HasPrivate: true,
		CreatedAt:  time.Now().Unix(),
	}}
	cfg.Client = ClientConfig{Enabled: false, PeerID: "router"}
	if v := strings.TrimSpace(peer["PersistentKeepalive"]); v != "" {
		if !validU16Range(v) {
			return nil, fmt.Errorf("PersistentKeepalive: ожидается число или диапазон 0–65535")
		}
		if strings.Contains(v, "-") || v == "0" {
			cfg.Peers[0].KeepaliveRange = v
		}
		if strings.Contains(v, "-") {
			cfg.Protocol = "awg"
		}
	}
	if v := strings.TrimSpace(iface["ProtocolVersion"]); v != "" {
		cfg.ProtocolVersion = v
	}
	if cfg.ProtocolVersion == "" && cfg.Protocol == "awg" {
		// Presence is relevant for format detection, even for explicitly disabled
		// values such as RandomTrailers=off or S3=0.
		for _, name := range []string{"HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies"} {
			if _, exists := iface[name]; exists {
				cfg.ProtocolVersion = "3.1"
				break
			}
		}
		if cfg.ProtocolVersion == "" {
			_, s3 := iface["S3"]
			_, s4 := iface["S4"]
			if s3 || s4 {
				cfg.ProtocolVersion = "2"
			}
		}
	}
	if cfg.Protocol == "awg" && cfg.ProtocolVersion == "" {
		cfg.ProtocolVersion = cfg.EffectiveProtocolVersion()
	}

	cfg.Normalize()
	if cfg.UseObfuscation() {
		if errs := cfg.Obf.Validate(); len(errs) > 0 {
			return nil, fmt.Errorf("%s", strings.Join(errs, "; "))
		}
	}
	return cfg, nil
}

func normalizeImportedConfig(text string) (string, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return "", fmt.Errorf("конфиг пустой")
	}
	if vpn := findVPNString(text); vpn != "" {
		return confFromVPNString(vpn)
	}
	return text, nil
}

func findVPNString(text string) string {
	for _, f := range strings.Fields(text) {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(f)), "vpn://") {
			return strings.TrimSpace(f)
		}
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(text)), "vpn://") {
		return strings.TrimSpace(text)
	}
	return ""
}

func confFromVPNString(vpn string) (string, error) {
	encoded := strings.TrimSpace(vpn)
	if len(encoded) >= len("vpn://") {
		encoded = encoded[len("vpn://"):]
	}
	if encoded == "" {
		return "", fmt.Errorf("vpn:// строка пустая")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(encoded + strings.Repeat("=", (4-len(encoded)%4)%4))
	}
	if err != nil {
		return "", fmt.Errorf("не удалось декодировать vpn://: %w", err)
	}
	if len(raw) <= 4 {
		return "", fmt.Errorf("vpn:// данные слишком короткие")
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw[4:]))
	if err != nil {
		return "", fmt.Errorf("не удалось распаковать vpn://: %w", err)
	}
	plain, err := io.ReadAll(io.LimitReader(zr, 4<<20))
	_ = zr.Close()
	if err != nil {
		return "", fmt.Errorf("не удалось прочитать vpn://: %w", err)
	}
	return confFromAmneziaJSON(plain)
}

func confFromAmneziaJSON(data []byte) (string, error) {
	var root struct {
		DNS1       string `json:"dns1"`
		DNS2       string `json:"dns2"`
		Containers []struct {
			AWG amneziaImportedProtocol `json:"awg"`
			WG  amneziaImportedProtocol `json:"wireguard"`
		} `json:"containers"`
	}
	if err := json.Unmarshal(data, &root); err != nil {
		return "", fmt.Errorf("vpn:// JSON не распознан: %w", err)
	}
	var lastRaw json.RawMessage
	var protocolVersion string
	for i := len(root.Containers) - 1; i >= 0; i-- {
		if len(root.Containers[i].AWG.LastConfig) > 0 && string(root.Containers[i].AWG.LastConfig) != "null" {
			lastRaw = root.Containers[i].AWG.LastConfig
			protocolVersion = root.Containers[i].AWG.ProtocolVersion
			break
		}
		if len(root.Containers[i].WG.LastConfig) > 0 && string(root.Containers[i].WG.LastConfig) != "null" {
			lastRaw = root.Containers[i].WG.LastConfig
			break
		}
	}
	if len(lastRaw) == 0 {
		return "", fmt.Errorf("в .vpn не найден AWG last_config")
	}

	var lastJSON []byte
	var lastStr string
	if err := json.Unmarshal(lastRaw, &lastStr); err == nil {
		lastJSON = []byte(lastStr)
	} else {
		lastJSON = lastRaw
	}
	var last struct {
		Config          string          `json:"config"`
		MTU             json.RawMessage `json:"mtu"`
		Port            json.RawMessage `json:"port"`
		ProtocolVersion string          `json:"protocol_version"`
	}
	if err := json.Unmarshal(lastJSON, &last); err != nil {
		return "", fmt.Errorf("AWG last_config не распознан: %w", err)
	}
	conf := strings.TrimSpace(last.Config)
	if conf == "" {
		return "", fmt.Errorf("AWG last_config не содержит WireGuard config")
	}
	conf = strings.ReplaceAll(conf, "$PRIMARY_DNS", strings.TrimSpace(root.DNS1))
	conf = strings.ReplaceAll(conf, "$SECONDARY_DNS", strings.TrimSpace(root.DNS2))
	if mtu := rawJSONString(last.MTU); mtu != "" {
		conf = setInterfaceKV(conf, "MTU", mtu)
	}
	if port := rawJSONString(last.Port); port != "" {
		conf = setInterfaceKV(conf, "ListenPort", port)
	}
	if protocolVersion == "" {
		protocolVersion = last.ProtocolVersion
	}
	if protocolVersion != "" {
		switch protocolVersion {
		case "1.0", "1.5", "2", "3.1":
			// Internal import metadata, consumed by ImportClientConf and never
			// emitted into the awg configuration sent to the engine.
			conf = setInterfaceKV(conf, "ProtocolVersion", protocolVersion)
		default:
			return "", fmt.Errorf("неподдерживаемая версия AmneziaWG: %s", protocolVersion)
		}
	}
	return conf, nil
}

type amneziaImportedProtocol struct {
	LastConfig      json.RawMessage `json:"last_config"`
	ProtocolVersion string          `json:"protocol_version"`
}

func rawJSONString(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}
	var n json.Number
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&n); err == nil {
		return n.String()
	}
	return ""
}

func setInterfaceKV(conf, key, value string) string {
	if strings.TrimSpace(value) == "" {
		return conf
	}
	lines := strings.Split(conf, "\n")
	inIface := false
	insertAt := -1
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			if inIface {
				insertAt = i
				break
			}
			inIface = strings.EqualFold(strings.TrimSpace(t[1:len(t)-1]), "Interface")
			continue
		}
		if inIface {
			insertAt = i + 1
			if k, _, ok := splitKV(t); ok && strings.EqualFold(k, key) {
				lines[i] = key + " = " + value
				return strings.Join(lines, "\n")
			}
		}
	}
	if insertAt < 0 {
		return conf
	}
	line := key + " = " + value
	lines = append(lines, "")
	copy(lines[insertAt+1:], lines[insertAt:])
	lines[insertAt] = line
	return strings.Join(lines, "\n")
}

func splitKV(line string) (key, value string, ok bool) {
	eq := strings.IndexByte(line, '=')
	if eq < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:eq]), strings.TrimSpace(line[eq+1:]), true
}

func hasAWGObfuscation(iface map[string]string) bool {
	for _, k := range []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5", "HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies", "ProtocolVersion"} {
		if strings.TrimSpace(iface[k]) != "" {
			return true
		}
	}
	return false
}

// parseConfSections returns the [Interface] and [Peer] key-value maps from the
// given .conf text. Multiple [Peer] sections are not supported here (a client
// .conf has exactly one).
func parseConfSections(text string) (iface, peer map[string]string, err error) {
	iface = map[string]string{}
	peer = map[string]string{}
	section := ""
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		k, v, ok := splitKV(line)
		if !ok {
			continue
		}
		switch section {
		case "interface":
			iface[k] = v
		case "peer":
			peer[k] = v
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, err
	}
	if len(iface) == 0 {
		return nil, nil, fmt.Errorf("секция [Interface] отсутствует или пуста")
	}
	if len(peer) == 0 {
		return nil, nil, fmt.Errorf("секция [Peer] отсутствует или пуста")
	}
	return iface, peer, nil
}

// deriveServerAddrs picks plausible server Address (.1) and Subnet (/24) from the
// client's Address. Used only for UI display; the local client doesn't need them
// to bring its tunnel up.
func deriveServerAddrs(clientAddr string) (addr, subnet string) {
	if strings.Contains(clientAddr, ",") {
		clientAddr = strings.Split(clientAddr, ",")[0]
	}
	ip, _, err := net.ParseCIDR(strings.TrimSpace(clientAddr))
	if err != nil || ip.To4() == nil {
		return "", ""
	}
	v4 := ip.To4()
	return fmt.Sprintf("%d.%d.%d.1/24", v4[0], v4[1], v4[2]),
		fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}
