package awg

import (
	"bufio"
	"fmt"
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
	iface, peer, err := parseConfSections(text)
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
	cfg.Enabled = true
	cfg.Install = "imported" // ponytail: marker so UI knows there is no remote SSH to redeploy
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
		Jc:   atoi(iface["Jc"]),
		Jmin: atoi(iface["Jmin"]),
		Jmax: atoi(iface["Jmax"]),
		S1:   atoi(iface["S1"]),
		S2:   atoi(iface["S2"]),
		S3:   atoi(iface["S3"]),
		S4:   atoi(iface["S4"]),
		H1:   strings.TrimSpace(iface["H1"]),
		H2:   strings.TrimSpace(iface["H2"]),
		H3:   strings.TrimSpace(iface["H3"]),
		H4:   strings.TrimSpace(iface["H4"]),
		I1:   strings.TrimSpace(iface["I1"]),
		I2:   strings.TrimSpace(iface["I2"]),
		I3:   strings.TrimSpace(iface["I3"]),
		I4:   strings.TrimSpace(iface["I4"]),
		I5:   strings.TrimSpace(iface["I5"]),
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

	cfg.Normalize()
	return cfg, nil
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
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		k := strings.TrimSpace(line[:eq])
		v := strings.TrimSpace(line[eq+1:])
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
