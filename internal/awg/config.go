// Package awg models and deploys an AmneziaWG 2.0 ("AWG2") VPN: it provisions a
// server on a remote VPS over SSH, renders server/client configs, and is the
// portable core behind the panel's «Сервисы → AWG2» tab. All obfuscation
// parameters are AmneziaWG 2.0 and must be byte-identical on both ends.
package awg

import (
	"fmt"
	"net"
	"strings"
)

// ServerConfig is the full AWG2 state, persisted as awg.json (0600 — it holds
// private keys and the VPS password). It mirrors the socks5/tgws config shape
// (Default/Normalize/Validate).
type ServerConfig struct {
	Enabled bool `json:"enabled"` // UI hint only; deploy is always an explicit action

	Conn    Credentials `json:"conn"`    // VPS SSH connection
	Install string      `json:"install"` // "apt" (default) | "userspace"

	// WG server identity — generated ONCE and reused on every re-deploy.
	PrivateKey string `json:"private_key"` // base64; REDACTED in API responses
	PublicKey  string `json:"public_key"`  // base64; safe to expose

	ListenPort int    `json:"listen_port"` // server UDP port
	Address    string `json:"address"`     // server tunnel address, CIDR
	Subnet     string `json:"subnet"`      // VPN subnet for NAT MASQUERADE
	MTU        int    `json:"mtu"`
	DNS        string `json:"dns"`       // pushed into client configs
	WANIface   string `json:"wan_iface"` // VPS WAN iface ("" = auto-detect on deploy)
	Endpoint   string `json:"endpoint"`  // public host:port clients dial

	Obf   Obfuscation `json:"obf"`   // AmneziaWG 2.0 obfuscation (Interface-level)
	Peers []Peer      `json:"peers"` // the Keenetic router is conventionally peer #1

	Client     ClientConfig  `json:"client"`      // local-router client bring-up (Part B)
	Routing    RoutingConfig `json:"routing"`     // local-router split routing (Part C)
	Interface  string        `json:"interface"`   // server interface name, "awg0"
	DeployedAt int64         `json:"deployed_at"` // unix seconds; 0 = never deployed
}

// Credentials is the VPS SSH connection. Secret fields are REDACTED in API
// responses and preserved (kept from the stored copy) when sent back blank.
type Credentials struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	AuthKind string `json:"auth_kind"`          // "password" | "key"
	Password string `json:"password,omitempty"` // REDACTED
	KeyPEM   string `json:"key_pem,omitempty"`  // REDACTED (PEM private key)
	KeyPass  string `json:"key_pass,omitempty"` // REDACTED (key passphrase)
	KnownKey string `json:"known_key"`          // TOFU-pinned host key (authorized_keys line)
}

// Obfuscation holds the AmneziaWG 2.0 [Interface]-level parameters. H1..H4 and
// I1..I5 are strings so header ranges ("x-y") and the I-packet CPS DSL survive.
// These MUST be identical on server and client.
type Obfuscation struct {
	Jc   int    `json:"jc"`
	Jmin int    `json:"jmin"`
	Jmax int    `json:"jmax"`
	S1   int    `json:"s1"`
	S2   int    `json:"s2"`
	S3   int    `json:"s3"` // 2.0: cookie-reply padding
	S4   int    `json:"s4"` // 2.0: transport padding
	H1   string `json:"h1"`
	H2   string `json:"h2"`
	H3   string `json:"h3"`
	H4   string `json:"h4"`
	I1   string `json:"i1"` // 2.0: signature packets (CPS DSL); optional
	I2   string `json:"i2"`
	I3   string `json:"i3"`
	I4   string `json:"i4"`
	I5   string `json:"i5"`
}

// Peer is one client of the server. Secret fields REDACTED in API responses.
type Peer struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"` // REDACTED; "" if only a pubkey was supplied
	PSK        string `json:"psk"`         // REDACTED
	Address    string `json:"address"`     // peer tunnel address, e.g. 10.13.13.2/32
	AllowedIPs string `json:"allowed_ips"` // client-side routing
	Keepalive  int    `json:"keepalive"`
	IsRouter   bool   `json:"is_router"`   // this peer is the local Keenetic router
	HasPrivate bool   `json:"has_private"` // computed for the frontend
	CreatedAt  int64  `json:"created_at"`
}

// ClientConfig controls bringing the local router up as a client of the server.
type ClientConfig struct {
	Enabled bool   `json:"enabled"` // bring awg0 up (boot + now)
	PeerID  string `json:"peer_id"` // which Peer represents this router
}

// Zone is a named group of domains/IPs for split routing.
type Zone struct {
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
	IPs     []string `json:"ips"`
	Enabled bool     `json:"enabled"`
}

// RoutingConfig controls the local-router split routing (Part C).
type RoutingConfig struct {
	Mode         string `json:"mode"` // "off"|"full"|"include"|"exclude"
	Zones        []Zone `json:"zones"`
	MTU          int    `json:"mtu"` // awg0 client MTU
	Killswitch   bool   `json:"killswitch"`
	DomainSource string `json:"domain_source"` // "resolve"|"dnsmasq"
}

// Default returns a disabled, ready-to-fill server config with AWG 2.0 defaults.
func Default() *ServerConfig {
	return &ServerConfig{
		Conn:       Credentials{Port: 22, User: "root", AuthKind: "password"},
		Install:    "apt",
		ListenPort: 51820,
		Address:    "10.13.13.1/24",
		Subnet:     "10.13.13.0/24",
		MTU:        1420,
		DNS:        "1.1.1.1, 1.0.0.1",
		Obf:        DefaultObf(),
		Peers:      []Peer{},
		Interface:  "awg0",
		Routing: RoutingConfig{
			Mode:         "off",
			Zones:        []Zone{},
			MTU:          1376,
			DomainSource: "resolve",
		},
	}
}

// Normalize fills zero/blank fields with defaults so a partial config is usable.
func (c *ServerConfig) Normalize() {
	if c.Conn.Port == 0 {
		c.Conn.Port = 22
	}
	if c.Conn.User == "" {
		c.Conn.User = "root"
	}
	if c.Conn.AuthKind != "key" {
		c.Conn.AuthKind = "password"
	}
	if c.Install != "userspace" {
		c.Install = "apt"
	}
	if c.ListenPort == 0 {
		c.ListenPort = 51820
	}
	if c.Address == "" {
		c.Address = "10.13.13.1/24"
	}
	if c.Subnet == "" {
		c.Subnet = "10.13.13.0/24"
	}
	if c.MTU == 0 {
		c.MTU = 1420
	}
	if c.Interface == "" {
		c.Interface = "awg0"
	}
	if strings.TrimSpace(c.Endpoint) == "" && strings.TrimSpace(c.Conn.Host) != "" {
		c.Endpoint = fmt.Sprintf("%s:%d", strings.TrimSpace(c.Conn.Host), c.ListenPort)
	}
	c.Obf.normalize()
	if c.Peers == nil {
		c.Peers = []Peer{}
	}
	for i := range c.Peers {
		p := &c.Peers[i]
		if p.Keepalive == 0 {
			p.Keepalive = 25
		}
		if strings.TrimSpace(p.AllowedIPs) == "" {
			p.AllowedIPs = "0.0.0.0/0, ::/0"
		}
		p.HasPrivate = strings.TrimSpace(p.PrivateKey) != ""
	}
	if c.Routing.Mode == "" {
		c.Routing.Mode = "off"
	}
	if c.Routing.MTU == 0 {
		c.Routing.MTU = 1376
	}
	if c.Routing.DomainSource != "dnsmasq" {
		c.Routing.DomainSource = "resolve"
	}
	if c.Routing.Zones == nil {
		c.Routing.Zones = []Zone{}
	}
	for i := range c.Routing.Zones {
		if c.Routing.Zones[i].Domains == nil {
			c.Routing.Zones[i].Domains = []string{}
		}
		if c.Routing.Zones[i].IPs == nil {
			c.Routing.Zones[i].IPs = []string{}
		}
	}
}

// Validate returns Russian-language problems with the config (empty = valid).
func (c *ServerConfig) Validate() []string {
	var errs []string
	if strings.TrimSpace(c.Conn.Host) == "" {
		errs = append(errs, "укажите адрес VPS")
	}
	if c.Conn.Port < 1 || c.Conn.Port > 65535 {
		errs = append(errs, "порт SSH вне диапазона")
	}
	if strings.TrimSpace(c.Conn.User) == "" {
		errs = append(errs, "укажите пользователя SSH")
	}
	if c.Conn.AuthKind != "password" && c.Conn.AuthKind != "key" {
		errs = append(errs, "неизвестный метод авторизации SSH")
	}
	if c.Install != "apt" && c.Install != "userspace" {
		errs = append(errs, "неизвестный метод установки")
	}
	if c.ListenPort < 1 || c.ListenPort > 65535 {
		errs = append(errs, "UDP-порт сервера вне диапазона")
	}
	if _, _, err := net.ParseCIDR(strings.TrimSpace(c.Address)); err != nil {
		errs = append(errs, "адрес интерфейса должен быть в формате CIDR, напр. 10.13.13.1/24")
	}
	if _, _, err := net.ParseCIDR(strings.TrimSpace(c.Subnet)); err != nil {
		errs = append(errs, "подсеть должна быть в формате CIDR, напр. 10.13.13.0/24")
	}
	if c.MTU < 1280 || c.MTU > 1500 {
		errs = append(errs, "MTU вне диапазона 1280–1500")
	}
	errs = append(errs, c.Obf.Validate()...)
	seenName := map[string]bool{}
	seenPub := map[string]bool{}
	seenAddr := map[string]bool{}
	for _, p := range c.Peers {
		name := strings.TrimSpace(p.Name)
		if name == "" {
			errs = append(errs, "у пира пустое имя")
		} else if seenName[name] {
			errs = append(errs, "повтор имени пира: "+name)
		}
		seenName[name] = true
		if p.PublicKey != "" {
			if seenPub[p.PublicKey] {
				errs = append(errs, "повтор публичного ключа пира: "+name)
			}
			seenPub[p.PublicKey] = true
		}
		addr := strings.TrimSpace(p.Address)
		if !validPeerAddr(addr) {
			errs = append(errs, "адрес пира должен быть IP или CIDR: "+name)
		} else if seenAddr[addr] {
			errs = append(errs, "повтор адреса пира: "+name)
		}
		seenAddr[addr] = true
	}
	switch c.Routing.Mode {
	case "off", "full", "include", "exclude":
	default:
		errs = append(errs, "неизвестный режим маршрутизации")
	}
	if c.Routing.DomainSource != "resolve" && c.Routing.DomainSource != "dnsmasq" {
		errs = append(errs, "неизвестный источник доменов для маршрутизации")
	}
	return errs
}

func validPeerAddr(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	return net.ParseIP(s) != nil
}
