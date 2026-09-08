// Package awg models and deploys AmneziaWG VPN servers over SSH and renders
// server/client configs. New servers use AWG 3.1; existing AWG 1.x/2.0 and plain
// WireGuard profiles retain their wire parameters until explicitly changed.
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
	Enabled            bool   `json:"enabled"`                       // profile is available in the UI; deploy/connect are still explicit actions
	Protocol           string `json:"protocol,omitempty"`            // "awg" (default) | "wireguard" (plain WG import)
	ProtocolVersion    string `json:"protocol_version,omitempty"`    // absent preserves legacy profiles; "1.0", "1.5", "2", "3.1"
	TrafficObfuscation *bool  `json:"traffic_obfuscation,omitempty"` // nil preserves legacy behavior; false renders plain WG

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

	Client      ClientConfig  `json:"client"`                 // local-router client bring-up (Part B)
	Routing     RoutingConfig `json:"routing"`                // local-router split routing (Part C)
	Interface   string        `json:"interface"`              // server interface name, "awg0"
	ClientIface string        `json:"client_iface,omitempty"` // local router interface, "awg0"/"awg1"/...
	DeployedAt  int64         `json:"deployed_at"`            // unix seconds; 0 = never deployed
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

// Obfuscation holds the AmneziaWG [Interface]-level parameters. H1..H4 and
// I1..I5 are strings so header ranges ("x-y") and the I-packet CPS DSL survive.
// These MUST be identical on server and client.
type Obfuscation struct {
	Jc                     int    `json:"jc"`
	Jmin                   int    `json:"jmin"`
	Jmax                   int    `json:"jmax"`
	S1                     int    `json:"s1"`
	S2                     int    `json:"s2"`
	S3                     int    `json:"s3"` // 2.0: cookie-reply padding
	S4                     int    `json:"s4"` // 2.0: transport padding
	H1                     string `json:"h1"`
	H2                     string `json:"h2"`
	H3                     string `json:"h3"`
	H4                     string `json:"h4"`
	I1                     string `json:"i1"` // 2.0: signature packets (CPS DSL); optional
	I2                     string `json:"i2"`
	I3                     string `json:"i3"`
	I4                     string `json:"i4"`
	I5                     string `json:"i5"`
	HeaderProtectionKey    string `json:"header_protection_key,omitempty"`     // base64 shared secret; REDACTED in API responses
	HasHeaderProtectionKey bool   `json:"has_header_protection_key,omitempty"` // computed for the frontend
	ContentPaddingAddition string `json:"content_padding_addition,omitempty"`
	RekeyAfterTime         string `json:"rekey_after_time,omitempty"`
	RekeyTimeout           string `json:"rekey_timeout,omitempty"`
	RejectAfterTime        string `json:"reject_after_time,omitempty"`
	KeepaliveTimeout       string `json:"keepalive_timeout,omitempty"`
	MaxHandshakeAttempts   string `json:"max_handshake_attempts,omitempty"`
	RandomTrailers         bool   `json:"random_trailers,omitempty"`
	DisableCookies         bool   `json:"disable_cookies,omitempty"`
}

// Peer is one client of the server. Secret fields REDACTED in API responses.
type Peer struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	PublicKey      string `json:"public_key"`
	PrivateKey     string `json:"private_key"` // REDACTED; "" if only a pubkey was supplied
	PSK            string `json:"psk"`         // REDACTED
	Address        string `json:"address"`     // peer tunnel address, e.g. 10.13.13.2/32
	AllowedIPs     string `json:"allowed_ips"` // client-side routing
	Keepalive      int    `json:"keepalive"`
	KeepaliveRange string `json:"keepalive_range,omitempty"` // AWG 3.1 range or explicit zero; takes precedence over Keepalive
	IsRouter       bool   `json:"is_router"`                 // this peer is the local Keenetic router
	HasPrivate     bool   `json:"has_private"`               // computed for the frontend
	CreatedAt      int64  `json:"created_at"`
}

// ClientConfig controls bringing the local router up as a client of the server.
type ClientConfig struct {
	Enabled bool   `json:"enabled"` // bring awg0 up (boot + now)
	PeerID  string `json:"peer_id"` // which Peer represents this router
}

// Zone (rendered in the UI as «Правило») is a named match-list for split
// routing. Each rule carries its own Route — "tunnel" pushes its members
// THROUGH the VPN, "direct" keeps them on the native WAN. The order of the
// Zones slice IS the priority: when a name matches several rules, the FIRST
// matching rule's route wins (the array is walked top-to-bottom and the
// decision short-circuits at the first hit).
//
// Mode is the legacy field name. Old configs use "include"/"exclude"; we
// migrate to Route on first read in RouteValue() so both names coexist.
type Zone struct {
	Name      string   `json:"name"`
	TunnelID  string   `json:"tunnel_id,omitempty"` // AWG2 connection used by this rule when Route=="tunnel".
	Order     int      `json:"order,omitempty"`     // Global routing priority across all tunnels (1 = top).
	Route     string   `json:"route,omitempty"`     // "tunnel" | "direct" — new vocabulary
	Mode      string   `json:"mode,omitempty"`      // legacy: "include" (→ tunnel) | "exclude" (→ direct)
	Domains   []string `json:"domains"`
	IPs       []string `json:"ips"`
	SourceIPs []string `json:"source_ips"` // per-source-device filter: if non-empty, the zone applies ONLY to packets from these LAN IPs/CIDRs. Empty = whole LAN (the historical default).
	Enabled   bool     `json:"enabled"`
}

// RouteValue returns the rule's effective route in the new vocabulary,
// migrating the legacy Mode field when Route is empty. "tunnel" / "direct".
func (z Zone) RouteValue() string {
	if z.Route == "tunnel" || z.Route == "direct" {
		return z.Route
	}
	if z.Mode == "exclude" {
		return "direct"
	}
	return "tunnel"
}

// IsCatchAll reports whether this zone matches every name/IP — a bare "*" in
// Domains or "0.0.0.0/0" / "::/0" in IPs. Under first-match-wins a catch-all
// rule shadows every rule after it in the array.
func (z Zone) IsCatchAll() bool {
	for _, d := range z.Domains {
		if s := strings.TrimSpace(d); s == "*" {
			return true
		}
	}
	for _, ip := range z.IPs {
		switch strings.TrimSpace(ip) {
		case "0.0.0.0/0", "::/0":
			return true
		}
	}
	return false
}

// RoutingConfig controls the local-router split routing (Part C).
type RoutingConfig struct {
	Mode         string `json:"mode"` // "off"|"zones" (direction is per-zone)|"full" (route everything)
	Zones        []Zone `json:"zones"`
	MTU          int    `json:"mtu"` // legacy; tunnel MTU lives in ServerConfig.MTU
	Killswitch   bool   `json:"killswitch"`
	DomainSource string `json:"domain_source"` // "resolve"|"dnsproxy"
	SNIRouting   bool   `json:"sni_routing"`   // additional: sniff TLS ClientHello SNI and route matched domains' IPs via the tunnel (beats DoH + CDN)
	TraceEnabled bool   `json:"trace_enabled"` // per-flow trace log (DNS + SNI) — off by default; flip from UI when debugging
	Active       bool   `json:"active"`        // committed → re-apply on boot (set on commit, cleared on explicit teardown)
}

// Default returns a new self-hosted AWG 3.1 profile. Shared obfuscation secrets
// are generated by ConfigureTrafficObfuscation or EnsureKeys and then persisted.
func Default() *ServerConfig {
	on := true
	return &ServerConfig{
		Enabled:            true,
		Protocol:           "awg",
		ProtocolVersion:    "3.1",
		TrafficObfuscation: &on,
		Conn:               Credentials{Port: 22, User: "root", AuthKind: "password"},
		Install:            "apt",
		ListenPort:         51820,
		Address:            "10.13.13.1/24",
		Subnet:             "10.13.13.0/24",
		MTU:                1420,
		DNS:                "1.1.1.1, 1.0.0.1",
		Obf:                DefaultObf(),
		Peers:              []Peer{},
		Interface:          "awg0",
		ClientIface:        "awg0",
		Routing: RoutingConfig{
			Mode:         "off",
			Zones:        []Zone{},
			MTU:          1420,
			DomainSource: "resolve",
		},
	}
}

func (c ServerConfig) UseObfuscation() bool {
	return c.Protocol != "wireguard" && (c.TrafficObfuscation == nil || *c.TrafficObfuscation)
}

// Normalize fills zero/blank fields with defaults so a partial config is usable.
func (c *ServerConfig) Normalize() {
	if c.Install != "userspace" && c.Install != "imported" {
		c.Install = "apt"
	}
	if c.Install == "imported" {
		c.Conn = Credentials{}
	} else {
		if c.Conn.Port == 0 {
			c.Conn.Port = 22
		}
		if c.Conn.User == "" {
			c.Conn.User = "root"
		}
		if c.Conn.AuthKind != "key" {
			c.Conn.AuthKind = "password"
		}
	}
	if c.Protocol != "wireguard" {
		c.Protocol = "awg"
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
	if c.ClientIface == "" {
		c.ClientIface = "awg0"
	}
	if c.Install != "imported" && strings.TrimSpace(c.Endpoint) == "" && strings.TrimSpace(c.Conn.Host) != "" {
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
		// Self-heal a peer that kept its private key but lost its public key (a
		// corrupted save / a bad re-deploy). Without this the server conf renders
		// `PublicKey = ` (empty) → `awg setconf` parse error → server won't start.
		if strings.TrimSpace(p.PublicKey) == "" && p.HasPrivate {
			if pub, err := PubFromPriv(p.PrivateKey); err == nil {
				p.PublicKey = pub
			}
		}
	}
	c.Routing.Normalize()
}

// Normalize fills zero/blank routing-only fields without touching the owning
// server connection. Route edits must be valid even for imported/WARP profiles
// that intentionally do not have VPS SSH credentials.
func (r *RoutingConfig) Normalize() {
	if r.Mode == "" {
		r.Mode = "off"
	}
	if r.MTU == 0 {
		r.MTU = 1420
	}
	if r.DomainSource != "dnsproxy" {
		r.DomainSource = "resolve"
	}
	if r.Zones == nil {
		r.Zones = []Zone{}
	}
	for i := range r.Zones {
		if r.Zones[i].Domains == nil {
			r.Zones[i].Domains = []string{}
		}
		if r.Zones[i].IPs == nil {
			r.Zones[i].IPs = []string{}
		}
		// Per-zone include/exclude: a zone with no explicit mode inherits the OLD
		// global routing mode (pre-migration), defaulting to include.
		if r.Zones[i].Mode != "include" && r.Zones[i].Mode != "exclude" {
			if r.Mode == "exclude" {
				r.Zones[i].Mode = "exclude"
			} else {
				r.Zones[i].Mode = "include"
			}
		}
	}
	// The global include/exclude is gone - direction is per-zone now; an old global
	// include/exclude collapses to "zones" (the per-zone derivation). Migrate AFTER
	// the zone loop so zones inherit the old global value first.
	if r.Mode == "include" || r.Mode == "exclude" {
		r.Mode = "zones"
	}
}

// Validate returns Russian-language problems with the config (empty = valid).
func (c *ServerConfig) Validate() []string {
	var errs []string
	if c.Install != "imported" {
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
	}
	if c.Install != "apt" && c.Install != "userspace" && c.Install != "imported" {
		errs = append(errs, "неизвестный метод установки")
	}
	if c.ListenPort < 1 || c.ListenPort > 65535 {
		errs = append(errs, "UDP-порт сервера вне диапазона")
	}
	if !validInterfaceName(c.Interface) {
		errs = append(errs, "имя интерфейса должно содержать 1–15 букв, цифр, точек, дефисов или подчёркиваний")
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
	if c.UseObfuscation() {
		errs = append(errs, c.Obf.Validate()...)
	}
	switch c.ProtocolVersion {
	case "", "1.0", "1.5", "2", "3.1":
	default:
		errs = append(errs, "неизвестная версия AmneziaWG")
	}
	seenName := map[string]bool{}
	seenPub := map[string]bool{}
	seenAddr := map[string]bool{}
	for _, p := range c.Peers {
		if !validU16Range(p.KeepaliveValue()) {
			errs = append(errs, "PersistentKeepalive: ожидается число или диапазон 0–65535")
		}
		name := strings.TrimSpace(p.Name)
		if name == "" {
			errs = append(errs, "у пира пустое имя")
		} else if seenName[name] {
			errs = append(errs, "повтор имени пира: "+name)
		}
		seenName[name] = true
		if strings.TrimSpace(p.PublicKey) == "" {
			errs = append(errs, "у пира пустой публичный ключ: "+name)
		} else {
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
	case "off", "full", "zones", "include", "exclude": // include/exclude accepted for back-compat (Normalize migrates → "zones")
	default:
		errs = append(errs, "неизвестный режим маршрутизации")
	}
	if c.Routing.DomainSource != "resolve" && c.Routing.DomainSource != "dnsproxy" {
		errs = append(errs, "неизвестный источник доменов для маршрутизации")
	}
	return errs
}

func validInterfaceName(name string) bool {
	if len(name) < 1 || len(name) > 15 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return name != "." && name != ".."
}

func validPeerAddr(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if strings.Contains(s, ",") {
		for _, part := range strings.Split(s, ",") {
			if !validPeerAddr(part) {
				return false
			}
		}
		return true
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	return net.ParseIP(s) != nil
}
