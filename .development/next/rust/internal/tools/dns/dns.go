// Package dns resolves a hostname through a chosen encrypted DNS server
// (DNS-over-HTTPS or DNS-over-TLS). It is used by runs to test each strategy
// against different DNS providers, since the resolved IP (and whether the ISP
// poisons it) is part of what makes a bypass work.
package dns

import (
	"fmt"
	"net/url"
	"strings"
)

// Type is the transport of an encrypted DNS server.
const (
	DoH = "doh" // address is a full https URL (RFC 8484, application/dns-message)
	DoT = "dot" // address is host[:port], TLS on 853 by default
)

// Server is one user-configurable encrypted DNS endpoint.
type Server struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"` // DoH | DoT
	Addr string `json:"addr"` // DoH: https URL; DoT: host[:port]
}

// Defaults seeds the DNS list with the providers requested by the user, with a
// DoH entry for each and a DoT entry where the provider is known to offer one.
// Addresses verified 2026-05-28; users can edit/delete them in the UI.
func Defaults() []Server {
	return []Server{
		{ID: "google-doh", Name: "Google · DoH", Type: DoH, Addr: "https://dns.google/dns-query"},
		{ID: "google-dot", Name: "Google · DoT", Type: DoT, Addr: "dns.google"},
		{ID: "cloudflare-doh", Name: "Cloudflare · DoH", Type: DoH, Addr: "https://cloudflare-dns.com/dns-query"},
		{ID: "cloudflare-dot", Name: "Cloudflare · DoT", Type: DoT, Addr: "one.one.one.one"},
		{ID: "comss-doh", Name: "Comss · DoH", Type: DoH, Addr: "https://dns.comss.one/dns-query"},
		{ID: "yandex-doh", Name: "Yandex · DoH", Type: DoH, Addr: "https://common.dot.dns.yandex.net/dns-query"},
		{ID: "yandex-dot", Name: "Yandex · DoT", Type: DoT, Addr: "common.dot.dns.yandex.net"},
		{ID: "xboxdns-doh", Name: "xbox-dns · DoH", Type: DoH, Addr: "https://xbox-dns.ru/dns-query"},
		{ID: "xboxdns-dot", Name: "xbox-dns · DoT", Type: DoT, Addr: "xbox-dns.ru"},
		{ID: "geohide-doh", Name: "GeoHide · DoH", Type: DoH, Addr: "https://dns.geohide.ru:8443/dns-query"},
		{ID: "geohide-dot", Name: "GeoHide · DoT", Type: DoT, Addr: "dns.geohide.ru"},
		{ID: "adguard-doh", Name: "AdGuard · DoH", Type: DoH, Addr: "https://dns.adguard-dns.com/dns-query"},
		{ID: "adguard-dot", Name: "AdGuard · DoT", Type: DoT, Addr: "dns.adguard-dns.com"},
	}
}

// Normalize trims fields and lowercases the type. It does not assign an ID.
func (s *Server) Normalize() {
	s.Name = strings.TrimSpace(s.Name)
	s.Type = strings.ToLower(strings.TrimSpace(s.Type))
	s.Addr = strings.TrimSpace(s.Addr)
}

// Validate checks a server is usable before it is saved or queried.
func (s *Server) Validate() error {
	if s.Name == "" {
		return fmt.Errorf("укажите название DNS")
	}
	switch s.Type {
	case DoH:
		u, err := url.Parse(s.Addr)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("DoH-адрес должен быть https://… ссылкой")
		}
	case DoT:
		if s.Addr == "" || strings.ContainsAny(s.Addr, "/ ") {
			return fmt.Errorf("DoT-адрес должен быть host или host:port")
		}
	default:
		return fmt.Errorf("тип DNS должен быть doh или dot")
	}
	return nil
}
