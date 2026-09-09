package dnsserver

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

type Upstream struct {
	Address      string   `json:"address"`
	BootstrapIPs []string `json:"bootstrap_ips"`
}

type Rule struct {
	ID                string     `json:"id"`
	Enabled           bool       `json:"enabled"`
	Domain            string     `json:"domain"`
	IncludeSubdomains bool       `json:"include_subdomains"`
	Upstream          Upstream   `json:"upstream"`
	Pool              []Upstream `json:"pool"`
}

type Config struct {
	Enabled         bool       `json:"enabled"`
	ListenHost      string     `json:"listen_host"`
	DNSPort         int        `json:"dns_port"`
	DefaultUpstream Upstream   `json:"default_upstream"`
	DefaultPool     []Upstream `json:"default_pool"`
	LoggingEnabled  bool       `json:"logging_enabled"`
	FastDNS         bool       `json:"fast_dns"`
	AWGFallback     string     `json:"awg_fallback"`
	TimeoutSeconds  int        `json:"timeout_seconds"`
	CacheSize       int        `json:"cache_size"`
	CacheTTLSeconds int        `json:"cache_ttl_seconds"`
	Rules           []Rule     `json:"rules"`
}

func Default() Config {
	u := Upstream{Address: "https://xbox-dns.ru/dns-query", BootstrapIPs: []string{}}
	c := Config{ListenHost: "auto", DNSPort: 5355,
		DefaultUpstream: Upstream{Address: "https://1.1.1.1/dns-query", BootstrapIPs: []string{}},
		AWGFallback:     "auto", TimeoutSeconds: 3, CacheSize: 512, CacheTTLSeconds: 3600, LoggingEnabled: true, FastDNS: true, DefaultPool: []Upstream{}}
	for i, domain := range []string{"claude.com", "grok.com", "claude.ai"} {
		c.Rules = append(c.Rules, Rule{ID: fmt.Sprintf("rule-%d", i+1), Enabled: true, Domain: domain, IncludeSubdomains: true, Upstream: u})
	}
	return c
}

func normalizeDomain(s string) (string, error) {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if s == "" {
		return "", fmt.Errorf("пустое доменное имя")
	}
	a, err := idna.Lookup.ToASCII(s)
	if err != nil || len(a) > 253 {
		return "", fmt.Errorf("некорректный домен %q", s)
	}
	for _, l := range strings.Split(a, ".") {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", fmt.Errorf("некорректный домен %q", s)
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return "", fmt.Errorf("некорректный домен %q", s)
			}
		}
	}
	return a, nil
}

func normalizeUpstream(u *Upstream) error {
	u.Address = strings.TrimSpace(u.Address)
	if len(u.Address) > 2048 {
		return fmt.Errorf("адрес DoH не должен превышать 2048 символов")
	}
	a, err := url.Parse(u.Address)
	if err != nil || a.Scheme != "https" || a.Hostname() == "" || a.User != nil || a.Fragment != "" || a.Opaque != "" {
		return fmt.Errorf("DNS-сервер должен иметь адрес DoH https://… без логина и фрагмента")
	}
	if a.Port() != "" {
		p, e := strconv.Atoi(a.Port())
		if e != nil || p < 1 || p > 65535 {
			return fmt.Errorf("неверный порт DoH")
		}
	}
	if a.Path == "" {
		a.Path = "/dns-query"
	}
	host := a.Hostname()
	if ip := net.ParseIP(host); ip == nil {
		if host, err = normalizeDomain(host); err != nil {
			return fmt.Errorf("неверное имя DoH: %w", err)
		}
	} else {
		host = ip.String()
	}
	// Equivalent spellings share a pool entry and scheduler history.
	if a.Port() != "" && a.Port() != "443" {
		a.Host = net.JoinHostPort(host, a.Port())
	} else if strings.Contains(host, ":") {
		a.Host = "[" + host + "]"
	} else {
		a.Host = host
	}
	u.Address = a.String()
	if len(u.BootstrapIPs) > 16 {
		return fmt.Errorf("не более 16 bootstrap IP на сервер")
	}
	clean := []string{}
	seen := map[string]bool{}
	for _, s := range u.BootstrapIPs {
		ip := net.ParseIP(strings.TrimSpace(s))
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("bootstrap IP должен быть IP-адресом: %q", s)
		}
		v := ip.String()
		if !seen[v] {
			seen[v] = true
			clean = append(clean, v)
		}
	}
	u.BootstrapIPs = clean
	return nil
}

// NormalizeValidate never replaces explicit empty rule lists.
func (c *Config) NormalizeValidate() error {
	c.ListenHost = strings.TrimSpace(c.ListenHost)
	if c.ListenHost == "" {
		c.ListenHost = "auto"
	}
	if c.ListenHost != "auto" {
		ip := net.ParseIP(c.ListenHost)
		if ip == nil || ip.IsUnspecified() || (!ip.IsPrivate() && !ip.IsLoopback()) {
			return fmt.Errorf("укажите локальный IP LAN или auto")
		}
		c.ListenHost = ip.String()
	}
	if c.DNSPort < 1 || c.DNSPort > 65535 {
		return fmt.Errorf("порт DNS должен быть от 1 до 65535")
	}
	if c.TimeoutSeconds < 1 || c.TimeoutSeconds > 10 {
		return fmt.Errorf("таймаут попытки: от 1 до 10 секунд")
	}
	if c.CacheSize < 0 || c.CacheSize > 4096 {
		return fmt.Errorf("размер DNS-кэша: от 0 до 4096 записей")
	}
	if c.CacheTTLSeconds < 1 || c.CacheTTLSeconds > 86400 {
		return fmt.Errorf("время хранения DNS-кэша: от 1 до 86400 секунд")
	}
	if c.AWGFallback == "" {
		c.AWGFallback = "auto"
	}
	if strings.HasPrefix(c.AWGFallback, "awg:") {
		c.AWGFallback = strings.TrimPrefix(c.AWGFallback, "awg:")
	}
	if len(c.AWGFallback) > 100 {
		return fmt.Errorf("неверное подключение AWG")
	}
	if err := normalizePool(&c.DefaultUpstream, &c.DefaultPool); err != nil {
		return err
	}
	if len(c.Rules) > 512 {
		return fmt.Errorf("не более 512 правил DNS")
	}
	ids, domains := map[string]bool{}, map[string]bool{}
	for i := range c.Rules {
		r := &c.Rules[i]
		d, e := normalizeDomain(r.Domain)
		if e != nil {
			return e
		}
		r.Domain = d
		if r.ID == "" {
			r.ID = fmt.Sprintf("rule-%d", i+1)
		}
		if ids[r.ID] {
			return fmt.Errorf("повторяется ID правила %s", r.ID)
		}
		ids[r.ID] = true
		if r.Enabled && domains[d] {
			return fmt.Errorf("повторяется включённое правило для %s", d)
		}
		if r.Enabled {
			domains[d] = true
		}
		if e := normalizePool(&r.Upstream, &r.Pool); e != nil {
			return fmt.Errorf("%s: %w", d, e)
		}
	}
	if c.Rules == nil {
		c.Rules = []Rule{}
	}
	return nil
}

// A rule owns its complete pool. Falling back must never silently send a
// domain assigned to a special DNS provider to the default provider instead.
func (c Config) upstreamsFor(domain string) ([]Upstream, string) {
	best := -1
	u := c.DefaultUpstream
	pool := c.DefaultPool
	source := "default"
	for _, r := range c.Rules {
		if r.Enabled && len(r.Domain) > best && (domain == r.Domain || r.IncludeSubdomains && strings.HasSuffix(domain, "."+r.Domain)) {
			best = len(r.Domain)
			u = r.Upstream
			pool = r.Pool
			source = r.Domain
		}
	}
	return append([]Upstream{u}, pool...), source
}

func (c Config) upstreamFor(domain string) Upstream {
	pool, _ := c.upstreamsFor(domain)
	return pool[0]
}

const maxPoolUpstreams = 8

func normalizePool(primary *Upstream, pool *[]Upstream) error {
	if len(*pool) >= maxPoolUpstreams {
		return fmt.Errorf("не более %d DoH-серверов в одном пуле, включая основной", maxPoolUpstreams)
	}
	if err := normalizeUpstream(primary); err != nil {
		return err
	}
	seen := map[string]bool{primary.Address: true}
	clean := make([]Upstream, 0, len(*pool))
	for _, u := range *pool {
		if err := normalizeUpstream(&u); err != nil {
			return err
		}
		if !seen[u.Address] {
			seen[u.Address] = true
			clean = append(clean, u)
		}
	}
	*pool = clean
	return nil
}

func cloneUpstreams(pool []Upstream) []Upstream {
	copy := append([]Upstream{}, pool...)
	for i := range copy {
		copy[i].BootstrapIPs = append([]string{}, copy[i].BootstrapIPs...)
	}
	return copy
}

func cloneConfig(c Config) Config {
	c.DefaultUpstream.BootstrapIPs = append([]string{}, c.DefaultUpstream.BootstrapIPs...)
	c.DefaultPool = cloneUpstreams(c.DefaultPool)
	c.Rules = append([]Rule{}, c.Rules...)
	for i := range c.Rules {
		c.Rules[i].Upstream.BootstrapIPs = append([]string{}, c.Rules[i].Upstream.BootstrapIPs...)
		c.Rules[i].Pool = cloneUpstreams(c.Rules[i].Pool)
	}
	return c
}

func validateNoSelfUpstream(c Config, host string) error {
	all := append([]Upstream{c.DefaultUpstream}, c.DefaultPool...)
	for _, rule := range c.Rules {
		if rule.Enabled {
			all = append(all, rule.Upstream)
			all = append(all, rule.Pool...)
		}
	}
	for _, u := range all {
		endpoint, err := url.Parse(u.Address)
		if err != nil {
			return err
		}
		port := endpoint.Port()
		if port == "" {
			port = "443"
		}
		if port != strconv.Itoa(c.DNSPort) {
			continue
		}
		self := endpoint.Hostname() == host
		for _, ip := range u.BootstrapIPs {
			if net.ParseIP(ip).Equal(net.ParseIP(host)) {
				self = true
			}
		}
		if self {
			return fmt.Errorf("DoH upstream указывает на этот DNS-сервер; выберите внешний DNS")
		}
	}
	return nil
}
