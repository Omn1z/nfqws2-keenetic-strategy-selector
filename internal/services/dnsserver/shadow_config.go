package dnsserver

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

const shadowRoute = "shadow"

type ShadowDomain struct {
	Domain            string `json:"domain"`
	IncludeSubdomains bool   `json:"include_subdomains"`
}

// Servers is retained only to read old exports. Discovery is always automatic;
// normalization discards manually configured upstreams.
// Old configurations keep Shadow DNS disabled until the user enables it.
type ShadowDNSConfig struct {
	Enabled bool           `json:"enabled"`
	Servers []string       `json:"servers"`
	Domains []ShadowDomain `json:"domains"`
}

func defaultShadowDNS() *ShadowDNSConfig {
	return &ShadowDNSConfig{Servers: []string{}, Domains: []ShadowDomain{
		{Domain: "ru", IncludeSubdomains: true}, {Domain: "xn--p1ai", IncludeSubdomains: true},
		{Domain: "vk.*", IncludeSubdomains: true}, {Domain: "avito.*", IncludeSubdomains: true},
	}}
}

func (s *ShadowDNSConfig) normalizeValidate() error {
	if len(s.Domains) > 4096 {
		return fmt.Errorf("Shadow DNS: не больше 4096 доменов")
	}
	s.Servers = []string{}
	domains := make([]ShadowDomain, 0, len(s.Domains))
	indices := map[string]int{}
	for _, rule := range s.Domains {
		domain := strings.TrimSpace(rule.Domain)
		if strings.HasPrefix(domain, "*.") {
			domain = strings.TrimPrefix(domain, "*.")
			rule.IncludeSubdomains = true
		}
		if strings.HasPrefix(domain, ".") {
			domain = strings.TrimPrefix(domain, ".")
			rule.IncludeSubdomains = true
		}
		var err error
		rule.Domain, err = normalizeShadowPattern(domain)
		if err != nil {
			return fmt.Errorf("Shadow DNS: %w", err)
		}
		if previous, ok := indices[rule.Domain]; ok {
			domains[previous].IncludeSubdomains = domains[previous].IncludeSubdomains || rule.IncludeSubdomains
			continue
		}
		indices[rule.Domain] = len(domains)
		domains = append(domains, rule)
	}
	s.Domains = domains
	if s.Enabled && len(s.Domains) == 0 {
		return fmt.Errorf("Shadow DNS: добавьте хотя бы один домен")
	}
	return nil
}

func normalizeShadowPattern(pattern string) (string, error) {
	pattern = strings.TrimSuffix(strings.TrimSpace(pattern), ".")
	labels := strings.Split(pattern, ".")
	anchored := false
	for i, label := range labels {
		if label == "*" {
			continue
		}
		normalized, err := normalizeDomain(label)
		if err != nil || strings.Contains(normalized, ".") {
			return "", fmt.Errorf("некорректная маска домена %q; * заменяет целую часть имени", pattern)
		}
		labels[i], anchored = normalized, true
	}
	result := strings.Join(labels, ".")
	if !anchored || len(result) > 253 {
		return "", fmt.Errorf("некорректная маска домена %q", pattern)
	}
	return result, nil
}

func normalizeShadowServer(raw string) (string, error) {
	address := strings.TrimSpace(raw)
	host, port := address, "53"
	if ip := net.ParseIP(address); ip == nil {
		var err error
		host, port, err = net.SplitHostPort(address)
		if err != nil {
			return "", fmt.Errorf("Shadow DNS: укажите IP DNS-сервера или IP:порт: %q", raw)
		}
	}
	ip := net.ParseIP(host)
	p, err := strconv.Atoi(port)
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.Equal(net.IPv4bcast) || err != nil || p < 1 || p > 65535 {
		return "", fmt.Errorf("Shadow DNS: недопустимый адрес DNS-сервера: %q", raw)
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(p)), nil
}

// A reversed label trie avoids scanning every pattern on each DNS request.
// A wildcard consumes exactly one complete label; a leading *. is represented
// by descendants and includes the apex as well as all its subdomains.
type shadowMatcher struct {
	labels      map[string]*shadowMatcher
	wildcard    *shadowMatcher
	exact       bool
	descendants bool
}

func newShadowMatcher(cfg *ShadowDNSConfig) *shadowMatcher {
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	m := &shadowMatcher{}
	for _, rule := range cfg.Domains {
		node := m
		labels := strings.Split(rule.Domain, ".")
		for i := len(labels) - 1; i >= 0; i-- {
			if labels[i] == "*" {
				if node.wildcard == nil {
					node.wildcard = &shadowMatcher{}
				}
				node = node.wildcard
			} else {
				if node.labels == nil {
					node.labels = map[string]*shadowMatcher{}
				}
				child := node.labels[labels[i]]
				if child == nil {
					child = &shadowMatcher{}
					node.labels[labels[i]] = child
				}
				node = child
			}
		}
		node.exact = true
		node.descendants = node.descendants || rule.IncludeSubdomains
	}
	return m
}

func (m *shadowMatcher) matches(domain string) bool {
	if m == nil {
		return false
	}
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	if domain == "" || len(domain) > 253 {
		return false
	}
	return m.matchLabels(domain)
}

func (m *shadowMatcher) matchLabels(domain string) bool {
	if m == nil {
		return false
	}
	if m.descendants {
		return true
	}
	if domain == "" {
		return m.exact
	}
	i := strings.LastIndexByte(domain, '.')
	label, rest := domain[i+1:], ""
	if i >= 0 {
		rest = domain[:i]
	}
	if label == "" {
		return false
	}
	return m.labels[label].matchLabels(rest) || m.wildcard.matchLabels(rest)
}
