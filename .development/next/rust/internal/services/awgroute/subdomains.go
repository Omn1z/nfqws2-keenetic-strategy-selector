package awgroute

import (
	"net"
	"strings"

	"nfqws2strategy/internal/services/awg"
)

// Apply the rule policy after list/geosite expansion. Never mutate the cached
// expansion: two rules can use the same source with different subdomain choices.
// Missing policy preserves legacy suffix/glob behavior on existing routers.
func (svc *Service) expandZoneEntries(z awg.Zone) ([]string, []string) {
	domains, ips := svc.expandEntries(z.Domains)
	if z.IncludeSubdomains == nil {
		return domains, ips
	}
	out := make([]string, len(domains))
	for i, raw := range domains {
		out[i] = domainSubdomainPolicy(raw, *z.IncludeSubdomains)
	}
	return out, ips
}

func domainSubdomainPolicy(raw string, include bool) string {
	name := strings.ToLower(strings.TrimSpace(raw))
	for _, prefix := range []string{"full:", "domain:"} {
		if strings.HasPrefix(name, prefix) {
			name = strings.TrimSpace(strings.TrimPrefix(name, prefix))
			break
		}
	}
	name = strings.TrimSuffix(name, ".")
	if include && strings.HasPrefix(name, "*.") {
		name = strings.TrimPrefix(name, "*.")
	}
	name = strings.TrimPrefix(name, ".")
	if !routingHostname(name) {
		// IPs, catch-all, regexes and arbitrary globs keep their explicit meaning.
		return raw
	}
	if include {
		return name
	}
	return "full:" + name
}

// A compile-time normalization, not a DNS lookup. Ordinary domain list entries
// and punycode names are accepted; arbitrary regex/glob/IP text is untouched.
func routingHostname(name string) bool {
	if name == "" || len(name) > 253 || net.ParseIP(name) != nil {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
				return false
			}
		}
	}
	return true
}

// Full matchers still pre-resolve their apex for static ipset seeding. A full:
// marker must never be sent to nslookup or the user-supplied lookup callback.
func routingResolveName(raw string) string {
	name := strings.TrimSpace(raw)
	if strings.HasPrefix(strings.ToLower(name), "full:") {
		name = strings.TrimSpace(name[len("full:"):])
	}
	return name
}
