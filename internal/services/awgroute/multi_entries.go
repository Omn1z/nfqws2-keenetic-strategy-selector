package awgroute

import (
	"net"
	"nfqws2strategy/internal/services/awg"
	"sort"
	"strings"
)

func (svc *Service) awgMultiRuleEntriesWithLookup(z awg.Zone, lookup func(string) []string) ([]string, bool, bool) {
	seen := map[string]bool{}
	out := []string{}
	add := func(raw string) {
		if ent, ok := awgNormalizeMultiEntry(raw); ok && !seen[ent] {
			seen[ent] = true
			out = append(out, ent)
		}
	}
	catchAll := z.IsCatchAll()
	staticOK := len(z.Domains) == 0 && len(z.IPs) == 0
	expDomains, expIPs := svc.expandEntries(z.Domains)
	for _, ip := range append(append([]string{}, z.IPs...), expIPs...) {
		if awgIsCatchAll(ip) {
			catchAll = true
			staticOK = true
			continue
		}
		before := len(out)
		add(ip)
		if len(out) > before {
			staticOK = true
		}
	}
	for _, d := range expDomains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if awgIsCatchAll(d) {
			catchAll = true
			staticOK = true
			continue
		}
		if isMaskEntry(d) {
			continue
		}
		for _, ip := range lookup(d) {
			if _, ok := sharedCDNProvider(ip); ok {
				svc.awgNoteSharedCDNSkip("multi-resolve", ip)
				continue
			}
			before := len(out)
			add(ip)
			if len(out) > before {
				staticOK = true
			}
		}
	}
	sort.Strings(out)
	return out, catchAll, staticOK
}

func awgNormalizeMultiEntry(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" || s == "*" {
		return "", false
	}
	if ip := net.ParseIP(s); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String() + "/32", true
		}
		return "", false
	}
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		return "", false
	}
	if v4 := ip.To4(); v4 != nil {
		n.IP = v4
		return n.String(), true
	}
	return "", false
}
