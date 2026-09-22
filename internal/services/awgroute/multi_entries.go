package awgroute

import (
	"net"
	"sort"
	"strings"
	"sync"

	"nfqws2strategy/internal/services/awg"
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
	// A geosite/list can expand into thousands of names. Resolve them with the
	// same bounded concurrency as the legacy ipset builder, then consume the
	// answers in rule order so matching and cache behavior remain deterministic.
	answers := make([][]string, len(expDomains))
	queries := make([]int, 0, len(expDomains))
	for i, raw := range expDomains {
		d := strings.TrimSpace(raw)
		if d != "" && !awgIsCatchAll(d) && !isMaskEntry(d) {
			queries = append(queries, i)
		}
	}
	if len(queries) < 8 {
		for _, i := range queries {
			answers[i] = lookup(strings.TrimSpace(expDomains[i]))
		}
	} else {
		workers := len(queries)
		if workers > 32 {
			workers = 32
		}
		jobs := make(chan int)
		var wg sync.WaitGroup
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range jobs {
					answers[i] = lookup(strings.TrimSpace(expDomains[i]))
				}
			}()
		}
		for _, i := range queries {
			jobs <- i
		}
		close(jobs)
		wg.Wait()
	}
	for i, d := range expDomains {
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
		for _, ip := range answers[i] {
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
