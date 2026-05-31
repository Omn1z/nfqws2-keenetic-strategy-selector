package tgws

import (
	"math/rand"
	"sync"
)

// domainBalancer maps each DC to a "current" Cloudflare-proxied fallback
// domain, rotating on demand. Safe for concurrent use.
type domainBalancer struct {
	mu      sync.Mutex
	domains []string
	active  map[int]string
}

func newDomainBalancer() *domainBalancer {
	return &domainBalancer{active: map[int]string{}}
}

func (b *domainBalancer) updatePool(domains []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if sameSet(b.domains, domains) {
		return
	}
	b.domains = append([]string(nil), domains...)
	b.active = map[int]string{}
	if len(b.domains) > 0 {
		for _, dc := range dcIDs {
			b.active[dc] = b.domains[rand.Intn(len(b.domains))]
		}
	}
}

// promote pins domain as the preferred one for dc. Returns true if it changed.
func (b *domainBalancer) promote(dc int, domain string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.active[dc] == domain {
		return false
	}
	b.active[dc] = domain
	return true
}

// candidatesFor returns the active domain first, then the rest shuffled.
func (b *domainBalancer) candidatesFor(dc int) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	active := b.active[dc]
	out := make([]string, 0, len(b.domains))
	if active != "" {
		out = append(out, active)
	}
	rest := make([]string, 0, len(b.domains))
	for _, d := range b.domains {
		if d != active {
			rest = append(rest, d)
		}
	}
	rand.Shuffle(len(rest), func(i, j int) { rest[i], rest[j] = rest[j], rest[i] })
	return append(out, rest...)
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ca := map[string]int{}
	for _, x := range a {
		ca[x]++
	}
	for _, x := range b {
		ca[x]--
	}
	for _, v := range ca {
		if v != 0 {
			return false
		}
	}
	return true
}
