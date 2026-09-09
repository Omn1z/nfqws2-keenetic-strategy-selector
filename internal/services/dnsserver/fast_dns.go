package dnsserver

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"nfqws2strategy/internal/services/dnsroute"
)

const (
	fastDNSCapacity        = 256
	fastDNSWorkers         = 2
	fastDNSRefreshInterval = time.Hour
	fastDNSStaleInterval   = time.Hour
	fastDNSRetryInterval   = time.Minute
	fastDNSLookupTimeout   = 4 * time.Second
)

type FastDNSTarget struct {
	Route string
	Host  string
}

type FastDNSStatus struct {
	Enabled       bool   `json:"enabled"`
	Entries       int    `json:"entries"`
	Ready         int    `json:"ready"`
	Refreshing    int    `json:"refreshing"`
	LastRefreshAt string `json:"last_refresh_at,omitempty"`
	NextRefreshAt string `json:"next_refresh_at,omitempty"`
	LastError     string `json:"last_error,omitempty"`
}

type fastDNSFlight struct {
	done       chan struct{}
	ips        []string
	err        error
	foreground bool
	running    bool
	sequence   uint64
}

type fastDNSEntry struct {
	target      FastDNSTarget
	ips         []string
	refreshed   time.Time
	expires     time.Time
	staleUntil  time.Time
	retryAt     time.Time
	lastUsed    time.Time
	lastError   string
	refreshSoon bool
	flight      *fastDNSFlight
}

// FastDNSCache holds socket destinations only. The caller still uses the DoH
// hostname for HTTPS Host, SNI and certificate verification. Refreshes use the
// same route as the original lookup, and survive cancellation of one DNS race.
type FastDNSCache struct {
	mu          sync.Mutex
	entries     map[string]*fastDNSEntry
	lifetime    context.Context
	lookup      func(context.Context, string, string) ([]string, error)
	targets     func() []FastDNSTarget
	now         func() time.Time
	wake        chan struct{}
	workersOnce sync.Once
	startOnce   sync.Once
	sequence    uint64
}

func NewFastDNSCache(lifetime context.Context, lookup func(context.Context, string, string) ([]string, error), targets func() []FastDNSTarget) *FastDNSCache {
	return &FastDNSCache{entries: make(map[string]*fastDNSEntry), lifetime: lifetime, lookup: lookup, targets: targets, now: time.Now, wake: make(chan struct{}, fastDNSWorkers)}
}

// Start is called after the backend has prepared its routes. Only configured
// provider names are warmed; user query names are never sent to bootstrap DNS.
func (c *FastDNSCache) Start() {
	c.startWorkers()
	c.startOnce.Do(func() {
		go func() {
			c.maintain()
			ticker := time.NewTicker(fastDNSRetryInterval)
			defer ticker.Stop()
			for {
				select {
				case <-c.lifetime.Done():
					return
				case <-ticker.C:
					c.maintain()
				}
			}
		}()
	})
}

func (c *FastDNSCache) startWorkers() {
	c.workersOnce.Do(func() {
		for range fastDNSWorkers {
			go c.worker()
		}
	})
}

func fastDNSKey(route, host string) string {
	return route + "|" + strings.TrimSuffix(strings.ToLower(host), ".")
}

// Lookup returns warm addresses immediately. One shared refresh supplies all
// concurrent misses; a canceled waiter does not abort that refresh for others.
func (c *FastDNSCache) Lookup(ctx context.Context, route, host string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := c.lifetime.Err(); err != nil {
		return nil, err
	}
	c.startWorkers()
	c.mu.Lock()
	if err := c.lifetime.Err(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	now := c.now()
	e := c.entryLocked(FastDNSTarget{Route: route, Host: host}, true, now)
	if e == nil {
		c.mu.Unlock()
		return nil, fmt.Errorf("fast-dns: очередь bootstrap заполнена")
	}
	e.lastUsed = now
	if len(e.ips) > 0 && now.Before(e.expires) {
		ips := append([]string(nil), e.ips...)
		c.mu.Unlock()
		return ips, nil
	}
	usable := len(e.ips) > 0 && now.Before(e.staleUntil)
	if e.flight == nil && !now.Before(e.retryAt) {
		c.scheduleLocked(e, !usable)
	} else if e.flight != nil && !usable {
		// Foreground misses take precedence over the remaining warm-up queue.
		e.flight.foreground = true
	}
	if usable {
		ips := append([]string(nil), e.ips...)
		c.mu.Unlock()
		return ips, nil
	}
	flight := e.flight
	lastError := e.lastError
	c.mu.Unlock()
	if flight == nil {
		return nil, fmt.Errorf("fast-dns bootstrap %s: %s", host, lastError)
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.lifetime.Done():
		return nil, c.lifetime.Err()
	case <-flight.done:
		return append([]string(nil), flight.ips...), flight.err
	}
}

// RefreshSoon reacts to transport failures without discarding working IPs or
// causing a bootstrap storm. The last refresh/retry is always at least a minute
// apart; cancellation after another route wins must not call this method.
func (c *FastDNSCache) RefreshSoon(route, host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lifetime.Err() != nil {
		return
	}
	e := c.entries[fastDNSKey(route, host)]
	if e == nil || e.flight != nil {
		return
	}
	now := c.now()
	e.refreshSoon = true
	if now.Before(e.retryAt) || now.Before(e.refreshed.Add(fastDNSRetryInterval)) {
		return
	}
	c.scheduleLocked(e, false)
}

// entryLocked never evicts an active lookup or a waiting foreground request.
// A full background warm-up may yield a queued slot to an actual DNS request.
func (c *FastDNSCache) entryLocked(target FastDNSTarget, foreground bool, now time.Time) *fastDNSEntry {
	key := fastDNSKey(target.Route, target.Host)
	if e := c.entries[key]; e != nil {
		return e
	}
	if len(c.entries) >= fastDNSCapacity {
		if !foreground {
			return nil
		}
		oldestKey := ""
		var oldest *fastDNSEntry
		for candidateKey, candidate := range c.entries {
			if candidate.flight != nil && (candidate.flight.running || candidate.flight.foreground) {
				continue
			}
			if oldest == nil || candidate.lastUsed.Before(oldest.lastUsed) {
				oldestKey, oldest = candidateKey, candidate
			}
		}
		if oldest == nil {
			return nil
		}
		if oldest.flight != nil {
			oldest.flight.err = fmt.Errorf("fast-dns: фоновый bootstrap уступил место DNS-запросу")
			close(oldest.flight.done)
		}
		delete(c.entries, oldestKey)
	}
	target.Host = strings.TrimSuffix(strings.ToLower(target.Host), ".")
	e := &fastDNSEntry{target: target, lastUsed: now}
	c.entries[key] = e
	return e
}

func (c *FastDNSCache) scheduleLocked(e *fastDNSEntry, foreground bool) {
	if c.lifetime.Err() != nil || e.flight != nil {
		return
	}
	c.sequence++
	e.flight = &fastDNSFlight{done: make(chan struct{}), foreground: foreground, sequence: c.sequence}
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *FastDNSCache) maintain() {
	if c.lifetime.Err() != nil {
		return
	}
	var targets []FastDNSTarget
	if c.targets != nil {
		targets = c.targets()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lifetime.Err() != nil {
		return
	}
	now := c.now()
	// A full cache is not churned by periodic warm-up. Less common providers
	// outside the warm-up bound can still claim an LRU slot on demand.
	for i, target := range targets {
		if i == fastDNSCapacity {
			break
		}
		c.entryLocked(target, false, now)
	}
	for _, e := range c.entries {
		if e.flight == nil && (!now.Before(e.expires) || e.lastError != "" || e.refreshSoon) && !now.Before(e.retryAt) {
			c.scheduleLocked(e, false)
		}
	}
}

func (c *FastDNSCache) worker() {
	for {
		if c.lifetime.Err() != nil {
			return
		}
		c.mu.Lock()
		var entry *fastDNSEntry
		for _, e := range c.entries {
			if e.flight == nil || e.flight.running {
				continue
			}
			if entry == nil || e.flight.foreground && !entry.flight.foreground || e.flight.foreground == entry.flight.foreground && e.flight.sequence < entry.flight.sequence {
				entry = e
			}
		}
		if entry == nil {
			c.mu.Unlock()
			select {
			case <-c.lifetime.Done():
				return
			case <-c.wake:
				continue
			}
		}
		flight := entry.flight
		flight.running = true
		c.mu.Unlock()
		ctx, cancel := context.WithTimeout(c.lifetime, fastDNSLookupTimeout)
		ips, err := c.lookup(ctx, entry.target.Route, entry.target.Host)
		if err == nil {
			err = ctx.Err()
		}
		cancel()
		if err == nil {
			ips = validFastDNSIPs(ips)
			if len(ips) == 0 {
				err = fmt.Errorf("fast-dns bootstrap %s: нет IP-адресов", entry.target.Host)
			}
		}
		c.mu.Lock()
		if c.lifetime.Err() != nil {
			// Do not publish even a successful result after service shutdown.
			flight.err = c.lifetime.Err()
			close(flight.done)
			c.mu.Unlock()
			return
		}
		now := c.now()
		entry.flight = nil
		if err == nil {
			entry.ips = append([]string(nil), ips...)
			entry.refreshed = now
			entry.expires = now.Add(fastDNSRefreshInterval)
			entry.staleUntil = entry.expires.Add(fastDNSStaleInterval)
			entry.retryAt = now.Add(fastDNSRetryInterval)
			entry.lastError = ""
			entry.refreshSoon = false
			flight.ips = append([]string(nil), ips...)
		} else {
			entry.retryAt = now.Add(fastDNSRetryInterval)
			entry.lastError = err.Error()
			if len(entry.lastError) > 512 {
				entry.lastError = entry.lastError[:512]
				for !utf8.ValidString(entry.lastError) {
					entry.lastError = entry.lastError[:len(entry.lastError)-1]
				}
			}
			flight.err = err
		}
		close(flight.done)
		c.mu.Unlock()
	}
}

func validFastDNSIPs(ips []string) []string {
	result := make([]string, 0, 16)
	seen := make(map[string]bool, 16)
	for _, text := range ips {
		ip := net.ParseIP(text)
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || seen[ip.String()] {
			continue
		}
		result = append(result, ip.String())
		seen[ip.String()] = true
		if len(result) == 16 {
			break
		}
	}
	return result
}

func (c *FastDNSCache) Snapshot() FastDNSStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	status := FastDNSStatus{Entries: len(c.entries)}
	now := c.now()
	var latest, next, errorAt time.Time
	for _, e := range c.entries {
		if len(e.ips) > 0 && now.Before(e.staleUntil) {
			status.Ready++
		}
		if e.flight != nil {
			status.Refreshing++
		}
		if e.refreshed.After(latest) {
			latest = e.refreshed
		}
		refreshAt := e.expires
		if e.lastError != "" || e.refreshSoon || !now.Before(refreshAt) && e.retryAt.After(refreshAt) {
			refreshAt = e.retryAt
		}
		if !refreshAt.IsZero() && (next.IsZero() || refreshAt.Before(next)) {
			next = refreshAt
		}
		if e.lastError != "" && e.retryAt.After(errorAt) {
			status.LastError, errorAt = e.lastError, e.retryAt
		}
	}
	if !latest.IsZero() {
		status.LastRefreshAt = latest.UTC().Format(time.RFC3339Nano)
	}
	if !next.IsZero() {
		status.NextRefreshAt = next.UTC().Format(time.RFC3339Nano)
	}
	return status
}

func fastDNSTargets(cfg Config, routes []dnsroute.Route) []FastDNSTarget {
	eligible := eligibleRoutes(cfg, routes)
	targets := make([]FastDNSTarget, 0)
	seen := make(map[string]bool)
	add := func(upstream Upstream) bool {
		if len(upstream.BootstrapIPs) > 0 {
			return true
		}
		endpoint, err := url.Parse(upstream.Address)
		if err != nil || endpoint.Hostname() == "" || net.ParseIP(endpoint.Hostname()) != nil {
			return true
		}
		for _, route := range eligible {
			if !route.Available {
				continue
			}
			host := strings.TrimSuffix(strings.ToLower(endpoint.Hostname()), ".")
			key := fastDNSKey(route.ID, host)
			if !seen[key] {
				if len(targets) == fastDNSCapacity {
					return false
				}
				seen[key] = true
				targets = append(targets, FastDNSTarget{Route: route.ID, Host: host})
			}
		}
		return true
	}
	if !add(cfg.DefaultUpstream) {
		return targets
	}
	for _, upstream := range cfg.DefaultPool {
		if !add(upstream) {
			return targets
		}
	}
	for _, rule := range cfg.Rules {
		if !rule.Enabled {
			continue
		}
		if !add(rule.Upstream) {
			return targets
		}
		for _, upstream := range rule.Pool {
			if !add(upstream) {
				return targets
			}
		}
	}
	return targets
}
