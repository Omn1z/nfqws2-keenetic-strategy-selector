package tgws

import (
	"context"
	"errors"
	"log"
	"math/rand"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// wsDomainsFor returns the native Telegram WS endpoints for a DC. The media
// variant is preferred for media connections.
func wsDomainsFor(dc int, isMedia bool) []string {
	if dc == 203 {
		dc = 2
	}
	a := "kws" + itoa(dc) + "-1.web.telegram.org"
	b := "kws" + itoa(dc) + ".web.telegram.org"
	if isMedia {
		return []string{a, b}
	}
	return []string{b, a}
}

type poolKey struct {
	dc       int
	media    bool
	targetIP string
}

type pooledWS struct {
	ws      *rawWebSocket
	created time.Time
}

// wsPool is an idle-keep-alive pool of warm WS connections with background
// refill, keyed by (DC, is_media).
type wsPool struct {
	ctx    context.Context
	target int
	buffer int
	stats  *Stats

	mu               sync.Mutex
	idle             map[poolKey][]pooledWS
	refilling        map[poolKey]uint64
	domains          map[poolKey][]string
	failures         map[poolKey]int
	refillAfter      map[poolKey]time.Time
	generation       uint64
	tryFrontingFirst atomic.Bool
	frontingEnabled  bool
	dial             wsDialFunc
	dialSlots        chan struct{}
}

const poolMaxAge = 120 * time.Second
const poolCheckInterval = 5 * time.Second
const poolDialConcurrency = 4
const frontingSNI = "sprinthost.ru"

type wsDialFunc func(context.Context, string, string, time.Duration, string, int, string) (*rawWebSocket, error)

// newWSPool keeps SNI fronting opt-in on Keenetic: some upstream fronts return
// HTTP 101 but then fail to carry the requested DC's MTProto stream.
// An omitted option is disabled; callers enabling the upstream strategy must
// pass true explicitly before any background warmup starts.
func newWSPool(ctx context.Context, target, buffer int, stats *Stats, fronting ...bool) *wsPool {
	if target < 0 {
		target = 0
	}
	if stats == nil {
		stats = &Stats{}
	}
	p := &wsPool{
		ctx:         ctx,
		target:      target,
		buffer:      buffer,
		stats:       stats,
		idle:        map[poolKey][]pooledWS{},
		refilling:   map[poolKey]uint64{},
		domains:     map[poolKey][]string{},
		failures:    map[poolKey]int{},
		refillAfter: map[poolKey]time.Time{},
		dial:        connectWSWithSNI,
		dialSlots:   make(chan struct{}, poolDialConcurrency),
	}
	p.frontingEnabled = len(fronting) > 0 && fronting[0]
	// Upstream resets this preference before starting each proxy instance.
	p.tryFrontingFirst.Store(false)
	if target > 0 {
		go p.maintain()
	}
	return p
}

// acquire returns a warm connection if one is available, else nil (the caller
// should connect fresh). Either way it kicks off a background refill.
func (p *wsPool) acquire(dc int, isMedia bool, targetIP string, domains []string) *rawWebSocket {
	key := poolKey{dc, isMedia, targetIP}
	now := time.Now()

	p.mu.Lock()
	bucket := p.idle[key]
	for len(bucket) > 0 {
		head := bucket[0]
		bucket = bucket[1:]
		if now.Sub(head.created) >= poolMaxAge || !head.ws.idleHealthy() {
			go func(ws *rawWebSocket) { _ = ws.close() }(head.ws)
			continue
		}
		p.idle[key] = bucket
		p.mu.Unlock()
		p.stats.poolHits.Add(1)
		p.reportSuccess(dc, isMedia)
		p.scheduleRefill(key, targetIP, domains)
		return head.ws
	}
	p.idle[key] = bucket
	p.mu.Unlock()

	p.stats.poolMisses.Add(1)
	p.scheduleRefill(key, targetIP, domains)
	return nil
}

func (p *wsPool) warmup(dcToIP map[int]string) {
	for dc, ip := range dcToIP {
		if ip == "" {
			continue
		}
		for _, media := range []bool{false, true} {
			p.scheduleRefill(poolKey{dc, media, ip}, ip, wsDomainsFor(dc, media))
		}
	}
}

func (p *wsPool) reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, bucket := range p.idle {
		for _, pw := range bucket {
			go func(ws *rawWebSocket) { _ = ws.close() }(pw.ws)
		}
	}
	p.idle = map[poolKey][]pooledWS{}
	p.generation++
	p.refilling = map[poolKey]uint64{}
	p.domains = map[poolKey][]string{}
	p.failures = map[poolKey]int{}
	p.refillAfter = map[poolKey]time.Time{}
	p.tryFrontingFirst.Store(false)
}

func (p *wsPool) reportSuccess(dc int, isMedia bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for key := range p.failures {
		if key.dc == dc && key.media == isMedia {
			delete(p.failures, key)
			delete(p.refillAfter, key)
		}
	}
}

func (p *wsPool) scheduleRefill(key poolKey, targetIP string, domains []string) {
	p.mu.Lock()
	if p.target == 0 || p.ctx.Err() != nil {
		p.mu.Unlock()
		return
	}
	p.domains[key] = append([]string(nil), domains...)
	_, running := p.refilling[key]
	if running || time.Now().Before(p.refillAfter[key]) {
		p.mu.Unlock()
		return
	}
	generation := p.generation
	p.refilling[key] = generation
	p.mu.Unlock()
	go p.refill(key, targetIP, append([]string(nil), domains...), generation)
}

func (p *wsPool) refill(key poolKey, targetIP string, domains []string, generation uint64) {
	defer func() {
		p.mu.Lock()
		if current, ok := p.refilling[key]; ok && current == generation {
			delete(p.refilling, key)
		}
		p.mu.Unlock()
	}()
	if p.ctx.Err() != nil {
		return
	}
	p.mu.Lock()
	if p.generation != generation {
		p.mu.Unlock()
		return
	}
	needed := p.target - len(p.idle[key])
	p.mu.Unlock()
	if needed <= 0 {
		return
	}

	var wg sync.WaitGroup
	results := make([]*rawWebSocket, needed)
	for i := 0; i < needed; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = p.connectOne(targetIP, domains)
		}(i)
	}
	wg.Wait()

	p.mu.Lock()
	if p.ctx.Err() != nil || p.generation != generation {
		p.mu.Unlock()
		for _, ws := range results {
			if ws != nil {
				_ = ws.close()
			}
		}
		return
	}
	connected := 0
	for _, ws := range results {
		if ws != nil {
			p.idle[key] = append(p.idle[key], pooledWS{ws: ws, created: time.Now()})
			connected++
		}
	}
	if connected > 0 {
		delete(p.failures, key)
		delete(p.refillAfter, key)
	} else {
		p.failures[key]++
		delay := poolRefillBackoff(p.failures[key])
		p.refillAfter[key] = time.Now().Add(delay)
		log.Printf("tgws: WS pool refill failed DC%d media=%t; retry in %s", key.dc, key.media, delay)
	}
	p.mu.Unlock()
}

func poolRefillBackoff(failures int) time.Duration {
	shift := failures - 1
	if shift < 0 {
		shift = 0
	}
	if shift > 12 {
		shift = 12
	}
	delay := time.Second * time.Duration(1<<shift)
	if delay > time.Hour {
		return time.Hour
	}
	return delay
}

// Keep ready sockets fresh even when no clients consume them. Failed and
// partially successful refills are retried with a bounded backoff.
func (p *wsPool) maintain() {
	ticker := time.NewTicker(poolCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			p.reset()
			return
		case now := <-ticker.C:
			p.rotate(now)
		}
	}
}

func (p *wsPool) rotate(now time.Time) {
	p.mu.Lock()
	targets := make(map[poolKey][]string, len(p.domains))
	var expired []*rawWebSocket
	for key, domains := range p.domains {
		bucket := p.idle[key]
		ready := bucket[:0]
		for _, item := range bucket {
			if now.Sub(item.created) >= poolMaxAge || item.ws.isClosed() {
				expired = append(expired, item.ws)
			} else {
				ready = append(ready, item)
			}
		}
		p.idle[key] = ready
		if len(ready) < p.target {
			targets[key] = append([]string(nil), domains...)
		}
	}
	p.mu.Unlock()
	for _, ws := range expired {
		go ws.close()
	}
	for key, domains := range targets {
		p.scheduleRefill(key, key.targetIP, domains)
	}
}

func (p *wsPool) connectOne(targetIP string, domains []string) *rawWebSocket {
	// Warm all configured DC/media buckets without starting their entire TLS
	// burst at once on a router. A slot covers both ordinary and fronted
	// attempts; foreground client dials do not enter this background queue.
	if p.ctx.Err() != nil {
		return nil
	}
	select {
	case p.dialSlots <- struct{}{}:
		defer func() { <-p.dialSlots }()
	case <-p.ctx.Done():
		return nil
	}
	// Cancellation can win simultaneously with an available slot.
	if p.ctx.Err() != nil {
		return nil
	}
	for index, domain := range domains {
		frontedFirst := p.frontingEnabled && p.tryFrontingFirst.Load()
		if frontedFirst {
			if ws := p.connectFronted(targetIP, domain); ws != nil {
				logAlternatePooledDomain(ws, index, targetIP, domains)
				return ws
			}
		}
		ws, err := p.dial(p.ctx, targetIP, domain, 8*time.Second, "/apiws", p.buffer, domain)
		if err == nil {
			p.tryFrontingFirst.Store(false)
			logAlternatePooledDomain(ws, index, targetIP, domains)
			return ws
		}
		if hs, ok := err.(*wsHandshakeError); ok && hs.isRedirect() {
			continue
		}
		if p.frontingEnabled && !frontedFirst && shouldTryFronting(err) {
			ws := p.connectFronted(targetIP, domain)
			logAlternatePooledDomain(ws, index, targetIP, domains)
			return ws
		}
		return nil
	}
	return nil
}

func logAlternatePooledDomain(ws *rawWebSocket, index int, targetIP string, domains []string) {
	if ws != nil && index > 0 {
		log.Printf("tgws: WS pool accepted alternate domain %s (preferred=%s, target=%s, sni=%s)",
			domains[index], domains[0], targetIP, censorDomains(ws.sni))
	}
}

func shouldTryFronting(err error) bool {
	var ne net.Error
	// Match upstream's timeout/reset-only fallback. An EOF from the ordinary
	// endpoint must not populate the pool with a fronted HTTP 101 connection
	// that cannot actually carry this DC's MTProto stream.
	return (errors.As(err, &ne) && ne.Timeout()) || errors.Is(err, syscall.ECONNRESET)
}

func (p *wsPool) connectFronted(targetIP, domain string) *rawWebSocket {
	if !p.frontingEnabled {
		return nil
	}
	ws, err := p.dial(p.ctx, targetIP, domain, 7*time.Second, "/apiws", p.buffer, frontingSNI)
	if err != nil {
		return nil
	}
	p.stats.connectionsFronting.Add(1)
	p.tryFrontingFirst.Store(true)
	return ws
}

type cfPoolKey struct {
	dc       int
	targetIP string
}
type pooledWorkerWS struct {
	pooledWS
	domain string
}

// Workers carry a raw TCP stream and can be shared by media/non-media clients.
// Limit warm sockets to one per DC so a router does not exhaust worker quotas.
type cfWorkerPool struct {
	ctx            context.Context
	target, buffer int
	stats          *Stats
	mu             sync.Mutex
	idle           map[cfPoolKey][]pooledWorkerWS
	refilling      map[cfPoolKey]uint64
	generation     uint64
	dial           wsDialFunc
}

func newCFWorkerPool(ctx context.Context, target, buffer int, stats *Stats) *cfWorkerPool {
	if target < 0 {
		target = 0
	}
	if target > 1 {
		target = 1
	}
	if stats == nil {
		stats = &Stats{}
	}
	return &cfWorkerPool{ctx: ctx, target: target, buffer: buffer, stats: stats,
		idle: map[cfPoolKey][]pooledWorkerWS{}, refilling: map[cfPoolKey]uint64{}, dial: connectWSWithSNI}
}

func (p *cfWorkerPool) acquire(dc int, targetIP string, domains []string) (*rawWebSocket, string) {
	key := cfPoolKey{dc, targetIP}
	now := time.Now()
	p.mu.Lock()
	bucket := p.idle[key]
	for len(bucket) > 0 {
		head := bucket[0]
		bucket = bucket[1:]
		allowed := false
		for _, domain := range domains {
			if domain == head.domain {
				allowed = true
				break
			}
		}
		if !allowed || now.Sub(head.created) >= 100*time.Second || !head.ws.idleHealthy() {
			go head.ws.close()
			continue
		}
		p.idle[key] = bucket
		p.mu.Unlock()
		p.stats.cfPoolHits.Add(1)
		p.scheduleRefill(key, domains)
		return head.ws, head.domain
	}
	p.idle[key] = bucket
	p.mu.Unlock()
	p.stats.cfPoolMisses.Add(1)
	return nil, ""
}

func (p *cfWorkerPool) warmup(dcToIP map[int]string, domains []string) {
	for dc, ip := range dcToIP {
		if ip != "" {
			p.scheduleRefill(cfPoolKey{dc, ip}, domains)
		}
	}
}

func (p *cfWorkerPool) scheduleRefill(key cfPoolKey, domains []string) {
	p.mu.Lock()
	_, running := p.refilling[key]
	if p.target == 0 || running || p.ctx.Err() != nil {
		p.mu.Unlock()
		return
	}
	generation := p.generation
	p.refilling[key] = generation
	p.mu.Unlock()
	go p.refill(key, append([]string(nil), domains...), generation)
}

func (p *cfWorkerPool) refill(key cfPoolKey, domains []string, generation uint64) {
	defer func() {
		p.mu.Lock()
		if current, ok := p.refilling[key]; ok && current == generation {
			delete(p.refilling, key)
		}
		p.mu.Unlock()
	}()
	p.mu.Lock()
	needed := p.target - len(p.idle[key])
	valid := generation == p.generation && p.ctx.Err() == nil
	p.mu.Unlock()
	if needed <= 0 || !valid {
		return
	}
	for _, domain := range p.availableDomains(domains) {
		ws, err := p.dial(p.ctx, domain, domain, 8*time.Second, cfWorkerPath(key.dc, key.targetIP), p.buffer, domain)
		if err != nil {
			p.reportFailure(domain, err)
			continue
		}
		p.mu.Lock()
		if p.ctx.Err() != nil || p.generation != generation {
			p.mu.Unlock()
			_ = ws.close()
			return
		}
		p.idle[key] = append(p.idle[key], pooledWorkerWS{pooledWS: pooledWS{ws: ws, created: time.Now()}, domain: domain})
		p.mu.Unlock()
		return
	}
}

func cfWorkerPath(dc int, targetIP string) string {
	return "/apiws?" + url.Values{"dst": {targetIP}, "dc": {itoa(dc)}}.Encode()
}

func (p *cfWorkerPool) availableDomains(domains []string) []string {
	seen := make(map[string]bool, len(domains))
	unique := make([]string, 0, len(domains))
	for _, domain := range domains {
		if domain != "" && !seen[domain] {
			unique = append(unique, domain)
			seen[domain] = true
		}
	}
	rand.Shuffle(len(unique), func(i, j int) { unique[i], unique[j] = unique[j], unique[i] })
	return unique
}

// Upstream intentionally does not disable workers on HTTP 429: the status
// returned for exhausted daily quotas has not been established yet.
func (p *cfWorkerPool) reportFailure(_ string, _ error) {}

func (p *cfWorkerPool) reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, bucket := range p.idle {
		for _, item := range bucket {
			go item.ws.close()
		}
	}
	p.generation++
	p.idle = map[cfPoolKey][]pooledWorkerWS{}
	p.refilling = map[cfPoolKey]uint64{}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
