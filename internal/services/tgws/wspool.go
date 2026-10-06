package tgws

import (
	"context"
	"log"
	"math/rand"
	"net/url"
	"sync"
	"sync/atomic"
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
	return []string{b}
}

type poolKey struct {
	dc       int
	media    bool
	test     bool
	targetIP string
}

type pooledWS struct {
	ws      *rawWebSocket
	created time.Time
}

// wsPool is an idle-keep-alive pool of warm WS connections with background
// refill, keyed by DC, media/test mode and destination.
type wsPool struct {
	ctx    context.Context
	target int
	buffer int
	stats  *Stats

	mu               sync.Mutex
	idle             map[poolKey][]pooledWS
	checking         map[*rawWebSocket]chan struct{}
	wake             chan struct{}
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
		checking:    map[*rawWebSocket]chan struct{}{},
		wake:        make(chan struct{}, 1),
		refilling:   map[poolKey]uint64{},
		domains:     map[poolKey][]string{},
		failures:    map[poolKey]int{},
		refillAfter: map[poolKey]time.Time{},
		dialSlots:   make(chan struct{}, poolDialConcurrency),
	}
	p.dial = func(ctx context.Context, host, domain string, timeout time.Duration, path string, bufferSize int, sni string) (*rawWebSocket, error) {
		return connectWSWithSNI(ctx, host, domain, timeout, path, bufferSize, sni, true)
	}
	p.frontingEnabled = len(fronting) > 0 && fronting[0]
	// Upstream resets this preference before starting each proxy instance.
	p.tryFrontingFirst.Store(false)
	if target > 0 {
		go p.maintain()
	}
	return p
}

// acquire never performs a foreground dial. A miss starts a background refill
// while the caller proceeds to its other transports.
func (p *wsPool) acquire(dc int, isMedia bool, targetIP string, domains []string, isTest ...bool) *rawWebSocket {
	if p.target == 0 || targetIP == "" || p.ctx.Err() != nil {
		return nil
	}
	key := poolKey{dc: dc, media: isMedia, test: len(isTest) > 0 && isTest[0], targetIP: targetIP}
	for {
		now := time.Now()
		p.mu.Lock()
		bucket := p.idle[key]
		var kept []pooledWS
		var waiting chan struct{}
		for len(bucket) > 0 {
			head := bucket[0]
			bucket = bucket[1:]
			if done := p.checking[head.ws]; done != nil {
				kept = append(kept, head)
				waiting = done
				continue
			}
			if now.Sub(head.created) >= poolMaxAge || !head.ws.idleHealthy() {
				go func(ws *rawWebSocket) { _ = ws.close() }(head.ws)
				continue
			}
			if len(kept) == 0 {
				p.idle[key] = bucket
			} else {
				p.idle[key] = append(kept, bucket...)
			}
			p.mu.Unlock()
			p.stats.poolHits.Add(1)
			p.scheduleRefill(key, targetIP, domains)
			return head.ws
		}
		p.idle[key] = kept
		p.mu.Unlock()
		if waiting != nil {
			// A background probe owns this idle socket for at most its short
			// read deadline. Do not hand it to a bridge while that read runs.
			select {
			case <-waiting:
				continue
			case <-p.ctx.Done():
				return nil
			}
		}
		p.stats.poolMisses.Add(1)
		p.scheduleRefill(key, targetIP, domains)
		return nil
	}
}

func (p *wsPool) warmup(dcToIP map[int]string, isTest ...bool) {
	for dc, ip := range dcToIP {
		if ip == "" {
			continue
		}
		for _, media := range []bool{false, true} {
			p.scheduleRefill(poolKey{dc: dc, media: media, test: len(isTest) > 0 && isTest[0], targetIP: ip}, ip, wsDomainsFor(dc, media))
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
	for _, done := range p.checking {
		close(done)
	}
	p.checking = map[*rawWebSocket]chan struct{}{}
	p.generation++
	p.refilling = map[poolKey]uint64{}
	p.domains = map[poolKey][]string{}
	p.failures = map[poolKey]int{}
	p.refillAfter = map[poolKey]time.Time{}
	p.tryFrontingFirst.Store(false)
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
		p.wakeMaintenance()
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

	path := wsPath
	if key.test {
		path = wsTestPath
	}
	type result struct {
		ws  *rawWebSocket
		err error
	}
	results := make(chan result, needed)
	for i := 0; i < needed; i++ {
		go func() {
			ws, err := p.connectOneResult(targetIP, domains, path)
			results <- result{ws, err}
		}()
	}
	connected := 0
	queueOnly := true
	for i := 0; i < needed; i++ {
		item := <-results
		if !isWSHandshakeQueueError(item.err) {
			queueOnly = false
		}
		if item.ws == nil {
			continue
		}
		p.mu.Lock()
		valid := p.ctx.Err() == nil && p.generation == generation
		if valid {
			// A slow sibling dial must not withhold an already warm socket.
			p.idle[key] = append(p.idle[key], pooledWS{ws: item.ws, created: time.Now()})
			connected++
		}
		p.mu.Unlock()
		if !valid {
			_ = item.ws.close()
		}
	}
	p.mu.Lock()
	if p.ctx.Err() != nil || p.generation != generation {
		p.mu.Unlock()
		return
	}
	if connected > 0 {
		delete(p.failures, key)
		delete(p.refillAfter, key)
	} else {
		delay := time.Second
		if !queueOnly {
			p.failures[key]++
			delay = poolRefillBackoff(p.failures[key])
		}
		p.refillAfter[key] = time.Now().Add(delay)
		if queueOnly {
			log.Printf("tgws: WS pool refill waiting for local setup capacity DC%d media=%t; retry in %s", key.dc, key.media, delay)
		} else {
			log.Printf("tgws: WS pool refill failed DC%d media=%t; retry in %s", key.dc, key.media, delay)
		}
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
	timer := time.NewTimer(poolCheckInterval)
	defer timer.Stop()
	for {
		select {
		case <-p.ctx.Done():
			p.reset()
			return
		case now := <-timer.C:
			p.rotate(now)
		case <-p.wake:
		}
		timer.Reset(p.maintenanceDelay(time.Now()))
	}
}

func (p *wsPool) wakeMaintenance() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

func (p *wsPool) maintenanceDelay(now time.Time) time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	delay := poolCheckInterval
	for key := range p.domains {
		for _, item := range p.idle[key] {
			delay = min(delay, max(time.Millisecond, item.created.Add(poolMaxAge).Sub(now)))
		}
		if _, running := p.refilling[key]; !running && len(p.idle[key]) < p.target {
			if after := p.refillAfter[key]; !after.IsZero() {
				delay = min(delay, max(time.Millisecond, after.Sub(now)))
			}
		}
	}
	return delay
}

func (p *wsPool) rotate(now time.Time) {
	p.mu.Lock()
	generation := p.generation
	type candidate struct {
		key  poolKey
		item pooledWS
	}
	var candidates []candidate
	for key := range p.domains {
		for _, item := range p.idle[key] {
			candidates = append(candidates, candidate{key, item})
		}
	}
	p.mu.Unlock()
	for _, candidate := range candidates {
		p.mu.Lock()
		if p.generation != generation || p.ctx.Err() != nil {
			p.mu.Unlock()
			return
		}
		present := false
		for _, item := range p.idle[candidate.key] {
			if item.ws == candidate.item.ws {
				present = true
				break
			}
		}
		if !present || p.checking[candidate.item.ws] != nil {
			p.mu.Unlock()
			continue
		}
		done := make(chan struct{})
		p.checking[candidate.item.ws] = done
		p.mu.Unlock()

		// Probe one socket at a time outside the pool mutex. acquire either
		// borrows another ready socket or waits only for this short probe.
		healthy := now.Sub(candidate.item.created) < poolMaxAge && candidate.item.ws.idleHealthy()
		p.mu.Lock()
		if p.checking[candidate.item.ws] == done {
			delete(p.checking, candidate.item.ws)
			if !healthy {
				bucket := p.idle[candidate.key]
				for i, item := range bucket {
					if item.ws == candidate.item.ws {
						copy(bucket[i:], bucket[i+1:])
						bucket[len(bucket)-1] = pooledWS{}
						p.idle[candidate.key] = bucket[:len(bucket)-1]
						break
					}
				}
			}
			close(done)
		}
		p.mu.Unlock()
		if !healthy {
			go candidate.item.ws.close()
		}
	}
	p.mu.Lock()
	targets := make(map[poolKey][]string, len(p.domains))
	for key, domains := range p.domains {
		if len(p.idle[key]) < p.target {
			targets[key] = append([]string(nil), domains...)
		}
	}
	p.mu.Unlock()
	for key, domains := range targets {
		p.scheduleRefill(key, key.targetIP, domains)
	}
}

func (p *wsPool) connectOne(targetIP string, domains []string) *rawWebSocket {
	ws, _ := p.connectOneResult(targetIP, domains)
	return ws
}

func (p *wsPool) connectOneResult(targetIP string, domains []string, paths ...string) (*rawWebSocket, error) {
	// Warm all configured DC/media buckets without starting their entire TLS
	// burst at once on a router. A slot covers both ordinary and fronted
	// attempts; ordinary client sessions only consume ready sockets.
	if p.ctx.Err() != nil {
		return nil, p.ctx.Err()
	}
	select {
	case p.dialSlots <- struct{}{}:
		defer func() { <-p.dialSlots }()
	case <-p.ctx.Done():
		return nil, p.ctx.Err()
	}
	// Cancellation can win simultaneously with an available slot.
	if p.ctx.Err() != nil {
		return nil, p.ctx.Err()
	}
	var lastFailure error
	path := wsPath
	if len(paths) > 0 {
		path = paths[0]
	}
	for index, domain := range domains {
		modes := []bool{false}
		if p.frontingEnabled {
			frontedFirst := p.tryFrontingFirst.Load()
			modes = []bool{frontedFirst, !frontedFirst}
		}
		for _, fronted := range modes {
			if err := p.ctx.Err(); err != nil {
				return nil, err
			}
			sni, timeout := domain, 8*time.Second
			if fronted {
				sni, timeout = frontingSNI, 7*time.Second
			}
			ws, err := p.dial(p.ctx, targetIP, domain, timeout, path, p.buffer, sni)
			if err == nil && ws != nil {
				p.tryFrontingFirst.Store(fronted)
				if fronted {
					p.stats.connectionsFronting.Add(1)
				}
				logAlternatePooledDomain(ws, index, targetIP, domains)
				return ws, nil
			}
			if isWSHandshakeQueueError(err) {
				if lastFailure != nil {
					return nil, lastFailure
				}
				return nil, err
			}
			if p.ctx.Err() != nil {
				return nil, p.ctx.Err()
			}
			p.stats.wsErrors.Add(1)
			lastFailure = err
		}
	}
	return nil, lastFailure
}

func logAlternatePooledDomain(ws *rawWebSocket, index int, targetIP string, domains []string) {
	if ws != nil && index > 0 {
		log.Printf("tgws: WS pool accepted alternate domain %s (preferred=%s, target=%s, sni=%s)",
			domains[index], domains[0], targetIP, censorDomains(ws.sni))
	}
}

func (p *wsPool) connectFronted(targetIP, domain string) *rawWebSocket {
	ws, _ := p.connectFrontedResult(targetIP, domain)
	return ws
}

func (p *wsPool) connectFrontedResult(targetIP, domain string) (*rawWebSocket, error) {
	if !p.frontingEnabled {
		return nil, nil
	}
	ws, err := p.dial(p.ctx, targetIP, domain, 7*time.Second, "/apiws", p.buffer, frontingSNI)
	if err != nil {
		return nil, err
	}
	p.stats.connectionsFronting.Add(1)
	p.tryFrontingFirst.Store(true)
	return ws, nil
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

func newCFWorkerPool(ctx context.Context, target, buffer int, stats *Stats, secureOpt ...bool) *cfWorkerPool {
	if target < 0 {
		target = 0
	}
	if target > 1 {
		target = 1
	}
	if stats == nil {
		stats = &Stats{}
	}
	secure := true
	if len(secureOpt) > 0 {
		secure = secureOpt[0]
	}
	p := &cfWorkerPool{ctx: ctx, target: target, buffer: buffer, stats: stats,
		idle: map[cfPoolKey][]pooledWorkerWS{}, refilling: map[cfPoolKey]uint64{}}
	p.dial = func(ctx context.Context, host, domain string, timeout time.Duration, path string, bufferSize int, sni string) (*rawWebSocket, error) {
		return connectWSWithSNI(ctx, host, domain, timeout, path, bufferSize, sni, secure)
	}
	return p
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
			if isWSHandshakeQueueError(err) {
				return
			}
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
