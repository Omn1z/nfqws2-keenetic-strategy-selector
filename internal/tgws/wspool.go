package tgws

import (
	"context"
	"sync"
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
	dc    int
	media bool
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

	mu        sync.Mutex
	idle      map[poolKey][]pooledWS
	refilling map[poolKey]bool
}

const poolMaxAge = 120 * time.Second

func newWSPool(ctx context.Context, target, buffer int, stats *Stats) *wsPool {
	if target < 0 {
		target = 0
	}
	return &wsPool{
		ctx:       ctx,
		target:    target,
		buffer:    buffer,
		stats:     stats,
		idle:      map[poolKey][]pooledWS{},
		refilling: map[poolKey]bool{},
	}
}

// acquire returns a warm connection if one is available, else nil (the caller
// should connect fresh). Either way it kicks off a background refill.
func (p *wsPool) acquire(dc int, isMedia bool, targetIP string, domains []string) *rawWebSocket {
	key := poolKey{dc, isMedia}
	now := time.Now()

	p.mu.Lock()
	bucket := p.idle[key]
	for len(bucket) > 0 {
		head := bucket[0]
		bucket = bucket[1:]
		if now.Sub(head.created) > poolMaxAge || head.ws.isClosed() {
			go func(ws *rawWebSocket) { _ = ws.close() }(head.ws)
			continue
		}
		p.idle[key] = bucket
		p.mu.Unlock()
		p.stats.poolHits.Add(1)
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
			p.scheduleRefill(poolKey{dc, media}, ip, wsDomainsFor(dc, media))
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
	p.refilling = map[poolKey]bool{}
}

func (p *wsPool) scheduleRefill(key poolKey, targetIP string, domains []string) {
	p.mu.Lock()
	if p.target == 0 || p.refilling[key] {
		p.mu.Unlock()
		return
	}
	p.refilling[key] = true
	p.mu.Unlock()
	go p.refill(key, targetIP, domains)
}

func (p *wsPool) refill(key poolKey, targetIP string, domains []string) {
	defer func() {
		p.mu.Lock()
		p.refilling[key] = false
		p.mu.Unlock()
	}()
	if p.ctx.Err() != nil {
		return
	}
	p.mu.Lock()
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
	for _, ws := range results {
		if ws != nil {
			p.idle[key] = append(p.idle[key], pooledWS{ws: ws, created: time.Now()})
		}
	}
	p.mu.Unlock()
}

func (p *wsPool) connectOne(targetIP string, domains []string) *rawWebSocket {
	for _, domain := range domains {
		ws, err := connectWS(p.ctx, targetIP, domain, 8*time.Second, "/apiws", p.buffer)
		if err == nil {
			return ws
		}
		if hs, ok := err.(*wsHandshakeError); ok && hs.isRedirect() {
			continue
		}
		return nil
	}
	return nil
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
