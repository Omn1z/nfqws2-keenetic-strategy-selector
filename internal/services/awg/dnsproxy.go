package awg

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var errDNSQueryShort = errors.New("DNS query shorter than 12-byte header")

// DNSProxy is a transparent DNS interceptor for split-routing by domain mask.
// It relays each query VERBATIM to an upstream resolver and, for every answer
// whose QUERIED NAME matches one of the active matchers, calls onMatch(ip) for
// each A/AAAA address found (the caller adds them to the routing ipset). It never
// rewrites DNS messages — it only reads the question name and the answer IPs — so
// clients are unaffected. Intended to sit behind an iptables REDIRECT of LAN :53.
// The raw-message parsing helpers live in dnswire.go.
type DNSProxy struct {
	addr     string
	upstream string // resolver to forward to (fixed at NewDNSProxy time)
	// onMatch is called ONCE per matched DNS response, with the qname and the
	// full list of A/AAAA IPs the answer contained (2-8 typical for big
	// CDNs). The per-IP work — ipset add, family bookkeeping — happens
	// inside the callback; the per-NAME decision (FMW route + source-zone
	// match) is computed once at the top, not 2-8x per query.
	onMatch func(name string, ips []string)
	// onQuery, if set, is invoked once per successfully forwarded DNS query with
	// the client IP, qname, qtype mnemonic ("A"/"AAAA"/raw uint), the resolved
	// IPs, and whether the response was sinkholed. The route layer uses it for
	// trace rows and source-aware DNS learning before the response returns.
	onQuery func(srcIP, qname, qtype string, ips []string, sinkholed bool)
	// onBlock, if set, is invoked when maybeBlockAAAA synthesizes an empty NOERROR
	// response for a matched AAAA query — so trace can show "AAAA blocked, fallback to v4".
	onBlock  func(srcIP, qname string)
	matchers atomic.Pointer[MatcherSet]
	// aaaaBlocker, if set, decides per query whether to strip AAAA. Overrides
	// the legacy matchers.MatchAny fallback in maybeBlockAAAA. Used by the AWG
	// route layer to apply first-match-wins semantics: only strip AAAA when
	// the FIRST matching rule wants the name tunneled AND the tunnel can't
	// carry v6. Returns true → block; false → let the AAAA flow through.
	// srcIP is the LAN client whose AAAA we're considering — source-bound zones
	// need it to evaluate per-device.
	aaaaBlocker atomic.Pointer[func(srcIP, name string) bool]

	mu      sync.Mutex
	udp     *net.UDPConn
	tcp     net.Listener
	stop    chan struct{}
	running bool

	rmu    sync.Mutex
	recent map[string][]string // recently-seen qname → answer IPs, for re-matching on a mask change

	// bufPool reuses ~1500-byte buffers across DNS reads/writes. With ~50 QPS the
	// previous per-query `make([]byte, 1500)` produced ~70 KB/s allocation pressure
	// — small per second, but it amortizes to MB of GC work per hour on the router.
	bufPool sync.Pool
	// upstreamPool keeps connected UDP sockets to the upstream resolver alive
	// across queries instead of re-dialing per call. net.DialUDP isn't free on
	// ARM64 (socket alloc + netlink + descriptor table), and the previous
	// dial-write-read-close cycle cost the kernel ~200 µs per query.
	upstreamPool sync.Pool
}

// recentCap bounds the recently-seen-name cache (reset wholesale on overflow).
const recentCap = 4096

// NewDNSProxy creates a proxy listening on addr (e.g. 127.0.0.1:5354) that
// forwards to upstream (e.g. 127.0.0.1:53). onMatch fires ONCE per matched
// response with the qname and all answer IPs together (not once per IP), so
// the consumer only computes its per-name decision once per query.
func NewDNSProxy(addr, upstream string, onMatch func(name string, ips []string)) *DNSProxy {
	p := &DNSProxy{addr: addr, upstream: upstream, onMatch: onMatch}
	empty := MatcherSet{Trie: newSuffixTrie()}
	p.matchers.Store(&empty)
	// *[]byte (sync.Pool best practice — avoids the heap copy on each round-trip).
	// 1500 covers EDNS0's 1232-byte default plus any plain UDP resolver.
	p.bufPool.New = func() interface{} { b := make([]byte, 1500); return &b }
	return p
}

// getUpstreamConn acquires a connected UDP socket to the upstream resolver.
// Returns nil on dial failure.
func (p *DNSProxy) getUpstreamConn() (*net.UDPConn, error) {
	if p.upstream == "" {
		return nil, net.ErrClosed
	}
	if v := p.upstreamPool.Get(); v != nil {
		return v.(*net.UDPConn), nil
	}
	raddr, err := net.ResolveUDPAddr("udp", p.upstream)
	if err != nil {
		return nil, err
	}
	return net.DialUDP("udp", nil, raddr)
}

// putUpstreamConn returns a healthy conn to the pool. Errored conns should be
// closed by the caller, never returned (their socket buffer may be misaligned
// with a future response).
func (p *DNSProxy) putUpstreamConn(c *net.UDPConn) {
	if c == nil {
		return
	}
	// Clear any deadline before stashing so the next user inherits the default.
	_ = c.SetDeadline(time.Time{})
	p.upstreamPool.Put(c)
}

// SetOnQuery wires the trace callback for "one query completed" events.
// Pass nil to disable.
//
// `sinkholed` is true when isSinkholeResponse() classified the upstream reply
// as a Pi-hole / ad-blocker null-answer (NXDOMAIN, empty NOERROR, or
// 0.0.0.0/:: only). The awgroute trace closure uses it to label such rows
// "blocked" rather than the misleading FMW routing decision that would have
// applied to a real answer.
//
// The legacy 5th `matched bool` parameter (now repurposed for `sinkholed`)
// previously cost one atomic.Load + full MatcherSet walk per query for a
// value nobody read; the new flag is a 2-instruction header check.
func (p *DNSProxy) SetOnQuery(cb func(srcIP, qname, qtype string, ips []string, sinkholed bool)) {
	p.onQuery = cb
}

// SetOnBlock wires the trace callback for "AAAA blocked" events. Pass nil to disable.
func (p *DNSProxy) SetOnBlock(cb func(srcIP, qname string)) {
	p.onBlock = cb
}

// SetAAAABlocker installs a per-query AAAA-block decider. When set, it
// overrides the legacy "any matcher matches → block" rule in maybeBlockAAAA.
// Pass nil to fall back to the legacy behaviour.
func (p *DNSProxy) SetAAAABlocker(fn func(srcIP, name string) bool) {
	if fn == nil {
		p.aaaaBlocker.Store(nil)
		return
	}
	p.aaaaBlocker.Store(&fn)
}

// SetMatchers atomically swaps the active matcher set and re-checks recently-seen
// names against the NEW matchers, calling onMatch for matches. This makes a mask
// edit apply to domains the device already resolved (its DNS cache won't re-query
// them for a while) — the same "immediate" behaviour an explicit domain gets from
// server-side resolution. Runs async so it never blocks the apply path.
func (p *DNSProxy) SetMatchers(ms *MatcherSet) {
	if ms == nil {
		empty := MatcherSet{Trie: newSuffixTrie()}
		ms = &empty
	}
	p.matchers.Store(ms)
	if p.onMatch == nil {
		return
	}
	p.rmu.Lock()
	snapshot := make(map[string][]string, len(p.recent))
	for k, v := range p.recent {
		snapshot[k] = v
	}
	p.rmu.Unlock()
	if len(snapshot) == 0 {
		return
	}
	go func() {
		for name, ips := range snapshot {
			if ms.MatchAny(name) {
				p.onMatch(name, ips)
			}
		}
	}()
}

// remember stores a recently-seen name→IPs so a later mask change can pick it up
// without waiting for the device to re-query.
func (p *DNSProxy) remember(name string, ips []string) {
	p.rmu.Lock()
	if p.recent == nil || len(p.recent) >= recentCap {
		p.recent = make(map[string][]string, 256)
	}
	p.recent[name] = ips
	p.rmu.Unlock()
}

// SnapshotRecent returns a copy of the recently-seen name→IPs cache, so the caller
// can persist it to disk and the masks survive a panel restart / reboot.
func (p *DNSProxy) SnapshotRecent() map[string][]string {
	p.rmu.Lock()
	defer p.rmu.Unlock()
	out := make(map[string][]string, len(p.recent))
	for k, v := range p.recent {
		out[k] = v
	}
	return out
}

// LoadRecent merges a persisted name→IPs cache into the recent set (called on
// start, before SetMatchers, so a mask immediately re-applies to domains seen in a
// previous run without waiting for the device to look them up again).
func (p *DNSProxy) LoadRecent(m map[string][]string) {
	p.rmu.Lock()
	defer p.rmu.Unlock()
	if p.recent == nil {
		p.recent = make(map[string][]string, len(m)+16)
	}
	for k, v := range m {
		if len(p.recent) >= recentCap {
			break
		}
		p.recent[k] = v
	}
}

// Start binds the UDP + TCP listeners and serves until Stop. Idempotent.
func (p *DNSProxy) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running {
		return nil
	}
	ua, err := net.ResolveUDPAddr("udp", p.addr)
	if err != nil {
		return err
	}
	uc, err := net.ListenUDP("udp", ua)
	if err != nil {
		return err
	}
	tl, err := net.Listen("tcp", p.addr)
	if err != nil {
		uc.Close()
		return err
	}
	p.udp, p.tcp, p.stop, p.running = uc, tl, make(chan struct{}), true
	go p.serveUDP(uc)
	go p.serveTCP(tl)
	return nil
}

// Stop closes the listeners. Idempotent.
func (p *DNSProxy) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.running {
		return
	}
	p.running = false
	close(p.stop)
	if p.udp != nil {
		p.udp.Close()
	}
	if p.tcp != nil {
		p.tcp.Close()
	}
}

func (p *DNSProxy) Running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.running
}

func (p *DNSProxy) serveUDP(uc *net.UDPConn) {
	for {
		// Borrow a buffer from the pool. handleUDP is responsible for putting it
		// back — we hand off ownership via the goroutine spawn below.
		bp := p.bufPool.Get().(*[]byte)
		b := *bp
		n, client, err := uc.ReadFromUDP(b)
		if err != nil {
			p.bufPool.Put(bp)
			return // listener closed
		}
		go p.handleUDP(uc, client, bp, n)
	}
}

func (p *DNSProxy) handleUDP(uc *net.UDPConn, client *net.UDPAddr, bp *[]byte, n int) {
	defer p.bufPool.Put(bp)
	query := (*bp)[:n]
	srcIP := ""
	if client != nil && client.IP != nil {
		srcIP = client.IP.String()
	}
	// EDNS Client Subnet wins over the socket peer — pi-hole sits between LAN
	// and us, so without ECS the trace would show every query as 127.0.0.1.
	if ecs, ok := parseECSFromQuery(query); ok {
		srcIP = ecs
	}
	// Parse the DNS question ONCE here and thread it down. Previously the same
	// label-walk happened in maybeBlockAAAA, inspect, traceQuery, and the
	// onBlock branch — 2-4× redundant per query at ~50 QPS on a busy LAN.
	qname, qtype, qok := questionInfo(query)
	if blk, ok := p.maybeBlockAAAAParsed(srcIP, query, qname, qtype, qok); ok {
		_, _ = uc.WriteToUDP(blk, client)
		if p.onBlock != nil && qname != "" {
			p.onBlock(srcIP, qname)
		}
		return
	}
	respBP := p.bufPool.Get().(*[]byte)
	defer p.bufPool.Put(respBP)
	respBuf := *respBP
	respN, err := p.forwardUDPInto(query, respBuf)
	if err != nil || respN == 0 {
		return
	}
	resp := respBuf[:respN]
	p.inspectParsed(qname, qok, resp)
	p.traceQueryParsed(srcIP, qname, qtype, qok, resp)
	_, _ = uc.WriteToUDP(resp, client)
}

// traceQueryParsed is the parse-once variant: handleUDP/handleTCP parse the
// DNS question once at entry and pass the result down. The callback (in
// awgroute) computes its own routing decision via routeFor; we just feed it
// the answer IPs and a sinkhole flag so it can label Pi-hole-blocked rows
// "blocked" instead of "tunnel"/"direct".
func (p *DNSProxy) traceQueryParsed(srcIP, qname string, qtype uint16, qok bool, resp []byte) {
	if p.onQuery == nil || !qok || qname == "" {
		return
	}
	p.onQuery(srcIP, qname, dnsQTypeStr(qtype), answerIPs(resp), isSinkholeResponse(resp))
}

// dnsQTypeStr is a tiny mnemonic decoder for the trace log. Anything outside
// the handful of types we care about is rendered as the numeric code.
func dnsQTypeStr(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 28:
		return "AAAA"
	case 5:
		return "CNAME"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 33:
		return "SRV"
	case 65:
		return "HTTPS"
	}
	return ""
}

// forwardUDPInto sends a DNS query to the upstream resolver and reads the
// response into respBuf. Returns the number of bytes read. Uses a pooled
// connected UDP socket so the common case is zero alloc / zero syscall fork.
// On any I/O error the conn is dropped (not returned to the pool) — the next
// query dials fresh.
//
// Validates the response txid (and best-effort qname) against the query before
// returning: a pooled connected UDP socket can have a buffered duplicate /
// retransmit from a prior query queued on it; without validation we'd hand that
// stale answer to the wrong caller (different qname → IPs land in the wrong
// ipset). On txid mismatch we drain and retry until the per-query deadline
// expires; on read error or deadline we close+drop the conn.
func (p *DNSProxy) forwardUDPInto(query, respBuf []byte) (int, error) {
	if len(query) < 12 {
		return 0, errDNSQueryShort
	}
	qtxid := uint16(query[0])<<8 | uint16(query[1])
	qname, _, _ := questionInfo(query)

	u, err := p.getUpstreamConn()
	if err != nil {
		return 0, err
	}
	deadline := time.Now().Add(4 * time.Second)
	_ = u.SetDeadline(deadline)
	if _, err := u.Write(query); err != nil {
		_ = u.Close()
		return 0, err
	}
	for {
		n, err := u.Read(respBuf)
		if err != nil {
			_ = u.Close()
			return 0, err
		}
		if n < 12 {
			continue // zero-byte/junk datagram (#10): keep reading until deadline
		}
		rtxid := uint16(respBuf[0])<<8 | uint16(respBuf[1])
		if rtxid != qtxid {
			continue // stale dup from a previous pooled query (#9)
		}
		// qname check is best-effort: some upstreams normalize case or trim
		// trailing dots — only reject when both ends produced a real name.
		if qname != "" {
			if rname, _, ok := questionInfo(respBuf[:n]); ok && rname != "" && rname != qname {
				continue
			}
		}
		p.putUpstreamConn(u)
		return n, nil
	}
}

func (p *DNSProxy) serveTCP(tl net.Listener) {
	for {
		conn, err := tl.Accept()
		if err != nil {
			return
		}
		go p.handleTCP(conn)
	}
}

func (p *DNSProxy) handleTCP(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
	query, err := readTCPMsg(conn)
	if err != nil {
		return
	}
	srcIP := ""
	if a, ok := conn.RemoteAddr().(*net.TCPAddr); ok && a != nil && a.IP != nil {
		srcIP = a.IP.String()
	}
	if ecs, ok := parseECSFromQuery(query); ok {
		srcIP = ecs
	}
	qname, qtype, qok := questionInfo(query)
	if blk, ok := p.maybeBlockAAAAParsed(srcIP, query, qname, qtype, qok); ok {
		_ = writeTCPMsg(conn, blk)
		if p.onBlock != nil && qname != "" {
			p.onBlock(srcIP, qname)
		}
		return
	}
	// Upstream over UDP even though the inbound is TCP — the only path on this
	// router that wires our upstream is native dnsmasq on 127.0.0.1:53, which
	// accepts UDP fine but silently drops TCP queries (OpenWrt build flag).
	// Forwarding via TCP would dial, read 0 bytes, and pi-hole would log
	// "Connection prematurely closed" on every cache-miss large enough to fall
	// back to TCP. UDP→TCP wrap covers >99% of responses; oversized payloads
	// (>1232B with EDNS0) get the upstream's TC flag preserved, telling the
	// client to retry — same behaviour pi-hole gets from any plain UDP upstream.
	bp := p.bufPool.Get().(*[]byte)
	respBuf := *bp
	n, err := p.forwardUDPInto(query, respBuf)
	if err != nil || n == 0 {
		p.bufPool.Put(bp)
		return
	}
	// Copy out before returning the pooled buffer — writeTCPMsg keeps the
	// slice across the conn write and a concurrent query could clobber it.
	out := make([]byte, n)
	copy(out, respBuf[:n])
	p.bufPool.Put(bp)
	p.inspectParsed(qname, qok, out)
	p.traceQueryParsed(srcIP, qname, qtype, qok, out)
	_ = writeTCPMsg(conn, out)
}

// inspect reads the question name from the query and, if it matches, adds every
// A/AAAA IP from the response via onMatch. Read-only; never mutates the messages.
// inspectParsed is the parse-once variant: handleUDP/handleTCP parse the
// question once and pass name + ok down. Same logic as the legacy inspect.
func (p *DNSProxy) inspectParsed(name string, ok bool, resp []byte) {
	if !ok || name == "" {
		return
	}
	ips := answerIPs(resp)
	if len(ips) > 0 {
		p.remember(name, ips)
	}
	ms := p.matchers.Load()
	if ms == nil || !ms.MatchAny(name) {
		return
	}
	if p.onMatch != nil {
		p.onMatch(name, ips)
	}
}

// maybeBlockAAAA: if the query is an AAAA (IPv6) lookup that the configured
// blocker (or legacy fallback) says to strip, return a synthesized empty
// NOERROR response (blocked=true) so the client falls back to the A record.
//
// Under first-match-wins the AWG route layer installs an aaaaBlocker that
// blocks only when the FIRST matching rule wants the name tunneled AND the
// tunnel can't carry v6 — without that, the legacy "any matcher matches →
// block" path would strip AAAA for every name once the user had a catch-all
// rule, which is what just bit us. Returns (nil,false) otherwise (relay).
// maybeBlockAAAA is a convenience wrapper that parses the question itself.
// Kept for tests + any external user that still has only the raw query buffer.
// Hot path uses maybeBlockAAAAParsed directly so it doesn't double-parse.
func (p *DNSProxy) maybeBlockAAAA(srcIP string, query []byte) ([]byte, bool) {
	name, qtype, ok := questionInfo(query)
	return p.maybeBlockAAAAParsed(srcIP, query, name, qtype, ok)
}

// maybeBlockAAAAParsed is the parse-once variant: caller (handleUDP/handleTCP)
// hands in the pre-parsed name + qtype + ok. Same semantics as maybeBlockAAAA.
// srcIP is the LAN client IP so source-bound zones can route by device.
func (p *DNSProxy) maybeBlockAAAAParsed(srcIP string, query []byte, name string, qtype uint16, ok bool) ([]byte, bool) {
	if !ok || qtype != 28 { // 28 = AAAA
		return nil, false
	}
	if b := p.aaaaBlocker.Load(); b != nil {
		if !(*b)(srcIP, name) {
			return nil, false
		}
		return emptyNoErrorResponse(query), true
	}
	// Legacy fallback (no blocker installed): block AAAA for any name the
	// general matcher set hits. Kept for backwards-compat with non-AWG users
	// of this package.
	ms := p.matchers.Load()
	if ms == nil || !ms.MatchAny(name) {
		return nil, false
	}
	return emptyNoErrorResponse(query), true
}
