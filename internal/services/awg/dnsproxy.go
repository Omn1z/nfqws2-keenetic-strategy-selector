package awg

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// DNSProxy is a transparent DNS interceptor for split-routing by domain mask.
// It relays each query VERBATIM to an upstream resolver and, for every answer
// whose QUERIED NAME matches one of the active matchers, calls onMatch(ip) for
// each A/AAAA address found (the caller adds them to the routing ipset). It never
// rewrites DNS messages — it only reads the question name and the answer IPs — so
// clients are unaffected. Intended to sit behind an iptables REDIRECT of LAN :53.
// The raw-message parsing helpers live in dnswire.go.
type DNSProxy struct {
	addr     string
	upstream string
	onMatch  func(name, ip string)
	matchers atomic.Pointer[[]DomainMatcher]

	mu      sync.Mutex
	udp     *net.UDPConn
	tcp     net.Listener
	stop    chan struct{}
	running bool

	rmu    sync.Mutex
	recent map[string][]string // recently-seen qname → answer IPs, for re-matching on a mask change
}

// recentCap bounds the recently-seen-name cache (reset wholesale on overflow).
const recentCap = 4096

// NewDNSProxy creates a proxy listening on addr (e.g. 127.0.0.1:5354) that
// forwards to upstream (e.g. 127.0.0.1:53). onMatch is called with the matched
// query name + each matched A/AAAA IP (safe for concurrent use); the caller routes
// the IP to the right ipset by which zone the name matched.
func NewDNSProxy(addr, upstream string, onMatch func(name, ip string)) *DNSProxy {
	p := &DNSProxy{addr: addr, upstream: upstream, onMatch: onMatch}
	var empty []DomainMatcher
	p.matchers.Store(&empty)
	return p
}

// SetMatchers atomically swaps the active matcher set and re-checks recently-seen
// names against the NEW matchers, calling onMatch for matches. This makes a mask
// edit apply to domains the device already resolved (its DNS cache won't re-query
// them for a while) — the same "immediate" behaviour an explicit domain gets from
// server-side resolution. Runs async so it never blocks the apply path.
func (p *DNSProxy) SetMatchers(ms []DomainMatcher) {
	p.matchers.Store(&ms)
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
			if MatchAny(ms, name) {
				for _, ip := range ips {
					p.onMatch(name, ip)
				}
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
		b := make([]byte, 1500)
		n, client, err := uc.ReadFromUDP(b)
		if err != nil {
			return // listener closed
		}
		go p.handleUDP(uc, client, b[:n])
	}
}

func (p *DNSProxy) handleUDP(uc *net.UDPConn, client *net.UDPAddr, query []byte) {
	if blk, ok := p.maybeBlockAAAA(query); ok {
		_, _ = uc.WriteToUDP(blk, client)
		return
	}
	resp, err := p.forwardUDP(query)
	if err != nil || len(resp) == 0 {
		return
	}
	p.inspect(query, resp)
	_, _ = uc.WriteToUDP(resp, client)
}

// forwardUDP relays a raw query to the upstream resolver and returns the raw
// response.
func (p *DNSProxy) forwardUDP(query []byte) ([]byte, error) {
	c, err := net.DialTimeout("udp", p.upstream, 4*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := c.Write(query); err != nil {
		return nil, err
	}
	resp := make([]byte, 1500)
	n, err := c.Read(resp)
	if err != nil {
		return nil, err
	}
	return resp[:n], nil
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
	if blk, ok := p.maybeBlockAAAA(query); ok {
		_ = writeTCPMsg(conn, blk)
		return
	}
	up, err := net.DialTimeout("tcp", p.upstream, 4*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	_ = up.SetDeadline(time.Now().Add(4 * time.Second))
	if err := writeTCPMsg(up, query); err != nil {
		return
	}
	resp, err := readTCPMsg(up)
	if err != nil {
		return
	}
	p.inspect(query, resp)
	_ = writeTCPMsg(conn, resp)
}

// inspect reads the question name from the query and, if it matches, adds every
// A/AAAA IP from the response via onMatch. Read-only; never mutates the messages.
func (p *DNSProxy) inspect(query, resp []byte) {
	name, ok := questionName(query)
	if !ok || name == "" {
		return
	}
	ips := answerIPs(resp)
	// Remember EVERY resolved name (matched or not) so a future mask edit can apply
	// to it without waiting for the device to look it up again.
	if len(ips) > 0 {
		p.remember(name, ips)
	}
	ms := p.matchers.Load()
	if ms == nil || !MatchAny(*ms, name) {
		return
	}
	for _, ip := range ips {
		if p.onMatch != nil {
			p.onMatch(name, ip)
		}
	}
}

// maybeBlockAAAA: if the query is an AAAA (IPv6) lookup for a MATCHED name,
// return a synthesized empty NOERROR response (blocked=true) so the client falls
// back to the A record — the tunnel/ipset are IPv4-only, and handing back a real
// AAAA would let an IPv6-capable device bypass the tunnel. Returns (nil,false)
// otherwise (relay normally).
func (p *DNSProxy) maybeBlockAAAA(query []byte) ([]byte, bool) {
	name, qtype, ok := questionInfo(query)
	if !ok || qtype != 28 { // 28 = AAAA
		return nil, false
	}
	ms := p.matchers.Load()
	if ms == nil || !MatchAny(*ms, name) {
		return nil, false
	}
	return emptyNoErrorResponse(query), true
}
