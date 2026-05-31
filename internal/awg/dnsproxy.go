package awg

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var errShortMsg = errors.New("dns: bad tcp message length")

// DNSProxy is a transparent DNS interceptor for split-routing by domain mask.
// It relays each query VERBATIM to an upstream resolver and, for every answer
// whose QUERIED NAME matches one of the active matchers, calls onMatch(ip) for
// each A/AAAA address found (the caller adds them to the routing ipset). It never
// rewrites DNS messages — it only reads the question name and the answer IPs — so
// clients are unaffected. Intended to sit behind an iptables REDIRECT of LAN :53.
type DNSProxy struct {
	addr     string
	upstream string
	onMatch  func(ip string)
	matchers atomic.Pointer[[]DomainMatcher]

	mu      sync.Mutex
	udp     *net.UDPConn
	tcp     net.Listener
	stop    chan struct{}
	running bool
}

// NewDNSProxy creates a proxy listening on addr (e.g. 127.0.0.1:5354) that
// forwards to upstream (e.g. 127.0.0.1:53). onMatch is called with each matched
// A/AAAA IP (it must be safe for concurrent use).
func NewDNSProxy(addr, upstream string, onMatch func(string)) *DNSProxy {
	p := &DNSProxy{addr: addr, upstream: upstream, onMatch: onMatch}
	var empty []DomainMatcher
	p.matchers.Store(&empty)
	return p
}

// SetMatchers atomically swaps the active matcher set.
func (p *DNSProxy) SetMatchers(ms []DomainMatcher) { p.matchers.Store(&ms) }

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
	ms := p.matchers.Load()
	if ms == nil || !MatchAny(*ms, name) {
		return
	}
	for _, ip := range answerIPs(resp) {
		if p.onMatch != nil {
			p.onMatch(ip)
		}
	}
}

// ---- DNS wire parsing (read-only, bounds-checked) ----

// questionName returns the first question's name (dotted, lowercased) from a DNS
// message.
func questionName(msg []byte) (string, bool) {
	if len(msg) < 12 {
		return "", false
	}
	if qd := int(msg[4])<<8 | int(msg[5]); qd < 1 {
		return "", false
	}
	name, _, ok := readName(msg, 12)
	return name, ok
}

// answerIPs returns all A/AAAA addresses from a DNS response message.
func answerIPs(msg []byte) []string {
	if len(msg) < 12 {
		return nil
	}
	qd := int(msg[4])<<8 | int(msg[5])
	an := int(msg[6])<<8 | int(msg[7])
	pos := 12
	for i := 0; i < qd; i++ {
		_, np, ok := readName(msg, pos)
		if !ok {
			return nil
		}
		pos = np + 4 // qtype + qclass
		if pos > len(msg) {
			return nil
		}
	}
	var out []string
	for i := 0; i < an; i++ {
		_, np, ok := readName(msg, pos)
		if !ok {
			return out
		}
		pos = np
		if pos+10 > len(msg) {
			return out
		}
		typ := int(msg[pos])<<8 | int(msg[pos+1])
		rdlen := int(msg[pos+8])<<8 | int(msg[pos+9])
		pos += 10
		if pos+rdlen > len(msg) {
			return out
		}
		switch {
		case typ == 1 && rdlen == 4:
			out = append(out, net.IPv4(msg[pos], msg[pos+1], msg[pos+2], msg[pos+3]).String())
		case typ == 28 && rdlen == 16:
			ip := make(net.IP, 16)
			copy(ip, msg[pos:pos+16])
			out = append(out, ip.String())
		}
		pos += rdlen
	}
	return out
}

// readName decodes a (possibly compressed) domain name, returning the dotted
// lowercased name and the position just past the name in the ORIGINAL stream.
func readName(msg []byte, pos int) (string, int, bool) {
	var labels []string
	next := -1
	jumps := 0
	for {
		if pos < 0 || pos >= len(msg) {
			return "", 0, false
		}
		b := msg[pos]
		switch {
		case b == 0:
			if next < 0 {
				next = pos + 1
			}
			return joinLabels(labels), next, true
		case b&0xc0 == 0xc0:
			if pos+1 >= len(msg) {
				return "", 0, false
			}
			if next < 0 {
				next = pos + 2
			}
			pos = int(b&0x3f)<<8 | int(msg[pos+1])
			jumps++
			if jumps > 16 {
				return "", 0, false
			}
		default:
			l := int(b)
			if pos+1+l > len(msg) {
				return "", 0, false
			}
			labels = append(labels, string(msg[pos+1:pos+1+l]))
			pos += 1 + l
		}
	}
}

func joinLabels(labels []string) string {
	if len(labels) == 0 {
		return ""
	}
	out := labels[0]
	for _, l := range labels[1:] {
		out += "." + l
	}
	return toLower(out)
}

// toLower lowercases ASCII without importing strings (small + alloc-light).
func toLower(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			if b == nil {
				b = []byte(s)
			}
			b[i] = c + 32
		}
	}
	if b == nil {
		return s
	}
	return string(b)
}

func readTCPMsg(c net.Conn) ([]byte, error) {
	var l [2]byte
	if _, err := readFull(c, l[:]); err != nil {
		return nil, err
	}
	n := int(l[0])<<8 | int(l[1])
	if n == 0 || n > 65535 {
		return nil, errShortMsg
	}
	buf := make([]byte, n)
	if _, err := readFull(c, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeTCPMsg(c net.Conn, msg []byte) error {
	out := make([]byte, 2+len(msg))
	out[0] = byte(len(msg) >> 8)
	out[1] = byte(len(msg))
	copy(out[2:], msg)
	_, err := c.Write(out)
	return err
}

func readFull(c net.Conn, b []byte) (int, error) {
	got := 0
	for got < len(b) {
		n, err := c.Read(b[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}
