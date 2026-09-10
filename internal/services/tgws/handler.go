package tgws

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"nfqws2strategy/internal/tools/tgfronts"
)

const (
	ipFailCooldown     = time.Hour
	dcFailCooldown     = 60 * time.Second
	wsFastFailTimeout  = 2 * time.Second
	wsDefaultTimeout   = 5 * time.Second
	handshakeReadLimit = 10 * time.Second
)

type handlerSettings struct {
	secret        []byte
	dcRedirects   map[int]string
	bufferSize    int
	fakeTLSDomain string
	proxyProtocol bool
	forceTestDC   bool
	fallback      fallbackConfig
	awgAvailable  func() bool // live "is the AWG2 tunnel up?" probe (may be nil)
}

// rwStream is the client-facing stream — either a raw buffered TCP conn or a
// Fake-TLS unwrapper. Both strip/add nothing the bridge needs to know about.
type rwStream interface {
	io.Reader
	io.Writer
}

// bufConn pairs a buffered reader (so peeked bytes aren't lost) with the
// underlying conn for writes.
type bufConn struct {
	r *bufio.Reader
	c net.Conn
}

func (b *bufConn) Read(p []byte) (int, error)  { return b.r.Read(p) }
func (b *bufConn) Write(p []byte) (int, error) { return b.c.Write(p) }
func (b *bufConn) Close() error                { return b.c.Close() }

type cooldownTracker struct {
	mu          sync.Mutex
	blacklist   map[string]bool
	failUntil   map[string]time.Time
	ipFailUntil map[string]time.Time
}

func newCooldownTracker() *cooldownTracker {
	return &cooldownTracker{blacklist: map[string]bool{}, failUntil: map[string]time.Time{}, ipFailUntil: map[string]time.Time{}}
}

func (c *cooldownTracker) isBlacklisted(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.blacklist[key]
}
func (c *cooldownTracker) addBlacklist(key string) {
	c.mu.Lock()
	c.blacklist[key] = true
	c.mu.Unlock()
}
func (c *cooldownTracker) remainingCooldown(key string) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.failUntil[key]; ok {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}
func (c *cooldownTracker) cooldown(key string) {
	c.mu.Lock()
	c.failUntil[key] = time.Now().Add(dcFailCooldown)
	c.mu.Unlock()
}
func (c *cooldownTracker) clear(key string) {
	c.mu.Lock()
	delete(c.failUntil, key)
	c.mu.Unlock()
}

func (c *cooldownTracker) ipCoolingDown(ip string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	until := c.ipFailUntil[ip]
	if time.Now().Before(until) {
		return true
	}
	delete(c.ipFailUntil, ip)
	return false
}

func (c *cooldownTracker) cooldownIP(ip string) {
	c.mu.Lock()
	c.ipFailUntil[ip] = time.Now().Add(ipFailCooldown)
	c.mu.Unlock()
}

func (c *cooldownTracker) clearIP(ip string) {
	c.mu.Lock()
	delete(c.ipFailUntil, ip)
	c.mu.Unlock()
}

type clientHandler struct {
	ctx      context.Context
	settings handlerSettings
	pool     *wsPool
	stats    *Stats
	bal      *domainBalancer
	cooldown *cooldownTracker
	connect  func(context.Context, string, string, time.Duration, string, int) (*rawWebSocket, error)
}

func newClientHandler(ctx context.Context, s handlerSettings, pool *wsPool, stats *Stats, bal *domainBalancer) *clientHandler {
	return &clientHandler{ctx: ctx, settings: s, pool: pool, stats: stats, bal: bal, cooldown: newCooldownTracker(), connect: connectWS}
}

func (h *clientHandler) handle(conn net.Conn) {
	h.stats.connectionsTotal.Add(1)
	h.stats.connectionsActive.Add(1)
	label := "?"
	if a := conn.RemoteAddr(); a != nil {
		label = a.String()
	}
	applyConnOptions(conn, h.settings.bufferSize)

	defer func() {
		h.stats.connectionsActive.Add(-1)
		_ = conn.Close()
	}()

	br := bufio.NewReaderSize(conn, 64*1024)
	handshake, stream, ok := h.readInit(br, conn, label)
	if !ok {
		return
	}

	parsed := parseClientHandshake(handshake, h.settings.secret)
	if parsed == nil {
		h.stats.connectionsBad.Add(1)
		log.Printf("tgws: [%s] bad handshake (wrong secret or proto)", label)
		drain(stream)
		return
	}
	h.serveAuthenticated(parsed, stream, conn, label)
}

func (h *clientHandler) readInit(br *bufio.Reader, conn net.Conn, label string) ([]byte, rwStream, bool) {
	_ = conn.SetReadDeadline(time.Now().Add(handshakeReadLimit))
	if h.settings.proxyProtocol {
		if err := consumeProxyProtocol(br); err != nil {
			return nil, nil, false
		}
	}

	first, err := br.ReadByte()
	if err != nil {
		return nil, nil, false
	}
	masking := h.settings.fakeTLSDomain
	if first == tlsRecordHandshake && masking != "" {
		return h.readInitViaFakeTLS(br, conn, first, masking, label)
	}
	if masking != "" {
		redirect := "HTTP/1.1 301 Moved Permanently\r\n" +
			"Location: https://" + masking + "/\r\n" +
			"Content-Length: 0\r\nConnection: close\r\n\r\n"
		_, _ = conn.Write([]byte(redirect))
		return nil, nil, false
	}
	rest := make([]byte, handshakeLen-1)
	if _, err := io.ReadFull(br, rest); err != nil {
		return nil, nil, false
	}
	_ = conn.SetReadDeadline(time.Time{})
	hs := make([]byte, 0, handshakeLen)
	hs = append(hs, first)
	hs = append(hs, rest...)
	return hs, &bufConn{r: br, c: conn}, true
}

func (h *clientHandler) readInitViaFakeTLS(br *bufio.Reader, conn net.Conn, first byte, masking, label string) ([]byte, rwStream, bool) {
	hdrRest := make([]byte, 4)
	if _, err := io.ReadFull(br, hdrRest); err != nil {
		return nil, nil, false
	}
	tlsHeader := append([]byte{first}, hdrRest...)
	recordLen := int(binary.BigEndian.Uint16(tlsHeader[3:5]))
	recordBody := make([]byte, recordLen)
	if _, err := io.ReadFull(br, recordBody); err != nil {
		return nil, nil, false
	}
	clientHello := append(tlsHeader, recordBody...)

	cr, sid, ok := verifyClientHello(clientHello, h.settings.secret)
	if !ok {
		log.Printf("tgws: [%s] Fake-TLS verify failed -> masking via %s", label, censorDomains(masking))
		h.stats.connectionsMasked.Add(1)
		_ = conn.SetReadDeadline(time.Time{})
		relayToMaskingDomain(&bufConn{r: br, c: conn}, clientHello, masking, h.ctx)
		return nil, nil, false
	}
	serverHello := buildServerHello(h.settings.secret, cr, sid)
	if _, err := conn.Write(serverHello); err != nil {
		return nil, nil, false
	}
	stream := newFakeTLSStream(br, conn)
	handshake := make([]byte, handshakeLen)
	if _, err := io.ReadFull(stream, handshake); err != nil {
		return nil, nil, false
	}
	_ = conn.SetReadDeadline(time.Time{})
	return handshake, stream, true
}

func (h *clientHandler) serveAuthenticated(parsed *clientHandshake, stream rwStream, conn net.Conn, label string) {
	dc, isTest := normalizeClientDC(parsed.dcID, h.settings.forceTestDC)
	isMedia := parsed.isMedia
	protoInt := parsed.protoInt()
	dcKey := connectionDCKey(dc, isTest, isMedia)
	mediaTag := ""
	if isMedia {
		mediaTag = " media"
	}
	if isTest {
		mediaTag += " test"
	}
	closeClient := func() { _ = conn.Close() }
	dcIndex := dc
	if isMedia {
		dcIndex = -dc
	}
	relayInit := generateRelayHandshake(parsed.protoTag, dcIndex)
	reenc := buildContext(parsed.prekeyIV, h.settings.secret, relayInit)
	fallback := func() {
		splitter := newMessageSplitter(relayInit, protoInt)
		if !attemptFallback(h.ctx, stream, stream, closeClient, relayInit, dc, isTest, isMedia, reenc, h.stats, h.settings.fallback, h.bal, splitter) {
			log.Printf("tgws: [%s] DC%d%s no fallback available", label, dc, mediaTag)
		}
	}

	targetIP, hasRoute := h.settings.dcRedirects[dc]
	// DCs without a user-configured redirect (DC1/3/5 have no unblocked direct
	// front) can still reach their real front THROUGH the AWG tunnel — but only
	// while the tunnel is actually up; otherwise fall through to the normal chain.
	if !hasRoute {
		if front, okFront := tgfronts.FrontForDC(dc); okFront && h.settings.awgAvailable != nil && h.settings.awgAvailable() {
			targetIP, hasRoute = front, true
			log.Printf("tgws: [%s] DC%d%s -> AWG front %s", label, dc, mediaTag, front)
		}
	}
	if !hasRoute || h.cooldown.isBlacklisted(dcKey) {
		reason := "no DC route"
		if hasRoute {
			reason = "DC blacklisted"
		}
		log.Printf("tgws: [%s] DC%d%s %s -> fallback", label, dc, mediaTag, reason)
		fallback()
		return
	}

	domains := wsDomainsFor(dc, isMedia)
	path := wsPath
	if isTest {
		path = wsTestPath
	}
	var ws *rawWebSocket
	if !isTest && h.pool != nil {
		ws = h.pool.acquire(dc, isMedia, targetIP, domains)
	}
	// A timeout means both SNI alternatives share an unreachable IP. Skip
	// repeated foreground dials for an hour when CF can serve the connection,
	// but let a successfully refilled pool override that negative cache.
	hasCFFallback := (!isTest && h.settings.fallback.cfproxyEnabled) || len(h.settings.fallback.cfproxyWorkerDomains) > 0
	if ws == nil && hasCFFallback && h.cooldown.ipCoolingDown(targetIP) {
		log.Printf("tgws: [%s] DC%d%s IP %s on cooldown -> fallback", label, dc, mediaTag, targetIP)
		fallback()
		return
	}
	timeout := wsDefaultTimeout
	if h.cooldown.remainingCooldown(dcKey) > 0 {
		timeout = wsFastFailTimeout
	}

	if ws != nil {
		log.Printf("tgws: [%s] DC%d%s -> pool hit via %s (host=%s, sni=%s)", label, dc, mediaTag, targetIP, censorDomains(ws.domain), censorDomains(ws.sni))
	} else {
		ws = h.connectDirect(dcKey, targetIP, domains, path, timeout, label)
	}

	if ws == nil {
		fallback()
		return
	}

	h.cooldown.clear(dcKey)
	h.cooldown.clearIP(targetIP)
	if !isTest && h.pool != nil {
		h.pool.reportSuccess(dc, isMedia)
	}
	h.stats.connectionsWS.Add(1)
	splitter := newMessageSplitter(relayInit, protoInt)
	if err := ws.send(relayInit); err != nil {
		_ = ws.close()
		return
	}
	bridgeWS(stream, stream, closeClient, ws, reenc, h.stats, splitter, label+" DC"+dcKey)
}

func normalizeClientDC(dc int, forceTest bool) (int, bool) {
	if dc >= 10000 {
		return dc - 10000, true
	}
	return dc, forceTest
}

func connectionDCKey(dc int, isTest, isMedia bool) string {
	key := itoa(dc)
	if isTest {
		key += "t"
	}
	if isMedia {
		key += "m"
	}
	return key
}

func (h *clientHandler) connectDirect(dcKey, targetIP string, domains []string, path string, timeout time.Duration, label string) *rawWebSocket {
	allRedirects := len(domains) > 0
	for _, domain := range domains {
		if h.ctx.Err() != nil {
			return nil
		}
		log.Printf("tgws: [%s] DC%s -> wss://%s%s via %s", label, dcKey, domain, path, targetIP)
		ws, err := h.connect(h.ctx, targetIP, domain, timeout, path, h.settings.bufferSize)
		if err == nil {
			return ws
		}
		h.stats.wsErrors.Add(1)
		if h.ctx.Err() != nil {
			return nil
		}
		var hs *wsHandshakeError
		if errors.As(err, &hs) && hs.isRedirect() {
			log.Printf("tgws: [%s] DC%s %d from %s -> %s", label, dcKey, hs.statusCode, domain, censorDomains(hs.location))
			continue
		}
		allRedirects = false
		var netErr net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
			h.cooldown.cooldownIP(targetIP)
			log.Printf("tgws: [%s] DC%s IP %s timed out; cooldown for %ds", label, dcKey, targetIP, int(ipFailCooldown.Seconds()))
			break
		}
		log.Printf("tgws: [%s] DC%s WS connect failed: %s", label, dcKey, censorDomains(err.Error()))
	}
	if allRedirects {
		h.cooldown.addBlacklist(dcKey)
		log.Printf("tgws: [%s] DC%s blacklisted for WS (all redirects)", label, dcKey)
	} else {
		h.cooldown.cooldown(dcKey)
	}
	return nil
}

func consumeProxyProtocol(br *bufio.Reader) error {
	// HAProxy v1 has a 107-byte maximum line. The connection's handshake
	// deadline is already set, and a missing newline cannot allocate endlessly.
	var line []byte
	for len(line) < 107 {
		b, err := br.ReadByte()
		if err != nil {
			return err
		}
		line = append(line, b)
		if b == '\n' {
			if !strings.HasPrefix(string(line), "PROXY ") || !strings.HasSuffix(string(line), "\r\n") {
				return fmt.Errorf("invalid PROXY protocol v1 header")
			}
			return nil
		}
	}
	return fmt.Errorf("PROXY protocol v1 header too long")
}

func drain(r io.Reader) {
	buf := make([]byte, 4096)
	for {
		if _, err := r.Read(buf); err != nil {
			return
		}
	}
}
