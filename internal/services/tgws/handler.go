package tgws

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"nfqws2strategy/internal/tools/tgfronts"
)

const (
	dcFailCooldown     = 30 * time.Second
	wsFastFailTimeout  = 2 * time.Second
	wsDefaultTimeout   = 10 * time.Second
	handshakeReadLimit = 10 * time.Second
)

type handlerSettings struct {
	secret        []byte
	dcRedirects   map[int]string
	bufferSize    int
	fakeTLSDomain string
	proxyProtocol bool
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

type cooldownTracker struct {
	mu        sync.Mutex
	blacklist map[string]bool
	failUntil map[string]time.Time
}

func newCooldownTracker() *cooldownTracker {
	return &cooldownTracker{blacklist: map[string]bool{}, failUntil: map[string]time.Time{}}
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

type clientHandler struct {
	ctx      context.Context
	settings handlerSettings
	pool     *wsPool
	stats    *Stats
	bal      *domainBalancer
	cooldown *cooldownTracker
}

func newClientHandler(ctx context.Context, s handlerSettings, pool *wsPool, stats *Stats, bal *domainBalancer) *clientHandler {
	return &clientHandler{ctx: ctx, settings: s, pool: pool, stats: stats, bal: bal, cooldown: newCooldownTracker()}
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
	if h.settings.proxyProtocol {
		consumeProxyProtocol(br)
	}
	_ = conn.SetReadDeadline(time.Now().Add(handshakeReadLimit))

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
		log.Printf("tgws: [%s] Fake-TLS verify failed -> masking via %s", label, masking)
		h.stats.connectionsMasked.Add(1)
		_ = conn.SetReadDeadline(time.Time{})
		relayToMaskingDomain(&bufConn{r: br, c: conn}, clientHello, masking)
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
	dc, isMedia := parsed.dcID, parsed.isMedia
	protoInt := parsed.protoInt()
	dcKey := itoa(dc)
	mediaTag := ""
	if isMedia {
		dcKey += "m"
		mediaTag = " media"
	}
	closeClient := func() { _ = conn.Close() }

	relayInit := generateRelayHandshake(parsed.protoTag, parsed.dcIndex())
	reenc := buildContext(parsed.prekeyIV, h.settings.secret, relayInit)

	targetIP, hasRoute := h.settings.dcRedirects[dc]
	// DCs without a user-configured redirect (DC1/3/5 have no unblocked direct
	// front) can still reach their real front THROUGH the AWG2 tunnel — but only
	// while the tunnel is actually up; otherwise fall through to the normal chain.
	if !hasRoute {
		if front, okFront := tgfronts.FrontForDC(dc); okFront && h.settings.awgAvailable != nil && h.settings.awgAvailable() {
			targetIP, hasRoute = front, true
			log.Printf("tgws: [%s] DC%d%s -> AWG2 front %s", label, dc, mediaTag, front)
		}
	}
	if !hasRoute || h.cooldown.isBlacklisted(dcKey) {
		reason := "no DC route"
		if hasRoute {
			reason = "DC blacklisted"
		}
		log.Printf("tgws: [%s] DC%d%s %s -> fallback", label, dc, mediaTag, reason)
		splitter := newMessageSplitter(relayInit, protoInt)
		if !attemptFallback(h.ctx, stream, stream, closeClient, relayInit, dc, isMedia, reenc, h.stats, h.settings.fallback, h.bal, splitter) {
			log.Printf("tgws: [%s] DC%d%s no fallback available", label, dc, mediaTag)
		}
		return
	}

	domains := wsDomainsFor(dc, isMedia)
	timeout := wsDefaultTimeout
	if h.cooldown.remainingCooldown(dcKey) > 0 {
		timeout = wsFastFailTimeout
	}

	ws := h.pool.acquire(dc, isMedia, targetIP, domains)
	wsRedirectOnly := true
	if ws != nil {
		log.Printf("tgws: [%s] DC%d%s -> pool hit via %s", label, dc, mediaTag, targetIP)
	} else {
		for _, domain := range domains {
			log.Printf("tgws: [%s] DC%d%s -> wss://%s via %s", label, dc, mediaTag, domain, targetIP)
			w, err := connectWS(h.ctx, targetIP, domain, timeout, "/apiws", h.settings.bufferSize)
			if err == nil {
				ws = w
				wsRedirectOnly = false
				break
			}
			h.stats.wsErrors.Add(1)
			if hs, isHS := err.(*wsHandshakeError); isHS && hs.isRedirect() {
				log.Printf("tgws: [%s] DC%d%s %d from %s -> %s", label, dc, mediaTag, hs.statusCode, domain, hs.location)
				continue
			}
			wsRedirectOnly = false
			log.Printf("tgws: [%s] DC%d%s WS connect failed: %v", label, dc, mediaTag, err)
		}
	}

	if ws == nil {
		if wsRedirectOnly {
			h.cooldown.addBlacklist(dcKey)
			log.Printf("tgws: [%s] DC%d%s blacklisted for WS (all redirects)", label, dc, mediaTag)
		} else {
			h.cooldown.cooldown(dcKey)
			log.Printf("tgws: [%s] DC%d%s WS cooldown for %ds", label, dc, mediaTag, int(dcFailCooldown.Seconds()))
		}
		splitter := newMessageSplitter(relayInit, protoInt)
		attemptFallback(h.ctx, stream, stream, closeClient, relayInit, dc, isMedia, reenc, h.stats, h.settings.fallback, h.bal, splitter)
		return
	}

	h.cooldown.clear(dcKey)
	h.stats.connectionsWS.Add(1)
	splitter := newMessageSplitter(relayInit, protoInt)
	if err := ws.send(relayInit); err != nil {
		_ = ws.close()
		return
	}
	bridgeWS(stream, stream, closeClient, ws, reenc, h.stats, splitter)
}

func consumeProxyProtocol(br *bufio.Reader) {
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	text := strings.TrimSpace(line)
	if !strings.HasPrefix(text, "PROXY ") {
		// Not a PROXY header — but we've consumed the line. The reference
		// implementation only enables this when fronted by a proxy, so the
		// first line is always the PROXY header in practice.
		return
	}
}

func drain(r io.Reader) {
	buf := make([]byte, 4096)
	for {
		if _, err := r.Read(buf); err != nil {
			return
		}
	}
}
