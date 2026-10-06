package tgws

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"nfqws2strategy/internal/tools/tgfronts"
)

const (
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

type clientHandler struct {
	ctx      context.Context
	settings handlerSettings
	pool     *wsPool
	stats    *Stats
	bal      *domainBalancer
}

func newClientHandler(ctx context.Context, s handlerSettings, pool *wsPool, stats *Stats, bal *domainBalancer) *clientHandler {
	return &clientHandler{ctx: ctx, settings: s, pool: pool, stats: stats, bal: bal}
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
		if !attemptFallback(h.ctx, stream, stream, closeClient, relayInit, dc, isTest, isMedia, reenc, h.stats, h.settings.fallback, h.bal, splitter, protoInt) {
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
	if !hasRoute {
		log.Printf("tgws: [%s] DC%d%s no DC route -> fallback", label, dc, mediaTag)
		fallback()
		return
	}

	domains := wsDomainsFor(dc, isMedia)
	var ws *rawWebSocket
	if h.pool != nil {
		ws = h.pool.acquire(dc, isMedia, targetIP, domains, isTest)
	}
	if ws == nil {
		// Only the bounded background pool establishes direct WS connections.
		// A client must not wait for another foreground retry of an unavailable DC.
		log.Printf("tgws: [%s] DC%d%s WS pool unavailable -> fallback", label, dc, mediaTag)
		fallback()
		return
	}
	log.Printf("tgws: [%s] DC%d%s -> pool hit via %s (host=%s, sni=%s)", label, dc, mediaTag, targetIP, censorDomains(ws.domain), censorDomains(ws.sni))
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
