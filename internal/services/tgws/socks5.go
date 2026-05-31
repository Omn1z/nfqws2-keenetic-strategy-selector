package tgws

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync/atomic"
	"time"
)

// socks5 implements the client-facing front-end adapted from TGLock
// (github.com/by-sonic/tglock). It speaks SOCKS5 to a local client (Telegram
// Desktop / mobile), classifies the CONNECT target: a Telegram DC IP is
// tunneled over WSS to kws{dc}.web.telegram.org (reusing connectWS/rawWebSocket
// — a transparent byte pipe, since the client speaks obfuscated2 end-to-end to
// the DC), while any other target is relayed directly (a plain SOCKS5).

const socks5HandshakeTimeout = 15 * time.Second

type socks5Settings struct {
	user        string
	pass        string
	bufferSize  int
	dcRedirects map[int]string
}

type socks5Handler struct {
	ctx      context.Context
	settings socks5Settings
	stats    *Socks5Stats
}

func newSocks5Handler(ctx context.Context, s socks5Settings, stats *Socks5Stats) *socks5Handler {
	return &socks5Handler{ctx: ctx, settings: s, stats: stats}
}

func (h *socks5Handler) handle(conn net.Conn) {
	h.stats.total.Add(1)
	h.stats.active.Add(1)
	defer func() {
		h.stats.active.Add(-1)
		_ = conn.Close()
	}()
	applyConnOptions(conn, h.settings.bufferSize)

	_ = conn.SetReadDeadline(time.Now().Add(socks5HandshakeTimeout))
	if !h.greet(conn) {
		h.stats.bad.Add(1)
		return
	}
	host, port, ok := h.readConnect(conn)
	if !ok {
		h.stats.bad.Add(1)
		return
	}
	// Optimistic success reply (BND.ADDR 127.0.0.1:port), TGLock-faithful — the
	// client sends its obfuscated2 init immediately after, before it cares.
	_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, byte(port >> 8), byte(port)})
	_ = conn.SetReadDeadline(time.Time{})

	dcGuess, isTG := dcFromIP(net.ParseIP(host))
	if !isTG {
		h.stats.direct.Add(1)
		h.directRelay(conn, host, port)
		return
	}

	// Telegram path: read exactly the 64-byte obfuscated2 init and sniff the DC.
	var init [64]byte
	_ = conn.SetReadDeadline(time.Now().Add(socks5HandshakeTimeout))
	if _, err := io.ReadFull(conn, init[:]); err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	dc := dcFromInit(init)
	if dc == 0 {
		dc = dcGuess // fall back to the IP guess
	}
	if dc == 0 {
		dc = 2
	}
	h.stats.telegram.Add(1)
	h.stats.lastDC.Store(int64(dc))
	h.tunnelWS(conn, dc, init[:])
}

// greet performs the SOCKS5 method negotiation. With no configured user it
// accepts no-auth (0x00); otherwise it requires username/password (RFC 1929).
func (h *socks5Handler) greet(conn net.Conn) bool {
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil || head[0] != 0x05 {
		return false
	}
	n := int(head[1])
	methods := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(conn, methods); err != nil {
			return false
		}
	}
	if h.settings.user == "" {
		_, err := conn.Write([]byte{0x05, 0x00})
		return err == nil
	}
	if !containsByte(methods, 0x02) {
		_, _ = conn.Write([]byte{0x05, 0xFF}) // no acceptable method
		return false
	}
	if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
		return false
	}
	return h.auth(conn)
}

func (h *socks5Handler) auth(conn net.Conn) bool {
	v := make([]byte, 2) // VER, ULEN
	if _, err := io.ReadFull(conn, v); err != nil || v[0] != 0x01 {
		return false
	}
	uname := make([]byte, int(v[1]))
	if _, err := io.ReadFull(conn, uname); err != nil {
		return false
	}
	pl := make([]byte, 1)
	if _, err := io.ReadFull(conn, pl); err != nil {
		return false
	}
	passwd := make([]byte, int(pl[0]))
	if _, err := io.ReadFull(conn, passwd); err != nil {
		return false
	}
	if string(uname) == h.settings.user && string(passwd) == h.settings.pass {
		_, _ = conn.Write([]byte{0x01, 0x00}) // success
		return true
	}
	_, _ = conn.Write([]byte{0x01, 0x01}) // failure
	return false
}

// readConnect parses the CONNECT request and returns the target host:port.
func (h *socks5Handler) readConnect(conn net.Conn) (string, int, bool) {
	head := make([]byte, 4) // VER, CMD, RSV, ATYP
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", 0, false
	}
	if head[0] != 0x05 || head[1] != 0x01 { // CONNECT only
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return "", 0, false
	}
	var host string
	switch head[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", 0, false
		}
		host = net.IP(b).String()
	case 0x03: // domain
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return "", 0, false
		}
		name := make([]byte, int(l[0]))
		if _, err := io.ReadFull(conn, name); err != nil {
			return "", 0, false
		}
		host = string(name)
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", 0, false
		}
		host = net.IP(b).String()
	default:
		_, _ = conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // ATYP not supported
		return "", 0, false
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(conn, pb); err != nil {
		return "", 0, false
	}
	return host, int(binary.BigEndian.Uint16(pb)), true
}

// socks5WebFrontIP is a reachable Telegram web front. DNS for kws{dc}.web.telegram.org
// resolves to DC IPs that ISPs commonly block (the very reason this proxy exists),
// so by default we dial this known-good front IP with the right SNI — mirroring
// the MTProto proxy. A per-DC override in DCRedirects takes precedence.
const socks5WebFrontIP = "149.154.167.220"

func (h *socks5Handler) tunnelWS(conn net.Conn, dc int, init []byte) {
	domain := fmt.Sprintf("kws%d.web.telegram.org", dc)
	host := socks5WebFrontIP
	if ip := h.settings.dcRedirects[dc]; ip != "" {
		host = ip // per-DC override
	}
	ws, err := connectWS(h.ctx, host, domain, wsDefaultTimeout, "/apiws", h.settings.bufferSize)
	if err != nil && host != domain {
		// Fallback: try resolving the domain via DNS directly.
		host = domain
		ws, err = connectWS(h.ctx, domain, domain, wsDefaultTimeout, "/apiws", h.settings.bufferSize)
	}
	if err != nil {
		log.Printf("socks5: DC%d WS connect failed: %v", dc, err)
		return
	}
	log.Printf("socks5: DC%d -> wss://%s via %s", dc, domain, host)
	if err := ws.send(init); err != nil { // 64-byte init verbatim as the first frame
		_ = ws.close()
		return
	}
	bridgeTransparent(conn, ws, h.stats)
}

func (h *socks5Handler) directRelay(conn net.Conn, host string, port int) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	remote, err := dialer.DialContext(h.ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return
	}
	applyConnOptions(remote, h.settings.bufferSize)
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn, counter *atomic.Int64) {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 65536)
		for {
			n, rerr := src.Read(buf)
			if n > 0 {
				counter.Add(int64(n))
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if rerr != nil {
				return
			}
		}
	}
	go pipe(remote, conn, &h.stats.bytesUp)
	go pipe(conn, remote, &h.stats.bytesDown)
	<-done
	_ = remote.Close()
	_ = conn.Close()
	<-done
}

// bridgeTransparent pipes the client TCP stream and the upstream WS verbatim
// (one TCP read = one WS binary frame; one WS frame = one TCP write). No
// re-encryption — the client's obfuscated2 stream is end-to-end with the DC.
func bridgeTransparent(client net.Conn, ws *rawWebSocket, stats *Socks5Stats) {
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 65536)
		for {
			n, err := client.Read(buf)
			if n > 0 {
				stats.bytesUp.Add(int64(n))
				if e := ws.send(buf[:n]); e != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			data, err := ws.recv()
			if err != nil {
				return
			}
			stats.bytesDown.Add(int64(len(data)))
			if _, e := client.Write(data); e != nil {
				return
			}
		}
	}()
	<-done
	_ = ws.close()
	_ = client.Close()
	<-done
}

// dcFromIP maps a SOCKS CONNECT target IPv4 to a Telegram DC (the TGLock table).
// Returns ok=false for any non-Telegram / non-IPv4 address.
func dcFromIP(ip net.IP) (int, bool) {
	o := ip.To4()
	if o == nil {
		return 0, false
	}
	switch {
	case o[0] == 149 && o[1] == 154:
		switch {
		case o[2] >= 160 && o[2] <= 163:
			return 1, true
		case o[2] >= 164 && o[2] <= 167:
			return 2, true
		case o[2] >= 168 && o[2] <= 171:
			return 3, true
		case o[2] >= 172 && o[2] <= 175:
			return 1, true
		default:
			return 2, true
		}
	case o[0] == 91 && o[1] == 108:
		switch {
		case o[2] >= 56 && o[2] <= 59:
			return 5, true
		case o[2] >= 8 && o[2] <= 11:
			return 3, true
		case o[2] >= 12 && o[2] <= 15:
			return 4, true
		default:
			return 2, true
		}
	case (o[0] == 91 && o[1] == 105) || (o[0] == 185 && o[1] == 76):
		return 2, true
	}
	return 0, false
}

// dcFromInit decrypts the 64-byte obfuscated2 init (direct client->DC, no proxy
// secret) and reads the datacenter id: AES-256-CTR key=init[8:40], iv=init[40:56];
// dc = abs(int32 LE at dec[60:64]), valid only in 1..5. Returns 0 if out of range.
func dcFromInit(init [64]byte) int {
	block, err := aes.NewCipher(init[8:40])
	if err != nil {
		return 0
	}
	dec := make([]byte, 64)
	cipher.NewCTR(block, init[40:56]).XORKeyStream(dec, init[:])
	id := int32(binary.LittleEndian.Uint32(dec[60:64]))
	if id < 0 {
		id = -id
	}
	if id >= 1 && id <= 5 {
		return int(id)
	}
	return 0
}

func containsByte(b []byte, x byte) bool {
	for _, v := range b {
		if v == x {
			return true
		}
	}
	return false
}
