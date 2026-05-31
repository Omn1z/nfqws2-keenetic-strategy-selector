package tgws

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// wsHandshakeError carries the HTTP status from a failed WS upgrade so the
// caller can distinguish redirects (try the next domain) from hard failures.
type wsHandshakeError struct {
	statusCode int
	statusLine string
	location   string
}

func (e *wsHandshakeError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.statusCode, e.statusLine)
}

func (e *wsHandshakeError) isRedirect() bool {
	switch e.statusCode {
	case 301, 302, 303, 307, 308:
		return true
	}
	return false
}

// rawWebSocket is a bare-bones RFC 6455 client: binary frames, masked
// client->server, ping/pong handling, clean close. No fragmentation — the
// upstream Telegram WS endpoint never fragments.
type rawWebSocket struct {
	conn   net.Conn
	r      *bufio.Reader
	wmu    sync.Mutex
	closed bool
}

func applyConnOptions(conn net.Conn, bufferSize int) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tcp.SetNoDelay(true)
	if bufferSize > 0 {
		_ = tcp.SetReadBuffer(bufferSize)
		_ = tcp.SetWriteBuffer(bufferSize)
	}
}

// connectWS opens a TLS+WebSocket connection to host:443 presenting sniDomain
// as the SNI/Host. Certificate verification is intentionally disabled — the
// transport secrecy is provided by the MTProto layer, not TLS.
func connectWS(ctx context.Context, host, sniDomain string, timeout time.Duration, path string, bufferSize int) (*rawWebSocket, error) {
	if timeout > 10*time.Second {
		timeout = 10 * time.Second
	}
	dialer := &net.Dialer{Timeout: timeout}
	raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return nil, err
	}
	applyConnOptions(raw, bufferSize)

	tconn := tls.Client(raw, &tls.Config{ServerName: sniDomain, InsecureSkipVerify: true})
	_ = tconn.SetDeadline(time.Now().Add(timeout))
	if err := tconn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}

	keyRaw := make([]byte, 16)
	_, _ = rand.Read(keyRaw)
	wsKey := base64.StdEncoding.EncodeToString(keyRaw)
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + sniDomain + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + wsKey + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Protocol: binary\r\n\r\n"
	if _, err := tconn.Write([]byte(req)); err != nil {
		_ = tconn.Close()
		return nil, err
	}

	br := bufio.NewReaderSize(tconn, 64*1024)
	statusCode, statusLine, headers, err := readWSResponse(br)
	if err != nil {
		_ = tconn.Close()
		return nil, err
	}
	if statusCode == 101 {
		_ = tconn.SetDeadline(time.Time{}) // clear the handshake deadline
		return &rawWebSocket{conn: tconn, r: br}, nil
	}
	_ = tconn.Close()
	return nil, &wsHandshakeError{statusCode: statusCode, statusLine: statusLine, location: headers["location"]}
}

func readWSResponse(br *bufio.Reader) (int, string, map[string]string, error) {
	var lines []string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return 0, "", nil, err
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			break
		}
		lines = append(lines, trimmed)
	}
	if len(lines) == 0 {
		return 0, "empty response", map[string]string{}, nil
	}
	statusCode := 0
	if parts := strings.SplitN(lines[0], " ", 3); len(parts) >= 2 {
		statusCode, _ = strconv.Atoi(parts[1])
	}
	headers := map[string]string{}
	for _, hl := range lines[1:] {
		if i := strings.Index(hl, ":"); i >= 0 {
			headers[strings.ToLower(strings.TrimSpace(hl[:i]))] = strings.TrimSpace(hl[i+1:])
		}
	}
	return statusCode, lines[0], headers, nil
}

func (ws *rawWebSocket) isClosed() bool { return ws.closed }

func (ws *rawWebSocket) send(data []byte) error {
	ws.wmu.Lock()
	defer ws.wmu.Unlock()
	if ws.closed {
		return io.ErrClosedPipe
	}
	_, err := ws.conn.Write(buildFrame(wsOpBinary, data))
	return err
}

func (ws *rawWebSocket) sendBatch(parts [][]byte) error {
	ws.wmu.Lock()
	defer ws.wmu.Unlock()
	if ws.closed {
		return io.ErrClosedPipe
	}
	var buf []byte
	for _, p := range parts {
		buf = append(buf, buildFrame(wsOpBinary, p)...)
	}
	_, err := ws.conn.Write(buf)
	return err
}

// recv blocks until a binary/text frame arrives and returns its payload.
// Returns io.EOF when the peer closes.
func (ws *rawWebSocket) recv() ([]byte, error) {
	for !ws.closed {
		opcode, payload, err := ws.readFrame()
		if err != nil {
			return nil, err
		}
		switch opcode {
		case wsOpClose:
			ws.closed = true
			echo := []byte{}
			if len(payload) >= 2 {
				echo = payload[:2]
			}
			ws.writeControl(wsOpClose, echo)
			return nil, io.EOF
		case wsOpPing:
			ws.writeControl(wsOpPong, payload)
		case wsOpPong:
			// ignore
		case wsOpText, wsOpBinary:
			return payload, nil
		}
	}
	return nil, io.EOF
}

func (ws *rawWebSocket) writeControl(opcode int, data []byte) {
	ws.wmu.Lock()
	defer ws.wmu.Unlock()
	if ws.closed && opcode != wsOpClose {
		return
	}
	_, _ = ws.conn.Write(buildFrame(opcode, data))
}

func (ws *rawWebSocket) close() error {
	ws.wmu.Lock()
	if ws.closed {
		ws.wmu.Unlock()
		return nil
	}
	ws.closed = true
	_, _ = ws.conn.Write(buildFrame(wsOpClose, nil))
	ws.wmu.Unlock()
	return ws.conn.Close()
}

func buildFrame(opcode int, data []byte) []byte {
	length := len(data)
	flags := byte(wsFinBit | opcode)
	mask := make([]byte, 4)
	_, _ = rand.Read(mask)

	var head []byte
	switch {
	case length < 126:
		head = []byte{flags, byte(wsMaskBit | length)}
	case length < 65536:
		head = []byte{flags, byte(wsMaskBit | 126), byte(length >> 8), byte(length)}
	default:
		head = make([]byte, 10)
		head[0] = flags
		head[1] = byte(wsMaskBit | 127)
		binary.BigEndian.PutUint64(head[2:], uint64(length))
	}
	out := make([]byte, 0, len(head)+4+length)
	out = append(out, head...)
	out = append(out, mask...)
	for i := 0; i < length; i++ {
		out = append(out, data[i]^mask[i&3])
	}
	return out
}

func (ws *rawWebSocket) readFrame() (int, []byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(ws.r, header); err != nil {
		return 0, nil, err
	}
	opcode := int(header[0] & 0x0F)
	length := int(header[1] & 0x7F)
	switch length {
	case 126:
		b := make([]byte, 2)
		if _, err := io.ReadFull(ws.r, b); err != nil {
			return 0, nil, err
		}
		length = int(binary.BigEndian.Uint16(b))
	case 127:
		b := make([]byte, 8)
		if _, err := io.ReadFull(ws.r, b); err != nil {
			return 0, nil, err
		}
		length = int(binary.BigEndian.Uint64(b))
	}

	var mask []byte
	if header[1]&wsMaskBit != 0 {
		mask = make([]byte, 4)
		if _, err := io.ReadFull(ws.r, mask); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(ws.r, payload); err != nil {
		return 0, nil, err
	}
	if mask != nil {
		for i := range payload {
			payload[i] ^= mask[i&3]
		}
	}
	return opcode, payload, nil
}
