package tgws

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type memoryWSConn struct {
	input  *bytes.Reader
	output bytes.Buffer
	closed atomic.Bool
}

func newMemoryWS(data []byte) (*rawWebSocket, *memoryWSConn) {
	c := &memoryWSConn{input: bytes.NewReader(data)}
	return &rawWebSocket{conn: c, r: bufio.NewReader(c)}, c
}
func (c *memoryWSConn) Read(p []byte) (int, error) { return c.input.Read(p) }
func (c *memoryWSConn) Write(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return c.output.Write(p)
}
func (c *memoryWSConn) Close() error                     { c.closed.Store(true); return nil }
func (c *memoryWSConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *memoryWSConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *memoryWSConn) SetDeadline(time.Time) error      { return nil }
func (c *memoryWSConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memoryWSConn) SetWriteDeadline(time.Time) error { return nil }

func serverFrame(op byte, data []byte, fin bool) []byte {
	h := make([]byte, 10)
	h[0] = op
	if fin {
		h[0] |= wsFinBit
	}
	switch {
	case len(data) < 126:
		h[1] = byte(len(data))
		h = h[:2]
	case len(data) < 65536:
		h[1] = 126
		binary.BigEndian.PutUint16(h[2:], uint16(len(data)))
		h = h[:4]
	default:
		h[1] = 127
		binary.BigEndian.PutUint64(h[2:], uint64(len(data)))
	}
	return append(h, data...)
}

func TestWSReassemblesFragmentsAcrossControlFrames(t *testing.T) {
	var data []byte
	data = append(data, serverFrame(wsOpBinary, []byte("AAA"), false)...)
	data = append(data, serverFrame(wsOpPing, []byte("ping"), true)...)
	data = append(data, serverFrame(wsOpCont, []byte("BBB"), false)...)
	data = append(data, serverFrame(wsOpPong, nil, true)...)
	data = append(data, serverFrame(wsOpCont, []byte("CCC"), true)...)
	ws, c := newMemoryWS(data)
	got, err := ws.recv()
	if err != nil || string(got) != "AAABBBCCC" {
		t.Fatalf("recv=%q, %v", got, err)
	}
	pong, _ := newMemoryWS(c.output.Bytes())
	op, payload, fin, err := pong.readFrame()
	if err != nil || op != wsOpPong || !fin || string(payload) != "ping" {
		t.Fatalf("pong=%d %q %t %v", op, payload, fin, err)
	}
}

func TestWSRejectsOversizedFrameBeforeAllocating(t *testing.T) {
	for _, length := range []uint64{wsMaxMessageLen + 1, 1 << 40, 1 << 63} {
		header := []byte{0x82, 127, 0, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint64(header[2:], length)
		ws, _ := newMemoryWS(header)
		_, err := ws.recv()
		if err == nil || !strings.Contains(err.Error(), "frame too large") {
			t.Fatalf("length=%d: %v", length, err)
		}
	}
}

func TestWSRejectsOversizedReassembledMessage(t *testing.T) {
	data := serverFrame(wsOpBinary, make([]byte, wsMaxMessageLen), false)
	data = append(data, serverFrame(wsOpCont, []byte{1}, true)...)
	ws, _ := newMemoryWS(data)
	if _, err := ws.recv(); err == nil || !strings.Contains(err.Error(), "message exceeds") {
		t.Fatalf("recv: %v", err)
	}
}

func TestWSMaskRoundTripAllLengthHeaders(t *testing.T) {
	for _, length := range []int{0, 5, 125, 126, 65535, 65536} {
		payload := bytes.Repeat([]byte{0xab}, length)
		frame := buildFrame(wsOpBinary, payload)
		if frame[1]&wsMaskBit == 0 {
			t.Fatal("client frame is unmasked")
		}
		ws, _ := newMemoryWS(frame)
		got, err := ws.recv()
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("length=%d err=%v", length, err)
		}
	}
}

func TestWSCloseFrameClosesTransport(t *testing.T) {
	ws, c := newMemoryWS(serverFrame(wsOpClose, []byte{3, 232}, true))
	if _, err := ws.recv(); !errors.Is(err, io.EOF) {
		t.Fatalf("recv: %v", err)
	}
	if !ws.isClosed() || !c.closed.Load() {
		t.Fatal("close frame leaked underlying connection")
	}
	if err := ws.send([]byte{1}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("send after close: %v", err)
	}
}

func TestWSCloseUnblocksConcurrentSend(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	ws := &rawWebSocket{conn: client, r: bufio.NewReader(client)}
	sent := make(chan error, 1)
	go func() { sent <- ws.send([]byte("blocked")) }()
	deadline := time.Now().Add(time.Second)
	for ws.wmu.TryLock() {
		ws.wmu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("send did not start")
		}
		time.Sleep(time.Millisecond)
	}
	closed := make(chan struct{})
	go func() { _ = ws.close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("close waited for blocked write mutex")
	}
	select {
	case err := <-sent:
		if err == nil {
			t.Fatal("blocked send succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("send remained blocked")
	}
}

func TestWSResponseHeadersAreBoundedAndPreserveFirstFrame(t *testing.T) {
	wsResponse := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"
	br := bufio.NewReaderSize(strings.NewReader(wsResponse+"frame"), 16)
	code, _, _, err := readWSResponse(br)
	if err != nil || code != 101 {
		t.Fatalf("response: %d %v", code, err)
	}
	rest, _ := io.ReadAll(br)
	if string(rest) != "frame" {
		t.Fatalf("lost buffered data: %q", rest)
	}
	_, _, _, err = readWSResponse(bufio.NewReader(strings.NewReader("HTTP/1.1 101 OK\r\nX: " + strings.Repeat("x", 64*1024))))
	if err == nil || !strings.Contains(err.Error(), "exceed") {
		t.Fatalf("oversized headers: %v", err)
	}
}

func TestWSIdleProbeRejectsClosedPeerAndBufferedClose(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	_ = server.Close()
	ws := &rawWebSocket{conn: client, r: bufio.NewReader(client)}
	if ws.idleHealthy() || !ws.isClosed() {
		t.Fatal("idle probe accepted a closed peer")
	}
	ws, _ = newMemoryWS(serverFrame(wsOpClose, []byte{3, 232}, true))
	if _, err := ws.r.Peek(2); err != nil {
		t.Fatal(err)
	}
	if ws.idleHealthy() || !ws.isClosed() {
		t.Fatal("idle probe accepted a buffered WS CLOSE")
	}
}

func TestWSIdleProbePreservesBufferedDataAndPing(t *testing.T) {
	for _, ping := range []bool{false, true} {
		var input []byte
		if ping {
			input = serverFrame(wsOpPing, []byte("ping"), true)
		}
		input = append(input, serverFrame(wsOpBinary, []byte("ready"), true)...)
		ws, _ := newMemoryWS(input)
		if _, err := ws.r.Peek(2); err != nil {
			t.Fatal(err)
		}
		if !ws.idleHealthy() {
			t.Fatalf("rejected buffered data (ping=%t)", ping)
		}
		got, err := ws.recv()
		if err != nil || string(got) != "ready" {
			t.Fatalf("probe consumed buffered data: %q %v", got, err)
		}
	}
}

func TestWSIdleProbeKeepsOpenSocketUsableAfterTimeout(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ws := &rawWebSocket{conn: client, r: bufio.NewReader(client)}
	if !ws.idleHealthy() {
		t.Fatal("idle timeout rejected an open peer")
	}
	time.Sleep(3 * wsIdleProbeTimeout)
	done := make(chan error, 1)
	go func() { _, err := server.Write(serverFrame(wsOpBinary, []byte("later"), true)); done <- err }()
	got, err := ws.recv()
	if err != nil || string(got) != "later" {
		t.Fatalf("socket unusable after probe timeout: %q %v", got, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func newIdleProbeTLSPipe(t *testing.T, version uint16) (*rawWebSocket, *tls.Conn) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	clientRaw, serverRaw := net.Pipe()
	t.Cleanup(func() { _ = clientRaw.Close(); _ = serverRaw.Close() })
	client := tls.Client(clientRaw, &tls.Config{InsecureSkipVerify: true, MinVersion: version, MaxVersion: version})
	server := tls.Server(serverRaw, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{certificate}, PrivateKey: privateKey}}, MinVersion: version, MaxVersion: version})
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))
	done := make(chan error, 1)
	go func() { done <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_ = client.SetDeadline(time.Time{})
	_ = server.SetDeadline(time.Time{})
	return &rawWebSocket{conn: client, r: bufio.NewReader(client)}, server
}

func TestWSIdleProbeTLSReadTimeoutDoesNotPoisonConnection(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			ws, server := newIdleProbeTLSPipe(t, version)
			if !ws.idleHealthy() {
				t.Fatal("TLS idle timeout rejected an open peer")
			}
			// A leaked probe deadline is expired before any application traffic.
			time.Sleep(3 * wsIdleProbeTimeout)
			_ = server.SetDeadline(time.Now().Add(time.Second))
			done := make(chan error, 1)
			go func() {
				defer server.NetConn().Close()
				serverWS := &rawWebSocket{conn: server, r: bufio.NewReader(server)}
				_, payload, _, err := serverWS.readFrame()
				if err == nil && string(payload) != "request" {
					err = errors.New("unexpected TLS WS request")
				}
				if err == nil {
					_, err = server.Write(serverFrame(wsOpBinary, []byte("response"), true))
				}
				done <- err
			}()
			if err := ws.send([]byte("request")); err != nil {
				t.Fatal(err)
			}
			got, err := ws.recv()
			if err != nil || string(got) != "response" {
				t.Fatalf("TLS unusable after read timeout: %q %v", got, err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
