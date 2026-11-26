package tgws

import (
	"bufio"
	"bytes"
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type h2TestDelivery struct {
	body  []byte
	quick bool
	err   error
}

type h2TestChannel struct {
	uploads        chan h2TestDelivery
	downloads      chan h2TestDelivery
	closed         chan struct{}
	once           sync.Once
	deliveredCount atomic.Int64
	terminal       *mtprotoTransportError // Fixed before the bridge starts.
	sendErr        error
}

func newH2TestChannel() *h2TestChannel {
	return &h2TestChannel{uploads: make(chan h2TestDelivery, 8), downloads: make(chan h2TestDelivery, 8), closed: make(chan struct{})}
}

func (c *h2TestChannel) send(ctx context.Context, body []byte, quick bool) error {
	if c.sendErr != nil {
		return c.sendErr
	}
	select {
	case c.uploads <- h2TestDelivery{body: body, quick: quick}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-c.closed:
		return io.ErrClosedPipe
	}
}

func (c *h2TestChannel) receive(ctx context.Context) ([]byte, error) {
	select {
	case reply := <-c.downloads:
		return reply.body, reply.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, io.ErrClosedPipe
	}
}

func (c *h2TestChannel) close()                                 { c.once.Do(func() { close(c.closed) }) }
func (c *h2TestChannel) delivered()                             { c.deliveredCount.Add(1) }
func (c *h2TestChannel) transportError() *mtprotoTransportError { return c.terminal }

type h2ShortWriter struct{ io.Writer }

func (w h2ShortWriter) Write(data []byte) (int, error) {
	return w.Writer.Write(data[:1])
}

type h2BridgeHarness struct {
	peer    io.ReadWriter
	conn    net.Conn
	cancel  context.CancelFunc
	done    chan struct{}
	send    cipher.Stream
	receive cipher.Stream
	stats   *Stats
	proto   uint32
}

func startH2Bridge(t *testing.T, proto uint32, fakeTLS, shortWrites bool, channel *h2TestChannel) *h2BridgeHarness {
	t.Helper()
	client, local := net.Pipe()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_ = local.SetDeadline(time.Now().Add(5 * time.Second))
	var localStream io.ReadWriter = local
	var peer io.ReadWriter = client
	if fakeTLS {
		localStream = newFakeTLSStream(bufio.NewReader(local), local)
		peer = newFakeTLSStream(bufio.NewReader(client), client)
	}
	var writer io.Writer = localStream
	if shortWrites {
		writer = h2ShortWriter{writer}
	}
	var tag [4]byte
	binary.LittleEndian.PutUint32(tag[:], proto)
	secret := []byte("0123456789abcdef")
	init := makeClientInit(secret, tag[:], -2)
	handshake := parseClientHandshake(init, secret)
	crypto := buildContext(handshake.prekeyIV, secret, generateRelayHandshake(handshake.protoTag, handshake.dcIndex()))
	// A /api bridge must never access either relay cipher.
	crypto.upstreamEncrypt, crypto.upstreamDecrypt = nil, nil
	send := newCTR(sha256Sum(init[8:40], secret), init[40:56])
	send.XORKeyStream(make([]byte, 64), zero64)
	reversed := reverse(init[8:56])
	receive := newCTR(sha256Sum(reversed[:32], secret), reversed[32:])
	ctx, cancel := context.WithCancel(context.Background())
	h := &h2BridgeHarness{peer: peer, conn: client, cancel: cancel, done: make(chan struct{}), send: send, receive: receive, stats: &Stats{}, proto: proto}
	go func() {
		defer close(h.done)
		bridgeH2(ctx, localStream, writer, func() { _ = local.Close() }, channel, crypto, h.stats, proto, "test H2")
	}()
	t.Cleanup(func() {
		cancel()
		_ = client.Close()
		_ = local.Close()
		h.wait(t)
	})
	return h
}

func (h *h2BridgeHarness) wait(t *testing.T) {
	t.Helper()
	select {
	case <-h.done:
	case <-time.After(3 * time.Second):
		t.Fatal("H2 bridge did not stop both workers")
	}
}

func (h *h2BridgeHarness) upload(t *testing.T, body []byte, quick bool) {
	t.Helper()
	body = append([]byte(nil), body...)
	if h.proto == protoIntPaddedIntermediate {
		body = append(body, bytes.Repeat([]byte{0xcc}, 7)...)
	}
	data := protocolCipher(h.send, transportPacket(h.proto, body, quick))
	// Divide transport headers across writes, including Fake TLS records.
	for _, fragment := range [][]byte{data[:1], data[1:3], data[3:]} {
		if _, err := h.peer.Write(fragment); err != nil {
			t.Fatal(err)
		}
	}
}

// The peer decoder is intentionally independent from readH2Packet: native
// replies may be four-byte transport errors, whereas upload messages may not.
func (h *h2BridgeHarness) reply(t *testing.T, want []byte) {
	t.Helper()
	read := func(n int) []byte {
		data := make([]byte, n)
		if _, err := io.ReadFull(h.peer, data); err != nil {
			t.Fatal(err)
		}
		h.receive.XORKeyStream(data, data)
		return data
	}
	length := 0
	if h.proto == protoIntAbridged {
		first := read(1)[0]
		if first&0x80 != 0 {
			t.Fatal("reply incorrectly requests a quick ACK")
		}
		length = int(first) * 4
		if first == 0x7f {
			header := read(3)
			length = (int(header[0]) | int(header[1])<<8 | int(header[2])<<16) * 4
		}
	} else {
		length = int(binary.LittleEndian.Uint32(read(4)))
	}
	padding := length - len(want)
	if padding < 0 || padding > 3 || (h.proto != protoIntPaddedIntermediate && padding != 0) {
		t.Fatalf("invalid reply frame length %d, expected body %d", length, len(want))
	}
	if got := read(length); !bytes.Equal(got[:len(want)], want) {
		t.Fatalf("native reply changed: got %x want %x", got, want)
	}
}

func TestH2BridgeEncryptedNativeAndFakeTLS(t *testing.T) {
	for _, proto := range []uint32{protoIntAbridged, protoIntIntermediate, protoIntPaddedIntermediate} {
		for _, fakeTLS := range []bool{false, true} {
			t.Run(fmt.Sprintf("%x/tls%t", proto, fakeTLS), func(t *testing.T) {
				channel := newH2TestChannel()
				h := startH2Bridge(t, proto, fakeTLS, true, channel)
				for i, size := range []int{40, 520} {
					body := bytes.Repeat([]byte{byte(i + 1)}, size)
					h.upload(t, body, i%2 == 0)
					select {
					case got := <-channel.uploads:
						if !bytes.Equal(got.body, body) || got.quick != (i%2 == 0) {
							t.Fatal("HTTP channel received altered message or quick-ACK flag")
						}
					case <-time.After(time.Second):
						t.Fatal("missing HTTP upload")
					}
				}
				// Independent HTTP streams may complete in a different order.
				for _, size := range []int{512, 24} {
					body := bytes.Repeat([]byte{0x8b}, size)
					channel.downloads <- h2TestDelivery{body: body}
					h.reply(t, body)
				}
				_ = h.conn.Close()
				h.wait(t)
				if h.stats.bytesDown.Load() != 536 || h.stats.bytesUp.Load() != 0 || channel.deliveredCount.Load() != 2 {
					t.Fatalf("incorrect H2 accounting: %s delivered=%d", h.stats.summary(), channel.deliveredCount.Load())
				}
			})
		}
	}
}

func TestH2BridgeForwardsTransportErrorsBeforeEOF(t *testing.T) {
	for _, proto := range []uint32{protoIntAbridged, protoIntIntermediate, protoIntPaddedIntermediate} {
		for _, fakeTLS := range []bool{false, true} {
			t.Run(fmt.Sprintf("%x/tls%t", proto, fakeTLS), func(t *testing.T) {
				channel := newH2TestChannel()
				h := startH2Bridge(t, proto, fakeTLS, true, channel)
				first := bytes.Repeat([]byte{0x71}, 24)
				channel.downloads <- h2TestDelivery{body: first}
				h.reply(t, first)
				channel.downloads <- h2TestDelivery{err: fmt.Errorf("wrapped: %w", &mtprotoTransportError{code: -404, source: "HTTP 404"})}
				// Signed little-endian -404 from MTProto, never the string "404".
				h.reply(t, []byte{0x6c, 0xfe, 0xff, 0xff})
				h.wait(t)
				if _, err := h.peer.Read(make([]byte, 1)); err != io.EOF {
					t.Fatalf("expected EOF after framed error, got %v", err)
				}
				if h.stats.bytesDown.Load() != 28 {
					t.Fatalf("error delivery was not counted: %s", h.stats.summary())
				}
			})
		}
	}
}

func TestH2BridgePreservesStoredErrorWhenUploadStopsFirst(t *testing.T) {
	channel := newH2TestChannel()
	channel.terminal = &mtprotoTransportError{code: -429, source: "HTTP 429"}
	channel.sendErr = io.ErrClosedPipe
	h := startH2Bridge(t, protoIntIntermediate, false, false, channel)
	h.upload(t, bytes.Repeat([]byte{0x67}, 24), false)
	h.reply(t, []byte{0x53, 0xfe, 0xff, 0xff})
	h.wait(t)
}

func TestH2BridgeCancellationClosesIdleAndBlockedNativeIO(t *testing.T) {
	for _, blockedWrite := range []bool{false, true} {
		t.Run(fmt.Sprintf("blockedWrite%t", blockedWrite), func(t *testing.T) {
			channel := newH2TestChannel()
			h := startH2Bridge(t, protoIntIntermediate, false, false, channel)
			if blockedWrite {
				channel.downloads <- h2TestDelivery{body: make([]byte, 32)}
				// Reading a single encrypted prefix byte guarantees the worker
				// is already in its native write; leave the remainder blocked.
				if _, err := io.ReadFull(h.peer, make([]byte, 1)); err != nil {
					t.Fatal(err)
				}
			}
			h.cancel()
			h.wait(t)
			select {
			case <-channel.closed:
			default:
				t.Fatal("cancellation left the HTTP channel open")
			}
		})
	}
}

func TestH2BridgeDoesNotSendGenericErrorsAsMTProto(t *testing.T) {
	channel := newH2TestChannel()
	h := startH2Bridge(t, protoIntIntermediate, false, false, channel)
	channel.downloads <- h2TestDelivery{err: errors.New("HTTP network timeout")}
	h.wait(t)
	if _, err := h.peer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("expected EOF for non-protocol error, got %v", err)
	}
	if h.stats.bytesDown.Load() != 0 {
		t.Fatal("generic network error was sent as MTProto data")
	}
}
