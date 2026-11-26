package tgws

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func transportPacket(proto uint32, payload []byte, quickAck bool) []byte {
	var header []byte
	if proto == protoIntAbridged {
		words := len(payload) / 4
		if words < 0x7f {
			header = []byte{byte(words)}
		} else {
			header = []byte{0x7f, byte(words), byte(words >> 8), byte(words >> 16)}
		}
		if quickAck {
			header[0] |= 0x80
		}
	} else {
		header = make([]byte, 4)
		binary.LittleEndian.PutUint32(header, uint32(len(payload)))
		if quickAck {
			header[3] |= 0x80
		}
	}
	return append(header, payload...)
}

func TestMessageSplitterUpstreamFraming(t *testing.T) {
	for _, proto := range []uint32{protoIntAbridged, protoIntIntermediate, protoIntPaddedIntermediate} {
		for _, chunkSize := range []int{1, 7, 65536} {
			t.Run(fmt.Sprintf("%x/chunk%d", proto, chunkSize), func(t *testing.T) {
				relay := generateRelayHandshake(protoTagIntermediate, 2)
				splitter := newMessageSplitter(relay, proto)
				// Include short, extended abridged and quick-ack requested packets.
				var plain []byte
				var lengths []int
				for i, size := range []int{4, 16, 508, 512, 40} {
					packet := transportPacket(proto, bytes.Repeat([]byte{byte(i)}, size), i%2 != 0)
					plain = append(plain, packet...)
					lengths = append(lengths, len(packet))
				}
				encrypted := make([]byte, len(plain))
				upstreamPacketDecryptor(relay).XORKeyStream(encrypted, plain)
				var parts [][]byte
				for offset := 0; offset < len(encrypted); offset += chunkSize {
					end := offset + chunkSize
					if end > len(encrypted) {
						end = len(encrypted)
					}
					parts = append(parts, splitter.split(encrypted[offset:end])...)
				}
				if len(parts) != len(lengths) {
					t.Fatalf("got %d frames, want %d", len(parts), len(lengths))
				}
				for i, part := range parts {
					if len(part) != lengths[i] {
						t.Errorf("frame %d: length %d, want %d", i, len(part), lengths[i])
					}
				}
				if !bytes.Equal(bytes.Join(parts, nil), encrypted) || len(splitter.flush()) != 0 {
					t.Fatal("splitting changed or retained ciphertext")
				}
			})
		}
	}
}

func TestMessageSplitterInvalidAndPartialPackets(t *testing.T) {
	for _, proto := range []uint32{protoIntAbridged, protoIntIntermediate, protoIntPaddedIntermediate, 0} {
		t.Run(fmt.Sprintf("%x", proto), func(t *testing.T) {
			relay := generateRelayHandshake(protoTagIntermediate, 2)
			splitter := newMessageSplitter(relay, proto)
			if got := splitter.split(nil); len(got) != 0 {
				t.Fatal("empty input generated frames")
			}
			// A zero length (or unknown protocol) switches to transparent forwarding.
			encrypted := make([]byte, 8)
			upstreamPacketDecryptor(relay).XORKeyStream(encrypted, make([]byte, 8))
			parts := splitter.split(encrypted)
			if len(parts) != 1 || !bytes.Equal(parts[0], encrypted) {
				t.Fatal("invalid packet was not forwarded intact")
			}
			next := []byte("already encrypted")
			parts = splitter.split(next)
			if len(parts) != 1 || !bytes.Equal(parts[0], next) {
				t.Fatal("disabled splitter altered the next chunk")
			}
		})
	}
	relay := generateRelayHandshake(protoTagIntermediate, 2)
	splitter := newMessageSplitter(relay, protoIntIntermediate)
	partial := transportPacket(protoIntIntermediate, bytes.Repeat([]byte("x"), 32), false)[:10]
	encrypted := make([]byte, len(partial))
	upstreamPacketDecryptor(relay).XORKeyStream(encrypted, partial)
	if got := splitter.split(encrypted); len(got) != 0 {
		t.Fatal("incomplete packet generated a frame")
	}
	if !bytes.Equal(splitter.flush(), encrypted) || len(splitter.flush()) != 0 {
		t.Fatal("flush must return the partial ciphertext exactly once")
	}
}

func protocolCipher(stream cipher.Stream, data []byte) []byte {
	out := make([]byte, len(data))
	stream.XORKeyStream(out, data)
	return out
}

// Read a short masked frame as an independent Telegram WebSocket test peer.
func protocolReadFrame(conn net.Conn, n int) ([]byte, error) {
	header := make([]byte, 6)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if header[0] != 0x82 || header[1] != byte(n)|0x80 {
		return nil, fmt.Errorf("unexpected binary frame: %x", header)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	for i := range payload {
		payload[i] ^= header[2+i%4]
	}
	return payload, nil
}

func TestBridgesReencryptBothDirectionsAndStop(t *testing.T) {
	for _, transport := range []string{"tcp", "ws"} {
		t.Run(transport, func(t *testing.T) {
			client, local := net.Pipe()
			remote, telegram := net.Pipe()
			for _, conn := range []net.Conn{client, local, remote, telegram} {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			}
			secret := []byte("0123456789abcdef")
			init := makeClientInit(secret, protoTagIntermediate, -4)
			handshake := parseClientHandshake(init, secret)
			relay := generateRelayHandshake(handshake.protoTag, handshake.dcIndex())
			ctx := buildContext(handshake.prekeyIV, secret, relay)
			clientSend := newCTR(sha256Sum(init[8:40], secret), init[40:56])
			clientSend.XORKeyStream(make([]byte, 64), zero64)
			clientReverse := reverse(init[8:56])
			clientRecv := newCTR(sha256Sum(clientReverse[:32], secret), clientReverse[32:])
			telegramRecv := upstreamPacketDecryptor(relay)
			telegramReverse := reverse(relay[8:56])
			telegramSend := newCTR(telegramReverse[:32], telegramReverse[32:])
			stats := &Stats{}
			done := make(chan struct{})
			go func() {
				defer close(done)
				if transport == "ws" {
					ws := &rawWebSocket{conn: remote, r: bufio.NewReader(remote)}
					bridgeWS(local, local, func() { _ = local.Close() }, ws, ctx, stats, newMessageSplitter(relay, protoIntIntermediate), "test DC4 media")
				} else {
					bridgeTCP(local, local, remote, func() { _ = local.Close() }, ctx, stats)
				}
			}()
			up := transportPacket(protoIntIntermediate, []byte("a client message"), false)
			down := []byte("a Telegram reply")
			peerDone := make(chan error, 1)
			go func() {
				var encrypted []byte
				var err error
				if transport == "ws" {
					encrypted, err = protocolReadFrame(telegram, len(up))
				} else {
					encrypted = make([]byte, len(up))
					_, err = io.ReadFull(telegram, encrypted)
				}
				if err == nil && !bytes.Equal(protocolCipher(telegramRecv, encrypted), up) {
					err = fmt.Errorf("Telegram received incorrect plaintext")
				}
				if err == nil {
					encrypted = protocolCipher(telegramSend, down)
					if transport == "ws" {
						encrypted = append([]byte{0x82, byte(len(encrypted))}, encrypted...)
					}
					_, err = telegram.Write(encrypted)
				}
				peerDone <- err
			}()
			ciphertext := protocolCipher(clientSend, up)
			// Deliberately divide the MTProto length header across TCP writes.
			for _, part := range [][]byte{ciphertext[:2], ciphertext[2:]} {
				if _, err := client.Write(part); err != nil {
					t.Fatal(err)
				}
			}
			reply := make([]byte, len(down))
			if _, err := io.ReadFull(client, reply); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(protocolCipher(clientRecv, reply), down) {
				t.Fatal("client received incorrect plaintext")
			}
			if err := <-peerDone; err != nil {
				t.Fatal(err)
			}
			_ = client.Close()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("bridge did not stop after the client disconnected")
			}
			if stats.bytesUp.Load() != int64(len(up)) || stats.bytesDown.Load() != int64(len(down)) {
				t.Fatalf("incorrect bridge traffic counters: %s", stats.summary())
			}
		})
	}
}
