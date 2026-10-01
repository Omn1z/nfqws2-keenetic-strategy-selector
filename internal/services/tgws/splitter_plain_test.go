package tgws

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"
)

type unusedSplitterDecryptor struct{}

func (unusedSplitterDecryptor) XORKeyStream([]byte, []byte) {
	panic("the plaintext splitter must not decrypt the upload again")
}

func TestMessageSplitterPlainPreservesFramingAndBufferOwnership(t *testing.T) {
	for _, proto := range []uint32{protoIntAbridged, protoIntIntermediate, protoIntPaddedIntermediate} {
		for _, chunkSize := range []int{1, 2, 3, 7, 64, 65536} {
			t.Run(fmt.Sprintf("%x/chunk%d", proto, chunkSize), func(t *testing.T) {
				relay := generateRelayHandshake(protoTagIntermediate, 2)
				splitter := newMessageSplitter(relay, proto)
				splitter.decryptor = unusedSplitterDecryptor{}
				var plain []byte
				var lengths []int
				for i, size := range []int{4, 16, 508, 512, 40} {
					packet := transportPacket(proto, bytes.Repeat([]byte{byte(i + 1)}, size), i%2 != 0)
					plain = append(plain, packet...)
					lengths = append(lengths, len(packet))
				}
				ciphertext := make([]byte, len(plain))
				upstreamPacketDecryptor(relay).XORKeyStream(ciphertext, plain)
				var parts [][]byte
				for offset := 0; offset < len(plain); offset += chunkSize {
					end := offset + chunkSize
					if end > len(plain) {
						end = len(plain)
					}
					plainChunk := append([]byte(nil), plain[offset:end]...)
					cipherChunk := append([]byte(nil), ciphertext[offset:end]...)
					parts = append(parts, splitter.splitPlain(cipherChunk, plainChunk)...)
					if !bytes.Equal(plainChunk, plain[offset:end]) || !bytes.Equal(cipherChunk, ciphertext[offset:end]) {
						t.Fatal("splitter changed a caller's plaintext or ciphertext")
					}
					// The bridge reuses its read buffer after every chunk. Neither
					// buffered headers/payloads nor emitted frames may alias it.
					for i := range plainChunk {
						plainChunk[i] ^= 0xff
						cipherChunk[i] ^= 0xff
					}
				}
				if len(parts) != len(lengths) {
					t.Fatalf("got %d frames, want %d", len(parts), len(lengths))
				}
				for i, part := range parts {
					if len(part) != lengths[i] {
						t.Fatalf("frame %d: got %d bytes, want %d", i, len(part), lengths[i])
					}
				}
				if !bytes.Equal(bytes.Join(parts, nil), ciphertext) || len(splitter.flush()) != 0 {
					t.Fatal("plaintext framing changed or retained ciphertext")
				}
			})
		}
	}
}

func TestMessageSplitterPlainUnknownAndPartialPackets(t *testing.T) {
	for _, proto := range []uint32{protoIntAbridged, protoIntIntermediate, protoIntPaddedIntermediate, 0} {
		t.Run(fmt.Sprintf("%x", proto), func(t *testing.T) {
			splitter := newMessageSplitter(generateRelayHandshake(protoTagIntermediate, 2), proto)
			splitter.decryptor = unusedSplitterDecryptor{}
			if parts := splitter.splitPlain(nil, nil); len(parts) != 0 {
				t.Fatal("empty input generated a frame")
			}
			// A zero/unknown shape keeps the existing transparent fallback.
			plain, ciphertext := make([]byte, 8), []byte("cipher01")
			parts := splitter.splitPlain(ciphertext, plain)
			if len(parts) != 1 || !bytes.Equal(parts[0], ciphertext) {
				t.Fatal("unknown packet was not forwarded intact")
			}
			clear(ciphertext)
			if string(parts[0]) != "cipher01" {
				t.Fatal("first fallback frame retained the caller's buffer")
			}
			next := []byte("cipher02")
			parts = splitter.splitPlain(next, make([]byte, len(next)))
			if len(parts) != 1 || !bytes.Equal(parts[0], next) || len(splitter.flush()) != 0 {
				t.Fatal("transparent fallback changed or retained the next chunk")
			}
		})
	}
	for _, proto := range []uint32{protoIntAbridged, protoIntIntermediate, protoIntPaddedIntermediate} {
		t.Run(fmt.Sprintf("%x/partial", proto), func(t *testing.T) {
			relay := generateRelayHandshake(protoTagIntermediate, 2)
			plain := transportPacket(proto, bytes.Repeat([]byte{42}, 32), false)[:10]
			ciphertext := make([]byte, len(plain))
			upstreamPacketDecryptor(relay).XORKeyStream(ciphertext, plain)
			splitter := newMessageSplitter(relay, proto)
			splitter.decryptor = unusedSplitterDecryptor{}
			if parts := splitter.splitPlain(ciphertext, plain); len(parts) != 0 {
				t.Fatal("partial packet generated a frame")
			}
			tail := splitter.flush()
			if !bytes.Equal(tail, ciphertext) || len(splitter.flush()) != 0 {
				t.Fatal("flush must preserve partial ciphertext exactly once")
			}
			for i := range ciphertext {
				ciphertext[i] ^= 0xff
			}
			if bytes.Equal(tail, ciphertext) {
				t.Fatal("flushed ciphertext retained the caller's buffer")
			}
		})
	}
}

func TestBridgeWSUsesExistingPlaintextForEveryTransport(t *testing.T) {
	for _, tc := range []struct {
		proto uint32
		tag   []byte
	}{
		{protoIntAbridged, protoTagAbridged},
		{protoIntIntermediate, protoTagIntermediate},
		{protoIntPaddedIntermediate, protoTagPaddedIntermediate},
	} {
		t.Run(fmt.Sprintf("%x", tc.proto), func(t *testing.T) {
			client, local := net.Pipe()
			remote, telegram := net.Pipe()
			for _, conn := range []net.Conn{client, local, remote, telegram} {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			}
			secret := []byte("0123456789abcdef")
			init := makeClientInit(secret, tc.tag, -4)
			parsed := parseClientHandshake(init, secret)
			relay := generateRelayHandshake(parsed.protoTag, parsed.dcIndex())
			splitter := newMessageSplitter(relay, tc.proto)
			splitter.decryptor = unusedSplitterDecryptor{}
			clientSend := newCTR(sha256Sum(init[8:40], secret), init[40:56])
			clientSend.XORKeyStream(make([]byte, 64), zero64)
			telegramRecv := upstreamPacketDecryptor(relay)
			var packets [][]byte
			for i, size := range []int{4, 512, 40} {
				packets = append(packets, transportPacket(tc.proto, bytes.Repeat([]byte{byte(i + 1)}, size), i != 0))
			}
			stats := &Stats{}
			stopped := make(chan struct{})
			go func() {
				defer close(stopped)
				ws := &rawWebSocket{conn: remote, r: bufio.NewReader(remote)}
				bridgeWS(local, local, func() { _ = local.Close() }, ws,
					buildContext(parsed.prekeyIV, secret, relay), stats, splitter, "plaintext test")
			}()
			peerDone := make(chan error, 1)
			go func() {
				peer := &rawWebSocket{conn: telegram, r: bufio.NewReader(telegram)}
				for i, packet := range packets {
					opcode, data, fin, err := peer.readFrame()
					if err != nil {
						peerDone <- err
						return
					}
					if opcode != wsOpBinary || !fin || !bytes.Equal(protocolCipher(telegramRecv, data), packet) {
						peerDone <- fmt.Errorf("incorrect encrypted packet %d", i)
						return
					}
				}
				peerDone <- nil
			}()
			plain := bytes.Join(packets, nil)
			ciphertext := protocolCipher(clientSend, plain)
			for _, part := range [][]byte{ciphertext[:1], ciphertext[1:3], ciphertext[3:]} {
				if _, err := client.Write(part); err != nil {
					t.Fatal(err)
				}
			}
			if err := <-peerDone; err != nil {
				t.Fatal(err)
			}
			_ = client.Close()
			select {
			case <-stopped:
			case <-time.After(3 * time.Second):
				t.Fatal("plaintext bridge did not stop")
			}
			if stats.bytesUp.Load() != int64(len(plain)) {
				t.Fatal("plaintext bridge changed the upload counter")
			}
		})
	}
}

// Benchmark both upload paths with the same authentic 64KiB transport packet.
// Only the discarded third AES pass and its plaintext allocation differ.
// -tags=purego compares software crypto without relying on desktop AES support.
func BenchmarkUploadSplitterPlaintext(b *testing.B) {
	const size = 65536
	prekey, secret, relay := make([]byte, 48), make([]byte, 16), make([]byte, 64)
	for i := range relay {
		relay[i] = byte(i)
	}
	plain := bytes.Repeat([]byte{42}, size)
	binary.LittleEndian.PutUint32(plain[:4], size-4)
	clientEncrypt := newCTR(sha256Sum(prekey[:32], secret), prekey[32:])
	clientEncrypt.XORKeyStream(make([]byte, 64), zero64)
	input := protocolCipher(clientEncrypt, plain)
	for _, legacy := range []bool{true, false} {
		name := "existing-plaintext"
		if legacy {
			name = "legacy-decrypt"
		}
		b.Run(name, func(b *testing.B) {
			b.SetBytes(size)
			b.ReportAllocs()
			readBuffer := make([]byte, size)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				copy(readBuffer, input)
				ctx := buildContext(prekey, secret, relay)
				splitter := newMessageSplitter(relay, protoIntIntermediate)
				reenc := make([]byte, size)
				var parts [][]byte
				if legacy {
					ctx.clientDecrypt.XORKeyStream(reenc, readBuffer)
					ctx.upstreamEncrypt.XORKeyStream(reenc, reenc)
					parts = splitter.split(reenc)
				} else {
					ctx.clientDecrypt.XORKeyStream(readBuffer, readBuffer)
					ctx.upstreamEncrypt.XORKeyStream(reenc, readBuffer)
					parts = splitter.splitPlain(reenc, readBuffer)
				}
				if len(parts) != 1 || len(parts[0]) != size {
					b.Fatal("upload splitter changed packet boundaries")
				}
			}
		})
	}
}
