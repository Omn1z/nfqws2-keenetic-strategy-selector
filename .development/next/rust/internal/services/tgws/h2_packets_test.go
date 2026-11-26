package tgws

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"testing"
	"testing/iotest"
)

type h2IdentityCipher struct{}

func (h2IdentityCipher) XORKeyStream(dst, src []byte) { copy(dst, src) }

func h2TestCipher() cipher.Stream { return newCTR(bytes.Repeat([]byte{0x5a}, 32), make([]byte, 16)) }

func TestH2ReadPacketEncryptedFragmented(t *testing.T) {
	for _, proto := range []uint32{protoIntAbridged, protoIntIntermediate, protoIntPaddedIntermediate} {
		t.Run(fmt.Sprintf("%x", proto), func(t *testing.T) {
			var packets, bodies [][]byte
			for i, size := range []int{24, 40, 504, 520} {
				body := bytes.Repeat([]byte{byte(i + 1)}, size)
				bodies = append(bodies, body)
				padded := append([]byte(nil), body...)
				if proto == protoIntPaddedIntermediate {
					padded = append(padded, bytes.Repeat([]byte{0xcc}, i*5)...)
				}
				packets = append(packets, transportPacket(proto, padded, i%2 != 0))
			}
			encrypted := protocolCipher(h2TestCipher(), bytes.Join(packets, nil))
			reader := iotest.OneByteReader(bytes.NewReader(encrypted))
			decryptor := h2TestCipher()
			for i, want := range bodies {
				got, quick, err := readH2Packet(reader, decryptor, proto)
				if err != nil || !bytes.Equal(got, want) || quick != (i%2 != 0) {
					t.Fatalf("packet %d: body=%x quick=%t err=%v", i, got, quick, err)
				}
			}
			if _, _, err := readH2Packet(reader, decryptor, proto); err != io.EOF {
				t.Fatalf("missing terminal EOF: %v", err)
			}
		})
	}
}

func TestH2PaddedClearPacketUsesDeclaredMessageLength(t *testing.T) {
	for pad := range h2MaxPlainPadding + 1 {
		body := make([]byte, 28)
		binary.LittleEndian.PutUint32(body[16:20], 8)
		copy(body[20:], "req_pq!!")
		packet := transportPacket(protoIntPaddedIntermediate, append(append([]byte(nil), body...), bytes.Repeat([]byte{0xa5}, pad)...), true)
		got, quick, err := readH2Packet(bytes.NewReader(packet), h2IdentityCipher{}, protoIntPaddedIntermediate)
		if err != nil || !bytes.Equal(got, body) || !quick {
			t.Fatalf("padding %d: got %x quick=%t err=%v", pad, got, quick, err)
		}
	}
}

func TestH2ReadPacketRejectsInvalidFrames(t *testing.T) {
	clear := func(length uint32, pad int) []byte {
		body := make([]byte, 24+pad)
		binary.LittleEndian.PutUint32(body[16:20], length)
		return transportPacket(protoIntPaddedIntermediate, body, false)
	}
	cases := []struct {
		name  string
		proto uint32
		wire  []byte
	}{
		{"unknown protocol", 123, []byte{1}},
		{"short extended prefix", protoIntAbridged, []byte{0xff, 1}},
		{"zero length", protoIntAbridged, []byte{0}},
		{"below minimum", protoIntIntermediate, []byte{20, 0, 0, 0}},
		{"oversized abridged", protoIntAbridged, []byte{0xff, 0xff, 0xff, 0xff}},
		{"oversized intermediate", protoIntIntermediate, []byte{0xff, 0xff, 0xff, 0xff}},
		{"oversized padded", protoIntPaddedIntermediate, []byte{0x01, 0x01, 0x40, 0}},
		{"unaligned", protoIntIntermediate, transportPacket(protoIntIntermediate, make([]byte, 25), false)},
		{"truncated body", protoIntAbridged, []byte{6, 0, 1}},
		{"clear missing data", protoIntPaddedIntermediate, clear(8, 0)},
		{"clear length overflow", protoIntPaddedIntermediate, clear(0xffffffff, 0)},
		{"clear too short", protoIntPaddedIntermediate, clear(0, 0)},
		{"clear excess padding", protoIntPaddedIntermediate, clear(4, h2MaxPlainPadding+1)},
		{"clear unaligned", protoIntPaddedIntermediate, clear(5, 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := readH2Packet(bytes.NewReader(tc.wire), h2IdentityCipher{}, tc.proto); err == nil {
				t.Fatal("invalid frame accepted")
			}
		})
	}
}

func TestH2PaddedClearPacketPreservesDeclaredDataAndPacketBounds(t *testing.T) {
	for _, size := range []int{292, h2MaxPacket, h2MaxPacket + 4} {
		body := make([]byte, size)
		binary.LittleEndian.PutUint32(body[16:20], uint32(size-20))
		copy(body[20:], "message data and declared padding")
		wire := transportPacket(protoIntPaddedIntermediate, append(append([]byte(nil), body...), bytes.Repeat([]byte{0xa5}, h2MaxPlainPadding)...), true)
		got, quick, err := readH2Packet(bytes.NewReader(wire), h2IdentityCipher{}, protoIntPaddedIntermediate)
		if size > h2MaxPacket {
			if err == nil {
				t.Fatal("extended plaintext padding relaxed the MTProto body limit")
			}
		} else if err != nil || !quick || !bytes.Equal(got, body) {
			t.Fatalf("declared data lost: size=%d decoded=%d quick=%v err=%v", size, len(got), quick, err)
		}
	}
	// Encrypted packets have no plaintext message_data_length to consult.
	// Keep their 16-byte cipher-block rounding, not the plaintext allowance.
	body := bytes.Repeat([]byte{0x5a}, 56)
	for pad := 0; pad <= 15; pad++ {
		wire := transportPacket(protoIntPaddedIntermediate, append(append([]byte(nil), body...), bytes.Repeat([]byte{0xa5}, pad)...), false)
		got, _, err := readH2Packet(bytes.NewReader(wire), h2IdentityCipher{}, protoIntPaddedIntermediate)
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("encrypted padding %d: decoded=%d err=%v", pad, len(got), err)
		}
	}
	oversized := bytes.Repeat([]byte{0x5a}, h2MaxPacket+8)
	if _, _, err := readH2Packet(bytes.NewReader(transportPacket(protoIntPaddedIntermediate, oversized, false)), h2IdentityCipher{}, protoIntPaddedIntermediate); err == nil {
		t.Fatal("accepted oversized encrypted body under plaintext padding allowance")
	}
}

func TestH2EncodeReplyWireFormatAndBounds(t *testing.T) {
	for _, proto := range []uint32{protoIntAbridged, protoIntIntermediate, protoIntPaddedIntermediate} {
		for _, size := range []int{4, 24, 504, 508, h2MaxPacket} {
			body := bytes.Repeat([]byte{0x47}, size)
			got, err := encodeH2Reply(body, proto)
			if err != nil {
				t.Fatal(err)
			}
			if proto != protoIntPaddedIntermediate {
				if !bytes.Equal(got, transportPacket(proto, body, false)) {
					t.Fatalf("wire encoding differs: proto=%x size=%d", proto, size)
				}
			} else {
				length := int(binary.LittleEndian.Uint32(got[:4]))
				if length != len(got)-4 || length-size < 0 || length-size > 3 || !bytes.Equal(got[4:4+size], body) {
					t.Fatalf("padded encoding differs: size=%d length=%d", size, length)
				}
			}
		}
		for _, size := range []int{0, 1, 3, 25, h2MaxPacket + 4} {
			if _, err := encodeH2Reply(make([]byte, size), proto); err == nil {
				t.Fatalf("accepted invalid reply size %d", size)
			}
		}
	}
	if _, err := encodeH2Reply(make([]byte, 4), 123); err == nil {
		t.Fatal("accepted unknown protocol")
	}
}
