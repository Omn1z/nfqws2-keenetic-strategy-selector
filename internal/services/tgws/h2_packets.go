package tgws

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

const h2MaxPacket = 4 * 1024 * 1024

// readH2Packet removes only the client's transport encryption and framing.
// The enclosed MTProto message (including its end-to-end encryption) goes
// unchanged to /api, without the WebSocket relay's obfuscation handshake.
func readH2Packet(reader io.Reader, decryptor cipher.Stream, proto uint32) ([]byte, bool, error) {
	plaintext := func(dst []byte) error {
		if _, err := io.ReadFull(reader, dst); err != nil {
			return err
		}
		decryptor.XORKeyStream(dst, dst)
		return nil
	}
	var header [4]byte
	var length uint64
	var quick bool
	switch proto {
	case protoIntAbridged:
		if err := plaintext(header[:1]); err != nil {
			return nil, false, err
		}
		quick = header[0]&0x80 != 0
		words := uint32(header[0] & 0x7f)
		if words == 0x7f {
			if err := plaintext(header[:3]); err != nil {
				return nil, false, err
			}
			words = uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16
		}
		length = uint64(words) * 4
	case protoIntIntermediate, protoIntPaddedIntermediate:
		if err := plaintext(header[:]); err != nil {
			return nil, false, err
		}
		value := binary.LittleEndian.Uint32(header[:])
		quick, length = value&0x80000000 != 0, uint64(value&0x7fffffff)
	default:
		return nil, false, fmt.Errorf("unsupported native MTProto transport: %x", proto)
	}
	limit := uint64(h2MaxPacket)
	if proto == protoIntPaddedIntermediate {
		limit += 15
	}
	if length < 24 || length > limit {
		return nil, false, fmt.Errorf("native packet length outside supported range: %d", length)
	}
	body := make([]byte, int(length))
	if err := plaintext(body); err != nil {
		return nil, false, err
	}
	if proto == protoIntPaddedIntermediate {
		packetLength := uint64(24) + (length-24)/16*16
		if binary.LittleEndian.Uint64(body[:8]) == 0 {
			packetLength = 20 + uint64(binary.LittleEndian.Uint32(body[16:20]))
		}
		if packetLength < 24 || packetLength > length || length-packetLength > 15 {
			return nil, false, fmt.Errorf("invalid padded native packet")
		}
		body = body[:int(packetLength)]
	}
	if len(body)%4 != 0 || len(body) > h2MaxPacket {
		return nil, false, fmt.Errorf("invalid native packet alignment or size")
	}
	return body, quick, nil
}

func encodeH2Reply(body []byte, proto uint32) ([]byte, error) {
	if len(body) == 0 || len(body)%4 != 0 || len(body) > h2MaxPacket {
		return nil, fmt.Errorf("invalid HTTP MTProto response length: %d", len(body))
	}
	if proto == protoIntAbridged {
		words := len(body) / 4
		if words < 0x7f {
			return append([]byte{byte(words)}, body...), nil
		}
		return append([]byte{0x7f, byte(words), byte(words >> 8), byte(words >> 16)}, body...), nil
	}
	if proto != protoIntIntermediate && proto != protoIntPaddedIntermediate {
		return nil, fmt.Errorf("unsupported native MTProto transport: %x", proto)
	}
	var padding [4]byte
	padLen := 0
	if proto == protoIntPaddedIntermediate {
		if _, err := rand.Read(padding[:]); err != nil {
			return nil, err
		}
		padLen = int(padding[0] % 4)
	}
	out := make([]byte, 4+len(body)+padLen)
	binary.LittleEndian.PutUint32(out[:4], uint32(len(body)+padLen))
	copy(out[4:], body)
	copy(out[4+len(body):], padding[1:1+padLen])
	return out, nil
}
