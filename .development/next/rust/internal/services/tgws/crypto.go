package tgws

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
)

// newCTR builds an AES-CTR keystream cipher. In CTR mode encryption and
// decryption are the same XOR operation, so one type serves both.
func newCTR(key, iv []byte) cipher.Stream {
	block, err := aes.NewCipher(key)
	if err != nil {
		// key length is always 32 here; an error is a programming bug.
		panic("tgws: aes: " + err.Error())
	}
	return cipher.NewCTR(block, iv)
}

// clientHandshake is what we extracted from the client's 64-byte init packet.
type clientHandshake struct {
	dcID     int
	isMedia  bool
	protoTag []byte // 4 bytes
	prekeyIV []byte // 48 bytes, ready to derive client-side keys
}

func (c *clientHandshake) dcIndex() int {
	if c.isMedia {
		return -c.dcID
	}
	return c.dcID
}

func (c *clientHandshake) protoInt() uint32 {
	switch {
	case bytesEqual(c.protoTag, protoTagAbridged):
		return protoIntAbridged
	case bytesEqual(c.protoTag, protoTagIntermediate):
		return protoIntIntermediate
	default:
		return protoIntPaddedIntermediate
	}
}

// parseClientHandshake authenticates and parses a client init packet. Returns
// nil if the secret/proto don't match.
func parseClientHandshake(handshake, secret []byte) *clientHandshake {
	if len(handshake) < handshakeLen {
		return nil
	}
	prekeyIV := make([]byte, prekeyLen+ivLen)
	copy(prekeyIV, handshake[skipLen:skipLen+prekeyLen+ivLen])

	key := sha256Sum(prekeyIV[:prekeyLen], secret)
	iv := append([]byte(nil), prekeyIV[prekeyLen:]...)

	decrypted := make([]byte, handshakeLen)
	newCTR(key, iv).XORKeyStream(decrypted, handshake)

	protoTag := decrypted[protoTagPos : protoTagPos+4]
	if !bytesEqual(protoTag, protoTagAbridged) &&
		!bytesEqual(protoTag, protoTagIntermediate) &&
		!bytesEqual(protoTag, protoTagPaddedIntermediate) {
		return nil
	}

	dcSigned := int16(binary.LittleEndian.Uint16(decrypted[dcIdxPos : dcIdxPos+2]))
	dcID := int(dcSigned)
	isMedia := dcSigned < 0
	if isMedia {
		dcID = -dcID
	}
	return &clientHandshake{
		dcID:     dcID,
		isMedia:  isMedia,
		protoTag: append([]byte(nil), protoTag...),
		prekeyIV: prekeyIV,
	}
}

// generateRelayHandshake builds a fresh 64-byte handshake for the upstream
// Telegram side. The first 56 bytes are random; the last 8 carry the encrypted
// proto tag + DC index.
func generateRelayHandshake(protoTag []byte, dcIdx int) []byte {
	buf := make([]byte, handshakeLen)
	for {
		_, _ = rand.Read(buf)
		if buf[0] == 0xEF {
			continue
		}
		if startsWithReserved(buf[:4]) {
			continue
		}
		if bytesEqual(buf[4:8], reservedContinue) {
			continue
		}
		break
	}

	plain := append([]byte(nil), buf...)
	key := plain[skipLen : skipLen+prekeyLen]
	iv := plain[skipLen+prekeyLen : skipLen+prekeyLen+ivLen]

	enc := newCTR(key, iv)
	encryptedFull := make([]byte, handshakeLen)
	enc.XORKeyStream(encryptedFull, plain)

	// tail = proto tag (4) + dc index (2, signed LE) + random (2)
	tailPlain := make([]byte, 8)
	copy(tailPlain[0:4], protoTag)
	binary.LittleEndian.PutUint16(tailPlain[4:6], uint16(int16(dcIdx)))
	_, _ = rand.Read(tailPlain[6:8])

	out := append([]byte(nil), plain...)
	for i := 0; i < 8; i++ {
		ks := encryptedFull[protoTagPos+i] ^ plain[protoTagPos+i]
		out[protoTagPos+i] = tailPlain[i] ^ ks
	}
	return out
}

// reencryptionContext holds the four AES-CTR streams used to re-encrypt
// bridge traffic.
type reencryptionContext struct {
	clientDecrypt   cipher.Stream // decrypts bytes from the client
	clientEncrypt   cipher.Stream // encrypts bytes to the client
	upstreamEncrypt cipher.Stream // encrypts bytes to Telegram
	upstreamDecrypt cipher.Stream // decrypts bytes from Telegram
}

// buildContext derives all four ciphers from a verified client handshake and
// the freshly generated relay handshake.
func buildContext(clientPrekeyIV, secret, relayHandshake []byte) *reencryptionContext {
	// Client side: authenticated by secret.
	clientDecKey := sha256Sum(clientPrekeyIV[:prekeyLen], secret)
	clientDecIV := append([]byte(nil), clientPrekeyIV[prekeyLen:]...)

	reversed := reverse(clientPrekeyIV)
	clientEncKey := sha256Sum(reversed[:prekeyLen], secret)
	clientEncIV := append([]byte(nil), reversed[prekeyLen:]...)

	clientDecrypt := newCTR(clientDecKey, clientDecIV)
	clientEncrypt := newCTR(clientEncKey, clientEncIV)
	// Fast-forward past the 64 init bytes we already consumed.
	clientDecrypt.XORKeyStream(make([]byte, 64), zero64)

	// Upstream side: raw obfuscation, no secret.
	relayEncKey := relayHandshake[skipLen : skipLen+prekeyLen]
	relayEncIV := relayHandshake[skipLen+prekeyLen : skipLen+prekeyLen+ivLen]
	relayReversed := reverse(relayHandshake[skipLen : skipLen+prekeyLen+ivLen])
	relayDecKey := relayReversed[:keyLen]
	relayDecIV := relayReversed[keyLen:]

	upstreamEncrypt := newCTR(relayEncKey, relayEncIV)
	upstreamDecrypt := newCTR(relayDecKey, relayDecIV)
	upstreamEncrypt.XORKeyStream(make([]byte, 64), zero64)

	return &reencryptionContext{
		clientDecrypt:   clientDecrypt,
		clientEncrypt:   clientEncrypt,
		upstreamEncrypt: upstreamEncrypt,
		upstreamDecrypt: upstreamDecrypt,
	}
}

// upstreamPacketDecryptor returns a fresh decryptor for the upstream encrypted
// stream, in lockstep with upstreamEncrypt. Used by messageSplitter to peek
// packet lengths without disturbing the main upstreamEncrypt stream.
func upstreamPacketDecryptor(relayHandshake []byte) cipher.Stream {
	key := relayHandshake[skipLen : skipLen+prekeyLen]
	iv := relayHandshake[skipLen+prekeyLen : skipLen+prekeyLen+ivLen]
	dec := newCTR(key, iv)
	dec.XORKeyStream(make([]byte, 64), zero64)
	return dec
}

// --- small helpers -------------------------------------------------------

func sha256Sum(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func startsWithReserved(first4 []byte) bool {
	for _, r := range reservedStarts {
		if bytesEqual(first4, r) {
			return true
		}
	}
	return false
}
