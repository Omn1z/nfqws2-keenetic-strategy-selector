package tgws

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"
)

// makeClientInit builds a 64-byte obf2 init packet the way a Telegram client
// would: the proto tag + DC index tail is encrypted with the secret-derived
// keystream, so the server's parseClientHandshake must recover them.
func makeClientInit(secret, protoTag []byte, dcIdx int) []byte {
	buf := make([]byte, 64)
	_, _ = rand.Read(buf)
	key := sha256Sum(buf[8:40], secret)
	iv := append([]byte(nil), buf[40:56]...)
	full := make([]byte, 64)
	newCTR(key, iv).XORKeyStream(full, buf)

	tail := make([]byte, 8)
	copy(tail[0:4], protoTag)
	binary.LittleEndian.PutUint16(tail[4:6], uint16(int16(dcIdx)))

	out := append([]byte(nil), buf...)
	for i := 0; i < 8; i++ {
		ks := full[56+i] ^ buf[56+i]
		out[56+i] = tail[i] ^ ks
	}
	return out
}

func TestParseClientHandshake(t *testing.T) {
	secret := make([]byte, 16)
	_, _ = rand.Read(secret)

	cases := []struct {
		tag   []byte
		dcIdx int
		media bool
		dc    int
	}{
		{protoTagAbridged, 2, false, 2},
		{protoTagIntermediate, -4, true, 4},
		{protoTagPaddedIntermediate, 1, false, 1},
		{protoTagAbridged, -2, true, 2},
	}
	for _, c := range cases {
		init := makeClientInit(secret, c.tag, c.dcIdx)
		got := parseClientHandshake(init, secret)
		if got == nil {
			t.Fatalf("parse returned nil for dc=%d tag=%x", c.dcIdx, c.tag)
		}
		if got.dcID != c.dc || got.isMedia != c.media {
			t.Errorf("dc/media mismatch: got dc=%d media=%v want dc=%d media=%v", got.dcID, got.isMedia, c.dc, c.media)
		}
		if !bytesEqual(got.protoTag, c.tag) {
			t.Errorf("proto tag mismatch: got %x want %x", got.protoTag, c.tag)
		}
	}

	// Wrong secret must fail to authenticate.
	init := makeClientInit(secret, protoTagAbridged, 2)
	bad := make([]byte, 16)
	_, _ = rand.Read(bad)
	if parseClientHandshake(init, bad) != nil {
		t.Error("parse accepted a packet under the wrong secret")
	}
}

func TestRelayHandshakeConstraints(t *testing.T) {
	for i := 0; i < 200; i++ {
		h := generateRelayHandshake(protoTagAbridged, 2)
		if len(h) != 64 {
			t.Fatalf("relay handshake len = %d", len(h))
		}
		if h[0] == 0xEF {
			t.Error("relay handshake starts with reserved 0xEF")
		}
		if startsWithReserved(h[:4]) {
			t.Error("relay handshake starts with a reserved 4-byte marker")
		}
		if bytesEqual(h[4:8], reservedContinue) {
			t.Error("relay handshake has reserved continuation bytes")
		}
	}
}

// The MessageSplitter's packet decryptor must stay byte-for-byte in lockstep
// with upstreamEncrypt so it can read plaintext packet lengths out of the
// re-encrypted stream.
func TestUpstreamSplitterSync(t *testing.T) {
	relay := generateRelayHandshake(protoTagIntermediate, 2)

	enc := newCTR(relay[skipLen:skipLen+prekeyLen], relay[skipLen+prekeyLen:skipLen+prekeyLen+ivLen])
	enc.XORKeyStream(make([]byte, 64), zero64) // skip the init bytes, like upstreamEncrypt
	dec := upstreamPacketDecryptor(relay)

	payload := []byte("the quick brown fox jumps over the lazy MTProto packet boundary")
	ct := make([]byte, len(payload))
	enc.XORKeyStream(ct, payload)
	pt := make([]byte, len(ct))
	dec.XORKeyStream(pt, ct)
	if !bytes.Equal(pt, payload) {
		t.Fatalf("splitter decryptor out of sync:\n got %q\nwant %q", pt, payload)
	}
}

func makeClientHello(secret []byte, ts uint32) []byte {
	data := make([]byte, sessionIDOffset+sessionIDLen)
	data[0] = tlsRecordHandshake
	data[5] = 0x01
	data[43] = sessionIDLen
	_, _ = rand.Read(data[sessionIDOffset : sessionIDOffset+sessionIDLen])

	// random zeroed for the HMAC computation
	for i := 0; i < clientRandomLen; i++ {
		data[clientRandomOffset+i] = 0
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(data)
	expected := mac.Sum(nil)

	copy(data[clientRandomOffset:clientRandomOffset+28], expected[:28])
	var tsb [4]byte
	binary.LittleEndian.PutUint32(tsb[:], ts)
	for i := 0; i < 4; i++ {
		data[clientRandomOffset+28+i] = tsb[i] ^ expected[28+i]
	}
	return data
}

func TestFakeTLSVerifyAndServerHello(t *testing.T) {
	secret := make([]byte, 16)
	_, _ = rand.Read(secret)

	hello := makeClientHello(secret, uint32(time.Now().Unix()))
	cr, sid, ok := verifyClientHello(hello, secret)
	if !ok {
		t.Fatal("verifyClientHello rejected a valid hello")
	}
	if len(cr) != 32 || len(sid) != 32 {
		t.Fatalf("bad lengths: cr=%d sid=%d", len(cr), len(sid))
	}

	// Stale timestamp must be rejected.
	stale := makeClientHello(secret, uint32(time.Now().Unix()-10*timestampTolerance))
	if _, _, ok := verifyClientHello(stale, secret); ok {
		t.Error("verifyClientHello accepted a stale timestamp")
	}

	// ServerHello must carry an HMAC-consistent server_random.
	resp := buildServerHello(secret, cr, sid)
	if len(resp) < shRandomOffset+32 {
		t.Fatalf("server hello too short: %d", len(resp))
	}
	gotRandom := append([]byte(nil), resp[shRandomOffset:shRandomOffset+32]...)
	zeroed := append([]byte(nil), resp...)
	for i := 0; i < 32; i++ {
		zeroed[shRandomOffset+i] = 0
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(cr)
	mac.Write(zeroed)
	if !hmac.Equal(mac.Sum(nil), gotRandom) {
		t.Error("server_random is not HMAC-consistent")
	}
	// session id must be echoed back.
	if !bytes.Equal(resp[shSessionOffset:shSessionOffset+32], sid) {
		t.Error("server hello did not echo the session id")
	}
}
