// Package tgws is a Telegram MTProto -> WebSocket proxy, ported from the
// Python tg-ws-keenetic project. It runs in-process alongside the strategy
// selector and is controlled from the "TG WS Proxy" web tab.
//
// A client speaks obfuscated MTProto (optionally wrapped in Fake TLS) to our
// TCP listener; we authenticate the handshake with the configured secret,
// re-encrypt the stream, and relay it to Telegram over a WSS connection to
// kws*.web.telegram.org (with CF/TCP fallbacks). Payload bytes are never seen
// in plaintext: they are decrypted with the client key and immediately
// re-encrypted with the upstream key.
package tgws

// --- MTProto obfuscation handshake ---------------------------------------

const (
	handshakeLen = 64
	skipLen      = 8
	prekeyLen    = 32
	keyLen       = 32
	ivLen        = 16
	protoTagPos  = 56
	dcIdxPos     = 60
)

var (
	protoTagAbridged           = []byte{0xef, 0xef, 0xef, 0xef}
	protoTagIntermediate       = []byte{0xee, 0xee, 0xee, 0xee}
	protoTagPaddedIntermediate = []byte{0xdd, 0xdd, 0xdd, 0xdd}
)

const (
	protoIntAbridged           = 0xEFEFEFEF
	protoIntIntermediate       = 0xEEEEEEEE
	protoIntPaddedIntermediate = 0xDDDDDDDD
)

// zero64 is 64 zero bytes used to fast-forward an AES-CTR stream past the
// already-consumed init packet.
var zero64 = make([]byte, 64)

// Bytes/patterns that must NOT appear at the start of a relay handshake,
// because Telegram protocol detection uses them as markers for HTTP, TLS etc.
var reservedStarts = [][]byte{
	{0x48, 0x45, 0x41, 0x44}, // "HEAD"
	{0x50, 0x4f, 0x53, 0x54}, // "POST"
	{0x47, 0x45, 0x54, 0x20}, // "GET "
	{0xee, 0xee, 0xee, 0xee},
	{0xdd, 0xdd, 0xdd, 0xdd},
	{0x16, 0x03, 0x01, 0x02}, // TLS record header
}

var reservedContinue = []byte{0x00, 0x00, 0x00, 0x00}

// dcDefaultIPs are used as the final TCP fallback when WS is unreachable.
var dcDefaultIPs = map[int]string{
	1:   "149.154.175.50",
	2:   "149.154.167.51",
	3:   "149.154.175.100",
	4:   "149.154.167.91",
	5:   "149.154.171.5",
	203: "91.105.192.100",
}

// dcIDs are the valid DC numbers we route to.
var dcIDs = []int{1, 2, 3, 4, 5, 203}

// --- TLS record types ----------------------------------------------------

const (
	tlsRecordCCS       = 0x14
	tlsRecordHandshake = 0x16
	tlsRecordAppData   = 0x17
	tlsAppDataMax      = 16384
)

// --- Fake TLS handshake layout ------------------------------------------

const (
	clientRandomOffset = 11
	clientRandomLen    = 32
	sessionIDOffset    = 44
	sessionIDLen       = 32
	timestampTolerance = 120 // seconds
)

// --- WebSocket -----------------------------------------------------------

const (
	wsOpCont   = 0x0
	wsOpText   = 0x1
	wsOpBinary = 0x2
	wsOpClose  = 0x8
	wsOpPing   = 0x9
	wsOpPong   = 0xA

	wsFinBit  = 0x80
	wsMaskBit = 0x80
)
