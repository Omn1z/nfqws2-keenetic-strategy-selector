package tgws

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"time"
)

var ccsFrame = []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}

// serverHelloTemplate is a fixed TLS 1.3 ServerHello skeleton; server_random,
// session_id echo and the x25519 pubkey are filled in per connection.
var serverHelloTemplate = func() []byte {
	var b []byte
	b = append(b, 0x16, 0x03, 0x03, 0x00, 0x7a)                   // record header (len 122)
	b = append(b, 0x02, 0x00, 0x00, 0x76)                         // ServerHello, len 118
	b = append(b, 0x03, 0x03)                                     // legacy_version
	b = append(b, make([]byte, 32)...)                            // server_random  (offset 11)
	b = append(b, 0x20)                                           // session_id len = 32
	b = append(b, make([]byte, 32)...)                            // session_id echo (offset 44)
	b = append(b, 0x13, 0x01, 0x00)                               // cipher 0x1301 + compression
	b = append(b, 0x00, 0x2e)                                     // extensions length 46
	b = append(b, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20) // key_share
	b = append(b, make([]byte, 32)...)                            // x25519 pubkey  (offset 89)
	b = append(b, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04)             // supported_versions: TLS 1.3
	return b
}()

const (
	shRandomOffset  = 11
	shSessionOffset = 44
	shPubkeyOffset  = 89
)

// verifyClientHello returns (client_random, session_id, ok) if the ClientHello
// is an authentic Telegram Fake-TLS hello for our secret.
func verifyClientHello(data, secret []byte) (clientRandom, sessionID []byte, ok bool) {
	if len(data) < 43 {
		return nil, nil, false
	}
	if data[0] != tlsRecordHandshake || data[5] != 0x01 {
		return nil, nil, false
	}
	clientRandom = append([]byte(nil), data[clientRandomOffset:clientRandomOffset+clientRandomLen]...)

	zeroed := append([]byte(nil), data...)
	for i := 0; i < clientRandomLen; i++ {
		zeroed[clientRandomOffset+i] = 0
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(zeroed)
	expected := mac.Sum(nil)
	if !hmac.Equal(expected[:28], clientRandom[:28]) {
		return nil, nil, false
	}

	var tsXor [4]byte
	for i := 0; i < 4; i++ {
		tsXor[i] = clientRandom[28+i] ^ expected[28+i]
	}
	ts := int64(binary.LittleEndian.Uint32(tsXor[:]))
	if diff := time.Now().Unix() - ts; diff > timestampTolerance || diff < -timestampTolerance {
		return nil, nil, false
	}

	sessionID = make([]byte, sessionIDLen)
	if len(data) >= sessionIDOffset+sessionIDLen && data[43] == sessionIDLen {
		copy(sessionID, data[sessionIDOffset:sessionIDOffset+sessionIDLen])
	}
	return clientRandom, sessionID, true
}

// buildServerHello forges a ServerHello + dummy AppData whose server_random
// authenticates against the client's HMAC.
func buildServerHello(secret, clientRandom, sessionID []byte) []byte {
	hello := append([]byte(nil), serverHelloTemplate...)
	copy(hello[shSessionOffset:shSessionOffset+32], sessionID)
	pub := make([]byte, 32)
	_, _ = rand.Read(pub)
	copy(hello[shPubkeyOffset:shPubkeyOffset+32], pub)

	appdataSize := 1900 + randInt(201)
	appdata := make([]byte, appdataSize)
	_, _ = rand.Read(appdata)
	appRecord := make([]byte, 0, 5+appdataSize)
	appRecord = append(appRecord, 0x17, 0x03, 0x03)
	appRecord = appendU16BE(appRecord, appdataSize)
	appRecord = append(appRecord, appdata...)

	response := make([]byte, 0, len(hello)+len(ccsFrame)+len(appRecord))
	response = append(response, hello...)
	response = append(response, ccsFrame...)
	response = append(response, appRecord...)

	mac := hmac.New(sha256.New, secret)
	mac.Write(clientRandom)
	mac.Write(response)
	serverRandom := mac.Sum(nil)
	copy(response[shRandomOffset:shRandomOffset+32], serverRandom)
	return response
}

// wrapTLSRecords chops a buffer into TLS Application Data records of <=16KB.
func wrapTLSRecords(data []byte) []byte {
	var out []byte
	for off := 0; off < len(data); off += tlsAppDataMax {
		end := off + tlsAppDataMax
		if end > len(data) {
			end = len(data)
		}
		chunk := data[off:end]
		out = append(out, 0x17, 0x03, 0x03)
		out = appendU16BE(out, len(chunk))
		out = append(out, chunk...)
	}
	return out
}

// fakeTLSStream hides TLS record framing: reads strip app-data record headers,
// writes wrap data into records. It satisfies io.Reader/io.Writer so the rest
// of the handler (and io.ReadFull) can treat it like a plain stream.
type fakeTLSStream struct {
	r          *bufio.Reader
	w          net.Conn
	pending    []byte
	recordLeft int
}

func newFakeTLSStream(r *bufio.Reader, w net.Conn) *fakeTLSStream {
	return &fakeTLSStream{r: r, w: w}
}

func (s *fakeTLSStream) Read(p []byte) (int, error) {
	if len(s.pending) == 0 {
		chunk, err := s.readRecordChunk()
		if err != nil {
			return 0, err
		}
		if len(chunk) == 0 {
			return 0, io.EOF
		}
		s.pending = chunk
	}
	n := copy(p, s.pending)
	s.pending = s.pending[n:]
	return n, nil
}

func (s *fakeTLSStream) readRecordChunk() ([]byte, error) {
	if s.recordLeft > 0 {
		n := s.recordLeft
		if n > 65536 {
			n = 65536
		}
		buf := make([]byte, n)
		m, err := s.r.Read(buf)
		if m > 0 {
			s.recordLeft -= m
			return buf[:m], nil
		}
		return nil, err
	}
	for {
		header := make([]byte, 5)
		if _, err := io.ReadFull(s.r, header); err != nil {
			return nil, err
		}
		recType := header[0]
		recLen := int(binary.BigEndian.Uint16(header[3:5]))
		if recType == tlsRecordCCS {
			if recLen > 0 {
				if _, err := io.CopyN(io.Discard, s.r, int64(recLen)); err != nil {
					return nil, err
				}
			}
			continue
		}
		if recType != tlsRecordAppData {
			return nil, io.EOF
		}
		n := recLen
		if n > 65536 {
			n = 65536
		}
		buf := make([]byte, n)
		m, err := s.r.Read(buf)
		if m == 0 {
			return nil, err
		}
		if recLen-m > 0 {
			s.recordLeft = recLen - m
		}
		return buf[:m], nil
	}
}

func (s *fakeTLSStream) Write(p []byte) (int, error) {
	if _, err := s.w.Write(wrapTLSRecords(p)); err != nil {
		return 0, err
	}
	return len(p), nil
}

// relayToMaskingDomain tunnels the client to a real HTTPS site when Fake-TLS
// auth fails, forwarding the bytes already read (the client hello) first.
func relayToMaskingDomain(client io.ReadWriter, initial []byte, domain string) {
	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(domain, "443"), 10*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()
	if len(initial) > 0 {
		if _, err := upstream.Write(initial); err != nil {
			return
		}
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstream); done <- struct{}{} }()
	<-done
}

// --- helpers -------------------------------------------------------------

func appendU16BE(b []byte, v int) []byte {
	return append(b, byte(v>>8), byte(v))
}

func randInt(n int) int {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}
