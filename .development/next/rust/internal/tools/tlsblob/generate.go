// Package tlsblob builds and extracts TLS ClientHello byte blobs for use as
// nfqws2 fake payloads (--blob=name:@file). A blob is a raw TLS record
// (0x16 0x03 .. handshake) carrying a ClientHello with a chosen SNI — exactly
// what the engine injects as a fake packet to confuse DPI.
package tlsblob

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

// GenerateClientHello builds a real TLS ClientHello record for the given SNI by
// running a stdlib TLS client over an in-memory connection and capturing its
// first flight. alpn (e.g. ["h2","http/1.1"]) and minVer (tls.VersionTLS1x; 0 =
// library default) are optional. The bytes are format-compatible with captured
// hellos (5-byte record header + handshake), ready to save as a blob.
func GenerateClientHello(sni string, alpn []string, minVer uint16) ([]byte, error) {
	sni = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(sni), "."))
	if sni == "" {
		return nil, errors.New("укажите домен (SNI)")
	}
	if net.ParseIP(sni) != nil {
		return nil, errors.New("SNI должен быть доменом, а не IP-адресом")
	}
	cc := &captureConn{}
	c := tls.Client(cc, &tls.Config{
		ServerName:         sni,
		NextProtos:         alpn,
		MinVersion:         minVer,
		InsecureSkipVerify: true, // we never reach verification; handshake aborts after the hello
	})
	_ = c.Handshake() // writes the ClientHello, then our Read returns EOF and aborts
	if len(cc.written) < 6 || cc.written[0] != 0x16 {
		return nil, errors.New("не удалось собрать ClientHello")
	}
	return cc.written, nil
}

// captureConn is a net.Conn that records everything written (the ClientHello)
// and returns EOF on read so tls.Client.Handshake stops after the first flight.
type captureConn struct{ written []byte }

func (c *captureConn) Write(p []byte) (int, error) {
	c.written = append(c.written, p...)
	return len(p), nil
}
func (c *captureConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) LocalAddr() net.Addr              { return emptyAddr{} }
func (c *captureConn) RemoteAddr() net.Addr             { return emptyAddr{} }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }

type emptyAddr struct{}

func (emptyAddr) Network() string { return "tls-capture" }
func (emptyAddr) String() string  { return "tls-capture" }
