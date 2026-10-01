package tgws

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

type wsTrustAuthority struct {
	certificate *x509.Certificate
	key         ed25519.PrivateKey
}

func newWSTrustAuthority(t *testing.T, serial int64) wsTrustAuthority {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return wsTrustAuthority{certificate: certificate, key: privateKey}
}

func (ca wsTrustAuthority) roots() *x509.CertPool {
	roots := x509.NewCertPool()
	roots.AddCert(ca.certificate)
	return roots
}

func (ca wsTrustAuthority) issue(t *testing.T, domain string, expired bool) tls.Certificate {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notBefore, notAfter := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	if expired {
		notBefore, notAfter = time.Now().Add(-3*time.Hour), time.Now().Add(-2*time.Hour)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		DNSNames:     []string{domain},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, publicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.certificate.Raw}, PrivateKey: privateKey}
}

type wsTrustPeerResult struct {
	sni       string
	request   string
	didResume bool
	version   uint16
	err       error
}

// The private CA exists only in the supplied pool. This fixture neither reads
// the host's system trust nor changes the process-wide router CA singleton.
func startWSTrustPeer(t *testing.T, certificate tls.Certificate) (address string, finished <-chan wsTrustPeerResult) {
	return startWSTrustPeers(t, certificate, 1, 0)
}

func startWSTrustPeers(t *testing.T, certificate tls.Certificate, count int, version uint16) (address string, finished <-chan wsTrustPeerResult) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	config := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	if version != 0 {
		config.MinVersion, config.MaxVersion = version, version
	}
	done := make(chan wsTrustPeerResult, count)
	go func() {
		for i := 0; i < count; i++ {
			raw, acceptErr := ln.Accept()
			if acceptErr != nil {
				done <- wsTrustPeerResult{err: acceptErr}
				return
			}
			done <- serveWSTrustPeer(raw, config)
		}
	}()
	return ln.Addr().String(), done
}

func serveWSTrustPeer(raw net.Conn, config *tls.Config) (result wsTrustPeerResult) {
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(2 * time.Second))
	conn := tls.Server(raw, config)
	if result.err = conn.Handshake(); result.err != nil {
		return result
	}
	state := conn.ConnectionState()
	result.sni, result.didResume, result.version = state.ServerName, state.DidResume, state.Version
	reader := bufio.NewReader(conn)
	var request strings.Builder
	for {
		line, readErr := reader.ReadString('\n')
		request.WriteString(line)
		if readErr != nil {
			result.err = readErr
			return result
		}
		if line == "\r\n" {
			break
		}
	}
	result.request = request.String()
	if _, result.err = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"); result.err != nil {
		return result
	}
	peer := &rawWebSocket{conn: conn, r: reader}
	opcode, data, fin, frameErr := peer.readFrame()
	if frameErr != nil {
		result.err = frameErr
		return result
	}
	if opcode != wsOpBinary || !fin || string(data) != "trusted request" {
		result.err = fmt.Errorf("unexpected encrypted WS frame: opcode=%d fin=%t payload=%q", opcode, fin, data)
		return result
	}
	_, result.err = conn.Write(serverFrame(wsOpBinary, []byte("trusted response"), true))
	return result
}

func awaitWSTrustPeer(t *testing.T, finished <-chan wsTrustPeerResult) wsTrustPeerResult {
	t.Helper()
	select {
	case result := <-finished:
		return result
	case <-time.After(4 * time.Second):
		t.Fatal("local TLS peer did not finish")
		return wsTrustPeerResult{}
	}
}

func TestConnectWSOrdinaryUsesExplicitTrustedRoots(t *testing.T) {
	const domain = "telegram.test"
	ca := newWSTrustAuthority(t, 1)
	address, finished := startWSTrustPeer(t, ca.issue(t, domain, false))
	roots := ca.roots()
	template := &tls.Config{
		RootCAs:            roots,
		ServerName:         "template-must-stay-unchanged.test",
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
	ws, err := connectWSWithTLSConfig(context.Background(), address, domain, 2*time.Second, "/apiws", 0, domain, true, template)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.close()
	if err := ws.send([]byte("trusted request")); err != nil {
		t.Fatal(err)
	}
	response, err := ws.recv()
	if err != nil || string(response) != "trusted response" {
		t.Fatalf("trusted ordinary WS roundtrip: payload=%q err=%v", response, err)
	}
	result := awaitWSTrustPeer(t, finished)
	if result.err != nil || result.sni != domain || !strings.Contains(result.request, "Host: "+domain+"\r\n") {
		t.Fatalf("ordinary TLS request: %+v", result)
	}
	if template.RootCAs != roots || template.ServerName != "template-must-stay-unchanged.test" || !template.InsecureSkipVerify || template.MinVersion != tls.VersionTLS12 {
		t.Fatal("connection mutated the shared TLS template")
	}
}

func TestConnectWSOrdinaryRejectsInvalidCertificatesWithoutBypass(t *testing.T) {
	const domain = "telegram.test"
	ca, foreign := newWSTrustAuthority(t, 2), newWSTrustAuthority(t, 3)
	for _, tc := range []struct {
		name   string
		roots  *x509.CertPool
		cert   tls.Certificate
		reason string
	}{
		{"empty roots", x509.NewCertPool(), ca.issue(t, domain, false), "authority"},
		{"foreign authority", foreign.roots(), ca.issue(t, domain, false), "authority"},
		{"wrong hostname", ca.roots(), ca.issue(t, "other.test", false), "hostname"},
		{"expired certificate", ca.roots(), ca.issue(t, domain, true), "expired"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			address, finished := startWSTrustPeer(t, tc.cert)
			// A caller's insecure template must not turn an ordinary endpoint
			// into implicit fronting or bypass verification after a failure.
			template := &tls.Config{RootCAs: tc.roots, InsecureSkipVerify: true}
			ws, err := connectWSWithTLSConfig(context.Background(), address, domain, 2*time.Second, "/apiws", 0, domain, true, template)
			if ws != nil {
				_ = ws.close()
				t.Fatal("ordinary endpoint accepted an invalid certificate")
			}
			if err == nil {
				t.Fatal("missing certificate verification failure")
			}
			switch tc.reason {
			case "authority":
				var failure x509.UnknownAuthorityError
				if !errors.As(err, &failure) {
					t.Fatalf("want unknown authority rejection, got %v", err)
				}
			case "hostname":
				var failure x509.HostnameError
				if !errors.As(err, &failure) {
					t.Fatalf("want hostname rejection, got %v", err)
				}
			case "expired":
				var failure x509.CertificateInvalidError
				if !errors.As(err, &failure) || failure.Reason != x509.Expired {
					t.Fatalf("want expired certificate rejection, got %v", err)
				}
			}
			result := awaitWSTrustPeer(t, finished)
			if result.err == nil || result.request != "" {
				t.Fatalf("HTTP upgrade reached a rejected TLS peer: %+v", result)
			}
			if template.RootCAs != tc.roots || !template.InsecureSkipVerify || template.ServerName != "" {
				t.Fatal("verification failure mutated the shared TLS template")
			}
		})
	}
}

func TestConnectWSOrdinaryReusesTLSSessionCache(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			const domain = "telegram.test"
			ca := newWSTrustAuthority(t, 4)
			address, finished := startWSTrustPeers(t, ca.issue(t, domain, false), 2, version)
			template := &tls.Config{
				RootCAs:            ca.roots(),
				ClientSessionCache: tls.NewLRUClientSessionCache(4),
				MinVersion:         version,
				MaxVersion:         version,
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			for i := 0; i < 2; i++ {
				ws, err := connectWSWithTLSConfig(ctx, address, domain, time.Second, "/apiws", 0, domain, true, template)
				if err != nil {
					t.Fatalf("connection %d: %v", i+1, err)
				}
				if err := ws.send([]byte("trusted request")); err != nil {
					_ = ws.close()
					t.Fatal(err)
				}
				// Reading application data also consumes the TLS 1.3 session
				// ticket sent after the handshake. Both versions must carry a
				// real WS response after resuming, not just finish a handshake.
				response, err := ws.recv()
				_ = ws.close()
				if err != nil || string(response) != "trusted response" {
					t.Fatalf("connection %d response: %q %v", i+1, response, err)
				}
				result := awaitWSTrustPeer(t, finished)
				if result.err != nil || result.version != version || result.didResume != (i == 1) {
					t.Fatalf("connection %d resumption: %+v", i+1, result)
				}
			}
		})
	}
}
