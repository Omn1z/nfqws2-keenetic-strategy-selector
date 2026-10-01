package tlsroots

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
	pem  []byte
}

func makeTestCA(t *testing.T, name string) testCA {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func writeCAFile(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func testPool(cas ...testCA) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, ca := range cas {
		pool.AddCert(ca.cert)
	}
	return pool
}

func assertTrusted(t *testing.T, roots *x509.CertPool, ca testCA) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), DNSNames: []string{"telegram.example"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Minute),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: "telegram.example"}); err != nil {
		t.Fatalf("CA %q was not trusted: %v", ca.cert.Subject.CommonName, err)
	}
}

func TestIndividualCertificatesWithoutBundle(t *testing.T) {
	etc := t.TempDir()
	ca := makeTestCA(t, "Entware individual CA")
	unrelated := makeTestCA(t, "unrelated extension CA")
	certDir := filepath.Join(etc, "ssl", "certs")
	writeCAFile(t, filepath.Join(certDir, "root.CRT"), ca.pem)
	writeCAFile(t, filepath.Join(certDir, "broken.crt"), []byte("not a certificate"))
	writeCAFile(t, filepath.Join(certDir, "unrelated.txt"), unrelated.pem)
	if err := os.Mkdir(filepath.Join(certDir, "directory.pem"), 0700); err != nil {
		t.Fatal(err)
	}
	native := x509.NewCertPool()
	l := newLoader(func() (*x509.CertPool, error) { return native, nil }, func(string) string { return "" }, func() string { return filepath.Join(etc, "ssl", "certs") })
	roots := l.pool()
	if !roots.Equal(testPool(ca)) {
		t.Fatal("individual CA was missing or an unrelated file was trusted")
	}
	if !native.Equal(x509.NewCertPool()) {
		t.Fatal("native pool was mutated")
	}
	assertTrusted(t, roots, ca)
}

func TestBundlesPreserveNativeRootsAndDeduplicate(t *testing.T) {
	etc := t.TempDir()
	nativeCA := makeTestCA(t, "native CA")
	certPEM := makeTestCA(t, "cert.pem CA")
	bundlePEM := makeTestCA(t, "ca-bundle.pem CA")
	certBundle := makeTestCA(t, "ca-certificates.crt CA")
	native := testPool(nativeCA)
	writeCAFile(t, filepath.Join(etc, "ssl", "cert.pem"), certPEM.pem)
	writeCAFile(t, filepath.Join(etc, "ssl", "ca-bundle.pem"), bundlePEM.pem)
	writeCAFile(t, filepath.Join(etc, "ssl", "certs", "ca-certificates.crt"), append(append([]byte(nil), certBundle.pem...), nativeCA.pem...))
	writeCAFile(t, filepath.Join(etc, "ssl", "certs", "duplicate.crt"), certBundle.pem)
	l := newLoader(func() (*x509.CertPool, error) { return native, nil }, func(string) string { return "" }, func() string { return filepath.Join(etc, "ssl", "certs") })
	roots := l.pool()
	if !roots.Equal(testPool(nativeCA, certPEM, bundlePEM, certBundle)) {
		t.Fatal("bundle roots were missing, duplicated, or replaced native roots")
	}
	if !native.Equal(testPool(nativeCA)) {
		t.Fatal("native roots were mutated by platform loading")
	}
	for _, ca := range []testCA{nativeCA, certPEM, bundlePEM, certBundle} {
		assertTrusted(t, roots, ca)
	}
}

func TestExplicitEnvironmentOverridesDoNotAddPlatformRoots(t *testing.T) {
	etc := t.TempDir()
	platformCA := makeTestCA(t, "platform CA")
	overrideCA := makeTestCA(t, "explicit CA")
	writeCAFile(t, filepath.Join(etc, "ssl", "certs", "root.crt"), platformCA.pem)
	for _, tc := range []struct {
		name, file, dir string
	}{
		{"file", "explicit.pem", ""},
		{"directory", "", "explicit-certs"},
		{"both", "explicit.pem", "explicit-certs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			etcCalls := 0
			l := newLoader(func() (*x509.CertPool, error) { return testPool(overrideCA), nil }, func(key string) string {
				if key == "SSL_CERT_FILE" {
					return tc.file
				}
				if key == "SSL_CERT_DIR" {
					return tc.dir
				}
				return ""
			}, func() string { etcCalls++; return filepath.Join(etc, "ssl", "certs") })
			if !l.pool().Equal(testPool(overrideCA)) || etcCalls != 0 {
				t.Fatal("explicit trust override was broadened by platform CA files")
			}
		})
	}
}

func TestSystemFailureAndMissingStoreAreBestEffort(t *testing.T) {
	ca := makeTestCA(t, "native partial CA")
	for _, tc := range []struct {
		name   string
		native *x509.CertPool
	}{
		{"nil native pool", nil},
		{"partial native pool", testPool(ca)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := newLoader(func() (*x509.CertPool, error) { return tc.native, errors.New("native CA load failed") }, func(string) string { return "" }, func() string { return filepath.Join(t.TempDir(), "missing") })
			want := tc.native
			if want == nil {
				want = x509.NewCertPool()
			}
			if !l.pool().Equal(want) {
				t.Fatal("missing platform store discarded the available native roots")
			}
		})
	}
}

func TestLoaderIsCachedAndConcurrent(t *testing.T) {
	etc := t.TempDir()
	ca := makeTestCA(t, "initial CA")
	lateCA := makeTestCA(t, "late CA")
	writeCAFile(t, filepath.Join(etc, "ssl", "certs", "root.crt"), ca.pem)
	var systemCalls, etcCalls atomic.Int32
	l := newLoader(func() (*x509.CertPool, error) { systemCalls.Add(1); return x509.NewCertPool(), nil }, func(string) string { return "" }, func() string { etcCalls.Add(1); return filepath.Join(etc, "ssl", "certs") })
	const readers = 32
	results := make(chan *x509.CertPool, readers)
	var wg sync.WaitGroup
	for range readers {
		wg.Add(1)
		go func() { defer wg.Done(); results <- l.pool() }()
	}
	wg.Wait()
	close(results)
	first := l.pool()
	for result := range results {
		if result != first || !result.Equal(testPool(ca)) {
			t.Fatal("concurrent callers received distinct or incomplete cached pools")
		}
	}
	writeCAFile(t, filepath.Join(etc, "ssl", "certs", "late.crt"), lateCA.pem)
	if l.pool() != first || !l.pool().Equal(testPool(ca)) || systemCalls.Load() != 1 || etcCalls.Load() != 1 {
		t.Fatal("cached loader reread certificate files or replaced its pool")
	}
}

func TestConfigurePreservesExplicitTrust(t *testing.T) {
	Configure(nil)
	explicit := x509.NewCertPool()
	cfg := &tls.Config{RootCAs: explicit, ServerName: "telegram.example", MinVersion: tls.VersionTLS12}
	Configure(cfg)
	if cfg.RootCAs != explicit || cfg.ServerName != "telegram.example" || cfg.MinVersion != tls.VersionTLS12 {
		t.Fatal("Configure modified an explicit trust store or unrelated TLS settings")
	}
	defaultCfg := &tls.Config{ServerName: "telegram.example"}
	Configure(defaultCfg)
	if defaultCfg.RootCAs == nil || defaultCfg.RootCAs != Pool() || defaultCfg.ServerName != "telegram.example" {
		t.Fatal("Configure did not install the shared roots")
	}
}

func TestMalformedUnreadableAndOversizedFilesDoNotDiscardValidRoots(t *testing.T) {
	etc := t.TempDir()
	ca := makeTestCA(t, "valid CA")
	certDir := filepath.Join(etc, "ssl", "certs")
	writeCAFile(t, filepath.Join(certDir, "valid.crt"), ca.pem)
	writeCAFile(t, filepath.Join(etc, "ssl", "cert.pem"), []byte("bad PEM"))
	writeCAFile(t, filepath.Join(certDir, "unreadable.crt"), []byte("bad PEM"))
	if err := os.Chmod(filepath.Join(certDir, "unreadable.crt"), 0); err != nil {
		t.Fatal(err)
	}
	// A directory where a bundle file belongs is ignored as well.
	if err := os.Mkdir(filepath.Join(etc, "ssl", "ca-bundle.pem"), 0700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(certDir, "oversized.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(8*1024*1024 + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	l := newLoader(func() (*x509.CertPool, error) { return nil, nil }, func(string) string { return "" }, func() string { return filepath.Join(etc, "ssl", "certs") })
	if !l.pool().Equal(testPool(ca)) {
		t.Fatal("an invalid platform file discarded a valid CA")
	}
}

func BenchmarkCachedPool(b *testing.B) {
	l := newLoader(func() (*x509.CertPool, error) { return x509.NewCertPool(), nil }, func(string) string { return "" }, func() string { return "" })
	roots := l.pool()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if l.pool() != roots {
			b.Fatal("cached pool was replaced")
		}
	}
}
