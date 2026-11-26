// Package tlsroots adds the router's CA store to Go's native trusted roots.
// Entware installs CA certificates below /opt/etc, outside Go's Linux defaults.
package tlsroots

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	routerpath "nfqws2strategy/internal/tools/path"
)

var shared = newLoader(x509.SystemCertPool, os.Getenv, func() string {
	return routerpath.Path(routerpath.TLSCertDir)
})

// Pool returns the process-wide trusted roots, loaded once. Callers must treat
// the pool as immutable; Clone it before adding certificates of their own.
// Explicit SSL_CERT_FILE or SSL_CERT_DIR settings retain Go's override semantics.
func Pool() *x509.CertPool { return shared.pool() }

// Configure fills missing roots in cfg while preserving explicitly supplied
// trust stores. It does not change process environment or default transports.
func Configure(cfg *tls.Config) {
	if cfg != nil && cfg.RootCAs == nil {
		cfg.RootCAs = Pool()
	}
}

// Each loader owns its dependencies and cache, so tests can simulate router
// layouts without changing the process environment or resetting global state.
type loader struct {
	once    sync.Once
	roots   *x509.CertPool
	system  func() (*x509.CertPool, error)
	getenv  func(string) string
	certDir func() string
}

func newLoader(system func() (*x509.CertPool, error), getenv func(string) string, certDir func() string) *loader {
	return &loader{system: system, getenv: getenv, certDir: certDir}
}

func (l *loader) pool() *x509.CertPool {
	l.once.Do(func() {
		roots, _ := l.system()
		if roots == nil {
			roots = x509.NewCertPool()
		} else {
			// Preserve the native pool even when a provider shares its instance.
			roots = roots.Clone()
		}
		if l.getenv("SSL_CERT_FILE") == "" && l.getenv("SSL_CERT_DIR") == "" {
			appendPlatformRoots(roots, l.certDir())
		}
		l.roots = roots
	})
	return l.roots
}

func appendPlatformRoots(roots *x509.CertPool, certDir string) {
	if certDir == "" {
		return
	}
	sslDir := filepath.Dir(certDir)
	for _, name := range []string{
		filepath.Join(sslDir, "cert.pem"),
		filepath.Join(sslDir, "ca-bundle.pem"),
		filepath.Join(certDir, "ca-certificates.crt"),
	} {
		appendFile(roots, name)
	}
	entries, err := os.ReadDir(certDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		switch strings.ToLower(filepath.Ext(entry.Name())) {
		case ".crt", ".pem", ".cer":
			appendFile(roots, filepath.Join(certDir, entry.Name()))
		}
	}
}

func appendFile(roots *x509.CertPool, name string) {
	// Ignore special files and bound an accidental oversized file. Normal CA
	// bundles are far below this limit; unreadable or malformed files leave
	// the other native and platform roots intact.
	const maxBundleSize = 8 * 1024 * 1024
	info, err := os.Stat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxBundleSize {
		return
	}
	f, err := os.Open(name)
	if err != nil {
		return
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxBundleSize {
		return
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBundleSize+1))
	if err == nil && len(data) <= maxBundleSize {
		roots.AppendCertsFromPEM(data)
	}
}
