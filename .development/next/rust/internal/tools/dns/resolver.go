package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Resolver resolves hostnames through encrypted DNS servers and caches the
// outcome for its lifetime. A run creates one resolver so the same (server,host)
// pair is queried only once across the whole strategy×DNS matrix.
type Resolver struct {
	httpc      *http.Client
	dotTimeout time.Duration

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	ip  string
	err error
}

func NewResolver() *Resolver {
	return &Resolver{
		httpc:      &http.Client{Timeout: 8 * time.Second},
		dotTimeout: 6 * time.Second,
		cache:      map[string]cacheEntry{},
	}
}

// Resolve returns the first IPv4 address for host via srv, caching the result
// (including failures) for the resolver's lifetime.
func (r *Resolver) Resolve(ctx context.Context, srv Server, host string) (string, error) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	key := srv.ID + "|" + host
	r.mu.Lock()
	if e, ok := r.cache[key]; ok {
		r.mu.Unlock()
		return e.ip, e.err
	}
	r.mu.Unlock()

	ip, err := r.resolveOnce(ctx, srv, host)

	r.mu.Lock()
	r.cache[key] = cacheEntry{ip: ip, err: err}
	r.mu.Unlock()
	return ip, err
}

func (r *Resolver) resolveOnce(ctx context.Context, srv Server, host string) (string, error) {
	q, err := buildQuery(host)
	if err != nil {
		return "", err
	}
	var resp []byte
	switch srv.Type {
	case DoH:
		resp, err = r.doh(ctx, srv.Addr, q)
	case DoT:
		resp, err = r.dot(ctx, srv.Addr, q)
	default:
		return "", fmt.Errorf("dns: unknown type %q", srv.Type)
	}
	if err != nil {
		return "", err
	}
	return parseA(resp)
}

func (r *Resolver) doh(ctx context.Context, endpoint string, q []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(q))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := r.httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dns: doh status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 65535))
}

func (r *Resolver) dot(ctx context.Context, addr string, q []byte) ([]byte, error) {
	host, port := addr, "853"
	if h, p, err := net.SplitHostPort(addr); err == nil {
		host, port = h, p
	}
	d := net.Dialer{Timeout: r.dotTimeout}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, &tls.Config{ServerName: host})
	defer conn.Close()

	deadline := time.Now().Add(r.dotTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}

	msg := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(msg, uint16(len(q)))
	copy(msg[2:], q)
	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}

	var lenb [2]byte
	if _, err := io.ReadFull(conn, lenb[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(lenb[:])
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
