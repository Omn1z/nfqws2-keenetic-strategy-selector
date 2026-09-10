package dnsserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"nfqws2strategy/internal/services/dnsroute"
)

type resolverTestBackend struct {
	mu                       sync.Mutex
	routes                   []dnsroute.Route
	address                  string
	fail                     map[string]bool
	calls                    []string
	addresses                []string
	dialHook                 func(context.Context, string, string, string) (net.Conn, error)
	prepareCount, closeCount int
	prepareErr               error
	observe                  func(context.Context, string, []byte, net.IP) ([]byte, error)
}

func (b *resolverTestBackend) Prepare(context.Context, dnsroute.ListenOptions) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.prepareCount++
	return b.prepareErr
}
func (b *resolverTestBackend) Routes() []dnsroute.Route {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]dnsroute.Route{}, b.routes...)
}
func (b *resolverTestBackend) DialContext(ctx context.Context, route, network, address string) (net.Conn, error) {
	b.mu.Lock()
	b.calls = append(b.calls, route)
	b.addresses = append(b.addresses, address)
	fail := b.fail[route]
	target := b.address
	hook := b.dialHook
	b.mu.Unlock()
	host, _, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil {
		return nil, fmt.Errorf("unexpected unpinned dial %q", address)
	}
	if fail {
		return nil, fmt.Errorf("test route %s is blocked", route)
	}
	if hook != nil {
		return hook(ctx, route, network, address)
	}
	return (&net.Dialer{}).DialContext(ctx, network, target)
}
func (b *resolverTestBackend) ObserveAnswer(ctx context.Context, domain string, wire []byte, ip net.IP) ([]byte, error) {
	b.mu.Lock()
	observe := b.observe
	b.mu.Unlock()
	if observe != nil {
		return observe(ctx, domain, wire, ip)
	}
	return wire, nil
}
func (b *resolverTestBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closeCount++
	return nil
}
func (b *resolverTestBackend) setFailures(routes ...string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.fail = map[string]bool{}
	for _, r := range routes {
		b.fail[r] = true
	}
	b.calls = nil
	b.addresses = nil
}
func (b *resolverTestBackend) dialCalls() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string{}, b.calls...)
}

func resolverWire(t *testing.T, name string, id uint16, qtype uint16) []byte {
	t.Helper()
	q := new(mdns.Msg)
	q.SetQuestion(mdns.Fqdn(name), qtype)
	q.Id = id
	wire, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
func resolverAnswer(q *mdns.Msg, ttl uint32) *mdns.Msg {
	r := new(mdns.Msg)
	r.SetReply(q)
	r.RecursionAvailable = true
	r.Answer = []mdns.RR{&mdns.A{Hdr: mdns.RR_Header{Name: q.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: ttl}, A: net.ParseIP("203.0.113.20")}}
	return r
}

// Prime the real transport with an untrusted local CA, prove it is rejected,
// then trust that CA in this test instance only. No production insecure mode or
// certificate injection API is added for testing.
func trustResolverFixture(t *testing.T, r *Resolver, u Upstream, roots *x509.CertPool) {
	t.Helper()
	endpoint, err := url.Parse(u.Address)
	if err != nil {
		t.Fatal(err)
	}
	wire := resolverWire(t, "example.com", 0, mdns.TypeA)
	for _, route := range r.backend.Routes() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err = r.doH(ctx, route.ID, endpoint, u.BootstrapIPs[0], wire)
		cancel()
		if err == nil {
			t.Fatal("upstream accepted an untrusted TLS certificate")
		}
	}
	r.mu.Lock()
	for _, client := range r.clients {
		tr := client.Transport.(*http.Transport)
		tr.TLSClientConfig = tr.TLSClientConfig.Clone()
		tr.TLSClientConfig.RootCAs = roots
	}
	r.mu.Unlock()
}

func upstreamTestCertificate(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"dns.home.arpa"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}, roots
}

func newResolverFixture(t *testing.T, reply func(*mdns.Msg) *mdns.Msg) (*Resolver, *resolverTestBackend, *httptest.Server) {
	t.Helper()
	serverTLS, roots := upstreamTestCertificate(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.TLS.ServerName != "dns.home.arpa" || !strings.HasPrefix(req.Host, "dns.home.arpa:") {
			t.Errorf("lost upstream host/SNI: %q %q", req.Host, req.TLS.ServerName)
		}
		switch req.URL.Path {
		case "/oversized":
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write(make([]byte, 65536))
			return
		case "/html":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html>blocked</html>"))
			return
		case "/redirect":
			w.Header().Set("Location", "https://"+req.Host+"/dns-query")
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
		wire, err := io.ReadAll(req.Body)
		if err != nil {
			// Losing HTTP/2 streams may be canceled before their small request
			// body arrives. That is the expected result of another route winning.
			if req.Context().Err() == nil {
				t.Error(err)
			}
			return
		}
		var q mdns.Msg
		if err := q.Unpack(wire); err != nil {
			t.Error(err)
			return
		}
		r := reply(&q)
		data, err := r.Pack()
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(data)
	}))
	server.TLS = serverTLS
	server.EnableHTTP2 = true
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	u := Upstream{Address: "https://dns.home.arpa:" + port + "/dns-query", BootstrapIPs: []string{"127.0.0.1"}}
	b := &resolverTestBackend{address: server.Listener.Addr().String(), routes: []dnsroute.Route{{ID: "nfqws", Name: "NFQWS", Available: true}, {ID: "awg:first", Name: "AWG 1", Available: true}, {ID: "awg:warp", Name: "WARP", Available: true}}}
	cfg := Default()
	cfg.DefaultUpstream = u
	cfg.Rules = nil
	cfg.CacheSize = 0
	cfg.TimeoutSeconds = 1
	r := NewResolver(cfg, b)
	t.Cleanup(r.Close)
	trustResolverFixture(t, r, u, roots)
	b.setFailures()
	return r, b, server
}

func TestResolverRacesAWGAndRetriesFailedRoutesOnEveryCacheMiss(t *testing.T) {
	failed := make(chan string, 4)
	var requireFailures atomic.Bool
	requireFailures.Store(true)
	r, b, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg {
		if requireFailures.Load() {
			// Keep the successful response pending until both blocked routes
			// have participated. The assertion never relies on goroutine order.
			for i := 0; i < 2; i++ {
				select {
				case <-failed:
				case <-time.After(2 * time.Second):
					t.Error("a failed route was not retried alongside WARP")
					return resolverAnswer(q, 60)
				}
			}
		}
		return resolverAnswer(q, 60)
	})
	b.mu.Lock()
	target := b.address
	b.dialHook = func(ctx context.Context, route, network, _ string) (net.Conn, error) {
		if route != "awg:warp" {
			failed <- route
			return nil, fmt.Errorf("test route %s is blocked", route)
		}
		return (&net.Dialer{}).DialContext(ctx, network, target)
	}
	b.mu.Unlock()
	wire := resolverWire(t, "claude.com", 0x4321, mdns.TypeA)
	for attempt := 0; attempt < 2; attempt++ {
		answer, out, err := r.Resolve(context.Background(), wire)
		if err != nil || out.Route != "awg:warp" {
			t.Fatalf("attempt %d: route %q err %v", attempt, out.Route, err)
		}
		var msg mdns.Msg
		if err := msg.Unpack(answer); err != nil || msg.Id != 0x4321 {
			t.Fatalf("lost client query ID: %x %v", answer, err)
		}
		calls := b.dialCalls()
		for _, route := range []string{"nfqws", "awg:first"} {
			if !slices.Contains(calls, route) {
				t.Fatalf("attempt %d did not retry failed route %s: %v", attempt, route, calls)
			}
		}
		if attempt == 0 {
			slices.Sort(calls)
			if !reflect.DeepEqual(calls, []string{"awg:first", "awg:warp", "nfqws"}) {
				t.Fatalf("initial request did not try every candidate: %v", calls)
			}
		}
		b.setFailures()
	}
	// Make NFQWS the only working route to prove a previously failed route
	// remains eligible. Close the old WARP connection before blocking its dial.
	requireFailures.Store(false)
	b.mu.Lock()
	b.dialHook = nil
	b.mu.Unlock()
	b.setFailures("awg:first", "awg:warp")
	r.mu.Lock()
	for _, client := range r.clients {
		client.CloseIdleConnections()
	}
	r.mu.Unlock()
	_, out, err := r.Resolve(context.Background(), wire)
	if err != nil || out.Route != "nfqws" {
		t.Fatalf("recovered NFQWS was not retried: %+v %v", out, err)
	}
}

func TestResolverSlowFirstIPDoesNotStarveHealthySecondIP(t *testing.T) {
	r, b, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg { return resolverAnswer(q, 60) })
	r.cfg.AWGFallback = "off"
	r.cfg.DefaultUpstream.BootstrapIPs = []string{"192.0.2.1", "127.0.0.1"}
	blocked := make(chan struct{})
	t.Cleanup(func() { close(blocked) })
	b.mu.Lock()
	upstream := b.address
	b.dialHook = func(ctx context.Context, _, network, address string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(address)
		if host == "192.0.2.1" {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-blocked:
				return nil, fmt.Errorf("test blackhole closed")
			}
		}
		return (&net.Dialer{}).DialContext(ctx, network, upstream)
	}
	b.mu.Unlock()
	query := resolverWire(t, "example.com", 1, mdns.TypeA)
	started := time.Now()
	if _, out, err := r.Resolve(context.Background(), query); err != nil || out.Route != "nfqws" {
		t.Fatalf("first IP consumed the entire route budget: %+v %v", out, err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("healthy IP exceeded one-second route budget: %v", elapsed)
	}
	b.mu.Lock()
	first := append([]string{}, b.addresses...)
	b.mu.Unlock()
	if len(first) != 2 || !strings.HasPrefix(first[0], "192.0.2.1:") || !strings.HasPrefix(first[1], "127.0.0.1:") {
		t.Fatalf("incorrect fallback IP order: %v", first)
	}
	// Force a new socket so the next request proves the preferred IP changed,
	// rather than succeeding only because an old HTTP/2 connection was reused.
	r.mu.Lock()
	for _, client := range r.clients {
		client.CloseIdleConnections()
	}
	r.mu.Unlock()
	b.setFailures()
	if _, out, err := r.Resolve(context.Background(), query); err != nil || out.Route != "nfqws" {
		t.Fatalf("subsequent request failed: %+v %v", out, err)
	}
	b.mu.Lock()
	next := append([]string{}, b.addresses...)
	b.mu.Unlock()
	if len(next) != 1 || !strings.HasPrefix(next[0], "127.0.0.1:") {
		t.Fatalf("subsequent request retried the blackhole first: %v", next)
	}
}

func TestResolverDomainRulesMatchLabelBoundariesAndLongestSuffix(t *testing.T) {
	c := Default()
	c.Rules = []Rule{
		{Enabled: true, Domain: "claude.com", IncludeSubdomains: true, Upstream: Upstream{Address: "https://parent.example/dns-query"}},
		{Enabled: true, Domain: "api.claude.com", IncludeSubdomains: true, Upstream: Upstream{Address: "https://child.example/dns-query"}},
		{Enabled: false, Domain: "x.api.claude.com", IncludeSubdomains: true, Upstream: Upstream{Address: "https://disabled.example/dns-query"}},
		{Enabled: true, Domain: "grok.com", IncludeSubdomains: false, Upstream: Upstream{Address: "https://exact.example/dns-query"}},
	}
	for domain, want := range map[string]string{"claude.com": "parent", "a.claude.com": "parent", "api.claude.com": "child", "x.api.claude.com": "child", "notclaude.com": "default", "claude.com.attacker.test": "default", "grok.com": "exact", "api.grok.com": "default"} {
		got := c.upstreamFor(domain).Address
		if want == "default" {
			if got != c.DefaultUpstream.Address {
				t.Errorf("%s selected %s", domain, got)
			}
		} else if !strings.HasPrefix(got, "https://"+want+".example/") {
			t.Errorf("%s selected %s, want %s", domain, got, want)
		}
	}
}

func TestResolverRejectsMismatchedDNSAnswersAndRecovers(t *testing.T) {
	var mu sync.Mutex
	bad := true
	r, b, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg {
		mu.Lock()
		invalid := bad
		mu.Unlock()
		response := resolverAnswer(q, 60)
		if invalid {
			response.Question[0].Name = "another.example."
		}
		return response
	})
	query := resolverWire(t, "example.com", 123, mdns.TypeA)
	if _, _, err := r.Resolve(context.Background(), query); err == nil {
		t.Fatal("accepted a mismatched question")
	}
	mu.Lock()
	bad = false
	mu.Unlock()
	b.setFailures()
	if _, out, err := r.Resolve(context.Background(), query); err != nil || !slices.Contains([]string{"nfqws", "awg:first", "awg:warp"}, out.Route) {
		t.Fatalf("resolver stuck after invalid upstream response: %+v %v", out, err)
	}
}

func TestResolverCacheAgesTTLAndExpiresWithoutChangingStoredAnswer(t *testing.T) {
	r, b, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg { return resolverAnswer(q, 5) })
	r.cfg.CacheSize = 8
	now := time.Now()
	r.now = func() time.Time { return now }
	query := resolverWire(t, "example.com", 1, mdns.TypeA)
	if _, out, err := r.Resolve(context.Background(), query); err != nil || out.Cached {
		t.Fatal(out, err)
	}
	now = now.Add(2 * time.Second)
	query = resolverWire(t, "example.com", 2, mdns.TypeA)
	answer, out, err := r.Resolve(context.Background(), query)
	if err != nil || !out.Cached {
		t.Fatal(out, err)
	}
	var msg mdns.Msg
	if err := msg.Unpack(answer); err != nil || msg.Id != 2 || msg.Answer[0].Header().Ttl != 3 {
		t.Fatalf("incorrect cached reply: %v %v", &msg, err)
	}
	now = now.Add(2 * time.Second)
	answer, _, _ = r.Resolve(context.Background(), query)
	_ = msg.Unpack(answer)
	if msg.Answer[0].Header().Ttl != 1 {
		t.Fatalf("cache compounded TTL ageing: %d", msg.Answer[0].Header().Ttl)
	}
	now = now.Add(time.Second)
	b.setFailures()
	if _, out, err := r.Resolve(context.Background(), query); err != nil || out.Cached {
		t.Fatalf("expired cache returned: %+v %v", out, err)
	}
}

func TestResolverValidationBoundsAndDNSNames(t *testing.T) {
	for _, name := range []string{".", "_sip._tcp.example.com", "example.com"} {
		if _, _, err := parseQuery(resolverWire(t, name, 1, mdns.TypeSRV)); err != nil {
			t.Errorf("valid DNS name %q rejected: %v", name, err)
		}
	}
	q := new(mdns.Msg)
	q.SetQuestion("example.com.", mdns.TypeA)
	q.Id = 0
	valid := resolverAnswer(q, 60)
	for _, mutate := range []func(*mdns.Msg){func(m *mdns.Msg) { m.Id = 42 }, func(m *mdns.Msg) { m.Question[0].Qtype = mdns.TypeAAAA }, func(m *mdns.Msg) { m.Truncated = true }, func(m *mdns.Msg) { m.Rcode = mdns.RcodeRefused }, func(m *mdns.Msg) { m.Rcode = mdns.RcodeFormatError }, func(m *mdns.Msg) { m.Rcode = mdns.RcodeNotImplemented }} {
		m := valid.Copy()
		mutate(m)
		raw, _ := m.Pack()
		if _, err := validateResponse(raw, q); err == nil {
			t.Errorf("accepted invalid answer: %v", m)
		}
	}
	negative := valid.Copy()
	negative.Rcode = mdns.RcodeNameError
	negative.Answer = nil
	negativeWire, err := negative.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateResponse(negativeWire, q); err != nil {
		t.Fatalf("valid NXDOMAIN response rejected: %v", err)
	}
	if _, err := validateResponse(make([]byte, 65536), q); err == nil {
		t.Fatal("accepted oversized DNS answer")
	}
	if _, _, err := parseQuery(make([]byte, 65536)); err == nil {
		t.Fatal("accepted oversized DNS request")
	}
}

func TestResolverRejectsOversizedHTMLAndRedirectedDoH(t *testing.T) {
	r, _, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg { return resolverAnswer(q, 60) })
	endpoint, err := url.Parse(r.cfg.DefaultUpstream.Address)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/oversized", "/html", "/redirect"} {
		endpoint.Path = path
		r.cfg.DefaultUpstream.Address = endpoint.String()
		if _, _, err := r.Resolve(context.Background(), resolverWire(t, "example.com", 1, mdns.TypeA)); err == nil {
			t.Errorf("accepted invalid DoH response at %s", path)
		}
	}
}
