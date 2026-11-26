package dnsserver

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"nfqws2strategy/internal/services/dnsroute"
)

func closeResolverFixtureIdle(r *Resolver) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, client := range r.clients {
		client.CloseIdleConnections()
	}
}

func awaitResolverSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func TestResolverRaceReturnsWARPWithoutWaitingForBlockedRoutes(t *testing.T) {
	r, b, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg { return resolverAnswer(q, 60) })
	r.cfg.TimeoutSeconds = 3
	r.cfg.CacheSize = 8
	r.cfg.DefaultUpstream.BootstrapIPs = []string{"192.0.2.1", "127.0.0.1"}
	r.mu.Lock()
	var roots *x509.CertPool
	for _, client := range r.clients {
		roots = client.Transport.(*http.Transport).TLSClientConfig.RootCAs
		break
	}
	r.mu.Unlock()
	trustResolverFixture(t, r, r.cfg.DefaultUpstream, roots)
	// A domain's selected provider must remain the same in every competing route.
	selected := r.cfg.DefaultUpstream
	r.cfg.Rules = []Rule{{Enabled: true, Domain: "claude.ai", IncludeSubdomains: true, Upstream: selected}}
	r.cfg.DefaultUpstream = Upstream{Address: "https://wrong-provider.invalid/dns-query"}
	closeResolverFixtureIdle(r)
	b.setFailures()
	started := map[string]chan struct{}{"nfqws": make(chan struct{}), "awg:first": make(chan struct{})}
	canceled := map[string]chan struct{}{"nfqws": make(chan struct{}), "awg:first": make(chan struct{})}
	r.mu.Lock()
	for route := range started {
		r.ipCursor[route+"|"+selected.Address] = 0
	}
	r.mu.Unlock()
	b.mu.Lock()
	upstream := b.address
	b.dialHook = func(ctx context.Context, route, network, _ string) (net.Conn, error) {
		if ready := started[route]; ready != nil {
			close(ready)
			<-ctx.Done()
			close(canceled[route])
			return nil, ctx.Err()
		}
		for _, ready := range started {
			select {
			case <-ready:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return (&net.Dialer{}).DialContext(ctx, network, upstream)
	}
	b.mu.Unlock()
	before := time.Now()
	answer, out, err := r.Resolve(context.Background(), resolverWire(t, "api.claude.ai", 0x4321, mdns.TypeA))
	if err != nil || out.Route != "awg:warp" || out.Upstream != selected.Address {
		t.Fatalf("race failed: %+v %v", out, err)
	}
	if elapsed := time.Since(before); elapsed > time.Second {
		t.Fatalf("waited for a blocked route: %v", elapsed)
	}
	var reply mdns.Msg
	if err := reply.Unpack(answer); err != nil || reply.Id != 0x4321 {
		t.Fatalf("lost client ID: %v %v", reply.Id, err)
	}
	for route, done := range canceled {
		awaitResolverSignal(t, done, route+" dial cancellation")
	}
	r.mu.Lock()
	for route := range started {
		if got := r.ipCursor[route+"|"+selected.Address]; got != 0 {
			t.Errorf("canceled %s advanced preferred IP to %d", route, got)
		}
	}
	r.mu.Unlock()
	_, cached, err := r.Resolve(context.Background(), resolverWire(t, "api.claude.ai", 0x4322, mdns.TypeA))
	if err != nil || !cached.Cached || cached.Route != "awg:warp" || cached.Upstream != selected.Address {
		t.Fatalf("race result not cached correctly: %+v %v", cached, err)
	}
}

func TestResolverRaceRejectsFastInvalidDNSResponses(t *testing.T) {
	for _, code := range []int{mdns.RcodeFormatError, mdns.RcodeNotImplemented, mdns.RcodeServerFailure, mdns.RcodeRefused} {
		t.Run(mdns.RcodeToString[code], func(t *testing.T) {
			r, b, good := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg { return resolverAnswer(q, 60) })
			badReply := make(chan struct{})
			var once sync.Once
			bad := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				raw, _ := io.ReadAll(req.Body)
				var q mdns.Msg
				if err := q.Unpack(raw); err != nil {
					t.Error(err)
					return
				}
				msg := new(mdns.Msg)
				msg.SetRcode(&q, code)
				wire, _ := msg.Pack()
				w.Header().Set("Content-Type", "application/dns-message")
				_, _ = w.Write(wire)
				once.Do(func() { close(badReply) })
			}))
			bad.TLS = good.TLS.Clone()
			bad.EnableHTTP2 = true
			bad.StartTLS()
			t.Cleanup(bad.Close)
			closeResolverFixtureIdle(r)
			b.mu.Lock()
			b.routes = []dnsroute.Route{{ID: "nfqws", Name: "NFQWS", Available: true}, {ID: "awg:warp", Name: "WARP", Available: true}}
			upstream := b.address
			b.dialHook = func(ctx context.Context, route, network, _ string) (net.Conn, error) {
				target := bad.Listener.Addr().String()
				if route == "awg:warp" {
					select {
					case <-badReply:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
					target = upstream
				}
				return (&net.Dialer{}).DialContext(ctx, network, target)
			}
			b.mu.Unlock()
			_, out, err := r.Resolve(context.Background(), resolverWire(t, "example.com", 1, mdns.TypeA))
			if err != nil || out.Route != "awg:warp" {
				t.Fatalf("invalid response won race: %+v %v", out, err)
			}
		})
	}
}

func TestResolverRaceAcceptsValidNXDOMAIN(t *testing.T) {
	r, _, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg {
		msg := new(mdns.Msg)
		msg.SetRcode(q, mdns.RcodeNameError)
		return msg
	})
	raw, out, err := r.Resolve(context.Background(), resolverWire(t, "missing.example", 17, mdns.TypeA))
	if err != nil || out.Route == "" {
		t.Fatalf("NXDOMAIN rejected: %+v %v", out, err)
	}
	var msg mdns.Msg
	if err := msg.Unpack(raw); err != nil || msg.Rcode != mdns.RcodeNameError || msg.Id != 17 {
		t.Fatalf("incorrect NXDOMAIN answer: %+v %v", msg, err)
	}
}

func TestResolverRaceCancelsLosingTLSHandshake(t *testing.T) {
	r, b, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg { return resolverAnswer(q, 60) })
	r.cfg.TimeoutSeconds = 3
	closeResolverFixtureIdle(r)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	handshakeStarted, connectionClosed := make(chan struct{}), make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 4096)
		if _, err := conn.Read(buf); err != nil {
			return
		}
		close(handshakeStarted)
		for {
			if _, err := conn.Read(buf); err != nil {
				close(connectionClosed)
				return
			}
		}
	}()
	b.mu.Lock()
	b.routes = []dnsroute.Route{{ID: "nfqws", Name: "NFQWS", Available: true}, {ID: "awg:warp", Name: "WARP", Available: true}}
	upstream := b.address
	b.dialHook = func(ctx context.Context, route, network, _ string) (net.Conn, error) {
		target := listener.Addr().String()
		if route == "awg:warp" {
			select {
			case <-handshakeStarted:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			target = upstream
		}
		return (&net.Dialer{}).DialContext(ctx, network, target)
	}
	b.mu.Unlock()
	before := time.Now()
	_, out, err := r.Resolve(context.Background(), resolverWire(t, "example.com", 1, mdns.TypeA))
	if err != nil || out.Route != "awg:warp" {
		t.Fatalf("TLS race failed: %+v %v", out, err)
	}
	awaitResolverSignal(t, connectionClosed, "canceled TLS handshake socket close")
	if elapsed := time.Since(before); elapsed > time.Second {
		t.Fatalf("losing TLS handshake stayed alive: %v", elapsed)
	}
}

func TestResolverRaceBoundsAttemptsAcrossQueriesAndCloseCancelsAll(t *testing.T) {
	r, b, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg { return resolverAnswer(q, 60) })
	r.cfg.TimeoutSeconds = 3
	closeResolverFixtureIdle(r)
	var active, peak atomic.Int32
	saturated := make(chan struct{})
	var once sync.Once
	b.mu.Lock()
	// Many distinct route pools avoid the transport's separate per-host
	// connection limit hiding whether the shared route limit is reached.
	b.routes = []dnsroute.Route{{ID: "nfqws", Name: "NFQWS", Available: true}}
	for i := 0; i < 40; i++ {
		b.routes = append(b.routes, dnsroute.Route{ID: fmt.Sprintf("awg:route%d", i), Name: fmt.Sprintf("Route %d", i), Available: true})
	}
	b.dialHook = func(ctx context.Context, _, _, _ string) (net.Conn, error) {
		current := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); current > old; old = peak.Load() {
			if peak.CompareAndSwap(old, current) {
				break
			}
		}
		if current == maxConcurrentRouteAttempts {
			once.Do(func() { close(saturated) })
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	b.mu.Unlock()
	const queries = 4
	results := make(chan error, queries)
	for i := 0; i < queries; i++ {
		wire := resolverWire(t, fmt.Sprintf("query%d.example", i), uint16(i), mdns.TypeA)
		go func() { _, _, err := r.Resolve(context.Background(), wire); results <- err }()
	}
	awaitResolverSignal(t, saturated, "shared route attempt limit")
	r.Close()
	for i := 0; i < queries; i++ {
		select {
		case err := <-results:
			if err == nil {
				t.Error("request succeeded after all routes canceled")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Close did not stop a queued request")
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for (active.Load() != 0 || len(r.attempts) != 0) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if active.Load() != 0 || len(r.attempts) != 0 {
		t.Fatalf("canceled attempts leaked: active=%d slots=%d", active.Load(), len(r.attempts))
	}
	if got := peak.Load(); got > maxConcurrentRouteAttempts {
		t.Fatalf("route attempts exceeded shared limit: %d", got)
	}
	if _, _, err := r.Resolve(context.Background(), resolverWire(t, "later.example", 1, mdns.TypeA)); err == nil {
		t.Fatal("closed resolver accepted a new request")
	}
	r.mu.Lock()
	pools := len(r.clients)
	r.mu.Unlock()
	if pools != 0 {
		t.Fatalf("closed resolver recreated %d HTTP pools", pools)
	}
}
