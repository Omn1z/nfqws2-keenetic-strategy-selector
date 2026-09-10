package dnsserver

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"nfqws2strategy/internal/services/dnsroute"
)

func newPoolResolverFixture(t *testing.T, handler http.Handler) (*Resolver, *resolverTestBackend) {
	t.Helper()
	serverTLS, roots := upstreamTestCertificate(t)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = serverTLS
	server.EnableHTTP2 = true
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	primary := Upstream{Address: "https://dns.home.arpa:" + port + "/primary", BootstrapIPs: []string{"127.0.0.1"}}
	secondary := Upstream{Address: "https://dns.home.arpa:" + port + "/secondary", BootstrapIPs: []string{"127.0.0.1"}}
	cfg := Default()
	cfg.DefaultUpstream, cfg.DefaultPool = primary, []Upstream{secondary}
	cfg.Rules, cfg.CacheSize, cfg.TimeoutSeconds = nil, 0, 1
	b := &resolverTestBackend{address: server.Listener.Addr().String(), routes: schedulerTestRoutes()}
	r := NewResolver(cfg, b)
	t.Cleanup(r.Close)
	trustResolverFixture(t, r, primary, roots)
	b.setFailures()
	return r, b
}

func writePoolReply(t *testing.T, w http.ResponseWriter, req *http.Request, rcode int) {
	t.Helper()
	wire, err := io.ReadAll(req.Body)
	if err != nil {
		return
	}
	var query mdns.Msg
	if err := query.Unpack(wire); err != nil {
		t.Error(err)
		return
	}
	answer := resolverAnswer(&query, 60)
	answer.Rcode = rcode
	if rcode != mdns.RcodeSuccess {
		answer.Answer = nil
	}
	packed, err := answer.Pack()
	if err != nil {
		t.Error(err)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	_, _ = w.Write(packed)
}

func TestResolverRacesPoolAcrossAllRoutesAndCancelsLosersNeutrally(t *testing.T) {
	started := make(chan string, 6)
	gate := make(chan struct{})
	r, _ := newPoolResolverFixture(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		started <- req.URL.Path
		if req.URL.Path == "/primary" {
			<-req.Context().Done()
			return
		}
		select {
		case <-gate:
			writePoolReply(t, w, req, mdns.RcodeSuccess)
		case <-req.Context().Done():
		}
	}))
	r.cfg.CacheSize = 16
	events := make(chan AttemptEvent, 6)
	r.SetAttemptObserver(func(event AttemptEvent) { events <- event })
	type resolved struct {
		out Outcome
		err error
	}
	done := make(chan resolved, 1)
	go func() {
		_, out, err := r.Resolve(context.Background(), resolverWire(t, "example.com", 12, mdns.TypeA))
		done <- resolved{out, err}
	}()
	counts := map[string]int{}
	for i := 0; i < 6; i++ {
		select {
		case path := <-started:
			counts[path]++
		case <-time.After(2 * time.Second):
			t.Fatal("provider/route pair was not started alongside the others")
		}
	}
	if counts["/primary"] != 3 || counts["/secondary"] != 3 {
		t.Fatalf("not a provider×route race: %v", counts)
	}
	close(gate)
	select {
	case result := <-done:
		if result.err != nil || result.out.Upstream != r.cfg.DefaultPool[0].Address {
			t.Fatalf("secondary winner: %+v %v", result.out, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("waited for losing primary timeouts")
	}
	for i := 0; i < 6; i++ {
		select {
		case event := <-events:
			if strings.HasSuffix(event.Upstream, "/primary") && (!event.Canceled || event.Success || event.Error != "") {
				t.Fatalf("canceled loser produced error evidence: %+v", event)
			}
		case <-time.After(time.Second):
			t.Fatal("attempt cancellation did not finish")
		}
	}
	for _, candidate := range r.SchedulerSnapshot("example.com").Candidates {
		if strings.HasSuffix(candidate.Upstream, "/primary") && (candidate.Attempts != 1 || candidate.Failures != 0 || candidate.Score != 25) {
			t.Fatalf("loser was penalized: %+v", candidate)
		}
	}
	_, cached, err := r.Resolve(context.Background(), resolverWire(t, "example.com", 13, mdns.TypeA))
	if err != nil || !cached.Cached || cached.Upstream != r.cfg.DefaultPool[0].Address {
		t.Fatalf("cache lost winning provider: %+v %v", cached, err)
	}
}

func TestResolverBadProviderDoesNotBeatValidProviderAndRulePoolIsIsolated(t *testing.T) {
	failed := make(chan struct{}, 3)
	r, b := newPoolResolverFixture(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/primary" {
			writePoolReply(t, w, req, mdns.RcodeServerFailure)
			return
		}
		select {
		case <-failed:
			writePoolReply(t, w, req, mdns.RcodeSuccess)
		case <-req.Context().Done():
		}
	}))
	b.routes = b.routes[:1]
	r.cfg.Rules = []Rule{{ID: "special", Enabled: true, Domain: "claude.ai", IncludeSubdomains: true, Upstream: r.cfg.DefaultUpstream, Pool: r.cfg.DefaultPool}}
	r.cfg.DefaultUpstream = Upstream{Address: "https://192.0.2.250/dns-query"}
	r.cfg.DefaultPool = []Upstream{{Address: "https://192.0.2.251/dns-query"}}
	r.SetAttemptObserver(func(event AttemptEvent) {
		if event.Error != "" {
			failed <- struct{}{}
		}
	})
	_, out, err := r.Resolve(context.Background(), resolverWire(t, "api.claude.ai", 14, mdns.TypeA))
	if err != nil || !strings.HasSuffix(out.Upstream, "/secondary") {
		t.Fatalf("invalid DNS result won race: %+v %v", out, err)
	}
	view := r.SchedulerSnapshot("api.claude.ai")
	if view.Candidates[0].Upstream != out.Upstream || view.Candidates[1].Failures != 1 || !strings.Contains(view.Candidates[1].LastError, "SERVFAIL") {
		t.Fatalf("failure not demoted: %+v", view)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, address := range b.addresses {
		if strings.Contains(address, "192.0.2.25") {
			t.Fatalf("special domain leaked to default pool: %s", address)
		}
	}
}

func TestResolverSchedulerOrderControlsActualDispatchWhenSlotsAreOccupied(t *testing.T) {
	routes := make([]dnsroute.Route, 40)
	for i := range routes {
		routes[i] = dnsroute.Route{ID: fmt.Sprintf("awg:%02d", i), Available: true}
	}
	started := make(chan string, 64)
	b := &resolverTestBackend{routes: routes, dialHook: func(ctx context.Context, route, _, _ string) (net.Conn, error) {
		started <- route
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	cfg := Default()
	cfg.Rules, cfg.CacheSize = nil, 0
	r := NewResolver(cfg, b)
	defer r.Close()
	preferred := routes[39].ID
	r.scheduler.record(AttemptEvent{Route: preferred, Upstream: cfg.DefaultUpstream.Address, Success: true, DurationMS: 5})
	// Occupy every slot: opening just one should start the ranked head even
	// though it is the last route reported by the backend.
	for i := 0; i < maxConcurrentRouteAttempts; i++ {
		r.attempts <- struct{}{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _, _, _ = r.Resolve(ctx, resolverWire(t, "example.com", 15, mdns.TypeA)) }()
	<-r.attempts
	select {
	case route := <-started:
		if route != preferred {
			t.Fatalf("UI ranking did not affect actual dispatch: %s", route)
		}
	case <-time.After(time.Second):
		t.Fatal("preferred pair was not dispatched")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("blocked dispatch did not cancel")
	}
	// Restore test-owned slots without racing actual worker token release.
	for i := 0; i < maxConcurrentRouteAttempts-1; i++ {
		<-r.attempts
	}
}

func TestSchedulerConcurrentSnapshotAndObservation(t *testing.T) {
	s := NewScheduler()
	cfg := Default()
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				s.started("nfqws", cfg.DefaultUpstream.Address)
				s.record(AttemptEvent{Route: "nfqws", Upstream: cfg.DefaultUpstream.Address, Success: true, DurationMS: 25})
				_ = s.Snapshot(cfg, schedulerTestRoutes(), "example.com")
			}
		}()
	}
	wg.Wait()
	view := s.Snapshot(cfg, schedulerTestRoutes(), "example.com").Candidates[0]
	if view.Successes != 800 || view.Attempts != 800 {
		t.Fatalf("lost concurrent observations: %+v", view)
	}
}
