package dnsserver

import (
	"context"
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

func TestResolverHTTP2CancellationKeepsSharedConnectionUsable(t *testing.T) {
	serverTLS, roots := upstreamTestCertificate(t)
	slowStarted := make(chan struct{})
	slowCanceled := make(chan struct{})
	fastStarted := make(chan struct{})
	finishFast := make(chan struct{})
	type requestInfo struct {
		protocol int
		alpn     string
		remote   string
	}
	var mu sync.Mutex
	requests := make(map[string]requestInfo)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.TLS.ServerName != "dns.home.arpa" || !strings.HasPrefix(req.Host, "dns.home.arpa:") {
			t.Errorf("lost upstream host/SNI: %q %q", req.Host, req.TLS.ServerName)
		}
		wire, err := io.ReadAll(req.Body)
		if err != nil {
			if req.Context().Err() == nil {
				t.Error(err)
			}
			return
		}
		var query mdns.Msg
		if err := query.Unpack(wire); err != nil {
			t.Error(err)
			return
		}
		name := query.Question[0].Name
		mu.Lock()
		requests[name] = requestInfo{protocol: req.ProtoMajor, alpn: req.TLS.NegotiatedProtocol, remote: req.RemoteAddr}
		mu.Unlock()
		switch name {
		case "slow.example.":
			close(slowStarted)
			<-req.Context().Done()
			close(slowCanceled)
			return
		case "fast.example.":
			close(fastStarted)
			select {
			case <-finishFast:
			case <-req.Context().Done():
				return
			}
		}
		answer, err := resolverAnswer(&query, 60).Pack()
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(answer)
	}))
	server.TLS = serverTLS
	server.EnableHTTP2 = true
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	u := Upstream{Address: "https://dns.home.arpa:" + port + "/dns-query", BootstrapIPs: []string{"127.0.0.1"}}
	b := &resolverTestBackend{address: server.Listener.Addr().String(), routes: []dnsroute.Route{{ID: "nfqws", Name: "NFQWS", Available: true}}}
	cfg := Default()
	cfg.DefaultUpstream = u
	cfg.Rules = nil
	cfg.CacheSize = 0
	cfg.AWGFallback = "off"
	cfg.TimeoutSeconds = 3
	r := NewResolver(cfg, b)
	t.Cleanup(r.Close)
	trustResolverFixture(t, r, u, roots)
	b.setFailures()
	resolve := func(ctx context.Context, name string, id uint16) error {
		wire := resolverWire(t, name, id, mdns.TypeA)
		answer, out, err := r.Resolve(ctx, wire)
		if err != nil {
			return err
		}
		var msg mdns.Msg
		if err := msg.Unpack(answer); err != nil {
			return err
		}
		if out.Route != "nfqws" || out.Cached || msg.Id != id || len(msg.Answer) != 1 {
			t.Errorf("unexpected response to %s: outcome=%+v message=%v", name, out, &msg)
		}
		return nil
	}
	if err := resolve(context.Background(), "warmup.example", 1); err != nil {
		t.Fatal(err)
	}
	wait := func(ch <-chan struct{}, event string) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for %s", event)
		}
	}
	slowCtx, cancelSlow := context.WithCancel(context.Background())
	defer cancelSlow()
	slowResult := make(chan error, 1)
	go func() { slowResult <- resolve(slowCtx, "slow.example", 2) }()
	wait(slowStarted, "slow HTTP/2 stream")
	fastResult := make(chan error, 1)
	go func() { fastResult <- resolve(context.Background(), "fast.example", 3) }()
	wait(fastStarted, "concurrent fast HTTP/2 stream")
	cancelSlow()
	select {
	case err := <-slowResult:
		if err == nil {
			t.Fatal("canceled slow request returned success")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("slow request did not return after cancellation")
	}
	wait(slowCanceled, "server observing slow stream cancellation")
	close(finishFast)
	select {
	case err := <-fastResult:
		if err != nil {
			t.Fatalf("canceling another stream broke the active request: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fast request did not complete")
	}
	if err := resolve(context.Background(), "next.example", 4); err != nil {
		t.Fatalf("connection became unusable after stream cancellation: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	remote := requests["warmup.example."].remote
	for _, name := range []string{"warmup.example.", "slow.example.", "fast.example.", "next.example."} {
		info, ok := requests[name]
		if !ok || info.protocol != 2 || info.alpn != "h2" || info.remote != remote {
			t.Errorf("request %s did not reuse the same HTTP/2 connection: %+v, warmup remote=%s", name, info, remote)
		}
	}
	if calls := b.dialCalls(); len(calls) != 1 || calls[0] != "nfqws" {
		t.Fatalf("stream cancellation discarded the healthy connection: dials=%v", calls)
	}
}
