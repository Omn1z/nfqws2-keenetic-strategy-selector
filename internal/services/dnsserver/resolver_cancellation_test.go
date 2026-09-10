package dnsserver

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"nfqws2strategy/internal/services/dnsroute"
)

func awaitCancellationSummary(t *testing.T, summaries <-chan CancellationSummary) CancellationSummary {
	t.Helper()
	select {
	case summary := <-summaries:
		return summary
	case <-time.After(2 * time.Second):
		t.Fatal("dispatched workers did not produce a cancellation summary")
		return CancellationSummary{}
	}
}

func TestResolverCancellationSummaryDoesNotDelayWinner(t *testing.T) {
	r, b, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg { return resolverAnswer(q, 60) })
	r.cfg.CacheSize, r.cfg.TimeoutSeconds = 0, 3
	b.setFailures()
	closeResolverFixtureIdle(r)
	started := map[string]chan struct{}{"nfqws": make(chan struct{}), "awg:first": make(chan struct{})}
	b.mu.Lock()
	upstream := b.address
	b.dialHook = func(ctx context.Context, route, network, _ string) (net.Conn, error) {
		if ready := started[route]; ready != nil {
			close(ready)
			<-ctx.Done()
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
	// Keep both losing workers unfinished after they observe cancellation. The
	// winner must still return before their diagnostics and summary can finish.
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	canceled := make(chan AttemptEvent, 2)
	summaries := make(chan CancellationSummary, 2)
	logs := NewLogBuffer()
	logs.SetEnabled(true)
	s := &Service{logs: logs}
	r.SetAttemptObserver(func(event AttemptEvent) {
		s.recordAttempt(event)
		if event.Canceled {
			canceled <- event
			<-release
		}
	})
	r.SetCancellationObserver(func(summary CancellationSummary) {
		s.recordCancellations(summary)
		summaries <- summary
	})
	done := make(chan Outcome, 1)
	go func() {
		_, out, err := r.Resolve(context.Background(), resolverWire(t, "api.claude.ai", 71, mdns.TypeAAAA))
		if err != nil {
			out.Error = err.Error()
		}
		done <- out
	}()
	select {
	case out := <-done:
		if out.Error != "" || out.Route != "awg:warp" {
			t.Fatalf("wrong race winner: %+v", out)
		}
	case <-time.After(time.Second):
		t.Fatal("answer waited for cancellation diagnostics")
	}
	for i := 0; i < 2; i++ {
		select {
		case event := <-canceled:
			if event.Error != "" || event.Success {
				t.Fatalf("canceled worker changed observer semantics: %+v", event)
			}
		case <-time.After(time.Second):
			t.Fatal("losing worker did not cancel")
		}
	}
	select {
	case summary := <-summaries:
		t.Fatalf("summary preceded worker completion: %+v", summary)
	default:
	}
	releaseOnce.Do(func() { close(release) })
	summary := awaitCancellationSummary(t, summaries)
	if summary.Domain != "api.claude.ai" || summary.Type != "AAAA" || summary.Count != 2 {
		t.Fatalf("incorrect cancellation summary: %+v", summary)
	}
	view := r.SchedulerSnapshot("api.claude.ai")
	for _, candidate := range view.Candidates {
		if candidate.Route != "awg:warp" && (candidate.Attempts != 1 || candidate.Failures != 0 || candidate.Score != 25) {
			t.Fatalf("summary penalized canceled worker: %+v", candidate)
		}
	}
	snapshot := s.Logs(0)
	assertLogSnapshot(t, snapshot)
	if len(snapshot.Entries) != 1 {
		t.Fatalf("success/canceled attempts spammed log: %+v", snapshot.Entries)
	}
	entry := snapshot.Entries[0]
	if entry.Event != "canceled" || entry.Domain != summary.Domain || entry.QType != summary.Type || entry.Count != 2 || entry.Message != "" || entry.Route != "" || entry.Upstream != "" {
		t.Fatalf("cancellation log lost context or retained repeated details: %+v", entry)
	}
}

func TestResolverConcurrentSameDomainCancellationSummariesRemainSeparate(t *testing.T) {
	started := make(chan struct{}, 6)
	b := &resolverTestBackend{routes: schedulerTestRoutes(), dialHook: func(ctx context.Context, _, _, _ string) (net.Conn, error) {
		started <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	cfg := Default()
	cfg.Rules, cfg.CacheSize, cfg.TimeoutSeconds = nil, 0, 3
	cfg.DefaultUpstream = Upstream{Address: "https://192.0.2.1/dns-query"}
	r := NewResolver(cfg, b)
	defer r.Close()
	summaries := make(chan CancellationSummary, 3)
	r.SetCancellationObserver(func(summary CancellationSummary) { summaries <- summary })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var requests sync.WaitGroup
	for i := 0; i < 2; i++ {
		requests.Add(1)
		go func(id uint16) {
			defer requests.Done()
			_, _, err := r.Resolve(ctx, resolverWire(t, "same.example", id, mdns.TypeA))
			if err == nil {
				t.Error("canceled request unexpectedly succeeded")
			}
		}(uint16(i))
	}
	for i := 0; i < 6; i++ {
		awaitResolverSignal(t, started, "concurrent DNS attempt")
	}
	cancel()
	requests.Wait()
	for i := 0; i < 2; i++ {
		if summary := awaitCancellationSummary(t, summaries); summary.Domain != "same.example" || summary.Type != "A" || summary.Count != 3 {
			t.Fatalf("concurrent same-domain requests were merged or lost: %+v", summary)
		}
	}
	select {
	case summary := <-summaries:
		t.Fatalf("extra summary for concurrent requests: %+v", summary)
	default:
	}
}

func TestResolverCancellationSummaryExcludesUndispatchedCandidates(t *testing.T) {
	started := make(chan struct{}, maxConcurrentRouteAttempts)
	routes := make([]dnsroute.Route, maxConcurrentRouteAttempts+8)
	for i := range routes {
		routes[i] = dnsroute.Route{ID: fmt.Sprintf("awg:%d", i), Available: true}
	}
	b := &resolverTestBackend{routes: routes, dialHook: func(ctx context.Context, _, _, _ string) (net.Conn, error) {
		started <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	cfg := Default()
	cfg.Rules, cfg.CacheSize, cfg.TimeoutSeconds = nil, 0, 3
	cfg.DefaultUpstream = Upstream{Address: "https://192.0.2.1/dns-query"}
	r := NewResolver(cfg, b)
	defer r.Close()
	summaries := make(chan CancellationSummary, 2)
	r.SetCancellationObserver(func(summary CancellationSummary) { summaries <- summary })
	done := make(chan error, 1)
	go func() {
		_, _, err := r.Resolve(context.Background(), resolverWire(t, "closing.example", 1, mdns.TypeA))
		done <- err
	}()
	for i := 0; i < maxConcurrentRouteAttempts; i++ {
		awaitResolverSignal(t, started, "occupied route attempt slot")
	}
	r.Close()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "context canceled") {
			t.Fatalf("close did not cancel request: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not release request")
	}
	if summary := awaitCancellationSummary(t, summaries); summary.Count != maxConcurrentRouteAttempts {
		t.Fatalf("undispatched candidates counted as canceled: %+v", summary)
	}
	if len(r.attempts) != 0 {
		t.Fatalf("summary preceded slot cleanup: %d", len(r.attempts))
	}
}

func TestResolverAttemptTimeoutRemainsDiagnosticError(t *testing.T) {
	b := &resolverTestBackend{routes: schedulerTestRoutes()[:1], dialHook: func(ctx context.Context, _, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	cfg := Default()
	cfg.Rules, cfg.CacheSize, cfg.TimeoutSeconds = nil, 0, 1
	cfg.DefaultUpstream = Upstream{Address: "https://192.0.2.1/dns-query"}
	r := NewResolver(cfg, b)
	defer r.Close()
	logs := NewLogBuffer()
	logs.SetEnabled(true)
	s := &Service{logs: logs}
	r.SetAttemptObserver(s.recordAttempt)
	r.SetCancellationObserver(s.recordCancellations)
	_, _, err := r.Resolve(context.Background(), resolverWire(t, "timeout.example", 1, mdns.TypeA))
	if err == nil {
		t.Fatal("timed out route unexpectedly resolved DNS")
	}
	snapshot := s.Logs(0)
	if len(snapshot.Entries) != 1 || snapshot.Entries[0].Event != "attempt_error" || !strings.Contains(snapshot.Entries[0].Message, "deadline exceeded") {
		t.Fatalf("real timeout was suppressed or counted as cancellation: %+v", snapshot.Entries)
	}
	if candidates := r.SchedulerSnapshot("timeout.example").Candidates; len(candidates) != 1 || candidates[0].Failures != 1 {
		t.Fatalf("timeout no longer penalizes scheduler: %+v", candidates)
	}
}
