package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"nfqws2strategy/internal/services/dnsroute"
)

func awaitDNSServiceFlightWaiters(t *testing.T, r *Resolver, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		count := 0
		for _, flight := range r.inflight {
			count += flight.waiters
		}
		r.mu.Unlock()
		if count == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("concurrent service queries did not join the shared upstream result")
}

func TestDNSServiceSharedResponsesKeepPerClientObserverAndDeliveryCounters(t *testing.T) {
	for _, observerFails := range []bool{false, true} {
		t.Run(fmt.Sprintf("observer_fails=%v", observerFails), func(t *testing.T) {
			s, backend, _ := newDNSServiceFixture(t, 8)
			started, release := make(chan struct{}), make(chan struct{})
			var startOnce, releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			var observedMu sync.Mutex
			observed := map[string]int{}
			backend.mu.Lock()
			target := backend.address
			backend.routes = []dnsroute.Route{{ID: "nfqws", Name: "NFQWS", Available: true}}
			backend.dialHook = func(ctx context.Context, _, network, _ string) (net.Conn, error) {
				startOnce.Do(func() { close(started) })
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-release:
					return (&net.Dialer{}).DialContext(ctx, network, target)
				}
			}
			backend.observe = func(_ context.Context, domain string, wire []byte, clientIP net.IP) ([]byte, error) {
				observedMu.Lock()
				observed[clientIP.String()]++
				observedMu.Unlock()
				if domain != "shared.example" {
					return nil, errors.New("incorrect observer domain")
				}
				if observerFails && clientIP.String() == "192.168.3.99" {
					return nil, errors.New("fixture per-client routing failure")
				}
				return wire, nil
			}
			backend.mu.Unlock()
			type delivery struct {
				client string
				result TestResult
			}
			results := make(chan delivery, 8)
			query := func(client string) {
				ctx := context.WithValue(context.Background(), clientIPContextKey{}, net.ParseIP(client))
				results <- delivery{client: client, result: s.Test(ctx, "shared.example", "A")}
			}
			go query("192.168.3.1") // deterministic leader; joiners have other devices
			awaitResolverSignal(t, started, "service upstream leader")
			for _, client := range []string{"192.168.3.2", "192.168.3.3", "192.168.3.4", "192.168.3.5", "192.168.3.6", "192.168.3.7", "192.168.3.99"} {
				go query(client)
			}
			awaitDNSServiceFlightWaiters(t, activeDNSRun(s).resolver, 8)
			unblock()
			wantShared, wantFailures := uint64(7), uint64(0)
			if observerFails {
				wantShared, wantFailures = 6, 1
			}
			for range 8 {
				select {
				case got := <-results:
					failed := observerFails && got.client == "192.168.3.99"
					wantSharedFlag := got.client != "192.168.3.1" && !failed
					if got.result.Cached || got.result.Shared != wantSharedFlag || got.result.OK == failed || got.result.Blocked || (got.result.Error != "") != failed {
						t.Fatalf("wrong shared delivery flags for %s: cached=%v shared=%v ok=%v blocked=%v error=%q", got.client, got.result.Cached, got.result.Shared, got.result.OK, got.result.Blocked, got.result.Error)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("shared service response did not complete")
				}
			}
			stats := s.Status().Stats
			if stats.Queries != 8 || stats.SharedResponses != wantShared || stats.CacheHits != 0 || stats.Failures != wantFailures || stats.NFQWSSuccess != 1 || stats.AWGSuccess != 0 {
				t.Fatalf("shared followers were counted as independent upstream/cache responses: queries=%d shared=%d cache=%d fail=%d nfqws=%d awg=%d", stats.Queries, stats.SharedResponses, stats.CacheHits, stats.Failures, stats.NFQWSSuccess, stats.AWGSuccess)
			}
			if calls := len(backend.dialCalls()); calls != 1 {
				t.Fatalf("identical service burst opened %d upstream attempts", calls)
			}
			observedMu.Lock()
			if len(observed) != 8 {
				t.Errorf("shared result skipped device-specific observers: %d clients", len(observed))
			}
			for client, count := range observed {
				if count != 1 {
					t.Errorf("observer for %s ran %d times", client, count)
				}
			}
			observedMu.Unlock()
			events := map[string]uint64{}
			for _, entry := range s.Logs(0).Entries {
				events[entry.Event]++
				if entry.Event == "shared" && (entry.Message == "" || entry.Route != "nfqws" || entry.Upstream == "") {
					t.Fatal("shared log lacks clear delivery/origin metadata")
				}
				if entry.Event == "shared" || entry.Event == "answer" || entry.Event == "error" {
					if entry.Source != "diagnostic" || entry.Transport != "api" || entry.ClientIP == "" || (entry.Event == "shared" && entry.ClientIP == "192.168.3.1") {
						t.Fatalf("shared delivery inherited the initiating client's identity: %+v", entry)
					}
				}
			}
			if events["shared"] != wantShared || events["answer"] != 1 || events["error"] != wantFailures || events["cache"] != 0 {
				t.Fatalf("shared delivery log events were mixed with upstream/cache/error events: %v", events)
			}
			// A later TTL-cache hit is distinct from a shared in-flight answer,
			// clears the previous shared flag and still runs its own observer.
			ctx := context.WithValue(context.Background(), clientIPContextKey{}, net.ParseIP("192.168.3.8"))
			if result := s.Test(ctx, "shared.example", "A"); !result.OK || !result.Cached || result.Shared {
				t.Fatal("subsequent TTL-cache answer retained shared-flight metadata")
			}
			stats = s.Status().Stats
			if !stats.LastCached || stats.LastShared || stats.CacheHits != 1 || stats.SharedResponses != wantShared || stats.NFQWSSuccess != 1 {
				t.Fatal("last delivery/counters do not distinguish TTL-cache from shared network responses")
			}
		})
	}
}
