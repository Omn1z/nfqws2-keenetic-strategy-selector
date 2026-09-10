package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"nfqws2strategy/internal/services/dnsroute"
)

func disabledMethodQuery(t *testing.T) []byte {
	t.Helper()
	query := new(mdns.Msg)
	query.SetQuestion("example.com.", mdns.TypeA)
	wire, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestMethodDisableCancelsActiveAttemptWithoutSchedulerPenalty(t *testing.T) {
	cfg := Default()
	cfg.FastDNS, cfg.CacheSize, cfg.Rules = false, 0, nil
	started := make(chan struct{})
	backend := &resolverTestBackend{routes: []dnsroute.Route{{ID: "nfqws", Available: true}}, dialHook: func(ctx context.Context, _, _, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	r := NewResolver(cfg, backend)
	defer r.Close()
	cancellations := make(chan CancellationSummary, 1)
	r.SetCancellationObserver(func(summary CancellationSummary) { cancellations <- summary })
	done := make(chan error, 1)
	wire := disabledMethodQuery(t)
	go func() {
		_, _, err := r.Resolve(context.Background(), wire)
		done <- err
	}()
	<-started
	r.setDisabledMethods([]DisabledMethod{{Upstream: cfg.DefaultUpstream.Address, Route: "nfqws"}})
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), errMethodDisabled.Error()) {
			t.Fatalf("disabled active attempt returned wrong result: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("active socket was not canceled promptly")
	}
	select {
	case summary := <-cancellations:
		if summary.Count != 1 {
			t.Fatalf("wrong neutral cancellation count: %+v", summary)
		}
	case <-time.After(time.Second):
		t.Fatal("active cancellation not recorded as neutral")
	}
	view := r.SchedulerSnapshot("").Candidates[0]
	if !view.Disabled || view.Position != 0 || view.Attempts != 1 || view.Successes != 0 || view.Failures != 0 || view.ConsecutiveFailures != 0 || view.LastResultAt != "" {
		t.Fatalf("manual disable changed scheduler evidence: %+v", view)
	}
}

func TestMethodDisableRechecksQueuedAttemptBeforeDial(t *testing.T) {
	cfg := Default()
	cfg.FastDNS, cfg.CacheSize, cfg.Rules = false, 0, nil
	var calls atomic.Int32
	backend := &resolverTestBackend{routes: []dnsroute.Route{{ID: "nfqws", Available: true}}, dialHook: func(context.Context, string, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("unexpected dial")
	}}
	r := NewResolver(cfg, backend)
	defer r.Close()
	for range maxConcurrentRouteAttempts {
		r.attempts <- struct{}{}
	}
	done := make(chan error, 1)
	wire := disabledMethodQuery(t)
	go func() {
		_, _, err := r.Resolve(context.Background(), wire)
		done <- err
	}()
	waitFastDNS(t, func() bool {
		r.scheduler.mu.Lock()
		defer r.scheduler.mu.Unlock()
		return r.scheduler.races == 1
	})
	r.setDisabledMethods([]DisabledMethod{{Upstream: cfg.DefaultUpstream.Address, Route: "nfqws"}})
	<-r.attempts
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), errMethodDisabled.Error()) {
			t.Fatalf("queued disabled attempt result: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("disabled queued attempt did not finish")
	}
	if calls.Load() != 0 || r.SchedulerSnapshot("").Candidates[0].Attempts != 0 {
		t.Fatal("queued disabled pair dialed or gained a scheduler start")
	}
}

func TestMethodDisableAllPairsDoesNotEscapeSpecialPool(t *testing.T) {
	cfg := Default()
	cfg.CacheSize = 0
	backend := &resolverTestBackend{routes: []dnsroute.Route{{ID: "nfqws", Available: true}, {ID: "awg:warp", Available: true}}, dialHook: func(context.Context, string, string, string) (net.Conn, error) {
		t.Error("all-disabled special pool dialed a provider")
		return nil, errors.New("unexpected dial")
	}}
	for _, route := range backend.routes {
		cfg.DisabledMethods = append(cfg.DisabledMethods, DisabledMethod{Upstream: cfg.Rules[0].Upstream.Address, Route: route.ID})
	}
	r := NewResolver(cfg, backend)
	defer r.Close()
	query := new(mdns.Msg)
	query.SetQuestion("claude.com.", mdns.TypeA)
	wire, _ := query.Pack()
	_, outcome, err := r.Resolve(context.Background(), wire)
	if err == nil || !strings.Contains(err.Error(), "выключенные методы") || outcome.Upstream != cfg.Rules[0].Upstream.Address {
		t.Fatalf("missing actionable all-disabled error: %+v %v", outcome, err)
	}
}

func TestMethodDisableFastDNSKeepsSharedProfilesAndCancelsLastHost(t *testing.T) {
	cfg := Default()
	cfg.DefaultUpstream = Upstream{Address: "https://resolver.example/profile-a"}
	cfg.DefaultPool = []Upstream{{Address: "https://resolver.example/profile-b"}}
	cfg.Rules = nil
	backend := &resolverTestBackend{routes: []dnsroute.Route{{ID: "nfqws", Available: true}, {ID: "awg:warp", Available: true}}}
	r := NewResolver(cfg, backend)
	defer r.Close()
	var calls atomic.Int32
	r.fastDNS.lookup = func(context.Context, string, string) ([]string, error) {
		calls.Add(1)
		return []string{"192.0.2.1"}, nil
	}
	if _, err := r.fastDNS.Lookup(context.Background(), "nfqws", "resolver.example"); err != nil {
		t.Fatal(err)
	}
	disabledA := DisabledMethod{Upstream: cfg.DefaultUpstream.Address, Route: "nfqws"}
	disabledB := DisabledMethod{Upstream: cfg.DefaultPool[0].Address, Route: "nfqws"}
	r.setDisabledMethods([]DisabledMethod{disabledA})
	if _, err := r.fastDNS.Lookup(context.Background(), "nfqws", "resolver.example"); err != nil || calls.Load() != 1 {
		t.Fatalf("disabling one URL profile discarded shared host cache: %v calls=%d", err, calls.Load())
	}
	r.setDisabledMethods([]DisabledMethod{disabledA, disabledB})
	if r.fastDNS.Snapshot().Entries != 0 {
		t.Fatal("last disabled profile retained automatic bootstrap work")
	}
	if _, err := r.fastDNS.Lookup(context.Background(), "nfqws", "resolver.example"); !errors.Is(err, errMethodDisabled) {
		t.Fatalf("disabled host was warmed on demand: %v", err)
	}
	wantTargets := []FastDNSTarget{{Route: "awg:warp", Host: "resolver.example"}}
	if got := fastDNSTargets(r.policyConfig(), backend.Routes()); !reflect.DeepEqual(got, wantTargets) {
		t.Fatalf("host warming crossed disabled route/profile: %v", got)
	}
	r.fastDNS.maintain()
	waitFastDNS(t, func() bool { return r.fastDNS.Snapshot().Ready == 1 && r.fastDNS.Snapshot().Refreshing == 0 })
	if calls.Load() != 2 {
		t.Fatalf("maintenance restarted disabled NFQWS bootstrap: %d", calls.Load())
	}
	// Reenable the host, then disable it again while its bootstrap is active.
	r.setDisabledMethods([]DisabledMethod{disabledA})
	started := make(chan struct{})
	r.fastDNS.lookup = func(ctx context.Context, _, _ string) ([]string, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	done := make(chan error, 1)
	go func() {
		_, err := r.fastDNS.Lookup(context.Background(), "nfqws", "resolver.example")
		done <- err
	}()
	<-started
	r.setDisabledMethods([]DisabledMethod{disabledA, disabledB})
	select {
	case err := <-done:
		if !errors.Is(err, errMethodDisabled) {
			t.Fatalf("bootstrap cancellation lost policy reason: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("in-flight disabled bootstrap was not canceled")
	}
	if r.fastDNS.Snapshot().Entries != 1 {
		t.Fatal("disabled bootstrap result repopulated the cache")
	}
}

func TestMethodDisableAlsoBlocksAndCancelsLiteralBootstrapProviders(t *testing.T) {
	cfg := Default()
	cfg.DefaultUpstream = Upstream{Address: "https://resolver.example/dns-query"}
	cfg.Rules = nil
	cloudflare := DisabledMethod{Route: "nfqws", Upstream: "https://1.1.1.1/dns-query"}
	google := DisabledMethod{Route: "nfqws", Upstream: "https://8.8.8.8/dns-query"}
	started := make(chan struct{})
	var calls atomic.Int32
	backend := &resolverTestBackend{routes: []dnsroute.Route{{ID: "nfqws", Available: true}}, dialHook: func(ctx context.Context, _, _, addr string) (net.Conn, error) {
		calls.Add(1)
		if addr == "1.1.1.1:443" {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("remaining bootstrap unavailable: %s", addr)
	}}
	r := NewResolver(cfg, backend)
	defer r.Close()
	done := make(chan error, 1)
	go func() {
		_, _, err := r.lookupEndpointIPs(context.Background(), "nfqws", "resolver.example")
		done <- err
	}()
	<-started
	r.setDisabledMethods([]DisabledMethod{cloudflare})
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "remaining bootstrap unavailable") || calls.Load() != 2 {
			t.Fatalf("disabling bootstrap did not cancel and try the next allowed provider: %v calls=%d", err, calls.Load())
		}
	case <-time.After(time.Second):
		t.Fatal("literal bootstrap did not respond to hot disable")
	}
	r.setDisabledMethods([]DisabledMethod{cloudflare, google})
	if _, _, err := r.lookupEndpointIPs(context.Background(), "nfqws", "resolver.example"); err == nil || calls.Load() != 2 {
		t.Fatalf("disabled literal provider was reused for implicit bootstrap: %v calls=%d", err, calls.Load())
	}
}
