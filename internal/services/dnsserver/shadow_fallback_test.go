package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

func enableShadowFixture(r *Resolver, b *resolverTestBackend) *shadowTestBackend {
	r.cfg.ShadowDNS.Enabled = true
	r.cfg.RouteMode = RouteModeVPNOnly
	r.shadow = newShadowMatcher(r.cfg.ShadowDNS)
	r.shadowStatus = initialShadowStatus(r.cfg.ShadowDNS)
	// One allowed route makes the expected upstream and request counts exact.
	r.setDisabledMethods([]DisabledMethod{{Route: "awg:first", Upstream: r.cfg.DefaultUpstream.Address}})
	shadow := &shadowTestBackend{resolverTestBackend: b, servers: []string{"192.0.2.53:53"}, addresses: map[string]string{}}
	r.backend = shadow
	return shadow
}

func TestShadowFallbackUsesConfiguredDNSWhenProviderUnavailable(t *testing.T) {
	for _, mode := range []string{"discovery", "no_servers", "unsupported", "connection", "servfail"} {
		t.Run(mode, func(t *testing.T) {
			r, b, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg { return resolverAnswer(q, 900) })
			shadow := enableShadowFixture(r, b)
			switch mode {
			case "discovery":
				shadow.discoveryErr = errors.New("DHCP information unavailable")
			case "no_servers":
				shadow.servers = nil
			case "unsupported":
				r.backend = b
			case "servfail":
				shadow.addresses["udp|192.0.2.53:53"] = shadowDNSFixture(t, "udp", func(q *mdns.Msg) *mdns.Msg {
					return new(mdns.Msg).SetRcode(q, mdns.RcodeServerFailure)
				})
			}
			wire, out, err := r.Resolve(context.Background(), resolverWire(t, "www.ozon.ru", 704, mdns.TypeA))
			if err != nil || out.Error != "" || out.Route != "awg:warp" || out.Upstream != r.cfg.DefaultUpstream.Address {
				t.Fatalf("provider failure did not use configured DNS: %+v %v", out, err)
			}
			var response mdns.Msg
			if err := response.Unpack(wire); err != nil || response.Id != 704 || len(response.Answer) != 1 || response.Answer[0].Header().Ttl != 30 {
				t.Fatalf("fallback response or recovery TTL: %v %v", response, err)
			}
			status := r.ShadowStatus()
			if !status.FallbackActive || status.Error == "" || status.NextProbeAt == "" {
				t.Fatalf("fallback status does not explain provider outage: %+v", status)
			}
			for _, route := range b.dialCalls() {
				if route != "awg:warp" {
					t.Fatalf("fallback bypassed VPN-only or disabled-method policy: %s", route)
				}
			}
		})
	}
}

func TestShadowFallbackPreservesDomainUpstreamAndDisabledMethods(t *testing.T) {
	r, b, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg { return resolverAnswer(q, 60) })
	enableShadowFixture(r, b)
	selected := r.cfg.DefaultUpstream
	// The default endpoint deliberately returns HTML. Only the matching domain
	// rule owns the working DoH endpoint; fallback must retain that selection.
	r.cfg.DefaultUpstream.Address = strings.Replace(selected.Address, "/dns-query", "/html", 1)
	r.cfg.Rules = []Rule{{ID: "ru", Enabled: true, Domain: "ozon.ru", IncludeSubdomains: true, Upstream: selected}}
	_, out, err := r.Resolve(context.Background(), resolverWire(t, "a.ozon.ru", 1, mdns.TypeA))
	if err != nil || out.Route != "awg:warp" || out.Upstream != selected.Address {
		t.Fatalf("lost domain-specific DNS configuration: %+v %v", out, err)
	}
	for _, route := range b.dialCalls() {
		if route != "awg:warp" {
			t.Fatalf("used disallowed route %q", route)
		}
	}
	b.setFailures()
	r.setDisabledMethods([]DisabledMethod{{Route: "awg:first", Upstream: selected.Address}, {Route: "awg:warp", Upstream: selected.Address}})
	_, out, err = r.Resolve(context.Background(), resolverWire(t, "b.ozon.ru", 2, mdns.TypeA))
	if err == nil || out.Error == "" || len(b.dialCalls()) != 0 {
		t.Fatalf("fallback resurrected disabled routes: %+v %v calls=%v", out, err, b.dialCalls())
	}
}

func TestShadowFallbackCooldownCacheAndProviderRecovery(t *testing.T) {
	var dohQueries atomic.Int32
	r, b, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg {
		dohQueries.Add(1)
		return resolverAnswer(q, 3600)
	})
	shadow := enableShadowFixture(r, b)
	r.cfg.CacheSize = 64
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	r.now = func() time.Time { return time.Unix(0, clock.Load()) }
	for i := 0; i < 2; i++ {
		_, out, err := r.Resolve(context.Background(), resolverWire(t, "ozon.ru", uint16(i+1), mdns.TypeA))
		if err != nil || out.Route != "awg:warp" || out.Cached != (i == 1) {
			t.Fatalf("fallback cache response %d: %+v %v", i, out, err)
		}
	}
	if shadow.count() != 1 || dohQueries.Load() != 1 {
		t.Fatalf("repeat query missed cache: provider=%d doh=%d", shadow.count(), dohQueries.Load())
	}
	if snapshot := r.SchedulerSnapshot("ozon.ru"); snapshot.Reason == "shadow" || snapshot.EffectiveCandidateCount != 1 || len(snapshot.Candidates) == 0 {
		t.Fatalf("scheduler hides the configured fallback candidates: %+v", snapshot)
	}
	udp := shadowDNSFixture(t, "udp", func(q *mdns.Msg) *mdns.Msg { return resolverAnswer(q, 300) })
	shadow.shadowMu.Lock()
	shadow.addresses["udp|192.0.2.53:53"] = udp
	shadow.shadowMu.Unlock()
	for i := 0; i < 3; i++ {
		_, out, err := r.Resolve(context.Background(), resolverWire(t, fmt.Sprintf("cooldown%d.ru", i), uint16(i+10), mdns.TypeA))
		if err != nil || out.Route != "awg:warp" {
			t.Fatalf("cooldown fallback %d: %+v %v", i, out, err)
		}
	}
	if shadow.count() != 1 {
		t.Fatal("each new domain retried the unavailable provider during cooldown")
	}
	clock.Add(int64(31 * time.Second))
	_, out, err := r.Resolve(context.Background(), resolverWire(t, "ozon.ru", 30, mdns.TypeA))
	if err != nil || out.Route != shadowRoute || out.Cached || shadow.count() != 2 || dohQueries.Load() != 4 {
		t.Fatalf("provider did not recover after fallback cache expiry: %+v %v provider=%d doh=%d", out, err, shadow.count(), dohQueries.Load())
	}
	if status := r.ShadowStatus(); status.FallbackActive || status.Error != "" || status.NextProbeAt != "" {
		t.Fatalf("stale provider outage after recovery: %+v", status)
	}
	if snapshot := r.SchedulerSnapshot("ozon.ru"); snapshot.Reason != "shadow" || len(snapshot.Candidates) != 0 {
		t.Fatalf("scheduler still presents DoH as the active Shadow route: %+v", snapshot)
	}
	_, out, err = r.Resolve(context.Background(), resolverWire(t, "ozon.ru", 31, mdns.TypeA))
	if err != nil || out.Route != shadowRoute || !out.Cached || shadow.count() != 2 {
		t.Fatalf("recovered provider result is not cached: %+v %v", out, err)
	}
}

func TestShadowValidNXDOMAINDoesNotTriggerFallback(t *testing.T) {
	var dohQueries atomic.Int32
	r, b, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg {
		dohQueries.Add(1)
		return resolverAnswer(q, 60)
	})
	shadow := enableShadowFixture(r, b)
	shadow.addresses["udp|192.0.2.53:53"] = shadowDNSFixture(t, "udp", func(q *mdns.Msg) *mdns.Msg {
		return new(mdns.Msg).SetRcode(q, mdns.RcodeNameError)
	})
	wire, out, err := r.Resolve(context.Background(), resolverWire(t, "missing.ozon.ru", 1, mdns.TypeA))
	var response mdns.Msg
	decodeErr := response.Unpack(wire)
	if err != nil || decodeErr != nil || response.Rcode != mdns.RcodeNameError || out.Route != shadowRoute || dohQueries.Load() != 0 || len(b.dialCalls()) != 0 || r.ShadowStatus().FallbackActive {
		t.Fatalf("valid negative answer treated as provider outage: %+v %v decode=%v rcode=%d doh=%d", out, err, decodeErr, response.Rcode, dohQueries.Load())
	}
}

type shadowControlledDialBackend struct {
	*shadowTestBackend
	dial func(context.Context, string, string) (net.Conn, error)
}

func (b *shadowControlledDialBackend) DialShadowDNS(ctx context.Context, network, address string) (net.Conn, error) {
	return b.dial(ctx, network, address)
}

func TestShadowCancellationDoesNotActivateFallback(t *testing.T) {
	r, b, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg { return resolverAnswer(q, 60) })
	shadow := enableShadowFixture(r, b)
	entered := make(chan struct{})
	r.backend = &shadowControlledDialBackend{shadowTestBackend: shadow, dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wire := resolverWire(t, "ozon.ru", 1, mdns.TypeA)
	query := new(mdns.Msg)
	if err := query.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := r.resolveUncached(ctx, query, wire, "ozon.ru")
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("provider lookup did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation was lost: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("provider cancellation did not terminate")
	}
	if status := r.ShadowStatus(); status.FallbackActive || status.Error != "" || status.NextProbeAt != "" || len(b.dialCalls()) != 0 {
		t.Fatalf("cancellation marked outage or dialed configured DoH: %+v calls=%v", status, b.dialCalls())
	}
}

func TestShadowProviderTimeoutLeavesBudgetForConfiguredDNS(t *testing.T) {
	r, b, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg { return resolverAnswer(q, 60) })
	shadow := enableShadowFixture(r, b)
	r.backend = &shadowControlledDialBackend{shadowTestBackend: shadow, dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	_, out, err := r.Resolve(ctx, resolverWire(t, "ozon.ru", 1, mdns.TypeA))
	if err != nil || out.Route != "awg:warp" || !r.ShadowStatus().FallbackActive {
		t.Fatalf("provider child timeout consumed fallback budget: %+v %v status=%+v", out, err, r.ShadowStatus())
	}
}

func TestShadowCanceledRecoveryAllowsNextRequestToRetry(t *testing.T) {
	r, b, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg { return resolverAnswer(q, 60) })
	shadow := enableShadowFixture(r, b)
	udp := shadowDNSFixture(t, "udp", func(q *mdns.Msg) *mdns.Msg { return resolverAnswer(q, 60) })
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	r.now = func() time.Time { return time.Unix(0, clock.Load()) }
	var probes atomic.Int32
	entered := make(chan struct{})
	r.backend = &shadowControlledDialBackend{shadowTestBackend: shadow, dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		switch probes.Add(1) {
		case 1:
			return nil, errors.New("provider offline")
		case 2:
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		default:
			return (&net.Dialer{}).DialContext(ctx, network, udp)
		}
	}}
	if _, _, err := r.Resolve(context.Background(), resolverWire(t, "initial.ru", 1, mdns.TypeA)); err != nil {
		t.Fatal(err)
	}
	before := r.ShadowStatus()
	clock.Add(int64(31 * time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wire := resolverWire(t, "probe.ru", 2, mdns.TypeA)
	query := new(mdns.Msg)
	if err := query.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := r.resolveUncached(ctx, query, wire, "probe.ru")
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("recovery probe did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("recovery cancellation lost: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("recovery cancellation did not terminate")
	}
	if after := r.ShadowStatus(); !after.FallbackActive || after.NextProbeAt != before.NextProbeAt || after.Error != before.Error {
		t.Fatalf("cancellation replaced the outage or postponed recovery: before=%+v after=%+v", before, after)
	}
	_, out, err := r.Resolve(context.Background(), resolverWire(t, "retry.ru", 3, mdns.TypeA))
	if err != nil || out.Route != shadowRoute || probes.Load() != 3 || r.ShadowStatus().FallbackActive {
		t.Fatalf("canceled probe remained locked: %+v %v probes=%d status=%+v", out, err, probes.Load(), r.ShadowStatus())
	}
}

func TestShadowFallbackConcurrentDomainsUseOneRecoveryProbe(t *testing.T) {
	r, b, _ := newResolverFixture(t, func(q *mdns.Msg) *mdns.Msg { return resolverAnswer(q, 60) })
	shadow := enableShadowFixture(r, b)
	r.cfg.TimeoutSeconds = 5
	udp := shadowDNSFixture(t, "udp", func(q *mdns.Msg) *mdns.Msg { return resolverAnswer(q, 60) })
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	r.now = func() time.Time { return time.Unix(0, clock.Load()) }
	var probes atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	r.backend = &shadowControlledDialBackend{shadowTestBackend: shadow, dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		count := probes.Add(1)
		if count == 1 {
			return nil, errors.New("provider offline")
		}
		if count == 2 {
			close(entered)
		}
		select {
		case <-release:
			return (&net.Dialer{}).DialContext(ctx, network, udp)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	if _, out, err := r.Resolve(context.Background(), resolverWire(t, "first.ru", 1, mdns.TypeA)); err != nil || out.Route != "awg:warp" {
		t.Fatalf("initial fallback failed: %+v %v", out, err)
	}
	clock.Add(int64(31 * time.Second))
	type result struct {
		out Outcome
		err error
	}
	recovered := make(chan result, 1)
	probeWire := resolverWire(t, "probe.ru", 2, mdns.TypeA)
	go func() {
		_, out, err := r.Resolve(context.Background(), probeWire)
		recovered <- result{out, err}
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("recovery probe did not start")
	}
	others := make(chan result, 6)
	for i := 0; i < cap(others); i++ {
		wire := resolverWire(t, fmt.Sprintf("other%d.ru", i), uint16(i+3), mdns.TypeA)
		go func() {
			_, out, err := r.Resolve(context.Background(), wire)
			others <- result{out, err}
		}()
	}
	for i := 0; i < cap(others); i++ {
		select {
		case answer := <-others:
			if answer.err != nil || answer.out.Route != "awg:warp" {
				t.Fatalf("another domain waited for recovery instead of using configured DNS: %+v", answer)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("other domains stalled behind provider probe")
		}
	}
	if probes.Load() != 2 {
		t.Fatalf("concurrent domains started %d probes instead of one recovery probe", probes.Load()-1)
	}
	unblock()
	select {
	case answer := <-recovered:
		if answer.err != nil || answer.out.Route != shadowRoute || r.ShadowStatus().FallbackActive {
			t.Fatalf("recovery failed: %+v status=%+v", answer, r.ShadowStatus())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("recovery probe did not finish")
	}
}
