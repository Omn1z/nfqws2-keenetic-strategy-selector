package dnsserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"nfqws2strategy/internal/tools/store"
)

func maintenanceQuestion(t *testing.T, req *http.Request) *mdns.Msg {
	t.Helper()
	wire, err := io.ReadAll(req.Body)
	if err != nil {
		if req.Context().Err() == nil {
			t.Error(err)
		}
		return nil
	}
	var question mdns.Msg
	if err := question.Unpack(wire); err != nil || len(question.Question) != 1 {
		t.Errorf("invalid maintenance question: %+v, %v", question.Question, err)
		return nil
	}
	return &question
}

func maintenanceReply(t *testing.T, w http.ResponseWriter, question *mdns.Msg) {
	t.Helper()
	answer := resolverAnswer(question, 60)
	if question.Question[0].Qtype == mdns.TypeNS {
		answer.Answer = []mdns.RR{&mdns.NS{Hdr: mdns.RR_Header{Name: ".", Rrtype: mdns.TypeNS, Class: mdns.ClassINET, Ttl: 60}, Ns: "a.root-servers.net."}}
	}
	wire, err := answer.Pack()
	if err != nil {
		t.Error(err)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	_, _ = w.Write(wire)
}

func TestSchedulerMaintenanceProbeSurvivesClientWinnerAndDoesNotCacheReplies(t *testing.T) {
	probeStarted, probeCanceled, releaseProbe := make(chan struct{}), make(chan struct{}), make(chan struct{})
	userStarted, userCanceled := make(chan struct{}), make(chan struct{})
	r, backend := newPoolResolverFixture(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		question := maintenanceQuestion(t, req)
		if question == nil {
			return
		}
		if question.Question[0].Qtype == mdns.TypeNS {
			close(probeStarted)
			select {
			case <-releaseProbe:
				maintenanceReply(t, w, question)
			case <-req.Context().Done():
				close(probeCanceled)
			}
			return
		}
		if req.URL.Path == "/primary" {
			close(userStarted)
			<-req.Context().Done()
			close(userCanceled)
			return
		}
		select {
		case <-userStarted:
			maintenanceReply(t, w, question)
		case <-req.Context().Done():
		}
	}))
	backend.routes = backend.routes[:1]
	r.cfg.CacheSize, r.cfg.TimeoutSeconds = 8, 5
	var observed atomic.Int32
	backend.observe = func(_ context.Context, _ string, wire []byte, _ net.IP) ([]byte, error) {
		observed.Add(1)
		return wire, nil
	}
	done := make(chan struct{})
	go func() { r.runSchedulerProbe(); close(done) }()
	awaitResolverSignal(t, probeStarted, "independent root NS probe")
	if status := r.CacheStatus(); status.Entries != 0 {
		t.Fatalf("probe populated answer cache before completion: %+v", status)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, outcome, err := r.Resolve(ctx, resolverWire(t, "example.com", 71, mdns.TypeA))
	if err != nil || outcome.Cached || outcome.Upstream != r.cfg.DefaultPool[0].Address {
		t.Fatalf("ordinary race did not return secondary independently: %+v, %v", outcome, err)
	}
	awaitResolverSignal(t, userCanceled, "ordinary losing request cancellation")
	select {
	case <-done:
		t.Fatal("ordinary winner terminated the independent probe")
	case <-probeCanceled:
		t.Fatal("ordinary winner canceled the independent probe context")
	default:
	}
	close(releaseProbe)
	awaitResolverSignal(t, done, "independent probe result")
	if got := r.CacheStatus().Entries; got != 1 {
		t.Fatalf("probe reply changed the client answer cache: entries=%d", got)
	}
	if observed.Load() != 0 {
		t.Fatal("maintenance probe trained backend domain/IP routing")
	}
	view := r.SchedulerSnapshot("")
	for _, candidate := range view.Candidates {
		if candidate.Upstream == r.cfg.DefaultUpstream.Address && (candidate.ProbeSuccesses != 1 || candidate.ProbeFailures != 0 || candidate.Successes != 1 || candidate.Failures != 0 || candidate.Probing) {
			t.Fatalf("probe did not supply independent successful evidence: %+v", candidate)
		}
	}
	if view.ActiveProbes != 0 {
		t.Fatal("completed probe retained its scheduler lease")
	}
}

func TestSchedulerMaintenanceSpecialPoolReplyDoesNotBecomeClientAnswer(t *testing.T) {
	requests := make(chan struct {
		path string
		q    mdns.Question
	}, 1)
	r, backend := newPoolResolverFixture(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		question := maintenanceQuestion(t, req)
		if question == nil {
			return
		}
		requests <- struct {
			path string
			q    mdns.Question
		}{req.URL.Path, question.Question[0]}
		maintenanceReply(t, w, question)
	}))
	backend.routes = backend.routes[:1]
	special := r.cfg.DefaultPool[0]
	r.cfg.DefaultPool = nil
	r.cfg.Rules = []Rule{{ID: "special", Enabled: true, Domain: "claude.ai", Upstream: special}}
	r.cfg.CacheSize = 8
	r.scheduler.record(AttemptEvent{Route: backend.routes[0].ID, Upstream: r.cfg.DefaultUpstream.Address, Success: true, DurationMS: 20})
	var observed atomic.Int32
	backend.observe = func(_ context.Context, _ string, wire []byte, _ net.IP) ([]byte, error) {
		observed.Add(1)
		return wire, nil
	}
	r.runSchedulerProbe()
	select {
	case request := <-requests:
		if request.path != "/secondary" || request.q.Name != "claude.ai." || request.q.Qtype != mdns.TypeA {
			t.Fatalf("special domain sent to wrong pool or with wrong question: %+v", request)
		}
	default:
		t.Fatal("special pool probe did not reach its upstream")
	}
	if r.CacheStatus().Entries != 0 || observed.Load() != 0 {
		t.Fatal("special probe produced a client answer or backend route observation")
	}
	if candidate := r.SchedulerSnapshot("claude.ai").Candidates[0]; candidate.ProbeSuccesses != 1 {
		t.Fatalf("special probe was not measured: %+v", candidate)
	}
}

func TestSchedulerMaintenanceSkipsWhenClientAttemptSlotsFull(t *testing.T) {
	backend := &resolverTestBackend{routes: schedulerTestRoutes()}
	r := NewResolver(Default(), backend)
	defer r.Close()
	for range cap(r.attempts) {
		r.attempts <- struct{}{}
	}
	done := make(chan struct{})
	go func() { r.runSchedulerProbe(); close(done) }()
	awaitResolverSignal(t, done, "nonblocking probe skip under client load")
	view := r.SchedulerSnapshot("")
	if len(backend.dialCalls()) != 0 || view.TrackedPairs != 0 || view.ActiveProbes != 0 || len(r.attempts) != cap(r.attempts) {
		t.Fatalf("skipped probe consumed client capacity or changed scheduler evidence: %+v, slots=%d", view, len(r.attempts))
	}
	for _, candidate := range view.Candidates {
		if candidate.Attempts != 0 || candidate.ProbeAttempts != 0 || candidate.LastProbeAt != "" {
			t.Fatalf("skipped probe changed counters: %+v", candidate)
		}
	}
}

func TestSchedulerMaintenanceShutdownCancelsProbeNeutrally(t *testing.T) {
	started, canceled := make(chan struct{}), make(chan struct{})
	r, backend := newPoolResolverFixture(t, http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		if maintenanceQuestion(t, req) == nil {
			return
		}
		close(started)
		<-req.Context().Done()
		close(canceled)
	}))
	backend.routes = backend.routes[:1]
	r.cfg.DefaultPool, r.cfg.TimeoutSeconds = nil, 5
	var notifications atomic.Int32
	r.SetAttemptObserver(func(AttemptEvent) { notifications.Add(1) })
	done := make(chan struct{})
	go func() { r.runSchedulerProbe(); close(done) }()
	awaitResolverSignal(t, started, "active probe before shutdown")
	if len(r.attempts) != 1 || r.SchedulerSnapshot("").ActiveProbes != 1 {
		t.Fatal("active probe does not occupy exactly one slot and lease")
	}
	r.Close()
	awaitResolverSignal(t, done, "probe shutdown completion")
	awaitResolverSignal(t, canceled, "probe upstream cancellation")
	view := r.SchedulerSnapshot("")
	candidate := view.Candidates[0]
	if len(r.attempts) != 0 || view.ActiveProbes != 0 || candidate.Probing || candidate.ProbeAttempts != 1 || candidate.ProbeFailures != 0 || candidate.ProbeSuccesses != 0 || candidate.Failures != 0 || candidate.LastResultAt != "" || candidate.Score != 25 || notifications.Load() != 0 {
		t.Fatalf("shutdown leaked resources or penalized the probe: %+v, slots=%d, notifications=%d", view, len(r.attempts), notifications.Load())
	}
}

func TestSchedulerMaintenanceFailedProbeRecordsDiagnostic(t *testing.T) {
	r, backend := newPoolResolverFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	backend.routes = backend.routes[:1]
	r.cfg.DefaultPool = nil
	events := make(chan AttemptEvent, 1)
	r.SetAttemptObserver(func(event AttemptEvent) { events <- event })
	r.runSchedulerProbe()
	select {
	case event := <-events:
		if event.Canceled || event.Success || event.Domain != "." || event.Type != "NS" || !strings.Contains(event.Error, "Фоновая проверка: ") || !strings.Contains(event.Error, "503") {
			t.Fatalf("missing contextual probe error: %+v", event)
		}
	default:
		t.Fatal("failed probe emitted no diagnostic")
	}
	if candidate := r.SchedulerSnapshot("").Candidates[0]; candidate.ProbeFailures != 1 || candidate.Failures != 1 || candidate.Probing {
		t.Fatalf("failed probe did not update scheduler: %+v", candidate)
	}
}

func TestFastDNSConfigLegacyDefaultAndExplicitOffPersist(t *testing.T) {
	for _, legacy := range []bool{true, false} {
		t.Run(fmt.Sprintf("legacy=%v", legacy), func(t *testing.T) {
			st, err := store.New(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			cfg := Default()
			cfg.FastDNS = false
			raw, _ := json.Marshal(cfg)
			var saved map[string]any
			if err := json.Unmarshal(raw, &saved); err != nil {
				t.Fatal(err)
			}
			if legacy {
				delete(saved, "fast_dns")
			}
			if err := st.Save(configFile, saved); err != nil {
				t.Fatal(err)
			}
			s := New(st, &resolverTestBackend{}, func(string) (string, error) { return "127.0.0.1", nil })
			defer s.Close()
			if s.Config().FastDNS != legacy || s.Status().FastDNS.Enabled != legacy {
				t.Fatalf("legacy default overrode explicit disabled setting: %+v", s.Status())
			}
			updated := s.Config()
			updated.FastDNS = false
			if err := s.SetConfig(updated); err != nil {
				t.Fatal(err)
			}
			reopened := New(st, &resolverTestBackend{}, func(string) (string, error) { return "127.0.0.1", nil })
			defer reopened.Close()
			if reopened.Config().FastDNS || reopened.Status().FastDNS.Enabled {
				t.Fatal("explicit FastDNS off did not survive saving and reload")
			}
		})
	}
}

func TestResolverFastDNSManualBootstrapAndLiteralAddressBypassCache(t *testing.T) {
	r := NewResolver(Default(), &resolverTestBackend{})
	defer r.Close()
	var lookups atomic.Int32
	r.fastDNS = NewFastDNSCache(r.lifetime, func(context.Context, string, string) ([]string, error) {
		lookups.Add(1)
		return nil, fmt.Errorf("unexpected automatic lookup")
	}, nil)
	u := Upstream{Address: "https://dns.example/dns-query", BootstrapIPs: []string{"192.0.2.15", "2001:db8::15"}}
	ips, err := r.endpointIPs(context.Background(), "nfqws", u, "dns.example")
	if err != nil || !reflect.DeepEqual(ips, u.BootstrapIPs) || lookups.Load() != 0 || r.fastDNS.Snapshot().Entries != 0 {
		t.Fatalf("manual bootstrap went through automatic FastDNS lookup: %v, %v", ips, err)
	}
	ips[0] = "192.0.2.99"
	if u.BootstrapIPs[0] != "192.0.2.15" {
		t.Fatal("manual bootstrap result aliases saved configuration")
	}
	ips, err = r.endpointIPs(context.Background(), "nfqws", Upstream{Address: "https://1.1.1.1/dns-query"}, "1.1.1.1")
	if err != nil || !reflect.DeepEqual(ips, []string{"1.1.1.1"}) || lookups.Load() != 0 {
		t.Fatalf("literal provider attempted hostname lookup: %v, %v", ips, err)
	}
}

type maintenanceRoundTripper func(*http.Request) (*http.Response, error)

func (f maintenanceRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestResolverFastDNSDisabledKeepsLegacyRouteScopedBootstrapCache(t *testing.T) {
	cfg := Default()
	cfg.FastDNS = false
	r := NewResolver(cfg, &resolverTestBackend{})
	defer r.Close()
	if r.fastDNS != nil {
		t.Fatal("disabled FastDNS allocated an active cache")
	}
	now := time.Unix(10000, 0)
	r.now = func() time.Time { return now }
	var lookups atomic.Int32
	client := &http.Client{Transport: maintenanceRoundTripper(func(req *http.Request) (*http.Response, error) {
		question := maintenanceQuestion(t, req)
		if question == nil {
			return nil, fmt.Errorf("invalid bootstrap query")
		}
		if question.Question[0].Name != "dns.example." || req.URL.Hostname() != "1.1.1.1" {
			t.Errorf("legacy lookup did not use pinned independent DoH: %s, %v", req.URL, question.Question)
		}
		lookups.Add(1)
		wire, err := resolverAnswer(question, 60).Pack()
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/dns-message"}}, Body: io.NopCloser(bytes.NewReader(wire))}, err
	})}
	r.clients["nfqws|1.1.1.1|1.1.1.1:443"] = client
	r.clients["awg:warp|1.1.1.1|1.1.1.1:443"] = client
	upstream := Upstream{Address: "https://dns.example/dns-query"}
	for range 2 {
		ips, err := r.endpointIPs(context.Background(), "nfqws", upstream, "dns.example")
		if err != nil || !reflect.DeepEqual(ips, []string{"203.0.113.20"}) {
			t.Fatalf("legacy bootstrap failed: %v, %v", ips, err)
		}
	}
	if lookups.Load() != 1 {
		t.Fatal("disabled FastDNS stopped reusing the ordinary bootstrap TTL cache")
	}
	if _, err := r.endpointIPs(context.Background(), "awg:warp", upstream, "dns.example"); err != nil || lookups.Load() != 2 {
		t.Fatalf("legacy cache was shared across routes: lookups=%d, %v", lookups.Load(), err)
	}
	now = now.Add(61 * time.Second)
	if _, err := r.endpointIPs(context.Background(), "nfqws", upstream, "dns.example"); err != nil || lookups.Load() != 3 {
		t.Fatalf("legacy bootstrap TTL stopped expiring: lookups=%d, %v", lookups.Load(), err)
	}
}
