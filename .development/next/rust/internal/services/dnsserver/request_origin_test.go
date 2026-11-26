package dnsserver

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	mdns "github.com/miekg/dns"
)

func TestDNSListenerOriginIdentifiesSocketPeerWithoutGuessingForwardedDevice(t *testing.T) {
	for _, tc := range []struct {
		peer, bind, transport, source, ip string
	}{
		{"192.168.3.40:54832", "192.168.3.1", "udp", "client", "192.168.3.40"},
		{"192.168.3.1:54832", "192.168.3.1", "tcp", "local", "192.168.3.1"},
		{"127.0.0.1:54832", "192.168.3.1", "udp", "local", "127.0.0.1"},
		{"[::1]:54832", "::1", "tcp", "local", "::1"},
		{"[fd00::40]:54832", "fd00::1", "udp", "client", "fd00::40"},
	} {
		ctx := withListenerOrigin(context.Background(), tc.peer, tc.bind, tc.transport)
		origin := requestOriginFromContext(ctx)
		if origin != (requestOrigin{ClientIP: tc.ip, Source: tc.source, Transport: tc.transport}) || !ContextClientIP(ctx).Equal(net.ParseIP(tc.ip)) {
			t.Fatalf("peer %s has incorrect origin: %+v", tc.peer, origin)
		}
	}
	if got := requestOriginFromContext(context.Background()); got != (requestOrigin{Source: "internal"}) {
		t.Fatalf("context without client identity claimed a LAN sender: %+v", got)
	}
}

func TestDNSServiceLogsDistinguishTCPUDPDiagnosticAndInternalCachedAnswers(t *testing.T) {
	s, backend, udp := newDNSServiceFixture(t, 8)
	s.logs.Clear()
	var mu sync.Mutex
	observed := map[string]int{}
	backend.mu.Lock()
	backend.observe = func(_ context.Context, _ string, wire []byte, ip net.IP) ([]byte, error) {
		mu.Lock()
		observed[ip.String()]++
		mu.Unlock()
		return wire, nil
	}
	backend.mu.Unlock()
	queryDNSService(t, udp, s.Status().Endpoints.DNS, 1)
	tcp := *udp
	tcp.Net = "tcp"
	queryDNSService(t, &tcp, s.Status().Endpoints.DNS, 2)
	if result := s.Test(context.Background(), "example.com", "A"); !result.OK || !result.Cached || result.Source != "diagnostic" || result.Transport != "api" || result.ClientIP != "" {
		t.Fatalf("API diagnostic has incorrect origin/cache flags: %+v", result)
	}
	run := activeDNSRun(s)
	client := withListenerOrigin(context.Background(), "192.168.3.40:52525", "192.168.3.1", "udp")
	for _, ctx := range []context.Context{client, context.Background()} {
		if _, out, err := s.exchange(ctx, run, resolverWire(t, "example.com", 3, mdns.TypeA)); err != nil || !out.Cached {
			t.Fatalf("cached service exchange failed: %+v %v", out, err)
		}
	}
	entries := s.Logs(0).Entries
	var answers []LogEntry
	for _, entry := range entries {
		if entry.Event == "answer" || entry.Event == "cache" {
			answers = append(answers, entry)
		}
	}
	want := []requestOrigin{
		{ClientIP: "127.0.0.1", Source: "local", Transport: "udp"},
		{ClientIP: "127.0.0.1", Source: "local", Transport: "tcp"},
		{Source: "diagnostic", Transport: "api"},
		{ClientIP: "192.168.3.40", Source: "client", Transport: "udp"},
		{Source: "internal"},
	}
	if len(answers) != len(want) {
		t.Fatalf("got %d answer log entries, want %d: %+v", len(answers), len(want), entries)
	}
	for i, origin := range want {
		entry := answers[i]
		if entry.ClientIP != origin.ClientIP || entry.Source != origin.Source || entry.Transport != origin.Transport || (i > 0 && entry.Event != "cache") {
			t.Errorf("delivery %d has incorrect cache/source attribution: %+v", i, entry)
		}
	}
	stats := s.Status().Stats
	if stats.LastSource != "internal" || stats.LastClientIP != "" || stats.LastTransport != "" || !stats.LastCached || stats.Queries != 5 {
		t.Fatalf("stats retained preceding client's identity: %+v", stats)
	}
	mu.Lock()
	defer mu.Unlock()
	if observed["127.0.0.1"] != 2 || observed["192.168.3.40"] != 1 || observed["<nil>"] != 2 {
		t.Fatalf("cache or diagnostics skipped per-client routing observer: %v", observed)
	}
}

func TestDNSBackgroundProbeAndAttemptErrorsKeepDistinctOrigin(t *testing.T) {
	backend := &resolverTestBackend{routes: schedulerTestRoutes()[:2], dialHook: func(context.Context, string, string, string) (net.Conn, error) {
		return nil, errors.New("fixture unreachable")
	}}
	cfg := Default()
	cfg.Rules, cfg.DefaultPool, cfg.FastDNS = nil, nil, false
	r := NewResolver(cfg, backend)
	defer r.Close()
	logs := NewLogBuffer()
	logs.SetEnabled(true)
	s := &Service{logs: logs}
	r.SetAttemptObserver(s.recordAttempt)
	r.runSchedulerProbe()
	entries := logs.Snapshot(0).Entries
	if len(entries) != 1 || entries[0].Source != "probe" || entries[0].ClientIP != "" || entries[0].Domain != "." || entries[0].Event != "attempt_error" {
		t.Fatalf("background root probe claimed a user request: %+v", entries)
	}
	s.recordAttempt(AttemptEvent{Domain: "mobile.de", Type: "A", Source: "client", ClientIP: "192.168.3.40", Transport: "udp", Error: "fixture failure"})
	s.recordCancellations(CancellationSummary{Domain: "mobile.de", Type: "A", Count: 3, Source: "diagnostic", Transport: "api"})
	entries = logs.Snapshot(0).Entries
	if len(entries) != 3 || entries[1].ClientIP != "192.168.3.40" || entries[1].Source != "client" || entries[1].Transport != "udp" || entries[2].Source != "diagnostic" || entries[2].Transport != "api" || entries[2].ClientIP != "" {
		t.Fatalf("attempt/cancellation log dropped caller attribution: %+v", entries)
	}
}
