package dnsserver

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	mdns "github.com/miekg/dns"
	"nfqws2strategy/internal/services/dnsroute"
	"nfqws2strategy/internal/tools/store"
)

func activeDNSRun(s *Service) *serviceRun {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active
}

func TestDNSDiagnosticsTogglePersistsWithoutRestart(t *testing.T) {
	s, backend, client := newDNSServiceFixture(t, 8)
	initialRun := activeDNSRun(s)
	if !s.Config().LoggingEnabled || !s.Logs(0).Enabled {
		t.Fatal("new DNS configuration must enable diagnostics logging")
	}
	if msg := queryDNSService(t, client, s.Status().Endpoints.DNS, 301); msg.Rcode != mdns.RcodeSuccess {
		t.Fatalf("initial DNS request failed: %s", mdns.RcodeToString[msg.Rcode])
	}
	backend.mu.Lock()
	initialPrepares, initialCloses := backend.prepareCount, backend.closeCount
	backend.mu.Unlock()
	if err := s.SetLoggingEnabled(false); err != nil {
		t.Fatal(err)
	}
	var saved Config
	if err := s.store.Load(configFile, &saved); err != nil || saved.LoggingEnabled {
		t.Fatalf("logging disable was not saved: %v", err)
	}
	disabled := s.Logs(0)
	if disabled.Enabled || len(disabled.Entries) == 0 {
		t.Fatal("disabling logging must retain the existing log")
	}
	if msg := queryDNSService(t, client, s.Status().Endpoints.DNS, 302); msg.Rcode != mdns.RcodeSuccess {
		t.Fatalf("logging toggle interrupted DNS: %s", mdns.RcodeToString[msg.Rcode])
	}
	if after := s.Logs(0); after.LastID != disabled.LastID || after.Bytes != disabled.Bytes {
		t.Fatal("queries appended logs while logging was disabled")
	}
	cleared := s.ClearLogs()
	if cleared.Enabled || cleared.Bytes != 0 || len(cleared.Entries) != 0 || cleared.LastID != disabled.LastID {
		t.Fatalf("clear changed logging/cursor state: %+v", cleared)
	}
	if err := s.SetLoggingEnabled(true); err != nil {
		t.Fatal(err)
	}
	if err := s.store.Load(configFile, &saved); err != nil || !saved.LoggingEnabled {
		t.Fatalf("logging enable was not saved: %v", err)
	}
	if msg := queryDNSService(t, client, s.Status().Endpoints.DNS, 303); msg.Rcode != mdns.RcodeSuccess {
		t.Fatalf("DNS did not continue after enabling logs: %s", mdns.RcodeToString[msg.Rcode])
	}
	if s.Status().Stats.Queries != 3 || s.Status().Stats.CacheHits != 2 || activeDNSRun(s) != initialRun {
		t.Fatalf("logging toggle restarted DNS or reset its cache: %+v", s.Status().Stats)
	}
	backend.mu.Lock()
	prepares, closes := backend.prepareCount, backend.closeCount
	backend.mu.Unlock()
	if prepares != initialPrepares || closes != initialCloses {
		t.Fatalf("logging toggle changed network state: prepare %d -> %d, close %d -> %d", initialPrepares, prepares, initialCloses, closes)
	}
	logs := s.Logs(cleared.LastID)
	if !logs.Enabled || len(logs.Entries) < 2 || logs.Entries[len(logs.Entries)-1].Event != "cache" {
		t.Fatalf("logging did not resume after the clear cursor: %+v", logs)
	}
}

func TestDNSDiagnosticsRecordsAttemptErrorAnswerAndCache(t *testing.T) {
	s, backend, client := newDNSServiceFixture(t, 8)
	s.ClearLogs()
	backend.setFailures("nfqws", "awg:first", "awg:warp")
	wire, outcome, err := s.exchange(context.Background(), activeDNSRun(s), resolverWire(t, "failed.example", 310, mdns.TypeA))
	var failed mdns.Msg
	if err != nil || failed.Unpack(wire) != nil || failed.Rcode != mdns.RcodeServerFailure || outcome.Error == "" {
		t.Fatalf("failed DNS attempt must produce SERVFAIL and an outcome error: %v %+v", err, outcome)
	}
	backend.setFailures()
	for _, id := range []uint16{311, 312} {
		if msg := queryDNSService(t, client, s.Status().Endpoints.DNS, id); msg.Rcode != mdns.RcodeSuccess {
			t.Fatalf("DNS recovery failed: %s", mdns.RcodeToString[msg.Rcode])
		}
	}
	logs := s.Logs(0)
	assertLogSnapshot(t, logs)
	found := map[string]int{}
	for _, entry := range logs.Entries {
		found[entry.Event]++
		switch entry.Event {
		case "attempt_error":
			if entry.Domain != "failed.example" || entry.QType != "A" || entry.Upstream == "" || entry.Route == "" || entry.Message == "" || entry.Level != "warn" {
				t.Errorf("attempt error lacks DNS context: %+v", entry)
			}
		case "error":
			if entry.Domain != "failed.example" || entry.QType != "A" || entry.Message == "" || entry.Level != "error" {
				t.Errorf("final error lacks DNS context: %+v", entry)
			}
		case "answer", "cache":
			if entry.Domain != "example.com" || entry.QType != "A" || entry.Upstream == "" || entry.Route == "" {
				t.Errorf("successful DNS event lacks DNS context: %+v", entry)
			}
			if entry.Message != "" {
				t.Errorf("successful DNS event repeats its label in storage: %+v", entry)
			}
		}
	}
	for _, event := range []string{"attempt_error", "error", "answer", "cache"} {
		if found[event] == 0 {
			t.Errorf("missing event %q; events=%v", event, found)
		}
	}
	if found["attempt_error"] != 3 || found["error"] != 1 || found["answer"] != 1 || found["cache"] != 1 || found["attempt_success"] != 0 {
		t.Fatalf("unexpected event counts: %v", found)
	}
}

func TestDNSDiagnosticsLegacyLoggingDefaultAndExplicitDisable(t *testing.T) {
	for _, value := range []string{"missing", "true", "false"} {
		t.Run(value, func(t *testing.T) {
			st, err := store.New(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			encoded, _ := json.Marshal(Default())
			var saved map[string]any
			if err := json.Unmarshal(encoded, &saved); err != nil {
				t.Fatal(err)
			}
			delete(saved, "logging_enabled")
			if value != "missing" {
				saved["logging_enabled"] = value == "true"
			}
			if err := st.Save(configFile, saved); err != nil {
				t.Fatal(err)
			}
			s := New(st, &resolverTestBackend{}, func(string) (string, error) { return "127.0.0.1", nil })
			defer s.Close()
			want := value != "false"
			if s.Config().LoggingEnabled != want || s.Logs(0).Enabled != want || s.Config().Enabled {
				t.Fatalf("loading %s logging state changed defaults: %+v", value, s.Config())
			}
			if len(s.Config().Rules) != 3 {
				t.Fatal("logging migration lost domain rules")
			}
			if err := s.SetLoggingEnabled(want); err != nil {
				t.Fatal(err)
			}
			var persisted Config
			if err := st.Load(configFile, &persisted); err != nil || persisted.LoggingEnabled != want {
				t.Fatalf("migrated logging preference was not saved: %v", err)
			}
		})
	}
}

func TestDNSDiagnosticsFailedSaveKeepsLoggingAndDNS(t *testing.T) {
	s, _, client := newDNSServiceFixture(t, 8)
	run := activeDNSRun(s)
	// Occupy the store's atomic-write temporary path with a directory to cause
	// a portable write failure without changing real filesystem permissions.
	if err := os.Mkdir(s.store.Path(configFile+".tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.SetLoggingEnabled(false); err == nil {
		t.Fatal("logging toggle unexpectedly ignored a persistence failure")
	}
	if !s.Config().LoggingEnabled || !s.Logs(0).Enabled || activeDNSRun(s) != run {
		t.Fatal("failed save changed active logging or restarted DNS")
	}
	var persisted Config
	if err := s.store.Load(configFile, &persisted); err != nil || !persisted.LoggingEnabled {
		t.Fatalf("failed save damaged persisted logging state: %v", err)
	}
	if msg := queryDNSService(t, client, s.Status().Endpoints.DNS, 320); msg.Rcode != mdns.RcodeSuccess {
		t.Fatalf("failed logging save interrupted DNS: %s", mdns.RcodeToString[msg.Rcode])
	}
}

func TestDNSDiagnosticsSchedulerAndLogSurviveConfigSave(t *testing.T) {
	s, backend, client := newDNSServiceFixture(t, 8)
	backend.mu.Lock()
	backend.routes = []dnsroute.Route{{ID: "nfqws", Name: "NFQWS", Available: true}}
	backend.mu.Unlock()
	if msg := queryDNSService(t, client, s.Status().Endpoints.DNS, 330); msg.Rcode != mdns.RcodeSuccess {
		t.Fatalf("initial DNS request failed: %s", mdns.RcodeToString[msg.Rcode])
	}
	before, err := s.SchedulerSnapshot("EXAMPLE.COM.")
	if err != nil || before.Domain != "example.com" || len(before.Candidates) != 1 || before.Candidates[0].Successes != 1 || before.Candidates[0].Attempts != 1 {
		t.Fatalf("actual query did not teach the scheduler: %v %+v", err, before)
	}
	scheduler, logs, run := s.scheduler, s.logs, activeDNSRun(s)
	retainedID := s.Logs(0).LastID
	cfg := s.Config()
	cfg.CacheSize++
	if err := s.SetConfig(cfg); err != nil || !s.Status().Running {
		t.Fatalf("configuration save failed: %v %s", err, s.Status().LastError)
	}
	if s.scheduler != scheduler || s.logs != logs || activeDNSRun(s) == run {
		t.Fatal("configuration save did not retain diagnostics across a resolver replacement")
	}
	if activeDNSRun(s).resolver.scheduler != scheduler {
		t.Fatal("replacement resolver does not use the shared service scheduler")
	}
	after, err := s.SchedulerSnapshot("example.com")
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("configuration save lost learned scheduler history: %v\nbefore=%+v\nafter=%+v", err, before, after)
	}
	retained := false
	for _, entry := range s.Logs(0).Entries {
		retained = retained || entry.ID == retainedID
	}
	if !retained {
		t.Fatal("configuration save erased existing DNS logs")
	}
	if _, err := s.SchedulerSnapshot("https://not-a-domain.example/path"); err == nil {
		t.Fatal("scheduler accepted an invalid domain")
	}
}

func TestDNSDiagnosticsAttemptObserverEnforcesLogCapacity(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := New(st, &resolverTestBackend{}, func(string) (string, error) { return "127.0.0.1", nil })
	defer s.Close()
	for i := 0; i < 150; i++ {
		s.recordAttempt(AttemptEvent{Domain: "example.com", Type: "A", Route: "nfqws", Upstream: "https://1.1.1.1/dns-query", Error: strings.Repeat("DNS недоступен \"\\\n", 200)})
	}
	logs := s.Logs(0)
	assertLogSnapshot(t, logs)
	if logs.Dropped == 0 || len(logs.Entries) == 0 || logs.LastID != 150 {
		t.Fatalf("service observer did not evict old entries: retained=%d dropped=%d last=%d", len(logs.Entries), logs.Dropped, logs.LastID)
	}
}
