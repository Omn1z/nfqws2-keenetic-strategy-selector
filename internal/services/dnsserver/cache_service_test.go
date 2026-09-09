package dnsserver

import (
	"encoding/json"
	"reflect"
	"testing"

	mdns "github.com/miekg/dns"
	"nfqws2strategy/internal/services/dnsroute"
	"nfqws2strategy/internal/tools/store"
)

func TestDNSServiceClearCacheKeepsResolverStatsAndHistory(t *testing.T) {
	s, backend, client := newDNSServiceFixture(t, 8)
	// One route makes the completed scheduler history deterministic: no losing
	// attempts remain in flight when the cache is cleared.
	backend.mu.Lock()
	backend.routes = []dnsroute.Route{{ID: "nfqws", Name: "NFQWS", Available: true}}
	backend.mu.Unlock()
	initialRun := activeDNSRun(s)
	for _, id := range []uint16{401, 402} {
		if msg := queryDNSService(t, client, s.Status().Endpoints.DNS, id); msg.Rcode != mdns.RcodeSuccess {
			t.Fatalf("initial DNS query failed: %s", mdns.RcodeToString[msg.Rcode])
		}
	}
	before := s.Status()
	if before.Cache.Entries != 1 || before.Cache.Capacity != 8 || before.Cache.TTLSeconds != 3600 || before.Stats.Queries != 2 || before.Stats.CacheHits != 1 {
		t.Fatalf("unexpected populated cache state: cache=%+v stats=%+v", before.Cache, before.Stats)
	}
	history, err := s.SchedulerSnapshot("example.com")
	if err != nil || len(history.Candidates) != 1 || history.Candidates[0].Successes != 1 {
		t.Fatalf("missing learned scheduler history: %v %+v", err, history)
	}
	retainedLogID := s.Logs(0).LastID
	backend.mu.Lock()
	prepares, closes := backend.prepareCount, backend.closeCount
	backend.mu.Unlock()
	if removed := s.ClearCache(); removed != 1 {
		t.Fatalf("removed %d cache entries, want 1", removed)
	}
	after := s.Status()
	if !after.Running || activeDNSRun(s) != initialRun || after.Cache.Entries != 0 || after.Cache.Capacity != before.Cache.Capacity || after.Cache.TTLSeconds != before.Cache.TTLSeconds {
		t.Fatalf("cache clear changed the running resolver: %+v", after)
	}
	if !reflect.DeepEqual(after.Stats, before.Stats) || !reflect.DeepEqual(after.Config, before.Config) {
		t.Fatalf("cache clear changed configuration or statistics: before=%+v after=%+v", before.Stats, after.Stats)
	}
	nextHistory, err := s.SchedulerSnapshot("example.com")
	if err != nil || !reflect.DeepEqual(history, nextHistory) {
		t.Fatalf("cache clear changed scheduler history: %v\nbefore=%+v\nafter=%+v", err, history, nextHistory)
	}
	retained := false
	for _, entry := range s.Logs(0).Entries {
		retained = retained || entry.ID == retainedLogID
	}
	if !retained {
		t.Fatal("cache clear erased diagnostic history")
	}
	backend.mu.Lock()
	preparesAfter, closesAfter := backend.prepareCount, backend.closeCount
	backend.mu.Unlock()
	if preparesAfter != prepares || closesAfter != closes {
		t.Fatalf("cache clear changed routing: prepare %d -> %d, close %d -> %d", prepares, preparesAfter, closes, closesAfter)
	}
	if removed := s.ClearCache(); removed != 0 {
		t.Fatalf("empty cache clear removed %d entries", removed)
	}
	for i, id := range []uint16{403, 404} {
		if msg := queryDNSService(t, client, after.Endpoints.DNS, id); msg.Rcode != mdns.RcodeSuccess {
			t.Fatalf("DNS query after clearing failed: %s", mdns.RcodeToString[msg.Rcode])
		}
		current := s.Status()
		if current.Stats.Queries != uint64(3+i) || current.Stats.CacheHits != uint64(1+i) || current.Cache.Entries != 1 {
			t.Fatalf("query %d did not refill then reuse the cache: cache=%+v stats=%+v", i, current.Cache, current.Stats)
		}
	}
	status := s.Status()
	summary := s.Summary()
	if !summary.Enabled || !summary.Running || summary.Endpoint != status.Endpoints.DNS || summary.LastError != status.LastError || !reflect.DeepEqual(summary.Stats, status.Stats) || !reflect.DeepEqual(summary.Cache, status.Cache) {
		t.Fatalf("dashboard summary differs from DNS status: summary=%+v status=%+v", summary, status)
	}
}

type summaryOnlyDNSBackend struct{ resolverTestBackend }

func (*summaryOnlyDNSBackend) Routes() []dnsroute.Route {
	panic("dashboard summary must not inspect network routes")
}

func TestDNSServiceSummaryAndClearAreSafeWhileDisabled(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	backend := &summaryOnlyDNSBackend{}
	s := New(st, backend, func(string) (string, error) { return "127.0.0.1", nil })
	defer s.Close()
	if removed := s.ClearCache(); removed != 0 {
		t.Fatalf("disabled cache clear removed %d entries", removed)
	}
	summary := s.Summary()
	if summary.Enabled || summary.Running || summary.Endpoint != "127.0.0.1:5355" || summary.LastError != "" || summary.Stats != (Stats{}) {
		t.Fatalf("unexpected disabled dashboard summary: %+v", summary)
	}
	if summary.Cache.Entries != 0 || summary.Cache.Capacity != 512 || summary.Cache.TTLSeconds != 3600 {
		t.Fatalf("disabled cache metadata lost configured limits: %+v", summary.Cache)
	}
	backend.mu.Lock()
	prepares, closes := backend.prepareCount, backend.closeCount
	backend.mu.Unlock()
	if prepares != 0 || closes != 0 {
		t.Fatal("disabled cache operations changed network state")
	}
}

func TestDNSServiceCacheTTLMigrationPreservesSavedConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name string
		ttl  int
	}{
		{name: "legacy_missing", ttl: 3600},
		{name: "explicit", ttl: 900},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, err := store.New(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			want := Default()
			want.ListenHost, want.DNSPort = "127.0.0.1", 5399
			want.CacheSize, want.CacheTTLSeconds = 128, tc.ttl
			want.LoggingEnabled, want.AWGFallback, want.TimeoutSeconds = false, "off", 7
			want.DefaultUpstream = Upstream{Address: "https://9.9.9.9/dns-query", BootstrapIPs: []string{"9.9.9.9"}}
			want.DefaultPool = []Upstream{{Address: "https://1.0.0.1/dns-query", BootstrapIPs: []string{"1.0.0.1"}}}
			want.Rules = []Rule{}
			if err := want.NormalizeValidate(); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(want)
			if err != nil {
				t.Fatal(err)
			}
			var saved map[string]any
			if err := json.Unmarshal(encoded, &saved); err != nil {
				t.Fatal(err)
			}
			if tc.name == "legacy_missing" {
				delete(saved, "cache_ttl_seconds")
			}
			if err := st.Save(configFile, saved); err != nil {
				t.Fatal(err)
			}
			s := New(st, &resolverTestBackend{}, func(string) (string, error) { return "127.0.0.1", nil })
			defer s.Close()
			if got := s.Config(); !reflect.DeepEqual(got, want) {
				t.Fatalf("cache lifetime migration changed saved configuration:\ngot=%+v\nwant=%+v", got, want)
			}
			if s.Summary().LastError != "" || s.Summary().Cache.TTLSeconds != tc.ttl {
				t.Fatalf("migrated lifetime missing from dashboard summary: %+v", s.Summary())
			}
			if err := s.SetConfig(s.Config()); err != nil {
				t.Fatal(err)
			}
			var persisted Config
			if err := st.Load(configFile, &persisted); err != nil || !reflect.DeepEqual(persisted, want) {
				t.Fatalf("cache lifetime/configuration did not persist: %v\ngot=%+v\nwant=%+v", err, persisted, want)
			}
		})
	}
}
