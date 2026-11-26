package awgroute

import (
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/store"
)

func learnedHistoryFixtureZone() awg.Zone {
	include := true
	return awg.Zone{Name: "Video", Order: 1, Enabled: true, Route: "tunnel", TunnelID: "primary", FallbackTunnelIDs: []string{"backup-a", "backup-b"}, Domains: []string{"list:video", "example.com"}, IncludeSubdomains: &include, IPs: []string{"192.0.2.0/24"}, SourceIPs: []string{"192.168.1.0/24"}}
}

func TestAWGRoutingLearnedRuleKeyFollowsSemanticScope(t *testing.T) {
	zone := learnedHistoryFixtureZone()
	key := AWGRoutingLearnedRuleKey(zone)
	cosmetic := zone
	cosmetic.Name = "Renamed"
	cosmetic.Order = 8
	cosmetic.Enabled = false
	cosmetic.Domains = []string{" EXAMPLE.COM ", "list:video", "example.com"}
	if got := AWGRoutingLearnedRuleKey(cosmetic); got != key {
		t.Fatalf("cosmetic edit reset history: %s != %s", got, key)
	}
	legacy := zone
	legacy.Route = ""
	legacy.Mode = "include"
	if AWGRoutingLearnedRuleKey(legacy) != key {
		t.Fatal("equivalent legacy route changed key")
	}
	for _, test := range []struct {
		name string
		edit func(*awg.Zone)
	}{
		{"route", func(z *awg.Zone) { z.Route = "direct" }},
		{"connection", func(z *awg.Zone) { z.TunnelID = "different" }},
		{"fallback_priority", func(z *awg.Zone) { z.FallbackTunnelIDs = []string{"backup-b", "backup-a"} }},
		{"domain_source", func(z *awg.Zone) { z.Domains = []string{"list:other"} }},
		{"case_sensitive_list", func(z *awg.Zone) { z.Domains = []string{"list:Video", "example.com"} }},
		{"source_device", func(z *awg.Zone) { z.SourceIPs = []string{"192.168.2.0/24"} }},
		{"destination_network", func(z *awg.Zone) { z.IPs = []string{"198.51.100.0/24"} }},
		{"subdomains", func(z *awg.Zone) { include := false; z.IncludeSubdomains = &include }},
		{"waiting_connection", func(z *awg.Zone) { z.WaitingForConnection = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := zone
			test.edit(&changed)
			if AWGRoutingLearnedRuleKey(changed) == key {
				t.Fatal("different policy reused another scope's history")
			}
		})
	}
}

func TestRoutingLearnedNormalizesDeduplicatesAndCopies(t *testing.T) {
	var history routingLearnedHistory
	at := time.Unix(1000, 0)
	ips := []string{"192.0.2.1", "192.0.2.1", "::ffff:192.0.2.1", "2001:0db8::1", "invalid", "0.0.0.0"}
	history.Record("rule-a", " ПРИМЕР.РФ. ", "::ffff:192.168.1.19", ips, "dns", true, 2, 3, at)
	ips[0] = "198.51.100.1"
	history.Record("rule-a", "xn--e1afmkfd.xn--p1ai", "192.168.1.20", []string{"192.0.2.1"}, "sni", false, 2, 3, at.Add(time.Second))
	got := history.Snapshot("rule-a", 2, 3, true)
	if len(got) != 1 {
		t.Fatalf("entries %v", got)
	}
	entry := got[0]
	if entry.Domain != "xn--e1afmkfd.xn--p1ai" || !reflect.DeepEqual(entry.IPs, []string{"192.0.2.1", "2001:db8::1"}) || !reflect.DeepEqual(entry.SourceIPs, []string{"192.168.1.19", "192.168.1.20"}) || entry.FirstSeen != 1000 || entry.LastSeen != 1001 || entry.Source != "sni" || entry.Additional || !entry.Confirmed {
		t.Fatalf("unexpected deduplicated observation: %+v", entry)
	}
	got[0].IPs[0] = "changed"
	got[0].SourceIPs[0] = "changed"
	got[0].Domain = "changed"
	names := history.Names("rule-a")
	names[0] = "changed"
	fresh := history.Snapshot("rule-a", 2, 3, true)
	if fresh[0].Domain == "changed" || fresh[0].IPs[0] == "changed" || fresh[0].SourceIPs[0] == "changed" || history.Names("rule-a")[0] == "changed" {
		t.Fatal("snapshot shares mutable history storage")
	}
	if len(history.Snapshot("rule-b", 2, 3, true)) != 0 {
		t.Fatal("another rule inherited the observation")
	}
}

func TestRoutingLearnedRejectsInvalidObservationData(t *testing.T) {
	at := time.Unix(1000, 0)
	for _, test := range []struct {
		key, domain, sourceIP, source string
		ips                           []string
	}{
		{"", "example.com", "", "dns", []string{"192.0.2.1"}},
		{"bad\nkey", "example.com", "", "dns", []string{"192.0.2.1"}},
		{"rule", "https://example.com/", "", "dns", []string{"192.0.2.1"}},
		{"rule", "*.example.com", "", "dns", []string{"192.0.2.1"}},
		{"rule", "192.0.2.1", "", "dns", []string{"192.0.2.1"}},
		{"rule", "example.com", "not-an-ip", "dns", []string{"192.0.2.1"}},
		{"rule", "example.com", "", "other", []string{"192.0.2.1"}},
		{"rule", "example.com", "", "dns", []string{"invalid", "::", "0.0.0.0"}},
	} {
		var history routingLearnedHistory
		history.Record(test.key, test.domain, test.sourceIP, test.ips, test.source, false, 0, 0, at)
		if len(history.entries) != 0 {
			t.Errorf("invalid observation retained: %+v", test)
		}
	}
}

func TestRoutingLearnedConfirmationRequiresCurrentReadyEpoch(t *testing.T) {
	var history routingLearnedHistory
	at := time.Unix(1000, 0)
	history.Record("rule", "example.com", "", []string{"192.0.2.1"}, "dns", true, 3, 4, at)
	for _, test := range []struct {
		generation, epoch uint64
		ready, confirmed  bool
	}{{3, 4, true, true}, {2, 4, true, false}, {3, 5, true, false}, {3, 4, false, false}} {
		if got := history.Snapshot("rule", test.generation, test.epoch, test.ready)[0].Confirmed; got != test.confirmed {
			t.Errorf("confirmation %+v: %v", test, got)
		}
	}
	history.Record("rule", "example.com", "", []string{"192.0.2.2"}, "dns", true, 3, 5, at.Add(time.Second))
	if history.Snapshot("rule", 3, 5, true)[0].Confirmed {
		t.Fatal("new response falsely confirmed retained addresses from an older kernel epoch")
	}
	history.Record("rule", "example.com", "", []string{"192.0.2.1"}, "dns", true, 3, 5, at.Add(2*time.Second))
	if !history.Snapshot("rule", 3, 5, true)[0].Confirmed {
		t.Fatal("confirmed addresses remain stale")
	}
	history.Record("rule", "example.com", "", []string{"192.0.2.1"}, "dns", true, 2, 4, at)
	if !history.Snapshot("rule", 3, 5, true)[0].Confirmed {
		t.Fatal("late obsolete event replaced newer installation confirmation")
	}
}

func TestRoutingLearnedBoundsEvictOldestAndKeepRecentNames(t *testing.T) {
	var history routingLearnedHistory
	at := time.Unix(1000, 0)
	for i := 0; i < routingLearnedRuleLimit+1; i++ {
		history.Record("rule", fmt.Sprintf("name-%03d.example", i), "", []string{"192.0.2.1"}, "dns", true, 1, 1, at.Add(time.Duration(i)*time.Second))
	}
	entries := history.Snapshot("rule", 1, 1, true)
	if len(entries) != routingLearnedRuleLimit || entries[0].Domain != "name-512.example" {
		t.Fatalf("rule bound/order: len=%d first=%+v", len(entries), entries[0])
	}
	for _, entry := range entries {
		if entry.Domain == "name-000.example" {
			t.Fatal("oldest domain was retained beyond rule capacity")
		}
	}
	names := history.Names("rule")
	if len(names) != routingLearnedNamesLimit || names[0] != "name-512.example" || names[len(names)-1] != "name-385.example" {
		t.Fatalf("warmup names not bounded/recent: %v", names)
	}
	// Refreshing an older name protects it from the next LRU eviction.
	history.Record("rule", "name-001.example", "", []string{"192.0.2.1"}, "dns", true, 1, 1, at.Add(1000*time.Second))
	history.Record("rule", "new.example", "", []string{"192.0.2.1"}, "dns", true, 1, 1, at.Add(1001*time.Second))
	if !slices.Contains(history.Names("rule"), "name-001.example") {
		t.Fatal("freshly observed name was evicted")
	}
	for i := 1; i <= 70; i++ {
		history.Record("addresses", "example.com", fmt.Sprintf("192.168.1.%d", i), []string{fmt.Sprintf("198.51.100.%d", i)}, "dns", true, 1, 1, at.Add(time.Duration(i)*time.Second))
	}
	bounded := history.Snapshot("addresses", 1, 1, true)[0]
	if len(bounded.IPs) != routingLearnedIPLimit || len(bounded.SourceIPs) != routingLearnedSourceLimit || slices.Contains(bounded.IPs, "198.51.100.1") || slices.Contains(bounded.SourceIPs, "192.168.1.1") || !slices.Contains(bounded.IPs, "198.51.100.70") {
		t.Fatalf("address/source bounds: %+v", bounded)
	}
	var total routingLearnedHistory
	for i := 0; i < routingLearnedLimit+1; i++ {
		total.Record(fmt.Sprintf("rule-%02d", i/routingLearnedRuleLimit), fmt.Sprintf("name-%04d.example", i), "", []string{"192.0.2.1"}, "dns", true, 1, 1, at.Add(time.Duration(i)*time.Second))
	}
	if len(total.entries) != routingLearnedLimit || total.entries["rule-00\x00name-0000.example"] != nil {
		t.Fatalf("global capacity did not evict oldest: %d", len(total.entries))
	}
}

func TestRoutingLearnedPersistenceNeverRestoresConfirmation(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var history routingLearnedHistory
	at := time.Unix(1000, 0)
	history.Record("rule", "example.com", "192.168.1.19", []string{"192.0.2.1", "2001:db8::1"}, "dns", true, 0, 0, at)
	history.Record("rule", "example.com", "192.168.1.20", []string{"192.0.2.1"}, "sni", true, 0, 0, at.Add(time.Second))
	if err := history.Flush(st); err != nil {
		t.Fatal(err)
	}
	wire, err := os.ReadFile(st.Path(routingLearnedFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"confirmed", "generation", "epoch"} {
		if strings.Contains(string(wire), field) {
			t.Fatalf("persisted runtime installation state %s", field)
		}
	}
	var loaded routingLearnedHistory
	if err := loaded.Load(st); err != nil {
		t.Fatal(err)
	}
	got := loaded.Snapshot("rule", 0, 0, true)
	if len(got) != 1 || got[0].Confirmed || got[0].FirstSeen != 1000 || got[0].LastSeen != 1001 || len(got[0].IPs) != 2 || len(got[0].SourceIPs) != 2 {
		t.Fatalf("restored observation %+v", got)
	}
	loaded.Record("rule", "example.com", "", []string{"192.0.2.1"}, "dns", true, 0, 0, at.Add(2*time.Second))
	if loaded.Snapshot("rule", 0, 0, true)[0].Confirmed {
		t.Fatal("fresh A answer falsely confirmed restored AAAA address")
	}
	loaded.Record("rule", "example.com", "", []string{"2001:db8::1"}, "dns", true, 0, 0, at.Add(3*time.Second))
	if !loaded.Snapshot("rule", 0, 0, true)[0].Confirmed {
		t.Fatal("freshly confirmed restored addresses not recognized")
	}
}

func TestRoutingLearnedFlushDirtyAndFailureRecovery(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var history routingLearnedHistory
	history.Record("rule", "example.com", "", []string{"192.0.2.1"}, "dns", true, 1, 1, time.Unix(1000, 0))
	if err := os.Mkdir(st.Path(routingLearnedFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := history.Flush(st); err == nil {
		t.Fatal("failed persistence reported success")
	}
	if err := os.Remove(st.Path(routingLearnedFile)); err != nil {
		t.Fatal(err)
	}
	if err := history.Flush(st); err != nil {
		t.Fatal(err)
	}
	// A clean Flush must not write on every frontend poll or persistence tick.
	if err := os.WriteFile(st.Path(routingLearnedFile), []byte("unchanged-marker"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := history.Flush(st); err != nil {
		t.Fatal(err)
	}
	wire, err := os.ReadFile(st.Path(routingLearnedFile))
	if err != nil || string(wire) != "unchanged-marker" {
		t.Fatalf("clean history rewritten: %s %v", wire, err)
	}
	if err := history.Load(st); err == nil {
		t.Fatal("corrupt persisted history accepted")
	}
	if !history.Snapshot("rule", 1, 1, true)[0].Confirmed {
		t.Fatal("failed Load discarded valid live history")
	}
	history.Record("rule", "other.example", "", []string{"192.0.2.2"}, "dns", true, 1, 1, time.Unix(1001, 0))
	if err := history.Flush(st); err != nil {
		t.Fatal(err)
	}
	var loaded routingLearnedHistory
	if err := loaded.Load(st); err != nil || len(loaded.Snapshot("rule", 1, 1, true)) != 2 {
		t.Fatalf("dirty history not saved after recovery: %v", err)
	}
}

func TestRoutingLearnedConcurrentRecordSnapshotAndFlush(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var history routingLearnedHistory
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				history.Record("rule", fmt.Sprintf("worker-%d-%d.example", worker, i), "", []string{"192.0.2.1"}, "dns", true, 1, 1, time.Unix(int64(1000+i), 0))
				history.Snapshot("rule", 1, 1, true)
				if err := history.Flush(st); err != nil {
					t.Errorf("flush: %v", err)
				}
			}
		}(worker)
	}
	wg.Wait()
	if err := history.Flush(st); err != nil {
		t.Fatal(err)
	}
	var loaded routingLearnedHistory
	if err := loaded.Load(st); err != nil {
		t.Fatal(err)
	}
	if len(loaded.Snapshot("rule", 1, 1, true)) != 160 {
		t.Fatalf("concurrent observations lost: %d", len(loaded.Snapshot("rule", 1, 1, true)))
	}
}

func TestRoutingLearnedAllNamesUsesNewestUniqueCandidatesAcrossRules(t *testing.T) {
	var history routingLearnedHistory
	at := time.Unix(1000, 0)
	observe := func(rule, domain string, seconds int) {
		history.Record(rule, domain, "", []string{"192.0.2.1"}, "dns", true, 1, 1, at.Add(time.Duration(seconds)*time.Second))
	}
	observe("old-rule", "shared.example", 0)
	observe("other-rule", "older.example", 1)
	observe("other-rule", "shared.example", 5)
	observe("old-rule", "b.example", 5)
	observe("new-rule", "a.example", 5)
	version, persisted, touch := history.version, history.persisted, history.touch
	want := []string{"a.example", "b.example", "shared.example", "older.example"}
	got := history.AllNames()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("global candidates %v, want %v", got, want)
	}
	got[0] = "mutated.example"
	if !reflect.DeepEqual(history.AllNames(), want) || history.version != version || history.persisted != persisted || history.touch != touch {
		t.Fatal("candidate read changed history or exposes mutable storage")
	}
	if len(history.Names("new-rule")) != 1 || history.Names("new-rule")[0] != "a.example" {
		t.Fatal("global candidate collection changed per-rule ownership")
	}
}

func TestRoutingLearnedAllNamesBoundedByGlobalHistory(t *testing.T) {
	var history routingLearnedHistory
	for i := 0; i < routingLearnedLimit+1; i++ {
		history.Record(fmt.Sprintf("rule-%02d", i/routingLearnedRuleLimit), fmt.Sprintf("name-%04d.example", i), "", []string{"192.0.2.1"}, "dns", true, 1, 1, time.Unix(int64(1000+i), 0))
	}
	names := history.AllNames()
	if len(names) != routingLearnedLimit || names[0] != "name-4096.example" || slices.Contains(names, "name-0000.example") {
		t.Fatalf("unbounded or stale candidate pool: len=%d first=%q", len(names), names[0])
	}
}
