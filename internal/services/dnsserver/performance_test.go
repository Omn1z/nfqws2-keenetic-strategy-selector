package dnsserver

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"nfqws2strategy/internal/tools/store"
)

func BenchmarkDNSLogAppendFull(b *testing.B) {
	logs := NewLogBuffer()
	logs.SetEnabled(true)
	entry := LogEntry{Time: "2026-10-02T00:00:00Z", Domain: "mobile.de", QType: "A", Route: "awg:primary", Event: "cache"}
	for i := 0; i < 2000; i++ {
		logs.Append(entry)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logs.Append(entry)
	}
}

func BenchmarkDNSLogSnapshotAtTail(b *testing.B) {
	logs := NewLogBuffer()
	logs.SetEnabled(true)
	for i := 0; i < 2000; i++ {
		logs.Append(LogEntry{Time: "2026-10-02T00:00:00Z", Domain: "mobile.de", QType: "A", Event: "cache"})
	}
	tail := logs.Snapshot(0).LastID
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logs.Snapshot(tail)
	}
}

func BenchmarkDNSStatusJSONWith180CachedAnswers(b *testing.B) {
	st, err := store.New(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	backend := &resolverTestBackend{routes: schedulerTestRoutes()[:2]}
	s := New(st, backend, func(string) (string, error) { return "192.168.3.1", nil })
	cfg := Default()
	cfg.Rules, cfg.CacheSize = nil, 2048
	r := NewResolver(cfg, backend)
	defer r.Close()
	s.cfg, s.active = cfg, &serviceRun{resolver: r}
	for i := 0; i < 180; i++ {
		q := new(mdns.Msg)
		q.SetQuestion(fmt.Sprintf("entry%d.example.", i), mdns.TypeA)
		r.cachePut(q.Question[0].Name, resolverAnswer(q, 600), "awg:primary", "https://1.1.1.1/dns-query", 0)
	}
	if s.Status().Cache.Entries != 180 {
		b.Fatal("benchmark cache fixture is incomplete")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := json.Marshal(s.Status()); err != nil {
			b.Fatal(err)
		}
	}
}

func TestDNSLogBufferWrapPreservesByteLimitAndCursors(t *testing.T) {
	logs := NewLogBuffer()
	logs.SetEnabled(true)
	for i := 0; i < 4000; i++ {
		entry := LogEntry{Time: time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC).Format(time.RFC3339), Event: "cache", Domain: "mobile.de", Message: fmt.Sprint(i)}
		if i%29 == 0 {
			entry.Upstream = fmt.Sprintf("https://%02000d.example/dns-query", i)
		}
		logs.Append(entry)
	}
	all := logs.Snapshot(0)
	assertLogSnapshot(t, all)
	if all.Dropped == 0 || all.LastID != 4000 || all.Dropped+uint64(len(all.Entries)) != 4000 {
		t.Fatalf("eviction lost newest entries or accounting: %+v", all)
	}
	for _, cursor := range []uint64{0, all.OldestID - 1, all.OldestID, all.LastID - 7, all.LastID, all.LastID + 1} {
		got := logs.Snapshot(cursor)
		want := 0
		for _, entry := range all.Entries {
			if entry.ID > cursor {
				if want >= len(got.Entries) || got.Entries[want] != entry {
					t.Fatalf("cursor %d returned a different entry at %d", cursor, want)
				}
				want++
			}
		}
		if len(got.Entries) != want || got.Bytes != all.Bytes || got.OldestID != all.OldestID {
			t.Fatalf("cursor %d broke snapshot metadata", cursor)
		}
	}
}
