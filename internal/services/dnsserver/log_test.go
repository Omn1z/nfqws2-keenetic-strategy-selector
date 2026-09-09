package dnsserver

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

func assertLogSnapshot(t *testing.T, snapshot LogSnapshot) {
	t.Helper()
	if snapshot.Bytes < 0 || snapshot.Bytes > MaxLogBytes || snapshot.MaxBytes != MaxLogBytes {
		t.Fatalf("invalid log size metadata: %+v", snapshot)
	}
	size := 0
	var previous uint64
	for _, entry := range snapshot.Entries {
		if entry.ID <= previous || entry.ID > snapshot.LastID {
			t.Fatalf("log IDs are not increasing: previous=%d entry=%d last=%d", previous, entry.ID, snapshot.LastID)
		}
		previous = entry.ID
		encoded, err := json.Marshal(entry)
		if err != nil || !json.Valid(encoded) {
			t.Fatalf("invalid log JSON: %s: %v", encoded, err)
		}
		size += len(encoded) + 1
		if _, err := time.Parse(time.RFC3339Nano, entry.Time); err != nil {
			t.Fatalf("invalid log time %q: %v", entry.Time, err)
		}
	}
	if size != snapshot.Bytes {
		t.Fatalf("retained JSON bytes=%d, reported=%d", size, snapshot.Bytes)
	}
	if len(snapshot.Entries) == 0 {
		if snapshot.OldestID != 0 {
			t.Fatalf("empty log oldest ID=%d", snapshot.OldestID)
		}
	} else if snapshot.OldestID != snapshot.Entries[0].ID {
		t.Fatalf("oldest ID=%d, first entry=%d", snapshot.OldestID, snapshot.Entries[0].ID)
	}
}

func TestDNSLogBufferDisabledAndClear(t *testing.T) {
	b := NewLogBuffer()
	b.Append(LogEntry{Message: "not retained"})
	if s := b.Snapshot(0); s.Enabled || len(s.Entries) != 0 || s.LastID != 0 {
		t.Fatalf("new buffer must be disabled and empty: %+v", s)
	}
	b.SetEnabled(true)
	b.Append(LogEntry{ID: 999, Message: "retained"})
	b.SetEnabled(false)
	b.Append(LogEntry{Message: "also not retained"})
	s := b.Snapshot(0)
	assertLogSnapshot(t, s)
	if s.Enabled || len(s.Entries) != 1 || s.Entries[0].ID != 1 || s.Entries[0].Message != "retained" {
		t.Fatalf("disabling must preserve old entries and skip new ones: %+v", s)
	}
	b.Clear()
	s = b.Snapshot(0)
	assertLogSnapshot(t, s)
	if s.Enabled || len(s.Entries) != 0 || s.LastID != 1 || s.Dropped != 0 {
		t.Fatalf("clear changed settings/ID or retained entries: %+v", s)
	}
	b.SetEnabled(true)
	b.Append(LogEntry{Message: "after clear"})
	s = b.Snapshot(0)
	if s.LastID != 2 || len(s.Entries) != 1 || s.Entries[0].ID != 2 {
		t.Fatalf("IDs must remain monotonic after clear: %+v", s)
	}
}

func TestDNSLogBufferEvictsOldestByEncodedBytes(t *testing.T) {
	b := NewLogBuffer()
	b.SetEnabled(true)
	const total = 350
	for i := 0; i < total; i++ {
		// Quotes, newlines, and multibyte characters make both rune counts and
		// unencoded string byte counts inadequate for enforcing the log limit.
		b.Append(LogEntry{Domain: fmt.Sprintf("%d.example.com", i), Message: strings.Repeat("ДНС🚀\n\"<&", 20+i%60)})
		assertLogSnapshot(t, b.Snapshot(0))
	}
	s := b.Snapshot(0)
	if s.Dropped == 0 || s.Dropped+uint64(len(s.Entries)) != total {
		t.Fatalf("wrong eviction count: retained=%d dropped=%d", len(s.Entries), s.Dropped)
	}
	for i, entry := range s.Entries {
		want := s.Dropped + uint64(i) + 1
		if entry.ID != want {
			t.Fatalf("entry %d has ID=%d, want=%d", i, entry.ID, want)
		}
	}
	if s.LastID != total || s.Entries[len(s.Entries)-1].ID != total {
		t.Fatal("newest entry was not retained")
	}
	b.Clear()
	if s := b.Snapshot(0); s.Dropped != 0 || s.Bytes != 0 || s.LastID != total {
		t.Fatalf("clear must reset evictions and size but not IDs: %+v", s)
	}
}

func TestDNSLogBufferRetainsCompactCancellationsAbovePreviousLimit(t *testing.T) {
	b := NewLogBuffer()
	b.SetEnabled(true)
	for i := 0; i < 600; i++ {
		b.Append(LogEntry{Level: "debug", Event: "canceled", Domain: "grouped-cancellations.example", QType: "AAAA", Count: 31})
	}
	snapshot := b.Snapshot(0)
	assertLogSnapshot(t, snapshot)
	if snapshot.MaxBytes != 128*1024 || snapshot.Bytes <= 64*1024 || snapshot.Dropped != 0 || len(snapshot.Entries) != 600 {
		t.Fatalf("compact cancellations were evicted before the new limit: bytes=%d max=%d dropped=%d entries=%d", snapshot.Bytes, snapshot.MaxBytes, snapshot.Dropped, len(snapshot.Entries))
	}
	for _, entry := range snapshot.Entries {
		if entry.Count != 31 {
			t.Fatalf("cancellation count was lost: %+v", entry)
		}
	}
}

func TestDNSLogBufferBoundsAndNormalizesSingleEntry(t *testing.T) {
	b := NewLogBuffer()
	b.SetEnabled(true)
	oversize := strings.Repeat("🚀\x00\xff\n\"<", 10000)
	b.Append(LogEntry{
		Time: oversize, Level: oversize, Event: oversize, Domain: oversize,
		QType: oversize, Upstream: oversize, Route: oversize, Message: oversize,
		DurationMS: -1, Count: -1,
	})
	s := b.Snapshot(0)
	assertLogSnapshot(t, s)
	if len(s.Entries) != 1 || s.Dropped != 0 {
		t.Fatalf("one oversized event must still be retained: %+v", s)
	}
	entry := s.Entries[0]
	for _, field := range []struct {
		name  string
		value string
		limit int
	}{
		{"level", entry.Level, 16}, {"event", entry.Event, 48},
		{"domain", entry.Domain, 253}, {"qtype", entry.QType, 24},
		{"upstream", entry.Upstream, 2048}, {"route", entry.Route, 128},
		{"message", entry.Message, 2048},
	} {
		if !utf8.ValidString(field.value) || len(field.value) > field.limit || !strings.HasSuffix(field.value, "…") {
			t.Errorf("%s was not bounded at a UTF-8 boundary: bytes=%d valid=%v", field.name, len(field.value), utf8.ValidString(field.value))
		}
	}
	if entry.DurationMS != 0 || entry.Count != 0 {
		t.Fatalf("negative counters were not normalized: %+v", entry)
	}
	b.Append(LogEntry{Time: "2026-09-09T13:12:11.123+03:00"})
	entry = b.Snapshot(0).Entries[1]
	if entry.Time != "2026-09-09T10:12:11.123Z" || entry.Level != "info" || entry.Event != "query" {
		t.Fatalf("wrong default fields/UTC time: %+v", entry)
	}
}

func TestDNSLogBufferSnapshotCursorAndOwnership(t *testing.T) {
	b := NewLogBuffer()
	b.SetEnabled(true)
	for i := 0; i < 10; i++ {
		b.Append(LogEntry{Message: fmt.Sprintf("event %d", i)})
	}
	all := b.Snapshot(0)
	after := b.Snapshot(7)
	if len(after.Entries) != 3 || after.Entries[0].ID != 8 || after.LastID != 10 || after.OldestID != 1 || after.Bytes != all.Bytes {
		t.Fatalf("cursor changed whole-buffer metadata or returned wrong entries: %+v", after)
	}
	if s := b.Snapshot(10); len(s.Entries) != 0 || s.Entries == nil || s.LastID != 10 {
		t.Fatalf("cursor at tail must return non-nil empty entries: %+v", s)
	}
	after.Entries[0].Message = "modified by consumer"
	if next := b.Snapshot(7); next.Entries[0].Message != "event 7" {
		t.Fatal("snapshot mutation changed stored entry")
	}
	b.Clear()
	b.Append(LogEntry{Message: "new event"})
	if s := b.Snapshot(10); len(s.Entries) != 1 || s.Entries[0].ID != 11 {
		t.Fatalf("cursor missed event after clear: %+v", s)
	}
}

func TestDNSLogBufferConcurrentAppendAndSnapshot(t *testing.T) {
	b := NewLogBuffer()
	b.SetEnabled(true)
	const writers, perWriter = 12, 120
	var wg sync.WaitGroup
	for writer := 0; writer < writers; writer++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				b.Append(LogEntry{Message: "concurrent DNS result"})
				if i%30 == 0 {
					assertLogSnapshot(t, b.Snapshot(0))
				}
			}
		}()
	}
	wg.Wait()
	s := b.Snapshot(0)
	assertLogSnapshot(t, s)
	if s.LastID != writers*perWriter || s.Dropped+uint64(len(s.Entries)) != writers*perWriter {
		t.Fatalf("concurrent appends lost events: last=%d retained=%d dropped=%d", s.LastID, len(s.Entries), s.Dropped)
	}
}

func TestDNSLogBufferConcurrentClearAndToggle(t *testing.T) {
	b := NewLogBuffer()
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				b.SetEnabled(i%5 != 0)
				b.Append(LogEntry{Message: "concurrent DNS result"})
				if i%17 == 0 {
					b.Clear()
				}
				assertLogSnapshot(t, b.Snapshot(0))
			}
		}()
	}
	wg.Wait()
	assertLogSnapshot(t, b.Snapshot(0))
}
