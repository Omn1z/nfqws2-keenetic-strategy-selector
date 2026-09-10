package dnsserver

import (
	"encoding/json"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// MaxLogBytes bounds the retained log payload, measured as JSON entries with a
// newline after each entry. Logs are held in memory and never written to disk.
const MaxLogBytes = 128 * 1024

type LogEntry struct {
	ID         uint64 `json:"id"`
	Time       string `json:"time"`
	Level      string `json:"level"`
	Event      string `json:"event"`
	Domain     string `json:"domain,omitempty"`
	QType      string `json:"qtype,omitempty"`
	Upstream   string `json:"upstream,omitempty"`
	Route      string `json:"route,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
	Count      int    `json:"count,omitempty"`
	Message    string `json:"message,omitempty"`
}

type LogSnapshot struct {
	Enabled  bool       `json:"enabled"`
	Bytes    int        `json:"bytes"`
	MaxBytes int        `json:"max_bytes"`
	OldestID uint64     `json:"oldest_id"`
	LastID   uint64     `json:"last_id"`
	Dropped  uint64     `json:"dropped"`
	Entries  []LogEntry `json:"entries"`
}

type bufferedLogEntry struct {
	entry LogEntry
	bytes int
}

type LogBuffer struct {
	mu      sync.Mutex
	enabled bool
	entries []bufferedLogEntry
	bytes   int
	lastID  uint64
	dropped uint64
}

// NewLogBuffer starts with logging disabled. Disabling logging retains existing
// entries; Clear is the explicit way to discard them.
func NewLogBuffer() *LogBuffer { return &LogBuffer{} }

func (b *LogBuffer) SetEnabled(enabled bool) {
	b.mu.Lock()
	b.enabled = enabled
	b.mu.Unlock()
}

func (b *LogBuffer) Append(entry LogEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.enabled {
		return
	}

	entry = normalizeLogEntry(entry)
	entry.ID = b.lastID + 1
	// The entry contains only bounded strings and integer fields, so encoding
	// cannot fail and one entry always fits within MaxLogBytes, even when every
	// character needs JSON escaping.
	encoded, _ := json.Marshal(entry)
	size := len(encoded) + 1
	remove := 0
	for b.bytes+size > MaxLogBytes && remove < len(b.entries) {
		b.bytes -= b.entries[remove].bytes
		remove++
		b.dropped++
	}
	if remove > 0 {
		remaining := copy(b.entries, b.entries[remove:])
		clear(b.entries[remaining:])
		b.entries = b.entries[:remaining]
	}
	b.entries = append(b.entries, bufferedLogEntry{entry: entry, bytes: size})
	b.bytes += size
	b.lastID = entry.ID
}

// Snapshot returns entries newer than afterID. Metadata describes the complete
// retained buffer, including entries excluded by the cursor. IDs remain
// monotonic across Clear so polling can continue without reusing old IDs.
func (b *LogBuffer) Snapshot(afterID uint64) LogSnapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	result := LogSnapshot{
		Enabled: b.enabled, Bytes: b.bytes, MaxBytes: MaxLogBytes,
		LastID: b.lastID, Dropped: b.dropped, Entries: []LogEntry{},
	}
	if len(b.entries) > 0 {
		result.OldestID = b.entries[0].entry.ID
	}
	for _, retained := range b.entries {
		if retained.entry.ID > afterID {
			result.Entries = append(result.Entries, retained.entry)
		}
	}
	return result
}

// Clear releases all retained entries and resets the eviction counter, keeping
// the logging setting and last assigned ID unchanged.
func (b *LogBuffer) Clear() {
	b.mu.Lock()
	b.entries = nil
	b.bytes = 0
	b.dropped = 0
	b.mu.Unlock()
}

func normalizeLogEntry(entry LogEntry) LogEntry {
	if parsed, err := time.Parse(time.RFC3339Nano, entry.Time); err == nil {
		entry.Time = parsed.UTC().Format(time.RFC3339Nano)
	} else {
		entry.Time = time.Now().UTC().Format(time.RFC3339Nano)
	}
	entry.Level = boundedLogString(entry.Level, 16)
	if entry.Level == "" {
		entry.Level = "info"
	}
	entry.Event = boundedLogString(entry.Event, 48)
	if entry.Event == "" {
		entry.Event = "query"
	}
	entry.Domain = boundedLogString(entry.Domain, 253)
	entry.QType = boundedLogString(entry.QType, 24)
	entry.Upstream = boundedLogString(entry.Upstream, 2048)
	entry.Route = boundedLogString(entry.Route, 128)
	entry.Message = boundedLogString(entry.Message, 2048)
	if entry.DurationMS < 0 {
		entry.DurationMS = 0
	}
	if entry.Count < 0 {
		entry.Count = 0
	}
	return entry
}

func boundedLogString(value string, limit int) string {
	value = strings.ToValidUTF8(value, "\uFFFD")
	if len(value) <= limit {
		return value
	}
	const suffix = "…"
	end := limit - len(suffix)
	for end > 0 && !utf8.RuneStart(value[end]) {
		end--
	}
	return value[:end] + suffix
}
