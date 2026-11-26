package dnsserver

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// MaxLogBytes bounds the retained log payload, measured as JSON entries with a
// newline after each entry. Logs are held in memory and never written to disk.
const MaxLogBytes = 128 * 1024

type LogEntry struct {
	BlockCategory string `json:"block_category,omitempty"`
	BlockRule     string `json:"block_rule,omitempty"`
	BlockSource   string `json:"block_source,omitempty"`
	BlockDomain   string `json:"block_domain,omitempty"`
	ID            uint64 `json:"id"`
	Time          string `json:"time"`
	Level         string `json:"level"`
	Event         string `json:"event"`
	Domain        string `json:"domain,omitempty"`
	QType         string `json:"qtype,omitempty"`
	Upstream      string `json:"upstream,omitempty"`
	Route         string `json:"route,omitempty"`
	ClientIP      string `json:"client_ip,omitempty"`
	Source        string `json:"source,omitempty"`
	Transport     string `json:"transport,omitempty"`
	DurationMS    int64  `json:"duration_ms,omitempty"`
	Count         int    `json:"count,omitempty"`
	Message       string `json:"message,omitempty"`
}

type LogSnapshot struct {
	InstanceID string     `json:"instance_id"`
	Enabled    bool       `json:"enabled"`
	Bytes      int        `json:"bytes"`
	MaxBytes   int        `json:"max_bytes"`
	OldestID   uint64     `json:"oldest_id"`
	LastID     uint64     `json:"last_id"`
	Dropped    uint64     `json:"dropped"`
	Entries    []LogEntry `json:"entries"`
}

type bufferedLogEntry struct {
	entry LogEntry
	bytes int
}

type LogBuffer struct {
	instanceID string
	mu         sync.Mutex
	enabled    bool
	entries    []bufferedLogEntry
	head       int
	count      int
	bytes      int
	lastID     uint64
	dropped    uint64
}

// NewLogBuffer starts with logging disabled. Disabling logging retains existing
// entries; Clear is the explicit way to discard them.
var logBufferSequence atomic.Uint64

func NewLogBuffer() *LogBuffer {
	// Opaque diagnostic identity, generated only once per buffer. A restart
	// can assign IDs beyond a browser's old cursor before its next poll;
	// numeric entry IDs alone therefore cannot identify a new journal.
	instanceID := fmt.Sprintf("%x-%x-%x", time.Now().UnixNano(), os.Getpid(), logBufferSequence.Add(1))
	return &LogBuffer{instanceID: instanceID}
}

func (b *LogBuffer) SetEnabled(enabled bool) {
	b.mu.Lock()
	b.enabled = enabled
	b.mu.Unlock()
}

func (b *LogBuffer) Enabled() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.enabled
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
	for b.bytes+size > MaxLogBytes && b.count > 0 {
		b.bytes -= b.entries[b.head].bytes
		// Release strings immediately; evicting one event never copies the
		// entire retained buffer while request handlers wait on the mutex.
		b.entries[b.head] = bufferedLogEntry{}
		b.head = (b.head + 1) % len(b.entries)
		b.count--
		b.dropped++
	}
	if b.count == len(b.entries) {
		capacity := b.count + b.count/2 + 16
		grown := make([]bufferedLogEntry, capacity)
		for i := 0; i < b.count; i++ {
			grown[i] = b.entries[(b.head+i)%len(b.entries)]
		}
		b.entries, b.head = grown, 0
	}
	b.entries[(b.head+b.count)%len(b.entries)] = bufferedLogEntry{entry: entry, bytes: size}
	b.count++
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
		InstanceID: b.instanceID,
		Enabled:    b.enabled, Bytes: b.bytes, MaxBytes: MaxLogBytes,
		LastID: b.lastID, Dropped: b.dropped, Entries: []LogEntry{},
	}
	if b.count > 0 {
		result.OldestID = b.entries[b.head].entry.ID
	}
	// Most UI polls ask after the previous tail; avoid scanning all retained
	// events, and allocate only the entries the cursor actually requests.
	if afterID >= b.lastID {
		return result
	}
	start := sort.Search(b.count, func(i int) bool {
		return b.entries[(b.head+i)%len(b.entries)].entry.ID > afterID
	})
	if start < b.count {
		result.Entries = make([]LogEntry, b.count-start)
		for i := start; i < b.count; i++ {
			result.Entries[i-start] = b.entries[(b.head+i)%len(b.entries)].entry
		}
	}
	return result
}

// Clear releases all retained entries and resets the eviction counter, keeping
// the logging setting and last assigned ID unchanged.
func (b *LogBuffer) Clear() {
	b.mu.Lock()
	b.entries = nil
	b.head, b.count = 0, 0
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
	entry.ClientIP = boundedLogString(entry.ClientIP, 64)
	entry.Source = boundedLogString(entry.Source, 24)
	entry.Transport = boundedLogString(entry.Transport, 16)
	entry.BlockCategory = boundedLogString(entry.BlockCategory, 16)
	entry.BlockRule = boundedLogString(entry.BlockRule, 2048)
	entry.BlockDomain = boundedLogString(entry.BlockDomain, 253)
	entry.BlockSource = boundedLogString(entry.BlockSource, 64)
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
