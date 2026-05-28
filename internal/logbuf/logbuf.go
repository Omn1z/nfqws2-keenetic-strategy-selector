// Package logbuf keeps a small in-memory ring of recent log lines tagged by
// module, surfaced in the UI "Логи" tab. It tees the standard logger so existing
// log.Printf calls (including the tgws "tgws: ..." lines) are captured, and also
// accepts direct tagged appends (used by the device trace).
package logbuf

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxEntries = 2000
	maxMsgLen  = 2000
)

type Entry struct {
	T      int64  `json:"t"` // unix millis
	Module string `json:"module"`
	Level  string `json:"level"` // info | warn | error
	Msg    string `json:"msg"`
}

var (
	mu   sync.Mutex
	ring []Entry
	base io.Writer = io.Discard

	sinkMu  sync.Mutex
	partial []byte
)

// Init sets the underlying writer (the -log file / stderr) and returns a Sink to
// pass to log.SetOutput. Call log.SetFlags(0) too so the stdlib timestamp isn't
// duplicated (logbuf adds its own).
func Init(w io.Writer) io.Writer {
	mu.Lock()
	base = w
	mu.Unlock()
	return sink{}
}

// Append records one tagged line into the ring and (timestamped) to the base writer.
func Append(module, level, msg string) {
	msg = strings.TrimRight(msg, "\n")
	if msg == "" {
		return
	}
	if len(msg) > maxMsgLen {
		msg = msg[:maxMsgLen]
	}
	now := time.Now()
	mu.Lock()
	ring = append(ring, Entry{T: now.UnixMilli(), Module: module, Level: level, Msg: msg})
	if len(ring) > maxEntries {
		ring = ring[len(ring)-maxEntries:]
	}
	w := base
	mu.Unlock()
	fmt.Fprintf(w, "%s [%s] %s\n", now.Format("2006-01-02 15:04:05"), module, msg)
}

// Snapshot returns recent entries (optionally filtered by module), oldest first,
// capped to the most recent `limit` (0 = all).
func Snapshot(module string, limit int) []Entry {
	mu.Lock()
	defer mu.Unlock()
	out := make([]Entry, 0, len(ring))
	for _, e := range ring {
		if module == "" || module == "all" || e.Module == module {
			out = append(out, e)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

// Modules lists the distinct modules currently in the ring (for the UI filter).
func Modules() []string {
	mu.Lock()
	defer mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, e := range ring {
		if !seen[e.Module] {
			seen[e.Module] = true
			out = append(out, e.Module)
		}
	}
	sort.Strings(out)
	return out
}

func Clear() {
	mu.Lock()
	ring = ring[:0]
	mu.Unlock()
}

// sink tees the standard logger into Append, splitting on newlines and inferring
// the module from the line prefix.
type sink struct{}

func (sink) Write(p []byte) (int, error) {
	sinkMu.Lock()
	partial = append(partial, p...)
	var lines []string
	for {
		i := bytes.IndexByte(partial, '\n')
		if i < 0 {
			break
		}
		lines = append(lines, string(partial[:i]))
		partial = partial[i+1:]
	}
	partial = append([]byte(nil), partial...) // keep remainder without growing the backing array
	sinkMu.Unlock()
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			Append(inferModule(line), inferLevel(line), line)
		}
	}
	return len(p), nil
}

var reHTTP = regexp.MustCompile(`^(GET|POST|PUT|DELETE|PATCH) /`)

func inferModule(line string) string {
	switch {
	case strings.HasPrefix(line, "tgws:"):
		return "tgws"
	case strings.HasPrefix(line, "trace"):
		return "trace"
	case strings.HasPrefix(line, "run:"):
		return "run"
	case strings.HasPrefix(line, "blockcheck"):
		return "blockcheck"
	case strings.HasPrefix(line, "dns:"):
		return "dns"
	case strings.HasPrefix(line, "update") || strings.HasPrefix(line, "selfupdate"):
		return "update"
	case reHTTP.MatchString(line):
		return "http"
	}
	return "system"
}

func inferLevel(line string) string {
	l := strings.ToLower(line)
	switch {
	case strings.Contains(l, "panic"), strings.Contains(l, "fatal"), strings.Contains(l, "error"), strings.Contains(l, "fail"):
		return "error"
	case strings.Contains(l, "warn"):
		return "warn"
	}
	return "info"
}
