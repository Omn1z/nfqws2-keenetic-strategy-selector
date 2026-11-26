// Package logbuf keeps a small in-memory ring of recent log lines tagged by
// module, surfaced in the UI "Логи" tab. It tees the standard logger so existing
// log.Printf calls (including the tgws "tgws: ..." lines) are captured, and also
// accepts direct tagged appends (used by the device trace).
package logbuf

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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
	mu          sync.Mutex
	ring        []Entry
	base        io.Writer = io.Discard
	proxyOutput io.Writer = io.Discard

	sinkMu  sync.Mutex
	partial []byte

	enabled atomic.Bool // logging on/off (the "Система" tab can disable it)
)

func init() {
	enabled.Store(true)
	// Pre-allocate ring at its steady-state capacity. Without this, the ring
	// kept doubling through Go's append growth and ended up with twice the
	// memory footprint (cap=4096 for len=2000) because the trim happens AFTER
	// the underlying array has already grown.
	ring = make([]Entry, 0, maxEntries+1)
}

// SetEnabled turns logging (ring + file) on or off. When off, Append is a no-op.
func SetEnabled(on bool) { enabled.Store(on) }

// Enabled reports whether logging is currently on.
func Enabled() bool { return enabled.Load() }

// Init sets the standard writer and the optional capped file for proxy diagnostics.
// With no file configured, proxy warnings and errors go to the standard writer.
// Set the standard logger flags to zero so its timestamp appears only once.
func Init(w io.Writer, proxyLogPath string) io.Writer {
	proxyWriter := w
	if proxyLogPath != "" {
		proxyWriter = newProxyLog(proxyLogPath)
	}
	mu.Lock()
	base = w
	proxyOutput = proxyWriter
	mu.Unlock()
	return sink{}
}

// Append records one tagged line into the ring and (timestamped) to the base writer.
// No-op when logging is disabled (the doc comment promised this; the previous
// impl only honoured it inside the sink path, not on direct Append callers).
func Append(module, level, msg string) {
	if !enabled.Load() {
		return
	}
	proxy := isProxyModule(module)
	if proxy && level != "warn" && level != "error" {
		return
	}
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
	if proxy {
		w = proxyOutput
	}
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
	if !enabled.Load() {
		return len(p), nil // swallow silently when off
	}
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
			module := inferModule(line)
			Append(module, inferLevel(module, line), line)
		}
	}
	return len(p), nil
}

func inferModule(line string) string {
	switch {
	case strings.HasPrefix(line, "tgws:"):
		return "tgws"
	case strings.HasPrefix(line, "socks5:"):
		return "socks5"
	case strings.HasPrefix(line, "proxy:"):
		return "proxy"
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
	case isHTTPLine(line):
		return "http"
	}
	return "system"
}

func isHTTPLine(line string) bool {
	for _, v := range [...]string{"GET /", "POST /", "PUT /", "DELETE /", "PATCH /"} {
		if strings.HasPrefix(line, v) {
			return true
		}
	}
	return false
}

func isProxyModule(module string) bool {
	return module == "tgws" || module == "socks5" || module == "proxy"
}

func inferLevel(module, line string) string {
	l := strings.ToLower(line)
	if isProxyModule(module) {
		switch {
		case strings.Contains(l, "autostart:"), strings.Contains(l, "no fallback available"), strings.Contains(l, "mtproto transport error"):
			return "error"
		case strings.Contains(l, "session closed"), strings.Contains(l, "fake-tls verify failed -> masking"):
			// Session-end summaries may contain a normal timeout or closed socket.
			return "info"
		case strings.Contains(l, "bad handshake"):
			return "warn"
		}
	}
	switch {
	case strings.Contains(l, "panic"), strings.Contains(l, "fatal"), strings.Contains(l, "error"), strings.Contains(l, "fail"):
		return "error"
	case strings.Contains(l, "warn"):
		return "warn"
	}
	return "info"
}
