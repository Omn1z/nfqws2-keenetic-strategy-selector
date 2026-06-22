package awgroute

import (
	"sync"
	"sync/atomic"
	"time"
)

// Per-flow trace log: a tag-free, in-memory ring that records each DNS query
// and SNI sighting the proxy/sniffer process, with the routing decision and a
// one-line reason. Turned off by default — when off, the hot path is one
// atomic load + early return (~5ns) so the recording cost only exists while
// the user is actively debugging. The API surface drains the ring; nothing is
// persisted to disk, so a selector restart clears it.

const traceRingCap = 5000

// TraceEntry is one routed-traffic event. Field names are short because they
// are serialized to JSON on every API hit (the ring can hold thousands).
type TraceEntry struct {
	TS       int64  `json:"ts"`              // unix-nanoseconds; 0 for empty slot
	Src      string `json:"src,omitempty"`   // LAN client IP ("" = router-local / SNI without src)
	Kind     string `json:"kind"`            // "dns" | "sni"
	Name     string `json:"name"`            // qname or SNI hostname
	Qtype    string `json:"qtype,omitempty"` // "A" | "AAAA" | "" for non-DNS
	Dst      string `json:"dst,omitempty"`   // resolved IP / SNI destination
	Decision string `json:"decision"`        // "tunnel" | "direct" | "blocked" | "cdn-skip"
	Rule     int    `json:"rule,omitempty"`  // 1-based index of the matched rule (0 = no rule, default route)
	Reason   string `json:"reason,omitempty"`
}

type traceRing struct {
	mu      sync.Mutex
	entries []TraceEntry
	next    int
	enabled atomic.Bool

	// Lifetime counters — incremented on every traceAppend (regardless of
	// whether recording is on, so the dashboard always has a clean rate
	// signal). Polled-then-delta'd by the UI to compute requests/sec.
	cntDNS     atomic.Uint64
	cntSNI     atomic.Uint64
	cntTunnel  atomic.Uint64
	cntDirect  atomic.Uint64
	cntBlocked atomic.Uint64
	cntCDNSkip atomic.Uint64
}

var awgTrace = func() *traceRing {
	r := &traceRing{entries: make([]TraceEntry, traceRingCap)}
	return r
}()

// traceEnabled is the hot-path check. One atomic load. Inlinable.
func traceEnabled() bool { return awgTrace.enabled.Load() }

// traceSetEnabled flips the toggle. Existing entries survive a disable so the
// user can still inspect a capture after pausing recording.
func traceSetEnabled(on bool) { awgTrace.enabled.Store(on) }

// traceAppend records one event. Counters always tick (cheap atomic add) so
// the dashboard rate signal works even when the ring isn't recording.
// The ring itself only fills when traceEnabled is on.
func traceAppend(e TraceEntry) {
	switch e.Kind {
	case "dns":
		awgTrace.cntDNS.Add(1)
	case "sni":
		awgTrace.cntSNI.Add(1)
	}
	switch e.Decision {
	case "tunnel":
		awgTrace.cntTunnel.Add(1)
	case "direct":
		awgTrace.cntDirect.Add(1)
	case "blocked":
		awgTrace.cntBlocked.Add(1)
	case "cdn-skip":
		awgTrace.cntCDNSkip.Add(1)
	}
	if !awgTrace.enabled.Load() {
		return
	}
	if e.TS == 0 {
		e.TS = time.Now().UnixNano()
	}
	awgTrace.mu.Lock()
	awgTrace.entries[awgTrace.next] = e
	awgTrace.next = (awgTrace.next + 1) % traceRingCap
	awgTrace.mu.Unlock()
}

// traceSnapshot returns entries newer than `since` (nanoseconds), in time
// order (oldest first). Pass 0 for all. Returns a fresh slice — caller owns it.
func traceSnapshot(since int64) []TraceEntry {
	awgTrace.mu.Lock()
	defer awgTrace.mu.Unlock()
	out := make([]TraceEntry, 0, traceRingCap)
	start := awgTrace.next
	for i := 0; i < traceRingCap; i++ {
		e := awgTrace.entries[(start+i)%traceRingCap]
		if e.TS == 0 || e.TS <= since {
			continue
		}
		out = append(out, e)
	}
	return out
}

// traceClear empties the ring without flipping the enable flag.
func traceClear() {
	awgTrace.mu.Lock()
	for i := range awgTrace.entries {
		awgTrace.entries[i] = TraceEntry{}
	}
	awgTrace.next = 0
	awgTrace.mu.Unlock()
}

// Exported façade used by the HTTP handlers.

// TraceStatus is returned by GET /api/awg2/trace/status.
type TraceStatus struct {
	Enabled bool `json:"enabled"`
	Count   int  `json:"count"`
	Cap     int  `json:"cap"`
}

// TraceStatus reports whether recording is on plus the current ring depth.
func (svc *Service) TraceStatus() TraceStatus {
	awgTrace.mu.Lock()
	n := 0
	for _, e := range awgTrace.entries {
		if e.TS != 0 {
			n++
		}
	}
	awgTrace.mu.Unlock()
	return TraceStatus{Enabled: traceEnabled(), Count: n, Cap: traceRingCap}
}

// TraceSnapshot returns entries newer than `since` (nanoseconds), oldest first.
func (svc *Service) TraceSnapshot(since int64) []TraceEntry { return traceSnapshot(since) }

// TraceClear empties the ring.
func (svc *Service) TraceClear() { traceClear() }

// TraceCounters is the lifetime counter snapshot returned by /api/awg2/trace/stats.
// Each field is monotonic; the dashboard computes rate as (now - prev) / dt.
type TraceCounters struct {
	DNS     uint64 `json:"dns"`
	SNI     uint64 `json:"sni"`
	Tunnel  uint64 `json:"tunnel"`
	Direct  uint64 `json:"direct"`
	Blocked uint64 `json:"blocked"`
	CDNSkip uint64 `json:"cdn_skip"`
}

// TraceCounters returns the lifetime counters. Atomic loads — no lock needed.
func (svc *Service) TraceCounters() TraceCounters {
	return TraceCounters{
		DNS:     awgTrace.cntDNS.Load(),
		SNI:     awgTrace.cntSNI.Load(),
		Tunnel:  awgTrace.cntTunnel.Load(),
		Direct:  awgTrace.cntDirect.Load(),
		Blocked: awgTrace.cntBlocked.Load(),
		CDNSkip: awgTrace.cntCDNSkip.Load(),
	}
}

// TraceSetEnabled flips the toggle AND persists it into the active server's
// Routing config so the choice survives a watchdog re-render. Returns the new
// state. When turning off, existing entries stay in the ring for inspection.
func (svc *Service) TraceSetEnabled(on bool) bool {
	traceSetEnabled(on)
	if m := svc.awgActive(); m != nil {
		c := m.Config()
		if c.Routing.TraceEnabled != on {
			c.Routing.TraceEnabled = on
			_ = m.SetConfig(&c)
			svc.awgSave()
		}
	}
	return on
}
