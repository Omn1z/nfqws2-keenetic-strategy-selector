package monitor

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"time"

	"nfqws2strategy/internal/tools/logbuf"
	"nfqws2strategy/internal/tools/netmon"
	"nfqws2strategy/internal/tools/store"
)

const (
	traceInterval   = 500 * time.Millisecond
	maxStoredTraces = 10
)

// TraceEvent is one timeline entry of a device trace (ms since start).
type TraceEvent struct {
	AtMs  int64  `json:"at_ms"`
	Kind  string `json:"kind"` // new | unreplied | replied | gone
	Proto string `json:"proto"`
	Dst   string `json:"dst"`
	Note  string `json:"note,omitempty"`
}

// TraceConn summarizes one connection (flow) seen during the trace.
type TraceConn struct {
	Proto      string `json:"proto"`
	Dst        string `json:"dst"`
	State      string `json:"state"`
	FirstMs    int64  `json:"first_ms"`
	LastMs     int64  `json:"last_ms"`
	Samples    int    `json:"samples"`
	MaxPackets int64  `json:"max_packets"`
	MaxBytes   int64  `json:"max_bytes"`
	Unreplied  bool   `json:"unreplied"`
	Gone       bool   `json:"gone"`
}

// Trace is a 30s (configurable) capture of one device's conntrack flows.
type Trace struct {
	ID        string       `json:"id"`
	IP        string       `json:"ip"`
	Seconds   int          `json:"seconds"`
	Status    string       `json:"status"` // running | done | error
	Error     string       `json:"error,omitempty"`
	StartedAt int64        `json:"started_at"`
	ElapsedMs int64        `json:"elapsed_ms"`
	Events    []TraceEvent `json:"events"`
	Conns     []TraceConn  `json:"conns"`
}

func traceDst(c netmon.Conn) string {
	if c.DstPort == 0 {
		return c.Dst.String()
	}
	return net.JoinHostPort(c.Dst.String(), strconv.Itoa(c.DstPort))
}

// StartDeviceTrace begins a conntrack-polling capture of one LAN device and
// returns the initial snapshot. The capture runs in a goroutine; poll GetTrace.
func (s *Service) StartDeviceTrace(ip string, seconds int) (*Trace, error) {
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("неверный IP")
	}
	if seconds <= 0 || seconds > 120 {
		seconds = 30
	}
	t := &Trace{ID: store.NewID(), IP: ip, Seconds: seconds, Status: "running", StartedAt: time.Now().Unix(), Events: []TraceEvent{}, Conns: []TraceConn{}}
	s.traceMu.Lock()
	s.traces[t.ID] = t
	s.traceOrder = append(s.traceOrder, t.ID)
	for len(s.traceOrder) > maxStoredTraces {
		delete(s.traces, s.traceOrder[0])
		s.traceOrder = s.traceOrder[1:]
	}
	s.traceMu.Unlock()
	go s.runTrace(t)
	return s.snapshotTrace(t.ID), nil
}

// GetTrace returns a serialization-safe copy of a trace.
func (s *Service) GetTrace(id string) (*Trace, bool) {
	t := s.snapshotTrace(id)
	return t, t != nil
}

func (s *Service) snapshotTrace(id string) *Trace {
	s.traceMu.Lock()
	defer s.traceMu.Unlock()
	t, ok := s.traces[id]
	if !ok {
		return nil
	}
	cp := *t
	// make(...,0,...) keeps the copies non-nil so they marshal to [] (not null)
	// even while empty — the UI indexes .length/.map on them.
	cp.Events = append(make([]TraceEvent, 0, len(t.Events)), t.Events...)
	cp.Conns = append(make([]TraceConn, 0, len(t.Conns)), t.Conns...)
	return &cp
}

func (s *Service) runTrace(t *Trace) {
	type cstate struct {
		conn         TraceConn
		present      bool
		wasUnreplied bool
	}
	seen := map[string]*cstate{}
	start := time.Now()
	deadline := start.Add(time.Duration(t.Seconds) * time.Second)
	logbuf.Append("trace", "info", fmt.Sprintf("trace %s: старт отслеживания %s на %d с", short(t.ID), t.IP, t.Seconds))

	tick := time.NewTicker(traceInterval)
	defer tick.Stop()
	for {
		now := time.Now()
		elapsed := now.Sub(start).Milliseconds()
		conns, err := netmon.Conntrack()
		if err != nil {
			s.traceMu.Lock()
			t.Status = "error"
			t.Error = err.Error()
			s.traceMu.Unlock()
			logbuf.Append("trace", "error", "trace: conntrack: "+err.Error())
			return
		}

		cur := map[string]netmon.Conn{}
		for _, c := range conns {
			if c.Src.String() != t.IP {
				continue
			}
			cur[fmt.Sprintf("%s|%s|%d|%d", c.Proto, c.Dst.String(), c.DstPort, c.SrcPort)] = c
		}

		s.traceMu.Lock()
		for _, st := range seen {
			st.present = false
		}
		for key, c := range cur {
			dst := traceDst(c)
			st := seen[key]
			if st == nil {
				st = &cstate{conn: TraceConn{Proto: c.Proto, Dst: dst, State: c.State, FirstMs: elapsed}}
				seen[key] = st
				t.Events = append(t.Events, TraceEvent{AtMs: elapsed, Kind: "new", Proto: c.Proto, Dst: dst, Note: c.State})
				logbuf.Append("trace", "info", fmt.Sprintf("+%dмс NEW   %s %s %s", elapsed, c.Proto, dst, c.State))
			}
			st.present = true
			st.conn.LastMs = elapsed
			st.conn.Samples++
			st.conn.State = c.State
			if c.Packets > st.conn.MaxPackets {
				st.conn.MaxPackets = c.Packets
			}
			if total := c.Bytes + c.ReplyBytes; total > st.conn.MaxBytes {
				st.conn.MaxBytes = total
			}
			if c.Unreplied && !st.wasUnreplied {
				st.conn.Unreplied = true
				t.Events = append(t.Events, TraceEvent{AtMs: elapsed, Kind: "unreplied", Proto: c.Proto, Dst: dst, Note: "нет ответа от назначения"})
				logbuf.Append("trace", "warn", fmt.Sprintf("+%dмс NOREPLY %s %s — нет ответа", elapsed, c.Proto, dst))
			} else if !c.Unreplied && st.wasUnreplied {
				t.Events = append(t.Events, TraceEvent{AtMs: elapsed, Kind: "replied", Proto: c.Proto, Dst: dst, Note: "ответ появился"})
				logbuf.Append("trace", "info", fmt.Sprintf("+%dмс REPLY %s %s — ответ появился", elapsed, c.Proto, dst))
			}
			st.wasUnreplied = c.Unreplied
		}
		for _, st := range seen {
			if !st.present && !st.conn.Gone {
				st.conn.Gone = true
				t.Events = append(t.Events, TraceEvent{AtMs: elapsed, Kind: "gone", Proto: st.conn.Proto, Dst: st.conn.Dst, Note: "соединение закрыто/сброшено"})
				logbuf.Append("trace", "warn", fmt.Sprintf("+%dмс GONE  %s %s — закрыто/сброшено", elapsed, st.conn.Proto, st.conn.Dst))
			}
		}
		t.ElapsedMs = elapsed
		s.traceMu.Unlock()

		if now.After(deadline) {
			break
		}
		<-tick.C
	}

	s.traceMu.Lock()
	t.Conns = t.Conns[:0]
	for _, st := range seen {
		t.Conns = append(t.Conns, st.conn)
	}
	sort.Slice(t.Conns, func(i, j int) bool { return t.Conns[i].FirstMs < t.Conns[j].FirstMs })
	t.Status = "done"
	dropped := 0
	for _, c := range t.Conns {
		if c.Gone || c.Unreplied {
			dropped++
		}
	}
	s.traceMu.Unlock()
	logbuf.Append("trace", "info", fmt.Sprintf("trace %s: готово — %d соединений, %d с проблемами, %d событий", short(t.ID), len(seen), dropped, len(t.Events)))
}

// short truncates an id for log lines (shared with pcap.go in this package).
func short(id string) string {
	if len(id) > 6 {
		return id[:6]
	}
	return id
}
