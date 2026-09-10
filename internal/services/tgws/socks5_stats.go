package tgws

import "sync/atomic"

// Socks5Stats holds lock-free counters for the SOCKS5 Telegram proxy.
type Socks5Stats struct {
	total     atomic.Int64
	active    atomic.Int64
	telegram  atomic.Int64 // tunneled-over-WSS connections
	direct    atomic.Int64 // pass-through (non-Telegram) connections
	bad       atomic.Int64 // rejected handshakes
	bytesUp   atomic.Int64
	bytesDown atomic.Int64
	lastDC    atomic.Int64
	startedAt atomic.Int64
}

// Socks5Snapshot is the JSON view polled by the web UI.
type Socks5Snapshot struct {
	Connections struct {
		Total    int64 `json:"total"`
		Active   int64 `json:"active"`
		Telegram int64 `json:"telegram"`
		Direct   int64 `json:"direct"`
		Bad      int64 `json:"bad"`
	} `json:"connections"`
	Traffic struct {
		BytesUp   int64  `json:"bytes_up"`
		BytesDown int64  `json:"bytes_down"`
		HumanUp   string `json:"human_up"`
		HumanDown string `json:"human_down"`
	} `json:"traffic"`
	LastDC    int64 `json:"last_dc"`
	StartedAt int64 `json:"started_at"`
}

func (s *Socks5Stats) snapshot() Socks5Snapshot {
	var out Socks5Snapshot
	out.Connections.Total = s.total.Load()
	out.Connections.Active = s.active.Load()
	out.Connections.Telegram = s.telegram.Load()
	out.Connections.Direct = s.direct.Load()
	out.Connections.Bad = s.bad.Load()
	up, down := s.bytesUp.Load(), s.bytesDown.Load()
	out.Traffic.BytesUp = up
	out.Traffic.BytesDown = down
	out.Traffic.HumanUp = humanBytes(up)
	out.Traffic.HumanDown = humanBytes(down)
	out.LastDC = s.lastDC.Load()
	out.StartedAt = s.startedAt.Load()
	return out
}
