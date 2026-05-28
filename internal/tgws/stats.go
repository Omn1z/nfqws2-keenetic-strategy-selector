package tgws

import (
	"fmt"
	"sync/atomic"
)

// Stats holds lightweight in-process counters for the proxy. All fields are
// accessed atomically so the bridge goroutines can update them lock-free.
type Stats struct {
	connectionsTotal       atomic.Int64
	connectionsActive      atomic.Int64
	connectionsWS          atomic.Int64
	connectionsTCPFallback atomic.Int64
	connectionsCFProxy     atomic.Int64
	connectionsBad         atomic.Int64
	connectionsMasked      atomic.Int64
	wsErrors               atomic.Int64
	bytesUp                atomic.Int64
	bytesDown              atomic.Int64
	poolHits               atomic.Int64
	poolMisses             atomic.Int64
	startedAt              atomic.Int64 // unix seconds
}

func humanBytes(n int64) string {
	f := float64(n)
	for _, unit := range []string{"B", "KB", "MB", "GB"} {
		if f < 1024 && f > -1024 {
			return fmt.Sprintf("%.1f%s", f, unit)
		}
		f /= 1024
	}
	return fmt.Sprintf("%.1fTB", f)
}

// Snapshot is a JSON-friendly view of the counters for the web UI.
type Snapshot struct {
	Connections struct {
		Total       int64 `json:"total"`
		Active      int64 `json:"active"`
		WS          int64 `json:"ws"`
		TCPFallback int64 `json:"tcp_fallback"`
		CFProxy     int64 `json:"cfproxy"`
		Bad         int64 `json:"bad"`
		Masked      int64 `json:"masked"`
	} `json:"connections"`
	Traffic struct {
		BytesUp   int64  `json:"bytes_up"`
		BytesDown int64  `json:"bytes_down"`
		HumanUp   string `json:"human_up"`
		HumanDown string `json:"human_down"`
	} `json:"traffic"`
	WS struct {
		Errors     int64 `json:"errors"`
		PoolHits   int64 `json:"pool_hits"`
		PoolMisses int64 `json:"pool_misses"`
	} `json:"ws"`
	StartedAt int64 `json:"started_at"`
}

func (s *Stats) snapshot() Snapshot {
	var out Snapshot
	out.Connections.Total = s.connectionsTotal.Load()
	out.Connections.Active = s.connectionsActive.Load()
	out.Connections.WS = s.connectionsWS.Load()
	out.Connections.TCPFallback = s.connectionsTCPFallback.Load()
	out.Connections.CFProxy = s.connectionsCFProxy.Load()
	out.Connections.Bad = s.connectionsBad.Load()
	out.Connections.Masked = s.connectionsMasked.Load()
	up, down := s.bytesUp.Load(), s.bytesDown.Load()
	out.Traffic.BytesUp = up
	out.Traffic.BytesDown = down
	out.Traffic.HumanUp = humanBytes(up)
	out.Traffic.HumanDown = humanBytes(down)
	out.WS.Errors = s.wsErrors.Load()
	out.WS.PoolHits = s.poolHits.Load()
	out.WS.PoolMisses = s.poolMisses.Load()
	out.StartedAt = s.startedAt.Load()
	return out
}

func (s *Stats) summary() string {
	pool := s.poolHits.Load() + s.poolMisses.Load()
	poolS := "n/a"
	if pool > 0 {
		poolS = fmt.Sprintf("%d/%d", s.poolHits.Load(), pool)
	}
	return fmt.Sprintf("total=%d active=%d ws=%d tcp_fb=%d cf=%d bad=%d masked=%d err=%d pool=%s up=%s down=%s",
		s.connectionsTotal.Load(), s.connectionsActive.Load(), s.connectionsWS.Load(),
		s.connectionsTCPFallback.Load(), s.connectionsCFProxy.Load(), s.connectionsBad.Load(),
		s.connectionsMasked.Load(), s.wsErrors.Load(), poolS,
		humanBytes(s.bytesUp.Load()), humanBytes(s.bytesDown.Load()))
}
