package app

import "nfqws2strategy/internal/tools/probe"

// List is a user-defined set of test targets plus strategies known to work.
type List struct {
	ID                   string          `json:"id"`
	Name                 string          `json:"name"`
	Domains              []string        `json:"domains"`
	IPs                  []string        `json:"ips"`
	BaseStrategyIDs      []string        `json:"base_strategy_ids"`
	SuccessfulStrategies []SavedStrategy `json:"successful_strategies"`
	TestURL              string          `json:"test_url,omitempty"` // optional override, else https://<domain>/
	CreatedAt            int64           `json:"created_at"`
	UpdatedAt            int64           `json:"updated_at"`
}

// SavedStrategy is a strategy that passed for a list, kept sorted by speed.
type SavedStrategy struct {
	StrategyID  string  `json:"strategy_id"`
	Name        string  `json:"name"`
	ArgLine     string  `json:"args"`
	DNS         string  `json:"dns,omitempty"`    // label of the DNS this best result used ("" = system)
	DNSID       string  `json:"dns_id,omitempty"` // server id of that DNS
	AvgTTFBms   int64   `json:"avg_ttfb_ms"`
	AvgSpeedBps int64   `json:"avg_speed_bps"`
	Coefficient float64 `json:"coefficient"`
	FoundAt     int64   `json:"found_at"`
	RunID       string  `json:"run_id"`
}

// Run captures a test run and its results.
type Run struct {
	ID         string           `json:"id"`
	ListID     string           `json:"list_id"`
	ListName   string           `json:"list_name"`
	Threads    int              `json:"threads"`
	Auto       bool             `json:"auto"`   // automatic strategy selection over the candidate catalog
	Status     string           `json:"status"` // running | done | cancelled | error
	Error      string           `json:"error,omitempty"`
	Total      int              `json:"total"` // strategies to test
	Done       int              `json:"done"`
	StartedAt  int64            `json:"started_at"`
	FinishedAt int64            `json:"finished_at,omitempty"`
	Targets    []string         `json:"targets"`
	Baseline   []TargetCheck    `json:"baseline,omitempty"` // no-bypass reachability of each target (auto runs)
	Results    []StrategyResult `json:"results"`
}

// BlockCheck captures a plain reachability check of a list's targets without any
// bypass: it tells the user which domains/IPs are actually DPI-blocked.
type BlockCheck struct {
	ID         string        `json:"id"`
	ListID     string        `json:"list_id"`
	ListName   string        `json:"list_name"`
	Threads    int           `json:"threads"`
	Status     string        `json:"status"` // running | done | cancelled | error
	Error      string        `json:"error,omitempty"`
	Total      int           `json:"total"`
	Done       int           `json:"done"`
	StartedAt  int64         `json:"started_at"`
	FinishedAt int64         `json:"finished_at,omitempty"`
	Targets    []TargetCheck `json:"targets"`
}

// TargetCheck is the no-bypass reachability verdict for one domain/IP.
type TargetCheck struct {
	Host     string `json:"host"`
	Blocked  bool   `json:"blocked"`
	Verdict  string `json:"verdict"` // ok | timeout | reset | refused | cap16k | dns | error
	Code     int    `json:"code"`
	Size     int64  `json:"size"`
	TTFBms   int64  `json:"ttfb_ms"`
	SpeedBps int64  `json:"speed_bps"`
	Err      string `json:"err,omitempty"`
}

// StrategyResult aggregates one strategy across all of a run's targets, for one
// DNS choice (a run tests each strategy through every selected DNS).
type StrategyResult struct {
	StrategyID   string         `json:"strategy_id"`
	Name         string         `json:"name"`
	ArgLine      string         `json:"args"`
	L7           string         `json:"l7"`
	DNS          string         `json:"dns,omitempty"`    // label of the DNS used ("" = system)
	DNSID        string         `json:"dns_id,omitempty"` // server id of the DNS used
	TargetsTotal int            `json:"targets_total"`
	TargetsOK    int            `json:"targets_ok"`
	AvgTTFBms    int64          `json:"avg_ttfb_ms"`
	AvgSpeedBps  int64          `json:"avg_speed_bps"`
	Coefficient  float64        `json:"coefficient"`
	Success      bool           `json:"success"`
	Error        string         `json:"error,omitempty"`
	PerTarget    []probe.Result `json:"per_target"`
}

// coefficient blends throughput (higher better) and latency (lower better) into
// a single sortable score: speed scaled down as latency grows.
func coefficient(avgSpeedBps, avgTTFBms int64) float64 {
	return float64(avgSpeedBps) * 1000.0 / (1000.0 + float64(avgTTFBms))
}
