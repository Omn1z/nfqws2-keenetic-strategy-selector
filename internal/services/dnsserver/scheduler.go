package dnsserver

import (
	"math"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"nfqws2strategy/internal/services/dnsroute"
)

const (
	maxSchedulerPairs   = 2048
	schedulerStaleAfter = 5 * time.Minute
)

const schedulerFormula = "Больше очков — раньше запуск: 100 × надёжность − min(80, задержка EWMA / 20) − min(100, 20 × ошибок подряд). До первого результата: надёжность 50%, задержка 500 мс. Первый результат задаёт надёжность 100% при успехе или 0% при ошибке; первый успешный ответ задаёт задержку. Последующие замеры обновляют значения как 80% предыдущего + 20% нового. Отмена нейтральна и не считается замером. Фоновая проверка запускается не чаще раза в 5 секунд, по одному варианту, и получает собственный результат независимо от победителя обычного запроса. Сначала проверяются варианты без результата, затем давно не измерявшиеся (от 60 секунд, с учётом очереди). Каждая 8-я гонка также даёт первый слот давно не измерявшемуся варианту. Если замеров не было 5 минут, новый результат задаёт свежую оценку без старого штрафа."

// AttemptEvent describes one actual network attempt, including provider
// bootstrap. Cancellation after a competing answer is neutral evidence.
type AttemptEvent struct {
	Domain     string `json:"domain"`
	Type       string `json:"type"`
	Route      string `json:"route"`
	RouteName  string `json:"route_name"`
	Upstream   string `json:"upstream"`
	DurationMS int64  `json:"duration_ms"`
	Success    bool   `json:"success"`
	Canceled   bool   `json:"canceled"`
	Error      string `json:"error,omitempty"`
}

type SchedulerCandidate struct {
	Position            int     `json:"position"`
	Route               string  `json:"route"`
	RouteName           string  `json:"route_name"`
	Upstream            string  `json:"upstream"`
	Available           bool    `json:"available"`
	Disabled            bool    `json:"disabled"`
	Score               float64 `json:"score"`
	Reliability         float64 `json:"reliability"`
	LatencyMS           float64 `json:"latency_ms"`
	LatencyPenalty      float64 `json:"latency_penalty"`
	FailurePenalty      float64 `json:"failure_penalty"`
	Attempts            uint64  `json:"attempts"`
	Successes           uint64  `json:"successes"`
	Failures            uint64  `json:"failures"`
	ConsecutiveFailures uint64  `json:"consecutive_failures"`
	LastError           string  `json:"last_error"`
	LastAttemptAt       string  `json:"last_attempt_at"`
	LastResultAt        string  `json:"last_result_at"`
	LastProbeAt         string  `json:"last_probe_at"`
	Probing             bool    `json:"probing"`
	ProbeAttempts       uint64  `json:"probe_attempts"`
	ProbeSuccesses      uint64  `json:"probe_successes"`
	ProbeFailures       uint64  `json:"probe_failures"`
	Exploration         bool    `json:"exploration"`
}

type SchedulerSnapshot struct {
	Domain               string               `json:"domain"`
	PoolSource           string               `json:"pool_source"`
	Formula              string               `json:"formula"`
	ParallelLimit        int                  `json:"parallel_limit"`
	TrackedPairs         int                  `json:"tracked_pairs"`
	ActiveProbes         int                  `json:"active_probes"`
	ProbeIntervalSeconds int                  `json:"probe_interval_seconds"`
	ProbeRecheckSeconds  int                  `json:"probe_recheck_seconds"`
	Candidates           []SchedulerCandidate `json:"candidates"`
}

type schedulerEntry struct {
	reliability, latency                               float64
	attempts, successes, failures, consecutiveFailures uint64
	lastError                                          string
	lastAttempt, touched                               time.Time
	lastResult, lastProbe                              time.Time
	probing                                            bool
	probeAttempts, probeSuccesses, probeFailures       uint64
}

type attemptCandidate struct {
	route      dnsroute.Route
	upstream   Upstream
	view       SchedulerCandidate
	lastResult time.Time
}

// Scheduler belongs to the service, so saving DNS settings can replace its
// resolver without erasing observations. It keeps no DNS names or answers.
type Scheduler struct {
	mu          sync.Mutex
	entries     map[string]*schedulerEntry
	races       uint64
	now         func() time.Time
	probeKey    string
	probeToken  uint64
	probeCursor int
	lastProbe   time.Time
}

func NewScheduler() *Scheduler {
	return &Scheduler{entries: make(map[string]*schedulerEntry), now: time.Now}
}

func schedulerKey(route, upstream string) string { return route + "|" + upstream }

func (s *Scheduler) entryLocked(key string, now time.Time) *schedulerEntry {
	e := s.entries[key]
	if e == nil {
		if len(s.entries) >= maxSchedulerPairs {
			var oldest string
			var earliest time.Time
			for k, entry := range s.entries {
				if entry.probing {
					continue
				}
				if earliest.IsZero() || entry.touched.Before(earliest) {
					oldest, earliest = k, entry.touched
				}
			}
			delete(s.entries, oldest)
		}
		e = &schedulerEntry{reliability: .5, latency: 500}
		s.entries[key] = e
	}
	e.touched = now
	return e
}

func (s *Scheduler) started(route, upstream string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	e := s.entryLocked(schedulerKey(route, upstream), now)
	e.attempts++
	e.lastAttempt = now
}

func (s *Scheduler) record(event AttemptEvent) {
	if event.Canceled {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recordLocked(event, s.now())
}

func (s *Scheduler) recordLocked(event AttemptEvent, now time.Time) {
	e := s.entryLocked(schedulerKey(event.Route, event.Upstream), now)
	stale := !e.lastResult.IsZero() && now.Sub(e.lastResult) >= schedulerStaleAfter
	first := e.successes+e.failures == 0 || stale
	if stale {
		e.reliability, e.latency, e.consecutiveFailures = .5, 500, 0
	}
	e.lastResult = now
	if event.Success {
		if e.successes == 0 || stale {
			e.latency = float64(event.DurationMS)
		} else {
			e.latency = .8*e.latency + .2*float64(event.DurationMS)
		}
		e.reliability = .8*e.reliability + .2
		if first {
			e.reliability = 1
		}
		e.successes++
		e.consecutiveFailures = 0
		e.lastError = ""
	} else {
		e.reliability *= .8
		if first {
			e.reliability = 0
		}
		e.failures++
		e.consecutiveFailures++
		e.lastError = event.Error
		if len(e.lastError) > 512 {
			e.lastError = e.lastError[:512]
			for !utf8.ValidString(e.lastError) {
				e.lastError = e.lastError[:len(e.lastError)-1]
			}
		}
	}
}

func eligibleRoutes(cfg Config, routes []dnsroute.Route) []dnsroute.Route {
	result := make([]dnsroute.Route, 0, len(routes))
	seen := make(map[string]bool, len(routes))
	for _, route := range routes {
		allowed := route.ID == "nfqws" || strings.HasPrefix(route.ID, "awg:") && cfg.AWGFallback != "off" && (cfg.AWGFallback == "auto" || route.ID == "awg:"+cfg.AWGFallback)
		if allowed && !seen[route.ID] {
			seen[route.ID] = true
			result = append(result, route)
		}
	}
	return result
}

func rounded(v float64) float64 { return math.Round(v*100) / 100 }

func (s *Scheduler) orderedLocked(cfg Config, routes []dnsroute.Route, domain string, advance bool) ([]attemptCandidate, string) {
	pool, source := cfg.upstreamsFor(domain)
	eligible := eligibleRoutes(cfg, routes)
	disabled := disabledMethodSet(cfg.DisabledMethods)
	result := make([]attemptCandidate, 0, len(pool)*len(eligible))
	for _, upstream := range pool {
		for _, route := range eligible {
			e := s.entries[schedulerKey(route.ID, upstream.Address)]
			if e == nil {
				e = &schedulerEntry{reliability: .5, latency: 500}
			}
			latencyPenalty := math.Min(80, e.latency/20)
			failurePenalty := math.Min(100, float64(e.consecutiveFailures)*20)
			view := SchedulerCandidate{Route: route.ID, RouteName: route.Name, Upstream: upstream.Address, Available: route.Available,
				Disabled: disabled[schedulerKey(route.ID, upstream.Address)],
				Score:    rounded(100*e.reliability - latencyPenalty - failurePenalty), Reliability: e.reliability, LatencyMS: rounded(e.latency), LatencyPenalty: rounded(latencyPenalty), FailurePenalty: failurePenalty,
				Attempts: e.attempts, Successes: e.successes, Failures: e.failures, ConsecutiveFailures: e.consecutiveFailures, LastError: e.lastError}
			view.Probing, view.ProbeAttempts, view.ProbeSuccesses, view.ProbeFailures = e.probing, e.probeAttempts, e.probeSuccesses, e.probeFailures
			if view.Disabled {
				view.Probing = false
			}
			if !route.Available {
				view.LastError = route.Error
			}
			if !e.lastAttempt.IsZero() {
				view.LastAttemptAt = e.lastAttempt.UTC().Format(time.RFC3339Nano)
			}
			if !e.lastResult.IsZero() {
				view.LastResultAt = e.lastResult.UTC().Format(time.RFC3339Nano)
			}
			if !e.lastProbe.IsZero() {
				view.LastProbeAt = e.lastProbe.UTC().Format(time.RFC3339Nano)
			}
			result = append(result, attemptCandidate{route: route, upstream: upstream, view: view, lastResult: e.lastResult})
		}
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].view.Disabled != result[j].view.Disabled {
			return !result[i].view.Disabled
		}
		if result[i].route.Available != result[j].route.Available {
			return result[i].route.Available
		}
		return result[i].view.Score > result[j].view.Score
	})
	available := 0
	for available < len(result) && result[available].route.Available && !result[available].view.Disabled {
		available++
	}
	// A continually canceled low-ranked pair must eventually get a chance to
	// demonstrate recovery, including when other requests occupy shared slots.
	nextRace := s.races + 1
	if advance {
		s.races = nextRace
	}
	if available > 1 && nextRace%8 == 0 {
		oldest := 0
		for i := 1; i < available; i++ {
			if result[i].lastResult.Before(result[oldest].lastResult) {
				oldest = i
			}
		}
		candidate := result[oldest]
		candidate.view.Exploration = true
		copy(result[1:oldest+1], result[:oldest])
		result[0] = candidate
	}
	for i := range result {
		if !result[i].view.Disabled {
			result[i].view.Position = i + 1
		}
	}
	return result, source
}

func (s *Scheduler) order(cfg Config, routes []dnsroute.Route, domain string) []attemptCandidate {
	s.mu.Lock()
	defer s.mu.Unlock()
	ordered, _ := s.orderedLocked(cfg, routes, domain, true)
	available := 0
	for available < len(ordered) && ordered[available].route.Available && !ordered[available].view.Disabled {
		available++
	}
	return ordered[:available]
}

func (s *Scheduler) Snapshot(cfg Config, routes []dnsroute.Route, domain string) SchedulerSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	ordered, source := s.orderedLocked(cfg, routes, domain, false)
	result := SchedulerSnapshot{Domain: domain, PoolSource: source, Formula: schedulerFormula, ParallelLimit: maxConcurrentRouteAttempts, TrackedPairs: len(s.entries), Candidates: make([]SchedulerCandidate, 0, len(ordered))}
	result.ProbeIntervalSeconds, result.ProbeRecheckSeconds = int(schedulerProbeInterval/time.Second), int(schedulerProbeRecheck/time.Second)
	if s.probeKey != "" {
		result.ActiveProbes = 1
	}
	for _, candidate := range ordered {
		result.Candidates = append(result.Candidates, candidate.view)
	}
	return result
}
