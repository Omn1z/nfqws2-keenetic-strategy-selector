package app

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nfqws2strategy/internal/catalog"
	"nfqws2strategy/internal/engine"
	"nfqws2strategy/internal/probe"
	"nfqws2strategy/internal/store"
)

const maxThreads = 8

// RunRequest describes a test run to start.
type RunRequest struct {
	ListID      string   `json:"list_id"`
	StrategyIDs []string `json:"strategy_ids"` // empty = all known strategies
	Threads     int      `json:"threads"`
	IncludeIPs  bool     `json:"include_ips"`
}

func (a *App) loadRuns() {
	names, _ := a.store.ListFiles("runs")
	for _, n := range names {
		if !strings.HasSuffix(n, ".json") {
			continue
		}
		var r Run
		if err := a.store.Load(filepath.Join("runs", n), &r); err == nil {
			if r.Status == "running" { // crashed mid-run
				r.Status = "error"
				r.Error = "interrupted"
			}
			a.runs[r.ID] = &r
			a.runOrder = append(a.runOrder, r.ID)
		}
	}
	sort.Slice(a.runOrder, func(i, j int) bool {
		return a.runs[a.runOrder[i]].StartedAt < a.runs[a.runOrder[j]].StartedAt
	})
}

// Runs returns runs newest-first.
func (a *App) Runs() []*Run {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]*Run, 0, len(a.runOrder))
	for i := len(a.runOrder) - 1; i >= 0; i-- {
		out = append(out, a.runs[a.runOrder[i]])
	}
	return out
}

func (a *App) GetRun(id string) (*Run, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	r, ok := a.runs[id]
	return r, ok
}

func (a *App) ActiveRun() *Run {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.active
}

// CancelRun cancels the active run if its id matches.
func (a *App) CancelRun(id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.active != nil && a.active.ID == id && a.cancel != nil {
		a.cancel()
		return nil
	}
	return fmt.Errorf("run not active")
}

// StartRun validates and launches a run asynchronously.
func (a *App) StartRun(req RunRequest) (*Run, error) {
	list, err := a.GetList(req.ListID)
	if err != nil {
		return nil, fmt.Errorf("list not found")
	}
	targets := append([]string{}, list.Domains...)
	if req.IncludeIPs {
		targets = append(targets, list.IPs...)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("list has no targets")
	}

	all := a.Strategies()
	var strategies []catalog.Strategy
	if len(req.StrategyIDs) == 0 {
		strategies = all
	} else {
		want := map[string]bool{}
		for _, id := range req.StrategyIDs {
			want[id] = true
		}
		for _, s := range all {
			if want[s.ID] {
				strategies = append(strategies, s)
			}
		}
	}
	if len(strategies) == 0 {
		return nil, fmt.Errorf("no strategies selected")
	}

	threads := req.Threads
	if threads <= 0 {
		threads = 4
	}
	if threads > maxThreads {
		threads = maxThreads
	}
	if threads > len(strategies) {
		threads = len(strategies)
	}

	a.mu.Lock()
	if a.active != nil {
		a.mu.Unlock()
		return nil, fmt.Errorf("a run is already in progress")
	}
	run := &Run{
		ID:        store.NewID(),
		ListID:    list.ID,
		ListName:  list.Name,
		Threads:   threads,
		Status:    "running",
		Total:     len(strategies),
		StartedAt: time.Now().Unix(),
		Targets:   targets,
		Results:   make([]StrategyResult, 0, len(strategies)),
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.active = run
	a.cancel = cancel
	a.runs[run.ID] = run
	a.runOrder = append(a.runOrder, run.ID)
	a.trimRunsLocked()
	a.mu.Unlock()

	go a.executeRun(ctx, run, list, strategies, threads, targets)
	return run, nil
}

func (a *App) executeRun(ctx context.Context, run *Run, list *List, strategies []catalog.Strategy, threads int, targets []string) {
	defer func() {
		a.mu.Lock()
		a.active = nil
		a.cancel = nil
		if run.Status == "running" {
			run.Status = "done"
		}
		run.FinishedAt = time.Now().Unix()
		a.mu.Unlock()
		_ = a.saveRun(run)
	}()

	// Build sandboxes (one per worker) and bring up their iptables rules.
	sandboxes := make([]*engine.Sandbox, threads)
	for w := 0; w < threads; w++ {
		sb := engine.NewSandbox(a.Cfg, w)
		if err := sb.RulesUp(); err != nil {
			a.failRun(run, fmt.Sprintf("worker %d rules: %v", w, err))
			for k := 0; k < w; k++ {
				sandboxes[k].RulesDown()
			}
			return
		}
		sandboxes[w] = sb
	}
	defer func() {
		for _, sb := range sandboxes {
			sb.StopNfqws()
			sb.RulesDown()
		}
	}()

	results := make([]StrategyResult, len(strategies))
	jobs := make(chan int)
	var done int32
	var wg sync.WaitGroup

	for w := 0; w < threads; w++ {
		wg.Add(1)
		go func(sb *engine.Sandbox) {
			defer wg.Done()
			pr := probe.New(sb.PortLo, sb.PortHi)
			for idx := range jobs {
				if ctx.Err() != nil {
					return
				}
				results[idx] = a.testStrategy(ctx, sb, pr, strategies[idx], targets)
				n := atomic.AddInt32(&done, 1)
				a.mu.Lock()
				run.Done = int(n)
				a.mu.Unlock()
			}
		}(sandboxes[w])
	}

	for i := range strategies {
		select {
		case <-ctx.Done():
			goto wait
		case jobs <- i:
		}
	}
wait:
	close(jobs)
	wg.Wait()

	// Collect results that were actually computed.
	final := make([]StrategyResult, 0, len(results))
	for _, r := range results {
		if r.StrategyID != "" {
			final = append(final, r)
		}
	}
	sortResults(final)

	a.mu.Lock()
	run.Results = final
	if ctx.Err() != nil {
		run.Status = "cancelled"
	}
	a.mu.Unlock()

	a.mergeSuccessful(list, run, final)
}

func (a *App) testStrategy(ctx context.Context, sb *engine.Sandbox, pr *probe.Prober, s catalog.Strategy, targets []string) StrategyResult {
	res := StrategyResult{StrategyID: s.ID, Name: s.Name, ArgLine: s.ArgLine, L7: s.L7, TargetsTotal: len(targets)}
	if err := sb.StartNfqws(s.Args()); err != nil {
		res.Error = firstLine(err.Error())
		return res
	}
	defer sb.StopNfqws()

	// Probe targets concurrently within this worker (distinct source ports), so a
	// failing strategy doesn't accumulate per-target timeouts.
	perTarget := make([]probe.Result, len(targets))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, t := range targets {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(i int, t string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			perTarget[i] = pr.Probe(t)
		}(i, t)
	}
	wg.Wait()

	var sumTTFB, sumSpeed int64
	for _, pres := range perTarget {
		if pres.Host == "" {
			continue // not probed (cancelled)
		}
		res.PerTarget = append(res.PerTarget, pres)
		if pres.OK {
			res.TargetsOK++
			sumTTFB += pres.TTFBms
			sumSpeed += pres.SpeedBps
		}
	}
	if res.TargetsOK > 0 {
		res.AvgTTFBms = sumTTFB / int64(res.TargetsOK)
		res.AvgSpeedBps = sumSpeed / int64(res.TargetsOK)
		res.Coefficient = coefficient(res.AvgSpeedBps, res.AvgTTFBms)
	}
	res.Success = res.TargetsOK == res.TargetsTotal && res.TargetsTotal > 0
	return res
}

// mergeSuccessful merges this run's successful strategies into the list, keeping
// the best coefficient per strategy and sorting by speed.
func (a *App) mergeSuccessful(list *List, run *Run, results []StrategyResult) {
	cur, err := a.GetList(list.ID)
	if err != nil {
		return
	}
	byID := map[string]SavedStrategy{}
	for _, s := range cur.SuccessfulStrategies {
		byID[s.StrategyID] = s
	}
	now := time.Now().Unix()
	for _, r := range results {
		if !r.Success {
			continue
		}
		prev, ok := byID[r.StrategyID]
		if !ok || r.Coefficient > prev.Coefficient {
			byID[r.StrategyID] = SavedStrategy{
				StrategyID: r.StrategyID, Name: r.Name, ArgLine: r.ArgLine,
				AvgTTFBms: r.AvgTTFBms, AvgSpeedBps: r.AvgSpeedBps, Coefficient: r.Coefficient,
				FoundAt: now, RunID: run.ID,
			}
		}
	}
	merged := make([]SavedStrategy, 0, len(byID))
	for _, s := range byID {
		merged = append(merged, s)
	}
	sort.Slice(merged, func(i, j int) bool { return merged[i].Coefficient > merged[j].Coefficient })
	cur.SuccessfulStrategies = merged
	_, _ = a.SaveList(cur)
}

func (a *App) failRun(run *Run, msg string) {
	a.mu.Lock()
	run.Status = "error"
	run.Error = msg
	a.mu.Unlock()
}

func (a *App) saveRun(run *Run) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.store.Save(filepath.Join("runs", run.ID+".json"), run)
}

func (a *App) trimRunsLocked() {
	for len(a.runOrder) > maxStoredRuns {
		oldest := a.runOrder[0]
		a.runOrder = a.runOrder[1:]
		delete(a.runs, oldest)
		_ = a.store.Delete(filepath.Join("runs", oldest+".json"))
	}
}

// sortResults orders by success first, then coefficient desc.
func sortResults(rs []StrategyResult) {
	sort.SliceStable(rs, func(i, j int) bool {
		if rs[i].Success != rs[j].Success {
			return rs[i].Success
		}
		return rs[i].Coefficient > rs[j].Coefficient
	})
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
