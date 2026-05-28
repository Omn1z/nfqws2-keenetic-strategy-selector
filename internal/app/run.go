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
	"nfqws2strategy/internal/dns"
	"nfqws2strategy/internal/engine"
	"nfqws2strategy/internal/probe"
	"nfqws2strategy/internal/store"
)

const maxThreads = 8

// RunRequest describes a test run to start. The targets come either from a saved
// list (ListID) or, for an ad-hoc run, directly via Targets (geo category or
// pasted text); successful strategies are only persisted when a list is used.
type RunRequest struct {
	ListID      string   `json:"list_id"`
	Targets     []string `json:"targets"` // ad-hoc targets when ListID is empty
	StrategyIDs []string `json:"strategy_ids"` // empty = all known strategies
	Threads     int      `json:"threads"`
	Auto        bool     `json:"auto"`  // automatic selection over the candidate catalog
	Blobs       []string `json:"blobs"` // each selected blob is tested as the fake payload (own pass)
	DNS         []string `json:"dns"`   // server ids to resolve targets through; each is its own pass ("" = system)
}

// runJob is one unit of work: a strategy variant tested through one DNS choice
// (nil = the system resolver). A run is the cross product of strategies and the
// selected DNS servers.
type runJob struct {
	strat catalog.Strategy
	dns   *dns.Server
}

// dnsLabel is the (id, display name) for a DNS choice; nil = the system resolver.
func dnsLabel(d *dns.Server) (id, name string) {
	if d == nil {
		return "", "Системный"
	}
	return d.ID, d.Name
}

// runDNSChoices maps selected server ids to DNS choices. Empty selection (or an
// unknown id list) means a single system-resolver pass. "system"/"" select the
// system resolver as an explicit comparison row.
func (a *App) runDNSChoices(ids []string) []*dns.Server {
	if len(ids) == 0 {
		return []*dns.Server{nil}
	}
	servers := a.DNSServers()
	byID := make(map[string]dns.Server, len(servers))
	for _, s := range servers {
		byID[s.ID] = s
	}
	var out []*dns.Server
	for _, id := range ids {
		if id == "" || id == "system" {
			out = append(out, nil)
			continue
		}
		if s, ok := byID[id]; ok {
			c := s
			out = append(out, &c)
		}
	}
	if len(out) == 0 {
		out = []*dns.Server{nil}
	}
	return out
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
	if !ok {
		return nil, false
	}
	// Snapshot under the lock: workers append to the live run concurrently, so the
	// caller must not encode the original slices.
	cp := *r
	cp.Results = append([]StrategyResult(nil), r.Results...)
	cp.Baseline = append([]TargetCheck(nil), r.Baseline...)
	return &cp, true
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

// AddRunThreads raises the active run's worker count to threads (capped at
// maxThreads) while it's in progress. Returns the resulting worker count.
func (a *App) AddRunThreads(id string, threads int) (int, error) {
	a.mu.Lock()
	if a.active == nil || a.active.ID != id {
		a.mu.Unlock()
		return 0, fmt.Errorf("run not active")
	}
	cur := a.active.Threads
	add := a.addWorker
	if add == nil {
		// The worker pool isn't up yet (auto baseline phase); remember the target
		// and apply it the moment the pool starts.
		a.pendingThreads = threads
		a.mu.Unlock()
		return threads, nil
	}
	a.mu.Unlock()
	add(threads)
	a.mu.Lock()
	if a.active != nil {
		cur = a.active.Threads
	}
	a.mu.Unlock()
	return cur, nil
}

// StartRun validates and launches a run asynchronously.
func (a *App) StartRun(req RunRequest) (*Run, error) {
	var list *List
	var targets []string
	listName := "произвольный набор"
	if req.ListID != "" {
		l, err := a.GetList(req.ListID)
		if err != nil {
			return nil, fmt.Errorf("list not found")
		}
		list, listName = l, l.Name
		targets = append([]string{}, l.Domains...)
		targets = append(targets, l.IPs...)
	} else {
		targets = cleanLines(req.Targets)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets")
	}

	var strategies []catalog.Strategy
	if req.Auto {
		strategies = catalog.AutoCandidates()
	} else {
		all := a.Strategies()
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
	}
	// Expand across selected blobs: each blob is tested as the fake payload.
	strategies = a.buildRunStrategies(strategies, req.Blobs)
	if len(strategies) == 0 {
		return nil, fmt.Errorf("no strategies selected")
	}

	// Cross with the selected DNS servers: each strategy is tested through every
	// DNS choice (empty selection = one system-resolver pass).
	choices := a.runDNSChoices(req.DNS)
	plan := make([]runJob, 0, len(strategies)*len(choices))
	for _, s := range strategies {
		for _, d := range choices {
			plan = append(plan, runJob{strat: s, dns: d})
		}
	}

	threads := req.Threads
	if threads <= 0 {
		threads = 4
	}
	if threads > maxThreads {
		threads = maxThreads
	}
	if threads > len(plan) {
		threads = len(plan)
	}

	a.mu.Lock()
	if a.active != nil || a.activeBC != nil {
		a.mu.Unlock()
		return nil, fmt.Errorf("a run is already in progress")
	}
	run := &Run{
		ID:        store.NewID(),
		ListID:    req.ListID,
		ListName:  listName,
		Threads:   threads,
		Auto:      req.Auto,
		Status:    "running",
		Total:     len(plan),
		StartedAt: time.Now().Unix(),
		Targets:   targets,
		Results:   make([]StrategyResult, 0, len(plan)),
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.active = run
	a.cancel = cancel
	a.pendingThreads = 0
	a.runs[run.ID] = run
	a.runOrder = append(a.runOrder, run.ID)
	a.trimRunsLocked()
	a.mu.Unlock()

	go a.executeRun(ctx, run, list, plan, threads, targets)
	return run, nil
}

func (a *App) executeRun(ctx context.Context, run *Run, list *List, plan []runJob, threads int, targets []string) {
	resolver := dns.NewResolver()
	defer func() {
		a.mu.Lock()
		a.active = nil
		a.cancel = nil
		a.addWorker = nil
		if run.Status == "running" {
			run.Status = "done"
		}
		run.FinishedAt = time.Now().Unix()
		a.mu.Unlock()
		_ = a.saveRun(run)
	}()

	testTargets := targets
	if run.Auto {
		// Baseline: probe each target with NO bypass at all (exclude-only sandbox,
		// so the running main nfqws service skips it and nothing desyncs it). This
		// reveals what's truly blocked; we then test candidates only on those.
		bsb := engine.NewSandbox(a.Cfg, threads)
		if err := bsb.RulesUpExcludeOnly(); err != nil {
			a.failRun(run, fmt.Sprintf("baseline rules: %v", err))
			return
		}
		base := baselineCheck(ctx, probe.New(bsb.PortLo, bsb.PortHi), targets)
		bsb.RulesDown()
		a.mu.Lock()
		run.Baseline = base
		a.mu.Unlock()
		if ctx.Err() != nil {
			return
		}
		var blocked []string
		for _, tc := range base {
			if tc.Blocked {
				blocked = append(blocked, tc.Host)
			}
		}
		if len(blocked) == 0 {
			a.mu.Lock()
			run.Total = 0 // nothing blocked without bypass — no strategy needed
			a.mu.Unlock()
			return
		}
		testTargets = blocked
	}

	// Dynamic worker pool: workers can be added mid-run (AddRunThreads) to speed
	// things up. Each worker owns one sandbox (queue + port range + iptables).
	jobs := make(chan int)
	var done int32
	var wg sync.WaitGroup
	var smu sync.Mutex
	var sandboxes []*engine.Sandbox
	started := 0
	feeding := true

	defer func() {
		smu.Lock()
		sbs := append([]*engine.Sandbox(nil), sandboxes...)
		smu.Unlock()
		for _, sb := range sbs {
			sb.StopNfqws()
			sb.RulesDown()
		}
	}()

	worker := func(sb *engine.Sandbox) {
		defer wg.Done()
		pr := probe.New(sb.PortLo, sb.PortHi)
		for idx := range jobs {
			if ctx.Err() != nil {
				return
			}
			res := a.testStrategy(ctx, sb, pr, plan[idx], testTargets, resolver)
			n := atomic.AddInt32(&done, 1)
			// Append live so the UI fills the results table as each strategy completes.
			a.mu.Lock()
			run.Results = append(run.Results, res)
			run.Done = int(n)
			a.mu.Unlock()
		}
	}
	// startWorker brings up one more worker if we're still feeding jobs and under
	// the cap. wg.Add happens under smu, before feeding is cleared, so Wait is safe.
	startWorker := func() bool {
		smu.Lock()
		if !feeding || started >= maxThreads {
			smu.Unlock()
			return false
		}
		w := started
		started++
		wg.Add(1)
		smu.Unlock()
		sb := engine.NewSandbox(a.Cfg, w)
		if err := sb.RulesUp(); err != nil {
			wg.Done()
			return false
		}
		smu.Lock()
		sandboxes = append(sandboxes, sb)
		smu.Unlock()
		go worker(sb)
		return true
	}

	for i := 0; i < threads; i++ {
		startWorker()
	}
	smu.Lock()
	live := started
	smu.Unlock()
	if live == 0 {
		a.failRun(run, "could not start any worker")
		return
	}
	a.mu.Lock()
	run.Threads = live
	a.addWorker = func(target int) {
		if target > maxThreads {
			target = maxThreads
		}
		for {
			smu.Lock()
			cur := started
			smu.Unlock()
			if cur >= target || !startWorker() {
				break
			}
		}
		smu.Lock()
		cur := started
		smu.Unlock()
		a.mu.Lock()
		run.Threads = cur
		a.mu.Unlock()
	}
	pend := a.pendingThreads // a +threads requested during the baseline phase
	a.pendingThreads = 0
	add := a.addWorker
	a.mu.Unlock()
	if pend > live {
		add(pend)
	}

	for i := range plan {
		select {
		case <-ctx.Done():
			goto wait
		case jobs <- i:
		}
	}
wait:
	smu.Lock()
	feeding = false
	smu.Unlock()
	a.mu.Lock()
	a.addWorker = nil
	a.mu.Unlock()
	close(jobs)
	wg.Wait()

	a.mu.Lock()
	sortResults(run.Results)
	if ctx.Err() != nil {
		run.Status = "cancelled"
	}
	final := append([]StrategyResult{}, run.Results...)
	a.mu.Unlock()

	if list != nil { // ad-hoc runs have no list to persist into
		a.mergeSuccessful(list, run, final)
	}
}

// baselineCheck probes each target with no bypass and classifies reachability.
func baselineCheck(ctx context.Context, pr *probe.Prober, targets []string) []TargetCheck {
	out := make([]TargetCheck, len(targets))
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
			out[i] = classifyProbe(t, pr.Probe(ctx, t))
		}(i, t)
	}
	wg.Wait()
	res := make([]TargetCheck, 0, len(out))
	for _, tc := range out {
		if tc.Host != "" {
			res = append(res, tc)
		}
	}
	return res
}

// classifyProbe turns a raw probe result into a no-bypass reachability verdict.
// The 16 KB truncation (the cap this whole tool targets), connection resets and
// timeouts are the block signals; an HTTP response that isn't cut means reachable.
func classifyProbe(host string, r probe.Result) TargetCheck {
	tc := TargetCheck{Host: host, Code: r.Code, Size: r.Size, TTFBms: r.TTFBms, SpeedBps: r.SpeedBps, Err: r.Err}
	switch {
	case r.Truncated:
		tc.Verdict, tc.Blocked = "cap16k", true
	case r.Code != 0:
		tc.Verdict, tc.Blocked = "ok", false
	default:
		e := strings.ToLower(r.Err)
		switch {
		case strings.Contains(e, "no such host"), strings.Contains(e, "lookup"), strings.Contains(e, "server misbehaving"):
			tc.Verdict = "dns"
		case strings.Contains(e, "reset"), strings.Contains(e, "forcibly closed"):
			tc.Verdict = "reset"
		case strings.Contains(e, "refused"):
			tc.Verdict = "refused"
		case strings.Contains(e, "timeout"), strings.Contains(e, "deadline"):
			tc.Verdict = "timeout"
		default:
			tc.Verdict = "error"
		}
		tc.Blocked = true
	}
	return tc
}

func (a *App) testStrategy(ctx context.Context, sb *engine.Sandbox, pr *probe.Prober, job runJob, targets []string, resolver *dns.Resolver) StrategyResult {
	s := job.strat
	dnsID, dnsName := dnsLabel(job.dns)
	res := StrategyResult{StrategyID: s.ID, Name: s.Name, ArgLine: s.ArgLine, L7: s.L7, DNS: dnsName, DNSID: dnsID, TargetsTotal: len(targets)}
	// Resolve targets through this job's DNS (nil = system resolver). The worker
	// runs one job at a time, so mutating the shared prober here is safe.
	if job.dns != nil {
		srv := *job.dns
		pr.Resolve = func(ctx context.Context, host string) (string, error) {
			return resolver.Resolve(ctx, srv, host)
		}
	} else {
		pr.Resolve = nil
	}
	if err := sb.StartNfqws(nil, s.Args()); err != nil {
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
			perTarget[i] = pr.Probe(ctx, t)
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
				DNS: r.DNS, DNSID: r.DNSID,
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
