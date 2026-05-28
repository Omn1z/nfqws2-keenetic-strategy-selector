package app

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"nfqws2strategy/internal/engine"
	"nfqws2strategy/internal/probe"
	"nfqws2strategy/internal/store"
)

// BlockCheckRequest starts a no-bypass reachability check. Targets come from a
// saved list (ListID) or, for an ad-hoc check, directly via Targets.
type BlockCheckRequest struct {
	ListID  string   `json:"list_id"`
	Targets []string `json:"targets"` // ad-hoc targets when ListID is empty
	Threads int      `json:"threads"`
}

// StartBlockCheck launches an asynchronous reachability check. It shares the
// "one operation at a time" guard with runs (both touch the mangle table).
func (a *App) StartBlockCheck(req BlockCheckRequest) (*BlockCheck, error) {
	var targets []string
	listName := "произвольный набор"
	if req.ListID != "" {
		list, err := a.GetList(req.ListID)
		if err != nil {
			return nil, fmt.Errorf("list not found")
		}
		listName = list.Name
		targets = append([]string{}, list.Domains...)
		targets = append(targets, list.IPs...)
	} else {
		targets = cleanLines(req.Targets)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets")
	}
	threads := req.Threads
	if threads <= 0 {
		threads = 4
	}
	if threads > maxThreads {
		threads = maxThreads
	}
	if threads > len(targets) {
		threads = len(targets)
	}

	a.mu.Lock()
	if a.active != nil || a.activeBC != nil {
		a.mu.Unlock()
		return nil, fmt.Errorf("a run is already in progress")
	}
	bc := &BlockCheck{
		ID:        store.NewID(),
		ListID:    req.ListID,
		ListName:  listName,
		Threads:   threads,
		Status:    "running",
		Total:     len(targets),
		StartedAt: time.Now().Unix(),
		Targets:   make([]TargetCheck, 0, len(targets)),
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.activeBC = bc
	a.cancelBC = cancel
	a.mu.Unlock()

	go a.executeBlockCheck(ctx, bc, targets, threads)
	return bc, nil
}

func (a *App) executeBlockCheck(ctx context.Context, bc *BlockCheck, targets []string, threads int) {
	defer func() {
		a.mu.Lock()
		a.activeBC = nil
		a.cancelBC = nil
		if bc.Status == "running" {
			bc.Status = "done"
		}
		bc.FinishedAt = time.Now().Unix()
		a.lastBC = bc
		a.mu.Unlock()
	}()

	// One exclude-only sandbox per worker: the test connection is marked so the
	// main nfqws service skips it, but nothing desyncs it — a true baseline.
	sandboxes := make([]*engine.Sandbox, threads)
	for w := 0; w < threads; w++ {
		sb := engine.NewSandbox(a.Cfg, w)
		if err := sb.RulesUpExcludeOnly(); err != nil {
			a.mu.Lock()
			bc.Status = "error"
			bc.Error = fmt.Sprintf("worker %d rules: %v", w, err)
			a.mu.Unlock()
			for k := 0; k < w; k++ {
				sandboxes[k].RulesDown()
			}
			return
		}
		sandboxes[w] = sb
	}
	defer func() {
		for _, sb := range sandboxes {
			sb.RulesDown()
		}
	}()

	jobs := make(chan string)
	var done int32
	var wg sync.WaitGroup
	for w := 0; w < threads; w++ {
		wg.Add(1)
		go func(sb *engine.Sandbox) {
			defer wg.Done()
			pr := probe.New(sb.PortLo, sb.PortHi)
			for host := range jobs {
				if ctx.Err() != nil {
					return
				}
				tc := classifyProbe(host, pr.Probe(ctx, host))
				n := atomic.AddInt32(&done, 1)
				a.mu.Lock()
				bc.Targets = append(bc.Targets, tc)
				bc.Done = int(n)
				a.mu.Unlock()
			}
		}(sandboxes[w])
	}

	for _, t := range targets {
		select {
		case <-ctx.Done():
			goto wait
		case jobs <- t:
		}
	}
wait:
	close(jobs)
	wg.Wait()

	a.mu.Lock()
	if ctx.Err() != nil {
		bc.Status = "cancelled"
	}
	sort.SliceStable(bc.Targets, func(i, j int) bool {
		if bc.Targets[i].Blocked != bc.Targets[j].Blocked {
			return bc.Targets[i].Blocked // blocked first
		}
		return bc.Targets[i].Host < bc.Targets[j].Host
	})
	a.mu.Unlock()
}

func (a *App) CancelBlockCheck(id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.activeBC != nil && a.activeBC.ID == id && a.cancelBC != nil {
		a.cancelBC()
		return nil
	}
	return fmt.Errorf("block check not active")
}

// GetBlockCheck returns a race-safe snapshot of the active or last-finished check.
func (a *App) GetBlockCheck(id string) (*BlockCheck, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var bc *BlockCheck
	switch {
	case a.activeBC != nil && a.activeBC.ID == id:
		bc = a.activeBC
	case a.lastBC != nil && a.lastBC.ID == id:
		bc = a.lastBC
	default:
		return nil, false
	}
	cp := *bc
	cp.Targets = append([]TargetCheck(nil), bc.Targets...)
	return &cp, true
}
