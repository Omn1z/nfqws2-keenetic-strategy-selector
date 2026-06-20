package app

// Hands-off automation for the DPI bypass:
//
//   - WATCHDOG. Optional NFQWS2 fallback for AWG. Disabled by default because it
//     can change how traffic is routed (what stopped answering may be sent
//     through VPN). When enabled, it can still start NFQWS2 if AWG dies, but it
//     never stops NFQWS2 just because AWG looks healthy.
//
//   - AUTO-PICK. Picking a working DPI strategy is normally a manual scan +
//     pick + apply dance. On first boot (or when the configured strategy
//     becomes dead) we run that ourselves: scan AutoCandidates, take the top
//     coefficient, write to nfqws2.conf. The user can disable via auto_pick=false.
//
//   - PERIODIC RE-SCAN. Censors rotate filters; what works today may not
//     tomorrow. If the user opts in, every interval_h hours we re-scan and
//     re-pick. Default OFF (user opt-in only) since each scan is real traffic.
//
// AWG health = (handshake age < 180s) AND (rx_bytes increasing OR no traffic
// expected). 30s tick, 2 confirmations before starting fallback in auto mode.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"nfqws2strategy/internal/services/awgroute"
	"nfqws2strategy/internal/tools/logbuf"
	"nfqws2strategy/internal/tools/netmon"
)

const (
	automationFile = "automation.json"

	awgStaleHandshakeSec int64 = 180
	tickInterval               = 30 * time.Second
	confirmTicks               = 2
)

// Canonical RU-blocked probes used when the user hasn't pinned a list. Small set
// so a scan finishes in <5 min on this hardware.
var defaultAutoPickTargets = []string{
	"youtube.com",
	"googlevideo.com",
	"instagram.com",
	"x.com",
	"openai.com",
}

// AutomationConfig is the user-tunable part.
type AutomationConfig struct {
	Mode         string `json:"mode"`          // "off" | "on" | "auto" (default: "off"; off = no service control)
	AutoPick     bool   `json:"auto_pick"`     // run a scan-and-apply if conf is empty/dead at boot (default true)
	PeriodicScan bool   `json:"periodic_scan"` // re-pick every IntervalH hours (default false — opt-in)
	IntervalH    int    `json:"interval_h"`    // re-scan period when PeriodicScan is on (default 24)
}

// AutomationState persists the AutomationConfig plus the most recent decision —
// the timestamps tell the user "yes, I did pick a strategy 12 minutes ago".
type AutomationState struct {
	AutomationConfig
	LastPickAt    int64  `json:"last_pick_at,omitempty"`
	LastPickArgs  string `json:"last_pick_args,omitempty"`
	LastPickName  string `json:"last_pick_name,omitempty"`
	LastPickError string `json:"last_pick_error,omitempty"`
}

// AutomationStatus is the live view shown to the UI.
type AutomationStatus struct {
	AutomationState
	AWGHealthy     bool   `json:"awg_healthy"`
	HandshakeAge   int64  `json:"handshake_age_sec"`
	Nfqws2Running  bool   `json:"nfqws2_running"`
	PickInProgress bool   `json:"pick_in_progress"`
	Note           string `json:"note,omitempty"`
}

type automationRuntime struct {
	mu     sync.Mutex
	state  AutomationState
	stopCh chan struct{}

	healthyStreak   int
	unhealthyStreak int
	lastRx          int64
	lastRxAt        time.Time

	pickRunning bool
	pickedAt    time.Time // last time we successfully applied a strategy
}

func defaultAutomation() AutomationState {
	return AutomationState{
		AutomationConfig: AutomationConfig{
			Mode:         "off",
			AutoPick:     true,
			PeriodicScan: false,
			IntervalH:    24,
		},
	}
}

// initAutomation loads persisted state (or seeds defaults), starts the watchdog
// loop, and — when AutoPick is enabled — kicks an opportunistic first-boot pick
// if we've never picked or the configured strategy looks dead.
func (a *App) initAutomation() {
	var st AutomationState
	if err := a.store.Load(automationFile, &st); err != nil || st.Mode == "" {
		st = defaultAutomation()
		_ = a.store.Save(automationFile, &st)
	}
	if st.Mode == "auto" {
		// v1.3.8 defaulted to "auto" and stopped NFQWS2 whenever AWG looked
		// healthy. Migrate that surprising default back to the historical behavior:
		// keep NFQWS2 running unless the user explicitly switches modes again.
		st.Mode = "on"
		_ = a.store.Save(automationFile, &st)
	}
	if st.IntervalH <= 0 {
		st.IntervalH = 24
	}
	a.automation = &automationRuntime{state: st, stopCh: make(chan struct{})}
	go a.automationLoop()
}

func (a *App) stopAutomation() {
	if a.automation == nil {
		return
	}
	close(a.automation.stopCh)
}

func (a *App) automationLoop() {
	rt := a.automation
	// Settle the initial sample so the first hysteresis tick isn't a phantom
	// "unhealthy" with zero rx_bytes.
	a.refreshAWGSample()
	a.maybeRunFirstBootPick()
	a.automationStep()

	tick := time.NewTicker(tickInterval)
	defer tick.Stop()
	for {
		select {
		case <-rt.stopCh:
			return
		case <-tick.C:
			a.automationStep()
		}
	}
}

func (a *App) automationStep() {
	rt := a.automation
	mode := a.AutomationConfig().Mode
	healthy, hAge := a.refreshAWGSample()

	rt.mu.Lock()
	if healthy {
		rt.healthyStreak++
		rt.unhealthyStreak = 0
	} else {
		rt.unhealthyStreak++
		rt.healthyStreak = 0
	}
	rt.mu.Unlock()

	switch mode {
	case "off":
		// Watchdog disabled: leave NFQWS2 exactly as the user/service manager set it.
	case "on":
		if !a.nfqws2Running() {
			a.silentNfqws2Start("mode=on")
		}
	default: // "auto"
		if rt.unhealthyStreak >= confirmTicks && !a.nfqws2Running() {
			a.silentNfqws2Start(fmt.Sprintf("AWG down %ds → fallback", hAge))
		}
	}

	// Periodic re-pick. Only run when AWG is healthy (so the scan rides the
	// VPN, not the censored ISP path) and no scan is currently in flight.
	if a.shouldPeriodicPick(healthy) {
		go a.runAutoPick("periodic")
	}
}

// refreshAWGSample reads the current AWG tunnel state and returns whether it
// looks healthy. Health = handshake age under awgStaleHandshakeSec AND (rx is
// growing OR we just don't have two samples yet so we can't say). The handshake
// check alone catches "tunnel dropped"; the rx delta catches "iface up but
// packets aren't moving" (silent firewall blackhole).
func (a *App) refreshAWGSample() (bool, int64) {
	rt := a.automation
	conns := a.awgroute.DashboardConns()
	if len(conns) == 0 {
		return false, 0
	}
	// Pick the first connected/running tunnel; that's "the" AWG link from the
	// dashboard's perspective.
	var pick *awgroute.AWGConn
	for i := range conns {
		if conns[i].Running {
			pick = &conns[i]
			break
		}
	}
	if pick == nil {
		return false, 0
	}
	now := time.Now()
	age := now.Unix() - pick.LastHandshake
	if pick.LastHandshake == 0 {
		age = awgStaleHandshakeSec + 1
	}
	rt.mu.Lock()
	prevRx, prevAt := rt.lastRx, rt.lastRxAt
	rt.lastRx = pick.RxBytes
	rt.lastRxAt = now
	rt.mu.Unlock()

	if age > awgStaleHandshakeSec {
		return false, age
	}
	// rx delta: only meaningful when we have a previous sample close in time.
	if !prevAt.IsZero() && now.Sub(prevAt) < 3*tickInterval {
		if pick.RxBytes == prevRx {
			// No bytes for a full tick on a tunnel with fresh handshake = suspicious
			// but not damning (idle LAN). Only flag if BOTH conditions: stale-ish
			// handshake (> half threshold) AND zero rx delta.
			if age > awgStaleHandshakeSec/2 {
				return false, age
			}
		}
	}
	return true, age
}

func (a *App) nfqws2Running() bool {
	qs, err := netmon.Queues()
	if err != nil {
		return false
	}
	for _, q := range qs {
		if q.Queue == a.Cfg.MainQueue {
			return true
		}
	}
	return false
}

func (a *App) silentNfqws2Start(why string) {
	logbuf.Append("automation", "info", "start nfqws2: "+why)
	a.Nfqws2Start()
}

func (a *App) silentNfqws2Stop(why string) {
	logbuf.Append("automation", "info", "stop nfqws2: "+why)
	a.Nfqws2Stop()
}

func (a *App) shouldPeriodicPick(healthy bool) bool {
	st := a.AutomationConfig()
	if !st.PeriodicScan {
		return false
	}
	if !healthy {
		return false
	}
	rt := a.automation
	rt.mu.Lock()
	last := rt.state.LastPickAt
	running := rt.pickRunning
	rt.mu.Unlock()
	if running {
		return false
	}
	interval := time.Duration(st.IntervalH) * time.Hour
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	if last == 0 {
		return false // first-boot pick is handled separately
	}
	return time.Since(time.Unix(last, 0)) >= interval
}

func (a *App) maybeRunFirstBootPick() {
	st := a.AutomationConfig()
	if !st.AutoPick {
		return
	}
	if a.automation.state.LastPickAt != 0 {
		return // already picked at least once; periodic loop will handle re-checks
	}
	if !a.confLooksEmpty() {
		// Conf already has a strategy — assume the user crafted it. Record the
		// timestamp so we don't re-run on every restart.
		a.automation.mu.Lock()
		a.automation.state.LastPickAt = time.Now().Unix()
		a.automation.state.LastPickArgs = "(pre-existing)"
		_ = a.store.Save(automationFile, &a.automation.state)
		a.automation.mu.Unlock()
		return
	}
	go a.runAutoPick("first-boot")
}

func (a *App) confLooksEmpty() bool {
	b, err := readConfArgs(a.Cfg.Nfqws2Conf)
	if err != nil {
		return true
	}
	trimmed := strings.TrimSpace(b)
	return trimmed == ""
}

// readConfArgs extracts NFQWS_ARGS="..." from the live conf so first-boot pick
// can decide if there's already a strategy in there.
func readConfArgs(path string) (string, error) {
	b, err := readFileBounded(path, 1<<20)
	if err != nil {
		return "", err
	}
	m := reArgsBlock.FindSubmatch(b)
	if m == nil {
		return "", nil
	}
	// reArgsBlock captures the wrapping quotes; group 0 covers NFQWS_ARGS="..." entirely.
	// The content sits between the two captured groups.
	full := string(m[0])
	open := strings.Index(full, `"`)
	close_ := strings.LastIndex(full, `"`)
	if open < 0 || close_ <= open {
		return "", nil
	}
	return full[open+1 : close_], nil
}

// runAutoPick performs scan → pick top coefficient → apply. Blocks the caller
// until done (caller is responsible for running it in a goroutine).
func (a *App) runAutoPick(reason string) {
	rt := a.automation
	rt.mu.Lock()
	if rt.pickRunning {
		rt.mu.Unlock()
		return
	}
	rt.pickRunning = true
	rt.mu.Unlock()
	defer func() {
		rt.mu.Lock()
		rt.pickRunning = false
		rt.mu.Unlock()
	}()

	logbuf.Append("automation", "info", "auto-pick start ("+reason+")")

	req := RunRequest{
		Auto:    true,
		Targets: defaultAutoPickTargets,
		Threads: 6,
	}
	run, err := a.StartRun(req)
	if err != nil {
		a.recordPickError(err)
		logbuf.Append("automation", "error", "auto-pick: "+err.Error())
		return
	}
	// Poll for completion. Auto scans on this hardware take 1–3 minutes.
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	winner, err := a.waitRunForWinner(ctx, run.ID)
	if err != nil {
		a.recordPickError(err)
		logbuf.Append("automation", "error", "auto-pick: "+err.Error())
		return
	}
	if err := a.ApplyStrategyToConfig(winner.ArgLine, true); err != nil {
		a.recordPickError(fmt.Errorf("apply: %w", err))
		logbuf.Append("automation", "error", "auto-pick apply: "+err.Error())
		return
	}
	rt.mu.Lock()
	rt.state.LastPickAt = time.Now().Unix()
	rt.state.LastPickArgs = winner.ArgLine
	rt.state.LastPickName = winner.Name
	rt.state.LastPickError = ""
	_ = a.store.Save(automationFile, &rt.state)
	rt.pickedAt = time.Now()
	rt.mu.Unlock()
	logbuf.Append("automation", "info", "auto-pick applied: "+winner.Name)
}

func (a *App) recordPickError(err error) {
	rt := a.automation
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.state.LastPickError = err.Error()
	// Don't overwrite LastPickAt — the previous successful pick stays valid.
	_ = a.store.Save(automationFile, &rt.state)
}

func (a *App) waitRunForWinner(ctx context.Context, runID string) (*StrategyResult, error) {
	tk := time.NewTicker(3 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			a.cancelActiveRunIfMatches(runID)
			return nil, errors.New("auto-pick timeout")
		case <-tk.C:
			a.mu.Lock()
			run, ok := a.runs[runID]
			a.mu.Unlock()
			if !ok {
				return nil, errors.New("run vanished")
			}
			if run.Status == "running" {
				continue
			}
			// Pick the best result with Success=true.
			results := append([]StrategyResult(nil), run.Results...)
			sort.Slice(results, func(i, j int) bool { return results[i].Coefficient > results[j].Coefficient })
			for _, r := range results {
				if r.Success {
					return &r, nil
				}
			}
			return nil, errors.New("no working strategy found")
		}
	}
}

func (a *App) cancelActiveRunIfMatches(runID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.active != nil && a.active.ID == runID && a.cancel != nil {
		a.cancel()
	}
}

// AutomationConfig returns the current persisted settings (thread-safe copy).
func (a *App) AutomationConfig() AutomationConfig {
	if a.automation == nil {
		return defaultAutomation().AutomationConfig
	}
	a.automation.mu.Lock()
	defer a.automation.mu.Unlock()
	return a.automation.state.AutomationConfig
}

// AutomationStatus snapshots config + live state for the UI panel.
func (a *App) AutomationStatus() AutomationStatus {
	if a.automation == nil {
		return AutomationStatus{AutomationState: defaultAutomation()}
	}
	healthy, age := a.refreshAWGSample()
	a.automation.mu.Lock()
	defer a.automation.mu.Unlock()
	return AutomationStatus{
		AutomationState: a.automation.state,
		AWGHealthy:      healthy,
		HandshakeAge:    age,
		Nfqws2Running:   a.nfqws2Running(),
		PickInProgress:  a.automation.pickRunning,
	}
}

// SetAutomationConfig merges the requested fields, persists, and applies. Empty
// mode field keeps the existing one so the UI can patch individual fields.
func (a *App) SetAutomationConfig(in AutomationConfig) (AutomationStatus, error) {
	if a.automation == nil {
		return AutomationStatus{}, errors.New("automation not initialized")
	}
	if in.Mode != "" && in.Mode != "off" && in.Mode != "on" && in.Mode != "auto" {
		return AutomationStatus{}, fmt.Errorf("bad mode %q", in.Mode)
	}
	a.automation.mu.Lock()
	if in.Mode != "" {
		a.automation.state.Mode = in.Mode
	}
	a.automation.state.AutoPick = in.AutoPick
	a.automation.state.PeriodicScan = in.PeriodicScan
	if in.IntervalH > 0 {
		a.automation.state.IntervalH = in.IntervalH
	}
	_ = a.store.Save(automationFile, &a.automation.state)
	a.automation.mu.Unlock()
	// Reset hysteresis on mode change so the next tick decides fresh.
	a.automation.mu.Lock()
	a.automation.healthyStreak = 0
	a.automation.unhealthyStreak = 0
	a.automation.mu.Unlock()
	return a.AutomationStatus(), nil
}

// TriggerAutoPickNow runs a scan-and-apply on demand (UI "пик сейчас" button).
func (a *App) TriggerAutoPickNow() error {
	if a.automation == nil {
		return errors.New("automation not initialized")
	}
	a.automation.mu.Lock()
	running := a.automation.pickRunning
	a.automation.mu.Unlock()
	if running {
		return errors.New("auto-pick already in progress")
	}
	go a.runAutoPick("manual")
	return nil
}

func readFileBounded(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, maxBytes)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return nil, err
	}
	return buf[:n], nil
}
