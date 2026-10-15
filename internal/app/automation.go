package app

// Hands-off automation for the DPI bypass:
//
//   - WATCHDOG. Optional NFQWS2 fallback for AWG. Disabled by default because it
//     can change how traffic is routed (what stopped answering may be sent
//     through VPN). When enabled, it can still start NFQWS2 if AWG dies, but it
//     never stops NFQWS2 just because AWG looks healthy.
//
//   - AUTO-PICK. Disabled by default; the user can enable the UI switch to
//     scan and apply a strategy on first boot when the config is empty.
//
//   - PERIODIC RE-SCAN. Optional scheduled picks require both auto_pick and
//     periodic_scan. Explicit "pick now" remains a separate manual action.
//
// AWG health = (handshake age < 180s) AND (rx_bytes increasing OR no traffic
// expected). 30s tick, 2 confirmations before starting fallback in auto mode.

import (
	"context"
	"errors"
	"fmt"
	"os"
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
	AutoPick     bool   `json:"auto_pick"`     // allow background scan-and-apply (default false)
	PeriodicScan bool   `json:"periodic_scan"` // scheduled picks while AutoPick is enabled (default false)
	IntervalH    int    `json:"interval_h"`    // re-scan period when PeriodicScan is on (default 24)
}

// AutomationState persists the AutomationConfig plus the most recent decision —
// the timestamps tell the user "yes, I did pick a strategy 12 minutes ago".
type AutomationState struct {
	AutomationConfig
	LastPickAt      int64  `json:"last_pick_at,omitempty"`
	LastPickArgs    string `json:"last_pick_args,omitempty"`
	LastPickName    string `json:"last_pick_name,omitempty"`
	LastPickError   string `json:"last_pick_error,omitempty"`
	Nfqws2ManualOff bool   `json:"nfqws2_manual_off"`
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
	mu               sync.Mutex
	serviceMu        sync.Mutex               // serialize explicit controls, watchdog and automatic applies
	serviceOps       *nfqws2ServiceOperations // optional pure operations for lifecycle tests
	serviceNeedsStop bool                     // retry failed process/firewall cleanup while manual OFF is retained
	state            AutomationState
	stopCh           chan struct{}

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
			AutoPick:     false,
			PeriodicScan: false,
			IntervalH:    24,
		},
	}
}

// loadAutomationState seeds disabled defaults while preserving the user's
// saved switches and history. It does not start background work.
func (a *App) loadAutomationState() AutomationState {
	var st AutomationState
	changed := false
	if err := a.store.Load(automationFile, &st); err != nil || st.Mode == "" {
		st = defaultAutomation()
		changed = true
	}
	if st.Mode == "auto" {
		// v1.3.8 defaulted to "auto" and stopped NFQWS2 whenever AWG looked
		// healthy. Migrate that surprising default back to the historical behavior:
		// keep NFQWS2 running unless the user explicitly switches modes again.
		st.Mode = "on"
		changed = true
	}
	if st.IntervalH <= 0 {
		st.IntervalH = 24
		changed = true
	}
	if changed {
		if err := a.store.Save(automationFile, &st); err != nil {
			logbuf.Append("automation", "error", "сохранение настроек автоматики: "+err.Error())
		}
	}
	return st
}

// initAutomation loads settings and starts the independent service watchdog.
func (a *App) initAutomation() {
	st := a.loadAutomationState()
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
	// The vendor S51 init can start before this panel on boot. Restore an
	// explicit OFF before sampling tunnels or considering background work.
	if a.nfqws2ManuallyOff() {
		a.restoreNfqws2ManualOff()
	}
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
	unhealthy := rt.unhealthyStreak >= confirmTicks
	rt.mu.Unlock()
	a.enforceNfqws2Automation(mode, unhealthy, hAge)

	// Periodic re-pick requires the master switch, a healthy AWG connection,
	// and no scan currently in flight.
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
	a.startNfqws2Automatically()
}

func (a *App) silentNfqws2Stop(why string) {
	logbuf.Append("automation", "info", "stop nfqws2: "+why)
	a.enforceNfqws2Automation("off", false, 0)
}

func (a *App) shouldPeriodicPick(healthy bool) bool {
	if a.nfqws2ManuallyOff() {
		return false
	}
	st := a.AutomationConfig()
	if !st.AutoPick || !st.PeriodicScan {
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
	if a.nfqws2ManuallyOff() {
		return
	}
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

// autoPickAllowed keeps the saved switch authoritative for background work,
// including work queued just before the user disabled it.
func (a *App) autoPickAllowed(reason string) bool {
	if a.nfqws2ManuallyOff() {
		return false
	}
	st := a.AutomationConfig()
	switch reason {
	case "manual":
		return true
	case "first-boot":
		return st.AutoPick
	case "periodic":
		return st.AutoPick && st.PeriodicScan
	default:
		return false
	}
}

// runAutoPick performs scan → pick top coefficient → apply. Blocks the caller
// until done (caller is responsible for running it in a goroutine).
func (a *App) runAutoPick(reason string) {
	if !a.autoPickAllowed(reason) {
		return
	}
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
	if !a.autoPickAllowed(reason) {
		logbuf.Append("automation", "info", "авто-пик выключен: результат фонового сканирования не применён")
		return
	}
	if err := a.applyAutoPickStrategyForReason(*winner, true, reason); err != nil {
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
			run, ok := a.GetRun(runID)
			if !ok {
				return nil, errors.New("run vanished")
			}
			if run.Status == "running" {
				continue
			}
			if run.Status != "done" {
				return nil, fmt.Errorf("auto-pick run %s: %s", run.Status, run.Error)
			}
			return autoPickWinner(run.Results)
		}
	}
}

// Recheck old/persisted results as well: versions before this guard could label
// HTTP-only profiles successful after a request that never used that profile.
func autoPickWinner(results []StrategyResult) (*StrategyResult, error) {
	var best *StrategyResult
	for _, result := range results {
		if !result.Success || result.TargetsTotal <= 0 || result.TargetsOK != result.TargetsTotal || validateHTTPSStrategy(result.ArgLine) != nil {
			continue
		}
		if best == nil || result.Coefficient > best.Coefficient {
			copy := result
			best = &copy
		}
	}
	if best == nil {
		return nil, errors.New("no working HTTPS (TCP/443, TLS) strategy found")
	}
	return best, nil
}

// Guard automatic writes independently of result selection. Manual config/apply
// actions remain able to install HTTP strategies when the user requests them.
func (a *App) applyAutoPickStrategy(result StrategyResult, restart bool) error {
	return a.applyAutoPickStrategyForReason(result, restart, "")
}

func (a *App) applyAutoPickStrategyForReason(result StrategyResult, restart bool, reason string) error {
	if _, err := autoPickWinner([]StrategyResult{result}); err != nil {
		return err
	}
	if a.automation == nil {
		return a.ApplyStrategyToConfig(result.ArgLine, restart)
	}
	a.automation.serviceMu.Lock()
	defer a.automation.serviceMu.Unlock()
	if a.nfqws2ManuallyOff() {
		return errors.New("NFQWS2 выключен вручную; автоматическая стратегия не применена")
	}
	if reason != "" && !a.autoPickAllowed(reason) {
		return errors.New("авто-пик выключен; результат фонового сканирования не применён")
	}
	if err := a.ApplyStrategyToConfig(result.ArgLine, false); err != nil {
		return err
	}
	if restart {
		if result := a.runNfqws2ServiceOperation("restart"); !result.OK {
			return errors.New(result.Detail)
		}
	}
	return nil
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
	next := a.automation.state
	if in.Mode != "" {
		next.Mode = in.Mode
	}
	next.AutoPick = in.AutoPick
	next.PeriodicScan = in.PeriodicScan
	if in.IntervalH > 0 {
		next.IntervalH = in.IntervalH
	}
	if err := a.store.Save(automationFile, &next); err != nil {
		a.automation.mu.Unlock()
		return AutomationStatus{}, fmt.Errorf("сохранение настроек автоматики: %w", err)
	}
	a.automation.state = next
	// Reset hysteresis on mode change so the next tick decides fresh.
	a.automation.healthyStreak = 0
	a.automation.unhealthyStreak = 0
	a.automation.mu.Unlock()
	return a.AutomationStatus(), nil
}

// TriggerAutoPickNow runs a scan-and-apply on demand (UI "пик сейчас" button),
// independently of the background automation switch.
func (a *App) TriggerAutoPickNow() error {
	if a.automation == nil {
		return errors.New("automation not initialized")
	}
	if a.nfqws2ManuallyOff() {
		return errors.New("NFQWS2 выключен вручную; сначала включите сервис")
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
