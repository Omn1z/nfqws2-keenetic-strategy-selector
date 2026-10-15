package app

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"nfqws2strategy/internal/services/awgroute"
	"nfqws2strategy/internal/tools/config"
	"nfqws2strategy/internal/tools/shell"
	"nfqws2strategy/internal/tools/store"
)

type nfqws2ControlFixture struct {
	app                     *App
	running                 atomic.Bool
	starts, stops, restarts atomic.Int32
}

func newNfqws2ControlFixture(t *testing.T) *nfqws2ControlFixture {
	t.Helper()
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	state := defaultAutomation()
	state.Mode = "on"
	state.AutoPick = true
	state.PeriodicScan = true
	state.LastPickAt = time.Now().Add(-48 * time.Hour).Unix()
	state.LastPickName = "saved strategy"
	cfg := config.Default()
	cfg.Nfqws2Conf = filepath.Join(t.TempDir(), "nfqws2.conf")
	if err := os.WriteFile(cfg.Nfqws2Conf, []byte("NFQWS_ARGS=\""+regressionTLSArgs+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &nfqws2ControlFixture{app: &App{Cfg: cfg, store: st, awgroute: &awgroute.Service{}, automation: &automationRuntime{state: state}}}
	f.app.automation.serviceOps = &nfqws2ServiceOperations{
		running: f.running.Load,
		start: func() ServiceResult {
			f.starts.Add(1)
			f.running.Store(true)
			return ServiceResult{Name: "nfqws2", OK: true}
		},
		stop: func() ServiceResult {
			f.stops.Add(1)
			f.running.Store(false)
			return ServiceResult{Name: "nfqws2", OK: true}
		},
		restart: func() ServiceResult {
			f.restarts.Add(1)
			f.running.Store(true)
			return ServiceResult{Name: "nfqws2", OK: true}
		},
	}
	if err := st.Save(automationFile, &state); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestNfqws2ManualOffSurvivesWatchdogSettingsAndReload(t *testing.T) {
	f := newNfqws2ControlFixture(t)
	f.running.Store(true)
	before := f.app.automation.state
	f.app.automation.serviceOps.stop = func() ServiceResult {
		var persisted AutomationState
		if err := f.app.store.Load(automationFile, &persisted); err != nil || !persisted.Nfqws2ManualOff {
			t.Fatalf("OFF not durable before stop: %+v %v", persisted, err)
		}
		f.stops.Add(1)
		f.running.Store(false)
		return ServiceResult{Name: "nfqws2", OK: true}
	}
	if result := f.app.Nfqws2Stop(); !result.OK {
		t.Fatal(result.Detail)
	}
	for _, mode := range []string{"on", "auto", "off"} {
		f.app.enforceNfqws2Automation(mode, true, 999)
	}
	if f.starts.Load() != 0 || f.restarts.Load() != 0 || f.running.Load() {
		t.Fatal("automation restarted an explicitly disabled engine")
	}
	for _, reason := range []string{"manual", "periodic", "first-boot"} {
		if f.app.autoPickAllowed(reason) {
			t.Fatalf("manual OFF allowed %s auto-pick", reason)
		}
	}
	if f.app.shouldPeriodicPick(true) || f.app.TriggerAutoPickNow() == nil {
		t.Fatal("manual OFF allowed scheduled/manual scan-and-apply")
	}
	if result := f.app.restartNfqws2(); result.OK || f.restarts.Load() != 0 {
		t.Fatal("restart implicitly enabled service")
	}
	if result := f.app.startNfqws2Automatically(); result.OK || f.starts.Load() != 0 {
		t.Fatal("automatic start cleared manual OFF")
	}
	want := before
	want.Nfqws2ManualOff = true
	if got := f.app.loadAutomationState(); got != want {
		t.Fatalf("reload lost OFF or preferences: %+v", got)
	}
	if _, err := f.app.SetAutomationConfig(before.AutomationConfig); err != nil {
		t.Fatal(err)
	}
	if f.app.automation.state != want {
		t.Fatal("automation preferences post erased the manual override/history")
	}
	if got := f.app.Nfqws2ServiceStatus(); got.Running || !got.ManualOff {
		t.Fatalf("status is not actual runtime+intent: %+v", got)
	}
}

func TestNfqws2ExplicitStartClearsOffOnlyAfterSuccessAndIsIdempotent(t *testing.T) {
	f := newNfqws2ControlFixture(t)
	if result := f.app.Nfqws2Stop(); !result.OK {
		t.Fatal(result.Detail)
	}
	f.app.automation.serviceOps.start = func() ServiceResult {
		f.starts.Add(1)
		return ServiceResult{Name: "nfqws2", Detail: "engine rejected strategy"}
	}
	if result := f.app.Nfqws2Start(); result.OK || !f.app.nfqws2ManuallyOff() {
		t.Fatal("failed start cleared persisted OFF")
	}
	f.app.automation.serviceOps.start = func() ServiceResult {
		f.starts.Add(1)
		if !f.app.nfqws2ManuallyOff() {
			t.Fatal("OFF cleared before validated startup")
		}
		f.running.Store(true)
		return ServiceResult{Name: "nfqws2", OK: true}
	}
	if result := f.app.Nfqws2Start(); !result.OK {
		t.Fatal(result.Detail)
	}
	if got := f.app.Nfqws2ServiceStatus(); !got.Running || got.ManualOff {
		t.Fatalf("successful startup state %+v", got)
	}
	if f.app.loadAutomationState().Nfqws2ManualOff {
		t.Fatal("successful startup was not persisted")
	}
	if result := f.app.Nfqws2Start(); !result.OK || f.starts.Load() != 2 {
		t.Fatal("duplicate start restarted an already running engine")
	}
}

func TestNfqws2ManualOffPersistenceFailureDoesNotLieAboutControl(t *testing.T) {
	for _, action := range []string{"stop", "start"} {
		t.Run(action, func(t *testing.T) {
			f := newNfqws2ControlFixture(t)
			if action == "start" {
				if result := f.app.Nfqws2Stop(); !result.OK {
					t.Fatal(result.Detail)
				}
			} else {
				f.running.Store(true)
			}
			if err := os.Remove(f.app.store.Path(automationFile)); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(f.app.store.Path(automationFile), 0o700); err != nil {
				t.Fatal(err)
			}
			var result ServiceResult
			if action == "start" {
				result = f.app.Nfqws2Start()
			} else {
				result = f.app.Nfqws2Stop()
			}
			if result.OK {
				t.Fatal("failed preference save reported success")
			}
			if action == "stop" && (!f.running.Load() || f.stops.Load() != 0 || f.app.nfqws2ManuallyOff()) {
				t.Fatal("failed OFF persistence changed service/runtime preference")
			}
			if action == "start" && (f.running.Load() || f.starts.Load() != 1 || f.stops.Load() != 2 || !f.app.nfqws2ManuallyOff()) {
				t.Fatal("failed ON persistence left service enabled against saved OFF")
			}
		})
	}
}

func TestNfqws2ManualOffRetriesFailedCleanupIncludingStartup(t *testing.T) {
	f := newNfqws2ControlFixture(t)
	f.running.Store(true)
	f.app.automation.serviceOps.stop = func() ServiceResult {
		f.stops.Add(1)
		f.running.Store(false)
		return ServiceResult{Name: "nfqws2", Detail: "firewall cleanup failed"}
	}
	if result := f.app.Nfqws2Stop(); result.OK || !f.app.nfqws2ManuallyOff() {
		t.Fatal("cleanup failure hid OFF intent")
	}
	f.app.automation.serviceOps.stop = func() ServiceResult {
		f.stops.Add(1)
		f.running.Store(false)
		return ServiceResult{Name: "nfqws2", OK: true}
	}
	f.app.enforceNfqws2Automation("on", true, 999)
	if f.stops.Load() != 2 || f.starts.Load() != 0 {
		t.Fatal("watchdog did not retry failed cleanup after queue disappeared")
	}
	f.app.enforceNfqws2Automation("on", true, 999)
	if f.stops.Load() != 2 {
		t.Fatal("unchanged stopped service was repeatedly restarted/stopped")
	}
	// On boot, process-less stale PID/firewall state still needs one cleanup.
	f.app.restoreNfqws2ManualOff()
	if f.stops.Load() != 3 {
		t.Fatal("startup skipped cleanup because queue was already absent")
	}
}

func TestNfqws2ManualOffBlocksBackgroundApplyAndFirewallRestore(t *testing.T) {
	f := newNfqws2ControlFixture(t)
	if result := f.app.Nfqws2Stop(); !result.OK {
		t.Fatal(result.Detail)
	}
	before, err := os.ReadFile(f.app.Cfg.Nfqws2Conf)
	if err != nil {
		t.Fatal(err)
	}
	newArgs := "--filter-tcp=443 --filter-l7=tls --lua-desync=multisplit:pos=1,sniext"
	if err := f.app.applyAutoPickStrategy(successfulAutoResult(newArgs, 10), true); err == nil {
		t.Fatal("background result applied while manually stopped")
	}
	if after, err := os.ReadFile(f.app.Cfg.Nfqws2Conf); err != nil || string(after) != string(before) {
		t.Fatal("blocked automatic apply changed configuration")
	}
	if _, err := os.Stat(f.app.Cfg.Nfqws2Conf + ".n2s.bak"); !os.IsNotExist(err) {
		t.Fatal("blocked automatic apply created a backup")
	}
	if err := f.app.ApplyStrategyToConfig(newArgs, true); err == nil || !strings.Contains(err.Error(), "стратегия сохранена") {
		t.Fatalf("manual save/restart result %v", err)
	}
	if f.starts.Load() != 0 || f.restarts.Load() != 0 || f.running.Load() {
		t.Fatal("manual strategy save implicitly enabled the stopped service")
	}
	if err := f.app.RestoreNfqws2Bypass(); err != nil {
		t.Fatal(err)
	} // nil manager proves background restore never reached it.
	if err := f.app.Nfqws2ApplyBypass(); err == nil {
		t.Fatal("explicit bypass apply falsely reported applied while service OFF")
	}
	called := false
	if err := f.app.withNfqws2FirewallApply(false, func() error { called = true; return errors.New("unexpected") }); err == nil || called {
		t.Fatal("manual OFF allowed firewall apply")
	}
}

func TestNfqws2ManualStopSerializesAfterInflightRestart(t *testing.T) {
	f := newNfqws2ControlFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	f.app.automation.serviceOps.restart = func() ServiceResult {
		f.restarts.Add(1)
		close(entered)
		<-release
		f.running.Store(true)
		return ServiceResult{Name: "nfqws2", OK: true}
	}
	restarted, stopped := make(chan ServiceResult, 1), make(chan ServiceResult, 1)
	go func() { restarted <- f.app.restartNfqws2() }()
	<-entered
	go func() { stopped <- f.app.Nfqws2Stop() }()
	close(release)
	if result := <-restarted; !result.OK {
		t.Fatal(result.Detail)
	}
	if result := <-stopped; !result.OK {
		t.Fatal(result.Detail)
	}
	f.app.enforceNfqws2Automation("on", true, 999)
	if f.running.Load() || !f.app.nfqws2ManuallyOff() || f.starts.Load() != 0 || f.stops.Load() != 1 {
		t.Fatal("in-flight restart/watchdog undid later manual OFF")
	}
}

func TestNfqws2BypassRestoreSerializesBeforeManualStop(t *testing.T) {
	f := newNfqws2ControlFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- f.app.withNfqws2FirewallApply(true, func() error { close(entered); <-release; return nil })
	}()
	<-entered
	stopped := make(chan ServiceResult, 1)
	go func() { stopped <- f.app.Nfqws2Stop() }()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if result := <-stopped; !result.OK {
		t.Fatal(result.Detail)
	}
	if err := f.app.RestoreNfqws2Bypass(); err != nil {
		t.Fatal(err)
	}
	if f.stops.Load() != 1 || !f.app.nfqws2ManuallyOff() {
		t.Fatal("late firewall restore escaped manual stop serialization")
	}
}

func TestNfqws2FailedStartCleansPartialDaemonWhenOff(t *testing.T) {
	f := newNfqws2ControlFixture(t)
	if result := f.app.Nfqws2Stop(); !result.OK {
		t.Fatal(result.Detail)
	}
	f.app.automation.serviceOps.start = func() ServiceResult {
		f.starts.Add(1)
		f.running.Store(true)
		return ServiceResult{Name: "nfqws2", Detail: "startup metadata failed after daemonization"}
	}
	if result := f.app.Nfqws2Start(); result.OK || f.running.Load() || !f.app.nfqws2ManuallyOff() || f.stops.Load() != 2 {
		t.Fatal("failed startup left a partial daemon running against saved OFF")
	}
}

func TestNfqws2PackageUpdateRestoresOffOnSuccessAndFailure(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[failed], func(t *testing.T) {
			f := newNfqws2ControlFixture(t)
			if result := f.app.Nfqws2Stop(); !result.OK {
				t.Fatal(result.Detail)
			}
			failure := errors.New("package install failed")
			output, err := f.app.withNfqws2PackageUpdate(func() (string, error) {
				f.running.Store(true)
				if failed {
					return "post-install output", failure
				}
				return "post-install output", nil
			})
			if output != "post-install output" || failed != errors.Is(err, failure) || f.running.Load() || !f.app.nfqws2ManuallyOff() || f.stops.Load() != 2 {
				t.Fatalf("package hook escaped OFF: output=%q err=%v state=%+v stops=%d", output, err, f.app.Nfqws2ServiceStatus(), f.stops.Load())
			}
		})
	}
}

func TestNfqws2QueuedWatchdogAndAutoPickRecheckLatestPreferences(t *testing.T) {
	f := newNfqws2ControlFixture(t)
	f.app.automation.serviceMu.Lock()
	started, finished := make(chan struct{}), make(chan struct{})
	go func() { close(started); f.app.enforceNfqws2Automation("on", true, 999); close(finished) }()
	<-started
	f.app.automation.mu.Lock()
	f.app.automation.state.Mode = "off"
	f.app.automation.mu.Unlock()
	f.app.automation.serviceMu.Unlock()
	<-finished
	if f.starts.Load() != 0 {
		t.Fatal("queued old mode=on overrode newly disabled watchdog")
	}
	for _, reason := range []string{"first-boot", "periodic"} {
		t.Run(reason, func(t *testing.T) {
			f.app.automation.mu.Lock()
			f.app.automation.state.AutoPick = true
			f.app.automation.state.PeriodicScan = true
			f.app.automation.mu.Unlock()
			before, err := os.ReadFile(f.app.Cfg.Nfqws2Conf)
			if err != nil {
				t.Fatal(err)
			}
			f.app.automation.serviceMu.Lock()
			entered, done := make(chan struct{}), make(chan error, 1)
			go func() {
				close(entered)
				done <- f.app.applyAutoPickStrategyForReason(successfulAutoResult("--filter-tcp=443 --lua-desync=multisplit:pos=1,sniext", 10), true, reason)
			}()
			<-entered
			f.app.automation.mu.Lock()
			if reason == "periodic" {
				f.app.automation.state.PeriodicScan = false
			} else {
				f.app.automation.state.AutoPick = false
			}
			f.app.automation.mu.Unlock()
			f.app.automation.serviceMu.Unlock()
			if err := <-done; err == nil {
				t.Fatal("queued background result ignored newly disabled preference")
			}
			after, err := os.ReadFile(f.app.Cfg.Nfqws2Conf)
			if err != nil || string(after) != string(before) || f.restarts.Load() != 0 {
				t.Fatal("blocked queued pick changed config or restarted service")
			}
		})
	}
}

func TestNfqws2StopFirewallInspectionSupportsLegacyWaitFlags(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		sh = filepath.Join(os.Getenv("ProgramFiles"), "Git", "bin", "bash.exe")
		if _, err := os.Stat(sh); err != nil {
			t.Skip("POSIX shell unavailable")
		}
	}
	for _, test := range []struct {
		name, mode string
		wantError  bool
		wantCalls  []string
	}{
		{"legacy1.4.21", "legacy", false, []string{"iptables -w 2 -t mangle -S", "iptables -t mangle -S", "ip6tables -w 2 -t mangle -S", "ip6tables -t mangle -S"}},
		{"modern", "modern", false, []string{"iptables -w 2 -t mangle -S", "ip6tables -w 2 -t mangle -S"}},
		{"legacyReadFailure", "legacy-failure", true, []string{"iptables -w 2 -t mangle -S", "iptables -t mangle -S"}},
		{"realReadFailure", "failure", true, []string{"iptables -w 2 -t mangle -S"}},
		{"legacyOwnedQueueRemains", "legacy-owned", true, []string{"iptables -w 2 -t mangle -S", "iptables -t mangle -S"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := filepath.Join(t.TempDir(), "calls")
			// Shell functions shadow both firewall executables. This harness can
			// only inspect its fabricated rules, including when run on a router.
			mock := `mock_rules() {
  name=$1
  shift
  printf '%s %s\n' "$name" "$*" >> "$NFQWS_TEST_CALLS"
  if [ "$1" = -w ]; then
    [ "$2" = 2 ] || return 99
    case "$NFQWS_TEST_MODE" in legacy*) return 2 ;; failure) return 4 ;; esac
  fi
  case "$NFQWS_TEST_MODE" in *failure) return 4 ;; esac
  case "$NFQWS_TEST_MODE" in *owned) printf '%s\n' '-A nfqws_pre -j NFQUEUE --queue-num 300 --queue-bypass' ;;
    *) printf '%s\n' '-P PREROUTING ACCEPT' '-A other -j NFQUEUE --queue-num 301 --queue-bypass' ;; esac
}

iptables() { mock_rules iptables "$@"; }
ip6tables() { mock_rules ip6tables "$@"; }
`
			command := "NFQWS_TEST_CALLS=" + shell.Quote(filepath.ToSlash(calls)) + "; NFQWS_TEST_MODE=" + shell.Quote(test.mode) + "\n" + mock + nfqws2StoppedFirewallCheck(300)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, sh, "-c", command).CombinedOutput()
			if (err != nil) != test.wantError {
				t.Fatalf("inspection error=%v output=%q", err, output)
			}
			wire, readErr := os.ReadFile(calls)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if got, want := strings.TrimSpace(string(wire)), strings.Join(test.wantCalls, "\n"); got != want {
				t.Fatalf("wrong bounded/nonwaiting inspection calls:\n%s\nwant:\n%s", got, want)
			}
			if test.wantError && len(output) == 0 {
				t.Fatal("firewall inspection failure omitted its diagnostic")
			}
		})
	}
}

func TestNfqws2MainDaemonIdentityRejectsWorkersAndStalePID(t *testing.T) {
	for _, test := range []struct {
		name  string
		argv  []string
		queue int
		want  bool
	}{
		{"foregroundMain", []string{"/usr/bin/nfqws2", "--qnum=300"}, 300, true},
		{"partiallyStartedMain", []string{"/opt/usr/bin/nfqws2.real", "--daemon", "--pidfile=MAIN_PID", "--qnum=300"}, 300, true},
		{"customQueueDaemon", []string{"/opt/usr/bin/nfqws2-keenetic", "--daemon", "--pidfile", "MAIN_PID", "--qnum", "411"}, 300, true},
		{"customQueueProcd", []string{"/usr/bin/nfqws2", "--qnum=411"}, 411, true},
		{"worker", []string{"/usr/bin/nfqws2", "--qnum=200", "--writable=/tmp/nfqws2-strategy/w0"}, 300, false},
		{"workerSeparateOptions", []string{"/usr/bin/nfqws2", "--qnum", "201", "--writable", "/tmp/nfqws2-strategy/w1"}, 300, false},
		{"workerClaimingMainQueue", []string{"/usr/bin/nfqws2", "--qnum=300", "--writable=/tmp/nfqws2-strategy/w0"}, 300, false},
		{"otherForegroundQueue", []string{"/usr/bin/nfqws2", "--qnum=200"}, 300, false},
		{"otherDaemonQueue", []string{"/usr/bin/nfqws2", "--daemon", "--qnum=200"}, 300, false},
		{"otherPidfile", []string{"/usr/bin/nfqws2", "--daemon", "--pidfile=/tmp/other.pid", "--qnum=300"}, 300, false},
		{"stalePanelPID", []string{"/usr/bin/nfqws2-strategy", "--qnum=300"}, 300, false},
		{"staleUnrelatedPID", []string{"/usr/bin/sleep", "300"}, 300, false},
		{"missingQueue", []string{"/usr/bin/nfqws2", "--daemon", "--pidfile=MAIN_PID"}, 300, false},
		{"invalidQueue", []string{"/usr/bin/nfqws2", "--qnum=65536"}, 300, false},
		{"incompleteQueue", []string{"/usr/bin/nfqws2", "--qnum"}, 300, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			pidFile := filepath.Join(root, "nfqws2.pid")
			procRoot := filepath.Join(root, "proc")
			if err := os.MkdirAll(filepath.Join(procRoot, "1234"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(pidFile, []byte("1234\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			argv := make([]string, len(test.argv))
			for i, arg := range test.argv {
				argv[i] = strings.ReplaceAll(arg, "MAIN_PID", pidFile)
			}
			if err := os.WriteFile(filepath.Join(procRoot, "1234", "cmdline"), []byte(strings.Join(argv, "\x00")+"\x00"), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := nfqws2MainDaemonRunning(pidFile, procRoot, test.queue); got != test.want {
				t.Fatalf("main daemon=%v, want=%v for argv %q", got, test.want, argv)
			}
			// An exact process name elsewhere in proc cannot replace a missing
			// main pidfile, and a pidfile left after exit is never sufficient.
			if err := os.Remove(pidFile); err != nil {
				t.Fatal(err)
			}
			if nfqws2MainDaemonRunning(pidFile, procRoot, test.queue) {
				t.Fatal("process without main pidfile reported as the service")
			}
			if err := os.WriteFile(pidFile, []byte("4321\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if nfqws2MainDaemonRunning(pidFile, procRoot, test.queue) {
				t.Fatal("dead pidfile reported as the service")
			}
		})
	}
}

func TestNfqws2WorkerOnlyStateDoesNotTriggerManualOffOrSkipStart(t *testing.T) {
	f := newNfqws2ControlFixture(t)
	procRoot := filepath.Join(t.TempDir(), "proc")
	pidFile := nfqws2ServicePIDPath(f.app.Cfg.Nfqws2Conf)
	if err := os.MkdirAll(filepath.Join(procRoot, "1234"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pidFile, []byte("1234\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	worker := "/opt/usr/bin/nfqws2\x00--qnum=200\x00--writable=/tmp/nfqws2-strategy/w0\x00"
	if err := os.WriteFile(filepath.Join(procRoot, "1234", "cmdline"), []byte(worker), 0o600); err != nil {
		t.Fatal(err)
	}
	f.app.automation.serviceOps.running = func() bool {
		return f.running.Load() || nfqws2MainDaemonRunning(pidFile, procRoot, f.app.Cfg.MainQueue)
	}
	if err := f.app.persistNfqws2ManualOff(true); err != nil {
		t.Fatal(err)
	}
	if status := f.app.Nfqws2ServiceStatus(); status.Running || !status.ManualOff {
		t.Fatalf("sandbox worker changed main service status: %+v", status)
	}
	f.app.enforceNfqws2Automation("on", true, 999)
	if f.stops.Load() != 0 {
		t.Fatal("manual OFF watchdog killed workers while main service was absent")
	}
	if result := f.app.Nfqws2Start(); !result.OK || f.starts.Load() != 1 || f.app.nfqws2ManuallyOff() {
		t.Fatal("worker was mistaken for an already running main service")
	}
}

func TestNfqws2MainDaemonIdentityRejectsMalformedPIDAndOversizedProc(t *testing.T) {
	root := t.TempDir()
	pidFile := filepath.Join(root, "nfqws2.pid")
	procRoot := filepath.Join(root, "proc")
	if err := os.MkdirAll(filepath.Join(procRoot, "1234"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, pid := range []string{"", "1", "-1234", "1234 4321", "../1234", "01234", strings.Repeat("1", 65)} {
		if err := os.WriteFile(pidFile, []byte(pid), 0o600); err != nil {
			t.Fatal(err)
		}
		if nfqws2MainDaemonRunning(pidFile, procRoot, 300) {
			t.Fatalf("accepted malformed main PID %q", pid)
		}
	}
	if err := os.WriteFile(pidFile, []byte("1234"), 0o600); err != nil {
		t.Fatal(err)
	}
	wire := "/usr/bin/nfqws2\x00--qnum=300\x00--lua-desync=" + strings.Repeat("x", 256*1024)
	if err := os.WriteFile(filepath.Join(procRoot, "1234", "cmdline"), []byte(wire), 0o600); err != nil {
		t.Fatal(err)
	}
	if nfqws2MainDaemonRunning(pidFile, procRoot, 300) {
		t.Fatal("accepted an oversized process identity")
	}
}

func TestNfqws2MainQueueUsesLiteralRuntimeConfig(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "nfqws2.conf")
	for _, test := range []struct {
		config, runtime string
		want            int
	}{
		{"NFQUEUE_NUM=411\n", "", 411},
		{"NFQUEUE_NUM=411\n", "NFQUEUE_NUM=412\n", 412},
		{"NFQUEUE_NUM=411\n", "NFQUEUE_NUM=65536\n", 411},
		{"NFQUEUE_NUM=$SOME_QUEUE\n", "", 300},
		{"NFQUEUE_NUM=$(printf 411)\n", "", 300},
	} {
		t.Run(strconv.Itoa(test.want)+test.runtime, func(t *testing.T) {
			if err := os.WriteFile(conf, []byte(test.config), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(conf+".run", []byte(test.runtime), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := nfqws2ServiceMainQueue(conf, 300); got != test.want {
				t.Fatalf("effective main queue=%d, want=%d", got, test.want)
			}
		})
	}
}
