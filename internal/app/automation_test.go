package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nfqws2strategy/internal/services/awgroute"
	"nfqws2strategy/internal/tools/config"
	"nfqws2strategy/internal/tools/store"
)

func successfulAutoResult(args string, coefficient float64) StrategyResult {
	return StrategyResult{ArgLine: args, Success: true, TargetsTotal: 2, TargetsOK: 2, Coefficient: coefficient}
}

func TestAutoPickWinnerRejectsHTTPDespiteHigherScore(t *testing.T) {
	http := successfulAutoResult(regressionHTTPArgs, 100)
	http.L7 = "tls" // A persisted or incorrect label cannot override argv.
	tls := successfulAutoResult(regressionTLSArgs, 10)
	tls.L7 = "http" // Conversely, old metadata cannot disqualify a real TLS profile.
	partial := successfulAutoResult(regressionTLSArgs, 1000)
	partial.TargetsOK = 1
	empty := successfulAutoResult(regressionTLSArgs, 1000)
	empty.TargetsTotal, empty.TargetsOK = 0, 0
	failed := successfulAutoResult(regressionTLSArgs, 1000)
	failed.Success = false
	results := []StrategyResult{http, partial, empty, failed, tls}
	winner, err := autoPickWinner(results)
	if err != nil || winner.ArgLine != regressionTLSArgs || winner.Coefficient != 10 {
		t.Fatalf("wrong winner: %+v, %v", winner, err)
	}
	if results[0].ArgLine != regressionHTTPArgs {
		t.Fatal("winner selection reordered stored results")
	}
	if winner, err := autoPickWinner(results[:4]); err == nil || winner != nil {
		t.Fatalf("automated winner selected without a validated TLS result: %+v, %v", winner, err)
	}
}

func TestAutoPickApplyRejectsHTTPBeforeBackupOrWrite(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "nfqws2.conf")
	original := "# keep user settings\nNFQWS_ARGS=\"" + regressionTLSArgs + "\"\nNFQWS_ARGS_QUIC=\"--filter-udp=443 --lua-desync=fake:blob=quic_initial\"\nNFQWS_ARGS_UDP=\"--filter-udp=50000 --lua-desync=fake\"\n"
	if err := os.WriteFile(conf, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	backup := conf + ".n2s.bak"
	if err := os.WriteFile(backup, []byte("previous known good backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &App{Cfg: &config.Config{Nfqws2Conf: conf}}
	if err := a.applyAutoPickStrategy(successfulAutoResult(regressionHTTPArgs, 100), false); err == nil {
		t.Fatal("automated HTTP-only overwrite accepted")
	}
	for path, want := range map[string]string{conf: original, backup: "previous known good backup"} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatalf("rejected winner modified %s: %q, %v", filepath.Base(path), got, err)
		}
	}
	// A valid TLS selection still applies, preserves unrelated protocol fields,
	// and backs up the exact previous file for recovery.
	newTLS := "--filter-tcp=80,443 --filter-l7=tls --lua-desync=multisplit:pos=1,midsld"
	if err := a.applyAutoPickStrategy(successfulAutoResult(newTLS, 10), false); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(conf)
	if want := strings.Replace(original, regressionTLSArgs, newTLS, 1); err != nil || string(got) != want {
		t.Fatalf("valid auto apply changed unrelated settings: %q, %v", got, err)
	}
	if got, err := os.ReadFile(backup); err != nil || string(got) != original {
		t.Fatalf("valid auto apply lost backup: %q, %v", got, err)
	}
	// The explicit manual API has a different contract: users may intentionally
	// replace NFQWS_ARGS with an HTTP strategy, or edit complete profiles.
	if err := a.ApplyStrategyToConfig(regressionHTTPArgs, false); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(conf)
	if want := strings.Replace(original, regressionTLSArgs, regressionHTTPArgs, 1); err != nil || string(got) != want {
		t.Fatalf("explicit manual HTTP apply was changed: %q, %v", got, err)
	}
}

func TestAutomationSwitchDefaultsOffAndPersistsUserChoice(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a := &App{Cfg: config.Default(), store: st, awgroute: &awgroute.Service{}}
	initial := a.loadAutomationState()
	if initial.AutoPick || initial.PeriodicScan || initial.Mode != "off" || initial.IntervalH != 24 {
		t.Fatalf("unexpected first-install settings: %+v", initial)
	}
	var persisted AutomationState
	if err := st.Load(automationFile, &persisted); err != nil || persisted != initial {
		t.Fatalf("default settings were not saved: %+v, %v", persisted, err)
	}
	initial.LastPickAt = 1234567890
	initial.LastPickName = "previous strategy"
	initial.LastPickArgs = regressionTLSArgs
	initial.LastPickError = "previous diagnostic"
	a.automation = &automationRuntime{state: initial}
	for _, enabled := range []bool{true, false, true} {
		// The master switch must retain the periodic preference while off, so
		// enabling it again resumes the schedule chosen by the user.
		requested := AutomationConfig{Mode: "on", AutoPick: enabled, PeriodicScan: true, IntervalH: 7}
		status, err := a.SetAutomationConfig(requested)
		if err != nil {
			t.Fatalf("set auto_pick=%t: %v", enabled, err)
		}
		want := initial
		want.AutomationConfig = requested
		if status.AutomationState != want || a.AutomationConfig() != requested {
			t.Fatalf("switch changed unrelated history or ignored requested settings: %+v", status)
		}
		if got := a.loadAutomationState(); got != want {
			t.Fatalf("auto_pick=%t did not survive reload: got %+v, want %+v", enabled, got, want)
		}
		if err := st.Load(automationFile, &persisted); err != nil || persisted != want {
			t.Fatalf("auto_pick=%t did not persist: %+v, %v", enabled, persisted, err)
		}
	}
}

func TestAutoPickSwitchControlsBackgroundSources(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, periodic := range []bool{false, true} {
			state := AutomationState{
				AutomationConfig: AutomationConfig{Mode: "off", AutoPick: enabled, PeriodicScan: periodic, IntervalH: 1},
				LastPickAt:       time.Now().Add(-48 * time.Hour).Unix(),
			}
			a := &App{automation: &automationRuntime{state: state}}
			for reason, want := range map[string]bool{
				"first-boot": enabled,
				"periodic":   enabled && periodic,
				"manual":     true,
				"unknown":    false,
			} {
				if got := a.autoPickAllowed(reason); got != want {
					t.Fatalf("auto_pick=%t periodic_scan=%t reason=%s: got %t, want %t", enabled, periodic, reason, got, want)
				}
			}
			if got := a.shouldPeriodicPick(true); got != (enabled && periodic) {
				t.Fatalf("overdue scheduled pick: auto_pick=%t periodic_scan=%t got %t", enabled, periodic, got)
			}
			if a.shouldPeriodicPick(false) {
				t.Fatal("unhealthy tunnel allowed a scheduled pick")
			}
			// Re-evaluating the permission after a scan must see a newly disabled
			// switch before applying its result; manual requests stay independent.
			a.automation.state.AutoPick = false
			if a.autoPickAllowed("first-boot") || a.autoPickAllowed("periodic") || !a.autoPickAllowed("manual") {
				t.Fatal("permission check ignored the latest switch value")
			}
		}
	}
}

func TestAutomationSwitchSaveFailureKeepsPreviousState(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// A directory at the target path makes the atomic rename fail on all OSes.
	if err := os.Mkdir(st.Path(automationFile), 0o700); err != nil {
		t.Fatal(err)
	}
	original := defaultAutomation()
	a := &App{Cfg: config.Default(), store: st, awgroute: &awgroute.Service{}, automation: &automationRuntime{state: original}}
	if _, err := a.SetAutomationConfig(AutomationConfig{Mode: "on", AutoPick: true}); err == nil {
		t.Fatal("failed switch save was reported as successful")
	}
	if a.automation.state != original {
		t.Fatalf("failed switch save changed runtime settings: %+v", a.automation.state)
	}
}
