package app

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"nfqws2strategy/internal/services/strategy/core/catalog"
	"nfqws2strategy/internal/tools/config"
	"nfqws2strategy/internal/tools/store"
)

func TestExecuteRunFirewallSetupFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses an executable POSIX shell firewall fake")
	}
	for _, tc := range []struct {
		name    string
		threads int
		auto    bool
		errText string
	}{
		{name: "single_worker", threads: 1, errText: "could not start any worker"},
		{name: "all_workers", threads: 3, errText: "could not start any worker"},
		{name: "automatic_baseline", threads: 3, auto: true, errText: "baseline rules"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			logPath := filepath.Join(dir, "iptables.log")
			// Use only the temporary directory in PATH: even a typo in the fake
			// must never fall through to a real router firewall command.
			t.Setenv("PATH", dir)
			t.Setenv("N2S_WORKER_TEST_IPTABLES_LOG", logPath)
			const firewall = "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$N2S_WORKER_TEST_IPTABLES_LOG\"\nprintf '%s\\n' 'mock firewall unavailable' >&2\nexit 1\n"
			if err := os.WriteFile(filepath.Join(dir, "iptables"), []byte(firewall), 0o700); err != nil {
				t.Fatal(err)
			}
			st, err := store.New(filepath.Join(dir, "data"))
			if err != nil {
				t.Fatal(err)
			}
			plan := []runJob{{strat: catalog.Strategy{ID: "never-probed", ArgLine: "--filter-tcp=443"}}}
			// Failure must happen before any target resolution, probe, or engine
			// launch. A loopback literal also keeps a regressed target local.
			targets := []string{"127.0.0.1"}
			run := &Run{ID: "failed-firewall", Status: "running", Auto: tc.auto, Threads: tc.threads, Total: len(plan)}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			a := &App{
				Cfg: &config.Config{
					WANIfaces: []string{"testwan0"}, FirstQueue: 200,
					PortBase: 50000, PortsPerWorker: 200,
					NfqwsBin: filepath.Join(dir, "must-not-launch-nfqws"),
				},
				store: st, active: run, cancel: cancel,
			}
			done := make(chan struct{})
			go func() {
				a.executeRun(ctx, run, nil, plan, tc.threads, targets)
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				cancel()
				t.Fatal("run remained blocked even after context cancellation")
			}
			if run.Status != "error" || !strings.Contains(run.Error, tc.errText) || !strings.Contains(run.Error, "mock firewall unavailable") {
				t.Fatalf("run status = %q, error = %q; want firewall setup error", run.Status, run.Error)
			}
			if ctx.Err() != nil {
				t.Fatalf("run waited for context cancellation instead of reporting setup failure: %v", ctx.Err())
			}
			if run.FinishedAt == 0 || run.Done != 0 || len(run.Results) != 0 || len(run.Baseline) != 0 {
				t.Fatalf("run did not finish cleanly before probing: %+v", run)
			}
			if a.active != nil || a.cancel != nil || a.addWorker != nil {
				t.Fatal("failed run left active worker state behind")
			}
			var saved Run
			if err := st.Load(filepath.Join("runs", run.ID+".json"), &saved); err != nil {
				t.Fatalf("load persisted failed run: %v", err)
			}
			if saved.Status != "error" || saved.Error != run.Error || saved.FinishedAt == 0 {
				t.Fatalf("persisted run lost failure state: %+v", saved)
			}
			log, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatal(err)
			}
			wantAttempts := tc.threads
			if tc.auto {
				wantAttempts = 1
			}
			if got := strings.Count(string(log), " -N STRAT_POST_"); got != wantAttempts {
				t.Fatalf("sandbox setup attempts = %d, want %d; firewall log:\n%s", got, wantAttempts, log)
			}
		})
	}
}
