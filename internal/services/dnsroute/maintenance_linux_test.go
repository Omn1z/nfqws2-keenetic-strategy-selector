//go:build linux

package dnsroute

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func maintenanceTestAdapter(t *testing.T) (*Adapter, context.Context) {
	t.Helper()
	a := New(nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	a.started, a.hookReady = true, true
	a.listen = ListenOptions{Host: "192.168.3.1", DNSPort: 5355, DisableNFQWS: true}
	a.lanIface, a.lanSubnet = "br0", "192.168.3.0/24"
	a.runCtx, a.cancel = ctx, cancel
	return a, ctx
}

func waitMaintenanceTest(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func TestMaintenanceInspectionDoesNotBlockRoutes(t *testing.T) {
	a, ctx := maintenanceTestAdapter(t)
	prior := command
	t.Cleanup(func() { command = prior })
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	checks := 0
	command = func(_ context.Context, name string, args ...string) (string, error) {
		if name != "iptables" || !strings.Contains(strings.Join(args, " "), " -C ") {
			return "", errors.New("healthy maintenance must inspect only")
		}
		checks++
		if checks == 1 {
			close(entered)
			<-release
		}
		return "", nil
	}
	done := make(chan struct{})
	go func() { defer close(done); a.maintainOnce(ctx) }()
	waitMaintenanceTest(t, entered, "blocked firewall inspection")
	routeDone := make(chan struct{})
	go func() { defer close(routeDone); a.Routes() }()
	select {
	case <-routeDone:
	case <-time.After(250 * time.Millisecond):
		unblock()
		waitMaintenanceTest(t, done, "maintenance cleanup")
		t.Fatal("read-only firewall inspection blocked route lookup")
	}
	unblock()
	waitMaintenanceTest(t, done, "maintenance completion")
	if checks != 5 {
		t.Fatalf("listener checks = %d, want 5 and no repairs", checks)
	}
}

func TestMaintenanceCloseCancelsInspectionWithoutRepair(t *testing.T) {
	a, ctx := maintenanceTestAdapter(t)
	priorCommand, priorHook := command, hookPath
	t.Cleanup(func() { command, hookPath = priorCommand, priorHook })
	// An absent owned hook lets Close exercise its join/cancel path without
	// invoking any host firewall cleanup in this unprivileged test.
	hookPath = filepath.Join(t.TempDir(), "missing-hook")
	a.hookReady = false
	entered := make(chan struct{})
	var installed bool
	command = func(ctx context.Context, name string, _ ...string) (string, error) {
		if name == "sh" {
			installed = true
			return "", nil
		}
		close(entered)
		<-ctx.Done()
		return "", ctx.Err()
	}
	a.done = make(chan struct{})
	done := a.done
	go func() { defer close(done); a.maintainOnce(ctx) }()
	waitMaintenanceTest(t, entered, "inspection start")
	closeDone := make(chan struct{})
	var closeErr error
	go func() { defer close(closeDone); closeErr = a.Close() }()
	waitMaintenanceTest(t, closeDone, "Close while inspection is blocked")
	if closeErr != nil || installed || a.started {
		t.Fatalf("close err=%v installed=%v started=%v", closeErr, installed, a.started)
	}
}

func TestMaintenanceDiscardsInspectionFromPreviousRun(t *testing.T) {
	a, ctx := maintenanceTestAdapter(t)
	prior := command
	t.Cleanup(func() { command = prior })
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	installed := false
	command = func(_ context.Context, name string, _ ...string) (string, error) {
		if name == "sh" {
			installed = true
			return "", nil
		}
		close(entered)
		<-release // simulate an inspection completing after a run replacement
		return "", errors.New("old rule is absent")
	}
	done := make(chan struct{})
	go func() { defer close(done); a.maintainOnce(ctx) }()
	waitMaintenanceTest(t, entered, "inspection start")
	next, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.mu.Lock()
	a.runCtx = next
	a.hookReady = false
	a.mu.Unlock()
	unblock()
	waitMaintenanceTest(t, done, "stale inspection completion")
	if installed || a.hookReady || !a.updated.IsZero() {
		t.Fatal("old inspection changed the replacement run")
	}
}

func TestMaintenanceBusyLifecycleSkipsRepairAndRetries(t *testing.T) {
	a, ctx := maintenanceTestAdapter(t)
	prior := command
	t.Cleanup(func() { command = prior })
	checks, repairs := 0, 0
	command = func(_ context.Context, name string, _ ...string) (string, error) {
		if name == "sh" {
			repairs++
			return "", nil
		}
		checks++
		return "", errors.New("rule missing")
	}
	a.opMu.Lock()
	done := make(chan struct{})
	go func() { defer close(done); a.maintainOnce(ctx) }()
	select {
	case <-done:
		a.opMu.Unlock()
	case <-time.After(time.Second):
		a.opMu.Unlock()
		waitMaintenanceTest(t, done, "maintenance cleanup")
		t.Fatal("maintenance waited on a joining lifecycle operation")
	}
	if repairs != 0 {
		t.Fatal("maintenance wrote while another lifecycle operation owned the adapter")
	}
	a.maintainOnce(ctx)
	if checks != 2 || repairs != 1 || !a.hookReady {
		t.Fatalf("repair retry: checks=%d repairs=%d ready=%v", checks, repairs, a.hookReady)
	}
}

func TestMaintenanceRepairFailureKeepsRetryableState(t *testing.T) {
	a, ctx := maintenanceTestAdapter(t)
	prior := command
	t.Cleanup(func() { command = prior })
	failRepair := true
	command = func(_ context.Context, name string, _ ...string) (string, error) {
		if name == "sh" && !failRepair {
			return "", nil
		}
		return "", errors.New("not ready")
	}
	a.maintainOnce(ctx)
	if a.hookReady {
		t.Fatal("failed hook repair was advertised as ready")
	}
	failRepair = false
	a.maintainOnce(ctx)
	if !a.hookReady {
		t.Fatal("next maintenance did not retry failed hook repair")
	}
}
