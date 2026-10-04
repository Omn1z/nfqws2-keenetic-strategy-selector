package dnsroute

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

func TestShadowDiagnosticsPassiveSnapshotDoesNotWaitForDiscovery(t *testing.T) {
	a := New(nil, nil)
	a.cfg.Version = "v-test"
	a.shadow.discoveryMu.Lock()
	defer a.shadow.discoveryMu.Unlock()
	done := make(chan ShadowDiagnostics, 1)
	go func() { done <- a.ShadowDiagnostics() }()
	select {
	case snapshot := <-done:
		if snapshot.Enabled || snapshot.Version != 1 || snapshot.AppVersion != "v-test" || snapshot.Platform != runtime.GOOS+"/"+runtime.GOARCH || snapshot.InProgress || snapshot.Attempts == nil || len(snapshot.Attempts) != 0 || snapshot.CapturedAt.IsZero() {
			t.Fatalf("invalid passive initial snapshot: %+v", snapshot)
		}
	case <-time.After(time.Second):
		t.Fatal("status waited for discovery instead of reading independent diagnostics")
	}
	if shadowDiagnosticEnabled(context.Background()) {
		t.Fatal("plain context unexpectedly enabled capture")
	}
	shadowDiagnosticEvent(context.Background(), "ignored", "no discovery", time.Second)
	if len(a.ShadowDiagnostics().Attempts) != 0 {
		t.Fatal("reading diagnostics initiated an attempt")
	}
}

func TestShadowDiagnosticsDefaultOffHasNoCollectionOrAllocations(t *testing.T) {
	var state shadowDiagnosticState
	parent := context.Background()
	state.mu.Lock() // Disabled begin/events must not even take the history mutex.
	done := make(chan bool, 1)
	go func() {
		ctx, finish := state.begin(parent)
		shadowDiagnosticEvent(ctx, "ignored", "disabled", 0)
		finish([]string{"192.0.2.53"}, errors.New("ignored"), time.Now())
		done <- ctx == parent && !shadowDiagnosticEnabled(ctx)
	}()
	select {
	case unchanged := <-done:
		if !unchanged {
			t.Error("disabled collector changed context")
		}
	case <-time.After(time.Second):
		t.Error("disabled collection waited for the history mutex")
	}
	state.mu.Unlock()
	if got := state.snapshot(); got.Enabled || got.InProgress || len(got.Attempts) != 0 || state.nextID != 0 {
		t.Fatal("diagnostics recorded while disabled", got)
	}
	if allocations := testing.AllocsPerRun(100, func() {
		ctx, finish := state.begin(parent)
		shadowDiagnosticEvent(ctx, "ignored", "disabled", 0)
		finish(nil, nil, time.Time{})
	}); allocations != 0 {
		t.Fatalf("disabled diagnostic path allocated: %v", allocations)
	}
}

func TestShadowDiagnosticsSwitchClearsAndRejectsOldEnableCycle(t *testing.T) {
	a := New(nil, nil)
	a.shadow.discoveryMu.Lock()
	defer a.shadow.discoveryMu.Unlock()
	toggled := make(chan struct{})
	go func() { a.SetShadowDiagnostics(true); close(toggled) }()
	select {
	case <-toggled:
	case <-time.After(time.Second):
		t.Fatal("diagnostic toggle waited for discovery")
	}
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	old, finishOld := a.shadow.diagnostics.begin(parent)
	oldCollector := old.Value(shadowDiagnosticContextKey{}).(shadowDiagnosticContext)
	shadowDiagnosticEvent(old, "old", "clear me", 0)
	oldID := a.ShadowDiagnostics().Attempts[0].ID
	a.SetShadowDiagnostics(true)
	if got := a.ShadowDiagnostics(); !got.Enabled || len(got.Attempts) != 1 {
		t.Fatal("idempotent enable lost history", got)
	}
	a.SetShadowDiagnostics(false)
	if shadowDiagnosticEnabled(old) || old.Err() != nil || oldCollector.session.ctx.Err() == nil {
		t.Fatal("switch-off did not cancel only optional diagnostics")
	}
	if got := a.ShadowDiagnostics(); got.Enabled || got.InProgress || len(got.Attempts) != 0 {
		t.Fatal("switch-off retained history", got)
	}
	a.SetShadowDiagnostics(true)
	ctx, finish := a.shadow.diagnostics.begin(context.Background())
	if shadowDiagnosticEnabled(old) || !shadowDiagnosticEnabled(ctx) {
		t.Fatal("old context became enabled again")
	}
	shadowDiagnosticEvent(old, "late", "must not reach new cycle", 0)
	finishOld([]string{"192.0.2.99"}, errors.New("old error"), time.Now())
	got := a.ShadowDiagnostics()
	if !got.Enabled || len(got.Attempts) != 1 || got.Attempts[0].ID <= oldID || got.Attempts[0].FinishedAt != nil || len(got.Attempts[0].Events) != 0 || len(got.Attempts[0].Servers) != 0 {
		t.Fatal("old completion affected the new cycle", got)
	}
	shadowDiagnosticEvent(ctx, "new", "new cycle", 0)
	finish(nil, nil, time.Time{})
	if got := a.ShadowDiagnostics(); got.InProgress || len(got.Attempts[0].Events) != 1 {
		t.Fatal("new cycle did not collect", got)
	}
	a.SetShadowDiagnostics(false)
	a.SetShadowDiagnostics(false)
	if got := New(nil, nil).ShadowDiagnostics(); got.Enabled {
		t.Fatal("diagnostic preference persisted across new runtime")
	}
}

func TestShadowDiagnosticsConcurrentToggleAndCollection(t *testing.T) {
	var state shadowDiagnosticState
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 200 {
				ctx, finish := state.begin(context.Background())
				shadowDiagnosticEvent(ctx, "event", "bounded metadata", 0)
				finish(nil, nil, time.Time{})
				snapshot := state.snapshot()
				if len(snapshot.Attempts) > shadowDiagnosticAttempts || !snapshot.Enabled && len(snapshot.Attempts) != 0 {
					t.Error("unbounded or disabled history", snapshot)
				}
			}
		}()
	}
	for range 200 {
		state.setEnabled(true)
		state.setEnabled(false)
	}
	workers.Wait()
	state.setEnabled(false)
	if got := state.snapshot(); got.Enabled || got.InProgress || len(got.Attempts) != 0 {
		t.Fatal("final switch-off left history", got)
	}
}

func TestShadowDiagnosticsCopiesCompletedAndInflightState(t *testing.T) {
	var state shadowDiagnosticState
	state.setEnabled(true)
	parent, cancel := context.WithCancel(context.Background())
	ctx, finish := state.begin(parent)
	if !shadowDiagnosticEnabled(ctx) {
		t.Fatal("discovery context did not enable diagnostics")
	}
	shadowDiagnosticEvent(ctx, "wire.packet", "eth3 192.0.2.1:67 -> 192.0.2.2:68", 4*time.Millisecond)
	inflight := state.snapshot()
	if !inflight.InProgress || len(inflight.Attempts) != 1 || inflight.Attempts[0].FinishedAt != nil || inflight.Attempts[0].Events[0].DurationMS != 4 {
		t.Fatalf("missing inflight metadata: %+v", inflight)
	}
	cancel()
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("collector detached discovery cancellation")
	}
	servers := []string{"192.0.2.53:53"}
	next := time.Now().Add(30 * time.Second)
	finish(servers, context.Canceled, next)
	servers[0] = "mutated"
	shadowDiagnosticEvent(ctx, "late", "must be ignored", 0)
	finish(nil, nil, time.Time{})
	snapshot := state.snapshot()
	attempt := snapshot.Attempts[0]
	if snapshot.InProgress || attempt.FinishedAt == nil || attempt.NextRetryAt == nil || attempt.Error != context.Canceled.Error() || attempt.Servers[0] != "192.0.2.53:53" || len(attempt.Events) != 1 {
		t.Fatalf("completion changed or retained caller state: %+v", attempt)
	}
	if !attempt.NextRetryAt.Equal(next) || attempt.StartedAt.Location() != time.UTC || attempt.FinishedAt.Location() != time.UTC {
		t.Fatalf("invalid timestamp conversion: %+v", attempt)
	}
	snapshot.Attempts[0].Servers[0] = "external change"
	snapshot.Attempts[0].Events[0].Message = "external change"
	*snapshot.Attempts[0].FinishedAt = time.Time{}
	*snapshot.Attempts[0].NextRetryAt = time.Time{}
	unchanged := state.snapshot().Attempts[0]
	if unchanged.Servers[0] != "192.0.2.53:53" || unchanged.Events[0].Message != "eth3 192.0.2.1:67 -> 192.0.2.2:68" || unchanged.FinishedAt.IsZero() || unchanged.NextRetryAt.IsZero() {
		t.Fatalf("snapshot retained mutable references: %+v", unchanged)
	}
}

func TestShadowDiagnosticsBoundsHistoryEventsAndUTF8(t *testing.T) {
	var state shadowDiagnosticState
	state.setEnabled(true)
	stale, _ := state.begin(context.Background())
	for i := 0; i < 10; i++ {
		ctx, finish := state.begin(context.Background())
		for n := 0; n < 80; n++ {
			shadowDiagnosticEvent(ctx, fmt.Sprint(n), strings.Repeat("Ж", 400)+"\r\nsecret", time.Second)
		}
		finish([]string{"1", "2", "3", "4", "5", "6", "7", "8", "9"}, errors.New(strings.Repeat("Я", 400)), time.Time{})
	}
	shadowDiagnosticEvent(stale, "stale", "must not reach a new attempt", 0)
	snapshot := state.snapshot()
	if len(snapshot.Attempts) != 6 || snapshot.Attempts[0].ID != 6 || snapshot.Attempts[5].ID != 11 || snapshot.InProgress {
		t.Fatalf("unbounded/incorrect attempt history: %+v", snapshot)
	}
	for _, attempt := range snapshot.Attempts {
		if len(attempt.Events) != 48 || attempt.Events[0].Stage != "32" || attempt.Events[47].Stage != "79" || len(attempt.Servers) != 8 || len(attempt.Error) > 512 || !utf8.ValidString(attempt.Error) {
			t.Fatalf("unbounded diagnostics: %+v", attempt)
		}
		for _, event := range attempt.Events {
			if len(event.Message) > 512 || !utf8.ValidString(event.Message) || strings.ContainsAny(event.Message, "\r\n") {
				t.Fatalf("unbounded/invalid message: %q", event.Message)
			}
		}
	}
	if got := shadowDiagnosticText("ok\r\n\x00Жtail", 6); got != "ok" {
		// The cut ends within Ж: controls become spaces and partial UTF-8 is removed.
		t.Fatalf("unexpected safe truncation: %q", got)
	}
	raw, err := json.Marshal(snapshot)
	if err != nil || !strings.Contains(string(raw), `"version":1`) || strings.Contains(string(raw), "secret") {
		t.Fatalf("invalid diagnostic export: %v", err)
	}
}

func TestShadowDiagnosticsConcurrentSnapshotAndEvents(t *testing.T) {
	var state shadowDiagnosticState
	state.setEnabled(true)
	ctx, finish := state.begin(context.Background())
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := 0; i < 200; i++ {
				shadowDiagnosticEvent(ctx, "wire.packet", "bounded packet metadata", 0)
				snapshot := state.snapshot()
				if len(snapshot.Attempts) > 0 && len(snapshot.Attempts[0].Events) > 0 {
					snapshot.Attempts[0].Events[0].Message = "caller mutation"
				}
			}
		}()
	}
	workers.Wait()
	finish(nil, nil, time.Time{})
	attempt := state.snapshot().Attempts[0]
	if len(attempt.Events) != shadowDiagnosticEvents {
		t.Fatalf("unexpected concurrent event count: %d", len(attempt.Events))
	}
	for _, event := range attempt.Events {
		if event.Message != "bounded packet metadata" {
			t.Fatalf("snapshot mutation escaped: %q", event.Message)
		}
	}
}
