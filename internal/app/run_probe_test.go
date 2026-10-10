package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"nfqws2strategy/internal/tools/probe"
	"nfqws2strategy/internal/tools/store"
)

func TestProbeQueuedTarget(t *testing.T) {
	for _, tc := range []struct {
		name                string
		before, after       uint32
		beforeErr, afterErr error
		probeErr            string
		wantOK, wantFetch   bool
		wantErr             string
	}{
		{name: "real_queue_traffic", before: 8, after: 29, wantOK: true, wantFetch: true},
		{name: "success_via_VPN", before: 8, after: 8, wantFetch: true, wantErr: "не получила пакетов"},
		{name: "counter_wrap", before: ^uint32(0), after: 0, wantOK: true, wantFetch: true},
		{name: "queue_missing_before", beforeErr: errors.New("not bound"), wantErr: "до запроса"},
		{name: "queue_disappears", afterErr: errors.New("not bound"), wantFetch: true, wantErr: "после запроса"},
		{name: "network_failure_preserved", before: 8, after: 29, probeErr: "connection reset", wantFetch: true, wantErr: "connection reset"},
		{name: "network_and_queue_failure", before: 8, after: 8, probeErr: "timeout", wantFetch: true, wantErr: "timeout; тестовая NFQUEUE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls, fetched := 0, false
			counter := func() (uint32, error) {
				calls++
				if calls == 1 {
					return tc.before, tc.beforeErr
				}
				return tc.after, tc.afterErr
			}
			fetch := func(_ context.Context, host string) probe.Result {
				fetched = true
				return probe.Result{Host: host, Code: 200, Size: 131072, OK: tc.probeErr == "", Err: tc.probeErr}
			}
			r := probeQueuedTarget(context.Background(), "example.test", fetch, counter)
			if r.OK != tc.wantOK || fetched != tc.wantFetch || !strings.Contains(r.Err, tc.wantErr) {
				t.Fatalf("result=%+v fetched=%v", r, fetched)
			}
			if r.Host != "example.test" || (fetched && (r.Code != 200 || r.Size != 131072)) {
				t.Fatalf("lost diagnostic response: %+v", r)
			}
			wantCalls := 2
			if !tc.wantFetch {
				wantCalls = 1
			}
			if calls != wantCalls {
				t.Fatalf("counter calls=%d want=%d", calls, wantCalls)
			}
		})
	}
}

func TestLocalProbeFailureDoesNotSelectStrategy(t *testing.T) {
	local := classifyProbe("instagram.com", probe.Result{LocalError: true, Err: "dial tcp: cannot assign requested address"})
	if local.Blocked || local.Verdict != "local_error" {
		t.Fatalf("local bind failure classified as DPI: %+v", local)
	}
	blocked := classifyProbe("blocked.test", probe.Result{Err: "connection reset by peer"})
	reachable := classifyProbe("reachable.test", probe.Result{Code: 403, Size: 1234})
	got, err := blockedBaselineTargets([]TargetCheck{blocked, reachable, local})
	if err == nil || !strings.Contains(err.Error(), "instagram.com") || len(got) != 0 {
		t.Fatalf("incomplete baseline accepted: %v %v", got, err)
	}
	got, err = blockedBaselineTargets([]TargetCheck{blocked, reachable})
	if err != nil || !reflect.DeepEqual(got, []string{"blocked.test"}) {
		t.Fatalf("valid baseline rejected: %v %v", got, err)
	}
	got, err = blockedBaselineTargets([]TargetCheck{reachable})
	if err != nil || len(got) != 0 {
		t.Fatalf("reachable baseline: %v %v", got, err)
	}
}

func TestMergeSuccessfulReplacesChangedArguments(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a := &App{store: st}
	list, err := a.SaveList(&List{Name: "catalog regression", SuccessfulStrategies: []SavedStrategy{
		{StrategyID: "fixed-candidate", ArgLine: "old unsafe args", Coefficient: 100},
		{StrategyID: "unchanged-candidate", ArgLine: "unchanged args", Coefficient: 100},
	}})
	if err != nil {
		t.Fatal(err)
	}
	a.mergeSuccessful(list, &Run{ID: "fresh-run"}, []StrategyResult{
		{StrategyID: "fixed-candidate", ArgLine: "corrected args", Coefficient: 10, Success: true},
		{StrategyID: "unchanged-candidate", ArgLine: "unchanged args", Coefficient: 10, Success: true},
	})
	got, err := a.GetList(list.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.SuccessfulStrategies) != 2 {
		t.Fatalf("saved: %+v", got.SuccessfulStrategies)
	}
	for _, s := range got.SuccessfulStrategies {
		if s.StrategyID == "fixed-candidate" && (s.ArgLine != "corrected args" || s.RunID != "fresh-run") {
			t.Fatalf("old arguments survived a fresh successful test: %+v", s)
		}
		if s.StrategyID == "unchanged-candidate" && s.Coefficient != 100 {
			t.Fatalf("best measurement lost: %+v", s)
		}
	}
}
