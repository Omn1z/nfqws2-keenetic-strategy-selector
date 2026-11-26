//go:build linux

package awgroute

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDNSLearnScriptDeduplicatesAndValidatesDestinations(t *testing.T) {
	script, err := awgDNSLearnScript([]ipsetAddReq{{set: "awgm_001", ip: "203.0.113.19"}, {set: "awgm_001", ip: "203.0.113.19"}, {set: "awg2_inc_6", ip: "2001:db8::19"}})
	if err != nil || script != "add awgm_001 203.0.113.19 -exist\nadd awg2_inc_6 2001:db8::19 -exist\n" {
		t.Fatalf("unexpected batch: %q %v", script, err)
	}
	for _, request := range []ipsetAddReq{{set: "awgm_001\nflush awg2_inc", ip: "203.0.113.19"}, {set: strings.Repeat("x", 32), ip: "203.0.113.19"}, {set: "awgm_001", ip: "203.0.113.19; true"}, {set: "awgm_001", ip: "0.0.0.0"}} {
		if script, err := awgDNSLearnScript([]ipsetAddReq{request}); err == nil || script != "" {
			t.Fatalf("invalid command was accepted: %q %v", script, err)
		}
	}
}

func TestDNSLearningMemoAvoidsRepeatedForksAndInvalidatesOnRestore(t *testing.T) {
	svc := new(Service)
	requests := []ipsetAddReq{{set: "awgm_001", ip: "203.0.113.19"}}
	calls := 0
	run := func(context.Context, string, string) (string, error) { calls++; return "", nil }
	for i := 0; i < 3; i++ {
		if err := svc.awgIPSetLearnWith(context.Background(), requests, run); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("unchanged DNS answers ran %d commands, want one", calls)
	}
	finish := svc.routingDNSGate.begin(false)
	finish(nil)
	if err := svc.awgIPSetLearnWith(context.Background(), requests, run); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("same-generation kernel restore did not invalidate memo: %d", calls)
	}
}

func TestFailedDNSLearningIsNotMemoized(t *testing.T) {
	svc := new(Service)
	requests := []ipsetAddReq{{set: "awgm_001", ip: "203.0.113.19"}}
	calls := 0
	failure := errors.New("kernel rejected set")
	run := func(context.Context, string, string) (string, error) { calls++; return "", failure }
	for i := 0; i < 2; i++ {
		if err := svc.awgIPSetLearnWith(context.Background(), requests, run); !errors.Is(err, failure) {
			t.Fatalf("route failure was hidden: %v", err)
		}
	}
	if calls != 2 {
		t.Fatalf("a failed add was memoized: %d", calls)
	}
}

func TestDNSLearningMemoDoesNotPublishAcrossKernelReplacement(t *testing.T) {
	svc := new(Service)
	requests := []ipsetAddReq{{set: "awgm_001", ip: "203.0.113.19"}}
	entered, resume := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- svc.awgIPSetLearnWith(context.Background(), requests, func(context.Context, string, string) (string, error) {
			close(entered)
			<-resume
			return "", nil
		})
	}()
	<-entered
	finish := svc.routingDNSGate.begin(false)
	finish(nil)
	close(resume)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("old writer did not finish")
	}
	calls := 0
	if err := svc.awgIPSetLearnWith(context.Background(), requests, func(context.Context, string, string) (string, error) { calls++; return "", nil }); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("old success was cached for replacement kernel sets")
	}
}

func TestDNSLearningBoundsOnlyRoutedDestinations(t *testing.T) {
	requests := make([]ipsetAddReq, 65)
	for i := range requests {
		requests[i] = ipsetAddReq{set: "awgm_001", ip: "203.0.113." + strconv.Itoa(i+1)}
	}
	if script, err := awgDNSLearnScript(requests); script != "" || err == nil {
		t.Fatalf("unbounded routed answer accepted: %q %v", script, err)
	}
	if script, err := awgDNSLearnScript(requests[:64]); script == "" || err != nil {
		t.Fatalf("bounded routed answer rejected: %q %v", script, err)
	}
}

func TestQueuedDNSLearningDrainsWithoutForkAfterReplacementStarts(t *testing.T) {
	svc := new(Service)
	g := &svc.routingDNSGate
	g.learnToken = make(chan struct{}, 1)
	g.learnToken <- struct{}{}
	release, err := g.acquire(context.Background(), 0, true)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		err := svc.awgIPSetLearnWith(context.Background(), []ipsetAddReq{{set: "awgm_001", ip: "192.0.2.21"}}, func(context.Context, string, string) (string, error) {
			t.Error("queued learner forked after replacement started")
			return "", nil
		})
		release()
		done <- err
	}()
	began := make(chan func(error), 1)
	go func() { began <- g.begin(false) }()
	deadline := time.Now().Add(time.Second)
	for {
		g.mu.Lock()
		applying := g.applying
		g.mu.Unlock()
		if applying {
			break
		}
		if time.Now().After(deadline) {
			<-g.learnToken
			t.Fatal("replacement never started")
		}
		time.Sleep(time.Millisecond)
	}
	<-g.learnToken
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("queued learner accepted stale policy")
		}
	case <-time.After(time.Second):
		t.Fatal("queued learner did not drain")
	}
	select {
	case finish := <-began:
		finish(nil)
	case <-time.After(time.Second):
		t.Fatal("drained learner kept replacement blocked")
	}
}

func TestSetInstallFailureIsReturnedAndDoesNotContinue(t *testing.T) {
	failure := errors.New("set restore failed")
	calls := 0
	err := awgInstallSetScripts(awgSetPlan{globalScript: "create awg2_inc hash:net\n", sourceScript: "create awg2_z0 hash:net\n"}, func(command, script string) (string, error) {
		calls++
		return "kernel rejected set", failure
	})
	if !errors.Is(err, failure) || calls != 1 {
		t.Fatalf("failed global restore was hidden or source restore continued: %v, calls=%d", err, calls)
	}
}

func TestMultiRuleReadinessRecognizesOnlyExactOwnedSelector(t *testing.T) {
	tunnel := awgMultiTunnel{Table: 901, Mark: awgMultiMark(1)}
	pref := awgMultiPref(tunnel)
	valid := strconv.Itoa(pref) + ": from all fwmark " + tunnel.Mark + "/" + awgMultiMarkMask + " lookup 901\n"
	if !awgMultiHasRouteRule(valid, tunnel) {
		t.Fatal("existing valid rule was not recognized")
	}
	for _, invalid := range []string{
		strings.Replace(valid, "lookup 901", "lookup 902", 1),
		strings.Replace(valid, awgMultiMarkMask, "0xffffffff", 1),
		strings.Replace(valid, strconv.Itoa(pref)+":", strconv.Itoa(pref+1)+":", 1),
		"100: from all lookup 901\n",
	} {
		if awgMultiHasRouteRule(invalid, tunnel) {
			t.Fatalf("foreign selector was accepted: %q", invalid)
		}
	}
}
