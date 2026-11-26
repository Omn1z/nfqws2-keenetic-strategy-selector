package awgroute

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRoutingDNSGateRejectsOldGenerationAndCanceledWait(t *testing.T) {
	var gate routingDNSGate
	finish := gate.begin(true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if release, err := gate.acquire(ctx, gate.version(), true); release != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled wait acquired the policy: %v", err)
	}
	finish(nil)
	if release, err := gate.acquire(context.Background(), 0, true); release != nil || err == nil {
		t.Fatal("an old-generation learner acquired replacement sets")
	}
	release, err := gate.acquire(context.Background(), 1, true)
	if err != nil {
		t.Fatal(err)
	}
	release()
	release() // A duplicate completion cannot decrement another reader.
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if gate.readers != 0 {
		t.Fatalf("unbalanced readers: %d", gate.readers)
	}
}

func TestRoutingDNSGateDrainsLearningBeforeKernelReplacement(t *testing.T) {
	var gate routingDNSGate
	release, err := gate.acquire(context.Background(), 0, true)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan func(error), 1)
	go func() { entered <- gate.begin(true) }()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		gate.mu.Lock()
		applying := gate.applying
		gate.mu.Unlock()
		if applying {
			break
		}
		select {
		case <-deadline.C:
			release()
			t.Fatal("replacement never entered its readiness barrier")
		case <-tick.C:
		}
	}
	select {
	case finish := <-entered:
		finish(nil)
		release()
		t.Fatal("kernel replacement started while a DNS learner was writing")
	default:
	}
	if err := gate.verify(0); err == nil {
		t.Fatal("overlapping replacement was not detected before reply")
	}
	release()
	select {
	case finish := <-entered:
		finish(nil)
	case <-time.After(time.Second):
		t.Fatal("finished DNS learner did not release kernel replacement")
	}
}

func TestRoutingDNSGateFailedApplyBlocksAnswersUntilRecovery(t *testing.T) {
	svc := new(Service)
	failure := errors.New("firewall hook failed")
	finish := svc.routingDNSGate.begin(true)
	finish(failure)
	if state := svc.RoutingDNSReadiness(); state.Ready || state.Applying || state.Revision != 1 || state.Error == "" {
		t.Fatalf("failed policy was advertised as ready: %+v", state)
	}
	if release, err := svc.routingDNSGate.acquire(context.Background(), 1, true); release != nil || !errors.Is(err, failure) {
		t.Fatalf("failed policy delivered an answer: %v", err)
	}
	finish = svc.routingDNSGate.begin(false)
	finish(nil)
	if state := svc.RoutingDNSReadiness(); !state.Ready || state.Revision != 1 || state.Error != "" {
		t.Fatalf("successful recovery did not restore the same generation: %+v", state)
	}
}
