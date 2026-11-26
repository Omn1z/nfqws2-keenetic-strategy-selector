package awgroute

import (
	"errors"
	"testing"
)

func TestClientRoutingRecoveryReinstallsFailedSetsBeforeReady(t *testing.T) {
	for _, cause := range []string{"set installation failed", "DNS proxy failed to start", "firewall hook failed"} {
		t.Run(cause, func(t *testing.T) {
			svc := new(Service)
			finish := svc.routingDNSGate.begin(true)
			finish(errors.New(cause))
			calls := 0
			failedRestore := errors.New("recovery set installation failed")
			restore := func() error { calls++; return failedRestore }
			wasReady := svc.RoutingDNSReadiness().Ready
			finish = svc.routingDNSGate.begin(false)
			err := awgRestoreRoutingSets(false, wasReady, restore) // Existing hook.
			finish(err)
			if !errors.Is(err, failedRestore) || calls != 1 || svc.RoutingDNSReadiness().Ready {
				t.Fatalf("existing hook concealed failed sets: calls=%d err=%v readiness=%+v", calls, err, svc.RoutingDNSReadiness())
			}
			// A successful retry must perform the installation again, preserve
			// this policy generation, and only then allow normal recovery.
			wasReady = svc.RoutingDNSReadiness().Ready
			finish = svc.routingDNSGate.begin(false)
			err = awgRestoreRoutingSets(false, wasReady, func() error { calls++; return nil })
			finish(err)
			if err != nil || calls != 2 || !svc.RoutingDNSReadiness().Ready || svc.RoutingDNSReadiness().Revision != 1 {
				t.Fatalf("complete recovery failed: calls=%d err=%v readiness=%+v", calls, err, svc.RoutingDNSReadiness())
			}
			// Snapshot readiness before begin: the gate is applying during the
			// callback, but a healthy reconnect must not flush learned sets.
			wasReady = svc.RoutingDNSReadiness().Ready
			finish = svc.routingDNSGate.begin(false)
			err = awgRestoreRoutingSets(false, wasReady, func() error { calls++; return nil })
			finish(err)
			if calls != 2 || err != nil || !svc.RoutingDNSReadiness().Ready {
				t.Fatalf("healthy recovery rewrote learned sets: calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestClientRoutingRecoveryMissingHookRequiresSetsEvenWhenHealthy(t *testing.T) {
	svc := new(Service)
	wasReady := svc.RoutingDNSReadiness().Ready
	finish := svc.routingDNSGate.begin(false)
	failure := errors.New("set initialization failed")
	calls := 0
	err := awgRestoreRoutingSets(true, wasReady, func() error { calls++; return failure })
	finish(err)
	if calls != 1 || !errors.Is(err, failure) || svc.RoutingDNSReadiness().Ready {
		t.Fatalf("missing hook bypassed initialization: calls=%d err=%v readiness=%+v", calls, err, svc.RoutingDNSReadiness())
	}
}
