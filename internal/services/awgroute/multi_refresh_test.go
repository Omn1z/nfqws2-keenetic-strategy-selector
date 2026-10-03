package awgroute

import (
	"errors"
	"testing"
)

func TestMultiRefreshFailedInstallCannotRecoverThroughExistingHookOnly(t *testing.T) {
	for _, cause := range []string{"DNS learner failed to start", "ipset restore failed", "firewall hook failed"} {
		t.Run(cause, func(t *testing.T) {
			svc := &Service{}
			finish := svc.routingDNSGate.begin(false)
			finish(errors.New(cause))
			// A failed full refresh can still leave its hook file present. The
			// next tick must retry every prerequisite, including the learner.
			if !svc.awgMultiNeedsFullRefresh(false, 16) {
				t.Fatal("a failed prerequisite was allowed to recover by executing the existing hook only")
			}
			// Another failed attempt must keep choosing full recovery. A
			// successful full attempt releases the normal cheap route refresh.
			finish = svc.routingDNSGate.begin(false)
			finish(errors.New(cause))
			if !svc.awgMultiNeedsFullRefresh(false, 17) {
				t.Fatal("full recovery stopped retrying after its prerequisite failed again")
			}
			finish = svc.routingDNSGate.begin(false)
			finish(nil)
			if svc.awgMultiNeedsFullRefresh(false, 18) {
				t.Fatal("a successful recovery did not restore the normal refresh branch")
			}
		})
	}
}

func TestMultiRefreshHealthyPolicyRetainsPeriodicAndMissingHookRecovery(t *testing.T) {
	svc := &Service{}
	finish := svc.routingDNSGate.begin(false)
	finish(nil)
	if svc.awgMultiNeedsFullRefresh(false, 14) {
		t.Fatal("a healthy existing policy unnecessarily chose full recovery")
	}
	if !svc.awgMultiNeedsFullRefresh(false, 15) {
		t.Fatal("the periodic complete refresh was skipped")
	}
	if !svc.awgMultiNeedsFullRefresh(true, 16) {
		t.Fatal("a missing hook did not require full recovery")
	}
}
