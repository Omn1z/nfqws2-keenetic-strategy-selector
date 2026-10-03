package awgroute

// Read readiness before the caller begins its refresh. The routine branch
// restores routes and executes an existing hook; it cannot recover a missing
// DNS learner or a set installation that failed on the previous tick.
func (svc *Service) awgMultiNeedsFullRefresh(hookMissing bool, ticks int) bool {
	return hookMissing || ticks%15 == 0 || !svc.RoutingDNSReadiness().Ready
}

// Audit is read-only. Do not begin a write epoch for a healthy policy: doing
// so blocks every DNS observer and discards its confirmed-ipset memo even
// when nothing in the kernel needs changing. A real repair remains gated.
func (svc *Service) awgMaintainMultiPolicy(hookMissing bool, ticks int, audit func() bool, refresh, repair func() error) error {
	ready := svc.RoutingDNSReadiness().Ready
	if ready && !hookMissing && audit() {
		if ticks%15 != 0 {
			return nil
		}
		finish := svc.routingDNSGate.begin(false)
		err := refresh()
		finish(err)
		return err
	}
	finish := svc.routingDNSGate.begin(false)
	err := repair()
	finish(err)
	return err
}
