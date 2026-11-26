package awgroute

// A hook file can survive an incomplete set/proxy installation. Recovery must
// restore its prerequisites while readiness is failed; healthy reconnects keep
// their learned sets intact. Snapshot wasReady before entering the DNS gate.
func awgRestoreRoutingSets(hookMissing, wasReady bool, restore func() error) error {
	if hookMissing || !wasReady {
		return restore()
	}
	return nil
}
