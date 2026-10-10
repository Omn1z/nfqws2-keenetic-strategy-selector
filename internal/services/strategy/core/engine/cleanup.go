package engine

import "nfqws2strategy/internal/tools/config"

// CleanupSandboxes removes every test sandbox's leftover iptables chains (for
// worker slots 0..maxWorker, which includes the baseline slot) and kills any
// orphaned test nfqws2 children.
//
// It only touches the tester's STRAT_* mangle chains, its exact worker-scoped
// RETURN guards in the main service's chains, and test nfqws2 processes launched
// into /tmp/nfqws2-strategy. It never flushes the main service's chains or stops
// its process. Safe and idempotent: call it at startup to repair a
// previous unclean exit (which would otherwise leave a stale exclude-connmark
// rule that makes the main nfqws2 skip connections), and on shutdown.
func CleanupSandboxes(cfg *config.Config, maxWorker int) {
	for w := 0; w <= maxWorker; w++ {
		NewSandbox(cfg, w).RulesDown()
	}
	killOrphanedNfqws()
}
