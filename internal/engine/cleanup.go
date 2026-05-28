package engine

import "nfqws2strategy/internal/config"

// CleanupSandboxes removes every test sandbox's leftover iptables chains (for
// worker slots 0..maxWorker, which includes the baseline slot) and kills any
// orphaned test nfqws2 children.
//
// It only ever touches the tester's own STRAT_* mangle chains and the nfqws2
// processes launched into /tmp/nfqws2-strategy — the main nfqws2 service (queue
// 300) is never affected. Safe and idempotent: call it at startup to repair a
// previous unclean exit (which would otherwise leave a stale exclude-connmark
// rule that makes the main nfqws2 skip connections), and on shutdown.
func CleanupSandboxes(cfg *config.Config, maxWorker int) {
	for w := 0; w <= maxWorker; w++ {
		NewSandbox(cfg, w).RulesDown()
	}
	killOrphanedNfqws()
}
