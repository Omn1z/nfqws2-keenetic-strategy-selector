// Package awgroute owns the AWG2 capability end-to-end: the remote AmneziaWG 2.0
// server manager (SSH deploy / peers / status) plus the router-side client and
// split-routing runtime — engine install, awg0 tunnel up/down, and the policy
// routing (fwmark → table → awg0) guarded by a server-side dead-man's switch.
// The OS-specific work lives in the *_linux.go / *_other.go files; this package
// was extracted from internal/app, which now keeps thin delegators.
package awgroute

import (
	"os"
	"strings"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/config"
	"nfqws2strategy/internal/tools/store"
)

// Service owns the AWG2 server manager + the router-side client/split-routing
// runtime (dead-man's-switch state).
type Service struct {
	cfg   *config.Config
	store *store.Store
	awg   *awg.Manager
	route awgRouteState
}

// New loads the persisted AWG2 config, creates the server manager, and — if the
// client tunnel was enabled — autostarts it and re-applies committed routing. It
// NEVER auto-deploys the remote VPS (that is always an explicit user action).
func New(cfg *config.Config, st *store.Store) *Service {
	svc := &Service{cfg: cfg, store: st}
	svc.initAWG()
	return svc
}

// RepairRouting clears any AWG2 routing state leaked by an unclean exit. Called
// at startup, after the manager exists.
func (svc *Service) RepairRouting() { svc.awgRepairRouting() }

// TeardownRouting removes the live split-routing without clearing the committed
// flag (so it restores when the tunnel returns). Called on shutdown.
func (svc *Service) TeardownRouting() { svc.awgTeardownRouting() }

// opkgBin returns the Entware opkg path (used by the AWG2 engine install).
func opkgBin() string {
	if _, err := os.Stat("/opt/bin/opkg"); err == nil {
		return "/opt/bin/opkg"
	}
	return "opkg"
}

// lastLines keeps at most the final n lines, for compact UI display.
func lastLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return s
	}
	return strings.Join(lines[len(lines)-n:], "\n")
}
