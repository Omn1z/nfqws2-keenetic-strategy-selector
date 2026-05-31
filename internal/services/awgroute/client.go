package awgroute

// Router-side AWG2 client: install OUR self-built engine (amneziawg-go + awg)
// and bring up the local awg0 tunnel as a client of the deployed server. The
// OS-specific work lives in awgclient_{linux,other}.go.

import (
	"sync"
	"time"

	"nfqws2strategy/internal/services/awg"
)

// EngineInfo reports the installed userspace AmneziaWG engine on the router.
type EngineInfo struct {
	Installed  bool   `json:"installed"`
	AwgVersion string `json:"awg_version"`
	Arch       string `json:"arch"`
	Supported  bool   `json:"supported"` // an engine asset exists for this arch
	TunOK      bool   `json:"tun_ok"`    // /dev/net/tun present
	Error      string `json:"error,omitempty"`
}

// ClientStatus is the local awg0 tunnel state (from `awg show awg0`).
type ClientStatus struct {
	Running       bool   `json:"running"`
	IfacePresent  bool   `json:"iface_present"`
	LastHandshake int64  `json:"last_handshake"`
	RxBytes       int64  `json:"rx_bytes"`
	TxBytes       int64  `json:"tx_bytes"`
	Endpoint      string `json:"endpoint"`
	Address       string `json:"address"`
	MTU           int    `json:"mtu"`
	Connected     bool   `json:"connected"` // handshake within ~180s
	Error         string `json:"error,omitempty"`
}

// Public app methods (delegating to the OS impl) used by the server handlers.
func (svc *Service) AWG2EngineInfo() EngineInfo         { return svc.awgEngineInfoOS() }
func (svc *Service) AWG2InstallEngine() (string, error) { return svc.awgInstallEngineOS() }
func (svc *Service) awgClientStatus() *ClientStatus     { return svc.awgClientStatusOS() }

// AWG2ClientUp brings up the local tunnel and persists Client.Enabled=true so it
// autostarts after a panel restart.
func (svc *Service) AWG2ClientUp() error {
	if err := svc.awgClientUpOS(); err != nil {
		return err
	}
	svc.awg.SetClientEnabled(true)
	svc.awgSave()
	return nil
}

// AWG2ClientDown tears down split-routing first (the table points at awg0, which
// is about to disappear), clears the autostart flag, then drops the tunnel.
func (svc *Service) AWG2ClientDown() error {
	svc.awgTeardownRouting()
	svc.awg.SetClientEnabled(false)
	svc.awgSave()
	return svc.awgClientDownOS()
}

// awgRouteState holds the split-routing runtime (dead-man's-switch + refresher
// + the optional domain-mask DNS proxy).
type awgRouteState struct {
	mu          sync.Mutex
	rollback    *time.Timer
	stopRefresh chan struct{}
	active      bool
	dnsProxy    *awg.DNSProxy
}

func (svc *Service) AWG2ApplyRouting() error { return svc.awgApplyRoutingOS() }

// AWG2CommitRouting disarms the dead-man's switch and marks routing committed so
// it auto-applies after a restart/reboot.
func (svc *Service) AWG2CommitRouting() error {
	if err := svc.awgCommitRoutingOS(); err != nil {
		return err
	}
	svc.awg.SetRoutingActive(true)
	svc.awgSave()
	return nil
}

// AWG2TeardownRouting is the explicit "снять маршрутизацию" action — it clears
// the committed flag so routing does NOT come back on the next boot.
func (svc *Service) AWG2TeardownRouting() error {
	svc.awg.SetRoutingActive(false)
	svc.awgSave()
	return svc.awgTeardownRoutingOS()
}

func (svc *Service) awgRepairRouting() { svc.awgRepairRoutingOS() }

// awgTeardownRouting is the internal teardown (e.g. on client-down/shutdown). It
// does NOT clear the committed flag, so routing restores when the tunnel returns.
func (svc *Service) awgTeardownRouting() { _ = svc.awgTeardownRoutingOS() }
