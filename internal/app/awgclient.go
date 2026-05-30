package app

// Router-side AWG2 client: install OUR self-built engine (amneziawg-go + awg)
// and bring up the local awg0 tunnel as a client of the deployed server. The
// OS-specific work lives in awgclient_{linux,other}.go.

import (
	"sync"
	"time"
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
func (a *App) AWG2EngineInfo() EngineInfo        { return a.awgEngineInfoOS() }
func (a *App) AWG2InstallEngine() (string, error) { return a.awgInstallEngineOS() }
func (a *App) AWG2ClientUp() error                { return a.awgClientUpOS() }
func (a *App) AWG2ClientDown() error              { return a.awgClientDownOS() }
func (a *App) awgClientStatus() *ClientStatus     { return a.awgClientStatusOS() }

// awgRouteState holds the split-routing runtime (dead-man's-switch + refresher).
type awgRouteState struct {
	mu          sync.Mutex
	rollback    *time.Timer
	stopRefresh chan struct{}
	active      bool
}

func (a *App) AWG2ApplyRouting() error    { return a.awgApplyRoutingOS() }
func (a *App) AWG2CommitRouting() error   { return a.awgCommitRoutingOS() }
func (a *App) AWG2TeardownRouting() error { return a.awgTeardownRoutingOS() }
func (a *App) awgRepairRouting()          { a.awgRepairRoutingOS() }
func (a *App) awgTeardownRouting()        { _ = a.awgTeardownRoutingOS() }
