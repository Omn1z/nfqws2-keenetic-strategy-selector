package app

import (
	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/services/awgroute"
)

// The AWG2 server manager + the router-side client/split-routing runtime now live
// in internal/services/awgroute. These type aliases + thin delegators keep the App
// surface the HTTP handlers call unchanged. Lifecycle (New / RepairRouting /
// TeardownRouting / StopAWG) is wired from app.New / app.Shutdown.

type (
	AWG2Status   = awgroute.AWG2Status
	EngineInfo   = awgroute.EngineInfo
	ClientStatus = awgroute.ClientStatus
)

func (a *App) AWG2StatusView() AWG2Status               { return a.awgroute.AWG2StatusView() }
func (a *App) AWG2SetConfig(in *awg.ServerConfig) error { return a.awgroute.AWG2SetConfig(in) }
func (a *App) AWG2Deploy() (awg.DeployResult, error)    { return a.awgroute.AWG2Deploy() }
func (a *App) AWG2RefreshStatus() (awg.Status, error)   { return a.awgroute.AWG2RefreshStatus() }
func (a *App) AWG2AddPeer(in awg.Peer) (awg.Peer, error) {
	return a.awgroute.AWG2AddPeer(in)
}
func (a *App) AWG2RemovePeer(id string) error { return a.awgroute.AWG2RemovePeer(id) }
func (a *App) AWG2ClientConfig(id string) (text, filename string, err error) {
	return a.awgroute.AWG2ClientConfig(id)
}

func (a *App) AWG2EngineInfo() EngineInfo         { return a.awgroute.AWG2EngineInfo() }
func (a *App) AWG2InstallEngine() (string, error) { return a.awgroute.AWG2InstallEngine() }
func (a *App) AWG2ClientUp() error                { return a.awgroute.AWG2ClientUp() }
func (a *App) AWG2ClientDown() error              { return a.awgroute.AWG2ClientDown() }

func (a *App) AWG2SetRouting(rc awg.RoutingConfig) error { return a.awgroute.AWG2SetRouting(rc) }
func (a *App) AWG2ApplyRouting() error                   { return a.awgroute.AWG2ApplyRouting() }
func (a *App) AWG2CommitRouting() error                  { return a.awgroute.AWG2CommitRouting() }
func (a *App) AWG2TeardownRouting() error                { return a.awgroute.AWG2TeardownRouting() }
