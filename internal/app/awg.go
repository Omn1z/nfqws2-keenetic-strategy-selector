package app

import (
	"context"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/services/awgroute"
	"nfqws2strategy/internal/services/tunnelroute"
)

// The AWG2 server manager + the router-side client/split-routing runtime now live
// in internal/services/awgroute. These type aliases + thin delegators keep the App
// surface the HTTP handlers call unchanged. Lifecycle (New / RepairRouting /
// TeardownRouting / StopAWG) is wired from app.New / app.Shutdown.

type (
	AWG2Status             = awgroute.AWG2Status
	EngineInfo             = awgroute.EngineInfo
	ClientStatus           = awgroute.ClientStatus
	AWG2DeployServerResult = awgroute.AWG2DeployServerResult
)

func (a *App) AWG2StatusView() AWG2Status           { return a.awgroute.AWG2StatusView() }
func (a *App) AWG2AddServer(name string) AWG2Status { return a.awgroute.AWG2AddServer(name) }
func (a *App) AWG2SelectServer(id string) error     { return a.awgroute.AWG2SelectServer(id) }
func (a *App) AWG2RenameServer(id, name string) error {
	return a.awgroute.AWG2RenameServer(id, name)
}
func (a *App) AWG2SetServerEnabled(id string, enabled bool) error {
	err := a.awgroute.AWG2SetServerEnabled(id, enabled)
	if err == nil {
		a.syncProxyTunnelRoutes(a.proxy.AWGFallback())
	}
	return err
}
func (a *App) AWG2Import(text, name string) (AWG2Status, error) {
	return a.awgroute.AWG2Import(text, name)
}
func (a *App) AWG2CreateWARP(ctx context.Context, opts awgroute.WARPCreateOptions) (AWG2Status, error) {
	return a.awgroute.AWG2CreateWARP(ctx, opts)
}
func (a *App) AWG2DeleteServer(id string) error {
	ifaces := a.awgroute.ClientIfaces()
	err := a.awgroute.AWG2DeleteServer(id)
	if err == nil {
		for _, iface := range ifaces {
			tunnelroute.DelTGFrontRoutes(iface)
		}
		a.syncProxyTunnelRoutes(a.proxy.AWGFallback())
	}
	return err
}
func (a *App) AWG2SetConfig(in *awg.ServerConfig) error { return a.awgroute.AWG2SetConfig(in) }
func (a *App) AWG2Deploy() (awg.DeployResult, error)    { return a.awgroute.AWG2Deploy() }
func (a *App) AWG2DeployServer(id string) (awg.DeployResult, error) {
	return a.awgroute.AWG2DeployServer(id)
}
func (a *App) AWG2DeployServers(ids []string) []AWG2DeployServerResult {
	return a.awgroute.AWG2DeployServers(ids)
}
func (a *App) AWG2RefreshStatus() (awg.Status, error) { return a.awgroute.AWG2RefreshStatus() }
func (a *App) AWG2AddPeer(in awg.Peer) (awg.Peer, error) {
	return a.awgroute.AWG2AddPeer(in)
}
func (a *App) AWG2RemovePeer(id string) error { return a.awgroute.AWG2RemovePeer(id) }
func (a *App) AWG2ClientConfig(id string) (text, filename string, err error) {
	return a.awgroute.AWG2ClientConfig(id)
}
func (a *App) AWG2ClientExport(id, format string) (text, filename, contentType string, err error) {
	return a.awgroute.AWG2ClientExport(id, format)
}

func (a *App) AWG2EngineInfo() EngineInfo         { return a.awgroute.AWG2EngineInfo() }
func (a *App) AWG2InstallEngine() (string, error) { return a.awgroute.AWG2InstallEngine() }
func (a *App) AWG2ClientUp() error {
	err := a.awgroute.AWG2ClientUp()
	if err == nil {
		a.syncProxyTunnelRoutes(a.proxy.AWGFallback())
	}
	return err
}
func (a *App) AWG2ClientDown() error {
	err := a.awgroute.AWG2ClientDown()
	if err == nil {
		a.syncProxyTunnelRoutes(a.proxy.AWGFallback())
	}
	return err
}

func (a *App) AWG2SetRouting(rc awg.RoutingConfig) error { return a.awgroute.AWG2SetRouting(rc) }
func (a *App) AWG2SetRoutingRules(rc awg.RoutingConfig) error {
	err := a.awgroute.AWG2SetRoutingRules(rc)
	if err == nil {
		a.syncProxyTunnelRoutes(a.proxy.AWGFallback())
	}
	return err
}
func (a *App) AWG2ApplyRouting() error    { return a.awgroute.AWG2ApplyRouting() }
func (a *App) AWG2CommitRouting() error   { return a.awgroute.AWG2CommitRouting() }
func (a *App) AWG2TeardownRouting() error { return a.awgroute.AWG2TeardownRouting() }

func (a *App) AWG2TraceStatus() awgroute.TraceStatus { return a.awgroute.TraceStatus() }
func (a *App) AWG2TraceSnapshot(since int64) []awgroute.TraceEntry {
	return a.awgroute.TraceSnapshot(since)
}
func (a *App) AWG2TraceSetEnabled(on bool) bool          { return a.awgroute.TraceSetEnabled(on) }
func (a *App) AWG2TraceClear()                           { a.awgroute.TraceClear() }
func (a *App) AWG2TraceCounters() awgroute.TraceCounters { return a.awgroute.TraceCounters() }
func (a *App) AWG2InsertTopRule(domain, route, name string) error {
	return a.awgroute.AWG2InsertTopRule(domain, route, name)
}
func (a *App) AWG2CopyRulesFromServer(fromID string) (int, error) {
	return a.awgroute.AWG2CopyRulesFromServer(fromID)
}
func (a *App) AWG2SpeedTest(ctx context.Context, opts awgroute.SpeedTestOptions) awgroute.SpeedTestResult {
	return a.awgroute.RunSpeedTest(ctx, opts)
}

type ProxyAWGFallback = ProxyTunnelFallback

func (a *App) ProxyAWGFallbackView() ProxyAWGFallback { return a.ProxyTunnelFallbackView() }

func (a *App) SetProxyAWGFallback(v string) {
	v = normalizeTunnelFallbackSel(v)
	a.proxy.SetAWGFallback(v)
	a.syncProxyTunnelRoutes(v)
}
