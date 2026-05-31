package app

import (
	"nfqws2strategy/internal/services/monitor"
	"nfqws2strategy/internal/tools/tcpdump"
)

// Live network monitoring (dashboard, connections, device activity, device
// traces, tcpdump captures) now lives in internal/services/monitor. These type
// aliases + thin delegators keep the App surface the HTTP handlers call
// unchanged.

type (
	DashboardView      = monitor.DashboardView
	ConnectionsView    = monitor.ConnectionsView
	DeviceActivityView = monitor.DeviceActivityView
	Trace              = monitor.Trace
	TraceEvent         = monitor.TraceEvent
	TraceConn          = monitor.TraceConn
	Pcap               = monitor.Pcap
)

// ErrNeedTcpdump re-exports the shared sentinel so the server's
// errors.Is(err, app.ErrNeedTcpdump) keeps working for both the device pcap
// capture and the ClientHello blob capture.
var ErrNeedTcpdump = tcpdump.ErrNeedInstall

func (a *App) Dashboard(host string) DashboardView         { return a.monitor.Dashboard(host) }
func (a *App) Connections() (ConnectionsView, error)       { return a.monitor.Connections() }
func (a *App) DeviceActivity() (DeviceActivityView, error) { return a.monitor.DeviceActivity() }

func (a *App) StartDeviceTrace(ip string, seconds int) (*Trace, error) {
	return a.monitor.StartDeviceTrace(ip, seconds)
}
func (a *App) GetTrace(id string) (*Trace, bool) { return a.monitor.GetTrace(id) }

func (a *App) StartPcap(ip string, seconds int) (*Pcap, error) {
	return a.monitor.StartPcap(ip, seconds)
}
func (a *App) GetPcap(id string) (*Pcap, bool)                 { return a.monitor.GetPcap(id) }
func (a *App) PcapFile(id string) (path, name string, ok bool) { return a.monitor.PcapFile(id) }

// InstallPackage installs a whitelisted opkg package (currently only tcpdump),
// surfaced by the device-capture install prompt.
func (a *App) InstallPackage(pkg string) (string, error) { return tcpdump.Install(pkg) }
