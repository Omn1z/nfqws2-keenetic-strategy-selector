// Package monitor assembles the live network views the UI polls: the dashboard
// home snapshot (Telegram proxy status + conntrack/NFQUEUE/WAN counters), the full
// connection list, per-device activity, plus on-demand device traces and tcpdump
// packet captures. Everything /proc/conntrack-derived is best-effort: it stays
// empty (never errors) off-router, so the pages always render.
package monitor

import (
	"sync"

	"nfqws2strategy/internal/services/proxy"
	"nfqws2strategy/internal/tools/config"
	"nfqws2strategy/internal/tools/netmon"
	"nfqws2strategy/internal/tools/store"
)

// Service owns the live-monitoring views plus the in-memory trace/pcap registries.
type Service struct {
	cfg   *config.Config
	store *store.Store
	proxy *proxy.Service // the dashboard surfaces the two Telegram proxies' status

	traceMu    sync.Mutex
	traces     map[string]*Trace
	traceOrder []string

	pcapMu    sync.Mutex
	pcaps     map[string]*Pcap
	pcapOrder []string
}

// New builds the monitor service. px is read for the dashboard's TG WS / SOCKS5
// status cards.
func New(cfg *config.Config, st *store.Store, px *proxy.Service) *Service {
	return &Service{
		cfg:    cfg,
		store:  st,
		proxy:  px,
		traces: map[string]*Trace{},
		pcaps:  map[string]*Pcap{},
	}
}

// DashboardView is the home-page snapshot: TG WS proxy status, conntrack totals,
// the DPI engine's NFQUEUE stats, and WAN byte counters (the UI derives a rate
// by diffing successive samples).
type DashboardView struct {
	TGWS   proxy.TGWSStatus   `json:"tgws"`
	Socks5 proxy.Socks5Status `json:"socks5"`

	// Nfqws2Running is true when the DPI engine's NFQUEUE (MainQueue) is bound.
	Nfqws2Running bool `json:"nfqws2_running"`

	Conntrack struct {
		Count int `json:"count"`
		Max   int `json:"max"`
	} `json:"conntrack"`

	Conns struct {
		Total   int            `json:"total"`
		Failing int            `json:"failing"`
		ByProto map[string]int `json:"by_proto"`
	} `json:"conns"`

	Queues    []netmon.QueueStat  `json:"queues"`
	MainQueue int                 `json:"main_queue"`
	WAN       []netmon.IfaceBytes `json:"wan"`
}

// Dashboard assembles the home view. The TG WS card works on any platform; the
// /proc-derived sections are best-effort and simply stay empty when unavailable
// (e.g. on the non-Linux dev box), so the page always renders.
func (s *Service) Dashboard(host string) DashboardView {
	var d DashboardView
	d.TGWS = s.proxy.TGWSStatusFor(host)
	d.Socks5 = s.proxy.Socks5StatusFor(host)
	d.MainQueue = s.cfg.MainQueue
	d.Conns.ByProto = map[string]int{}

	if cur, limit, err := netmon.Count(); err == nil {
		d.Conntrack.Count = cur
		d.Conntrack.Max = limit
	}
	if conns, err := netmon.Conntrack(); err == nil {
		d.Conns.Total = len(conns)
		for _, c := range conns {
			d.Conns.ByProto[c.Proto]++
			if c.Failing() {
				d.Conns.Failing++
			}
		}
	}
	if qs, err := netmon.Queues(); err == nil {
		d.Queues = qs
		for _, q := range qs {
			if q.Queue == s.cfg.MainQueue {
				d.Nfqws2Running = true
				break
			}
		}
	}
	if ifs, err := netmon.Ifaces(); err == nil {
		want := make(map[string]bool, len(s.cfg.WANIfaces))
		for _, n := range s.cfg.WANIfaces {
			want[n] = true
		}
		for _, f := range ifs {
			if want[f.Iface] {
				d.WAN = append(d.WAN, f)
			}
		}
	}
	return d
}

// ConnectionsView is the full live connection list for the Connections tab
// (filtered/sorted/paginated client-side — the table is small).
type ConnectionsView struct {
	Items []netmon.Conn `json:"items"`
	Count int           `json:"count"`
}

func (s *Service) Connections() (ConnectionsView, error) {
	conns, err := netmon.Conntrack()
	if err != nil {
		return ConnectionsView{}, err
	}
	return ConnectionsView{Items: conns, Count: len(conns)}, nil
}

// DeviceActivityView groups live connections by LAN device.
type DeviceActivityView struct {
	Devices []netmon.Device `json:"devices"`
}

func (s *Service) DeviceActivity() (DeviceActivityView, error) {
	conns, err := netmon.Conntrack()
	if err != nil {
		return DeviceActivityView{}, err
	}
	arp, _ := netmon.ARP() // best-effort: enriches MAC/bridge, not required
	return DeviceActivityView{Devices: netmon.GroupDevices(conns, arp)}, nil
}
