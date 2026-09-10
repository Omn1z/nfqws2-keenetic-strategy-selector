// Package dnsroute gives the DNS service isolated router-side upstream paths.
// NFQWS uses the live queue; AWG sockets are bound to one particular tunnel.
// It never changes the selected AWG server or the user's split-routing policy.
package dnsroute

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"nfqws2strategy/internal/services/awgroute"
	"nfqws2strategy/internal/tools/config"
)

type ListenOptions struct {
	Host    string
	DNSPort int
}

type Route struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Interface string `json:"interface,omitempty"`
	Available bool   `json:"available"`
	Error     string `json:"error,omitempty"`
}

type routeState struct {
	Route
	slot   int
	v4, v6 string // last successfully installed gateway/device route signature
}

type Adapter struct {
	cfg                 *config.Config
	awg                 *awgroute.Service
	opMu                sync.Mutex
	mu                  sync.Mutex
	started             bool
	listen              ListenOptions
	lanIface, lanSubnet string
	routes              map[string]*routeState
	nextSlot            int
	updated             time.Time
	hookReady           bool
	cancel              context.CancelFunc
	runCtx              context.Context
	conns               map[*routedConn]struct{}
	done                chan struct{}
}

type routedConn struct {
	net.Conn
	once   sync.Once
	closed func()
}

func (c *routedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.closed)
	return err
}

// New has no OS side effects. Rules are installed only by Prepare.
func New(cfg *config.Config, awg *awgroute.Service) *Adapter {
	if cfg == nil {
		cfg = config.Default()
	}
	cp := *cfg
	cp.WANIfaces = append([]string(nil), cfg.WANIfaces...)
	return &Adapter{cfg: &cp, awg: awg, routes: make(map[string]*routeState), nextSlot: 1}
}

func (a *Adapter) Prepare(ctx context.Context, options ListenOptions) error {
	a.opMu.Lock()
	defer a.opMu.Unlock()
	return a.prepareOS(ctx, options)
}
func (a *Adapter) Routes() []Route { return a.routesOS() }
func (a *Adapter) DialContext(ctx context.Context, routeID, network, address string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil || port == "" {
		return nil, fmt.Errorf("DNS transport requires a literal IP:port; bootstrap hostnames separately")
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("DNS upstream requires TCP: %s", network)
	}
	return a.dialOS(ctx, routeID, network, address)
}

// ObserveAnswer preserves AWG's per-client DNS learning and IPv6 suppression.
// The caller caches the unfiltered answer, and invokes this on cache hits too.
func (a *Adapter) ObserveAnswer(ctx context.Context, domain string, response []byte, clientIP net.IP) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if a.awg == nil {
		return response, nil
	}
	return a.awg.ObserveDNSAnswer(ctx, domain, response, clientIP)
}

func (a *Adapter) Close() error {
	a.opMu.Lock()
	defer a.opMu.Unlock()
	return a.closeOS()
}

// ResolveLANHost chooses an owned LAN address, avoiding WAN and VPN devices.
// A literal address must be assigned locally; wildcard listeners are forbidden.
func ResolveLANHost(host string, wanIfaces []string) (string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	if host != "" && host != "auto" {
		ip := net.ParseIP(host)
		if ip == nil || ip.IsUnspecified() {
			return "", fmt.Errorf("DNS listen host must be a local LAN IP")
		}
		_, _, err = localLAN(ip, ifs, wanIfaces)
		return ip.String(), err
	}
	sort.SliceStable(ifs, func(i, j int) bool {
		score := func(n string) int {
			if n == "br0" {
				return 0
			}
			if strings.HasPrefix(n, "br") {
				return 1
			}
			return 2
		}
		return score(ifs[i].Name) < score(ifs[j].Name)
	})
	for _, ifc := range ifs {
		if !lanInterface(ifc, wanIfaces) {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, addr := range addrs {
			ip, _, e := net.ParseCIDR(addr.String())
			if e == nil && ip.To4() != nil && ip.IsPrivate() {
				return ip.String(), nil
			}
		}
	}
	return "", fmt.Errorf("не найден локальный IPv4 адрес LAN; задайте адрес интерфейса вручную")
}

func localLAN(ip net.IP, ifs []net.Interface, wan []string) (string, string, error) {
	if !ip.IsPrivate() && !ip.IsLoopback() {
		return "", "", fmt.Errorf("DNS listener must use a private LAN or loopback address")
	}
	for _, ifc := range ifs {
		if !ip.IsLoopback() && !lanInterface(ifc, wan) {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, addr := range addrs {
			own, subnet, err := net.ParseCIDR(addr.String())
			if err == nil && own.Equal(ip) {
				return ifc.Name, subnet.String(), nil
			}
		}
	}
	return "", "", fmt.Errorf("DNS listen address %s is not assigned to a LAN interface", ip)
}

func lanInterface(ifc net.Interface, wan []string) bool {
	if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
		return false
	}
	for _, w := range wan {
		if ifc.Name == w {
			return false
		}
	}
	for _, prefix := range []string{"awg", "nwg", "wg", "tun", "tap", "ppp", "ipsec", "docker", "veth"} {
		if strings.HasPrefix(ifc.Name, prefix) {
			return false
		}
	}
	return true
}

func validInterface(name string) bool {
	if len(name) == 0 || len(name) > 15 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}
