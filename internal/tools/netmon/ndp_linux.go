//go:build linux

package netmon

import (
	"bufio"
	"context"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// 5 s is short enough that newly-connected LAN devices show up nearly
// instantly, long enough that the 4 frontend panes polling /api/devices
// concurrently (Devices, Connections, TracePane, DevicesRoutingPane) coalesce
// to ONE `ip -6 neigh show` shell-out per window instead of one per request.
// Under load the spawn was pushing the router into 4+ load average.
const ndpCacheTTL = 5 * time.Second

var (
	ndpMu       sync.Mutex
	ndpCache    map[string][]string
	ndpCacheErr error
	ndpCacheAt  time.Time
)

// NDP returns mac → []v6-address from the kernel's v6 neighbour cache via
// `ip -6 neigh show`. There is no `/proc/net/ipv6_neigh` equivalent to the v4
// ARP file, and v6 LAN traffic almost always uses link-local (`fe80::/10`)
// sources that conntrack-based aggregation filters out — so this is the only
// reliable v6→MAC source on this router. Best-effort: returns nil on any error.
//
// ponytail: shell-out is the pragmatic answer here; the netlink alternative
// pulls in cgo or a netlink dep for one read.
func NDP() (map[string][]string, error) {
	ndpMu.Lock()
	if time.Since(ndpCacheAt) < ndpCacheTTL && (ndpCache != nil || ndpCacheErr != nil) {
		c, e := ndpCache, ndpCacheErr
		ndpMu.Unlock()
		return c, e
	}
	ndpMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ip", "-6", "neigh", "show").Output()
	if err != nil {
		ndpMu.Lock()
		ndpCache, ndpCacheErr, ndpCacheAt = nil, err, time.Now()
		ndpMu.Unlock()
		return nil, err
	}
	m := map[string]map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		// Format: "<addr> dev <iface> lladdr <mac> <STATE>" (also "router",
		// "FAILED" without lladdr — skip those).
		f := strings.Fields(sc.Text())
		var addr, mac, iface string
		for i := 0; i < len(f); i++ {
			if i == 0 {
				addr = f[0]
				continue
			}
			if f[i] == "dev" && i+1 < len(f) {
				iface = f[i+1]
			}
			if f[i] == "lladdr" && i+1 < len(f) {
				mac = strings.ToLower(f[i+1])
			}
		}
		if addr == "" || mac == "" {
			continue
		}
		// ponytail: keep only LAN bridges. eth3/WAN neighbours (upstream
		// router, ISP peers) leak in otherwise as "без имени" ghost devices.
		if !strings.HasPrefix(iface, "br-") {
			continue
		}
		// Drop multicast/unspecified just in case (link-local v6 is the whole
		// point, so keep `fe80::/10`).
		if strings.HasPrefix(addr, "ff") || addr == "::" {
			continue
		}
		if m[mac] == nil {
			m[mac] = map[string]bool{}
		}
		m[mac][addr] = true
	}
	out2 := make(map[string][]string, len(m))
	for mac, set := range m {
		for a := range set {
			out2[mac] = append(out2[mac], a)
		}
	}
	ndpMu.Lock()
	ndpCache, ndpCacheErr, ndpCacheAt = out2, nil, time.Now()
	ndpMu.Unlock()
	return out2, nil
}
