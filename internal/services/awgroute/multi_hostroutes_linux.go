//go:build linux

package awgroute

import (
	"encoding/json"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"nfqws2strategy/internal/tools/logbuf"
)

const awgHostRoutesFile = awgSetDir + "/awg2_hostroutes.json"

type awgHostRoute struct {
	Dest  string `json:"dest"`
	Iface string `json:"iface"`
	V6    bool   `json:"v6,omitempty"`
}

func (svc *Service) awgApplyMultiHostRoutesOS() {
	svc.awgClearMultiHostRoutesOS()
	if err := svc.awgApplyMultiPolicyOS(); err != nil {
		logbuf.Append("awg2", "warn", "multi-routing: "+err.Error())
	}
}

func (svc *Service) awgApplyLegacyMultiHostRoutesOS() {
	desired := svc.awgDesiredHostRoutes()
	prev := awgLoadHostRoutes()
	want := map[string]awgHostRoute{}
	for _, r := range desired {
		want[hostRouteKey(r)] = r
	}
	for _, r := range prev {
		if _, ok := want[hostRouteKey(r)]; !ok {
			awgDelHostRoute(r)
		}
	}
	for _, r := range desired {
		awgSetHostRoute(r)
	}
	awgSaveHostRoutes(desired)
	if len(desired) > 0 {
		logbuf.Append("awg2", "info", "multi-routing: host routes applied: "+strconvItoa(len(desired)))
	}
}

func (svc *Service) awgClearMultiHostRoutesOS() {
	for _, r := range awgLoadHostRoutes() {
		awgDelHostRoute(r)
	}
	_ = os.Remove(awgHostRoutesFile)
	svc.awgClearMultiPolicyOS()
}

func (svc *Service) awgDesiredHostRoutes() []awgHostRoute {
	claimed := map[string]bool{}
	out := []awgHostRoute{}
	add := func(dest, iface string, v6 bool) {
		if dest == "" || iface == "" || claimed[dest] {
			return
		}
		claimed[dest] = true
		out = append(out, awgHostRoute{Dest: dest, Iface: iface, V6: v6})
	}
	for _, srv := range svc.serverSnapshot() {
		cfg := srv.Manager.Config()
		if !cfg.Enabled || !cfg.Client.Enabled || !cfg.Routing.Active || cfg.Routing.Mode == "off" || cfg.Routing.Mode == "full" {
			continue
		}
		iface := awgClientIfaceName(cfg)
		if !validAWGClientIfaceName(iface) {
			continue
		}
		for _, z := range effectiveZones(cfg.Routing) {
			if !z.Enabled || z.RouteValue() != "tunnel" || len(z.SourceIPs) > 0 || z.IsCatchAll() {
				continue
			}
			domains, ips := svc.expandEntries(z.Domains)
			for _, raw := range append(append([]string{}, z.IPs...), ips...) {
				if dest, v6, ok := normalizeHostRouteDest(raw); ok && !hostRouteExcluded(dest, cfg.Endpoint) {
					add(dest, iface, v6)
				}
			}
			for _, d := range domains {
				for _, ip := range resolveDomainAll(d) {
					if dest, v6, ok := normalizeHostRouteDest(ip); ok && !hostRouteExcluded(dest, cfg.Endpoint) {
						add(dest, iface, v6)
					}
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].V6 != out[j].V6 {
			return !out[i].V6
		}
		return out[i].Dest < out[j].Dest
	})
	return out
}

func normalizeHostRouteDest(raw string) (string, bool, bool) {
	s := strings.TrimSpace(raw)
	if s == "" || s == "*" {
		return "", false, false
	}
	if ip := net.ParseIP(s); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String() + "/32", false, true
		}
		return "", false, false
	}
	if ip, n, err := net.ParseCIDR(s); err == nil {
		if v4 := ip.To4(); v4 != nil {
			n.IP = v4
			return n.String(), false, true
		}
		return "", false, false
	}
	return "", false, false
}

func hostRouteExcluded(dest, endpoint string) bool {
	ipPart := strings.SplitN(dest, "/", 2)[0]
	ip := net.ParseIP(ipPart)
	if ip == nil {
		return true
	}
	if endpointIP := resolveHostIP(hostOf(endpoint)); endpointIP != "" && ip.Equal(net.ParseIP(endpointIP)) {
		return true
	}
	for _, raw := range awgExcludes {
		_, n, err := net.ParseCIDR(raw)
		if err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

func awgSetHostRoute(r awgHostRoute) {
	fam := "ip"
	if r.V6 {
		fam = "ip -6"
	}
	_, _ = awgRun(fam + " route replace " + r.Dest + " dev " + r.Iface)
}

func awgDelHostRoute(r awgHostRoute) {
	fam := "ip"
	if r.V6 {
		fam = "ip -6"
	}
	_, _ = awgRun(fam + " route del " + r.Dest + " dev " + r.Iface + " 2>/dev/null")
}

func awgLoadHostRoutes() []awgHostRoute {
	b, err := os.ReadFile(awgHostRoutesFile)
	if err != nil {
		return nil
	}
	var out []awgHostRoute
	_ = json.Unmarshal(b, &out)
	return out
}

func awgSaveHostRoutes(routes []awgHostRoute) {
	_ = os.MkdirAll(awgSetDir, 0o755)
	b, _ := json.Marshal(routes)
	_ = os.WriteFile(awgHostRoutesFile, b, 0o600)
}

func hostRouteKey(r awgHostRoute) string {
	if r.V6 {
		return "6|" + r.Dest
	}
	return "4|" + r.Dest
}

func strconvItoa(v int) string {
	return strconv.Itoa(v)
}
