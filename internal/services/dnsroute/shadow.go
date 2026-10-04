package dnsroute

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The last private DNS slot is reserved for direct provider queries. It is
// deliberately absent from Routes: regular DoH must never select this path.
const shadowRouteSlot = maxRouteSlots - 1

type shadowState struct {
	diagnostics shadowDiagnosticState
	// Discovery has a separate lock so a slow firmware command cannot stall
	// ordinary encrypted DNS, cache hits, or the adapter status endpoint.
	discoveryMu    sync.Mutex
	servers        []string
	discoveryErr   error
	discoveryUntil time.Time
	// Ignored DHCP DNS can disappear from the firmware ring log. Retain only
	// auto-learned, unexpired leases, and revalidate their WAN identity before
	// using them after the short discovery cache expires.
	leases       map[string]shadowRememberedLease
	leasesLoaded bool
	leaseDigest  string
	inform       shadowInformState
	native       shadowNativeState
	// Route fields below are protected by Adapter.opMu. Preparing their
	// kernel tables must never hold the ordinary DNS/cache/status mutex.
	route   *routeState
	checked [2]time.Time
}

// ShadowDNSServers returns literal IP:port endpoints advertised by a WAN's
// DHCP/PPP configuration. A local DNS proxy is never used as a fallback.
func (a *Adapter) ShadowDNSServers(ctx context.Context) ([]string, error) {
	return a.shadowServersOS(ctx)
}

// DialShadowDNS opens only direct WAN sockets. DNS message handling, timeout,
// UDP truncation/TCP retry, and cache policy belong to the DNS server package.
func (a *Adapter) DialShadowDNS(ctx context.Context, network, address string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if network != "udp" && network != "udp4" && network != "udp6" && network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("Shadow DNS requires UDP or TCP")
	}
	ip, err := shadowEndpoint(address)
	if err != nil {
		return nil, err
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("check local DNS addresses: %w", err)
	}
	for _, addr := range addrs {
		own, _, e := net.ParseCIDR(addr.String())
		if e == nil && own.Equal(ip) {
			return nil, fmt.Errorf("Shadow DNS cannot use a router-local address (DNS loop)")
		}
	}
	return a.dialShadowOS(ctx, network, address)
}

func shadowEndpoint(address string) (net.IP, error) {
	host, port, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	n, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || n < 1 || n > 65535 || ip == nil || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return nil, fmt.Errorf("Shadow DNS requires a non-local unicast IP:port")
	}
	return ip, nil
}

func filterShadowServers(candidates []string, local []net.IP) []string {
	result := []string{}
	seen := map[string]bool{}
	for _, candidate := range candidates {
		if ip := net.ParseIP(candidate); ip != nil {
			candidate = net.JoinHostPort(ip.String(), "53")
		}
		ip, err := shadowEndpoint(candidate)
		if err != nil {
			continue
		}
		own := false
		for _, x := range local {
			if ip.Equal(x) {
				own = true
				break
			}
		}
		if own {
			continue
		}
		_, port, _ := net.SplitHostPort(candidate)
		candidate = net.JoinHostPort(ip.String(), port)
		if !seen[candidate] {
			result = append(result, candidate)
			seen[candidate] = true
		}
		if len(result) == 8 {
			break
		}
	}
	return result
}

type keeneticDNSServer struct{ address, port, iface, service string }

// Firmware emits a block per server. Only peer-provided, interface-specific
// DNS is eligible; global static entries and DoH/DoT blocks are not ISP DNS.
func parseKeeneticShadowServers(output string) []keeneticDNSServer {
	var result []keeneticDNSServer
	var current *keeneticDNSServer
	flush := func() {
		if current == nil {
			return
		}
		s := strings.ToLower(current.service)
		if current.address != "" && validKeeneticInterface(current.iface) && (strings.Contains(s, "dhcp") || strings.Contains(s, "ppp") || strings.Contains(s, "ipcp")) {
			result = append(result, *current)
		}
	}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(strings.ReplaceAll(line, "\x1b[K", ""))
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if key == "server" || key == "server-tls" || key == "server-https" {
			flush()
			current = nil
			if key == "server" {
				current = &keeneticDNSServer{}
			}
			continue
		}
		if current == nil {
			continue
		}
		switch key {
		case "address":
			current.address = value
		case "port":
			current.port = value
		case "interface":
			current.iface = value
		case "service":
			current.service = value
		}
	}
	flush()
	return result
}

func validKeeneticInterface(name string) bool {
	if len(name) == 0 || len(name) > 100 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/_.-", r)) {
			return false
		}
	}
	for _, prefix := range []string{"Wireguard", "OpenVPN", "L2TP", "PPTP", "SSTP", "IPsec", "Bridge"} {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	return true
}

func validShadowWAN(name string) bool {
	if !validInterface(name) || name == "lo" {
		return false
	}
	// DSA deployments can put the uplink inside a dedicated WAN bridge.
	// It must still be advertised by ubus/config and own the main default.
	if name == "br-wan" || strings.HasPrefix(name, "br-wan.") {
		return true
	}
	for _, prefix := range []string{"awg", "nwg", "wg", "tun", "tap", "br", "docker", "veth"} {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	return true
}

func parseOpenWrtShadowServers(output string, wan []string) []string {
	_, servers := parseOpenWrtShadowWAN(output, wan, nil)
	return servers
}

// Map both logical (wan) and physical (eth1) configuration names to the live
// L3 device (pppoe-wan). Main-table defaults also permit discovery when the
// NFQWS config still contains its Keenetic-specific eth3 installation default.
func parseOpenWrtShadowWAN(output string, configured, defaults []string) ([]string, []string) {
	var data struct {
		Interfaces []struct {
			Name     string   `json:"interface"`
			Proto    string   `json:"proto"`
			Up       bool     `json:"up"`
			L3Device string   `json:"l3_device"`
			Device   string   `json:"device"`
			DNS      []string `json:"dns-server"`
			Inactive struct {
				DNS []string `json:"dns-server"`
			} `json:"inactive"`
		} `json:"interface"`
	}
	if json.Unmarshal([]byte(output), &data) != nil {
		return nil, nil
	}
	var devices, result []string
	for _, iface := range data.Interfaces {
		if !iface.Up {
			continue
		}
		device := iface.L3Device
		if device == "" {
			device = iface.Device
		}
		if !validShadowWAN(device) {
			continue
		}
		// Unknown protocols can be VPNs with arbitrary device names (for
		// example xfrm0). A main default alone does not prove direct WAN.
		switch iface.Proto {
		case "dhcp", "dhcpv6", "static", "pppoe", "pppoa", "3g", "qmi", "ncm", "mbim", "modemmanager", "wwan",
			"6in4", "6rd", "dslite", "464xlat", "map":
		default:
			continue
		}
		matched := false
		for _, name := range configured {
			if name == device || name == iface.Name || name == iface.Device {
				matched = true
				break
			}
		}
		for _, name := range defaults {
			if name == device {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		devices = append(devices, device)
		// netifd retains peer DNS here when peerdns=0. It is still supplied
		// by the live WAN, and must precede a manually selected system DNS.
		if len(iface.Inactive.DNS) > 0 {
			result = append(result, iface.Inactive.DNS...)
		} else {
			result = append(result, iface.DNS...)
		}
	}
	return devices, result
}

type keeneticShadowLease struct {
	iface        string
	clientIP     net.IP
	serverIP     net.IP
	servers      []string
	stamp        string
	leaseSeconds uint64
}

// DHCP server identity is separate from DNS lease lifetime. The peer observed
// in an ACK may be asked for current options with DHCPINFORM after that lease
// expires, but is never itself assumed to be a DNS resolver.
type shadowDHCPTarget struct {
	wanKey             string
	clientIP, serverIP net.IP
	stamp              string
	// A silent unicast peer is retried through the verified WAN broadcast
	// path on the next discovery pass, without extending that pass's budget.
	preferBroadcast bool
}

type shadowInformAnswer struct {
	servers []string
	expires time.Time
	refresh bool
}

type shadowInformState struct {
	targets    map[string]shadowDHCPTarget
	answers    map[string]shadowInformAnswer
	retryAfter map[string]time.Time
	probe      func(context.Context, string, net.IP, net.IP) ([]string, error)
	// The orchestrator uses this serial to keep known-peer and broadcast
	// discovery within a single DHCP exchange per pass, including multi-WAN.
	unicastAttempts uint64
	// Initial discovery has no known DHCP peer yet. Keep its bounded retry
	// separately so a failed broadcast cannot poison a learned unicast target.
	broadcastKey   string
	broadcastRetry time.Time
	probeDiscover  func(context.Context, string, net.IP) (net.IP, []string, error)
}

func (target shadowDHCPTarget) valid(key string, ips []net.IP) bool {
	if key == "" || target.wanKey != key {
		return false
	}
	for _, ip := range ips {
		if ip.Equal(target.clientIP) {
			return true
		}
	}
	return false
}

func (s *shadowInformState) remember(iface string, target shadowDHCPTarget, routerNow time.Time) {
	if _, exists := s.targets[iface]; !exists {
		// Firmware logs can use ISP while interface enumeration uses its
		// GigabitEthernet ID. One verified WAN address must keep one target.
		var aliases []string
		for name, previous := range s.targets {
			if previous.wanKey == target.wanKey && previous.clientIP.Equal(target.clientIP) {
				aliases = append(aliases, name)
			}
		}
		if len(aliases) > 0 {
			sort.Strings(aliases)
			iface = aliases[0]
		}
	}
	if previous, ok := s.targets[iface]; ok {
		observed := shadowLeaseObservedAt(target.stamp, routerNow)
		retained := shadowLeaseObservedAt(previous.stamp, routerNow)
		if !observed.IsZero() && !retained.IsZero() && observed.Before(retained) {
			return
		}
		// A live broadcast may have found a different peer since this log ACK.
		// Its retained stamp is a watermark: replaying that same old log must
		// not restore the unreachable peer or discard the fresh DNS answer.
		if previous.wanKey == target.wanKey && previous.clientIP.Equal(target.clientIP) && previous.stamp == target.stamp && (target.stamp != "" || previous.serverIP.Equal(target.serverIP)) {
			return
		}
		if previous.wanKey == target.wanKey && previous.clientIP.Equal(target.clientIP) && previous.serverIP.Equal(target.serverIP) {
			target.preferBroadcast = previous.preferBroadcast
			if answer, exists := s.answers[iface]; exists {
				answer.refresh = true
				s.answers[iface] = answer
			}
		} else {
			delete(s.answers, iface)
			delete(s.retryAfter, iface)
		}
	}
	if s.targets == nil {
		s.targets = map[string]shadowDHCPTarget{}
	}
	if _, exists := s.targets[iface]; !exists && len(s.targets) >= 8 {
		return
	}
	s.targets[iface] = target
}

type shadowRememberedLease struct {
	wanKey       string
	clientIP     net.IP
	servers      []string
	expires      time.Time
	stamp        string
	leaseSeconds uint64
	observedAt   time.Time // native packet receipt; independent of firmware log timezone
}

func shadowLeaseRemaining(lease keeneticShadowLease, routerNow time.Time) time.Duration {
	// 0xffffffff means an infinite DHCP lease. It cannot supply a bounded
	// fallback lifetime, so only current authoritative DNS can cover that case.
	if lease.leaseSeconds == 0 || lease.leaseSeconds >= 0xffffffff {
		return 0
	}
	started := shadowLeaseObservedAt(lease.stamp, routerNow)
	if started.IsZero() {
		return 0
	}
	remaining := started.Add(time.Duration(lease.leaseSeconds) * time.Second).Sub(routerNow)
	if remaining <= 0 {
		return 0
	}
	// Never retain a ring-log observation indefinitely even on a DHCP server
	// advertising unusually long leases. This only shortens the real lifetime.
	if remaining > 7*24*time.Hour {
		remaining = 7 * 24 * time.Hour
	}
	return remaining
}

func shadowLeaseObservedAt(stamp string, routerNow time.Time) time.Time {
	if routerNow.IsZero() {
		return time.Time{}
	}
	started, err := time.ParseInLocation("Jan _2 15:04:05 2006", stamp+" "+strconv.Itoa(routerNow.Year()), routerNow.Location())
	if err != nil {
		return time.Time{}
	}
	if started.After(routerNow) {
		started = started.AddDate(-1, 0, 0)
	}
	return started
}

func shadowWANKey(routes string, wan []string, ips []net.IP) string {
	allowed := map[string]bool{}
	for _, name := range wan {
		allowed[name] = validShadowWAN(name)
	}
	var parts []string
	for _, line := range strings.Split(routes, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "default" {
			continue
		}
		device, gateway := "", ""
		for i := 1; i+1 < len(fields); i++ {
			switch fields[i] {
			case "dev":
				device = fields[i+1]
			case "via":
				gateway = fields[i+1]
			}
		}
		if allowed[device] {
			if gateway != "" && net.ParseIP(gateway) == nil {
				continue
			}
			parts = append(parts, "route="+device+"/"+gateway)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	addresses := 0
	for _, ip := range ips {
		if ip.To4() != nil {
			parts = append(parts, "ip="+ip.String())
			addresses++
		}
	}
	if addresses == 0 {
		return ""
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

func (lease shadowRememberedLease) valid(key string, ips []net.IP, now time.Time) bool {
	if key == "" || lease.wanKey != key || !now.Before(lease.expires) {
		return false
	}
	for _, ip := range ips {
		if ip.Equal(lease.clientIP) {
			return true
		}
	}
	return false
}

// Ignored peer DNS is intentionally omitted from "show ip name-server" by
// KeeneticOS. The DHCP ACK log retains it. Only the last ACK for an interface
// is eligible, and the caller must verify its address against that live WAN.
// Unattributed DNS lines, other log timestamps and incomplete leases fail closed.
func parseKeeneticShadowLeases(output string) []keeneticShadowLease {
	var records []string
	for _, line := range strings.Split(strings.ReplaceAll(output, "\x1b[K", ""), "\n") {
		line = strings.TrimRight(line, "\r")
		if len(line) > 4 && line[1:3] == " [" {
			records = append(records, strings.TrimSpace(line))
		} else if len(records) > 0 && strings.HasPrefix(line, " ") {
			records[len(records)-1] += " " + strings.TrimSpace(line)
		}
	}
	var leases []keeneticShadowLease
	indices := map[string]int{}
	current, stamp, obtained, remaining := -1, "", false, 0
	for _, record := range records {
		end := strings.Index(record, "] ")
		if end < 0 {
			continue
		}
		timestamp, message := record[3:end], record[end+2:]
		if strings.HasPrefix(message, "ndhcpc: ") {
			current = -1
			fields := strings.Fields(strings.TrimPrefix(message, "ndhcpc: "))
			if len(fields) < 9 || fields[1] != "received" || fields[2] != "ACK" || fields[3] != "for" || fields[5] != "from" {
				continue
			}
			iface := strings.TrimSuffix(fields[0], ":")
			ip := net.ParseIP(fields[4])
			if !validKeeneticInterface(iface) || ip == nil {
				continue
			}
			index, ok := indices[iface]
			if !ok {
				index = len(leases)
				indices[iface] = index
				leases = append(leases, keeneticShadowLease{})
			}
			seconds, _ := strconv.ParseUint(fields[8], 10, 32)
			if fields[7] != "lease" {
				seconds = 0
			}
			server := net.ParseIP(fields[6])
			if server.To4() == nil || !server.IsGlobalUnicast() {
				server = nil
			}
			leases[index] = keeneticShadowLease{iface: iface, clientIP: ip, serverIP: server, stamp: timestamp, leaseSeconds: seconds}
			current, stamp, obtained, remaining = index, timestamp, false, 16
			continue
		}
		if current < 0 || timestamp != stamp || remaining == 0 {
			current = -1
			continue
		}
		remaining--
		if strings.HasPrefix(message, "ndm: Dhcp::Client: obtained IP address ") {
			address := strings.TrimSuffix(strings.TrimPrefix(message, "ndm: Dhcp::Client: obtained IP address "), ".")
			ip, _, err := net.ParseCIDR(address)
			obtained = err == nil && ip.Equal(leases[current].clientIP)
		}
		if obtained {
			if ip := parseKeeneticIgnoredDNS(message); ip != nil && len(leases[current].servers) < 8 {
				leases[current].servers = append(leases[current].servers, ip.String())
			}
		}
	}
	return leases
}

// Older firmware logs the same ignored peer address under Dhcp::Client.
// Callers still require the original ACK/address/timestamp association; neither
// spelling by itself proves that an address belongs to the active WAN lease.
func parseKeeneticIgnoredDNS(message string) net.IP {
	for _, prefix := range []string{"ndm: Dns::InterfaceSpecific: name server ", "ndm: Dhcp::Client: name server "} {
		if address, ok := strings.CutPrefix(message, prefix); ok {
			if address, ok = strings.CutSuffix(address, " is ignored."); ok {
				return net.ParseIP(address)
			}
			return nil
		}
	}
	return nil
}
