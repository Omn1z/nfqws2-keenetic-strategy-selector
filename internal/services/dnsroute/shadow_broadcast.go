package dnsroute

import (
	"net"
	"strconv"
	"strings"
)

type shadowBroadcastWAN struct {
	native, device string
	client         net.IP
}

// Only a native physical WAN which owns both a configured kernel address and
// the live main default may originate discovery. An interface name alone is
// insufficient: LAN Ethernet ports and arbitrarily named VPNs also exist.
func parseShadowBroadcastWANs(output, routes string, configured []string, devices map[string]string) []shadowBroadcastWAN {
	defaults := map[string]bool{}
	for _, line := range strings.Split(routes, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "default" {
			continue
		}
		for i := 1; i+1 < len(fields); i++ {
			if fields[i] == "dev" && validShadowWAN(fields[i+1]) {
				for _, name := range configured {
					if name == fields[i+1] {
						defaults[name] = true
					}
				}
			}
		}
	}
	var result []shadowBroadcastWAN
	seen := map[string]bool{}
	var values map[string]string
	name, nested := "", false
	flush := func() {
		if name == "" || values == nil || values["connected"] != "yes" || values["global"] != "yes" || values["defaultgw"] != "yes" || values["security-level"] != "public" {
			return
		}
		id := values["id"]
		if id == "" {
			id = name
		}
		if !validKeeneticInterface(id) {
			return
		}
		switch values["type"] {
		case "Ethernet", "GigabitEthernet", "FastEthernet", "Vlan", "VLAN":
		default:
			return
		}
		ip := net.ParseIP(values["address"])
		if ip.To4() == nil || !ip.IsGlobalUnicast() || ip.IsLoopback() {
			return
		}
		device := devices[ip.String()]
		if !defaults[device] || seen[device] {
			return
		}
		seen[device] = true
		result = append(result, shadowBroadcastWAN{native: id, device: device, client: ip})
	}
	for _, line := range strings.Split(strings.ReplaceAll(output, "\x1b[K", ""), "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "Interface, name = "); ok {
			flush()
			name, nested, values = "", false, map[string]string{}
			decoded, err := strconv.Unquote(strings.TrimSuffix(rest, ":"))
			if err == nil && validKeeneticInterface(decoded) {
				name = decoded
			}
			continue
		}
		if name == "" || nested {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		// Firmware prints IPv6, ports and summaries below the scalar status.
		// Their address/id/defaultgw fields must never fill missing WAN data.
		if key == "ipv6" || key == "summary" || key == "addresses" || strings.HasPrefix(key, "port,") {
			nested = true
			continue
		}
		switch key {
		case "id", "type", "address", "connected", "global", "defaultgw", "security-level":
			if _, exists := values[key]; !exists {
				values[key] = value
			}
		}
	}
	flush()
	return result
}
