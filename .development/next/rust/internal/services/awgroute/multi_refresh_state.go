package awgroute

import (
	"net/netip"
	"strconv"
	"strings"
)

const awgMultiActionPrefix = "AWG2_TO_"

// Only a complete ordered policy and all its required shared rules can avoid
// a refresh. Unknown/missing output is conservative: the caller repairs it.
func awgMultiFirewallIntact(snapshot, chain string, expected []string, shared map[string][]string) bool {
	actual := map[string][]string{}
	declaredActions := map[string]bool{}
	complete := map[string]bool{}
	table := ""
	for _, raw := range strings.Split(snapshot, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "*") {
			if table != "" {
				return false
			}
			table = strings.TrimPrefix(line, "*")
			continue
		}
		if line == "COMMIT" {
			if table == "" {
				return false
			}
			complete[table] = true
			table = ""
			continue
		}
		if table == "mangle" && strings.HasPrefix(line, ":") {
			fields := strings.Fields(strings.TrimPrefix(line, ":"))
			if len(fields) > 0 && awgIsMultiActionChain(fields[0]) {
				declaredActions[fields[0]] = true
			}
		}
		if table == "" || !strings.HasPrefix(line, "-A ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			return false
		}
		key := table + "/" + fields[1]
		actual[key] = append(actual[key], awgCanonicalFirewallRule(line))
	}
	if table != "" || (len(expected) > 0 && !complete["mangle"]) {
		return false
	}
	expectedChains := map[string][]string{}
	for _, want := range expected {
		fields := strings.Fields(want)
		if len(fields) < 4 || fields[0] != "-A" || (fields[1] != chain && !awgIsMultiActionChain(fields[1])) {
			return false
		}
		expectedChains[fields[1]] = append(expectedChains[fields[1]], awgCanonicalFirewallRule(want))
	}
	if len(expected) > 0 && len(expectedChains[chain]) == 0 {
		return false
	}
	for name, rules := range expectedChains {
		policy := actual["mangle/"+name]
		if len(policy) != len(rules) {
			return false
		}
		for i, want := range rules {
			if policy[i] != want {
				return false
			}
		}
	}
	for name := range declaredActions {
		if len(expected) > 0 && len(expectedChains[name]) == 0 {
			return false
		}
	}
	for tableChain, required := range shared {
		if !complete[strings.SplitN(tableChain, "/", 2)[0]] {
			return false
		}
		seen := make(map[string]bool, len(actual[tableChain]))
		for _, rule := range actual[tableChain] {
			seen[rule] = true
		}
		for _, rule := range required {
			if !seen[awgCanonicalFirewallRule(rule)] {
				return false
			}
		}
	}
	if len(expected) > 0 {
		for _, name := range []string{"PREROUTING", "OUTPUT"} {
			rules := actual["mangle/"+name]
			if len(rules) == 0 || rules[0] != "-A "+name+" -j "+chain {
				return false
			}
		}
	}
	return len(expected) > 0 || len(shared) > 0
}

func awgIsMultiActionChain(name string) bool {
	if len(name) != len(awgMultiActionPrefix)+8 || !strings.HasPrefix(name, awgMultiActionPrefix) {
		return false
	}
	_, err := strconv.ParseUint(strings.TrimPrefix(name, awgMultiActionPrefix), 16, 32)
	return err == nil
}

func awgCanonicalFirewallRule(line string) string {
	fields := strings.Fields(line)
	for i, field := range fields {
		if field == "--goto" {
			fields[i] = "-g"
		}
	}
	for i := 1; i < len(fields); i++ {
		if fields[i-1] == "--tcp-flags" && i+1 < len(fields) {
			fields[i], fields[i+1] = awgCanonicalTCPFlags(fields[i]), awgCanonicalTCPFlags(fields[i+1])
		}
		switch fields[i-1] {
		case "-s", "-d":
			if ip, err := netip.ParseAddr(fields[i]); err == nil {
				fields[i] = netip.PrefixFrom(ip, ip.BitLen()).String()
			} else if p, err := netip.ParsePrefix(fields[i]); err == nil {
				fields[i] = p.Masked().String()
			}
		case "--set-xmark":
			parts := strings.Split(fields[i], "/")
			for j, part := range parts {
				if value, err := strconv.ParseUint(part, 0, 32); err == nil {
					parts[j] = strconv.FormatUint(value, 16)
				}
			}
			fields[i] = strings.Join(parts, "/")
		}
	}
	return strings.Join(fields, " ")
}

func awgCanonicalTCPFlags(value string) string {
	if bits, err := strconv.ParseUint(value, 0, 8); err == nil {
		return strconv.FormatUint(bits, 16)
	}
	var mask uint64
	for _, flag := range strings.Split(value, ",") {
		switch flag {
		case "FIN":
			mask |= 1
		case "SYN":
			mask |= 2
		case "RST":
			mask |= 4
		case "PSH":
			mask |= 8
		case "ACK":
			mask |= 16
		case "URG":
			mask |= 32
		case "ALL":
			mask |= 63
		case "NONE":
		default:
			return value
		}
	}
	return strconv.FormatUint(mask, 16)
}

type awgMultiRouteExpectation struct {
	Table              int
	Iface              string
	EndpointIP         string
	EndpointIPs        []string
	Online, Killswitch bool
}

// iproute2's table-all output omits "table main" on some router versions.
// Require the actual tunnel default/blackhole and the endpoint's WAN escape.
func awgMultiRoutesIntact(snapshot, gateway, wan string, tunnels []awgMultiRouteExpectation) bool {
	type route struct {
		dst, dev, via, table, metric string
		blackhole                    bool
	}
	var routes []route
	for _, line := range strings.Split(snapshot, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		r := route{table: "main", metric: "0"}
		if fields[0] == "blackhole" {
			r.blackhole = true
			fields = fields[1:]
		}
		if len(fields) == 0 {
			continue
		}
		r.dst = fields[0]
		for i := 1; i+1 < len(fields); i++ {
			switch fields[i] {
			case "table":
				r.table = fields[i+1]
			case "dev":
				r.dev = fields[i+1]
			case "via":
				r.via = fields[i+1]
			case "metric":
				r.metric = fields[i+1]
			}
		}
		routes = append(routes, r)
	}
	for _, tunnel := range tunnels {
		online, blackhole := !tunnel.Online, !tunnel.Killswitch
		for _, r := range routes {
			if r.table == strconv.Itoa(tunnel.Table) && r.dst == "default" {
				if r.blackhole && r.metric == "1000" {
					blackhole = true
				}
				if !r.blackhole && r.dev == tunnel.Iface && r.metric == "0" {
					online = true
				}
			}
		}
		if !online || !blackhole {
			return false
		}
		if wan != "" {
			for _, endpoint := range canonicalEndpointIPs(append(append([]string(nil), tunnel.EndpointIPs...), tunnel.EndpointIP)...) {
				if ip, err := netip.ParseAddr(endpoint); err == nil && ip.Is4() && !awgEndpointRouteIntact(snapshot, endpoint, gateway, wan) {
					return false
				}
			}
		}
	}
	return len(tunnels) > 0
}

func awgEndpointRouteIntact(snapshot, endpoint, gateway, wan string) bool {
	ip, err := netip.ParseAddr(endpoint)
	if err != nil || wan == "" {
		return false
	}
	want := netip.PrefixFrom(ip, ip.BitLen())
	for _, line := range strings.Split(snapshot, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		dst, err := netip.ParsePrefix(fields[0])
		if err != nil {
			if address, e := netip.ParseAddr(fields[0]); e == nil {
				dst = netip.PrefixFrom(address, address.BitLen())
			}
		}
		if dst != want {
			continue
		}
		dev, via, table := "", "", "main"
		for i := 1; i+1 < len(fields); i++ {
			switch fields[i] {
			case "dev":
				dev = fields[i+1]
			case "via":
				via = fields[i+1]
			case "table":
				table = fields[i+1]
			}
		}
		if dev == wan && via == gateway && (table == "main" || table == "254") {
			return true
		}
	}
	return false
}
