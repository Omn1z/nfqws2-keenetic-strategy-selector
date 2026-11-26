package dnsroute

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

type keeneticShadowPPPSession struct {
	pid       string
	device    string
	sessionID uint64
	clientIP  net.IP
	servers   []string
	stamp     string
}

// pppd reports peer DNS before Keenetic applies its ignore-DNS policy. Unlike
// unattributed Dns::InterfaceSpecific messages, these records identify a process,
// PPP session and kernel interface. The caller must still match the current
// native PPPoE session, its address and the configured main default route.
func parseKeeneticShadowPPPSessions(output string) []keeneticShadowPPPSession {
	if len(output) > shadowNativeLogBytes {
		output = output[len(output)-shadowNativeLogBytes:]
		_, output, _ = strings.Cut(output, "\n")
	}
	type progress struct {
		keeneticShadowPPPSession
		stage  int // session, interface, connect, address, DNS
		badDNS bool
	}
	processes := map[string]*progress{}
	latest := map[string]*progress{}
	exceedsBound := false
	reset := func(pid string) *progress {
		previous := processes[pid]
		if previous != nil && latest[previous.device] == previous {
			latest[previous.device] = nil
		}
		next := &progress{keeneticShadowPPPSession: keeneticShadowPPPSession{pid: pid}}
		processes[pid] = next
		return next
	}
	remember := func(state *progress) {
		if _, exists := latest[state.device]; !exists && len(latest) >= 64 {
			exceedsBound = true
			return
		}
		latest[state.device] = state
	}
	consume := func(record string) {
		end := strings.Index(record, "] ")
		if end < 3 {
			return
		}
		stamp, message := record[3:end], record[end+2:]
		rest, ok := strings.CutPrefix(message, "pppd[")
		if !ok {
			return
		}
		pid, message, ok := strings.Cut(rest, "]: ")
		pidNumber, err := strconv.ParseUint(pid, 10, 32)
		if !ok || err != nil || pidNumber == 0 || strconv.FormatUint(pidNumber, 10) != pid {
			// A malformed PPP record cannot safely bridge adjacent evidence.
			clear(processes)
			clear(latest)
			return
		}
		state := processes[pid]
		if state == nil {
			if len(processes) >= 64 {
				exceedsBound = true
				return
			}
			state = reset(pid)
		}
		fields := strings.Fields(message)
		if len(fields) == 0 {
			return
		}
		switch {
		case strings.HasPrefix(message, "PPP session"):
			state = reset(pid)
			if len(fields) == 4 && fields[0] == "PPP" && fields[1] == "session" && fields[2] == "is" {
				id, err := strconv.ParseUint(fields[3], 10, 16)
				_, stampErr := time.Parse("Jan _2 15:04:05", stamp)
				if err == nil && id != 0 && stampErr == nil {
					state.sessionID, state.stamp, state.stage = id, stamp, 1
				}
			}
		case strings.HasPrefix(message, "Using interface"):
			previous := state
			state = reset(pid)
			if len(fields) == 3 && fields[0] == "Using" && fields[1] == "interface" && shadowPPPDevice(fields[2]) {
				state.device = fields[2]
				remember(state)
				if previous.stage == 1 {
					state.sessionID, state.stamp, state.stage = previous.sessionID, previous.stamp, 2
				}
			}
		case strings.HasPrefix(message, "Connect:"):
			previous := state
			state = reset(pid)
			if len(fields) == 4 && fields[0] == "Connect:" && shadowPPPDevice(fields[1]) && fields[2] == "<-->" && validInterface(fields[3]) {
				state.device = fields[1]
				remember(state)
				if previous.stage == 2 && previous.device == state.device {
					state.sessionID, state.stamp, state.stage = previous.sessionID, previous.stamp, 3
				}
			}
		case fields[0] == "local" && (len(fields) == 1 || fields[1] != "LL"):
			state.clientIP, state.servers, state.badDNS = nil, nil, false
			if state.stage >= 3 {
				state.stage = 3
				if len(fields) == 4 && fields[1] == "IP" && fields[2] == "address" {
					ip := net.ParseIP(fields[3])
					if ip.To4() != nil && ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
						state.clientIP, state.stage = ip.To4(), 4
					}
				}
			}
		case fields[0] == "primary" || fields[0] == "secondary":
			if state.stage < 4 {
				return
			}
			if len(fields) != 4 || fields[1] != "DNS" || fields[2] != "address" {
				state.servers, state.badDNS = nil, true
				return
			}
			ip := net.ParseIP(fields[3])
			if ip.To4() == nil || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				state.servers, state.badDNS = nil, true
				return
			}
			if state.badDNS {
				return
			}
			if fields[0] == "primary" {
				state.servers = nil
			}
			if len(state.servers) < 2 && (len(state.servers) == 0 || state.servers[0] != ip.String()) {
				state.servers = append(state.servers, ip.String())
			}
			state.stage = 5
		case strings.HasPrefix(message, "Connection terminated"),
			strings.HasPrefix(message, "Modem hangup"),
			strings.HasPrefix(message, "LCP terminated"),
			strings.HasPrefix(message, "IPCP terminated"),
			strings.HasPrefix(message, "Terminating on signal"),
			strings.HasPrefix(message, "No network protocols running"),
			strings.HasPrefix(message, "Exit"),
			strings.HasPrefix(message, "pppd "),
			strings.HasPrefix(message, "Plugin "):
			reset(pid)
		}
	}
	// Keep the same wrapped-record grammar as ndmc's DHCP parser, but never
	// retain arbitrary unbounded log text or associate across a discarded record.
	record, oversized := "", false
	flush := func() {
		if oversized {
			clear(processes)
			clear(latest)
		} else if record != "" {
			consume(record)
		}
	}
	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimRight(strings.ReplaceAll(line, "\x1b[K", ""), "\r")
		if len(line) > 4 && line[1:3] == " [" {
			flush()
			record, oversized = "", len(line) > shadowNativeLogRecord
			if !oversized {
				record = strings.TrimSpace(line)
			}
		} else if record != "" && !oversized && strings.HasPrefix(line, " ") {
			line = strings.TrimSpace(line)
			if len(record)+len(line)+1 > shadowNativeLogRecord {
				oversized = true
			} else {
				record += " " + line
			}
		}
	}
	flush()
	if exceedsBound {
		return nil
	}
	var result []keeneticShadowPPPSession
	devices := make([]string, 0, len(latest))
	for device := range latest {
		devices = append(devices, device)
	}
	sort.Strings(devices)
	for _, device := range devices {
		if state := latest[device]; state != nil && state.stage == 5 && state.sessionID != 0 && state.clientIP != nil && len(state.servers) != 0 && !state.badDNS {
			result = append(result, state.keeneticShadowPPPSession)
		}
	}
	return result
}

func shadowPPPDevice(device string) bool {
	unit, ok := strings.CutPrefix(device, "ppp")
	number, err := strconv.ParseUint(unit, 10, 32)
	return ok && validInterface(device) && err == nil && strconv.FormatUint(number, 10) == unit
}
