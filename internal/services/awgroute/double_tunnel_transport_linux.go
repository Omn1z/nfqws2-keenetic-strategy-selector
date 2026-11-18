//go:build linux

package awgroute

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"nfqws2strategy/internal/services/awg"
)

// Bit 29 prevents the LAN routing chains from remarking these sockets. Bit 31
// separates their exact selectors from the diagnostic and LAN routing rules.
const doubleTunnelMarkPrefix uint32 = 0xa0000000

// DNS routing uses 701–827 and LAN AWG policy uses 901–964. Keep this
// range between them, within the numeric IDs accepted by Keenetic BusyBox.
const doubleTunnelTableBase = 828
const doubleTunnelTableSlots = 72
const doubleTunnelRouteProto = "99"

type doubleTunnelTransport struct {
	OuterIface string `json:"outer_iface"`
	Endpoint   string `json:"endpoint"`
	MTU        int    `json:"mtu"`
}

type doubleTunnelSelector struct {
	mark  uint32
	table string
}

func newDoubleTunnelSelector(iface string) (doubleTunnelSelector, error) {
	if !validAWGClientIfaceName(iface) {
		return doubleTunnelSelector{}, fmt.Errorf("некорректный интерфейс двойного туннеля")
	}
	slot, err := strconv.ParseUint(iface[3:], 10, 28)
	if err != nil || "awg"+strconv.FormatUint(slot, 10) != iface {
		return doubleTunnelSelector{}, fmt.Errorf("некорректный номер интерфейса двойного туннеля")
	}
	return doubleTunnelSelector{
		mark:  doubleTunnelMarkPrefix | uint32(slot),
		table: strconv.FormatUint(doubleTunnelTableBase+slot%doubleTunnelTableSlots, 10),
	}, nil
}

func (s doubleTunnelSelector) markArg() string { return fmt.Sprintf("0x%x", s.mark) }

func doubleTunnelStatePath(iface string) string {
	return filepath.Join(filepath.Dir(awgSockPath(iface)), iface+".double-tunnel.json")
}

func readDoubleTunnelTransport(iface string) (doubleTunnelTransport, error) {
	var state doubleTunnelTransport
	data, err := os.ReadFile(doubleTunnelStatePath(iface))
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return state, err
	}
	if !validAWGClientIfaceName(state.OuterIface) || state.OuterIface == iface || net.ParseIP(state.Endpoint) == nil || state.MTU < 576 {
		return state, fmt.Errorf("состояние двойного туннеля повреждено")
	}
	return state, nil
}

func doubleTunnelAddress(iface string, endpoint net.IP, allowed string) (net.IP, int, error) {
	if strings.TrimSpace(allowed) != "" {
		covered := false
		for _, entry := range strings.Split(allowed, ",") {
			_, prefix, _ := net.ParseCIDR(strings.TrimSpace(entry))
			if prefix != nil && prefix.Contains(endpoint) {
				covered = true
				break
			}
		}
		if !covered {
			return nil, 0, fmt.Errorf("адрес основного AWG отсутствует в AllowedIPs внешнего туннеля")
		}
	}
	link, err := net.InterfaceByName(iface)
	if err != nil || link.Flags&net.FlagUp == 0 {
		return nil, 0, fmt.Errorf("внешний интерфейс %s недоступен", iface)
	}
	addresses, err := link.Addrs()
	if err != nil {
		return nil, 0, err
	}
	for _, address := range addresses {
		ip, _, _ := net.ParseCIDR(address.String())
		if ip != nil && (ip.To4() != nil) == (endpoint.To4() != nil) && !ip.IsLinkLocalUnicast() {
			return ip, link.MTU, nil
		}
	}
	return nil, 0, fmt.Errorf("у внешнего интерфейса %s нет адреса для этого семейства IP", iface)
}

func doubleTunnelMTU(cfg awg.ServerConfig, outerMTU int, ipv4 bool) (int, error) {
	// Transport header and tag (32), UDP (8), and the transport IP header.
	// AWG caps normal alignment padding at the effective TUN MTU, and
	// RandomTrailers at its adaptive UDP window. An unusually large
	// configured handshake or junk packet can still exceed the path MTU.
	overhead := 80
	if ipv4 {
		overhead = 60
	}
	if cfg.UseObfuscation() {
		overhead += cfg.Obf.S4
		// AWG 3.1 uses adaptive trailers and content padding. Preserve headroom
		// for explicit ContentPaddingAddition regardless of the current window.
		padding := strings.TrimSpace(cfg.Obf.ContentPaddingAddition)
		if dash := strings.LastIndexByte(padding, '-'); dash >= 0 {
			padding = strings.TrimSpace(padding[dash+1:])
		}
		if padding != "" {
			maximum, err := strconv.ParseUint(padding, 10, 16)
			if err != nil {
				return 0, fmt.Errorf("некорректный ContentPaddingAddition внутреннего AWG")
			}
			overhead += int(maximum)
		}
	}
	mtu := min(awgTunnelMTU(cfg), outerMTU-overhead)
	if mtu < 576 {
		return 0, fmt.Errorf("MTU внешнего туннеля недостаточен для двойного туннеля с этим профилем AWG")
	}
	return mtu, nil
}

// Check the entire family, including rule references to our table, before
// touching reserved IDs. After a restart, the state file identifies our exact
// selectors and routes, so repair can restore them without flushing a table.
func (s doubleTunnelSelector) inspect(family string, state *doubleTunnelTransport, run func(string) (string, error)) (map[string]bool, bool, error) {
	rules, err := run(family + " rule show")
	if err != nil {
		if family == "ip -6" && (strings.Contains(rules, "Address family not supported") || strings.Contains(rules, "Protocol not supported")) {
			return nil, false, nil
		}
		return nil, false, awgCmdErr(family+" rule show", rules, err)
	}
	present := make(map[string]bool)
	for _, line := range strings.Split(rules, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		full := strings.Join(fields, " ")
		mark := s.markArg()
		lookup := "60: from all fwmark " + mark + " lookup " + s.table
		guard := "61: from all fwmark " + mark
		guardOutput := strings.TrimPrefix(strings.TrimPrefix(full, guard+" "), "lookup main ")
		if full == lookup || guardOutput == "prohibit" || guardOutput == "reject" {
			if state == nil {
				return nil, false, fmt.Errorf("маркер двойного туннеля уже используется")
			}
			present[fields[0]] = true
			continue
		}
		if err := s.checkOtherRule(fields); err != nil {
			return nil, false, err
		}
	}
	command := family + " route show table " + s.table
	routes, err := run(command)
	if err != nil && !strings.Contains(routes, "FIB table does not exist") {
		return nil, false, awgCmdErr(command, routes, err)
	}
	if err != nil {
		return present, true, nil
	}
	for _, line := range strings.Split(routes, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if state == nil || !state.ownsRoute(fields) {
			return nil, false, fmt.Errorf("таблица двойного туннеля %s содержит чужие маршруты", s.table)
		}
	}
	return present, true, nil
}

func (s doubleTunnelSelector) checkOtherRule(fields []string) error {
	priority, err := strconv.Atoi(strings.TrimSuffix(fields[0], ":"))
	higherPriority := err != nil || priority <= 61
	selectorMatch, masked := true, false
	for i := 1; i+1 < len(fields); i++ {
		if (fields[i] == "lookup" || fields[i] == "table") && fields[i+1] == s.table {
			return fmt.Errorf("таблица двойного туннеля %s уже используется", s.table)
		}
		if fields[i] == "fwmark" {
			masked = true
			if strings.SplitN(fields[i+1], "/", 2)[0] == s.markArg() {
				return fmt.Errorf("маркер двойного туннеля уже используется другим правилом")
			}
			selectorMatch = doubleTunnelMarkMatches(s.mark, fields[i+1])
		}
	}
	// Keep the standard local table ahead of our rules. An earlier socket
	// mark selector or unconditional route could divert the nested UDP.
	markedRuleMatches := masked && selectorMatch != (fields[1] == "not")
	unconditionalLookup := !masked && len(fields) == 5 && fields[1] == "from" && fields[2] == "all" && fields[3] == "lookup" && fields[4] != "local"
	if higherPriority && (markedRuleMatches || unconditionalLookup) {
		return fmt.Errorf("более приоритетное правило маршрутизации пересекается с двойным туннелем")
	}
	return nil
}

func doubleTunnelMarkMatches(mark uint32, value string) bool {
	text, maskText, hasMask := strings.Cut(value, "/")
	valueMark, err := strconv.ParseUint(text, 0, 32)
	if err != nil {
		return true
	}
	mask := uint64(0xffffffff)
	if hasMask {
		mask, err = strconv.ParseUint(maskText, 0, 32)
		if err != nil {
			return true
		}
	}
	return uint64(mark)&mask == valueMark&mask
}

// BusyBox omits protocol in route output. Verify the destination, interface
// and guard metric as well as the protocol field when the tool reports it.
func (state doubleTunnelTransport) ownsRoute(fields []string) bool {
	has := func(key, value string) bool {
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == key && fields[i+1] == value {
				return true
			}
		}
		return false
	}
	for i, field := range fields {
		if field == "proto" && (i+1 == len(fields) || fields[i+1] != doubleTunnelRouteProto) {
			return false
		}
	}
	if len(fields) >= 2 && fields[0] == "blackhole" && fields[1] == "default" {
		return has("metric", "1000")
	}
	addr, bits, hasPrefix := strings.Cut(fields[0], "/")
	ip := net.ParseIP(addr)
	if ip == nil || !ip.Equal(net.ParseIP(state.Endpoint)) {
		return false
	}
	return (!hasPrefix || ip.To4() != nil && bits == "32" || ip.To4() == nil && bits == "128") && has("dev", state.OuterIface)
}

func (s doubleTunnelSelector) apply(family string, present map[string]bool, route string, run func(string) (string, error)) error {
	mark := " fwmark " + s.markArg()
	commands := make([]string, 0, 4)
	if !present["61:"] {
		commands = append(commands, family+" rule add pref 61"+mark+" type prohibit")
	}
	commands = append(commands, family+" route replace blackhole default table "+s.table+" protocol "+doubleTunnelRouteProto+" metric 1000")
	if route != "" {
		commands = append(commands, family+" route replace "+route+" table "+s.table+" protocol "+doubleTunnelRouteProto)
	}
	if !present["60:"] {
		commands = append(commands, family+" rule add pref 60"+mark+" table "+s.table)
	}
	for _, command := range commands {
		if out, err := run(command); err != nil {
			return awgCmdErr(command, out, err)
		}
	}
	return nil
}

func doubleTunnelCommand(ctx context.Context) func(string) (string, error) {
	return func(cmd string) (string, error) {
		commandCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		return awgRunShell(commandCtx, cmd, "")
	}
}

func (svc *Service) prepareDoubleTunnelTransportOS(inner, outer *awg.Manager, endpoint string) (uint32, int, error) {
	innerCfg, outerCfg := inner.RuntimeConfig(), outer.RuntimeConfig()
	iface, outerIface := awgClientIface(innerCfg), awgClientIface(outerCfg)
	if iface == outerIface {
		return 0, 0, fmt.Errorf("двойной туннель не может использовать собственный интерфейс")
	}
	selector, err := newDoubleTunnelSelector(iface)
	if err != nil {
		return 0, 0, err
	}
	endpointIP := net.ParseIP(endpoint)
	peer, ok := outer.RouterPeer()
	if !ok || endpointIP == nil {
		return 0, 0, fmt.Errorf("внешний пир или адрес основного AWG недоступен")
	}
	source, outerMTU, err := doubleTunnelAddress(outerIface, endpointIP, peer.AllowedIPs)
	if err != nil {
		return 0, 0, err
	}
	mtu, err := doubleTunnelMTU(innerCfg, outerMTU, endpointIP.To4() != nil)
	if err != nil {
		return 0, 0, err
	}
	previous, err := readDoubleTunnelTransport(iface)
	owned := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, 0, err
	}
	if owned && (previous.OuterIface != outerIface || previous.Endpoint != endpointIP.String()) {
		return 0, 0, fmt.Errorf("сначала переподключите основной AWG для смены внешнего транспорта")
	}
	ctx := svc.clientOpContext()
	run := doubleTunnelCommand(ctx)
	var ownership *doubleTunnelTransport
	if owned {
		ownership = &previous
	}
	ipv4, _, err := selector.inspect("ip", ownership, run)
	if err != nil {
		return 0, 0, err
	}
	ipv6, hasIPv6, err := selector.inspect("ip -6", ownership, run)
	if err != nil {
		return 0, 0, err
	}
	if !hasIPv6 && endpointIP.To4() == nil {
		return 0, 0, fmt.Errorf("роутер не поддерживает IPv6-маршрутизацию для двойного туннеля")
	}
	state := doubleTunnelTransport{OuterIface: outerIface, Endpoint: endpointIP.String(), MTU: mtu}
	if previous != state {
		data, err := json.Marshal(state)
		if err != nil {
			return 0, 0, err
		}
		path := doubleTunnelStatePath(iface)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return 0, 0, err
		}
		if err := writeFile0600(path, string(data)); err != nil {
			return 0, 0, err
		}
	}
	v4Route, v6Route := "", ""
	if endpointIP.To4() != nil {
		v4Route = endpointIP.String() + "/32 dev " + outerIface + " src " + source.String()
	} else {
		v6Route = endpointIP.String() + "/128 dev " + outerIface + " src " + source.String()
	}
	if err := selector.apply("ip", ipv4, v4Route, run); err != nil {
		return 0, 0, err
	}
	if hasIPv6 {
		if err := selector.apply("ip -6", ipv6, v6Route, run); err != nil {
			return 0, 0, err
		}
	}
	return selector.mark, mtu, nil
}

func (svc *Service) repairDoubleTunnelTransportOS(inner, outer *awg.Manager) error {
	iface := awgClientIface(inner.RuntimeConfig())
	state, err := readDoubleTunnelTransport(iface)
	if err != nil {
		return err
	}
	_, mtu, err := svc.prepareDoubleTunnelTransportOS(inner, outer, state.Endpoint)
	if err != nil {
		return err
	}
	if link, err := net.InterfaceByName(iface); err == nil && link.MTU == mtu {
		return nil
	}
	command := "ip link set " + iface + " mtu " + strconv.Itoa(mtu)
	out, err := doubleTunnelCommand(svc.clientOpContext())(command)
	if err != nil {
		return awgCmdErr(command, out, err)
	}
	return nil
}

func clearDoubleTunnelTransportOS(ctx context.Context, iface string) error {
	path := doubleTunnelStatePath(iface)
	state, err := readDoubleTunnelTransport(iface)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	selector, err := newDoubleTunnelSelector(iface)
	if err != nil {
		return err
	}
	run := doubleTunnelCommand(ctx)
	for _, family := range []string{"ip", "ip -6"} {
		present, enabled, err := selector.inspect(family, &state, run)
		if err != nil {
			return err
		}
		if !enabled {
			continue
		}
		mark := " fwmark " + selector.markArg()
		commands := []string{}
		routeCmd := family + " route show table " + selector.table
		routes, err := run(routeCmd)
		if err != nil && !strings.Contains(routes, "FIB table does not exist") {
			return awgCmdErr(routeCmd, routes, err)
		}
		for _, line := range strings.Split(routes, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 || !state.ownsRoute(fields) {
				continue
			}
			table := " table " + selector.table + " protocol " + doubleTunnelRouteProto
			if fields[0] == "blackhole" {
				commands = append(commands, family+" route del blackhole default"+table+" metric 1000")
			} else {
				commands = append(commands, family+" route del "+fields[0]+" dev "+state.OuterIface+table)
			}
		}
		if present["60:"] {
			commands = append(commands, family+" rule del pref 60"+mark+" table "+selector.table)
		}
		if present["61:"] {
			commands = append(commands, family+" rule del pref 61"+mark+" type prohibit")
		}
		for _, command := range commands {
			if out, err := run(command); err != nil {
				return awgCmdErr(command, out, err)
			}
		}
	}
	return os.Remove(path)
}

// The running inner interface may be smaller than its saved direct-path MTU.
func awgActiveTunnelMTU(cfg awg.ServerConfig) int {
	if state, err := readDoubleTunnelTransport(awgClientIface(cfg)); err == nil {
		return state.MTU
	}
	return awgTunnelMTU(cfg)
}
