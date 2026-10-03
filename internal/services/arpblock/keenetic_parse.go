package arpblock

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

var nativeBridgePattern = regexp.MustCompile(`^Bridge(0|[1-9][0-9]*)$`)
var nativeAPPattern = regexp.MustCompile(`^WifiMaster(0|[1-9][0-9]*)/AccessPoint(0|[1-9][0-9]*)$`)
var nativeIDPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_./:-]*$`)
var nativeEscape = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

// NativeConfig deliberately contains no credentials or other running-config
// lines. It is safe to hash for an optimistic-concurrency revision.
type NativeConfig struct {
	Bridges                []NativeBridgeConfig
	AccessPoints           []NativeAccessPointConfig
	IsolatePrivate         bool
	IsolatePrivateExplicit bool
}

type NativeBridgeConfig struct {
	ID, Rename, Description, SecurityLevel, Address, Mask              string
	Members                                                            []string
	Up, Global, PeerIsolation, PeerIsolationExplicit, ExplicitSecurity bool
}

type NativeAccessPointConfig struct {
	ID, Rename, Description, SSID string
	Up                            bool
}

type NativeBridgeStatus struct {
	ID, Type, InterfaceName, State, SecurityLevel, Address, Mask string
	Global, GlobalExplicit                                       bool
}

type nativeConfigBlock struct {
	id    string
	lines []string
}

// ParseKeeneticConfig reads the native hierarchy without executing or retaining
// arbitrary commands. Only direct children of interface blocks are relevant.
func ParseKeeneticConfig(text string) (NativeConfig, error) {
	out := NativeConfig{Bridges: []NativeBridgeConfig{}, AccessPoints: []NativeAccessPointConfig{}, IsolatePrivate: true}
	if len(text) > 2<<20 {
		return out, fmt.Errorf("конфигурация Keenetic слишком велика")
	}
	text = nativeEscape.ReplaceAllString(strings.ReplaceAll(text, "\r", ""), "")
	var blocks []nativeConfigBlock
	current := -1
	ids := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "!") {
			if len(line) == len(strings.TrimLeft(line, " \t")) {
				current = -1
			}
			continue
		}
		if len(line) != len(strings.TrimLeft(line, " \t")) {
			if current >= 0 {
				blocks[current].lines = append(blocks[current].lines, line)
			}
			continue
		}
		current = -1
		if trimmed == "isolate-private" || trimmed == "no isolate-private" {
			if out.IsolatePrivateExplicit {
				return out, fmt.Errorf("неоднозначный isolate-private в конфигурации")
			}
			out.IsolatePrivate, out.IsolatePrivateExplicit = trimmed == "isolate-private", true
		}
		if !strings.HasPrefix(trimmed, "interface ") && !strings.HasPrefix(trimmed, "interface\t") {
			continue
		}
		parts := strings.Fields(trimmed)
		if len(parts) != 2 || !nativeIDPattern.MatchString(parts[1]) {
			return out, fmt.Errorf("некорректный заголовок интерфейса Keenetic")
		}
		if ids[parts[1]] {
			return out, fmt.Errorf("повторный блок интерфейса Keenetic")
		}
		ids[parts[1]] = true
		blocks = append(blocks, nativeConfigBlock{id: parts[1]})
		current = len(blocks) - 1
	}
	aliases := map[string]string{}
	for id := range ids {
		aliases[id] = id
	}
	for _, block := range blocks {
		bridge, ap, err := parseNativeBlock(block)
		if err != nil {
			return out, err
		}
		alias := bridge.Rename
		if alias == "" {
			alias = ap.Rename
		}
		if alias != "" {
			if existing, ok := aliases[alias]; ok && existing != block.id {
				return out, fmt.Errorf("неоднозначный псевдоним интерфейса Keenetic")
			}
			aliases[alias] = block.id
		}
		if nativeBridgePattern.MatchString(block.id) {
			out.Bridges = append(out.Bridges, bridge)
		}
		if nativeAPPattern.MatchString(block.id) {
			out.AccessPoints = append(out.AccessPoints, ap)
		}
	}
	if len(out.Bridges) == 0 {
		return out, fmt.Errorf("в конфигурации не найдены сегменты Bridge")
	}
	return out, nil
}

func parseNativeBlock(block nativeConfigBlock) (NativeBridgeConfig, NativeAccessPointConfig, error) {
	b := NativeBridgeConfig{ID: block.id, Members: []string{}}
	a := NativeAccessPointConfig{ID: block.id}
	isBridge, isAP := nativeBridgePattern.MatchString(block.id), nativeAPPattern.MatchString(block.id)
	depth := int(^uint(0) >> 1)
	for _, line := range block.lines {
		if n := len(line) - len(strings.TrimLeft(line, " \t")); n < depth {
			depth = n
		}
	}
	seen := map[string]bool{}
	for _, line := range block.lines {
		if len(line)-len(strings.TrimLeft(line, " \t")) != depth {
			continue
		}
		line = strings.TrimSpace(line)
		words := strings.Fields(line)
		if len(words) == 0 {
			continue
		}
		key := words[0]
		if key == "no" && len(words) > 1 {
			key = words[1]
		}
		if key == "name" {
			key = "rename"
		}
		if !isBridge && !isAP && key != "rename" {
			continue
		}
		if isAP && key != "rename" && key != "description" && key != "ssid" && key != "up" && key != "down" {
			continue
		}
		switch key {
		case "rename", "description", "security-level", "include", "inherit", "peer-isolation", "up", "down", "ssid", "ip":
		default:
			continue
		}
		if key == "ip" && (len(words) < 2 || (words[1] != "address" && words[1] != "global")) {
			continue
		}
		if key == "ip" {
			key += " " + words[1]
		}
		if key == "down" {
			key = "up"
		}
		if key != "include" && key != "inherit" {
			if seen[key] {
				return b, a, fmt.Errorf("неоднозначное поле %s интерфейса", key)
			}
			seen[key] = true
		}
		args, err := nativeWords(line)
		if err != nil {
			return b, a, fmt.Errorf("некорректное поле %s интерфейса", key)
		}
		bad := func() (NativeBridgeConfig, NativeAccessPointConfig, error) {
			return b, a, fmt.Errorf("некорректное поле %s интерфейса", key)
		}
		switch key {
		case "rename", "description", "ssid", "security-level":
			if len(args) != 2 {
				return bad()
			}
			switch key {
			case "rename":
				b.Rename = args[1]
				a.Rename = args[1]
			case "description":
				b.Description = args[1]
				a.Description = args[1]
			case "ssid":
				a.SSID = args[1]
			case "security-level":
				if args[1] != "private" && args[1] != "protected" && args[1] != "public" {
					return bad()
				}
				b.SecurityLevel = args[1]
				b.ExplicitSecurity = true
			}
		case "include", "inherit":
			if len(args) != 2 || !nativeIDPattern.MatchString(args[1]) {
				return bad()
			}
			if contains(b.Members, args[1]) {
				return bad()
			}
			b.Members = append(b.Members, args[1])
		case "peer-isolation":
			if line != "peer-isolation" && line != "no peer-isolation" {
				return bad()
			}
			b.PeerIsolation = line == "peer-isolation"
			b.PeerIsolationExplicit = true
		case "up":
			if line != "up" && line != "no up" && line != "down" {
				return bad()
			}
			b.Up = line == "up"
			a.Up = b.Up
		case "ip global":
			b.Global = true
		case "ip address":
			if len(args) != 4 || !validNativeIPv4(args[2], args[3]) {
				return bad()
			}
			b.Address = args[2]
			b.Mask = args[3]
		}
	}
	return b, a, nil
}

// nativeWords only decodes quoting for known, non-secret scalar fields.
func nativeWords(line string) ([]string, error) {
	var words []string
	for len(line) > 0 {
		line = strings.TrimLeft(line, " \t")
		if line == "" {
			break
		}
		if line[0] != '"' {
			n := strings.IndexAny(line, " \t")
			if n < 0 {
				n = len(line)
			}
			if strings.ContainsAny(line[:n], "\"\x00\r\n") {
				return nil, fmt.Errorf("invalid token")
			}
			words = append(words, line[:n])
			line = line[n:]
			continue
		}
		var value strings.Builder
		closed := false
		i := 1
		for ; i < len(line); i++ {
			if line[i] == '"' {
				closed = true
				i++
				break
			}
			if line[i] == '\\' {
				i++
				if i == len(line) {
					break
				}
				if line[i] == 'x' && i+2 < len(line) {
					if decoded, err := strconv.ParseUint(line[i+1:i+3], 16, 8); err == nil {
						if decoded < 32 || decoded == 127 {
							return nil, fmt.Errorf("invalid quoted token")
						}
						value.WriteByte(byte(decoded))
						i += 2
						continue
					}
				}
				// Native dumps use hex-escaped UTF-8. Preserve unknown escape
				// forms rather than silently deleting meaningful backslashes.
				if line[i] != '\\' && line[i] != '"' {
					value.WriteByte('\\')
				}
			}
			if line[i] < 32 {
				return nil, fmt.Errorf("invalid quoted token")
			}
			value.WriteByte(line[i])
		}
		if !closed || (i < len(line) && line[i] != ' ' && line[i] != '\t') {
			return nil, fmt.Errorf("invalid quotation")
		}
		words = append(words, value.String())
		line = line[i:]
	}
	return words, nil
}

func validNativeIPv4(address, mask string) bool {
	ip := net.ParseIP(address).To4()
	m := net.ParseIP(mask).To4()
	if ip == nil || m == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	ones, bits := net.IPMask(m).Size()
	return bits == 32 && ones > 0 && ones < 32
}

func ParseKeeneticInterfaceStatus(text, expectedID string) (NativeBridgeStatus, error) {
	var out NativeBridgeStatus
	if !nativeBridgePattern.MatchString(expectedID) || len(text) > 256<<10 {
		return out, fmt.Errorf("некорректный идентификатор или ответ интерфейса")
	}
	text = nativeEscape.ReplaceAllString(strings.ReplaceAll(text, "\r", ""), "")
	column := -1
	for _, line := range strings.Split(text, "\n") {
		if i := strings.IndexByte(line, ':'); i >= 0 && strings.TrimSpace(line[:i]) == "id" && (column < 0 || i < column) {
			column = i
		}
	}
	fields := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		i := strings.IndexByte(line, ':')
		if i < 0 || i != column {
			continue
		}
		key := strings.TrimSpace(line[:i])
		switch key {
		case "id", "type", "interface-name", "state", "security-level", "address", "mask", "global":
		default:
			continue
		}
		if _, exists := fields[key]; exists {
			return out, fmt.Errorf("неоднозначное поле статуса интерфейса")
		}
		fields[key] = strings.TrimSpace(line[i+1:])
	}
	if fields["id"] != expectedID || fields["type"] != "Bridge" {
		return out, fmt.Errorf("Keenetic не подтвердил идентичность Bridge")
	}
	out = NativeBridgeStatus{ID: fields["id"], Type: fields["type"], InterfaceName: fields["interface-name"], State: fields["state"], SecurityLevel: fields["security-level"], Address: fields["address"], Mask: fields["mask"]}
	if value, ok := fields["global"]; ok {
		if value != "yes" && value != "no" {
			return out, fmt.Errorf("неизвестное состояние global интерфейса")
		}
		out.GlobalExplicit = true
		out.Global = value == "yes"
	}
	return out, nil
}

func ValidatePeerIsolationTarget(b NativeBridgeConfig, s NativeBridgeStatus) error {
	if !nativeBridgePattern.MatchString(b.ID) || s.ID != b.ID || s.Type != "Bridge" {
		return fmt.Errorf("не подтверждён интерфейс LAN Bridge")
	}
	if !b.ExplicitSecurity || (b.SecurityLevel != "private" && b.SecurityLevel != "protected") || s.SecurityLevel != b.SecurityLevel {
		return fmt.Errorf("не подтверждён локальный уровень безопасности сегмента")
	}
	if b.Global || !s.GlobalExplicit || s.Global {
		return fmt.Errorf("WAN/global интерфейс нельзя изменять")
	}
	if !b.Up || s.State != "up" {
		return fmt.Errorf("сегмент выключен")
	}
	if len(b.Members) == 0 {
		return fmt.Errorf("к сегменту не подключены интерфейсы")
	}
	if !validNativeIPv4(b.Address, b.Mask) || s.Address != b.Address || s.Mask != b.Mask {
		return fmt.Errorf("не подтверждён адрес локального сегмента")
	}
	if b.Rename != "" && s.InterfaceName != b.Rename {
		return fmt.Errorf("псевдоним сегмента изменился")
	}
	return nil
}
