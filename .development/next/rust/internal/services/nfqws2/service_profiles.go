package nfqws2

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

const (
	MaxServiceStrategies         = 64
	MaxServiceGroups             = 32
	MaxServiceEntries            = 2048
	MaxServiceTotalEntries       = 32768
	MaxServiceStrategyBytes      = 32768
	MaxServiceStrategyTokens     = 2048
	MaxServiceTotalStrategyBytes = 1048576
)

// ServiceStrategy owns explicitly scoped nfqws2 profiles. Disabled services
// remain editable drafts and contribute no profiles, lists or firewall ports.
type ServiceStrategy struct {
	ID      string                 `json:"id"`
	Name    string                 `json:"name"`
	Enabled bool                   `json:"enabled"`
	Groups  []ServiceStrategyGroup `json:"groups"`
}

type ServiceStrategyGroup struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Kind     string   `json:"kind"`
	Entries  []string `json:"entries"`
	Strategy string   `json:"strategy"`
}

// CompiledServiceStrategies contains argv, never executable shell source.
// Args contains --new between profiles, with no leading/trailing separator.
// Lists keys are managed basenames; TCPPorts/UDPPorts use iptables ':' ranges.
type CompiledServiceStrategies struct {
	Services        []ServiceStrategy `json:"services"`
	Args            []string          `json:"args"`
	Lists           map[string]string `json:"lists"`
	TCPPorts        string            `json:"tcp_ports"`
	UDPPorts        string            `json:"udp_ports"`
	EnabledServices int               `json:"enabled_services"`
	EnabledGroups   int               `json:"enabled_groups"`
	Profiles        int               `json:"profiles"`
	Warnings        []string          `json:"warnings"`
}

var serviceIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
var serviceMethodPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// NormalizeServiceStrategies copies, bounds and normalizes user input without
// mutating it. Enabled profiles are validated here as well as by the compiler.
func NormalizeServiceStrategies(services []ServiceStrategy) ([]ServiceStrategy, error) {
	if len(services) > MaxServiceStrategies {
		return nil, fmt.Errorf("допустимо не более %d сервисов", MaxServiceStrategies)
	}
	out := make([]ServiceStrategy, 0, len(services))
	serviceIDs := make(map[string]bool)
	totalEntries := 0
	totalStrategyBytes := 0
	for _, service := range services {
		if !serviceIDPattern.MatchString(service.ID) || serviceIDs[strings.ToLower(service.ID)] {
			return nil, fmt.Errorf("некорректный или повторяющийся ID сервиса %q", service.ID)
		}
		serviceIDs[strings.ToLower(service.ID)] = true
		name, err := normalizeServiceName(service.Name)
		if err != nil {
			return nil, fmt.Errorf("сервис %q: %w", service.ID, err)
		}
		if len(service.Groups) > MaxServiceGroups {
			return nil, fmt.Errorf("сервис %q: допустимо не более %d групп", name, MaxServiceGroups)
		}
		result := ServiceStrategy{ID: service.ID, Name: name, Enabled: service.Enabled, Groups: make([]ServiceStrategyGroup, 0, len(service.Groups))}
		groupIDs := make(map[string]bool)
		for _, group := range service.Groups {
			if !serviceIDPattern.MatchString(group.ID) || groupIDs[strings.ToLower(group.ID)] {
				return nil, fmt.Errorf("сервис %q: некорректный или повторяющийся ID группы %q", name, group.ID)
			}
			groupIDs[strings.ToLower(group.ID)] = true
			groupName, err := normalizeServiceName(group.Name)
			if err != nil {
				return nil, fmt.Errorf("сервис %q, группа %q: %w", name, group.ID, err)
			}
			if group.Kind != "domains" && group.Kind != "ips" {
				return nil, fmt.Errorf("сервис %q, группа %q: тип должен быть domains или ips", name, groupName)
			}
			if len(group.Entries) > MaxServiceEntries {
				return nil, fmt.Errorf("сервис %q, группа %q: допустимо не более %d записей", name, groupName, MaxServiceEntries)
			}
			totalEntries += len(group.Entries)
			if totalEntries > MaxServiceTotalEntries {
				return nil, fmt.Errorf("допустимо не более %d записей во всех сервисах", MaxServiceTotalEntries)
			}
			entries := make([]string, 0, len(group.Entries))
			seen := make(map[string]bool)
			for _, entry := range group.Entries {
				if len(entry) > 512 || !utf8.ValidString(entry) {
					return nil, fmt.Errorf("сервис %q, группа %q: слишком длинная или некорректная запись", name, groupName)
				}
				entry = strings.TrimSpace(entry)
				if entry == "" || strings.HasPrefix(entry, "#") {
					continue
				}
				if group.Kind == "domains" {
					entry, err = NormalizeServiceDomain(entry)
				} else {
					entry, err = normalizeServiceIP(entry)
				}
				if err != nil {
					return nil, fmt.Errorf("сервис %q, группа %q: %w", name, groupName, err)
				}
				if !seen[entry] {
					entries = append(entries, entry)
					seen[entry] = true
				}
			}
			strategy := strings.TrimSpace(group.Strategy)
			totalStrategyBytes += len(group.Strategy)
			if totalStrategyBytes > MaxServiceTotalStrategyBytes {
				return nil, fmt.Errorf("общий размер стратегий превышает %d байт", MaxServiceTotalStrategyBytes)
			}
			if len(group.Strategy) > MaxServiceStrategyBytes || !utf8.ValidString(strategy) {
				return nil, fmt.Errorf("сервис %q, группа %q: стратегия превышает %d байт или содержит некорректный текст", name, groupName, MaxServiceStrategyBytes)
			}
			if err := validateServiceStrategyText(strategy); err != nil {
				return nil, fmt.Errorf("сервис %q, группа %q: %w", name, groupName, err)
			}
			if service.Enabled && (len(entries) != 0 || strategy != "") {
				if len(entries) == 0 || strategy == "" {
					return nil, fmt.Errorf("сервис %q, группа %q: для включения нужны записи и стратегия", name, groupName)
				}
				if _, _, _, err := compileServiceGroupProfiles(strategy); err != nil {
					return nil, fmt.Errorf("сервис %q, группа %q: %w", name, groupName, err)
				}
			}
			result.Groups = append(result.Groups, ServiceStrategyGroup{ID: group.ID, Name: groupName, Kind: group.Kind, Entries: entries, Strategy: strategy})
		}
		out = append(out, result)
	}
	if err := validateServiceTargetConflicts(out); err != nil {
		return nil, err
	}
	return out, nil
}

func normalizeServiceName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > 120 {
		return "", fmt.Errorf("имя должно содержать от 1 до 120 символов")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("имя содержит управляющий символ")
		}
	}
	return name, nil
}

// NormalizeServiceDomain accepts an apex, its '*.apex' spelling or an IDN.
// nfqws2 hostlists include subdomains, so all three spellings share one scope.
func NormalizeServiceDomain(value string) (string, error) {
	original := value
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "*.")
	value = strings.TrimPrefix(value, ".")
	value = strings.TrimSuffix(value, ".")
	value, err := idna.Lookup.ToASCII(value)
	value = strings.ToLower(value)
	if err != nil || value == "" || len(value) > 253 || !strings.Contains(value, ".") {
		return "", fmt.Errorf("некорректный домен %q", original)
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return "", fmt.Errorf("IP-адрес %q должен находиться в IP-группе", original)
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("некорректный домен %q", original)
		}
		for _, c := range label {
			if c < 'a' || c > 'z' {
				if c < '0' || c > '9' {
					if c != '-' {
						return "", fmt.Errorf("некорректный домен %q", original)
					}
				}
			}
		}
	}
	return value, nil
}

func normalizeServiceIP(value string) (string, error) {
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Zone() != "" {
			return "", fmt.Errorf("некорректная IP-сеть %q", value)
		}
		if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		prefix = prefix.Masked()
		if prefix.Bits() == prefix.Addr().BitLen() {
			return prefix.Addr().String(), nil
		}
		return prefix.String(), nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil || addr.Zone() != "" {
		return "", fmt.Errorf("некорректный IP-адрес %q", value)
	}
	return addr.Unmap().String(), nil
}

// CompileServiceStrategies produces scoped service profiles in input order.
// The caller must prepend these to its global profiles (nfqws2 selects the
// first matching profile) and serialize each argv token safely for its runtime.
func CompileServiceStrategies(services []ServiceStrategy, listsDir string) (CompiledServiceStrategies, error) {
	normalized, err := NormalizeServiceStrategies(services)
	if err != nil {
		return CompiledServiceStrategies{}, err
	}
	result := CompiledServiceStrategies{Services: normalized, Args: []string{}, Lists: make(map[string]string), Warnings: []string{}}
	var tcp, udp servicePortSet
	hasDomains, hasIPs := false, false
	for _, service := range normalized {
		if !service.Enabled {
			continue
		}
		result.EnabledServices++
		for _, group := range service.Groups {
			if len(group.Entries) == 0 && group.Strategy == "" {
				continue
			}
			if strings.IndexFunc(listsDir, unicode.IsSpace) >= 0 {
				return CompiledServiceStrategies{}, fmt.Errorf("путь к спискам сервиса содержит пробелы: nfqws2-keenetic не поддерживает такие пути")
			}
			profiles, groupTCP, groupUDP, err := compileServiceGroupProfiles(group.Strategy)
			if err != nil { // Kept local so callers never need to trust stored drafts.
				return CompiledServiceStrategies{}, fmt.Errorf("сервис %q, группа %q: %w", service.Name, group.Name, err)
			}
			listContent := strings.Join(group.Entries, "\n") + "\n"
			basename := serviceListBasename(service.ID, group.ID, group.Kind, listContent)
			result.Lists[basename] = listContent
			flag := "--hostlist="
			if group.Kind == "ips" {
				hasIPs = true
				flag = "--ipset="
			} else {
				hasDomains = true
			}
			for _, profile := range profiles {
				if len(result.Args) != 0 {
					result.Args = append(result.Args, "--new")
				}
				result.Args = append(result.Args, flag+filepath.ToSlash(filepath.Join(listsDir, basename)))
				result.Args = append(result.Args, profile...)
				result.Profiles++
			}
			result.EnabledGroups++
			tcp.merge(&groupTCP)
			udp.merge(&groupUDP)
		}
	}
	result.TCPPorts, result.UDPPorts = tcp.String(), udp.String()
	if hasDomains && hasIPs {
		result.Warnings = append(result.Warnings, "Доменные и IP-зоны могут пересекаться после DNS-разрешения; при пересечении применяется первый подходящий профиль в порядке сервисов и групп.")
	}
	return result, nil
}

func serviceListBasename(serviceID, groupID, kind, content string) string {
	digest := sha256.Sum256([]byte(content))
	return fmt.Sprintf("n2s_service_%s_%s_%s_%x.list", serviceID, groupID, kind, digest[:8])
}

func validateServiceStrategyText(strategy string) error {
	for _, r := range strategy {
		if (unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t') || r == '$' || r == '`' || r == ';' || r == '|' || r == '&' {
			return fmt.Errorf("стратегия содержит запрещённый символ %q: shell-команды и подстановки не поддерживаются", r)
		}
	}
	return nil
}

// lexServiceStrategy is a shell-like argument lexer, deliberately without any
// expansion or execution. Quotes preserve spaces; backslash-newline continues
// a line. A '#' at the beginning of a token starts a line comment.
func lexServiceStrategy(strategy string) ([]string, error) {
	if err := validateServiceStrategyText(strategy); err != nil {
		return nil, err
	}
	tokens := make([]string, 0)
	var token strings.Builder
	var quote byte
	started := false
	flush := func() {
		if started {
			tokens = append(tokens, token.String())
			token.Reset()
			started = false
		}
	}
	for i := 0; i < len(strategy); i++ {
		c := strategy[i]
		if c == '\\' && quote != '\'' {
			if i+1 >= len(strategy) {
				return nil, fmt.Errorf("стратегия заканчивается незавершённым экранированием")
			}
			next := strategy[i+1]
			if next == '\n' {
				i++
				continue
			}
			if next == '\r' && i+2 < len(strategy) && strategy[i+2] == '\n' {
				i += 2
				continue
			}
			if quote == '"' && next != '"' && next != '\\' {
				token.WriteByte(c)
				started = true
				continue
			}
			token.WriteByte(next)
			started = true
			i++
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			} else {
				token.WriteByte(c)
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote, started = c, true
		case ' ', '\t', '\r', '\n':
			flush()
		case '#':
			if !started {
				for i < len(strategy) && strategy[i] != '\n' {
					i++
				}
			} else {
				token.WriteByte(c)
			}
		default:
			token.WriteByte(c)
			started = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("незакрытая кавычка в стратегии")
	}
	flush()
	if len(tokens) > MaxServiceStrategyTokens {
		return nil, fmt.Errorf("слишком много аргументов стратегии")
	}
	for _, token := range tokens {
		if strings.IndexFunc(token, unicode.IsSpace) >= 0 {
			return nil, fmt.Errorf("аргумент стратегии %q содержит пробел: nfqws2-keenetic не поддерживает пробелы внутри аргумента", token)
		}
	}
	return tokens, nil
}

func compileServiceGroupProfiles(strategy string) ([][]string, servicePortSet, servicePortSet, error) {
	var tcp, udp servicePortSet
	tokens, err := lexServiceStrategy(strategy)
	if err != nil {
		return nil, tcp, udp, err
	}
	profiles := make([][]string, 0, 1)
	start := 0
	for i := 0; i <= len(tokens); i++ {
		if i != len(tokens) && tokens[i] != "--new" {
			continue
		}
		if i == start {
			return nil, tcp, udp, fmt.Errorf("пустой профиль: --new разрешён только между заполненными профилями")
		}
		profile := tokens[start:i]
		transportSeen := false
		for _, token := range profile {
			key, value, hasValue := strings.Cut(token, "=")
			if !hasValue || value == "" {
				return nil, tcp, udp, fmt.Errorf("аргумент %q должен иметь вид --параметр=значение", token)
			}
			switch key {
			case "--filter-tcp", "--filter-udp":
				ports, err := parseServicePorts(value)
				if err != nil {
					return nil, tcp, udp, fmt.Errorf("%s: %w", key, err)
				}
				transportSeen = true
				if key == "--filter-tcp" {
					tcp.merge(&ports)
				} else {
					udp.merge(&ports)
				}
			case "--filter-l3", "--filter-l7", "--payload", "--in-range", "--out-range":
			case "--lua-desync":
				method, _, _ := strings.Cut(value, ":")
				if !serviceMethodPattern.MatchString(method) {
					return nil, tcp, udp, fmt.Errorf("некорректный метод --lua-desync %q", method)
				}
			default:
				if !strings.HasPrefix(key, "--dpi-desync") {
					return nil, tcp, udp, fmt.Errorf("параметр %s не поддерживается внутри сервиса: списки задаются группой, глобальные параметры — в конфигурации", key)
				}
			}
		}
		if !transportSeen {
			return nil, tcp, udp, fmt.Errorf("профиль %d: укажите --filter-tcp или --filter-udp для автоматического определения портов", len(profiles)+1)
		}
		profiles = append(profiles, profile)
		start = i + 1
	}
	return profiles, tcp, udp, nil
}

type servicePortSet [1024]uint64

func (ports *servicePortSet) merge(other *servicePortSet) {
	for i := range ports {
		ports[i] |= other[i]
	}
}

func (ports *servicePortSet) includes(port int) bool {
	return ports[port/64]&(uint64(1)<<uint(port%64)) != 0
}

func (ports *servicePortSet) addRange(lo, hi int) {
	if lo > hi {
		return
	}
	first, last := lo/64, hi/64
	lowMask := ^uint64(0) << uint(lo%64)
	highMask := ^uint64(0) >> uint(63-hi%64)
	if first == last {
		ports[first] |= lowMask & highMask
		return
	}
	ports[first] |= lowMask
	for word := first + 1; word < last; word++ {
		ports[word] = ^uint64(0)
	}
	ports[last] |= highMask
}

func (ports *servicePortSet) String() string {
	ranges := []string{}
	for lo := 1; lo <= 65535; lo++ {
		if !ports.includes(lo) {
			continue
		}
		hi := lo
		for hi+1 <= 65535 && ports.includes(hi+1) {
			hi++
		}
		item := strconv.Itoa(lo)
		if hi != lo {
			item += ":" + strconv.Itoa(hi)
		}
		ranges = append(ranges, item)
		lo = hi
	}
	return strings.Join(ranges, ",")
}

// nfqws2 ORs comma-separated and repeated filters. '~' negates one entry,
// rather than subtracting from the preceding entries; preserve that behavior.
func parseServicePorts(value string) (servicePortSet, error) {
	var ports servicePortSet
	for _, item := range strings.Split(value, ",") {
		negated := strings.HasPrefix(item, "~")
		item = strings.TrimPrefix(item, "~")
		lo, hi := uint64(1), uint64(65535)
		if item != "*" {
			loText, hiText, ranged := strings.Cut(item, "-")
			if !ranged {
				hiText = loText
			}
			if !decimalServicePort(loText) || !decimalServicePort(hiText) {
				return ports, fmt.Errorf("некорректный фильтр портов %q: используйте 443, 80-90, ~443 или *", value)
			}
			var loErr, hiErr error
			lo, loErr = strconv.ParseUint(loText, 10, 16)
			hi, hiErr = strconv.ParseUint(hiText, 10, 16)
			if loErr != nil || hiErr != nil || lo == 0 || hi == 0 || lo > hi {
				return ports, fmt.Errorf("некорректный фильтр портов %q: допустимы порты 1–65535", value)
			}
		}
		if negated {
			ports.addRange(1, int(lo)-1)
			ports.addRange(int(hi)+1, 65535)
		} else {
			ports.addRange(int(lo), int(hi))
		}
	}
	for _, included := range ports {
		if included != 0 {
			return ports, nil
		}
	}
	return ports, fmt.Errorf("фильтр %q не выбирает ни одного порта", value)
}

func decimalServicePort(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

type serviceTargetGroup struct {
	service string
	group   string
	kind    string
	entries []string
}

func validateServiceTargetConflicts(services []ServiceStrategy) error {
	type target struct {
		owner  serviceTargetGroup
		entry  string
		key    string
		prefix netip.Prefix
		group  int
	}
	var domains, ips []target
	groupIndex := 0
	for _, service := range services {
		if !service.Enabled {
			continue
		}
		for _, group := range service.Groups {
			if len(group.Entries) == 0 {
				continue
			}
			owner := serviceTargetGroup{service.Name, group.Name, group.Kind, nil}
			for _, entry := range group.Entries {
				item := target{owner: owner, entry: entry, group: groupIndex}
				if group.Kind == "domains" {
					labels := strings.Split(entry, ".")
					for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
						labels[i], labels[j] = labels[j], labels[i]
					}
					item.key = strings.Join(labels, ".") + "."
					domains = append(domains, item)
				} else {
					item.prefix = serviceIPPrefix(entry)
					ips = append(ips, item)
				}
			}
			groupIndex++
		}
	}
	conflict := func(a, b target) error {
		return fmt.Errorf("конфликт зон: сервис %q / группа %q (%s) пересекается с сервисом %q / группой %q (%s); разделите зоны или отключите один сервис", a.owner.service, a.owner.group, a.entry, b.owner.service, b.owner.group, b.entry)
	}
	sort.SliceStable(domains, func(i, j int) bool { return domains[i].key < domains[j].key })
	var stack []target
	for _, item := range domains {
		for len(stack) > 0 && !strings.HasPrefix(item.key, stack[len(stack)-1].key) {
			stack = stack[:len(stack)-1]
		}
		for _, parent := range stack {
			if item.group != parent.group {
				return conflict(parent, item)
			}
		}
		stack = append(stack, item)
	}
	sort.SliceStable(ips, func(i, j int) bool {
		if c := ips[i].prefix.Addr().Compare(ips[j].prefix.Addr()); c != 0 {
			return c < 0
		}
		return ips[i].prefix.Bits() < ips[j].prefix.Bits()
	})
	stack = nil
	for _, item := range ips {
		for len(stack) > 0 && !stack[len(stack)-1].prefix.Overlaps(item.prefix) {
			stack = stack[:len(stack)-1]
		}
		for _, parent := range stack {
			if item.group != parent.group {
				return conflict(parent, item)
			}
		}
		stack = append(stack, item)
	}
	return nil
}

// MergeServicePorts unions static firewall port lists. iptables multiport has
// fifteen slots, and a range consumes two slots. Refuse a larger result instead
// of silently leaving a service's packets outside the queue.
func MergeServicePorts(base, extra string) (string, error) {
	var merged servicePortSet
	for _, source := range []string{base, extra} {
		if strings.TrimSpace(source) == "" {
			continue
		}
		for _, item := range strings.Split(source, ",") {
			item = strings.TrimSpace(item)
			item = strings.ReplaceAll(item, ":", "-")
			if strings.Contains(item, "~") || item == "*" {
				return "", fmt.Errorf("неподдерживаемый список firewall-портов %q", source)
			}
			ports, err := parseServicePorts(item)
			if err != nil {
				return "", err
			}
			merged.merge(&ports)
		}
	}
	result := merged.String()
	slots := 0
	if result != "" {
		for _, item := range strings.Split(result, ",") {
			slots++
			if strings.Contains(item, ":") {
				slots++
			}
		}
	}
	if slots > 15 {
		return "", fmt.Errorf("суммарный список портов требует %d слотов: iptables multiport допускает 15; объедините соседние порты в диапазоны", slots)
	}
	return result, nil
}

func serviceIPPrefix(value string) netip.Prefix {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix
	}
	addr := netip.MustParseAddr(value)
	return netip.PrefixFrom(addr, addr.BitLen())
}
