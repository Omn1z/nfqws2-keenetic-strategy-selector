// Package openwrtdns manages only the four OpenWrt options needed to bind the
// built-in DNS forwarder to this application's running local DNS listener.
package openwrtdns

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	routerpath "nfqws2strategy/internal/tools/path"
)

const snapshotName = "openwrt-dns-binding.json"

type Endpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}
type Binding struct {
	Interface string   `json:"interface"`
	Instance  string   `json:"instance"`
	Endpoint  Endpoint `json:"endpoint"`
}
type Interface struct {
	ID       string   `json:"id"`
	Label    string   `json:"label"`
	Protocol string   `json:"protocol"`
	Device   string   `json:"device"`
	Up       bool     `json:"up"`
	Default  bool     `json:"default"`
	DNS      []string `json:"dns"`
}
type Instance struct {
	ID       string   `json:"id"`
	Label    string   `json:"label"`
	Networks []string `json:"networks"`
	Enabled  bool     `json:"enabled"`
}
type State struct {
	Supported  bool        `json:"supported"`
	Reason     string      `json:"reason,omitempty"`
	Interfaces []Interface `json:"interfaces"`
	Instances  []Instance  `json:"instances"`
	Managed    bool        `json:"managed"`
	Pending    bool        `json:"pending,omitempty"`
	Binding    *Binding    `json:"binding,omitempty"`
	Conflict   string      `json:"conflict,omitempty"`
	Warnings   []string    `json:"warnings"`
	Revision   string      `json:"revision"`
}
type snapshot struct {
	Version          int               `json:"version"`
	Binding          Binding           `json:"binding"`
	Original         map[string]option `json:"original"`
	Applied          map[string]option `json:"applied"`
	Pending          bool              `json:"pending,omitempty"`
	Before           map[string]option `json:"before,omitempty"`
	InstanceIdentity string            `json:"instanceIdentity,omitempty"`
}
type runner func(context.Context, string, ...string) (string, error)
type Manager struct {
	mu        sync.Mutex
	filename  string
	supported bool
	run       runner
}

func New(dataDir string) *Manager {
	_, err := os.Stat("/etc/openwrt_release")
	return &Manager{filename: filepath.Join(dataDir, snapshotName), supported: runtime.GOOS == "linux" && routerpath.IsOpenWrt() && err == nil, run: execute}
}

func (m *Manager) CurrentBinding() (*Binding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.supported {
		return nil, nil
	}
	s, err := m.readSnapshot()
	if err != nil || s == nil {
		return nil, err
	}
	b := s.Binding
	return &b, nil
}
func (m *Manager) Managed() (bool, error) {
	binding, err := m.CurrentBinding()
	return binding != nil, err
}

type inspection struct {
	network, dhcp configuration
	backup        *snapshot
	current       map[string]option
	pending       bool
	revision      string
}

func (m *Manager) inspect(ctx context.Context) (inspection, error) {
	var result inspection
	for _, pkg := range []string{"network", "dhcp"} {
		out, err := m.run(ctx, "uci", "-q", "changes", pkg)
		if err != nil {
			return result, fmt.Errorf("проверка изменений UCI %s: %w", pkg, err)
		}
		result.pending = result.pending || strings.TrimSpace(out) != ""
	}
	for _, target := range []struct {
		name string
		into *configuration
	}{{"network", &result.network}, {"dhcp", &result.dhcp}} {
		out, err := m.run(ctx, "uci", "-q", "-N", "export", target.name)
		if err != nil {
			return result, fmt.Errorf("чтение UCI %s: %w", target.name, err)
		}
		*target.into, err = parseExport(out, target.name)
		if err != nil {
			return result, err
		}
	}
	var err error
	result.backup, err = m.readSnapshot()
	if err != nil {
		return result, err
	}
	if result.backup != nil {
		if err = checkInstanceIdentity(result.dhcp, result.backup); err != nil {
			return result, err
		}
		result.current, err = managedOptions(result.network, result.dhcp, result.backup.Binding)
		if err != nil {
			return result, err
		}
	}
	encoded, _ := json.Marshal(result.backup)
	sum := sha256.Sum256([]byte(result.network.Raw + "\x00" + result.dhcp.Raw + "\x00" + string(encoded)))
	result.revision = hex.EncodeToString(sum[:])
	return result, nil
}

func (m *Manager) Status(ctx context.Context) (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state := State{Supported: m.supported, Interfaces: []Interface{}, Instances: []Instance{}, Warnings: []string{}}
	if !m.supported {
		state.Reason = "Автоматическая настройка доступна только на OpenWrt с UCI и dnsmasq"
		return state, nil
	}
	view, err := m.inspect(ctx)
	if err != nil {
		return state, err
	}
	state.Revision = view.revision
	if view.pending {
		if view.backup == nil || !view.backup.Pending || m.guardChanges(ctx, view.current) != nil {
			state.Conflict = "В UCI есть несохранённые изменения network или dhcp. Сначала примените или отмените их."
		}
	}
	if view.backup != nil {
		state.Managed = true
		state.Pending = view.backup.Pending
		binding := view.backup.Binding
		state.Binding = &binding
		if conflict(view.current, view.backup) != nil {
			state.Conflict = "Управляемые DNS-параметры изменены вне приложения. Автоматическая перезапись остановлена."
		}
		if view.backup.Pending {
			state.Warnings = append(state.Warnings, "Предыдущее применение не завершено. Восстановите прежние DNS-настройки.")
		}
	}
	var live struct {
		Interfaces []struct {
			Name   string `json:"interface"`
			Up     bool   `json:"up"`
			Device string `json:"l3_device"`
			Route  []struct {
				Target string `json:"target"`
				Mask   int    `json:"mask"`
			} `json:"route"`
		} `json:"interface"`
	}
	if out, e := m.run(ctx, "ubus", "call", "network.interface", "dump"); e == nil {
		_ = json.Unmarshal([]byte(out), &live)
	}
	for _, s := range view.network.Sections {
		if s.Type != "interface" || s.ID == "loopback" || !validID(s.ID) {
			continue
		}
		i := Interface{ID: s.ID, Label: s.ID, Protocol: s.scalar("proto"), Device: s.scalar("device"), DNS: append([]string{}, s.Options["dns"].Values...)}
		for _, l := range live.Interfaces {
			if l.Name == s.ID {
				i.Up = l.Up
				if l.Device != "" {
					i.Device = l.Device
				}
				for _, r := range l.Route {
					if r.Mask == 0 && (r.Target == "0.0.0.0" || r.Target == "::") {
						i.Default = true
					}
				}
			}
		}
		state.Interfaces = append(state.Interfaces, i)
	}
	sort.SliceStable(state.Interfaces, func(i, j int) bool {
		if state.Interfaces[i].Default != state.Interfaces[j].Default {
			return state.Interfaces[i].Default
		}
		return state.Interfaces[i].ID < state.Interfaces[j].ID
	})
	for _, s := range view.dhcp.Sections {
		if s.Type == "dnsmasq" {
			state.Instances = append(state.Instances, Instance{ID: s.ID, Label: s.ID, Networks: append([]string{}, s.Options["interface"].Values...), Enabled: s.scalar("disabled") != "1" && s.scalar("port") != "0"})
			for _, key := range []string{"confdir", "serversfile"} {
				if s.scalar(key) != "" {
					state.Warnings = append(state.Warnings, "dnsmasq "+s.ID+": дополнительные "+key+" могут задавать DNS вне управляемой привязки; их содержимое не изменяется.")
				}
			}
		}
	}
	state.Warnings = append(state.Warnings, "DNS-forwarding выбранного dnsmasq применяется ко всем сетям, которые обслуживает этот экземпляр. Локальные и специальные доменные DNS-правила сохраняются.")
	return state, nil
}

func validateEndpoint(e Endpoint) error {
	ip := net.ParseIP(e.Host)
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || e.Port < 1 || e.Port > 65535 || e.Port == 53 {
		return fmt.Errorf("нужен локальный LAN IP работающего DNS-сервера и порт, отличный от 53")
	}
	return nil
}
func managedOptions(network, dhcp configuration, b Binding) (map[string]option, error) {
	n, ok := network.find(b.Interface, "interface")
	if !ok || b.Interface == "loopback" {
		return nil, fmt.Errorf("сетевой интерфейс UCI не найден")
	}
	d, ok := dhcp.find(b.Instance, "dnsmasq")
	if !ok {
		return nil, fmt.Errorf("экземпляр dnsmasq не найден")
	}
	return map[string]option{"network." + b.Interface + ".peerdns": n.Options["peerdns"], "network." + b.Interface + ".dns": n.Options["dns"], "dhcp." + b.Instance + ".noresolv": d.Options["noresolv"], "dhcp." + b.Instance + ".server": d.Options["server"]}, nil
}
func conflict(current map[string]option, s *snapshot) error {
	for key, value := range current {
		if reflect.DeepEqual(value, s.Applied[key]) {
			continue
		}
		if s.Pending && (reflect.DeepEqual(value, s.Before[key]) || value.Kind == "" || listPrefix(value, s.Applied[key]) || listPrefix(value, s.Before[key])) {
			continue
		}
		return fmt.Errorf("параметр %s изменён вне приложения", key)
	}
	return nil
}

func listPrefix(value, want option) bool {
	return value.Kind == "list" && want.Kind == "list" && len(value.Values) <= len(want.Values) && reflect.DeepEqual(value.Values, want.Values[:len(value.Values)])
}

func instanceIdentity(s section) string {
	values := map[string]option{}
	for key, value := range s.Options {
		if key != "server" && key != "noresolv" {
			values[key] = value
		}
	}
	encoded, _ := json.Marshal(values)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
func checkInstanceIdentity(c configuration, s *snapshot) error {
	if !strings.HasPrefix(s.Binding.Instance, "@") {
		return nil
	}
	selected, ok := c.find(s.Binding.Instance, "dnsmasq")
	if !ok || instanceIdentity(selected) != s.InstanceIdentity {
		return fmt.Errorf("анонимный экземпляр dnsmasq изменён или переставлен; автоматическая перезапись остановлена")
	}
	for _, other := range c.Sections {
		if other.Type == "dnsmasq" && other.ID != selected.ID && instanceIdentity(other) == s.InstanceIdentity {
			return fmt.Errorf("невозможно однозначно определить анонимный экземпляр dnsmasq")
		}
	}
	return nil
}

func (m *Manager) Apply(ctx context.Context, iface, instance string, endpoint Endpoint, revision string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.supported {
		return fmt.Errorf("автонастройка DNS поддерживается только на OpenWrt")
	}
	if !validID(iface) || !validInstance(instance) {
		return fmt.Errorf("некорректный идентификатор UCI")
	}
	if err := validateEndpoint(endpoint); err != nil {
		return err
	}
	unlock, err := lockTransaction(ctx, m.filename)
	if err != nil {
		return err
	}
	defer unlock()
	view, err := m.inspect(ctx)
	if err != nil {
		return err
	}
	if view.pending {
		return fmt.Errorf("сначала примените или отмените несохранённые изменения UCI network/dhcp")
	}
	if revision != "" && revision != view.revision {
		return fmt.Errorf("настройки OpenWrt изменились; обновите состояние и повторите")
	}
	binding := Binding{Interface: iface, Instance: instance, Endpoint: endpoint}
	current, err := managedOptions(view.network, view.dhcp, binding)
	if err != nil {
		return err
	}
	d, _ := view.dhcp.find(instance, "dnsmasq")
	if d.scalar("disabled") == "1" || d.scalar("port") == "0" {
		return fmt.Errorf("выбранный dnsmasq выключен или не обслуживает DNS")
	}
	if view.backup != nil {
		if view.backup.Binding.Interface != iface || view.backup.Binding.Instance != instance {
			return fmt.Errorf("сначала восстановите прежнюю привязку перед выбором другого интерфейса или dnsmasq")
		}
		if err := conflict(current, view.backup); err != nil {
			return err
		}
		if view.backup.Pending {
			return fmt.Errorf("предыдущее применение не завершено; сначала восстановите DNS")
		}
	}
	original := current
	if view.backup != nil {
		original = view.backup.Original
	}
	servers := []string{net.ParseIP(endpoint.Host).String() + "#" + strconv.Itoa(endpoint.Port)}
	for _, value := range current["dhcp."+instance+".server"].Values {
		if conditionalServer(value) {
			servers = append(servers, value)
		}
	}
	applied := map[string]option{"network." + iface + ".peerdns": {Kind: "option", Values: []string{"0"}}, "network." + iface + ".dns": {Kind: "list", Values: []string{net.ParseIP(endpoint.Host).String()}}, "dhcp." + instance + ".noresolv": {Kind: "option", Values: []string{"1"}}, "dhcp." + instance + ".server": {Kind: "list", Values: servers}}
	if view.backup != nil && reflect.DeepEqual(current, applied) && view.backup.Binding == binding {
		return nil
	}
	next := &snapshot{Version: 1, Binding: binding, Original: original, Applied: applied, Pending: true, Before: current}
	if strings.HasPrefix(instance, "@") {
		next.InstanceIdentity = instanceIdentity(d)
		if err = checkInstanceIdentity(view.dhcp, next); err != nil {
			return err
		}
	}
	if err = m.writeSnapshot(next); err != nil {
		return err
	}
	if err = m.replaceAndReload(ctx, current, applied, binding, next.InstanceIdentity); err != nil {
		return m.rollback(err, current, next, view.backup)
	}
	next.Pending = false
	next.Before = nil
	if err = m.writeSnapshot(next); err != nil {
		return m.rollback(err, current, next, view.backup)
	}
	return nil
}

func (m *Manager) Restore(ctx context.Context, revision string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.supported {
		return fmt.Errorf("автонастройка DNS поддерживается только на OpenWrt")
	}
	backup, err := m.readSnapshot()
	if err != nil || backup == nil {
		return err
	}
	unlock, err := lockTransaction(ctx, m.filename)
	if err != nil {
		return err
	}
	defer unlock()
	view, err := m.inspect(ctx)
	if err != nil {
		return err
	}
	if view.backup == nil {
		return nil
	}
	if view.pending {
		if !view.backup.Pending {
			return fmt.Errorf("сначала примените или отмените несохранённые изменения UCI network/dhcp")
		}
		if err = m.guardChanges(ctx, view.current); err != nil {
			return err
		}
	}
	if revision != "" && revision != view.revision {
		return fmt.Errorf("настройки OpenWrt изменились; обновите состояние")
	}
	if err := conflict(view.current, view.backup); err != nil {
		return err
	}
	saved := *view.backup
	pending := saved
	pending.Pending = true
	pending.Before = view.current
	pending.Applied = saved.Original
	if err = m.writeSnapshot(&pending); err != nil {
		return err
	}
	if err = m.replaceAndReload(ctx, view.current, saved.Original, saved.Binding, saved.InstanceIdentity); err != nil {
		return m.rollback(err, view.current, &pending, &saved)
	}
	if err = os.Remove(m.filename); err != nil && !os.IsNotExist(err) {
		return m.rollback(err, view.current, &pending, &saved)
	}
	return nil
}

func (m *Manager) replaceAndReload(ctx context.Context, current, desired map[string]option, binding Binding, identity string) error {
	keys := make([]string, 0, len(desired))
	for key := range desired {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := desired[key]
		if reflect.DeepEqual(current[key], value) {
			continue
		}
		if current[key].Kind != "" {
			if _, err := m.run(ctx, "uci", "-q", "delete", key); err != nil {
				return fmt.Errorf("очистка %s: %w", key, err)
			}
		}
		for _, entry := range value.Values {
			operation := "set"
			if value.Kind == "list" {
				operation = "add_list"
			}
			if _, err := m.run(ctx, "uci", "-q", operation, key+"="+entry); err != nil {
				return fmt.Errorf("запись %s: %w", key, err)
			}
		}
	}
	for _, pkg := range []string{"network", "dhcp"} {
		if err := m.guardChanges(ctx, desired); err != nil {
			return err
		}
		if _, err := m.run(ctx, "uci", "-q", "commit", pkg); err != nil {
			return fmt.Errorf("сохранение %s: %w", pkg, err)
		}
	}
	if _, err := m.run(ctx, "ubus", "call", "network", "reload"); err != nil {
		return fmt.Errorf("применение DNS интерфейса: %w", err)
	}
	reloadInstance, err := m.reloadInstance(ctx, binding.Instance)
	if err != nil {
		return err
	}
	if _, err := m.run(ctx, "/etc/init.d/dnsmasq", "reload", reloadInstance); err != nil {
		return fmt.Errorf("применение dnsmasq: %w", err)
	}
	return m.verifyApplied(ctx, desired, binding, identity)
}

func (m *Manager) rollback(cause error, before map[string]option, pending, previous *snapshot) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// Read the actual partial transaction; no unrelated option is restored.
	var network, dhcp configuration
	for _, v := range []struct {
		name string
		to   *configuration
	}{{"network", &network}, {"dhcp", &dhcp}} {
		out, err := m.run(ctx, "uci", "-q", "-N", "export", v.name)
		if err != nil {
			return errors.Join(cause, fmt.Errorf("откат не завершён: %w", err))
		}
		*v.to, err = parseExport(out, v.name)
		if err != nil {
			return errors.Join(cause, err)
		}
	}
	current, err := managedOptions(network, dhcp, pending.Binding)
	if err != nil {
		return errors.Join(cause, err)
	}
	if err = checkInstanceIdentity(dhcp, pending); err != nil {
		return errors.Join(cause, err)
	}
	recovery := *pending
	recovery.Pending = true
	recovery.Before = before
	if err = conflict(current, &recovery); err != nil {
		return errors.Join(cause, err)
	}
	if err = m.guardChanges(ctx, before); err != nil {
		return errors.Join(cause, err)
	}
	if err = m.replaceAndReload(ctx, current, before, pending.Binding, pending.InstanceIdentity); err != nil {
		return errors.Join(cause, fmt.Errorf("откат не завершён, резервная копия сохранена: %w", err))
	}
	if previous != nil {
		err = m.writeSnapshot(previous)
	} else {
		err = os.Remove(m.filename)
		if os.IsNotExist(err) {
			err = nil
		}
	}
	return errors.Join(cause, err)
}

func (m *Manager) readSnapshot() (*snapshot, error) {
	info, err := os.Lstat(m.filename)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return nil, fmt.Errorf("неверный файл резервной копии DNS OpenWrt")
	}
	data, err := os.ReadFile(m.filename)
	if err != nil {
		return nil, err
	}
	var s snapshot
	if err = json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("неверная резервная копия DNS: %w", err)
	}
	if err = validateSnapshot(&s); err != nil {
		return nil, err
	}
	return &s, nil
}
func validateSnapshot(s *snapshot) error {
	if s.Version != 1 || !validID(s.Binding.Interface) || !validInstance(s.Binding.Instance) || validateEndpoint(s.Binding.Endpoint) != nil || (strings.HasPrefix(s.Binding.Instance, "@") && len(s.InstanceIdentity) != 64) {
		return fmt.Errorf("неверная привязка DNS в резервной копии")
	}
	expected := []string{"network." + s.Binding.Interface + ".peerdns", "network." + s.Binding.Interface + ".dns", "dhcp." + s.Binding.Instance + ".noresolv", "dhcp." + s.Binding.Instance + ".server"}
	for _, values := range []map[string]option{s.Original, s.Applied} {
		if err := validateOptions(values, expected); err != nil {
			return err
		}
	}
	if s.Pending {
		if err := validateOptions(s.Before, expected); err != nil {
			return err
		}
	} else if len(s.Before) != 0 {
		return fmt.Errorf("неверная транзакция DNS")
	}
	return nil
}
func validateOptions(values map[string]option, keys []string) error {
	if len(values) != len(keys) {
		return fmt.Errorf("неверный набор управляемых DNS-полей")
	}
	for _, key := range keys {
		v, ok := values[key]
		if !ok || (v.Kind != "" && v.Kind != "list" && v.Kind != "option") || (v.Kind == "" && len(v.Values) != 0) || (v.Kind == "option" && len(v.Values) != 1) || (v.Kind == "list" && len(v.Values) == 0) || len(v.Values) > 256 {
			return fmt.Errorf("неверный параметр резервной копии DNS")
		}
		for _, entry := range v.Values {
			if len(entry) > 4096 || strings.ContainsAny(entry, "\x00\r\n") {
				return fmt.Errorf("неверное значение резервной копии DNS")
			}
		}
	}
	return nil
}
func (m *Manager) writeSnapshot(s *snapshot) error {
	if err := validateSnapshot(s); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > 64<<10 {
		return fmt.Errorf("резервная копия DNS слишком велика")
	}
	if err = os.MkdirAll(filepath.Dir(m.filename), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(m.filename), ".openwrt-dns-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, m.filename)
}
