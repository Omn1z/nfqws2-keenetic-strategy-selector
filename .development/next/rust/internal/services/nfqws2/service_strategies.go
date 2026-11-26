package nfqws2

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"nfqws2strategy/internal/tools/config"
)

var ErrServiceStrategiesChanged = errors.New("настройки NFQWS2 изменились; загрузите сервисы заново перед сохранением")

func managedServiceList(name string) bool {
	base := filepath.Base(strings.TrimSuffix(name, ".gz"))
	return strings.HasPrefix(base, "n2s_service_") && strings.HasSuffix(base, ".list")
}

var errManagedServiceList = errors.New("список управляется вкладкой «Сервисы»; измените зоны в группе сервиса")

type ServiceStrategiesState struct {
	Services        []ServiceStrategy `json:"services"`
	Revision        string            `json:"revision"`
	TCPPorts        string            `json:"tcp_ports"`
	UDPPorts        string            `json:"udp_ports"`
	Profiles        int               `json:"profiles"`
	RestartRequired bool              `json:"restart_required"`
	Warnings        []string          `json:"warnings"`
}

type ServiceStrategiesPreview struct {
	TCPPorts string   `json:"tcp_ports"`
	UDPPorts string   `json:"udp_ports"`
	Profiles int      `json:"profiles"`
	Warnings []string `json:"warnings"`
	Args     string   `json:"args"`
}

type serviceStrategiesDocument struct {
	Services        []ServiceStrategy `json:"services"`
	RestartRequired bool              `json:"restart_required"`
}

func (m *Manager) serviceStrategiesLocation() assetLocation {
	return assetLocation{m.cfg.DataDir, "nfqws2-service-strategies.json", "conf"}
}

func (m *Manager) serviceStrategiesRead() (serviceStrategiesDocument, []byte, []byte, error) {
	doc := serviceStrategiesDocument{Services: []ServiceStrategy{}}
	data, _, err := readAssetLocation(m.serviceStrategiesLocation())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return doc, nil, nil, err
	}
	if err == nil {
		if err = json.Unmarshal(data, &doc); err != nil {
			return doc, nil, nil, fmt.Errorf("сервисы: %w", err)
		}
	}
	if doc.Services == nil {
		doc.Services = []ServiceStrategy{}
	}
	conf, err := readCapped(m.cfg.Nfqws2Conf)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return doc, nil, nil, err
	}
	return doc, data, conf, nil
}

func serviceStrategiesRevision(data, conf []byte) string {
	h := sha256.New()
	h.Write(data)
	h.Write([]byte{0})
	h.Write(conf)
	return hex.EncodeToString(h.Sum(nil))
}

func serviceConfigBase(source string) (string, error) {
	from, to, found, err := config.ManagedServiceConfigRange(source)
	if err != nil {
		return "", err
	}
	if !found {
		return source, nil
	}
	return source[:from] + source[to:], nil
}

func compileServiceConfig(source string, services []ServiceStrategy, listsDir string) (CompiledServiceStrategies, string, string, string, error) {
	compiled, err := CompileServiceStrategies(services, listsDir)
	if err != nil {
		return compiled, "", "", "", err
	}
	base, err := serviceConfigBase(source)
	if err != nil {
		return compiled, "", "", "", err
	}
	ports := [2]string{}
	for i, key := range []string{"TCP_PORTS", "UDP_PORTS"} {
		extra := compiled.TCPPorts
		if i == 1 {
			extra = compiled.UDPPorts
		}
		value, _, e := config.LiteralShellConfigValue(base, key)
		if e != nil {
			if extra != "" {
				return compiled, "", "", "", fmt.Errorf("%s: для автоматических портов сервиса задайте исходные порты явно: %w", key, e)
			}
			continue
		}
		if extra == "" {
			ports[i] = value
			continue
		}
		ports[i], e = MergeServicePorts(value, extra)
		if e != nil {
			return compiled, "", "", "", fmt.Errorf("%s: %w", key, e)
		}
	}
	if compiled.Profiles == 0 {
		return compiled, base, ports[0], ports[1], nil
	}
	if source == "" {
		return compiled, "", "", "", fmt.Errorf("nfqws2.conf не найден; сначала настройте движок NFQWS2")
	}
	// The vendor init expands CUSTOM before the global profiles. Conditional
	// separation avoids an empty catch-all profile when CUSTOM was empty.
	args := strings.Join(compiled.Args, " ")
	escaped := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "$", "\\$", "`", "\\`").Replace(args)
	var block strings.Builder
	if !strings.HasSuffix(base, "\n") {
		block.WriteByte('\n')
	}
	block.WriteString("# BEGIN N2S SERVICE STRATEGIES\n")
	block.WriteString("NFQWS_ARGS_CUSTOM=\"" + escaped + "${NFQWS_ARGS_CUSTOM:+ --new }${NFQWS_ARGS_CUSTOM}\"\n")
	if compiled.TCPPorts != "" {
		block.WriteString("TCP_PORTS='" + ports[0] + "'\n")
	}
	if compiled.UDPPorts != "" {
		block.WriteString("UDP_PORTS='" + ports[1] + "'\n")
	}
	block.WriteString("# END N2S SERVICE STRATEGIES\n")
	output := base + block.String()
	if _, _, _, err := config.ManagedServiceConfigRange(output); err != nil {
		return compiled, "", "", "", err
	}
	return compiled, output, ports[0], ports[1], nil
}

func (m *Manager) serviceStrategiesState(doc serviceStrategiesDocument, data, conf []byte) (ServiceStrategiesState, error) {
	compiled, expectedConf, tcp, udp, err := compileServiceConfig(string(conf), doc.Services, filepath.ToSlash(filepath.Join(filepath.Dir(m.cfg.Nfqws2Conf), "lists")))
	if err != nil {
		return ServiceStrategiesState{}, err
	}
	return ServiceStrategiesState{Services: compiled.Services, Revision: serviceStrategiesRevision(data, conf), TCPPorts: tcp, UDPPorts: udp, Profiles: compiled.Profiles, RestartRequired: doc.RestartRequired || expectedConf != string(conf), Warnings: compiled.Warnings}, nil
}

func (m *Manager) ServiceStrategies() (ServiceStrategiesState, error) {
	m.assetsMu.Lock()
	defer m.assetsMu.Unlock()
	doc, data, conf, err := m.serviceStrategiesRead()
	if err != nil {
		return ServiceStrategiesState{}, err
	}
	return m.serviceStrategiesState(doc, data, conf)
}

func (m *Manager) PreviewServiceStrategies(services []ServiceStrategy) (ServiceStrategiesPreview, error) {
	m.assetsMu.Lock()
	defer m.assetsMu.Unlock()
	_, _, conf, err := m.serviceStrategiesRead()
	if err != nil {
		return ServiceStrategiesPreview{}, err
	}
	compiled, _, tcp, udp, err := compileServiceConfig(string(conf), services, filepath.ToSlash(filepath.Join(filepath.Dir(m.cfg.Nfqws2Conf), "lists")))
	if err != nil {
		return ServiceStrategiesPreview{}, err
	}
	return ServiceStrategiesPreview{TCPPorts: tcp, UDPPorts: udp, Profiles: compiled.Profiles, Warnings: compiled.Warnings, Args: strings.Join(compiled.Args, " ")}, nil
}

type serviceFileUpdate struct {
	loc  assetLocation
	data []byte
	mode os.FileMode
}

// All content is validated before writes; replace the config last, with rollback
// on any failure. Lists are kept when disabled because the running engine may
// still use them until a full restart (SIGHUP is not sufficient).
func applyServiceFiles(updates []serviceFileUpdate) error {
	type previous struct {
		update serviceFileUpdate
		data   []byte
		mode   os.FileMode
		exists bool
	}
	before := make([]previous, 0, len(updates))
	for _, u := range updates {
		data, mode, err := readAssetLocation(u.loc)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		before = append(before, previous{u, data, mode, err == nil})
	}
	for i, u := range updates {
		if err := writeAssetLocation(u.loc, u.data, u.mode); err != nil {
			var rollback []error
			for j := i - 1; j >= 0; j-- {
				p := before[j]
				var e error
				if p.exists {
					e = writeAssetLocation(p.update.loc, p.data, p.mode)
				} else {
					e = removeAssetLocation(p.update.loc)
				}
				if e != nil {
					rollback = append(rollback, e)
				}
			}
			return errors.Join(append([]error{err}, rollback...)...)
		}
	}
	return nil
}

func (m *Manager) SaveServiceStrategies(services []ServiceStrategy, revision string) (ServiceStrategiesState, error) {
	m.assetsMu.Lock()
	defer m.assetsMu.Unlock()
	doc, oldData, conf, err := m.serviceStrategiesRead()
	if err != nil {
		return ServiceStrategiesState{}, err
	}
	if revision == "" || revision != serviceStrategiesRevision(oldData, conf) {
		return ServiceStrategiesState{}, ErrServiceStrategiesChanged
	}
	listsDir := filepath.ToSlash(filepath.Join(filepath.Dir(m.cfg.Nfqws2Conf), "lists"))
	compiled, nextConf, _, _, err := compileServiceConfig(string(conf), services, listsDir)
	if err != nil {
		return ServiceStrategiesState{}, err
	}
	updates := []serviceFileUpdate{}
	listNames := make([]string, 0, len(compiled.Lists))
	for name := range compiled.Lists {
		listNames = append(listNames, name)
	}
	sort.Strings(listNames)
	runtimeChanged := nextConf != string(conf)
	for _, name := range listNames {
		loc := assetLocation{listsDir, name, "list"}
		old, _, e := readAssetLocation(loc)
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return ServiceStrategiesState{}, e
		}
		if string(old) != compiled.Lists[name] {
			runtimeChanged = true
			updates = append(updates, serviceFileUpdate{loc, []byte(compiled.Lists[name]), 0644})
		}
	}
	doc.Services = compiled.Services
	doc.RestartRequired = doc.RestartRequired || runtimeChanged
	nextData, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return ServiceStrategiesState{}, err
	}
	nextData = append(nextData, '\n')
	updates = append(updates, serviceFileUpdate{m.serviceStrategiesLocation(), nextData, 0600})
	if nextConf != string(conf) {
		updates = append(updates, serviceFileUpdate{assetLocation{filepath.Dir(m.cfg.Nfqws2Conf), filepath.Base(m.cfg.Nfqws2Conf), "conf"}, []byte(nextConf), 0644})
	}
	if err = applyServiceFiles(updates); err != nil {
		return ServiceStrategiesState{}, err
	}
	return m.serviceStrategiesState(doc, nextData, []byte(nextConf))
}

// A concurrent save during restart must stay pending for another restart.
func (m *Manager) ServiceStrategiesApplied(revision string) error {
	if revision == "" {
		return nil
	}
	m.assetsMu.Lock()
	defer m.assetsMu.Unlock()
	doc, data, conf, err := m.serviceStrategiesRead()
	if err != nil {
		return err
	}
	if revision == "" || revision != serviceStrategiesRevision(data, conf) {
		return nil
	}
	if !doc.RestartRequired {
		return nil
	}
	doc.RestartRequired = false
	data, err = json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return writeAssetLocation(m.serviceStrategiesLocation(), append(data, '\n'), 0600)
}

// Base ports/strategies may have changed in the raw editor. Regenerate the
// override immediately before a full start so it uses those current values.
func (m *Manager) PrepareServiceStrategies() error {
	state, err := m.ServiceStrategies()
	if err != nil {
		return err
	}
	if !state.RestartRequired {
		return nil
	}
	_, err = m.SaveServiceStrategies(state.Services, state.Revision)
	return err
}
