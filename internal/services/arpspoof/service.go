package arpspoof

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"nfqws2strategy/internal/tools/config"
	"nfqws2strategy/internal/tools/store"
)

const stateFile = "arp_spoofing.json"

const arpRefreshInterval = 30 * time.Second

var (
	reMACPrefix = regexp.MustCompile(`^[0-9A-Fa-f]{2}([:-]?[0-9A-Fa-f]{2}){0,2}$`)
	reIfaceName = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)
)

// Service persists the desired fake router MAC and applies L2 firewall rules.
type Service struct {
	cfg   *config.Config
	store *store.Store

	mu        sync.Mutex
	config    Config
	lastError string
	appliedAt int64
	origMACs  map[string]string

	stopRefresh chan struct{}
}

func New(cfg *config.Config, st *store.Store) *Service {
	s := &Service{cfg: cfg, store: st}
	var stt state
	if err := st.Load(stateFile, &stt); err == nil {
		s.config = normalizeConfig(stt.Config)
		if hasWirelessSlaveIface(s.config.Ifaces) {
			s.config.Ifaces = nil
		}
		s.lastError = stt.LastError
		s.appliedAt = stt.AppliedAt
		s.origMACs = cleanMACMap(stt.OriginalMACs)
	}
	if s.origMACs == nil {
		s.origMACs = map[string]string{}
	}
	if s.config.VendorID == "" {
		s.config.VendorID = "huawei"
	}
	if s.config.Prefix == "" {
		s.config.Prefix = firstVendorPrefix(s.config.VendorID)
	}
	return s
}

func (s *Service) View() View {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.viewLocked()
}

func (s *Service) viewLocked() View {
	cfg := normalizeConfig(s.config)
	ifaces := interfaceCandidates(s.cfg.WANIfaces)
	return View{
		Config:          cfg,
		Vendors:         Vendors(),
		Ifaces:          ifaces,
		SuggestedIfaces: suggestedInterfaceNames(ifaces),
		HookPath:        hookPath,
		Tools:           toolStatus(),
		Active:          cfg.Enabled && s.lastError == "",
		LastError:       s.lastError,
		AppliedAt:       s.appliedAt,
	}
}

func (s *Service) SaveConfig(in Config) (View, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, err := s.prepareConfig(in)
	if err != nil {
		return s.viewLocked(), err
	}
	s.config = cfg
	err = s.saveApply()
	return s.viewLocked(), err
}

func (s *Service) SetEnabled(enabled bool) (View, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg := s.config
	cfg.Enabled = enabled
	if enabled {
		prepared, err := s.prepareConfig(cfg)
		if err != nil {
			return s.viewLocked(), err
		}
		cfg = prepared
	} else {
		cfg = normalizeConfig(cfg)
		cfg.Enabled = false
		cfg.UpdatedAt = time.Now().Unix()
	}
	s.config = cfg
	err := s.saveApply()
	return s.viewLocked(), err
}

func (s *Service) Apply() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, err := s.prepareConfig(s.config)
	if err != nil {
		s.lastError = err.Error()
		_ = s.save()
		return err
	}
	s.config = cfg
	return s.saveApply()
}

func (s *Service) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopRefreshLocked()
}

func (s *Service) GenerateMAC(prefix string) (string, error) {
	p, err := normalizePrefix(prefix)
	if err != nil {
		return "", err
	}
	return generateMAC(p)
}

func (s *Service) prepareConfig(in Config) (Config, error) {
	cfg := Config{
		Enabled:   in.Enabled,
		VendorID:  strings.TrimSpace(in.VendorID),
		Ifaces:    cleanIfaces(in.Ifaces),
		UpdatedAt: in.UpdatedAt,
	}
	if cfg.VendorID == "" {
		cfg.VendorID = "custom"
	}
	prefix := strings.TrimSpace(in.Prefix)
	if prefix == "" {
		cfg.Prefix = firstVendorPrefix(cfg.VendorID)
	} else {
		p, err := normalizePrefix(prefix)
		if err != nil {
			return Config{}, err
		}
		cfg.Prefix = p
		if cfg.VendorID != "" && cfg.VendorID != "custom" && !vendorHasPrefix(cfg.VendorID, cfg.Prefix) {
			cfg.VendorID = "custom"
		}
	}
	mac := strings.TrimSpace(in.MAC)
	if mac == "" && cfg.Prefix != "" && cfg.Enabled {
		mac, err := generateMAC(cfg.Prefix)
		if err != nil {
			return Config{}, err
		}
		cfg.MAC = mac
	}
	if mac != "" {
		normalized, err := normalizeMAC(mac)
		if err != nil {
			return Config{}, err
		}
		cfg.MAC = normalized
	}
	if cfg.Enabled {
		if cfg.MAC == "" {
			return Config{}, fmt.Errorf("fake MAC is empty")
		}
	}
	cfg.UpdatedAt = time.Now().Unix()
	return cfg, nil
}

func (s *Service) saveApply() error {
	if err := s.applyConfig(s.config); err != nil {
		s.lastError = err.Error()
		if s.config.Enabled {
			s.startRefreshLocked()
		} else {
			s.stopRefreshLocked()
		}
		_ = s.save()
		return err
	}
	s.lastError = ""
	s.appliedAt = time.Now().Unix()
	if s.config.Enabled {
		s.startRefreshLocked()
	} else {
		s.stopRefreshLocked()
	}
	return s.save()
}

func (s *Service) save() error {
	return s.store.Save(stateFile, state{Config: s.config, LastError: s.lastError, AppliedAt: s.appliedAt, OriginalMACs: s.origMACs})
}

func (s *Service) startRefreshLocked() {
	if s.stopRefresh != nil {
		return
	}
	stop := make(chan struct{})
	s.stopRefresh = stop
	go s.refreshLoop(stop)
}

func (s *Service) stopRefreshLocked() {
	if s.stopRefresh == nil {
		return
	}
	close(s.stopRefresh)
	s.stopRefresh = nil
}

func (s *Service) refreshLoop(stop <-chan struct{}) {
	ticker := time.NewTicker(arpRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			s.refreshOnce()
		}
	}
}

func (s *Service) refreshOnce() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.config.Enabled {
		return
	}
	if err := s.refreshConfig(s.config); err != nil {
		if s.lastError != err.Error() {
			s.lastError = err.Error()
			_ = s.save()
		}
		return
	}
	if s.lastError != "" {
		s.lastError = ""
		_ = s.save()
	}
}

func normalizeConfig(in Config) Config {
	in.MAC, _ = normalizeMAC(in.MAC)
	in.Prefix, _ = normalizePrefix(in.Prefix)
	in.VendorID = strings.TrimSpace(in.VendorID)
	in.Ifaces = cleanIfaces(in.Ifaces)
	return in
}

func cleanIfaces(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, iface := range in {
		iface = strings.TrimSpace(iface)
		if iface == "" || seen[iface] || !reIfaceName.MatchString(iface) {
			continue
		}
		seen[iface] = true
		out = append(out, iface)
	}
	sort.Strings(out)
	return out
}

func cleanMACMap(in map[string]string) map[string]string {
	out := map[string]string{}
	for iface, mac := range in {
		iface = strings.TrimSpace(iface)
		if iface == "" || !reIfaceName.MatchString(iface) {
			continue
		}
		normalized, err := normalizeMAC(mac)
		if err != nil {
			continue
		}
		out[iface] = normalized
	}
	return out
}

func normalizePrefix(prefix string) (string, error) {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return "", nil
	}
	if !reMACPrefix.MatchString(prefix) {
		return "", fmt.Errorf("prefix must contain 1-3 complete MAC bytes")
	}
	raw := strings.NewReplacer(":", "", "-", "").Replace(prefix)
	if len(raw)%2 != 0 || len(raw) < 2 || len(raw) > 6 {
		return "", fmt.Errorf("prefix must contain 1-3 complete MAC bytes")
	}
	b, err := hex.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("invalid MAC prefix")
	}
	return strings.ToUpper(formatMACBytes(b)), nil
}

func normalizeMAC(mac string) (string, error) {
	mac = strings.TrimSpace(mac)
	if mac == "" {
		return "", nil
	}
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return "", fmt.Errorf("invalid MAC address")
	}
	if hw[0]&1 != 0 {
		return "", fmt.Errorf("MAC must be unicast, not multicast")
	}
	allZero, allFF := true, true
	for _, b := range hw {
		if b != 0 {
			allZero = false
		}
		if b != 0xff {
			allFF = false
		}
	}
	if allZero || allFF {
		return "", fmt.Errorf("invalid MAC address")
	}
	return strings.ToUpper(formatMACBytes(hw)), nil
}

func generateMAC(prefix string) (string, error) {
	prefix, err := normalizePrefix(prefix)
	if err != nil {
		return "", err
	}
	raw := strings.NewReplacer(":", "", "-", "").Replace(prefix)
	pb, _ := hex.DecodeString(raw)
	if len(pb) > 6 {
		return "", fmt.Errorf("prefix is too long")
	}
	if len(pb) > 0 && pb[0]&1 != 0 {
		return "", fmt.Errorf("prefix must be unicast, not multicast")
	}
	mac := make([]byte, 6)
	copy(mac, pb)
	if _, err := rand.Read(mac[len(pb):]); err != nil {
		return "", err
	}
	if len(pb) == 0 {
		mac[0] &^= 1
		mac[0] |= 2
	}
	return strings.ToUpper(formatMACBytes(mac)), nil
}

func formatMACBytes(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}

func interfaceCandidates(wan []string) []Interface {
	wanSet := map[string]bool{}
	for _, n := range wan {
		wanSet[n] = true
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]Interface, 0, len(ifs))
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 || len(i.HardwareAddr) != 6 {
			continue
		}
		up := i.Flags&net.FlagUp != 0
		suggested := up && !wanSet[i.Name] && looksLAN(i.Name)
		out = append(out, Interface{
			Name:      i.Name,
			MAC:       strings.ToUpper(i.HardwareAddr.String()),
			Up:        up,
			Suggested: suggested,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Suggested != out[j].Suggested {
			return out[i].Suggested
		}
		if out[i].Up != out[j].Up {
			return out[i].Up
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func suggestedInterfaceNames(ifaces []Interface) []string {
	out := []string{}
	for _, iface := range ifaces {
		if iface.Suggested {
			out = append(out, iface.Name)
		}
	}
	if len(out) == 0 {
		for _, iface := range ifaces {
			if iface.Up {
				out = append(out, iface.Name)
			}
		}
	}
	return out
}

func looksLAN(name string) bool {
	n := strings.ToLower(name)
	return strings.HasPrefix(n, "br") ||
		strings.HasPrefix(n, "lan")
}

func hasWirelessSlaveIface(ifaces []string) bool {
	for _, name := range ifaces {
		n := strings.ToLower(name)
		if strings.HasPrefix(n, "ra") ||
			strings.HasPrefix(n, "apcli") ||
			strings.HasPrefix(n, "wifi") ||
			strings.HasPrefix(n, "wlan") ||
			strings.HasPrefix(n, "wl") {
			return true
		}
	}
	return false
}

func toolStatus() Tools {
	return Tools{
		IP:        lookupTool("ip") != "",
		Arptables: lookupTool("arptables", "arptables-legacy") != "",
		Ebtables:  lookupTool("ebtables", "ebtables-legacy") != "",
	}
}

func lookupTool(names ...string) string {
	for _, name := range names {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	return ""
}
