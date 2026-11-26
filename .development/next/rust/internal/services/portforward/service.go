package portforward

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"nfqws2strategy/internal/tools/config"
	"nfqws2strategy/internal/tools/store"
)

const stateFile = "port_forwarding.json"

// Service persists rules and applies the matching router firewall hook.
type Service struct {
	cfg   *config.Config
	store *store.Store

	mu    sync.Mutex
	rules []Rule
}

func New(cfg *config.Config, st *store.Store) *Service {
	s := &Service{cfg: cfg, store: st}
	var stt state
	if err := st.Load(stateFile, &stt); err == nil {
		s.rules = normalizeRules(stt.Rules)
	}
	return s
}

func (s *Service) View() View {
	s.mu.Lock()
	defer s.mu.Unlock()
	return View{
		Presets:   Presets(),
		Rules:     cloneRules(s.rules),
		WANIfaces: append([]string{}, s.cfg.WANIfaces...),
		HookPath:  hookPath,
	}
}

func (s *Service) Apply() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applyRules(cloneRules(s.rules))
}

func (s *Service) SaveRule(in Rule) (Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rule, err := s.prepareRule(in)
	if err != nil {
		return Rule{}, err
	}
	if rule.ID == "" {
		rule.ID = store.NewID()
		rule.CreatedAt = time.Now().Unix()
		s.rules = append(s.rules, rule)
	} else {
		found := false
		for i := range s.rules {
			if s.rules[i].ID != rule.ID {
				continue
			}
			rule.CreatedAt = s.rules[i].CreatedAt
			s.rules[i] = rule
			found = true
			break
		}
		if !found {
			return Rule{}, fmt.Errorf("rule not found")
		}
	}
	rule.UpdatedAt = time.Now().Unix()
	for i := range s.rules {
		if s.rules[i].ID == rule.ID {
			s.rules[i].UpdatedAt = rule.UpdatedAt
			rule = s.rules[i]
			break
		}
	}
	if err := s.saveApplyLocked(); err != nil {
		return rule, err
	}
	return cloneRule(rule), nil
}

func (s *Service) SetEnabled(id string, enabled bool) (Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.rules {
		if s.rules[i].ID != id {
			continue
		}
		s.rules[i].Enabled = enabled
		s.rules[i].UpdatedAt = time.Now().Unix()
		rule := cloneRule(s.rules[i])
		if err := s.saveApplyLocked(); err != nil {
			return rule, err
		}
		return rule, nil
	}
	return Rule{}, fmt.Errorf("rule not found")
}

func (s *Service) DeleteRule(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("empty rule id")
	}
	out := s.rules[:0]
	found := false
	for _, r := range s.rules {
		if r.ID == id {
			found = true
			continue
		}
		out = append(out, r)
	}
	if !found {
		return fmt.Errorf("rule not found")
	}
	s.rules = out
	return s.saveApplyLocked()
}

func (s *Service) prepareRule(in Rule) (Rule, error) {
	preset, profile, ok := findPresetProfile(strings.TrimSpace(in.PresetID), strings.TrimSpace(in.ProfileID))
	if !ok {
		return Rule{}, fmt.Errorf("unknown preset profile")
	}
	ip := strings.TrimSpace(in.DeviceIP)
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return Rule{}, fmt.Errorf("select a LAN device with an IPv4 address")
	}

	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = preset.Name + " - " + profile.Name
	}
	if err := validateRanges(profile.TCP); err != nil {
		return Rule{}, fmt.Errorf("invalid TCP ports in preset: %w", err)
	}
	if err := validateRanges(profile.UDP); err != nil {
		return Rule{}, fmt.Errorf("invalid UDP ports in preset: %w", err)
	}

	return Rule{
		ID:          strings.TrimSpace(in.ID),
		Name:        name,
		PresetID:    preset.ID,
		ProfileID:   profile.ID,
		DeviceIP:    parsed.To4().String(),
		DeviceName:  strings.TrimSpace(in.DeviceName),
		DeviceMAC:   strings.TrimSpace(in.DeviceMAC),
		DeviceIface: strings.TrimSpace(in.DeviceIface),
		Enabled:     in.Enabled,
		TCP:         cloneRanges(profile.TCP),
		UDP:         cloneRanges(profile.UDP),
		CreatedAt:   in.CreatedAt,
		UpdatedAt:   time.Now().Unix(),
	}, nil
}

func (s *Service) saveApplyLocked() error {
	if err := s.store.Save(stateFile, state{Rules: s.rules}); err != nil {
		return err
	}
	return s.applyRules(cloneRules(s.rules))
}

func validateRanges(rs []Range) error {
	for _, r := range rs {
		if r.Start < 1 || r.End < 1 || r.Start > 65535 || r.End > 65535 || r.Start > r.End {
			return fmt.Errorf("%d-%d", r.Start, r.End)
		}
	}
	return nil
}

func normalizeRules(in []Rule) []Rule {
	out := make([]Rule, 0, len(in))
	svc := &Service{}
	for _, r := range in {
		normalized, err := svc.prepareRule(r)
		if err != nil {
			continue
		}
		normalized.ID = r.ID
		normalized.CreatedAt = r.CreatedAt
		normalized.UpdatedAt = r.UpdatedAt
		out = append(out, normalized)
	}
	return out
}

func cloneRules(in []Rule) []Rule {
	if len(in) == 0 {
		return []Rule{}
	}
	out := make([]Rule, len(in))
	for i := range in {
		out[i] = cloneRule(in[i])
	}
	return out
}

func cloneRule(r Rule) Rule {
	r.TCP = cloneRanges(r.TCP)
	r.UDP = cloneRanges(r.UDP)
	return r
}
