package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
)

const maxDisabledMethods = 2048

var errMethodDisabled = errors.New("метод DoH × маршрут выключен пользователем")

type DisabledMethod struct {
	Upstream string `json:"upstream"`
	Route    string `json:"route"`
}

func normalizeDisabledMethods(methods []DisabledMethod) ([]DisabledMethod, error) {
	if len(methods) > maxDisabledMethods {
		return nil, fmt.Errorf("не более %d выключенных методов DNS", maxDisabledMethods)
	}
	clean := make([]DisabledMethod, 0, len(methods))
	seen := make(map[string]bool, len(methods))
	for _, method := range methods {
		upstream := Upstream{Address: method.Upstream}
		if err := normalizeUpstream(&upstream); err != nil {
			return nil, fmt.Errorf("выключенный метод DNS: %w", err)
		}
		method.Upstream = upstream.Address
		method.Route = strings.TrimSpace(method.Route)
		valid := method.Route == "nfqws"
		if strings.HasPrefix(method.Route, "awg:") && len(method.Route) > 4 && len(method.Route) <= 100 {
			valid = true
			for _, ch := range method.Route[4:] {
				if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-' || ch == '.') {
					valid = false
					break
				}
			}
		}
		if !valid {
			return nil, fmt.Errorf("метод DNS: маршрут должен быть nfqws или awg:ID")
		}
		key := schedulerKey(method.Route, method.Upstream)
		if !seen[key] {
			seen[key] = true
			clean = append(clean, method)
		}
	}
	return clean, nil
}

func disabledMethodSet(methods []DisabledMethod) map[string]bool {
	result := make(map[string]bool, len(methods))
	for _, method := range methods {
		result[schedulerKey(method.Route, method.Upstream)] = true
	}
	return result
}

// methodPolicy is the only mutable configuration inside a running resolver.
// Full Config remains immutable; requests take a small policy snapshot for
// queue ordering, then register against this live policy immediately at start.
type methodPolicy struct {
	mu       sync.Mutex
	disabled map[string]bool
	methods  []DisabledMethod
	active   map[string]map[uint64]context.CancelCauseFunc
	nextID   uint64
}

func newMethodPolicy(methods []DisabledMethod) *methodPolicy {
	return &methodPolicy{disabled: disabledMethodSet(methods), methods: append([]DisabledMethod{}, methods...), active: make(map[string]map[uint64]context.CancelCauseFunc)}
}

func (p *methodPolicy) snapshot() []DisabledMethod {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]DisabledMethod{}, p.methods...)
}

func (p *methodPolicy) allowed(route, upstream string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.disabled[schedulerKey(route, upstream)]
}

func (p *methodPolicy) apply(methods []DisabledMethod) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.methods = append([]DisabledMethod{}, methods...)
	p.disabled = disabledMethodSet(methods)
	for key, calls := range p.active {
		if p.disabled[key] {
			for _, cancel := range calls {
				cancel(errMethodDisabled)
			}
		}
	}
}

func (p *methodPolicy) begin(parent context.Context, route, upstream string) (context.Context, func(), error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := schedulerKey(route, upstream)
	if p.disabled[key] {
		return nil, nil, errMethodDisabled
	}
	ctx, cancel := context.WithCancelCause(parent)
	p.nextID++
	id := p.nextID
	if p.active[key] == nil {
		p.active[key] = make(map[uint64]context.CancelCauseFunc)
	}
	p.active[key][id] = cancel
	return ctx, func() {
		p.mu.Lock()
		delete(p.active[key], id)
		if len(p.active[key]) == 0 {
			delete(p.active, key)
		}
		p.mu.Unlock()
		cancel(nil)
	}, nil
}

func (r *Resolver) policyConfig() Config {
	cfg := r.cfg
	cfg.DisabledMethods = r.methods.snapshot()
	return cfg
}

func (r *Resolver) setDisabledMethods(methods []DisabledMethod) {
	r.methods.apply(methods)
	if r.fastDNS != nil {
		r.fastDNS.pruneDisallowed()
	}
}

// SetMethodEnabled persists only the selected pair and applies it without
// replacing listeners, cached answers, counters or scheduler observations.
func (s *Service) SetMethodEnabled(upstream, route string, enabled bool) error {
	method, err := normalizeDisabledMethods([]DisabledMethod{{Upstream: upstream, Route: route}})
	if err != nil {
		return err
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	cfg := s.Config()
	key := schedulerKey(method[0].Route, method[0].Upstream)
	methods := make([]DisabledMethod, 0, len(cfg.DisabledMethods)+1)
	found := false
	for _, current := range cfg.DisabledMethods {
		if schedulerKey(current.Route, current.Upstream) == key {
			found = true
			if enabled {
				continue
			}
		}
		methods = append(methods, current)
	}
	if found == !enabled {
		return nil
	}
	if !enabled {
		methods = append(methods, method[0])
	}
	if len(methods) > maxDisabledMethods {
		return fmt.Errorf("не более %d выключенных методов DNS", maxDisabledMethods)
	}
	cfg.DisabledMethods = methods
	if err := s.store.Save(configFile, cfg); err != nil {
		return err
	}
	s.mu.Lock()
	if s.active != nil {
		s.active.resolver.setDisabledMethods(methods)
	}
	s.cfg.DisabledMethods = append([]DisabledMethod{}, methods...)
	s.mu.Unlock()
	return nil
}
