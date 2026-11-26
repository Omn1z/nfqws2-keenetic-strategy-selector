package arpspoof

import (
	"errors"
	"fmt"
	"os"
	"sort"
)

// The native network manager and the kernel must agree on the address. On
// Keenetic, changing only the kernel leaves NDM emitting the old ARP sender MAC.
type macState struct {
	MAC          string
	Inconsistent bool
}

type macOperations struct {
	targets  func(Config) ([]string, error)
	read     func(string) (macState, error)
	write    func(string, string) error
	announce func(string, bool)
}

// applyMACConfig owns the durable recovery journal; platform adapters own how
// to change an address. Tests use an isolated store and never touch interfaces.
func (s *Service) applyMACConfig(cfg Config, logAnnounce bool, ops macOperations) error {
	var targets []string
	var err error
	if cfg.Enabled {
		targets, err = ops.targets(cfg)
		if err != nil {
			return err
		}
		if len(targets) == 0 {
			return fmt.Errorf("AUTO did not find an eligible LAN bridge; WAN interfaces are never used")
		}
	}
	desired := make(map[string]string, len(targets)+len(s.origMACs))
	selected := make(map[string]bool, len(targets))
	for _, name := range targets {
		desired[name] = cfg.MAC
		selected[name] = true
	}
	for name, original := range s.origMACs {
		if !selected[name] {
			desired[name] = original
		}
	}
	names := make([]string, 0, len(desired))
	for name := range desired {
		names = append(names, name)
	}
	sort.Strings(names)
	before := make(map[string]macState, len(names))
	missing := make(map[string]bool)
	for _, name := range names {
		current, err := ops.read(name)
		if err != nil {
			if !selected[name] && errors.Is(err, os.ErrNotExist) {
				missing[name] = true
				continue
			}
			return fmt.Errorf("interface %s: %w", name, err)
		}
		before[name] = current
	}
	// Persist every original address before the first network mutation. A new
	// bridge discovered by refresh must remain recoverable after an app crash.
	added := []string{}
	for _, name := range targets {
		if _, ok := s.origMACs[name]; ok {
			continue
		}
		if before[name].MAC == cfg.MAC {
			return fmt.Errorf("interface %s already uses the requested MAC but its original MAC is unknown", name)
		}
		added = append(added, name)
	}
	if len(added) > 0 {
		for _, name := range added {
			s.origMACs[name] = before[name].MAC
		}
		if err := s.save(); err != nil {
			for _, name := range added {
				delete(s.origMACs, name)
			}
			return fmt.Errorf("save original MACs before applying: %w", err)
		}
	}
	var changed []string
	for _, name := range names {
		if missing[name] || before[name].MAC == desired[name] && !before[name].Inconsistent {
			continue
		}
		// Include the attempted operation: a native command can fail after a
		// partial update, so the old address must be reapplied in that case too.
		changed = append(changed, name)
		if err := ops.write(name, desired[name]); err != nil {
			rollbackErrors := []error{fmt.Errorf("set %s MAC: %w", name, err)}
			for i := len(changed) - 1; i >= 0; i-- {
				restore := changed[i]
				if restoreErr := ops.write(restore, before[restore].MAC); restoreErr != nil {
					rollbackErrors = append(rollbackErrors, fmt.Errorf("restore %s after failed apply: %w", restore, restoreErr))
				} else {
					ops.announce(restore, true)
				}
			}
			return errors.Join(rollbackErrors...)
		}
		ops.announce(name, logAnnounce)
	}
	removed := false
	for name := range s.origMACs {
		if !selected[name] {
			delete(s.origMACs, name)
			removed = true
		}
	}
	if removed {
		return s.save()
	}
	return nil
}
