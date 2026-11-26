//go:build !linux

package portforward

const hookPath = ""

func (s *Service) applyRules(_ []Rule) error { return nil }
