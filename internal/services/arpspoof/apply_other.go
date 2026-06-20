//go:build !linux

package arpspoof

const hookPath = ""

func (s *Service) applyConfig(_ Config) error { return nil }
