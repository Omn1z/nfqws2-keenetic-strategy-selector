//go:build !linux

package awgroute

import "nfqws2strategy/internal/services/awg"

func (svc *Service) awgEndpointHintsOS(*awg.Manager, []string) map[string]bool { return nil }
