package dnsserver

import "fmt"

// Diagnostics is a runtime troubleshooting switch, not a DNS configuration
// change. Toggling it must not restart listeners, discard caches or renew WAN.
func (s *Service) SetShadowDiagnostics(enabled bool) error {
	backend, ok := s.backend.(interface{ SetShadowDiagnostics(bool) })
	if !ok {
		return fmt.Errorf("переключение диагностики Shadow DNS не поддерживается")
	}
	backend.SetShadowDiagnostics(enabled)
	return nil
}
