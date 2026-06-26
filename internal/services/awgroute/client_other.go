//go:build !linux

package awgroute

import (
	"fmt"
	"runtime"

	"nfqws2strategy/internal/services/awg"
)

// Non-router stubs (the AWG2 client only runs on the Keenetic router).

func (svc *Service) awgEngineInfoOS() EngineInfo {
	return EngineInfo{Arch: runtime.GOARCH, Error: "клиент AWG2 поддерживается только на роутере (Linux)"}
}
func (svc *Service) awgInstallEngineOS() (string, error) {
	return "", fmt.Errorf("установка движка доступна только на роутере")
}
func (svc *Service) awgClientUpOS() error {
	return fmt.Errorf("туннель доступен только на роутере")
}
func (svc *Service) awgClientUpManagerOS(am *awg.Manager) error { return svc.awgClientUpOS() }
func (svc *Service) awgClientDownOS() error {
	return fmt.Errorf("туннель доступен только на роутере")
}
func (svc *Service) awgClientStatusOS() *ClientStatus { return nil }
func (svc *Service) awgClientDownManagerOS(am *awg.Manager) error {
	return svc.awgClientDownOS()
}
func (svc *Service) awgClientStatusManagerOS(am *awg.Manager) *ClientStatus {
	return nil
}
func awgSetActiveIfaceOS(iface string)                    {}
func (svc *Service) awgDisableLegacyExternalWatchdogsOS() {}

func (svc *Service) awgApplyRoutingOS() error {
	return fmt.Errorf("маршрутизация доступна только на роутере")
}
func (svc *Service) awgRefreshRoutingOS() error { return nil }
func (svc *Service) awgCommitRoutingOS() error {
	return fmt.Errorf("маршрутизация доступна только на роутере")
}
func (svc *Service) awgTeardownRoutingOS() error { return nil }
func (svc *Service) awgRepairRoutingOS()         {}
