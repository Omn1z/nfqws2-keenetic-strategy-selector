//go:build !linux

package app

import (
	"fmt"
	"runtime"
)

// Non-router stubs (the AWG2 client only runs on the Keenetic router).

func (a *App) awgEngineInfoOS() EngineInfo {
	return EngineInfo{Arch: runtime.GOARCH, Error: "клиент AWG2 поддерживается только на роутере (Linux)"}
}
func (a *App) awgInstallEngineOS() (string, error) {
	return "", fmt.Errorf("установка движка доступна только на роутере")
}
func (a *App) awgClientUpOS() error   { return fmt.Errorf("туннель доступен только на роутере") }
func (a *App) awgClientDownOS() error { return fmt.Errorf("туннель доступен только на роутере") }
func (a *App) awgClientStatusOS() *ClientStatus { return nil }

func (a *App) awgApplyRoutingOS() error    { return fmt.Errorf("маршрутизация доступна только на роутере") }
func (a *App) awgRefreshRoutingOS() error  { return nil }
func (a *App) awgCommitRoutingOS() error   { return fmt.Errorf("маршрутизация доступна только на роутере") }
func (a *App) awgTeardownRoutingOS() error { return nil }
func (a *App) awgRepairRoutingOS()         {}
