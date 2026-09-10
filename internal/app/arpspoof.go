package app

import "nfqws2strategy/internal/services/arpspoof"

type ARPSpoofingView = arpspoof.View
type ARPSpoofingConfig = arpspoof.Config

func (a *App) ARPSpoofingView() ARPSpoofingView {
	return a.arpspoof.View()
}

func (a *App) SaveARPSpoofingConfig(c ARPSpoofingConfig) (ARPSpoofingView, error) {
	return a.arpspoof.SaveConfig(c)
}

func (a *App) SetARPSpoofingEnabled(enabled bool) (ARPSpoofingView, error) {
	return a.arpspoof.SetEnabled(enabled)
}

func (a *App) GenerateARPSpoofingMAC(prefix string) (string, error) {
	return a.arpspoof.GenerateMAC(prefix)
}
