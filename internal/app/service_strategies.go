package app

import "nfqws2strategy/internal/services/nfqws2"

func (a *App) Nfqws2ServiceStrategies() (nfqws2.ServiceStrategiesState, error) {
	return a.nfqws2.ServiceStrategies()
}

func (a *App) SaveNfqws2ServiceStrategies(services []nfqws2.ServiceStrategy, revision string) (nfqws2.ServiceStrategiesState, error) {
	return a.nfqws2.SaveServiceStrategies(services, revision)
}

func (a *App) PreviewNfqws2ServiceStrategies(services []nfqws2.ServiceStrategy) (nfqws2.ServiceStrategiesPreview, error) {
	return a.nfqws2.PreviewServiceStrategies(services)
}
