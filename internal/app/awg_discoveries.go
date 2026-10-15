package app

import "nfqws2strategy/internal/services/awgroute"

func (a *App) AWG2DiscoveredRoutes() awgroute.AWGRoutingDiscoveredSnapshot {
	return a.awgroute.AWG2DiscoveredRoutes()
}
