package app

import (
	"context"

	"nfqws2strategy/internal/services/awgroute"
)

func (a *App) AWG2SetFailover(id string, cfg awgroute.FailoverConfig) error {
	err := a.awgroute.AWG2SetFailover(id, cfg)
	if err == nil {
		a.syncProxyTunnelRoutes(a.proxy.AWGFallback())
	}
	return err
}

func (a *App) AWG2TestConnection(ctx context.Context, id string) awgroute.ConnectionTestResult {
	return a.awgroute.AWG2TestConnection(ctx, id)
}
