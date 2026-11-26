package app

import (
	"encoding/json"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/services/awgroute"
)

func (a *App) AWG2ExportRoutingRules(draft *awg.RoutingConfig) (awgroute.AWGRoutingDocument, error) {
	return a.awgroute.AWG2ExportRoutingRules(draft)
}

func (a *App) AWG2PreviewRoutingRules(document json.RawMessage) (awgroute.AWGRoutingImportPlan, error) {
	return a.awgroute.AWG2PreviewRoutingRules(document)
}

func (a *App) AWG2ImportRoutingRules(request awgroute.AWGRoutingImportRequest) (awgroute.AWGRoutingImportResult, error) {
	result, err := a.awgroute.AWG2ImportRoutingRules(request)
	if err == nil {
		a.syncProxyTunnelRoutes(a.proxy.AWGFallback())
	}
	return result, err
}
