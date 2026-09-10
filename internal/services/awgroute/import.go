package awgroute

import (
	"strings"

	"nfqws2strategy/internal/services/awg"
	storeutil "nfqws2strategy/internal/tools/store"
)

// AWG2Import parses an existing AmneziaWG client .conf and registers it as a new
// active AWG2 server entry, marked DeployedAt=now so the panel skips SSH-deploy
// and lets the user go straight to "client up" + routing. Mirrors AWG2AddServer
// but seeds the manager with the imported config instead of awg.Default().
func (svc *Service) AWG2Import(text, name string) (AWG2Status, error) {
	_, unlock := svc.lockClientOps(false)
	defer unlock()
	cfg, err := awg.ImportClientConf(text)
	if err != nil {
		return svc.AWG2StatusView(), err
	}
	cfg.ClientIface = svc.nextAWGClientIface()

	id := "awg-" + storeutil.NewID()
	srv := &managedServer{ID: id, Name: strings.TrimSpace(name), Manager: awg.NewManager(cfg)}

	svc.mu.Lock()
	if svc.servers == nil {
		svc.servers = map[string]*managedServer{}
	}
	svc.servers[id] = srv
	svc.order = append(svc.order, id)
	svc.activeID = id
	svc.awg = srv.Manager
	svc.mu.Unlock()
	svc.syncActiveAWGIface()

	svc.route.tunnelUpAt.Store(0)
	svc.awgSave()
	return svc.AWG2StatusView(), nil
}
