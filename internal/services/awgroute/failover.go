package awgroute

import (
	"fmt"
	"strings"
	"time"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/logbuf"
)

// FailoverConfig is local connection policy, independent of the remote wire
// configuration and of the profile currently selected in the editor.
type FailoverConfig struct {
	FallbackTunnelIDs []string `json:"fallback_tunnel_ids"`
	Standby           bool     `json:"standby"`
}

type ConnectionFailoverStatus struct {
	FallbackTunnelIDs []string `json:"fallback_tunnel_ids"`
	Standby           bool     `json:"standby"`
	Activated         bool     `json:"activated"`
	ActiveTunnelID    string   `json:"active_tunnel_id"`
}

func (svc *Service) clientShouldRun(am *awg.Manager) bool {
	if am == nil {
		return false
	}
	cfg := am.RuntimeLocalClientIdentity()
	if !cfg.Enabled || !cfg.ClientEnabled || !cfg.CanStart {
		return false
	}
	if !cfg.Standby {
		return true
	}
	svc.clients.mu.Lock()
	active := svc.clients.standbyActive[am]
	svc.clients.mu.Unlock()
	return active
}

// A recently created interface is not proof that a server is reachable. Let
// the first handshake finish, then start a reserve while the primary keeps
// retrying. A failed local start needs a second attempt before failover.
func clientNeedsFallback(r clientRecovery, now time.Time) bool {
	if !r.Recovering {
		return false
	}
	return r.Attempts > 1 || r.Attempts > 0 && !r.VerifyUntil.IsZero() && !now.Before(r.VerifyUntil) ||
		!r.ProbeAt.IsZero() && !now.Before(r.probeDeadline())
}

func clientAuthenticated(st *ClientStatus, now time.Time) bool {
	if st == nil || !st.Running {
		return false
	}
	return st.Connected || st.LastHandshake > 0 && now.Unix() >= st.LastHandshake && now.Unix()-st.LastHandshake < int64(clientStaleAfter/time.Second)
}

func (svc *Service) clientLifecycleDriver() clientDriver {
	if svc.clients.driver != nil {
		return svc.clients.driver
	}
	return systemClientDriver{svc}
}

// Connection fallbacks follow rule-specific reserves. Nested backup lists are
// expanded with stable order; the visited set also tolerates a damaged saved
// graph without hanging a routing refresh.
func (svc *Service) connectionFallbackTunnelIDs(primary string, ruleFallbacks []string) []string {
	byID := map[string]*managedServer{}
	for _, srv := range svc.serverSnapshot() {
		byID[srv.ID] = srv
	}
	seen := map[string]bool{primary: true}
	out := []string{}
	var appendID func(string)
	appendID = func(id string) {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		out = append(out, id)
		if srv := byID[id]; srv != nil {
			for _, next := range srv.Manager.RuntimeLocalClientIdentity().FallbackTunnelIDs {
				appendID(next)
			}
		}
	}
	for _, id := range ruleFallbacks {
		appendID(id)
	}
	if srv := byID[primary]; srv != nil {
		for _, id := range srv.Manager.RuntimeLocalClientIdentity().FallbackTunnelIDs {
			appendID(id)
		}
	}
	return out
}

// Backup profiles need no duplicate domain lists or committed zones of their
// own. They inherit routing eligibility from any committed primary using them.
func (svc *Service) connectionRoutingEnabled(srv *managedServer) bool {
	if srv == nil {
		return false
	}
	return svc.connectionRoutingEligibility()[srv.ID]
}

// Compile the small connection graph once for a routing pass. Domain lists,
// credentials and peers never need cloning to decide backup eligibility.
func (svc *Service) connectionRoutingEligibility() map[string]bool {
	identities := map[string]awg.LocalClientIdentity{}
	for _, srv := range svc.serverSnapshot() {
		identities[srv.ID] = srv.Manager.RuntimeLocalClientIdentity()
	}
	usable := map[string]bool{}
	expanded := map[string]bool{}
	var include func(string)
	include = func(id string) {
		c, ok := identities[id]
		if !ok || expanded[id] {
			return
		}
		expanded[id] = true
		if c.Enabled && c.ClientEnabled && c.RoutingMode != "off" {
			usable[id] = true
		}
		// A disabled intermediate cannot carry traffic, but its ordered child
		// reserves remain candidates, just as in the flattened selection graph.
		for _, child := range c.FallbackTunnelIDs {
			include(child)
		}
	}
	for id, c := range identities {
		if c.Enabled && c.ClientEnabled && c.RoutingMode != "off" && c.RoutingActive {
			include(id)
		}
	}
	return usable
}

// reconcileStandbyClients runs with lifecycle operations held. Runtime demand
// is a union, so a reserve shared by several primaries survives until every
// demanding primary has authenticated again. Intent remains persisted as-is.
func (svc *Service) reconcileStandbyClients() {
	if svc.clientOpContext().Err() != nil {
		return
	}
	servers := svc.serverSnapshot()
	byID := map[string]*managedServer{}
	for _, srv := range servers {
		byID[srv.ID] = srv
	}
	driver := svc.clientLifecycleDriver()
	statuses := map[*awg.Manager]*ClientStatus{}
	status := func(am *awg.Manager) *ClientStatus {
		if current, known := statuses[am]; known {
			return current
		}
		current := driver.status(am)
		statuses[am] = current
		return current
	}
	now := time.Now()
	svc.clients.mu.Lock()
	states := make(map[*awg.Manager]clientRecovery, len(svc.clients.states))
	for am, state := range svc.clients.states {
		states[am] = state
	}
	svc.clients.mu.Unlock()
	wanted := map[*awg.Manager]bool{}
	rules := svc.awgRoutingRules()
	for _, primary := range servers {
		cfg := primary.Manager.RuntimeLocalClientIdentity()
		if cfg.Standby || !svc.clientShouldRun(primary.Manager) || clientAuthenticated(status(primary.Manager), now) {
			continue
		}
		needsReserve := clientNeedsFallback(states[primary.Manager], now)
		lists := [][]string{svc.connectionFallbackTunnelIDs(primary.ID, nil)}
		for _, rule := range rules {
			if rule.Enabled && !rule.WaitingForConnection && rule.RouteValue() == "tunnel" && rule.TunnelID == primary.ID && len(rule.FallbackTunnelIDs) > 0 {
				lists = append(lists, svc.connectionFallbackTunnelIDs(primary.ID, rule.FallbackTunnelIDs))
			}
		}
		for _, candidates := range lists {
			for _, id := range candidates {
				reserve := byID[id]
				if reserve == nil {
					continue
				}
				identity := reserve.Manager.RuntimeLocalClientIdentity()
				if !identity.Enabled || !identity.ClientEnabled || !identity.CanStart {
					continue
				}
				connected := clientAuthenticated(status(reserve.Manager), now)
				if !needsReserve {
					// A service restart forgets the in-memory recovery/demand
					// maps. Keep an already authenticated reserve carrying
					// traffic while its primary is initially verified; do not
					// wake a new cold reserve before the normal failure grace.
					if connected {
						wanted[reserve.Manager] = true
						break
					}
					continue
				}
				wanted[reserve.Manager] = true
				if connected || !clientNeedsFallback(states[reserve.Manager], now) {
					break
				}
			}
		}
	}
	svc.clients.mu.Lock()
	svc.clients.standbyActive = wanted
	svc.clients.mu.Unlock()
	for _, srv := range servers {
		if !srv.Manager.RuntimeLocalClientIdentity().Standby || wanted[srv.Manager] {
			continue
		}
		st := status(srv.Manager)
		if st != nil && (st.Running || st.IfacePresent) {
			var err error
			if down, ok := driver.(interface{ down(*awg.Manager) error }); ok {
				err = down.down(srv.Manager)
			} else if svc.clients.driver == nil {
				err = svc.awgClientDownManagerOS(srv.Manager)
			}
			if err != nil {
				logbuf.Append("awg2", "warn", "отключение резервного туннеля: "+err.Error())
			}
		}
		svc.forgetClientRecovery(srv.Manager)
	}
}

func (svc *Service) connectionFailoverStatus(srv *managedServer, statuses map[string]*ClientStatus) *ConnectionFailoverStatus {
	cfg := srv.Manager.RuntimeLocalClientIdentity()
	svc.clients.mu.Lock()
	activated := svc.clients.standbyActive[srv.Manager]
	svc.clients.mu.Unlock()
	status := &ConnectionFailoverStatus{FallbackTunnelIDs: append([]string{}, cfg.FallbackTunnelIDs...), Standby: cfg.Standby, Activated: cfg.Standby && activated}
	byID := map[string]*managedServer{}
	for _, candidate := range svc.serverSnapshot() {
		byID[candidate.ID] = candidate
	}
	for _, id := range fallbackCandidates(srv.ID, svc.connectionFallbackTunnelIDs(srv.ID, nil)) {
		candidate := byID[id]
		if candidate != nil && svc.clientShouldRun(candidate.Manager) && clientAuthenticated(statuses[id], time.Now()) {
			status.ActiveTunnelID = id
			break
		}
	}
	return status
}

// Legacy full-tunnel profiles may have no explicit zones. Materialize the
// existing blanket route only for policy compilation, so failover can use the
// multi-tunnel datapath without inserting anything into the user's saved list.
func (svc *Service) awgPolicyRoutingRules() []awg.Zone {
	rules := svc.awgRoutingRules()
	if len(rules) != 0 {
		return rules
	}
	for _, srv := range svc.serverSnapshot() {
		cfg := srv.Manager.RuntimeConfig()
		if cfg.Enabled && cfg.Client.Enabled && cfg.Routing.Active && cfg.Routing.Mode == "full" && len(cfg.Client.FallbackTunnelIDs) > 0 {
			return []awg.Zone{{Name: "Весь трафик", TunnelID: srv.ID, Route: "tunnel", Domains: []string{"*"}, Enabled: true}}
		}
	}
	return rules
}

// Resolve a logical primary to the physical tunnel used by DNS and proxy
// consumers too; their saved selection remains the primary profile ID.
func (svc *Service) effectiveConnectedServer(primary string) *managedServer {
	byID := map[string]*managedServer{}
	for _, srv := range svc.serverSnapshot() {
		byID[srv.ID] = srv
	}
	owner := byID[primary]
	if owner == nil || !owner.Manager.Enabled() || !owner.Manager.ClientEnabled() {
		return nil
	}
	for _, id := range fallbackCandidates(primary, svc.connectionFallbackTunnelIDs(primary, nil)) {
		if srv := byID[id]; srv != nil && svc.tunnelUpForManagedServer(srv) {
			return srv
		}
	}
	return nil
}

func (svc *Service) AWG2SetFailover(id string, in FailoverConfig) error {
	_, unlock := svc.lockClientOps(true)
	defer unlock()
	return svc.setConnectionFailoverWithOps(id, in, svc.awgApplyConnectionFailoverPolicyOS)
}

func (svc *Service) legacyFullRoutingOwner() *managedServer {
	var fallback *managedServer
	activeID := svc.activeServerID()
	for _, srv := range svc.serverSnapshot() {
		c := srv.Manager.RuntimeLocalClientIdentity()
		if !c.Enabled || !c.ClientEnabled || c.Standby || !c.RoutingActive || c.RoutingMode != "full" {
			continue
		}
		if srv.ID == activeID {
			return srv
		}
		if fallback == nil {
			fallback = srv
		}
	}
	return fallback
}

func (svc *Service) setConnectionFailoverWithOps(id string, in FailoverConfig, apply func() error) error {
	if err := svc.clientOpContext().Err(); err != nil {
		return err
	}
	id = strings.TrimSpace(id)
	servers := svc.serverSnapshot()
	byID := map[string]*managedServer{}
	for _, srv := range servers {
		byID[srv.ID] = srv
	}
	srv := byID[id]
	if srv == nil {
		return fmt.Errorf("AWG2-сервер не найден")
	}
	for _, candidate := range in.FallbackTunnelIDs {
		if strings.TrimSpace(candidate) == id {
			return fmt.Errorf("подключение не может быть резервом для самого себя")
		}
	}
	fallbacks, err := normalizeFallbackTunnelIDs(id, in.FallbackTunnelIDs, func(id string) bool { return byID[id] != nil })
	if err != nil {
		return err
	}
	graph := map[string][]string{}
	for _, entry := range servers {
		graph[entry.ID] = entry.Manager.Config().Client.FallbackTunnelIDs
	}
	graph[id] = fallbacks
	marks := map[string]int{}
	var visit func(string) bool
	visit = func(current string) bool {
		if marks[current] != 0 {
			return marks[current] == 2
		}
		marks[current] = 1
		for _, next := range graph[current] {
			if !visit(next) {
				return false
			}
		}
		marks[current] = 2
		return true
	}
	if !visit(id) {
		return fmt.Errorf("цикл резервных подключений недопустим")
	}
	// Save before publishing the candidate so failed storage never appears as
	// an acknowledged change in status or another subsequent save.
	candidate := svc.snapshotAWGState()
	for i := range candidate.Servers {
		if candidate.Servers[i].ID == id {
			candidate.Servers[i].Config.Client.Standby = in.Standby
			candidate.Servers[i].Config.Client.FallbackTunnelIDs = fallbacks
		}
	}
	if err := svc.store.SaveSecret(awgConfigFile, &candidate); err != nil {
		return err
	}
	cfg := srv.Manager.Config()
	cfg.Client.Standby, cfg.Client.FallbackTunnelIDs = in.Standby, fallbacks
	if err := srv.Manager.SetConfig(&cfg); err != nil {
		return err
	}
	svc.BumpZonesRevision()
	svc.reconcileStandbyClients()
	return apply()
}
