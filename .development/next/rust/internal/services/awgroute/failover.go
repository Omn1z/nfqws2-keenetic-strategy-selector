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
	FallbackTunnelIDs []string              `json:"fallback_tunnel_ids"`
	Standby           bool                  `json:"standby"`
	DoubleTunnelID    *string               `json:"double_tunnel_id,omitempty"`
	DoubleTunnelMode  *awg.DoubleTunnelMode `json:"double_tunnel_mode,omitempty"`
}

type ConnectionFailoverStatus struct {
	FallbackTunnelIDs  []string             `json:"fallback_tunnel_ids"`
	Standby            bool                 `json:"standby"`
	Activated          bool                 `json:"activated"`
	ActiveTunnelID     string               `json:"active_tunnel_id"`
	DoubleTunnelID     string               `json:"double_tunnel_id,omitempty"`
	DoubleTunnelMode   awg.DoubleTunnelMode `json:"double_tunnel_mode"`
	DoubleTunnelActive bool                 `json:"double_tunnel_active"`
	DoubleTunnelIP     string               `json:"double_tunnel_ip,omitempty"`
	DoubleTunnelError  string               `json:"double_tunnel_error,omitempty"`
}

func (svc *Service) clientShouldRun(am *awg.Manager) bool {
	if svc.awgPersistenceReady() != nil {
		return false
	}
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
	return r.pathUnavailable || r.Attempts > 1 || r.Attempts > 0 && !r.VerifyUntil.IsZero() && !now.Before(r.VerifyUntil) ||
		!r.ProbeAt.IsZero() && !now.Before(r.probeDeadline())
}

func clientAuthenticated(st *ClientStatus, now time.Time) bool {
	if st == nil || !st.Running || st.pathUnavailable || (st.transportMarked && !st.transportVerified) {
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
	svc.mu.RLock()
	owner := svc.servers[primary]
	svc.mu.RUnlock()
	primaryIdentity := awg.LocalClientIdentity{}
	if owner != nil {
		primaryIdentity = owner.Manager.RuntimeLocalClientIdentity()
	}
	if primaryIdentity.DoubleTunnelMode == awg.DoubleTunnelPermanent || len(ruleFallbacks) == 0 && len(primaryIdentity.FallbackTunnelIDs) == 0 {
		return nil
	}
	identities := map[string]awg.LocalClientIdentity{primary: primaryIdentity}
	for _, srv := range svc.serverSnapshot() {
		if srv.ID != primary {
			identities[srv.ID] = srv.Manager.RuntimeLocalClientIdentity()
		}
	}
	return connectionFallbackTunnelIDs(identities, primary, ruleFallbacks)
}

func connectionFallbackTunnelIDs(identities map[string]awg.LocalClientIdentity, primary string, ruleFallbacks []string) []string {
	owner := identities[primary]
	if owner.DoubleTunnelMode == awg.DoubleTunnelPermanent {
		return nil
	}
	if len(owner.FallbackTunnelIDs) == 0 && len(ruleFallbacks) == 0 {
		return nil
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
		if identity := identities[id]; identity.DoubleTunnelMode != awg.DoubleTunnelPermanent {
			for _, next := range identity.FallbackTunnelIDs {
				appendID(next)
			}
		}
	}
	for _, id := range ruleFallbacks {
		appendID(id)
	}
	for _, id := range owner.FallbackTunnelIDs {
		appendID(id)
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
		if c.DoubleTunnelMode != awg.DoubleTunnelPermanent {
			for _, child := range c.FallbackTunnelIDs {
				include(child)
			}
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
	if svc.clientOpContext().Err() != nil || svc.awgPersistenceReady() != nil {
		return
	}
	servers := svc.serverSnapshot()
	plan := newFailoverPlanner(svc, servers)
	for _, srv := range servers {
		if !plan.identities[srv.ID].Standby {
			plan.check(srv)
		}
	}
	// A cold reserve can itself require double tunneling. Its outer link is
	// demanded before the watchdog tries to open the reserve's VPN socket.
	for _, srv := range servers {
		if plan.ordinary[srv.Manager] && plan.identities[srv.ID].Standby {
			plan.check(srv)
		}
	}
	svc.clients.mu.Lock()
	svc.clients.standbyActive = plan.wanted
	for am, r := range plan.exhaustedStates {
		svc.clients.states[am] = r
	}
	svc.clients.doubleTunnels = plan.double
	svc.clients.mu.Unlock()
	for _, srv := range servers {
		if !plan.identities[srv.ID].Standby || plan.wanted[srv.Manager] {
			continue
		}
		am := srv.Manager
		if st := plan.status(am); st != nil && (st.Running || st.IfacePresent) {
			if err := svc.stopFailoverClient(plan.driver, am); err != nil {
				logbuf.Append("awg2", "warn", "отключение резервного туннеля: "+err.Error())
			}
		}
		svc.forgetClientRecovery(am)
	}
}

type failoverPlanner struct {
	svc             *Service
	driver          clientDriver
	now             time.Time
	settings        RecoverySettings
	byID            map[string]*managedServer
	identities      map[string]awg.LocalClientIdentity
	statuses        map[*awg.Manager]*ClientStatus
	exhaustedStates map[*awg.Manager]clientRecovery
	wanted          map[*awg.Manager]bool
	ordinary        map[*awg.Manager]bool
	double          map[*awg.Manager]doubleTunnelState
	rules           map[string][][]string
	readRules       bool
}

func newFailoverPlanner(svc *Service, servers []*managedServer) *failoverPlanner {
	p := &failoverPlanner{
		svc: svc, driver: svc.clientLifecycleDriver(), now: time.Now(), settings: svc.currentRecoverySettings(),
		byID: make(map[string]*managedServer, len(servers)), identities: make(map[string]awg.LocalClientIdentity, len(servers)),
		statuses: map[*awg.Manager]*ClientStatus{}, exhaustedStates: map[*awg.Manager]clientRecovery{},
		wanted: map[*awg.Manager]bool{}, ordinary: map[*awg.Manager]bool{}, double: map[*awg.Manager]doubleTunnelState{},
	}
	for _, srv := range servers {
		p.byID[srv.ID] = srv
		p.identities[srv.ID] = srv.Manager.RuntimeLocalClientIdentity()
	}
	return p
}

func (p *failoverPlanner) status(am *awg.Manager) *ClientStatus {
	st, known := p.statuses[am]
	if !known {
		st = p.driver.status(am)
		p.statuses[am] = st
	}
	return st
}

func (p *failoverPlanner) recovery(am *awg.Manager) clientRecovery {
	if r, ok := p.exhaustedStates[am]; ok {
		return r
	}
	p.svc.clients.mu.Lock()
	r := p.svc.clients.states[am]
	p.svc.clients.mu.Unlock()
	return r
}

func (p *failoverPlanner) doubleState(am *awg.Manager) doubleTunnelState {
	p.svc.clients.mu.Lock()
	defer p.svc.clients.mu.Unlock()
	return p.svc.clients.doubleTunnels[am]
}

func (p *failoverPlanner) exhausted(am *awg.Manager) bool {
	if !p.svc.endpointPoolAllowsFallback(am) {
		return false
	}
	r := p.recovery(am)
	if !r.directExhausted && clientNeedsFallback(r, p.now) && !p.now.Before(r.VerifyUntil) {
		r.directExhausted = true
		p.exhaustedStates[am] = r
	}
	return r.directExhausted
}

func (p *failoverPlanner) check(primary *managedServer) {
	am, id := primary.Manager, primary.ID
	cfg := p.identities[id]
	if !cfg.Enabled || !cfg.ClientEnabled || !cfg.CanStart {
		return
	}
	current := p.doubleState(am)
	outer := p.byID[cfg.DoubleTunnelID]
	if outer == primary || p.identities[cfg.DoubleTunnelID].DoubleTunnelMode == awg.DoubleTunnelPermanent {
		outer = nil
	}
	if current.mode != cfg.DoubleTunnelMode || current.configured != outer {
		// Keep the installed transport until checkDoubleTunnel tears it down
		// or switches it. Trial windows belong only to the saved policy.
		current = doubleTunnelState{outer: current.outer, mode: cfg.DoubleTunnelMode, configured: outer}
	}
	current.wanted = nil
	st := p.status(am)
	nested := st != nil && st.transportMarked
	connected := clientAuthenticated(st, p.now)
	if cfg.DoubleTunnelMode == awg.DoubleTunnelPermanent {
		if connected {
			current.trialStarted = time.Time{}
		} else if current.trialStarted.IsZero() {
			current.trialStarted = p.now
		}
		p.demandDouble(outer, st, &current)
		p.double[am] = current
		return
	}
	if !nested && connected {
		return
	}
	directFailed := clientNeedsFallback(p.recovery(am), p.now)
	if outer != nil && current.prioritizesDouble() && (nested || directFailed || !current.trialStarted.IsZero()) {
		p.planEarlyDouble(primary, outer, st, &current, nested && connected)
		p.double[am] = current
		return
	}
	doubleEligible := outer != nil && (nested || p.exhausted(am))
	reserves := p.demandReserves(primary, nested || doubleEligible || directFailed && p.svc.endpointPoolAllowsFallback(am))
	if doubleEligible && !reserves.connected && (nested || !reserves.pending) {
		p.demandDouble(outer, st, &current)
	}
	if current.wanted != nil || current.outer != nil {
		p.double[am] = current
	}
}

func (p *failoverPlanner) planEarlyDouble(primary, outer *managedServer, st *ClientStatus, current *doubleTunnelState, ready bool) {
	if current.trialStarted.IsZero() {
		current.trialStarted = p.now
	}
	// The outer and inner each get one handshake window. A failed local
	// start or a proven path outage can advance to ordinary reserves sooner.
	nestedFailed := st != nil && st.transportMarked && st.pathUnavailable || current.outer != nil && current.err != "" && !current.next.IsZero()
	current.ordinaryAllowed = current.ordinaryAllowed || p.doubleTrialElapsed(*current) || nestedFailed ||
		(current.mode == awg.DoubleTunnelAutomatic && ready) || !p.canStartOuter(outer)
	var reserves failoverReserveState
	if current.ordinaryAllowed && (!ready || current.mode == awg.DoubleTunnelAutomatic) {
		reserves = p.demandReserves(primary, true)
	}
	if current.mode == awg.DoubleTunnelAutomatic && reserves.connectionConnected {
		return
	}
	if !p.now.Before(current.directUntil) {
		p.demandDouble(outer, st, current)
	}
}

func (p *failoverPlanner) doubleTrialElapsed(state doubleTunnelState) bool {
	return !state.trialStarted.IsZero() && !p.now.Before(state.trialStarted.Add(2*p.settings.handshakeTimeout()))
}

func (p *failoverPlanner) canStartOuter(outer *managedServer) bool {
	if outer == nil {
		return false
	}
	cfg := p.identities[outer.ID]
	return cfg.Enabled && cfg.ClientEnabled && cfg.CanStart
}

func (p *failoverPlanner) demandDouble(outer *managedServer, st *ClientStatus, current *doubleTunnelState) {
	if !p.canStartOuter(outer) {
		return
	}
	p.wanted[outer.Manager] = true
	current.wanted = outer.Manager
	if current.outer == nil && st != nil && st.transportMarked && st.transportOuterIface == p.identities[outer.ID].ClientIface {
		current.outer = outer.Manager
	}
}

type failoverReserveState struct {
	connected           bool
	connectionConnected bool
	pending             bool
}

func (p *failoverPlanner) demandReserves(primary *managedServer, startNew bool) failoverReserveState {
	if !p.readRules {
		p.rules, p.readRules = p.svc.awgRuleFailovers(), true
	}
	out := p.demandReserveList(connectionFallbackTunnelIDs(p.identities, primary.ID, nil), startNew)
	out.connectionConnected = out.connected
	for _, fallbacks := range p.rules[primary.ID] {
		if len(fallbacks) == 0 {
			continue
		}
		state := p.demandReserveList(connectionFallbackTunnelIDs(p.identities, primary.ID, fallbacks), startNew)
		out.connected = out.connected || state.connected
		out.pending = out.pending || state.pending
	}
	return out
}

func (p *failoverPlanner) demandReserveList(ids []string, startNew bool) failoverReserveState {
	for _, id := range ids {
		reserve := p.byID[id]
		cfg := p.identities[id]
		if reserve == nil || !cfg.Enabled || !cfg.ClientEnabled || !cfg.CanStart {
			continue
		}
		permanent := cfg.DoubleTunnelMode == awg.DoubleTunnelPermanent
		if permanent && !p.canStartOuter(p.byID[cfg.DoubleTunnelID]) {
			continue
		}
		connected := clientAuthenticated(p.status(reserve.Manager), p.now)
		// A service restart forgets demand. Retain a warm reserve during
		// primary verification, but do not wake a cold one before it fails.
		if connected || startNew {
			p.wanted[reserve.Manager], p.ordinary[reserve.Manager] = true, true
		}
		if connected {
			return failoverReserveState{connected: true}
		}
		if startNew && permanent && !p.doubleTrialElapsed(p.doubleState(reserve.Manager)) {
			return failoverReserveState{pending: true}
		}
		if startNew && !permanent && !p.exhausted(reserve.Manager) {
			return failoverReserveState{pending: true}
		}
	}
	return failoverReserveState{}
}

func (svc *Service) stopFailoverClient(driver clientDriver, am *awg.Manager) error {
	if down, ok := driver.(interface{ down(*awg.Manager) error }); ok {
		return down.down(am)
	}
	if svc.clients.driver == nil {
		return svc.awgClientDownManagerOS(am)
	}
	return nil
}

func (svc *Service) connectionFailoverStatus(srv *managedServer, statuses map[string]*ClientStatus) *ConnectionFailoverStatus {
	cfg := srv.Manager.RuntimeLocalClientIdentity()
	svc.clients.mu.Lock()
	activated := svc.clients.standbyActive[srv.Manager]
	svc.clients.mu.Unlock()
	status := &ConnectionFailoverStatus{FallbackTunnelIDs: append([]string{}, cfg.FallbackTunnelIDs...), Standby: cfg.Standby, Activated: cfg.Standby && activated}
	svc.doubleTunnelFailoverStatus(srv.Manager, cfg, statuses[srv.ID], status)
	byID := map[string]*managedServer{}
	for _, candidate := range svc.serverSnapshot() {
		byID[candidate.ID] = candidate
	}
	for _, id := range svc.orderedFallbackCandidates(srv.ID, svc.endpointFallbackTunnelIDs(srv.ID, nil)) {
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
	if owner := svc.legacyFullRoutingOwner(); owner != nil && owner.Manager.RuntimeLocalClientIdentity().DoubleTunnelMode == awg.DoubleTunnelPermanent {
		return rules
	}
	for _, srv := range svc.serverSnapshot() {
		cfg := srv.Manager.RuntimeLocalClientIdentity()
		if cfg.Enabled && cfg.ClientEnabled && cfg.RoutingActive && cfg.RoutingMode == "full" &&
			cfg.DoubleTunnelMode != awg.DoubleTunnelPermanent && len(cfg.FallbackTunnelIDs) > 0 {
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
	for _, id := range svc.orderedFallbackCandidates(primary, svc.endpointFallbackTunnelIDs(primary, nil)) {
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
	transports := map[string]string{}
	for _, entry := range servers {
		config := entry.Manager.RuntimeLocalClientIdentity()
		graph[entry.ID] = config.FallbackTunnelIDs
		transports[entry.ID] = config.DoubleTunnelID
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
	outer := transports[id]
	mode := srv.Manager.RuntimeLocalClientIdentity().DoubleTunnelMode
	if in.DoubleTunnelMode != nil {
		mode = *in.DoubleTunnelMode
		if !mode.Valid() {
			return fmt.Errorf("неизвестный режим двойного туннеля")
		}
	}
	if in.DoubleTunnelID != nil {
		outer = strings.TrimSpace(*in.DoubleTunnelID)
		if outer == "" {
			mode = awg.DoubleTunnelLastResort
		}
	}
	if outer != "" && byID[outer] == nil {
		return fmt.Errorf("внешнее подключение для двойного туннеля не найдено")
	}
	if outer == "" && mode == awg.DoubleTunnelPermanent && srv.Manager.RuntimeLocalClientIdentity().DoubleTunnelMode != mode {
		return fmt.Errorf("выберите внешний туннель для постоянного двойного туннелирования")
	}
	transports[id] = outer
	if doubleTunnelCycle(transports, id) {
		return fmt.Errorf("цикл двойных туннелей недопустим")
	}
	if mode == awg.DoubleTunnelPermanent && outer != "" {
		for other, transport := range transports {
			if other != id && transport == id {
				return fmt.Errorf("подключение с постоянным двойным туннелем нельзя использовать как внешний транспорт")
			}
		}
	}
	if transport := byID[outer]; transport != nil && transport.Manager.RuntimeLocalClientIdentity().DoubleTunnelMode == awg.DoubleTunnelPermanent {
		return fmt.Errorf("подключение с постоянным двойным туннелем нельзя использовать как внешний транспорт")
	}
	// Save before publishing the candidate so failed storage never appears as
	// an acknowledged change in status or another subsequent save.
	candidate := svc.snapshotAWGState()
	for i := range candidate.Servers {
		if candidate.Servers[i].ID == id {
			candidate.Servers[i].Config.Client.Standby = in.Standby
			candidate.Servers[i].Config.Client.FallbackTunnelIDs = fallbacks
			candidate.Servers[i].Config.Client.DoubleTunnelID = outer
			candidate.Servers[i].Config.Client.DoubleTunnelMode = mode
		}
	}
	if err := svc.persistAWGState(&candidate); err != nil {
		return err
	}
	srv.Manager.SetClientFailoverPolicy(fallbacks, in.Standby, outer, mode)
	svc.route.tunnelUpAt.Store(0)
	svc.BumpZonesRevision()
	svc.reconcileStandbyClients()
	if mode == awg.DoubleTunnelPermanent && svc.clientShouldRun(srv.Manager) {
		svc.checkPermanentDoubleTunnel(srv.Manager)
	}
	return apply()
}

func doubleTunnelCycle(transports map[string]string, id string) bool {
	visited := map[string]bool{}
	for id != "" {
		if visited[id] {
			return true
		}
		visited[id] = true
		id = transports[id]
	}
	return false
}
