package awgroute

import (
	"fmt"
	"time"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/logbuf"
)

type doubleTunnelState struct {
	configured      *managedServer
	mode            awg.DoubleTunnelMode
	trialStarted    time.Time
	directUntil     time.Time
	ordinaryAllowed bool

	wanted      *awg.Manager
	outer       *awg.Manager
	engine      string
	outerEngine string
	outerIface  string
	ip          string
	err         string
	next        time.Time
	repairAt    time.Time
}

func (s doubleTunnelState) prioritizesDouble() bool {
	return s.mode == awg.DoubleTunnelPreferred || s.mode == awg.DoubleTunnelAutomatic
}

// The OS client reads this when creating the transport socket. A pending
// standby demand alone never redirects a socket through an unverified outer.
func (svc *Service) doubleTunnelOuter(am *awg.Manager) *awg.Manager {
	svc.clients.mu.Lock()
	defer svc.clients.mu.Unlock()
	return svc.clients.doubleTunnels[am].outer
}

func (svc *Service) doubleTunnelNeedsOuter(am *awg.Manager) bool {
	svc.clients.mu.Lock()
	defer svc.clients.mu.Unlock()
	for _, state := range svc.clients.doubleTunnels {
		if state.wanted == am {
			return true
		}
	}
	return false
}

func (svc *Service) doubleTunnelHealth(am *awg.Manager, st *ClientStatus) {
	if st == nil {
		return
	}
	if !st.transportMarked {
		if am.ClientDoubleTunnelMode() == awg.DoubleTunnelPermanent {
			st.Connected = false
			st.pathUnavailable = true
		}
		return
	}
	svc.clients.mu.Lock()
	current := svc.clients.doubleTunnels[am]
	svc.clients.mu.Unlock()
	st.transportVerified = current.ip != "" && current.engine == st.engineID &&
		current.outer != nil && current.wanted == current.outer && current.outerIface == st.transportOuterIface && st.transportOuterIface != ""
	st.Connected = st.Connected && st.transportVerified
}

func (svc *Service) doubleTunnelFailoverStatus(am *awg.Manager, cfg awg.LocalClientIdentity, st *ClientStatus, out *ConnectionFailoverStatus) {
	out.DoubleTunnelID, out.DoubleTunnelMode = cfg.DoubleTunnelID, cfg.DoubleTunnelMode
	if cfg.DoubleTunnelID == "" && cfg.DoubleTunnelMode != awg.DoubleTunnelPermanent {
		return
	}
	svc.clients.mu.Lock()
	current := svc.clients.doubleTunnels[am]
	svc.clients.mu.Unlock()
	out.DoubleTunnelActive = st != nil && st.transportMarked && clientAuthenticated(st, time.Now())
	if out.DoubleTunnelActive {
		out.DoubleTunnelIP = current.ip
	}
	out.DoubleTunnelError = current.err
}

func (svc *Service) checkPermanentDoubleTunnel(am *awg.Manager) {
	driver := svc.clientLifecycleDriver()
	if st := driver.status(am); st != nil {
		svc.checkDoubleTunnel(am, driver, st, time.Now())
	}
}

func (svc *Service) checkDoubleTunnel(am *awg.Manager, driver clientDriver, st *ClientStatus, now time.Time) bool {
	permanent := am.ClientDoubleTunnelMode() == awg.DoubleTunnelPermanent
	svc.clients.mu.Lock()
	current := svc.clients.doubleTunnels[am]
	requiredAsOuter := false
	for inner, choice := range svc.clients.doubleTunnels {
		if inner != am && choice.wanted == am {
			requiredAsOuter = true
			break
		}
	}
	svc.clients.mu.Unlock()
	waitingFirst := !requiredAsOuter && current.wanted != nil && current.prioritizesDouble() && !current.ordinaryAllowed
	if st.StatusUnavailable && !permanent {
		return waitingFirst
	}
	if !permanent && current.wanted == nil && current.outer == nil && !st.transportMarked {
		return false
	}
	if !permanent && !st.transportMarked && clientAuthenticated(st, now) {
		svc.saveDoubleTunnelState(am, doubleTunnelState{})
		return false
	}
	outer := current.wanted
	var outerStatus *ClientStatus
	if outer != nil && !requiredAsOuter {
		outerStatus = driver.status(outer)
	}
	outerDirect := outerStatus != nil && !outerStatus.transportMarked
	outerReady := outerDirect && !outerStatus.StatusUnavailable && clientAuthenticated(outerStatus, now) && svc.clientShouldRun(outer)
	wantedIface := ""
	if outer != nil {
		wantedIface = outer.RuntimeLocalClientIdentity().ClientIface
	}
	matchingTransport := st.transportMarked && wantedIface != "" && st.transportOuterIface == wantedIface
	if permanent && !outerReady {
		// Stop an old direct or differently marked client before waiting.
		current.mode = awg.DoubleTunnelPermanent
		current.ip = ""
		current.err = "ожидание внешнего туннеля"
		if !matchingTransport && (st.Running || st.IfacePresent) {
			if err := svc.stopFailoverClient(driver, am); err != nil {
				current.err = err.Error()
			} else {
				current = current.withTransport(nil)
				current.err = "ожидание внешнего туннеля"
			}
		}
		svc.saveDoubleTunnelState(am, current)
		return true
	}
	if permanent && st.StatusUnavailable && matchingTransport {
		return false
	}
	if matchingTransport && outerDirect {
		if !outerReady {
			svc.clients.mu.Lock()
			outerRecovery := svc.clients.states[outer]
			svc.clients.mu.Unlock()
			if !clientNeedsFallback(outerRecovery, now) {
				current.ip, current.err, current.next = "", "ожидание внешнего туннеля", time.Time{}
				svc.saveDoubleTunnelState(am, current)
				return true
			}
		} else {
			if !svc.repairDoubleTunnel(am, driver, outerStatus, &current, now) {
				return false
			}
			svc.verifyDoubleTunnel(am, driver, st, current, now)
			return false
		}
	}
	if !outerReady {
		outer = nil
	}
	if !st.transportMarked && outer == nil {
		current.outer, current.engine, current.outerEngine, current.outerIface, current.ip = nil, "", "", "", ""
		if current.wanted != nil && !requiredAsOuter {
			current.err = "ожидание прямого подключения внешнего туннеля"
		}
		svc.saveDoubleTunnelState(am, current)
		return waitingFirst
	}
	if !st.transportMarked && current.outer == outer && now.Before(current.next) {
		return true
	}
	return svc.restartDoubleTunnel(am, driver, outer)
}

func (svc *Service) repairDoubleTunnel(am *awg.Manager, driver clientDriver, outerStatus *ClientStatus, current *doubleTunnelState, now time.Time) bool {
	if current.outer != current.wanted || current.outerEngine != outerStatus.engineID {
		*current = current.withTransport(current.wanted)
		current.outerEngine = outerStatus.engineID
	}
	repairer, ok := driver.(interface {
		repairDoubleTunnel(*awg.Manager, *awg.Manager) error
	})
	if !ok || now.Before(current.repairAt) {
		return true
	}
	if err := repairer.repairDoubleTunnel(am, current.outer); err != nil {
		current.ip, current.err = "", err.Error()
		svc.saveDoubleTunnelState(am, *current)
		return false
	}
	current.repairAt = time.Now().Add(30 * time.Second)
	svc.saveDoubleTunnelState(am, *current)
	return true
}

func (svc *Service) saveDoubleTunnelState(am *awg.Manager, state doubleTunnelState) {
	svc.clients.mu.Lock()
	defer svc.clients.mu.Unlock()
	if state.wanted == nil && state.outer == nil && state.trialStarted.IsZero() && state.mode != awg.DoubleTunnelPermanent {
		delete(svc.clients.doubleTunnels, am)
		return
	}
	if svc.clients.doubleTunnels == nil {
		svc.clients.doubleTunnels = map[*awg.Manager]doubleTunnelState{}
	}
	svc.clients.doubleTunnels[am] = state
}

func (s doubleTunnelState) withTransport(outer *awg.Manager) doubleTunnelState {
	return doubleTunnelState{
		configured: s.configured, mode: s.mode, trialStarted: s.trialStarted,
		directUntil: s.directUntil, ordinaryAllowed: s.ordinaryAllowed,
		wanted: s.wanted, outer: outer,
	}
}

func (svc *Service) reconnectDoubleTunnel(am *awg.Manager, driver clientDriver) bool {
	outer := svc.doubleTunnelOuter(am)
	if am.ClientDoubleTunnelMode() == awg.DoubleTunnelPermanent {
		if outer != nil {
			svc.restartDoubleTunnel(am, driver, outer)
		}
		return true
	}
	return outer != nil && svc.restartDoubleTunnel(am, driver, nil)
}

func (svc *Service) restartDoubleTunnel(am *awg.Manager, driver clientDriver, outer *awg.Manager) bool {
	ctx := svc.clientOpContext()
	if ctx.Err() != nil {
		return true
	}
	svc.clients.mu.Lock()
	state := svc.clients.doubleTunnels[am].withTransport(outer)
	svc.clients.mu.Unlock()
	// Both paths use this profile's existing peer. Recreate one local daemon
	// so its transport mark and any negotiated handshake belong to one path.
	if outer != nil {
		am.SelectClientEndpoint(0)
	} else {
		svc.forgetClientRecovery(am)
		if state.prioritizesDouble() {
			state.ordinaryAllowed = true
			state.directUntil = time.Now().Add(svc.currentRecoverySettings().handshakeTimeout())
		}
	}
	state.wanted = outer
	svc.saveDoubleTunnelState(am, state)
	err := recoverWithExistingPeer(driver, am)
	if ctx.Err() != nil {
		return true
	}
	svc.recordClientAttempt(am, err)
	svc.route.tunnelUpAt.Store(0)
	if err != nil {
		state.err = err.Error()
		state.next = time.Now().Add(clientProbeGrace)
		svc.saveDoubleTunnelState(am, state)
		logbuf.Append("awg2", "warn", "двойной туннель: "+err.Error())
	}
	return true
}

func recoverWithExistingPeer(driver clientDriver, am *awg.Manager) error {
	if local, ok := driver.(interface{ recoverWithExistingPeer(*awg.Manager) error }); ok {
		return local.recoverWithExistingPeer(am)
	}
	return driver.recover(am)
}

func (svc *Service) verifyDoubleTunnel(am *awg.Manager, driver clientDriver, st *ClientStatus, current doubleTunnelState, now time.Time) {
	if current.engine != st.engineID {
		current.engine, current.ip, current.err, current.next = st.engineID, "", "", time.Time{}
		svc.saveDoubleTunnelState(am, current)
	}
	if current.ip != "" || now.Before(current.next) || !st.Running || st.LastHandshake <= 0 ||
		now.Unix() < st.LastHandshake || now.Unix()-st.LastHandshake >= int64(clientStaleAfter/time.Second) {
		return
	}
	verifier, ok := driver.(interface {
		verifyDoubleTunnel(*awg.Manager) (string, error)
	})
	if !ok {
		return
	}
	ip, err := verifier.verifyDoubleTunnel(am)
	if svc.clientOpContext().Err() != nil {
		return
	}
	if err != nil {
		current.err = err.Error()
		current.next = time.Now().Add(clientProbeGrace)
		svc.saveDoubleTunnelState(am, current)
		return
	}
	current.outerIface, current.ip, current.err = st.transportOuterIface, ip, ""
	svc.saveDoubleTunnelState(am, current)
	svc.clients.mu.Lock()
	if svc.clients.states == nil {
		svc.clients.states = map[*awg.Manager]clientRecovery{}
	}
	recovery := svc.clients.states[am]
	recovery.RoutesPending = true
	svc.clients.states[am] = recovery
	svc.clients.mu.Unlock()
	svc.route.tunnelUpAt.Store(0)
	logbuf.Append("awg2", "info", fmt.Sprintf("двойной туннель %s: handshake и HTTPS подтверждены", awgClientIfaceName(am.RuntimeConfig())))
}

func (d systemClientDriver) verifyDoubleTunnel(am *awg.Manager) (string, error) {
	return probeConnectionDataOS(d.svc.clientOpContext(), awgClientIfaceName(am.RuntimeConfig()))
}
