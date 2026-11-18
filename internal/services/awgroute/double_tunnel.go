package awgroute

import (
	"fmt"
	"time"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/logbuf"
)

type doubleTunnelState struct {
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

func (svc *Service) setWantedDoubleTunnelsLocked(wanted, inherited map[*awg.Manager]*awg.Manager) {
	if svc.clients.doubleTunnels == nil && len(wanted) > 0 {
		svc.clients.doubleTunnels = map[*awg.Manager]doubleTunnelState{}
	}
	for am, current := range svc.clients.doubleTunnels {
		if wanted[am] == nil && current.outer == nil {
			delete(svc.clients.doubleTunnels, am)
			continue
		}
		current.wanted = wanted[am]
		svc.clients.doubleTunnels[am] = current
	}
	for am, outer := range wanted {
		current := svc.clients.doubleTunnels[am]
		current.wanted = outer
		if current.outer == nil {
			current.outer = inherited[am]
		}
		svc.clients.doubleTunnels[am] = current
	}
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
	if !st.transportMarked {
		return
	}
	svc.clients.mu.Lock()
	current := svc.clients.doubleTunnels[am]
	svc.clients.mu.Unlock()
	st.transportVerified = current.ip != "" && current.engine == st.engineID &&
		current.outer != nil && current.wanted == current.outer && current.outerIface == st.transportOuterIface && st.transportOuterIface != ""
	st.Connected = st.Connected && st.transportVerified
}

func (svc *Service) doubleTunnelFailoverStatus(am *awg.Manager, id string, st *ClientStatus, out *ConnectionFailoverStatus) {
	out.DoubleTunnelID = id
	if id == "" {
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

func (svc *Service) checkDoubleTunnel(am *awg.Manager, driver clientDriver, st *ClientStatus, now time.Time) bool {
	svc.clients.mu.Lock()
	current := svc.clients.doubleTunnels[am]
	requiredAsOuter := false
	for inner, choice := range svc.clients.doubleTunnels {
		if inner != am && choice.outer == am && choice.wanted == am {
			requiredAsOuter = true
			break
		}
	}
	svc.clients.mu.Unlock()
	if st.StatusUnavailable || (current.wanted == nil && current.outer == nil && !st.transportMarked) {
		return false
	}
	if !st.transportMarked && clientAuthenticated(st, now) {
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
		wantedIface = awgClientIfaceName(outer.RuntimeConfig())
	}
	if st.transportMarked && outer != nil && st.transportOuterIface == wantedIface && outerDirect {
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
		current = doubleTunnelState{wanted: current.wanted}
		if current.wanted != nil && !requiredAsOuter {
			current.err = "ожидание прямого подключения внешнего туннеля"
		}
		svc.saveDoubleTunnelState(am, current)
		return false
	}
	if !st.transportMarked && current.outer == outer && now.Before(current.next) {
		return true
	}
	return svc.restartDoubleTunnel(am, driver, outer)
}

func (svc *Service) repairDoubleTunnel(am *awg.Manager, driver clientDriver, outerStatus *ClientStatus, current *doubleTunnelState, now time.Time) bool {
	if current.outer != current.wanted || current.outerEngine != outerStatus.engineID {
		*current = doubleTunnelState{wanted: current.wanted, outer: current.wanted, outerEngine: outerStatus.engineID}
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
	if state.wanted == nil && state.outer == nil {
		delete(svc.clients.doubleTunnels, am)
		return
	}
	if svc.clients.doubleTunnels == nil {
		svc.clients.doubleTunnels = map[*awg.Manager]doubleTunnelState{}
	}
	svc.clients.doubleTunnels[am] = state
}

func (svc *Service) restartDoubleTunnel(am *awg.Manager, driver clientDriver, outer *awg.Manager) bool {
	ctx := svc.clientOpContext()
	if ctx.Err() != nil {
		return true
	}
	// Both paths use this profile's existing peer. Recreate one local daemon
	// so its transport mark and any negotiated handshake belong to one path.
	if outer != nil {
		am.SelectClientEndpoint(0)
	} else {
		svc.forgetClientRecovery(am)
	}
	state := doubleTunnelState{wanted: outer, outer: outer}
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
	svc.route.tunnelUpAt.Store(0)
	logbuf.Append("awg2", "info", fmt.Sprintf("двойной туннель %s: handshake и HTTPS подтверждены", awgClientIfaceName(am.RuntimeConfig())))
}

func (d systemClientDriver) verifyDoubleTunnel(am *awg.Manager) (string, error) {
	return probeConnectionDataOS(d.svc.clientOpContext(), awgClientIfaceName(am.RuntimeConfig()))
}
