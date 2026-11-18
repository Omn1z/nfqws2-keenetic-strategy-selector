package awgroute

import (
	"errors"
	"testing"
	"time"

	"nfqws2strategy/internal/services/awg"
)

type doubleTunnelTestDriver struct {
	*failoverTestDriver
	svc       *Service
	verifyErr error
	checks    int
}

func (d *doubleTunnelTestDriver) status(am *awg.Manager) *ClientStatus {
	st := d.failoverTestDriver.status(am)
	d.svc.doubleTunnelHealth(am, st)
	return st
}

func (d *doubleTunnelTestDriver) verifyDoubleTunnel(*awg.Manager) (string, error) {
	d.checks++
	return "203.0.113.10", d.verifyErr
}

func TestDoubleTunnelWaitsForDirectReservesAndConfirmsData(t *testing.T) {
	svc, driver, entries := failoverTestService(t)
	primary, reserve, outer := entries[0].Manager, entries[1].Manager, entries[2].Manager
	outer.SetEnabled(true)
	outer.SetClientEnabled(true)
	setTestFailover(t, reserve, true)
	setTestFailover(t, outer, true)
	primary.SetClientFailoverPolicy([]string{entries[1].ID}, false, entries[2].ID)
	if err := primary.SetEndpointBackups([]string{"192.0.2.2"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	svc.clients.states = map[*awg.Manager]clientRecovery{primary: {Recovering: true, Attempts: 2}}
	d := &doubleTunnelTestDriver{failoverTestDriver: driver, svc: svc, verifyErr: errors.New("no HTTPS data")}
	svc.clients.driver = d
	_, unlock := svc.lockClientOps(false)
	defer unlock()
	svc.reconcileStandbyClients()
	if svc.clientShouldRun(reserve) || svc.clientShouldRun(outer) {
		t.Fatal("woke a reserve before the IP pool was exhausted")
	}
	svc.prepareClientEndpointAttempt(primary, false)
	svc.prepareClientEndpointAttempt(primary, true)
	svc.prepareClientEndpointAttempt(primary, true)
	svc.clients.states[reserve] = clientRecovery{Recovering: true, Attempts: 2, VerifyUntil: now.Add(time.Minute)}
	svc.reconcileStandbyClients()
	if !svc.clientShouldRun(reserve) || svc.clientShouldRun(outer) {
		t.Fatal("woke the outer tunnel while the ordinary reserve was being verified")
	}
	svc.clients.states[reserve] = clientRecovery{Recovering: true, Attempts: 2}
	svc.reconcileStandbyClients()
	if !svc.clientShouldRun(outer) || svc.doubleTunnelOuter(primary) != nil {
		t.Fatal("outer was not demanded, or was selected before authentication")
	}
	d.states[outer] = ClientStatus{Running: true, Connected: true, LastHandshake: now.Unix()}
	d.onRecover = func(am *awg.Manager) error {
		if am == primary && svc.doubleTunnelOuter(am) == outer {
			if am.RuntimeConfig().Endpoint != am.ClientEndpointCandidates()[0] {
				t.Fatal("nested mode reused a failed direct backup endpoint")
			}
			d.states[am] = ClientStatus{Running: true, Endpoint: am.RuntimeConfig().Endpoint,
				engineID: "inner/1", transportMarked: true, transportOuterIface: outer.RuntimeConfig().ClientIface}
		}
		return nil
	}
	svc.checkClient(entries[0])
	if svc.doubleTunnelOuter(primary) != outer || d.attempts[primary] != 1 || svc.tunnelUpForManagedServer(entries[0]) {
		t.Fatal("inner tunnel was not switched, or was reported healthy before its handshake")
	}
	svc.checkClient(entries[0])
	if d.checks != 0 {
		t.Fatal("started data probe before the inner handshake")
	}
	inner := d.states[primary]
	inner.Connected, inner.LastHandshake = true, now.Unix()
	d.states[primary] = inner
	svc.checkClient(entries[0])
	if d.checks != 1 || clientAuthenticated(d.status(primary), now) {
		t.Fatal("handshake alone reported a double tunnel as healthy")
	}
	d.verifyErr = nil
	state := svc.clients.doubleTunnels[primary]
	state.next = time.Time{}
	svc.clients.doubleTunnels[primary] = state
	svc.checkClient(entries[0])
	status := svc.connectionFailoverStatus(entries[0], map[string]*ClientStatus{entries[0].ID: d.status(primary)})
	if !status.DoubleTunnelActive || status.DoubleTunnelIP != "203.0.113.10" || status.ActiveTunnelID != entries[0].ID {
		t.Fatalf("unexpected verified status: %+v", status)
	}
	d.states[reserve] = ClientStatus{Running: true, Connected: true, LastHandshake: now.Unix()}
	svc.reconcileStandbyClients()
	svc.checkClient(entries[0])
	if svc.clientShouldRun(outer) || svc.doubleTunnelOuter(primary) != nil || d.attempts[primary] != 2 {
		t.Fatal("an authenticated ordinary reserve did not supersede the double tunnel")
	}
}

func TestDoubleTunnelAdoptsInheritedTransportAndProtectsOuter(t *testing.T) {
	svc, driver, entries := failoverTestService(t)
	primary, outer, next := entries[0].Manager, entries[1].Manager, entries[2].Manager
	next.SetEnabled(true)
	next.SetClientEnabled(true)
	primary.SetClientFailoverPolicy(nil, false, entries[1].ID)
	outer.SetClientFailoverPolicy(nil, false, entries[2].ID)
	now := time.Now()
	driver.states[primary] = ClientStatus{Running: true, Connected: true, LastHandshake: now.Unix(),
		transportMarked: true, transportOuterIface: outer.RuntimeConfig().ClientIface, engineID: "inner/1"}
	driver.states[next] = ClientStatus{Running: true, Connected: true, LastHandshake: now.Unix()}
	svc.clients.states = map[*awg.Manager]clientRecovery{outer: {Recovering: true, Attempts: 2}}
	d := &doubleTunnelTestDriver{failoverTestDriver: driver, svc: svc}
	svc.clients.driver = d
	_, unlock := svc.lockClientOps(false)
	defer unlock()
	svc.reconcileStandbyClients()
	if svc.doubleTunnelOuter(primary) != outer {
		t.Fatal("supervisor forgot the inherited outer")
	}
	svc.checkClient(entries[1])
	if svc.doubleTunnelOuter(outer) != nil {
		t.Fatal("an outer tunnel in use switched itself to nested transport")
	}
	d.states[outer] = ClientStatus{Running: true, Connected: true, LastHandshake: now.Unix()}
	svc.checkClient(entries[0])
	if !clientAuthenticated(d.status(primary), now) || d.attempts[primary] != 0 {
		t.Fatal("healthy inherited tunnel was restarted instead of verified")
	}
	inner := d.states[primary]
	inner.Connected, inner.LastHandshake = false, now.Add(-clientStaleAfter).Unix()
	d.states[primary] = inner
	svc.clients.states[primary] = clientRecovery{Attempts: 1, Recovering: true}
	svc.checkClient(entries[0])
	if svc.doubleTunnelOuter(primary) != nil || d.attempts[primary] != 1 {
		t.Fatal("failed nested tunnel did not retry the primary via WAN")
	}
}
