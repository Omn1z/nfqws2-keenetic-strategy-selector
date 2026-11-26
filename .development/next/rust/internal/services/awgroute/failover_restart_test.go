package awgroute

import (
	"testing"
	"time"

	"nfqws2strategy/internal/services/awg"
)

func TestRestartKeepsAuthenticatedReserveDuringInitialPrimaryVerification(t *testing.T) {
	for _, perRule := range []bool{false, true} {
		name := "connection-list"
		if perRule {
			name = "rule-list"
		}
		t.Run(name, func(t *testing.T) {
			svc, driver, servers := failoverTestService(t)
			primary, reserve, cold := servers[0].Manager, servers[1].Manager, servers[2].Manager
			cold.SetEnabled(true)
			cold.SetClientEnabled(true)
			setTestFailover(t, reserve, true)
			setTestFailover(t, cold, true)
			if perRule {
				primary.SetRoutingState(awg.RoutingConfig{Mode: "zones", Active: true, Zones: []awg.Zone{{Name: "existing", TunnelID: servers[0].ID, FallbackTunnelIDs: []string{servers[1].ID, servers[2].ID}, Enabled: true, Route: "tunnel"}}}, true)
			} else {
				setTestFailover(t, primary, false, servers[1].ID, servers[2].ID)
			}
			driver.states[primary] = ClientStatus{Running: true}
			driver.states[reserve] = ClientStatus{Running: true, Connected: true, LastHandshake: time.Now().Unix()}
			// Working kernel interfaces survive a panel restart, unlike both
			// of these process-local maps.
			svc.clients.states = nil
			svc.clients.standbyActive = nil
			svc.checkClients()
			if driver.downCalls[reserve] != 0 || driver.attempts[reserve] != 0 || !svc.clientShouldRun(reserve) {
				t.Fatal("panel restart interrupted already authenticated reserve")
			}
			if driver.attempts[cold] != 0 || svc.clientShouldRun(cold) {
				t.Fatal("initial verification prematurely woke another cold reserve")
			}
			driver.states[primary] = ClientStatus{Running: true, Connected: true, LastHandshake: time.Now().Unix()}
			svc.checkClients()
			if driver.downCalls[reserve] != 1 || svc.clientShouldRun(reserve) {
				t.Fatal("authenticated primary recovery did not release its reserve")
			}
		})
	}
}
