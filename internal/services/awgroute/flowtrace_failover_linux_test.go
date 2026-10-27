//go:build linux

package awgroute

import (
	"net/netip"
	"strings"
	"testing"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/netmon"
)

func TestFlowTraceFollowsPhysicalConnectionBackupAndReturnsToPrimary(t *testing.T) {
	svc, driver, entries := failoverTestService(t)
	primary, backup := entries[0].Manager, entries[1].Manager
	setTestFailover(t, primary, false, "two")
	setTestFailover(t, backup, true)
	backup.SetRoutingState(awg.RoutingConfig{Mode: "zones", Active: false}, false)
	primary.SetRoutingState(awg.RoutingConfig{Mode: "zones", Active: true, Zones: []awg.Zone{{
		Name: "TG", TunnelID: "one", Route: "tunnel", Enabled: true, IPs: []string{"149.154.160.0/20", "91.108.4.0/22"},
	}}}, true)
	svc.clients.standbyActive = map[*awg.Manager]bool{backup: true}
	driver.states[backup] = ClientStatus{Running: true, Connected: true}
	flow := netmon.Conn{Src: netip.MustParseAddr("192.168.3.100"), Dst: netip.MustParseAddr("149.154.167.51")}
	decision := awgFlowDecisionFor(flow, svc.awgFlowTraceRules())
	if decision.TunnelID != "two" || decision.TunnelIface != "awg1" || !strings.Contains(decision.Reason, "-> awg1") {
		t.Fatalf("trace retained the dead primary instead of its physical backup: %+v", decision)
	}
	if primary.Config().Routing.Zones[0].TunnelID != "one" {
		t.Fatal("trace changed the logical rule owner")
	}
	driver.states[primary] = ClientStatus{Running: true, Connected: true}
	decision = awgFlowDecisionFor(flow, svc.awgFlowTraceRules())
	if decision.TunnelID != "one" || decision.TunnelIface != "awg0" {
		t.Fatalf("trace did not return to the recovered primary: %+v", decision)
	}
}

func TestFlowTraceUsesRuleSpecificReserveBeforeConnectionReserve(t *testing.T) {
	svc, driver, entries := failoverTestService(t)
	primary, specific, general := entries[0].Manager, entries[1].Manager, entries[2].Manager
	general.SetEnabled(true)
	general.SetClientEnabled(true)
	setTestFailover(t, primary, false, "off")
	primary.SetRoutingState(awg.RoutingConfig{Mode: "zones", Active: true, Zones: []awg.Zone{{
		Name: "TG", TunnelID: "one", Route: "tunnel", Enabled: true, FallbackTunnelIDs: []string{"two"}, IPs: []string{"149.154.160.0/20"},
	}}}, true)
	// Rule-only reserves are committed by the normal rules save operation.
	specific.SetRoutingState(awg.RoutingConfig{Mode: "zones", Active: true}, true)
	driver.states[specific] = ClientStatus{Running: true, Connected: true}
	driver.states[general] = ClientStatus{Running: true, Connected: true}
	decision := awgFlowDecisionFor(netmon.Conn{Dst: netip.MustParseAddr("149.154.167.51")}, svc.awgFlowTraceRules())
	if decision.TunnelID != "two" || decision.TunnelIface != "awg1" {
		t.Fatalf("trace ignored the rule's explicit reserve priority: %+v", decision)
	}
}
