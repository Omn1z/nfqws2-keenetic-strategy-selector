package awgroute

import (
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/store"
)

type failoverTestDriver struct {
	*fakeClientDriver
	downCalls map[*awg.Manager]int
}

func (d *failoverTestDriver) down(am *awg.Manager) error {
	d.downCalls[am]++
	d.states[am] = ClientStatus{}
	return nil
}

func failoverTestService(t *testing.T) (*Service, *failoverTestDriver, []*managedServer) {
	t.Helper()
	svc, base, entries := testSupervisedService(t)
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc.store = st
	for i, entry := range entries {
		cfg := entry.Manager.Config()
		cfg.ClientIface = []string{"awg0", "awg1", "awg2", "awg3"}[i]
		if err := entry.Manager.SetConfig(&cfg); err != nil {
			t.Fatal(err)
		}
	}
	driver := &failoverTestDriver{fakeClientDriver: base, downCalls: map[*awg.Manager]int{}}
	svc.clients.driver = driver
	return svc, driver, entries
}

func setTestFailover(t *testing.T, am *awg.Manager, standby bool, backups ...string) {
	t.Helper()
	cfg := am.Config()
	cfg.Client.Standby, cfg.Client.FallbackTunnelIDs = standby, backups
	if err := am.SetConfig(&cfg); err != nil {
		t.Fatal(err)
	}
}

func TestConnectionColdStandbyStartsAfterSecondFailureAndReturnsOffline(t *testing.T) {
	svc, driver, entries := failoverTestService(t)
	primary, reserve := entries[0].Manager, entries[1].Manager
	setTestFailover(t, primary, false, "two")
	setTestFailover(t, reserve, true)
	svc.checkClients()
	if driver.attempts[primary] != 1 || driver.attempts[reserve] != 0 || svc.clientShouldRun(reserve) {
		t.Fatal("cold reserve started before first retry failed")
	}
	svc.clients.mu.Lock()
	r := svc.clients.states[primary]
	r.RetryAt = time.Time{}
	svc.clients.states[primary] = r
	svc.clients.mu.Unlock()
	svc.checkClients()
	if driver.attempts[primary] != 2 || driver.attempts[reserve] != 1 || !svc.clientShouldRun(reserve) {
		t.Fatal("second failure did not activate reserve")
	}
	driver.states[reserve] = ClientStatus{Running: true, Connected: true, LastHandshake: time.Now().Unix()}
	if got := svc.FallbackIface("one"); got != awgClientIfaceName(reserve.RuntimeConfig()) || !svc.TunnelUpForServer("one") {
		t.Fatal("logical primary did not resolve through authenticated reserve")
	}
	primary.SetClientEnabled(false)
	if svc.TunnelUpForServer("one") || svc.FallbackIface("one") != "" {
		t.Fatal("disabled primary retained its logical route through reserve")
	}
	primary.SetClientEnabled(true)
	driver.states[primary] = ClientStatus{Running: true, Connected: true, LastHandshake: time.Now().Unix()}
	svc.checkClients()
	if svc.clientShouldRun(reserve) || driver.downCalls[reserve] != 1 {
		t.Fatal("recovered primary left reserve online")
	}
	if svc.activeServerID() != "one" || !reserve.ClientEnabled() || !reserve.Config().Client.Standby || !reflect.DeepEqual(primary.Config().Client.FallbackTunnelIDs, []string{"two"}) {
		t.Fatal("failover changed selection or persisted client intent")
	}
}

func TestSharedColdReserveWaitsForEveryPrimary(t *testing.T) {
	svc, driver, entries := failoverTestService(t)
	first, second, reserve := entries[0].Manager, entries[1].Manager, entries[2].Manager
	reserve.SetEnabled(true)
	reserve.SetClientEnabled(true)
	setTestFailover(t, reserve, true)
	setTestFailover(t, first, false, "off")
	setTestFailover(t, second, false, "off")
	svc.clients.states = map[*awg.Manager]clientRecovery{
		first: {Recovering: true, Attempts: 2}, second: {Recovering: true, Attempts: 2},
	}
	_, unlock := svc.lockClientOps(false)
	defer unlock()
	svc.reconcileStandbyClients()
	if !svc.clientShouldRun(reserve) {
		t.Fatal("shared reserve was not demanded")
	}
	driver.states[reserve] = ClientStatus{Running: true, Connected: true}
	driver.states[first] = ClientStatus{Running: true, Connected: true}
	svc.reconcileStandbyClients()
	if !svc.clientShouldRun(reserve) || driver.downCalls[reserve] != 0 {
		t.Fatal("first primary recovery stopped reserve still needed by second")
	}
	driver.states[second] = ClientStatus{Running: true, Connected: true}
	svc.reconcileStandbyClients()
	if svc.clientShouldRun(reserve) || driver.downCalls[reserve] != 1 {
		t.Fatal("reserve remained after all primaries recovered")
	}
}

func TestColdReservesFollowPriorityAndWakeOnHandshakeTimeout(t *testing.T) {
	svc, driver, entries := failoverTestService(t)
	primary, first, last := entries[0].Manager, entries[1].Manager, entries[2].Manager
	last.SetEnabled(true)
	last.SetClientEnabled(true)
	setTestFailover(t, primary, false, "two", "off")
	setTestFailover(t, first, true)
	setTestFailover(t, last, true)
	svc.clients.states = map[*awg.Manager]clientRecovery{primary: {Recovering: true, Attempts: 1, VerifyUntil: time.Now().Add(-time.Second)}}
	_, unlock := svc.lockClientOps(false)
	defer unlock()
	svc.reconcileStandbyClients()
	if !svc.clientShouldRun(first) || svc.clientShouldRun(last) {
		t.Fatal("first timeout did not start only highest-priority reserve")
	}
	svc.clients.states[first] = clientRecovery{Recovering: true, Attempts: 2}
	svc.reconcileStandbyClients()
	if !svc.clientShouldRun(last) {
		t.Fatal("exhausted first reserve blocked the remaining list")
	}
	driver.states[first] = ClientStatus{Running: true, Connected: true}
	driver.states[last] = ClientStatus{Running: true, Connected: true}
	svc.reconcileStandbyClients()
	if svc.clientShouldRun(last) || driver.downCalls[last] != 1 {
		t.Fatal("lower-priority reserve stayed online after first reserve recovered")
	}
}

func TestRuleSpecificColdReserveParticipatesInDemand(t *testing.T) {
	svc, _, entries := failoverTestService(t)
	primary, reserve := entries[0].Manager, entries[1].Manager
	setTestFailover(t, reserve, true)
	primary.SetRoutingState(awg.RoutingConfig{Mode: "zones", Active: true, Zones: []awg.Zone{{TunnelID: "one", FallbackTunnelIDs: []string{"two"}, Enabled: true, Route: "tunnel"}}}, true)
	svc.clients.states = map[*awg.Manager]clientRecovery{primary: {Recovering: true, Attempts: 2}}
	_, unlock := svc.lockClientOps(false)
	defer unlock()
	svc.reconcileStandbyClients()
	if !svc.clientShouldRun(reserve) {
		t.Fatal("rule-specific backup was ignored by cold standby supervisor")
	}
}

func TestSaveConnectionFailoverRejectsCyclesAndPersistsLocalPolicy(t *testing.T) {
	svc, _, entries := failoverTestService(t)
	_, unlock := svc.lockClientOps(false)
	defer unlock()
	apply := func() error { return nil }
	if err := svc.setConnectionFailoverWithOps("one", FailoverConfig{FallbackTunnelIDs: []string{" two ", "two"}}, apply); err != nil {
		t.Fatal(err)
	}
	for _, in := range []FailoverConfig{{FallbackTunnelIDs: []string{"missing"}}, {FallbackTunnelIDs: []string{"one"}}} {
		if err := svc.setConnectionFailoverWithOps("one", in, apply); err == nil {
			t.Fatal("invalid fallback reference accepted")
		}
	}
	if err := svc.setConnectionFailoverWithOps("two", FailoverConfig{FallbackTunnelIDs: []string{"one"}}, apply); err == nil {
		t.Fatal("fallback cycle accepted")
	}
	if err := svc.setConnectionFailoverWithOps("two", FailoverConfig{Standby: true}, apply); err != nil {
		t.Fatal(err)
	}
	loaded := svc.loadAWGState()
	if !reflect.DeepEqual(loaded.Servers[0].Config.Client.FallbackTunnelIDs, []string{"two"}) || !loaded.Servers[1].Config.Client.Standby {
		t.Fatal("restart lost backup order or standby intent")
	}
	copy := entries[0].Manager.Config()
	copy.Client.FallbackTunnelIDs[0] = "changed"
	if entries[0].Manager.Config().Client.FallbackTunnelIDs[0] != "two" {
		t.Fatal("config clone exposed mutable backup list")
	}
}

func TestConnectionFailoverStorageErrorDoesNotPublishCandidate(t *testing.T) {
	svc, _, entries := failoverTestService(t)
	// A directory in place of the target config file makes atomic rename fail.
	if err := os.Mkdir(svc.store.Path(awgConfigFile), 0700); err != nil {
		t.Fatal(err)
	}
	_, unlock := svc.lockClientOps(false)
	defer unlock()
	if err := svc.setConnectionFailoverWithOps("one", FailoverConfig{FallbackTunnelIDs: []string{"two"}}, func() error { return nil }); err == nil {
		t.Fatal("failed storage was reported as saved")
	}
	if len(entries[0].Manager.Config().Client.FallbackTunnelIDs) != 0 {
		t.Fatal("storage failure published uncommitted policy")
	}
}

func TestConnectionFailoverApplyErrorKeepsSavedIntent(t *testing.T) {
	svc, _, entries := failoverTestService(t)
	_, unlock := svc.lockClientOps(false)
	defer unlock()
	want := errors.New("kernel busy")
	if err := svc.setConnectionFailoverWithOps("one", FailoverConfig{FallbackTunnelIDs: []string{"two"}}, func() error { return want }); !errors.Is(err, want) {
		t.Fatalf("policy apply error = %v", err)
	}
	if len(entries[0].Manager.Config().Client.FallbackTunnelIDs) != 1 {
		t.Fatal("routing apply failure erased saved failover settings")
	}
}

func TestFullModeFailoverCompilesCatchAllWithoutChangingSavedRules(t *testing.T) {
	svc, _, entries := failoverTestService(t)
	primary := entries[0].Manager
	setTestFailover(t, primary, false, "two")
	primary.SetRoutingState(awg.RoutingConfig{Mode: "full", Active: true}, true)
	rules := svc.awgPolicyRoutingRules()
	if len(rules) != 1 || rules[0].TunnelID != "one" || !rules[0].IsCatchAll() || len(svc.awgRoutingRules()) != 0 {
		t.Fatal("legacy full mode did not inherit connection-level failover")
	}
}

func TestDormantStandbyLeftoverInterfaceIsNotAnActiveFallback(t *testing.T) {
	svc, driver, entries := failoverTestService(t)
	primary, reserve := entries[0].Manager, entries[1].Manager
	setTestFailover(t, primary, false, "two")
	setTestFailover(t, reserve, true)
	status := &ClientStatus{Running: true, Connected: true, LastHandshake: time.Now().Unix()}
	driver.states[reserve] = *status
	if svc.TunnelUpForServer("one") || svc.FallbackIface("one") != "" || svc.connectionFailoverStatus(entries[0], map[string]*ClientStatus{"two": status}).ActiveTunnelID != "" {
		t.Fatal("leftover or temporary-test standby interface was advertised as active")
	}
	svc.clients.standbyActive = map[*awg.Manager]bool{reserve: true}
	if !svc.TunnelUpForServer("one") || svc.connectionFailoverStatus(entries[0], map[string]*ClientStatus{"two": status}).ActiveTunnelID != "two" {
		t.Fatal("demanded authenticated reserve was not advertised")
	}
}

func TestConnectionReserveInheritsRoutingEligibilityWithoutCopiedRules(t *testing.T) {
	svc, _, entries := failoverTestService(t)
	primary, reserve := entries[0].Manager, entries[1].Manager
	setTestFailover(t, primary, false, "two")
	setTestFailover(t, reserve, true)
	primary.SetRoutingState(awg.RoutingConfig{Mode: "zones", Active: true, Zones: []awg.Zone{{TunnelID: "one", Route: "tunnel", Domains: []string{"example.org"}, Enabled: true}}}, true)
	reserve.SetRoutingState(awg.RoutingConfig{Mode: "zones"}, false)
	if !svc.connectionRoutingEnabled(entries[1]) || len(reserve.Config().Routing.Zones) != 0 || reserve.Config().Routing.Active {
		t.Fatal("reserve required copied zones or its own committed routing")
	}
	primary.SetClientEnabled(false)
	if svc.connectionRoutingEnabled(entries[1]) {
		t.Fatal("disabled primary continued to lend routing eligibility")
	}
}

func TestConnectionRoutingTraversesDisabledIntermediateReserve(t *testing.T) {
	svc, _, entries := failoverTestService(t)
	primary, middle, reserve := entries[0].Manager, entries[1].Manager, entries[2].Manager
	setTestFailover(t, primary, false, "two")
	setTestFailover(t, middle, true, "off")
	setTestFailover(t, reserve, true)
	primary.SetRoutingState(awg.RoutingConfig{Mode: "zones", Active: true}, true)
	middle.SetEnabled(false)
	middle.SetClientEnabled(false)
	reserve.SetEnabled(true)
	reserve.SetClientEnabled(true)
	reserve.SetRoutingState(awg.RoutingConfig{Mode: "zones"}, false)
	eligible := svc.connectionRoutingEligibility()
	if eligible["two"] || !eligible["off"] || !reflect.DeepEqual(svc.connectionFallbackTunnelIDs("one", nil), []string{"two", "off"}) {
		t.Fatal("routing graph disagrees with flattened fallback candidates")
	}
	primary.SetEnabled(false)
	if svc.connectionRoutingEligibility()["off"] {
		t.Fatal("disabled root lent routing eligibility to its descendants")
	}
}
