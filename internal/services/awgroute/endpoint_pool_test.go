package awgroute

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"nfqws2strategy/internal/services/awg"
)

type endpointHintTestDriver struct {
	*failoverTestDriver
	hints map[string]bool
	scans int
}

func (d *endpointHintTestDriver) endpointHints(*awg.Manager, []string) map[string]bool {
	d.scans++
	return d.hints
}

func endpointPoolTestService(t *testing.T) (*Service, *endpointHintTestDriver, *awg.Manager, *awg.Manager) {
	t.Helper()
	svc, base, entries := failoverTestService(t)
	primary, reserve := entries[0].Manager, entries[1].Manager
	setTestFailover(t, primary, false, "two")
	setTestFailover(t, reserve, true)
	if err := primary.SetEndpointBackups([]string{"192.0.2.2", "192.0.2.3"}); err != nil {
		t.Fatal(err)
	}
	driver := &endpointHintTestDriver{failoverTestDriver: base}
	svc.clients.driver = driver
	return svc, driver, primary, reserve
}

func TestEndpointPoolExhaustsEveryIPBeforeOtherProfile(t *testing.T) {
	svc, driver, primary, reserve := endpointPoolTestService(t)
	var tried []string
	driver.onRecover = func(am *awg.Manager) error {
		if am == primary {
			tried = append(tried, am.RuntimeConfig().Endpoint)
		}
		return errors.New("offline")
	}
	for attempt := 1; attempt <= 3; attempt++ {
		svc.checkClients()
		if svc.clientShouldRun(reserve) || driver.attempts[reserve] != 0 || svc.endpointPoolAllowsFallback(primary) {
			t.Fatalf("profile reserve activated before IP%d failed", attempt)
		}
	}
	want := []string{"192.0.2.1:2408", "192.0.2.2:2408", "192.0.2.3:2408"}
	if !reflect.DeepEqual(tried, want) {
		t.Fatalf("attempted %v, want %v", tried, want)
	}
	svc.checkClients()
	if !svc.endpointPoolAllowsFallback(primary) || !svc.clientShouldRun(reserve) || driver.attempts[reserve] == 0 {
		t.Fatal("exhausted IP pool did not activate profile fallback")
	}
	if primary.Config().Endpoint != "192.0.2.1:2408" {
		t.Fatal("rotation persisted over primary endpoint")
	}
}

func TestEndpointPoolPingHintsReorderWithoutExcludingUnresponsiveIPs(t *testing.T) {
	svc, driver, primary, _ := endpointPoolTestService(t)
	driver.hints = map[string]bool{"192.0.2.3:2408": true}
	svc.prepareClientEndpointAttempt(primary, true) // initial primary is always first
	if primary.RuntimeConfig().Endpoint != "192.0.2.1:2408" || driver.scans != 0 {
		t.Fatal("ping bypassed initial primary")
	}
	svc.prepareClientEndpointAttempt(primary, true)
	if primary.RuntimeConfig().Endpoint != "192.0.2.3:2408" || svc.endpointPoolAllowsFallback(primary) {
		t.Fatal("reachable hint not preferred or mistaken for authenticated success")
	}
	svc.prepareClientEndpointAttempt(primary, true)
	if primary.RuntimeConfig().Endpoint != "192.0.2.2:2408" {
		t.Fatal("ICMP-negative backup was excluded")
	}
	if svc.endpointPoolAllowsFallback(primary) {
		t.Fatal("ping negative counted as completed AWG failure")
	}
	svc.prepareClientEndpointAttempt(primary, true)
	if !svc.endpointPoolAllowsFallback(primary) {
		t.Fatal("all actual failures did not exhaust pool")
	}
}

func TestEndpointHealthyBackupStaysStickyAndRescansPrimaryOnlyOnFailure(t *testing.T) {
	svc, driver, primary, _ := endpointPoolTestService(t)
	svc.prepareClientEndpointAttempt(primary, true)
	svc.prepareClientEndpointAttempt(primary, true)
	driver.states[primary] = ClientStatus{Running: true, Connected: true, Endpoint: "192.0.2.2:2408", LastHandshake: time.Now().Unix(), engineID: "42/1"}
	svc.checkClients()
	scans := driver.scans
	for i := 0; i < 3; i++ {
		svc.checkClients()
	}
	if primary.RuntimeConfig().Endpoint != "192.0.2.2:2408" || driver.scans != scans || svc.endpointPoolAllowsFallback(primary) {
		t.Fatal("healthy backup was probed away or kept failed cycle")
	}
	driver.hints = map[string]bool{"192.0.2.1:2408": true}
	svc.prepareClientEndpointAttempt(primary, true)
	if primary.RuntimeConfig().Endpoint != "192.0.2.1:2408" || driver.scans != scans+1 {
		t.Fatal("next real failure did not reconsider primary")
	}
}

func TestEndpointStatusUnavailableAndCancellationDoNotConsumePool(t *testing.T) {
	svc, driver, primary, _ := endpointPoolTestService(t)
	primary.SelectClientEndpoint(1)
	driver.states[primary] = ClientStatus{Running: true, Connected: true, Endpoint: "192.0.2.2:2408", LastHandshake: time.Now().Unix(), engineID: "42/1"}
	svc.checkClients()
	driver.states[primary] = ClientStatus{Running: true, StatusUnavailable: true, engineID: "42/1"}
	svc.checkClients()
	if driver.attempts[primary] != 0 || driver.scans != 0 || primary.RuntimeConfig().Endpoint != "192.0.2.2:2408" {
		t.Fatal("status read failure advanced pool without handshake verification")
	}
	svc.clients.mu.Lock()
	r := svc.clients.states[primary]
	r.ProbeUntil = time.Now().Add(-time.Second)
	svc.clients.states[primary] = r
	svc.clients.mu.Unlock()
	svc.checkClients()
	if driver.scans != 0 || primary.RuntimeConfig().Endpoint != "192.0.2.2:2408" {
		t.Fatal("status-socket repair rotated a network endpoint")
	}
	before := primary.RuntimeConfig().Endpoint
	rollback := svc.prepareClientEndpointAttempt(primary, true)
	rollback()
	if primary.RuntimeConfig().Endpoint != before {
		t.Fatal("cancel rollback consumed candidate")
	}
}

func TestEndpointAttemptCancellationRollsBackActualSupervisorSelection(t *testing.T) {
	svc, driver, primary, _ := endpointPoolTestService(t)
	svc.prepareClientEndpointAttempt(primary, true)
	svc.clients.states = map[*awg.Manager]clientRecovery{}
	svc.clients.states[primary] = clientRecovery{Seen: true, Attempts: 1, Recovering: true, FailureSince: time.Now()}
	driver.onRecover = func(*awg.Manager) error { svc.cancelClientOp(); return context.Canceled }
	_, unlock := svc.lockClientOps(false)
	svc.checkClient(svc.serverSnapshot()[0])
	unlock()
	if primary.RuntimeConfig().Endpoint != "192.0.2.1:2408" || svc.endpointPoolAllowsFallback(primary) {
		t.Fatal("cancelled supervisor attempt consumed an IP")
	}
}

func TestEndpointRestartAdoptionRetriesAfterUnavailableStatus(t *testing.T) {
	svc, driver, primary, _ := endpointPoolTestService(t)
	driver.states[primary] = ClientStatus{Running: true, StatusUnavailable: true, engineID: "42/1"}
	svc.checkClients()
	driver.states[primary] = ClientStatus{Running: true, Connected: true, Endpoint: "192.0.2.3:2408", LastHandshake: time.Now().Unix(), engineID: "42/1"}
	svc.checkClients()
	if primary.RuntimeConfig().Endpoint != "192.0.2.3:2408" || driver.attempts[primary] != 0 {
		t.Fatal("initial UAPI timeout prevented later adoption of working backup")
	}
}

func TestEndpointPanelRestartAdoptsKnownBackupWithoutPoisoningPrimaryDNS(t *testing.T) {
	svc, driver, primary, _ := endpointPoolTestService(t)
	cfg := primary.Config()
	cfg.Endpoint = "vpn.example:2408"
	if err := primary.SetConfig(&cfg); err != nil {
		t.Fatal(err)
	}
	svc.rememberPolicyDNS("vpn.example", []string{"192.0.2.1"})
	status := ClientStatus{Running: true, Connected: true, Endpoint: "192.0.2.2:2408", LastHandshake: time.Now().Unix(), engineID: "42/1"}
	svc.rememberClientEndpointStatus(primary, &status)
	if svc.cachedPolicyHostIP("vpn.example") != "192.0.2.1" {
		t.Fatal("observing backup rewrote primary hostname cache")
	}
	driver.states[primary] = status
	svc.checkClients()
	if primary.RuntimeConfig().Endpoint != "192.0.2.2:2408" || driver.attempts[primary] != 0 {
		t.Fatal("panel restart replaced healthy existing backup")
	}
	svc.endpointStatus(primary, &status)
	if status.EndpointPrimary != "vpn.example:2408" || status.EndpointCandidate != "192.0.2.2:2408" || status.EndpointIndex != 1 || status.EndpointCount != 3 {
		t.Fatalf("runtime endpoint status incomplete: primary=%q active=%q index=%d count=%d", status.EndpointPrimary, status.EndpointCandidate, status.EndpointIndex, status.EndpointCount)
	}
}

func TestEndpointColdPrimaryDNSCacheLearnsOnlyAuthenticatedPrimaryHint(t *testing.T) {
	svc, _, primary, _ := endpointPoolTestService(t)
	cfg := primary.Config()
	cfg.Endpoint = "vpn.example:2408"
	if err := primary.SetConfig(&cfg); err != nil {
		t.Fatal(err)
	}
	status := ClientStatus{Running: true, Endpoint: "192.0.2.10:2408"}
	svc.rememberClientEndpointStatus(primary, &status)
	if svc.cachedPolicyHostIP("vpn.example") != "" {
		t.Fatal("unauthenticated unknown endpoint poisoned primary DNS")
	}
	status.LastHandshake = time.Now().Unix()
	status.Connected = true
	svc.rememberClientEndpointStatus(primary, &status)
	if svc.cachedPolicyHostIP("vpn.example") != "192.0.2.10" {
		t.Fatal("cold primary WAN escape was not learned from authenticated live peer")
	}
	found := false
	for _, endpoint := range svc.ClientEndpointCandidates() {
		found = found || endpoint == "192.0.2.10:2408"
	}
	if !found {
		t.Fatal("NFQUEUE provider omitted learned primary address")
	}
}

func TestEndpointColdIdlePrimaryGetsWANEscapeBeforeProbeWithoutHealthOrRotation(t *testing.T) {
	svc, driver, primary, _ := endpointPoolTestService(t)
	cfg := primary.Config()
	cfg.Endpoint = "vpn.example:2408"
	if err := primary.SetConfig(&cfg); err != nil {
		t.Fatal(err)
	}
	status := ClientStatus{Running: true, Endpoint: "192.0.2.10:2408", LastHandshake: time.Now().Add(-13 * time.Hour).Unix(), RxBytes: 100, engineID: "42/1"}
	svc.rememberClientEndpointStatus(primary, &status)
	if svc.cachedPolicyEndpointIP("vpn.example") != "192.0.2.10" || svc.cachedPolicyHostIP("vpn.example") != "" {
		t.Fatal("idle live peer needs a WAN escape, not an ordinary primary DNS answer")
	}
	found := false
	for _, endpoint := range svc.ClientEndpointCandidates() {
		found = found || endpoint == "192.0.2.10:2408"
	}
	if !found {
		t.Fatal("idle primary transport is missing from NFQUEUE exemptions")
	}
	driver.states[primary] = status
	svc.checkClient(svc.servers["one"])
	if driver.probes != 1 || driver.restores != 1 || driver.attempts[primary] != 0 || primary.RuntimeConfig().Endpoint != "vpn.example:2408" {
		t.Fatal("idle primary was rotated/restarted before its normal keepalive verification")
	}
	svc.clients.mu.Lock()
	recovery := svc.clients.states[primary]
	svc.clients.mu.Unlock()
	if !recovery.Recovering || !recovery.HealthyAt.IsZero() || svc.endpointPoolAllowsFallback(primary) || status.Connected {
		t.Fatal("transport escape invented authenticated health or exhausted the IP pool")
	}
}

func TestEndpointPoolRestartKeepsAuthenticatedLogicalFallback(t *testing.T) {
	svc, driver, primary, reserve := endpointPoolTestService(t)
	driver.states[primary] = ClientStatus{Running: true}
	driver.states[reserve] = ClientStatus{Running: true, Connected: true, LastHandshake: time.Now().Unix()}
	svc.checkClients()
	if svc.endpointPoolAllowsFallback(primary) {
		t.Fatal("restart incorrectly marked endpoint pool exhausted")
	}
	if svc.FallbackIface("one") != awgClientIfaceName(reserve.RuntimeConfig()) || !svc.TunnelUpForServer("one") {
		t.Fatal("logical DNS/proxy fallback dropped working reserve during primary pool verification")
	}
	status := svc.connectionFailoverStatus(svc.serverSnapshot()[0], map[string]*ClientStatus{"two": func() *ClientStatus { s := driver.states[reserve]; return &s }()})
	if status.ActiveTunnelID != "two" {
		t.Fatal("status no longer names working physical reserve")
	}
	selected := selectFallbackTunnelID("one", svc.endpointFallbackTunnelIDs("one", []string{"two"}), func(string) bool { return true }, func(id string) bool { return id == "two" })
	if selected != "two" {
		t.Fatal("rule-level policy dropped an authenticated existing reserve")
	}
}

func TestEndpointPoolSaveFailurePreservesRuntimeAndPolicy(t *testing.T) {
	svc, _, primary, _ := endpointPoolTestService(t)
	primary.SelectClientEndpoint(1)
	before := primary.Config().Client.EndpointBackups
	if err := os.Mkdir(svc.store.Path(awgConfigFile), 0700); err != nil {
		t.Fatal(err)
	}
	if err := svc.AWG2SetEndpointBackups("one", []string{"192.0.2.99"}); err == nil {
		t.Fatal("failed persistence reported success")
	}
	if !reflect.DeepEqual(primary.Config().Client.EndpointBackups, before) || primary.RuntimeConfig().Endpoint != "192.0.2.2:2408" {
		t.Fatal("failed save published policy or lost active backup")
	}
}

func TestEndpointPoolSaveAfterRenameFailureRestoresDiskIntent(t *testing.T) {
	svc, _, primary, _ := endpointPoolTestService(t)
	primary.SelectClientEndpoint(1)
	before := primary.Config().Client.EndpointBackups
	calls := 0
	save := func(state awgPersisted) error {
		calls++
		if err := svc.store.SaveSecret(awgConfigFile, &state); err != nil {
			return err
		}
		if calls == 1 {
			return errors.New("mock chmod failure after rename")
		}
		return nil
	}
	_, unlock := svc.lockClientOps(false)
	err := svc.setEndpointBackupsWithOps("one", []string{"192.0.2.99"}, save)
	unlock()
	if err == nil || calls != 2 {
		t.Fatal("post-rename failure did not restore previous disk snapshot")
	}
	if !reflect.DeepEqual(svc.loadAWGState().Servers[0].Config.Client.EndpointBackups, before) || !reflect.DeepEqual(primary.Config().Client.EndpointBackups, before) || primary.RuntimeConfig().Endpoint != "192.0.2.2:2408" {
		t.Fatal("failed save changed disk policy, memory policy or active endpoint")
	}
}

func TestEndpointPoolUncertainDiskAndCommittedRuntimeErrorsAreExplicit(t *testing.T) {
	t.Run("rollback failed", func(t *testing.T) {
		svc, _, primary, _ := endpointPoolTestService(t)
		primary.SelectClientEndpoint(1)
		before := primary.Config().Client.EndpointBackups
		calls := 0
		save := func(state awgPersisted) error {
			calls++
			if calls == 1 {
				if err := svc.store.SaveSecret(awgConfigFile, &state); err != nil {
					t.Fatal(err)
				}
			}
			return errors.New("mock persistent storage failure")
		}
		_, unlock := svc.lockClientOps(false)
		err := svc.setEndpointBackupsWithOps("one", []string{"192.0.2.99"}, save)
		unlock()
		var uncertain *EndpointBackupsPersistenceUncertainError
		if !errors.As(err, &uncertain) || calls != 2 || !reflect.DeepEqual(primary.Config().Client.EndpointBackups, before) || primary.RuntimeConfig().Endpoint != "192.0.2.2:2408" {
			t.Fatal("uncertain disk error was hidden or changed published state")
		}
	})
	t.Run("saved but recovery failed", func(t *testing.T) {
		svc, driver, primary, _ := endpointPoolTestService(t)
		primary.SelectClientEndpoint(1)
		driver.states[primary] = ClientStatus{Running: true, Endpoint: "192.0.2.2:2408"}
		err := svc.AWG2SetEndpointBackups("one", []string{"192.0.2.99"})
		var committed *EndpointBackupsCommittedError
		if !errors.As(err, &committed) || !reflect.DeepEqual(primary.Config().Client.EndpointBackups, []string{"192.0.2.99:2408"}) || !reflect.DeepEqual(svc.loadAWGState().Servers[0].Config.Client.EndpointBackups, primary.Config().Client.EndpointBackups) {
			t.Fatal("committed policy was reported as an uncommitted save failure")
		}
	})
}

func TestEndpointPoolSetterPersistsWithoutRedeployAndHookHasNoStateLocks(t *testing.T) {
	svc, _, primary, _ := endpointPoolTestService(t)
	primary.SelectClientEndpoint(1)
	if err := svc.AWG2SetEndpointBackups("one", []string{"192.0.2.2", "2001:db8::2"}); err != nil {
		t.Fatal(err)
	}
	loaded := svc.loadAWGState()
	if !reflect.DeepEqual(loaded.Servers[0].Config.Client.EndpointBackups, []string{"192.0.2.2:2408", "[2001:db8::2]:2408"}) || primary.PendingApply() {
		t.Fatal("local endpoint edit was lost or required remote deployment")
	}
	if primary.RuntimeConfig().Endpoint != "192.0.2.2:2408" {
		t.Fatal("adding another reserve displaced healthy selection")
	}
	svc.SetClientEndpointHook(func() error {
		_ = svc.ClientEndpointCandidates()
		svc.clients.mu.Lock()
		svc.clients.mu.Unlock()
		return errors.New("mock bypass failure")
	})
	if err := svc.refreshClientEndpointBypass(); err == nil {
		t.Fatal("transport bypass error hidden")
	}
}

func TestEndpointHealthDoesNotCarryAcrossDaemonOrEndpointGeneration(t *testing.T) {
	now := time.Now()
	for _, next := range []ClientStatus{
		{Running: true, Endpoint: "192.0.2.1:2408", LastHandshake: now.Add(-time.Hour).Unix(), RxBytes: 200, engineID: "43/1"},
		{Running: true, Endpoint: "192.0.2.2:2408", LastHandshake: now.Add(-time.Hour).Unix(), RxBytes: 200, engineID: "42/1"},
	} {
		before := ClientStatus{Running: true, Endpoint: "192.0.2.1:2408", LastHandshake: now.Add(-time.Hour).Unix(), RxBytes: 100, engineID: "42/1"}
		r := clientRecovery{Seen: true, RX: 100, Handshake: before.LastHandshake, HealthyAt: now, LastStatus: before}
		if r.observe(next, now.Add(time.Second)) != clientProbe || !r.Recovering {
			t.Fatal("old authenticated progress renewed health for another generation")
		}
	}
}
