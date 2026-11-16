package awgroute

import (
	"testing"
	"time"

	"nfqws2strategy/internal/services/awg"
)

func TestUnavailableLiveClientGetsBoundedVerificationBeforeReconnect(t *testing.T) {
	now := time.Unix(100000, 0)
	settings := DefaultRecoverySettings()
	healthy := ClientStatus{Running: true, Connected: true, LastHandshake: now.Unix(), RxBytes: 100, engineID: "7/123"}
	var r clientRecovery
	r.observeWithSettings(healthy, now, settings)
	failed := ClientStatus{Running: true, IfacePresent: true, StatusUnavailable: true, engineID: healthy.engineID}
	firstFailure := now.Add(clientWatchInterval)
	if got := r.observeWithSettings(failed, firstFailure, settings); got != clientWait {
		t.Fatalf("transient read failure restarted a live daemon: %v", got)
	}
	deadline := firstFailure.Add(settings.handshakeTimeout())
	for at := firstFailure.Add(time.Second); at.Before(deadline); at = at.Add(time.Second) {
		if r.observeWithSettings(failed, at, settings) != clientWait {
			t.Fatal("live daemon restarted within the status verification window")
		}
	}
	if !r.ProbeUntil.Equal(deadline) {
		t.Fatal("failed status polls extended verification")
	}
	if r.observeWithSettings(failed, deadline, settings) != clientReconnect {
		t.Fatal("permanently stuck status socket was never recovered")
	}
	if r.LastStatusAt != now {
		t.Fatal("failed reads refreshed the last successful status")
	}
}

func TestUnavailableStatusPreservesSameDaemonHealthOnlyBriefly(t *testing.T) {
	now := time.Unix(100000, 0)
	settings := DefaultRecoverySettings()
	old := ClientStatus{Running: true, Connected: true, LastHandshake: now.Unix(), RxBytes: 100, TxBytes: 50, engineID: "7/123"}
	var r clientRecovery
	r.observeWithSettings(old, now, settings)
	failed := ClientStatus{Running: true, StatusUnavailable: true, engineID: old.engineID, Error: "status read timeout"}
	r.observeWithSettings(failed, now.Add(time.Second), settings)
	current := failed
	r.restoreUnavailableStatus(&current, now.Add(2*time.Second), settings)
	if !current.Connected || !clientAuthenticated(&current, now.Add(2*time.Second)) || current.RxBytes != old.RxBytes || current.Error == "" {
		t.Fatal("temporary read failure hid live reserve health or error")
	}
	for _, changed := range []ClientStatus{
		{Running: true, StatusUnavailable: true, engineID: "7/124"}, // reused PID
		{Running: true, StatusUnavailable: true, engineID: "8/123"}, // replaced daemon
		{Running: true, StatusUnavailable: true},                    // no confirmed daemon
		{StatusUnavailable: true, engineID: old.engineID},           // daemon gone
	} {
		r.restoreUnavailableStatus(&changed, now.Add(2*time.Second), settings)
		if changed.Connected || changed.LastHandshake != 0 || changed.RxBytes != 0 {
			t.Fatal("unavailable status reused health from a different process")
		}
	}
	current = failed
	r.restoreUnavailableStatus(&current, now.Add(settings.handshakeTimeout()), settings)
	if current.Connected {
		t.Fatal("cached status survived its bounded verification window")
	}
}

func TestUnavailableStatusRecoversWithoutRestartAndMissingDaemonDoesNotWait(t *testing.T) {
	now := time.Unix(100000, 0)
	healthy := ClientStatus{Running: true, LastHandshake: now.Unix(), RxBytes: 100, engineID: "7/123"}
	var r clientRecovery
	r.observe(healthy, now)
	r.observe(ClientStatus{Running: true, StatusUnavailable: true, engineID: healthy.engineID}, now.Add(time.Second))
	if r.observe(healthy, now.Add(2*time.Second)) != clientWait || r.Recovering || !r.UnavailableAt.IsZero() {
		t.Fatal("successful status read did not clear transient failure")
	}
	if r.observe(ClientStatus{}, now.Add(3*time.Second)) != clientReconnect {
		t.Fatal("confirmed missing daemon incorrectly received status-read grace")
	}
}

func TestStandbyReserveSurvivesItsTransientStatusReadFailure(t *testing.T) {
	svc, driver, servers := failoverTestService(t)
	primary, reserve := servers[0], servers[1]
	setTestFailover(t, primary.Manager, false, reserve.ID)
	setTestFailover(t, reserve.Manager, true)
	now := time.Now()
	healthy := ClientStatus{Running: true, Connected: true, LastHandshake: now.Unix(), RxBytes: 100, engineID: "7/123"}
	var r clientRecovery
	r.observe(healthy, now.Add(-time.Second))
	failed := ClientStatus{Running: true, StatusUnavailable: true, engineID: healthy.engineID}
	r.observe(failed, now)
	r.restoreUnavailableStatus(&failed, now, DefaultRecoverySettings())
	svc.clients.states = map[*awg.Manager]clientRecovery{
		primary.Manager: {Recovering: true, Attempts: 2}, reserve.Manager: r,
	}
	driver.states[primary.Manager] = ClientStatus{}
	driver.states[reserve.Manager] = failed
	svc.clients.standbyActive = map[*awg.Manager]bool{reserve.Manager: true}
	// The failed primary still needs this reserve. A temporary local status
	// timeout must not stop its daemon or activate the next cold reserve.
	svc.reconcileStandbyClients()
	if !svc.clients.standbyActive[reserve.Manager] || driver.downCalls[reserve.Manager] != 0 {
		t.Fatal("temporary status failure stopped the working reserve")
	}
}
