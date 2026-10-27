package awgroute

import (
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"nfqws2strategy/internal/services/awg"
)

func TestRecoveryPhasesFollowOutageTimeInsteadOfAttempts(t *testing.T) {
	settings := DefaultRecoverySettings()
	for _, test := range []struct{ elapsed, delay time.Duration }{
		{0, 0}, {time.Second * 59, 0}, {time.Minute, 5 * time.Second},
		{30 * time.Minute, 5 * time.Second}, {time.Hour - time.Nanosecond, 5 * time.Second},
		{time.Hour, 90 * time.Second}, {24 * time.Hour, 90 * time.Second},
	} {
		if got := settings.retryDelay(test.elapsed); got != test.delay {
			t.Fatalf("outage=%s: got %s, want %s", test.elapsed, got, test.delay)
		}
	}
	settings.SlowRetryAfterSeconds = 1800
	if got := settings.retryDelay(30 * time.Minute); got != 90*time.Second {
		t.Fatalf("configured half-hour boundary: %s", got)
	}
	start := time.Unix(100000, 0)
	var recovery clientRecovery
	for range 1000 {
		recovery.attemptedWithSettings(start, errors.New("WAN unavailable"), settings)
	}
	if !recovery.RetryAt.Equal(start) || !recovery.FailureSince.Equal(start) {
		t.Fatal("attempt count delayed retries during first minute")
	}
	recovery.attemptedWithSettings(start.Add(61*time.Second), errors.New("WAN unavailable"), settings)
	if want := start.Add(66 * time.Second); !recovery.RetryAt.Equal(want) {
		t.Fatalf("second phase: retry=%s want=%s", recovery.RetryAt, want)
	}
	recovery.attemptedWithSettings(start.Add(1800*time.Second), errors.New("WAN unavailable"), settings)
	if want := start.Add(1890 * time.Second); !recovery.RetryAt.Equal(want) {
		t.Fatalf("slow phase: retry=%s want=%s", recovery.RetryAt, want)
	}
}

func TestRecoveryPauseBeginsAfterHandshakeWindow(t *testing.T) {
	start := time.Unix(100000, 0)
	settings := DefaultRecoverySettings()
	recovery := clientRecovery{FailureSince: start}
	recovery.attemptedWithSettings(start.Add(45*time.Second), nil, settings)
	if want := start.Add(65 * time.Second); !recovery.VerifyUntil.Equal(want) {
		t.Fatalf("handshake verification=%s want=%s", recovery.VerifyUntil, want)
	}
	if want := start.Add(70 * time.Second); !recovery.RetryAt.Equal(want) {
		t.Fatalf("pause hidden under handshake grace: retry=%s want=%s", recovery.RetryAt, want)
	}
	st := ClientStatus{Running: true}
	if recovery.observeWithSettings(st, start.Add(64*time.Second), settings) != clientWait || recovery.observeWithSettings(st, start.Add(69*time.Second), settings) != clientWait {
		t.Fatal("restarted before handshake grace and subsequent pause finished")
	}
	if recovery.observeWithSettings(st, start.Add(70*time.Second), settings) != clientReconnect {
		t.Fatal("failed handshake did not retry after pause")
	}
	// A real answer immediately ends recovery even during a scheduled pause.
	st.LastHandshake = start.Add(66 * time.Second).Unix()
	if recovery.observeWithSettings(st, start.Add(66*time.Second), settings) != clientWait || recovery.Recovering || !recovery.FailureSince.IsZero() {
		t.Fatal("authenticated answer did not clear outage and pending wait")
	}
}

func TestRecoveryStatusSeparatesHandshakeVerificationFromRetryPause(t *testing.T) {
	start := time.Unix(100000, 0)
	settings := DefaultRecoverySettings()
	manager := &awg.Manager{}
	svc := &Service{}
	var recovery clientRecovery
	recovery.observeWithSettings(ClientStatus{Running: true}, start, settings)
	svc.clients.states = map[*awg.Manager]clientRecovery{manager: recovery}
	var status ClientStatus
	svc.clientRecoveryStatus(manager, &status)
	if want := start.Add(20 * time.Second).Unix(); status.VerificationUntil != want || status.RetryAt != want {
		t.Fatalf("initial handshake probe: verification=%d retry=%d want=%d", status.VerificationUntil, status.RetryAt, want)
	}

	recovery.attemptedWithSettings(start.Add(45*time.Second), nil, settings)
	svc.clients.states[manager] = recovery
	svc.clientRecoveryStatus(manager, &status)
	if status.VerificationUntil != start.Add(65*time.Second).Unix() || status.RetryAt != start.Add(70*time.Second).Unix() {
		t.Fatalf("handshake deadline must precede five-second pause: %+v", status)
	}

	recovery.observeWithSettings(ClientStatus{Running: true, LastHandshake: start.Add(66 * time.Second).Unix()}, start.Add(66*time.Second), settings)
	svc.clients.states[manager] = recovery
	// Reusing the status object must not retain an old verification deadline.
	svc.clientRecoveryStatus(manager, &status)
	if status.VerificationUntil != 0 || status.Recovering || status.RetryCount != 0 {
		t.Fatalf("authenticated progress retained verification: %+v", status)
	}
}

func TestRecoveryConfiguredProbeWindowAndRetimingPreserveOutage(t *testing.T) {
	start := time.Unix(100000, 0)
	settings := DefaultRecoverySettings()
	settings.HandshakeTimeoutSeconds = 35
	var recovery clientRecovery
	st := ClientStatus{Running: true}
	if recovery.observeWithSettings(st, start, settings) != clientProbe {
		t.Fatal("missing handshake did not trigger probe")
	}
	if !recovery.FailureSince.Equal(start) || !recovery.probeDeadline().Equal(start.Add(35*time.Second)) {
		t.Fatal("probe did not start outage/configured grace")
	}
	if recovery.observeWithSettings(st, start.Add(21*time.Second), settings) != clientWait {
		t.Fatal("configured probe fell back to old fixed grace")
	}
	settings.HandshakeTimeoutSeconds = 10
	recovery.updateSettings(settings)
	if !recovery.FailureSince.Equal(start) || !recovery.probeDeadline().Equal(start.Add(10*time.Second)) {
		t.Fatal("retiming restarted the probe or outage clock")
	}
	if recovery.observeWithSettings(st, start.Add(21*time.Second), settings) != clientReconnect {
		t.Fatal("shorter configured grace not applied to pending probe")
	}
	recovery.attemptedWithSettings(start.Add(70*time.Second), nil, settings)
	settings.RetryDelaySeconds = 8
	settings.HandshakeTimeoutSeconds = 15
	recovery.updateSettings(settings)
	if !recovery.FailureSince.Equal(start) || !recovery.RetryAt.Equal(start.Add(93*time.Second)) {
		t.Fatal("setting update lost original attempt/outage timestamps")
	}
	// Read-only health observations and profile settings do not forgive an outage.
	for i := 0; i < 10; i++ {
		recovery.observeWithSettings(st, start.Add(71*time.Second), settings)
	}
	if !recovery.FailureSince.Equal(start) {
		t.Fatal("polling reset outage clock")
	}
}

func TestRecoverySettingsValidationAndLegacyDefaults(t *testing.T) {
	want := DefaultRecoverySettings()
	if normalizeRecoverySettings(nil) != want || normalizeRecoverySettings(&RecoverySettings{}) != want {
		t.Fatal("legacy profile lost recovery defaults")
	}
	if err := want.Validate(); err != nil {
		t.Fatal(err)
	}
	changes := []func(*RecoverySettings){
		func(s *RecoverySettings) { s.FastRetrySeconds = 0 }, func(s *RecoverySettings) { s.FastRetrySeconds = 601 },
		func(s *RecoverySettings) { s.RetryDelaySeconds = 0 }, func(s *RecoverySettings) { s.RetryDelaySeconds = 31 },
		func(s *RecoverySettings) { s.SlowRetryAfterSeconds = 1799 }, func(s *RecoverySettings) { s.SlowRetryAfterSeconds = 3601 },
		func(s *RecoverySettings) { s.SlowRetryDelaySeconds = 89 }, func(s *RecoverySettings) { s.SlowRetryDelaySeconds = 901 },
		func(s *RecoverySettings) { s.HandshakeTimeoutSeconds = 4 }, func(s *RecoverySettings) { s.HandshakeTimeoutSeconds = 61 },
	}
	for i, change := range changes {
		candidate := want
		change(&candidate)
		if candidate.Validate() == nil {
			t.Fatalf("invalid settings %d accepted", i)
		}
	}
}

func TestRecoverySettingsPersistGloballyWithoutChangingProfilesOrRoutes(t *testing.T) {
	svc, driver, servers := failoverTestService(t)
	beforeProfiles := svc.snapshotAWGState().Servers
	beforeRules := svc.awgRoutingRules()
	beforeSelection := svc.activeServerID()
	start := time.Now().Add(-2 * time.Minute)
	r := clientRecovery{FailureSince: start}
	r.attemptedWithSettings(start.Add(90*time.Second), nil, DefaultRecoverySettings())
	svc.clients.states = map[*awg.Manager]clientRecovery{servers[0].Manager: r}
	want := DefaultRecoverySettings()
	want.FastRetrySeconds = 75
	want.RetryDelaySeconds = 7
	want.SlowRetryAfterSeconds = 1800
	want.SlowRetryDelaySeconds = 120
	want.HandshakeTimeoutSeconds = 15
	if err := svc.AWG2SetRecoverySettings(want); err != nil {
		t.Fatal(err)
	}
	if svc.currentRecoverySettings() != want || svc.AWG2StatusView().RecoverySettings != want {
		t.Fatal("global settings absent from status")
	}
	if !reflect.DeepEqual(beforeProfiles, svc.snapshotAWGState().Servers) || !reflect.DeepEqual(beforeRules, svc.awgRoutingRules()) || svc.activeServerID() != beforeSelection {
		t.Fatal("global recovery setting changed profile or routing state")
	}
	if len(driver.attempts) != 0 || len(driver.downCalls) != 0 {
		t.Fatal("saving settings restarted a tunnel")
	}
	updated := svc.clients.states[servers[0].Manager]
	if !updated.FailureSince.Equal(start) || !updated.RetryAt.Equal(start.Add(112*time.Second)) {
		t.Fatalf("pending retry not recalculated: %+v", updated)
	}
	if err := svc.AWG2SelectServer(servers[1].ID); err != nil {
		t.Fatal(err)
	}
	if svc.currentRecoverySettings() != want || !svc.clients.states[servers[0].Manager].FailureSince.Equal(start) {
		t.Fatal("selecting a profile reset global policy or outage clock")
	}
	reloaded := &Service{store: svc.store}
	reloaded.installAWGState(reloaded.loadAWGState())
	if reloaded.currentRecoverySettings() != want {
		t.Fatal("restart lost global recovery settings")
	}
}

func TestRecoverySettingsStorageOrCancellationErrorDoesNotPublish(t *testing.T) {
	svc, _, _ := failoverTestService(t)
	before := svc.currentRecoverySettings()
	if err := os.Mkdir(svc.store.Path(awgConfigFile), 0700); err != nil {
		t.Fatal(err)
	}
	want := before
	want.RetryDelaySeconds = 9
	if err := svc.AWG2SetRecoverySettings(want); err == nil {
		t.Fatal("failed storage reported success")
	}
	if svc.currentRecoverySettings() != before {
		t.Fatal("failed storage published uncommitted settings")
	}
	svc.clients.stopping.Store(true)
	if err := svc.AWG2SetRecoverySettings(want); err == nil {
		t.Fatal("stopped service accepted setting write")
	}
	if svc.currentRecoverySettings() != before {
		t.Fatal("cancelled operation changed settings")
	}
}
