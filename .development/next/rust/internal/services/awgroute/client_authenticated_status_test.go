package awgroute

import (
	"testing"
	"time"

	"nfqws2strategy/internal/services/awg"
)

func TestClientRecoveryStatusKeepsReceivingReserveEligibleForFailover(t *testing.T) {
	now := time.Now()
	am := new(awg.Manager)
	st := ClientStatus{Running: true, LastHandshake: now.Add(-time.Hour).Unix(), RxBytes: 1000}
	svc := &Service{}
	svc.clients.states = map[*awg.Manager]clientRecovery{
		am: {Seen: true, RX: 1000, Handshake: st.LastHandshake, HealthyAt: now.Add(-time.Second)},
	}
	svc.clientRecoveryStatus(am, &st)
	if !st.Connected || !clientAuthenticated(&st, now) {
		t.Fatal("status/failover rejected a reserve the supervisor verified by RX")
	}
	if st.Recovering {
		t.Fatal("healthy receiving reserve is marked as reconnecting")
	}
}

func TestClientAuthenticatedStatusUsesRXWithoutExtendingHealthOnPoll(t *testing.T) {
	now := time.Unix(100000, 0)
	st := ClientStatus{Running: true, LastHandshake: now.Add(-time.Hour).Unix(), RxBytes: 100}
	var recovery clientRecovery
	if recovery.observe(st, now) != clientProbe {
		t.Fatal("idle old handshake did not request verification")
	}
	st.RxBytes++
	verified := now.Add(time.Second)
	if recovery.observe(st, verified) != clientWait || recovery.Recovering {
		t.Fatal("authenticated receive did not recover the tunnel")
	}
	if !recovery.authenticatedStatus(&st, verified) {
		t.Fatal("live RX with an old handshake is reported offline")
	}
	if !recovery.authenticatedStatus(&st, verified.Add(clientStaleAfter-time.Second)) {
		t.Fatal("authenticated health expired early")
	}
	if recovery.authenticatedStatus(&st, verified.Add(clientStaleAfter)) {
		t.Fatal("status polling extended the authenticated health window")
	}
	if recovery.HealthyAt != verified {
		t.Fatal("status polling changed supervisor state")
	}
}

func TestClientAuthenticatedStatusDoesNotReusePriorDaemonHealth(t *testing.T) {
	now := time.Unix(100000, 0)
	recovery := clientRecovery{Seen: true, RX: 100, Handshake: now.Add(-time.Hour).Unix(), HealthyAt: now}
	healthy := ClientStatus{Running: true, RxBytes: 100, LastHandshake: recovery.Handshake}
	tests := []struct {
		name string
		edit func(*ClientStatus, *clientRecovery)
	}{
		{"down", func(s *ClientStatus, _ *clientRecovery) { s.Running = false }},
		{"new socket without handshake", func(s *ClientStatus, _ *clientRecovery) { s.LastHandshake = 0 }},
		{"counter reset", func(s *ClientStatus, _ *clientRecovery) { s.RxBytes = 10 }},
		{"different handshake generation", func(s *ClientStatus, _ *clientRecovery) { s.LastHandshake++ }},
		{"recovery underway", func(_ *ClientStatus, r *clientRecovery) { r.Recovering = true }},
		{"not observed", func(_ *ClientStatus, r *clientRecovery) { r.Seen = false }},
		{"future observation", func(_ *ClientStatus, r *clientRecovery) { r.HealthyAt = now.Add(time.Second) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, r := healthy, recovery
			tt.edit(&st, &r)
			if r.authenticatedStatus(&st, now) {
				t.Fatal("stale supervisor health authenticated a different or unverified daemon")
			}
		})
	}
}
