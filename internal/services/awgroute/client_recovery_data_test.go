package awgroute

import (
	"testing"
	"time"

	"nfqws2strategy/internal/services/awg"
)

func TestEstablishedClientConfirmsDataOutageBeforeHandshakeExpires(t *testing.T) {
	now := time.Unix(100000, 0)
	status := ClientStatus{Running: true, Connected: true, LastHandshake: now.Unix(),
		RxBytes: 100, TxBytes: 100, Endpoint: "192.0.2.1:51820", engineID: "123/456"}
	var recovery clientRecovery
	if action := recovery.observe(status, now); action != clientWait {
		t.Fatal("new healthy observation should not trigger probes")
	}
	for elapsed := clientWatchInterval; elapsed < 4*clientWatchInterval; elapsed += clientWatchInterval {
		status.TxBytes += 1024
		if action := recovery.observe(status, now.Add(elapsed)); action != clientWait {
			t.Fatalf("early action %v before sustained stalling at %v", action, elapsed)
		}
	}
	status.TxBytes += 1024
	probeAt := now.Add(4 * clientWatchInterval)
	if recovery.observe(status, probeAt) != clientProbeData {
		t.Fatal("established tunnel did not challenge the stalled data path")
	}
	finished := probeAt.Add(3 * time.Second)
	after := status
	after.TxBytes += 512
	if !recovery.confirmDataOutage(status, after, finished) || !clientNeedsFallback(recovery, finished) {
		t.Fatal("confirmed data timeouts did not make fallback immediately eligible")
	}
	am := awg.NewManager(awg.Default())
	svc := &Service{}
	svc.clients.states = map[*awg.Manager]clientRecovery{am: recovery}
	svc.clientRecoveryStatus(am, &after)
	if after.Connected || clientAuthenticated(&after, finished) {
		t.Fatal("an old handshake masked the confirmed outage")
	}
	if recovery.observe(after, finished.Add(clientWatchInterval)) != clientReconnect {
		t.Fatal("watchdog ignored confirmed data loss while handshake was recent")
	}
	after.RxBytes++
	if recovery.observe(after, finished.Add(2*clientWatchInterval)) != clientWait || recovery.pathUnavailable || recovery.Recovering {
		t.Fatal("authenticated data did not clear the outage")
	}
}

func TestClientDataOutageRequiresProbeTransmissionAndMatchingLivePeer(t *testing.T) {
	now := time.Unix(100000, 0)
	before := ClientStatus{Running: true, Connected: true, LastHandshake: now.Unix(),
		RxBytes: 100, TxBytes: 100, Endpoint: "192.0.2.1:51820", engineID: "123/456"}
	for _, candidate := range []func(*ClientStatus){
		func(after *ClientStatus) { after.TxBytes = before.TxBytes },
		func(after *ClientStatus) { after.RxBytes++ },
		func(after *ClientStatus) { after.LastHandshake++ },
		func(after *ClientStatus) { after.engineID = "999/456" },
		func(after *ClientStatus) { after.Endpoint = "192.0.2.2:51820" },
		func(after *ClientStatus) { after.StatusUnavailable = true },
	} {
		after := before
		after.TxBytes++
		candidate(&after)
		recovery := clientRecovery{TrafficStallAt: now.Add(-clientTrafficStall)}
		if recovery.confirmDataOutage(before, after, now) {
			t.Fatal("inconclusive probe or authenticated progress triggered failover")
		}
	}
}

func TestIsolatedKeepalivesDoNotTriggerFastDataProbe(t *testing.T) {
	now := time.Unix(100000, 0)
	status := ClientStatus{Running: true, Connected: true, LastHandshake: now.Unix(), RxBytes: 100}
	var recovery clientRecovery
	recovery.observe(status, now)
	for elapsed := clientWatchInterval; elapsed < 2*time.Minute; elapsed += clientWatchInterval {
		if elapsed%(8*clientWatchInterval) == 0 {
			status.TxBytes += 32
		}
		if recovery.observe(status, now.Add(elapsed)) != clientWait {
			t.Fatal("idle tunnel needed an active data probe after an isolated keepalive")
		}
	}
}
