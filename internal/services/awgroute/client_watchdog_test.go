package awgroute

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/store"
)

func TestClientRecoveryIdleNeedsProbeAndGrace(t *testing.T) {
	now := time.Unix(100000, 0)
	st := ClientStatus{Running: true, LastHandshake: now.Add(-13 * time.Hour).Unix(), RxBytes: 100}
	var r clientRecovery
	if got := r.observe(st, now); got != clientProbe {
		t.Fatalf("old idle handshake: got %v, want probe", got)
	}
	if got := r.observe(st, now.Add(clientProbeGrace-time.Second)); got != clientWait {
		t.Fatal("restarted during probe grace")
	}
	if got := r.observe(st, now.Add(clientProbeGrace)); got != clientReconnect {
		t.Fatal("failed active probe never recovered")
	}
	// A response proves the transport alive even when the old session has not
	// rekeyed yet. This avoids disconnecting legitimate idle peers.
	st.RxBytes++
	if got := r.observe(st, now.Add(clientProbeGrace+time.Second)); got != clientWait || r.Recovering {
		t.Fatal("RX progress did not clear suspicion")
	}
	if got := r.observe(st, now.Add(clientProbeGrace+time.Minute)); got != clientWait {
		t.Fatal("immediately probed a live peer again")
	}
}

func TestClientRecoveryNeverExhaustsAndOnlyHandshakeResets(t *testing.T) {
	now := time.Unix(100000, 0)
	var r clientRecovery
	for i := 1; i <= 40; i++ {
		if got := r.observe(ClientStatus{}, now); got != clientReconnect {
			t.Fatalf("attempt %d never reached: %v", i, got)
		}
		r.attempted(now, errors.New("WAN offline"))
		if got := r.observe(ClientStatus{}, r.RetryAt.Add(-time.Nanosecond)); got != clientWait {
			t.Fatalf("attempt %d bypassed backoff", i)
		}
		if r.RetryAt.Sub(now) > clientRetryMax {
			t.Fatal("unbounded backoff")
		}
		now = r.RetryAt
	}
	if r.Attempts != 40 {
		t.Fatal("attempt limit/reset while offline")
	}
	// Successful interface/UAPI creation does not mean the handshake recovered.
	r.attempted(now, nil)
	st := ClientStatus{Running: true}
	if got := r.observe(st, now.Add(time.Second)); got != clientWait || r.Attempts != 41 {
		t.Fatal("iface-up reset failures")
	}
	if got := r.observe(st, r.VerifyUntil); got != clientWait { // retry cap is longer than initial handshake grace
		t.Fatal("backoff must also hold while verifying")
	}
	if got := r.observe(st, r.RetryAt); got != clientReconnect {
		t.Fatal("unanswered handshake did not retry")
	}
	st.LastHandshake = r.RetryAt.Unix()
	if got := r.observe(st, r.RetryAt); got != clientWait || r.Attempts != 0 || r.Recovering {
		t.Fatal("fresh handshake did not reset backoff")
	}
	for n, want := range []time.Duration{15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 5 * time.Minute, 5 * time.Minute} {
		if got := clientRetryDelay(n + 1); got != want {
			t.Fatalf("delay %d: %s != %s", n+1, got, want)
		}
	}
}

func TestClientRecoveryHandshakeAgeDoesNotDoubleGrace(t *testing.T) {
	now := time.Unix(100000, 0)
	st := ClientStatus{Running: true, LastHandshake: now.Unix(), RxBytes: 100}
	var r clientRecovery
	for elapsed := time.Duration(0); elapsed < clientStaleAfter; elapsed += clientWatchInterval {
		if r.observe(st, now.Add(elapsed)) != clientWait {
			t.Fatal("fresh handshake triggered probe")
		}
	}
	if r.observe(st, now.Add(clientStaleAfter)) != clientProbe {
		t.Fatal("fresh status polls extended the handshake health window")
	}
}

func TestPendingDeploymentSurvivesSaveReloadAndLocalControls(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := awg.Default()
	cfg.Conn.Host, cfg.Endpoint = "192.0.2.1", "192.0.2.1:51820"
	cfg.DeployedAt = 1
	cfg.Client.Enabled = true
	cfg.ProtocolVersion = "2"
	cfg.TrafficObfuscation = nil
	cfg.Obf = awg.Obfuscation{Jc: 4, Jmin: 40, Jmax: 70, S1: 15, S2: 20, H1: "123", H2: "456", H3: "789", H4: "987"}
	m := awg.NewManager(cfg)
	svc := &Service{store: st, activeID: "one", order: []string{"one"}, servers: map[string]*managedServer{"one": {ID: "one", Manager: m}}, awg: m}
	old := m.Config()
	next := m.Config()
	next.ProtocolVersion = "3.1"
	next.MTU = old.MTU - 10
	next.Obf.S1++
	if err := svc.AWG2SetConfig(&next); err != nil {
		t.Fatal(err)
	}
	if !m.PendingApply() || awgClientWireChanged(old, m.RuntimeConfig()) || old.MTU != m.RuntimeConfig().MTU {
		t.Fatal("saving wire config replaced the deployed client")
	}
	// A second edit must retain the first deployed snapshot, not the first draft.
	next = m.Config()
	next.Obf.S2++
	if err := svc.AWG2SetConfig(&next); err != nil {
		t.Fatal(err)
	}
	if awgClientWireChanged(old, m.RuntimeConfig()) {
		t.Fatal("second draft overwrote applied snapshot")
	}
	reloaded := &Service{store: st}
	reloaded.installAWGState(reloaded.loadAWGState())
	loaded := reloaded.awgActive()
	if !loaded.PendingApply() || awgClientWireChanged(old, loaded.RuntimeConfig()) {
		t.Fatal("restart forgot last-applied wire config")
	}
	loaded.SetClientEnabled(false)
	if loaded.RuntimeConfig().Client.Enabled {
		t.Fatal("applied snapshot resurrected disabled client")
	}
	if !svc.AWG2StatusView().DeploymentPending || !svc.awgServerSummaries()[0].DeploymentPending {
		t.Fatal("pending deployment absent from status")
	}
	if got := svc.awgServerSummaries()[0].ProtocolVersion; got != old.EffectiveProtocolVersion() {
		t.Fatal("summary reports desired rather than active wire version")
	}
	loaded.SetAppliedConfig(nil) // successful Manager.Deploy clears this snapshot
	reloaded.awgSave()
	if reloaded.loadAWGState().Servers[0].AppliedConfig != nil {
		t.Fatal("applied snapshot persisted after successful apply")
	}
}

func TestInvalidConfigDoesNotLeaveDeploymentPending(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := awg.Default()
	cfg.Conn.Host, cfg.Endpoint, cfg.DeployedAt = "192.0.2.1", "192.0.2.1:51820", 1
	m := awg.NewManager(cfg)
	svc := &Service{store: st, awg: m}
	in := m.Config()
	in.MTU = 1
	if err := svc.AWG2SetConfig(&in); err == nil {
		t.Fatal("invalid config accepted")
	}
	if m.PendingApply() {
		t.Fatal("failed validation left pending snapshot")
	}
}

func TestMTUOnlyDoesNotRequireRemoteDeployment(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := awg.Default()
	cfg.Conn.Host, cfg.Endpoint, cfg.DeployedAt = "192.0.2.1", "192.0.2.1:51820", 1
	cfg.Client.Enabled = false
	m := awg.NewManager(cfg)
	svc := &Service{store: st, awg: m}
	in := m.Config()
	in.MTU -= 10
	if err := svc.AWG2SetConfig(&in); err != nil {
		t.Fatal(err)
	}
	if m.PendingApply() || m.RuntimeConfig().MTU != in.MTU {
		t.Fatal("MTU-only edit incorrectly staged for VPS deployment")
	}
}

type fakeClientDriver struct {
	states    map[*awg.Manager]ClientStatus
	attempts  map[*awg.Manager]int
	probes    int
	restores  int
	err       error
	current   bool
	onRecover func(*awg.Manager) error
}

func (d *fakeClientDriver) status(m *awg.Manager) *ClientStatus { st := d.states[m]; return &st }
func (d *fakeClientDriver) probe(*awg.Manager) error            { d.probes++; return nil }
func (d *fakeClientDriver) recover(m *awg.Manager) error {
	d.attempts[m]++
	if d.onRecover != nil {
		return d.onRecover(m)
	}
	return d.err
}
func (d *fakeClientDriver) restoreRoutes(*awg.Manager) error { d.restores++; return nil }
func (d *fakeClientDriver) currentEngine(*awg.Manager) bool  { return d.current }

func testSupervisedService(t *testing.T) (*Service, *fakeClientDriver, []*managedServer) {
	t.Helper()
	svc := &Service{servers: map[string]*managedServer{}}
	d := &fakeClientDriver{states: map[*awg.Manager]ClientStatus{}, attempts: map[*awg.Manager]int{}, current: true, err: errors.New("offline")}
	svc.clients.driver = d
	var servers []*managedServer
	for _, id := range []string{"one", "two", "off", "client-off"} {
		cfg := awg.Default()
		cfg.Install = "imported"
		cfg.Endpoint = "192.0.2.1:2408"
		cfg.Enabled = id != "off"
		cfg.Client.Enabled = id != "client-off"
		srv := &managedServer{ID: id, Manager: awg.NewManager(cfg)}
		svc.servers[id] = srv
		svc.order = append(svc.order, id)
		servers = append(servers, srv)
	}
	svc.activeID = "one"
	svc.awg = servers[0].Manager
	return svc, d, servers
}

func TestClientSupervisorEveryEnabledServerAndStartupFailure(t *testing.T) {
	svc, d, servers := testSupervisedService(t)
	svc.checkClients()
	if d.attempts[servers[0].Manager] != 1 || d.attempts[servers[1].Manager] != 1 {
		t.Fatal("only selected server recovered")
	}
	if d.attempts[servers[2].Manager] != 0 || d.attempts[servers[3].Manager] != 0 {
		t.Fatal("disabled tunnel was started")
	}
	svc.checkClients()
	if d.attempts[servers[0].Manager] != 1 {
		t.Fatal("startup failure bypassed backoff")
	}
	// The next window must retry the startup failure, and re-check user intent
	// after obtaining the operation lock rather than acting on an old snapshot.
	svc.clients.mu.Lock()
	for m, r := range svc.clients.states {
		r.RetryAt = time.Time{}
		svc.clients.states[m] = r
	}
	svc.clients.mu.Unlock()
	servers[0].Manager.SetClientEnabled(false)
	svc.checkClients()
	if d.attempts[servers[0].Manager] != 1 || d.attempts[servers[1].Manager] != 2 {
		t.Fatal("retry ignored updated client intent")
	}
	svc.mu.Lock()
	delete(svc.servers, "two")
	svc.mu.Unlock()
	_, unlock := svc.lockClientOps(false)
	svc.checkClient(servers[1])
	unlock()
	if d.attempts[servers[1].Manager] != 2 {
		t.Fatal("deleted snapshot was resurrected")
	}
}

func TestClientSupervisorOldBinaryIsReplacedDespiteFreshHandshake(t *testing.T) {
	svc, d, servers := testSupervisedService(t)
	m := servers[0].Manager
	d.current = false
	d.states[m] = ClientStatus{Running: true, LastHandshake: time.Now().Unix()}
	svc.checkClients()
	if d.restores != 0 {
		t.Fatal("routing restore ran before old engine replacement")
	}
	svc.checkClients()
	if d.attempts[m] != 1 {
		t.Fatal("fresh old binary either skipped replacement or reset retry backoff")
	}
}

func TestClientOperationCancellationAndShutdown(t *testing.T) {
	svc, d, servers := testSupervisedService(t)
	entered := make(chan struct{})
	exited := make(chan struct{})
	var once sync.Once
	d.onRecover = func(m *awg.Manager) error {
		once.Do(func() { close(entered) })
		<-svc.clientOpContext().Done()
		return context.Canceled
	}
	go func() { svc.checkClients(); close(exited) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("recovery never began")
	}
	// A user disable cancels a scan before waiting for lifecycle serialization.
	_, unlock := svc.lockClientOps(true)
	servers[0].Manager.SetClientEnabled(false)
	servers[1].Manager.SetClientEnabled(false)
	unlock()
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("cancelled recovery stayed alive")
	}
	svc.StopAWG()
	before := d.attempts[servers[0].Manager]
	servers[0].Manager.SetClientEnabled(true)
	svc.checkClients()
	if d.attempts[servers[0].Manager] != before {
		t.Fatal("shutdown resurrected tunnel")
	}
	if unlock, ok := svc.tryClientOps(); ok {
		unlock()
		t.Fatal("refresh accepted after shutdown")
	}
}
