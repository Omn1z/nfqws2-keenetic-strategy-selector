package awgroute

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/logbuf"
)

const clientWatchInterval = 3 * time.Second

// ops serializes local interface/config/policy mutations. Read-only status and
// DNS traffic never take it. A down/delete/shutdown cancels the current operation
// before waiting for ops, so a WARP scan cannot hold the user off for minutes.
// Refresh loops use TryLock: teardown can join them while it owns ops.
type clientSupervisor struct {
	ops                   sync.Mutex
	mu                    sync.Mutex
	ctx                   context.Context
	cancel                context.CancelFunc
	stop                  chan struct{}
	wg                    sync.WaitGroup
	stopping              atomic.Bool
	waiters               atomic.Int32
	states                map[*awg.Manager]clientRecovery
	endpoints             map[*awg.Manager]clientEndpointPool
	endpointHook          func() error
	standbyActive         map[*awg.Manager]bool
	doubleTunnels         map[*awg.Manager]doubleTunnelState
	onRecovered           func()
	driver                clientDriver
	fallbackSignature     string
	fallbackSignatureSeen bool
}

// Driver boundary permits lifecycle tests without router/network side effects.
type clientDriver interface {
	status(*awg.Manager) *ClientStatus
	probe(*awg.Manager) error
	recover(*awg.Manager) error
	restoreRoutes(*awg.Manager) error
	currentEngine(*awg.Manager) bool
}
type systemClientDriver struct{ svc *Service }

func (d systemClientDriver) status(am *awg.Manager) *ClientStatus {
	return d.svc.awgClientStatusManagerOS(am)
}
func (d systemClientDriver) probe(am *awg.Manager) error   { return d.svc.awgProbeClientOS(am) }
func (d systemClientDriver) recover(am *awg.Manager) error { return d.svc.awgRecoverClientOS(am) }
func (d systemClientDriver) restoreRoutes(am *awg.Manager) error {
	return d.svc.awgRestoreClientRoutesOS(am)
}
func (d systemClientDriver) currentEngine(am *awg.Manager) bool {
	return awgClientCurrentEngineIfaceOS(clientIfaceName(am.RuntimeClientStatus().ClientIface))
}
func (d systemClientDriver) endpointHints(am *awg.Manager, pool []string) map[string]bool {
	return d.svc.awgEndpointHintsOS(am, pool)
}

func waitClientContext(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (svc *Service) cancelClientOp() {
	svc.clients.mu.Lock()
	if svc.clients.cancel != nil {
		svc.clients.cancel()
	}
	svc.clients.mu.Unlock()
}

func (svc *Service) lockClientOps(interrupt bool) (context.Context, func()) {
	svc.clients.waiters.Add(1)
	if interrupt {
		svc.cancelClientOp()
	}
	svc.clients.ops.Lock()
	svc.clients.waiters.Add(-1)
	return svc.clientOpLocked()
}

func (svc *Service) tryClientOps() (func(), bool) {
	if svc.clients.stopping.Load() || svc.clients.waiters.Load() > 0 || !svc.clients.ops.TryLock() {
		return nil, false
	}
	// A failed reload quarantines background work while existing daemons and
	// rules keep carrying traffic. Check after locking so a restore cannot
	// interleave between the fence and a watchdog/firewall mutation.
	if svc.awgPersistenceReady() != nil {
		svc.clients.ops.Unlock()
		return nil, false
	}
	_, unlock := svc.clientOpLocked()
	return unlock, true
}

func (svc *Service) clientOpLocked() (context.Context, func()) {
	ctx, cancel := context.WithCancel(context.Background())
	svc.clients.mu.Lock()
	svc.clients.ctx, svc.clients.cancel = ctx, cancel
	if svc.clients.stopping.Load() {
		cancel()
	}
	svc.clients.mu.Unlock()
	return ctx, func() {
		cancel()
		svc.clients.mu.Lock()
		svc.clients.ctx, svc.clients.cancel = nil, nil
		svc.clients.mu.Unlock()
		svc.clients.ops.Unlock()
	}
}

func (svc *Service) clientOpContext() context.Context {
	svc.clients.mu.Lock()
	defer svc.clients.mu.Unlock()
	if svc.clients.ctx != nil {
		return svc.clients.ctx
	}
	if svc.clients.stopping.Load() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx
	}
	return context.Background()
}

func (svc *Service) forgetClientRecovery(am *awg.Manager) {
	svc.clients.mu.Lock()
	delete(svc.clients.states, am)
	delete(svc.clients.endpoints, am)
	delete(svc.clients.doubleTunnels, am)
	am.ResetClientEndpoint()
	svc.clients.mu.Unlock()
}

// SetClientRecoveryHook lets the app restore Telegram front host-routes after
// an interface was recreated. The callback must not call a lifecycle mutator.
func (svc *Service) SetClientRecoveryHook(fn func()) {
	svc.clients.mu.Lock()
	svc.clients.onRecovered = fn
	svc.clients.mu.Unlock()
}

func (svc *Service) recordClientAttempt(am *awg.Manager, err error) {
	settings := svc.currentRecoverySettings()
	pool := am.ClientEndpointCandidates()
	svc.clients.mu.Lock()
	defer svc.clients.mu.Unlock()
	if svc.clients.states == nil {
		svc.clients.states = map[*awg.Manager]clientRecovery{}
	}
	r := svc.clients.states[am]
	r.attemptedWithSettings(time.Now(), err, settings)
	svc.clients.states[am] = r
	endpoint := svc.endpointPoolLocked(am, pool)
	endpoint.started = true
	if index := endpointChoice(pool, am.RuntimeClientStatus().Endpoint); index >= 0 {
		endpoint.index = index
	}
	svc.clients.endpoints[am] = endpoint
}

func (svc *Service) clientRecoveryStatus(am *awg.Manager, st *ClientStatus) {
	if st == nil {
		return
	}
	svc.clients.mu.Lock()
	r := svc.clients.states[am]
	svc.clients.mu.Unlock()
	now := time.Now()
	r.restoreUnavailableStatus(st, now, svc.currentRecoverySettings())
	// A successful receive is authenticated by the engine just like a fresh
	// handshake. Keep status/failover consistent with observeWithSettings: an
	// idle rekey timestamp must not hide a tunnel still receiving valid data.
	// Read-only polls do not extend this window, and counters/handshake must
	// still belong to the generation the supervisor actually observed.
	st.Connected = st.Connected || r.authenticatedStatus(st, now)
	st.pathUnavailable = r.pathUnavailable && sameClientGeneration(r.LastStatus, *st) &&
		st.LastHandshake <= r.Handshake && st.RxBytes <= r.RX
	if st.pathUnavailable {
		st.Connected = false
	}
	svc.doubleTunnelHealth(am, st)
	svc.endpointStatus(am, st)
	st.Recovering, st.RetryCount, st.RecoveryError = r.Recovering, r.Attempts, r.Error
	verification := r.VerifyUntil
	next := r.RetryAt
	if r.VerifyUntil.After(next) {
		next = r.VerifyUntil
	}
	if !r.ProbeAt.IsZero() && r.Attempts == 0 {
		next = r.probeDeadline()
		verification = next
	}
	st.VerificationUntil = 0
	if !verification.IsZero() {
		st.VerificationUntil = verification.Unix()
	}
	if !next.IsZero() {
		st.RetryAt = next.Unix()
	}
}

func (svc *Service) startClientSupervisor() {
	if !clientSupervisorSupported() {
		return
	}
	svc.clients.mu.Lock()
	if svc.clients.stop != nil || svc.clients.stopping.Load() {
		svc.clients.mu.Unlock()
		return
	}
	stop := make(chan struct{})
	svc.clients.stop = stop
	svc.clients.wg.Add(1)
	svc.clients.mu.Unlock()
	go func() {
		defer svc.clients.wg.Done()
		t := time.NewTicker(clientWatchInterval)
		defer t.Stop()
		for {
			svc.checkClients()
			select {
			case <-stop:
				return
			case <-t.C:
			}
		}
	}()
}

// StopAWG leaves persisted intent and working tunnels intact across a panel
// restart, but no boot/retry/refresh operation may outlive shutdown.
func (svc *Service) StopAWG() {
	svc.clients.stopping.Store(true)
	svc.clients.mu.Lock()
	if svc.clients.stop != nil {
		close(svc.clients.stop)
		svc.clients.stop = nil
	}
	if svc.clients.cancel != nil {
		svc.clients.cancel()
	}
	svc.clients.mu.Unlock()
	svc.clients.wg.Wait()
	// Join a user operation too, after cancellation, before shutdown tears down routes.
	svc.clients.ops.Lock()
	svc.clients.ops.Unlock()
}

func (svc *Service) checkClients() {
	if svc.awgPersistenceReady() != nil {
		return
	}
	// Observe primaries before deciding which cold reserves are needed. A
	// second reconciliation handles a timeout discovered in this same pass.
	if unlock, ok := svc.tryClientOps(); ok {
		svc.reconcileStandbyClients()
		unlock()
	}
	for _, srv := range svc.serverSnapshot() {
		unlock, ok := svc.tryClientOps()
		if !ok {
			return
		}
		svc.checkClient(srv)
		unlock()
	}
	if unlock, ok := svc.tryClientOps(); ok {
		svc.reconcileStandbyClients()
		for _, srv := range svc.serverSnapshot() {
			if srv.Manager.RuntimeLocalClientIdentity().Standby && svc.clientShouldRun(srv.Manager) {
				svc.checkClient(srv)
			}
		}
		unlock()
	}
	if svc.refreshFallbackRoutingIfNeeded() {
		logbuf.Append("awg2", "info", "fallback-маршрутизация: выбранное подключение изменилось, правила обновлены")
	}
}

// Called with ops held; membership and desired flags are re-read after locking.
func (svc *Service) checkClient(srv *managedServer) {
	if svc.awgPersistenceReady() != nil {
		return
	}
	svc.mu.RLock()
	present := svc.servers[srv.ID] == srv
	svc.mu.RUnlock()
	am := srv.Manager
	if !present || !svc.clientShouldRun(am) || svc.clientOpContext().Err() != nil {
		svc.forgetClientRecovery(am)
		return
	}
	driver := svc.clients.driver
	if driver == nil {
		driver = systemClientDriver{svc}
	}
	st := driver.status(am)
	if st == nil {
		return
	}
	now := time.Now()
	settings := svc.currentRecoverySettings()
	if svc.checkDoubleTunnel(am, driver, st, now) {
		return
	}
	observed := *st
	svc.observeClientEndpoint(am, &observed)
	if st.Running && !driver.currentEngine(am) {
		observed.Running = false
	}
	svc.clients.mu.Lock()
	if svc.clients.states == nil {
		svc.clients.states = map[*awg.Manager]clientRecovery{}
	}
	r := svc.clients.states[am]
	if !r.Seen {
		r.RoutesPending = true
	}
	wasRecovering := r.Recovering
	action := r.observeWithSettings(observed, now, settings)
	svc.clients.states[am] = r
	svc.clients.mu.Unlock()
	if !r.Recovering && observed.Running && !observed.StatusUnavailable && !observed.transportMarked {
		svc.authenticatedClientEndpoint(am)
	}
	if action != clientReconnect && observed.Running && r.RoutesPending && svc.clientOpContext().Err() == nil {
		if err := driver.restoreRoutes(am); err == nil {
			svc.clients.mu.Lock()
			r.RoutesPending = false
			svc.clients.states[am] = r
			svc.clients.mu.Unlock()
		} else {
			logbuf.Append("awg2", "warn", "восстановление маршрутов: "+err.Error())
		}
	}
	if wasRecovering && !r.Recovering {
		logbuf.Append("awg2", "info", "автовосстановление "+clientIfaceName(am.RuntimeClientStatus().ClientIface)+": handshake/приём данных восстановлен")
		svc.clients.mu.Lock()
		hook := svc.clients.onRecovered
		svc.clients.mu.Unlock()
		if hook != nil {
			hook()
		}
	}
	switch action {
	case clientProbe:
		if err := driver.probe(am); err != nil {
			logbuf.Append("awg2", "warn", "проверка "+clientIfaceName(am.RuntimeClientStatus().ClientIface)+": "+err.Error())
		}
	case clientProbeData:
		svc.checkStalledClientData(am, driver, observed)
	case clientReconnect:
		if svc.reconnectDoubleTunnel(am, driver) {
			return
		}
		iface := clientIfaceName(am.RuntimeClientStatus().ClientIface)
		logbuf.Append("awg2", "warn", fmt.Sprintf("автовосстановление %s: попытка %d (handshake=%d)", iface, r.Attempts+1, st.LastHandshake))
		if err := svc.clientOpContext().Err(); err != nil {
			return
		}
		rotateEndpoint := !observed.StatusUnavailable && (!st.Running || observed.Running) && (observed.Running || r.Attempts > 0)
		rollbackEndpoint := svc.prepareClientEndpointAttempt(am, rotateEndpoint)
		if svc.clientOpContext().Err() != nil {
			rollbackEndpoint()
			return
		}
		var err error
		if svc.doubleTunnelNeedsOuter(am) {
			err = recoverWithExistingPeer(driver, am)
		} else {
			err = driver.recover(am)
		}
		if svc.clientOpContext().Err() != nil {
			rollbackEndpoint()
			return
		}
		svc.recordClientAttempt(am, err)
		svc.route.tunnelUpAt.Store(0)
		if err != nil {
			logbuf.Append("awg2", "warn", fmt.Sprintf("автовосстановление %s: %v; следующая попытка через %s", iface, err, settings.retryDelay(time.Since(r.FailureSince))))
		}
	}
}

func (svc *Service) checkStalledClientData(am *awg.Manager, driver clientDriver, before ClientStatus) {
	prober, ok := driver.(interface {
		clientDataUnanswered(*awg.Manager) bool
	})
	if !ok || !prober.clientDataUnanswered(am) || svc.clientOpContext().Err() != nil {
		return
	}
	after := driver.status(am)
	if after == nil {
		return
	}
	svc.clients.mu.Lock()
	recovery := svc.clients.states[am]
	confirmed := recovery.confirmDataOutage(before, *after, time.Now())
	if confirmed {
		svc.clients.states[am] = recovery
	}
	svc.clients.mu.Unlock()
	if confirmed {
		svc.route.tunnelUpAt.Store(0)
		logbuf.Append("awg2", "warn", "проверка "+clientIfaceName(am.RuntimeClientStatus().ClientIface)+": "+recovery.Error)
	}
}
