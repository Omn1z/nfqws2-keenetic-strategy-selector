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

const (
	clientWatchInterval = 10 * time.Second
	clientStaleAfter    = 5 * time.Minute
	clientProbeGrace    = 90 * time.Second
	clientRetryMin      = 15 * time.Second
	clientRetryMax      = 5 * time.Minute
)

// ops serializes local interface/config/policy mutations. Read-only status and
// DNS traffic never take it. A down/delete/shutdown cancels the current operation
// before waiting for ops, so a WARP scan cannot hold the user off for minutes.
// Refresh loops use TryLock: teardown can join them while it owns ops.
type clientSupervisor struct {
	ops         sync.Mutex
	mu          sync.Mutex
	ctx         context.Context
	cancel      context.CancelFunc
	stop        chan struct{}
	wg          sync.WaitGroup
	stopping    atomic.Bool
	waiters     atomic.Int32
	states      map[*awg.Manager]clientRecovery
	onRecovered func()
	driver      clientDriver
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
	return awgClientCurrentEngineOS(am.RuntimeConfig())
}

type clientRecovery struct {
	Seen          bool
	RX            int64
	Handshake     int64
	HealthyAt     time.Time
	ProbeAt       time.Time
	VerifyUntil   time.Time
	RetryAt       time.Time
	Attempts      int
	Recovering    bool
	Error         string
	RoutesPending bool
}

type clientRecoveryAction int

const (
	clientWait clientRecoveryAction = iota
	clientProbe
	clientReconnect
)

// observe only treats authenticated progress as recovery. An old handshake is
// normal on an idle WireGuard peer: first request a keepalive, then allow the
// engine its complete handshake/retry window before replacing the interface.
func (r *clientRecovery) observe(st ClientStatus, now time.Time) clientRecoveryAction {
	progress := r.Seen && (st.RxBytes > r.RX || st.LastHandshake > r.Handshake)
	r.Seen, r.RX, r.Handshake = true, st.RxBytes, st.LastHandshake
	fresh := st.LastHandshake > 0 && now.Unix()-st.LastHandshake >= 0 && now.Unix()-st.LastHandshake < int64(clientStaleAfter/time.Second)
	if st.Running && (fresh || progress) {
		healthyAt := r.HealthyAt
		if fresh && time.Unix(st.LastHandshake, 0).After(healthyAt) {
			healthyAt = time.Unix(st.LastHandshake, 0)
		}
		if progress {
			healthyAt = now
		}
		*r = clientRecovery{Seen: true, RX: st.RxBytes, Handshake: st.LastHandshake, HealthyAt: healthyAt, RoutesPending: r.RoutesPending}
		return clientWait
	}
	if now.Before(r.RetryAt) {
		return clientWait
	}
	if !st.Running {
		return clientReconnect
	}
	if now.Before(r.VerifyUntil) {
		return clientWait
	}
	if !r.HealthyAt.IsZero() && now.Sub(r.HealthyAt) < clientStaleAfter {
		return clientWait
	}
	if r.Attempts > 0 {
		return clientReconnect
	}
	if r.ProbeAt.IsZero() {
		r.ProbeAt, r.Recovering = now, true
		r.Error = "проверка туннеля без свежего handshake"
		return clientProbe
	}
	if now.Sub(r.ProbeAt) < clientProbeGrace {
		return clientWait
	}
	return clientReconnect
}

func clientRetryDelay(attempts int) time.Duration {
	d := clientRetryMin
	for n := 1; n < attempts && d < clientRetryMax; n++ {
		d *= 2
	}
	if d > clientRetryMax {
		return clientRetryMax
	}
	return d
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

func (r *clientRecovery) attempted(now time.Time, err error) {
	r.Attempts++
	r.Recovering = true
	r.RoutesPending = true
	r.RetryAt = now.Add(clientRetryDelay(r.Attempts))
	r.VerifyUntil = time.Time{}
	if err != nil {
		r.Error = err.Error()
	} else {
		r.Error = "ожидание handshake после переподключения"
		r.VerifyUntil = now.Add(clientProbeGrace)
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
	svc.clients.mu.Lock()
	defer svc.clients.mu.Unlock()
	if svc.clients.states == nil {
		svc.clients.states = map[*awg.Manager]clientRecovery{}
	}
	r := svc.clients.states[am]
	r.attempted(time.Now(), err)
	svc.clients.states[am] = r
}

func (svc *Service) clientRecoveryStatus(am *awg.Manager, st *ClientStatus) {
	if st == nil {
		return
	}
	svc.clients.mu.Lock()
	r := svc.clients.states[am]
	svc.clients.mu.Unlock()
	st.Recovering, st.RetryCount, st.RecoveryError = r.Recovering, r.Attempts, r.Error
	next := r.RetryAt
	if r.VerifyUntil.After(next) {
		next = r.VerifyUntil
	}
	if !r.ProbeAt.IsZero() && r.Attempts == 0 {
		next = r.ProbeAt.Add(clientProbeGrace)
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
	for _, srv := range svc.serverSnapshot() {
		unlock, ok := svc.tryClientOps()
		if !ok {
			return
		}
		svc.checkClient(srv)
		unlock()
	}
}

// Called with ops held; membership and desired flags are re-read after locking.
func (svc *Service) checkClient(srv *managedServer) {
	svc.mu.RLock()
	present := svc.servers[srv.ID] == srv
	svc.mu.RUnlock()
	am := srv.Manager
	if !present || !awgShouldAutostartClient(am.RuntimeConfig()) || svc.clientOpContext().Err() != nil {
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
	observed := *st
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
	action := r.observe(observed, now)
	svc.clients.states[am] = r
	svc.clients.mu.Unlock()
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
		logbuf.Append("awg2", "info", "автовосстановление "+awgClientIfaceName(am.Config())+": handshake/приём данных восстановлен")
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
			logbuf.Append("awg2", "warn", "проверка "+awgClientIfaceName(am.Config())+": "+err.Error())
		}
	case clientReconnect:
		iface := awgClientIfaceName(am.Config())
		logbuf.Append("awg2", "warn", fmt.Sprintf("автовосстановление %s: попытка %d (handshake=%d)", iface, r.Attempts+1, st.LastHandshake))
		err := driver.recover(am)
		if svc.clientOpContext().Err() != nil {
			return
		}
		svc.recordClientAttempt(am, err)
		svc.route.tunnelUpAt.Store(0)
		if err != nil {
			logbuf.Append("awg2", "warn", fmt.Sprintf("автовосстановление %s: %v; следующая попытка через %s", iface, err, clientRetryDelay(r.Attempts+1)))
		}
	}
}
