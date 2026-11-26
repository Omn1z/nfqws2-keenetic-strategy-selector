package awgroute

import "time"

const (
	clientStaleAfter    = 3 * time.Minute
	clientProbeGrace    = 20 * time.Second
	clientTrafficStall  = 8 * time.Second
	clientDataProbeRate = 30 * time.Second
)

type clientRecovery struct {
	Seen            bool
	RX              int64
	TX              int64
	Handshake       int64
	HealthyAt       time.Time
	TrafficStallAt  time.Time
	LastSendingAt   time.Time
	LastDataProbeAt time.Time
	ProbeAt         time.Time
	ProbeUntil      time.Time
	VerifyUntil     time.Time
	RetryAt         time.Time
	FailureSince    time.Time
	AttemptAt       time.Time
	Attempts        int
	Recovering      bool
	Error           string
	RoutesPending   bool
	LastStatus      ClientStatus
	LastStatusAt    time.Time
	UnavailableAt   time.Time
	UnavailableID   string
	directExhausted bool
	pathUnavailable bool
}

type clientRecoveryAction int

const (
	clientWait clientRecoveryAction = iota
	clientProbe
	clientProbeData
	clientReconnect
)

// observe only treats authenticated progress as recovery. An old handshake is
// normal on an idle WireGuard peer: first request a keepalive, then allow
// several handshake transmissions before replacing the interface.
func (r *clientRecovery) observe(st ClientStatus, now time.Time) clientRecoveryAction {
	return r.observeWithSettings(st, now, DefaultRecoverySettings())
}

func (r *clientRecovery) observeWithSettings(st ClientStatus, now time.Time, settings RecoverySettings) clientRecoveryAction {
	if st.StatusUnavailable && st.Running && st.engineID != "" {
		return r.observeUnavailable(st, now, settings)
	}
	if !r.UnavailableAt.IsZero() && r.Attempts == 0 && !r.pathUnavailable {
		r.ProbeAt, r.ProbeUntil = time.Time{}, time.Time{}
		r.Recovering, r.Error = false, ""
		r.FailureSince = time.Time{}
	}
	r.UnavailableAt, r.UnavailableID = time.Time{}, ""
	defer func() {
		st.Connected = st.Connected || r.authenticatedStatus(&st, now)
		r.LastStatus, r.LastStatusAt = st, now
	}()
	sameGeneration := sameClientGeneration(r.LastStatus, st)
	if r.Seen && !sameGeneration {
		r.HealthyAt = time.Time{}
		r.TrafficStallAt, r.LastSendingAt, r.LastDataProbeAt = time.Time{}, time.Time{}, time.Time{}
		r.pathUnavailable = false
	}
	progress := r.Seen && sameGeneration && (st.RxBytes > r.RX || st.LastHandshake > r.Handshake)
	sending := r.Seen && sameGeneration && st.TxBytes > r.TX
	r.Seen, r.RX, r.TX, r.Handshake = true, st.RxBytes, st.TxBytes, st.LastHandshake
	fresh := st.LastHandshake > 0 && now.Unix()-st.LastHandshake >= 0 && now.Unix()-st.LastHandshake < int64(clientStaleAfter/time.Second)
	if st.Running && (progress || fresh && !r.pathUnavailable) {
		healthyAt := r.HealthyAt
		if fresh && time.Unix(st.LastHandshake, 0).After(healthyAt) {
			healthyAt = time.Unix(st.LastHandshake, 0)
		}
		if progress {
			healthyAt = now
		}
		stallAt, sendingAt, probeAt := r.TrafficStallAt, r.LastSendingAt, r.LastDataProbeAt
		if progress {
			stallAt, sendingAt = time.Time{}, time.Time{}
		}
		*r = clientRecovery{
			Seen: true, RX: st.RxBytes, TX: st.TxBytes, Handshake: st.LastHandshake, HealthyAt: healthyAt,
			TrafficStallAt: stallAt, LastSendingAt: sendingAt, LastDataProbeAt: probeAt, RoutesPending: r.RoutesPending,
			directExhausted: st.transportMarked && r.directExhausted,
		}
		return r.observeTrafficStall(now, sending && !progress)
	}
	if now.Before(r.RetryAt) {
		return clientWait
	}
	if !st.Running {
		r.beginFailure(now)
		return clientReconnect
	}
	if now.Before(r.VerifyUntil) {
		return clientWait
	}
	if !r.pathUnavailable && !r.HealthyAt.IsZero() && now.Sub(r.HealthyAt) < clientStaleAfter {
		return r.observeTrafficStall(now, sending)
	}
	if r.Attempts > 0 {
		r.beginFailure(now)
		return clientReconnect
	}
	if r.ProbeAt.IsZero() {
		r.beginFailure(now)
		r.ProbeAt, r.Recovering = now, true
		r.ProbeUntil = now.Add(settings.handshakeTimeout())
		r.Error = "проверка туннеля без свежего handshake"
		return clientProbe
	}
	if now.Before(r.probeDeadline()) {
		return clientWait
	}
	return clientReconnect
}

func sameClientGeneration(left, right ClientStatus) bool {
	return left.engineID == right.engineID &&
		(left.Endpoint == "" || right.Endpoint == "" || left.Endpoint == right.Endpoint)
}

// A single unanswered packet is common. Challenge an authenticated tunnel only
// while it continues to send traffic without receiving anything back.
func (r *clientRecovery) observeTrafficStall(now time.Time, sending bool) clientRecoveryAction {
	if !sending {
		if now.Sub(r.LastSendingAt) > clientTrafficStall {
			r.TrafficStallAt = time.Time{}
		}
		return clientWait
	}
	if r.Handshake <= 0 {
		return clientWait
	}
	if r.TrafficStallAt.IsZero() || now.Sub(r.LastSendingAt) > clientTrafficStall {
		r.TrafficStallAt = now
	}
	r.LastSendingAt = now
	if now.Sub(r.TrafficStallAt) < clientTrafficStall ||
		(!r.LastDataProbeAt.IsZero() && now.Sub(r.LastDataProbeAt) < clientDataProbeRate) {
		return clientWait
	}
	r.LastDataProbeAt = now
	return clientProbeData
}

func (r *clientRecovery) confirmDataOutage(before, after ClientStatus, now time.Time) bool {
	if !after.Running || after.StatusUnavailable || before.engineID == "" || !sameClientGeneration(before, after) ||
		after.RxBytes != before.RxBytes || after.LastHandshake != before.LastHandshake || after.TxBytes <= before.TxBytes {
		return false
	}
	r.beginFailure(r.TrafficStallAt)
	r.pathUnavailable, r.Recovering = true, true
	r.ProbeAt, r.ProbeUntil = now, now
	r.Error = "туннель передаёт пакеты, но не получает ответов"
	return true
}

// A stalled status socket is not proof that its live daemon has died. Give
// that exact process one bounded verification window; failed reads neither
// renew authenticated health nor restart the window on every poll.
func (r *clientRecovery) observeUnavailable(st ClientStatus, now time.Time, settings RecoverySettings) clientRecoveryAction {
	if r.UnavailableAt.IsZero() || r.UnavailableID != st.engineID {
		r.UnavailableAt, r.UnavailableID = now, st.engineID
		r.ProbeAt = now
		r.ProbeUntil = now.Add(settings.handshakeTimeout())
	}
	r.beginFailure(now)
	r.Recovering = true
	r.Error = "временно недоступен статус работающего туннеля"
	if now.Before(r.RetryAt) || now.Before(r.ProbeUntil) {
		return clientWait
	}
	return clientReconnect
}

func (r *clientRecovery) beginFailure(now time.Time) {
	if r.FailureSince.IsZero() {
		r.FailureSince = now
	}
}

func (r clientRecovery) probeDeadline() time.Time {
	if !r.ProbeUntil.IsZero() {
		return r.ProbeUntil
	}
	if !r.ProbeAt.IsZero() {
		return r.ProbeAt.Add(clientProbeGrace)
	}
	return time.Time{}
}

func (r *clientRecovery) attempted(now time.Time, err error) {
	r.attemptedWithSettings(now, err, DefaultRecoverySettings())
}

func (r *clientRecovery) attemptedWithSettings(now time.Time, err error, settings RecoverySettings) {
	r.beginFailure(now)
	r.AttemptAt = now
	r.Attempts++
	r.Recovering = true
	r.RoutesPending = true
	r.VerifyUntil = time.Time{}
	if err != nil {
		r.Error = err.Error()
	} else {
		r.Error = "ожидание handshake после переподключения"
		r.VerifyUntil = now.Add(settings.handshakeTimeout())
	}
	r.scheduleRetry(settings)
}

func (r *clientRecovery) scheduleRetry(settings RecoverySettings) {
	if r.AttemptAt.IsZero() {
		return
	}
	base := r.AttemptAt
	if !r.VerifyUntil.IsZero() {
		base = r.VerifyUntil
	}
	r.RetryAt = base.Add(settings.retryDelay(base.Sub(r.FailureSince)))
}

func (r *clientRecovery) updateSettings(settings RecoverySettings) {
	if !r.Recovering {
		return
	}
	if !r.ProbeAt.IsZero() && r.Attempts == 0 && !r.pathUnavailable {
		r.ProbeUntil = r.ProbeAt.Add(settings.handshakeTimeout())
	}
	if !r.AttemptAt.IsZero() {
		if !r.VerifyUntil.IsZero() {
			r.VerifyUntil = r.AttemptAt.Add(settings.handshakeTimeout())
		}
		r.scheduleRetry(settings)
	}
}

func (r clientRecovery) authenticatedStatus(st *ClientStatus, now time.Time) bool {
	if st == nil || !st.Running || st.StatusUnavailable || !r.Seen || r.Recovering || st.LastHandshake <= 0 ||
		st.LastHandshake != r.Handshake || st.RxBytes < r.RX || r.HealthyAt.IsZero() {
		return false
	}
	if !sameClientGeneration(r.LastStatus, *st) {
		return false
	}
	age := now.Sub(r.HealthyAt)
	return age >= 0 && age < clientStaleAfter
}

func (r clientRecovery) restoreUnavailableStatus(st *ClientStatus, now time.Time, settings RecoverySettings) {
	if !st.StatusUnavailable || !st.Running || !r.LastStatus.Running || st.engineID == "" || st.engineID != r.LastStatus.engineID {
		return
	}
	age := now.Sub(r.LastStatusAt)
	if r.LastStatusAt.IsZero() || age < 0 || age >= settings.handshakeTimeout() {
		return
	}
	old := r.LastStatus
	st.LastHandshake, st.RxBytes, st.TxBytes = old.LastHandshake, old.RxBytes, old.TxBytes
	st.Endpoint, st.Address, st.MTU = old.Endpoint, old.Address, old.MTU
	st.transportMarked, st.transportOuterIface = old.transportMarked, old.transportOuterIface
	healthAge := now.Sub(r.HealthyAt)
	st.Connected = old.Connected && !r.HealthyAt.IsZero() && healthAge >= 0 && healthAge < clientStaleAfter
}
