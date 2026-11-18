package awgroute

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"nfqws2strategy/internal/services/awg"
)

type clientEndpointPool struct {
	signature                    string
	index                        int
	failed                       uint16
	started, exhausted, observed bool
}

type EndpointBackupsCommittedError struct{ Err error }

func (err *EndpointBackupsCommittedError) Error() string {
	return "резервные IP сохранены; применить к работающему туннелю пока не удалось: " + err.Err.Error()
}
func (err *EndpointBackupsCommittedError) Unwrap() error { return err.Err }

type EndpointBackupsPersistenceUncertainError struct{ Err error }

func (err *EndpointBackupsPersistenceUncertainError) Error() string {
	return "не удалось подтвердить сохранение резервных IP или восстановить прежний файл; состояние на диске требует повторной проверки: " + err.Err.Error()
}
func (err *EndpointBackupsPersistenceUncertainError) Unwrap() error { return err.Err }

// The application refreshes its narrow UDP transport exclusions here. The
// callback runs with lifecycle ops held, but never service/client state locks.
func (svc *Service) SetClientEndpointHook(fn func() error) {
	svc.clients.mu.Lock()
	svc.clients.endpointHook = fn
	svc.clients.mu.Unlock()
}

func (svc *Service) refreshClientEndpointBypass() error {
	svc.clients.mu.Lock()
	hook := svc.clients.endpointHook
	svc.clients.mu.Unlock()
	if hook != nil {
		return hook()
	}
	return nil
}

func endpointParts(endpoint string) (string, string) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(endpoint))
	if err != nil {
		return "", ""
	}
	if parsed, err := strconv.Atoi(port); err == nil {
		port = strconv.Itoa(parsed)
	}
	if ip, e := netip.ParseAddr(host); e == nil {
		host = ip.Unmap().String()
	} else {
		host = strings.ToLower(strings.TrimSuffix(host, "."))
	}
	return host, port
}

func endpointChoice(pool []string, endpoint string) int {
	host, port := endpointParts(endpoint)
	for i, candidate := range pool {
		h, p := endpointParts(candidate)
		if host != "" && host == h && port == p {
			return i
		}
	}
	return -1
}

func (svc *Service) liveEndpointChoice(pool []string, endpoint string) int {
	if i := endpointChoice(pool, endpoint); i >= 0 {
		return i
	}
	host, port := endpointParts(endpoint)
	for i, candidate := range pool {
		h, p := endpointParts(candidate)
		if port == p && host != "" && svc.cachedPolicyEndpointIP(h) == host {
			return i
		}
	}
	return -1
}

func (svc *Service) endpointPoolLocked(am *awg.Manager, pool []string) clientEndpointPool {
	if svc.clients.endpoints == nil {
		svc.clients.endpoints = map[*awg.Manager]clientEndpointPool{}
	}
	state := svc.clients.endpoints[am]
	signature := strings.Join(pool, "\x00")
	if state.signature != signature {
		state = clientEndpointPool{signature: signature}
		if index := endpointChoice(pool, am.RuntimeConfig().Endpoint); index >= 0 {
			state.index = index
		}
	}
	return state
}

// A panel restart can inherit a working daemon on a reserve IP. Adopt only a
// configured canonical candidate (same port), without touching its peer/UAPI.
func (svc *Service) observeClientEndpoint(am *awg.Manager, st *ClientStatus) {
	pool := am.ClientEndpointCandidates()
	svc.clients.mu.Lock()
	state := svc.endpointPoolLocked(am, pool)
	if !state.observed {
		if st != nil && st.Running && !st.StatusUnavailable {
			if index := svc.liveEndpointChoice(pool, st.Endpoint); index >= 0 {
				state.index = index
				am.SelectClientEndpoint(index)
				state.started = true
			}
		}
		if st != nil && !st.StatusUnavailable {
			state.observed = true
		}
	}
	svc.clients.endpoints[am] = state
	svc.clients.mu.Unlock()
}

// Called immediately before a failed tunnel is actually retried. Successful
// authentication clears the failed cycle while leaving the chosen IP sticky.
func (svc *Service) prepareClientEndpointAttempt(am *awg.Manager, rotate bool) func() {
	pool := am.ClientEndpointCandidates()
	svc.clients.mu.Lock()
	state := svc.endpointPoolLocked(am, pool)
	svc.clients.mu.Unlock()
	var reachable map[string]bool
	if rotate && state.started && len(pool) > 1 {
		if probe, ok := svc.clientLifecycleDriver().(interface {
			endpointHints(*awg.Manager, []string) map[string]bool
		}); ok {
			reachable = probe.endpointHints(am, pool)
		}
	}
	svc.clients.mu.Lock()
	previous := state
	if rotate && state.started && len(pool) > 1 {
		state.failed |= 1 << state.index
		if state.failed == uint16((1<<len(pool))-1) {
			state.exhausted = true
			state.failed = 0
		}
		next := -1
		for i, candidate := range pool {
			if state.failed&(1<<i) == 0 && (next < 0 || reachable[candidate] && !reachable[pool[next]]) {
				next = i
			}
		}
		if next >= 0 {
			state.index = next
		}
	}
	state.started = true
	am.SelectClientEndpoint(state.index)
	svc.clients.endpoints[am] = state
	svc.clients.mu.Unlock()
	return func() {
		svc.clients.mu.Lock()
		svc.clients.endpoints[am] = previous
		am.SelectClientEndpoint(previous.index)
		svc.clients.mu.Unlock()
	}
}

func (svc *Service) authenticatedClientEndpoint(am *awg.Manager) {
	pool := am.ClientEndpointCandidates()
	svc.clients.mu.Lock()
	defer svc.clients.mu.Unlock()
	state := svc.endpointPoolLocked(am, pool)
	state.failed, state.exhausted, state.started = 0, false, true
	svc.clients.endpoints[am] = state
}

func (svc *Service) endpointPoolAllowsFallback(am *awg.Manager) bool {
	pool := am.ClientEndpointCandidates()
	if len(pool) <= 1 {
		return true
	}
	svc.clients.mu.Lock()
	defer svc.clients.mu.Unlock()
	return svc.endpointPoolLocked(am, pool).exhausted
}

func (svc *Service) endpointFallbackTunnelIDs(primary string, ruleFallbacks []string) []string {
	fallbacks := svc.connectionFallbackTunnelIDs(primary, ruleFallbacks)
	for _, srv := range svc.serverSnapshot() {
		if srv.ID == primary && !svc.endpointPoolAllowsFallback(srv.Manager) {
			// A restart can inherit an authenticated reserve already carrying
			// traffic. Keep that path until primary verification completes, but
			// never activate or select an unverified cold profile early.
			var warm []string
			byID := map[string]*managedServer{}
			for _, candidate := range svc.serverSnapshot() {
				byID[candidate.ID] = candidate
			}
			for _, id := range fallbacks {
				if candidate := byID[id]; candidate != nil && svc.clientShouldRun(candidate.Manager) && clientAuthenticated(svc.clientLifecycleDriver().status(candidate.Manager), time.Now()) {
					warm = append(warm, id)
				}
			}
			return warm
		}
	}
	return fallbacks
}

func (svc *Service) endpointStatus(am *awg.Manager, st *ClientStatus) {
	if st == nil {
		return
	}
	pool := am.ClientEndpointCandidates()
	if len(pool) == 0 {
		return
	}
	st.EndpointPrimary, st.EndpointCount = pool[0], len(pool)
	st.EndpointCandidate = am.RuntimeConfig().Endpoint
	st.EndpointIndex = endpointChoice(pool, st.EndpointCandidate)
	if index := svc.liveEndpointChoice(pool, st.Endpoint); index >= 0 {
		st.EndpointIndex = index
		st.EndpointCandidate = pool[index]
	}
	st.EndpointPoolExhausted = svc.endpointPoolAllowsFallback(am) && len(pool) > 1
}

func (svc *Service) rememberClientEndpointStatus(am *awg.Manager, st *ClientStatus) {
	if st == nil || st.Endpoint == "" {
		return
	}
	pool := am.ClientEndpointCandidates()
	index := svc.liveEndpointChoice(pool, st.Endpoint)
	if index < 0 && len(pool) > 1 && st.Running && !st.StatusUnavailable {
		primaryHost, primaryPort := endpointParts(pool[0])
		ip, port := endpointParts(st.Endpoint)
		if net.ParseIP(primaryHost) == nil && net.ParseIP(ip) != nil && port == primaryPort {
			// The live local peer knows its transport address even when an
			// idle handshake is old and the DNS cache was lost on restart.
			// Keep that address out of catch-all routing before probing it;
			// this WAN-escape hint grants no authenticated health or rotation.
			// Explicit backups matched above never become primary DNS hints.
			svc.rememberPolicyEndpointIP(primaryHost, ip)
			if clientAuthenticated(st, time.Now()) {
				index = 0
			}
		}
	}
	if index < 0 && len(pool) == 1 {
		index = 0
	} // retain legacy primary-only roaming hints
	if index < 0 {
		return
	}
	host, _ := endpointParts(pool[index])
	ip, _ := endpointParts(st.Endpoint)
	if net.ParseIP(ip) != nil {
		svc.rememberPolicyDNS(host, []string{ip})
	}
}

// ClientEndpointCandidates supplies the complete configured transport pool to
// NFQUEUE exclusions. Runtime selection never removes the other WAN escapes.
func (svc *Service) ClientEndpointCandidates() []string {
	var out []string
	seen := map[string]bool{}
	for _, srv := range svc.serverSnapshot() {
		if srv.Manager.Enabled() {
			for _, endpoint := range srv.Manager.ClientEndpointCandidates() {
				if endpoint != "" && !seen[endpoint] {
					seen[endpoint] = true
					out = append(out, endpoint)
				}
				host, port := endpointParts(endpoint)
				if ip := svc.cachedPolicyEndpointIP(host); ip != "" {
					resolved := net.JoinHostPort(ip, port)
					if !seen[resolved] {
						seen[resolved] = true
						out = append(out, resolved)
					}
				}
			}
		}
	}
	return out
}

func (svc *Service) AWG2SetEndpointBackups(id string, endpoints []string) error {
	_, unlock := svc.lockClientOps(false)
	defer unlock()
	if svc.store == nil {
		return fmt.Errorf("хранилище настроек AWG недоступно")
	}
	return svc.setEndpointBackupsWithOps(id, endpoints, func(state awgPersisted) error { return svc.persistAWGState(&state) })
}

func (svc *Service) setEndpointBackupsWithOps(id string, endpoints []string, save func(awgPersisted) error) error {
	id = strings.TrimSpace(id)
	if err := svc.clientOpContext().Err(); err != nil {
		return err
	}
	var am *awg.Manager
	for _, srv := range svc.serverSnapshot() {
		if srv.ID == strings.TrimSpace(id) {
			am = srv.Manager
			break
		}
	}
	if am == nil {
		return fmt.Errorf("AWG2-сервер не найден")
	}
	pool := am.ClientEndpointCandidates()
	backups, err := awg.NormalizeEndpointBackups(pool[0], endpoints)
	if err != nil {
		return err
	}
	// Persist the candidate first; storage failure preserves both published
	// configuration and the current healthy runtime endpoint.
	previousState := svc.snapshotAWGState()
	state := svc.snapshotAWGState()
	for i := range state.Servers {
		if state.Servers[i].ID == id {
			state.Servers[i].Config.Client.EndpointBackups = backups
		}
	}
	if err := save(state); err != nil {
		// SaveSecret may fail while repairing permissions after its rename.
		// Restore disk intent as well as leaving runtime/config unpublished.
		if restoreErr := save(previousState); restoreErr != nil {
			return &EndpointBackupsPersistenceUncertainError{Err: errors.Join(err, restoreErr)}
		}
		return err
	}
	previous := am.RuntimeConfig().Endpoint
	if err := am.SetEndpointBackups(backups); err != nil {
		return &EndpointBackupsCommittedError{Err: err}
	}
	svc.clients.mu.Lock()
	delete(svc.clients.endpoints, am)
	svc.clients.mu.Unlock()
	svc.BumpZonesRevision()
	if svc.clientShouldRun(am) {
		driver := svc.clientLifecycleDriver()
		if status := driver.status(am); status != nil && status.Running {
			if am.RuntimeConfig().Endpoint != previous {
				svc.forgetClientRecovery(am)
				err := driver.recover(am)
				svc.recordClientAttempt(am, err)
				if err != nil {
					return &EndpointBackupsCommittedError{Err: err}
				}
			}
			if err := driver.restoreRoutes(am); err != nil {
				return &EndpointBackupsCommittedError{Err: err}
			}
		}
	}
	return nil
}
