package awgroute

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"nfqws2strategy/internal/services/awg"
)

// DeleteServerCommittedError means the profile was durably deleted and its
// rules migrated, but refreshing the local runtime failed. API callers should
// acknowledge the deletion and still migrate their external logical references.
type DeleteServerCommittedError struct{ Err error }

func (e *DeleteServerCommittedError) Error() string {
	return "подключение удалено, правила перенесены; применение маршрутизации: " + e.Err.Error()
}
func (e *DeleteServerCommittedError) Unwrap() error { return e.Err }

// DeleteServerPersistenceUncertainError requires retaining any outer migration
// journal: both saving and restoring failed, and neither complete state could
// be confirmed on disk. Original live managers remain available in memory.
type DeleteServerPersistenceUncertainError struct{ Err error }

func (e *DeleteServerPersistenceUncertainError) Error() string {
	return "сохранение переноса не подтверждено; исходные подключения сохранены в памяти: " + e.Err.Error()
}
func (e *DeleteServerPersistenceUncertainError) Unwrap() error { return e.Err }

type deleteReplacementOps struct {
	persist func(*awgPersisted) error
	down    func(*awg.Manager) error
	start   func(*awg.Manager) error
	apply   func() error
}

// AWG2DeleteServerWithReplacement reassigns the deleted connection's rules and
// backup references in one saved state. A blank replacement keeps the existing
// explicit waiting-rule deletion behavior.
func (svc *Service) AWG2DeleteServerWithReplacement(id, replacementID string) error {
	if strings.TrimSpace(replacementID) == "" {
		return svc.AWG2DeleteServer(id)
	}
	_, unlock := svc.lockClientOps(true)
	defer unlock()
	return svc.awgDeleteServerWithReplacementWithOps(id, replacementID, deleteReplacementOps{
		persist: func(state *awgPersisted) error { return svc.store.SaveSecret(awgConfigFile, state) },
		down:    svc.awgClientDownManagerOS,
		start:   svc.clientLifecycleDriver().recover,
		apply:   svc.awgApplyConnectionFailoverPolicyOS,
	})
}

// The caller holds client operations. No manager, interface, selected profile
// or routing rule is changed until validation and the atomic save succeed.
func (svc *Service) awgDeleteServerWithReplacementWithOps(id, replacementID string, ops deleteReplacementOps) error {
	if err := svc.clientOpContext().Err(); err != nil {
		return err
	}
	id, replacementID = strings.TrimSpace(id), strings.TrimSpace(replacementID)
	if id == "" || replacementID == "" || id == replacementID {
		return fmt.Errorf("выберите другое существующее подключение для переноса правил")
	}
	svc.mu.RLock()
	source, target := svc.servers[id], svc.servers[replacementID]
	svc.mu.RUnlock()
	if source == nil {
		return fmt.Errorf("удаляемое AWG2-подключение не найдено")
	}
	if target == nil {
		return fmt.Errorf("подключение для переноса правил не найдено")
	}
	before := svc.snapshotAWGState()
	candidate, transferActive, err := awgReplacementState(before, svc.awgRoutingRules(), id, replacementID)
	if err != nil {
		return err
	}
	var saveWarning error
	if err := ops.persist(&candidate); err != nil {
		// SaveSecret can fail after rename while fixing file permissions. Restore
		// the old snapshot too; ordinary pre-rename failures remain harmless.
		if rollbackErr := ops.persist(&before); rollbackErr != nil {
			failure := errors.Join(err, fmt.Errorf("восстановление сохранённого состояния: %w", rollbackErr))
			var saved awgPersisted
			if loadErr := svc.store.Load(awgConfigFile, &saved); loadErr != nil {
				return &DeleteServerPersistenceUncertainError{Err: errors.Join(failure, loadErr)}
			}
			if awgPersistedStatesEqual(saved, before) {
				return fmt.Errorf("перенос не выполнен: %w", failure)
			}
			if !awgPersistedStatesEqual(saved, candidate) {
				return &DeleteServerPersistenceUncertainError{Err: failure}
			}
			// A confirmed candidate can be published consistently even when the
			// filesystem refused both permission repair and rollback. Its rules
			// are durable; expose the warning as a committed result below.
			saveWarning = failure
		} else {
			return fmt.Errorf("перенос не сохранён: %w", err)
		}
	}

	// Keep the same manager objects for all remaining tunnels. In particular,
	// their recovery counters, live status, pending deployment and secrets stay
	// associated with the original physical interfaces.
	for _, entry := range candidate.Servers {
		svc.mu.RLock()
		srv := svc.servers[entry.ID]
		svc.mu.RUnlock()
		if srv == nil {
			continue
		} // Membership is stable while operations are held.
		srv.Manager.SetRoutingState(entry.Config.Routing, entry.Config.Routing.Active)
		srv.Manager.SetClientFailoverPolicy(entry.Config.Client.FallbackTunnelIDs, entry.Config.Client.Standby)
		if entry.AppliedConfig != nil {
			srv.Manager.SetAppliedConfig(entry.AppliedConfig)
		}
	}
	svc.mu.Lock()
	delete(svc.servers, id)
	order := make([]string, 0, len(candidate.Servers))
	for _, entry := range candidate.Servers {
		order = append(order, entry.ID)
	}
	svc.order = order
	svc.activeID = candidate.ActiveID
	svc.awg = svc.servers[candidate.ActiveID].Manager
	svc.pendingRules = cloneAWGZones(candidate.PendingRules)
	svc.connectionRefs = cloneAWGConnectionRefs(candidate.ConnectionRefs)
	svc.mu.Unlock()
	svc.forgetClientRecovery(source.Manager)
	svc.clients.mu.Lock()
	delete(svc.clients.standbyActive, source.Manager)
	svc.clients.mu.Unlock()
	svc.syncActiveAWGIface()
	svc.BumpZonesRevision()
	svc.route.tunnelUpAt.Store(0)

	runtimeErr := saveWarning
	if transferActive && svc.clientShouldRun(target.Manager) {
		status := svc.clientLifecycleDriver().status(target.Manager)
		if status == nil || !status.Running || !svc.clientLifecycleDriver().currentEngine(target.Manager) {
			err := ops.start(target.Manager)
			svc.recordClientAttempt(target.Manager, err)
			runtimeErr = errors.Join(runtimeErr, err)
		}
	}
	// This is a shared-policy transition: applying the new policy replaces old
	// routes without tearing down the other working connections globally.
	runtimeErr = errors.Join(runtimeErr, ops.apply())
	runtimeErr = errors.Join(runtimeErr, ops.down(source.Manager))
	svc.reconcileStandbyClients()
	if runtimeErr != nil {
		return &DeleteServerCommittedError{Err: runtimeErr}
	}
	return nil
}

func awgPersistedStatesEqual(a, b awgPersisted) bool {
	left, leftErr := json.Marshal(a)
	right, rightErr := json.Marshal(b)
	return leftErr == nil && rightErr == nil && bytes.Equal(left, right)
}

func awgReplacementFallbacks(primary string, fallbacks []string, source, target string) []string {
	mapped := make([]string, 0, len(fallbacks))
	for _, id := range fallbacks {
		id = strings.TrimSpace(id)
		if id == source {
			id = target
		}
		mapped = append(mapped, id)
	}
	out, _ := normalizeFallbackTunnelIDs(primary, mapped, nil)
	return out
}

// awgReplacementState compiles all logical references privately. The ordered
// global rule view includes pending rules and legacy implicit primary IDs.
func awgReplacementState(before awgPersisted, rules []awg.Zone, sourceID, targetID string) (awgPersisted, bool, error) {
	candidate := before
	candidate.Servers = make([]awgPersistedServer, 0, len(before.Servers)-1)
	candidate.PendingRules = nil
	candidate.ConnectionRefs = cloneAWGConnectionRefs(before.ConnectionRefs)
	var source awgPersistedServer
	targetFound := false
	for _, entry := range before.Servers {
		if entry.ID == sourceID {
			source = entry
			continue
		}
		if entry.ID == targetID {
			targetFound = true
		}
		candidate.Servers = append(candidate.Servers, entry)
	}
	if source.ID == "" || !targetFound {
		return before, false, fmt.Errorf("подключения для переноса не найдены")
	}
	if candidate.ActiveID == sourceID {
		candidate.ActiveID = targetID
	}

	part := map[string][]awg.Zone{}
	transferActive := source.Config.Routing.Active && source.Config.Routing.Mode == "full"
	for index, original := range cloneAWGZones(rules) {
		z := original
		// The observed sequence already resolved legacy zeros and duplicate
		// priorities using the old server order. Repartitioning changes that
		// tie-breaker, so persist unique ranks before moving rule ownership.
		z.Order = index + 1
		if z.TunnelID == sourceID {
			z.TunnelID, z.WaitingForConnection = targetID, false
			if z.Enabled && source.Config.Routing.Active {
				transferActive = true
			}
		}
		z.FallbackTunnelIDs = awgReplacementFallbacks(z.TunnelID, z.FallbackTunnelIDs, sourceID, targetID)
		if z.WaitingForConnection {
			candidate.PendingRules = append(candidate.PendingRules, z)
		} else {
			part[z.TunnelID] = append(part[z.TunnelID], z)
		}
	}
	for i := range candidate.Servers {
		entry := &candidate.Servers[i]
		entry.Config.Routing.Zones = cloneAWGZones(part[entry.ID])
		fallbacks := entry.Config.Client.FallbackTunnelIDs
		if entry.ID == targetID {
			fallbacks = append(append([]string{}, fallbacks...), source.Config.Client.FallbackTunnelIDs...)
			if transferActive && entry.Config.Routing.Mode != "off" {
				entry.Config.Routing.Active = true
				entry.Config.Client.Standby = false
			}
		}
		entry.Config.Client.FallbackTunnelIDs = awgReplacementFallbacks(entry.ID, fallbacks, sourceID, targetID)
		if entry.AppliedConfig != nil {
			// Applied snapshots keep remote wire settings. Local policy is live
			// even during a pending deployment, so update its copies consistently.
			applied := *entry.AppliedConfig
			applied.Client.FallbackTunnelIDs = cloneAWGStrings(entry.Config.Client.FallbackTunnelIDs)
			applied.Client.Standby = entry.Config.Client.Standby
			applied.Routing = entry.Config.Routing
			entry.AppliedConfig = &applied
		}
	}
	if err := awgValidateReplacementGraph(candidate.Servers); err != nil {
		return before, false, err
	}
	candidate.ConnectionRefs = awgRetainedConnectionRefs(candidate.ConnectionRefs, candidate.PendingRules, candidate.Servers)
	return candidate, transferActive, nil
}

func awgValidateReplacementGraph(servers []awgPersistedServer) error {
	graph := make(map[string][]string, len(servers))
	for _, entry := range servers {
		graph[entry.ID] = entry.Config.Client.FallbackTunnelIDs
	}
	marks := map[string]int{}
	var visit func(string) bool
	visit = func(id string) bool {
		if marks[id] != 0 {
			return marks[id] == 2
		}
		marks[id] = 1
		for _, next := range graph[id] {
			if !visit(next) {
				return false
			}
		}
		marks[id] = 2
		return true
	}
	for id := range graph {
		if !visit(id) {
			return fmt.Errorf("перенос создаёт цикл резервных подключений; измените список резервов перед удалением")
		}
	}
	return nil
}
