package awgroute

import (
	"errors"
	"os"
	"reflect"
	"testing"

	"nfqws2strategy/internal/services/awg"
)

func deleteReplacementTestOps(svc *Service) deleteReplacementOps {
	return deleteReplacementOps{
		persist: func(state *awgPersisted) error { return svc.store.SaveSecret(awgConfigFile, state) },
		down:    func(*awg.Manager) error { return nil }, start: func(*awg.Manager) error { return nil }, apply: func() error { return nil },
	}
}

func runDeleteReplacement(t *testing.T, svc *Service, from, to string, ops deleteReplacementOps) error {
	t.Helper()
	_, unlock := svc.lockClientOps(false)
	defer unlock()
	return svc.awgDeleteServerWithReplacementWithOps(from, to, ops)
}

func TestDeleteReplacementPreservesGlobalRulePropertiesAndPendingRules(t *testing.T) {
	svc := pendingRuleFixture(t, "source", "target", "other")
	on, off := true, false
	rules := []awg.Zone{
		{Name: "all details", TunnelID: "source", Order: 1, Route: "tunnel", Mode: "include", Domains: []string{"list:video", "exact.example"}, IncludeSubdomains: &on, IPs: []string{"203.0.113.0/24"}, SourceIPs: []string{"192.168.3.7/32"}, FallbackTunnelIDs: []string{"target", "other"}, Enabled: true},
		{Name: "target direct", TunnelID: "target", Order: 2, Route: "direct", Mode: "exclude", Domains: []string{"direct.example"}, IncludeSubdomains: &off, IPs: []string{}, SourceIPs: []string{}, Enabled: true},
		{Name: "disabled", TunnelID: "source", Order: 3, Route: "tunnel", Mode: "include", Domains: []string{"disabled.example"}, IPs: []string{}, SourceIPs: []string{}, Enabled: false},
		{Name: "other fallback", TunnelID: "other", Order: 4, Route: "tunnel", Mode: "include", Domains: []string{"other.example"}, IPs: []string{}, SourceIPs: []string{}, FallbackTunnelIDs: []string{"source", "target"}, Enabled: true},
		{Name: "source waiting", TunnelID: "source", WaitingForConnection: true, Order: 5, Route: "tunnel", Domains: []string{"waiting.example"}, IncludeSubdomains: &off, Enabled: true},
		{Name: "unrelated waiting", TunnelID: "historical", WaitingForConnection: true, Order: 6, Route: "tunnel", Domains: []string{"historical.example"}, FallbackTunnelIDs: []string{"source", "target"}, Enabled: false},
	}
	if err := svc.awgSaveRoutingRules(svc.currentRoutingSettings().apply(awg.RoutingConfig{Zones: rules})); err != nil {
		t.Fatal(err)
	}
	beforeRules := svc.awgRoutingRules()
	beforeSettings, beforeRecovery := svc.currentRoutingSettings(), svc.currentRecoverySettings()
	targetManager, otherManager := svc.servers["target"].Manager, svc.servers["other"].Manager
	otherBefore := otherManager.Config()
	if err := runDeleteReplacement(t, svc, "source", "target", deleteReplacementTestOps(svc)); err != nil {
		t.Fatal(err)
	}
	for _, state := range []*Service{svc, reloadPendingRuleFixture(svc)} {
		want := cloneAWGZones(beforeRules)
		for i := range want {
			if want[i].TunnelID == "source" {
				want[i].TunnelID, want[i].WaitingForConnection = "target", false
				if want[i].Mode == "" {
					want[i].Mode = "include"
				}
			}
			want[i].FallbackTunnelIDs = awgReplacementFallbacks(want[i].TunnelID, want[i].FallbackTunnelIDs, "source", "target")
			if !want[i].WaitingForConnection && len(want[i].FallbackTunnelIDs) == 0 {
				want[i].FallbackTunnelIDs = nil
			}
		}
		if !reflect.DeepEqual(state.awgRoutingRules(), want) {
			t.Fatal("replacement changed rule data, enabled state, subdomains, source filters or global order")
		}
		if state.servers["source"] != nil || state.activeServerID() != "target" || len(state.pendingRules) != 1 || state.pendingRules[0].TunnelID != "historical" {
			t.Fatal("replacement lost pending rules or selected an unrelated profile")
		}
		if state.currentRoutingSettings() != beforeSettings || state.currentRecoverySettings() != beforeRecovery {
			t.Fatal("replacement reset shared settings")
		}
		if state.connectionRefs["source"].Ref != "" {
			t.Fatal("fully replaced connection retained stale deleted identity")
		}
		cfg := state.servers["other"].Manager.Config()
		cfg.Routing.Zones = otherBefore.Routing.Zones
		if !reflect.DeepEqual(cfg, otherBefore) {
			t.Fatal("replacement changed unrelated connection settings or secrets")
		}
	}
	if svc.servers["target"].Manager != targetManager || svc.servers["other"].Manager != otherManager {
		t.Fatal("replacement discarded live managers of remaining tunnels")
	}
}

func TestDeleteReplacementMapsConnectionFallbacksAndStartsFormerStandby(t *testing.T) {
	svc := pendingRuleFixture(t, "source", "target", "other", "last")
	svc.servers["source"].Manager.SetClientFailoverPolicy([]string{"other", "last"}, false)
	svc.servers["target"].Manager.SetClientFailoverPolicy([]string{"source", "other"}, true)
	svc.servers["other"].Manager.SetClientFailoverPolicy(nil, true)
	svc.servers["last"].Manager.SetClientFailoverPolicy(nil, true)
	rule := awg.Zone{Name: "active source", TunnelID: "source", Route: "tunnel", Domains: []string{"*"}, Enabled: true}
	if err := svc.awgSaveRoutingRules(svc.currentRoutingSettings().apply(awg.RoutingConfig{Zones: []awg.Zone{rule}})); err != nil {
		t.Fatal(err)
	}
	target := svc.servers["target"].Manager
	oldTarget := target.Config()
	oldTarget.Client.PeerID, oldTarget.Client.Enabled = "committed-router-peer", false
	target.SetAppliedConfig(&oldTarget)
	started, down := 0, 0
	ops := deleteReplacementTestOps(svc)
	ops.start = func(am *awg.Manager) error {
		if am != target {
			t.Fatal("started an unrelated tunnel")
		}
		started++
		return nil
	}
	ops.down = func(am *awg.Manager) error {
		if am == target {
			t.Fatal("stopped the replacement tunnel")
		}
		down++
		return nil
	}
	if err := runDeleteReplacement(t, svc, "source", "target", ops); err != nil {
		t.Fatal(err)
	}
	for _, state := range []*Service{svc, reloadPendingRuleFixture(svc)} {
		cfg := state.servers["target"].Manager.Config()
		if cfg.Client.Standby || !cfg.Client.Enabled || !cfg.Routing.Active || !reflect.DeepEqual(cfg.Client.FallbackTunnelIDs, []string{"other", "last"}) || !state.clientShouldRun(state.servers["target"].Manager) {
			t.Fatal("former standby did not become an eligible primary with deduplicated backup priority")
		}
		if applied := state.servers["target"].Manager.AppliedConfig(); applied == nil || !reflect.DeepEqual(applied.Client.FallbackTunnelIDs, cfg.Client.FallbackTunnelIDs) || !reflect.DeepEqual(applied.Routing.Zones, cfg.Routing.Zones) || applied.Client.PeerID != oldTarget.Client.PeerID || applied.Client.Enabled != oldTarget.Client.Enabled {
			t.Fatal("pending deployment retained stale local references")
		}
	}
	if started != 1 || down != 1 {
		t.Fatal("runtime did not start target and stop only removed interface")
	}
}

func TestDeleteReplacementDoesNotActivateUncommittedSourceRules(t *testing.T) {
	svc := pendingRuleFixture(t, "source", "target")
	rule := awg.Zone{Name: "saved only", TunnelID: "source", Domains: []string{"example.org"}, Enabled: true}
	if err := svc.awgSaveRoutingRules(svc.currentRoutingSettings().apply(awg.RoutingConfig{Zones: []awg.Zone{rule}})); err != nil {
		t.Fatal(err)
	}
	svc.servers["source"].Manager.SetRoutingActive(false)
	target := svc.servers["target"].Manager
	target.SetRoutingActive(false)
	target.SetClientFailoverPolicy(nil, true)
	ops := deleteReplacementTestOps(svc)
	ops.start = func(*awg.Manager) error { t.Fatal("uncommitted rules started a tunnel"); return nil }
	if err := runDeleteReplacement(t, svc, "source", "target", ops); err != nil {
		t.Fatal(err)
	}
	for _, state := range []*Service{svc, reloadPendingRuleFixture(svc)} {
		cfg := state.servers["target"].Manager.Config()
		if cfg.Routing.Active || !cfg.Client.Standby || len(cfg.Routing.Zones) != 1 || !cfg.Routing.Zones[0].Enabled {
			t.Fatal("migration activated saved-only rules or changed their enabled state")
		}
	}
}

func TestDeleteReplacementKeepsSelectedUnrelatedProfileAndDisabledTargetIntent(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "draft", true: "disabled"}[disabled], func(t *testing.T) {
			svc := pendingRuleFixture(t, "source", "target", "selected")
			svc.activeID, svc.awg = "selected", svc.servers["selected"].Manager
			target := svc.servers["target"].Manager
			if disabled {
				target.SetEnabled(false)
				target.SetClientEnabled(false)
			} else {
				cfg := target.Config()
				cfg.Endpoint = ""
				cfg.Install = "apt"
				cfg.DeployedAt = 0
				svc.servers["target"].Manager = awg.NewManager(&cfg)
				target = svc.servers["target"].Manager
			}
			rule := awg.Zone{TunnelID: "source", Domains: []string{"example.org"}, Enabled: true}
			if err := svc.awgSaveRoutingRules(svc.currentRoutingSettings().apply(awg.RoutingConfig{Zones: []awg.Zone{rule}})); err != nil {
				t.Fatal(err)
			}
			before := target.Config()
			ops := deleteReplacementTestOps(svc)
			ops.start = func(*awg.Manager) error { t.Fatal("disabled/draft replacement was started implicitly"); return nil }
			if err := runDeleteReplacement(t, svc, "source", "target", ops); err != nil {
				t.Fatal(err)
			}
			if svc.activeServerID() != "selected" || target.Enabled() != before.Enabled || target.ClientEnabled() != before.Client.Enabled || len(target.Config().Routing.Zones) != 1 {
				t.Fatal("replacement changed selection or explicit availability intent")
			}
		})
	}
}

func TestDeleteReplacementRejectsMissingSameIDAndCyclesWithoutSideEffects(t *testing.T) {
	for _, targetID := range []string{"missing", "source", "target"} {
		t.Run(targetID, func(t *testing.T) {
			svc := pendingRuleFixture(t, "source", "target", "middle")
			if targetID == "target" {
				// A -> middle -> target was acyclic. Merging A into target
				// would produce target -> middle -> target.
				svc.servers["source"].Manager.SetClientFailoverPolicy([]string{"middle"}, false)
				svc.servers["middle"].Manager.SetClientFailoverPolicy([]string{"target"}, false)
			}
			before := svc.snapshotAWGState()
			ops := deleteReplacementTestOps(svc)
			ops.persist = func(*awgPersisted) error { t.Fatal("invalid target reached persistence"); return nil }
			ops.down = func(*awg.Manager) error { t.Fatal("validation changed runtime"); return nil }
			if err := runDeleteReplacement(t, svc, "source", targetID, ops); err == nil {
				t.Fatal("invalid replacement accepted")
			}
			if !reflect.DeepEqual(svc.snapshotAWGState(), before) {
				t.Fatal("failed validation changed saved intent")
			}
		})
	}
}

func TestDeleteReplacementStorageFailureAndPostRenameErrorRestoreOriginal(t *testing.T) {
	for _, postRename := range []bool{false, true} {
		t.Run(map[bool]string{false: "write failure", true: "post rename failure"}[postRename], func(t *testing.T) {
			svc := pendingRuleFixture(t, "source", "target")
			if err := svc.awgSaveErr(); err != nil {
				t.Fatal(err)
			}
			before := svc.snapshotAWGState()
			want := errors.New("isolated storage failure")
			calls := 0
			ops := deleteReplacementTestOps(svc)
			ops.persist = func(state *awgPersisted) error {
				calls++
				if calls == 1 {
					if postRename {
						if err := svc.store.SaveSecret(awgConfigFile, state); err != nil {
							t.Fatal(err)
						}
					}
					return want
				}
				return svc.store.SaveSecret(awgConfigFile, state)
			}
			ops.down = func(*awg.Manager) error { t.Fatal("storage failure changed runtime"); return nil }
			ops.start = ops.down
			err := runDeleteReplacement(t, svc, "source", "target", ops)
			var committed *DeleteServerCommittedError
			if !errors.Is(err, want) || errors.As(err, &committed) || !reflect.DeepEqual(svc.snapshotAWGState(), before) {
				t.Fatal("storage failure changed manager state or claimed a committed delete")
			}
			if !reflect.DeepEqual(reloadPendingRuleFixture(svc).snapshotAWGState(), before) {
				t.Fatal("storage failure lost the original connection after restart")
			}
		})
	}
}

func TestDeleteReplacementRealStorageFailureDoesNotDeleteConnection(t *testing.T) {
	svc := pendingRuleFixture(t, "source", "target")
	before := svc.snapshotAWGState()
	if err := os.Mkdir(svc.store.Path(awgConfigFile), 0700); err != nil {
		t.Fatal(err)
	}
	ops := deleteReplacementTestOps(svc)
	ops.down = func(*awg.Manager) error { t.Fatal("failed save stopped a tunnel"); return nil }
	if err := runDeleteReplacement(t, svc, "source", "target", ops); err == nil {
		t.Fatal("unwritable destination reported success")
	}
	if !reflect.DeepEqual(svc.snapshotAWGState(), before) {
		t.Fatal("failed save deleted an in-memory connection")
	}
}

func TestDeleteReplacementDistinguishesConfirmedAndUncertainFailedRollback(t *testing.T) {
	for _, diskState := range []string{"before", "candidate", "other"} {
		t.Run(diskState, func(t *testing.T) {
			svc := pendingRuleFixture(t, "source", "target")
			if err := svc.awgSaveErr(); err != nil {
				t.Fatal(err)
			}
			before := svc.snapshotAWGState()
			want := errors.New("isolated save/rollback failure")
			calls := 0
			ops := deleteReplacementTestOps(svc)
			ops.persist = func(state *awgPersisted) error {
				calls++
				if calls == 1 && diskState != "before" {
					toSave := state
					if diskState == "other" {
						toSave = &awgPersisted{}
					}
					if err := svc.store.SaveSecret(awgConfigFile, toSave); err != nil {
						t.Fatal(err)
					}
				}
				return want
			}
			err := runDeleteReplacement(t, svc, "source", "target", ops)
			var committed *DeleteServerCommittedError
			var uncertain *DeleteServerPersistenceUncertainError
			if !errors.Is(err, want) {
				t.Fatal("persistence failure was hidden")
			}
			switch diskState {
			case "before":
				if errors.As(err, &committed) || errors.As(err, &uncertain) || !reflect.DeepEqual(svc.snapshotAWGState(), before) {
					t.Fatal("confirmed original state was treated as committed/uncertain")
				}
			case "candidate":
				if !errors.As(err, &committed) || errors.As(err, &uncertain) || svc.servers["source"] != nil {
					t.Fatal("confirmed durable candidate was not published as committed")
				}
			case "other":
				if errors.As(err, &committed) || !errors.As(err, &uncertain) || !reflect.DeepEqual(svc.snapshotAWGState(), before) {
					t.Fatal("uncertain disk state was reported as a safe rejection or changed live managers")
				}
			}
		})
	}
}

func TestDeleteReplacementRuntimeFailureReportsCommittedAndKeepsMigratedRules(t *testing.T) {
	svc := pendingRuleFixture(t, "source", "target")
	rule := awg.Zone{TunnelID: "source", Domains: []string{"example.org"}, Enabled: true}
	if err := svc.awgSaveRoutingRules(svc.currentRoutingSettings().apply(awg.RoutingConfig{Zones: []awg.Zone{rule}})); err != nil {
		t.Fatal(err)
	}
	want := errors.New("isolated runtime failure")
	ops := deleteReplacementTestOps(svc)
	ops.apply = func() error { return want }
	err := runDeleteReplacement(t, svc, "source", "target", ops)
	var committed *DeleteServerCommittedError
	if !errors.As(err, &committed) || !errors.Is(err, want) {
		t.Fatal("committed runtime failure cannot be distinguished from a rejected deletion")
	}
	for _, state := range []*Service{svc, reloadPendingRuleFixture(svc)} {
		if state.servers["source"] != nil || len(state.awgRoutingRules()) != 1 || state.awgRoutingRules()[0].TunnelID != "target" || state.awgRoutingRules()[0].WaitingForConnection {
			t.Fatal("runtime failure lost the durably migrated rules")
		}
	}
}

func TestDeleteReplacementPreservesObservedPriorityWithLegacyTiesAndZeros(t *testing.T) {
	svc := pendingRuleFixture(t, "source", "other", "target")
	// Bypass the modern rules editor's unique-rank normalization to represent
	// saved legacy priorities: duplicate positives, a large positive, and zeros
	// whose public positions overlap that large positive after repartitioning.
	sourceRouting := svc.servers["source"].Manager.Config().Routing
	sourceRouting.Zones = []awg.Zone{
		{Name: "source legacy zero", TunnelID: "source", Order: 0, Route: "direct", Mode: "exclude", Domains: []string{"*"}, Enabled: true},
		{Name: "source tie first", TunnelID: "source", Order: 1, Route: "tunnel", Mode: "include", Domains: []string{"*"}, Enabled: true},
	}
	svc.servers["source"].Manager.SetRoutingState(sourceRouting, true)
	otherRouting := svc.servers["other"].Manager.Config().Routing
	otherRouting.Zones = []awg.Zone{
		{Name: "other tie second", TunnelID: "other", Order: 1, Route: "direct", Mode: "exclude", Domains: []string{"*"}, Enabled: true},
		{Name: "other legacy zero", TunnelID: "other", Order: 0, Route: "tunnel", Mode: "include", Domains: []string{"other.example"}, Enabled: false},
	}
	svc.servers["other"].Manager.SetRoutingState(otherRouting, true)
	targetRouting := svc.servers["target"].Manager.Config().Routing
	targetRouting.Zones = []awg.Zone{{Name: "large positive", TunnelID: "target", Order: 99, Route: "tunnel", Mode: "include", Domains: []string{"*"}, Enabled: true}}
	svc.servers["target"].Manager.SetRoutingState(targetRouting, true)
	svc.pendingRules = []awg.Zone{{Name: "pending zero", TunnelID: "historical", WaitingForConnection: true, Order: 0, Route: "tunnel", Mode: "include", Domains: []string{"waiting.example"}, FallbackTunnelIDs: []string{"historical-backup"}, Enabled: true}}
	want := svc.awgRoutingRules()
	for i := range want {
		want[i].Order = i + 1
		if want[i].TunnelID == "source" {
			want[i].TunnelID = "target"
		}
	}
	if want[0].Name != "source tie first" || want[1].Name != "other tie second" || want[2].Name != "large positive" {
		t.Fatal("legacy fixture did not expose the intended observed priority")
	}
	if err := runDeleteReplacement(t, svc, "source", "target", deleteReplacementTestOps(svc)); err != nil {
		t.Fatal(err)
	}
	for _, state := range []*Service{svc, reloadPendingRuleFixture(svc)} {
		if !reflect.DeepEqual(state.awgRoutingRules(), want) {
			t.Fatal("replacement changed observed global priority or rule criteria across repartition/restart")
		}
	}
}
