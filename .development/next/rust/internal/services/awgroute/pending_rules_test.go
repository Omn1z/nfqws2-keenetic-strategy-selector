package awgroute

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/store"
)

func pendingRuleFixture(t *testing.T, ids ...string) *Service {
	t.Helper()
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	settings := routingSettingsFrom(sharedRoutingFixture())
	state := awgPersisted{Routing: &settings}
	for i, id := range ids {
		cfg := awg.Default()
		cfg.Install = "imported"
		cfg.Protocol = "awg"
		cfg.Endpoint = id + ".example:443"
		public := make([]byte, 32)
		public[0] = byte(i + 1)
		cfg.PublicKey = base64.StdEncoding.EncodeToString(public)
		cfg.PrivateKey = "secret-private-" + id
		cfg.Conn.Password = "secret-ssh-password-" + id
		cfg.Conn.KeyPEM = "secret-ssh-key-" + id
		cfg.Peers = []awg.Peer{{ID: "router", Name: "Router", IsRouter: true, PublicKey: "client-public-" + id, PrivateKey: "secret-client-" + id, PSK: "secret-psk-" + id}}
		cfg.ClientIface = "awg" + string(rune('0'+i))
		cfg.Client.Enabled = true
		cfg.Routing = settings.apply(cfg.Routing)
		cfg.Routing.Active = true
		state.Servers = append(state.Servers, awgPersistedServer{ID: id, Name: "Label " + id, Config: *cfg})
	}
	if len(ids) > 0 {
		state.ActiveID = ids[0]
	}
	svc := &Service{store: st}
	svc.installAWGState(state)
	return svc
}

func deletePendingRuleFixture(t *testing.T, svc *Service, id string, applyErr error) {
	t.Helper()
	_, unlock := svc.lockClientOps(false)
	defer unlock()
	err := svc.awgDeleteServerWithOps(id, func() error { return nil }, func(*awg.Manager) error { return nil }, func() error { return applyErr })
	if applyErr != nil {
		if !errors.Is(err, applyErr) {
			t.Fatal("deletion hid the routing installation error")
		}
	} else if err != nil {
		t.Fatal(err)
	}
}

func reloadPendingRuleFixture(svc *Service) *Service {
	reloaded := &Service{store: svc.store}
	reloaded.installAWGState(reloaded.loadAWGState())
	return reloaded
}

func TestDeleteConnectionRetainsRulesOrderFallbacksAndSecretsOfRemainingProfile(t *testing.T) {
	svc := pendingRuleFixture(t, "primary", "backup")
	on, off := true, false
	rules := []awg.Zone{
		{Name: "primary enabled", TunnelID: "primary", FallbackTunnelIDs: []string{"backup"}, Order: 1, Route: "tunnel", Mode: "include", Domains: []string{"example.org", "list:sites"}, IncludeSubdomains: &on, IPs: []string{"203.0.113.9/32"}, SourceIPs: []string{"192.168.3.10/32"}, Enabled: true},
		{Name: "backup enabled", TunnelID: "backup", FallbackTunnelIDs: []string{"primary"}, Order: 2, Route: "tunnel", Mode: "include", Domains: []string{"backup.example"}, IPs: []string{}, SourceIPs: []string{}, Enabled: true},
		{Name: "primary disabled exact", TunnelID: "primary", Order: 3, Route: "direct", Mode: "exclude", Domains: []string{"exact.example"}, IncludeSubdomains: &off, IPs: []string{}, SourceIPs: []string{}, Enabled: false},
	}
	if err := svc.awgSaveRoutingRules(svc.currentRoutingSettings().apply(awg.RoutingConfig{Zones: rules})); err != nil {
		t.Fatal(err)
	}
	before := svc.awgRoutingRules()
	remainingBefore := svc.servers["backup"].Manager.Config()
	wantRef := awgConnectionReference(svc.servers["primary"])
	applyFailure := errors.New("isolated apply failure")
	deletePendingRuleFixture(t, svc, "primary", applyFailure)
	reloaded := reloadPendingRuleFixture(svc)
	for _, state := range []*Service{svc, reloaded} {
		want := cloneAWGZones(before)
		want[0].WaitingForConnection, want[2].WaitingForConnection = true, true
		if !reflect.DeepEqual(state.awgRoutingRules(), want) || len(state.pendingRules) != 2 {
			t.Fatal("deleting/reloading changed rule content, priority, enabled state, subdomain policy or fallback order")
		}
		if !reflect.DeepEqual(state.servers["backup"].Manager.Config(), remainingBefore) {
			t.Fatal("deleting another connection changed the remaining profile's keys, connection settings or rules")
		}
		if state.connectionRefSnapshot()["primary"] != wantRef {
			t.Fatal("the deleted connection's public identity did not survive restart")
		}
		metadata, err := json.Marshal(state.connectionRefSnapshot())
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"secret-private-", "secret-ssh-", "secret-client-", "secret-psk-", "private_key", "key_pem", "password", "preshared"} {
			if strings.Contains(string(metadata), forbidden) {
				t.Fatal("a retained public connection reference contains secret material")
			}
		}
	}
	raw, err := os.ReadFile(svc.store.Path(awgConfigFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret-private-primary") || strings.Contains(string(raw), "secret-client-primary") || strings.Contains(string(raw), "secret-psk-primary") {
		t.Fatal("deleting a profile retained its private tunnel identity in persisted metadata")
	}
	// Explicit reassignment resumes only the chosen rules; it keeps their
	// content and does not resurrect the deleted manager or private keys.
	reassigned := reloaded.awgRoutingRules()
	for i := range reassigned {
		if reassigned[i].WaitingForConnection {
			reassigned[i].TunnelID = "backup"
			reassigned[i].WaitingForConnection = false
		}
	}
	if err := reloaded.awgSaveRoutingRules(reloaded.currentRoutingSettings().apply(awg.RoutingConfig{Zones: reassigned})); err != nil {
		t.Fatal(err)
	}
	if len(reloaded.pendingRules) != 0 || reloaded.servers["primary"] != nil || len(reloaded.awgRoutingRules()) != 3 {
		t.Fatal("explicit reassignment lost rules or restored the removed connection")
	}
	if reloaded.connectionRefs["primary"].Ref == "" {
		t.Fatal("reassignment removed an identity still referenced as a fallback")
	}
}

func TestDeleteLastLegacyConnectionKeepsWaitingRulesAndHistoricalIdentity(t *testing.T) {
	svc := pendingRuleFixture(t, "awg0")
	rule := awg.Zone{Name: "all", TunnelID: "awg0", Route: "tunnel", Domains: []string{"*"}, IPs: []string{}, SourceIPs: []string{}, Enabled: true}
	if err := svc.awgSaveRoutingRules(svc.currentRoutingSettings().apply(awg.RoutingConfig{Zones: []awg.Zone{rule}})); err != nil {
		t.Fatal(err)
	}
	wantRef := awgConnectionReference(svc.servers["awg0"])
	if wantRef.ServerPublicKey == "" || len(wantRef.Fingerprint) != 32 {
		t.Fatal("fixture did not create a complete public connection identity")
	}
	wantSettings := svc.currentRoutingSettings()
	deletePendingRuleFixture(t, svc, "awg0", nil)
	for _, state := range []*Service{svc, reloadPendingRuleFixture(svc)} {
		if len(state.servers) != 1 || state.activeServerID() == "awg0" || state.currentRoutingSettings() != wantSettings {
			t.Fatal("delete-last reused the old identity or reset shared settings")
		}
		got := state.awgRoutingRules()
		if len(got) != 1 || !got[0].WaitingForConnection || got[0].TunnelID != "awg0" || !got[0].Enabled || got[0].Domains[0] != "*" {
			t.Fatal("delete-last discarded or automatically reassigned the waiting rule")
		}
		if state.connectionRefSnapshot()["awg0"] != wantRef || state.globalRoutingConfig(got).Active {
			t.Fatal("a blank replacement overwrote the historical descriptor or activated a waiting rule")
		}
		exported, err := state.AWG2ExportRoutingRules(nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(exported.Connections) != 1 || exported.Connections[0] != wantRef || len(exported.Routing.Zones) != 1 || !exported.Routing.Zones[0].WaitingForConnection {
			t.Fatal("export after deletion/restart lost the waiting rule or deleted connection's public identity")
		}
	}
}

func TestPendingRulesStayDetachedAcrossSaveSelectionAndIdentityReuse(t *testing.T) {
	svc := pendingRuleFixture(t, "available")
	rule := awg.Zone{Name: "waiting", TunnelID: "available", WaitingForConnection: true, Domains: []string{"waiting.example"}, FallbackTunnelIDs: []string{"unknown-backup"}, Enabled: false}
	if err := svc.awgSaveRoutingRules(svc.currentRoutingSettings().apply(awg.RoutingConfig{Zones: []awg.Zone{rule}})); err != nil {
		t.Fatal(err)
	}
	if err := svc.AWG2SelectServer("available"); err != nil {
		t.Fatal(err)
	}
	state := reloadPendingRuleFixture(svc)
	got := state.awgRoutingRules()
	if len(got) != 1 || !got[0].WaitingForConnection || got[0].TunnelID != "available" || got[0].Enabled || len(state.servers["available"].Manager.Config().Routing.Zones) != 0 || state.globalRoutingConfig(got).Active {
		t.Fatal("an existing/selected same-ID profile automatically adopted a waiting rule")
	}
	// An explicit blank waiting selection differs from legacy empty TunnelID.
	got[0].TunnelID = ""
	if err := state.awgSaveRoutingRules(state.currentRoutingSettings().apply(awg.RoutingConfig{Zones: got})); err != nil {
		t.Fatal(err)
	}
	if state.awgRoutingRules()[0].TunnelID != "" || !state.awgRoutingRules()[0].WaitingForConnection {
		t.Fatal("saving an explicit waiting selection assigned the default profile")
	}
}

func TestPendingUnknownActivePrimaryFailsBeforeAnyPolicyMutation(t *testing.T) {
	svc := pendingRuleFixture(t, "available")
	before, err := json.Marshal(svc.snapshotAWGState())
	if err != nil {
		t.Fatal(err)
	}
	ref := AWG2ConnectionRef{Ref: "detached", Label: "Imported"}
	err = svc.awgSaveRoutingRulesWithRefs(awg.RoutingConfig{Mode: "off", Zones: []awg.Zone{{TunnelID: "missing", Domains: []string{"site.example"}, Enabled: true}}}, map[string]AWG2ConnectionRef{"detached": ref})
	if err == nil {
		t.Fatal("an unknown active primary was accepted without explicit waiting")
	}
	after, err := json.Marshal(svc.snapshotAWGState())
	if err != nil || string(after) != string(before) {
		t.Fatal("validation failure changed profiles, shared settings, pending rules or retained references")
	}
}

func TestPendingDiskSaveFailureDoesNotPublishAnyPolicyMutation(t *testing.T) {
	svc := pendingRuleFixture(t, "available")
	before, err := json.Marshal(svc.snapshotAWGState())
	if err != nil {
		t.Fatal(err)
	}
	revision := svc.zonesRevision.Load()
	// Make the config path's parent a regular file. This deterministically
	// fails atomic persistence without invoking host networking or permissions.
	// Store's directory is private; obtaining a Store for the parent before
	// replacing it with a file produces the same impossible path safely.
	parent := filepath.Join(t.TempDir(), "parent")
	st, err := store.New(parent)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(parent); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(parent, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc.store = st
	refs := map[string]AWG2ConnectionRef{"detached": {Ref: "detached", Label: "Detached"}}
	err = svc.awgSaveRoutingRulesWithRefs(awg.RoutingConfig{Mode: "off", Zones: []awg.Zone{{TunnelID: "detached", WaitingForConnection: true, Domains: []string{"site.example"}, Enabled: true}}}, refs)
	if err == nil {
		t.Fatal("an impossible config path reported a successful save")
	}
	after, err := json.Marshal(svc.snapshotAWGState())
	if err != nil || string(after) != string(before) || svc.zonesRevision.Load() != revision {
		t.Fatal("a disk failure published uncommitted profiles, settings, pending rules, references or revision")
	}
}

func TestPendingLegacyMigrationDistinguishesEmptyFromMissingPrimary(t *testing.T) {
	on, off := true, false
	cfg := awg.Default()
	cfg.Routing = awg.RoutingConfig{Mode: "exclude", Zones: []awg.Zone{
		{Name: "legacy owner", Domains: []string{"legacy.example"}, Enabled: true},
		{Name: "missing primary", TunnelID: "deleted", Domains: []string{"deleted.example"}, IncludeSubdomains: &off, FallbackTunnelIDs: []string{"backup-gone"}, Order: 7, Enabled: false},
		{Name: "explicit wait", TunnelID: "owner", WaitingForConnection: true, Domains: []string{"wait.example"}, IncludeSubdomains: &on, Order: 8, Enabled: true},
	}}
	state := normalizeAWGState(awgPersisted{ActiveID: "owner", Servers: []awgPersistedServer{{ID: "owner", Config: *cfg}}})
	if len(state.Servers[0].Config.Routing.Zones) != 1 || state.Servers[0].Config.Routing.Zones[0].TunnelID != "" || state.Servers[0].Config.Routing.Zones[0].RouteValue() != "direct" {
		t.Fatal("legacy empty TunnelID stopped belonging to its original manager")
	}
	if len(state.PendingRules) != 2 || state.PendingRules[0].TunnelID != "deleted" || !state.PendingRules[0].WaitingForConnection || state.PendingRules[0].Enabled || state.PendingRules[0].Order != 7 || *state.PendingRules[0].IncludeSubdomains || !*state.PendingRules[1].IncludeSubdomains {
		t.Fatal("migration did not retain missing/explicit-wait rule state")
	}
	if state.ConnectionRefs["deleted"].Ref != "deleted" || state.ConnectionRefs["backup-gone"].Fingerprint != "" {
		t.Fatal("legacy missing connection references became an automatic identity match")
	}
	state.Servers = nil
	state.PendingRules[0].TunnelID = "awg0"
	state = normalizeAWGState(state)
	if len(state.PendingRules) != 2 || state.Servers[0].ID == "awg0" {
		t.Fatal("empty-server normalization lost waiting rules or reused their historical ID")
	}
}

func TestPendingReferenceGarbageCollectionKeepsOnlyReferencedDeletedConnections(t *testing.T) {
	svc := pendingRuleFixture(t, "primary", "backup")
	rule := awg.Zone{Name: "primary", TunnelID: "primary", FallbackTunnelIDs: []string{"backup"}, Domains: []string{"example.org"}, Enabled: true}
	if err := svc.awgSaveRoutingRules(svc.currentRoutingSettings().apply(awg.RoutingConfig{Zones: []awg.Zone{rule}})); err != nil {
		t.Fatal(err)
	}
	deletePendingRuleFixture(t, svc, "primary", nil)
	if svc.connectionRefs["primary"].Ref == "" {
		t.Fatal("garbage collection removed a waiting rule's primary identity")
	}
	if err := svc.awgSaveRoutingRules(svc.currentRoutingSettings().apply(awg.RoutingConfig{})); err != nil {
		t.Fatal(err)
	}
	if len(svc.connectionRefs) != 0 || len(reloadPendingRuleFixture(svc).connectionRefs) != 0 {
		t.Fatal("unreferenced deleted metadata accumulated after its rules were removed")
	}
}

func TestPendingSnapshotsDoNotShareMutableRuleOrReferenceState(t *testing.T) {
	svc := pendingRuleFixture(t, "primary", "backup")
	on := true
	rule := awg.Zone{TunnelID: "primary", Domains: []string{"example.org"}, IncludeSubdomains: &on, FallbackTunnelIDs: []string{"backup"}, Enabled: true}
	if err := svc.awgSaveRoutingRules(svc.currentRoutingSettings().apply(awg.RoutingConfig{Zones: []awg.Zone{rule}})); err != nil {
		t.Fatal(err)
	}
	deletePendingRuleFixture(t, svc, "primary", nil)
	snapshot := svc.snapshotAWGState()
	snapshot.PendingRules[0].Domains[0] = "other.example"
	*snapshot.PendingRules[0].IncludeSubdomains = false
	snapshot.PendingRules[0].FallbackTunnelIDs[0] = "other"
	ref := snapshot.ConnectionRefs["primary"]
	ref.Label = "Changed"
	snapshot.ConnectionRefs["primary"] = ref
	got := svc.awgRoutingRules()[0]
	if got.Domains[0] != "example.org" || !*got.IncludeSubdomains || got.FallbackTunnelIDs[0] != "backup" || svc.connectionRefs["primary"].Label == "Changed" {
		t.Fatal("a snapshot mutation changed retained rules or connection identity")
	}
}

func TestPendingPrimaryDeletionDoesNotPromoteBackupToLegacyFullOwner(t *testing.T) {
	for _, mode := range []string{"zones", "full"} {
		t.Run(mode, func(t *testing.T) {
			svc := pendingRuleFixture(t, "primary", "backup")
			rule := awg.Zone{TunnelID: "primary", FallbackTunnelIDs: []string{"backup"}, Route: "tunnel", Domains: []string{"example.org"}, Enabled: true}
			rc := svc.currentRoutingSettings().apply(awg.RoutingConfig{Zones: []awg.Zone{rule}})
			rc.Mode = mode
			if err := svc.awgSaveRoutingRules(rc); err != nil {
				t.Fatal(err)
			}
			if !svc.servers["backup"].Manager.Config().Routing.Active {
				t.Fatal("fixture backup was not committed for fallback")
			}
			deletePendingRuleFixture(t, svc, "primary", nil)
			state := reloadPendingRuleFixture(svc)
			if awgShouldRestoreRouting(state.servers["backup"].Manager.RuntimeConfig()) || state.globalRoutingConfig(state.awgRoutingRules()).Active {
				t.Fatal("a waiting primary automatically promoted its former backup to an active/full-mode route")
			}
		})
	}
}
