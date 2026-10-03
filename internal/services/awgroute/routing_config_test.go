package awgroute

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"nfqws2strategy/internal/services/awg"
)

func sharedRoutingFixture() awg.RoutingConfig {
	includeSubdomains := true
	return awg.RoutingConfig{
		Mode:         "zones",
		MTU:          1392,
		Killswitch:   true,
		DomainSource: "dnsproxy",
		SNIRouting:   true,
		TraceEnabled: true,
		Active:       true,
		Zones: []awg.Zone{{
			Name:              "sites",
			TunnelID:          "primary",
			FallbackTunnelIDs: []string{"backup"},
			Domains:           []string{"example.org"},
			IncludeSubdomains: &includeSubdomains,
			Enabled:           true,
		}},
	}
}

func TestNormalizeAWGStateMigratesSharedPolicyFromCommittedConnection(t *testing.T) {
	primary := awg.Default()
	primary.Routing = sharedRoutingFixture()
	primary.Conn.Host = "primary.example"
	primary.Conn.Password = "primary-password"
	primary.MTU = 1360
	primary.Client.Enabled = true
	backup := awg.Default()
	backup.Conn.Host = "backup.example"
	backup.Conn.Password = "backup-password"
	backup.MTU = 1280
	st := normalizeAWGState(awgPersisted{
		ActiveID: "backup", // a newly added profile used to reset the routing form
		Servers: []awgPersistedServer{
			{ID: "primary", Config: *primary},
			{ID: "backup", Config: *backup},
		},
	})
	want := routingSettingsFrom(primary.Routing)
	if st.Routing == nil || *st.Routing != want {
		t.Fatalf("shared settings = %+v, want %+v", st.Routing, want)
	}
	for _, entry := range st.Servers {
		if got := routingSettingsFrom(entry.Config.Routing); got != want {
			t.Fatalf("%s settings = %+v, want %+v", entry.ID, got, want)
		}
	}
	if st.Servers[1].Config.Routing.Active || len(st.Servers[1].Config.Routing.Zones) != 0 {
		t.Fatal("a new connection must not inherit committed state or another connection's rules")
	}
	if st.Servers[0].Config.Conn.Password != "primary-password" || st.Servers[1].Config.Conn.Password != "backup-password" {
		t.Fatal("migration changed connection credentials")
	}
	if st.Servers[0].Config.MTU != 1360 || st.Servers[1].Config.MTU != 1280 {
		t.Fatal("migration changed tunnel MTU")
	}
	gotZone := st.Servers[0].Config.Routing.Zones[0]
	if gotZone.IncludeSubdomains == nil || !*gotZone.IncludeSubdomains || gotZone.TunnelID != "primary" || !reflect.DeepEqual(gotZone.FallbackTunnelIDs, []string{"backup"}) {
		t.Fatalf("migration lost rule fields: %+v", gotZone)
	}
}

func TestNormalizeAWGStateExplicitSharedOffOverridesLegacyConnectionSettings(t *testing.T) {
	profile := awg.Default()
	profile.Routing = sharedRoutingFixture()
	profile.Client.Enabled = true
	explicit := routingSettingsFrom(awg.RoutingConfig{Mode: "off", MTU: 1320, DomainSource: "resolve"})
	st := normalizeAWGState(awgPersisted{
		ActiveID: "primary",
		Routing:  &explicit,
		Servers:  []awgPersistedServer{{ID: "primary", Config: *profile}},
	})
	got := st.Servers[0].Config.Routing
	if routingSettingsFrom(got) != explicit {
		t.Fatalf("explicit shared policy was replaced by legacy data: %+v", got)
	}
	if len(got.Zones) != 1 || got.Zones[0].IncludeSubdomains == nil || !*got.Zones[0].IncludeSubdomains {
		t.Fatalf("disabling shared routing must preserve editable rules: %+v", got.Zones)
	}
	// The old committed bit belongs to the connection, but Mode=off makes it
	// inapplicable. It cannot override an explicit shared policy during reload.
	if awgShouldRestoreRouting(st.Servers[0].Config) {
		t.Fatal("an explicitly disabled shared policy must not restore routing")
	}
}

func TestNormalizeAWGStateMigratesLegacyExcludeBeforeSharingSettings(t *testing.T) {
	first := awg.Default()
	first.Routing.Mode = "exclude"
	first.Routing.Zones = []awg.Zone{{Name: "native", Domains: []string{"example.org"}, Enabled: true}}
	second := awg.Default()
	st := normalizeAWGState(awgPersisted{
		ActiveID: "second",
		Servers:  []awgPersistedServer{{ID: "first", Config: *first}, {ID: "second", Config: *second}},
	})
	if st.Routing.Mode != "zones" || st.Servers[0].Config.Routing.Zones[0].RouteValue() != "direct" {
		t.Fatalf("legacy exclude changed meaning during migration: %+v", st.Servers[0].Config.Routing)
	}
}

func TestRoutingSettingsExtractionDoesNotMutateOrPersistRuleState(t *testing.T) {
	rc := sharedRoutingFixture()
	rc.Mode = "exclude"
	rc.Zones[0].Mode = ""
	settings := routingSettingsFrom(rc)
	if rc.Zones[0].Mode != "" || rc.Mode != "exclude" {
		t.Fatal("settings extraction mutated the input rule snapshot")
	}
	b, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(b, &shape); err != nil {
		t.Fatal(err)
	}
	if len(shape) != 6 {
		t.Fatalf("shared settings must contain only the six router fields: %s", b)
	}
	for _, field := range []string{"zones", "active", "conn", "private_key", "endpoint"} {
		if _, present := shape[field]; present {
			t.Fatalf("connection/rule state leaked into shared policy: %s", b)
		}
	}
}

func TestGlobalRoutingConfigDoesNotDependOnSelectedConnection(t *testing.T) {
	primary := awg.Default()
	primary.Routing = sharedRoutingFixture()
	primary.Client.Enabled = true
	backup := awg.Default()
	settings := routingSettingsFrom(primary.Routing)
	backup.Routing = settings.apply(backup.Routing)
	one := &managedServer{ID: "primary", Manager: awg.NewManager(primary)}
	two := &managedServer{ID: "backup", Manager: awg.NewManager(backup)}
	svc := &Service{
		activeID: "backup",
		order:    []string{"primary", "backup"},
		servers:  map[string]*managedServer{"primary": one, "backup": two},
		awg:      two.Manager,
		routing:  &settings,
	}
	got := svc.globalRoutingConfig(svc.awgRoutingRules())
	if routingSettingsFrom(got) != settings || !got.Active || len(got.Zones) != 1 || got.Zones[0].IncludeSubdomains == nil || !*got.Zones[0].IncludeSubdomains {
		t.Fatalf("global routing view followed the empty selected profile: %+v", got)
	}
	one.Manager.SetEnabled(false)
	if svc.globalRoutingConfig(svc.awgRoutingRules()).Active {
		t.Fatal("a disabled connection must not make the shared policy active")
	}
}

func TestNormalizeAWGStatePreservesSubdomainPolicyTriState(t *testing.T) {
	on, off := true, false
	profile := awg.Default()
	profile.Routing.Zones = []awg.Zone{
		{Name: "legacy", Domains: []string{"legacy.example"}, Enabled: true},
		{Name: "suffix", Domains: []string{"suffix.example"}, IncludeSubdomains: &on, Enabled: true},
		{Name: "exact", Domains: []string{"exact.example"}, IncludeSubdomains: &off, Enabled: true},
	}
	state := normalizeAWGState(awgPersisted{ActiveID: "one", Servers: []awgPersistedServer{{ID: "one", Config: *profile}}})
	b, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	var reloaded awgPersisted
	if err := json.Unmarshal(b, &reloaded); err != nil {
		t.Fatal(err)
	}
	reloaded = normalizeAWGState(reloaded)
	zones := reloaded.Servers[0].Config.Routing.Zones
	if zones[0].IncludeSubdomains != nil || zones[1].IncludeSubdomains == nil || !*zones[1].IncludeSubdomains || zones[2].IncludeSubdomains == nil || *zones[2].IncludeSubdomains {
		t.Fatalf("migration/JSON lost nil/true/false subdomain policies: %+v", zones)
	}
}

func TestNormalizeAWGStateDoesNotActivateOffLegacyProfileWithStaleCommit(t *testing.T) {
	primary := awg.Default()
	primary.Routing = sharedRoutingFixture()
	primary.Client.Enabled = true
	selected := awg.Default()
	selected.Routing.Active = true // stale legacy state: its Mode is still off
	selected.Client.Enabled = true
	st := normalizeAWGState(awgPersisted{
		ActiveID: "empty",
		Servers:  []awgPersistedServer{{ID: "primary", Config: *primary}, {ID: "empty", Config: *selected}},
	})
	if *st.Routing != routingSettingsFrom(primary.Routing) {
		t.Fatalf("a stale off-profile commit replaced the working global policy: %+v", st.Routing)
	}
	if st.Servers[1].Config.Routing.Active {
		t.Fatal("migration activated a profile whose routing had been disabled")
	}
}

// This opt-in check reads a local backup without logging any connection
// secrets or copying that backup into the repository. Normal test runs skip it.
func TestNormalizeAWGStateRouterBackupPreservesConnectionAndRuleOwnership(t *testing.T) {
	backupPath := os.Getenv("N2S_AWG_BACKUP_PATH")
	if backupPath == "" {
		t.Skip("set N2S_AWG_BACKUP_PATH to a local awg.json backup")
	}
	raw, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal("could not read the configured local AWG backup")
	}
	var original, candidate awgPersisted
	if json.Unmarshal(raw, &original) != nil || json.Unmarshal(raw, &candidate) != nil {
		t.Fatal("the configured AWG backup is not a valid multi-connection state")
	}
	if len(original.Servers) == 0 {
		t.Fatal("the configured AWG backup has no connections")
	}
	normalized := normalizeAWGState(candidate)
	want := legacyRoutingSettings(original.Servers, original.ActiveID)
	if original.Routing != nil {
		want = routingSettingsFrom(original.Routing.apply(awg.RoutingConfig{}))
	}
	if normalized.ActiveID != original.ActiveID || len(normalized.Servers) != len(original.Servers) || normalized.Routing == nil || *normalized.Routing != want {
		t.Fatal("migration changed the selected connection, connection count, or expected shared policy")
	}
	assertOriginalConnections := func(state awgPersisted) {
		t.Helper()
		for _, before := range original.Servers {
			var after *awgPersistedServer
			for i := range state.Servers {
				if state.Servers[i].ID == before.ID {
					after = &state.Servers[i]
					break
				}
			}
			if after == nil {
				t.Fatalf("connection %s disappeared during normalization", before.ID)
			}
			expected := before.Config
			repairImportedInstallMarker(&expected)
			expected.Normalize()
			if expected.Routing.Mode == "off" {
				expected.Routing.Active = false
			}
			expected.Routing = want.apply(expected.Routing)
			if before.Name != after.Name || !reflect.DeepEqual(expected, after.Config) || !reflect.DeepEqual(before.AppliedConfig, after.AppliedConfig) {
				t.Fatalf("connection %s changed individual settings, committed state, or rule ownership", before.ID)
			}
		}
	}
	assertOriginalConnections(normalized)
	// Model the persisted shape of adding/selecting a blank profile. This
	// validates migration independently of router filesystem/runtime effects.
	blankID := "validation-blank-profile"
	for _, server := range normalized.Servers {
		if server.ID == blankID {
			t.Fatal("the reserved validation profile ID is already present")
		}
	}
	blank := awg.Default()
	blank.Routing = want.apply(blank.Routing)
	added := normalized
	added.Servers = append(append([]awgPersistedServer(nil), normalized.Servers...), awgPersistedServer{ID: blankID, Config: *blank})
	added.ActiveID = blankID
	added = normalizeAWGState(added)
	if added.Routing == nil || *added.Routing != want || added.ActiveID != blankID || len(added.Servers) != len(original.Servers)+1 {
		t.Fatal("adding a blank profile replaced the existing shared routing policy")
	}
	newConfig := added.Servers[len(added.Servers)-1].Config
	if newConfig.Routing.Active || len(newConfig.Routing.Zones) != 0 || newConfig.Conn.Host != "" || newConfig.Conn.Password != "" || newConfig.Conn.KeyPEM != "" || newConfig.Endpoint != "" || newConfig.PrivateKey != "" {
		t.Fatal("the blank profile inherited committed rules or connection secrets")
	}
	assertOriginalConnections(added)
	removed := added
	removed.Servers = append([]awgPersistedServer(nil), added.Servers[:len(added.Servers)-1]...)
	removed.ActiveID = original.ActiveID
	removed = normalizeAWGState(removed)
	if removed.Routing == nil || *removed.Routing != want || len(removed.Servers) != len(original.Servers) {
		t.Fatal("deleting a blank profile replaced the shared routing policy")
	}
	assertOriginalConnections(removed)
}
