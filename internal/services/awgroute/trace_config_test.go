package awgroute

import (
	"reflect"
	"testing"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/store"
)

func TestTraceToggleUpdatesSharedPolicyAndAllConnectionMirrors(t *testing.T) {
	previousRecording := traceEnabled()
	defer traceSetEnabled(previousRecording)
	persist, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	primary := awg.Default()
	primary.Routing = sharedRoutingFixture()
	primary.Routing.TraceEnabled = false
	primary.Client.Enabled = true
	primary.Conn.Password = "fixture-primary"
	settings := routingSettingsFrom(primary.Routing)
	backup := awg.Default()
	backup.Install = "imported"
	backup.Conn = awg.Credentials{}
	backup.Endpoint = "192.0.2.22:2408"
	backup.MTU = 1280
	backup.Routing = settings.apply(backup.Routing)
	one := &managedServer{ID: "primary", Manager: awg.NewManager(primary)}
	two := &managedServer{ID: "backup", Manager: awg.NewManager(backup)}
	svc := &Service{
		store:    persist,
		activeID: "backup",
		order:    []string{"primary", "backup"},
		servers:  map[string]*managedServer{"primary": one, "backup": two},
		awg:      two.Manager,
		routing:  &settings,
	}
	beforePrimary := one.Manager.Config()
	beforeBackup := two.Manager.Config()
	for _, enabled := range []bool{true, false} {
		if svc.TraceSetEnabled(enabled) != enabled || traceEnabled() != enabled {
			t.Fatal("recording did not follow the toggle")
		}
		if svc.currentRoutingSettings().TraceEnabled != enabled || svc.globalRoutingConfig(svc.awgRoutingRules()).TraceEnabled != enabled {
			t.Fatal("shared routing view retained the previous trace setting")
		}
		for _, server := range svc.serverSnapshot() {
			if server.Manager.Config().Routing.TraceEnabled != enabled {
				t.Fatalf("%s retained a stale trace setting", server.ID)
			}
		}
		saved := svc.loadAWGState()
		if saved.Routing == nil || saved.Routing.TraceEnabled != enabled {
			t.Fatal("the shared trace setting was not persisted")
		}
	}
	afterPrimary := one.Manager.Config()
	afterBackup := two.Manager.Config()
	if beforePrimary.Routing.Active != afterPrimary.Routing.Active || beforeBackup.Routing.Active != afterBackup.Routing.Active || !reflect.DeepEqual(beforePrimary.Routing.Zones, afterPrimary.Routing.Zones) || !reflect.DeepEqual(beforeBackup.Routing.Zones, afterBackup.Routing.Zones) {
		t.Fatal("a trace toggle changed rule ownership or committed connection state")
	}
	if afterPrimary.Conn.Password != "fixture-primary" || afterBackup.Install != "imported" || afterBackup.Conn.Host != "" || afterBackup.MTU != 1280 {
		t.Fatal("a trace-only edit changed individual connection settings")
	}
}
