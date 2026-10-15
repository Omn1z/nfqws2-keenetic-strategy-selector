package app

import (
	"bytes"
	"errors"
	"os"
	"reflect"
	"testing"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/services/awgroute"
	"nfqws2strategy/internal/tools/backup"
	"nfqws2strategy/internal/tools/config"
	"nfqws2strategy/internal/tools/store"
)

func TestBackupRestoreReloadsAWGHistoryWithoutApplyingRouting(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.DataDir = st.Path("")
	include := true
	zone := awg.Zone{Name: "waiting", Domains: []string{"example.com"}, IncludeSubdomains: &include, Enabled: true, WaitingForConnection: true}
	// A detached rule does not start any tunnel or configure host routing.
	if err := st.SaveSecret("awg.json", map[string]any{
		"servers": []any{}, "pending_rules": []awg.Zone{zone}, "routing": map[string]any{"mode": "off"},
	}); err != nil {
		t.Fatal(err)
	}
	writeHistory := func(domain string) {
		t.Helper()
		if err := st.SaveSecret("awg-routing-learned.json", map[string]any{
			"version": 1,
			"entries": []map[string]any{{
				"rule_key": awgroute.AWGRoutingLearnedRuleKey(zone), "domain": domain,
				"ips": []string{"192.0.2.10"}, "source_ips": []string{}, "source": "dns",
				"first_seen": 1000, "last_seen": 1001, "additional": true,
			}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	writeHistory("restored.example.com")
	var archive bytes.Buffer
	if _, err := backup.Build([]string{cfg.DataDir}, &archive); err != nil {
		t.Fatal(err)
	}
	writeHistory("current.example.com")
	svc := awgroute.New(cfg, st)
	defer svc.CloseRoutingDiscoveries()
	a := &App{Cfg: cfg, store: st, awgroute: svc}
	before := svc.AWG2DiscoveredRoutes()
	if len(before.Rules) != 1 || len(before.Rules[0].Entries) != 1 || before.Rules[0].Entries[0].Domain != "current.example.com" {
		t.Fatalf("invalid pre-restore fixture: %+v", before)
	}
	if _, err := a.BackupRestore(bytes.NewReader(archive.Bytes())); err != nil {
		t.Fatal(err)
	}
	after := svc.AWG2DiscoveredRoutes()
	if len(after.Rules) != 1 || len(after.Rules[0].Entries) != 1 || after.Rules[0].Entries[0].Domain != "restored.example.com" || after.Rules[0].Entries[0].Confirmed {
		t.Fatalf("backup restore did not replace in-memory history: %+v", after)
	}
	if before.Revision != after.Revision || before.Active != after.Active || !reflect.DeepEqual(before.Rules[0].Rule, after.Rules[0].Rule) {
		t.Fatal("restoring history applied or changed the running routing policy")
	}
	wire, err := os.ReadFile(st.Path("awg-routing-learned.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.BackupRestore(bytes.NewReader([]byte("invalid backup"))); !errors.Is(err, backup.ErrNotBackup) {
		t.Fatalf("malformed archive failure lost: %v", err)
	}
	if failed := svc.AWG2DiscoveredRoutes(); !reflect.DeepEqual(after, failed) {
		t.Fatal("failed restore replaced current observations")
	}
	svc.CloseRoutingDiscoveries()
	persisted, err := os.ReadFile(st.Path("awg-routing-learned.json"))
	if err != nil || !bytes.Equal(wire, persisted) {
		t.Fatalf("shutdown overwrote restored history: %s %v", persisted, err)
	}
}
