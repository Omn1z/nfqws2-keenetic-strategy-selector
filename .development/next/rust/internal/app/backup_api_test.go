package app

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/services/awgroute"
	"nfqws2strategy/internal/tools/backup"
	"nfqws2strategy/internal/tools/config"
	"nfqws2strategy/internal/tools/dns"
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
	if err := st.Save("dns.json", []dns.Server{}); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	if _, err := backup.Build([]string{cfg.DataDir}, &archive); err != nil {
		t.Fatal(err)
	}
	writeHistory("current.example.com")
	svc := awgroute.New(cfg, st)
	defer svc.CloseRoutingDiscoveries()
	a := &App{Cfg: cfg, store: st, awgroute: svc}
	a.initDNS()
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

func TestBackupRestoreReloadsLegacyDNSBeforeNextWrite(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.DataDir = st.Path("")
	a := &App{Cfg: cfg, store: st}
	a.initDNS()
	want := a.DNSServers()
	if len(want) < 2 {
		t.Fatal("invalid DNS defaults fixture")
	}
	var archive bytes.Buffer
	if _, _, err := a.BackupBuild(&archive); err != nil {
		t.Fatal(err)
	}
	if err := a.DeleteDNSServer(want[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.BackupRestore(bytes.NewReader(archive.Bytes())); err != nil {
		t.Fatal(err)
	}
	if got := a.DNSServers(); !reflect.DeepEqual(got, want) {
		t.Fatal("restore left the previous DNS list in memory")
	}
	updated := want[1]
	updated.Name = "updated after restore"
	if _, err := a.SaveDNSServer(updated); err != nil {
		t.Fatal(err)
	}
	var persisted []dns.Server
	if err := st.Load("dns.json", &persisted); err != nil {
		t.Fatal(err)
	}
	if len(persisted) != len(want) || persisted[0].ID != want[0].ID {
		t.Fatal("next write overwrote restored DNS with the previous list")
	}
}

func TestBackupRestoreReloadsAWGAfterLaterFileFails(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.DataDir = st.Path("")
	include := true
	zone := awg.Zone{Name: "restored rule", Domains: []string{"example.com"}, IncludeSubdomains: &include, Enabled: true, WaitingForConnection: true}
	writeAWG := func(name string) {
		t.Helper()
		next := zone
		next.Name = name
		if err := st.SaveSecret("awg.json", map[string]any{"servers": []any{}, "pending_rules": []awg.Zone{next}, "routing": map[string]any{"mode": "off"}}); err != nil {
			t.Fatal(err)
		}
	}
	writeAWG(zone.Name)
	if err := st.Save("dns.json", []dns.Server{}); err != nil {
		t.Fatal(err)
	}
	last := filepath.Join(cfg.DataDir, "zzz-last.json")
	if err := os.WriteFile(last, []byte("last member"), 0o600); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	if _, err := backup.Build([]string{cfg.DataDir}, &archive); err != nil {
		t.Fatal(err)
	}
	writeAWG("current rule")
	svc := awgroute.New(cfg, st)
	defer svc.CloseRoutingDiscoveries()
	a := &App{Cfg: cfg, store: st, awgroute: svc}
	a.initDNS()
	if err := os.Remove(last); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(last, 0o700); err != nil {
		t.Fatal(err)
	}
	// The final member cannot replace a directory. Earlier complete AWG/DNS
	// files have committed, so returning an error must still reload them.
	n, err := a.BackupRestore(bytes.NewReader(archive.Bytes()))
	if err == nil || n < 1 {
		t.Fatalf("partial commit not reported: %d %v", n, err)
	}
	rules := svc.AWG2DiscoveredRoutes().Rules
	if len(rules) != 1 || rules[0].Rule.Name != zone.Name {
		t.Fatal("callback failure left previous AWG configuration in memory")
	}
}
