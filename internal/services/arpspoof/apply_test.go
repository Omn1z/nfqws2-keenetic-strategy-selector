package arpspoof

import (
	"errors"
	"os"
	"reflect"
	"testing"

	"nfqws2strategy/internal/tools/config"
	"nfqws2strategy/internal/tools/store"
)

const testFakeMAC = "64:6E:EA:F1:7B:EF"

type macFixture struct {
	s       *Service
	ops     macOperations
	targets []string
	states  map[string]macState
	writes  []string
	ann     []string
	fail    string
}

func newMACFixture(t *testing.T) *macFixture {
	t.Helper()
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := &macFixture{
		s:       New(&config.Config{}, st),
		targets: []string{"br0"},
		states: map[string]macState{
			"br0": {MAC: "50:FF:20:DD:5A:75"},
			"br2": {MAC: "52:FF:20:DD:5A:73"},
		},
	}
	f.s.config = Config{Enabled: true, MAC: testFakeMAC}
	f.ops = macOperations{
		targets: func(Config) ([]string, error) { return f.targets, nil },
		read: func(name string) (macState, error) {
			state, ok := f.states[name]
			if !ok {
				return macState{}, os.ErrNotExist
			}
			return state, nil
		},
		write: func(name, mac string) error {
			// A process crash after this point must not lose recovery data.
			var persisted state
			if err := st.Load(stateFile, &persisted); err != nil || persisted.OriginalMACs[name] == "" {
				t.Fatalf("network mutation without durable original for %s: %v %+v", name, err, persisted)
			}
			f.writes = append(f.writes, name+"="+mac)
			if f.fail == name {
				f.fail = ""
				return errors.New("simulated adapter failure")
			}
			f.states[name] = macState{MAC: mac}
			return nil
		},
		announce: func(name string, _ bool) { f.ann = append(f.ann, name) },
	}
	return f
}

func TestAUTONeverFallsBackToWAN(t *testing.T) {
	for _, interfaces := range [][]Interface{
		{{Name: "eth3", Up: true}},
		{{Name: "br0", Up: false}, {Name: "eth3", Up: true}},
		{{Name: "br-wan", Up: true}, {Name: "wlan0", Up: true}},
	} {
		if got := suggestedInterfaceNames(interfaces); len(got) != 0 {
			t.Fatalf("AUTO selected ineligible interface: %v", got)
		}
	}
}

func TestMACApplyRefreshAndRestore(t *testing.T) {
	f := newMACFixture(t)
	if err := f.s.applyMACConfig(f.s.config, true, f.ops); err != nil {
		t.Fatal(err)
	}
	if f.states["br0"].MAC != testFakeMAC || len(f.writes) != 1 || len(f.ann) != 1 {
		t.Fatalf("apply: %+v %+v", f.writes, f.ann)
	}
	if err := f.s.applyMACConfig(f.s.config, false, f.ops); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 1 || len(f.ann) != 1 {
		t.Fatal("unchanged refresh generated network traffic")
	}
	f.s.config.Enabled = false
	if err := f.s.applyMACConfig(f.s.config, true, f.ops); err != nil {
		t.Fatal(err)
	}
	if f.states["br0"].MAC != "50:FF:20:DD:5A:75" || len(f.writes) != 2 || len(f.ann) != 2 {
		t.Fatalf("restore must announce original MAC: %+v %+v", f.writes, f.ann)
	}
	var saved state
	if err := f.s.store.Load(stateFile, &saved); err != nil || len(saved.OriginalMACs) != 0 {
		t.Fatalf("recovery journal not cleared after restore: %+v %v", saved, err)
	}
}

func TestMACRestoreRemovedTarget(t *testing.T) {
	f := newMACFixture(t)
	if err := f.s.applyMACConfig(f.s.config, true, f.ops); err != nil {
		t.Fatal(err)
	}
	f.targets = []string{"br2"}
	if err := f.s.applyMACConfig(f.s.config, false, f.ops); err != nil {
		t.Fatal(err)
	}
	if f.states["br0"].MAC != "50:FF:20:DD:5A:75" || f.states["br2"].MAC != testFakeMAC {
		t.Fatalf("removed target was not restored: %+v", f.states)
	}
	if !reflect.DeepEqual(f.s.origMACs, map[string]string{"br2": "52:FF:20:DD:5A:73"}) {
		t.Fatalf("wrong recovery state: %+v", f.s.origMACs)
	}
}

func TestMACRefreshPersistsNewBridgeForRestart(t *testing.T) {
	f := newMACFixture(t)
	if err := f.s.applyMACConfig(f.s.config, true, f.ops); err != nil {
		t.Fatal(err)
	}
	f.targets = []string{"br0", "br2"}
	if err := f.s.applyMACConfig(f.s.config, false, f.ops); err != nil {
		t.Fatal(err)
	}
	restarted := New(&config.Config{}, f.s.store)
	restarted.config.Enabled = false
	if err := restarted.applyMACConfig(restarted.config, true, f.ops); err != nil {
		t.Fatal(err)
	}
	if f.states["br0"].MAC != "50:FF:20:DD:5A:75" || f.states["br2"].MAC != "52:FF:20:DD:5A:73" {
		t.Fatalf("restart lost originals: %+v", f.states)
	}
}

func TestMACRollbackPartialFailure(t *testing.T) {
	f := newMACFixture(t)
	f.targets = []string{"br0", "br2"}
	f.fail = "br2"
	if err := f.s.applyMACConfig(f.s.config, true, f.ops); err == nil {
		t.Fatal("expected adapter failure")
	}
	if f.states["br0"].MAC != "50:FF:20:DD:5A:75" || f.states["br2"].MAC != "52:FF:20:DD:5A:73" {
		t.Fatalf("partial apply did not roll back: %+v", f.states)
	}
	if !reflect.DeepEqual(f.ann, []string{"br0", "br2", "br0"}) {
		t.Fatalf("rollback must announce restored MACs: %v", f.ann)
	}
}

func TestMACJournalFailurePreventsNetworkMutation(t *testing.T) {
	f := newMACFixture(t)
	if err := os.Mkdir(f.s.store.Path(stateFile), 0700); err != nil {
		t.Fatal(err)
	}
	if err := f.s.applyMACConfig(f.s.config, true, f.ops); err == nil {
		t.Fatal("expected store failure")
	}
	if len(f.writes) != 0 || len(f.s.origMACs) != 0 {
		t.Fatalf("mutated before durable recovery state: %+v %+v", f.writes, f.s.origMACs)
	}
}

func TestMACPreflightAvoidsPartialChanges(t *testing.T) {
	f := newMACFixture(t)
	f.targets = []string{"br0", "br999"}
	if err := f.s.applyMACConfig(f.s.config, true, f.ops); err == nil {
		t.Fatal("expected missing bridge error")
	}
	if len(f.writes) != 0 || len(f.s.origMACs) != 0 {
		t.Fatal("preflight failure mutated an interface or recovery state")
	}
}

func TestMACRepairNativeMismatch(t *testing.T) {
	f := newMACFixture(t)
	if err := f.s.applyMACConfig(f.s.config, true, f.ops); err != nil {
		t.Fatal(err)
	}
	f.states["br0"] = macState{MAC: testFakeMAC, Inconsistent: true}
	if err := f.s.applyMACConfig(f.s.config, true, f.ops); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 2 || f.states["br0"].Inconsistent {
		t.Fatal("matching MAC skipped required native cache synchronization")
	}
}

func TestMACUnknownOriginalDoesNotInventRecovery(t *testing.T) {
	f := newMACFixture(t)
	f.targets = []string{"br0", "br2"}
	f.states["br2"] = macState{MAC: testFakeMAC}
	if err := f.s.applyMACConfig(f.s.config, true, f.ops); err == nil {
		t.Fatal("expected unknown original error")
	}
	if len(f.writes) != 0 || len(f.s.origMACs) != 0 {
		t.Fatal("unknown original mutated interfaces or fabricated recovery data")
	}
}
