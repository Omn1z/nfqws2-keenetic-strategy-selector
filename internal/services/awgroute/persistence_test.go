package awgroute

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/config"
	"nfqws2strategy/internal/tools/store"
)

// Deliberately bypass Service.New: no fixture may run router cleanup commands.
func persistenceFixture(t *testing.T, dir string) (*Service, *int) {
	t.Helper()
	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{cfg: &config.Config{DataDir: dir}, store: st}
	cleanupCalls := new(int)
	svc.loadAndInitializeAWG(func() { *cleanupCalls++ })
	return svc, cleanupCalls
}

func TestAWGPersistenceInvalidStateNeverOverwritesOrStarts(t *testing.T) {
	for _, input := range []string{"", "{", "null", "{}", `{"servers":null}`, `{"unrelated":true}`, `{"servers":[]}`, `{"servers":[{"config":{}}]}`} {
		t.Run(input, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, awgConfigFile)
			if err := os.WriteFile(path, []byte(input), 0600); err != nil {
				t.Fatal(err)
			}
			svc, cleanups := persistenceFixture(t, dir)
			if msg, _ := svc.awgPersistenceStatus(); msg == "" || *cleanups != 0 {
				t.Fatal("invalid state did not fence initialization")
			}
			if len(svc.awgActive().Config().Peers) != 0 || svc.clientShouldRun(svc.awgActive()) {
				t.Fatal("invalid state generated or started a replacement profile")
			}
			if svc.awgSaveErr() == nil || svc.store.SaveSecret(awgConfigFile, defaultAWGState()) == nil {
				t.Fatal("invalid state permitted a default save")
			}
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, []byte(input)) {
				t.Fatal("invalid source bytes were replaced")
			}
		})
	}
}

func TestAWGPersistenceNewStateAndBackupRecoveryPreserveIdentity(t *testing.T) {
	dir := t.TempDir()
	svc, cleanups := persistenceFixture(t, dir)
	if msg, recovered := svc.awgPersistenceStatus(); msg != "" || recovered || *cleanups != 1 {
		t.Fatal("genuinely new installation was not initialized")
	}
	before := svc.snapshotAWGState()
	if len(before.Servers[0].Config.Peers) != 1 {
		t.Fatal("new installation did not retain its local router identity")
	}
	path := filepath.Join(dir, awgConfigFile)
	valid, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	bad := []byte("{interrupted-write")
	if err := os.WriteFile(path, bad, 0600); err != nil {
		t.Fatal(err)
	}
	reloaded, _ := persistenceFixture(t, dir)
	if msg, recovered := reloaded.awgPersistenceStatus(); msg != "" || !recovered {
		t.Fatal("valid private generation was not recovered")
	}
	if !reflect.DeepEqual(before, reloaded.snapshotAWGState()) {
		t.Fatal("recovery changed profile identity or policy")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, valid) {
		t.Fatal("recovery did not restore the exact valid bytes")
	}
	var preserved bool
	_ = filepath.WalkDir(filepath.Join(dir, ".store"), func(path string, entry os.DirEntry, err error) error {
		if err == nil && !entry.IsDir() {
			data, _ := os.ReadFile(path)
			preserved = preserved || bytes.Equal(data, bad)
		}
		return nil
	})
	if !preserved {
		t.Fatal("recovery discarded damaged original evidence")
	}
}

func TestAWGPersistenceLegacyShapeAndDetachedRules(t *testing.T) {
	legacy := awg.Default()
	legacy.Endpoint = "192.0.2.19:51820"
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	state, err := decodePersistedAWG(data)
	if err != nil || len(state.Servers) != 1 || state.Servers[0].Config.Endpoint != legacy.Endpoint {
		t.Fatal("real legacy profile was rejected or changed")
	}
	detached := awgPersisted{Routing: defaultAWGState().Routing, PendingRules: []awg.Zone{{Name: "detached", TunnelID: "removed", WaitingForConnection: true, Enabled: true}}}
	detached.Servers = []awgPersistedServer{}
	data, _ = json.Marshal(detached)
	state, err = decodePersistedAWG(data)
	if err != nil || len(state.PendingRules) != 1 || state.PendingRules[0].TunnelID != "removed" {
		t.Fatal("deliberately detached policy was rejected or discarded")
	}
}

func TestAWGPersistenceMutationFailureDoesNotPublishCandidate(t *testing.T) {
	for _, action := range []string{"add", "rename", "select", "config"} {
		t.Run(action, func(t *testing.T) {
			svc, _, entries := failoverTestService(t)
			before := svc.snapshotAWGState()
			if err := os.Mkdir(svc.store.Path(awgConfigFile), 0700); err != nil {
				t.Fatal(err)
			}
			var err error
			switch action {
			case "add":
				_, err = svc.AWG2AddServer("candidate")
			case "rename":
				err = svc.AWG2RenameServer(entries[0].ID, "candidate")
			case "select":
				err = svc.AWG2SelectServer(entries[1].ID)
			case "config":
				candidate := svc.awgActive().Config()
				candidate.MTU = 1300
				err = svc.AWG2SetConfig(&candidate)
			}
			if err == nil || !reflect.DeepEqual(before, svc.snapshotAWGState()) {
				t.Fatal("failed save published a candidate or reported success")
			}
		})
	}
}

func TestAWGPersistenceRestoreReloadsPartialCommitAndKeepsIdenticalManagers(t *testing.T) {
	dir := t.TempDir()
	svc, _ := persistenceFixture(t, dir)
	manager := svc.awgActive()
	if _, err := svc.RestorePersistedState(func() (int, error) { return 0, nil }); err != nil || svc.awgActive() != manager {
		t.Fatal("identical restore discarded the live manager")
	}
	state := svc.snapshotAWGState()
	state.Servers[0].Name = "restored"
	data, _ := json.MarshalIndent(state, "", "  ")
	laterFailure := errors.New("later archive member failed")
	n, err := svc.RestorePersistedState(func() (int, error) {
		if err := os.WriteFile(filepath.Join(dir, awgConfigFile), data, 0600); err != nil {
			return 0, err
		}
		return 1, laterFailure
	})
	if n != 1 || !errors.Is(err, laterFailure) || svc.snapshotAWGState().Servers[0].Name != "restored" {
		t.Fatal("partial archive commit left old live state authoritative")
	}
	if err := svc.awgSaveErr(); err != nil {
		t.Fatalf("restored baseline could not be saved: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, awgConfigFile))
	if err != nil {
		t.Fatal(err)
	}
	restored, err := decodePersistedAWG(got)
	if err != nil || restored.Servers[0].Name != "restored" {
		t.Fatal("next save resurrected stale pre-restore state")
	}
}

func TestAWGPersistenceDeployStopsBeforeRemoteSideEffects(t *testing.T) {
	svc, _ := persistenceFixture(t, t.TempDir())
	am := svc.awgActive()
	cfg := am.Config()
	cfg.Client.Enabled = false
	cfg.Conn.Host = "192.0.2.20"
	cfg.Endpoint = "192.0.2.20:51820"
	if err := am.SetConfig(&cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(svc.store.Path(awgConfigFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(svc.store.Path(awgConfigFile), 0700); err != nil {
		t.Fatal(err)
	}
	result, err := svc.deployServer(svc.servers[svc.activeServerID()])
	if err == nil || result.OK || am.Config().DeployedAt != 0 {
		t.Fatal("deployment proceeded without durable key persistence")
	}
}

func TestAWGPersistenceFailedReloadLeavesRunningReserveUntouched(t *testing.T) {
	svc, driver, entries := failoverTestService(t)
	primary, reserve := entries[0].Manager, entries[1].Manager
	setTestFailover(t, primary, false, entries[1].ID)
	setTestFailover(t, reserve, true)
	driver.states[reserve] = ClientStatus{Running: true, Connected: true, LastHandshake: time.Now().Unix()}
	svc.clients.standbyActive = map[*awg.Manager]bool{reserve: true}
	svc.clients.states = map[*awg.Manager]clientRecovery{primary: {Recovering: true, Attempts: 2}}
	before := svc.clients.states[primary]
	beforeState := svc.snapshotAWGState()
	if err := os.WriteFile(svc.store.Path(awgConfigFile), []byte("{damaged"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RestorePersistedState(func() (int, error) { return 0, nil }); err == nil {
		t.Fatal("damaged restored state was accepted")
	}
	if unlock, ok := svc.tryClientOps(); ok {
		unlock()
		t.Fatal("failed reload allowed background policy work")
	}
	svc.checkClients()
	_, unlock := svc.lockClientOps(false)
	svc.reconcileStandbyClients()
	svc.checkClient(entries[0])
	deleteSideEffects := 0
	deleteErr := svc.awgDeleteServerWithOps(entries[0].ID, func() error { deleteSideEffects++; return nil }, func(*awg.Manager) error { deleteSideEffects++; return nil }, func() error { deleteSideEffects++; return nil })
	unlock()
	if deleteErr == nil || deleteSideEffects != 0 || !reflect.DeepEqual(beforeState, svc.snapshotAWGState()) {
		t.Fatal("queued delete mutated quarantined state")
	}
	if len(driver.downCalls) != 0 || len(driver.attempts) != 0 || driver.probes != 0 || driver.restores != 0 {
		t.Fatal("failed reload changed a running daemon or routes")
	}
	if !svc.clients.standbyActive[reserve] || svc.clients.states[primary] != before || svc.servers[entries[1].ID].Manager != reserve {
		t.Fatal("failed reload discarded live reserve ownership or recovery state")
	}
}
