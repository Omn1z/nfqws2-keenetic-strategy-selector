package awg

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func rollbackBash(t *testing.T) string {
	t.Helper()
	if bash, err := exec.LookPath("bash"); err == nil {
		return bash
	}
	bash := filepath.Join(os.Getenv("ProgramFiles"), "Git", "bin", "bash.exe")
	if _, err := os.Stat(bash); err != nil {
		t.Skip("bash unavailable for scoped rollback checks")
	}
	return bash
}

// Run only the transaction helpers against a fresh temporary directory. The
// service/network commands are shell functions, so no real interface or service
// can be stopped or started by these tests.
func runRollbackShell(t *testing.T, dir, script string, active bool) (string, error) {
	t.Helper()
	prefix := "'" + strings.ReplaceAll(filepath.ToSlash(dir), "'", "'\\''") + "'"
	script = strings.ReplaceAll(script, "/etc/amnezia/amneziawg", prefix)
	activeCode := "1"
	if active {
		activeCode = "0"
	}
	stubs := "ip() { return 1; }\nawg-quick() { return 0; }\nawg() { echo 51820; }\nsystemctl() { if [ \"$1\" = is-active ]; then return " + activeCode + "; fi; return 0; }\n"
	cmd := exec.Command(rollbackBash(t))
	cmd.Stdin = strings.NewReader(stubs + script)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestRemoteRollbackRestoresPreviousFileAndCleansBackup(t *testing.T) {
	dir := t.TempDir()
	old := []byte("[Interface]\nPrivateKey = old-sensitive-key\nListenPort = 51820\n")
	next := []byte("[Interface]\nPrivateKey = new-sensitive-key\nHeaderProtectionKey = new-sensitive-header\n")
	config := filepath.Join(dir, "awg0.conf")
	if err := os.WriteFile(config, old, 0600); err != nil {
		t.Fatal(err)
	}
	backup := "/etc/amnezia/amneziawg/.nfqws-deploy-awg0-test"
	if out, err := runRollbackShell(t, dir, backupConfigScript("awg0", backup), true); err != nil || !strings.Contains(out, "previous=1") {
		t.Fatalf("backup failed: %v %s", err, out)
	}
	localBackup := filepath.Join(dir, ".nfqws-deploy-awg0-test")
	if err := os.WriteFile(filepath.Join(localBackup, "new.conf"), next, 0600); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(next))
	if out, err := runRollbackShell(t, dir, activateConfigScript("awg0", backup, digest, true), true); err != nil {
		t.Fatalf("activate: %v %s", err, out)
	}
	for i := 0; i < 2; i++ { // repeat after an uncertain SSH response: backup still exists
		out, err := runRollbackShell(t, dir, rollbackConfigScript("awg0", backup, digest, true), true)
		if err != nil {
			t.Fatalf("rollback: %v %s", err, out)
		}
		if strings.Contains(out, "sensitive") {
			t.Fatal("rollback printed config secrets")
		}
	}
	got, err := os.ReadFile(config)
	if err != nil || string(got) != string(old) {
		t.Fatal("previous config was not restored")
	}
	if out, err := runRollbackShell(t, dir, cleanupConfigBackupScript(backup), true); err != nil {
		t.Fatalf("cleanup: %v %s", err, out)
	}
	if _, err := os.Stat(localBackup); !os.IsNotExist(err) {
		t.Fatal("completed rollback left backup")
	}
}

func TestRemoteRollbackFirstDeploymentDoesNotRemoveForeignConfig(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(fmt.Sprintf("foreign=%v", foreign), func(t *testing.T) {
			dir := t.TempDir()
			backup := "/etc/amnezia/amneziawg/.nfqws-deploy-awg0-test"
			if out, err := runRollbackShell(t, dir, backupConfigScript("awg0", backup), false); err != nil || !strings.Contains(out, "previous=0") {
				t.Fatalf("backup: %v %s", err, out)
			}
			next := []byte("only-our-new-config")
			if err := os.WriteFile(filepath.Join(dir, ".nfqws-deploy-awg0-test", "new.conf"), next, 0600); err != nil {
				t.Fatal(err)
			}
			digest := fmt.Sprintf("%x", sha256.Sum256(next))
			if out, err := runRollbackShell(t, dir, activateConfigScript("awg0", backup, digest, false), false); err != nil {
				t.Fatalf("activate: %v %s", err, out)
			}
			config := filepath.Join(dir, "awg0.conf")
			if foreign {
				if err := os.WriteFile(config, []byte("foreign-data"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			out, err := runRollbackShell(t, dir, rollbackConfigScript("awg0", backup, digest, false), true)
			if foreign {
				if err == nil {
					t.Fatal("rollback accepted foreign config")
				}
				got, _ := os.ReadFile(config)
				if string(got) != "foreign-data" {
					t.Fatal("rollback deleted foreign data")
				}
				if _, err := os.Stat(filepath.Join(dir, ".nfqws-deploy-awg0-test")); err != nil {
					t.Fatal("failed rollback lost backup")
				}
			} else {
				if err != nil {
					t.Fatalf("rollback: %v %s", err, out)
				}
				if _, err := os.Stat(config); !os.IsNotExist(err) {
					t.Fatal("rollback retained failed first config")
				}
			}
		})
	}
}

func TestRemoteRollbackRefusesUnmanagedActiveInterface(t *testing.T) {
	dir := t.TempDir()
	if _, err := runRollbackShell(t, dir, backupConfigScript("awg0", "/etc/amnezia/amneziawg/.nfqws-deploy-awg0-test"), true); err == nil {
		t.Fatal("accepted running interface without a managed config")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatal("unmanaged interface check created files")
	}
}

type disconnectedDeployRunner struct {
	fakeRunner
	disconnected bool
	cancel       context.CancelFunc
}

func (r *disconnectedDeployRunner) Run(ctx context.Context, cmd string) (string, string, error) {
	if strings.Contains(cmd, "==LISTEN==") {
		r.disconnected = true
		if r.cancel != nil {
			r.cancel()
		}
	}
	if r.disconnected {
		r.cmds = append(r.cmds, cmd)
		return "", "", errors.New("SSH disconnected")
	}
	return r.fakeRunner.Run(ctx, cmd)
}

func TestDeployReconnectsForRollbackAfterVerifySSHFailure(t *testing.T) {
	c, _ := testAWG31(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &disconnectedDeployRunner{cancel: cancel}
	fresh := &fakeRunner{}
	reconnections := 0
	res := Deploy(ctx, r, c, nil, func(ctx context.Context) (runner, error) {
		if ctx.Err() != nil {
			t.Fatal("rollback inherited cancelled context")
		}
		reconnections++
		return fresh, nil
	})
	if res.OK || res.RollbackStatus != "restored" || res.RollbackError != "" || res.RollbackBackup != "" || reconnections < 1 {
		t.Fatalf("rollback result: %+v reconnects=%d", res, reconnections)
	}
	if !strings.Contains(strings.Join(fresh.cmds, "\n"), "systemctl restart awg-quick@awg0") {
		t.Fatal("fresh SSH session did not restore service")
	}
}

func TestDeployReportsUnconfirmedRollbackAndKeepsBackup(t *testing.T) {
	c, _ := testAWG31(t)
	r := &disconnectedDeployRunner{}
	res := Deploy(context.Background(), r, c, nil)
	if res.OK || res.RollbackStatus != "failed" || res.RollbackError == "" || res.RollbackBackup == "" {
		t.Fatalf("lost rollback failure details: %+v", res)
	}
	for _, cmd := range r.cmds {
		if strings.Contains(cmd, "configuration backup removed") {
			t.Fatal("failed rollback deleted recovery copy")
		}
	}
}

func TestDeployFirstFailureReportsRemovalOfOnlyNewConfig(t *testing.T) {
	c, _ := testAWG31(t)
	r := &failingAWGRunner{fakeRunner: fakeRunner{responses: []kv{{"echo previous=1", "previous=0"}}}, fail: "==LISTEN=="}
	res := Deploy(context.Background(), r, c, nil)
	if res.OK || res.RollbackStatus != "removed_new" {
		t.Fatalf("first-deploy failure: %+v", res)
	}
}
