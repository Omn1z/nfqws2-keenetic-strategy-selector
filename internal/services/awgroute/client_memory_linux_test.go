//go:build linux

package awgroute

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"nfqws2strategy/internal/services/awg"
)

func init() {
	if os.Getenv("N2S_TEST_AWG_MEMORY_POLICY_PROCESS") == "1" {
		// Start before testing.Main parses the synthetic awg1 argument. Using
		// this test executable also works on BusyBox routers, where renaming a
		// copied /bin/cat would select an unknown applet instead of running cat.
		for {
			time.Sleep(time.Hour)
		}
	}
}

// A daemon started under the previous policy must remain eligible for reuse.
// In particular, checking the engine on every supervisor tick must not require
// the new GOMEMLIMIT/GOGC environment or kill its still-working process.
func TestAWGCurrentEngineKeepsDaemonWithPreviousMemoryPolicy(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	engine := filepath.Join(dir, "amneziawg-go")
	if err := os.Symlink(testExecutable, engine); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(engine, "awg1")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOMEMLIMIT=128MiB", "GOGC=200", "GODEBUG=madvdontneed=1", "N2S_TEST_AWG_MEMORY_POLICY_PROCESS=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	previousDir := awgEngineDir
	awgEngineDir = dir
	t.Cleanup(func() { awgEngineDir = previousDir; clientEnginePIDs.Delete("awg1") })

	if got := awgDaemonMemoryEnvironment([]byte("MemTotal: 497676 kB\n")); got == "GOMEMLIMIT=128MiB GOGC=200 GODEBUG=madvdontneed=1" {
		t.Fatal("fixture must exercise a changed launch policy")
	}
	cfg := awg.Default()
	cfg.ClientIface = "awg1"
	for i := 0; i < 2; i++ {
		if !awgClientCurrentEngineOS(*cfg) {
			t.Fatal("live old-policy daemon was marked for replacement")
		}
		if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
			t.Fatalf("engine compatibility check stopped the original PID %d: %v", cmd.Process.Pid, err)
		}
	}
}
