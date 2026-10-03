package awgroute

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func firewallRestoreTestShell(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		if shell, err := exec.LookPath("sh"); err == nil {
			return shell
		}
	}
	if shell, err := exec.LookPath("bash"); err == nil {
		return shell
	}
	shell := filepath.Join(os.Getenv("ProgramFiles"), "Git", "bin", "bash.exe")
	if _, err := os.Stat(shell); err != nil {
		t.Skip("shell unavailable for isolated restore contention checks")
	}
	return shell
}

func TestFirewallRestoreRetriesOnlyLockContentionWithoutReplayingHook(t *testing.T) {
	document := "*mangle\n:AWG2_MULTI -\n-A AWG2_MULTI -m set --match-set awgm_001 dst -j MARK --set-xmark 0x10100000/0x1ff00000\nCOMMIT\n"
	for _, tc := range []struct {
		mode      string
		calls     int
		exit      int
		wait      bool
		committed bool
	}{
		{"transient", 3, 0, false, true},
		{"transient-wait", 3, 0, true, true},
		{"always-busy", 5, 4, false, false},
		{"unsupported-wait", 1, 2, true, false},
		{"non-lock-resource-error", 1, 4, false, false},
		{"bad-rule-with-lock-text", 1, 2, false, false},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			dir := t.TempDir()
			mock := filepath.Join(dir, "mock-restore.sh")
			fake := `#!/bin/sh
if [ "$1" = --help ]; then
  case "$AWG_TEST_MODE" in *wait*) printf 'usage: -w wait\n' ;; *) printf 'usage: --noflush\n' ;; esac
  exit 0
fi
count=$(cat "$AWG_TEST_STATE" 2>/dev/null || printf 0)
count=$((count + 1))
printf '%s' "$count" > "$AWG_TEST_STATE"
printf '%s\n' "$*" >> "$AWG_TEST_ARGS"
cat > "$AWG_TEST_DOC.$count"
case "$AWG_TEST_MODE" in
  unsupported-wait) printf 'unrecognized option -w\n' >&2; exit 2 ;;
  non-lock-resource-error) printf 'table allocation failed\n' >&2; exit 4 ;;
  bad-rule-with-lock-text) printf 'Bad argument; xtables lock is unrelated\n' >&2; exit 2 ;;
  always-busy) printf 'Another app is currently holding the xtables lock.\n' >&2; exit 4 ;;
esac
if [ "$count" -lt 3 ]; then
  printf 'Another app is currently holding the xtables lock. Perhaps you want to use the -w option?\n' >&2
  exit 4
fi
printf 'commit\n' >> "$AWG_TEST_COMMIT"
`
			if err := os.WriteFile(mock, []byte(fake), 0o755); err != nil {
				t.Fatal(err)
			}
			quote := func(path string) string { return "'" + strings.ReplaceAll(filepath.ToSlash(path), "'", "'\\''") + "'" }
			// Always replace restore with this temp executable, even on a router.
			// Other hook actions are represented by a lifecycle log, not executed.
			script := "set -e\niptables-restore() { sh " + quote(mock) + " \"$@\"; }\n"
			script += "sleep() { printf 'pause\\n' >> \"$AWG_TEST_PAUSES\"; }\n"
			script += "printf 'cleanup\\n' >> \"$AWG_TEST_LIFECYCLE\"\n"
			script += awgFirewallRestoreShell("awg_restore_test", "iptables-restore", "TESTRESTORE", document)
			script += "awg_restore_test\nprintf 'jumps-and-nat\\n' >> \"$AWG_TEST_LIFECYCLE\"\n"
			cmd := exec.Command(firewallRestoreTestShell(t))
			cmd.Stdin = strings.NewReader(script)
			cmd.Env = append(os.Environ(), "AWG_TEST_MODE="+tc.mode)
			for name, file := range map[string]string{"STATE": "state", "ARGS": "args", "DOC": "doc", "COMMIT": "commit", "PAUSES": "pauses", "LIFECYCLE": "lifecycle"} {
				cmd.Env = append(cmd.Env, "AWG_TEST_"+name+"="+filepath.ToSlash(filepath.Join(dir, file)))
			}
			out, err := cmd.CombinedOutput()
			exit := 0
			if err != nil {
				failure, ok := err.(*exec.ExitError)
				if !ok {
					t.Fatalf("could not run isolated helper: %v", err)
				}
				exit = failure.ExitCode()
			}
			state, readErr := os.ReadFile(filepath.Join(dir, "state"))
			if exit != tc.exit || readErr != nil || string(state) != strconv.Itoa(tc.calls) {
				t.Fatalf("exit=%d calls=%s; want exit=%d calls=%d: %v %s", exit, state, tc.exit, tc.calls, readErr, out)
			}
			for i := 1; i <= tc.calls; i++ {
				got, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("doc.%d", i)))
				if err != nil || !bytes.Equal(got, []byte(document)) {
					t.Fatalf("retry %d changed the restore document or mark mask: %v %q", i, err, got)
				}
			}
			args, _ := os.ReadFile(filepath.Join(dir, "args"))
			for _, line := range strings.Split(strings.TrimSpace(string(args)), "\n") {
				want := "--noflush"
				if tc.wait {
					want = "-w --noflush"
				}
				if line != want {
					t.Fatalf("restore arguments=%q, want %q", line, want)
				}
			}
			commits, _ := os.ReadFile(filepath.Join(dir, "commit"))
			lifecycle, _ := os.ReadFile(filepath.Join(dir, "lifecycle"))
			wantCommits, wantLifecycle := "", "cleanup\n"
			if tc.committed {
				wantCommits, wantLifecycle = "commit\n", "cleanup\njumps-and-nat\n"
			}
			if string(commits) != wantCommits || string(lifecycle) != wantLifecycle {
				t.Fatalf("retry repeated hook actions or hid failure: commits=%q lifecycle=%q", commits, lifecycle)
			}
			pauses, _ := os.ReadFile(filepath.Join(dir, "pauses"))
			if got := strings.Count(string(pauses), "pause\n"); got != tc.calls-1 {
				t.Fatalf("retry pauses=%d, want %d", got, tc.calls-1)
			}
		})
	}
}
