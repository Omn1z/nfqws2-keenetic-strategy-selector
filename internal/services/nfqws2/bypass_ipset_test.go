package nfqws2

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"nfqws2strategy/internal/tools/shell"
)

func isolatedBypassScript(t *testing.T, lockDir string) string {
	t.Helper()
	const original = `lock="/tmp/nfqws-bypass-$CMD.lock"`
	if strings.Count(generatedBypassScript, original) != 1 {
		t.Fatal("production lock location changed: update the isolated test mapping")
	}
	return strings.Replace(generatedBypassScript, original, `lock=`+shell.Quote(filepath.ToSlash(lockDir))+`"/nfqws-bypass-$CMD.lock"`, 1)
}

func isolatedFunctionMockBypassScript(t *testing.T, lockDir string) string {
	t.Helper()
	isolated := isolatedBypassScript(t, lockDir)
	const restore = `RESTORE="${CMD}-restore"`
	if strings.Count(isolated, restore) != 1 {
		t.Fatal("production restore selector changed: update the isolated test mapping")
	}
	// dash rejects hyphens in function names. Map only the executable selector
	// to POSIX mock names so the unmodified transaction still runs under /bin/sh.
	return strings.Replace(isolated, restore, `RESTORE="${CMD}_restore"`, 1)
}

func bypassTestShell(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		if name, err := exec.LookPath("sh"); err == nil {
			return name
		}
	}
	name := filepath.Join(os.Getenv("ProgramFiles"), "Git", "bin", "bash.exe")
	if _, err := os.Stat(name); err != nil {
		t.Skip("POSIX shell unavailable")
	}
	return name
}

// Functions shadow every firewall utility, including when run as root on a
// real router. State lives exclusively in t.TempDir; there is no live firewall.
const bypassKernelMock = `
command() {
  [ "$1" = -v ] || return 97
  if [ "$MODE" = missing-ipset ] && [ "$2" = ipset ]; then return 1; fi
  type "$2"
}
ipset() {
  printf 'ipset %s\n' "$*" >> "$TESTROOT/calls"
  [ "$MODE" != no-ipset ] || return 1
  if [ "$1" = -exist ]; then shift; fi
  case "$1" in
    create) [ ! -e "$TESTROOT/$2" ] || return 1; : > "$TESTROOT/$2" ;;
    destroy) rm -f "$TESTROOT/$2" ;;
    list) [ -f "$TESTROOT/$2" ] ;;
    restore)
      if [ "$MODE" = competing ] || [ "$MODE" = competing-other-tmp ]; then
        child_tmp="$TMPDIR"
        [ "$MODE" != competing-other-tmp ] || child_tmp="$TESTROOT/different-tmpdir"
        if TMPDIR="$child_tmp" MODE=normal sh "$0" "$CMD" > "$TESTROOT/contender-output" 2>&1; then return 96; fi
        read -r owner < "$TMPDIR/nfqws-bypass-$CMD.lock/pid"
        [ "$owner" = "$$" ] || return 96
      fi
      while read -r verb name address; do
        printf '%s\n' "$address" >> "$TESTROOT/$name"
        if [ "$MODE" = term-fill ]; then kill -TERM "$$"; return 1; fi
        [ "$MODE" != fail-fill ] || return 1
      done
      ;;
    swap)
      [ "$MODE" != fail-swap ] || return 1
      mv "$TESTROOT/$2" "$TESTROOT/swap"
      mv "$TESTROOT/$3" "$TESTROOT/$2"
      mv "$TESTROOT/swap" "$TESTROOT/$3"
      if [ "$MODE" = term-swap ] && [ ! -f "$TESTROOT/signalled" ]; then
        : > "$TESTROOT/signalled"
        kill -TERM "$$"
      fi
      ;;
    *) echo "unexpected mock ipset: $*" >&2; return 97 ;;
  esac
}
iptables() {
  printf 'iptables %s\n' "$*" >> "$TESTROOT/calls"
  case "$4" in
    -S|-L) [ "$MODE" != missing-parent ] ;;
    -N) : > "$TESTROOT/probe" ;;
    -F) case "$5" in n2s_nfqb_[0-9]*) : ;; *) return 98 ;; esac ;;
    -X) rm -f "$TESTROOT/probe" ;;
    -A) case "$5" in n2s_nfqb_[0-9]*) [ "$MODE" != no-kernel-match ] ;; *) return 98 ;; esac ;;
    -C) [ "$MODE" != missing-jumps ] ;;
    *) echo "unexpected mock iptables: $*" >&2; return 97 ;;
  esac
}
ip6tables() { iptables "$@"; }
iptables_restore() {
  printf 'restore %s\n' "$*" >> "$TESTROOT/calls"
  cat > "$TESTROOT/pending"
  if [ "$MODE" = term-commit ]; then kill -TERM "$$"; return 1; fi
  [ "$MODE" != fail-commit ] || return 1
  cp "$TESTROOT/pending" "$TESTROOT/chain"
  if [ "$MODE" = term-after-commit ]; then kill -TERM "$$"; fi
}
ip6tables_restore() { iptables_restore "$@"; }
sleep() { printf 'sleep\n' >> "$TESTROOT/calls"; }
if [ "$MODE" = busy ]; then
  mkdir "$TMPDIR/nfqws-bypass-$1.lock"
  printf '%s\n' "$$" > "$TMPDIR/nfqws-bypass-$1.lock/pid"
fi
if [ "$MODE" = abandoned ]; then
  mkdir "$TMPDIR/nfqws-bypass-$1.lock"
  printf '2147483647\n' > "$TMPDIR/nfqws-bypass-$1.lock/pid"
fi
`

type bypassRun struct {
	dir, output string
	err         error
}

func runMockBypass(t *testing.T, family, mode, ips, resolved string) bypassRun {
	t.Helper()
	dir := t.TempDir()
	for _, sub := range []string{"lists", "tmp"} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, data := range map[string]string{
		"lists/nfqueue_bypass_ips.list":      ips,
		"lists/nfqueue_bypass_resolved.list": resolved,
		"lists/nfqueue_bypass_domains.list":  "must-not-query.example\n",
		"n2s_nfqb4":                          "198.51.100.9\n",
		"n2s_nfqb6":                          "2001:db8::9\n",
		"chain":                              "original firewall\n",
		"helper.sh":                          "#!/bin/sh\n" + bypassKernelMock + isolatedFunctionMockBypassScript(t, filepath.Join(dir, "tmp")),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(bypassTestShell(t), filepath.ToSlash(filepath.Join(dir, "helper.sh")), family)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TESTROOT="+filepath.ToSlash(dir), "TMPDIR="+filepath.ToSlash(filepath.Join(dir, "tmp")), "MODE="+mode)
	out, err := cmd.CombinedOutput()
	return bypassRun{dir, string(out), err}
}

func (r bypassRun) read(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(r.dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func (r bypassRun) absent(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		if _, err := os.Stat(filepath.Join(r.dir, name)); !os.IsNotExist(err) {
			t.Errorf("temporary object %s remains: %v", name, err)
		}
	}
}

func TestGeneratedBypassIPSetFamiliesAndValidation(t *testing.T) {
	inputs := "192.0.2.1\n192.0.2.1 ;duplicate\n203.0.113.0/24 # net\n0.0.0.0/0\n" +
		"2001:db8::1\n2001:db8:1::/48\n::/0\n" +
		"host.example\n999.1.1.1\n1.2.3\n1.2.3.4/33\n1.2.3.4/\n1.2.3.4/24/2\n" +
		":::/32\n:2001:db8::1\n2001:db8::1::\n12345::1\n::/129\n::/\n192.0.2.9 -j DROP\n"
	for _, family := range []string{"iptables", "ip6tables"} {
		t.Run(family, func(t *testing.T) {
			r := runMockBypass(t, family, "normal", inputs, "192.0.2.1\n2001:db8::1\n")
			if r.err != nil {
				t.Fatalf("helper: %v: %s", r.err, r.output)
			}
			set := "n2s_nfqb4"
			want := "192.0.2.1\n203.0.113.0/24\n0.0.0.0/1\n128.0.0.0/1\n"
			if family == "ip6tables" {
				set = "n2s_nfqb6"
				want = "2001:db8::1\n2001:db8:1::/48\n::/1\n8000::/1\n"
			}
			if got := r.read(t, set); got != want {
				t.Fatalf("addresses: got %q want %q", got, want)
			}
			chain := r.read(t, "chain")
			for _, direction := range []string{"dst", "src"} {
				if !strings.Contains(chain, fmt.Sprintf("-A nfqws2_bypass -m set --match-set %s %s -j ACCEPT\n", set, direction)) {
					t.Errorf("missing %s rule: %s", direction, chain)
				}
			}
			if strings.Count(chain, "-A ") != 2 || strings.Contains(chain, "-I ") {
				t.Fatalf("unexpected chain or duplicate jump: %s", chain)
			}
			calls := r.read(t, "calls")
			if strings.Contains(calls, " -D ") || strings.Contains(calls, " -F nfqws2_bypass") {
				t.Fatalf("live chain detached or flushed: %s", calls)
			}
			r.absent(t, set+"_new", "probe", "tmp/nfqws-bypass-"+family+".lock")
		})
	}
}

func TestGeneratedBypassIPSetFailurePreservesPolicy(t *testing.T) {
	for _, mode := range []string{"fail-fill", "fail-swap", "fail-commit", "term-fill", "term-swap", "term-commit", "busy", "abandoned", "missing-parent"} {
		t.Run(mode, func(t *testing.T) {
			r := runMockBypass(t, "iptables", mode, "203.0.113.7\n", "")
			if r.err == nil {
				t.Fatalf("expected %s failure", mode)
			}
			if got := r.read(t, "n2s_nfqb4"); got != "198.51.100.9\n" {
				t.Fatalf("failed update changed live set: %q", got)
			}
			if got := r.read(t, "chain"); got != "original firewall\n" {
				t.Fatalf("failed update changed chain: %q", got)
			}
			r.absent(t, "n2s_nfqb4_new", "probe")
			if mode != "busy" && mode != "abandoned" {
				r.absent(t, "tmp/nfqws-bypass-iptables.lock")
			} else if count := strings.Count(r.read(t, "calls"), "sleep\n"); count != 9 {
				t.Fatalf("busy wait is not bounded: %d", count)
			}
		})
	}
}

func TestGeneratedBypassSignalAfterCommitPreservesCommittedSet(t *testing.T) {
	r := runMockBypass(t, "iptables", "term-after-commit", "203.0.113.7\n", "")
	if r.err == nil {
		t.Fatal("expected interrupted status")
	}
	if got := r.read(t, "n2s_nfqb4"); got != "203.0.113.7\n" {
		t.Fatalf("committed chain lost its addresses: %q", got)
	}
	if got := r.read(t, "chain"); !strings.Contains(got, "--match-set n2s_nfqb4") {
		t.Fatalf("chain was not committed: %q", got)
	}
	r.absent(t, "n2s_nfqb4_new", "probe", "tmp/nfqws-bypass-iptables.lock")
}

func TestGeneratedBypassIPSetUnsupportedAndLifecycle(t *testing.T) {
	for _, mode := range []string{"no-ipset", "missing-ipset", "no-kernel-match", "missing-jumps", "competing", "competing-other-tmp"} {
		t.Run(mode, func(t *testing.T) {
			r := runMockBypass(t, "iptables", mode, "203.0.113.7\n", "")
			if r.err != nil {
				t.Fatalf("helper: %v: %s", r.err, r.output)
			}
			chain := r.read(t, "chain")
			if strings.HasPrefix(mode, "no-") || mode == "missing-ipset" {
				for _, direction := range []string{"-d", "-s"} {
					if !strings.Contains(chain, "-A nfqws2_bypass "+direction+" 203.0.113.7 -j ACCEPT") {
						t.Errorf("missing linear fallback rule: %s", chain)
					}
				}
			} else if !strings.Contains(chain, "--match-set n2s_nfqb4") {
				t.Errorf("expected sets: %s", chain)
			}
			if mode == "missing-jumps" {
				for _, parent := range []string{"nfqws_pre", "nfqws_post"} {
					if !strings.Contains(chain, "-I "+parent+" 1 -j nfqws2_bypass") {
						t.Errorf("missing jump in transaction: %s", chain)
					}
				}
			}
			if strings.HasPrefix(mode, "competing") && !strings.Contains(r.read(t, "contender-output"), "update is busy") {
				t.Fatal("concurrent helper was not refused by the owned lock")
			}
			r.absent(t, "n2s_nfqb4_new", "probe", "tmp/nfqws-bypass-iptables.lock", "tmp/nfqws-bypass-iptables.lock.reap")
		})
	}
}

func TestGeneratedBypassIPSetEmptyCacheClearsOnlyOwnedSet(t *testing.T) {
	r := runMockBypass(t, "iptables", "normal", "", "")
	if r.err != nil {
		t.Fatalf("helper: %v: %s", r.err, r.output)
	}
	if got := r.read(t, "n2s_nfqb4"); got != "" {
		t.Fatalf("stale addresses survived empty policy: %q", got)
	}
	if got := r.read(t, "n2s_nfqb6"); got != "2001:db8::9\n" {
		t.Fatalf("other family changed: %q", got)
	}
}
