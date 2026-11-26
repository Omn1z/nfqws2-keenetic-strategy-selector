package nfqws2

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestOpenWrtTransportRetryCommitsOnlyChangedInclude(t *testing.T) {
	const mock = `
uci() {
  if [ "$1" = -q ]; then
    [ "$MODE" = unchanged ] || return 1
    case "$3" in
      firewall.nfqws2_bypass_fw4) printf 'include\n' ;;
      *.type) printf 'script\n' ;;
      *.path) printf '/etc/nfqws2/nfqws-bypass-fw4.sh\n' ;;
      *.fw4_compatible) printf '1\n' ;;
    esac
  elif [ "$1" = commit ]; then
    printf 'commit called\n'
    [ "$MODE" != commit-failure ]
  elif [ "$1" = set ]; then :; else return 1; fi
}
`
	for _, mode := range []string{"unchanged", "changed", "commit-failure"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(bypassTestShell(t), "-c", mock+openWrtBypassIncludeCommand("/etc/nfqws2/nfqws-bypass-fw4.sh"))
			cmd.Env = append(os.Environ(), "MODE="+mode)
			out, err := cmd.CombinedOutput()
			if (err != nil) != (mode == "commit-failure") || strings.Contains(string(out), "commit called") != (mode != "unchanged") {
				t.Fatalf("error=%v output=%s", err, out)
			}
		})
	}
}
