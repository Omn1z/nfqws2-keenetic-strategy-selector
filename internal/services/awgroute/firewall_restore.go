package awgroute

import "fmt"

// Replay only the fixed restore document. A lock failure happens before the
// table commit; retrying the whole hook would unnecessarily repeat cleanup and
// shared-chain appends. The saved hook also needs this when invoked by ndm.
func awgFirewallRestoreShell(function, binary, delimiter, document string) string {
	return fmt.Sprintf(`%s() {
  IPTABLES_RESTORE='%s --noflush'
  if %s --help 2>&1 | grep -q -- ' -w'; then IPTABLES_RESTORE='%s -w --noflush'; fi
  AWG_RESTORE_ATTEMPT=0
  while :; do
    AWG_RESTORE_ATTEMPT=$((AWG_RESTORE_ATTEMPT + 1))
    if AWG_RESTORE_OUTPUT=$($IPTABLES_RESTORE <<'%s' 2>&1
%s%s
    ); then
      return 0
    else
      AWG_RESTORE_STATUS=$?
    fi
    case "$AWG_RESTORE_OUTPUT" in
      *xtables*lock*|*Another\ app*holding*lock*) ;;
      *) printf '%%s\n' "$AWG_RESTORE_OUTPUT" >&2; return "$AWG_RESTORE_STATUS" ;;
    esac
    if [ "$AWG_RESTORE_STATUS" -ne 4 ] || [ "$AWG_RESTORE_ATTEMPT" -ge 5 ]; then
      printf '%%s\n' "$AWG_RESTORE_OUTPUT" >&2
      return "$AWG_RESTORE_STATUS"
    fi
    sleep 1 || return 1
  done
}
`, function, binary, binary, binary, delimiter, document, delimiter)
}
