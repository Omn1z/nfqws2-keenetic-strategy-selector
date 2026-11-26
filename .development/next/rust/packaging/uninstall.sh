#!/bin/sh
# nfqws2-strategy uninstaller. Pass --purge to also remove stored data.
set -e

say() { echo "[nfqws2-strategy] $*"; }
[ "$(id -u)" = "0" ] || { echo "run as root" >&2; exit 1; }

if [ -f /etc/openwrt_release ] || { [ -f /etc/rc.common ] && [ -d /etc/init.d ]; }; then
  PLATFORM=openwrt
  PATH="/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
  export PATH
  compact_dir=/usr/lib/nfqws2-strategy
  INIT=/etc/init.d/nfqws2-strategy
  BIN=/usr/bin/n2s
  OLD_BIN=/usr/bin/nfqws2-strategy
  DATA=/etc/nfqws2-strategy
  PIDFILE=/var/run/nfqws2-strategy.pid
  LOGFILE=/var/log/nfqws2-strategy.log
  ENGINE_INIT=/etc/init.d/nfqws2-keenetic
  ENGINE_CONF=/etc/nfqws2
else
  PLATFORM=entware
  compact_dir=/opt/lib/nfqws2-strategy
  INIT=/opt/etc/init.d/S52nfqws2-strategy
  BIN=/opt/usr/bin/n2s
  OLD_BIN=/opt/usr/bin/nfqws2-strategy
  DATA=/opt/etc/nfqws2-strategy
  PIDFILE=/opt/var/run/nfqws2-strategy.pid
  LOGFILE=/opt/var/log/nfqws2-strategy.log
  ENGINE_INIT=/opt/etc/init.d/S51nfqws2
  ENGINE_CONF=/opt/etc/nfqws2
fi

remove_compact=0
active_compact=0
if [ "$(readlink "$BIN" 2>/dev/null)" = "$compact_dir/n2s-compact" ]; then
  active_compact=1
  if [ "${N2S_COMPACT_PRERM:-0}" != 1 ]; then
    remove_compact=1
    PM=opkg
    if [ "$PLATFORM" = openwrt ]; then
      if PATH=/usr/sbin:/usr/bin:/sbin:/bin command -v apk >/dev/null 2>&1; then
        PM=apk
      elif ! PATH=/usr/sbin:/usr/bin:/sbin:/bin command -v opkg >/dev/null 2>&1; then
        say "native OpenWrt package manager is missing"
        exit 1
      fi
    fi
    if [ "$PM" = apk ]; then
      rows=$(apk list --installed 'nfqws2-strategy-*') || { say "cannot list compact packages"; exit 1; }
      compact_installed=$(printf '%s\n' "$rows" | awk '{sub(/-[0-9].*$/, "", $1); print $1}')
    else
      compact_installed=$(opkg list-installed 'nfqws2-strategy-*') || { say "cannot list compact packages"; exit 1; }
    fi
    compact_modules=$(printf '%s\n' "$compact_installed" |
      awk '$1 ~ /^nfqws2-strategy-(runs|blockcheck|strategies|geo|trace|tgws)$/ {print $1}')
  fi
fi

compact_apk() (
  guard=/var/run/nfqws2-strategy-apk.lock
  saved_mask=$(umask)
  umask 077
  exec 9>>"$guard" || exit 1
  umask "$saved_mask"
  flock -x 9 || exit 1
  status=0
  sh -c 'printf "%s\n" "$$" > "$1" || exit 1; shift; exec apk "$@"' sh "$guard" "$@" 9>&- || status=$?
  : > "$guard"
  exit "$status"
)

remove_compact_packages() {
  # opkg checks dependencies as each package is removed. Remove the module
  # aliases before their common executable. apk solves the set in one pass.
  set -- $compact_modules
  tools=$(printf '%s\n' "$compact_installed" | awk '$1 == "nfqws2-strategy-tools" {print $1; exit}')
  if [ "$PM" = apk ]; then
    compact_apk del "$@" $tools nfqws2-strategy-compact
  else
    if [ "$#" -gt 0 ]; then opkg remove "$@" || return 1; fi
    if [ -n "$tools" ]; then opkg remove "$tools" || return 1; fi
    opkg remove nfqws2-strategy-compact
  fi
}

# An old binary has no restore command and cannot own this new snapshot. Only
# invoke the command when a backup exists, before removing any recovery files.
restore_openwrt_dns() {
  [ "$PLATFORM" = openwrt ] || return 0
  dns_backup="$DATA/openwrt-dns-binding.json"
  [ -e "$dns_backup" ] || [ -L "$dns_backup" ] || return 0
  if [ ! -x "$BIN" ]; then
    say "ERROR: cannot restore managed OpenWrt DNS: executable $BIN is missing" >&2
    say "uninstall stopped; keep $dns_backup and restore DNS before removing the service" >&2
    return 1
  fi
  if ! N2S_DATA="$DATA" "$BIN" openwrt-dns-restore; then
    say "ERROR: OpenWrt DNS restoration failed; uninstall stopped to preserve the service and backup" >&2
    say "resolve the reported UCI conflict/error, keep $dns_backup, then retry uninstall" >&2
    return 1
  fi
  if [ -e "$dns_backup" ] || [ -L "$dns_backup" ]; then
    say "ERROR: OpenWrt DNS backup remains at $dns_backup; uninstall stopped" >&2
    return 1
  fi
}

# Remove only the tagged post-start block, including older versions that
# targeted nfqws-bypass.sh. Restoring a saved init file could undo engine
# upgrades or unrelated user edits, so leave every other line intact.
remove_bypass_init_hook() {
  [ -f "$ENGINE_INIT" ] || return 0
  marker='# nfqws2-strategy: reapply NFQUEUE bypass'
  grep -Fq "$marker" "$ENGINE_INIT" || return 0
  tmp=$(mktemp "$ENGINE_INIT.n2s-new.XXXXXX") || return 1
  if ! awk -v marker="$marker" '
    function own(line, family) {
      return line ~ /^[[:space:]]*\[ -x / && index(line, " ] && ") &&
        (index(line, "/nfqws-bypass.sh") || index(line, "/nfqws-strategy-bypass.sh")) &&
        index(line, " " family " >/dev/null 2>&1 || true")
    }
    { lines[NR]=$0; trimmed=$0; sub(/^[[:space:]]+/, "", trimmed); sub(/[[:space:]]+$/, "", trimmed)
      if (trimmed == marker) tags[NR]=1
    }
    END {
      for (i in tags) if (!own(lines[i+1], "iptables") || !own(lines[i+2], "ip6tables")) exit 1
      for (i=1; i<=NR; i++) {
        if (tags[i]) { i+=2; continue }
        print lines[i]
      }
    }
  ' "$ENGINE_INIT" > "$tmp"; then
    rm -f "$tmp"
    say "warning: preserved an unrecognized NFQWS2 bypass hook; remove it manually from $ENGINE_INIT"
    return 1
  fi
  chmod +x "$tmp"
  mv "$tmp" "$ENGINE_INIT"
}

remove_bypass_files() {
  rm -f "$ENGINE_CONF/nfqws-strategy-bypass.sh" \
    "$ENGINE_CONF/nfqws-bypass-fw4.sh" \
    "${ENGINE_CONF%/*}/ndm/netfilter.d/101-nfqws2-bypass.sh" \
    "$ENGINE_CONF/lists/nfqueue_bypass_resolved.list"
  # The dedicated chain belongs to this panel. Remove its jumps before the
  # chain, without restarting NFQWS2 or running its vendor bypass helper.
  for cmd in iptables ip6tables; do
    command -v "$cmd" >/dev/null 2>&1 || continue
    for parent in nfqws_post nfqws_pre; do
      while "$cmd" -w -t mangle -C "$parent" -j nfqws2_bypass 2>/dev/null; do
        "$cmd" -w -t mangle -D "$parent" -j nfqws2_bypass 2>/dev/null || break
      done
    done
    "$cmd" -w -t mangle -F nfqws2_bypass 2>/dev/null || true
    "$cmd" -w -t mangle -X nfqws2_bypass 2>/dev/null || true
  done
  # Release only panel-owned sets, after removing their firewall references.
  if command -v ipset >/dev/null 2>&1; then
    for set in n2s_nfqb4 n2s_nfqb6 n2s_nfqb4_new n2s_nfqb6_new; do
      ipset destroy "$set" 2>/dev/null || true
    done
  fi
}

# Restore while the local DNS listener is still available. Repeat after stop
# in case a concurrent web request applied a new binding just before shutdown.
managed_include=
if [ "$PLATFORM" = openwrt ] && command -v uci >/dev/null 2>&1; then
  section=firewall.nfqws2_bypass_fw4
  if [ "$(uci -q get "$section")" = include ] &&
     [ "$(uci -q get "$section.type")" = script ] &&
     [ "$(uci -q get "$section.path")" = "$ENGINE_CONF/nfqws-bypass-fw4.sh" ]; then
    changes=$(uci changes firewall) || exit 1
    [ -z "$changes" ] || { say "resolve pending firewall edits before removing the panel include"; exit 1; }
    managed_include=$section
  fi
fi
restore_openwrt_dns || exit 1
[ -x "$INIT" ] && "$INIT" stop 2>/dev/null || true
if [ -x "$BIN" ] && [ "$("$BIN" release-native-clients --supported 2>/dev/null || true)" = native-client-release-v1 ]; then
  N2S_DATA="$DATA" "$BIN" release-native-clients || { say "could not release the verified AWG clients; service files retained"; exit 1; }
fi
restore_openwrt_dns || exit 1
if [ -n "$managed_include" ]; then uci delete "$managed_include" && uci commit firewall || exit 1; fi
if [ "$remove_compact" = 1 ]; then
  N2S_INSTALLING_COMPACT=1 remove_compact_packages || { say "compact package removal failed"; exit 1; }
fi
if [ "$PLATFORM" = openwrt ]; then
  "$INIT" disable 2>/dev/null || true
fi
rm -f "$INIT" "$BIN" "$OLD_BIN" "$PIDFILE" "$LOGFILE" "${LOGFILE}.proxy"
# Leave the NFQWS2 package, vendor helper, configs and user lists intact.
remove_bypass_init_hook || true
remove_bypass_files
say "removed service and binary"

if [ "$active_compact" = 1 ]; then
  rm -f "$compact_dir/.compact-repair"
  rm -rf "$compact_dir/.compact-previous"
fi

if [ "${1:-}" = "--purge" ]; then
  rm -rf "$DATA"
  say "purged data dir $DATA"
else
  say "kept data dir $DATA (run with --purge to remove lists/results/blobs)"
fi
say "Done."
