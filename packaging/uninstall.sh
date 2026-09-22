#!/bin/sh
# nfqws2-strategy uninstaller. Pass --purge to also remove stored data.
set -e

say() { echo "[nfqws2-strategy] $*"; }
[ "$(id -u)" = "0" ] || { echo "run as root" >&2; exit 1; }

if [ -f /etc/openwrt_release ] || { [ -f /etc/rc.common ] && [ -d /etc/init.d ]; }; then
  PLATFORM=openwrt
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
  INIT=/opt/etc/init.d/S52nfqws2-strategy
  BIN=/opt/usr/bin/n2s
  OLD_BIN=/opt/usr/bin/nfqws2-strategy
  DATA=/opt/etc/nfqws2-strategy
  PIDFILE=/opt/var/run/nfqws2-strategy.pid
  LOGFILE=/opt/var/log/nfqws2-strategy.log
  ENGINE_INIT=/opt/etc/init.d/S51nfqws2
  ENGINE_CONF=/opt/etc/nfqws2
fi

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
}

[ -x "$INIT" ] && "$INIT" stop 2>/dev/null || true
if [ "$PLATFORM" = openwrt ]; then
  "$INIT" disable 2>/dev/null || true
fi
rm -f "$INIT" "$BIN" "$OLD_BIN" "$PIDFILE" "$LOGFILE"
# Leave the NFQWS2 package, vendor helper, configs and user lists intact.
remove_bypass_init_hook || true
remove_bypass_files
if [ "$PLATFORM" = openwrt ]; then
  if command -v uci >/dev/null 2>&1; then
    uci -q delete firewall.nfqws2_bypass_fw4 2>/dev/null || true
    uci commit firewall 2>/dev/null || true
  fi
fi
say "removed service and binary"

if [ "${1:-}" = "--purge" ]; then
  rm -rf "$DATA"
  say "purged data dir $DATA"
else
  say "kept data dir $DATA (run with --purge to remove lists/results/blobs)"
fi
say "Done."
