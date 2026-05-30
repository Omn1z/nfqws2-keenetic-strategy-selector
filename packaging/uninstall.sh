#!/bin/sh
# nfqws2-strategy uninstaller.  Pass --purge to also remove stored data.
set -e
INIT=/opt/etc/init.d/S52nfqws2-strategy
BIN=/opt/usr/bin/n2s
OLD_BIN=/opt/usr/bin/nfqws2-strategy   # pre-v0.10.2 name
DATA=/opt/etc/nfqws2-strategy

say() { echo "[nfqws2-strategy] $*"; }
[ "$(id -u)" = "0" ] || { echo "run as root" >&2; exit 1; }

[ -x "$INIT" ] && "$INIT" stop 2>/dev/null || true
rm -f "$INIT" "$BIN" "$OLD_BIN" /opt/var/run/nfqws2-strategy.pid
say "removed service and binary"

if [ "$1" = "--purge" ]; then
  rm -rf "$DATA"
  say "purged data dir $DATA"
else
  say "kept data dir $DATA (run with --purge to remove lists/results/blobs)"
fi
say "Done."
