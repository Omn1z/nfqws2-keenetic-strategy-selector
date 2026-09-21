#!/bin/sh
# nfqws2-strategy uninstaller. Pass --purge to also remove stored data.
set -e

say() { echo "[nfqws2-strategy] $*"; }
[ "$(id -u)" = "0" ] || { echo "run as root" >&2; exit 1; }

if [ -f /etc/openwrt_release ] || { [ -f /etc/rc.common ] && [ -d /etc/init.d ]; }; then
  INIT=/etc/init.d/nfqws2-strategy
  BIN=/usr/bin/n2s
  OLD_BIN=/usr/bin/nfqws2-strategy
  DATA=/etc/nfqws2-strategy
  PIDFILE=/var/run/nfqws2-strategy.pid
  LOGFILE=/var/log/nfqws2-strategy.log
else
  INIT=/opt/etc/init.d/S52nfqws2-strategy
  BIN=/opt/usr/bin/n2s
  OLD_BIN=/opt/usr/bin/nfqws2-strategy
  DATA=/opt/etc/nfqws2-strategy
  PIDFILE=/opt/var/run/nfqws2-strategy.pid
  LOGFILE=/opt/var/log/nfqws2-strategy.log
fi

[ -x "$INIT" ] && "$INIT" stop 2>/dev/null || true
if [ -f /etc/openwrt_release ] || { [ -f /etc/rc.common ] && [ -d /etc/init.d ]; }; then
  "$INIT" disable 2>/dev/null || true
fi
rm -f "$INIT" "$BIN" "$OLD_BIN" "$PIDFILE" "$LOGFILE"
# Remove the optional OpenWrt fw4 include created by the NFQUEUE Bypass tab;
# leave the NFQWS2 engine package, its configs and user lists intact.
if [ -f /etc/openwrt_release ] || { [ -f /etc/rc.common ] && [ -d /etc/init.d ]; }; then
  if command -v uci >/dev/null 2>&1; then
    uci -q delete firewall.nfqws2_bypass_fw4 2>/dev/null || true
    uci commit firewall 2>/dev/null || true
  fi
fi
if [ -f /etc/openwrt_release ] || { [ -f /etc/rc.common ] && [ -d /etc/init.d ]; }; then
  rm -f /etc/nfqws2/nfqws-bypass-fw4.sh
fi
say "removed service and binary"

if [ "$1" = "--purge" ]; then
  rm -rf "$DATA"
  say "purged data dir $DATA"
else
  say "kept data dir $DATA (run with --purge to remove lists/results/blobs)"
fi
say "Done."
