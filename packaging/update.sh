#!/bin/sh
# nfqws2-strategy updater: fetch the latest release binary and restart the
# service. Lists/results/blobs are preserved; the init script is refreshed so
# existing installs pick up init fixes (e.g. the stale-pidfile-after-reboot
# hardening in is_running()).
set -e

# ----- keep in sync with install.sh -----
REPO="Omn1z/nfqws2-keenetic-strategy-selector"
# -----------------------------------------

BIN=/opt/usr/bin/n2s
OLD_BIN=/opt/usr/bin/nfqws2-strategy   # pre-v0.10.2 name (S51 pgrep collision); removed on migration
INIT=/opt/etc/init.d/S52nfqws2-strategy

say() { echo "[nfqws2-strategy] $*"; }
die() { echo "[nfqws2-strategy] ERROR: $*" >&2; exit 1; }

# write_init regenerates the service init script. KEEP IN SYNC with install.sh.
# Needs $BIN, $INIT, $PORT set.
write_init() {
  cat > "$INIT" <<EOF
#!/bin/sh
BIN=$BIN
PIDFILE=/opt/var/run/nfqws2-strategy.pid
LOGFILE=/opt/var/log/nfqws2-strategy.log
PORT=$PORT
EOF
  cat >> "$INIT" <<'EOF'
# PIDFILE lives on persistent /opt (ubifs) and survives reboots — so verify the
# saved PID is really OUR binary (not a reused PID) before treating it as running.
is_running() {
  [ -f "$PIDFILE" ] || return 1
  _pid="$(cat "$PIDFILE" 2>/dev/null)"
  [ -n "$_pid" ] || return 1
  kill -0 "$_pid" 2>/dev/null || return 1
  case "$(cat "/proc/$_pid/cmdline" 2>/dev/null)" in
    */n2s*) return 0 ;;
    *) return 1 ;;
  esac
}
start() {
  if is_running; then echo "nfqws2-strategy already running"; return 0; fi
  rm -f "$PIDFILE"
  "$BIN" serve -d -l ":$PORT" -log "$LOGFILE" -pid "$PIDFILE"
  sleep 1
  if is_running; then echo "nfqws2-strategy started on :$PORT"; else echo "start failed; see $LOGFILE"; return 1; fi
}
stop() {
  if is_running; then
    PID="$(cat "$PIDFILE")"
    kill "$PID" 2>/dev/null
    i=0
    while kill -0 "$PID" 2>/dev/null && [ "$i" -lt 8 ]; do sleep 1; i=$((i+1)); done
    kill -9 "$PID" 2>/dev/null
  fi
  rm -f "$PIDFILE"; echo "nfqws2-strategy stopped"
}
case "$1" in
  start) start ;;
  stop) stop ;;
  restart) stop; start ;;
  status) is_running && echo running || echo stopped ;;
  *) echo "usage: $0 {start|stop|restart|status}" ;;
esac
EOF
  chmod +x "$INIT"
}

[ "$(id -u)" = "0" ] || die "run as root"
[ -x "$INIT" ] || die "not installed (run install.sh first)"
command -v opkg >/dev/null 2>&1 || die "opkg not found"

arch_raw=$(opkg print-architecture 2>/dev/null | awk '{print $2}')
[ -n "$arch_raw" ] || arch_raw=$(uname -m)
case "$arch_raw" in
  *aarch64*|*arm64*) GOARCH=arm64 ;;
  *armv7*|*armv8*)   GOARCH=arm ;;
  *mipsel*)          GOARCH=mipsle ;;
  *mips*)            GOARCH=mipsle ;;
  *x86_64*|*x64*)    GOARCH=amd64 ;;
  *)                 die "unsupported architecture: $arch_raw" ;;
esac
ASSET="nfqws2-strategy-linux-$GOARCH"
URL="https://github.com/$REPO/releases/latest/download/$ASSET"

fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then wget -O "$2" "$1"
  else die "need curl or wget"; fi
}

say "current: $("$BIN" version 2>/dev/null || "$OLD_BIN" version 2>/dev/null || echo '?')"
say "downloading $URL"
fetch "$URL" "$BIN.new" || die "download failed"
chmod +x "$BIN.new"

PORT="$(sed -n 's/^PORT=//p' "$INIT" 2>/dev/null | head -1)"
[ -n "$PORT" ] || PORT=8090
"$INIT" stop 2>/dev/null || true
mv "$BIN.new" "$BIN"
write_init   # refresh the init (new binary path + stale-pidfile fix), preserving PORT
# migrate away from the pre-v0.10.2 binary name so S51's `pgrep -nf /opt/usr/bin/nfqws2`
# stops matching us (the cause of nfqws-keenetic-web showing nfqws2 as "stopped").
if [ "$OLD_BIN" != "$BIN" ] && [ -e "$OLD_BIN" ]; then rm -f "$OLD_BIN" && say "removed old binary $OLD_BIN"; fi
"$INIT" start || die "service failed to start"
say "updated to: $("$BIN" version 2>/dev/null || echo '?')"
say "Done."
