#!/bin/sh
# nfqws2-strategy installer for Keenetic / Entware.
# Usage:  curl -fsSL https://raw.githubusercontent.com/Omn1z/nfqws2-keenetic-strategy-selector/master/packaging/install.sh | sh
set -e

# ----- change this before publishing -----
REPO="Omn1z/nfqws2-keenetic-strategy-selector"
# ------------------------------------------
PORT="${N2S_PORT:-8090}"

BIN_DIR=/opt/usr/bin
BIN="$BIN_DIR/nfqws2-strategy"
INIT=/opt/etc/init.d/S52nfqws2-strategy
DATA=/opt/etc/nfqws2-strategy

say() { echo "[nfqws2-strategy] $*"; }
die() { echo "[nfqws2-strategy] ERROR: $*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "run as root"
command -v opkg >/dev/null 2>&1 || die "opkg not found (is this Entware?)"

# --- detect architecture ---
arch_raw=$(opkg print-architecture 2>/dev/null | awk '{print $2}')
[ -n "$arch_raw" ] || arch_raw=$(uname -m)
case "$arch_raw" in
  *aarch64*|*arm64*) GOARCH=arm64 ;;
  *armv7*|*armv8*)   GOARCH=arm ;;
  *mipsel*)          GOARCH=mipsle ;;
  *mips*)            GOARCH=mipsle ;;  # Keenetic MIPS are little-endian
  *x86_64*|*x64*)    GOARCH=amd64 ;;
  *)                 die "unsupported architecture: $arch_raw" ;;
esac
ASSET="nfqws2-strategy-linux-$GOARCH"
URL="https://github.com/$REPO/releases/latest/download/$ASSET"
say "arch=$arch_raw -> $ASSET"

# --- download ---
fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then wget -O "$2" "$1"
  else die "need curl or wget"; fi
}
mkdir -p "$DATA" /opt/var/log /opt/var/run "$BIN_DIR"
if [ -n "$N2S_BIN_SRC" ]; then
  say "using local binary $N2S_BIN_SRC (skipping download)"
  cp "$N2S_BIN_SRC" "$BIN.new"
else
  say "downloading $URL"
  fetch "$URL" "$BIN.new" || die "download failed"
fi
chmod +x "$BIN.new"

# --- stop old, install new ---
[ -x "$INIT" ] && "$INIT" stop 2>/dev/null || true
mv "$BIN.new" "$BIN"

# --- write init script ---
cat > "$INIT" <<EOF
#!/bin/sh
BIN=$BIN
PIDFILE=/opt/var/run/nfqws2-strategy.pid
LOGFILE=/opt/var/log/nfqws2-strategy.log
PORT=$PORT
EOF
cat >> "$INIT" <<'EOF'
# PIDFILE lives on persistent /opt (ubifs), so it survives a reboot. A plain
# `kill -0` would false-positive if the stale PID was reused by another boot-time
# process — and then start() would skip launching us. So verify the PID is really
# OUR binary via /proc/<pid>/cmdline (the shell truncates the NUL-separated cmdline
# at argv[0], i.e. the binary path).
is_running() {
  [ -f "$PIDFILE" ] || return 1
  _pid="$(cat "$PIDFILE" 2>/dev/null)"
  [ -n "$_pid" ] || return 1
  kill -0 "$_pid" 2>/dev/null || return 1
  case "$(cat "/proc/$_pid/cmdline" 2>/dev/null)" in
    *nfqws2-strategy*) return 0 ;;
    *) return 1 ;;
  esac
}
start() {
  if is_running; then echo "nfqws2-strategy already running"; return 0; fi
  rm -f "$PIDFILE"   # drop any stale pidfile (survives reboots on persistent /opt)
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

"$INIT" start || die "service failed to start"

IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oE 'src [0-9.]+' | awk '{print $2}' | head -1)
[ -n "$IP" ] || IP="<router-ip>"
say "installed version: $("$BIN" version 2>/dev/null || echo '?')"
say "Web UI: http://$IP:$PORT"
say "Done."
