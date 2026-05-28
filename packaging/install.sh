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
is_running() { [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; }
start() {
  if is_running; then echo "nfqws2-strategy already running"; return 0; fi
  "$BIN" serve -d -l ":$PORT" -log "$LOGFILE" -pid "$PIDFILE"
  sleep 1
  if is_running; then echo "nfqws2-strategy started on :$PORT"; else echo "start failed; see $LOGFILE"; return 1; fi
}
stop() {
  if is_running; then kill "$(cat "$PIDFILE")" 2>/dev/null; sleep 1; fi
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
