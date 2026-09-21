#!/bin/sh
# nfqws2-strategy updater: fetch the latest release binary and restart the
# service. Data, lists, results and blobs are preserved.
set -e

REPO="Omn1z/nfqws2-keenetic-strategy-selector"

say() { echo "[nfqws2-strategy] $*"; }
die() { echo "[nfqws2-strategy] ERROR: $*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "run as root"

if [ -f /etc/openwrt_release ] || { [ -f /etc/rc.common ] && [ -d /etc/init.d ]; }; then
  PLATFORM=openwrt
  BIN=/usr/bin/n2s
  OLD_BIN=/usr/bin/nfqws2-strategy
  INIT=/etc/init.d/nfqws2-strategy
  DATA=/etc/nfqws2-strategy
  LOG_DIR=/var/log
  RUN_DIR=/var/run
  ENGINE_BIN=/usr/bin/nfqws2
  ENGINE_INIT=/etc/init.d/nfqws2-keenetic
else
  PLATFORM=entware
  BIN=/opt/usr/bin/n2s
  OLD_BIN=/opt/usr/bin/nfqws2-strategy
  INIT=/opt/etc/init.d/S52nfqws2-strategy
  DATA=/opt/etc/nfqws2-strategy
  LOG_DIR=/opt/var/log
  RUN_DIR=/opt/var/run
  ENGINE_BIN=/opt/usr/bin/nfqws2
  ENGINE_INIT=/opt/etc/init.d/S51nfqws2
  command -v opkg >/dev/null 2>&1 || die "OpenWrt was not detected and opkg is missing"
fi

[ -x "$INIT" ] || die "not installed (run install.sh first)"

arch_raw=
if command -v apk >/dev/null 2>&1; then
  arch_raw=$(apk --print-arch 2>/dev/null || true)
elif command -v opkg >/dev/null 2>&1; then
  arch_raw=$(opkg print-architecture 2>/dev/null | awk '$2 != "all" && $2 != "noarch" {if ($3+0 >= p) {p=$3+0; a=$2}} END {print a}')
fi
[ -n "$arch_raw" ] 2>/dev/null || arch_raw=$(uname -m)
case "$arch_raw" in
  *aarch64*|*arm64*) GOARCH=arm64 ;;
  *armv5*|*armv6*|*arm_arm1176*) die "ARMv7 or newer is required: $arch_raw" ;;
  *armv7*|*armv8*|*armhf*|arm_*) GOARCH=arm ;;
  *mips64*) die "unsupported architecture: $arch_raw" ;;
  *mipsel*|*mipsle*) GOARCH=mipsle ;;
  mips)
    endian=$(od -An -t u1 -j 5 -N 1 /bin/busybox 2>/dev/null | tr -d ' ')
    case "$endian" in 1) GOARCH=mipsle ;; 2) GOARCH=mips ;; *) die "cannot detect MIPS byte order" ;; esac ;;
  *mips*) GOARCH=mips ;;
  *x86_64*|*amd64*|*x64*) GOARCH=amd64 ;;
  *) die "unsupported architecture: $arch_raw" ;;
esac
URL="https://github.com/$REPO/releases/latest/download/nfqws2-strategy-linux-$GOARCH"

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$2" "$1"
  else
    die "need curl or wget (on OpenWrt install one with apk)"
  fi
}

# Older panel installations predate the unified dependency/engine setup.  Use
# the same signed installer in dependency-only mode before replacing the panel,
# so `update.sh` is a complete recovery path on a fresh OpenWrt 25 router.
if [ ! -x "$ENGINE_BIN" ] || [ ! -x "$ENGINE_INIT" ]; then
  say "NFQWS2 is missing; bootstrapping engine and dependencies"
  bootstrap=$(mktemp /tmp/nfqws2-install.XXXXXX) || die "cannot create temporary installer"
  fetch "https://github.com/$REPO/releases/latest/download/install.sh" "$bootstrap" || { rm -f "$bootstrap"; die "cannot download unified installer"; }
  N2S_DEPS_ONLY=1 sh "$bootstrap" || { rm -f "$bootstrap"; die "NFQWS2 bootstrap failed"; }
  rm -f "$bootstrap"
fi

# Keep upgrades safe for the stock NFQWS2 1.2.8 OpenWrt template too.  That
# template contains a QUIC fake without a blob, which makes Lua reject the
# packet at runtime even though the service itself stays up.
repair_nfqw2_config() {
  conf=/etc/nfqws2/nfqws2.conf
  [ "$PLATFORM" = openwrt ] || conf=/opt/etc/nfqws2/nfqws2.conf
  [ -f "$conf" ] || return 0
  grep -Fq -- 'fake:repeats=6:strategy=1' "$conf" || return 0
  [ -f "$conf.n2s-bak" ] || cp "$conf" "$conf.n2s-bak"
  sed -i 's/fake:repeats=6:strategy=1/fake:blob=quic_initial:repeats=6:strategy=1/g' "$conf"
  say "repaired NFQWS2 QUIC fake payload in $conf"
  "$ENGINE_INIT" restart >/dev/null 2>&1 || true
}
repair_nfqw2_config

# Keep the port selected in the existing init script across an update.
PORT="$(sed -n 's/^PORT=//p' "$INIT" 2>/dev/null | head -1 | tr -d '\"')"
case "$PORT" in
  ''|*[!0-9]*) PORT=8090 ;;
esac
[ "$PORT" -ge 1 ] 2>/dev/null && [ "$PORT" -le 65535 ] 2>/dev/null || PORT=8090

say "current: $("$BIN" version 2>/dev/null || "$OLD_BIN" version 2>/dev/null || echo '?')"
say "arch=$arch_raw -> $URL"
fetch "$URL" "$BIN.new" || die "download failed"
chmod +x "$BIN.new"
"$INIT" stop 2>/dev/null || true
mv "$BIN.new" "$BIN"
[ -e "$OLD_BIN" ] && [ "$OLD_BIN" != "$BIN" ] && rm -f "$OLD_BIN" && say "removed old binary $OLD_BIN"

if [ "$PLATFORM" = openwrt ]; then
  cat > "$INIT" <<EOF
#!/bin/sh /etc/rc.common
START=99
STOP=10
USE_PROCD=1

BIN="$BIN"
LOGFILE="$LOG_DIR/nfqws2-strategy.log"
PORT="$PORT"

start_service() {
  procd_open_instance
  procd_set_param command "\$BIN" serve -l ":\$PORT" -log "\$LOGFILE"
  procd_set_param env N2S_DATA="$DATA" N2S_INIT="$INIT" N2S_NFQWS2_CONF="/etc/nfqws2/nfqws2.conf" N2S_NFQWS_BIN="/usr/bin/nfqws2" N2S_NFQWS2_INIT="/etc/init.d/nfqws2-keenetic"
  procd_set_param respawn 3600 5 5
  procd_close_instance
}
EOF
  chmod +x "$INIT"
  "$INIT" enable 2>/dev/null || true
else
  cat > "$INIT" <<EOF
#!/bin/sh
BIN=$BIN
PIDFILE=$RUN_DIR/nfqws2-strategy.pid
LOGFILE=$LOG_DIR/nfqws2-strategy.log
PORT=$PORT
EOF
  cat >> "$INIT" <<'EOF'
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
fi
chmod +x "$INIT"
"$INIT" start || die "service failed to start"
say "updated to: $("$BIN" version 2>/dev/null || echo '?')"
say "Done."
