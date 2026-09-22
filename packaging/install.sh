#!/bin/sh
# Unified nfqws2-strategy installer/updater for Keenetic/Entware and OpenWrt.
# Usage: wget -qO- https://github.com/Omn1z/nfqws2-keenetic-strategy-selector/releases/latest/download/install.sh | sh
set -e

REPO="Omn1z/nfqws2-keenetic-strategy-selector"
ENGINE_REPO="https://nfqws.github.io/nfqws2-keenetic"
PATH="/usr/sbin:/usr/bin:/sbin:/bin:/opt/bin:/opt/sbin:/opt/usr/bin:$PATH"
export PATH

say() { echo "[nfqws2-strategy] $*"; }
die() { echo "[nfqws2-strategy] ERROR: $*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "run as root"

# The same entrypoint installs missing runtime dependencies, the signed NFQWS2
# feed and package, then installs/updates the panel without replacing its data.
if [ -f /etc/openwrt_release ] || { [ -f /etc/rc.common ] && [ -d /etc/init.d ]; }; then
  PLATFORM=openwrt
  BIN_DIR=/usr/bin
  BIN="$BIN_DIR/n2s"
  OLD_BIN="$BIN_DIR/nfqws2-strategy"
  INIT=/etc/init.d/nfqws2-strategy
  DATA=/etc/nfqws2-strategy
  LOG_DIR=/var/log
  RUN_DIR=/var/run
  ENGINE_INIT=/etc/init.d/nfqws2-keenetic
  ENGINE_BIN=/usr/bin/nfqws2
  ENGINE_CONF=/etc/nfqws2
  if command -v apk >/dev/null 2>&1; then
    PM=apk
    say "detected OpenWrt (apk)"
  elif command -v opkg >/dev/null 2>&1; then
    PM=opkg
    say "detected OpenWrt (opkg compatibility mode)"
  else
    die "OpenWrt package manager not found (apk/opkg)"
  fi
else
  PLATFORM=entware
  BIN_DIR=/opt/usr/bin
  BIN="$BIN_DIR/n2s"
  OLD_BIN="$BIN_DIR/nfqws2-strategy"
  INIT=/opt/etc/init.d/S52nfqws2-strategy
  DATA=/opt/etc/nfqws2-strategy
  LOG_DIR=/opt/var/log
  RUN_DIR=/opt/var/run
  ENGINE_INIT=/opt/etc/init.d/S51nfqws2
  ENGINE_BIN=/opt/usr/bin/nfqws2
  ENGINE_CONF=/opt/etc/nfqws2
  PM=opkg
  command -v opkg >/dev/null 2>&1 || die "OpenWrt was not detected and opkg is missing (is this Entware?)"
  say "detected Keenetic/Entware"
fi

# Preserve the selected listening port when this installer is re-run.
PORT="${N2S_PORT:-}"
if [ -z "$PORT" ] && [ -f "$INIT" ]; then
  PORT=$(sed -n 's/^PORT=//p' "$INIT" | head -1 | tr -d '\"')
fi
case "$PORT" in ''|*[!0-9]*) PORT=8090 ;; esac
[ "$PORT" -ge 1 ] 2>/dev/null && [ "$PORT" -le 65535 ] 2>/dev/null || PORT=8090

# Package architectures contain byte order, unlike uname -m on many MIPS
# routers. Never assume all OpenWrt MIPS devices are little-endian.
arch_raw=
if [ "$PM" = apk ]; then
  arch_raw=$(apk --print-arch 2>/dev/null || true)
else
  arch_raw=$(opkg print-architecture 2>/dev/null | awk '$2 != "all" && $2 != "noarch" {if ($3+0 >= p) {p=$3+0; a=$2}} END {print a}')
fi
[ -n "$arch_raw" ] || arch_raw=$(uname -m)
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
  *)                 die "unsupported architecture: $arch_raw" ;;
esac
ASSET="nfqws2-strategy-linux-$GOARCH"
URL="https://github.com/$REPO/releases/latest/download/$ASSET"
say "arch=$arch_raw -> $ASSET"

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$2" "$1"
  else
    die "need curl or wget"
  fi
}

install_dependencies() {
  say "checking runtime dependencies ($PM)"
  if [ "$PM" = apk ]; then
    # apk uses the native firmware feeds for kernel modules. Never force a
    # mismatching kernel package or replace the router's configured feeds.
    # OpenWrt 25 apk cannot choose a provider for the virtual iptables and
    # ip6tables names on a fresh router. The nft variants also provide the
    # iptables-restore commands used by the NFQUEUE bypass helper.
    apk --update-cache add ca-certificates curl ip-full ipset kmod-ipt-ipset kmod-tun \
      iptables-nft iptables-mod-nfqueue iptables-mod-conntrack-extra iptables-mod-ipopt \
      iptables-mod-extra iptables-mod-filter ip6tables-nft ip6tables-extra ip6tables-mod-nat \
      || die "dependency installation failed; check feed availability and firmware/kernel versions"
  elif [ "$PLATFORM" = openwrt ]; then
    opkg update || die "package feed refresh failed"
    opkg install ca-certificates curl ip-full ipset kmod-ipt-ipset kmod-tun \
      iptables iptables-mod-nfqueue iptables-mod-conntrack-extra iptables-mod-ipopt \
      iptables-mod-extra iptables-mod-filter ip6tables ip6tables-extra ip6tables-mod-nat \
      || die "dependency installation failed; check feed availability and firmware/kernel versions"
  else
    opkg update || die "package feed refresh failed"
    opkg install ca-certificates curl ipset || die "dependency installation failed"
  fi
}

install_engine() {
  say "configuring NFQWS2 package feed"
  if [ "$PM" = apk ]; then
    mkdir -p /etc/apk/keys /etc/apk/repositories.d
    fetch "$ENGINE_REPO/openwrt/nfqws2-keenetic.pem" /etc/apk/keys/nfqws2-keenetic.pem.new || die "cannot download NFQWS2 repository key"
    mv /etc/apk/keys/nfqws2-keenetic.pem.new /etc/apk/keys/nfqws2-keenetic.pem
    printf '%s\n' "$ENGINE_REPO/openwrt/packages.adb" > /etc/apk/repositories.d/nfqws2-keenetic.list
    apk --update-cache add nfqws2-keenetic || die "NFQWS2 installation failed"
  elif [ "$PLATFORM" = openwrt ]; then
    mkdir -p /etc/opkg
    key=$(mktemp /tmp/nfqws2-key.XXXXXX) || die "cannot create temporary key file"
    fetch "$ENGINE_REPO/openwrt/nfqws2-keenetic.pub" "$key" || die "cannot download NFQWS2 repository key"
    opkg-key add "$key" || die "cannot trust NFQWS2 repository key"
    rm -f "$key"
    printf '%s\n' "src/gz nfqws2-keenetic $ENGINE_REPO/openwrt" > /etc/opkg/nfqws2-keenetic.conf
    opkg update && opkg install nfqws2-keenetic || die "NFQWS2 installation failed"
  else
    mkdir -p /opt/etc/opkg
    printf '%s\n' "src/gz nfqws2-keenetic $ENGINE_REPO/all" > /opt/etc/opkg/nfqws2-keenetic.conf
    opkg update && opkg install nfqws2-keenetic || die "NFQWS2 installation failed"
  fi
  [ -x "$ENGINE_BIN" ] && [ -x "$ENGINE_INIT" ] || die "NFQWS2 package did not install its binary/service"
  ensure_bypass_init_hook
  if [ "$PLATFORM" = openwrt ]; then
    "$ENGINE_INIT" enable || die "cannot enable NFQWS2 service"
  fi
  # Do not restart an already running engine when updating only the panel.
  if ! pidof nfqws2 >/dev/null 2>&1 && ! pidof nfqws2.real >/dev/null 2>&1; then
    "$ENGINE_INIT" start || die "NFQWS2 service failed to start"
  fi
}

repair_nfqw2_config() {
  # nfqws2 1.2.8's stock OpenWrt template contains one QUIC fake without a
  # payload blob. Lua rejects it at startup (`fake: 'blob' arg required`),
  # leaving NFQUEUE alive but unable to process UDP. Repair only that exact
  # upstream token and keep a one-time backup of the user's config.
  conf=/etc/nfqws2/nfqws2.conf
  [ "$PLATFORM" = openwrt ] || conf=/opt/etc/nfqws2/nfqws2.conf
  [ -f "$conf" ] || return 0
  grep -Fq -- 'fake:repeats=6:strategy=1' "$conf" || return 0
  [ -f "$conf.n2s-bak" ] || cp "$conf" "$conf.n2s-bak"
  sed -i 's/fake:repeats=6:strategy=1/fake:blob=quic_initial:repeats=6:strategy=1/g' "$conf"
  say "repaired NFQWS2 QUIC fake payload in $conf"
  "$ENGINE_INIT" restart >/dev/null 2>&1 || true
}

# Both upstream init scripts recreate nfqws_pre/nfqws_post on restart. Repair
# only our tagged block; the package's vendor nfqws-bypass.sh stays untouched.
# Migrate old blocks even before the new panel creates its owned helper, so an
# update never invokes the older vendor helper from our post-start hook.
ensure_bypass_init_hook() {
  bypass="$ENGINE_CONF/nfqws-strategy-bypass.sh"
  fw4_hook="$ENGINE_CONF/nfqws-bypass-fw4.sh"
  ndm_hook="${ENGINE_CONF%/*}/ndm/netfilter.d/101-nfqws2-bypass.sh"
  [ -f "$ENGINE_INIT" ] || return 0
  marker='# nfqws2-strategy: reapply NFQUEUE bypass'
  if [ ! -f "$bypass" ] && [ ! -f "$fw4_hook" ] && [ ! -f "$ndm_hook" ] &&
     ! grep -Fq "$marker" "$ENGINE_INIT"; then
    return 0
  fi
  tmp=$(mktemp "$ENGINE_INIT.n2s-new.XXXXXX") || return 1
  if ! awk -v marker="$marker" -v helper="$bypass" '
    function block() {
      print marker
      print "[ -x '\''" helper "'\'' ] && '\''" helper "'\'' iptables >/dev/null 2>&1 || true"
      print "[ -x '\''" helper "'\'' ] && '\''" helper "'\'' ip6tables >/dev/null 2>&1 || true"
    }
    function own(line, family) {
      return line ~ /^[[:space:]]*\[ -x / && index(line, " ] && ") &&
        (index(line, "/nfqws-bypass.sh") || index(line, "/nfqws-strategy-bypass.sh")) &&
        index(line, " " family " >/dev/null 2>&1 || true")
    }
    { lines[NR]=$0; trimmed=$0; sub(/^[[:space:]]+/, "", trimmed); sub(/[[:space:]]+$/, "", trimmed)
      if (trimmed == marker) { if (tag) bad=1; tag=NR }
      if (!anchor && trimmed ~ /^system_config([[:space:]]|$)/ && trimmed !~ /system_config[[:space:]]*\(\)/) anchor=NR
    }
    END {
      if (bad || (tag && (!own(lines[tag+1], "iptables") || !own(lines[tag+2], "ip6tables"))) || (!tag && !anchor)) exit 1
      for (i=1; i<=NR; i++) {
        if (i==tag) { block(); i+=2; continue }
        print lines[i]
        if (!tag && i==anchor) block()
      }
    }
  ' "$ENGINE_INIT" > "$tmp"; then
    rm -f "$tmp"
    say "warning: cannot safely repair NFQWS2 bypass hook (unknown block or no system_config anchor)"
    return 1
  fi
  if cmp -s "$ENGINE_INIT" "$tmp" 2>/dev/null; then
    rm -f "$tmp"
  else
    [ -f "$ENGINE_INIT.n2s-bak" ] || cp "$ENGINE_INIT" "$ENGINE_INIT.n2s-bak"
    chmod +x "$tmp"
    mv "$tmp" "$ENGINE_INIT"
  fi

  if [ "$PLATFORM" = openwrt ]; then
    cat > "$fw4_hook" <<EOF
#!/bin/sh
[ -x '$bypass' ] || exit 0
'$ENGINE_INIT' firewall_iptables >/dev/null 2>&1 || true
'$ENGINE_INIT' firewall_ip6tables >/dev/null 2>&1 || true
'$bypass' iptables >/dev/null || true
'$bypass' ip6tables >/dev/null || true
EOF
    chmod +x "$fw4_hook"
    if command -v uci >/dev/null 2>&1; then
      uci -q show firewall.nfqws2_bypass_fw4 >/dev/null 2>&1 || uci set firewall.nfqws2_bypass_fw4=include
      uci set firewall.nfqws2_bypass_fw4.type=script
      uci set "firewall.nfqws2_bypass_fw4.path=$fw4_hook"
      uci set firewall.nfqws2_bypass_fw4.fw4_compatible=1
      uci commit firewall
    fi
  else
    mkdir -p "${ndm_hook%/*}"
    cat > "$ndm_hook" <<EOF
#!/bin/sh
[ "\${table:-}" = mangle ] || exit 0
case "\${type:-}" in iptables|ip6tables) ;; *) exit 0 ;; esac
[ -x '$bypass' ] || exit 0
'$bypass' "\$type" >/dev/null || true
EOF
    chmod +x "$ndm_hook"
  fi
  # The owned helper only rewrites its own chain/jumps, without vendor DNS or
  # a full engine firewall rebuild. The panel refreshes its DNS cache on apply.
  [ -x "$bypass" ] || return 0
  "$bypass" iptables >/dev/null 2>&1 || true
  "$bypass" ip6tables >/dev/null 2>&1 || true
}

# Replace old tagged vendor calls before any package/config restart.
ensure_bypass_init_hook
if [ "${N2S_SKIP_DEPS:-0}" = 1 ]; then
  say "skipping package/dependency setup (N2S_SKIP_DEPS=1)"
else
  install_dependencies
  install_engine
  repair_nfqw2_config
fi
ensure_bypass_init_hook
if [ "${N2S_DEPS_ONLY:-0}" = 1 ]; then
  say "NFQWS2 and runtime dependencies are ready"
  exit 0
fi

mkdir -p "$DATA" "$LOG_DIR" "$RUN_DIR" "$BIN_DIR"
if [ -n "$N2S_BIN_SRC" ]; then
  say "using local binary $N2S_BIN_SRC (skipping download)"
  cp "$N2S_BIN_SRC" "$BIN.new"
else
  say "downloading $URL"
  fetch "$URL" "$BIN.new" || die "download failed"
fi
chmod +x "$BIN.new"
# Catch a wrong/corrupt architecture before stopping the working service.
"$BIN.new" version >/dev/null 2>&1 || die "downloaded panel binary cannot run on this router"

[ -x "$INIT" ] && "$INIT" stop 2>/dev/null || true
mv "$BIN.new" "$BIN"
[ -e "$OLD_BIN" ] && [ "$OLD_BIN" != "$BIN" ] && rm -f "$OLD_BIN" && say "removed old binary $OLD_BIN"

if [ "$PLATFORM" = openwrt ]; then
  # procd must supervise the foreground process. Do not use serve -d here:
  # daemonising behind procd makes crashes invisible and prevents respawn.
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
  "$INIT" start || die "service failed to start"
else
  cat > "$INIT" <<EOF
#!/bin/sh
BIN=$BIN
PIDFILE=$RUN_DIR/nfqws2-strategy.pid
LOGFILE=$LOG_DIR/nfqws2-strategy.log
PORT=$PORT
EOF
  cat >> "$INIT" <<'EOF'
# Verify the PID is really our binary; a stale PID can be reused after reboot.
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
  "$INIT" start || die "service failed to start"
fi

IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oE 'src [0-9.]+' | awk '{print $2}' | head -1)
[ -n "$IP" ] || IP="<router-ip>"
say "installed version: $("$BIN" version 2>/dev/null || echo '?')"
say "Web UI: http://$IP:$PORT"
say "Done."
