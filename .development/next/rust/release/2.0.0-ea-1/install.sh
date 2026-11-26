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
  COMPACT_BIN=/usr/lib/nfqws2-strategy/n2s-compact
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
  if PATH=/usr/sbin:/usr/bin:/sbin:/bin command -v apk >/dev/null 2>&1; then
    PM=apk
    say "detected OpenWrt (apk)"
  elif PATH=/usr/sbin:/usr/bin:/sbin:/bin command -v opkg >/dev/null 2>&1; then
    PM=opkg
    say "detected OpenWrt (opkg compatibility mode)"
  else
    die "OpenWrt package manager not found (apk/opkg)"
  fi
else
  PLATFORM=entware
  COMPACT_BIN=/opt/lib/nfqws2-strategy/n2s-compact
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

read_selective_init() {
  awk '/^[[:space:]]*export[[:space:]]+N2S_AWG_SELECTIVE_ACCEL=[01][[:space:]]*$/ {v=$0; sub(/.*=/,"",v); sub(/[[:space:]]+$/,"",v)} END{print v}' "$1"
}
valid_bind_host() {
  case "$1" in *'
'*) return 1 ;; esac
  [ -z "$1" ] || printf '%s\n' "$1" | grep -Eq '^(\[[0-9a-fA-F:.]+\]|[0-9.]+)$'
}
active_profile=full
bind_host=
if [ "$PLATFORM" = entware ] && [ -f "$INIT" ]; then
  bind_host=$(awk -F"'" '/^BIND_HOST=/ {
    if (++count>1 || NF!=3 || $1!="BIND_HOST=" || $3!="") exit 1
    print $2
  }' "$INIT") || die "ambiguous saved panel bind address"
  valid_bind_host "$bind_host" || die "invalid saved panel bind address"
fi
selective_accel=${N2S_AWG_SELECTIVE_ACCEL:-}
if [ -z "$selective_accel" ] && [ -f "$INIT" ]; then
  selective_accel=$(read_selective_init "$INIT")
fi
if [ "$(readlink "$BIN" 2>/dev/null)" = "$COMPACT_BIN" ]; then
  active_profile=compact
fi
profile=${N2S_PROFILE:-$active_profile}
case "$profile" in
  full) ;;
  compact)
    [ -z "${N2S_BIN_SRC:-}" ] || die "compact installs use the configured $PM feed; N2S_BIN_SRC selects a standalone full binary"
    ;;
  *) die "unknown N2S_PROFILE: $profile" ;;
esac

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
if [ "$profile" = full ]; then
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
fi
say "arch=$arch_raw profile=$profile"

# BEGIN verified HTTPS download helpers
https_curl_ready() {
  command -v curl >/dev/null 2>&1 || return 1
  https_curl_version=$(curl --version 2>/dev/null) || return 1
  printf '%s\n' "$https_curl_version" | grep -Eq '^Protocols:.* https([[:space:]]|$)'
}

https_wget_ready() {
  [ -x "$1" ] || return 1
  https_wget_version=$("$1" --version 2>/dev/null) || return 1
  case "$https_wget_version" in 'GNU Wget '*) ;; *) return 1 ;; esac
  printf '%s\n' "$https_wget_version" | grep -Eq '(^|[[:space:]])\+https([[:space:]]|$)'
}

https_wget_path() {
  https_entware_wget=${N2S_ENTWARE_WGET:-/opt/bin/wget}
  if https_wget_ready "$https_entware_wget"; then
    printf '%s\n' "$https_entware_wget"
    return 0
  fi
  https_path_wget=$(command -v wget 2>/dev/null) || return 1
  https_wget_ready "$https_path_wget" || return 1
  printf '%s\n' "$https_path_wget"
}

https_timeout_ready() {
  for https_timeout in "${N2S_TIMEOUT:-timeout}" "${N2S_ENTWARE_TIMEOUT:-/opt/bin/timeout}"; do
    if command -v "$https_timeout" >/dev/null 2>&1 && "$https_timeout" -s KILL 1 true >/dev/null 2>&1; then
      HTTPS_TIMEOUT=$https_timeout
      HTTPS_TIMEOUT_BUSYBOX=0
      return 0
    fi
  done
  https_busybox=${N2S_BUSYBOX:-/bin/busybox}
  if [ -x "$https_busybox" ] && "$https_busybox" timeout -s KILL 1 true >/dev/null 2>&1; then
    HTTPS_TIMEOUT=$https_busybox
    HTTPS_TIMEOUT_BUSYBOX=1
    return 0
  fi
  return 1
}

https_ensure_timeout() {
  https_timeout_ready && return 0
  say "installing coreutils-timeout for bounded HTTPS downloads"
  if [ "${PM:-}" = apk ] || { [ -z "${PM:-}" ] && command -v apk >/dev/null 2>&1; }; then
    apk --update-cache add coreutils-timeout || return 1
  elif command -v opkg >/dev/null 2>&1; then
    opkg update && opkg install coreutils-timeout || return 1
  else
    say "a working timeout command is required for GNU wget" >&2
    return 1
  fi
  hash -r 2>/dev/null || true
  https_timeout_ready || { say "coreutils-timeout is unavailable or cannot run; refusing an unbounded download" >&2; return 1; }
}

https_run_bounded() {
  https_seconds=$1
  shift
  if [ "$HTTPS_TIMEOUT_BUSYBOX" = 1 ]; then
    "$HTTPS_TIMEOUT" timeout -s KILL "$https_seconds" "$@"
  else
    "$HTTPS_TIMEOUT" -s KILL "$https_seconds" "$@"
  fi
}

https_prepare() {
  https_client_package=
  if ! https_curl_ready && ! https_wget_path >/dev/null; then
    if [ "${PLATFORM:-}" = openwrt ] || [ "${PM:-}" = apk ]; then
      https_client_package=curl
    else
      https_client_package=wget-ssl
    fi
  fi
  if [ "${PM:-}" = apk ] || { [ -z "${PM:-}" ] && command -v apk >/dev/null 2>&1; }; then
    apk --update-cache add ca-bundle ca-certificates $https_client_package || return 1
  else
    opkg update || return 1
    if [ "${PLATFORM:-}" = openwrt ]; then
      opkg install ca-bundle ca-certificates $https_client_package || return 1
    else
      opkg install ca-certificates $https_client_package || return 1
    fi
  fi
  https_curl_ready || https_wget_path >/dev/null || { say "no working HTTPS-capable curl or GNU wget after dependency setup" >&2; return 1; }
}

https_clock() {
  # Router /proc supplies monotonic time even when NTP corrects the wall clock.
  if [ -r /proc/uptime ]; then
    read -r https_uptime https_unused < /proc/uptime
    printf '%s\n' "${https_uptime%%.*}"
  else
    date +%s
  fi
}

https_wget_fetch() {
  https_wget=$1
  https_target=$2
  https_payload=$3
  https_headers=$4
  https_ensure_timeout || return 1
  https_start=$(https_clock) || return 1
  case "$https_start" in ''|*[!0-9]*) return 1 ;; esac
  https_hop=0
  while [ "$https_hop" -le 5 ]; do
    case "$https_target" in https://?*) ;; *) return 1 ;; esac
    case "$https_target" in *[[:space:]]*|*'\'*) return 1 ;; esac
    https_authority=${https_target#https://}
    https_authority=${https_authority%%[/?#]*}
    case "$https_authority" in ''|*@*) return 1 ;; esac
    https_now=$(https_clock) || return 1
    case "$https_now" in ''|*[!0-9]*) return 1 ;; esac
    https_remaining=$((300 - (https_now - https_start)))
    [ "$https_remaining" -le 300 ] || https_remaining=300
    [ "$https_remaining" -gt 0 ] || return 124
    rm -f "$https_payload"
    https_status=0
    https_run_bounded "$https_remaining" "$https_wget" -4 --https-only --max-redirect=0 --server-response \
      --timeout=30 --tries=1 -O "$https_payload" "$https_target" 2> "$https_headers" || https_status=$?
    if [ "$https_status" = 0 ]; then [ -s "$https_payload" ] && return 0; return 1; fi
    # Follow a bounded number of explicit HTTPS redirects ourselves. GNU
    # wget's --https-only is intended for recursive links, so do not rely on
    # it to prevent a redirect to plaintext. Ignore unindented diagnostic text.
    [ "$https_status" = 8 ] || return "$https_status"
    https_location=$(awk '
      /^[[:space:]]+HTTP\// { status=$2; location="" }
      /^[[:space:]]+/ && tolower($1)=="location:" {
        location=substr($0,index($0,":")+1); sub(/^[[:space:]]*/,"",location); sub(/[[:space:]]*$/,"",location)
      }
      END { if (status ~ /^30[12378]$/ && location!="") print location; else exit 1 }
    ' "$https_headers") || return 1
    https_target=$https_location
    https_hop=$((https_hop+1))
  done
  return 1
}

fetch() {
  (
    fetch_url=$1
    fetch_dest=$2
    case "$fetch_url" in https://?*) ;; *) exit 1 ;; esac
    fetch_dir=$(mktemp -d "$fetch_dest.n2s-download.XXXXXX") || exit 1
    fetch_part="$fetch_dir/payload.part"
    fetch_headers="$fetch_dir/headers"
    trap 'rm -f "$fetch_part" "$fetch_headers"; rmdir "$fetch_dir" 2>/dev/null || true' 0
    trap 'exit 129' 1
    trap 'exit 130' 2
    trap 'exit 143' 15
    if https_curl_ready; then
      for fetch_family in auto ipv4; do
        rm -f "$fetch_part"
        if [ "$fetch_family" = ipv4 ]; then set -- -4; else set --; fi
        if curl "$@" -fSL --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 300 \
          -o "$fetch_part" "$fetch_url" && [ -s "$fetch_part" ] && mv -f "$fetch_part" "$fetch_dest"; then exit 0; fi
      done
    fi
    fetch_wget=$(https_wget_path) || exit 1
    if https_wget_fetch "$fetch_wget" "$fetch_url" "$fetch_part" "$fetch_headers" && [ -s "$fetch_part" ] && mv -f "$fetch_part" "$fetch_dest"; then exit 0; fi
    exit 1
  )
}
# END verified HTTPS download helpers

compact_apk() (
  # apk clears hook environments. Identify its process without forwarding
  # installer credentials or changing the client's proxy configuration.
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

compact_inventory() {
  # Normalize apk's name-version listing to opkg's "name - version".
  # Limit the query to our feed so a router never buffers its full database.
  if [ "$PM" = apk ]; then
    rows=$(apk list "--$1" 'nfqws2-strategy-*') || return 1
    printf '%s\n' "$rows" | awk '
      match($1, /^nfqws2-strategy-(compact|runs|blockcheck|strategies|geo|trace|tgws|tools)-[0-9]/) {
        print substr($1, 1, RLENGTH-2), "-", substr($1, RLENGTH)
      }'
  else
    opkg "list-$1" 'nfqws2-strategy-*'
  fi
}

compact_packages() {
  # Only upgrade previously selected modules. Exact dependencies in the feed
  # tie their hashed UI imports and optional helper to the core build.
  compact_installed=$(compact_inventory installed) || return 1
  printf '%s\n' "$compact_installed" |
    awk '$1 ~ /^nfqws2-strategy-(runs|blockcheck|strategies|geo|trace|tgws|tools)$/ {print $1}'
}

retire_compact_snapshot() (
  backup=$compact_dir/.compact-previous
  receipt=$compact_dir/.compact-accepted-snapshot
  [ ! -L "$backup" ] && [ ! -L "$receipt" ] || exit 1
  if [ -e "$receipt" ]; then
    [ -f "$receipt" ] || exit 1
  elif [ "$1" = retry ]; then
    exit 0
  fi
  if [ -e "$backup" ]; then
    [ -d "$backup" ] || exit 1
    generation=$(panel_inode "$backup") || exit 1
    if [ -f "$receipt" ]; then
      [ "$(cat "$receipt")" = "$generation" ] || exit 1
    else
      # Keep acceptance outside the tree: a failed or partial recursive
      # removal can leave an otherwise complete old snapshot and its .ready.
      (umask 077; set -C; printf '%s\n' "$generation" > "$receipt") || exit 1
    fi
    if [ "$1" = accept ]; then rm -f "$backup/.ready" || exit 1; fi
    rm -rf "$backup" || exit 1
    [ ! -e "$backup" ] || exit 1
  fi
  rm -f "$receipt"
)

snapshot_compact() {
  # A failed multi-package upgrade can overwrite the live executable.
  # Keep private copies only while changing installed packages. User databases
  # and settings live in DATA, outside this package payload directory.
  compact_backup=$compact_dir/.compact-previous
  retire_compact_snapshot retry || return 1
  if [ ! -f "$compact_backup/.ready" ]; then
    # A retired or interrupted snapshot can still contain files from modules
    # that have since been removed. Start this generation from an empty tree.
    if [ -d "$compact_backup" ]; then rm -rf "$compact_backup" || return 1; fi
    mkdir -p "$compact_backup" || return 1
    snapshot_started=1
    cp -p "$COMPACT_BIN" "$compact_backup/n2s-compact" || return 1
    for file in install.sh uninstall.sh; do
      [ ! -f "$compact_dir/$file" ] || cp -p "$compact_dir/$file" "$compact_backup/" || return 1
    done
    for module in runs blockcheck strategies geo trace tgws tools; do
      src="$compact_dir/modules/$module"
      [ -d "$src" ] || continue
      mkdir -p "$compact_backup/modules/$module" || return 1
      for file in "$src"/"$module"-*.js.gz "$src/catalog.json" "$src/nfqws2-$module"; do
        if [ -f "$file" ] || [ -L "$file" ]; then
          cp -pP "$file" "$compact_backup/modules/$module/" || return 1
        fi
      done
    done
    touch "$compact_backup/.ready" || return 1
  else
    # An interrupted restore can leave live files hard-linked to this snapshot.
    # Keep the running inode intact; detach its backup before the package
    # manager can truncate both copies through the live path.
    for saved in "$compact_backup"/* "$compact_backup"/modules/*/*; do
      [ -f "$saved" ] && [ ! -L "$saved" ] || continue
      live="$compact_dir/${saved#"$compact_backup"/}"
      [ "$saved" -ef "$live" ] || continue
      pending="$compact_backup/.detaching"
      rm -f "$pending" && cp -p "$saved" "$pending" && mv -f "$pending" "$saved" || return 1
    done
  fi
  # On retry, reinstall every selected package even if the package manager
  # already recorded the candidate version.
  printf '%s\n' "$selected" > "$stage/repair" && mv -f "$stage/repair" "$repair_file" || return 1
  rollback_compact=1
}

restore_compact() {
  # A new package version can add a compiler or rename a hashed page.
  # Remove only package payloads introduced since the snapshot.
  for module in runs blockcheck strategies geo trace tgws tools; do
    dest="$compact_dir/modules/$module"
    set -- "$dest/nfqws2-$module"
    case "$module" in runs|blockcheck|strategies|geo) set -- "$@" "$dest"/"$module"-*.js.gz ;; esac
    [ "$module" != strategies ] || set -- "$@" "$dest/catalog.json"
    for file do
      snapshot_file="$compact_backup/modules/$module/${file##*/}"
      if { [ -f "$file" ] || [ -L "$file" ]; } && [ ! -f "$snapshot_file" ] && [ ! -L "$snapshot_file" ]; then
        rm -f "$file" || return 1
      fi
    done
  done
  for src in "$compact_backup" "$compact_backup"/modules/*; do
    [ -d "$src" ] || continue
    dest=$compact_dir
    [ "$src" = "$compact_backup" ] || dest="$compact_dir/modules/${src##*/}"
    mkdir -p "$dest" || return 1
    for file in "$src"/*; do
      [ -f "$file" ] || [ -L "$file" ] || continue
      target="$dest/${file##*/}"
      if [ ! -L "$file" ] && [ ! -L "$target" ] && [ "$file" -ef "$target" ]; then continue; fi
      # Preserve the complete snapshot for a retry if a later restore fails.
      # Hard links avoid a second full copy on filesystems that support them.
      pending="$dest/.n2s-restore"
      rm -f "$pending" || return 1
      if [ -L "$file" ]; then
        cp -pP "$file" "$pending" || return 1
      else
        ln "$file" "$pending" 2>/dev/null || cp -p "$file" "$pending" || return 1
      fi
      mv -f "$pending" "$target" || return 1
    done
  done
}

stage_compact() {
  stage_path=$1
  compact_dir=${COMPACT_BIN%/*}
  repair_file=$compact_dir/.compact-repair
  selected=$(compact_packages) || return 1
  if [ -f "$repair_file" ]; then
    selected=$(printf '%s\n' "$selected" | cat - "$repair_file" |
      awk '$1 ~ /^nfqws2-strategy-(runs|blockcheck|strategies|geo|trace|tgws|tools)$/ && !seen[$1]++ {print $1}')
  fi
  set -- nfqws2-strategy-compact
  for module in $selected; do set -- "$@" "$module"; done
  if [ "$active_profile" = compact ]; then
    upgradable=$(compact_inventory upgradable) || return 1
    if [ -f "$repair_file" ] || printf '%s\n' "$upgradable" | grep -Eq '^nfqws2-strategy-(compact|runs|blockcheck|strategies|geo|trace|tgws|tools) '; then
      repair=0
      [ ! -f "$repair_file" ] || repair=1
      snapshot_compact || return 1
      if [ "$PM" = apk ]; then
        if [ "$repair" = 1 ]; then
          # Add vanished modules back before repairing the installed files.
          # Their exact dependencies bring back an absent shared helper.
          (
            set -- nfqws2-strategy-compact
            for module in $selected; do
              if [ "$module" = nfqws2-strategy-tools ]; then
                case "$selected" in *nfqws2-strategy-runs*|*nfqws2-strategy-blockcheck*|*nfqws2-strategy-strategies*|*nfqws2-strategy-geo*) continue ;; esac
              fi
              set -- "$@" "$module"
            done
            compact_apk add --upgrade "$@"
          ) || return 1
          compact_apk fix --reinstall "$@" || return 1
        else
          # Targeted upgrade preserves apk's world set: deleting the last
          # optional module can still garbage-collect its shared executable.
          compact_apk upgrade "$@" || return 1
        fi
      elif [ "$repair" = 1 ]; then
        N2S_INSTALLING_COMPACT=1 opkg --force-reinstall install "$@" || return 1
      else
        N2S_INSTALLING_COMPACT=1 opkg install "$@" || return 1
      fi
    fi
  elif [ "$PM" = apk ]; then
    compact_apk add nfqws2-strategy-compact || return 1
  else
    N2S_INSTALLING_COMPACT=1 opkg install "$@" || return 1
  fi
  [ -x "$COMPACT_BIN" ] || return 1
  # Detect an unavailable/mixed module version before switching the link.
  installed=$(compact_inventory installed) || return 1
  base_version=$(printf '%s\n' "$installed" | awk '$1 == "nfqws2-strategy-compact" {print $3}')
  [ -n "$base_version" ] || return 1
  [ -z "${N2S_EXPECT_PACKAGE_VERSION:-}" ] || [ "$base_version" = "$N2S_EXPECT_PACKAGE_VERSION" ] || return 1
  if [ "${go_source:-0}" = 1 ] && [ "$("$COMPACT_BIN" prepare-go-routing --supported 2>/dev/null || true)" = go-routing-v1 ]; then
    # Go includes Telegram and packet capture in both editions. The full Go
    # panel also includes the four pages that already had compact packages.
    required='trace tgws'
    if [ "$active_profile" = full ]; then required="runs blockcheck strategies geo $required"; fi
    selected_names=" $(printf '%s\n' "$selected" | tr '\n' ' ') "
    set --
    for module in $required; do
      pkg=nfqws2-strategy-$module
      case "$selected_names" in *" $pkg "*) continue ;; esac
      selected=$(printf '%s\n%s\n' "$selected" "$pkg")
      set -- "$@" "$pkg"
    done
    if [ "$#" -gt 0 ]; then
      if [ "$active_profile" = compact ]; then snapshot_compact || return 1; fi
      N2S_INSTALLING_COMPACT=1 opkg install "$@" || return 1
      installed=$(compact_inventory installed) || return 1
      [ "$(printf '%s\n' "$installed" | awk '$1 == "nfqws2-strategy-compact" {print $3}')" = "$base_version" ] || return 1
    fi
  fi
  for module in $selected; do
    module_version=$(printf '%s\n' "$installed" | awk -v name="$module" '$1 == name {print $3}')
    [ "$module_version" = "$base_version" ] || return 1
  done
  ln -s "$COMPACT_BIN" "$stage_path"
}

install_dependencies() {
  https_prepare || die "cannot prepare a working HTTPS client"
  say "checking runtime dependencies ($PM)"
  if [ "$PM" = apk ]; then
    # apk uses the native firmware feeds for kernel modules. Never force a
    # mismatching kernel package or replace the router's configured feeds.
    # OpenWrt 25 apk cannot choose a provider for the virtual iptables and
    # ip6tables names on a fresh router. The nft variants also provide the
    # iptables-restore commands used by the NFQUEUE bypass helper.
    apk --update-cache add ip-full ipset kmod-ipt-ipset kmod-tun \
      iptables-nft iptables-mod-nfqueue iptables-mod-conntrack-extra iptables-mod-ipopt \
      iptables-mod-extra iptables-mod-filter ip6tables-nft ip6tables-extra ip6tables-mod-nat \
      || die "dependency installation failed; check feed availability and firmware/kernel versions"
  elif [ "$PLATFORM" = openwrt ]; then
    opkg update || die "package feed refresh failed"
    opkg install ip-full ipset kmod-ipt-ipset kmod-tun \
      iptables iptables-mod-nfqueue iptables-mod-conntrack-extra iptables-mod-ipopt \
      iptables-mod-extra iptables-mod-filter ip6tables ip6tables-extra ip6tables-mod-nat \
      || die "dependency installation failed; check feed availability and firmware/kernel versions"
  else
    opkg update || die "package feed refresh failed"
    opkg install ipset || die "dependency installation failed"
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
      # An existing include may have been customized by the administrator.
      # Creating ours must also never commit pending firewall edits.
      if ! uci -q show firewall.nfqws2_bypass_fw4 >/dev/null 2>&1; then
        changes=$(uci changes firewall) || return 1
        if [ -n "$changes" ]; then
          say "preserved pending firewall edits; skipped adding the panel include"
        else
          uci set firewall.nfqws2_bypass_fw4=include &&
            uci set firewall.nfqws2_bypass_fw4.type=script &&
            uci set "firewall.nfqws2_bypass_fw4.path=$fw4_hook" &&
            uci set firewall.nfqws2_bypass_fw4.fw4_compatible=1 &&
            uci commit firewall || return 1
        fi
      fi
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

panel_inode() {
  # The Entware BusyBox stat omits -c. In POSIX-style terse output the
  # device and inode follow size, blocks, mode, uid and gid.
  stat -L -t "$1" 2>/dev/null | awk -v path="$1" '
    index($0,path " ")==1 {split(substr($0,length(path)+2), f)
      if(f[6] ~ /^[[:xdigit:]]+$/ && f[7] ~ /^[0-9]+$/) {print f[6] ":" f[7]; ok=1}}
    END {exit !ok}'
}

panel_token() (
  pid=$1; expected=$2
  case "$pid" in ''|0|1|*[!0-9]*) exit 1 ;; esac
  [ "$(panel_inode "/proc/$pid/exe")" = "$expected" ] || exit 1
  tr '\000' '\n' < "/proc/$pid/cmdline" 2>/dev/null | awk -v path="$RUN_DIR/nfqws2-strategy.pid" '
    NR==2 && $0=="serve" {service=1} prev=="-pid" && $0==path {pidfile=1}
    {prev=$0} END {exit !(service && pidfile)}' || exit 1
  awk -v pid="$pid" '{sub(/^.*\) /,""); if ($20 !~ /^[0-9]+$/) exit 1; print pid "/" $20}' "/proc/$pid/stat"
)

find_panel() (
  # On a failed start the child may already exist before writing its PID.
  # A missing or stale PID file alone cannot authorize replacing live data.
  found=
  for entry in /proc/[0-9]*/exe; do
    [ -e "$entry" ] || continue
    proc=${entry%/exe}
    token=$(panel_token "${proc##*/}" "$1") || continue
    [ -z "$found" ] || exit 1
    found=$token
  done
  printf '%s' "$found"
)

wait_panel_exit() (
  token=$1; inode=$2; attempts=0
  interval=1; limit=120
  # Keep the same shutdown allowance, with less idle time between owners on
  # systems whose sleep supports fractional seconds.
  if sleep 0.0 2>/dev/null; then interval=0.1; limit=1200; fi
  while [ "$(panel_token "${token%/*}" "$inode" 2>/dev/null || true)" = "$token" ]; do
    [ "$attempts" -lt "$limit" ] || return 1
    sleep "$interval" || return 1
    attempts=$((attempts+1))
  done
)

prepare_parked_go_guard() (
  [ "$("$stage/n2s" prepare-go-routing --parked-guard-supported 2>/dev/null || true)" = go-routing-parked-guard-v1 ] || exit 0
  candidate=$(readlink -f "$stage/n2s") && [ -f "$candidate" ] &&
    ln "$candidate" "$stage/parked-guard-n2s" || exit 1
  [ "$(panel_inode "$stage/parked-guard-n2s")" = "$new_inode" ] || exit 1
  claim_go_restore || exit 1
  printf '%s\n' "$active_profile" "$profile" "$rollback_compact" "$snapshot_started" "$go_data_path" \
    "$go_process" "$go_endpoint" "$go_inode" "$new_inode" > "$stage/parked-guard-writing" &&
    mv -f "$stage/parked-guard-writing" "$stage/parked-guard-state" || exit 1
  result=$(N2S_DATA="$DATA" "$stage/parked-guard-n2s" prepare-go-routing --parked-guard "$go_endpoint") || exit 1
  case "$result" in
    armed) ;;
    ordinary) rm -f "$stage/parked-guard-state" "$stage/parked-guard-n2s" || exit 1 ;;
    *) exit 1 ;;
  esac
)

release_parked_go_guard() (
  [ -f "$stage/parked-guard-state" ] || exit 0
  [ ! -L "$stage/parked-guard-state" ] && [ ! -L "$stage/parked-guard-n2s" ] &&
    [ "$(panel_inode "$stage/parked-guard-n2s")" = "$new_inode" ] || exit 1
  [ "$(readlink -f "$DATA")" = "$go_data_path" ] && [ -n "$go_endpoint" ] || exit 1
  attempts=0
  until result=$(N2S_DATA="$DATA" "$stage/parked-guard-n2s" release-go-routing --parked-guard "$go_endpoint" 2>/dev/null) &&
      [ "$result" = released ]; do
    attempts=$((attempts+1)); [ "$attempts" -lt 30 ] || exit 1
    sleep 1
  done
)

read_parked_go_recovery() {
  [ ! -L "$stage/parked-guard-state" ] && [ ! -L "$stage/parked-guard-n2s" ] || return 1
  {
    IFS= read -r active_profile && IFS= read -r profile && IFS= read -r rollback_compact &&
    IFS= read -r snapshot_started && IFS= read -r go_data_path &&
    IFS= read -r go_process && IFS= read -r go_endpoint &&
    IFS= read -r go_inode && IFS= read -r new_inode
  } < "$stage/parked-guard-state" || return 1
  case "$active_profile/$profile" in
    full/full|full/compact|compact/full|compact/compact) ;;
    *) return 1 ;;
  esac
  case "$rollback_compact/$snapshot_started" in
    0/0|0/1|1/1) ;;
    *) return 1 ;;
  esac
  [ "$(readlink -f "$DATA")" = "$go_data_path" ] && [ "$go_data_path" != / ] &&
    [ "$(panel_inode "$stage/parked-guard-n2s")" = "$new_inode" ] || return 1
  go_trial=trial
  parked_recovering=1
  go_term_sent=0
  [ ! -f "$stage/parked-go-term" ] || go_term_sent=1
  go_data_stage=
  if [ -f "$stage/data-location" ]; then
    [ ! -L "$stage/data-location" ] && IFS= read -r go_data_stage < "$stage/data-location" &&
      [ "${go_data_stage%/*}" = "${go_data_path%/*}" ] && [ ! -L "$go_data_stage" ] || return 1
    case "${go_data_stage##*/}" in .n2s-go-data.??????) ;; *) return 1 ;; esac
  fi
}

signal_panel() {
  [ "$(panel_token "${1%/*}" "$2" 2>/dev/null || true)" = "$1" ] || return 1
  kill -TERM "${1%/*}"
}

snapshot_go_sets() (
  go_jump=$(N2S_DATA="$DATA" "$stage/n2s" prepare-go-routing --source-chain) || exit 1
  case "$go_jump" in
    AWG2_MULTI) iptables -w -t mangle -S AWG2_MULTI > "$stage/go-chain" || exit 1 ;;
    AWG2_MARK)
    # Go keeps its verified per-zone awg2_z* sets when it stops, in both
    # address families. Only the learned awgm_* sets need to be reinserted.
    iptables -w -t mangle -S AWG2_MARK > "$stage/go-chain" || exit 1
    grep -qx -- '-A AWG2_MARK -j MARK --set-xmark 0x10000000/0x10000000' "$stage/go-chain" || exit 1
    awk '/--match-set/ && !/^-A AWG2_MARK -s [0-9.]+(\/[0-9]+)? -m set --match-set awg2_z[0-9]+ dst -j (RETURN|MARK --set-xmark 0x10000000\/0x10000000)$/ { exit 1 }' "$stage/go-chain" || exit 1
      ;;
    *) exit 1 ;;
  esac
  awk '{for(i=1;i+2<=NF;i++) if($i=="--match-set" && $(i+1) ~ /^awgm_[0-9][0-9][0-9]$/ && $(i+2)=="dst") print $(i+1)}' "$stage/go-chain" |
    sort -u > "$stage/go-names" || exit 1
  : > "$stage/go-sets" || exit 1
  while IFS= read -r name; do
    ipset save "$name" > "$stage/go-set" &&
      awk -v set="$name" '$1=="add" && $2==set' "$stage/go-set" >> "$stage/go-sets" || exit 1
  done < "$stage/go-names"
  rm -f "$stage/go-set" "$stage/go-chain" "$stage/go-names"
)

has_routing_ip() (
  for tool in ip /opt/libexec/ip-full; do
    "$tool" -o -N -4 rule show >/dev/null 2>&1 && exit 0
    if "$tool" -V 2>/dev/null | grep -q '^ip utility, iproute2-'; then
      "$tool" -o -4 rule show >/dev/null 2>&1 && exit 0
    fi
  done
  exit 1
)

prepare_go_routing() (
  needed=$(N2S_DATA="$DATA" "$stage/n2s" prepare-go-routing --needs-ip) || exit 1
  case "$needed" in
    yes)
      if ! has_routing_ip; then
        [ "${N2S_SKIP_DEPS:-0}" != 1 ] && opkg install ip-full >&2 && has_routing_ip ||
          { say "the active AWG routing policy requires Entware ip-full" >&2; exit 1; }
      fi
      ;;
    no) ;;
    *) exit 1 ;;
  esac
  N2S_DATA="$DATA" "$stage/n2s" prepare-go-routing "$1"
)

go_listen_options() (
  # Read only the listener options of the Go process identified by panel_token.
  # A requested N2S_PORT applies to the next service, while Go is still serving.
  procdir=$1
  [ -r "$procdir/cmdline" ] || exit 1
  options=$(tr '\000' '\n' < "$procdir/cmdline" | awk '
    NR<=2 {next}
    value {if(value=="-l") listen=$0; value=""; next}
    $0=="-l" || $0=="-log" || $0=="-pid" {value=$0; next}
    $0=="--ignore-saved-port" {ignore=1}
    END {if(value!="") exit 1; print (ignore ? "explicit" : "saved") "/" listen}') || exit 1
  listen=${options#*/}
  if [ -z "$listen" ] && [ -r "$procdir/environ" ]; then
    listen=$(tr '\000' '\n' < "$procdir/environ" | awk '/^N2S_LISTEN=/ {print substr($0,12); exit}') || exit 1
  fi
  listen=${listen:-:8090}
  case "$listen" in *:*) ;; *) exit 1 ;; esac
  source_port=${listen##*:}
  case "$source_port" in ''|*[!0-9]*) exit 1 ;; esac
  [ "$source_port" -ge 1 ] && [ "$source_port" -le 65535 ] || exit 1
  printf '%s/%s\n' "${options%%/*}" "$listen"
)

resolve_handoff_ports() {
  source_listen=${go_listen#*/}
  go_port=${source_listen##*:}
  handoff_port=$PORT
  if [ "$("$stage/n2s" resolve-panel-port --supported 2>/dev/null || true)" = panel-port-v1 ]; then
    handoff_port=$(N2S_DATA="$DATA" "$stage/n2s" resolve-panel-port "$PORT") || return 1
    if [ "${go_listen%%/*}" = saved ]; then
      go_port=$(N2S_DATA="$DATA" "$stage/n2s" resolve-panel-port "$go_port") || return 1
    fi
  fi
  go_endpoint=$go_port
  if [ "$("$stage/n2s" prepare-go-routing --listen-address --supported 2>/dev/null || true)" = panel-listener-v1 ]; then
    handoff_local=1
    go_endpoint=$(N2S_DATA="$DATA" "$stage/n2s" prepare-go-routing --listen-address "$go_process" "$go_port") || return 1
    bind_host=${go_endpoint%:*}
    valid_bind_host "$bind_host" && [ "${go_endpoint##*:}" = "$go_port" ] || return 1
    case "${source_listen%:*}/$bind_host" in '/[::]'|'/0.0.0.0') bind_host= ;; esac
  else
    case "${source_listen%:*}" in '') ;; 127.0.0.1|0.0.0.0) bind_host=${source_listen%:*} ;; *) return 1 ;; esac
  fi
}

target_panel_endpoint() (
  count=0
  while :; do
    token=$(panel_token "$(cat "$RUN_DIR/nfqws2-strategy.pid")" "$new_inode") || exit 1
    if endpoint=$(N2S_DATA="$DATA" "$BIN" prepare-go-routing --listen-address "$token" "$handoff_port" 2>/dev/null); then
      [ -z "$bind_host" ] || [ "${endpoint%:*}" = "$bind_host" ] || exit 1
      printf '%s\n' "$endpoint"
      exit 0
    fi
    count=$((count+1)); [ "$count" -lt 30 ] || exit 1
    sleep 1
  done
)

capture_go_source() {
  go_executable=$(readlink -f "$BIN") && [ -f "$go_executable" ] || return 1
  go_inode=$(panel_inode "$go_executable") || return 1
  go_process=$(panel_token "$(cat "$RUN_DIR/nfqws2-strategy.pid")" "$go_inode") || return 1
  go_listen=$(go_listen_options "/proc/${go_process%/*}") || return 1
  go_data_path=$(readlink -f "$DATA") && [ -d "$go_data_path" ] && [ "$go_data_path" != / ] ||
    return 1
  case "$(readlink -f "$INIT")" in "$go_data_path"/*) return 1 ;; esac
  case "$(readlink -f "$stage")" in "$go_data_path"/*) return 1 ;; esac
  ln "$go_executable" "$stage/go-bin" || cp -p "$go_executable" "$stage/go-bin" || return 1
  cp -p "$INIT" "$stage/go-init"
}

prepare_go_data_snapshot() {
  [ "$(readlink -f "$DATA")" = "$go_data_path" ] || return 1
  go_data_inode=$(panel_inode "$go_data_path") || return 1
  # Rollback swaps directories by rename on the resolved data filesystem.
  go_data_stage=$(mktemp -d "${go_data_path%/*}/.n2s-go-data.XXXXXX") || return 1
  go_data_stage_inode=$(panel_inode "$go_data_stage") || return 1
  [ "${go_data_inode%:*}" = "${go_data_stage_inode%:*}" ] || return 1
  printf '%s\n' "$go_data_stage" > "$stage/data-location"
}

save_go_data_snapshot() {
  [ "$(readlink -f "$DATA")" = "$go_data_path" ] &&
    [ "$(panel_inode "$go_data_path")" = "$go_data_inode" ] &&
    [ ! -L "$go_data_stage" ] && [ "$(panel_inode "$go_data_stage")" = "$go_data_stage_inode" ] || return 1
  cp -a "$go_data_path" "$go_data_stage/copying" &&
    mv "$go_data_stage/copying" "$go_data_stage/original"
}

restore_live_compact() {
  [ "${active_profile:-full}" = compact ] && [ "${rollback_compact:-0}" = 1 ] || return 0
  restore_compact || return 1
  # A retry still needs the repair receipt because opkg recorded the new
  # version before the old files were restored.
  rollback_compact=0
  snapshot_started=1
}

shell_epoch() {
  awk '{sub(/^.*\) /,""); if ($20 !~ /^[0-9]+$/) exit 1; print $20}' "/proc/$1/stat" 2>/dev/null
}

claim_go_restore() {
  # Each exhausted slot stays in the private stage. Two installers recovering
  # after the same crash cannot unlink one another's lock or reuse a PID.
  epoch=$(shell_epoch "$$") && [ -n "$epoch" ] || return 1
  slot=0
  while :; do
    owner="$stage/rollback-owner.$slot"
    if ln -s "$$/$epoch" "$owner" 2>/dev/null; then return 0; fi
    token=$(readlink "$owner") || return 1
    [ "$token" != "$$/$epoch" ] || return 0
    pid=${token%/*}
    case "$pid" in ''|*[!0-9]*) return 1 ;; esac
    [ ! -d "/proc/$pid" ] || {
      previous=$(shell_epoch "$pid") && [ "$previous" != "${token#*/}" ] || return 1
    }
    slot=$((slot+1))
  done
}

old_go_files() {
  if [ "$active_profile" = compact ]; then
    [ "$(readlink "$BIN" 2>/dev/null)" = "$COMPACT_BIN" ] || return 1
  else
    [ ! -L "$BIN" ] || return 1
  fi
  cmp -s "$stage/go-bin" "$BIN"
}

resume_go_restore() {
  [ -d "$stage" ] && [ ! -L "$stage" ] && [ ! -L "$stage/rollback-state" ] &&
    claim_go_restore || return 1
  # This file is atomically published after stopping Rust and releasing its
  # routes and clients. It names both directory generations before any rename.
  {
    IFS= read -r active_profile && IFS= read -r compact_snapshot &&
    IFS= read -r go_data_path && IFS= read -r go_data_stage &&
    IFS= read -r stage_id && IFS= read -r backup_id && IFS= read -r original_id &&
    IFS= read -r candidate_id && IFS= read -r init_id &&
    IFS= read -r new_inode && IFS= read -r go_inode
  } < "$stage/rollback-state" || return 1
  case "$active_profile/$compact_snapshot" in full/0|compact/0|compact/1) ;; *) return 1 ;; esac
  [ "$(panel_inode "$stage")" = "$stage_id" ] && [ ! -L "$stage" ] &&
    [ "$(readlink -f "$DATA")" = "$go_data_path" ] && [ "$go_data_path" != / ] &&
    [ "${go_data_stage%/*}" = "${go_data_path%/*}" ] && [ ! -L "$go_data_stage" ] || return 1
  if [ "$compact_snapshot" = 1 ]; then
    compact_dir=${COMPACT_BIN%/*}
    compact_backup=$compact_dir/.compact-previous
  fi
  rollback_compact=0
  snapshot_started=$compact_snapshot
  rust_process=$(find_panel "$new_inode") && [ -z "$rust_process" ] || return 1
  bin_id=$(panel_inode "$BIN") || return 1
  if [ "$bin_id" != "$new_inode" ]; then old_go_files || return 1; fi
  if [ -e "$stage/rollback-init" ]; then
    [ "$(panel_inode "$INIT")" = "$init_id" ] && cmp -s "$INIT" "$stage/candidate-init" || return 1
  else
    cmp -s "$INIT" "$stage/go-init" || return 1
  fi
  installed_process=$(find_panel "$bin_id") || return 1
  old_process=$(find_panel "$go_inode") || return 1
  if [ -n "$installed_process$old_process" ]; then
    [ -f "$stage/rollback-payload-ready" ] && [ -n "$installed_process" ] &&
      { [ -z "$old_process" ] || [ "$old_process" = "$installed_process" ]; } || return 1
  fi
  if [ -f "$stage/rollback-cleaning" ]; then
    [ -n "$installed_process" ] && old_go_files &&
      [ "$(panel_inode "$go_data_path")" = "$original_id" ] &&
      { [ ! -e "$go_data_stage" ] || [ "$(panel_inode "$go_data_stage")" = "$backup_id" ]; } &&
      { [ ! -e "$go_data_stage/failed" ] || [ "$(panel_inode "$go_data_stage/failed")" = "$candidate_id" ]; }
    return
  fi
  [ "$(panel_inode "$go_data_stage")" = "$backup_id" ] || return 1
  # Observe both sides of each rename, including the gap between the two.
  if [ ! -e "$go_data_stage/failed" ]; then
    [ ! -L "$go_data_stage/failed" ] && [ "$(panel_inode "$go_data_path")" = "$candidate_id" ] &&
      [ "$(panel_inode "$go_data_stage/original")" = "$original_id" ] &&
      mv "$go_data_path" "$go_data_stage/failed" || return 1
  fi
  [ ! -L "$go_data_stage/failed" ] && [ "$(panel_inode "$go_data_stage/failed")" = "$candidate_id" ] || return 1
  if [ ! -e "$go_data_path" ]; then
    [ ! -L "$go_data_path" ] && [ ! -L "$go_data_stage/original" ] &&
      [ "$(panel_inode "$go_data_stage/original")" = "$original_id" ] &&
      mv "$go_data_stage/original" "$go_data_path" || return 1
  fi
  [ "$(panel_inode "$go_data_path")" = "$original_id" ] &&
    [ ! -e "$go_data_stage/original" ] && [ ! -L "$go_data_stage/original" ] || return 1
  if [ ! -f "$stage/rollback-payload-ready" ]; then
    if [ "$compact_snapshot" = 1 ] && [ ! -f "$stage/rollback-compact-ready" ]; then
      [ -f "$compact_backup/.ready" ] && restore_compact &&
        touch "$stage/rollback-compact-ready" || return 1
    fi
    if [ -f "$stage/rollback-init" ]; then mv -f "$stage/rollback-init" "$INIT" || return 1; fi
    if [ -e "$stage/rollback-bin" ] || [ -L "$stage/rollback-bin" ]; then
      mv -f "$stage/rollback-bin" "$BIN" || return 1
    fi
    old_go_files && cmp -s "$INIT" "$stage/go-init" && touch "$stage/rollback-payload-ready" || return 1
  fi
  old_go_files && cmp -s "$INIT" "$stage/go-init" || return 1
  if [ -z "$installed_process" ]; then "$INIT" start || return 1; fi
  restored_inode=$(panel_inode "$BIN") && restored_process=$(find_panel "$restored_inode") &&
    [ -n "$restored_process" ] || return 1
}

restore_go() {
  if [ -f "$stage/rollback-state" ]; then
    resume_go_restore || return 1
  elif [ ! -e "$stage/n2s" ]; then
    # The staged executable was installed. Avoid overwriting either process
    # if another operator has already recovered or replaced the service.
    [ "$(panel_inode "$BIN")" = "$new_inode" ] || return 1
    old_process=$(find_panel "$go_inode") && [ -z "$old_process" ] || return 1
    rust_process=$(find_panel "$new_inode") || return 1
    [ "$(readlink -f "$DATA")" = "$go_data_path" ] &&
      [ -d "$go_data_stage/original" ] && [ ! -e "$go_data_stage/failed" ] || return 1
    if [ "$go_trial" = trial ]; then
      N2S_DATA="$DATA" "$BIN" release-go-routing --checkpoint || return 1
    fi
    if [ -n "$rust_process" ]; then
      signal_panel "$rust_process" "$new_inode" && wait_panel_exit "$rust_process" "$new_inode" || return 1
    fi
    rust_process=$(find_panel "$new_inode") && [ -z "$rust_process" ] || return 1
    if [ "$go_trial" = trial ]; then
      [ "$(readlink -f "$DATA")" = "$go_data_path" ] &&
        [ "$(panel_inode "$BIN")" = "$new_inode" ] || return 1
      N2S_DATA="$DATA" "$BIN" release-go-routing || return 1
    fi
    if [ "$("$BIN" release-native-clients --supported 2>/dev/null || true)" = native-client-release-v1 ]; then
      [ "$(readlink -f "$DATA")" = "$go_data_path" ] && [ "$(panel_inode "$BIN")" = "$new_inode" ] || return 1
      rust_process=$(find_panel "$new_inode") && [ -z "$rust_process" ] || return 1
      N2S_DATA="$DATA" "$BIN" release-native-clients || return 1
    fi
    cp -p "$stage/go-init" "$stage/rollback-init" || return 1
    if [ "${active_profile:-full}" = compact ]; then
      [ "$(readlink "$stage/rollback-bin" 2>/dev/null || true)" = "$COMPACT_BIN" ] ||
        { [ ! -e "$stage/rollback-bin" ] && [ ! -L "$stage/rollback-bin" ] &&
          ln -s "$COMPACT_BIN" "$stage/rollback-bin"; } || return 1
    else
      if [ ! -e "$stage/rollback-bin" ]; then
        ln "$stage/go-bin" "$stage/rollback-bin" || cp -p "$stage/go-bin" "$stage/rollback-bin" || return 1
      fi
      cmp -s "$stage/go-bin" "$stage/rollback-bin" || return 1
    fi
    [ "$(panel_inode "$BIN")" = "$new_inode" ] || return 1
    old_process=$(find_panel "$go_inode") && [ -z "$old_process" ] || return 1
    rust_process=$(find_panel "$new_inode") && [ -z "$rust_process" ] || return 1
    [ "$(readlink -f "$DATA")" = "$go_data_path" ] &&
      [ -d "$go_data_stage/original" ] && [ ! -e "$go_data_stage/failed" ] || return 1
    claim_go_restore && cp -p "$INIT" "$stage/candidate-init" || return 1
    stage_id=$(panel_inode "$stage") && backup_id=$(panel_inode "$go_data_stage") &&
      original_id=$(panel_inode "$go_data_stage/original") && candidate_id=$(panel_inode "$go_data_path") &&
      init_id=$(panel_inode "$INIT") || return 1
    printf '%s\n' "${active_profile:-full}" "${rollback_compact:-0}" "$go_data_path" "$go_data_stage" \
      "$stage_id" "$backup_id" "$original_id" "$candidate_id" "$init_id" "$new_inode" "$go_inode" > "$stage/rollback-writing" &&
      mv -f "$stage/rollback-writing" "$stage/rollback-state" && resume_go_restore || return 1
  else
    old_process=$(find_panel "$go_inode") || return 1
    if [ -n "$old_process" ]; then
      # No Rust process has seen the data. Keep a working Go service, or
      # complete our already-requested shutdown before starting it once.
      if [ "$old_process" != "$go_process" ] || [ "$go_term_sent" = 0 ]; then
        release_parked_go_guard
        return
      fi
      # The durable marker can precede the signal if the installer crashed.
      # Finish the intended shutdown using only the same verified process.
      if [ "${parked_recovering:-0}" = 1 ]; then
        signal_panel "$go_process" "$go_inode" ||
          { old_process=$(find_panel "$go_inode") && [ -z "$old_process" ]; } || return 1
      fi
      wait_panel_exit "$go_process" "$go_inode" || return 1
    fi
    restore_live_compact || return 1
    if [ "${active_profile:-full}" = compact ]; then
      cmp -s "$stage/go-bin" "$COMPACT_BIN" || return 1
    fi
    "$INIT" start || return 1
  fi
  if [ -s "$stage/go-sets" ] && [ ! -f "$stage/rollback-cleaning" ]; then
    attempts=0
    until ipset -exist restore < "$stage/go-sets" 2>/dev/null; do
      attempts=$((attempts+1)); [ "$attempts" -lt 60 ] || return 1; sleep 1
    done
  fi
  release_parked_go_guard
}

verify_go_services() {
  [ "$rollback_go" = 1 ] || return 0
  [ "$("$BIN" finish-go-services --supported 2>/dev/null || true)" = go-services-v1 ] || return 0
  N2S_DATA="$DATA" "$BIN" finish-go-services "$1"
}

cleanup_accepted_install() {
  if [ -f "$stage/parked-guard-state" ]; then
    [ -f "$stage/parked-go-accepted" ] && [ ! -L "$stage/parked-go-accepted" ] &&
      [ "$(panel_inode "$BIN")" = "$new_inode" ] || return 1
    result=$(N2S_DATA="$DATA" "$BIN" release-go-routing --accept-parked-guard) &&
      [ "$result" = accepted ] || return 1
  fi
  if [ "$profile" = compact ]; then
    # Retire the snapshot before clearing the package repair receipt. If
    # removal is interrupted, the next repair snapshots the accepted files.
    retire_compact_snapshot accept || return 1
    rm -f "$repair_file" || return 1
  fi
  if [ "$go_trial" = trial ]; then
    rm -f "$DATA/.store/runtime/awg-go-release.json" || return 1
  fi
  accepted_cleanup=0
}

cleanup_stage() {
  if [ "${accepted_cleanup:-0}" = 1 ]; then
    if ! cleanup_accepted_install; then
      say "new service confirmed; obsolete installation receipts retained"
      [ ! -f "$stage/parked-guard-state" ] || return 1
    fi
  fi
  if [ "${rollback_go:-0}" = 1 ]; then
    say "restoring the previous Keenetic panel"
    restore_go || { say "recovery files retained in $stage ${go_data_stage:-}"; return 1; }
    say "previous Keenetic panel restored"
  fi
  if [ "${go_preparing:-0}" = 1 ]; then
    rm -f "$DATA/.store/runtime/awg-go-handoff.json" "$DATA/.store/runtime/awg-go-trial-check.json" "$DATA/.store/runtime/awg-go-clients-pending.json" "$DATA/.store/runtime/awg-go-release.json" "$DATA/.store/runtime/upgrade-go-services.json" || return 1
  fi
  if [ "$rollback_compact" = 1 ]; then
    restore_compact || { say "restore failed; previous package files retained in $compact_backup"; return 1; }
    rm -rf "$compact_backup"
    say "restored previous compact files; retry the installer to repair the package set"
    if [ "$was_running" = 1 ] && [ "$("$INIT" status)" != running ]; then "$INIT" start; fi
  elif [ "$snapshot_started" = 1 ]; then rm -rf "$compact_backup" || return 1; fi
  if [ -f "$stage/rollback-state" ]; then touch "$stage/rollback-cleaning" || return 1; fi
  if [ -n "${go_data_stage:-}" ]; then
    if [ -e "$go_data_stage" ] && [ -n "${go_data_stage_inode:-}" ]; then
      [ ! -L "$go_data_stage" ] && [ "$(panel_inode "$go_data_stage")" = "$go_data_stage_inode" ] || return 1
    fi
    rm -rf "$go_data_stage" || return 1
  fi
  rm -rf "$stage"
}

# An interrupted late rollback is recovered by the same installer, before it
# starts dependencies, creates DATA or stages another package generation.
if [ "$PLATFORM" = entware ]; then
  pending=
  for previous in "$BIN_DIR"/.n2s-install.??????; do
    [ ! -L "$previous/rollback-state" ] && [ ! -L "$previous/parked-guard-state" ] ||
      die "ambiguous pending Go recovery"
    [ -f "$previous/rollback-state" ] || [ -f "$previous/parked-guard-state" ] || continue
    [ -z "$pending" ] && [ ! -L "$previous" ] || die "ambiguous pending Go recovery"
    pending=$previous
  done
  if [ -n "$pending" ]; then
    stage=$pending rollback_go=1 go_preparing=1
    if [ -f "$stage/parked-guard-state" ]; then
      claim_go_restore || die "another installer owns the pending parked Go recovery"
      read_parked_go_recovery || die "invalid parked Go recovery in $stage"
      if [ -f "$stage/parked-go-accepted" ] && [ ! -L "$stage/parked-go-accepted" ] &&
          [ ! -e "$stage/rollback-state" ]; then
        rollback_go=0 go_preparing=0 rollback_compact=0 snapshot_started=0 accepted_cleanup=1
      fi
    fi
    cleanup_stage || die "Go recovery is pending in $stage"
    die "finished the pending Go recovery; rerun the installer to update"
  fi
fi

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

if [ "$active_profile" = full ] && [ "$profile" = full ] && [ -z "${N2S_BIN_SRC:-}" ] &&
    [ -x "$BIN" ] && [ "$("$BIN" prepare-go-routing --supported 2>/dev/null || true)" = go-routing-v1 ]; then
  # The standalone native panel validates its own release architecture, tag
  # and SHA256SUMS. A manual rerun must stay on that release channel.
  if [ -n "${N2S_EXPECT_VERSION:-}" ] && [ "$("$BIN" version)" = "$N2S_EXPECT_VERSION" ]; then exit 0; fi
  exec "$BIN" update
fi

mkdir -p "$DATA" "$LOG_DIR" "$RUN_DIR" "$BIN_DIR"
stage=$(mktemp -d "$BIN_DIR/.n2s-install.XXXXXX") || die "cannot stage panel binary"
rollback_compact=0
snapshot_started=0
was_running=0
rollback_go=0
go_preparing=0
go_term_sent=0
go_data_stage=
go_trial=inactive
handoff_port=$PORT
handoff_local=0
if [ "$active_profile" = compact ] && [ -x "$INIT" ] && [ "$("$INIT" status)" = running ]; then
  was_running=1
fi
trap cleanup_stage 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15
go_source=0
go_source_saved=0
# A compact upgrade can replace the path of the current executable while its
# Go process is still serving. Capture that process before opkg touches it.
if [ "$PLATFORM" = entware ] && [ -x "$BIN" ] &&
    { [ "$active_profile" = compact ] || [ ! -L "$BIN" ]; } &&
    [ -x "$INIT" ] && [ "$("$INIT" status)" = running ] &&
    [ "$("$BIN" prepare-go-routing --supported 2>/dev/null || true)" != go-routing-v1 ]; then
  go_source=1
  if capture_go_source; then go_source_saved=1; fi
fi
if [ "$profile" = compact ]; then
  stage_compact "$stage/n2s" || die "compact feed install failed; check the configured feed, architecture and matching module versions"
elif [ -n "${N2S_BIN_SRC:-}" ]; then
  say "using local binary $N2S_BIN_SRC (skipping download)"
  cp "$N2S_BIN_SRC" "$stage/n2s"
else
  say "downloading $URL"
  fetch "$URL" "$stage/n2s" || die "download failed"
fi
[ "$profile" = compact ] || chmod +x "$stage/n2s"
# Catch a wrong/corrupt architecture before stopping the working service.
staged_version=$("$stage/n2s" version 2>/dev/null) || die "panel binary cannot run on this router"
[ -z "${N2S_EXPECT_VERSION:-}" ] || [ "$staged_version" = "$N2S_EXPECT_VERSION" ] ||
  die "panel binary does not report the requested version"
if [ "${N2S_REQUIRE_NATIVE:-0}" = 1 ]; then
  [ "$("$stage/n2s" prepare-go-routing --supported 2>/dev/null)" = go-routing-v1 ] ||
    die "package does not contain the native Rust panel"
fi

if [ "$go_source" = 1 ] &&
    [ "$("$stage/n2s" prepare-go-routing --supported 2>/dev/null || true)" = go-routing-v1 ]; then
  # Go's saved active bit is also true during an unconfirmed trial. The new
  # executable checks the live owner and captures the selected sets first.
  [ "$go_source_saved" = 1 ] || die "cannot identify the working Go installation before updating packages"
  new_inode=$(panel_inode "$stage/n2s") || die "cannot identify the new executable"
  resolve_handoff_ports || die "cannot resolve the source and target panel ports for migration"
  if [ -z "$selective_accel" ] && [ -r "/proc/${go_process%/*}/environ" ]; then
    selective_accel=$(tr '\000' '\n' < "/proc/${go_process%/*}/environ" | awk '$0=="N2S_AWG_SELECTIVE_ACCEL=1" {print "1";exit}')
  fi
  prepare_go_data_snapshot || die "cannot reserve the Go settings snapshot on the data filesystem"
  go_preparing=1
  go_trial=$(prepare_go_routing "$go_endpoint") ||
    die "the working Go configuration could not be migrated"
  case "$go_trial" in
    inactive) ;;
    trial)
      [ "$("$stage/n2s" release-go-routing --supported 2>/dev/null || true)" = go-routing-release-v1 ] ||
        die "candidate cannot verify removal of its routing before rollback"
      snapshot_go_sets || die "cannot snapshot the active Go DNS sets"
      ;;
    *) die "unexpected routing migration status" ;;
  esac
  [ "$(find_panel "$go_inode")" = "$go_process" ] || die "the Go service changed during preparation"
  rollback_go=1
  if [ "$go_trial" = trial ]; then
    prepare_parked_go_guard || die "cannot hold the parked Go Kill Switch across the update"
    [ "$(find_panel "$go_inode")" = "$go_process" ] || die "the Go service changed while arming its guard"
  fi
  # Older S52 scripts force-kill the panel in eight seconds. Large live
  # policies need to finish restoring PPE and removing their own hooks.
  go_term_sent=1
  if [ -f "$stage/parked-guard-state" ]; then
    touch "$stage/parked-go-term" || die "cannot record the start of Go shutdown"
  fi
  if ! signal_panel "$go_process" "$go_inode"; then
    go_term_sent=0
    rm -f "$stage/parked-go-term"
    die "could not signal the working Go panel"
  fi
  wait_panel_exit "$go_process" "$go_inode" || die "the old panel is still cleaning up"
  remaining=$(find_panel "$go_inode") && [ -z "$remaining" ] || die "the old panel is still running"
  if [ "$go_trial" = trial ]; then
    [ ! -e "$DATA/awg-acceleration-state.json" ] || die "the old PPE recovery journal is still active"
  fi
  # Copy only after Go has stopped so the snapshot includes its final writes.
  save_go_data_snapshot || die "cannot save Go settings for rollback"
else
  if [ -x "$INIT" ]; then "$INIT" stop || die "could not stop the current service"; fi
fi
mv -f "$stage/n2s" "$BIN"

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
  procd_set_param env N2S_DATA="$DATA" N2S_INIT="$INIT" N2S_MODULE_DIR="${COMPACT_BIN%/*}/modules" N2S_NFQWS2_CONF="/etc/nfqws2/nfqws2.conf" N2S_NFQWS_BIN="/usr/bin/nfqws2" N2S_NFQWS2_INIT="/etc/init.d/nfqws2-keenetic"
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
BIND_HOST='$bind_host'
EOF
  if [ "$selective_accel" = 1 ]; then printf '%s\n' 'export N2S_AWG_SELECTIVE_ACCEL=1' >> "$INIT"; fi
  cat >> "$INIT" <<'EOF'
# Verify the PID is really our binary; a stale PID can be reused after reboot.
is_running() {
  [ -f "$PIDFILE" ] || return 1
  _pid="$(cat "$PIDFILE" 2>/dev/null)"
  case "$_pid" in ''|0|1|*[!0-9]*) return 1 ;; esac
  kill -0 "$_pid" 2>/dev/null || return 1
  if [ ! "/proc/$_pid/exe" -ef "$BIN" ]; then
    [ "$(readlink "/proc/$_pid/exe" 2>/dev/null)" = "$(readlink -f "$BIN") (deleted)" ] || return 1
  fi
  tr '\000' '\n' < "/proc/$_pid/cmdline" 2>/dev/null | awk -v path="$PIDFILE" '
    NR==2 && $0=="serve" {service=1} prev=="-pid" && $0==path {pidfile=1}
    {prev=$0} END {exit !(service && pidfile)}'
}
start() {
  if is_running; then echo "nfqws2-strategy already running"; return 0; fi
  rm -f "$PIDFILE"
  "$BIN" serve -d -l "$BIND_HOST:$PORT" -log "$LOGFILE" -pid "$PIDFILE"
  sleep 1
  if is_running; then echo "nfqws2-strategy started on :$PORT"; else echo "start failed; see $LOGFILE"; return 1; fi
}
stop() {
  if is_running; then
    PID="$(cat "$PIDFILE")"
    kill "$PID" 2>/dev/null
    i=0
    while is_running && [ "$i" -lt 60 ]; do sleep 1; i=$((i+1)); done
    if is_running; then echo "panel cleanup is still running"; return 1; fi
  fi
  rm -f "$PIDFILE"; echo "nfqws2-strategy stopped"
}
case "$1" in
  start) start ;;
  stop) stop ;;
  restart) stop && start ;;
  status) is_running && echo running || echo stopped ;;
  *) echo "usage: $0 {start|stop|restart|status}" ;;
esac
EOF
  chmod +x "$INIT"
  "$INIT" start || die "service failed to start"
fi

handoff_endpoint=$handoff_port
if [ "${handoff_local:-0}" = 1 ]; then
  handoff_endpoint=$(target_panel_endpoint) || die "could not verify the new local panel listener"
fi
verify_go_services "$handoff_endpoint" || die "migrated service verification failed"
if [ "$go_trial" = trial ]; then
  N2S_DATA="$DATA" "$BIN" finish-go-routing "$handoff_endpoint" || die "routing verification failed"
  if [ -f "$stage/parked-guard-state" ]; then
    touch "$stage/parked-go-accepted" || die "cannot record acceptance of the parked Go guard"
  fi
fi
# The running service and its routes are confirmed. A housekeeping error may
# leave old files for cleanup, but must never reactivate the old package set.
rollback_go=0 go_preparing=0 rollback_compact=0 snapshot_started=0 accepted_cleanup=1
cleanup_accepted_install || cleanup_accepted_install || die "new service confirmed but cleanup failed"
if [ "$active_profile" = compact ] && [ "$profile" = full ]; then
  selected=$(compact_packages) || die "cannot list compact packages for removal"
  # compact_packages emits names from a fixed allowlist. The base prerm
  # sees that the active binary is now full and leaves the service intact.
  if [ "$PM" = apk ]; then
    compact_apk del $selected nfqws2-strategy-compact || die "compact package removal failed"
  else
    set --
    tools=
    for package in $selected; do
      case "$package" in nfqws2-strategy-tools) tools=$package ;; *) set -- "$@" "$package" ;; esac
    done
    if [ "$#" -gt 0 ]; then opkg remove "$@" || die "compact module removal failed"; fi
    if [ -n "$tools" ]; then opkg remove "$tools" || die "shared helper removal failed"; fi
    opkg remove nfqws2-strategy-compact || die "compact package removal failed"
  fi
  rm -f "${COMPACT_BIN%/*}/.compact-repair"
  rm -rf "${COMPACT_BIN%/*}/.compact-previous"
fi

[ -e "$OLD_BIN" ] && [ "$OLD_BIN" != "$BIN" ] && rm -f "$OLD_BIN" && say "removed old binary $OLD_BIN"
IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oE 'src [0-9.]+' | awk '{print $2}' | head -1)
[ -n "$IP" ] || IP="<router-ip>"
say "installed version: $("$BIN" version 2>/dev/null || echo '?')"
case "$bind_host" in ''|'[::]'|0.0.0.0) ;; *) IP=$bind_host ;; esac
say "Web UI: http://$IP:$handoff_port"
say "Done."
