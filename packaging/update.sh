#!/bin/sh
# Update the panel through the single installer entrypoint. Keeping this file
# as a delegating wrapper prevents install/update from drifting on OpenWrt 25+
# (package manager, paths, architecture and procd setup all live in install.sh).
#
# Pipe usage:
#   wget -qO- .../update.sh | sh
# Local development:
#   N2S_SKIP_DEPS=1 N2S_BIN_SRC=./dist/nfqws2-strategy-linux-arm64 sh packaging/update.sh
set -e

REPO="Omn1z/nfqws2-keenetic-strategy-selector"

say() { echo "[nfqws2-strategy] $*"; }
die() { echo "[nfqws2-strategy] ERROR: $*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "run as root"

# A caller may provide an installer explicitly (useful for package tests and
# downstream mirrors). Otherwise a local checkout is preferred whenever this
# script has a real filename; a script received through stdin falls back to the
# latest release installer only at runtime.
installer="${N2S_INSTALLER:-}"
if [ -z "$installer" ] && [ -f "$0" ]; then
  script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd)
  if [ -f "$script_dir/install.sh" ]; then
    installer="$script_dir/install.sh"
  fi
fi

if [ -n "$installer" ]; then
  [ -r "$installer" ] || die "installer is not readable: $installer"
  say "delegating to $installer"
  exec sh "$installer"
fi

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

tmp=$(mktemp /tmp/nfqws2-install.XXXXXX) || die "cannot create temporary installer"
trap 'rm -f "$tmp"' 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15
url="https://github.com/$REPO/releases/latest/download/install.sh"
say "downloading unified installer"
fetch "$url" "$tmp" || die "download failed"
# Do not exec here: this shell must run its EXIT trap to remove the download.
status=0
sh "$tmp" || status=$?
exit "$status"
