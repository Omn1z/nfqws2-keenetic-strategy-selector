#!/bin/sh
# Published as /install.sh on this project's GitHub Pages site. The publisher
# replaces these tokens only after verifying the original release assets.
set -eu

PAGES_BASE_URL='@PAGES_BASE_URL@'
RELEASE_TAG='@RELEASE_TAG@'
SHA256SUMS_SHA256='@SHA256SUMS_SHA256@'
PATH="$PATH:/opt/bin:/opt/sbin:/opt/usr/bin"
export PATH

say() { printf '[nfqws2-strategy] %s\n' "$*"; }
die() { printf '[nfqws2-strategy] ERROR: %s\n' "$*" >&2; exit 1; }

detect_platform() {
  if [ -f /etc/openwrt_release ] || { [ -f /etc/rc.common ] && [ -d /etc/init.d ]; }; then
    PLATFORM=openwrt
    if command -v apk >/dev/null 2>&1; then
      PM=apk
    elif command -v opkg >/dev/null 2>&1; then
      PM=opkg
    else
      die "OpenWrt package manager not found (apk/opkg)"
    fi
  else
    PLATFORM=entware
    PM=opkg
    command -v opkg >/dev/null 2>&1 || die "OpenWrt was not detected and opkg is missing (is this Entware?)"
  fi
}

detect_asset() {
  # Keep this mapping consistent with the original release installer. Tests
  # exercise both implementations, including package priority and MIPS endian.
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
    *) die "unsupported architecture: $arch_raw" ;;
  esac
  ASSET="nfqws2-strategy-linux-$GOARCH"
}

prepare_https() {
  say "preparing HTTPS downloads ($PLATFORM, $PM)"
  https_prepare || die "cannot prepare a working HTTPS client from the configured package feeds"
}

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

verify_hash() {
  expected_hash=$1
  hash_file=$2
  [ "${#expected_hash}" -eq 64 ] || die "invalid SHA-256 for ${hash_file##*/}"
  case "$expected_hash" in *[!0-9a-f]*) die "invalid SHA-256 for ${hash_file##*/}" ;; esac
  actual_hash=$(sha256sum "$hash_file") || die "cannot hash ${hash_file##*/}"
  actual_hash=${actual_hash%% *}
  [ "$actual_hash" = "$expected_hash" ] || die "SHA-256 mismatch: ${hash_file##*/}; installation stopped"
}

release_hash() {
  # Reject missing/duplicate entries rather than accepting the first match.
  awk -v name="$1" '
    $2 == name || $2 == "*" name { count++; if (NF != 2) bad=1; hash=$1 }
    END { if (count != 1 || bad) exit 1; print hash }
  ' "$work/SHA256SUMS"
}

[ "$(id -u)" = 0 ] || die "run as root"
case "$PAGES_BASE_URL" in https://*) ;; *) die "unpublished bootstrap template" ;; esac
case "$RELEASE_TAG" in ''|*[!A-Za-z0-9._-]*) die "invalid release tag" ;; esac
detect_platform
detect_asset
say "release=$RELEASE_TAG, arch=$arch_raw -> $ASSET"
prepare_https
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required to verify the release"

if [ "$PLATFORM" = entware ]; then temp_base=/opt/tmp; else temp_base=/tmp; fi
mkdir -p "$temp_base" || die "cannot create temporary directory"
work=$(mktemp -d "$temp_base/n2s-bootstrap.XXXXXX") || die "cannot create temporary directory"
trap 'rm -rf "$work"' 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

release_url="$PAGES_BASE_URL/releases/$RELEASE_TAG"
say "downloading verified release from $PAGES_BASE_URL"
fetch "$release_url/SHA256SUMS" "$work/SHA256SUMS" || die "cannot download release checksums"
verify_hash "$SHA256SUMS_SHA256" "$work/SHA256SUMS"
for release_file in install.sh "$ASSET"; do
  expected=$(release_hash "$release_file") || die "missing or ambiguous release checksum: $release_file"
  fetch "$release_url/$release_file" "$work/$release_file" || die "cannot download $release_file"
  verify_hash "$expected" "$work/$release_file"
done
sh -n "$work/install.sh" || die "invalid release installer"
say "verified $RELEASE_TAG; starting the unified installer"
# Keep the parent alive so its trap removes the temporary files on all exits.
# The original release installer owns all dependency, engine and service setup.
status=0
N2S_BIN_SRC="$work/$ASSET" sh "$work/install.sh" || status=$?
exit "$status"
