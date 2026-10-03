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
  if [ "$PM" = apk ]; then
    apk --update-cache add ca-bundle ca-certificates curl || die "cannot install HTTPS prerequisites from the configured package feeds"
  else
    opkg update || die "cannot refresh the configured package feeds"
    if [ "$PLATFORM" = openwrt ]; then
      opkg install ca-bundle ca-certificates curl || die "cannot install HTTPS prerequisites"
    else
      opkg install ca-certificates curl wget-ssl || die "cannot install HTTPS prerequisites"
    fi
  fi
}

bounded_wget() {
  # wget's --timeout limits inactivity, not total transfer time. Validate the
  # portable timeout syntax before using it, including firmware BusyBox builds
  # that provide the applet without a standalone timeout symlink.
  if command -v timeout >/dev/null 2>&1 && timeout -s KILL 1 true >/dev/null 2>&1; then
    timeout -s KILL 300 "$@"
    return $?
  fi
  if [ -x /bin/busybox ] && /bin/busybox timeout -s KILL 1 true >/dev/null 2>&1; then
    /bin/busybox timeout -s KILL 300 "$@"
    return $?
  fi
  say "GNU wget fallback requires a working timeout command or BusyBox timeout; refusing an unbounded download" >&2
  return 1
}

fetch() {
  fetch_url=$1
  fetch_dest=$2
  fetch_part="$fetch_dest.part"
  # Use a bounded retry with IPv4 for broken IPv6 routes. Both attempts verify
  # certificates and prohibit redirects to plaintext HTTP.
  if command -v curl >/dev/null 2>&1; then
    for fetch_family in auto ipv4; do
      rm -f "$fetch_part"
      if [ "$fetch_family" = ipv4 ]; then set -- -4; else set --; fi
      if curl "$@" -fSL --proto '=https' --proto-redir '=https' \
        --connect-timeout 15 --max-time 300 -o "$fetch_part" "$fetch_url" &&
        [ -s "$fetch_part" ]; then
        mv "$fetch_part" "$fetch_dest" || { rm -f "$fetch_part"; return 1; }
        return 0
      fi
    done
  fi
  # Older Entware curl builds can crash. Only use GNU wget as an independent
  # fallback: some firmware BusyBox wget builds do not verify certificates.
  # Pages asset URLs are final URLs, so redirects can be disabled entirely.
  if [ -x /opt/bin/wget ] && /opt/bin/wget --version 2>/dev/null | grep -q '^GNU Wget '; then
    rm -f "$fetch_part"
    if bounded_wget /opt/bin/wget -4 --https-only --max-redirect=0 --timeout=30 --tries=1 \
      -O "$fetch_part" "$fetch_url" && [ -s "$fetch_part" ]; then
      mv "$fetch_part" "$fetch_dest" || { rm -f "$fetch_part"; return 1; }
      return 0
    fi
  fi
  rm -f "$fetch_part"
  return 1
}

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
