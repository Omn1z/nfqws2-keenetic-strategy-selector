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

fetch() {
  (
    fetch_url=$1
    fetch_dest=$2
    fetch_dir=$(mktemp -d "$fetch_dest.n2s-download.XXXXXX") || exit 1
    fetch_part="$fetch_dir/payload"
    trap 'rm -f "$fetch_part"; rmdir "$fetch_dir" 2>/dev/null || true' 0
    trap 'exit 129' 1
    trap 'exit 130' 2
    trap 'exit 143' 15
    if command -v curl >/dev/null 2>&1; then
      if curl -fSL "$fetch_url" -o "$fetch_part" && [ -s "$fetch_part" ] &&
         mv -f "$fetch_part" "$fetch_dest"; then
        exit 0
      fi
      rm -f "$fetch_part"
    fi
    fetch_entware_wget=${N2S_ENTWARE_WGET:-/opt/bin/wget}
    if [ -x "$fetch_entware_wget" ]; then
      if "$fetch_entware_wget" -O "$fetch_part" "$fetch_url" &&
         [ -s "$fetch_part" ] && mv -f "$fetch_part" "$fetch_dest"; then
        exit 0
      fi
      rm -f "$fetch_part"
    fi
    fetch_busybox=${N2S_BUSYBOX:-/bin/busybox}
    if [ -x "$fetch_busybox" ]; then
      if "$fetch_busybox" wget -O "$fetch_part" "$fetch_url" &&
         [ -s "$fetch_part" ] && mv -f "$fetch_part" "$fetch_dest"; then
        exit 0
      fi
      rm -f "$fetch_part"
    fi
    if command -v wget >/dev/null 2>&1; then
      if wget -O "$fetch_part" "$fetch_url" && [ -s "$fetch_part" ] &&
         mv -f "$fetch_part" "$fetch_dest"; then
        exit 0
      fi
    fi
    exit 1
  )
}

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
