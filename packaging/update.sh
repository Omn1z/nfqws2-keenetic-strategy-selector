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
  if command -v curl >/dev/null 2>&1; then
    curl -fSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$2" "$1"
  else
    die "need curl or wget to download install.sh"
  fi
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
