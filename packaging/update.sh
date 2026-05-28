#!/bin/sh
# nfqws2-strategy updater: fetch the latest release binary and restart the
# service. Lists/results/blobs and the init script are preserved.
set -e

# ----- keep in sync with install.sh -----
REPO="Omn1z/nfqws2-keenetic-strategy-selector"
# -----------------------------------------

BIN=/opt/usr/bin/nfqws2-strategy
INIT=/opt/etc/init.d/S52nfqws2-strategy

say() { echo "[nfqws2-strategy] $*"; }
die() { echo "[nfqws2-strategy] ERROR: $*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "run as root"
[ -x "$INIT" ] || die "not installed (run install.sh first)"
command -v opkg >/dev/null 2>&1 || die "opkg not found"

arch_raw=$(opkg print-architecture 2>/dev/null | awk '{print $2}')
[ -n "$arch_raw" ] || arch_raw=$(uname -m)
case "$arch_raw" in
  *aarch64*|*arm64*) GOARCH=arm64 ;;
  *armv7*|*armv8*)   GOARCH=arm ;;
  *mipsel*)          GOARCH=mipsle ;;
  *mips*)            GOARCH=mipsle ;;
  *x86_64*|*x64*)    GOARCH=amd64 ;;
  *)                 die "unsupported architecture: $arch_raw" ;;
esac
ASSET="nfqws2-strategy-linux-$GOARCH"
URL="https://github.com/$REPO/releases/latest/download/$ASSET"

fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then wget -O "$2" "$1"
  else die "need curl or wget"; fi
}

say "current: $("$BIN" version 2>/dev/null || echo '?')"
say "downloading $URL"
fetch "$URL" "$BIN.new" || die "download failed"
chmod +x "$BIN.new"

"$INIT" stop 2>/dev/null || true
mv "$BIN.new" "$BIN"
"$INIT" start || die "service failed to start"
say "updated to: $("$BIN" version 2>/dev/null || echo '?')"
say "Done."
