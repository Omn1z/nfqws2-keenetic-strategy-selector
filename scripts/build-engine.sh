#!/bin/sh
# Build the official AmneziaWG 3.1 engine for Keenetic/Entware: the userspace
# `amneziawg-go` daemon (pure Go, CGO off → fully static, runs on Entware
# regardless of libc). The panel drives it DIRECTLY over its UAPI socket, so
# NO C `awg` tool and NO musl toolchain are needed — this is just a cross-compile
# like our own binary.
#
# Output: dist/awg-engine-linux-<arch>.tar.gz (+ .sha256), each containing
# `amneziawg-go`. Runs on a Linux CI host. Needs: go >= 1.25, git, tar.
set -e

AWG_GO_REPO="https://github.com/amnezia-vpn/amneziawg-go"
AWG_GO_REF="${AWG_GO_REF:-v3.1.20260828}"
OUT="$(pwd)/dist"
WORK="$(pwd)/.engine-build"
mkdir -p "$OUT" "$WORK"

[ -d "$WORK/amneziawg-go/.git" ] || git clone --no-checkout --depth 1 "$AWG_GO_REPO" "$WORK/amneziawg-go"
# Refresh reused workspaces too; otherwise rebuilds silently keep an old engine.
git -C "$WORK/amneziawg-go" fetch --depth 1 origin "refs/tags/$AWG_GO_REF:refs/tags/$AWG_GO_REF"
git -C "$WORK/amneziawg-go" checkout --detach "$AWG_GO_REF"
if [ "$AWG_GO_REF" = v3.1.20260828 ]; then
  [ "$(git -C "$WORK/amneziawg-go" rev-parse HEAD)" = b5928efb6ca19f0153958460c3d141f04abc5c2e ] || { echo "unexpected upstream revision" >&2; exit 1; }
fi

build() { # name GOARCH GOARM GOMIPS
  name="$1"
  stage="$WORK/stage-$name"; rm -rf "$stage"; mkdir -p "$stage"
  (
    cd "$WORK/amneziawg-go"
    export GOOS=linux GOARCH="$2" CGO_ENABLED=0
    if [ -n "$3" ]; then export GOARM="$3"; else unset GOARM; fi
    if [ -n "$4" ]; then export GOMIPS="$4"; else unset GOMIPS; fi
    go build -trimpath -ldflags "-s -w" -o "$stage/amneziawg-go" .
  )
  ( cd "$stage" && tar -czf "$OUT/awg-engine-linux-$name.tar.gz" amneziawg-go )
  ( cd "$OUT" && sha256sum "awg-engine-linux-$name.tar.gz" > "awg-engine-linux-$name.tar.gz.sha256" )
  echo "packaged awg-engine-linux-$name.tar.gz"
}

build arm64  arm64  ""  ""
build arm    arm    7   ""
build mipsle mipsle ""  softfloat
build mips   mips   ""  softfloat

ls -la "$OUT"/awg-engine-linux-*
