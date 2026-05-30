#!/bin/sh
# Build OUR OWN AmneziaWG 2.0 engine for Keenetic/Entware: the userspace
# `amneziawg-go` daemon (pure Go) + the `awg` CLI from amneziawg-tools (C,
# statically linked against musl so it runs on Entware). No third-party binaries.
#
# Output: dist/awg-engine-linux-<arch>.tar.gz (+ .sha256), each containing
#   amneziawg-go  — creates the awg0 TUN + UAPI socket
#   awg           — `awg setconf` / `awg show` (talks to the UAPI socket)
# Bring-up on the router is manual (amneziawg-go awg0; ip link up; awg setconf;
# ip mtu) — awg-quick (a bash script) is NOT needed under busybox.
#
# Runs on a Linux CI host. Needs: go >= 1.24, git, curl, tar, make.
# Usage: sh scripts/build-engine.sh
set -e

AWG_GO_REPO="https://github.com/amnezia-vpn/amneziawg-go"
AWG_GO_REF="${AWG_GO_REF:-v0.2.16}"
AWG_TOOLS_REPO="https://github.com/amnezia-vpn/amneziawg-tools"
AWG_TOOLS_REF="${AWG_TOOLS_REF:-v1.0.20250901}"
MUSL_BASE="${MUSL_BASE:-https://musl.cc}"

OUT="$(pwd)/dist"
WORK="$(pwd)/.engine-build"
mkdir -p "$OUT" "$WORK"

# name:GOARCH:GOARM:GOMIPS:musl-toolchain (float must match the Go target)
ARCHES="
arm64:arm64:::aarch64-linux-musl
arm:arm:7::armv7l-linux-musleabihf
mipsle:mipsle::softfloat:mipsel-linux-muslsf
mips:mips::softfloat:mips-linux-muslsf
"

[ -d "$WORK/amneziawg-go" ] || git clone --depth 1 -b "$AWG_GO_REF" "$AWG_GO_REPO" "$WORK/amneziawg-go"
[ -d "$WORK/amneziawg-tools" ] || git clone --depth 1 -b "$AWG_TOOLS_REF" "$AWG_TOOLS_REPO" "$WORK/amneziawg-tools"

for row in $ARCHES; do
  name=$(echo "$row" | cut -d: -f1); [ -n "$name" ] || continue
  goarch=$(echo "$row" | cut -d: -f2)
  goarm=$(echo "$row" | cut -d: -f3)
  gomips=$(echo "$row" | cut -d: -f4)
  musl=$(echo "$row" | cut -d: -f5)
  echo "=== engine: $name (GOARCH=$goarch musl=$musl) ==="
  stage="$WORK/stage-$name"; rm -rf "$stage"; mkdir -p "$stage"

  # 1) amneziawg-go (pure Go, static, CGO off) — same flags as our own binary
  (
    cd "$WORK/amneziawg-go"
    export GOOS=linux GOARCH="$goarch" CGO_ENABLED=0
    if [ -n "$goarm" ]; then export GOARM="$goarm"; else unset GOARM; fi
    if [ -n "$gomips" ]; then export GOMIPS="$gomips"; else unset GOMIPS; fi
    go build -trimpath -ldflags "-s -w" -o "$stage/amneziawg-go" .
  )

  # 2) amneziawg-tools `awg` (C, static musl)
  tc="$WORK/${musl}-cross"
  if [ ! -d "$tc" ]; then
    echo "fetching musl toolchain ${musl}-cross ..."
    curl -fsSL "$MUSL_BASE/${musl}-cross.tgz" -o "$WORK/${musl}-cross.tgz"
    tar -xzf "$WORK/${musl}-cross.tgz" -C "$WORK"
  fi
  CC="$tc/bin/${musl}-gcc"
  (
    cd "$WORK/amneziawg-tools/src"
    make clean >/dev/null 2>&1 || true
    make CC="$CC" LDFLAGS="-static"
    cp wg "$stage/awg"
  )

  ( cd "$stage" && tar -czf "$OUT/awg-engine-linux-$name.tar.gz" amneziawg-go awg )
  ( cd "$OUT" && sha256sum "awg-engine-linux-$name.tar.gz" > "awg-engine-linux-$name.tar.gz.sha256" )
  echo "packaged awg-engine-linux-$name.tar.gz"
done

ls -la "$OUT"/awg-engine-linux-* 2>/dev/null || true
