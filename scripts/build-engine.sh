#!/bin/sh
# Build OUR OWN AmneziaWG 2.0 engine for Keenetic/Entware: the userspace
# `amneziawg-go` daemon (pure Go) + the `awg` CLI from amneziawg-tools (C,
# statically linked against musl so it runs on Entware). No third-party binaries.
#
# Output: dist/awg-engine-linux-<arch>.tar.gz (+ .sha256), each containing
#   amneziawg-go  — creates the awg0 TUN + UAPI socket
#   awg           — `awg setconf` / `awg show`
#
# Resilient: each arch is built independently; one arch (or a flaky musl.cc
# download) failing does NOT abort the others. The job fails only if ZERO
# bundles were produced. Verbose (set -x) so CI logs pinpoint any failure.
# Runs on a Linux CI host. Needs: go >= 1.24, git, curl, tar, make.
set -x

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

git clone --depth 1 -b "$AWG_GO_REF" "$AWG_GO_REPO" "$WORK/amneziawg-go" || { echo "FATAL: clone amneziawg-go failed"; exit 1; }
git clone --depth 1 -b "$AWG_TOOLS_REF" "$AWG_TOOLS_REPO" "$WORK/amneziawg-tools" || { echo "FATAL: clone amneziawg-tools failed"; exit 1; }

fetch_toolchain() {
  # $1 = musl toolchain name (e.g. aarch64-linux-musl)
  tc="$WORK/$1-cross"
  if [ -x "$tc/bin/$1-gcc" ]; then return 0; fi
  echo ">>> fetching musl toolchain $1-cross"
  curl --retry 4 --retry-delay 5 -fSL "$MUSL_BASE/$1-cross.tgz" -o "$WORK/$1-cross.tgz" || return 1
  tar -xzf "$WORK/$1-cross.tgz" -C "$WORK" || return 1
  [ -x "$tc/bin/$1-gcc" ]
}

built=0
for row in $ARCHES; do
  name=$(echo "$row" | cut -d: -f1); [ -n "$name" ] || continue
  goarch=$(echo "$row" | cut -d: -f2)
  goarm=$(echo "$row" | cut -d: -f3)
  gomips=$(echo "$row" | cut -d: -f4)
  musl=$(echo "$row" | cut -d: -f5)
  echo "================ engine: $name (GOARCH=$goarch musl=$musl) ================"
  stage="$WORK/stage-$name"; rm -rf "$stage"; mkdir -p "$stage"

  # 1) amneziawg-go (pure Go) — same flags as our own binary
  (
    cd "$WORK/amneziawg-go" || exit 1
    export GOOS=linux GOARCH="$goarch" CGO_ENABLED=0
    [ -n "$goarm" ] && export GOARM="$goarm" || unset GOARM
    [ -n "$gomips" ] && export GOMIPS="$gomips" || unset GOMIPS
    go build -trimpath -ldflags "-s -w" -o "$stage/amneziawg-go" .
  ) || { echo "!! amneziawg-go build failed for $name"; continue; }

  # 2) amneziawg-tools `awg` (C, static musl)
  if ! fetch_toolchain "$musl"; then echo "!! musl toolchain $musl unavailable, skipping $name"; continue; fi
  CC="$WORK/$musl-cross/bin/$musl-gcc"
  (
    cd "$WORK/amneziawg-tools/src" || exit 1
    make clean >/dev/null 2>&1 || true
    make CC="$CC" LDFLAGS="-static" wg || make CC="$CC" LDFLAGS="-static" || make CC="$CC" wg
  ) || { echo "!! awg (tools) build failed for $name"; continue; }
  if [ ! -x "$WORK/amneziawg-tools/src/wg" ]; then echo "!! awg binary missing for $name"; continue; fi
  cp "$WORK/amneziawg-tools/src/wg" "$stage/awg"

  # 3) package
  ( cd "$stage" && tar -czf "$OUT/awg-engine-linux-$name.tar.gz" amneziawg-go awg ) || continue
  ( cd "$OUT" && sha256sum "awg-engine-linux-$name.tar.gz" > "awg-engine-linux-$name.tar.gz.sha256" )
  echo ">>> packaged awg-engine-linux-$name.tar.gz"
  built=$((built + 1))
done

echo "================ built $built engine bundle(s) ================"
ls -la "$OUT"/awg-engine-linux-* 2>/dev/null || true
[ "$built" -ge 1 ] || { echo "FATAL: no engine bundles produced"; exit 1; }
