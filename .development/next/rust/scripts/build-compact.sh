#!/bin/sh
# Run from the repository root after npm ci --prefix frontend and rustup target add.
set -eu
if [ "$#" != 3 ]; then
    echo 'usage: sh scripts/build-compact.sh <arm64|armv7|mipsle|mips> <opkg-architecture> <package-version>' >&2
    exit 2
fi
platform=$1
arch=$2
version=$3
case "$arch" in ''|.*|*[!A-Za-z0-9._-]* ) echo 'invalid opkg architecture' >&2; exit 2;; esac
case "$version" in ''|.*|*[!A-Za-z0-9.+~-]* ) echo 'invalid package version' >&2; exit 2;; esac
target=
case "$platform" in
    arm64) goarch=arm64; target=aarch64-unknown-linux-musl;;
    armv7) goarch=arm; export GOARM=7; target=armv7-unknown-linux-musleabihf;;
    mipsle|mips) goarch=$platform; export GOMIPS=softfloat;;
    *) echo "unsupported platform: $platform" >&2; exit 2;;
esac

npm --prefix frontend run build:compact
out="dist/compact-build/$platform"
mkdir -p "$out"
GOOS=linux GOARCH="$goarch" CGO_ENABLED=0 go build -trimpath -buildvcs=false -tags n2s_compact \
    -ldflags "-s -w -X main.version=$version" -o "$out/panel" ./cmd/nfqws2-strategy
set --
if [ -n "$target" ]; then
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld
    export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER=rust-lld
    cargo build -p nfqws2-geo -p nfqws2-sysinfo --release --locked --offline --target "$target" --target-dir target
    set -- --geo "target/$target/release/nfqws2-geo"
fi
python3 scripts/build-compact-feed.py --panel "$out/panel" --arch "$arch" --version "$version" \
    --out "dist/compact-feeds/$arch/$version" "$@"
