#!/bin/sh
# Build native payloads for Entware, or stage them for an OpenWrt SDK.
set -eu
if [ "$#" != 3 ]; then
    echo 'usage: sh scripts/build-rust-compact.sh <arm64|armv7|mipsel|mips|x86_64> <package-architecture> <version>' >&2
    exit 2
fi
case "$1" in
    arm64) target=aarch64-unknown-linux-musl ;;
    armv7) target=armv7-unknown-linux-musleabihf ;;
    mipsle|mipsel) target=mipsel-unknown-linux-musl ;;
    mips) target=mips-unknown-linux-musl ;;
    x86_64) target=x86_64-unknown-linux-musl ;;
    *) echo "unsupported native target: $1" >&2; exit 2 ;;
esac
case "$2" in ''|.*|*[!A-Za-z0-9._-]*) echo "invalid opkg architecture" >&2; exit 2 ;; esac
case "$3" in ''|.*|*[!A-Za-z0-9.+~-]*) echo "invalid package version" >&2; exit 2 ;; esac
version=$3
layout=${N2S_COMPACT_TOOLS:-separate}
case "$layout" in
    separate) ;;
    shared) version=$version+shared ;;
    *) echo "N2S_COMPACT_TOOLS must be separate or shared" >&2; exit 2 ;;
esac
# Both layouts use the same panel. The opkg build suffix distinguishes their
# dependency graphs when the package manager selects a candidate version.
export N2S_BUILD_VERSION="$3"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld
export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER=rust-lld
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld
npm --prefix frontend run build:compact
arch=$2
case "$target" in
    mips*)
        # Tier-3 musl targets need rust-src and the target's C linker, compiler
        # and archiver (CARGO_TARGET_<TARGET>_LINKER, CC_<target>, AR_<target>).
        export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-Ctarget-feature=+crt-static -Clink-self-contained=no"
        set -- +nightly-2026-07-11 build -Zbuild-std=std,panic_abort ;;
    *) set -- build ;;
esac
if [ "$layout" = shared ]; then
    set -- "$@" -p nfqws2-tools
else
    set -- "$@" -p nfqws2-geo -p nfqws2-blockcheck -p nfqws2-runs -p nfqws2-strategies
fi
cargo "$@" --release --locked --target "$target" --target-dir target \
    --no-default-features --features nfqws2-strategy/compact \
    -p nfqws2-strategy -p nfqws2-trace -p nfqws2-tgws
bin="target/$target/release"
if [ "$layout" = shared ]; then
    set -- --shared-tools "$bin/nfqws2-tools"
else
    set -- --geo "$bin/nfqws2-geo" --runs "$bin/nfqws2-runs" --blockcheck "$bin/nfqws2-blockcheck" --strategies "$bin/nfqws2-strategies"
fi
out="dist/rust-feeds/$arch/$version"
if [ -n "${N2S_OPENWRT_ARCH:-}" ]; then
    out=${N2S_OPENWRT_RECIPE:?missing OpenWrt SDK recipe output directory}
    set -- "$@" --openwrt-arch "$N2S_OPENWRT_ARCH"
fi
python3 scripts/build-compact-feed.py "$@" --native-rust --panel "$bin/nfqws2-strategy" \
    --trace "$bin/nfqws2-trace" --tgws "$bin/nfqws2-tgws" \
    --version "$version" --arch "$arch" --out "$out"
