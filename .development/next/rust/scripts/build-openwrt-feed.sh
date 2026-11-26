#!/bin/sh
# Run from the repository root on Linux with a disposable, unpacked OpenWrt SDK.
# Usage: sh scripts/build-openwrt-feed.sh <sdk-dir> <version-release> <new-feed-dir>
set -eu
die() { echo "build-openwrt-feed: $*" >&2; exit 1; }
[ "$#" = 3 ] || die "expected <sdk-dir> <numeric-version-release, e.g. 1.8.7-1> <new-feed-dir>"
sdk=$(cd "$1" && pwd -P)
[ -f "$sdk/Config-build.in" ] && [ -d "$sdk/staging_dir/host/bin" ] || die "expected an unpacked OpenWrt SDK"
out=$(realpath -m "$3")
[ ! -e "$out" ] || die "output already exists: $out"
case "$out$sdk" in *[[:space:]]*) die "SDK and output paths must not contain spaces";; esac
recipe=$sdk/package/nfqws2-strategy
[ ! -e "$recipe" ] || die "use a fresh SDK package directory ($recipe already exists)"
make -C "$sdk" defconfig
arch=$(sed -n 's/^CONFIG_TARGET_ARCH_PACKAGES="\([^"]*\)"$/\1/p' "$sdk/.config")
binary_arch=$(PYTHONPATH=scripts python3 -c 'import sys; from openwrt_recipe import rust_arch; print(rust_arch(sys.argv[1]))' "$arch")
case "$binary_arch" in
    aarch64) cpu=arm64 ;;
    x86_64)
        cpu=x86_64
        # ring's x86 assembly build needs the target's musl C headers.
        # The native SDK includes this compiler and its matching sysroot.
        for cc in "$sdk"/staging_dir/toolchain-*/bin/x86_64-openwrt-linux-musl-gcc; do
            [ -x "$cc" ] || continue
            export CC_x86_64_unknown_linux_musl=${CC_x86_64_unknown_linux_musl:-$cc}
            export AR_x86_64_unknown_linux_musl=${AR_x86_64_unknown_linux_musl:-${cc%gcc}ar}
            break
        done ;;
    *) cpu=$binary_arch ;;
esac
N2S_OPENWRT_ARCH=$arch N2S_OPENWRT_RECIPE=$recipe sh scripts/build-rust-compact.sh "$cpu" "$binary_arch" "$2"

exec sh scripts/package-openwrt-feed.sh "$sdk" "$out"
