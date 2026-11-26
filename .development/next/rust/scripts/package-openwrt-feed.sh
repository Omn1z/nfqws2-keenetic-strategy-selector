#!/bin/sh
# Package a recipe previously staged in SDK/package/nfqws2-strategy. May also
# run on a separate Linux SDK host without the project's Rust/Node toolchains.
set -eu
umask 022
die() { echo "package-openwrt-feed: $*" >&2; exit 1; }
[ "$#" = 2 ] || die "expected <sdk-dir> <new-feed-dir>"
sdk=$(cd "$1" && pwd -P)
recipe=$sdk/package/nfqws2-strategy
[ -f "$sdk/Config-build.in" ] && [ -f "$recipe/packages.mk" ] || die "missing SDK or staged native recipe"
out=$(realpath -m "$2")
[ ! -e "$out" ] || die "output already exists: $out"
case "$out$sdk" in *[[:space:]]*) die "SDK and output paths must not contain spaces";; esac
make -C "$sdk" defconfig
arch=$(sed -n 's/^CONFIG_TARGET_ARCH_PACKAGES="\([^"]*\)"$/\1/p' "$sdk/.config")
case "$arch" in ''|.*|*[!A-Za-z0-9._-]*) die "invalid SDK package architecture: $arch";; esac
mkdir -p "$(dirname "$out")"
stage_root=$(mktemp -d "$(dirname "$out")/.n2s-openwrt.XXXXXX")
stage=$stage_root/packages/$arch
mkdir -p "$stage"
build=$(mktemp -d "$sdk/tmp/n2s-packages.XXXXXX")
trap 'echo "Unpublished build files in $stage_root" >&2' EXIT
bin=$sdk/staging_dir/host/bin
# A stable signing identity can be provisioned in the SDK before invocation.
# Keep private keys in the SDK and export only the matching verification key.
if grep -qx 'CONFIG_USE_APK=y' "$sdk/.config"; then
    key=$sdk/private-key.pem
    if [ ! -f "$key" ]; then
        [ ! -e "$sdk/public-key.pem" ] || die "private key missing for existing SDK public key"
        (umask 077; "$bin/openssl" ecparam -name prime256v1 -genkey -noout -out "$key")
    fi
    "$bin/openssl" pkey -in "$key" -pubout -out "$stage/public-key.pem"
    ext=apk
else
    key=$sdk/key-build
    if [ ! -f "$key" ]; then
        [ ! -e "$key.pub" ] || die "private key missing for existing SDK public key"
        (umask 077; "$bin/usign" -G -s "$key" -p "$key.pub" -c "NFQWS2 Strategy")
    fi
    cp "$key.pub" "$stage/public-key.pub"
    ext=ipk
fi
set -- "CONFIG_PER_FEED_REPO=" CONFIG_SIGNED_PACKAGES=y
for payload in "$recipe"/payload/*.tar.gz; do
    name=${payload##*/}
    set -- "$@" "CONFIG_PACKAGE_${name%.tar.gz}=m"
done
make -C "$sdk" "$@" "PACKAGE_DIR=$build" "PACKAGE_SUBDIRS=$build" package/nfqws2-strategy/compile
for payload in "$recipe"/payload/*.tar.gz; do
    name=${payload##*/}
    pkg=${name%.tar.gz}
    if [ "$ext" = apk ]; then pattern="$pkg-"; else pattern="${pkg}_"; fi
    # Dependencies built by a populated SDK belong to the firmware feeds.
    # A private feed contains exactly the panel and its optional packages.
    set -- "$build/$pattern"*."$ext"
    [ "$#" = 1 ] && [ -s "$1" ] || die "expected exactly one native $pkg.$ext in $build"
    mv "$1" "$stage/"
done
cp "$recipe/"*NOTICES.txt "$recipe/"*LICENSE.txt "$stage/"
# New SDKs hash OUTPUT_DIR/packages/ARCH_PACKAGES after indexing. Keep the
# hash root, the indexer's package directory and the delivered feed identical.
make -C "$sdk" CONFIG_SIGNED_PACKAGES=y "OUTPUT_DIR=$stage_root" \
    "PACKAGE_DIR=$stage" "PACKAGE_SUBDIRS=$stage" package/index
if [ "$ext" = apk ]; then
    "$bin/apk" --keys-dir "$stage" verify "$stage/packages.adb"
    index=$build/apk-index.json
    "$bin/apk" adbdump --format json "$stage/packages.adb" > "$index"
else
    "$bin/usign" -V -p "$stage/public-key.pub" -m "$stage/Packages" -x "$stage/Packages.sig"
    gzip -cd "$stage/Packages.gz" | cmp - "$stage/Packages"
    index=$stage/Packages
fi
python3 "$recipe/verify_index.py" "$recipe/payload" "$stage" "$arch" "$ext" "$index"
if [ -f "$stage/sha256sums" ]; then
    (cd "$stage" && sha256sum --check --status sha256sums)
fi
chmod 0755 "$stage"
mv -T "$stage" "$out"
trap - EXIT
rmdir "$stage_root/packages" "$stage_root"
rm -rf "$build"
echo "OpenWrt $arch $ext feed: $out"
