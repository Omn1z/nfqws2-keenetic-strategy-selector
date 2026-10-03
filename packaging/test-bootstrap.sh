#!/bin/sh
# Exercise the complete Pages bootstrap with fake packages/downloaders. Nothing
# is installed and no router path or external network endpoint is accessed.
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/n2s-bootstrap-test.XXXXXX")
test_dir=$(CDPATH= cd -- "$test_dir" && pwd)
case "$test_dir" in /*/n2s-bootstrap-test.*) ;; *) exit 1 ;; esac
trap 'rm -rf "$test_dir"' 0
mkdir -p "$test_dir/bin" "$test_dir/source" "$test_dir/etc" "$test_dir/router-tmp" "$test_dir/opt-tmp"
N2S_TEST_REAL_MV=$(command -v mv)
export N2S_TEST_REAL_MV

cat > "$test_dir/bin/id" <<'EOF'
#!/bin/sh
printf '%s\n' "${N2S_TEST_UID:-0}"
EOF
cat > "$test_dir/pm-apk" <<'EOF'
#!/bin/sh
if [ "$1" = --print-arch ]; then printf '%s\n' "${N2S_TEST_ARCH-aarch64_cortex-a53}"; exit; fi
printf 'apk %s\n' "$*" >> "$N2S_TEST_PACKAGES"
exit "${N2S_TEST_PM_STATUS:-0}"
EOF
cat > "$test_dir/bin/opkg" <<'EOF'
#!/bin/sh
if [ "$1" = print-architecture ]; then
  printf 'arch all 1\narch noarch 1\n'
  if [ -n "${N2S_TEST_ARCH-aarch64-3.10_kn}" ]; then
    printf 'arch wrong_low_priority 2\narch %s 10\n' "${N2S_TEST_ARCH-aarch64-3.10_kn}"
  fi
  exit
fi
printf 'opkg %s\n' "$*" >> "$N2S_TEST_PACKAGES"
exit "${N2S_TEST_PM_STATUS:-0}"
EOF
cat > "$test_dir/bin/od" <<'EOF'
#!/bin/sh
printf ' %s\n' "${N2S_TEST_ENDIAN:-1}"
EOF
cat > "$test_dir/bin/uname" <<'EOF'
#!/bin/sh
printf '%s\n' "${N2S_TEST_UNAME:-aarch64}"
EOF
cat > "$test_dir/bin/mv" <<'EOF'
#!/bin/sh
case "$1" in *.part) [ "${N2S_TEST_RENAME_FAIL:-0}" = 0 ] || exit 1 ;; esac
exec "$N2S_TEST_REAL_MV" "$@"
EOF
cat > "$test_dir/bin/timeout" <<'EOF'
#!/bin/sh
set -eu
[ "${N2S_TEST_TIMEOUT_MISSING:-0}" = 0 ] || exit 127
[ "$1" = -s ] && [ "$2" = KILL ]
if [ "$3" = 1 ] && [ "$4" = true ]; then exit 0; fi
[ "$3" = 300 ]
printf 'timeout %s\n' "$*" >> "$N2S_TEST_DOWNLOADS"
[ "${N2S_TEST_TIMEOUT_EXPIRED:-0}" = 0 ] || exit 137
shift 3
exec "$@"
EOF
cat > "$test_dir/bin/busybox" <<'EOF'
#!/bin/sh
set -eu
[ "${N2S_TEST_BUSYBOX_TIMEOUT:-0}" = 1 ] || exit 127
[ "$1" = timeout ] && [ "$2" = -s ] && [ "$3" = KILL ]
if [ "$4" = 1 ] && [ "$5" = true ]; then exit 0; fi
[ "$4" = 300 ]
printf 'busybox %s\n' "$*" >> "$N2S_TEST_DOWNLOADS"
shift 4
exec "$@"
EOF
cat > "$test_dir/bin/curl" <<'EOF'
#!/bin/sh
set -eu
printf 'curl %s\n' "$*" >> "$N2S_TEST_DOWNLOADS"
family=auto; secure=0; redirect=0; dest=; url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -4) family=ipv4 ;;
    -fSL) ;;
    --proto) shift; [ "$1" = '=https' ]; secure=1 ;;
    --proto-redir) shift; [ "$1" = '=https' ]; redirect=1 ;;
    --connect-timeout|--max-time) shift ;;
    -o) shift; dest=$1 ;;
    https://example.invalid/n2s/releases/v1.7.1/*|https://omn1z.github.io/nfqws2-keenetic-strategy-selector/install.sh) url=$1 ;;
    *) echo "unexpected curl argument: $1" >&2; exit 2 ;;
  esac
  shift
done
[ "$secure" = 1 ] && [ "$redirect" = 1 ] && [ -n "$dest" ] && [ -n "$url" ]
case "${N2S_TEST_CURL_MODE:-ok}" in
  fail) printf 'incomplete\n' > "$dest"; exit 35 ;;
  crash) printf 'incomplete\n' > "$dest"; exit 139 ;;
  empty) : > "$dest"; exit 0 ;;
  ipv4) [ "$family" = ipv4 ] || exit 7 ;;
  cancel) kill -TERM "$PPID"; exit 143 ;;
esac
download_name=${url##*/}
case "$url" in https://omn1z.github.io/nfqws2-keenetic-strategy-selector/install.sh) download_name=launcher.sh ;; esac
cp "$N2S_TEST_SOURCE/$download_name" "$dest"
if [ "${N2S_TEST_CORRUPT:-}" = "${url##*/}" ]; then printf 'corrupt\n' >> "$dest"; fi
EOF
cat > "$test_dir/bin/entware-wget" <<'EOF'
#!/bin/sh
set -eu
if [ "$1" = --version ]; then
  if [ "${N2S_TEST_WGET_GNU:-1}" = 1 ]; then printf 'GNU Wget 1.24\n'; else printf 'BusyBox wget\n'; fi
  exit
fi
printf 'wget %s\n' "$*" >> "$N2S_TEST_DOWNLOADS"
if [ "$1" = -4 ]; then
  [ "$2" = --https-only ] && [ "$3" = --max-redirect=0 ]
  [ "$4" = --timeout=30 ] && [ "$5" = --tries=1 ] && [ "$6" = -O ]
  dest=$7; url=$8
else
  [ "$1" = --https-only ] && [ "$2" = --max-redirect=0 ]
  [ "$3" = -T ] && [ "$4" = 30 ] && [ "$5" = -t ] && [ "$6" = 2 ] && [ "$7" = -O ]
  dest=$8; url=$9
fi
[ "${N2S_TEST_WGET_FAIL:-0}" = 0 ] || { printf 'partial\n' > "$dest"; exit 1; }
if [ "${N2S_TEST_WGET_EMPTY:-0}" = 1 ]; then : > "$dest"; exit 0; fi
case "$url" in
  https://example.invalid/n2s/releases/v1.7.1/*) download_name=${url##*/} ;;
  https://omn1z.github.io/nfqws2-keenetic-strategy-selector/install.sh) download_name=launcher.sh ;;
  *) exit 2 ;;
esac
cp "$N2S_TEST_SOURCE/$download_name" "$dest"
EOF
cat > "$test_dir/source/install.sh" <<'EOF'
#!/bin/sh
set -eu
[ -n "$N2S_BIN_SRC" ] && [ -s "$N2S_BIN_SRC" ]
[ "${N2S_SKIP_DEPS:-0}" = 0 ]
[ "$N2S_PORT" = 8123 ]
[ "$(cat "$N2S_BIN_SRC")" = 'verified panel fixture' ]
printf '%s\n' "${N2S_BIN_SRC##*/}" >> "$N2S_TEST_INSTALLED"
printf '%s\n' "$N2S_BIN_SRC" > "$N2S_TEST_BINARY_PATH"
exit "${N2S_TEST_INSTALL_STATUS:-0}"
EOF
for arch in arm64 arm mipsle mips amd64; do
  printf 'verified panel fixture\n' > "$test_dir/source/nfqws2-strategy-linux-$arch"
done
chmod +x "$test_dir/bin/"* "$test_dir/pm-apk"
PATH="$test_dir/bin:$PATH"
N2S_TEST_SOURCE="$test_dir/source"
N2S_TEST_PACKAGES="$test_dir/packages"
N2S_TEST_DOWNLOADS="$test_dir/downloads"
N2S_TEST_INSTALLED="$test_dir/installed"
N2S_TEST_BINARY_PATH="$test_dir/binary-path"
N2S_PORT=8123
export PATH N2S_TEST_SOURCE N2S_TEST_PACKAGES N2S_TEST_DOWNLOADS N2S_TEST_INSTALLED N2S_TEST_BINARY_PATH N2S_PORT
unset N2S_SKIP_DEPS

make_bootstrap() {
  (cd "$test_dir/source" && sha256sum install.sh nfqws2-strategy-linux-* | sed 's/ \*/  /' > SHA256SUMS)
  case "${N2S_TEST_MANIFEST:-ok}" in
    duplicate) duplicate_line=$(sed -n '/  install.sh$/p' "$test_dir/source/SHA256SUMS"); printf '%s\n' "$duplicate_line" >> "$test_dir/source/SHA256SUMS" ;;
    missing) sed '/  install.sh$/d' "$test_dir/source/SHA256SUMS" > "$test_dir/manifest"; mv "$test_dir/manifest" "$test_dir/source/SHA256SUMS" ;;
    invalid) sed 's/^[0-9a-f]*  install.sh$/bad-hash  install.sh/' "$test_dir/source/SHA256SUMS" > "$test_dir/manifest"; mv "$test_dir/manifest" "$test_dir/source/SHA256SUMS" ;;
  esac
  manifest_hash=$(sha256sum "$test_dir/source/SHA256SUMS"); manifest_hash=${manifest_hash%% *}
  sed -e 's#@PAGES_BASE_URL@#https://example.invalid/n2s#g' \
    -e 's#@RELEASE_TAG@#v1.7.1#g' -e "s#@SHA256SUMS_SHA256@#$manifest_hash#g" \
    -e "s#/etc/openwrt_release#$test_dir/etc/openwrt_release#g" \
    -e "s#/etc/rc.common#$test_dir/etc/rc.common#g" \
    -e "s#/etc/init.d#$test_dir/etc/init.d#g" \
    -e "s#/opt/bin/wget#$test_dir/bin/entware-wget#g" \
    -e "s#/bin/busybox#$test_dir/bin/busybox#g" \
    -e "s#temp_base=/opt/tmp#temp_base='$test_dir/opt-tmp'#g" \
    -e "s#temp_base=/tmp#temp_base='$test_dir/router-tmp'#g" \
    "$script_dir/bootstrap.sh" > "$test_dir/bootstrap.sh"
}
reset_result() {
  rm -f "$N2S_TEST_PACKAGES" "$N2S_TEST_DOWNLOADS" "$N2S_TEST_INSTALLED" "$N2S_TEST_BINARY_PATH"
}
check_clean() {
  for base in "$test_dir/router-tmp" "$test_dir/opt-tmp"; do
    for path in "$base"/n2s-bootstrap.*; do
      [ ! -e "$path" ] || { echo "bootstrap left temporary files: $path" >&2; exit 1; }
    done
  done
}
run_ok() {
  reset_result
  sh "$test_dir/bootstrap.sh" > "$test_dir/log" 2>&1 || { cat "$test_dir/log"; exit 1; }
  [ "$(wc -l < "$N2S_TEST_INSTALLED" | tr -d ' ')" = 1 ]
  [ ! -e "$(cat "$N2S_TEST_BINARY_PATH")" ]
  check_clean
}
run_bad() {
  reset_result
  if sh "$test_dir/bootstrap.sh" > "$test_dir/log" 2>&1; then
    echo 'bootstrap unexpectedly succeeded' >&2; cat "$test_dir/log"; exit 1
  fi
  [ ! -e "$N2S_TEST_INSTALLED" ]
  check_clean
}

# Full flow on each supported package family, without real package operations.
make_bootstrap
: > "$test_dir/etc/openwrt_release"
cp "$test_dir/pm-apk" "$test_dir/bin/apk"
run_ok
grep -qx 'apk --update-cache add ca-bundle ca-certificates curl' "$N2S_TEST_PACKAGES"
grep -qx 'nfqws2-strategy-linux-arm64' "$N2S_TEST_INSTALLED"
rm "$test_dir/bin/apk"
run_ok
grep -qx 'opkg install ca-bundle ca-certificates curl' "$N2S_TEST_PACKAGES"
rm "$test_dir/etc/openwrt_release"
run_ok
grep -qx 'opkg install ca-certificates curl wget-ssl' "$N2S_TEST_PACKAGES"
grep -q '/opt-tmp/' "$N2S_TEST_BINARY_PATH"

# Broken IPv6, crashing/empty curl, GNU wget fallback, and all-download failure.
for mode in ipv4 crash empty; do
  N2S_TEST_CURL_MODE=$mode; export N2S_TEST_CURL_MODE
  run_ok
  if [ "$mode" = ipv4 ]; then
    grep -q '^curl -4 ' "$N2S_TEST_DOWNLOADS"
  else
    grep -q '^wget ' "$N2S_TEST_DOWNLOADS"
    grep -q '^timeout -s KILL 300 ' "$N2S_TEST_DOWNLOADS"
  fi
done
N2S_TEST_CURL_MODE=fail; N2S_TEST_WGET_FAIL=1
export N2S_TEST_CURL_MODE N2S_TEST_WGET_FAIL
run_bad
unset N2S_TEST_WGET_FAIL
N2S_TEST_WGET_GNU=0; export N2S_TEST_WGET_GNU
run_bad
! grep -q '^wget ' "$N2S_TEST_DOWNLOADS"
unset N2S_TEST_CURL_MODE N2S_TEST_WGET_GNU

# GNU wget receives a total deadline; absent or expired timeout never runs it.
N2S_TEST_CURL_MODE=fail; N2S_TEST_TIMEOUT_MISSING=1; N2S_TEST_BUSYBOX_TIMEOUT=1
export N2S_TEST_CURL_MODE N2S_TEST_TIMEOUT_MISSING N2S_TEST_BUSYBOX_TIMEOUT
run_ok
grep -q '^busybox timeout -s KILL 300 ' "$N2S_TEST_DOWNLOADS"
unset N2S_TEST_BUSYBOX_TIMEOUT
run_bad
grep -q 'refusing an unbounded download' "$test_dir/log"
! grep -q '^wget ' "$N2S_TEST_DOWNLOADS"
unset N2S_TEST_TIMEOUT_MISSING
N2S_TEST_TIMEOUT_EXPIRED=1; export N2S_TEST_TIMEOUT_EXPIRED
run_bad
! grep -q '^wget ' "$N2S_TEST_DOWNLOADS"
unset N2S_TEST_CURL_MODE N2S_TEST_TIMEOUT_EXPIRED

# A successful transfer is still a failure if the atomic rename cannot finish.
N2S_TEST_RENAME_FAIL=1; export N2S_TEST_RENAME_FAIL
run_bad
grep -q 'cannot download release checksums' "$test_dir/log"
N2S_TEST_CURL_MODE=fail; export N2S_TEST_CURL_MODE
run_bad
grep -q '^wget ' "$N2S_TEST_DOWNLOADS"
grep -q 'cannot download release checksums' "$test_dir/log"
unset N2S_TEST_CURL_MODE N2S_TEST_RENAME_FAIL

# Cancellation during a download also removes the temporary directory.
N2S_TEST_CURL_MODE=cancel; export N2S_TEST_CURL_MODE
run_bad
unset N2S_TEST_CURL_MODE

# No script runs after corruption of any protected release asset or ambiguity.
for filename in SHA256SUMS install.sh nfqws2-strategy-linux-arm64; do
  N2S_TEST_CORRUPT=$filename; export N2S_TEST_CORRUPT
  run_bad
  grep -q 'SHA-256 mismatch' "$test_dir/log"
done
unset N2S_TEST_CORRUPT
for mode in duplicate missing invalid; do
  N2S_TEST_MANIFEST=$mode; export N2S_TEST_MANIFEST
  make_bootstrap
  run_bad
done
unset N2S_TEST_MANIFEST
make_bootstrap

# Dependency failure and non-root execution stop before even downloading data.
N2S_TEST_PM_STATUS=1; export N2S_TEST_PM_STATUS
run_bad
[ ! -e "$N2S_TEST_DOWNLOADS" ]
unset N2S_TEST_PM_STATUS
N2S_TEST_UID=1000; export N2S_TEST_UID
run_bad
[ ! -e "$N2S_TEST_PACKAGES" ]
unset N2S_TEST_UID

# The child installer's failure is returned intact, with temporary files removed.
N2S_TEST_INSTALL_STATUS=7; export N2S_TEST_INSTALL_STATUS
reset_result
status=0
sh "$test_dir/bootstrap.sh" > "$test_dir/log" 2>&1 || status=$?
[ "$status" = 7 ]
check_clean
unset N2S_TEST_INSTALL_STATUS

# Compare architecture selection against the original installer's actual code.
sed -n '/^detect_asset() {/,/^}/p' "$script_dir/bootstrap.sh" > "$test_dir/bootstrap-arch.sh"
sed -n '/^arch_raw=/,/^ASSET=/p' "$script_dir/install.sh" > "$test_dir/installer-arch.sh"
cat > "$test_dir/select-arch.sh" <<'EOF'
#!/bin/sh
set -eu
die() { echo "$*" >&2; exit 1; }
. "$1"
if command -v detect_asset >/dev/null 2>&1; then detect_asset; fi
printf '%s\n' "$ASSET"
EOF
cp "$test_dir/pm-apk" "$test_dir/bin/apk"
for pm in apk opkg; do
  PM=$pm; export PM
  for arch in '' aarch64_cortex-a53 aarch64-3.10_kn arm64 armv7 armv8 armhf arm_cortex-a9 arm_arm1176 armv5 armv6 mipsel_24kc mipsle mips_24kc mips64 mips x86_64 amd64 x64 riscv64; do
    N2S_TEST_ARCH=$arch; export N2S_TEST_ARCH
    for endian in 1 2 0; do
      N2S_TEST_ENDIAN=$endian; export N2S_TEST_ENDIAN
      a_status=0; b_status=0
      a=$(sh "$test_dir/select-arch.sh" "$test_dir/bootstrap-arch.sh" 2>/dev/null) || a_status=$?
      b=$(sh "$test_dir/select-arch.sh" "$test_dir/installer-arch.sh" 2>/dev/null) || b_status=$?
      [ "$a_status" = "$b_status" ] && [ "$a" = "$b" ] || { echo "architecture mismatch: $pm $arch endian=$endian" >&2; exit 1; }
    done
  done
done
# An unsupported router must not install packages or download any payload.
N2S_TEST_ARCH=riscv64; export N2S_TEST_ARCH
run_bad
[ ! -e "$N2S_TEST_PACKAGES" ] && [ ! -e "$N2S_TEST_DOWNLOADS" ]
unset N2S_TEST_ARCH N2S_TEST_ENDIAN PM

# Test exactly the user-facing README launcher, not a separately maintained copy.
# Only absolute filesystem paths are rewritten; its commands and URL are intact.
awk '
  /^## Установка$/ { section=1; next }
  section && /^```sh$/ { code=1; next }
  code && /^```$/ { exit }
  code { print }
' "$script_dir/../README.md" > "$test_dir/launcher-original.sh"
[ -s "$test_dir/launcher-original.sh" ]
sh -n "$test_dir/launcher-original.sh"
mkdir -p "$test_dir/launcher-tmp"
sed -e "s#/etc/openwrt_release#$test_dir/etc/openwrt_release#g" \
  -e "s#/etc/rc.common#$test_dir/etc/rc.common#g" \
  -e "s#/etc/init.d#$test_dir/etc/init.d#g" \
  -e "s#/opt/bin/wget#$test_dir/bin/entware-wget#g" \
  -e "s#/opt/bin:/opt/sbin:#$test_dir/bin:#g" \
  -e "s#/tmp/n2s-install\.#$test_dir/launcher-tmp/n2s-install.#g" \
  "$test_dir/launcher-original.sh" > "$test_dir/launcher-test.sh"
cat > "$test_dir/source/launcher.sh" <<'EOF'
#!/bin/sh
printf 'launched\n' >> "$N2S_TEST_INSTALLED"
printf '%s\n' "$0" > "$N2S_TEST_BINARY_PATH"
EOF
check_launcher_clean() {
  for path in "$test_dir/launcher-tmp"/n2s-install.*; do
    [ ! -e "$path" ] || { echo "README launcher left temporary file: $path" >&2; exit 1; }
  done
}
launcher_ok() {
  reset_result
  sh "$test_dir/launcher-test.sh" > "$test_dir/log" 2>&1 || { cat "$test_dir/log"; exit 1; }
  [ "$(cat "$N2S_TEST_INSTALLED")" = launched ]
  [ ! -e "$(cat "$N2S_TEST_BINARY_PATH")" ]
  check_launcher_clean
}
launcher_bad() {
  reset_result
  if sh "$test_dir/launcher-test.sh" > "$test_dir/log" 2>&1; then
    echo 'README launcher unexpectedly succeeded' >&2; cat "$test_dir/log"; exit 1
  fi
  [ ! -e "$N2S_TEST_INSTALLED" ]
  check_launcher_clean
}
for platform in apk opkg entware; do
  : > "$test_dir/etc/openwrt_release"
  cp "$test_dir/pm-apk" "$test_dir/bin/apk"
  case "$platform" in
    opkg) rm "$test_dir/bin/apk" ;;
    entware) rm "$test_dir/etc/openwrt_release" ;;
  esac
  launcher_ok
  case "$platform" in
    apk) grep -qx 'apk --update-cache add ca-bundle ca-certificates curl' "$N2S_TEST_PACKAGES" ;;
    opkg) grep -qx 'opkg install ca-bundle ca-certificates curl' "$N2S_TEST_PACKAGES" ;;
    entware)
      grep -qx 'opkg install ca-certificates wget-ssl' "$N2S_TEST_PACKAGES"
      grep -q '^wget ' "$N2S_TEST_DOWNLOADS"
      ! grep -q '^curl ' "$N2S_TEST_DOWNLOADS" ;;
  esac
  N2S_TEST_PM_STATUS=1; export N2S_TEST_PM_STATUS
  launcher_bad
  [ ! -e "$N2S_TEST_DOWNLOADS" ]
  [ "$(wc -l < "$N2S_TEST_PACKAGES" | tr -d ' ')" = 1 ]
  unset N2S_TEST_PM_STATUS
  if [ "$platform" = entware ]; then
    N2S_TEST_WGET_FAIL=1; export N2S_TEST_WGET_FAIL
    launcher_bad
    unset N2S_TEST_WGET_FAIL
    N2S_TEST_WGET_EMPTY=1; export N2S_TEST_WGET_EMPTY
    launcher_bad
    unset N2S_TEST_WGET_EMPTY
  else
    for mode in fail empty; do
      N2S_TEST_CURL_MODE=$mode; export N2S_TEST_CURL_MODE
      launcher_bad
    done
    N2S_TEST_CURL_MODE=ipv4; export N2S_TEST_CURL_MODE
    launcher_ok
    grep -q '^curl -4 ' "$N2S_TEST_DOWNLOADS"
    unset N2S_TEST_CURL_MODE
  fi
done

printf 'Pages bootstrap and README launcher: passed (platforms, architecture parity, secure fallback, checksums, cleanup, failure propagation)\n'
