#!/bin/sh
# Execute the real helper functions with isolated fake clients/package managers.
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/n2s-download-test.XXXXXX")
test_dir=$(CDPATH= cd -- "$test_dir" && pwd)
case "$test_dir" in /*/n2s-download-test.*) ;; *) exit 1 ;; esac
trap 'rm -rf "$test_dir"' 0
mkdir -p "$test_dir/bin"
say() { :; }
for name in bootstrap install update; do
  sed -n '/^# BEGIN verified HTTPS download helpers$/,/^# END verified HTTPS download helpers$/p' "$script_dir/$name.sh" > "$test_dir/$name-helpers"
  [ -s "$test_dir/$name-helpers" ]
done
cmp "$test_dir/bootstrap-helpers" "$test_dir/install-helpers"
cmp "$test_dir/bootstrap-helpers" "$test_dir/update-helpers"
. "$test_dir/bootstrap-helpers"
cat > "$test_dir/bin/curl" <<'EOF'
#!/bin/sh
set -eu
if [ "$1" = --version ]; then
  [ "${N2S_TEST_CURL_MODE:-crash}" != loader ] || { echo 'curl: libnghttp2.so.14: cannot open shared object file' >&2; exit 127; }
  printf 'curl 8.23.0\nProtocols: http https\n'; exit 0
fi
printf 'curl %s\n' "$*" >> "$N2S_TEST_LOG"
family=auto; secure=0; redirect=0; deadline=0; dest=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -4) family=ipv4 ;; -fSL) ;;
    --proto) shift; [ "$1" = '=https' ]; secure=1 ;;
    --proto-redir) shift; [ "$1" = '=https' ]; redirect=1 ;;
    --connect-timeout) shift; [ "$1" = 15 ] ;;
    --max-time) shift; [ "$1" = 300 ]; deadline=1 ;;
    -o) shift; dest=$1 ;; https://source.invalid/*) ;; *) exit 90 ;;
  esac
  shift
done
[ "$secure$redirect$deadline" = 111 ] && [ -n "$dest" ] || exit 91
case "${N2S_TEST_CURL_MODE:-crash}" in
  ok) printf 'complete curl\n' > "$dest" ;;
  ipv4) [ "$family" = ipv4 ] || exit 7; printf 'complete curl\n' > "$dest" ;;
  empty) : > "$dest" ;; cancel) kill -TERM "$PPID"; exit 143 ;;
  *) printf 'partial curl\n' > "$dest"; exit 139 ;;
esac
EOF
cat > "$test_dir/bin/wget" <<'EOF'
#!/bin/sh
if [ "$1" = --version ]; then
  [ "${N2S_TEST_WGET_MODE:-ok}" != loader ] || exit 127
  printf 'GNU Wget 1.24\n'
  if [ "${N2S_TEST_WGET_MODE:-ok}" = nossl ]; then printf '%s\n' '-https'; else printf '+https +ssl/openssl\n'; fi
  printf 'wget: libpcre2.so: no version information available\n' >&2
  exit 0
fi
printf 'wget %s\n' "$*" >> "$N2S_TEST_LOG"
[ "$1" = -4 ] && [ "$2" = --https-only ] && [ "$3" = --max-redirect=0 ] && [ "$4" = --server-response ] && [ "$5" = --timeout=30 ] && [ "$6" = --tries=1 ] && [ "$7" = -O ] || exit 92
dest=$8; url=$9
case "$url" in https://source.invalid/*|https://mirror.invalid/*) ;; *) exit 93 ;; esac
case "${N2S_TEST_WGET_REDIRECT:-none}" in
  https) if [ "$url" = https://source.invalid/panel ]; then printf '  HTTP/1.1 302 Found\n  Location: https://mirror.invalid/panel\n' >&2; exit 8; fi ;;
  http) printf '  HTTP/1.1 302 Found\n  Location: http://mirror.invalid/panel\n' >&2; exit 8 ;;
  relative) printf '  HTTP/1.1 302 Found\n  Location: /panel\n' >&2; exit 8 ;;
  loop) printf '  HTTP/1.1 302 Found\n  Location: https://source.invalid/panel\n' >&2; exit 8 ;;
esac
case "${N2S_TEST_WGET_MODE:-ok}" in fail) printf 'partial wget\n' > "$dest"; exit 4 ;; empty) : > "$dest" ;; *) printf 'complete wget\n' > "$dest" ;; esac
EOF
cat > "$test_dir/bin/timeout" <<'EOF'
#!/bin/sh
[ "${N2S_TEST_TIMEOUT_MISSING:-0}" = 0 ] || [ -f "$N2S_TEST_TIMEOUT_INSTALLED" ] || exit 127
[ "$1" = -s ] && [ "$2" = KILL ] || exit 94
seconds=$3
[ "$seconds" -ge 1 ] && [ "$seconds" -le 300 ] || exit 95
shift 3
if [ "$seconds" = 1 ] && [ "$1" = true ]; then exit 0; fi
printf 'timeout %s\n' "$seconds" >> "$N2S_TEST_LOG"
[ "${N2S_TEST_TIMEOUT_EXPIRED:-0}" = 0 ] || exit 137
exec "$@"
EOF
cat > "$test_dir/bin/busybox" <<'EOF'
#!/bin/sh
[ "${N2S_TEST_BUSYBOX_TIMEOUT:-0}" = 1 ] || exit 127
[ "$1" = timeout ] || exit 96
shift
N2S_TEST_TIMEOUT_MISSING=0 exec "$N2S_TIMEOUT" "$@"
EOF
cat > "$test_dir/bin/opkg" <<'EOF'
#!/bin/sh
printf 'opkg %s\n' "$*" >> "$N2S_TEST_LOG"
[ "${N2S_TEST_PM_FAIL:-0}" = 0 ] || exit 1
if [ "$*" = 'install coreutils-timeout' ]; then
  [ "${N2S_TEST_HELPER_BROKEN:-0}" = 0 ] || exit 0
  : > "$N2S_TEST_TIMEOUT_INSTALLED"
fi
EOF
cat > "$test_dir/bin/apk" <<'EOF'
#!/bin/sh
echo 'unexpected apk call in opkg fixture' >&2
exit 99
EOF
chmod +x "$test_dir/bin/"*
PATH="$test_dir/bin:$PATH"
N2S_TEST_LOG="$test_dir/calls"
N2S_TEST_TIMEOUT_INSTALLED="$test_dir/timeout-installed"
N2S_TIMEOUT="$test_dir/bin/timeout"; N2S_ENTWARE_TIMEOUT=$N2S_TIMEOUT
N2S_ENTWARE_WGET="$test_dir/bin/wget"; N2S_BUSYBOX="$test_dir/bin/busybox"
PLATFORM=entware; PM=opkg
export PATH N2S_TEST_LOG N2S_TEST_TIMEOUT_INSTALLED N2S_TIMEOUT N2S_ENTWARE_TIMEOUT N2S_ENTWARE_WGET N2S_BUSYBOX PLATFORM PM
dest="$test_dir/panel"
reset() { : > "$N2S_TEST_LOG"; printf 'old file\n' > "$dest"; rm -f "$N2S_TEST_TIMEOUT_INSTALLED"; }
clean() { for path in "$dest".n2s-download.*; do [ ! -e "$path" ] || exit 97; done; }
ok() { fetch https://source.invalid/panel "$dest"; [ "$(cat "$dest")" = "$1" ]; clean; }
bad() { if fetch https://source.invalid/panel "$dest"; then echo 'unsafe fetch unexpectedly succeeded' >&2; exit 1; fi; [ "$(cat "$dest")" = 'old file' ]; clean; }
reset; ok 'complete wget'; grep -q '^timeout ' "$N2S_TEST_LOG"
reset
if fetch http://source.invalid/panel "$dest"; then echo 'plaintext URL accepted' >&2; exit 1; fi
[ ! -s "$N2S_TEST_LOG" ]; [ "$(cat "$dest")" = 'old file' ]; clean
N2S_TEST_CURL_MODE=loader; export N2S_TEST_CURL_MODE
reset; https_prepare; ok 'complete wget'
! grep -q '^curl ' "$N2S_TEST_LOG"
grep -qx 'opkg install ca-certificates' "$N2S_TEST_LOG"
! grep -Eq 'opkg install .*curl|opkg install .*wget-ssl' "$N2S_TEST_LOG"
N2S_TEST_TIMEOUT_MISSING=1; export N2S_TEST_TIMEOUT_MISSING
reset; ok 'complete wget'; grep -qx 'opkg install coreutils-timeout' "$N2S_TEST_LOG"
N2S_TEST_PM_FAIL=1; export N2S_TEST_PM_FAIL
reset; bad; ! grep -q '^wget ' "$N2S_TEST_LOG"
unset N2S_TEST_PM_FAIL
N2S_TEST_HELPER_BROKEN=1; export N2S_TEST_HELPER_BROKEN
reset; bad; ! grep -q '^wget ' "$N2S_TEST_LOG"
unset N2S_TEST_HELPER_BROKEN
N2S_TEST_BUSYBOX_TIMEOUT=1; export N2S_TEST_BUSYBOX_TIMEOUT
reset; ok 'complete wget'; ! grep -q 'coreutils-timeout' "$N2S_TEST_LOG"
unset N2S_TEST_BUSYBOX_TIMEOUT N2S_TEST_TIMEOUT_MISSING
N2S_TEST_TIMEOUT_EXPIRED=1; export N2S_TEST_TIMEOUT_EXPIRED
reset; bad; ! grep -q '^wget ' "$N2S_TEST_LOG"
unset N2S_TEST_TIMEOUT_EXPIRED
for mode in empty fail loader nossl; do N2S_TEST_WGET_MODE=$mode; export N2S_TEST_WGET_MODE; reset; bad; done
unset N2S_TEST_WGET_MODE
for mode in http relative loop; do
  N2S_TEST_WGET_REDIRECT=$mode; export N2S_TEST_WGET_REDIRECT
  reset; bad; ! grep -q ' -O .* http://' "$N2S_TEST_LOG"
done
[ "$(grep -c '^wget ' "$N2S_TEST_LOG")" = 6 ]
N2S_TEST_WGET_REDIRECT=https; export N2S_TEST_WGET_REDIRECT
reset; ok 'complete wget'; [ "$(grep -c '^wget ' "$N2S_TEST_LOG")" = 2 ]
unset N2S_TEST_WGET_REDIRECT
for mode in ok ipv4; do N2S_TEST_CURL_MODE=$mode; export N2S_TEST_CURL_MODE; reset; ok 'complete curl'; ! grep -q '^wget ' "$N2S_TEST_LOG"; done
N2S_TEST_CURL_MODE=empty; export N2S_TEST_CURL_MODE
reset; ok 'complete wget'
N2S_TEST_CURL_MODE=cancel; export N2S_TEST_CURL_MODE
reset; bad
printf 'verified HTTPS helpers: passed (parity, broken curl loader, healthy wget, verified timeout install, TLS redirects, bounds, empty/partial failures, cancellation cleanup)\n'
