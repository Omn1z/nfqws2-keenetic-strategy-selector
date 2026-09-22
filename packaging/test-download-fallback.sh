#!/bin/sh
# Test both self-contained download helpers without touching router paths.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/n2s-download-test.XXXXXX")
test_dir=$(CDPATH= cd -- "$test_dir" && pwd)
case "$test_dir" in /*/n2s-download-test.*) ;; *) echo 'unexpected test directory' >&2; exit 1 ;; esac
trap 'rm -rf "$test_dir"' 0
mkdir -p "$test_dir/bin"

cat > "$test_dir/bin/curl" <<'EOF'
#!/bin/sh
[ "$1" = -fSL ] && [ "$3" = -o ] || exit 2
if [ "${N2S_TEST_CURL_EMPTY:-0}" = 1 ]; then
  : > "$4"
  exit 0
fi
printf 'partial curl download\n' > "$4"
exit 139
EOF
cat > "$test_dir/bin/entware-wget" <<'EOF'
#!/bin/sh
[ "$1" = -O ] || exit 2
if [ "${N2S_TEST_ENTWARE_WGET_FAIL:-0}" = 1 ]; then
  printf 'partial Entware wget download\n' > "$2"
  exit 1
fi
printf 'complete Entware wget download\n' > "$2"
EOF
cat > "$test_dir/bin/busybox" <<'EOF'
#!/bin/sh
[ "$1" = wget ] && [ "$2" = -O ] || exit 2
if [ "${N2S_TEST_BUSYBOX_FAIL:-0}" = 1 ]; then
  printf 'partial BusyBox download\n' > "$3"
  exit 1
fi
printf 'complete BusyBox download\n' > "$3"
EOF
cat > "$test_dir/bin/wget" <<'EOF'
#!/bin/sh
[ "$1" = -O ] || exit 2
if [ "${N2S_TEST_WGET_FAIL:-0}" = 1 ]; then
  printf 'partial wget download\n' > "$2"
  exit 1
fi
printf 'complete wget download\n' > "$2"
EOF
chmod +x "$test_dir/bin/curl" "$test_dir/bin/entware-wget" "$test_dir/bin/busybox" "$test_dir/bin/wget"

PATH="$test_dir/bin:$PATH"
N2S_ENTWARE_WGET="$test_dir/bin/entware-wget"
N2S_BUSYBOX="$test_dir/bin/busybox"
export PATH N2S_ENTWARE_WGET N2S_BUSYBOX

check_clean() {
  for leftover in "$1".n2s-download.*; do
    [ ! -e "$leftover" ] || { echo "temporary download left behind: $leftover" >&2; exit 1; }
  done
}

for installer in install update; do
  sed -n '/^fetch() {/,/^}/p' "$script_dir/$installer.sh" > "$test_dir/fetch.sh"
  . "$test_dir/fetch.sh"
  dest="$test_dir/$installer-download"

  printf 'old file\n' > "$dest"
  fetch https://example.invalid/panel "$dest"
  [ "$(cat "$dest")" = 'complete Entware wget download' ]
  check_clean "$dest"

  # A downloader that exits successfully with an empty file must still retry.
  N2S_TEST_CURL_EMPTY=1
  export N2S_TEST_CURL_EMPTY
  fetch https://example.invalid/panel "$dest"
  [ "$(cat "$dest")" = 'complete Entware wget download' ]
  check_clean "$dest"
  unset N2S_TEST_CURL_EMPTY

  N2S_TEST_ENTWARE_WGET_FAIL=1
  export N2S_TEST_ENTWARE_WGET_FAIL
  fetch https://example.invalid/panel "$dest"
  [ "$(cat "$dest")" = 'complete BusyBox download' ]
  check_clean "$dest"

  N2S_TEST_BUSYBOX_FAIL=1
  export N2S_TEST_BUSYBOX_FAIL
  fetch https://example.invalid/panel "$dest"
  [ "$(cat "$dest")" = 'complete wget download' ]
  check_clean "$dest"

  N2S_TEST_WGET_FAIL=1
  export N2S_TEST_WGET_FAIL
  if fetch https://example.invalid/panel "$dest"; then
    echo "$installer: download unexpectedly succeeded" >&2
    exit 1
  fi
  [ "$(cat "$dest")" = 'complete wget download' ]
  check_clean "$dest"
  unset N2S_TEST_ENTWARE_WGET_FAIL N2S_TEST_BUSYBOX_FAIL N2S_TEST_WGET_FAIL
done

printf 'installer download fallback: passed (curl 139/empty, Entware/BusyBox/wget fallback, cleanup)\n'
