#!/bin/sh
# Smoke the wrapper with fake root/download/installer commands. No router
# paths or packages are touched, and every download stays inside the sandbox.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/n2s-update-test.XXXXXX")
trap 'rm -rf "$tmp"' 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15
mkdir -p "$tmp/bin" "$tmp/local" "$tmp/pipe"

cat > "$tmp/bin/id" <<'EOF'
#!/bin/sh
printf '0\n'
EOF
cat > "$tmp/fake-install.sh" <<'EOF'
#!/bin/sh
set -eu
[ "$N2S_PORT" = 8123 ]
[ "$N2S_BIN_SRC" = local-binary ]
[ "$N2S_SKIP_DEPS" = 1 ]
printf 'delegated\n' >> "$N2S_TEST_RESULT"
EOF
cat > "$tmp/bin/curl" <<'EOF'
#!/bin/sh
set -eu
if [ "$1" = --version ]; then printf 'curl 8.23.0\nProtocols: http https\n'; exit 0; fi
secure=0; redirect=0; deadline=0; dest=; url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -4|-fSL) ;;
    --proto) shift; [ "$1" = '=https' ]; secure=1 ;;
    --proto-redir) shift; [ "$1" = '=https' ]; redirect=1 ;;
    --connect-timeout) shift; [ "$1" = 15 ] ;;
    --max-time) shift; [ "$1" = 300 ]; deadline=1 ;;
    -o) shift; dest=$1 ;;
    https://github.com/Omn1z/nfqws2-keenetic-strategy-selector/releases/latest/download/install.sh) url=$1 ;;
    *) exit 90 ;;
  esac
  shift
done
[ "$secure$redirect$deadline" = 111 ] && [ -n "$dest" ] && [ -n "$url" ]
cp "$N2S_TEST_INSTALLER" "$dest"
printf '%s\n' "$dest" > "$N2S_TEST_DOWNLOAD"
EOF
cat > "$tmp/bin/wget" <<'EOF'
#!/bin/sh
exit 99
EOF
chmod +x "$tmp/bin/id" "$tmp/bin/curl" "$tmp/bin/wget"

PATH="$tmp/bin:$PATH"
N2S_PORT=8123
N2S_BIN_SRC=local-binary
N2S_SKIP_DEPS=1
N2S_TEST_RESULT="$tmp/result"
N2S_TEST_INSTALLER="$tmp/fake-install.sh"
N2S_TEST_DOWNLOAD="$tmp/download"
N2S_ENTWARE_WGET="$tmp/bin/wget"
export N2S_ENTWARE_WGET PATH N2S_PORT N2S_BIN_SRC N2S_SKIP_DEPS
export N2S_TEST_RESULT N2S_TEST_INSTALLER N2S_TEST_DOWNLOAD
unset N2S_INSTALLER

# A local checkout finds the adjacent install.sh without network access.
cp "$script_dir/update.sh" "$tmp/local/update.sh"
cp "$tmp/fake-install.sh" "$tmp/local/install.sh"
sh "$tmp/local/update.sh"
[ ! -e "$tmp/download" ]

# An explicit installer also works when update.sh comes through stdin.
cat "$script_dir/update.sh" | N2S_INSTALLER="$tmp/fake-install.sh" sh
[ ! -e "$tmp/download" ]

# Pipe-to-sh without a local installer fetches the release entrypoint. The fake
# curl supplies our harmless script; the downloaded temporary file is cleaned.
cd "$tmp/pipe"
cat "$script_dir/update.sh" | sh
[ -f "$tmp/download" ]
download=$(cat "$tmp/download")
[ ! -e "$download" ]
[ "$(wc -l < "$tmp/result" | tr -d ' ')" = 3 ]
printf 'update wrapper smoke: passed (local, explicit, piped download)\n'
