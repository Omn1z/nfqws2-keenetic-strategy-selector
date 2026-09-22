#!/bin/sh
# Exercise the OpenWrt apk dependency selection without touching a router.
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/n2s-install-deps.XXXXXX")
test_dir=$(CDPATH= cd -- "$test_dir" && pwd)
case "$test_dir" in /*/n2s-install-deps.*) ;; *) echo 'unexpected test directory' >&2; exit 1 ;; esac
trap 'rm -rf "$test_dir"' 0
mkdir -p "$test_dir/bin"
cat > "$test_dir/bin/apk" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$N2S_TEST_APK_LOG"
EOF
chmod +x "$test_dir/bin/apk"
PATH="$test_dir/bin:$PATH"
N2S_TEST_APK_LOG="$test_dir/apk.log"
export PATH N2S_TEST_APK_LOG

# Source only the function under test; the installer entrypoint must not run.
sed -n '/^install_dependencies() {/,/^}/p' "$script_dir/install.sh" > "$test_dir/function.sh"
. "$test_dir/function.sh"
say() { :; }
die() { echo "$*" >&2; exit 1; }
PM=apk
PLATFORM=openwrt
install_dependencies

[ "$(wc -l < "$N2S_TEST_APK_LOG")" -eq 1 ]
set -- $(cat "$N2S_TEST_APK_LOG")
for required in --update-cache add iptables-nft ip6tables-nft iptables-mod-nfqueue; do
  found=0
  for arg do [ "$arg" = "$required" ] && found=1; done
  [ "$found" -eq 1 ] || { echo "missing apk argument: $required" >&2; exit 1; }
done
for virtual in iptables ip6tables; do
  for arg do
    [ "$arg" != "$virtual" ] || { echo "unresolved apk virtual package: $virtual" >&2; exit 1; }
  done
done
printf 'OpenWrt apk dependencies: passed\n'
