#!/bin/sh
# Exercise the installer/uninstaller functions in a private fake router tree.
# No package manager, router paths, network, or live firewall is used.
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/n2s-bypass-test.XXXXXX")
test_dir=$(CDPATH= cd -- "$test_dir" && pwd)
case "$test_dir" in /*/n2s-bypass-test.*) ;; *) echo 'unexpected test directory' >&2; exit 1 ;; esac
trap 'rm -rf "$test_dir"' 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15
mkdir -p "$test_dir/bin"
say() { printf '%s\n' "$*"; }

# Source only the functions: the real installer entrypoint must never run.
sed -n '/^ensure_bypass_init_hook() {/,/^}/p' "$script_dir/install.sh" > "$test_dir/functions.sh"
sed -n '/^remove_bypass_init_hook() {/,/^}/p' "$script_dir/uninstall.sh" >> "$test_dir/functions.sh"
sed -n '/^remove_bypass_files() {/,/^}/p' "$script_dir/uninstall.sh" >> "$test_dir/functions.sh"
. "$test_dir/functions.sh"

cat > "$test_dir/bin/uci" <<'EOF'
#!/bin/sh
printf 'uci %s\n' "$*" >> "$N2S_TEST_LOG"
EOF
cat > "$test_dir/bin/iptables" <<'EOF'
#!/bin/sh
printf 'iptables %s\n' "$*" >> "$N2S_TEST_LOG"
case " $* " in *' -C '*) exit 1 ;; esac
EOF
cp "$test_dir/bin/iptables" "$test_dir/bin/ip6tables"
chmod +x "$test_dir/bin/uci" "$test_dir/bin/iptables" "$test_dir/bin/ip6tables"
PATH="$test_dir/bin:$PATH"
N2S_TEST_LOG="$test_dir/calls"
export PATH N2S_TEST_LOG

write_init() {
  cat > "$ENGINE_INIT" <<EOF
#!/bin/sh
# user customization is preserved
system_config() { :; }
start_service() {
  system_config
EOF
  if [ -n "${1:-}" ]; then
    cat >> "$ENGINE_INIT" <<EOF
# nfqws2-strategy: reapply NFQUEUE bypass
[ -x '$1' ] && '$1' iptables >/dev/null 2>&1 || true
[ -x '$1' ] && '$1' ip6tables >/dev/null 2>&1 || true
EOF
  fi
  printf '}\n' >> "$ENGINE_INIT"
  chmod +x "$ENGINE_INIT"
}

for PLATFORM in openwrt entware; do
  ENGINE_CONF="$test_dir/$PLATFORM/etc/nfqws2"
  ENGINE_INIT="$test_dir/$PLATFORM/etc/init.d/nfqws2"
  mkdir -p "$ENGINE_CONF/lists" "${ENGINE_INIT%/*}"
  helper="$ENGINE_CONF/nfqws-strategy-bypass.sh"
  vendor="$ENGINE_CONF/nfqws-bypass.sh"
  cat > "$helper" <<'EOF'
#!/bin/sh
printf 'owned %s\n' "$*" >> "$N2S_TEST_LOG"
EOF
  cat > "$vendor" <<'EOF'
#!/bin/sh
printf 'vendor called\n' >> "$N2S_TEST_LOG"
exit 99
EOF
  chmod +x "$helper" "$vendor"
  printf 'example.com\n' > "$ENGINE_CONF/lists/nfqueue_bypass_domains.list"
  printf '192.0.2.1\n' > "$ENGINE_CONF/lists/nfqueue_bypass_ips.list"
  printf '192.0.2.2\n' > "$ENGINE_CONF/lists/nfqueue_bypass_resolved.list"
  write_init
  ensure_bypass_init_hook
  [ "$(grep -Fc '# nfqws2-strategy: reapply NFQUEUE bypass' "$ENGINE_INIT")" = 1 ]
  grep -Fq "$helper" "$ENGINE_INIT"
  cp "$ENGINE_INIT" "$test_dir/installed"
  ensure_bypass_init_hook
  cmp "$ENGINE_INIT" "$test_dir/installed"
  [ -f "$ENGINE_INIT.n2s-bak" ]

  # An old tagged vendor call migrates even before startup creates the new
  # helper. The guard must not execute the slow vendor script during update.
  write_init "$vendor"
  rm -f "$helper"
  ensure_bypass_init_hook
  grep -Fq "$helper" "$ENGINE_INIT"
  ! grep -Fq "$vendor" "$ENGINE_INIT"
  if [ "$PLATFORM" = openwrt ]; then
    hook="$ENGINE_CONF/nfqws-bypass-fw4.sh"
  else
    hook="${ENGINE_CONF%/*}/ndm/netfilter.d/101-nfqws2-bypass.sh"
  fi
  grep -Fq "$helper" "$hook"
  ! grep -Fq "$vendor" "$hook"
  sh -n "$ENGINE_INIT"
  sh -n "$hook"

  # Refuse to overwrite arbitrary edits following our marker.
  cp "$ENGINE_INIT" "$test_dir/good-init"
  sed 's@ ip6tables >/dev/null 2>&1 || true@ unexpected-command@' "$ENGINE_INIT" > "$test_dir/bad-init"
  cp "$test_dir/bad-init" "$ENGINE_INIT"
  if ensure_bypass_init_hook; then echo 'accepted malformed hook' >&2; exit 1; fi
  cmp "$ENGINE_INIT" "$test_dir/bad-init"
  cp "$test_dir/good-init" "$ENGINE_INIT"

  : > "$helper"
  remove_bypass_init_hook
  remove_bypass_files
  ! grep -Fq '# nfqws2-strategy: reapply NFQUEUE bypass' "$ENGINE_INIT"
  grep -Fq '# user customization is preserved' "$ENGINE_INIT"
  [ -f "$vendor" ]
  [ -f "$ENGINE_CONF/lists/nfqueue_bypass_domains.list" ]
  [ -f "$ENGINE_CONF/lists/nfqueue_bypass_ips.list" ]
  [ ! -e "$ENGINE_CONF/lists/nfqueue_bypass_resolved.list" ]
  [ ! -e "$helper" ]
  [ ! -e "$hook" ]
  sh -n "$ENGINE_INIT"
  # Uninstall also handles the previous release directly, without first
  # upgrading its tagged block or removing the vendor-owned helper.
  write_init "$vendor"
  remove_bypass_init_hook
  ! grep -Fq '# nfqws2-strategy: reapply NFQUEUE bypass' "$ENGINE_INIT"
  [ -f "$vendor" ]
done
! grep -Fq 'vendor called' "$N2S_TEST_LOG"
printf 'bypass hook smoke: passed (OpenWrt, Keenetic, migration, uninstall)\n'
