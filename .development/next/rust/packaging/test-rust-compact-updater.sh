#!/bin/sh
# Run inside a disposable, empty Entware chroot with no live /opt or /proc.
# The caller supplies /test/n2s (a native compact build) and the marker below.
set -eu
[ -f /test/.isolated-compact-updater ] && [ -x /test/n2s ] &&
    [ ! -e /opt/usr ] && [ ! -e /opt/etc ] && [ ! -e /opt/bin ] &&
    [ ! -e /opt/lib ] && [ ! -e /proc/self ] || exit 2
export PATH=/opt/bin:/bin:/usr/bin
root=/opt/lib/nfqws2-strategy
mkdir -p "$root" /opt/etc/nfqws2-strategy /opt/usr/bin /opt/bin /proc/self
cp /test/n2s "$root/n2s-compact"
ln -s "$root/n2s-compact" /opt/usr/bin/n2s
# Each command below executes exactly this binary. No host procfs is mounted.
ln -s "$root/n2s-compact" /proc/self/exe
cat > /opt/bin/opkg <<'EOF'
#!/bin/sh
case "$*" in
  update) exit 0 ;;
  'list-upgradable nfqws2-strategy-compact') cat /test/upgradable ;;
  'list-installed nfqws2-strategy-compact') echo 'nfqws2-strategy-compact - 2.0.0-ea-2+shared' ;;
  *) exit 2 ;;
esac
EOF
chmod 0755 /opt/bin/opkg
cat > "$root/install.sh" <<'EOF'
#!/bin/sh
set -eu
[ "$N2S_PROFILE" = compact ] && [ "$N2S_SKIP_DEPS" = 1 ] && [ "$N2S_REQUIRE_NATIVE" = 1 ]
[ "$N2S_EXPECT_PACKAGE_VERSION" = 2.0.0-ea-2+shared ] && [ "$N2S_EXPECT_VERSION" = 2.0.0-ea-2 ]
[ "$0" != /opt/lib/nfqws2-strategy/install.sh ]
echo passed >> /test/installer-calls
[ ! -e /test/fail ]
EOF
bin=/opt/usr/bin/n2s
ports=/opt/etc/nfqws2-strategy/ports.json
[ "$("$bin" resolve-panel-port --supported)" = panel-port-v1 ]
[ "$("$bin" resolve-panel-port 9079)" = 9079 ] && [ "$("$bin" resolve-panel-port 9080)" = 9080 ]
echo '{"panel_port":9095}' > "$ports"
[ "$("$bin" resolve-panel-port 9079)" = 9095 ] && [ "$("$bin" resolve-panel-port 9080)" = 9095 ]
echo '{"panel_port":65536}' > "$ports"
if "$bin" resolve-panel-port 9080 >/dev/null 2>&1; then exit 1; fi
rm "$ports"
receipt=/opt/etc/nfqws2-strategy/.store/runtime/compact-update.json
echo 'nfqws2-strategy-compact - 2.0.0-ea-1 - 2.0.0-ea-2+shared' > /test/upgradable
"$bin" checkupdate > /test/check
grep -Eq '"latest" *: *"2.0.0-ea-2"' /test/check
grep -Eq '"available" *: *true' /test/check
"$bin" update >/dev/null
grep -Eq '"stage" *: *"done"' "$receipt"
touch /test/fail
if "$bin" update >/dev/null 2>&1; then exit 1; fi
grep -Eq '"stage" *: *"error"' "$receipt"
: > /test/upgradable
"$bin" checkupdate | grep -Eq '"available" *: *false'
touch "$root/.compact-repair"
"$bin" checkupdate | grep -Eq '"latest" *: *"2.0.0-ea-2"'
rm -f /test/fail
"$bin" update >/dev/null
[ "$(wc -l </test/installer-calls)" -eq 3 ]
echo 'Native compact package check, exact upgrade, failure receipt and repair passed'
