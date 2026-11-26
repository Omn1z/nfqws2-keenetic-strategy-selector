#!/bin/sh
# Run inside a disposable, unbooted OpenWrt rootfs with the SDK feed at /fixture/feed.
set -eu
test -f /fixture/disposable-openwrt-root && test ! -e /proc/1 && test ! -S /var/run/ubus/ubus.sock || exit 2
. /etc/openwrt_release
feed=/fixture/feed
base=nfqws2-strategy-compact
module=nfqws2-strategy-strategies
panel=/usr/lib/nfqws2-strategy/n2s-compact
modules=/usr/lib/nfqws2-strategy/modules
command -v fw4 >/dev/null || command -v fw3 >/dev/null
mkdir -p /tmp/lock /etc/nfqws2-strategy
echo keep >/etc/nfqws2-strategy/test-data
if command -v apk >/dev/null; then
    rm -f /etc/apk/repositories /etc/apk/repositories.d/*.list
    cp "$feed/public-key.pem" /etc/apk/keys/n2s-test.pem
    echo "$feed/packages.adb" > /etc/apk/repositories.d/n2s.list
    apk --no-network verify "$feed/packages.adb"
    apk --no-network update
    add() { apk --no-network add "$@"; }
    remove() { apk --no-network del "$@"; }
else
    rm -f /etc/opkg/*.conf
    id=$(usign -F -p "$feed/public-key.pub")
    cp "$feed/public-key.pub" "/etc/opkg/keys/$id"
    echo "src/gz n2s file://$feed" >/etc/opkg/n2s.conf
    usign -V -p "$feed/public-key.pub" -m "$feed/Packages" -x "$feed/Packages.sig"
    opkg update
    add() { opkg install "$@"; }
    remove() { opkg --autoremove remove "$@"; }
fi
add "$base"
test -x "$panel"
test ! -e "$modules/strategies/nfqws2-strategies"
"$panel" version
"$panel" config | grep -q '"/etc/nfqws2-strategy"'
if "$panel" checkupdate >/fixture/checkupdate.log 2>&1; then
    echo "compact checkupdate unexpectedly accepted standalone updates" >&2
    exit 1
fi
grep -q 'OpenWrt' /fixture/checkupdate.log
grep -q 'apk' /fixture/checkupdate.log
grep -q 'opkg' /fixture/checkupdate.log
if [ "${N2S_TEST_MODULE_API:-0}" = 1 ]; then
    url=http://127.0.0.1:18090
    N2S_NOAUTH=1 N2S_DATA=/tmp/n2s-test "$panel" serve -l 127.0.0.1:18090 --ignore-saved-port >/fixture/panel.log 2>&1 &
    pid=$!
    trap 'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true' EXIT
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
        if wget -qO /tmp/modules "$url/api/modules"; then break; fi
        kill -0 "$pid" || { cat /fixture/panel.log >&2; exit 1; }
        sleep 1
    done
    grep -q "$module" /tmp/modules
    wget -qO /tmp/install --header='Content-Type: application/json' \
        --post-data="{\"package\":\"$module\"}" "$url/api/system/install"
    grep -q '"ok":true' /tmp/install || { cat /tmp/install >&2; exit 1; }
    kill "$pid"
    wait "$pid" || true
    trap - EXIT
else
    add "$module"
fi
test -x "$modules/strategies/nfqws2-strategies"
test -s "$modules/strategies/catalog.json"
case "$1" in
    shared) test "$(readlink "$modules/strategies/nfqws2-strategies")" = ../tools/nfqws2-tools ;;
    separate) test ! -L "$modules/strategies/nfqws2-strategies" ;;
    *) exit 2 ;;
esac
remove "$module"
test ! -e "$modules/strategies/nfqws2-strategies"
test ! -e "$modules/tools/nfqws2-tools"
test -x "$panel"
if command -v apk >/dev/null; then
    # Check the hooks with a live-looking service in this unbooted image.
    init=/etc/init.d/nfqws2-strategy
    bin=/usr/bin/n2s
    test ! -e "$init" && test ! -L "$init" && test ! -e "$bin" && test ! -L "$bin" || exit 1
    mkdir -p /var/run
    ln -s "$panel" "$bin"
    cat >"$init" <<'EOF'
#!/bin/sh
case "$1" in running) exit 0 ;; restart) echo restart >> /fixture/restarts ;; *) exit 1 ;; esac
EOF
    chmod +x "$init"
    : >/fixture/restarts
    sed -n '/^compact_apk() (/,/^)/p' "${panel%/*}/install.sh" >/fixture/managed-apk.sh
    . /fixture/managed-apk.sh
    compact_apk --no-network fix --reinstall "$base"
    test ! -s /fixture/restarts
    if compact_apk --no-network add n2s-missing-test-package; then exit 1; fi
    # A stale PID from a previous transaction must allow a direct reinstall.
    sh -c 'echo "$$" >/var/run/nfqws2-strategy-apk.lock; exec apk --no-network fix --reinstall "$1"' sh "$base"
    test "$(cat /fixture/restarts)" = restart
    rm "$init" "$bin"
fi
remove "$base"
test ! -e "$panel"
test "$(cat /etc/nfqws2-strategy/test-data)" = keep
echo "OpenWrt $DISTRIB_RELEASE ($DISTRIB_ARCH), $1: signed feed, install, optional module and removal passed"
