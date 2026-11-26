#!/bin/sh
# Run the remote VPN provisioning against private files and fake services.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
fixture=$(mktemp -d "${TMPDIR:-/tmp}/n2s-wg-deploy.XXXXXX")
fixture=$(CDPATH= cd -- "$fixture" && pwd)
case "$fixture" in /*/n2s-wg-deploy.*) ;; *) exit 1;; esac
trap 'rm -rf -- "$fixture"' EXIT
export N2S_WG_FIXTURE="$fixture"
export SSH_CONNECTION='198.51.100.9 3456 192.0.2.19 22'

apt_fixture() (
    root=$fixture/apt
    export N2S_APT_FIXTURE="$root"
    mkdir -p "$root/bin" "$root/usr/bin" "$root/usr/local/libexec"
    awk '{root=ENVIRON["N2S_APT_FIXTURE"];
        gsub("/etc/systemd/system", root "/etc/systemd/system");
        gsub("/usr/local/libexec/nfqws-awg-quick-userspace", root "/usr/local/libexec/nfqws-awg-quick-userspace");
        gsub("/usr/bin/amneziawg-go", root "/usr/bin/amneziawg-go"); print}' \
        "$here/../rust/awg-profile/src/deploy/apt-install.sh" > "$root/install.sh"
    printf '#!/bin/sh\nexit 0\n' > "$root/bin/awg"
    cp "$root/bin/awg" "$root/bin/awg-quick"
    cp "$root/bin/awg" "$root/usr/bin/amneziawg-go"
    cp "$root/bin/awg" "$root/usr/local/libexec/nfqws-awg-quick-userspace"
    printf '#!/bin/sh\necho 0\n' > "$root/bin/id"
    cat > "$root/bin/uname" <<'EOF'
#!/bin/sh
case "$*" in
 -r) echo 6.8.0-n2s-fixture;;
 -s) echo Linux;;
 *) exit 99;;
esac
EOF
    cat > "$root/bin/systemctl" <<'EOF'
#!/bin/sh
set -eu
s=$N2S_APT_FIXTURE
case "$*" in
 'show -p LoadState --value awg-quick@awg7.service') cat "$s/load-state";;
 'show -p FragmentPath --value awg-quick@awg7.service') cat "$s/fragment";;
 'show -p DropInPaths --value awg-quick@awg7.service') cat "$s/dropins";;
 'show -p ActiveState --value awg-quick@awg7.service') echo inactive;;
 *) printf '%s\n' "$*" >> "$s/service-writes"; exit 99;;
esac
EOF
    cat > "$root/bin/modinfo" <<'EOF'
#!/bin/sh
case "$*" in amneziawg|'-F filename amneziawg') ;; *) exit 99;; esac
s=$N2S_APT_FIXTURE
echo modinfo >> "$s/module-actions"
test -e "$s/module-listed"
EOF
    cat > "$root/bin/modprobe" <<'EOF'
#!/bin/sh
test "$*" = amneziawg || exit 99
s=$N2S_APT_FIXTURE
echo modprobe >> "$s/module-actions"
test -e "$s/module-loadable"
EOF
    cat > "$root/bin/stat" <<'EOF'
#!/bin/sh
test "$1 $2" = '-c %u' || exit 99
if [ -e "$N2S_APT_FIXTURE/foreign-owner" ]; then echo 1000; else echo 0; fi
EOF
    cat > "$root/bin/apt-get" <<'EOF'
#!/bin/sh
set -eu
s=$N2S_APT_FIXTURE
printf '%s\n' "$*" >> "$s/package-actions"
test "${DEBIAN_FRONTEND:-}" = noninteractive || exit 99
case "$*" in
 update\ *) ;;
 install\ *amneziawg*)
    case "$(cat "$s/package-result")" in
     installed)
        echo loaded > "$s/load-state"
        echo /usr/lib/systemd/system/awg-quick@.service > "$s/fragment"
        touch "$s/module-listed" "$s/module-loadable";;
     listed) touch "$s/module-listed";;
     failed) exit 1;;
     *) exit 99;;
    esac;;
 install\ *) ;;
 *) exit 99;;
esac
echo 'synthetic apt output'
EOF
    cat > "$root/bin/add-apt-repository" <<'EOF'
#!/bin/sh
test "$*" = '-y ppa:amnezia/ppa' || exit 99
echo 'ppa:amnezia/ppa' >> "$N2S_APT_FIXTURE/package-actions"
EOF
    chmod +x "$root/bin/"* "$root/usr/bin/amneziawg-go" "$root/usr/local/libexec/nfqws-awg-quick-userspace"
    export PATH="$root/bin:$PATH"
    : > "$root/dropins"; : > "$root/service-writes"
    : > "$root/package-actions"; : > "$root/module-actions"
    echo loaded > "$root/load-state"
    echo /usr/lib/systemd/system/awg-quick@.service > "$root/fragment"
    echo installed > "$root/package-result"
    apt_run() {
        status=$(sh "$root/install.sh" awg7)
        if [ "$status" != "$1" ]; then
            printf 'APT response was \"%s\" with expected \"%s\"\n' "$status" "$1" >&2
            exit 1
        fi
        test ! -s "$root/service-writes"
    }

    touch "$root/module-listed" "$root/module-loadable"
    apt_run ready
    grep -Fxq modprobe "$root/module-actions"
    test ! -s "$root/package-actions"

    # Exercise the install path when no systemd service or module exists yet.
    rm "$root/module-listed" "$root/module-loadable"
    echo not-found > "$root/load-state"; : > "$root/fragment"
    : > "$root/module-actions"
    apt_run installed
    grep -Fq 'linux-headers-6.8.0-n2s-fixture' "$root/package-actions"
    grep -Fxq 'ppa:amnezia/ppa' "$root/package-actions"
    grep -Fxq modprobe "$root/module-actions"

    # DKMS registration alone does not make the installed module usable.
    rm "$root/module-loadable"
    echo listed > "$root/package-result"
    apt_run fallback

    # Do not mutate packages or the unit when it was already configured as
    # userspace or carries a drop-in owned by the administrator.
    : > "$root/package-actions"
    dropin=$root/etc/systemd/system/awg-quick@awg7.service.d/10-nfqws-userspace.conf
    mkdir -p "${dropin%/*}"
    printf '%s\n' '[Service]' 'ExecStart=' "ExecStart=$root/usr/local/libexec/nfqws-awg-quick-userspace up %i" \
        'ExecStop=' "ExecStop=$root/usr/local/libexec/nfqws-awg-quick-userspace down %i" > "$dropin"
    printf '%s\n' "$dropin" > "$root/dropins"
    apt_run userspace
    touch "$root/foreign-owner"
    apt_run blocked
    rm "$root/foreign-owner"
    printf '%s\n' 'Environment=SITE_TEST=1' >> "$dropin"
    apt_run blocked
    grep -Fxq 'Environment=SITE_TEST=1' "$dropin"
    test ! -s "$root/package-actions"

    rm "$dropin"
    : > "$root/dropins"
    rmdir "${dropin%/*}"
    echo not-found > "$root/load-state"; : > "$root/fragment"
    echo failed > "$root/package-result"
    rm "$root/module-listed"
    apt_run fallback
    grep -Fxq 'install -y amneziawg' "$root/package-actions"
    echo 'AmneziaWG APT idempotence, DKMS install, fallback and service ownership passed'
)

apt_fixture
if [ "${1:-}" = --apt-only ]; then exit 0; fi
N2S_TEST_FLOCK=$(command -v flock || :)
export N2S_TEST_FLOCK
mkdir -p "$fixture/bin" "$fixture/root/etc" "$fixture/svc"
# Only the privileged filesystem root changes. All caller data, allowlists,
# ownership checks, service control, health checks and rollback run verbatim.
sed 's|^dir=/etc/wireguard$|dir=$N2S_WG_FIXTURE/root/etc/wireguard|' \
    "$here/../rust/awg-profile/src/deploy/apply.sh" >"$fixture/apply.sh"
grep -q '^dir=\$N2S_WG_FIXTURE/' "$fixture/apply.sh"

cat >"$fixture/bin/systemctl" <<'EOF'
#!/bin/sh
set -eu
s=$N2S_WG_FIXTURE/svc
dir=$N2S_WG_FIXTURE/root/etc/wireguard
service_backend() {
    if [ -s "$s/dropins" ]; then echo userspace; else echo kernel; fi
}
case "$*" in
 'show -p FragmentPath --value wg-quick@wg7.service') cat "$s/fragment";;
 'show -p DropInPaths --value wg-quick@wg7.service') cat "$s/dropins";;
 'show -p ActiveState --value wg-quick@wg7.service') cat "$s/active";;
 'is-enabled wg-quick@wg7.service') cat "$s/enabled"; [ "$(cat "$s/enabled")" = enabled ];;
 'start wg-quick@wg7.service')
    port=$(sed -n 's/^ListenPort = //p' "$dir/wg7.conf")
    if [ -e "$s/observe-backend" ]; then
        backend=$(service_backend)
        printf 'start %s %s\n' "$backend" "$port" >> "$s/backend-actions"
    fi
    if [ -e "$s/fail-$port" ]; then echo failed >"$s/active"; exit 1; fi
    if [ -e "$s/observe-backend" ]; then echo "$backend" > "$s/loaded-backend"; fi
    printf '%s\n' "$port" >"$s/listen"
    if [ -e "$s/wrong-port" ]; then echo 19 >"$s/listen"; rm "$s/wrong-port"; fi
    echo active >"$s/active"
    printf '%s\n' "$PUBLIC" >"$s/live"
    cp "$dir/wg7.conf" "$s/loaded"
    echo start >>"$s/actions";;
 'stop wg-quick@wg7.service')
    if [ -e "$s/loaded-backend" ]; then
        backend=$(service_backend)
        test "$backend" = "$(cat "$s/loaded-backend")"
        printf 'stop %s\n' "$backend" >> "$s/backend-actions"
        rm "$s/loaded-backend"
    fi
    echo inactive >"$s/active"; rm -f "$s/live"; echo stop >>"$s/actions";;
 'enable wg-quick@wg7.service')
    echo enabled >"$s/enabled"; echo enable >>"$s/actions"
    if [ -e "$s/fail-enable" ]; then rm "$s/fail-enable"; exit 1; fi;;
 'disable wg-quick@wg7.service') echo disabled >"$s/enabled"; echo disable >>"$s/actions";;
 'reset-failed wg-quick@wg7.service') echo inactive >"$s/active";;
 *) exit 99;;
esac
EOF
cat >"$fixture/bin/ip" <<'EOF'
#!/bin/sh
case "$*" in
 'link show dev wg7') test -e "$N2S_WG_FIXTURE/svc/live";;
 '-j -d link show dev wg7')
    if [ -e "$N2S_WG_FIXTURE/svc/incorrect-kind" ]; then kind=tun; else kind=amneziawg; fi
    printf '[{"linkinfo":{"info_kind":"%s"}}]\n' "$kind";;
 '-j address show') cat "$N2S_WG_FIXTURE/svc/addr";;
 '-j -4 route show table all') cat "$N2S_WG_FIXTURE/svc/routes4";;
 '-j -6 route show table all') cat "$N2S_WG_FIXTURE/svc/routes6";;
 *) exit 99;;
esac
EOF
cat >"$fixture/bin/wg" <<'EOF'
#!/bin/sh
case "$*" in
 pubkey) read -r priv; [ "$priv" = "$PRIVATE" ] && printf '%s\n' "$PUBLIC";;
 'show wg7 public-key') cat "$N2S_WG_FIXTURE/svc/live";;
 'show wg7 listen-port') cat "$N2S_WG_FIXTURE/svc/listen";;
 'show wg7 latest-handshakes') cat "$N2S_WG_FIXTURE/svc/handshakes";;
 'showconf wg7') cat "$N2S_WG_FIXTURE/svc/loaded" && test ! -e "$N2S_WG_FIXTURE/svc/failed-dump";;
 'syncconf wg7 '*)
    cp "$3" "$N2S_WG_FIXTURE/svc/loaded"
    echo sync >>"$N2S_WG_FIXTURE/svc/actions"
    if [ -e "$N2S_WG_FIXTURE/svc/external-sync" ]; then
        mv "$N2S_WG_FIXTURE/svc/external-sync" "$N2S_WG_FIXTURE/svc/loaded"
    fi
    if [ -e "$N2S_WG_FIXTURE/svc/fail-sync" ]; then rm "$N2S_WG_FIXTURE/svc/fail-sync"; exit 1; fi;;
 *) exit 99;;
esac
EOF
cat >"$fixture/bin/stat" <<'EOF'
#!/bin/sh
case "$1:$2" in
 -c:%u) echo 0;;
 -c:%a) if [ -d "$3" ]; then echo 700; else echo 600; fi;;
 -c:%u:%a) if [ -d "$3" ]; then echo 0:700; else echo 0:600; fi;;
 *) exit 99;;
esac
EOF
cat >"$fixture/bin/flock" <<'EOF'
#!/bin/sh
test "$*" = '-w 8 9' && test ! -e "$N2S_WG_FIXTURE/svc/busy" || exit 1
if [ -n "$N2S_TEST_FLOCK" ]; then exec "$N2S_TEST_FLOCK" -w 0.2 9; fi
EOF
printf '#!/bin/sh\necho 0\n' >"$fixture/bin/id"
cat >"$fixture/bin/wg-quick" <<'EOF'
#!/bin/sh
test "$1" = strip || exit 99
cat "$2"
EOF
chmod +x "$fixture/bin/"*
export PATH="$fixture/bin:$PATH"
# Synthetic material; the fake wg utility verifies a deterministic test pair.
PRIVATE='AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE='
PUBLIC='AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI='
export PRIVATE PUBLIC
s=$fixture/svc
dir=$fixture/root/etc/wireguard
file=$dir/wg7.conf
backup=$dir/.n2s-wg7.rollback
echo /usr/lib/systemd/system/wg-quick@.service >"$s/fragment"
: >"$s/dropins"
echo inactive >"$s/active"
echo disabled >"$s/enabled"
echo '[]' >"$s/addr"
echo '[{"dst":"default","dev":"eth0"}]' >"$s/routes4"
echo '[]' >"$s/routes6"
: >"$s/actions"
: >"$s/handshakes"
cat >"$fixture/one" <<EOF
# Managed by nfqws2-strategy (WireGuard)
[Interface]
PrivateKey = $PRIVATE
Address = 10.111.0.1/24, fd42::1/64
ListenPort = 51820
MTU = 1420

[Peer]
PublicKey = AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=
PresharedKey = BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU=
AllowedIPs = 10.111.0.2/32, fd42::2/128
EOF
sed 's/51820/51821/' "$fixture/one" >"$fixture/two"
run() {
    input=$1
    expected=$2
    hash=$(sha256sum <"$input")
    actual=$(sh "$fixture/apply.sh" wg7 "$PUBLIC" "${3:-${hash%% *}}" "${4:--}" <"$input")
    check_report "$expected" "${5:-}"
}
check_report() {
    expected=$1
    exact=$2
    if [ -n "$exact" ]; then [ "$actual" = "$expected $exact" ] && return; fi
    if [ -z "$exact" ]; then
        case "$actual" in
            "$expected "*) return;;
        esac
    fi
    printf 'unexpected response (%s); expected (%s %s)\n' "$actual" "$expected" "$exact" >&2; exit 1
}
# A pin/hash mismatch, injected hook, duplicate peer address, conflicting
# network/SSH address, unmanaged link or unit must never start the service.
prior=$(sha256sum <"$fixture/one"); prior=${prior%% *}
run "$fixture/two" 'error conflict' '' "$prior" 'preflight -'
test ! -d "$dir" && test ! -s "$s/actions"
run "$fixture/one" 'error invalid' 0000000000000000000000000000000000000000000000000000000000000000
sed '/^MTU/a\
PostUp = false
' "$fixture/one" >"$fixture/hooks"
run "$fixture/hooks" 'error invalid'
sed 's/10.111.0.2\/32/10.111.0.1\/32/' "$fixture/one" >"$fixture/overlap"
run "$fixture/overlap" 'error invalid'
echo '[{"ifname":"eth0","addr_info":[{"family":"inet","local":"10.111.0.9","prefixlen":24}]}]' >"$s/addr"
run "$fixture/one" 'error conflict'
echo '[]' >"$s/addr"
echo '[{"dst":"fd42::80/128","dev":"eth1"}]' >"$s/routes6"
run "$fixture/one" 'error conflict'
echo '[]' >"$s/routes6"
sed 's/10.111.0.1\/24/198.51.100.1\/24/' "$fixture/one" >"$fixture/ssh"
run "$fixture/ssh" 'error conflict'
touch "$s/busy"; run "$fixture/one" 'error busy'; rm "$s/busy"
if [ -n "$N2S_TEST_FLOCK" ]; then
    (exec 9>>"$dir/.n2s-deploy.lock"; "$N2S_TEST_FLOCK" -x 9; run "$fixture/one" 'error busy')
fi
if python3 -I -c 'import os,sys; os.symlink(sys.argv[1],sys.argv[2])' "$fixture/one" "$file" 2>/dev/null; then
    run "$fixture/one" 'error ownership'
    test -L "$file"; rm "$file"
fi
touch "$s/live"; run "$fixture/one" 'error ownership'; rm "$s/live"
echo /etc/systemd/system/custom.conf >"$s/dropins"; run "$fixture/one" 'error ownership'; : >"$s/dropins"
echo 'foreign' >"$file"; run "$fixture/one" 'error ownership'; test "$(cat "$file")" = foreign; rm "$file"
test ! -s "$s/actions" && test ! -e "$backup"

# Enabling can change system state before returning an error.
touch "$s/fail-enable"
run "$fixture/one" 'error apply' '' '-' 'activate removed_new'
test ! -e "$file" && test ! -e "$s/live" && test "$(cat "$s/enabled")" = disabled
run "$fixture/one" ok '' '-' 'verify 0'
cmp "$fixture/one" "$file"
cp "$s/actions" "$fixture/noop-log"
printf 'test-peer\t1735500000\n' >"$s/handshakes"
run "$fixture/one" ok '' '-' 'unchanged 1'
: >"$s/handshakes"
cmp "$s/actions" "$fixture/noop-log"
touch "$s/failed-dump"; run "$fixture/one" 'error ownership'; rm "$s/failed-dump"
cmp "$s/actions" "$fixture/noop-log"
# The disk can still contain our config while an administrator edited the
# running interface directly. Even an otherwise idempotent apply must refuse.
cp "$fixture/one" "$fixture/foreign-peer"
cat >>"$fixture/foreign-peer" <<'EOF'

[Peer]
PublicKey = BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY=
AllowedIPs = 10.111.0.23/32
EOF
sed 's/^AllowedIPs = .*/AllowedIPs = 10.111.0.23\/32/' "$fixture/one" >"$fixture/foreign-ips"
sed 's/^PresharedKey = .*/PresharedKey = BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=/' "$fixture/one" >"$fixture/foreign-psk"
for foreign in foreign-peer foreign-ips foreign-psk; do
    cp "$fixture/$foreign" "$s/loaded"
    run "$fixture/one" 'error ownership'
    run "$fixture/two" 'error ownership'
    cmp "$s/actions" "$fixture/noop-log"; cmp "$s/loaded" "$fixture/$foreign"; cmp "$file" "$fixture/one"
done
# Learned endpoints and list ordering don't change the peer identity.
sed 's|10.111.0.2/32, fd42::2/128|fd42:0::2/128, 10.111.0.2/32|' "$fixture/one" >"$s/loaded"
echo 'Endpoint = 192.0.2.7:45701' >>"$s/loaded"
run "$fixture/one" ok; cmp "$s/actions" "$fixture/noop-log"
# Rotating a peer key (with the same host routes) uses live reconciliation.
sed '/^PublicKey = /s/= .*/= BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=/' "$fixture/one" >"$fixture/rotated"
wrong=$(sha256sum <"$fixture/two"); wrong=${wrong%% *}
run "$fixture/rotated" 'error conflict' '' "$wrong"
cmp "$s/actions" "$fixture/noop-log"; cmp "$fixture/one" "$file"
run "$fixture/rotated" ok '' "$prior"
run "$fixture/rotated" ok '' "$prior"
cp "$fixture/noop-log" "$fixture/synced-log"; echo sync >>"$fixture/synced-log"
cmp "$s/actions" "$fixture/synced-log"; cmp "$s/loaded" "$fixture/rotated"
touch "$s/fail-sync"
run "$fixture/one" 'error apply'
cmp "$fixture/rotated" "$file"; cmp "$fixture/rotated" "$s/loaded"
printf 'sync\nsync\n' >>"$fixture/synced-log"; cmp "$s/actions" "$fixture/synced-log"
run "$fixture/one" ok
# wg syncconf cannot replace the old host route; changing AllowedIPs must
# restart the unit even when the server's key and UDP port stay the same.
sed 's/fd42::2\/128/fd42::3\/128/' "$fixture/one" >"$fixture/reroute"
run "$fixture/reroute" ok
printf 'sync\nstop\nstart\n' >>"$fixture/synced-log"; cmp "$s/actions" "$fixture/synced-log"
run "$fixture/one" ok
# The profile key, listen port, enabled state and backup are checked again
# after start. A mismatched running interface is never replaced.
echo foreign >"$s/live"; run "$fixture/two" 'error ownership'; echo "$PUBLIC" >"$s/live"
touch "$s/wrong-port"; run "$fixture/two" 'error apply' '' '-' 'verify restored'
cmp "$fixture/one" "$file"; test "$(cat "$s/listen")" = 51820; test "$(cat "$s/enabled")" = enabled
touch "$s/fail-51821" "$s/fail-51820"
run "$fixture/two" 'error rollback_failed' '' '-' 'activate journal'
cmp "$fixture/one" "$backup/prior.conf"
run "$fixture/two" 'error rollback_pending' '' '-' 'preflight journal'
test -s "$backup/state"
rm "$s/fail-51821" "$s/fail-51820"
cp "$s/actions" "$fixture/pending-actions"
run "$fixture/one" 'error rollback_pending' '' "$wrong"
cmp "$s/actions" "$fixture/pending-actions"; test -s "$backup/state"
run "$fixture/two" ok '' "$prior"
cmp "$fixture/two" "$file"; test "$(cat "$s/listen")" = 51821; test ! -e "$backup"
# Also restore an owned but intentionally inactive, enabled service.
echo inactive >"$s/active"; rm "$s/live"; touch "$s/fail-51820"
run "$fixture/one" 'error conflict' '' "$wrong"
run "$fixture/one" 'error apply'
cmp "$fixture/two" "$file"
test "$(cat "$s/active")" = inactive && test "$(cat "$s/enabled")" = enabled && test ! -e "$s/live"
rm "$s/fail-51820"; run "$fixture/one" ok
# A reported-successful netlink update is not confirmation. If an outside
# peer appears during apply, neither verification nor rollback may remove it.
cp "$fixture/foreign-peer" "$s/external-sync"
run "$fixture/rotated" 'error rollback_failed' '' "$prior"
cmp "$s/loaded" "$fixture/foreign-peer"; test -s "$backup/state"
cp "$s/actions" "$fixture/interference-log"
run "$fixture/rotated" 'error rollback_pending' '' "$prior"
cmp "$s/actions" "$fixture/interference-log"; cmp "$s/loaded" "$fixture/foreign-peer"
cp "$fixture/rotated" "$s/loaded"; run "$fixture/rotated" ok '' "$prior"
cmp "$s/loaded" "$fixture/rotated"; test ! -e "$backup"
echo 'WireGuard deployment ownership, conflicts, health checks, retry and rollback passed'

# Exercise the same transaction on an AmneziaWG host that already has its
# official tools and helper, while the new per-interface unit is still free.
awk '
    {gsub("/etc/amnezia/amneziawg", ENVIRON["N2S_WG_FIXTURE"] "/root/etc/amnezia/amneziawg");
     gsub("/etc/systemd/system", ENVIRON["N2S_WG_FIXTURE"] "/root/etc/systemd/system");
     gsub("/usr/local/libexec/nfqws-awg-quick-userspace", ENVIRON["N2S_WG_FIXTURE"] "/root/helper");
     gsub("/usr/bin/amneziawg-go", ENVIRON["N2S_WG_FIXTURE"] "/root/engine"); print}
' "$fixture/apply.sh" >"$fixture/awg.sh"
dir=$fixture/root/etc/amnezia/amneziawg
unitdir=$fixture/root/etc/systemd/system/awg-quick@awg7.service.d
file=$dir/awg7.conf
mkdir -p "$dir" "$fixture/root/etc/systemd/system"
printf '#!/bin/sh\nexit 0\n' >"$fixture/root/engine"
printf '#!/bin/sh\nexit 0\n' >"$fixture/root/helper"
chmod 755 "$fixture/root/engine" "$fixture/root/helper"
sed -e 's/wg-quick@wg7/awg-quick@awg7/g' -e 's/wg7\.conf/awg7.conf/g' \
    -e 's|root/etc/wireguard|root/etc/amnezia/amneziawg|' \
    -e '/^case "\$\*" in/a\
 daemon-reload) f="$N2S_WG_FIXTURE/root/etc/systemd/system/awg-quick@awg7.service.d/10-nfqws-userspace.conf"; if [ -f "$f" ]; then echo "$f" > "$s/dropins"; else : > "$s/dropins"; fi;;' \
    "$fixture/bin/systemctl" >"$fixture/services"; cp "$fixture/services" "$fixture/bin/systemctl"
sed -e 's/dev wg7/dev awg7/' -e '/^case "\$\*" in/a\
 "link show dev eth0") exit 0;;' "$fixture/bin/ip" >"$fixture/ip"; cp "$fixture/ip" "$fixture/bin/ip"
sed 's/wg7/awg7/g' "$fixture/bin/wg" >"$fixture/bin/awg"
cp "$fixture/bin/wg-quick" "$fixture/bin/awg-quick"
sed '/^case "\$1:\$2" in/a\
 -c:%d:%i) command -p stat "$@";;' "$fixture/bin/stat" >"$fixture/stat"; cp "$fixture/stat" "$fixture/bin/stat"
printf '#!/bin/sh\necho "backend rule diagnostic"\ntest -e "$N2S_WG_FIXTURE/svc/live"\n' >"$fixture/bin/iptables"
printf '#!/bin/sh\nexit 0\n' >"$fixture/bin/ss"
printf '#!/bin/sh\necho 1\n' >"$fixture/bin/sysctl"
chmod +x "$fixture/bin/"*
echo /usr/lib/systemd/system/awg-quick@.service >"$s/fragment"
: >"$s/dropins"; echo inactive >"$s/active"; echo disabled >"$s/enabled"
rm -f "$s/live"; : >"$s/actions"
cat >"$fixture/awg-one" <<EOF
[Interface]
PrivateKey = $PRIVATE
Address = 10.111.0.1/24
ListenPort = 51820
MTU = 1420
Jc = 4
Jmin = 8
Jmax = 80
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4
PostUp = sysctl -w net.ipv4.ip_forward=1; iptables -t nat -C POSTROUTING -s 10.111.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.111.0.0/24 -o eth0 -j MASQUERADE; iptables -C FORWARD -i %i -j ACCEPT 2>/dev/null || iptables -A FORWARD -i %i -j ACCEPT; iptables -C FORWARD -o %i -j ACCEPT 2>/dev/null || iptables -A FORWARD -o %i -j ACCEPT
PostDown = while iptables -t nat -D POSTROUTING -s 10.111.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null; do :; done; while iptables -D FORWARD -i %i -j ACCEPT 2>/dev/null; do :; done; while iptables -D FORWARD -o %i -j ACCEPT 2>/dev/null; do :; done

[Peer]
PublicKey = AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=
AllowedIPs = 10.111.0.2/32
EOF
awg_run() {
    sum=$(sha256sum <"$1")
    actual=$(sh "$fixture/awg.sh" awg7 "$PUBLIC" "${sum%% *}" "${3:--}" "${6:-awg}" "${4:-deploy}" <"$1")
    check_report "$2" "${5:-}"
}
touch "$s/fail-enable"
awg_run "$fixture/awg-one" 'error apply' '-' deploy 'activate removed_new'
test ! -e "$file" && test ! -d "$unitdir" && test ! -e "$dir/.n2s-awg7.rollback"
awg_run "$fixture/awg-one" ok '-' deploy 'verify 0'
test -f "$unitdir/10-nfqws-userspace.conf" && cmp "$fixture/awg-one" "$file"
cp "$fixture/awg-one" "$fixture/awg-two"
cat >>"$fixture/awg-two" <<'EOF'

[Peer]
PublicKey = BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=
AllowedIPs = 10.111.0.3/32
EOF
sum=$(sha256sum <"$fixture/awg-one"); old=${sum%% *}
: > "$s/actions"
awg_run "$fixture/awg-two" ok "$old" sync
test "$(cat "$s/actions")" = sync && cmp "$fixture/awg-two" "$file"
sed 's/PostUp = /PostUp = false; /' "$fixture/awg-two" > "$fixture/awg-unsafe"
awg_run "$fixture/awg-unsafe" 'error invalid' "$old" sync
printf '\n# foreign edit\n' >>"$file"
awg_run "$fixture/awg-two" 'error ownership' "$old" sync
echo 'AmneziaWG provisioning, Go peer sync, foreign configuration and rollback passed'

# Stock kernel mode owns the same server configuration and checks forwarding,
# but uses the vendor unit without an override or the userspace executable.
rm -f "$file" "$unitdir/10-nfqws-userspace.conf" "$fixture/root/engine" "$fixture/root/helper"
rmdir "$unitdir"
systemctl daemon-reload
systemctl stop awg-quick@awg7.service
systemctl disable awg-quick@awg7.service
: > "$s/actions"
cat >"$fixture/bin/modinfo" <<'EOF'
#!/bin/sh
test "$*" = amneziawg && test -e "$N2S_WG_FIXTURE/svc/module-listed"
EOF
chmod +x "$fixture/bin/modinfo"
touch "$s/module-listed"

# A missing kernel module must stop before changing the unit or profile.
rm "$s/module-listed"
awg_run "$fixture/awg-one" 'error prerequisite' '-' deploy 'preflight -' awg-kernel
test ! -s "$s/actions"
test ! -e "$file"
touch "$s/module-listed" "$s/fail-enable"
touch "$s/observe-backend"
awg_run "$fixture/awg-one" 'error apply' '-' deploy 'activate removed_new' awg-kernel
test ! -e "$file"
test ! -d "$unitdir"
test ! -e "$dir/.n2s-awg7.rollback"
test "$(cat "$s/active")/$(cat "$s/enabled")" = inactive/disabled

awg_run "$fixture/awg-one" ok '-' deploy 'verify 0' awg-kernel
cmp "$fixture/awg-one" "$file"
test ! -d "$unitdir"
test -z "$(cat "$s/dropins")"
: > "$s/actions"
awg_run "$fixture/awg-one" ok '-' deploy 'unchanged 0' awg-kernel
test ! -s "$s/actions"
touch "$s/incorrect-kind"
awg_run "$fixture/awg-one" 'error ownership' '-' deploy 'preflight -' awg-kernel
test ! -s "$s/actions"
rm "$s/incorrect-kind"

# An expected original digest permits updating an active stock config. If the
# replacement fails to start, verify both the restored file and running port.
sed 's/51820/51821/' "$fixture/awg-one" >"$fixture/awg-new-port"
touch "$s/fail-51821"
awg_run "$fixture/awg-new-port" 'error apply' "$old" deploy 'activate restored' awg-kernel
cmp "$fixture/awg-one" "$file"
test "$(cat "$s/active")/$(cat "$s/enabled")/$(cat "$s/listen")" = active/enabled/51820
test ! -d "$unitdir"
test ! -e "$dir/.n2s-awg7.rollback"
rm "$s/fail-51821"

# A Go deployment can sync peers against the existing stock unit, using a
# previous digest and the live server key as before. The running stock link is
# enough even when module metadata is temporarily unavailable after an upgrade.
: > "$s/actions"
rm "$s/module-listed"
awg_run "$fixture/awg-two" ok "$old" sync 'verify 0' awg-auto
touch "$s/module-listed"
test "$(cat "$s/actions")" = sync
cmp "$fixture/awg-two" "$file"
new_sum=$(sha256sum <"$fixture/awg-two"); new_sum=${new_sum%% *}
: > "$s/actions"
mkdir "$unitdir"
printf '[Service]\nEnvironment=SITE_TEST=1\n' > "$unitdir/20-admin.conf"
printf '%s\n' "$unitdir/20-admin.conf" > "$s/dropins"
awg_run "$fixture/awg-one" 'error ownership' "$new_sum" deploy '' awg-kernel
awg_run "$fixture/awg-one" 'error ownership' "$new_sum" sync '' awg-auto
test ! -s "$s/actions"
cmp "$fixture/awg-two" "$file"
grep -Fxq 'Environment=SITE_TEST=1' "$unitdir/20-admin.conf"
echo 'Stock AmneziaWG kernel deployment, Go peer sync, ownership and rollback passed'

rm "$unitdir/20-admin.conf"
rmdir "$unitdir"
systemctl daemon-reload
printf '#!/bin/sh\nexit 0\n' > "$fixture/root/engine"
cp "$fixture/root/engine" "$fixture/root/helper"
chmod 755 "$fixture/root/engine" "$fixture/root/helper"
sed -e 's/51820/51821/' -e '/^H4 = /a\
DisableCookies = on' "$fixture/awg-two" > "$fixture/awg-31"
awg_run "$fixture/awg-31" 'error invalid' "$new_sum" deploy 'preflight -' awg-kernel
test ! -s "$s/actions"
cmp "$fixture/awg-two" "$file"

# Stop the stock unit before installing the userspace ExecStop. Rollback must
# remove the replacement drop-in before starting the prior kernel config.
: > "$s/backend-actions"
touch "$s/fail-51821"
awg_run "$fixture/awg-31" 'error apply' "$new_sum" deploy 'activate restored'
cat > "$fixture/expected-backends" <<'EOF'
stop kernel
start userspace 51821
start kernel 51820
EOF
cmp "$fixture/expected-backends" "$s/backend-actions"
cmp "$fixture/awg-two" "$file"
test ! -d "$unitdir"
test "$(cat "$s/active")/$(cat "$s/enabled")/$(cat "$s/listen")" = active/enabled/51820
test ! -e "$dir/.n2s-awg7.rollback"

rm "$s/fail-51821"
: > "$s/backend-actions"
awg_run "$fixture/awg-31" ok "$new_sum" deploy 'verify 0'
cmp "$fixture/awg-31" "$file"
test -f "$unitdir/10-nfqws-userspace.conf"
test "$(cat "$s/loaded-backend")/$(cat "$s/listen")" = userspace/51821
echo 'AmneziaWG 3.1 userspace upgrade preserves the stock service on failure and switches on success'
