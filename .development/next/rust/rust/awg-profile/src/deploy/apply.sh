# Fixed SSH command. stdin is a bounded, checksummed WireGuard configuration.
# An interrupted update leaves the previous file and unit state in a private
# transaction directory. A retry with the same public key first restores them.
set -u
umask 077
# Only report() writes to the SSH response. Some iptables backends also
# print rule descriptions to stdout when checking a rule.
exec 3>&1 1>/dev/null 2>/dev/null
export LC_ALL=C
phase=preflight
report() { printf '%s %s %s\n' "$1" "$phase" "${2:--}" >&3; exit 0; }
systemctl() { command systemctl "$@" 3>&- 9>&-; }
[ "$#" -ge 3 ] && [ "$#" -le 6 ] || report 'error invalid'
iface=$1
pub=$2
digest=$3
previous=${4:--}
tool=${5:-wg}
operation=${6:-}
if [ -z "$operation" ]; then
    if [ "$previous" = - ]; then operation=deploy; else operation=sync; fi
fi
case "$operation" in deploy|sync) ;; *) report 'error invalid';; esac
dir=/etc/wireguard
backend=
case "$tool" in
    wg) quick=wg-quick ;;
    awg) backend=userspace ;;
    awg-kernel) backend=kernel ;;
    awg-auto) [ "$operation" = sync ] || report 'error invalid'; backend=auto ;;
    *) report 'error invalid' ;;
esac
if [ -n "$backend" ]; then
    tool=awg
    quick=awg-quick
    dir=/etc/amnezia/amneziawg
fi
requested_backend=$backend
case "$iface" in wg*) suffix=${iface#wg};; awg*) suffix=${iface#awg};; *) report 'error invalid';; esac
case "$suffix" in ''|*[!0-9]*) report 'error invalid';; esac
[ "${#iface}" -le 15 ] && [ "${#digest}" = 64 ] && [ "${#pub}" = 44 ] || report 'error invalid'
case "$digest" in *[!0-9a-f]*) report 'error invalid';; esac
if [ "$previous" != - ]; then
    [ "${#previous}" = 64 ] || report 'error invalid'
    case "$previous" in *[!0-9a-f]*) report 'error invalid';; esac
fi
case "$pub" in *[!A-Za-z0-9+/=]*) report 'error invalid';; esac
[ "$(id -u)" = 0 ] || report 'error prerequisite'
for cmd in systemctl ip "$tool" "$quick" sha256sum python3 flock mktemp stat head; do
    command -v "$cmd" >/dev/null || report 'error prerequisite'
done

[ ! -L "$dir" ] || report 'error ownership'
[ "$previous" = - ] || [ -d "$dir" ] || report 'error conflict'
[ -d "$dir" ] || mkdir -m 700 "$dir" || report 'error prerequisite'
[ "$(stat -c %u "$dir")" = 0 ] || report 'error ownership'
case "$(stat -c %a "$dir")" in 700|710|711|750|751|755) ;; *) report 'error ownership';; esac
unit=$quick@$iface.service
config=$dir/$iface.conf
journal=$dir/.n2s-$iface.rollback
lock=$dir/.n2s-deploy.lock
[ ! -L "$lock" ] && { [ ! -e "$lock" ] || [ -f "$lock" ]; } || report 'error ownership'
exec 9>>"$lock" || report 'error prerequisite'
flock -w 8 9 || report 'error busy'
case "$(systemctl show -p FragmentPath --value "$unit")" in
    /lib/systemd/system/"$quick"@.service|/usr/lib/systemd/system/"$quick"@.service) ;;
    *) report 'error ownership';;
esac
dropins=$(systemctl show -p DropInPaths --value "$unit") || report 'error prerequisite'
need_override=0
if [ "$tool" = awg ]; then
    unitdir=/etc/systemd/system/$unit.d
    override=$unitdir/10-nfqws-userspace.conf
    helper=/usr/local/libexec/nfqws-awg-quick-userspace
    [ ! -L "$unitdir" ] || report 'error ownership'
    expected=$(printf '%s\n' '[Service]' 'ExecStart=' "ExecStart=$helper up %i" 'ExecStop=' "ExecStop=$helper down %i")
    existing_backend=kernel
    if [ -e "$override" ] || [ -L "$override" ]; then
        [ -f "$override" ] && [ ! -L "$override" ] && [ "$(stat -c %u "$override")" = 0 ] &&
            [ "$(cat "$override")" = "$expected" ] || report 'error ownership'
        [ "$dropins" = "$override" ] || { [ -z "$dropins" ] && [ -f "$journal/override-inode" ]; } ||
            report 'error ownership'
        existing_backend=userspace
    else
        [ -z "$dropins" ] || report 'error ownership'
    fi
    if [ "$backend" = userspace ] || [ "$existing_backend" = userspace ]; then
        [ -x "$helper" ] && [ ! -L "$helper" ] && [ "$(stat -c %u "$helper")" = 0 ] &&
            [ -x /usr/bin/amneziawg-go ] || report 'error prerequisite'
    fi
    command -v iptables >/dev/null && command -v ss >/dev/null || report 'error prerequisite'
else
    [ -z "$dropins" ] || report 'error ownership'
fi

stage=$(mktemp -d "$dir/.n2s-stage-$iface.XXXXXX") || report 'error prerequisite'
clean() { [ ! -d "$stage" ] || rm -rf -- "$stage"; }
trap clean EXIT
hash() { sum=$(sha256sum < "$1") || return 1; printf '%s\n' "${sum%% *}"; }
flush() {
    python3 -I -c 'import os,sys
for path in sys.argv[1:]:
    fd=os.open(path, os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)' "$@"
}
secure_file() {
    [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c %u "$1")" = 0 ] || return 1
    case "$(stat -c %a "$1")" in 400|600) ;; *) return 1;; esac
}
install_override() {
    [ "$need_override" = 1 ] || return 0
    if [ ! -d "$unitdir" ]; then
        mkdir -m 755 "$unitdir" || return 1
        stat -c '%d:%i' "$unitdir" >"$journal/override-dir" || return 1
    fi
    [ "$(stat -c %u "$unitdir")" = 0 ] && [ -z "$(ls -A "$unitdir")" ] || return 1
    tmp_override=$(mktemp "$unitdir/.n2s-override.XXXXXX") || return 1
    printf '%s\n' "$expected" >"$tmp_override" &&
        stat -c '%d:%i' "$tmp_override" >"$journal/override-inode" &&
        flush "$journal/override-inode" "$journal" "$tmp_override" &&
        ln -T "$tmp_override" "$override"
    rc=$?; rm -f -- "$tmp_override"; [ "$rc" = 0 ] || return 1
    systemctl daemon-reload && [ "$(systemctl show -p DropInPaths --value "$unit")" = "$override" ]
}
remove_override() {
    [ "$tool" = awg ] || return 0
    if [ -f "$journal/override-inode" ] && [ -e "$override" ]; then
        secure_file "$journal/override-inode" && [ ! -L "$override" ] &&
            [ "$(stat -c '%d:%i' "$override")" = "$(cat "$journal/override-inode")" ] &&
            [ "$(cat "$override")" = "$expected" ] && rm -- "$override" && systemctl daemon-reload || return 1
    fi
    if [ -f "$journal/override-dir" ] && [ -d "$unitdir" ]; then
        secure_file "$journal/override-dir" &&
            [ "$(stat -c '%d:%i' "$unitdir")" = "$(cat "$journal/override-dir")" ] || return 1
        if [ -z "$(ls -A "$unitdir")" ]; then rmdir "$unitdir" || return 1; fi
    fi
}
current_hash() {
    if [ ! -e "$config" ] && [ ! -L "$config" ]; then printf 'absent\n'
    elif secure_file "$config"; then hash "$config"
    else return 1; fi
}
enabled() {
    state=$(systemctl is-enabled "$unit")
    case "$state" in enabled|disabled) printf '%s\n' "$state";; *) return 1;; esac
}
active() { systemctl show -p ActiveState --value "$unit"; }
live_at() {
    [ "$(active)" = active ] && [ "$("$tool" show "$iface" public-key)" = "$pub" ] &&
        [ "$("$tool" show "$iface" listen-port)" = "$1" ]
}
finish() {
    # Only a boolean crosses SSH. A failed stats query leaves the confirmed
    # deployment intact and cannot be mistaken for evidence of a handshake.
    [ "$operation" = deploy ] || report ok 0
    handshakes=$("$tool" show "$iface" latest-handshakes 3>&- 9>&-) || report ok 0
    if printf '%s\n' "$handshakes" | awk 'NF == 2 && $2 ~ /^[0-9]+$/ && $2 > 0 { seen=1 } END { exit !seen }'; then
        report ok 1
    fi
    report ok 0
}
kernel_link() {
    link=$(ip -j -d link show dev "$iface") || return 1
    printf '%s\n' "$link" | python3 -I -c 'import json,sys
try:
    links = json.load(sys.stdin)
    ok = len(links) == 1 and links[0]["linkinfo"]["info_kind"] == "amneziawg"
except (KeyError, TypeError, ValueError):
    ok = False
sys.exit(not ok)'
}
awg_forwarding() {
    [ "$tool" = awg ] || return 0
    if [ "$backend" = kernel ]; then kernel_link || return 1; fi
    nat=$(sed -n 's/^PostUp = .*POSTROUTING -s \([0-9./]*\) -o \([a-zA-Z0-9._-]*\) -j MASQUERADE;.*/\1 \2/p' "$1")
    case "$nat" in *' '*) ;; *) return 1;; esac
    [ "$(sysctl -n net.ipv4.ip_forward)" = 1 ] &&
        iptables -t nat -C POSTROUTING -s "${nat% *}" -o "${nat#* }" -j MASQUERADE &&
        iptables -C FORWARD -i "$iface" -j ACCEPT && iptables -C FORWARD -o "$iface" -j ACCEPT
}
runtime_peers_match() {
    # showconf includes the server private key and preshared keys. Never emit
    # it over SSH. The private stage and umask protect the bounded snapshot.
    # Append a NUL only after a successful dump. This checks the producer's
    # exit status even on POSIX shells without pipefail.
    { "$tool" showconf "$iface" && printf '\000'; } | head -c 1048577 >"$stage/live.conf" || return 1
    python3 -I - "$stage/live.conf" "$@" <<'PY'
import ipaddress, sys
from pathlib import Path

def peers(path, snapshot=False):
    with Path(path).open('rb') as src:
        data = src.read(1048577)
    if len(data) > 1048576:
        raise ValueError()
    if snapshot:
        if not data.endswith(b'\0'):
            raise ValueError()
        data = data[:-1]
    sections = []
    for line in data.decode('ascii').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('['):
            if line != ('[Peer]' if sections else '[Interface]'):
                raise ValueError()
            sections.append({})
            continue
        name, sep, value = line.partition('=')
        name, value = name.strip(), value.strip()
        if not sections or not sep or name in sections[-1]:
            raise ValueError()
        sections[-1][name] = value
    if not sections or 'PrivateKey' not in sections[0]:
        raise ValueError()
    result = {}
    for section in sections[1:]:
        key = section['PublicKey']
        if key in result:
            raise ValueError()
        allowed = frozenset(ipaddress.ip_network(ip.strip()) for ip in
                section.get('AllowedIPs', '').split(',') if ip.strip())
        result[key] = (section.get('PresharedKey', ''), allowed)
    return result

try:
    actual = peers(sys.argv[1], snapshot=True)
    sys.exit(0 if any(actual == peers(path) for path in sys.argv[2:]) else 1)
except (OSError, UnicodeError, ValueError, KeyError):
    sys.exit(1)
PY
    verified=$?
    rm -f -- "$stage/live.conf" || return 1
    return "$verified"
}

# Validate via data parsing. No value from this file is ever evaluated as a
# command. wg-quick hooks, includes, DNS, Table and SaveConfig are excluded.
# Mounted networks and the SSH control connection are checked on the VPS.
validate() {
    file=$1
    mode=$2
    python3 -I - "$file" "$pub" "$mode" "$iface" "$stage" "$tool" "$backend" <<'PY'
import base64, hashlib, ipaddress as ip, json, os, re, sys
from pathlib import Path
file, server_key, mode, iface, stage, tool, backend = sys.argv[1:]
def key(value):
    raw = base64.b64decode(value, validate=True)
    if len(raw) != 32 or not any(raw) or base64.b64encode(raw).decode() != value:
        raise ValueError()
def parse():
    path = Path(file)
    if path.stat().st_size > 262144:
        raise ValueError()
    text = path.read_bytes().decode('ascii')
    if any(ord(c) < 32 and c not in '\n\t' for c in text):
        raise ValueError()
    lines = text.split('\n')
    if tool == 'wg':
        if lines.pop(0) != '# Managed by nfqws2-strategy (WireGuard)':
            raise ValueError()
    elif lines[0] != '[Interface]':
        raise ValueError()
    sections = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line == ('[Peer]' if sections else '[Interface]'):
            sections.append({})
            continue
        name, sep, value = line.partition('=')
        name, value = name.strip(), value.strip()
        fields = ('PublicKey','PresharedKey','AllowedIPs') if len(sections) > 1 else ('PrivateKey','Address','MTU','ListenPort')
        if tool == 'awg' and len(sections) == 1:
            fields += tuple('Jc Jmin Jmax S1 S2 S3 S4 H1 H2 H3 H4 I1 I2 I3 I4 I5 HeaderProtectionKey ContentPaddingAddition RekeyAfterTime RekeyTimeout RejectAfterTime KeepaliveTimeout MaxHandshakeAttempts RandomTrailers DisableCookies PostUp PostDown'.split())
        if not sep or not sections or name not in fields or name in sections[-1] or not value:
            raise ValueError()
        sections[-1][name] = value
    server, *peers = sections
    if backend == 'kernel' and mode == 'network' and server.keys() & set('HeaderProtectionKey ContentPaddingAddition RekeyAfterTime RekeyTimeout RejectAfterTime KeepaliveTimeout MaxHandshakeAttempts RandomTrailers DisableCookies'.split()):
        raise ValueError()
    key(server_key)
    key(server['PrivateKey'])
    port = int(server['ListenPort'])
    mtu = int(server.get('MTU', '1420'))
    if not 1 <= port <= 65535 or not 576 <= mtu <= 9000:
        raise ValueError()
    networks, hosts, keys, peer_routes = set(), set(), {server_key}, set()
    def addr(value, host_only):
        if '/' not in value or '%' in value:
            raise ValueError()
        addr = ip.ip_interface(value.strip())
        if (addr.ip in hosts or addr.ip.is_unspecified or addr.ip.is_loopback or
                addr.ip.is_multicast or addr.ip.is_link_local or addr.network.prefixlen == 0 or
                (host_only and addr.network.prefixlen != addr.max_prefixlen)):
            raise ValueError()
        hosts.add(addr.ip)
        networks.add(addr.network)
        if host_only:
            peer_routes.add(str(addr.network))
    for value in server['Address'].split(','):
        addr(value, False)
    local_nets = networks.copy()
    if tool == 'awg':
        up = server['PostUp']
        match = re.search(r' -s ([0-9.]+/[0-9]{1,2}) -o ([a-zA-Z0-9][a-zA-Z0-9._-]{0,14}) -j MASQUERADE ', up)
        if not match: raise ValueError()
        subnet, wan = match.groups()
        network = ip.IPv4Network(subnet,strict=False)
        if network.prefixlen == 0: raise ValueError()
        networks.add(network)
        nat = f'POSTROUTING -s {subnet} -o {wan} -j MASQUERADE'
        chains = [('-t nat ',nat),('','FORWARD -i %i -j ACCEPT'),('','FORWARD -o %i -j ACCEPT')]
        expected_up = 'sysctl -w net.ipv4.ip_forward=1; ' + '; '.join(f'iptables {t}-C {r} 2>/dev/null || iptables {t}-A {r}' for t,r in chains)
        expected_down = '; '.join(f'while iptables {t}-D {r} 2>/dev/null; do :; done' for t,r in chains)
        if up != expected_up or server['PostDown'] != expected_down: raise ValueError()
    for peer in peers:
        key(peer['PublicKey'])
        if peer['PublicKey'] in keys:
            raise ValueError()
        keys.add(peer['PublicKey'])
        if 'PresharedKey' in peer:
            key(peer['PresharedKey'])
        for value in peer['AllowedIPs'].split(','):
            addr(value, True)
    # If this signature stays the same, wg syncconf can change the peers while
    # every kernel address, MTU, listener and wg-quick host route stays valid.
    if tool == 'awg':
        peer_routes = {r for r in peer_routes if not any(ip.ip_network(r).version==n.version and ip.ip_network(r).subnet_of(n) for n in local_nets)}
    shape = json.dumps([server, sorted(peer_routes)], sort_keys=True).encode()
    return port, networks, hashlib.sha256(shape).hexdigest()
try:
    port, networks, shape = parse()
except (ValueError, KeyError, OSError):
    sys.exit(8)
if mode == 'network':
    # Collapse a server subnet and its client host routes before comparing
    # against the usually much larger kernel route dump.
    by_family = {v:list(ip.collapse_addresses(n for n in networks if n.version == v)) for v in (4,6)}
    def overlaps(n):
        return any(p.overlaps(n) for p in by_family[n.version])
    try:
        ssh = os.environ['SSH_CONNECTION'].split()
        if len(ssh) != 4:
            raise ValueError()
        for addr in (ssh[0],ssh[2]):
            if overlaps(ip.ip_network(addr.split('%')[0])):
                sys.exit(9)
        for entry in json.loads((Path(stage)/'addr').read_bytes()):
            if entry['ifname'] != iface:
                for addr in entry['addr_info']:
                    if addr['family'] in ('inet','inet6') and overlaps(ip.ip_network(
                            addr['local']+'/'+str(addr['prefixlen']), strict=False)):
                        sys.exit(9)
        for family in ('4','6'):
            for route in json.loads((Path(stage)/family).read_bytes()):
                dst = route.get('dst', 'default')
                if dst not in ('default','0.0.0.0/0','::/0') and route.get('dev') != iface and overlaps(ip.ip_network(dst, strict=False)):
                    sys.exit(9)
    except (ValueError, KeyError, TypeError, OSError):
        sys.exit(10)
print(port, shape)
PY
}
owns_key() {
    [ "$(sed -n 's/^[[:space:]]*PrivateKey[[:space:]]*=[[:space:]]*//p' "$1" | sed 's/[[:space:]]*$//' | "$tool" pubkey)" = "$pub" ]
}
sync_peers() {
    "$quick" strip "$1" >"$stage/sync.conf" && "$tool" syncconf "$iface" "$stage/sync.conf" >/dev/null
}

# Restore only known files and a known interface. Keep the backup if an
# administrator changed anything in the meantime or systemd cannot restore.
rollback() {
    [ -d "$journal" ] && [ ! -L "$journal" ] && [ "$(stat -c %u:%a "$journal")" = 0:700 ] &&
        secure_file "$journal/state" || return 1
    IFS=' ' read -r owner old new was_active was_enabled old_port method < "$journal/state" || return 1
    [ "$owner" = "$pub" ] || return 1
    if [ "$previous" != - ]; then
        [ "$old" = "$previous" ] && [ "$new" = "$digest" ] || return 1
    fi
    case "$was_active/$was_enabled" in active/enabled|active/disabled|inactive/enabled|inactive/disabled) ;; *) return 1;; esac
    if [ "$old" != absent ]; then
        secure_file "$journal/prior.conf" && [ "$(hash "$journal/prior.conf")" = "$old" ] &&
            validate "$journal/prior.conf" stored >/dev/null && owns_key "$journal/prior.conf" || return 1
    fi
    now=$(current_hash) || return 1
    [ "$now" = "$old" ] || [ "$now" = "$new" ] || return 1
    st=$(active) || return 1
    if ip link show dev "$iface" >/dev/null; then
        [ "$("$tool" show "$iface" public-key)" = "$pub" ] || return 1
        # A subsequent administrator's live edits must survive rollback.
        # The previous or submitted snapshot is a possible owned state.
        candidate=$journal/next.conf
        if [ ! -f "$candidate" ] && [ "$now" = "$new" ]; then candidate=$config; fi
        if secure_file "$candidate" && [ "$(hash "$candidate")" = "$new" ]; then
            if [ "$old" = absent ]; then runtime_peers_match "$candidate" || return 1
            else runtime_peers_match "$journal/prior.conf" "$candidate" || return 1; fi
        elif [ "$old" != absent ]; then runtime_peers_match "$journal/prior.conf" || return 1
        else return 1; fi
    fi
    if [ "$tool" = awg ] && [ -f "$journal/override-inode" ]; then
        # A new userspace drop-in can replace an active stock unit. Stop the
        # owned replacement and remove its drop-in before starting the old unit.
        if [ "$st" = active ] && [ -e "$override" ]; then
            systemctl stop "$unit" >/dev/null || return 1
            st=$(active) || return 1
        fi
        [ "$st" != active ] || [ ! -e "$override" ] || return 1
        remove_override || return 1
    fi
    if [ "$method" = sync ] && [ "$was_active" = active ] && live_at "$old_port"; then
        # Reconcile the runtime even if a previous rollback restored the disk
        # file just before the SSH connection or process was interrupted.
        if sync_peers "$journal/prior.conf" && runtime_peers_match "$journal/prior.conf"; then
            if [ "$now" != "$old" ]; then
                cp -p -- "$journal/prior.conf" "$stage/restore.conf" && mv -fT -- "$stage/restore.conf" "$config" || return 1
            fi
            now=$old
        else
            # Only rebuild a known snapshot. A failed netlink update or a
            # concurrent administrator may have changed the running peer set.
            runtime_peers_match "$journal/prior.conf" "$candidate" || return 1
            now=restart
        fi
    fi
    if [ "$now" != "$old" ] || [ "$was_active" != active ] || ! live_at "$old_port"; then
        case "$st" in inactive|failed) ;; active) systemctl stop "$unit" >/dev/null || return 1;; *) return 1;; esac
        if ip link show dev "$iface" >/dev/null; then return 1; fi
        if [ "$old" = absent ]; then
            rm -f -- "$config" || return 1
        else
            cp -p -- "$journal/prior.conf" "$stage/restore.conf" && mv -fT -- "$stage/restore.conf" "$config" || return 1
        fi
        if [ "$was_active" = active ]; then
            systemctl start "$unit" >/dev/null && live_at "$old_port" || return 1
        elif [ "$st" = failed ]; then systemctl reset-failed "$unit" >/dev/null || return 1; fi
    fi
    en=$(enabled) || return 1
    if [ "$en" != "$was_enabled" ]; then
        if [ "$was_enabled" = enabled ]; then systemctl enable "$unit" >/dev/null || return 1
        else systemctl disable "$unit" >/dev/null || return 1; fi
    fi
    [ "$(active)" = "$was_active" ] && [ "$(enabled)" = "$was_enabled" ] && [ "$(current_hash)" = "$old" ] || return 1
    if [ "$was_active" = active ]; then live_at "$old_port" && runtime_peers_match "$config" || return 1; fi
    if [ "$tool" = awg ] && [ -f "$journal/forward" ]; then
        secure_file "$journal/forward" || return 1
        prior_forward=$(cat "$journal/forward")
        case "$prior_forward" in 0|1) ;; *) return 1;; esac
        if [ "$(sysctl -n net.ipv4.ip_forward)" != "$prior_forward" ]; then
            sysctl -w "net.ipv4.ip_forward=$prior_forward" >/dev/null || return 1
        fi
    fi
    remove_override || return 1
    flush "$dir" || return 1
    mv -T -- "$journal" "$stage/rolled-back" || return 1
    rm -rf -- "$stage/rolled-back"
}
report_rollback_failure() {
    if [ -d "$journal" ] && [ ! -L "$journal" ] && secure_file "$journal/state" &&
        IFS=' ' read -r failed_owner details <"$journal/state" && [ "$failed_owner" = "$pub" ]; then
        report "$1" journal
    fi
    report "$1" failed
}
on_failure() {
    trap '' HUP INT TERM
    if rollback; then
        if [ "$old" = absent ]; then report 'error apply' removed_new; fi
        report 'error apply' restored
    fi
    report_rollback_failure 'error rollback_failed'
}
if [ -e "$journal" ] || [ -L "$journal" ]; then
    rollback || report_rollback_failure 'error rollback_pending'
fi
if [ "$tool" = awg ]; then
    dropins=$(systemctl show -p DropInPaths --value "$unit") || report 'error prerequisite'
    if [ -e "$override" ]; then
        [ "$dropins" = "$override" ] || report 'error ownership'
        existing_backend=userspace
    else
        [ ! -L "$override" ] && [ -z "$dropins" ] || report 'error ownership'
        existing_backend=kernel
    fi
    if [ "$requested_backend" = auto ]; then backend=$existing_backend; fi
    if [ "$backend" != "$existing_backend" ] && [ "$operation" = sync ]; then report 'error ownership'; fi
    if [ "$backend" = kernel ]; then
        [ "$existing_backend" = kernel ] || report 'error ownership'
        if [ "$operation" = deploy ]; then modinfo amneziawg >/dev/null || report 'error prerequisite'; fi
    elif [ "$existing_backend" = kernel ]; then
        need_override=1
    fi
fi

mkdir -m 700 "$stage/txn" || report 'error prerequisite'
next=$stage/txn/next.conf
head -c 262145 >"$next" || report 'error invalid'
[ "$(hash "$next")" = "$digest" ] || report 'error invalid'
for family in 4 6; do ip -j "-$family" route show table all >"$stage/$family" || report 'error prerequisite'; done
ip -j address show >"$stage/addr" || report 'error prerequisite'
new_info=$(validate "$next" network)
case $? in 0) ;; 9) report 'error conflict';; 10) report 'error prerequisite';; *) report 'error invalid';; esac
new_port=${new_info%% *}
owns_key "$next" || report 'error invalid'
old=$(current_hash) || report 'error ownership'
was_enabled=$(enabled) || report 'error ownership'
was_active=$(active) || report 'error prerequisite'
if [ "$tool" = awg ] && [ "$old" != absent ]; then
    [ "$old" = "$previous" ] || [ "$old" = "$digest" ] || report 'error ownership'
fi
if [ "$operation" = sync ]; then
    # Peer edits may retry a committed write, but must never recreate a
    # deleted profile, revive a stopped unit or overwrite an administrator edit.
    [ "$old" = "$previous" ] || [ "$old" = "$digest" ] || report 'error conflict'
    [ "$was_active/$was_enabled" = active/enabled ] || report 'error conflict'
fi
if [ "$tool" = awg ] && ! live_at "$new_port"; then
    sockets=$(ss -Hlun "sport = :$new_port") || report 'error prerequisite'
    [ -z "$sockets" ] || report 'error conflict'
fi
if [ "$tool" = awg ]; then
    wan=$(sed -n 's/^PostUp = .* -o \([a-zA-Z0-9._-]*\) -j MASQUERADE;.*$/\1/p' "$next")
    ip link show dev "$wan" >/dev/null || report 'error prerequisite'
    subnet=$(sed -n 's/^PostUp = .* -s \([0-9./]*\) -o [a-zA-Z0-9._-]* -j MASQUERADE;.*$/\1/p' "$next")
    if [ "$was_active" != active ]; then
        for direction in -i -o; do
            if iptables -C FORWARD "$direction" "$iface" -j ACCEPT; then report 'error conflict'; fi
        done
        if iptables -t nat -C POSTROUTING -s "$subnet" -o "$wan" -j MASQUERADE; then report 'error conflict'; fi
    fi
    sysctl -n net.ipv4.ip_forward >"$stage/txn/forward" || report 'error prerequisite'
    case "$(cat "$stage/txn/forward")" in 0|1) ;; *) report 'error prerequisite';; esac
fi
case "$was_active" in inactive|active) ;; *) report 'error ownership';; esac
old_port=0
method=restart
if [ "$old" = absent ]; then
    [ "$was_active/$was_enabled" = inactive/disabled ] || report 'error ownership'
else
    old_info=$(validate "$config" stored) && owns_key "$config" || report 'error ownership'
    old_port=${old_info%% *}
    if [ "$need_override" = 0 ] && [ "$was_active" = active ] && [ "$old" != "$digest" ] && [ "${old_info#* }" = "${new_info#* }" ]; then method=sync; fi
    cp -p -- "$config" "$stage/txn/prior.conf" || report 'error prerequisite'
    [ "$(hash "$stage/txn/prior.conf")" = "$old" ] || report 'error ownership'
fi
if [ "$was_active" = active ]; then
    live_at "$old_port" && runtime_peers_match "$config" || report 'error ownership'
    if [ "$backend" = kernel ]; then kernel_link || report 'error ownership'; fi
elif ip link show dev "$iface" >/dev/null; then report 'error ownership'; fi
if [ "$need_override" = 0 ] && [ "$old" = "$digest" ] && [ "$was_enabled" = enabled ] && live_at "$new_port"; then
    runtime_peers_match "$next" && awg_forwarding "$next" || report 'error ownership'
    phase=unchanged
    finish
fi
phase=backup
printf '%s %s %s %s %s %s %s\n' "$pub" "$old" "$digest" "$was_active" "$was_enabled" "$old_port" "$method" >"$stage/txn/state" || report 'error prerequisite'
flush "$stage/txn/"* "$stage/txn" || report 'error prerequisite'
[ "$(current_hash)" = "$old" ] || report 'error ownership'
if [ "$was_active" = active ]; then live_at "$old_port" && runtime_peers_match "$config" || report 'error ownership'; fi
mv -T -- "$stage/txn" "$journal" || report 'error prerequisite'
trap on_failure HUP INT TERM
flush "$dir" || on_failure
phase=write
if [ "$need_override" = 1 ] && [ "$was_active" = active ]; then
    live_at "$old_port" && runtime_peers_match "$journal/prior.conf" || on_failure
    systemctl stop "$unit" >/dev/null || on_failure
    if ip link show dev "$iface" >/dev/null; then on_failure; fi
fi
install_override || on_failure
if [ "$old" != "$digest" ]; then
    if [ "$need_override" = 0 ] && [ "$was_active" = active ]; then
        live_at "$old_port" && runtime_peers_match "$journal/prior.conf" || on_failure
        if [ "$method" != sync ]; then systemctl stop "$unit" >/dev/null || on_failure; fi
    fi
    [ "$(current_hash)" = "$old" ] || on_failure
    cp -p -- "$journal/next.conf" "$stage/publish.conf" && mv -fT -- "$stage/publish.conf" "$config" || on_failure
    phase=activate
    if [ "$method" = sync ]; then sync_peers "$config" || on_failure; fi
fi
phase=activate
if ! live_at "$new_port"; then systemctl start "$unit" >/dev/null || on_failure; fi
if [ "$was_enabled" != enabled ]; then systemctl enable "$unit" >/dev/null || on_failure; fi
phase=verify
live_at "$new_port" && [ "$(enabled)" = enabled ] && [ "$(current_hash)" = "$digest" ] && runtime_peers_match "$config" && awg_forwarding "$config" || on_failure
flush "$dir" || on_failure
trap '' HUP INT TERM
mv -T -- "$journal" "$stage/committed" || on_failure
if ! flush "$dir"; then
    if ! mv -T -- "$stage/committed" "$journal"; then
        # Even an I/O failure during journal recovery must leave the private
        # prior.conf available under the staging directory for manual recovery.
        trap - EXIT
        report 'error rollback_failed' failed
    fi
    on_failure
fi
trap - HUP INT TERM
finish
