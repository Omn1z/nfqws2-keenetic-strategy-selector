# Start an explicit AWG 1.x/2.0 package deployment. Configuration, unit state
# and forwarding rules are handled separately by the transaction in apply.sh.
set -u
export LC_ALL=C DEBIAN_FRONTEND=noninteractive
iface=${1:-}
case "$iface" in wg*) suffix=${iface#wg};; awg*) suffix=${iface#awg};; *) exit 1;; esac
case "$suffix" in ''|*[!0-9]*) exit 1;; esac
[ "${#iface}" -lt 16 ] || exit 1
exec 3>&1 1>/dev/null 2>/dev/null
finish() { printf '%s\n' "$1" >&3; exit 0; }
unit=awg-quick@$iface.service
override=/etc/systemd/system/$unit.d/10-nfqws-userspace.conf
helper=/usr/local/libexec/nfqws-awg-quick-userspace
expected=$(printf '%s\n' '[Service]' 'ExecStart=' "ExecStart=$helper up %i" 'ExecStop=' "ExecStop=$helper down %i")
stock_unit() {
    case "$(systemctl show -p FragmentPath --value "$unit" 3>&-)" in
        /lib/systemd/system/awg-quick@.service|/usr/lib/systemd/system/awg-quick@.service) return 0;;
        *) return 1;;
    esac
}
if stock_unit; then
    dropins=$(systemctl show -p DropInPaths --value "$unit" 3>&-) || finish blocked
    if [ -e "$override" ] || [ -L "$override" ]; then
        [ "$dropins" = "$override" ] && [ ! -L "${override%/*}" ] &&
            [ -f "$override" ] && [ ! -L "$override" ] && [ "$(stat -c %u "$override")" = 0 ] &&
            [ "$(cat "$override")" = "$expected" ] || finish blocked
        finish userspace
    fi
    [ -z "$dropins" ] || finish blocked
else
    [ "$(systemctl show -p LoadState --value "$unit" 3>&-)" = not-found ] || finish blocked
    [ ! -e "${override%/*}" ] && [ ! -L "${override%/*}" ] || finish blocked
fi

tools_installed() { command -v awg >/dev/null && command -v awg-quick >/dev/null; }
module_present() { modinfo amneziawg >/dev/null 2>&1; }
module_loads() { modprobe amneziawg 3>&-; }
if tools_installed && stock_unit && module_present; then
    if module_loads; then finish ready; fi
    finish fallback
fi
command -v apt-get >/dev/null || finish fallback
(
    apt-get update -y || exit 1
    apt-get install -y software-properties-common ca-certificates iproute2 iptables || :
    if command -v add-apt-repository >/dev/null; then
        add-apt-repository -y ppa:amnezia/ppa || :
    fi
    apt-get update -y || exit 1
    apt-get install -y "linux-headers-$(uname -r)" amneziawg || apt-get install -y amneziawg
) 3>&- || finish fallback
if tools_installed && stock_unit && module_present && module_loads; then finish installed; fi
finish fallback
