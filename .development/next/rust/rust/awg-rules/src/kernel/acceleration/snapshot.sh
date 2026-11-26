# Limit ndmc output here; running-config can include credentials.
set -eu
if test -f /etc/openwrt_release || test -f /etc/rc.common; then exit 0; fi
if ! command -v ndmc >/dev/null 2>&1; then exit 0; fi
printf 'keenetic\n'
prefs=$(LD_PRELOAD= LD_LIBRARY_PATH=/lib:/usr/lib ndmc -c 'show running-config') || exit 1
printf '%s\n' "$prefs" | awk '
  $1=="no" && $2=="ppe" && ($3=="hardware" || $3=="software") && NF==3 {print "ppe", $3, "off"}
  $1=="ppe" && ($2=="hardware" || $2=="software") && NF==2 {print "ppe", $2, "on"}'
unset prefs
for leaf in nf_conntrack_fastnat nf_conntrack_fastroute nf_conntrack_fastnat_xfrm nf_conntrack_fastpath_esp swnat extif_offload ppe_enabled; do
    case "$leaf" in
        nf_*) group=netfilter ;; swnat) group=core ;; *) group=hwnat ;;
    esac
    path=/proc/sys/net/$group/$leaf
    if test -e "$path"; then
        # Keenetic procfs leaves some numeric values unterminated.
        value=$(cat "$path") || exit 1
        case "$value" in ''|*[!0-9]*) exit 1;; esac
        printf 'net.%s.%s %s\n' "$group" "$leaf" "$value"
    fi
done
