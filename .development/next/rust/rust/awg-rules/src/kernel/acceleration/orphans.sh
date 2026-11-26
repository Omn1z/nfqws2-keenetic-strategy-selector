set -eu
p=/opt/etc/ndm/netfilter.d/89-n2s-rust-acceleration.sh
if [ -e "$p" ] || [ -L "$p" ]; then echo hook; exit; fi
for tool in iptables ip6tables; do
    if ! command -v "$tool" >/dev/null 2>&1; then continue; fi
    if ! listing=$("$tool" -w -t mangle -S); then
        # Some IPv4-only builds still ship the ip6tables userspace binary.
        if [ "$tool" = ip6tables ] && [ -r /proc/net/route ] && [ -d /proc/sys/net ] &&
            [ ! -e /proc/net/ipv6_route ] && [ ! -e /proc/sys/net/ipv6 ] && [ ! -e /proc/net/if_inet6 ]; then
            continue
        fi
        exit 1
    fi
    printf '%s\n' "$listing" | awk -v scope="${1:-all}" '$1=="-N" && ($2 ~ /^N2RP[IFO]_/ || (scope=="all" && $2 ~ /^N2S_AWGPPE_(IN|FWD|OUT)$/)) {print "chain"; exit}'
done
