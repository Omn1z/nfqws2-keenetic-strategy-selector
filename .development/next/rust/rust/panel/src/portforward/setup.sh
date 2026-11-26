#!/bin/sh
# Managed by nfqws2-strategy.
set -e
[ "${type:-}" = ip6tables ] && exit 0
iptables -t nat -N N2S_PFWD 2>/dev/null || true
iptables -t nat -F N2S_PFWD
iptables -N N2S_PFWD_FWD 2>/dev/null || true
iptables -F N2S_PFWD_FWD
while iptables -t nat -D PREROUTING -j N2S_PFWD 2>/dev/null; do :; done
iptables -t nat -A PREROUTING -j N2S_PFWD
while iptables -D FORWARD -j N2S_PFWD_FWD 2>/dev/null; do :; done
iptables -I FORWARD 1 -j N2S_PFWD_FWD
