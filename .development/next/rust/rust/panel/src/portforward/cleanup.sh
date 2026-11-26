while iptables -t nat -D PREROUTING -j N2S_PFWD 2>/dev/null; do :; done
iptables -t nat -F N2S_PFWD 2>/dev/null || true
iptables -t nat -X N2S_PFWD 2>/dev/null || true
while iptables -D FORWARD -j N2S_PFWD_FWD 2>/dev/null; do :; done
iptables -F N2S_PFWD_FWD 2>/dev/null || true
iptables -X N2S_PFWD_FWD 2>/dev/null || true
