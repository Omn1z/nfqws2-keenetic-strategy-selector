pub const SECTIONS: &[(&str, &str)] = &[
    ("system", "uname -a; date; uptime"),
    ("accel", concat!(
        "for k in net.netfilter.nf_conntrack_fastnat net.netfilter.nf_conntrack_fastroute ",
        "net.netfilter.nf_conntrack_fastnat_xfrm net.netfilter.nf_conntrack_fastpath_esp ",
        "net.core.swnat net.core.swnat_reset net.hwnat.extif_offload net.hwnat.ppe_enabled; do ",
        r#"printf "%s=" "$k"; sysctl -n "$k" 2>/dev/null || echo NA; done"#)),
    ("awg-interfaces", concat!("ip addr show 2>&1 | sed -n '/awg[0-9]/,+7p'; ",
        "grep -E '(awg|nwg|eth3|br0)' /proc/net/dev || true")),
    ("routing", concat!("ip rule show; echo --- table901; ip route show table 901 2>&1; ",
        "echo --- table998; ip route show table 998 2>&1")),
    ("awg-iptables", concat!("for t in mangle nat filter; do echo ===$t===; ",
        "iptables -w -t $t -S 2>/dev/null | grep -Ei 'AWG2|awg[0-9]|TCPMSS|MASQUERADE' || true; done")),
    ("conntrack", concat!(
        r#"for f in /proc/net/nf_conntrack /proc/net/ip_conntrack; do [ -r "$f" ] && { "#,
        r#"echo file=$f; echo total=$(wc -l < "$f"); "#,
        r#"echo fastnat=$(grep -c FASTNAT "$f" 2>/dev/null); "#,
        r#"echo tunnel_fastnat=$(grep FASTNAT "$f" 2>/dev/null | grep -c 'dst=172.16.0.2'); "#,
        r#"echo unreplied=$(grep -c UNREPLIED "$f" 2>/dev/null); break; }; done"#)),
    ("processes", concat!("ps w 2>/dev/null | grep -Ei 'nfqws|awg|wireguard|strategy|amnezia|nwg' | grep -v grep || true; ",
        "echo --- top; top -b -n 1 2>/dev/null | head -n 18 || true")),
];
