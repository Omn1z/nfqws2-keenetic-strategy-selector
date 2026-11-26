//! Validate the original AWG2_MULTI rule order before transferring a blanket
//! that may overlap named, numeric or source-specific zones on either side.
use super::{err, go_action, plan, Member, Prefix, Routing};
use crate::kernel::Kernel;
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
};

fn mismatch() -> io::Error {
    err("порядок или назначение работающих правил Go отличается от пробной политики Rust")
}

pub(super) fn verify(
    k: &Kernel<'_>,
    live: &plan::Resolution,
    policy: &Routing,
    warm: &[Member],
) -> io::Result<()> {
    let raw = k.call("iptables", &["-t", "mangle", "-S"])?;
    let rows: Vec<Vec<_>> = raw
        .lines()
        .map(|l| l.split_ascii_whitespace().collect())
        .collect();
    for parent in ["OUTPUT", "PREROUTING"] {
        if !super::go_jumps(&rows, parent, "AWG2_MULTI", true) {
            return Err(mismatch());
        }
    }
    let mut chain = rows
        .iter()
        .filter(|w| w.starts_with(&["-A", "AWG2_MULTI"]))
        .map(|w| &w[2..])
        .peekable();
    if chain.next()
        != Some(
            [
                "-m",
                "mark",
                "--mark",
                "0x20000000/0x20000000",
                "-j",
                "RETURN",
            ]
            .as_slice(),
        )
    {
        return Err(mismatch());
    }
    let mut actual = BTreeSet::new();
    while let Some(["-d", s, "-j", "RETURN"]) = chain.peek().copied() {
        actual.insert(s.parse::<Prefix>()?);
        chain.next();
    }
    let private = [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
    ]
    .map(|p| p.parse::<Prefix>().unwrap());
    let mut wanted: BTreeSet<_> = private.into_iter().collect();
    wanted.extend(
        live.endpoints
            .iter()
            .filter(|ip| ip.is_ipv4())
            .map(|ip| Prefix::host(*ip)),
    );
    // A host already covered by a private range is not a policy difference.
    actual.retain(|p| !private.iter().any(|n| n != p && n.covers(*p)));
    wanted.retain(|p| !private.iter().any(|n| n != p && n.covers(*p)));
    if actual != wanted {
        return Err(mismatch());
    }
    let mut actions = BTreeMap::new();
    let mut policies = Vec::new();
    for (index, z) in policy
        .zones
        .iter()
        .enumerate()
        .filter(|(_, z)| z.enabled && !z.waiting_for_connection)
    {
        let mut sources = z
            .source_ips
            .iter()
            .filter(|s| !s.contains(':'))
            .map(|s| s.parse::<Prefix>())
            .collect::<io::Result<BTreeSet<_>>>()?;
        if sources.is_empty() {
            sources.insert(plan::Family::V4.any());
        }
        let dests = z
            .ips
            .iter()
            .chain(&z.domains)
            .filter(|p| crate::model::ipish(p) && !crate::model::catch_all(p) && !p.contains(':'))
            .map(|p| p.parse::<Prefix>())
            .chain(
                warm.iter()
                    .filter(|m| m.zone == index)
                    .map(|m| Ok(Prefix::host(m.ip))),
            )
            .collect::<io::Result<BTreeSet<_>>>()?;
        let named = z
            .domains
            .iter()
            .any(|p| !crate::model::ipish(p) && !crate::model::catch_all(p));
        if !z.only_catch_all() && dests.is_empty() && !named {
            continue;
        }
        let mut remaining = sources.clone();
        let mut iface = None;
        let name = format!("awgm_{index:03}");
        for _ in 0..sources.len() {
            let mut w = chain.next().ok_or_else(mismatch)?;
            let mut src = plan::Family::V4.any();
            if let ["-s", p, tail @ ..] = w {
                src = p.parse()?;
                w = tail;
            }
            if !remaining.remove(&src) {
                return Err(mismatch());
            }
            if !z.only_catch_all() {
                match w {
                    ["-m", "set", "--match-set", set, "dst", tail @ ..] if *set == name => w = tail,
                    _ => return Err(mismatch()),
                }
            }
            match (z.direction(), w) {
                ("direct", ["-j", "RETURN"]) => (),
                ("tunnel", ["-g", action]) => {
                    if !actions.contains_key(*action) {
                        actions.insert(
                            *action,
                            go_action(k, &rows, action, |i| live.plan.protected(i))?,
                        );
                    }
                    let selected = actions[*action].as_str();
                    if iface
                        .replace(selected.to_owned())
                        .is_some_and(|i| i != selected)
                    {
                        return Err(mismatch());
                    }
                }
                _ => return Err(mismatch()),
            }
        }
        policies.push((sources, dests, z.only_catch_all(), iface));
    }
    if chain.next().is_some() {
        return Err(mismatch());
    }
    for (s, primary) in live.plan.flows() {
        let src = s.source.sample();
        let dst = s.dest.sample();
        let old = policies
            .iter()
            .find(|(sources, dests, all, _)| {
                Prefix::host(src).ancestors().any(|p| sources.contains(&p))
                    && (*all || Prefix::host(dst).ancestors().any(|p| dests.contains(&p)))
            })
            .and_then(|(_, _, _, iface)| iface.as_deref());
        if old.is_none() || old != live.plan.effective(s, primary) {
            return Err(mismatch());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::LivePeer;
    use nfqws2_router_command::Runner;
    use serde_json::json;
    use std::time::Instant;
    struct Go(String);
    #[test]
    fn repeated_multi_classification_can_only_cross_the_owned_terminal_dns_reply_chain() {
        let multi = "-A PREROUTING -j AWG2_MULTI";
        let dispatch = "-A PREROUTING -m connmark --mark 0x8000d500/0x8000ffff -j N2S_DNS_PRE";
        let body="-A N2S_DNS_PRE -m mark --mark 0x40000000/0x40000000 -j ACCEPT\n-A N2S_DNS_PRE -p tcp -m connbytes --connbytes 1:32 --connbytes-dir reply --connbytes-mode packets -j NFQUEUE --queue-num 321 --queue-bypass\n-A N2S_DNS_PRE -j ACCEPT";
        let full = format!("{multi}\n{dispatch}\n{multi}\n-A PREROUTING -j N2S_AWGPPE_IN\n{body}");
        let check = |s: &str| {
            super::super::go_jumps(
                &s.lines()
                    .map(|l| l.split_ascii_whitespace().collect())
                    .collect::<Vec<_>>(),
                "PREROUTING",
                "AWG2_MULTI",
                true,
            )
        };
        assert!(check(&full));
        assert!(check(&format!("{multi}\n{multi}")));
        for wrong in [
            full.replace("0x8000ffff", "0xffffffff"),
            full.replace("0x40000000/0x40000000", "0x20000000/0x20000000"),
            full.replace("N2S_DNS_PRE -j ACCEPT", "N2S_DNS_PRE -j RETURN"),
            full.replace("N2S_DNS_PRE -j ACCEPT", "N2S_DNS_PRE -j MARK --set-xmark 1"),
            full.replace(dispatch, "-A PREROUTING -j N2S_AWGPPE_IN"),
            full.replacen(multi, "-A PREROUTING -j AWG2_MARK", 1),
        ] {
            assert!(!check(&wrong));
        }
    }
    impl Runner for Go {
        fn run(&self, cmd: &str, args: &[&str], _: Instant) -> io::Result<String> {
            match (cmd, args) {
                ("iptables", ["-t", "mangle", "-S"]) => Ok(self.0.clone()),
                ("ip", ["-o", "-N", "-4", "rule", "show"]) => {
                    Ok("71: from all fwmark 0x10100000/0x1ff00000 lookup 901".into())
                }
                ("ip", ["-o", "-N", "-4", "route", "show", "table", "901"]) => {
                    Ok("default dev awg0".into())
                }
                _ => panic!("unexpected mixed classifier operation"),
            }
        }
    }
    #[test]
    fn samples_kernel_sets_and_proves_order_source_and_physical_egress() {
        let doc = json!({"active_id":"s","routing":{"mode":"zones"},"servers":[{"id":"s","config":{"enabled":true,"public_key":"a".repeat(44),"endpoint":"198.51.100.10:443","client":{"enabled":true},"routing":{"mode":"zones","active":true,"zones":[
            {"enabled":true,"route":"direct","ips":["203.0.113.4"]},
            {"enabled":true,"route":"tunnel","source_ips":["192.168.1.20"],"domains":["*"]},
            {"enabled":true,"route":"direct","domains":["*"]}
        ]}}}]});
        let p = crate::policy::current(&doc).unwrap();
        let plan = plan::compile(&doc, None, false).unwrap();
        let resolved = plan::resolve(&doc, plan, false, None, |_, _| {
            Ok(LivePeer {
                ipv6_reachable: true,
                nested_mtu: None,
                prefer_ordinary: false,
                nested_transport: None,
                direct_backup: None,
                endpoint_predecessor: None,
                fresh_bound_ipv6_probe: None,
                active_replacement_peer: None,
                socket_mark: 0,
                endpoint: "198.51.100.10:443".parse().unwrap(),
                allowed: vec!["0.0.0.0/0".into()],
            })
        })
        .unwrap();
        let mut base="-A OUTPUT -j AWG2_MULTI\n-A PREROUTING -j AWG2_MULTI\n-A AWG2_MULTI -m mark --mark 0x20000000/0x20000000 -j RETURN\n".to_owned();
        for p in [
            "127.0.0.0/8",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "100.64.0.0/10",
            "198.51.100.10/32",
        ] {
            base += &format!("-A AWG2_MULTI -d {p} -j RETURN\n");
        }
        let direct = "-A AWG2_MULTI -m set --match-set awgm_000 dst -j RETURN";
        let tunnel = "-A AWG2_MULTI -s 192.168.1.20/32 -g AWG2_TO_10100000";
        let rules=format!("{direct}\n{tunnel}\n-A AWG2_MULTI -j RETURN\n-A AWG2_TO_10100000 -j MARK --set-xmark 0x10100000/0x1ff00000\n-A AWG2_TO_10100000 -j ACCEPT");
        for (rules, ok) in [
            (rules.clone(), true),
            (
                rules.replace(
                    &format!("{direct}\n{tunnel}"),
                    &format!("{tunnel}\n{direct}"),
                ),
                false,
            ),
            (rules.replace("192.168.1.20/32", "192.168.1.0/24"), false),
            (
                rules.replace("0x10100000/0x1ff00000", "0x10100000/0x10000000"),
                false,
            ),
        ] {
            let run = Go(base.clone() + &rules);
            assert_eq!(
                verify(&crate::kernel::kernel(&run), &resolved, &p, &[]).is_ok(),
                ok
            );
        }
    }
}
