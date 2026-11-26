use super::*;
mod active_replacement;
mod deferred_endpoint;
mod dns;
mod endpoint_retry;
mod handoff;
mod inherited_edit;
mod ipv6;
mod mss;
mod named_endpoint;
mod named_reconnect;
mod native_mtu;
mod observed;
mod openwrt;
mod packed;
mod profile_rebind;
mod routed_disable;
mod routed_full_disable;
mod routed_nested_full_disable;
mod routed_mixed_disable;
mod scoped_marked;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Mutex,
};

const KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
const BOOT: &str = "12121212-1212-1212-1212-121212121212";
struct Fake(Mutex<Firmware>);
#[derive(Default)]
struct Firmware {
    boot: String,
    rule: bool,
    main_specific: bool,
    mark_lookup: bool,
    probe_oif: Option<String>,
    source_main: BTreeSet<plan::Prefix>,
    source_default: BTreeSet<plan::Prefix>,
    fence: bool,
    throws: BTreeSet<plan::Prefix>,
    routes: BTreeMap<String, String>,
    scoped_rules: BTreeSet<(plan::Selector, u16)>,
    marked_scoped: BTreeSet<(plan::Selector, u16)>,
    scoped_routes: BTreeMap<(u16, plan::Prefix), String>,
    stops: BTreeSet<plan::Selector>,
    marked_stops: BTreeSet<plan::Selector>,
    watch_flow: Option<(&'static str, &'static str)>,
    leaked: bool,
    bad_lookup: bool,
    fail_selector_once: bool,
    firewall: BTreeMap<String, BTreeSet<String>>,
    mtu: BTreeMap<String, u16>,
    foreign_rule: String,
    foreign_route: String,
    main_routes: String,
    go_hook: bool,
    local: String,
    offload: bool,
    openwrt: &'static str,
    renamed_zone: bool,
    changes: usize,
    fail_after: Option<usize>,
}
impl Default for Fake {
    fn default() -> Self {
        Self(Mutex::new(Firmware {
            boot: BOOT.into(),
            ..Default::default()
        }))
    }
}
impl Runner for Fake {
    fn run(&self, prog: &str, args: &[&str], _: Instant) -> io::Result<String> {
        let mut f = self.0.lock().unwrap();
        match (prog, args) {
            ("cat", ["/proc/sys/kernel/random/boot_id"]) => return Ok(f.boot.clone()),
            ("cat", [file]) if file.starts_with("/sys/class/net/") && file.ends_with("/mtu") => {
                let iface = &file["/sys/class/net/".len()..file.len() - "/mtu".len()];
                return f.mtu.get(iface).map(u16::to_string).ok_or(io::ErrorKind::NotFound.into());
            }
            ("fw3" | "fw4", ["-q", "network", "lan"]) => {
                return Ok(if f.renamed_zone { "home" } else { "lan" }.into())
            }
            ("sh", ["-c", s]) if s.contains("91-awg2-multi.sh") => {
                return Ok(if f.go_hook {
                    "hook"
                } else {
                    "iptables\niptables:nat\niptables:filter\niptables:mangle"
                }
                .into())
            }
            ("sh", ["-c", s]) if s.contains("then echo ipv6; else echo ipv4-only") => {
                return Ok("ipv6".into())
            }
            ("sh", ["-c", s]) if s.contains("openwrt_release") => return Ok(f.openwrt.into()),
            ("sh", ["-c", _]) => return Ok(if f.offload { "on" } else { "" }.into()),
            ("ip", ["-o", "link", "show"]) => {
                return Ok("1: lo: <LOOPBACK,UP> mtu 65536\n".into())
            }
            ("ip", ["-o", "-4", "addr", "show"]) => return Ok(f.local.clone()),
            ("ip", ["-o", "-N", "-4", "rule", "show"]) => {
                let source_rules = f
                    .source_main
                    .iter()
                    .map(|s| format!("67: from {s} lookup 254 suppress_prefixlength 0"))
                    .chain(
                        f.source_default
                            .iter()
                            .map(|s| format!("68: from {s} fwmark 0/0x20000000 lookup 17842")),
                    )
                    .collect::<Vec<_>>()
                    .join("\n");
                return Ok(format!(
                    "0: from all lookup local\n{}\n{}\n{}\n{}\n32766: from all lookup main",
                    [
                        f.probe_oif
                            .as_ref()
                            .map(|i| format!(
                                "66: from all to 2606:4700:4700::1111 oif {i} lookup 17907"
                            ))
                            .unwrap_or_default().as_str(),
                        f.foreign_rule.as_str(),
                        &source_rules,
                        if f.main_specific {
                            "67: from all lookup main suppress_prefixlength 0"
                        } else {
                            ""
                        },
                        if f.mark_lookup {
                            "68: from all fwmark 0/0x20000000 lookup 17842"
                        } else {
                            ""
                        },
                    ]
                    .join("\n"),
                    f.scoped_rules
                        .iter()
                        .map(|(s, table)| {
                            let ip = |p: plan::Prefix| {
                                let text = p.to_string();
                                text.strip_suffix("/32").unwrap_or(&text).to_string()
                            };
                            let src = if s.source.any() {
                                "all".into()
                            } else {
                                ip(s.source)
                            };
                            let mark = if f.marked_scoped.contains(&(*s, *table)) {
                                " fwmark 0/0x20000000"
                            } else {
                                ""
                            };
                            format!("68: from {src} to {}{mark} lookup {table}", ip(s.dest))
                        })
                        .collect::<Vec<_>>()
                        .join("\n"),
                    if f.rule {
                        "68: from all lookup 17842"
                    } else {
                        ""
                    },
                    f.stops
                        .iter()
                        .map(|s| format!(
                            "69: from {} to {}{} blackhole",
                            if s.source.any() {
                                "all".into()
                            } else {
                                s.source.to_string()
                            },
                            s.dest,
                            if f.marked_stops.contains(s) {
                                " fwmark 0/0x20000000"
                            } else {
                                ""
                            }
                        ))
                        .collect::<Vec<_>>()
                        .join("\n"),
                ));
            }
            ("ip", ["-o", "-N", "-4", "route", "show", "table", "main"]) => {
                return Ok(format!("default via 198.51.100.1 dev wan0\n{}", f.main_routes))
            }
            ("ip", ["-o", "-N", "-4", "route", "show", "table", "all"]) => {
                let mut out = f.foreign_route.clone();
                for p in &f.throws {
                    out.push_str(&format!("\nthrow {p} table 17842 proto 242"));
                }
                if f.fence {
                    out.push_str("\nunreachable default table 17842 proto 242 metric 32000");
                }
                for (p, i) in &f.routes {
                    let dst = if p == "0.0.0.0/0" || p == "::/0" {
                        "default"
                    } else {
                        p
                    };
                    out.push_str(&format!("\n{dst} dev {i} table 17842 proto 242 scope link"));
                }
                for ((table, dest), iface) in &f.scoped_routes {
                    out.push_str(&format!(
                        "\n{dest} dev {iface} table {table} proto 242 scope link"
                    ));
                }
                return Ok(out);
            }
            ("ip", ["-4", "route", "get", a]) => {
                let dest = a.parse().unwrap();
                let iface = f
                    .routes
                    .iter()
                    .find(|(p, _)| f.rule && p.parse::<plan::Prefix>().unwrap().contains(dest))
                    .map(|(_, i)| i.as_str())
                    .unwrap_or_else(|| f.forward("198.51.100.2", a));
                if iface == "unreachable" {
                    return Err(io::Error::other("no route"));
                }
                return Ok(format!("{a} dev {iface}"));
            }
            ("ip", ["-4", "route", "get", a, "mark", "0x20000000"]) => {
                return Ok(format!("{a} dev wan0"))
            }
            ("ip", ["-4", "route", "get", d, "from", s, ..]) => {
                let iface = if f.bad_lookup {
                    "wan0"
                } else {
                    f.forward(s, d)
                };
                if iface == "unreachable" {
                    return Err(io::Error::other("no route"));
                }
                return Ok(format!("{d} from {s} dev {iface}"));
            }
            ("iptables", ["-w", "-t", table, "-S", chain]) => {
                let prefix = format!("-A {chain} ");
                let mut rules: Vec<_> = f
                    .firewall
                    .get(*table)
                    .into_iter()
                    .flatten()
                    .filter(|l| l.starts_with(&prefix))
                    .cloned()
                    .collect();
                rules.sort_by_key(|l| !l.ends_with("--reject-with icmp6-adm-prohibited"));
                return Ok(rules.join("\n"));
            }
            ("iptables", ["-w", "-t", table, "-S"]) => {
                return Ok(f
                    .firewall
                    .get(*table)
                    .map(|set| set.iter().cloned().collect::<Vec<_>>().join("\n"))
                    .unwrap_or_default());
            }
            ("ip", ["-4", "rule", op, "pref", "68", "table", "17842"]) => {
                assert_ne!(f.rule, *op == "add");
                f.rule = *op == "add";
            }
            (
                "ip",
                ["-4", "rule", op, "pref", "66", "to", "2606:4700:4700::1111", "oif", iface, "table", "17907"],
            ) => {
                if *op == "add" {
                    assert!(f.probe_oif.replace(iface.to_string()).is_none());
                } else {
                    assert_eq!(f.probe_oif.take().as_deref(), Some(*iface));
                }
            }
            ("ip", ["-4", "route", "get", dst, "oif", iface]) => {
                if f.probe_oif.as_deref() != Some(*iface)
                    || f.scoped_routes
                        .get(&(17907, dst.parse().unwrap()))
                        .map(String::as_str)
                        != Some(*iface)
                {
                    return Err(io::ErrorKind::NetworkUnreachable.into());
                }
                return Ok(format!("{dst} dev {iface} table 17907"));
            }
            (
                "ip",
                ["-4", "rule", op, "pref", "67", "lookup", "main", "suppress_prefixlength", "0"],
            ) => {
                assert_ne!(f.main_specific, *op == "add");
                f.main_specific = *op == "add";
            }
            (
                "ip",
                ["-4", "rule", op, "pref", "68", "fwmark", "0/0x20000000", "table", "17842"],
            ) => {
                assert_ne!(f.mark_lookup, *op == "add");
                f.mark_lookup = *op == "add";
            }
            (
                "ip",
                ["-4", "rule", op, "pref", "67", "from", src, "lookup", "main", "suppress_prefixlength", "0"],
            ) => {
                let p = src.parse().unwrap();
                if *op == "add" {
                    assert!(f.source_main.insert(p));
                } else {
                    assert!(f.source_main.remove(&p));
                }
            }
            (
                "ip",
                ["-4", "rule", op, "pref", "68", "from", src, "fwmark", "0/0x20000000", "table", "17842"],
            ) => {
                let p = src.parse().unwrap();
                if *op == "add" {
                    assert!(f.source_default.insert(p));
                } else {
                    assert!(f.source_default.remove(&p));
                }
            }
            ("ip", ["-4", "route", op, "throw", net, "table", "17842", "proto", "242"]) => {
                let p = net.parse().unwrap();
                if *op == "add" {
                    assert!(f.throws.insert(p));
                } else {
                    assert!(f.throws.remove(&p));
                }
            }
            (
                "ip",
                ["-4", "route", op, "unreachable", "default", "metric", "32000", "table", "17842", "proto", "242"],
            ) => {
                assert_ne!(f.fence, *op == "add");
                f.fence = *op == "add";
            }
            (
                "ip",
                ["-4", "rule", op, "pref", "68", "from", src, "to", dest, mark @ .., "table", table],
            ) if mark.is_empty() || mark == ["fwmark", "0/0x20000000"] => {
                let key = (
                    plan::Selector {
                        source: src.parse().unwrap(),
                        dest: dest.parse().unwrap(),
                    },
                    table.parse().unwrap(),
                );
                if *op == "add" {
                    assert!(f.scoped_rules.insert(key));
                    if !mark.is_empty() {
                        assert!(f.marked_scoped.insert(key));
                    }
                } else {
                    assert!(f.scoped_rules.remove(&key));
                    if !mark.is_empty() {
                        assert!(f.marked_scoped.remove(&key));
                    }
                }
            }
            (
                "ip",
                ["-4", "rule", op, "pref", "69", "from", src, "to", dest, mark @ .., "blackhole"],
            ) if mark.is_empty() || mark == ["fwmark", "0/0x20000000"] => {
                let s = plan::Selector {
                    source: src.parse().unwrap(),
                    dest: dest.parse().unwrap(),
                };
                if *op == "add" {
                    assert!(f.stops.insert(s));
                    if !mark.is_empty() {
                        assert!(f.marked_stops.insert(s));
                    }
                } else {
                    assert!(f.stops.remove(&s));
                    if !mark.is_empty() {
                        assert!(f.marked_stops.remove(&s));
                    }
                }
            }
            ("ip", ["-4", "route", op, "table", "17842", net, "dev", iface, "proto", "242"]) => {
                if *op == "add" {
                    assert!(f
                        .routes
                        .insert(net.to_string(), iface.to_string())
                        .is_none());
                } else if *op == "replace" {
                    assert!(f.routes.insert(net.to_string(), iface.to_string()).is_some());
                } else {
                    assert_eq!(f.routes.remove(*net).as_deref(), Some(*iface));
                }
            }
            ("ip", ["-4", "route", op, "table", table, net, "dev", iface, "proto", "242"]) => {
                let key = (table.parse().unwrap(), net.parse().unwrap());
                if *op == "add" {
                    assert!(f.scoped_routes.insert(key, iface.to_string()).is_none());
                } else {
                    assert_eq!(f.scoped_routes.remove(&key).as_deref(), Some(*iface));
                }
            }
            ("iptables", ["-w", "-t", table, op, chain, tail @ ..]) => {
                let set = f.firewall.entry(table.to_string()).or_default();
                let tail = if *op == "-I" {
                    tail.strip_prefix(&["1"]).unwrap_or(tail)
                } else {
                    tail
                };
                let record = format!("-A {chain} {}", tail.join(" "))
                    .replace("--comment n2s-awg-cidr", "--comment \"n2s-awg-cidr\"")
                    .replace("RELATED,ESTABLISHED", "ESTABLISHED,RELATED");
                if matches!(*op, "-A" | "-I") {
                    assert!(set.insert(record));
                } else {
                    assert_eq!(*op, "-D");
                    assert!(set.remove(&record));
                }
            }
            _ => panic!("unexpected firmware call: {prog} {args:?}"),
        }
        f.changes += 1;
        if let Some((s, d)) = f.watch_flow {
            let blocked = f.firewall.get("filter").is_some_and(|chain| {
                chain.iter().any(|r| {
                    r.starts_with("-A FORWARD -o wan0 ")
                        && r.ends_with("-j REJECT --reject-with icmp6-adm-prohibited")
                })
            });
            f.leaked |= f.forward(s, d) == "wan0" && !blocked;
        }
        let selector_added = matches!(args, ["-4", "rule", "add", "pref", "68", "from", ..]);
        if f.fail_after == Some(f.changes) || selector_added && f.fail_selector_once {
            f.fail_after = None;
            f.fail_selector_once = false;
            return Err(io::Error::other(
                "injected error after kernel accepted command",
            ));
        }
        Ok(String::new())
    }
}
impl Firmware {
    fn forward(&self, src: &str, dst: &str) -> &str {
        let src = src.parse().unwrap();
        let dst = dst.parse().unwrap();
        let marked_lookup = self.mark_lookup || self.source_default.iter().any(|p| p.contains(src));
        if marked_lookup && self.throws.iter().any(|p| p.contains(dst)) {
            return "wan0";
        }
        if self.rule || marked_lookup {
            if let Some((_, iface)) = self
                .routes
                .iter()
                .find(|(d, _)| d.parse::<plan::Prefix>().unwrap().contains(dst))
            {
                return iface;
            }
            if marked_lookup && self.fence {
                return "unreachable";
            }
        }
        let mut hit = self
            .scoped_rules
            .iter()
            .filter(|(s, _)| s.source.contains(src) && s.dest.contains(dst));
        if let Some((_, table)) = hit.next() {
            assert!(hit.next().is_none(), "positive selectors must be disjoint");
            if let Some((_, iface)) = self
                .scoped_routes
                .iter()
                .find(|((t, p), _)| t == table && p.contains(dst))
            {
                return iface;
            }
        }
        if self
            .stops
            .iter()
            .any(|s| s.source.contains(src) && s.dest.contains(dst))
        {
            return "blackhole";
        }
        "wan0"
    }
}
fn setup() -> (tempfile::TempDir, Store, Fake) {
    let tmp = tempfile::tempdir().unwrap();
    let db = Store::open(tmp.path()).unwrap();
    let f = Fake::default();
    nfqws2_awg_profile::edit_document(&db,|d|{
        d["routing_revision"]=json!(1);
        d["routing"]=json!({"mode":"zones"});
        let row=&mut d["servers"][0]["config"];
        row["enabled"]=json!(true);row["public_key"]=json!(KEY);row["client"]["enabled"]=json!(true);
        row["routing"]=json!({"mode":"zones","zones":[{"name":"mail","enabled":true,"ips":["203.0.113.7/24"]}]});
        Ok(())
    }).unwrap();
    (tmp, db, f)
}
fn peer(_: &Value, iface: &str) -> io::Result<LivePeer> {
    assert_eq!(iface, "awg0");
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
}
fn action(db: &Store, f: &Fake, op: Operation, now: u64) -> io::Result<()> {
    operate_at(db, f, op, now, peer)
}
fn edit_net(db: &Store, net: &str) {
    nfqws2_awg_profile::edit_document(db, |d| {
        d["routing_revision"] = json!(d["routing_revision"].as_u64().unwrap() + 1);
        d["servers"][0]["config"]["routing"]["zones"][0]["ips"] = json!([net]);
        Ok(())
    })
    .unwrap();
}
fn protect(db: &Store) {
    nfqws2_awg_profile::edit_document(db, |d| {
        d["routing"]["killswitch"] = json!(true);
        Ok(())
    })
    .unwrap();
}

#[test]
fn exclusive_zones_keep_direct_exceptions_and_other_peer_live_during_outage() {
    let (_tmp, db, f) = setup();
    scoped_policy(&db);
    protect(&db);
    let now = nfqws2_awg_profile::now();
    f.0.lock().unwrap().local = "2: br0 inet 192.168.1.1/24 scope global".into();
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &f, op, now, both_peers).unwrap();
    }
    let verify = |disposition: &str| {
        let fw = f.0.lock().unwrap();
        assert_eq!(fw.forward("192.168.1.7", "203.0.113.10"), disposition);
        assert_eq!(fw.forward("192.168.1.7", "203.0.113.9"), "wan0"); // direct exception
        assert_eq!(fw.forward("192.168.1.200", "203.0.113.10"), "awg1");
        assert_eq!(fw.forward("192.168.2.7", "203.0.113.10"), "wan0");
        assert_eq!(fw.forward("192.168.1.7", "198.51.100.10"), "wan0"); // VPN transport
    };
    verify("awg0");
    {
        let mut fw = f.0.lock().unwrap();
        // Deleting a Linux TUN also removes its device routes, immediately.
        fw.scoped_routes.retain(|_, iface| iface != "awg0");
        fw.watch_flow = Some(("192.168.1.7", "203.0.113.10"));
    }
    verify("blackhole");
    let recover = || {
        operate_at(&db, &f, Operation::Recover, now, |cfg, iface| {
            if iface == "awg0" {
                Err(io::ErrorKind::NotConnected.into())
            } else {
                both_peers(cfg, iface)
            }
        })
    };
    recover().unwrap();
    verify("blackhole");
    assert_eq!(scheduled(&db).unwrap(), Schedule::Restore);
    assert!(!inspect(&db, &f).unwrap().ready);
    let before = f.0.lock().unwrap().changes;
    recover().unwrap();
    assert_eq!(f.0.lock().unwrap().changes, before);
    operate_at(&db, &f, Operation::Recover, now, both_peers).unwrap();
    verify("awg0");
    assert!(!f.0.lock().unwrap().leaked);
    assert!(inspect(&db, &f).unwrap().ready);
    f.0.lock().unwrap().watch_flow = None;
    action(&db, &f, Operation::Teardown, now).unwrap();
    assert!(f.0.lock().unwrap().stops.is_empty());
}

#[test]
fn exclusive_reboot_with_peer_down_blocks_only_committed_ranges_then_recovers() {
    let (_tmp, db, f) = setup();
    protect(&db);
    for op in [Operation::Apply, Operation::Commit] {
        action(&db, &f, op, 10).unwrap();
    }
    // A newer trial must never become the saved policy after a power cut.
    edit_net(&db, "192.0.2.0/24");
    action(&db, &f, Operation::Apply, 20).unwrap();
    *f.0.lock().unwrap() = Firmware {
        boot: "34343434-3434-3434-3434-343434343434".into(),
        ..Firmware::default()
    };
    operate_at(&db, &f, Operation::Recover, 30, |_, _| {
        Err(io::ErrorKind::NotConnected.into())
    })
    .unwrap();
    {
        let fw = f.0.lock().unwrap();
        assert_eq!(fw.forward("192.168.3.4", "203.0.113.9"), "blackhole");
        assert_eq!(fw.forward("192.168.3.4", "192.0.2.9"), "wan0");
        assert!(fw.routes.is_empty() && !fw.rule);
    }
    assert_eq!(scheduled(&db).unwrap(), Schedule::Restore);
    action(&db, &f, Operation::Recover, 40).unwrap();
    assert_eq!(
        f.0.lock().unwrap().forward("192.168.3.4", "203.0.113.9"),
        "awg0"
    );
    action(&db, &f, Operation::Suspend, 50).unwrap();
    assert!(f.0.lock().unwrap().stops.is_empty()); // deliberate service stop/upgrade
    assert!(Journal::read(&db).unwrap().committed.killswitch);
}

#[test]
fn exclusive_replacement_and_ambiguous_failure_never_open_the_common_range() {
    let (_tmp, db, f) = setup();
    protect(&db);
    for op in [Operation::Apply, Operation::Commit] {
        action(&db, &f, op, 10).unwrap();
    }
    edit_net(&db, "203.0.113.8/30");
    {
        let mut fw = f.0.lock().unwrap();
        fw.watch_flow = Some(("192.168.3.4", "203.0.113.9"));
        fw.fail_after = Some(fw.changes + 4);
    }
    assert!(action(&db, &f, Operation::Apply, 20).is_err());
    assert!(Journal::read(&db).unwrap().preparing.is_empty());
    assert_eq!(
        f.0.lock().unwrap().forward("192.168.3.4", "203.0.113.4"),
        "awg0"
    );
    action(&db, &f, Operation::Apply, 20).unwrap();
    action(&db, &f, Operation::Recover, 111).unwrap();
    let fw = f.0.lock().unwrap();
    assert!(!fw.leaked);
    assert_eq!(fw.stops.len(), 1);
    assert_eq!(fw.forward("192.168.3.4", "203.0.113.9"), "awg0");
}

#[test]
fn exclusive_policy_checks_for_earlier_bypass_rules_and_foreign_stop_rules() {
    let (_tmp, db, f) = setup();
    protect(&db);
    for rule in [
        "55: from all lookup 500",
        "69: from all to 203.0.113.0/24 blackhole",
        "69: from all lookup main",
    ] {
        f.0.lock().unwrap().foreign_rule = rule.into();
        assert!(action(&db, &f, Operation::Apply, 10).is_err());
        assert_eq!(f.0.lock().unwrap().changes, 0);
    }
    f.0.lock().unwrap().foreign_rule = "55: from all to 198.51.100.0/24 lookup 500".into();
    action(&db, &f, Operation::Apply, 10).unwrap();
    action(&db, &f, Operation::Teardown, 20).unwrap();
    assert!(f.0.lock().unwrap().foreign_rule.starts_with("55:"));
}

#[test]
fn recovery_preserves_protection_when_peer_identity_or_address_grant_changes() {
    let (_tmp, db, f) = setup();
    scoped_policy(&db);
    protect(&db);
    let now = nfqws2_awg_profile::now();
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &f, op, now, both_peers).unwrap();
    }
    nfqws2_awg_profile::edit_document(&db, |doc| {
        // Same interface and server ID now declare a different public key.
        doc["servers"][0]["config"]["public_key"] =
            json!("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=");
        Ok(())
    })
    .unwrap();
    operate_at(&db, &f, Operation::Recover, now, |cfg, iface| {
        assert_eq!(iface, "awg1");
        both_peers(cfg, iface)
    })
    .unwrap();
    {
        let fw = f.0.lock().unwrap();
        assert_eq!(fw.forward("192.168.1.8", "203.0.113.9"), "blackhole");
        assert_eq!(fw.forward("192.168.1.200", "203.0.113.9"), "awg1");
    }
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["config"]["public_key"] = json!(KEY);
        Ok(())
    })
    .unwrap();
    operate_at(&db, &f, Operation::Recover, now, |cfg, iface| {
        let mut live = both_peers(cfg, iface)?;
        if iface == "awg1" {
            live.allowed = vec!["192.0.2.0/24".into()];
        }
        Ok(live)
    })
    .unwrap();
    let fw = f.0.lock().unwrap();
    assert_eq!(fw.forward("192.168.1.8", "203.0.113.9"), "awg0");
    assert_eq!(fw.forward("192.168.1.200", "203.0.113.9"), "blackhole");
}
#[test]
fn apply_commit_reboot_suspend_restore_and_teardown_preserve_foreign_objects() {
    let (_tmp, db, f) = setup();
    let now = nfqws2_awg_profile::now();
    {
        let mut state = f.0.lock().unwrap();
        state.foreign_rule = "800: from 192.0.2.1 lookup 200".into();
        state
            .firewall
            .entry("filter".into())
            .or_default()
            .insert("-A FORWARD -i guest -j DROP".into());
    }
    action(&db, &f, Operation::Apply, now).unwrap();
    let s = inspect(&db, &f).unwrap();
    assert!(s.active && s.ready && s.pending_commit);
    assert_eq!(scheduled(&db).unwrap(), Schedule::Expires(now + 90));
    action(&db, &f, Operation::Commit, now + 30).unwrap();
    assert!(!inspect(&db, &f).unwrap().pending_commit);
    action(&db, &f, Operation::Suspend, now + 31).unwrap();
    assert!(!inspect(&db, &f).unwrap().active);
    assert_eq!(scheduled(&db).unwrap(), Schedule::Restore);
    f.0.lock().unwrap().boot = "34343434-3434-3434-3434-343434343434".into();
    action(&db, &f, Operation::Recover, now + 32).unwrap();
    assert!(inspect(&db, &f).unwrap().active);
    action(&db, &f, Operation::Teardown, now + 33).unwrap();
    let state = f.0.lock().unwrap();
    assert!(state.routes.is_empty() && !state.rule);
    assert_eq!(
        state.firewall["filter"],
        BTreeSet::from(["-A FORWARD -i guest -j DROP".into()])
    );
    assert_eq!(state.foreign_rule, "800: from 192.0.2.1 lookup 200");
    assert!(nfqws2_awg_profile::read(&db).unwrap()["rust_static_routing"].is_null());
}
#[test]
fn failed_replacement_and_unconfirmed_revision_restore_original_commit() {
    let (_tmp, db, f) = setup();
    let now = nfqws2_awg_profile::now();
    action(&db, &f, Operation::Apply, now).unwrap();
    action(&db, &f, Operation::Commit, now).unwrap();
    edit_net(&db, "192.0.2.8/32");
    {
        let mut fw = f.0.lock().unwrap();
        fw.fail_after = Some(fw.changes + 4);
    }
    assert!(action(&db, &f, Operation::Apply, now + 10).is_err());
    assert_eq!(
        f.0.lock()
            .unwrap()
            .routes
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        ["203.0.113.0/24"]
    );
    assert!(inspect(&db, &f).unwrap().active && !inspect(&db, &f).unwrap().ready);
    action(&db, &f, Operation::Apply, now + 11).unwrap();
    assert!(action(&db, &f, Operation::Commit, now + 102).is_err());
    action(&db, &f, Operation::Recover, now + 102).unwrap();
    assert_eq!(
        f.0.lock()
            .unwrap()
            .routes
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        ["203.0.113.0/24"]
    );
    assert!(Journal::read(&db).unwrap().preparing.is_empty());
    assert_eq!(Journal::read(&db).unwrap().expires, 0);
}
#[test]
fn routing_mtu_is_a_fallback_for_legacy_tunnels() {
    let (_tmp, db, f) = setup();
    for (server_mtu, routing_mtu, effective) in [(1360, 1320, 1360), (0, 1320, 1320)] {
        nfqws2_awg_profile::edit_document(&db, |d| {
            d["routing"]["mtu"] = json!(routing_mtu);
            let config = &mut d["servers"][0]["config"];
            config["mtu"] = json!(server_mtu);
            config["routing"]["mtu"] = json!(routing_mtu);
            Ok(())
        })
        .unwrap();
        action(&db, &f, Operation::Apply, 100).unwrap();
        action(&db, &f, Operation::Commit, 101).unwrap();
        assert_eq!(
            Journal::read(&db).unwrap().committed.targets["awg0"].mtu,
            effective
        );
    }
}

#[test]
fn unsupported_policies_peer_and_kernel_conflicts_never_partially_apply() {
    let (_tmp, db, f) = setup();
    for (key, value) in [
        ("ips", json!(["2001:db8::1/129"])),
        ("source_ips", json!(["2001:db8::1"])),
        ("fallback_tunnel_ids", json!(["other"])),
        ("ips", json!(["2001:db8::1"])),
        ("ips", json!(["127.0.0.0/8"])),
        ("ips", json!(["198.51.100.0/24"])),
    ] {
        nfqws2_awg_profile::edit_document(&db, |d| {
            d["servers"][0]["config"]["routing"]["zones"][0] =
                json!({"name":"deny","enabled":true,"ips":["203.0.113.0/24"]});
            d["servers"][0]["config"]["routing"]["zones"][0][key] = value;
            Ok(())
        })
        .unwrap();
        assert!(action(&db, &f, Operation::Apply, 100).is_err());
    }
    edit_net(&db, "203.0.113.0/24");
    assert!(
        operate_at(&db, &f, Operation::Apply, 100, |_, _| Ok(LivePeer {
            ipv6_reachable: true,
            nested_mtu: None,
            prefer_ordinary: false,
            nested_transport: None,
            direct_backup: None,
            endpoint_predecessor: None,
            fresh_bound_ipv6_probe: None,
            active_replacement_peer: None,
            socket_mark: 0,
            endpoint: "198.51.100.3:9".parse().unwrap(),
            allowed: vec!["203.0.113.5/32".into()]
        }))
        .is_err()
    );
    for (rule, route, local, offload) in [
        ("68: from all lookup 17842", "", "", false),
        (
            "",
            "203.0.113.0/24 dev awg0 table 17842 proto 242 scope link",
            "",
            false,
        ),
        ("550: from all lookup 900", "", "", false),
        ("", "", "2: wan0 inet 203.0.113.42/24 scope global", false),
        ("", "", "", true),
    ] {
        {
            let mut fw = f.0.lock().unwrap();
            fw.foreign_rule = rule.into();
            fw.foreign_route = route.into();
            fw.local = local.into();
            fw.offload = offload;
        }
        assert!(action(&db, &f, Operation::Apply, 100).is_err());
        assert_eq!(f.0.lock().unwrap().changes, 0);
        assert!(Journal::read(&db).unwrap().idle());
    }
}
#[test]
fn main_route_guard_accepts_disjoint_numeric_types_and_rejects_overlap() {
    let (_tmp, db, router) = setup();
    let mut plan = Plan::default();
    plan.prefixes.insert("203.0.113.50".parse().unwrap(), "awg0".into());
    let check = || kernel(&router).guard(&plan, &BTreeSet::new());
    router.0.lock().unwrap().main_routes =
        "1 192.0.2.1 dev wan0\n6 192.0.2.2\n7 192.0.2.3\n8 192.0.2.4\n9 192.0.2.5".into();
    check().unwrap();
    for route in ["8 203.0.113.48/28", "prohibit 203.0.113.48/28"] {
        router.0.lock().unwrap().main_routes = route.into();
        let error = check().unwrap_err();
        assert!(error.to_string().contains("пересекает существующий маршрут"));
    }
    router.0.lock().unwrap().main_routes = "8 invalid".into();
    assert!(check().is_err());
    assert_eq!(router.0.lock().unwrap().changes, 0);
    assert!(Journal::read(&db).unwrap().idle());
}

#[test]
fn direct_exceptions_follow_zone_order_and_survive_recovery() {
    let (_tmp, db, f) = setup();
    let now = nfqws2_awg_profile::now();
    let set_order = |direct_first| {
        nfqws2_awg_profile::edit_document(&db, |doc| {
            let direct = json!({"name":"local gateway","route":"direct","enabled":true,"ips":["10.2.1.4/30"]});
            let vpn = json!({"name":"remote office","route":"tunnel","enabled":true,"ips":["10.2.1.0/28"]});
            doc["servers"][0]["config"]["routing"]["zones"] = if direct_first {
                json!([direct, vpn])
            } else {
                json!([vpn, direct])
            };
            Ok(())
        }).unwrap();
    };
    f.0.lock().unwrap().local = "1: br0 inet 192.168.1.1/24 scope global".into();
    set_order(true);
    action(&db, &f, Operation::Apply, now).unwrap();
    action(&db, &f, Operation::Commit, now + 1).unwrap();
    action(&db, &f, Operation::Suspend, now + 2).unwrap();
    action(&db, &f, Operation::Recover, now + 3).unwrap();
    let routes = |f: &Fake| {
        f.0.lock()
            .unwrap()
            .routes
            .keys()
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(routes(&f), ["10.2.1.0/30", "10.2.1.8/29"]);
    set_order(false);
    action(&db, &f, Operation::Apply, now + 4).unwrap();
    assert_eq!(routes(&f), ["10.2.1.0/28"]);
    edit_net(&db, "192.168.1.0/24");
    assert!(action(&db, &f, Operation::Apply, now + 5).is_err());
    assert_eq!(routes(&f), ["10.2.1.0/28"]);
}
#[test]
fn interrupted_trial_is_reconciled_and_reboot_does_not_adopt_foreign_objects() {
    let (_tmp, db, f) = setup();
    let now = nfqws2_awg_profile::now();
    action(&db, &f, Operation::Apply, now).unwrap();
    let mut j = Journal::read(&db).unwrap();
    j.preparing.push(j.installed.clone());
    j.installed = Snapshot::default();
    db.transaction(|tx| tx.save_runtime(RECEIPT, &j)).unwrap();
    action(&db, &f, Operation::Recover, now + 1).unwrap();
    assert!(f.0.lock().unwrap().routes.is_empty());
    action(&db, &f, Operation::Apply, now + 2).unwrap();
    action(&db, &f, Operation::Commit, now + 3).unwrap();
    let before = f.0.lock().unwrap().changes;
    f.0.lock().unwrap().boot = "10101010-1010-1010-1010-101010101010".into();
    assert!(action(&db, &f, Operation::Recover, now + 4).is_err());
    assert_eq!(f.0.lock().unwrap().changes, before);
}

#[test]
fn interrupted_recovery_reconciles_four_legacy_intents_without_growing_the_journal() {
    struct Cut<'a> {
        fake: &'a Fake,
        after: usize,
    }
    impl Runner for Cut<'_> {
        fn run(&self, prog: &str, args: &[&str], end: Instant) -> io::Result<String> {
            if self.fake.0.lock().unwrap().changes >= self.after {
                return Err(io::ErrorKind::NotConnected.into());
            }
            let result = self.fake.run(prog, args, end)?;
            if self.fake.0.lock().unwrap().changes >= self.after {
                // The kernel accepted the command, but the reply and all
                // subsequent attempts to inventory/compensate are lost.
                return Err(io::ErrorKind::ConnectionReset.into());
            }
            Ok(result)
        }
    }
    let (_tmp, db, f) = setup();
    protect(&db);
    for op in [Operation::Apply, Operation::Commit] {
        action(&db, &f, op, 100).unwrap();
    }
    edit_net(&db, "203.0.113.8/30");
    action(&db, &f, Operation::Apply, 105).unwrap();
    let mut broken = Journal::read(&db).unwrap();
    // The pre-fix writer could persist four plans. Make each claim distinct,
    // with one partially installed route. The committed /24 stop is absent.
    for n in [16, 32, 48, 64] {
        let mut p = broken.installed.clone();
        p.prefixes =
            BTreeMap::from([(format!("203.0.113.{n}/30").parse().unwrap(), "awg0".into())]);
        broken.preparing.push(p);
    }
    let residual = objects(&broken.preparing[1])
        .into_iter()
        .find(|o| matches!(o, Object::Route(..)))
        .unwrap();
    kernel(&f).mutate(&residual, true).unwrap();
    db.transaction(|tx| tx.save_runtime(RECEIPT, &broken))
        .unwrap();
    assert_eq!(Journal::read(&db).unwrap().preparing.len(), 4);
    let before = {
        let mut firmware = f.0.lock().unwrap();
        firmware.watch_flow = Some(("192.168.1.42", "203.0.113.9"));
        firmware.foreign_rule = "1000: from all lookup 1000".into();
        firmware.foreign_route = "10.5.6.0/24 dev adminvpn table 17842 proto static".into();
        firmware.changes
    };
    // The checkpoint cannot adopt a foreign route even after multiple crashes.
    assert!(action(&db, &f, Operation::Recover, 106).is_err());
    assert_eq!(f.0.lock().unwrap().changes, before);
    assert!(f.0.lock().unwrap().foreign_route.contains("adminvpn"));
    f.0.lock().unwrap().foreign_route.clear();
    let cut = |op, online| {
        let runner = Cut {
            fake: &f,
            after: f.0.lock().unwrap().changes + 1,
        };
        let result = operate_at(&db, &runner, op, 106, |c, i| {
            if online {
                peer(c, i)
            } else {
                Err(io::ErrorKind::NotConnected.into())
            }
        });
        assert!(result.is_err());
        assert_eq!(f.0.lock().unwrap().changes, runner.after);
    };
    for online in [true, false, true] {
        cut(Operation::Recover, online);
        let j = Journal::read(&db).unwrap();
        assert_eq!(j.preparing.len(), 5);
        assert_eq!(j.preparing.last().map(Snapshot::as_ref), Some(&j.committed.guards_only()));
        assert!(!f.0.lock().unwrap().leaked);
    }
    operate_at(&db, &f, Operation::Recover, 107, |_, _| {
        Err(io::ErrorKind::NotConnected.into())
    })
    .unwrap();
    assert!(Journal::read(&db).unwrap().preparing.is_empty());
    assert_eq!(path(&f, "203.0.113.9"), "blackhole");
    assert_eq!(path(&f, "203.0.113.20"), "blackhole");
    assert!(f.0.lock().unwrap().routes.is_empty());
    action(&db, &f, Operation::Recover, 108).unwrap();
    assert_eq!(path(&f, "203.0.113.20"), "awg0");
    assert!(!f.0.lock().unwrap().leaked);
    // Run the same sequence through the new writer, without synthesizing any
    // receipt. Only the interrupted apply and its one fixed checkpoint persist.
    action(&db, &f, Operation::Apply, 105).unwrap();
    edit_net(&db, "203.0.113.9/32");
    cut(Operation::Apply, true);
    assert_eq!(Journal::read(&db).unwrap().preparing.len(), 1);
    for online in [false, true, false] {
        cut(Operation::Recover, online);
        assert_eq!(Journal::read(&db).unwrap().preparing.len(), 2);
    }
    action(&db, &f, Operation::Recover, 108).unwrap();
    assert_eq!(path(&f, "203.0.113.20"), "awg0");
    assert!(!f.0.lock().unwrap().leaked);
    // Teardown can retire all claims directly without a fifth plan and can
    // resume even if the first deletion happened just before an interruption.
    let mut again = Journal::read(&db).unwrap();
    again.preparing = broken.preparing;
    db.transaction(|tx| tx.save_runtime(RECEIPT, &again))
        .unwrap();
    f.0.lock().unwrap().foreign_route = "10.5.6.0/24 dev adminvpn table 17842 proto static".into();
    cut(Operation::Teardown, false);
    assert_eq!(Journal::read(&db).unwrap().preparing.len(), 4);
    assert!(!f.0.lock().unwrap().leaked);
    f.0.lock().unwrap().watch_flow = None;
    action(&db, &f, Operation::Teardown, 110).unwrap();
    assert!(Journal::read(&db).unwrap().idle());
    let fw = f.0.lock().unwrap();
    assert!(fw.stops.is_empty() && fw.routes.is_empty() && !fw.rule);
    assert!(fw.foreign_rule.contains("1000") && fw.foreign_route.contains("adminvpn"));
}

fn scoped_policy(db: &Store) {
    nfqws2_awg_profile::edit_document(db, |doc| {
        let rows = doc["servers"].as_array_mut().unwrap();
        let mut backup = rows[0].clone();
        backup["id"] = json!("branch");
        backup["config"]["client_iface"] = json!("awg1");
        backup["config"]["routing"]["zones"] = json!([
            {"order":3,"name":"other office","route":"tunnel","enabled":true,
             "ips":["203.0.113.0/24"],"source_ips":["192.168.1.0/24"]}
        ]);
        rows[0]["config"]["routing"]["zones"] = json!([
            {"order":1,"name":"ordinary direct exception","route":"direct","enabled":true,
              "ips":["203.0.113.9"],"source_ips":["192.168.1.7"]},
            {"order":2,"name":"department network","enabled":true,
              "ips":["203.0.113.0/24"],"source_ips":["192.168.1.5/28"]}
        ]);
        rows.push(backup);
        Ok(())
    })
    .unwrap();
}
fn both_peers(v: &Value, iface: &str) -> io::Result<LivePeer> {
    assert_eq!(v["public_key"], KEY);
    assert!(matches!(iface, "awg0" | "awg1"));
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
}

fn redundant_policy(db: &Store, killswitch: bool) {
    nfqws2_awg_profile::edit_document(db, |doc| {
        doc["routing"]["killswitch"] = json!(killswitch);
        let rows = doc["servers"].as_array_mut().unwrap();
        let template = rows[0].clone();
        for (i, id) in ["rule", "nested", "profile"].into_iter().enumerate() {
            let mut row = template.clone();
            row["id"] = json!(id);
            row["config"]["client_iface"] = json!(format!("awg{}", i + 1));
            row["config"]["routing"]["zones"] = json!([]);
            rows.push(row);
        }
        rows[0]["config"]["client"]["fallback_tunnel_ids"] = json!(["profile"]);
        rows[1]["config"]["client"]["fallback_tunnel_ids"] = json!(["nested"]);
        rows[2]["config"]["client"]["standby"] = json!(true);
        rows[0]["config"]["routing"]["zones"] = json!([
            {"name":"keep local","route":"direct","enabled":true,"ips":["203.0.113.3"]},
            {"name":"branch","enabled":true,"ips":["203.0.113.1","203.0.113.2","203.0.113.3"],"fallback_tunnel_ids":["rule","profile"]},
            {"name":"other branch","enabled":true,"ips":["203.0.113.4"]}
        ]);
        Ok(())
    }).unwrap();
}

// The real callback authenticates the configured public key and latest handshake
// using UAPI. This fixture supplies its independently verified grants per peer.
fn refresh_with(db: &Store, f: &Fake, op: Operation, nets: [Option<&str>; 4]) -> io::Result<()> {
    let mut queried = BTreeSet::new();
    operate_at(db, f, op, nfqws2_awg_profile::now(), |cfg, iface| {
        assert_eq!(cfg["public_key"], KEY);
        assert!(
            queried.insert(iface.to_string()),
            "duplicate UAPI query per pass"
        );
        let index = iface.strip_prefix("awg").unwrap().parse::<usize>().unwrap();
        let allowed = nets[index].ok_or(io::ErrorKind::NotConnected)?;
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
            endpoint: "198.51.100.10:51820".parse().unwrap(),
            allowed: vec![allowed.to_owned()],
        })
    })
}
const ALL: Option<&str> = Some("0.0.0.0/0");

#[test]
fn active_reserve_order_can_settle_on_restart_without_replacing_the_live_path() {
    let (_dir, db, f) = setup();
    redundant_policy(&db, true);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["config"]["client"]["fallback_tunnel_ids"] =
            json!(["profile", "nested"]);
        Ok(())
    }).unwrap();
    for op in [Operation::Apply, Operation::Commit] {
        refresh_with(&db, &f, op, [ALL; 4]).unwrap();
    }
    let initial = path(&f, "203.0.113.4");
    assert_eq!(initial, "awg0");
    let changes = f.0.lock().unwrap().changes;
    let runtime = nfqws2_awg_profile::runtime::Runtime::new(
        std::path::Path::new("/unused-fixture-root"), Default::default(),
    );
    let authored = nfqws2_awg_profile::Failover {
        fallback_tunnel_ids: vec!["nested".into(), "profile".into()],
        ..Default::default()
    };
    let observed = |_cfg: &Value, _iface: &str| {
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
            endpoint: "198.51.100.10:51820".parse().unwrap(),
            allowed: vec!["0.0.0.0/0".into()],
        })
    };
    let arrange = |change| runtime.stage_active_failover_order(&db, "awg0", change, |before, after, retained| {
        stage_routed_failover_order(&db, &f, before, after, "awg0", retained, observed)
    });
    let outside = nfqws2_awg_profile::Failover {
        fallback_tunnel_ids: vec!["unknown".into(), "profile".into()],
        ..Default::default()
    };
    let doc = nfqws2_awg_profile::read(&db).unwrap();
    assert!(arrange(&outside).is_err());
    assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), doc);
    assert!(arrange(&authored).unwrap());
    assert_eq!(f.0.lock().unwrap().changes, changes);
    assert_eq!(Journal::read(&db).unwrap().installed.revision, 1);
    let staged = nfqws2_awg_profile::read(&db).unwrap();
    // Simulate loss first after writing settings, then after writing the new journal.
    assert!(finish_routed_failover_order(&db, &f, observed).unwrap());
    nfqws2_awg_profile::edit_document(&db, |doc| {
        *doc = staged;
        Ok(())
    }).unwrap();
    assert!(finish_routed_failover_order(&db, &f, observed).unwrap());
    assert!(!finish_routed_failover_order(&db, &f, observed).unwrap());
    assert_eq!(f.0.lock().unwrap().changes, changes);
    assert_eq!(path(&f, "203.0.113.4"), initial);
    assert_eq!(Journal::read(&db).unwrap().committed.revision, 2);
    refresh_with(&db, &f, Operation::Refresh, [None, ALL, ALL, ALL]).unwrap();
    assert_eq!(path(&f, "203.0.113.4"), "awg2");
    refresh_with(&db, &f, Operation::Refresh, [ALL; 4]).unwrap();
    let stable = f.0.lock().unwrap().changes;
    let reduced = nfqws2_awg_profile::Failover {
        fallback_tunnel_ids: vec!["profile".into()],
        ..Default::default()
    };
    assert!(arrange(&reduced).unwrap());
    assert!(finish_routed_failover_order(&db, &f, observed).unwrap());
    assert_eq!(f.0.lock().unwrap().changes, stable);
    assert_eq!(path(&f, "203.0.113.4"), "awg0");
    assert_eq!(Journal::read(&db).unwrap().committed.revision, 3);
    refresh_with(&db, &f, Operation::Refresh, [None, ALL, ALL, ALL]).unwrap();
    assert_eq!(path(&f, "203.0.113.4"), "awg3");
}

#[test]
fn active_reserve_edit_adds_cold_participant_without_writing_forwarding_rules() {
    let (_dir, db, f) = setup();
    protect(&db);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let mut reserve = doc["servers"][0].clone();
        reserve["id"] = "cold".into();
        reserve["config"]["client_iface"] = "awg1".into();
        reserve["config"]["endpoint"] = "198.51.100.11:443".into();
        reserve["config"]["client"]["standby"] = true.into();
        reserve["config"]["routing"]["zones"] = json!([]);
        doc["servers"].as_array_mut().unwrap().push(reserve);
        Ok(())
    })
    .unwrap();
    for op in [Operation::Apply, Operation::Commit] {
        action(&db, &f, op, 10).unwrap();
    }
    let original = Journal::read(&db).unwrap();
    let changes = f.0.lock().unwrap().changes;
    assert!(!original.installed.targets.contains_key("awg1"));
    let runtime = nfqws2_awg_profile::runtime::Runtime::new(
        std::path::Path::new("/unused-fixture-root"),
        Default::default(),
    );
    let change = nfqws2_awg_profile::Failover {
        fallback_tunnel_ids: vec!["cold".into()],
        ..Default::default()
    };
    assert!(runtime.stage_active_failover_order(&db, "awg0", &change, |before, after, retained| {
        stage_routed_failover_order(&db, &f, before, after, "awg0", retained, |cfg, iface| {
            if iface == "awg1" {
                return Err(io::ErrorKind::NotConnected.into());
            }
            peer(cfg, iface)
        })
    }).unwrap());
    assert!(finish_routed_failover_order(&db, &f, peer).unwrap());
    let updated = Journal::read(&db).unwrap();
    assert_eq!(updated.installed.revision, 2);
    assert_eq!(updated.installed.targets["awg1"].id, "cold");
    assert_eq!(objects(&updated.installed), objects(&original.installed));
    assert_eq!(f.0.lock().unwrap().changes, changes);
    assert_eq!(path(&f, "203.0.113.4"), "awg0");
}

#[test]
fn active_reserve_edit_retries_only_mss_rules_and_preserves_primary() {
    let (_dir, db, f) = setup();
    protect(&db);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let mut reserve = doc["servers"][0].clone();
        reserve["id"] = "hot".into();
        reserve["config"]["client_iface"] = "awg1".into();
        reserve["config"]["endpoint"] = "198.51.100.11:443".into();
        reserve["config"]["routing"]["zones"] = json!([]);
        doc["servers"].as_array_mut().unwrap().push(reserve);
        Ok(())
    }).unwrap();
    let doc = nfqws2_awg_profile::read(&db).unwrap();
    let k = kernel(&f);
    let intent = plan::compile_effective(
        &doc, crate::sources::current(&db, &doc).unwrap(), None, false, &[],
        plan::Layout { go_ipv4: true, ..Default::default() },
    ).unwrap();
    let mut initial = plan::resolve_on(&doc, intent, false, None, Some(plan::Verification::Read(&k)), both_peers).unwrap().plan;
    k.select_firewall(&mut initial).unwrap();
    let installed: Snapshot = initial.into();
    let old = Journal { boot: BOOT.into(), ..Default::default() };
    let original = Journal { installed: installed.clone(), committed: installed, ..old.clone() };
    db.transaction(|tx| transition(&db, tx, &f, &old, &original, None)).unwrap();

    let runtime = nfqws2_awg_profile::runtime::Runtime::new(
        std::path::Path::new("/unused-fixture-root"), Default::default(),
    );
    let change = |fallback_tunnel_ids| {
        let edit = nfqws2_awg_profile::Failover { fallback_tunnel_ids, ..Default::default() };
        runtime.stage_active_failover_order(&db, "awg0", &edit, |before, after, retained| {
            stage_routed_failover_order(&db, &f, before, after, "awg0", retained, both_peers)
        })
    };
    assert!(change(vec!["hot".into()]).unwrap());
    let pending = nfqws2_awg_profile::read(&db).unwrap();
    let marker = pending["rust_static_routing"][failover_order::FIELD].clone();
    assert_eq!(marker["route_update"], true);
    {
        let mut router = f.0.lock().unwrap();
        router.fail_after = Some(router.changes + 1);
    }
    assert!(finish_routed_failover_order(&db, &f, both_peers).is_err());
    assert_eq!(path(&f, "203.0.113.4"), "awg0");
    assert_eq!(Journal::read(&db).unwrap(), original);
    assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), pending);

    assert!(finish_routed_failover_order(&db, &f, both_peers).unwrap());
    let active = Journal::read(&db).unwrap();
    let objects_added = objects(&active.installed);
    let baseline = objects(&original.installed);
    assert_eq!(objects_added.symmetric_difference(&baseline).count(), 2);
    assert!(objects_added.symmetric_difference(&baseline).all(Object::fixed_mss));
    assert_eq!(path(&f, "203.0.113.4"), "awg0");

    // A crash after the new journal was saved can leave the marker behind.
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["rust_static_routing"][failover_order::FIELD] = marker;
        Ok(())
    }).unwrap();
    let changes = f.0.lock().unwrap().changes;
    assert!(finish_routed_failover_order(&db, &f, both_peers).unwrap());
    assert_eq!(f.0.lock().unwrap().changes, changes);

    assert!(change(vec![]).unwrap());
    assert!(finish_routed_failover_order(&db, &f, both_peers).unwrap());
    assert_eq!(objects(&Journal::read(&db).unwrap().installed), baseline);
    assert_eq!(path(&f, "203.0.113.4"), "awg0");
}

#[test]
fn active_optional_transport_edit_keeps_the_authenticated_direct_path() {
    let (_dir, db, f) = setup();
    protect(&db);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let rows = doc["servers"].as_array_mut().unwrap();
        let template = rows[0].clone();
        for (slot, id) in [(1, "old-outer"), (2, "new-outer")] {
            let mut outer = template.clone();
            outer["id"] = json!(id);
            outer["config"]["client_iface"] = json!(format!("awg{slot}"));
            outer["config"]["endpoint"] = json!(format!("198.51.100.{}:443", 10 + slot));
            outer["config"]["routing"]["zones"] = json!([]);
            rows.push(outer);
        }
        rows[0]["config"]["client"]["double_tunnel_id"] = json!("old-outer");
        rows[0]["config"]["client"]["double_tunnel_mode"] = json!("automatic");
        Ok(())
    }).unwrap();
    for op in [Operation::Apply, Operation::Commit] {
        action(&db, &f, op, 10).unwrap();
    }
    let runtime = nfqws2_awg_profile::runtime::Runtime::new(
        std::path::Path::new("/unused-fixture-root"), Default::default(),
    );
    let change = nfqws2_awg_profile::Failover {
        double_tunnel_id: Some("new-outer".into()),
        double_tunnel_mode: Some("preferred".into()),
        ..Default::default()
    };
    let before = nfqws2_awg_profile::read(&db).unwrap();
    let changes = f.0.lock().unwrap().changes;
    let mut observations = 0;
    assert!(runtime.stage_active_failover_order(&db, "awg0", &change, |before, after, retained| {
        stage_routed_failover_order(&db, &f, before, after, "awg0", retained, |cfg, iface| {
            observations += 1;
            let mut live = peer(cfg, iface)?;
            if observations > 1 {
                live.endpoint = "198.51.100.100:443".parse().unwrap();
            }
            Ok(live)
        })
    }).is_err());
    assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), before);

    for (request, outer, mode) in [
        (change, "new-outer", "preferred"),
        (nfqws2_awg_profile::Failover {
            double_tunnel_id: Some(String::new()),
            ..Default::default()
        }, "", "last_resort"),
    ] {
        assert!(runtime.stage_active_failover_order(&db, "awg0", &request, |before, after, retained| {
            stage_routed_failover_order(&db, &f, before, after, "awg0", retained, peer)
        }).unwrap());
        assert!(finish_routed_failover_order(&db, &f, peer).unwrap());
        let doc = nfqws2_awg_profile::read(&db).unwrap();
        let client = &doc["servers"][0]["config"]["client"];
        assert_eq!(client["double_tunnel_id"], outer);
        assert_eq!(client["double_tunnel_mode"], mode);
        assert_eq!(path(&f, "203.0.113.4"), "awg0");
        assert_eq!(f.0.lock().unwrap().changes, changes);
    }
}

#[test]
fn active_reserve_priority_switches_only_the_selected_healthy_reserve() {
    for killswitch in [false, true] {
        let (_dir, db, f) = setup();
        redundant_policy(&db, killswitch);
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["servers"][0]["config"]["client"]["fallback_tunnel_ids"] =
                json!(["profile", "nested"]);
            doc["servers"][2]["config"]["client"]["standby"] = json!(false);
            doc["servers"][2]["config"]["routing"]["zones"] = json!([
                {"name":"independent","enabled":true,"ips":["203.0.113.20"]}
            ]);
            Ok(())
        }).unwrap();
        let peers = |cfg: &Value, iface: &str| {
            if iface == "awg0" {
                return Err(io::ErrorKind::NotConnected.into());
            }
            let mut ready = peer(cfg, "awg0")?;
            if iface == "awg1" {
                ready.allowed = vec!["203.0.113.1/32".into()];
            }
            Ok(ready)
        };
        for op in [Operation::Apply, Operation::Commit] {
            operate_at(&db, &f, op, 10, peers).unwrap();
        }
        let original = Journal::read(&db).unwrap();
        assert!(!original.installed.selected.is_empty());
        assert!(original.committed.selected.is_empty());
        assert_eq!(path(&f, "203.0.113.4"), "awg3");
        assert_eq!(path(&f, "203.0.113.1"), "awg1");
        let runtime = nfqws2_awg_profile::runtime::Runtime::new(
            std::path::Path::new("/unused-fixture-root"), Default::default(),
        );
        let edit = nfqws2_awg_profile::Failover {
            fallback_tunnel_ids: vec!["nested".into(), "profile".into()],
            ..Default::default()
        };
        assert!(runtime.stage_active_failover_order(&db, "awg0", &edit, |before, after, retained| {
            stage_routed_failover_order(&db, &f, before, after, "awg0", retained, peers)
        }).unwrap());
        {
            let mut router = f.0.lock().unwrap();
            router.fail_after = Some(router.changes + 1);
        }
        assert!(finish_routed_failover_order(&db, &f, peers).is_err());
        assert_eq!(Journal::read(&db).unwrap(), original);
        assert_eq!(path(&f, "203.0.113.4"), "awg3");
        assert_eq!(path(&f, "203.0.113.1"), "awg1");
        assert!(finish_routed_failover_order(&db, &f, peers).unwrap());
        let settled = Journal::read(&db).unwrap();
        assert!(!settled.installed.selected.is_empty());
        assert!(settled.committed.selected.is_empty());
        assert_eq!(settled.installed.revision, 2);
        assert_eq!(settled.committed.revision, 2);
        assert_eq!(path(&f, "203.0.113.4"), "awg2");
        assert_eq!(path(&f, "203.0.113.1"), "awg1");

        let remove = nfqws2_awg_profile::Failover {
            fallback_tunnel_ids: vec!["profile".into()],
            ..Default::default()
        };
        assert!(runtime.stage_active_failover_order(&db, "awg0", &remove, |before, after, retained| {
            stage_routed_failover_order(&db, &f, before, after, "awg0", retained, peers)
        }).unwrap());
        assert!(finish_routed_failover_order(&db, &f, peers).unwrap());
        let transferred = Journal::read(&db).unwrap();
        assert_eq!(transferred.installed.revision, 3);
        assert_eq!(transferred.installed.targets, settled.installed.targets);
        assert_eq!(path(&f, "203.0.113.4"), "awg3");
        assert_eq!(path(&f, "203.0.113.1"), "awg1");
        assert_eq!(path(&f, "203.0.113.20"), "awg2");
    }
}

#[test]
fn active_standby_promotion_keeps_the_confirmed_route_without_kernel_writes() {
    let (_dir, db, f) = setup();
    redundant_policy(&db, true);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["config"]["client"]["fallback_tunnel_ids"] = json!(["nested", "profile"]);
        Ok(())
    }).unwrap();
    let candidates = |cfg: &Value, iface: &str| {
        if iface == "awg0" {
            return Err(io::ErrorKind::NotConnected.into());
        }
        peer(cfg, "awg0")
    };
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &f, op, 10, candidates).unwrap();
    }
    let before = Journal::read(&db).unwrap();
    let writes = f.0.lock().unwrap().changes;
    assert_eq!(path(&f, "203.0.113.4"), "awg2");

    let runtime = nfqws2_awg_profile::runtime::Runtime::new(
        std::path::Path::new("/unused-fixture-root"), Default::default(),
    );
    let edit = nfqws2_awg_profile::Failover::default();
    assert!(runtime.stage_active_failover_order(&db, "nested", &edit, |before, after, retained| {
        stage_routed_failover_order(&db, &f, before, after, "nested", retained, candidates)
    }).unwrap());
    assert!(finish_routed_failover_order(&db, &f, candidates).unwrap());
    let doc = nfqws2_awg_profile::read(&db).unwrap();
    assert_eq!(doc["servers"][2]["config"]["client"]["standby"], false);
    let after = Journal::read(&db).unwrap();
    assert_eq!(before.installed.selected, after.installed.selected);
    assert_eq!(objects(&before.installed), objects(&after.installed));
    assert_eq!(f.0.lock().unwrap().changes, writes);
    assert_eq!(path(&f, "203.0.113.4"), "awg2");

    // Profile's supervisor checks its own demand before this routing writer.
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let before = doc.clone();
        doc["servers"][2]["config"]["client"]["standby"] = json!(true);
        doc["routing_revision"] = json!(3);
        stage_routed_failover_order(&db, &f, &before, doc, "nested", None, candidates)
    }).unwrap();
    assert!(finish_routed_failover_order(&db, &f, candidates).unwrap());
    assert_eq!(nfqws2_awg_profile::read(&db).unwrap()["servers"][2]["config"]["client"]["standby"], true);
    assert_eq!(f.0.lock().unwrap().changes, writes);
    assert_eq!(path(&f, "203.0.113.4"), "awg2");
}

#[test]
fn active_optional_mode_edit_on_nested_path_requires_the_same_verified_outer() {
    let (_dir, db, f) = setup();
    protect(&db);
    let endpoint = "198.51.100.10:443".parse().unwrap();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let rows = doc["servers"].as_array_mut().unwrap();
        let mut outer = rows[0].clone();
        outer["id"] = json!("outer");
        outer["config"]["client_iface"] = json!("awg1");
        outer["config"]["endpoint"] = json!("198.51.100.11:443");
        outer["config"]["routing"]["zones"] = json!([]);
        rows.push(outer);
        rows[0]["config"]["endpoint"] = json!(endpoint);
        rows[0]["config"]["client"]["double_tunnel_id"] = json!("outer");
        rows[0]["config"]["client"]["double_tunnel_mode"] = json!("automatic");
        Ok(())
    }).unwrap();
    let (socket_mark, _) = nfqws2_awg_profile::nested_socket_selector("awg0").unwrap();
    let witness = nfqws2_awg_profile::RoutedNestedTransport {
        peer: nfqws2_awg_profile::RoutedMtuPeer {
            iface: "awg0".into(), outer_id: "outer".into(), outer_iface: "awg1".into(),
            endpoint, effective_mtu: 1370, socket_mark,
        },
        outer_endpoint: "198.51.100.11:443".parse().unwrap(),
    };
    let peers = |cfg: &Value, iface: &str| {
        let mut live = peer(cfg, iface)?;
        live.nested_mtu = Some(1370);
        live.socket_mark = socket_mark;
        Ok(live)
    };
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &f, op, 10, peers).unwrap();
    }
    let before = nfqws2_awg_profile::read(&db).unwrap();
    let writes = f.0.lock().unwrap().changes;
    let runtime = nfqws2_awg_profile::runtime::Runtime::new(
        std::path::Path::new("/unused-fixture-root"), Default::default(),
    );
    let edit = nfqws2_awg_profile::Failover {
        double_tunnel_mode: Some("preferred".into()), ..Default::default()
    };
    let stage = |witness| runtime.stage_active_failover_order(&db, "awg0", &edit, |before, after, _| {
        stage_routed_failover_order(&db, &f, before, after, "awg0", witness, peers)
    });
    assert!(stage(None).is_err());
    let mut wrong = witness.clone();
    wrong.peer.outer_iface = "awg2".into();
    assert!(stage(Some(&wrong)).is_err());
    assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), before);
    assert!(stage(Some(&witness)).unwrap());
    assert!(finish_routed_failover_order(&db, &f, peers).unwrap());
    assert_eq!(nfqws2_awg_profile::read(&db).unwrap()["servers"][0]["config"]["client"]["double_tunnel_mode"], "preferred");
    assert_eq!(path(&f, "203.0.113.4"), "awg0");
    assert_eq!(f.0.lock().unwrap().changes, writes);
}

#[test]
fn removing_the_selected_alternate_uses_only_a_verified_receiver_on_loss() {
    let (_dir, db, f) = setup();
    protect(&db);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let rows = doc["servers"].as_array_mut().unwrap();
        for (slot, id) in [(1, "first"), (2, "second")] {
            let mut reserve = rows[0].clone();
            reserve["id"] = json!(id);
            reserve["config"]["client_iface"] = json!(format!("awg{slot}"));
            reserve["config"]["routing"]["zones"] = json!([]);
            rows.push(reserve);
        }
        rows[0]["config"]["client"]["fallback_tunnel_ids"] = json!(["first", "second"]);
        Ok(())
    }).unwrap();
    let peers = |cfg: &Value, iface: &str| {
        if iface == "awg0" {
            return Err(io::ErrorKind::NotConnected.into());
        }
        peer(cfg, "awg0")
    };
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &f, op, 10, peers).unwrap();
    }
    let prior = Journal::read(&db).unwrap();
    let writes = f.0.lock().unwrap().changes;
    assert_eq!(path(&f, "203.0.113.4"), "awg1");
    let runtime = nfqws2_awg_profile::runtime::Runtime::new(
        std::path::Path::new("/unused-fixture-root"), Default::default(),
    );
    let change = nfqws2_awg_profile::Failover {
        fallback_tunnel_ids: vec!["second".into()],
        ..Default::default()
    };
    assert!(runtime.stage_active_failover_order(&db, "awg0", &change, |before, after, retained| {
        stage_routed_failover_order(&db, &f, before, after, "awg0", retained, peers)
    }).unwrap());
    let pending = nfqws2_awg_profile::read(&db).unwrap();
    let marker = pending["rust_static_routing"][failover_order::FIELD].clone();
    assert!(finish_routed_failover_order(&db, &f, |_, _| {
        Err(io::ErrorKind::NotConnected.into())
    }).is_err());
    assert_eq!(Journal::read(&db).unwrap(), prior);
    assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), pending);
    assert_eq!(f.0.lock().unwrap().changes, writes);
    let former_offline = |cfg: &Value, iface: &str| {
        if iface == "awg1" {
            return Err(io::ErrorKind::NotConnected.into());
        }
        peers(cfg, iface)
    };
    {
        let mut router = f.0.lock().unwrap();
        router.fail_after = Some(router.changes + 1);
    }
    assert!(finish_routed_failover_order(&db, &f, former_offline).is_err());
    let recovered = Journal::read(&db).unwrap();
    assert_eq!(recovered.installed.revision, prior.installed.revision);
    assert_eq!(recovered.installed.reserves, prior.installed.reserves);
    assert_eq!(path(&f, "203.0.113.4"), "awg2");

    assert!(finish_routed_failover_order(&db, &f, former_offline).unwrap());
    let next = Journal::read(&db).unwrap();
    assert!(!next.installed.targets.contains_key("awg1"));
    assert_eq!(path(&f, "203.0.113.4"), "awg2");

    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["rust_static_routing"][failover_order::FIELD] = marker;
        Ok(())
    }).unwrap();
    assert!(finish_routed_failover_order(&db, &f, |_, _| panic!("journal already committed")).unwrap());
    assert_eq!(Journal::read(&db).unwrap(), next);
    assert_eq!(path(&f, "203.0.113.4"), "awg2");
}

#[test]
fn automatic_routing_prefers_verified_ordinary_reserve_without_losing_nested_coverage() {
    let (_dir, db, f) = setup();
    check_automatic_routing_preference(&db, &f, |destination, iface| {
        assert_eq!(path(&f, destination), iface);
    });
}

fn check_automatic_routing_preference(
    db: &Store,
    runner: &dyn Runner,
    verify: impl Fn(&str, &str),
) {
    protect(db);
    nfqws2_awg_profile::edit_document(db, |doc| {
        let rows = doc["servers"].as_array_mut().unwrap();
        let template = rows[0].clone();
        for (slot, id) in [(1, "backup"), (2, "outer")] {
            let mut row = template.clone();
            row["id"] = json!(id);
            row["config"]["client_iface"] = json!(format!("awg{slot}"));
            row["config"]["endpoint"] = json!(format!("198.51.100.{}:443", 10 + slot));
            row["config"]["routing"]["zones"] = json!([]);
            rows.push(row);
        }
        let cfg = &mut rows[0]["config"];
        cfg["endpoint"] = json!("198.51.100.10:443");
        cfg["client"]["double_tunnel_id"] = json!("outer");
        cfg["client"]["double_tunnel_mode"] = json!("automatic");
        cfg["client"]["fallback_tunnel_ids"] = json!(["backup"]);
        cfg["routing"]["zones"] = json!([
            {"name":"both","enabled":true,"ips":["203.0.113.4","203.0.113.20"]}
        ]);
        Ok(())
    }).unwrap();
    let preferred = std::cell::Cell::new(false);
    let reserve_ready = std::cell::Cell::new(true);
    let observed = |cfg: &Value, iface: &str| {
        let mut live = peer(cfg, "awg0")?;
        if iface == "awg0" {
            live.socket_mark = nfqws2_awg_profile::nested_socket_selector(iface)?.0;
            live.nested_mtu = Some(1370);
            live.prefer_ordinary = preferred.get();
        } else {
            if !reserve_ready.get() {
                return Err(io::ErrorKind::NotConnected.into());
            }
            live.allowed = vec!["203.0.113.4/32".into()];
        }
        Ok(live)
    };
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(db, runner, op, 10, observed).unwrap();
    }
    verify("203.0.113.4", "awg0");
    preferred.set(true);
    operate_at(db, runner, Operation::Refresh, 11, observed).unwrap();
    verify("203.0.113.4", "awg1");
    verify("203.0.113.20", "awg0");
    reserve_ready.set(false);
    operate_at(db, runner, Operation::Refresh, 12, observed).unwrap();
    verify("203.0.113.4", "awg0");
    verify("203.0.113.20", "awg0");
    operate_at(db, runner, Operation::Teardown, 13, observed).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires a synthetic no-NIC Linux guest and isolated namespaces"]
fn automatic_verified_reserve_preserves_unmatched_real_fib() {
    assert!(std::path::Path::new("/synthetic-guest").is_file());
    for (kind, var) in [("net", "N2S_PARENT_NET"), ("mnt", "N2S_PARENT_MNT")] {
        let parent = std::env::var(var).unwrap();
        assert!(parent.starts_with(&format!("{kind}:[")));
        let current = std::fs::read_link(format!("/proc/self/ns/{kind}")).unwrap();
        assert_ne!(current.to_str(), Some(parent.as_str()));
    }
    struct LinuxRoutes(Fake);
    impl Runner for LinuxRoutes {
        fn run(&self, program: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
            if matches!(program, "iptables" | "ip6tables" | "sh") {
                self.0.run(program, args, deadline)
            } else {
                nfqws2_router_command::System.run(program, args, deadline)
            }
        }
    }
    let (_dir, db, fake) = setup();
    let runner = LinuxRoutes(fake);
    let k = kernel(&runner);
    check_automatic_routing_preference(&db, &runner, |destination, iface| {
        let route = k.call("ip", &["-4", "route", "get", destination]).unwrap();
        assert!(route.split_whitespace().collect::<Vec<_>>().windows(2).any(|fields| fields == ["dev", iface]));
    });
}

fn path(f: &Fake, dest: &str) -> String {
    f.0.lock().unwrap().forward("192.168.1.42", dest).into()
}

#[test]
fn failover_selects_authenticated_grants_per_selector_and_prefers_primary_on_return() {
    let (_dir, db, f) = setup();
    redundant_policy(&db, true);
    // The zone-specific reserve covers only .1; the nested standby can carry .2.
    // A separate zone on the same primary has only its connection-level reserve.
    let secondary = [None, Some("203.0.113.1/32"), ALL, ALL];
    for op in [Operation::Apply, Operation::Commit] {
        refresh_with(&db, &f, op, secondary).unwrap();
    }
    assert_eq!(scheduled(&db).unwrap(), Schedule::Failover);
    assert_eq!(path(&f, "203.0.113.1"), "awg1");
    assert_eq!(path(&f, "203.0.113.2"), "awg2");
    assert_eq!(path(&f, "203.0.113.3"), "wan0");
    assert_eq!(path(&f, "203.0.113.4"), "awg3");
    assert!(inspect(&db, &f).unwrap().ready);
    let stable = f.0.lock().unwrap().changes;
    refresh_with(&db, &f, Operation::Refresh, secondary).unwrap();
    assert_eq!(f.0.lock().unwrap().changes, stable);
    {
        let mut fw = f.0.lock().unwrap();
        fw.watch_flow = Some(("192.168.1.42", "203.0.113.2"));
        fw.fail_after = Some(fw.changes + 3);
    }
    // A failed failback restores the old healthy peer.
    assert!(refresh_with(&db, &f, Operation::Refresh, [ALL; 4]).is_err());
    assert_eq!(path(&f, "203.0.113.2"), "awg2");
    refresh_with(&db, &f, Operation::Refresh, [ALL; 4]).unwrap();
    assert_eq!(path(&f, "203.0.113.2"), "awg0");
    assert_eq!(path(&f, "203.0.113.4"), "awg0");
    assert!(!f.0.lock().unwrap().leaked);
}

#[test]
fn failed_handover_parks_unverified_prior_peer_and_recovery_keeps_committed_identity() {
    let (_dir, db, f) = setup();
    redundant_policy(&db, true);
    for op in [Operation::Apply, Operation::Commit] {
        refresh_with(&db, &f, op, [ALL; 4]).unwrap();
    }
    {
        let mut fw = f.0.lock().unwrap();
        fw.watch_flow = Some(("192.168.1.42", "203.0.113.1"));
        fw.fail_after = Some(fw.changes + 2);
    }
    assert!(refresh_with(&db, &f, Operation::Refresh, [None, ALL, ALL, ALL]).is_err());
    assert_eq!(path(&f, "203.0.113.1"), "blackhole");
    assert!(!inspect(&db, &f).unwrap().active);
    assert!(Journal::read(&db).unwrap().preparing.is_empty());
    refresh_with(&db, &f, Operation::Refresh, [None, ALL, ALL, ALL]).unwrap();
    assert_eq!(path(&f, "203.0.113.1"), "awg1");
    // A changed profile key must not inherit the old receipt's authority,
    // even if its new peer would authenticate at the same interface address.
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][1]["config"]["public_key"] =
            json!("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=");
        doc["servers"][0]["config"]["routing"]["zones"][1]["fallback_tunnel_ids"] = json!([]);
        Ok(())
    })
    .unwrap();
    refresh_with(&db, &f, Operation::Refresh, [None, ALL, ALL, None]).unwrap();
    assert_eq!(path(&f, "203.0.113.1"), "awg2");
    refresh_with(&db, &f, Operation::Refresh, [None; 4]).unwrap();
    assert_eq!(path(&f, "203.0.113.1"), "blackhole");
    assert_eq!(path(&f, "203.0.113.3"), "wan0");
    assert!(!f.0.lock().unwrap().leaked);
    let mut rebooted = Firmware {
        boot: "10101010-1010-1010-1010-101010101010".into(),
        ..Default::default()
    };
    std::mem::swap(&mut *f.0.lock().unwrap(), &mut rebooted);
    refresh_with(&db, &f, Operation::Recover, [None, ALL, None, ALL]).unwrap();
    assert_eq!(path(&f, "203.0.113.1"), "awg3");
}

#[test]
fn all_unavailable_without_killswitch_falls_through_and_keeps_recovery_armed() {
    let (_dir, db, f) = setup();
    redundant_policy(&db, false);
    assert!(refresh_with(&db, &f, Operation::Apply, [None; 4]).is_err());
    assert!(Journal::read(&db).unwrap().idle());
    for op in [Operation::Apply, Operation::Commit] {
        refresh_with(&db, &f, op, [ALL; 4]).unwrap();
    }
    refresh_with(&db, &f, Operation::Refresh, [None; 4]).unwrap();
    assert_eq!(path(&f, "203.0.113.1"), "wan0");
    assert_eq!(scheduled(&db).unwrap(), Schedule::Failover);
    refresh_with(&db, &f, Operation::Refresh, [None, None, None, ALL]).unwrap();
    assert_eq!(path(&f, "203.0.113.1"), "awg3");
}

#[test]
fn scoped_failover_rejects_foreign_backup_table_and_preserves_unselected_sources() {
    let (_dir, db, f) = setup();
    redundant_policy(&db, true);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        for zone in doc["servers"][0]["config"]["routing"]["zones"]
            .as_array_mut()
            .unwrap()
        {
            zone["source_ips"] = json!(["192.168.1.0/24"]);
        }
        Ok(())
    })
    .unwrap();
    f.0.lock().unwrap().local = "2: br0 inet 192.168.1.1/24 scope global".into();
    for op in [Operation::Apply, Operation::Commit] {
        refresh_with(&db, &f, op, [ALL; 4]).unwrap();
    }
    let before = {
        let mut fw = f.0.lock().unwrap();
        fw.foreign_route = "10.5.6.0/24 dev adminvpn table 17844 proto static".into();
        fw.changes
    };
    assert!(refresh_with(&db, &f, Operation::Refresh, [None, ALL, ALL, ALL]).is_err());
    {
        let mut fw = f.0.lock().unwrap();
        assert_eq!(fw.changes, before);
        assert!(fw.foreign_route.contains("adminvpn"));
        fw.foreign_route.clear();
        fw.watch_flow = Some(("192.168.1.42", "203.0.113.1"));
    }
    refresh_with(&db, &f, Operation::Refresh, [None, ALL, ALL, ALL]).unwrap();
    let saved = nfqws2_awg_profile::read(&db).unwrap();
    let receipt = &saved["rust_static_routing"];
    assert_eq!(receipt["active_reserves"], json!(["profile", "rule"]));
    assert_eq!(
        receipt["reserve_chains"]["awg0"],
        json!([["profile"], ["rule", "nested", "profile"]])
    );
    let fw = f.0.lock().unwrap();
    assert_eq!(fw.forward("192.168.1.42", "203.0.113.1"), "awg1");
    assert_eq!(fw.forward("192.168.2.42", "203.0.113.1"), "wan0");
    assert_eq!(fw.forward("192.168.1.42", "203.0.113.3"), "wan0");
    assert!(!fw.leaked);
}
#[test]
fn source_subnets_to_shared_destinations_preserve_order_direct_and_other_clients() {
    let (_tmp, db, f) = setup();
    scoped_policy(&db);
    f.0.lock().unwrap().local = "2: br0 inet 192.168.1.1/24 scope global".into();
    let now = nfqws2_awg_profile::now();
    let op = |what| operate_at(&db, &f, what, now, both_peers);
    op(Operation::Apply).unwrap();
    op(Operation::Commit).unwrap();
    let check = || {
        let fw = f.0.lock().unwrap();
        assert!(!fw.rule);
        assert_eq!(fw.forward("192.168.1.7", "203.0.113.9"), "wan0");
        assert_eq!(fw.forward("192.168.1.7", "203.0.113.10"), "awg0");
        assert_eq!(fw.forward("192.168.1.8", "203.0.113.9"), "awg0");
        assert_eq!(fw.forward("192.168.1.200", "203.0.113.9"), "awg1");
        assert_eq!(fw.forward("192.168.2.8", "203.0.113.9"), "wan0");
        assert_eq!(fw.forward("192.168.1.7", "203.0.112.233"), "wan0");
        assert!(fw.firewall["nat"]
            .iter()
            .all(|r| r.contains(" -s ") && r.contains(" -d ")));
        assert!(fw.firewall["filter"]
            .iter()
            .all(|r| r.contains(" -s ") && r.contains(" -d ")));
    };
    check();
    op(Operation::Suspend).unwrap();
    op(Operation::Recover).unwrap();
    check();
    op(Operation::Teardown).unwrap();
    let fw = f.0.lock().unwrap();
    assert!(fw.scoped_rules.is_empty() && fw.scoped_routes.is_empty());
}
#[test]
fn scoped_foreign_table_and_lookup_failures_restore_original_global_policy() {
    let (_tmp, db, f) = setup();
    let now = nfqws2_awg_profile::now();
    let op = |what| operate_at(&db, &f, what, now, both_peers);
    op(Operation::Apply).unwrap();
    op(Operation::Commit).unwrap();
    scoped_policy(&db);
    {
        let mut fw = f.0.lock().unwrap();
        fw.local = "2: br0 inet 192.168.1.1/24 scope global".into();
        fw.foreign_route = "203.0.113.0/24 dev awg7 table 17843 proto 242 scope link".into();
    }
    let changes = f.0.lock().unwrap().changes;
    assert!(op(Operation::Apply).is_err());
    assert_eq!(f.0.lock().unwrap().changes, changes);
    {
        let mut fw = f.0.lock().unwrap();
        fw.foreign_route.clear();
        fw.fail_selector_once = true;
    }
    assert!(op(Operation::Apply).is_err());
    f.0.lock().unwrap().bad_lookup = true;
    assert!(op(Operation::Apply).is_err());
    let fw = f.0.lock().unwrap();
    assert!(fw.rule && fw.scoped_rules.is_empty() && fw.scoped_routes.is_empty());
    assert_eq!(fw.routes["203.0.113.0/24"], "awg0");
    assert!(Journal::read(&db).unwrap().preparing.is_empty());
}
#[test]
fn scoped_direct_exception_to_global_vpn_preserves_outside_sources_and_destinations() {
    let (_tmp, db, f) = setup();
    nfqws2_awg_profile::edit_document(&db, |doc|{
        let zones=doc["servers"][0]["config"]["routing"]["zones"].as_array_mut().unwrap();
        zones.insert(0,json!({"enabled":true,"route":"direct","ips":["203.0.113.8/30"],"source_ips":["192.168.1.5/30"]}));
        Ok(())
    }).unwrap();
    action(&db, &f, Operation::Apply, 10).unwrap();
    let fw = f.0.lock().unwrap();
    assert_eq!(fw.forward("192.168.1.4", "203.0.113.9"), "wan0");
    assert_eq!(fw.forward("192.168.1.8", "203.0.113.9"), "awg0");
    assert_eq!(fw.forward("192.168.1.4", "203.0.113.12"), "awg0");
    assert_eq!(fw.forward("192.168.1.4", "198.51.100.10"), "wan0");
}
