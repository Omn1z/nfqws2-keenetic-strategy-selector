use super::super::learning::Member;
use super::*;
use std::net::Ipv4Addr;
#[path = "marked_recovery.rs"]
pub(super) mod marked_recovery;

#[test]
fn expanded_global_list_and_a_later_default_use_the_same_verified_packed_fib() {
    let (_root, db, _) = setup();
    let mut doc = nfqws2_awg_profile::read(&db).unwrap();
    doc["servers"][0]["config"]["endpoint"] = json!("198.51.100.10:443");
    let mut p = crate::policy::current(&doc).unwrap();
    let owner = p.zones[0].tunnel_id.clone();
    p.zones[0].source_key = Some("expanded".into());
    p.zones[0].ips = (0..300)
        .map(|i| Ipv4Addr::from(u32::from(Ipv4Addr::new(203, 0, 112, 0)) + i).to_string())
        .collect();
    p.zones.push(crate::Zone {
        enabled: true,
        tunnel_id: owner,
        route: "direct".into(),
        domains: vec!["*".into()],
        ..Default::default()
    });
    let result =
        plan::compile_effective(&doc, p.clone(), None, false, &[], Default::default()).unwrap();
    assert!(result.ordered_default && result.packed && result.scoped.is_empty());
    assert_eq!(result.prefixes.len(), 300);
    let claims = objects(&result);
    assert!(
        claims.contains(&Object::FullGuard(super::super::full::Guard::Main(
            plan::Family::V4
        )))
    );
    assert!(claims.contains(&Object::PackedLookup(plan::Family::V4)));
    assert!(claims.contains(&Object::Set(plan::Family::V4, "awg0".into())));
    p.zones[0].source_ips = vec!["192.168.1.2".into()];
    let compacted =
        plan::compile_effective(&doc, p.clone(), None, false, &[], Default::default()).unwrap();
    assert!(compacted.ordered_default && !compacted.packed && compacted.scoped.len() < 10);
    for n in 0..302 {
        let ip = Ipv4Addr::from(u32::from(Ipv4Addr::new(203, 0, 112, 0)) + n).into();
        assert_eq!(
            compacted.scoped.iter().any(|(s, _)| s.dest.contains(ip)),
            n < 300
        );
    }
    p.zones[0].ips.truncate(32);
    let scoped = plan::compile_effective(&doc, p, None, false, &[], Default::default()).unwrap();
    assert!(scoped.ordered_default && !scoped.packed && !scoped.scoped.is_empty());
}

#[test]
fn global_capacity_accepts_16384_hosts_and_64_interfaces_without_truncating() {
    let (_tmp, db, _) = setup();
    let mut doc = nfqws2_awg_profile::read(&db).unwrap();
    let mut p = crate::policy::current(&doc).unwrap();
    let template = p.zones[0].clone();
    let server = doc["servers"][0].clone();
    p.zones.clear();
    let mut servers = Vec::new();
    for i in 0..64 {
        let mut row = server.clone();
        let id = format!("t{i}");
        row["id"] = json!(id);
        row["config"]["client_iface"] = json!(format!("awg{i}"));
        let mut zone = template.clone();
        zone.tunnel_id = id;
        zone.source_key = Some("expanded".into());
        zone.ips = (0..256).map(|n| format!("77.1.{i}.{n}")).collect();
        p.zones.push(zone);
        servers.push(row);
    }
    doc["servers"] = json!(servers);
    let plan =
        plan::compile_effective(&doc, p.clone(), None, false, &[], Default::default()).unwrap();
    assert!(plan.packed);
    assert_eq!((plan.targets.len(), plan.prefixes.len()), (64, 16_384));
    plan.check_handoff_size().unwrap();
    p.zones[0].ips.push("77.2.0.1".into());
    let larger = plan::compile_effective(&doc, p, None, false, &[], Default::default()).unwrap();
    assert_eq!((larger.marks.len(), larger.prefixes.len()), (64, 16_385));
}

#[test]
fn packed_firewall_rules_preserve_the_tunnel_and_lan_interfaces() {
    use crate::kernel::inventory::Firewall;
    for (kind, expected) in [
        (Firewall::Nat, vec!["-o", "awg2"]),
        (Firewall::Out, vec!["-i", "br+", "-o", "awg2"]),
        (Firewall::In, vec!["-i", "awg2", "-o", "br+"]),
        (Firewall::Clamp, vec!["-o", "awg2", "-p", "tcp"]),
    ] {
        let object = Object::SetFirewall(plan::Family::V4, "awg2".into(), kind);
        let f = Fake::default();
        kernel(&f).mutate(&object, true).unwrap();
        let state = f.0.lock().unwrap();
        let rule = state.firewall.values().flatten().next().unwrap();
        let args: Vec<_> = rule.split_ascii_whitespace().collect();
        assert!(args.windows(expected.len()).any(|p| p == expected));
        assert!(args.windows(2).any(|p| p == ["-m", "set"]));
    }
}

#[test]
fn marked_65536_sparse_destinations_have_one_fib_and_do_not_capture_the_holes() {
    let (_dir, db, _) = setup();
    let doc = nfqws2_awg_profile::read(&db).unwrap();
    let mut p = crate::policy::current(&doc).unwrap();
    p.killswitch = false;
    let addr = |n: u32| Ipv4Addr::from(u32::from(Ipv4Addr::new(77, 16, 0, 0)) + 2 * n);
    p.zones[0].ips = (0..65536).map(|n| addr(n).to_string()).collect();
    let good =
        plan::compile_effective(&doc, p.clone(), None, false, &[], Default::default()).unwrap();
    let state = objects(&good);
    assert_eq!(good.prefixes.len(), 65536);
    assert_eq!(
        state
            .iter()
            .filter(|o| matches!(o, Object::SetMember(..)))
            .count(),
        65536
    );
    assert_eq!(
        state
            .iter()
            .filter(|o| matches!(o, Object::Route(..)))
            .count(),
        1
    );
    assert_eq!(
        state
            .iter()
            .filter(|o| matches!(o, Object::MarkLookup(..)))
            .count(),
        1
    );
    assert!(state.iter().all(|o| !matches!(o, Object::PackedLookup(_))));
    assert!(!good
        .prefixes
        .contains_key(&plan::Prefix::host(Ipv4Addr::new(77, 16, 0, 1))));
    let router = Router::default();
    let k = kernel(&router);
    let empty = BTreeSet::new();
    synchronize(&k, &empty, &state).unwrap();
    assert!(k.inventory(&state, true).unwrap() == state);
    k.verify_forward(&good).unwrap();
    assert_eq!(router.ip.0.lock().unwrap().scoped_routes.len(), 1);
    // No per-address route lookup; full membership is proven by ipset save.
    assert!(
        router
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(c, _)| c.contains("route get"))
            .count()
            < 8
    );
    synchronize(&k, &state, &empty).unwrap();
    assert!(k.inventory(&state, false).unwrap().is_empty());
    let mut direct = p.zones[0].clone();
    direct.ips = vec![addr(42).to_string()];
    direct.route = "direct".into();
    p.zones.insert(0, direct);
    let ordered =
        plan::compile_effective(&doc, p.clone(), None, false, &[], Default::default()).unwrap();
    assert_eq!(ordered.prefixes.len(), 65535);
    assert!(!ordered.prefixes.contains_key(&plan::Prefix::host(addr(42))));
    p.zones[1].ips.push(addr(65536).to_string());
    assert!(plan::compile_effective(&doc, p, None, false, &[], Default::default()).is_err());
}

#[test]
fn marked_activation_and_failover_verify_sets_and_recover_atomic_switch() {
    use std::sync::atomic::Ordering;
    let (_dir, db, _) = setup();
    let mut doc = nfqws2_awg_profile::read(&db).unwrap();
    let mut standby = doc["servers"][0].clone();
    standby["id"] = json!("cold");
    standby["config"]["client_iface"] = json!("awg1");
    standby["config"]["client"]["standby"] = json!(true);
    standby["config"]["routing"]["zones"] = json!([]);
    doc["servers"].as_array_mut().unwrap().push(standby);
    doc["servers"][0]["config"]["client"]["fallback_tunnel_ids"] = json!(["cold"]);
    doc["routing"]["killswitch"] = json!(false);
    doc["routing"]["domain_source"] = json!("dnsproxy");
    doc["servers"][0]["config"]["routing"]["zones"] = json!([{"enabled":true,"route":"tunnel","domains":["*.example.test"],"ips":["77.7.7.2","77.7.7.4","77.7.7.6","77.7.7.8","77.7.7.10","77.7.7.12","77.7.7.14","77.7.7.16","77.7.7.18","77.7.7.20","77.7.7.22","77.7.7.24"]}]);
    let mut plan = plan::compile_with_layout(
        &doc,
        None,
        false,
        &[],
        plan::Layout {
            packed: true,
            ..Default::default()
        },
    )
    .unwrap();
    plan.assign_marks(&Default::default()).unwrap();
    let primary = objects(&plan);
    let router = Router::default();
    let k = kernel(&router);
    let empty = BTreeSet::new();
    router.fail_set.store(true, Ordering::Relaxed);
    assert!(synchronize(&k, &empty, &primary).is_err());
    let partial = k.inventory(&primary, false).unwrap();
    assert!(!partial.is_empty() && !partial.iter().any(|o| matches!(o, Object::Classifier(..))));
    synchronize(&k, &partial, &empty).unwrap();
    assert!(router.sets.lock().unwrap().is_empty());
    synchronize(&k, &empty, &primary).unwrap();
    assert_eq!(k.inventory(&primary, true).unwrap(), primary);
    k.verify_forward(&plan).unwrap();
    let failover = plan::restore(&doc, &plan, Some(&plan), None, |cfg, iface| {
        if iface == "awg0" {
            return Err(io::ErrorKind::NotConnected.into());
        }
        peer(cfg, "awg0")
    })
    .unwrap()
    .plan;
    assert!(failover
        .flows()
        .all(|(s, i)| failover.effective(s, i) == Some("awg1")));
    let next = objects(&failover);
    let claims = primary.union(&next).cloned().collect();
    router.fail_switch.store(true, Ordering::Relaxed);
    assert!(synchronize(&k, &primary, &next).is_err());
    let half = k.inventory(&claims, false).unwrap();
    synchronize(&k, &half, &primary).unwrap();
    assert_eq!(k.inventory(&claims, true).unwrap(), primary);
    synchronize(&k, &primary, &next).unwrap();
    assert_eq!(k.inventory(&claims, true).unwrap(), next);
    k.verify_forward(&failover).unwrap();
    synchronize(&k, &next, &empty).unwrap();
    assert!(k.inventory(&claims, false).unwrap().is_empty());
}

#[derive(Default)]
pub(super) struct Router {
    pub(super) ip: Fake,
    pub(super) sets: Mutex<BTreeMap<String, BTreeSet<String>>>,
    pub(super) calls: Mutex<Vec<(String, usize)>>,
    fail_batch: std::sync::atomic::AtomicBool,
    pub(super) classifier: Mutex<Vec<String>>,
    pub(super) mark_tables: Mutex<BTreeMap<String, u16>>,
    pub(super) fail_set: std::sync::atomic::AtomicBool,
    pub(super) fail_switch: std::sync::atomic::AtomicBool,
}
impl Router {
    /// Inspect the generated PREROUTING marks and the populated test ipsets.
    pub(super) fn packet_mark(&self, src: &str, dst: &str) -> Option<String> {
        let src = src.parse().unwrap();
        let dst = dst.parse().unwrap();
        let rules = self.classifier.lock().unwrap();
        let sets = self.sets.lock().unwrap();
        let mut mark = None;
        for rule in &*rules {
            let words: Vec<_> = rule.split_whitespace().collect();
            if !words.starts_with(&["-A", "PREROUTING"]) {
                continue;
            }
            if !words.windows(3).filter(|w| w[0] == "--match-set").all(|w| {
                let address = match w[2] {
                    "src" => src,
                    "dst" => dst,
                    _ => panic!("unexpected direction"),
                };
                sets[w[1]]
                    .iter()
                    .any(|p| p.parse::<plan::Prefix>().unwrap().contains(address))
            }) {
                continue;
            }
            if let Some(value) = words.windows(2).find(|w| w[0] == "--set-xmark") {
                mark = Some(value[1].to_owned());
            }
            if words.ends_with(&["-j", "ACCEPT"]) {
                break;
            }
        }
        mark
    }
}
impl Runner for Router {
    fn run(&self, program: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
        self.calls
            .lock()
            .unwrap()
            .push((format!("{program} {}", args.join(" ")), 0));
        if program != "ipset" {
            if program == "iptables" && args == ["-w", "-t", "mangle", "-S"] {
                return Ok(format!(
                    "{}\n{}",
                    self.classifier.lock().unwrap().join("\n"),
                    self.ip.run(program, args, deadline)?
                ));
            }
            if args == ["-o", "-N", "-4", "rule", "show"] {
                let marked = self
                    .mark_tables
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|(val, t)| format!("68: from all fwmark {val} lookup {t}"))
                    .collect::<Vec<_>>()
                    .join("\n");
                return Ok(marked
                    + "\n"
                    + &self.ip.run(program, args, deadline)?.replace(
                        "68: from all lookup 17842",
                        "68: from all fwmark 0/0x20000000 lookup 17842",
                    ));
            }
            if let ["-4", "rule", op, "pref", "68", "fwmark", val, "table", table] = args {
                if super::super::marked::slot(val, table).is_some() {
                    let id = table.parse().unwrap();
                    let mut tables = self.mark_tables.lock().unwrap();
                    if *op == "add" {
                        assert!(tables.insert(val.to_string(), id).is_none());
                    } else {
                        assert_eq!(tables.remove(*val), Some(id));
                    }
                    return Ok(String::new());
                }
            }
            if let ["-4", "route", "get", addr, "mark", mark] = args {
                if *mark != "0x20000000" {
                    let mask = format!("{mark}/0x1ff00000");
                    let tables = self.mark_tables.lock().unwrap();
                    let fw = self.ip.0.lock().unwrap();
                    let route = tables
                        .get(&mask)
                        .and_then(|t| fw.scoped_routes.get(&(*t, plan::Family::V4.any())))
                        .map_or("wan0", String::as_str);
                    return Ok(format!("{addr} dev {route}"));
                }
            }
            if let ["-4", "rule", op, "pref", "68", "fwmark", "0/0x20000000", "table", "17842"] =
                args
            {
                return self.ip.run(
                    program,
                    &["-4", "rule", op, "pref", "68", "table", "17842"],
                    deadline,
                );
            }
            return self.ip.run(program, args, deadline);
        }
        let sets = self.sets.lock().unwrap();
        match args {
            ["list", "-name"] => Ok(sets.keys().cloned().collect::<Vec<_>>().join("\n")),
            ["save", name] => {
                let mut text =
                    format!("create {name} hash:net family inet hashsize 1024 maxelem 65536");
                for addr in &sets[*name] {
                    text.push_str(&format!("\nadd {name} {addr}"));
                }
                Ok(text)
            }
            ["list", name, "-terse"] => {
                let ip = self.ip.0.lock().unwrap();
                let refs = ip
                    .firewall
                    .values()
                    .flatten()
                    .filter(|line| line.contains(name))
                    .count()
                    + self
                        .classifier
                        .lock()
                        .unwrap()
                        .iter()
                        .filter(|r| r.contains(name))
                        .count();
                Ok(format!("References: {refs}"))
            }
            _ => panic!("unexpected {args:?}"),
        }
    }
    fn run_input(
        &self,
        program: &str,
        args: &[&str],
        input: &[u8],
        _: Instant,
    ) -> io::Result<String> {
        let doc = std::str::from_utf8(input).unwrap();
        self.calls
            .lock()
            .unwrap()
            .push((format!("{program} {}", args.join(" ")), doc.lines().count()));
        let mut sets = self.sets.lock().unwrap();
        let mut ip = self.ip.0.lock().unwrap();
        let mut output = Vec::new();
        if program == "iptables-restore" {
            assert_eq!(args, ["--noflush"]);
            if doc.contains("n2s-awg-cidr") {
                let tab = doc
                    .lines()
                    .next()
                    .unwrap()
                    .strip_prefix('*')
                    .unwrap()
                    .to_string();
                let mut next = ip.firewall.get(&tab).cloned().unwrap_or_default();
                for line in doc.lines().skip(1).filter(|l| *l != "COMMIT") {
                    if let Some(body) = line.strip_prefix("-A ") {
                        assert!(next.insert(format!("-A {body}")));
                    } else {
                        let body = line.strip_prefix("-D ").unwrap();
                        assert!(next.remove(&format!("-A {body}")));
                    }
                }
                ip.firewall.insert(tab, next);
                return Ok(String::new());
            }
            let mut rules = self.classifier.lock().unwrap();
            let mut next = rules.clone();
            for line in doc.lines() {
                if let Some(line) = line.strip_prefix("-D ") {
                    let pos = next
                        .iter()
                        .position(|r| r == &format!("-A {line}"))
                        .unwrap();
                    next.remove(pos);
                } else if let Some(line) = line.strip_prefix("-I ") {
                    let (parent, body) = line.split_once(" 1 ").unwrap();
                    next.insert(0, format!("-A {parent} {body}"));
                } else {
                    assert!(matches!(line, "*mangle" | "COMMIT"));
                }
            }
            *rules = next;
            if self
                .fail_switch
                .swap(false, std::sync::atomic::Ordering::Relaxed)
            {
                return Err(io::Error::other("after atomic switch"));
            }
            return Ok(String::new());
        }
        for (index, line) in doc.lines().enumerate() {
            if program == "ipset"
                && index == 10
                && self
                    .fail_set
                    .swap(false, std::sync::atomic::Ordering::Relaxed)
            {
                return Err(io::Error::other("after partial set restore"));
            }
            // iproute2 may have committed the first rows when a later row fails.
            if program == "ip"
                && index == 10
                && self
                    .fail_batch
                    .swap(false, std::sync::atomic::Ordering::Relaxed)
            {
                return Err(io::Error::other("injected partial route batch failure"));
            }
            let words: Vec<_> = line.split_whitespace().collect();
            match (program, words.as_slice()) {
                ("ipset", ["create", n, "hash:net", ..]) => {
                    assert!(sets.insert(n.to_string(), Default::default()).is_none());
                }
                ("ipset", ["add", n, p]) => {
                    assert!(sets.get_mut(*n).unwrap().insert(p.to_string()));
                }
                ("ipset", ["del", n, p]) => {
                    assert!(sets.get_mut(*n).unwrap().remove(*p));
                }
                ("ipset", ["destroy", n]) => {
                    assert!(sets.remove(*n).unwrap().is_empty());
                }
                ("ip", ["route", "add", "table", "17842", p, "dev", iface, "proto", "242"]) => {
                    assert!(ip.routes.insert(p.to_string(), iface.to_string()).is_none());
                }
                ("ip", ["route", "del", "table", "17842", p, "dev", iface, "proto", "242"]) => {
                    assert_eq!(ip.routes.remove(*p).as_deref(), Some(*iface));
                }
                ("ip", ["route", "get", p]) => {
                    assert!(ip.rule);
                    let route = ip.routes.get(&format!("{p}/32")).unwrap();
                    output.push(format!("{p} dev {route} src 192.0.2.1"));
                }
                _ => panic!("unexpected batch row {line}"),
            }
        }
        Ok(output.join("\n"))
    }
}

#[test]
fn standby_transport_keeps_ordinary_host_route_and_requires_mark_if_active() {
    let (_root, db, _) = setup();
    let mut doc = nfqws2_awg_profile::read(&db).unwrap();
    let ip: std::net::IpAddr = "203.0.113.17".parse().unwrap();
    let mut standby = doc["servers"][0].clone();
    standby["id"] = json!("cold");
    standby["config"]["client_iface"] = json!("awg1");
    standby["config"]["endpoint"] = json!("203.0.113.17:51820");
    standby["config"]["client"]["standby"] = json!(true);
    standby["config"]["routing"]["zones"] = json!([]);
    doc["servers"].as_array_mut().unwrap().push(standby);
    doc["routing"]["domain_source"] = json!("dnsproxy");
    doc["routing"]["killswitch"] = json!(false);
    let cfg = &mut doc["servers"][0]["config"];
    cfg["routing"]["zones"][0]["ips"] = json!([ip]);
    cfg["routing"]["zones"][0]["domains"] = json!(["*.example.test"]);
    cfg["client"]["fallback_tunnel_ids"] = json!(["cold"]);
    let plan = plan::compile_with_layout(
        &doc,
        None,
        false,
        &[],
        plan::Layout {
            packed: true,
            go_ipv4: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(plan.packed);
    assert!(plan
        .reject_active_overlap(&doc, &BTreeSet::from(["cold".into()]))
        .is_err());
    assert!(plan.reject_active_overlap(&doc, &BTreeSet::new()).is_ok());
    let run = |doc: &Value, mark| {
        plan::resolve(doc, plan.clone(), false, None, |cfg, iface| {
            if iface == "awg0" {
                return peer(cfg, iface);
            }
            Ok(LivePeer {
                ipv6_reachable: true,
                nested_mtu: None,
                prefer_ordinary: false,
                nested_transport: None,
                direct_backup: None,
                endpoint_predecessor: None,
                fresh_bound_ipv6_probe: None,
                active_replacement_peer: None,
                endpoint: (ip, 51820).into(),
                allowed: vec!["0.0.0.0/0".into()],
                socket_mark: mark,
            })
        })
    };
    assert!(run(&doc, 0).is_err());
    let proven = run(&doc, nfqws2_awg_profile::DIRECT_SOCKET_MARK).unwrap();
    assert_eq!(proven.plan.socket_bypass, BTreeSet::from([ip]));
    assert_eq!(proven.plan.prefixes[&plan::Prefix::host(ip)], "awg0");
    assert!(objects(&proven.plan).contains(&Object::PackedLookup(plan::Family::V4)));
    doc["servers"][1]["config"]["client"]["standby"] = json!(false);
    assert!(run(&doc, nfqws2_awg_profile::DIRECT_SOCKET_MARK).is_err());
}

#[test]
fn large_keenetic_handoff_adds_dns_with_constant_process_count_and_rejects_foreign_members() {
    let (_root, db, _) = setup();
    let addr = |n: u32| Ipv4Addr::from(u32::from(Ipv4Addr::new(77, 80, 0, 0)) + n);
    let mut static_addrs: Vec<_> = (0..114).map(|n| addr(n).to_string()).collect();
    static_addrs
        .extend(["10.0.3.42", "100.64.0.0/12", "192.168.0.20", "172.16.0.16"].map(str::to_owned));
    nfqws2_awg_profile::edit_document(&db,|d|{
        d["routing"]["domain_source"]=json!("dnsproxy");
        d["routing"]["killswitch"]=json!(false);
        d["servers"][0]["config"]["routing"]["zones"]=json!([{"enabled":true,"name":"relay","route":"tunnel","domains":["*.example.test"],"ips":static_addrs}]);
        Ok(())
    }).unwrap();
    let now = nfqws2_awg_profile::now();
    let members: Vec<_> = (114..1112)
        .map(|n| Member {
            zone: 0,
            ip: addr(n).into(),
            until: now + 3600,
        })
        .collect();
    let doc = nfqws2_awg_profile::read(&db).unwrap();
    let plan = plan::compile_policy(
        &doc,
        crate::policy::current(&doc).unwrap(),
        1,
        None,
        &members,
        false,
    )
    .unwrap();
    assert!(plan.packed && plan.prefixes.len() == 1112);
    assert!(plan::restore(&doc, &plan, None, None, |_, _| Ok(LivePeer {
        ipv6_reachable: true,
        nested_mtu: None,
        prefer_ordinary: false,
        nested_transport: None,
        direct_backup: None,
        endpoint_predecessor: None,
        fresh_bound_ipv6_probe: None,
        active_replacement_peer: None,
        socket_mark: 0,
        endpoint: (addr(2), 443).into(),
        allowed: vec!["0.0.0.0/0".into()]
    }))
    .is_err());
    let router = Router::default();
    let installed = Journal {
        boot: BOOT.into(),
        installed: plan.clone().into(),
        committed: plan.into(),
        ..Default::default()
    };
    let before = Journal {
        boot: BOOT.into(),
        ..Journal::default()
    };
    router
        .fail_batch
        .store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(db
        .transaction(|tx| transition(&db, tx, &router, &before, &installed, None))
        .is_err());
    assert!(router.sets.lock().unwrap().is_empty());
    assert!(router.ip.0.lock().unwrap().routes.is_empty());
    assert!(Journal::read(&db).unwrap().idle());
    router.calls.lock().unwrap().clear();
    db.transaction(|tx| transition(&db, tx, &router, &before, &installed, None))
        .unwrap();
    assert_eq!(router.sets.lock().unwrap()["n2srt4_awg0"].len(), 1112);
    assert_eq!(
        router
            .ip
            .0
            .lock()
            .unwrap()
            .firewall
            .values()
            .flatten()
            .count(),
        4
    );
    let mut calls = router.calls.lock().unwrap();
    assert!(calls.len() < 40, "initial calls {}", calls.len());
    assert!(calls.contains(&("ip -4 -batch -".into(), 1112)));
    assert!(calls
        .iter()
        .any(|(command, _)| command.contains("rule add pref 68 fwmark 0/0x20000000")));
    calls.clear();
    drop(calls);
    let answer = [addr(1112).into()];
    learn_answer(
        &db,
        &router,
        Answer {
            revision: 1,
            zone: 0,
            addresses: &answer,
            ttl: 300,
            qtype: 1,
        },
        peer,
        || Ok(()),
    )
    .unwrap();
    let calls = router.calls.lock().unwrap();
    assert!(calls.len() < 50, "DNS calls {}", calls.len());
    assert!(calls.contains(&("ipset restore".into(), 1)));
    assert!(calls.contains(&("ip -4 -batch -".into(), 1)));
    assert!(calls.contains(&("ip -o -4 -batch -".into(), 1)));
    drop(calls);
    let foreign = "91.200.100.10/32";
    router
        .sets
        .lock()
        .unwrap()
        .get_mut("n2srt4_awg0")
        .unwrap()
        .insert(foreign.into());
    assert!(operate_at(&db, &router, Operation::Teardown, now, peer).is_err());
    assert!(router.sets.lock().unwrap()["n2srt4_awg0"].contains(foreign));
    router
        .sets
        .lock()
        .unwrap()
        .get_mut("n2srt4_awg0")
        .unwrap()
        .remove(foreign);
    operate_at(&db, &router, Operation::Teardown, now, peer).unwrap();
    assert!(router.sets.lock().unwrap().is_empty());
    assert!(router.ip.0.lock().unwrap().routes.is_empty());
}
