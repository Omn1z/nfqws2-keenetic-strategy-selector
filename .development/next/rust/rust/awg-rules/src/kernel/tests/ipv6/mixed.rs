use super::*;
use crate::kernel::{handoff, legacy_scope};
use std::sync::atomic::Ordering;

const A: &str = "02:aa:22:33:44:55";
const B: &str = "02:bb:22:33:44:66";
const D: &str = "2001:db8:11::/48";
const T: &str = "2001:db8:22::/48";

#[test]
fn full_go_multi_handoff_keeps_only_observed_ipv6_reject_until_cold_boot() {
    const REJECT: &str = "-A FORWARD -o wan0 -m comment --comment \"awg2-v6-noleak\" -j REJECT --reject-with icmp6-adm-prohibited";
    const FOREIGN: &str = "-A FORWARD -s fd00::/8 -j ACCEPT";

    struct Go<'a> {
        router: &'a Dual,
        status: String,
        forward: String,
    }
    impl Runner for Go<'_> {
        fn run(&self, cmd: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
            match (cmd, args) {
                ("cat", ["/opt/var/run/nfqws2-strategy.pid"]) => Ok("31".into()),
                ("cat", ["/proc/31/stat"]) => Ok(format!("31 (n2s) {} 200", ["0"; 19].join(" "))),
                ("curl", _) => Ok(self.status.clone()),
                ("iptables", ["-t", "mangle", "-S", "PREROUTING"]) => {
                    Ok("-A PREROUTING -j AWG2_MULTI".into())
                }
                ("iptables", ["-t", "mangle", "-S", "AWG2_MULTI"]) => {
                    Ok("-A AWG2_MULTI -m set --match-set awgm_000 dst -g AWG2_TO_10100000".into())
                }
                ("ipset", ["save", "awgm_000"]) => {
                    Ok("create awgm_000 hash:net family inet\nadd awgm_000 203.0.113.9/32".into())
                }
                ("ip6tables", ["-w", "-t", "filter", "-S", "FORWARD"]) => Ok(self.forward.clone()),
                _ => self.router.run(cmd, args, deadline),
            }
        }
    }

    let (_dir, db, _) = setup();
    let router = Dual::default();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"] = json!({"mode":"full"});
        let row = &mut doc["servers"][0];
        row["config"]["routing"] = json!({"mode":"full","active":true,"zones":[
            {"enabled":true,"route":"tunnel","ips":["203.0.113.9"]}
        ]});
        row["applied_config"] = row["config"].clone();
        Ok(())
    }).unwrap();
    let doc = nfqws2_awg_profile::read(&db).unwrap();
    let policy = crate::policy::current(&doc).unwrap();
    let mut old = Go {
        router: &router,
        status: json!({
            "routing_config":policy, "routing_rules":policy.zones,
            "routing_state":{"revision":5,"ready":true,"applying":false},
            "servers":[{"id":doc["active_id"],"connected":true}]
        }).to_string(),
        forward: format!("{REJECT}\n{REJECT}\n{FOREIGN}"),
    };
    let port = 8090.try_into().unwrap();
    for invalid in [
        format!("{REJECT}\n{REJECT}\n{FOREIGN}"),
        format!("{FOREIGN}\n{REJECT}"),
        REJECT.replace("-o wan0", "-m mac --mac-source 02:00:00:00:00:01"),
    ] {
        old.forward = invalid;
        assert!(handoff::prepare_after(&db, &old, port, || {}, peer).is_err());
        assert!(!handoff::pending(&db).unwrap());
    }
    old.forward = FOREIGN.into();
    assert!(handoff::prepare_after(&db, &old, port, || {}, peer).unwrap());
    let runtime_capture = || db.read_runtime::<Value>("awg-go-handoff.json", 32 << 20).unwrap();
    assert!(runtime_capture()["go_multi_v6_reject"].is_null());
    old.forward = format!("{REJECT}\n{FOREIGN}");
    assert!(handoff::prepare_after(&db, &old, port, || {}, peer).unwrap());
    assert_eq!(runtime_capture()["go_multi_v6_reject"], "wan0");

    // Go has stopped and taken down its exact tagged reject. Rust can create
    // its own tagged rule while retaining the unrelated forwarding entry.
    let v6_filter = || router.v6.0.lock().unwrap().firewall["filter"].clone();
    router.v6.0.lock().unwrap().firewall.insert("filter".into(), BTreeSet::from([FOREIGN.into()]));
    let now = nfqws2_awg_profile::now();
    let now_plan = || Journal::read(&db).unwrap().installed;
    let fence = Object::LegacyV6Reject("wan0".into());
    let installed_fence = || objects(&now_plan()).contains(&fence);
    let step = |op, delay| operate_at(&db, &router, op, now + delay, peer).unwrap();
    step(Operation::Apply, 0);
    assert!(handoff::check_trial(&db, &router).is_ok());
    assert!(installed_fence());
    assert_eq!(v6_filter().len(), 2);
    assert!(v6_filter().contains(FOREIGN));
    {
        let fw = router.v4.0.lock().unwrap();
        assert_eq!(fw.forward("192.168.1.4", "203.0.113.9"), "awg0");
        assert_eq!(fw.forward("192.168.1.4", "8.8.8.8"), "wan0");
    }
    step(Operation::Commit, 1);
    handoff::finished(&db).unwrap();
    step(Operation::Suspend, 2);
    assert!(!installed_fence());
    assert_eq!(v6_filter(), BTreeSet::from([FOREIGN.into()]));
    step(Operation::Recover, 3);
    assert!(installed_fence());

    step(Operation::Suspend, 4);
    router.v4.0.lock().unwrap().boot = "34343434-3434-3434-3434-343434343434".into();
    step(Operation::Recover, 5);
    assert!(!installed_fence());
    assert_eq!(v6_filter(), BTreeSet::from([FOREIGN.into()]));
    step(Operation::Teardown, 6);
    assert_eq!(v6_filter(), BTreeSet::from([FOREIGN.into()]));
}

struct Lab {
    dual: Dual,
    sets: super::super::packed::Router,
    neighbour: Mutex<(String, String)>,
    lookups: Mutex<BTreeSet<String>>,
    v4_classifiers: Mutex<Vec<String>>,
    v4_lookups: Mutex<BTreeSet<String>>,
}
impl Default for Lab {
    fn default() -> Self {
        Self {
            dual: Default::default(),
            sets: Default::default(),
            neighbour: Mutex::new(("br0".into(), A.into())),
            lookups: Default::default(),
            v4_classifiers: Default::default(),
            v4_lookups: Default::default(),
        }
    }
}
impl Lab {
    fn topology(&self, cmd: &str, args: &[&str]) -> Option<String> {
        match (cmd, args) {
            ("sh", ["-c", p]) if p.contains("/sys/class/net/br*/bridge") => Some("br0\nbr1".into()),
            ("ip", ["-4", "neigh", "show"]) => {
                let n = self.neighbour.lock().unwrap();
                Some(format!("192.168.1.17 dev {} lladdr {} STALE", n.0, n.1))
            }
            ("ip", ["-6", "neigh", "show"]) => Some(String::new()),
            ("ip", ["-o", "-4", "addr", "show"]) => {
                Some("1: br0 inet 192.168.1.1/24\n2: br1 inet 192.168.2.1/24".into())
            }
            ("ip", ["-6", "addr", "show", "dev", "awg2", "scope", "global"]) => {
                Some("inet6 2001:db8:44::1/128 scope global".into())
            }
            _ => None,
        }
    }
    fn route(&self, ip: &str, mark: &str) -> io::Result<String> {
        let lookups = self.lookups.lock().unwrap();
        let fw = self.dual.v6.0.lock().unwrap();
        let route = if (mark == "0x1ff00000" && lookups.contains(legacy_scope::TUNNEL))
            || (mark == "0" && lookups.contains(legacy_scope::DEFAULT))
        {
            if let Some(dev) = fw.routes.get("::/0") {
                dev
            } else if fw.fence {
                return Err(io::ErrorKind::NetworkUnreachable.into());
            } else {
                "wan0"
            }
        } else if mark == "0" {
            fw.forward("fd00::2", ip)
        } else {
            "wan0"
        };
        Ok(format!("{ip} dev {route}"))
    }
    fn packet(&self, src: &str, bridge: &str, mac: &str, dest: &str) -> String {
        assert!(src.parse::<std::net::Ipv6Addr>().is_ok());
        let classifier = self.sets.classifier.lock().unwrap();
        let sets = self.sets.sets.lock().unwrap();
        let mut mark = "0";
        for row in &*classifier {
            let w = row.split_ascii_whitespace().collect::<Vec<_>>();
            let field = |k| w.windows(2).find(|p| p[0] == k).unwrap()[1];
            if field("-i") == bridge
                && field("--mac-source").eq_ignore_ascii_case(mac)
                && sets[field("--match-set")].iter().any(|s| {
                    s.parse::<crate::kernel::Prefix>()
                        .unwrap()
                        .contains(dest.parse().unwrap())
                })
            {
                mark = field("--set-xmark").split('/').next().unwrap();
                break;
            }
        }
        let dev = self.route(dest, mark).map_or_else(
            |_| "drop".to_owned(),
            |r| r.split_whitespace().last().unwrap().into(),
        );
        if dev == "wan0"
            && self
                .dual
                .v6
                .0
                .lock()
                .unwrap()
                .firewall
                .get("filter")
                .is_some_and(|r| r.iter().any(|s| s.contains("--reject-with")))
        {
            return "drop".into();
        }
        dev
    }
    fn route_v4(&self, ip: &str, mark: &str, end: Instant) -> io::Result<String> {
        let lookups = self.v4_lookups.lock().unwrap();
        if lookups.is_empty() && mark == "0" {
            return self.dual.run("ip", &["-4", "route", "get", ip], end);
        }
        let fw = self.dual.v4.0.lock().unwrap();
        let matching = mark == "0x1ff00000" && lookups.contains(legacy_scope::TUNNEL)
            || mark == "0" && (lookups.contains(legacy_scope::DEFAULT) || fw.mark_lookup);
        let dev = if matching
            && !fw
                .throws
                .iter()
                .any(|net| net.contains(ip.parse().unwrap()))
        {
            fw.routes
                .get("0.0.0.0/0")
                .map(String::as_str)
                .unwrap_or("wan0")
        } else {
            "wan0"
        };
        Ok(format!("{ip} dev {dev}"))
    }
    fn packet_v4(&self, source: &str, bridge: &str, dest: &str) -> String {
        let classifiers = self.v4_classifiers.lock().unwrap();
        let sets = self.sets.sets.lock().unwrap();
        let mark = classifiers
            .iter()
            .find_map(|row| {
                let words = row.split_ascii_whitespace().collect::<Vec<_>>();
                let arg = |key| words.windows(2).find(|p| p[0] == key).unwrap()[1];
                (arg("-i") == bridge
                    && arg("-s")
                        .parse::<Prefix>()
                        .unwrap()
                        .contains(source.parse().unwrap())
                    && sets[arg("--match-set")].iter().any(|ip| {
                        ip.parse::<Prefix>()
                            .unwrap()
                            .contains(dest.parse().unwrap())
                    }))
                .then(|| arg("--set-xmark").split_once('/').unwrap().0)
            })
            .unwrap_or("0");
        self.route_v4(dest, mark, Instant::now())
            .unwrap()
            .split_whitespace()
            .last()
            .unwrap()
            .into()
    }
}
impl Runner for Lab {
    fn run(&self, cmd: &str, args: &[&str], end: Instant) -> io::Result<String> {
        if let Some(r) = self.topology(cmd, args) {
            return Ok(r);
        }
        match (cmd, args) {
            ("ipset", ["list", set, "-terse"]) => {
                let existing = self.sets.run(cmd, args, end)?;
                let count = existing
                    .trim_start_matches("References: ")
                    .parse::<usize>()
                    .unwrap();
                let v4_count = self
                    .v4_classifiers
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|line| line.split_ascii_whitespace().any(|arg| arg == *set))
                    .count();
                Ok(format!("References: {}", count + v4_count))
            }
            ("ipset", ["save", set]) if set.starts_with("n2srt4_") => self.sets.run(cmd, args, end),
            ("ipset", _) => {
                let s = self.sets.run(cmd, args, end)?;
                Ok(s.replace("family inet ", "family inet6 "))
            }
            ("iptables", ["-w", "-t", "mangle", "-S"]) => Ok(format!(
                "{}\n{}",
                self.v4_classifiers.lock().unwrap().join("\n"),
                self.dual.run(cmd, args, end)?
            )),
            ("ip6tables", ["-w", "-t", "mangle", "-S"]) => Ok(format!(
                "{}\n{}",
                self.sets
                    .classifier
                    .lock()
                    .unwrap()
                    .join("\n")
                    .replace(&A.to_ascii_uppercase(), A)
                    .replace(&B.to_ascii_uppercase(), B),
                self.dual.run(cmd, args, end)?
            )),
            ("ip", ["-6", "rule", op, "pref", "68", "fwmark", mark, "table", "17842"])
                if matches!(*mark, legacy_scope::TUNNEL | legacy_scope::DEFAULT) =>
            {
                let mut seen = self.lookups.lock().unwrap();
                if *op == "add" {
                    assert!(seen.insert((*mark).into()));
                } else {
                    assert!(seen.remove(*mark));
                }
                Ok(String::new())
            }
            ("ip", ["-o", "-N", "-6", "rule", "show"]) => Ok(format!(
                "{}\n{}",
                self.lookups
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|m| format!("68: from all fwmark {m} lookup 17842"))
                    .collect::<Vec<_>>()
                    .join("\n"),
                self.dual.run(cmd, args, end)?
            )),
            ("ip", ["-6", "route", "get", addr, "mark", mark]) => self.route(addr, mark),
            ("ip", ["-6", "route", "get", addr]) => self.route(addr, "0"),
            ("ip", ["-4", "rule", op, "pref", "68", "fwmark", mark, "table", "17842"])
                if matches!(*mark, legacy_scope::TUNNEL | legacy_scope::DEFAULT) =>
            {
                let mut seen = self.v4_lookups.lock().unwrap();
                if *op == "add" {
                    assert!(seen.insert((*mark).into()));
                } else {
                    assert!(seen.remove(*mark));
                }
                Ok(String::new())
            }
            ("ip", ["-o", "-N", "-4", "rule", "show"]) => Ok(format!(
                "{}\n{}",
                self.v4_lookups
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|m| format!("68: from all fwmark {m} lookup 17842"))
                    .collect::<Vec<_>>()
                    .join("\n"),
                self.dual.run(cmd, args, end)?
            )),
            ("ip", ["-4", "route", "get", addr, "mark", mark @ ("0x1fe00000" | "0x1ff00000")]) => {
                self.route_v4(addr, mark, end)
            }
            (
                "ip",
                ["-4", "route", "get", addr, "from", "192.168.1.17", "iif", "br0", "mark", mark @ ("0x1fe00000" | "0x1ff00000")],
            ) => self.route_v4(addr, mark, end),
            ("ip", ["-4", "route", "get", addr]) => self.route_v4(addr, "0", end),
            _ => self.dual.run(cmd, args, end),
        }
    }
    fn run_input(
        &self,
        cmd: &str,
        args: &[&str],
        input: &[u8],
        end: Instant,
    ) -> io::Result<String> {
        match (cmd, args) {
            ("ipset", _) => self.sets.run_input(cmd, args, input, end),
            ("ip6tables-restore", _) => self.sets.run_input("iptables-restore", args, input, end),
            ("iptables-restore", ["--noflush"]) => {
                let body = std::str::from_utf8(input).unwrap();
                let mut rules = self.v4_classifiers.lock().unwrap();
                for line in body.lines() {
                    if let Some(line) = line.strip_prefix("-D ") {
                        let pos = rules
                            .iter()
                            .position(|r| r == &format!("-A {line}"))
                            .unwrap();
                        rules.remove(pos);
                    } else if let Some(line) = line.strip_prefix("-I PREROUTING 1 ") {
                        rules.insert(0, format!("-A PREROUTING {line}"));
                    } else {
                        assert!(matches!(line, "*mangle" | "COMMIT"));
                    }
                }
                Ok(String::new())
            }
            ("ip", [af, "-batch", "-"]) => {
                for l in std::str::from_utf8(input).unwrap().lines() {
                    let mut a = vec![*af];
                    a.extend(l.split_ascii_whitespace());
                    if let [family, "route", "replace", "table", table, net, "dev", iface, "proto", "242"] =
                        a.as_slice()
                    {
                        let firmware = if *family == "-4" {
                            &self.dual.v4
                        } else {
                            &self.dual.v6
                        };
                        let mut routes = firmware.0.lock().unwrap();
                        let replaced = if *table == "17842" {
                            routes.routes.insert((*net).into(), (*iface).into())
                        } else {
                            routes.scoped_routes.insert(
                                (table.parse().unwrap(), net.parse().unwrap()),
                                (*iface).into(),
                            )
                        };
                        assert!(replaced.is_some());
                        routes.changes += 1;
                        if routes.fail_after == Some(routes.changes) {
                            routes.fail_after = None;
                            return Err(io::Error::other("lost route replacement acknowledgement"));
                        }
                        continue;
                    }
                    self.dual.run(cmd, &a, end)?;
                }
                Ok(String::new())
            }
            _ => panic!("unexpected batch {cmd} {args:?}"),
        }
    }
}
struct Old<'a> {
    lab: &'a Lab,
    status: String,
    sets: bool,
    wrong: bool,
    dns: bool,
    broken_dns: bool,
}
impl Runner for Old<'_> {
    fn run(&self, cmd: &str, args: &[&str], end: Instant) -> io::Result<String> {
        if let Some(v) = self.lab.topology(cmd, args) {
            return Ok(v);
        }
        let go = handoff::LegacyTestRouter {
            dual: true,
            wrong_table: false,
            stranger: false,
        };
        match (cmd, args) {
            ("cat", ["/opt/var/run/nfqws2-strategy.pid"]) => Ok("31".into()),
            ("cat", ["/proc/31/stat"]) => Ok(format!("31 (n2s) {} 200", ["0"; 19].join(" "))),
            ("curl", _) => Ok(self.status.clone()),
            ("sh", ["-c", script]) if self.dns && script.contains("/sys/class/net/br*") => {
                Ok("br0\nbr1".into())
            }
            ("sh", ["-c", _, "dns-owner", "31"]) if self.dns => Ok("owned".into()),
            ("iptables" | "ip6tables", ["-w", "-t", "nat", "-S", ..]) if self.dns => {
                Ok(["br0", "br1"].into_iter().flat_map(|br| {
                    ["udp", "tcp"].into_iter().filter(move |proto| {
                        !self.broken_dns || br != "br1" || *proto != "tcp"
                    }).map(move |proto| format!("-A PREROUTING -i {br} -p {proto} -m {proto} --dport 53 -j REDIRECT --to-ports 5354"))
                }).collect::<Vec<_>>().join("\n"))
            }
            ("ipset", ["list", "-name"]) => Ok(if self.sets {
                if self.dns {"awg2_z0\nawg2_z0_6".into()}
                else { "awg2_z0\nawg2_z0_6\nawg2_z1\nawg2_z1_6".into() }
            } else {
                String::new()
            }),
            ("ipset", ["save", name]) => {
                let v6 = name.ends_with("_6");
                let mut r = format!(
                    "create {name} hash:net family {} hashsize 1024 maxelem 65536",
                    if v6 { "inet6" } else { "inet" }
                );
                if self.dns {
                    if !v6 {r += &format!("\nadd {name} 203.0.113.10");}
                } else if v6 {
                    r += &format!("\nadd {name} {D}");
                    if name.starts_with("awg2_z1") {
                        r += &format!("\nadd {name} {T}");
                    }
                }
                Ok(r)
            }
            ("iptables" | "ip6tables", ["-t", "mangle", "-S", ..])
            | ("iptables" | "ip6tables", ["-w", "-t", "mangle", "-S"]) => {
                let v6 = cmd == "ip6tables";
                let g = if v6 { "AWG2_MARK6" } else { "AWG2_MARK" };
                let base = go.run(cmd, &["-t", "mangle", "-S"], end)?;
                let blanket = format!("-A {g} -j MARK");
                let mut extra = String::new();
                if self.sets {
                    for (i, target) in ["RETURN", "MARK --set-xmark 0x10000000/0x10000000"]
                        .iter()
                        .enumerate()
                        .take(if self.dns { 1 } else { 2 })
                    {
                        let select = if v6 {
                            format!("-m mac --mac-source {}", if self.wrong { B } else { A })
                        } else {
                            "-s 192.168.1.17/32".into()
                        };
                        extra += &format!(
                            "-A {g} {select} -m set --match-set awg2_z{i}{} dst -j {target}\n",
                            if v6 { "_6" } else { "" }
                        );
                    }
                }
                Ok(base.replace(&blanket, &(extra + &blanket)))
            }
            ("ip6tables", ["-t", "filter", "-S", "FORWARD"])
            | ("ip", ["-o", "-N", _, "route", "show", "table", "998"])
            | ("ip", [_, "route", "get", _, "mark", "0x10000000"]) => go.run(cmd, args, end),
            ("ip", ["-o", "-N", _, "rule", "show"]) => Ok(format!(
                "{}\n{}",
                self.lab.run(cmd, args, end)?,
                go.run(cmd, args, end)?
            )),
            _ => self.lab.run(cmd, args, end),
        }
    }
}
fn peer(_: &Value, _: &str) -> io::Result<LivePeer> {
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
        allowed: vec!["0.0.0.0/0".into(), "::/0".into()],
    })
}
#[test]
fn legacy_mac_handoff_follows_temporary_addresses_and_recovers_lost_firewall_ack() {
    let (_dir, db, _) = setup();
    let lab = Lab::default();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"] = json!({"mode":"full"});
        let cfg = &mut doc["servers"][0]["config"];
        cfg["endpoint"] = json!("198.51.100.10:443");
        cfg["routing"] = json!({"mode":"full","active":true,"zones":[
            {"enabled":true,"route":"direct","source_ips":["192.168.1.17"],"ips":[D]},
            {"enabled":true,"route":"tunnel","source_ips":["192.168.1.17"],"ips":[D,T]}]});
        Ok(())
    })
    .unwrap();
    let doc = nfqws2_awg_profile::read(&db).unwrap();
    let policy = crate::policy::current(&doc).unwrap();
    let mut old=Old{lab:&lab,wrong:true,sets:true,dns:false,broken_dns:false,status:json!({"routing_config":policy,"routing_rules":policy.zones,
       "routing_state":{"revision":3,"ready":true,"applying":false},"servers":[{"id":doc["active_id"],"connected":true}]}).to_string()};
    let prepare = |source: &Old<'_>| {
        handoff::prepare_after(&db, source, 8090.try_into().unwrap(), || {}, peer)
    };
    assert!(prepare(&old).is_err());
    old.wrong = false;
    old.sets = false;
    assert!(prepare(&old).unwrap()); // No per-zone ipsets after a cold Go boot.
    handoff::cancel(&db).unwrap();
    old.sets = true;
    lab.dual.v6.0.lock().unwrap().foreign_rule =
        "65: from all fwmark 0x1fe00000/0x1ff00000 lookup 9001".into();
    assert!(prepare(&old).is_err());
    lab.dual.v6.0.lock().unwrap().foreign_rule.clear();
    assert!(prepare(&old).unwrap());
    let now = nfqws2_awg_profile::now();
    operate_at(&db, &lab, Operation::Apply, now, peer).unwrap();
    operate_at(&db, &lab, Operation::Commit, now + 1, peer).unwrap();
    let check = |mac, dir| {
        for src in ["2001:db8:55::1700", "2001:db8:55::bb1a"] {
            assert_eq!(lab.packet(src, "br0", mac, "2001:db8:11::70"), dir);
            assert_eq!(lab.packet(src, "br0", mac, "2001:db8:22::70"), "awg0");
            assert_eq!(lab.packet(src, "br1", mac, "2001:db8:11::70"), "awg0");
        }
    };
    check(A, "wan0");
    check(B, "awg0");
    lab.neighbour.lock().unwrap().1 = B.into();
    lab.sets.fail_switch.store(true, Ordering::Relaxed);
    assert!(operate_at(&db, &lab, Operation::Refresh, now + 2, peer).is_err());
    check(A, "wan0");
    check(B, "awg0");
    operate_at(&db, &lab, Operation::Refresh, now + 3, peer).unwrap();
    check(B, "wan0");
    check(A, "awg0");
    operate_at(&db, &lab, Operation::Suspend, now + 4, peer).unwrap();
    lab.dual.v4.0.lock().unwrap().boot = "34343434-3434-3434-3434-343434343434".into();
    operate_at(&db, &lab, Operation::Recover, now + 5, peer).unwrap();
    check(B, "wan0");
    operate_at(&db, &lab, Operation::Refresh, now + 6, |c, i| {
        peer(c, i).map(|mut p| {
            p.ipv6_reachable = false;
            p
        })
    })
    .unwrap();
    assert_eq!(
        lab.packet("2001:db8:55::aa", "br0", B, "2001:db8:22::7"),
        "awg0"
    );
    assert_eq!(
        lab.packet("2001:db8:55::bb", "br0", B, "2001:db8:11::7"),
        "drop"
    );
    lab.neighbour.lock().unwrap().0 = "br1".into();
    operate_at(&db, &lab, Operation::Refresh, now + 7, peer).unwrap();
    check(B, "awg0");
    operate_at(&db, &lab, Operation::Teardown, now + 8, peer).unwrap();
    assert!(
        lab.sets.classifier.lock().unwrap().is_empty()
            && lab.sets.sets.lock().unwrap().is_empty()
            && lab.lookups.lock().unwrap().is_empty()
    );
}

#[test]
fn go_legacy_client_dns_handoff_learning_and_recovery_keep_clients_separate() {
    let (_dir, db, _) = setup();
    let lab = Lab::default();
    lab.dual.v4.0.lock().unwrap().local = "3: br0 inet 192.168.1.1/24 scope global".into();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"] = json!({"mode":"full"});
        let mut old = doc["servers"][0].clone();
        old["id"] = json!("copied");
        old["config"]["enabled"] = json!(false);
        old["config"]["client"]["enabled"] = json!(false);
        old["config"]["routing"]["zones"] = json!([]);
        doc["servers"].as_array_mut().unwrap().push(old);
        let active = &mut doc["servers"][0]["config"];
        active["endpoint"] = json!("198.51.100.10:443");
        active["routing"] = json!({"mode":"full","active":true,"domain_source":"resolve","zones":[
            {"enabled":true,"route":"direct","tunnel_id":"copied","source_ips":["192.168.1.17"],"domains":["*.example.test"]},
        ]});
        Ok(())
    }).unwrap();
    let doc = nfqws2_awg_profile::read(&db).unwrap();
    let policy = crate::policy::current(&doc).unwrap();
    let mut old = Old {lab:&lab, wrong:false, sets:true, dns:true, broken_dns:true,
        status:json!({"routing_config":policy,"routing_rules":policy.zones,
            "routing_state":{"revision":3,"ready":true,"applying":false},"servers":[{"id":doc["active_id"],"connected":true}]}).to_string()};
    let prepare = |source: &Old<'_>| {
        handoff::prepare_after(&db, source, 8090.try_into().unwrap(), || {}, peer)
    };
    assert!(prepare(&old).is_err());
    old.broken_dns = false;
    assert!(prepare(&old).unwrap());
    let now = nfqws2_awg_profile::now();
    let bridges = ["br0".into(), "br1".into()];
    operate_with_inputs_at(&db, &lab, Operation::Apply, now, None, Some(&bridges), peer).unwrap();
    assert_eq!(lab.packet_v4("192.168.1.17", "br0", "203.0.113.10"), "wan0");
    assert_eq!(lab.packet_v4("192.168.1.18", "br0", "203.0.113.10"), "awg0");
    assert_eq!(lab.packet_v4("192.168.1.17", "br1", "203.0.113.10"), "awg0");
    let receipt = Journal::read(&db).unwrap();
    let revision = receipt.installed.revision;
    let clients = handoff::dns_clients(&lab, &policy).unwrap();
    let client = clients
        .iter()
        .find(|client| client.address.to_string() == "192.168.1.17")
        .unwrap();
    handoff::check_destination(&db, &lab, "203.0.113.10".parse().unwrap(), 0, client).unwrap();
    let learned = "203.0.113.53".parse().unwrap();
    assert!(handoff::check_destination(&db, &lab, learned, 0, client).is_err());
    let query = |source: &str, bridge| {
        learn_named_client_answer(
            &db,
            &lab,
            Answer {
                revision,
                zone: 0,
                qtype: 1,
                addresses: &[learned],
                ttl: 300,
            },
            DnsOrigin {
                client: Some(source.parse().unwrap()),
                ingress: Some(bridge),
            },
            "cdn.example.test",
            peer,
            || Ok(()),
        )
    };
    assert!(query("192.168.1.18", "br0").is_err());
    assert!(query("192.168.1.17", "br1").is_err());
    assert_eq!(query("192.168.1.17", "br0").unwrap().accepted, [learned]);
    handoff::check_destination(&db, &lab, learned, 0, client).unwrap();
    let check = || {
        assert_eq!(lab.packet_v4("192.168.1.17", "br0", "203.0.113.53"), "wan0");
        assert_eq!(lab.packet_v4("192.168.1.18", "br0", "203.0.113.53"), "awg0");
        assert_eq!(lab.packet_v4("192.168.1.17", "br1", "203.0.113.53"), "awg0");
    };
    check();
    let apply = |op, at| {
        operate_with_inputs_at(&db, &lab, op, now + at, None, Some(&bridges), peer).unwrap()
    };
    apply(Operation::Commit, 2);
    apply(Operation::Suspend, 3);
    assert!(lab.v4_classifiers.lock().unwrap().is_empty());
    lab.dual.v4.0.lock().unwrap().boot = "34343434-3434-3434-3434-343434343434".into();
    apply(Operation::Recover, 4);
    check();
    let original = Journal::read(&db).unwrap().committed;
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let base = doc["servers"][0]["config"].clone();
        let rows = doc["servers"].as_array_mut().unwrap();
        for (id, iface, endpoint, zones) in [
            ("next", "awg1", "198.51.100.11:443", json!([
                {"enabled":true,"route":"direct","source_ips":["192.168.2.17"],"domains":["cdn.new.test"]}
            ])),
            ("plain", "awg2", "198.51.100.12:443", json!([
                {"enabled":true,"route":"direct","source_ips":["192.168.2.19"]}
            ])),
        ] {
            let mut config = base.clone();
            config["client_iface"] = json!(iface);
            config["endpoint"] = json!(endpoint);
            config["routing"] = json!({"mode":"full","active":false,"zones":zones});
            rows.push(json!({"id":id,"config":config}));
        }
        Ok(())
    }).unwrap();
    let peer = |cfg: &Value, _: &str| {
        let mut live = peer(cfg, "awg0")?;
        live.endpoint = cfg["endpoint"].as_str().unwrap().parse().unwrap();
        Ok(live)
    };
    let tick = |seconds, bound| {
        operate_with_inputs_at(
            &db,
            &lab,
            Operation::LegacyWatchdog,
            now + seconds,
            None,
            bound,
            peer,
        )
    };
    nfqws2_awg_profile::select(&db, "next").unwrap();
    assert!(watchdog_needs_dns_listener(&db).unwrap());
    tick(60, None).unwrap();
    assert_eq!(lab.packet_v4("192.168.1.17", "br0", "203.0.113.53"), "wan0");
    tick(120, Some(&bridges)).unwrap();
    let current = Journal::read(&db).unwrap();
    assert_eq!(current.committed, original);
    assert_eq!(current.installed.dns_bridges, bridges);
    assert!(current
        .installed
        .learned
        .as_ref()
        .unwrap()
        .members
        .is_empty());
    assert_eq!(lab.packet_v4("192.168.1.17", "br0", "203.0.113.53"), "awg1");
    assert_eq!(lab.packet_v4("192.168.2.17", "br1", "203.0.113.53"), "awg1");

    let learned = "203.0.113.88".parse().unwrap();
    let learn = |ingress| {
        learn_named_client_answer(
            &db,
            &lab,
            Answer {
                revision: current.installed.revision,
                zone: 0,
                qtype: 1,
                addresses: &[learned],
                ttl: 100,
            },
            DnsOrigin {
                client: Some("192.168.2.17".parse().unwrap()),
                ingress: Some(ingress),
            },
            "cdn.new.test",
            peer,
            || Ok(()),
        )
    };
    assert!(learn("br0").is_err());
    assert_eq!(learn("br1").unwrap().accepted, [learned]);
    assert_eq!(Journal::read(&db).unwrap().committed, original);
    assert_eq!(lab.packet_v4("192.168.2.17", "br1", "203.0.113.88"), "wan0");
    assert_eq!(lab.packet_v4("192.168.2.17", "br0", "203.0.113.88"), "awg1");

    nfqws2_awg_profile::select(&db, "plain").unwrap();
    assert!(!watchdog_needs_dns_listener(&db).unwrap());
    tick(180, Some(&bridges)).unwrap();
    assert!(redirect_bridges(&db, false).unwrap().is_empty());
    assert_eq!(Journal::read(&db).unwrap().committed, original);
    assert_eq!(lab.packet_v4("192.168.2.17", "br1", "203.0.113.88"), "awg2");
    assert_eq!(lab.packet_v4("192.168.2.19", "br1", "203.0.113.88"), "wan0");
    assert_eq!(lab.packet_v4("192.168.2.19", "br0", "203.0.113.88"), "awg2");

    nfqws2_awg_profile::select(&db, "awg0").unwrap();
    assert!(watchdog_needs_dns_listener(&db).unwrap());
    tick(240, Some(&bridges)).unwrap();
    check();
    apply(Operation::Teardown, 250);
    assert!(lab.v4_classifiers.lock().unwrap().is_empty());
    assert!(lab.v4_lookups.lock().unwrap().is_empty());
    assert!(lab.sets.sets.lock().unwrap().is_empty());
}

#[test]
fn rebuilt_profile_reuses_only_matching_dns_sets_and_pins_new_source_only_rules() {
    use crate::kernel::learning::Member;

    let (_dir, db, _) = setup();
    let lab = Lab::default();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"] = json!({"mode":"full"});
        let a = &mut doc["servers"][0]["config"];
        a["routing"] = json!({"mode":"full","zones":[
            {"enabled":true,"route":"direct","source_ips":["192.168.1.17"],"domains":["*.corp.test"]},
            {"enabled":true,"route":"direct","source_ips":["192.168.2.17"],"domains":["*.old.test"]}
        ]});
        let mut b = a.clone();
        b["routing"]["zones"][1]["domains"] = json!(["*.new.test"]);
        b["routing"]["zones"].as_array_mut().unwrap().push(json!({
            "enabled":true,"route":"direct","source_ips":["192.168.2.19"]
        }));
        doc["servers"].as_array_mut().unwrap().push(json!({"id":"next","config":b}));
        Ok(())
    }).unwrap();
    let get = || nfqws2_awg_profile::read(&db).unwrap();
    let k = kernel(&lab);
    let (legacy_scope, mut learned) =
        legacy_scope::rebuild(&k, &db, &get(), &Plan::default()).unwrap();
    let keep = "203.0.113.17".parse().unwrap();
    let discard = "203.0.113.18".parse().unwrap();
    learned.as_mut().unwrap().members = vec![
        Member {
            zone: 0,
            ip: keep,
            until: u64::MAX,
        },
        Member {
            zone: 1,
            ip: discard,
            until: u64::MAX,
        },
    ];
    let previous = Plan {
        legacy_scope,
        learned,
        ..Plan::default()
    };
    nfqws2_awg_profile::select(&db, "next").unwrap();
    let (legacy_scope, learned) = legacy_scope::rebuild(&k, &db, &get(), &previous).unwrap();
    assert_eq!(
        learned.as_ref().unwrap().members,
        previous.learned.as_ref().unwrap().members[..1]
    );
    let alternate = Plan {
        full_endpoints: Some(BTreeSet::from(["198.51.100.11".parse().unwrap()])),
        legacy_scope,
        learned,
        ..Plan::default()
    };
    let scope = alternate.legacy_scope.as_ref().unwrap();
    let mark = |source: &str, bridge, dst| {
        scope
            .v4_dns_mark(&alternate, source.parse().unwrap(), bridge, dst)
            .unwrap()
    };
    let direct = Some("0x1fe00000");
    assert_eq!(mark("192.168.1.17", "br0", keep), direct);
    assert_eq!(mark("192.168.2.17", "br1", discard), None);
    assert_eq!(mark("192.168.2.19", "br1", discard), direct);
    assert_eq!(mark("192.168.2.19", "br0", discard), None);
    assert_eq!(
        mark("192.168.2.19", "br1", "192.168.2.1".parse().unwrap()),
        None
    );
    assert_eq!(
        mark("192.168.2.19", "br1", "198.51.100.11".parse().unwrap()),
        None
    );

    struct Move<'a>(&'a Lab, bool);
    impl Runner for Move<'_> {
        fn run(&self, cmd: &str, args: &[&str], end: Instant) -> io::Result<String> {
            if (cmd, args) == ("ip", &["-o", "-4", "addr", "show"][..]) {
                let duplicate = if self.1 {
                    "1: br0 inet 192.168.1.1/24\n"
                } else {
                    ""
                };
                return Ok(format!(
                    "{duplicate}2: br1 inet 192.168.1.1/24\n3: br1 inet 192.168.2.1/24"
                ));
            }
            self.0.run(cmd, args, end)
        }
    }
    let (_, rebound) =
        legacy_scope::rebuild(&kernel(&Move(&lab, false)), &db, &get(), &previous).unwrap();
    assert!(rebound.unwrap().members.is_empty());
    assert!(legacy_scope::rebuild(&kernel(&Move(&lab, true)), &db, &get(), &previous).is_err());
}
