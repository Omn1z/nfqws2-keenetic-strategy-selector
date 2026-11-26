use super::*;
use crate::kernel::prefix::Family;
#[cfg(target_os = "linux")]
mod archive_scope;
#[cfg(target_os = "linux")]
mod combined_edit;
#[cfg(target_os = "linux")]
mod disabled_replacement;
mod mixed;
mod full_combined_host;
mod native_full_edit;
mod nested_edit;
mod watchdog;

/// RPDB, FIB, netfilter and the default routes are independent in AF_INET
/// and AF_INET6. Reuse the firmware operation model in each namespace.
#[derive(Default)]
pub(super) struct Dual {
    pub(super) v4: Fake,
    pub(super) v6: Fake,
    nested_outer: Mutex<String>,
    extra_rpdb: Mutex<String>,
}
impl Runner for Dual {
    fn run(&self, program: &str, args: &[&str], end: Instant) -> io::Result<String> {
        if let ("ip", [family, "route", "get", addr, "mark", "0xa0000000"]) = (program, args) {
            if matches!((*family, *addr), ("-4", "198.51.100.77") | ("-6", "2001:db8:f00::1")) {
                return Ok(format!("{addr} dev {} table 828", self.nested_outer.lock().unwrap()));
            }
        }
        if program == "ip" && matches!(args, ["-o","-N","-4" | "-6","rule","show"])
            && !self.nested_outer.lock().unwrap().is_empty() {
            let family = if args[2] == "-4" {&self.v4} else {&self.v6};
            let mut rows = family.run(program, &["-o","-N","-4","rule","show"], end)?;
            rows.push_str("\n60: from all fwmark 0xa0000000 lookup 828\n61: from all fwmark 0xa0000000 8");
            rows.push_str(&self.extra_rpdb.lock().unwrap());
            return Ok(rows);
        }
        if program == "ip"
            && matches!(
                args,
                ["-6", "addr", "show", "dev", "awg0" | "awg1", "scope", "global"]
            )
        {
            return Ok("inet6 2001:db8::1/128 scope global".into());
        }
        if program == "ip6tables" {
            let text = self.v6.run("iptables", args, end)?;
            return Ok(if args.contains(&"-S") {
                text.replace("/128 ", " ")
            } else {
                text
            });
        }
        if program == "ip" && args.contains(&"-6") {
            let args = args
                .iter()
                .map(|v| if *v == "-6" { "-4" } else { *v })
                .collect::<Vec<_>>();
            let text = self.v6.run(program, &args, end)?;
            return Ok(text
                .replace("scope link", "metric 1024 pref medium")
                .replace("default via 198.51.100.1", "default via fe80::1"));
        }
        self.v4.run(program, args, end)
    }
}
fn dual_peer(_: &Value, iface: &str) -> io::Result<LivePeer> {
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
        endpoint: "[2001:db8:f00::1]:51820".parse().unwrap(),
        allowed: vec!["0.0.0.0/0".into(), "::/0".into()],
    })
}

#[test]
fn verified_single_table_go_upgrade_reaches_commit_and_restores_only_its_active_interface() {
    verified_legacy_upgrade(json!([]), false, "resolve");
}

#[test]
fn full_watchdog_only_ipv6_destinations_requires_live_blanket_and_survives_reboot() {
    verified_legacy_upgrade(json!([
        {"enabled":true,"route":"direct","ips":["2001:db8:20::/48"]},
        {"enabled":true,"route":"tunnel","ips":["2001:db8:33::1"]}
    ]), false, "resolve");
}

#[test]
fn full_watchdog_migrates_copied_sni_rules_without_creating_direct_exceptions() {
    for domain_source in ["resolve", "dnsproxy"] {
        verified_legacy_upgrade(json!([
            {"enabled":false,"route":"tunnel","tunnel_id":"copied","domains":["office.test"]},
            {"enabled":true,"route":"direct","tunnel_id":"copied","domains":["office.test"]},
            {"enabled":true,"route":"tunnel","tunnel_id":"copied","domains":["*.net.test"]}
        ]), true, domain_source);
    }
}

fn verified_legacy_upgrade(zones: Value, copied: bool, domain_source: &str) {
    use crate::kernel::handoff::{self, LegacyTestRouter};
    let (_tmp, db, _) = setup();
    let new = Dual::default();
    nfqws2_awg_profile::edit_document(&db, |d| {
        d["routing"] = json!({"mode":"full","domain_source":domain_source});
        let c = &mut d["servers"][0]["config"];
        c["endpoint"] = json!("198.51.100.10:443");
        c["routing"] = json!({"mode":"full","active":true,"sni_routing":copied,"domain_source":domain_source,"zones":if copied {json!([])} else {zones.clone()}});
        if copied {
            let mut cfg = c.clone();
            cfg["enabled"] = json!(false);
            cfg["client"]["enabled"] = json!(false);
            cfg["client_iface"] = json!("awg1");
            cfg["routing"] = json!({"mode":"full","active":false,"zones":zones});
            d["servers"].as_array_mut().unwrap().push(json!({"id":"copied","name":"","config":cfg}));
        }
        Ok(())
    })
    .unwrap();
    if copied {
        assert_eq!(crate::policy::copy(&db, "copied").unwrap(), 3);
        assert!(observations(&db).unwrap().1.unwrap().is_none());
    }
    let d = nfqws2_awg_profile::read(&db).unwrap();
    let p = crate::policy::current(&d).unwrap();
    struct Legacy<'a> {
        firewall: LegacyTestRouter,
        router: &'a Dual,
        status: String,
    }
    impl Runner for Legacy<'_> {
        fn run(&self, cmd: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
            match (cmd, args) {
                ("cat", ["/opt/var/run/nfqws2-strategy.pid"]) => Ok("31".into()),
                ("cat", ["/proc/31/stat"]) => Ok(format!("31 (n2s) {} 200", ["0"; 19].join(" "))),
                ("curl", _) => Ok(self.status.clone()),
                ("iptables" | "ip6tables", ["-t", "mangle", "-S", ..])
                | ("ip6tables", ["-t", "filter", "-S", "FORWARD"])
                | ("ip", ["-o", "-N", "-4" | "-6", "rule", "show"])
                | ("ip", ["-o", "-N", "-4" | "-6", "route", "show", "table", "998"])
                | ("ip", ["-4" | "-6", "route", "get", _, "mark", "0x10000000"]) => {
                    self.firewall.run(cmd, args, deadline)
                }
                _ => self.router.run(cmd, args, deadline),
            }
        }
    }
    let old=Legacy {firewall:LegacyTestRouter{dual:true,wrong_table:false,stranger:false},router:&new,status:json!({"routing_config":p,"routing_rules":p.zones,
      "routing_state":{"revision":3,"ready":true,"applying":false},"servers":[{"id":d["active_id"],"connected":true}]}).to_string()};
    let peer = |_: &Value, _: &str| {
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
    };
    assert!(handoff::prepare_after(&db, &old, 8090.try_into().unwrap(), || {}, peer).unwrap());
    if copied {
        assert_eq!(handoff::source_chain(&db, &old).unwrap(), "AWG2_MARK");
        assert!(!needs_dns_listener(&db).unwrap());
        assert!(dns_request(&db, Operation::Apply).unwrap().is_none());
    }
    let now = nfqws2_awg_profile::now();
    operate_at(&db, &new, Operation::Apply, now, peer).unwrap();
    assert!(handoff::check_trial(&db, &new).is_ok());
    if copied {
        let (dns, sni) = observations(&db).unwrap();
        assert!(dns.is_none());
        let sni = sni.unwrap().unwrap();
        assert!(sni.trial_expires() > now);
        let dst = "203.0.113.81".parse().unwrap();
        let cdn = "104.16.0.5".parse().unwrap();
        assert_eq!(sni.decision("OFFICE.test.", dst), ("direct", Some(2)));
        assert_eq!(sni.decision("office.test", cdn), ("cdn-skip", None));
        assert_eq!(sni.decision("video.net.test", dst), ("tunnel", Some(3)));
        assert_eq!(sni.decision("other.test", dst), ("direct", None));
        nfqws2_awg_profile::select(&db, "copied").unwrap();
        let still_live = observations(&db).unwrap().1.unwrap().unwrap();
        assert_eq!(still_live.decision("office.test", dst), ("direct", Some(2)));
        nfqws2_awg_profile::select(&db, "awg0").unwrap();
        assert_eq!(new.v4.0.lock().unwrap().forward("192.168.1.3", "203.0.113.81"), "awg0");
        let installed = Journal::read(&db).unwrap().installed;
        assert!(installed.full_direct.is_empty() && installed.learned.is_none());
    }
    operate_at(&db, &new, Operation::Commit, now + 1, peer).unwrap();
    assert!(matches!(
        Journal::read(&db).unwrap().committed.legacy_full,
        Some(plan::LegacyFull::Dual)
    ));
    if copied {
        assert_eq!(observations(&db).unwrap().1.unwrap().unwrap().trial_expires(), 0);
    } else if !p.zones.is_empty() {
        let old = Journal::read(&db).unwrap().committed.layout();
        let mut changed = nfqws2_awg_profile::read(&db).unwrap();
        changed["routing_revision"] = json!(old.legacy_revision.unwrap() + 1);
        let prior_ipv4_only = plan::Layout {
            go_ipv4: true,
            legacy_full: Some(plan::LegacyFull::Ipv4Only),
            ..old.clone()
        };
        for layout in [old, prior_ipv4_only] {
            let after = plan::compile_with_layout(&changed, None, false, &[], layout).unwrap();
            assert!(after.legacy_full.is_none() && after.full_endpoints.is_none());
            assert!(
                !after.go_ipv4
                    && after
                        .flows()
                        .any(|(s, _)| s.dest.contains("2001:db8:33::1".parse().unwrap()))
            );
        }
    }
    operate_at(&db, &new, Operation::Suspend, now + 2, peer).unwrap();
    assert!(observations(&db).unwrap().1.unwrap().is_none());
    new.v4.0.lock().unwrap().boot = "34343434-3434-3434-3434-343434343434".into();
    operate_at(&db, &new, Operation::Recover, now + 3, peer).unwrap();
    assert_eq!(observations(&db).unwrap().1.unwrap().is_some(), copied);
    assert_eq!(
        new.v6.0.lock().unwrap().forward("fd00::2", "2620:fe::fe"),
        "awg0"
    );
    let down = |c: &Value, i: &str| {
        peer(c, i).map(|mut p| {
            p.ipv6_reachable = false;
            p
        })
    };
    new.v6.0.lock().unwrap().watch_flow = Some(("fd00::2", "2620:fe::fe"));
    operate_at(&db, &new, Operation::Refresh, now + 4, down).unwrap();
    let j = Journal::read(&db).unwrap();
    assert!(
        matches!(j.installed.legacy_full, Some(plan::LegacyFull::ForwardReject { ref wan, .. }) if wan == "wan0")
    );
    assert!(!new.v6.0.lock().unwrap().mark_lookup);
    assert!(new.v4.0.lock().unwrap().mark_lookup);
    // A socket bound to the tunnel can retry immediately, while forwarded
    // and ordinary local traffic has no new route to the control host.
    let control = "2606:4700:4700::1111";
    assert_eq!(new.v6.0.lock().unwrap().forward("fd00::2", control), "wan0");
    assert!(new
        .run(
            "ip",
            &["-6", "route", "get", control, "oif", "awg0"],
            Instant::now()
        )
        .is_ok());
    assert!(new
        .run(
            "ip",
            &["-6", "route", "get", "2620:fe::fe", "oif", "awg0"],
            Instant::now()
        )
        .is_err());
    operate_at(&db, &new, Operation::Refresh, now + 5, peer).unwrap();
    assert!(new.v6.0.lock().unwrap().mark_lookup);
    assert!(!new.v6.0.lock().unwrap().leaked);
    assert!(matches!(
        Journal::read(&db).unwrap().installed.legacy_full,
        Some(plan::LegacyFull::Dual)
    ));
    operate_at(&db, &new, Operation::Teardown, now + 6, peer).unwrap();
    let v6 = new.v6.0.lock().unwrap();
    assert!(v6.probe_oif.is_none() && v6.scoped_routes.is_empty());
}

#[test]
fn source_bound_default_only_affects_selected_lan_and_keeps_other_clients_online() {
    let (_dir, db, _) = setup();
    let router = Dual::default();
    router.v4.0.lock().unwrap().local = "3: br0 inet 192.168.1.1/24 scope global".into();
    nfqws2_awg_profile::edit_document(&db,|doc|{
        doc["routing"]=json!({"mode":"zones","killswitch":true});
        doc["servers"][0]["config"]["endpoint"]=json!("198.51.100.10:443");
        doc["servers"][0]["config"]["routing"]["zones"]=json!([
            {"order":1,"enabled":true,"route":"direct","ips":["203.0.113.0/24"]},
            {"order":2,"enabled":true,"route":"tunnel","source_ips":["192.168.1.20","192.168.1.80/28"],"domains":["*"]}]);
        Ok(())
    }).unwrap();
    operate_at(&db, &router, Operation::Apply, 10, peer).unwrap();
    let fwd = |src: &str, dst: &str| router.v4.0.lock().unwrap().forward(src, dst).to_owned();
    for src in ["192.168.1.20", "192.168.1.84"] {
        assert_eq!(fwd(src, "8.8.8.8"), "awg0");
        assert_eq!(fwd(src, "203.0.113.18"), "wan0");
    }
    assert_eq!(fwd("192.168.1.81", "198.51.100.10"), "wan0");
    assert_eq!(fwd("192.168.1.22", "8.8.8.8"), "wan0");
    assert!(!router.v4.0.lock().unwrap().mark_lookup);
    operate_at(&db, &router, Operation::Commit, 11, peer).unwrap();
    operate_at(&db, &router, Operation::Refresh, 12, |_, _| {
        Err(io::ErrorKind::NotConnected.into())
    })
    .unwrap();
    assert_eq!(fwd("192.168.1.20", "8.8.8.8"), "unreachable");
    assert_eq!(fwd("192.168.1.22", "8.8.8.8"), "wan0");
    operate_at(&db, &router, Operation::Teardown, 13, peer).unwrap();
    assert!(router.v4.0.lock().unwrap().source_default.is_empty());
    assert!(router.v4.0.lock().unwrap().source_main.is_empty());
}

#[test]
fn static_direct_zones_precede_a_global_ipv4_default_across_commit_and_rollback() {
    let (_dir, db, _) = setup();
    let router = Dual::default();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"] = json!({"mode":"full","domain_source":"dnsproxy"});
        doc["servers"][0]["config"]["endpoint"] = json!("198.51.100.10:443");
        doc["servers"][0]["config"]["routing"]["zones"] = json!([
            {"order":1,"enabled":true,"route":"direct","ips":["203.0.113.0/24"]},
            {"order":2,"enabled":true,"route":"tunnel","domains":["*"]}]);
        Ok(())
    })
    .unwrap();
    let fwd = |dst: &str| {
        router
            .v4
            .0
            .lock()
            .unwrap()
            .forward("192.168.1.5", dst)
            .to_owned()
    };
    operate_at(&db, &router, Operation::Apply, 10, peer).unwrap();
    assert_eq!(fwd("203.0.113.8"), "wan0");
    assert_eq!(fwd("203.0.112.8"), "awg0");
    operate_at(&db, &router, Operation::Commit, 11, peer).unwrap();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing_revision"] = json!(2);
        doc["servers"][0]["config"]["routing"]["zones"][0]["ips"] = json!(["203.0.112.0/24"]);
        Ok(())
    })
    .unwrap();
    operate_at(&db, &router, Operation::Apply, 12, peer).unwrap();
    assert_eq!(fwd("203.0.112.8"), "wan0");
    let now = nfqws2_awg_profile::now();
    operate_at(&db, &router, Operation::Recover, now + TRIAL + 1, peer).unwrap();
    assert_eq!(fwd("203.0.113.8"), "wan0");
    assert_eq!(fwd("203.0.112.8"), "awg0");
}

#[test]
fn a_single_bare_multi_wildcard_routes_raw_ipv4_and_preserves_ipv6_underlay() {
    let (_dir, db, _) = setup();
    let router = Dual::default();
    for wildcard in ["*", "0.0.0.0/0", "::/0"] {
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["routing"] = json!({"mode":"zones","domain_source":"dnsproxy","sni_routing":true});
            doc["servers"][0]["config"]["endpoint"] = json!("198.51.100.10:443");
            let mut zone = json!({"enabled":true,"route":"tunnel"});
            zone[if wildcard == "*" { "domains" } else { "ips" }] = json!([wildcard]);
            doc["servers"][0]["config"]["routing"]["zones"] = json!([zone]);
            Ok(())
        })
        .unwrap();
        assert!(dns_request(&db, Operation::Apply).unwrap().is_none());
        assert!(!needs_dns_listener(&db).unwrap());
        operate_at(&db, &router, Operation::Apply, 10, peer).unwrap();
        assert_eq!(
            router
                .v4
                .0
                .lock()
                .unwrap()
                .forward("192.168.1.25", "9.9.9.9"),
            "awg0"
        );
        assert_eq!(
            router
                .v4
                .0
                .lock()
                .unwrap()
                .forward("192.168.1.25", "198.51.100.10"),
            "wan0"
        );
        assert_eq!(
            router
                .v6
                .0
                .lock()
                .unwrap()
                .forward("fd00::2", "2620:fe::fe"),
            "wan0"
        );
        assert_eq!(router.v6.0.lock().unwrap().changes, 0);
        operate_at(&db, &router, Operation::Teardown, 11, peer).unwrap();
    }
}

#[test]
fn full_guards_accept_linux_ipv6_loopback_and_preserve_foreign_routes() {
    let saved = [
        (
            "9 2001:db8:90::9 dev lo table 17842 proto 242 metric 1024 pref medium",
            true,
        ),
        (
            "7 default dev lo table 17842 proto 242 metric 32000 pref medium",
            true,
        ),
        (
            "7 default dev br0 table 17842 proto 242 metric 32000 pref medium",
            false,
        ),
        (
            "7 default dev lo table 17842 proto 99 metric 32000 pref medium",
            false,
        ),
    ];
    for (row, valid) in saved {
        let words: Vec<_> = row.split_ascii_whitespace().collect();
        assert_eq!(full::route(Family::V6, &words).is_ok(), valid, "{row}");
    }
}

#[test]
fn full_tunnel_keeps_lan_and_transport_and_blocks_unavailable_ipv6_through_reboot() {
    let (_dir, db, _) = setup();
    let router = Dual::default();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"] = json!({"mode":"full","killswitch":true});
        doc["servers"][0]["config"]["routing"] = json!({"mode":"full"});
        doc["servers"][0]["config"]["endpoint"] = json!("198.51.100.10:443");
        Ok(())
    })
    .unwrap();
    let now = nfqws2_awg_profile::now();
    let op = |action, at| operate_at(&db, &router, action, at, peer);
    op(Operation::Apply, now).unwrap();
    let public = |v4: &str, v6: &str| {
        assert_eq!(
            router
                .v4
                .0
                .lock()
                .unwrap()
                .forward("192.168.7.11", "9.9.9.9"),
            v4
        );
        assert_eq!(
            router
                .v6
                .0
                .lock()
                .unwrap()
                .forward("fd02::3", "2620:fe::fe"),
            v6
        );
    };
    public("awg0", "unreachable");
    for address in ["10.1.2.3", "192.168.7.1", "100.64.0.9", "198.51.100.10"] {
        assert_eq!(
            router.v4.0.lock().unwrap().forward("192.168.7.11", address),
            "wan0"
        );
    }
    assert_eq!(
        router.v6.0.lock().unwrap().forward("fd02::3", "fe80::7"),
        "wan0"
    );
    op(Operation::Recover, now + TRIAL + 1).unwrap();
    public("wan0", "wan0");
    op(Operation::Apply, now + 100).unwrap();
    op(Operation::Commit, now + 101).unwrap();
    op(Operation::Suspend, now + 102).unwrap();
    router.v4.0.lock().unwrap().boot = "34343434-3434-3434-3434-343434343434".into();
    op(Operation::Recover, now + 103).unwrap();
    public("awg0", "unreachable");
    operate_at(&db, &router, Operation::Refresh, now + 104, dual_peer).unwrap();
    public("awg0", "awg0");
    operate_at(&db, &router, Operation::Refresh, now + 105, |_, _| {
        Err(io::ErrorKind::NotConnected.into())
    })
    .unwrap();
    public("unreachable", "unreachable");
    op(Operation::Teardown, now + 106).unwrap();
    public("wan0", "wan0");
    for kernel in [&router.v4, &router.v6] {
        let f = kernel.0.lock().unwrap();
        assert!(
            !f.main_specific
                && !f.mark_lookup
                && !f.fence
                && f.throws.is_empty()
                && f.routes.is_empty()
        );
    }
}

#[test]
fn permanent_full_blocks_both_families_with_unchecked_killswitch_and_ignores_ordinary_reserves() {
    for old_receipt in [false, true] {
        let (_tmp, db, _) = setup();
        let router = Dual::default();
        nfqws2_awg_profile::edit_document(&db, |d| {
            d["routing"] = json!({"mode":"full","killswitch":false});
            let rows = d["servers"].as_array_mut().unwrap();
            rows[0]["config"]["endpoint"] = json!("198.51.100.10:51820");
            rows[0]["config"]["routing"] = json!({"mode":"full"});
            for (idx, id) in [(1, "reserve"), (2, "outer")] {
                let mut row = rows[0].clone();
                row["id"] = json!(id);
                row["config"]["client_iface"] = json!(format!("awg{idx}"));
                row["config"]["endpoint"] = json!(format!("198.51.100.1{idx}:51820"));
                rows.push(row);
            }
            let c = &mut rows[0]["config"]["client"];
            c["fallback_tunnel_ids"] = json!(["reserve"]);
            c["double_tunnel_id"] = json!("outer");
            if !old_receipt { c["double_tunnel_mode"] = json!("permanent"); }
            Ok(())
        }).unwrap();
        let path = |family: &Fake, v6: bool| {
            let kernel = family.0.lock().unwrap();
            if v6 {kernel.forward("fd12::2", "2620:fe::fe").to_owned()}
            else {kernel.forward("192.168.3.2", "9.9.9.9").to_owned()}
        };
        let direct = |cfg: &Value, iface: &str| {
            if !old_receipt {assert_eq!(iface, "awg0");}
            dual_peer(cfg, iface)
        };
        let now = nfqws2_awg_profile::now();
        if !old_receipt {
            *router.nested_outer.lock().unwrap() = "awg2".into();
            for extra in [
                "\n60: from all fwmark 0xa0000001 lookup 829\n61: from all fwmark 0xa0000001 prohibit",
                "\n59: from all lookup 829",
                "\n60: from all fwmark 0xa0000000/0xf0000000 lookup 828",
                "\n61: from all fwmark 0xa0000000 8",
            ] {
                *router.extra_rpdb.lock().unwrap() = extra.into();
                assert!(operate_at(&db, &router, Operation::Apply, now, direct).is_err());
                assert_eq!(router.v4.0.lock().unwrap().changes, 0);
                assert_eq!(router.v6.0.lock().unwrap().changes, 0);
            }
            router.extra_rpdb.lock().unwrap().clear();
        }
        for (offset, op) in [Operation::Apply, Operation::Commit].into_iter().enumerate() {
            operate_at(&db, &router, op, now + offset as u64, direct).unwrap();
        }
        if old_receipt {
            // This exactly reproduces the preceding compiler's plan: no
            // fence, connected ordinary reserve, even when permanent mode
            // had been saved with the same public policy and revision.
            operate_at(&db, &router, Operation::Refresh, now + 2, |cfg, iface| {
                if iface == "awg0" {Err(io::ErrorKind::NotConnected.into())}
                else {dual_peer(cfg, iface)}
            }).unwrap();
            assert_eq!(path(&router.v4, false), "awg1");
            assert!(!Journal::read(&db).unwrap().committed.killswitch);
            nfqws2_awg_profile::edit_document(&db, |d| {
                d["servers"][0]["config"]["client"]["double_tunnel_mode"] = json!("permanent");
                Ok(())
            }).unwrap();
            operate_at(&db, &router, Operation::Recover, now + 3, |cfg, iface| {
                assert_eq!(iface, "awg0", "recovery must not query the ordinary reserve");
                dual_peer(cfg, iface)
            }).unwrap();
        }
        assert_eq!(path(&router.v4, false), "unreachable");
        assert_eq!(path(&router.v6, true), "unreachable");
        let j = Journal::read(&db).unwrap();
        assert!(j.committed.killswitch && j.committed.reserves.is_empty());
        assert_eq!(j.committed.targets.keys().collect::<Vec<_>>(), ["awg0"]);
        let exempt = j.installed.full_endpoints.as_ref().unwrap();
        assert!(exempt.contains(&"198.51.100.10".parse::<std::net::IpAddr>().unwrap()));
        assert!(exempt.contains(&"198.51.100.12".parse::<std::net::IpAddr>().unwrap()));
        assert!(!exempt.contains(&"198.51.100.11".parse::<std::net::IpAddr>().unwrap()));
        assert_eq!(nfqws2_awg_profile::read(&db).unwrap()["routing"]["killswitch"], false);
        let nested = |cfg: &Value, iface: &str| {
            assert_eq!(iface, "awg0");
            Ok(LivePeer {socket_mark: 0xa0000000, ..dual_peer(cfg, iface)?})
        };
        *router.nested_outer.lock().unwrap() = "awg1".into();
        operate_at(&db, &router, Operation::Refresh, now + 4, nested).unwrap();
        assert_eq!(path(&router.v4, false), "unreachable");
        assert_eq!(path(&router.v6, true), "unreachable");
        *router.nested_outer.lock().unwrap() = "awg2".into();
        operate_at(&db, &router, Operation::Refresh, now + 4, nested).unwrap();
        assert_eq!(path(&router.v4, false), "awg0");
        assert_eq!(path(&router.v6, true), "awg0");
        assert!(router.v4.0.lock().unwrap().fence && router.v6.0.lock().unwrap().fence);
        {
            let mut fw = router.v4.0.lock().unwrap();
            fw.fail_after = Some(fw.changes + 1);
        }
        assert!(operate_at(&db, &router, Operation::Refresh, now + 5, |_, _| Err(io::ErrorKind::NotConnected.into())).is_err());
        assert_eq!(path(&router.v4, false), "unreachable");
        assert_eq!(path(&router.v6, true), "unreachable");
        operate_at(&db, &router, Operation::Refresh, now + 5, |_, _| Err(io::ErrorKind::NotConnected.into())).unwrap();
        assert_eq!(path(&router.v4, false), "unreachable");
        assert_eq!(path(&router.v6, true), "unreachable");
        operate_at(&db, &router, Operation::Teardown, now + 6, direct).unwrap();
        assert_eq!(path(&router.v4, false), "wan0");
        assert_eq!(path(&router.v6, true), "wan0");
    }
}

#[test]
fn nested_mtu_edit_requires_the_current_owned_generation_and_keeps_low_mtu_ipv6_fenced() {
    nested_mtu_case(1200, 1380, 1200, None);
    nested_mtu_case(1338, 1280, 1280, None);
}

#[test]
fn nested_port_edit_keeps_the_same_outer_path_and_mtu() {
    nested_mtu_case(1338, 1420, 1338, Some(8443));
}

fn nested_mtu_case(old_effective: u16, desired: u16, effective: u16, next_port: Option<u16>) {
    use nfqws2_awg_profile::{RoutedEndpointEdit, RoutedMtuChange, RoutedMtuOuter, RoutedMtuPeer};
    const OLD: &str = "[2001:db8:f00::1]:51820";
    let new_endpoint = next_port.map(|port| format!("[2001:db8:f00::1]:{port}"));
    let (_tmp, db, _) = setup();
    let router = Dual::default();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"] = json!({"mode":"full","killswitch":false});
        let rows = doc["servers"].as_array_mut().unwrap();
        let mut outer = rows[0].clone();
        outer["id"] = json!("outer");
        outer["config"]["client_iface"] = json!("awg2");
        outer["config"]["endpoint"] = json!("198.51.100.12:51820");
        outer["config"]["routing"] = json!({"mode":"off"});
        rows[0]["config"]["endpoint"] = json!(OLD);
        rows[0]["config"]["routing"] = json!({"mode":"full"});
        rows[0]["config"]["mtu"] = json!(1420);
        rows[0]["config"]["client"]["double_tunnel_mode"] = json!("permanent");
        rows[0]["config"]["client"]["double_tunnel_id"] = json!("outer");
        rows.push(outer);
        Ok(())
    }).unwrap();
    *router.nested_outer.lock().unwrap() = "awg2".into();
    let live_mtu = std::cell::Cell::new(old_effective);
    let live_port = std::cell::Cell::new(51820);
    let nested = |cfg: &Value, iface: &str| {
        assert_eq!(iface, "awg0");
        let mut peer = dual_peer(cfg, iface)?;
        peer.endpoint.set_port(live_port.get());
        peer.socket_mark = 0xa0000000;
        peer.nested_mtu = Some(live_mtu.get());
        Ok(peer)
    };
    let now = nfqws2_awg_profile::now();
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &router, op, now, nested).unwrap();
    }
    let before = Journal::read(&db).unwrap();
    let change = RoutedMtuChange {
        id: before.committed.targets["awg0"].id.clone(),
        iface: "awg0".into(),
        revision: before.committed.revision,
        before: 1420,
        after: desired,
        nested_outer: Some(RoutedMtuOuter { id: "outer".into(), iface: "awg2".into(), peer_key_sha256: [1; 32] }),
        nested_endpoint: next_port.is_none().then(|| OLD.into()),
        legacy_predecessor: None,
        native_mtu_endpoint: None,
        legacy_mtu_before_recorded: false,
        nested_mtu_before_recorded: false,
        implicit_before_mtu: None,
        endpoint_edit: new_endpoint.clone().map(|after| RoutedEndpointEdit { before: OLD.into(), after, previous_reserve: None, resolved_before: vec![], resolved_after: vec![] }),
    };
    let path = |v4: &str, v6: &str| {
        assert_eq!(router.v4.0.lock().unwrap().forward("192.168.3.2", "9.9.9.9"), v4);
        assert_eq!(router.v6.0.lock().unwrap().forward("fd12::2", "2620:fe::fe"), v6);
    };
    let v6 = |mtu| if mtu < 1280 { "unreachable" } else { "awg0" };
    path("awg0", v6(old_effective));
    router.v4.0.lock().unwrap().mtu.insert("awg0".into(), old_effective);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        if let Some(endpoint) = &new_endpoint {
            doc["servers"][0]["config"]["endpoint"] = json!(endpoint);
        } else {
            doc["servers"][0]["config"]["mtu"] = json!(change.after);
        }
        doc["servers"][0]["rust_pending_routed_mtu"] = json!(change);
        doc["servers"][0]["rust_pending_client_profile"] = json!(vec![0_u8; 32]);
        Ok(())
    }).unwrap();
    prepare_mtu_edit(&db, &router, &change).unwrap();
    let authority = mtu_edit::read(&db).unwrap().unwrap();
    path("unreachable", "unreachable");
    operate_with_redirect_and_mtu(&db, &router, Operation::Recover, None, None, nested,
        |_, _| panic!("proof requested before acknowledged launch")).unwrap();
    assert!(pending_mtu_edit(&db).unwrap());
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let row = doc["servers"][0].as_object_mut().unwrap();
        row.remove("rust_pending_client_profile");
        row.remove("rust_pending_routed_mtu");
        Ok(())
    }).unwrap();
    operate_with_redirect_and_mtu(&db, &router, Operation::Recover, None, None, nested,
        |_, _| panic!("proof requested for a desired edit with no launch marker")).unwrap();
    path("unreachable", "unreachable");
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["rust_pending_routed_mtu"] = json!(change);
        Ok(())
    }).unwrap();
    // An old generation can have the same live MTU, key, mark and address.
    // Only the profile runtime's owned configuration hash can authenticate
    // the new launch in that case. A missing verifier must leave paths parked.
    operate(&db, &router, Operation::Recover, nested).unwrap();
    path("unreachable", "unreachable");
    live_mtu.set(effective);
    if let Some(port) = next_port { live_port.set(port); }
    router.v4.0.lock().unwrap().mtu.insert("awg0".into(), effective);
    let prove = |saved: &RoutedMtuChange, live: &LivePeer| {
        assert_eq!(saved, &change);
        Ok(Some(RoutedMtuPeer {
            iface: "awg0".into(), outer_id: "outer".into(), outer_iface: "awg2".into(),
            endpoint: live.endpoint, effective_mtu: effective, socket_mark: live.socket_mark,
        }))
    };
    operate_with_redirect_and_mtu(&db, &router, Operation::Recover, None, None, nested, |saved, live| {
        let mut proof = prove(saved, live)?.unwrap();
        proof.outer_id = "different".into();
        Ok(Some(proof))
    }).unwrap();
    path("unreachable", "unreachable");
    router.v4.0.lock().unwrap().mtu.insert("awg0".into(), effective - 1);
    operate_with_redirect_and_mtu(&db, &router, Operation::Recover, None, None, nested, prove).unwrap();
    path("unreachable", "unreachable");
    router.v4.0.lock().unwrap().mtu.insert("awg0".into(), effective);
    *router.nested_outer.lock().unwrap() = "awg1".into();
    operate_with_redirect_and_mtu(&db, &router, Operation::Recover, None, None, nested, prove).unwrap();
    path("unreachable", "unreachable");
    *router.nested_outer.lock().unwrap() = "awg2".into();
    operate_with_redirect_and_mtu(&db, &router, Operation::Recover, None, None, nested, prove).unwrap();
    assert!(!pending_mtu_edit(&db).unwrap());
    let doc = nfqws2_awg_profile::read(&db).unwrap();
    assert!(nfqws2_awg_profile::pending_routed_mtu(&doc["servers"][0]).unwrap().is_none());
    let after = Journal::read(&db).unwrap();
    assert_eq!(after.committed.revision, before.committed.revision);
    assert_eq!(after.committed.targets["awg0"].mtu, desired);
    assert_eq!(after.installed.mss["awg0"], effective - 40);
    path("awg0", v6(effective));
    // Repeat the verification after a crash between clearing the profile
    // marker and deleting the already committed routing authority.
    let mut replay = serde_json::to_value(authority).unwrap();
    if next_port.is_some() { replay["endpoint_committed"] = json!(true); }
    db.transaction(|tx| tx.save_runtime("awg-routed-mtu.json", &replay)).unwrap();
    let changes = router.v4.0.lock().unwrap().changes;
    operate_with_redirect_and_mtu(&db, &router, Operation::Refresh, None, None, nested, prove).unwrap();
    assert!(!pending_mtu_edit(&db).unwrap());
    assert_eq!(router.v4.0.lock().unwrap().changes, changes);
    operate(&db, &router, Operation::Refresh, nested).unwrap();
    path("awg0", v6(effective));
    assert!(!router.v4.0.lock().unwrap().leaked && !router.v6.0.lock().unwrap().leaked);
}

// The launcher creates awg0, wan0 and br0 as isolated links and supplies
// the *original* namespace identities. All FIB probes are local lookups.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn full_policy_on_isolated_linux_tables() {
    for (kind, var) in [("net", "N2S_PARENT_NET"), ("mnt", "N2S_PARENT_MNT")] {
        let parent = std::env::var(var).unwrap();
        assert!(parent.starts_with(&format!("{kind}:[")));
        let current = std::fs::read_link(format!("/proc/self/ns/{kind}")).unwrap();
        assert_ne!(current.to_str().unwrap(), parent);
    }
    let ip = |args: &[&str]| {
        let result = std::process::Command::new("ip")
            .args(args)
            .output()
            .unwrap();
        result
            .status
            .success()
            .then(|| String::from_utf8(result.stdout).unwrap())
    };
    let dev = |family: &str, addr: &str| {
        let path = ip(&[family, "route", "get", addr])?;
        let mut words = path.split_ascii_whitespace();
        words.find(|s| *s == "dev")?;
        words.next().map(ToOwned::to_owned)
    };
    let tables = || {
        ["-4", "-6"].map(|f| {
            (
                ip(&[f, "rule", "show"]),
                ip(&[f, "route", "show", "table", "17842"]),
            )
        })
    };
    let baseline = tables();
    let (_dir, db, _) = setup();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"] = json!({"mode":"full","killswitch":true});
        doc["servers"][0]["config"]["routing"] = json!({"mode":"full"});
        doc["servers"][0]["config"]["endpoint"] = json!("198.51.100.10:443");
        Ok(())
    })
    .unwrap();
    let now = nfqws2_awg_profile::now();
    let kernel = nfqws2_router_command::System;
    let act = |op, at| operate_at(&db, &kernel, op, now + at, peer);
    act(Operation::Apply, 0).unwrap();
    assert_eq!(dev("-4", "9.9.9.9").as_deref(), Some("awg0"));
    assert_eq!(dev("-6", "2620:fe::fe"), None);
    for (f, addr, name) in [
        ("-4", "198.51.100.10", "wan0"),
        ("-4", "10.99.0.11", "br0"),
        ("-6", "2001:db8:44::3", "br0"),
    ] {
        assert_eq!(dev(f, addr).as_deref(), Some(name));
    }
    act(Operation::Recover, TRIAL + 1).unwrap();
    assert_eq!(dev("-4", "9.9.9.9").as_deref(), Some("wan0"));
    assert_eq!(dev("-6", "2620:fe::fe").as_deref(), Some("wan0"));
    act(Operation::Apply, 100).unwrap();
    act(Operation::Commit, 101).unwrap();
    operate_at(&db, &kernel, Operation::Refresh, now + 102, dual_peer).unwrap();
    assert_eq!(dev("-6", "2620:fe::fe").as_deref(), Some("awg0"));
    assert_eq!(dev("-6", "2001:db8:f00::1").as_deref(), Some("wan0"));
    operate_at(&db, &kernel, Operation::Refresh, now + 103, |_, _| {
        Err(io::ErrorKind::NotConnected.into())
    })
    .unwrap();
    assert_eq!(dev("-4", "9.9.9.9"), None);
    assert_eq!(dev("-6", "2620:fe::fe"), None);
    act(Operation::Teardown, 104).unwrap();
    let result = tables();
    for ((old_rules, old_table), (rules, table)) in baseline.into_iter().zip(result) {
        assert_eq!(old_rules, rules);
        assert_eq!(old_table.unwrap_or_default(), table.unwrap_or_default());
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires isolated netns with nested transport policy and CAP_NET_ADMIN"]
fn permanent_full_uses_real_ipv4_ipv6_fences_and_configured_outer_route() {
    assert_eq!(std::fs::read_to_string("/suite/permanent-full").unwrap(), "ea1-qemu-airgap");
    for (kind, var) in [("net", "N2S_PARENT_NET"), ("mnt", "N2S_PARENT_MNT")] {
        let parent = std::env::var(var).unwrap();
        assert!(parent.starts_with(&format!("{kind}:[")));
        assert_ne!(std::fs::read_link(format!("/proc/self/ns/{kind}")).unwrap().to_str(), Some(parent.as_str()));
    }
    let ip = |args: &[&str]| {
        let out = std::process::Command::new("ip").args(args).output().unwrap();
        out.status.success().then(|| String::from_utf8(out.stdout).unwrap())
    };
    let route = |fam: &str| ip(&[fam, "route", "get", if fam == "-4" {"9.9.9.9"} else {"2620:fe::fe"}]);
    let (_tmp, db, _) = setup();
    nfqws2_awg_profile::edit_document(&db, |d| {
        d["routing"] = json!({"mode":"full","killswitch":false});
        let rows = d["servers"].as_array_mut().unwrap();
        rows[0]["config"]["routing"] = json!({"mode":"full"});
        rows[0]["config"]["endpoint"] = json!("198.51.100.10:51820");
        for (n, name) in [(1, "reserve"), (2, "outer")] {
            let mut row = rows[0].clone();
            row["id"] = json!(name);
            row["config"]["client_iface"] = json!(format!("awg{n}"));
            row["config"]["endpoint"] = json!(format!("198.51.100.1{n}:51820"));
            rows.push(row);
        }
        let c = &mut rows[0]["config"]["client"];
        c["double_tunnel_mode"] = json!("permanent");
        c["double_tunnel_id"] = json!("outer");
        c["fallback_tunnel_ids"] = json!(["reserve"]);
        Ok(())
    }).unwrap();
    let go = |op, mark| operate(&db, &nfqws2_router_command::System, op, |c, i| {
        assert_eq!(i, "awg0");
        Ok(LivePeer {socket_mark: mark, ..dual_peer(c, i)?})
    });
    let before = ["-4","-6"].map(|f| ip(&[f,"rule","show"]).unwrap());
    go(Operation::Apply, 0).unwrap();
    go(Operation::Commit, 0).unwrap();
    for f in ["-4","-6"] {
        assert!(route(f).is_none());
        assert!(ip(&[f,"route","show","table","17842"]).unwrap().contains("unreachable default"));
    }
    // In this isolated guest the launcher has installed the real encrypted
    // socket lookup (60), prohibit rule (61) and peer route via awg2. Only
    // the userspace UAPI/handshake sample is injected.
    go(Operation::Refresh, 0xa0000000).unwrap();
    for f in ["-4","-6"] {
        assert!(route(f).unwrap().contains("dev awg0"));
    }
    assert!(ip(&["-6","route","replace","2001:db8:f00::1/128","dev","awg1","table","828","proto","99"]).is_some());
    go(Operation::Refresh, 0xa0000000).unwrap();
    for f in ["-4","-6"] {
        assert!(route(f).is_none());
    }
    go(Operation::Teardown, 0).unwrap();
    for (f, rules) in ["-4","-6"].into_iter().zip(before) {
        assert!(route(f).unwrap().contains("dev wan0"));
        assert_eq!(ip(&[f,"rule","show"]).unwrap(), rules);
    }
}

#[test]
fn keenetic_dns_redirects_follow_trial_rollback_learning_restart_and_teardown() {
    let (_dir, db, v4) = setup();
    let router = Dual {
        v4,
        ..Default::default()
    };
    zones(
        &db,
        json!([{"name":"office","enabled":true,"route":"tunnel","domains":["*.office.test"]}]),
    );
    let now = nfqws2_awg_profile::now();
    let bridges = vec!["br0".to_owned(), "br1".to_owned(), "br2".to_owned()];
    let run = |op, at| {
        operate_with_inputs_at(
            &db,
            &router,
            op,
            at,
            None,
            (op == Operation::Apply).then_some(bridges.as_slice()),
            dual_peer,
        )
    };
    let verify = |expected| {
        for fw in [&router.v4, &router.v6] {
            let state = fw.0.lock().unwrap();
            let entries = state
                .firewall
                .get("nat")
                .into_iter()
                .flatten()
                .filter(|rule| rule.contains(" REDIRECT ") && rule.contains("n2s-awg-cidr"))
                .collect::<Vec<_>>();
            assert_eq!(entries.len(), if expected { 6 } else { 0 });
            if expected {
                for br in &bridges {
                    for proto in ["tcp", "udp"] {
                        assert!(entries.iter().any(|s| s
                            .contains(&format!("-i {br} -p {proto} -m {proto} --dport 53 "))
                            && s.ends_with("--to-ports 5354")));
                    }
                }
            }
        }
    };
    let conflicting = "-A PREROUTING -i br+ -p udp -m udp --dport 53 -j REDIRECT --to-ports 5555";
    router
        .v6
        .0
        .lock()
        .unwrap()
        .firewall
        .entry("nat".into())
        .or_default()
        .insert(conflicting.into());
    assert!(run(Operation::Apply, now).is_err());
    assert!(router
        .v6
        .0
        .lock()
        .unwrap()
        .firewall
        .get_mut("nat")
        .unwrap()
        .remove(conflicting));
    verify(false);
    router.v6.0.lock().unwrap().fail_after = Some(2);
    assert!(run(Operation::Apply, now).is_err());
    verify(false);
    run(Operation::Apply, now).unwrap();
    verify(true);
    run(Operation::Recover, now + 91).unwrap();
    verify(false);
    run(Operation::Apply, now + 92).unwrap();
    let observation = observation(&db).unwrap().unwrap();
    learn_answer(
        &db,
        &router,
        Answer {
            revision: observation.revision,
            zone: observation.policy.matched("vpn.office.test", None).unwrap(),
            addresses: &["203.0.113.44".parse().unwrap()],
            ttl: 60,
            qtype: 1,
        },
        dual_peer,
        || Ok(()),
    )
    .unwrap();
    verify(true);
    run(Operation::Commit, now + 93).unwrap();
    run(Operation::Suspend, now + 94).unwrap();
    verify(false);
    assert!(redirect_bridges(&db, false).unwrap().is_empty());
    assert_eq!(redirect_bridges(&db, true).unwrap(), bridges);
    run(Operation::Recover, now + 95).unwrap();
    verify(true);
    let after_hotplug = vec!["br0".into(), "br3".into()];
    operate_with_inputs_at(
        &db,
        &router,
        Operation::Refresh,
        now + 96,
        None,
        Some(&after_hotplug),
        dual_peer,
    )
    .unwrap();
    assert_eq!(redirect_bridges(&db, true).unwrap(), after_hotplug);
    for fw in [&router.v4, &router.v6] {
        let state = fw.0.lock().unwrap();
        let nat = &state.firewall["nat"];
        assert_eq!(nat.iter().filter(|s| s.contains(" REDIRECT ")).count(), 4);
        assert!(nat.iter().any(|s| s.contains("-i br3 ")));
        assert!(nat
            .iter()
            .all(|s| !s.contains("-i br1 ") && !s.contains("-i br2 ")));
    }
    run(Operation::Teardown, now + 96).unwrap();
    verify(false);
    assert!(redirect_bridges(&db, true).unwrap().is_empty());
}
fn zones(db: &Store, z: Value) {
    nfqws2_awg_profile::edit_document(db, |doc| {
        doc["servers"][0]["config"]["routing"]["zones"] = z;
        doc["routing_revision"] = json!(doc["routing_revision"].as_u64().unwrap() + 1);
        Ok(())
    })
    .unwrap();
}
#[test]
fn dual_stack_preserves_separate_kernel_tables_and_recovers_both_after_power_loss() {
    let (_tmp, db, v4) = setup();
    let router = Dual {
        v4,
        ..Default::default()
    };
    zones(
        &db,
        json!([{"enabled":true,"ips":["2001:db8:1234::1/64","203.0.113.0/24"]}]),
    );
    protect(&db);
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &router, op, 10, dual_peer).unwrap();
    }
    assert!(inspect(&db, &router).unwrap().ready);
    let v6target = "2001:db8:1234::8";
    let v4target = "203.0.113.8";
    let verify = |active: bool| {
        for (fake, src, dst) in [
            (&router.v4, "192.168.1.1", v4target),
            (&router.v6, "fd21::1", v6target),
        ] {
            let fw = fake.0.lock().unwrap();
            assert_eq!(fw.rule, active);
            assert_eq!(fw.forward(src, dst), if active { "awg0" } else { "wan0" });
            assert_eq!(
                fw.firewall.values().map(BTreeSet::len).sum::<usize>(),
                if active { 5 } else { 0 }
            );
        }
    };
    verify(true);
    operate_at(&db, &router, Operation::Suspend, 12, dual_peer).unwrap();
    verify(false);
    for fake in [&router.v4, &router.v6] {
        *fake.0.lock().unwrap() = Firmware {
            boot: "51515151-5151-5151-5151-515151515151".into(),
            ..Default::default()
        };
    }
    operate_at(&db, &router, Operation::Recover, 13, dual_peer).unwrap();
    verify(true);
    let foreign = "-A INPUT -m comment --comment n2s-awg-cidr -j LOG";
    router
        .v6
        .0
        .lock()
        .unwrap()
        .firewall
        .entry("filter".into())
        .or_default()
        .insert(foreign.into());
    assert!(inspect(&db, &router).is_err());
    operate_at(&db, &router, Operation::Teardown, 14, dual_peer).unwrap();
    assert!(router
        .v6
        .0
        .lock()
        .unwrap()
        .firewall
        .get_mut("filter")
        .unwrap()
        .remove(foreign));
    verify(false);
}
#[test]
fn sources_match_only_their_family_and_ipv6_can_move_to_its_own_reserve() {
    let (_tmp, db, v4) = setup();
    let router = Dual {
        v4,
        ..Default::default()
    };
    scoped_policy(&db);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][1]["config"]["routing"]["zones"] = json!([]);
        Ok(())
    })
    .unwrap();
    zones(
        &db,
        json!([
            {"order":1,"enabled":true,"route":"direct","ips":["2001:db8:99::1"],"source_ips":["fd00:7::1"]},
            {"order":2,"enabled":true,"route":"tunnel","ips":["2001:db8:99::/125","203.0.113.6"],"source_ips":["fd00:7::/124","192.168.7.1"],"fallback_tunnel_ids":["branch"]}
        ]),
    );
    protect(&db);
    router.v6.0.lock().unwrap().local = "3: br0 inet6 fd00:7::10/64 scope global".into();
    router.v4.0.lock().unwrap().local = "3: br0 inet 192.168.7.2/24 scope global".into();
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &router, op, 10, dual_peer).unwrap();
    }
    for (primary, backup, want) in [
        (false, true, "awg1"),
        (false, false, "blackhole"),
        (true, true, "awg0"),
    ] {
        operate_at(&db, &router, Operation::Refresh, 13, |cfg, iface| {
            let mut peer = dual_peer(cfg, iface)?;
            if !(if iface == "awg0" { primary } else { backup }) {
                peer.allowed.retain(|s| !s.contains(':'));
            }
            Ok(peer)
        })
        .unwrap();
        let v6 = router.v6.0.lock().unwrap();
        assert_eq!(v6.forward("fd00:7::1", "2001:db8:99::1"), "wan0");
        assert_eq!(v6.forward("fd00:7::2", "2001:db8:99::1"), want);
        assert_eq!(v6.forward("fd00:8::2", "2001:db8:99::1"), "wan0");
        drop(v6);
        let v4 = router.v4.0.lock().unwrap();
        assert_eq!(v4.forward("192.168.7.1", "203.0.113.6"), "awg0");
        assert_eq!(v4.forward("192.168.7.2", "203.0.113.6"), "wan0");
    }
}
#[test]
fn ipv6_only_static_profile_uses_no_ipv4_tables_and_keeps_a_small_journal() {
    struct Ipv6Only(Dual);
    impl Runner for Ipv6Only {
        fn run(&self, command: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
            assert!(command != "iptables" && !args.contains(&"-4"));
            self.0.run(command, args, deadline)
        }
    }
    let (tmp, db, _) = setup();
    let router = Ipv6Only(Dual::default());
    zones(&db, json!([{"enabled":true,"ips":["fd12:3456::/64"]}]));
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &router, op, 10, |_, _| {
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
                endpoint: "[2001:db8:f00::1]:51820".parse().unwrap(),
                allowed: vec!["fd12:3456::/64".into()],
            })
        })
        .unwrap();
    }
    assert_eq!(
        router
            .0
            .v6
            .0
            .lock()
            .unwrap()
            .forward("fd10::1", "fd12:3456::10"),
        "awg0"
    );
    let bytes = std::fs::metadata(tmp.path().join(".store/runtime").join(RECEIPT))
        .unwrap()
        .len();
    assert!(
        bytes < 1024,
        "single IPv6 split receipt grew to {bytes} bytes"
    );
    eprintln!("Single IPv6 split receipt: {bytes} bytes");
}

#[test]
fn entware_ip_full_reads_native_ipv6_format_and_refuses_ambiguous_ownership() {
    const FULL: &str = "/opt/libexec/ip-full";
    struct Entware<'a> {
        installed: bool,
        aliases: &'a str,
        routes: &'a str,
    }
    impl Runner for Entware<'_> {
        fn run(&self, bin: &str, args: &[&str], _: Instant) -> io::Result<String> {
            let text = match (bin, args) {
                ("ip", _) => return Err(err("BusyBox: unsupported option")),
                (FULL, _) if !self.installed => return Err(io::ErrorKind::NotFound.into()),
                (FULL, ["-V"]) => "ip utility, iproute2-ss4.4.0-11-entware",
                (FULL, ["-N", "-V"]) => return Err(err("unknown option -N")),
                ("sh", ["-c", script]) if script.contains("rt_protos") => self.aliases,
                (FULL, ["-o", "-6", "rule", "show"]) => {
                    "0:\tfrom all lookup local\n32766:\tfrom all lookup main"
                }
                (FULL, ["-o", "-6", "route", "show", "table", "all"]) => self.routes,
                ("ip6tables", ["-w", "-t", _, "-S"]) => "",
                _ => panic!("unexpected route mutation or capability probe: {bin} {args:?}"),
            };
            Ok(text.into())
        }
    }
    let route = "2001:db8:beef::1 dev awg0  table 17842  proto 242  metric 1024  pref medium";
    let obj = Object::Route("2001:db8:beef::1".parse().unwrap(), "awg0".into(), 17842);
    let claims = BTreeSet::from([obj]);
    let mut system = Entware {
        installed: true,
        aliases: "rt_tables\n255 local\n254 main\n253 default\nrt_protos\n2 kernel\n",
        routes: route,
    };
    assert_eq!(kernel(&system).inventory(&claims, true).unwrap(), claims);
    // A loopback route on Keenetic is printed as unreachable even when
    // requested as unicast. Neither this nor a blackhole belongs to our TUN.
    for foreign in [
        "unreachable 2001:db8:beef::1 dev lo table 17842 proto 242 metric 1024 error -101 pref medium",
        "blackhole 2001:db8:beef::2 dev lo table 17842 proto 242 metric 21992 error -22 pref medium",
    ] {
        system.routes = foreign;
        assert!(kernel(&system).inventory(&claims,true).is_err());
        assert!(kernel(&system).inventory(&claims,false).unwrap().is_empty());
    }
    system.routes = route;
    for aliases in [
        "rt_tables\n0x45b2 hidden",
        "rt_protos\n242 custom",
        "rt_tables\n60 17842",
        "rt_tables\n12 local",
    ] {
        system.aliases = aliases;
        assert!(kernel(&system).inventory(&claims, true).is_err());
    }
    system.installed = false;
    assert!(kernel(&system)
        .inventory(&claims, true)
        .unwrap_err()
        .to_string()
        .contains("ip-full"));
}

#[test]
fn invalid_new_ipv6_plan_preserves_preexisting_ipv4_state_and_foreign_objects() {
    let (_tmp, db, v4) = setup();
    let router = Dual {
        v4,
        ..Default::default()
    };
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &router, op, 10, peer).unwrap();
    }
    let baseline = Journal::read(&db).unwrap().installed;
    let changes = router.v4.0.lock().unwrap().changes;
    router.v6.0.lock().unwrap().local = "3: br0 inet6 fd00:1234::1/64 scope global".into();
    for dest in [
        "2001:db8:f00::1",
        "fd00:1234::a",
        "fe80::1",
        "::ffff:203.0.113.7",
        "ff02::1",
        "::1",
        "::/0",
    ] {
        zones(&db, json!([{"enabled":true,"ips":[dest]}]));
        assert!(
            operate_at(&db, &router, Operation::Apply, 12, dual_peer).is_err(),
            "{dest}"
        );
        assert_eq!(Journal::read(&db).unwrap().installed, baseline);
    }
    zones(&db, json!([{"enabled":true,"ips":["2001:db8:111::1"]}]));
    assert!(operate_at(&db, &router, Operation::Apply, 12, peer).is_err());
    router.v6.0.lock().unwrap().foreign_route =
        "2001:db8:cafe::/48 dev adminvpn table 17842 proto static metric 1024".into();
    assert!(operate_at(&db, &router, Operation::Apply, 12, dual_peer).is_err());
    assert_eq!(router.v4.0.lock().unwrap().changes, changes);
    assert_eq!(router.v6.0.lock().unwrap().changes, 0);
    assert_eq!(Journal::read(&db).unwrap().installed, baseline);
}

#[test]
fn profile_hostnames_and_backup_addresses_use_the_same_resolver_as_the_engine() {
    let server = json!({"id":"a","config":{"enabled":true,"endpoint":"localhost:51820","client":{
        "endpoint_backups":["[2001:db8::3]:1234","198.51.100.5:1234"]
    }}});
    let expected = nfqws2_awg_profile::resolve_endpoint_addresses(
        "localhost:51820",
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap();
    let mut doc =
        json!({"servers":[server,{"id":"off","config":{"enabled":false,"endpoint":"invalid"}}]});
    let ips = plan::endpoints_for(&doc, true, |_| true).unwrap();
    assert!(expected
        .iter()
        .all(|a| ips.contains(&a.ip().to_canonical())));
    assert!(expected.iter().any(|a| a.ip().is_loopback()));
    for ip in ["2001:db8::3", "198.51.100.5"] {
        assert!(ips.contains(&ip.parse().unwrap()));
    }
    doc["servers"][0]["config"]["client"]["endpoint_backups"] = json!(["invalid"]);
    assert!(plan::endpoints_for(&doc, true, |_| true).is_err());
}

#[test]
fn direct_only_ipv6_dns_checks_local_networks_without_requiring_a_live_tunnel() {
    let (_tmp, db, v4) = setup();
    let router = Dual {
        v4,
        ..Default::default()
    };
    router.v6.0.lock().unwrap().local = "3: br0 inet6 fd00:b00::1/64 scope global".into();
    zones(
        &db,
        json!([{"enabled":true,"route":"direct","domains":["office.test"],"include_subdomains":false}]),
    );
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["config"]["endpoint"] = json!("unrelated.example:51820");
        Ok(())
    })
    .unwrap();
    let request = dns_request(&db, Operation::Apply).unwrap().unwrap();
    assert_eq!(request.dual_stack, ["office.test"]);
    for (ip, expected) in [("fd00:b00::20", false), ("2001:db8:ac::2", true)] {
        let snapshot = DnsSnapshot {
            request: request.clone(),
            answers: BTreeMap::from([("office.test".into(), vec![ip.parse().unwrap()])]),
        };
        let result = operate_with_dns_at(
            &db,
            &router,
            Operation::Apply,
            10,
            Some(&snapshot),
            |_, _| panic!("direct rule requests a peer"),
        );
        assert_eq!(result.is_ok(), expected, "{ip}: {result:?}");
        assert_eq!(router.v6.0.lock().unwrap().changes, 0);
    }
}
#[test]
fn one_dns_snapshot_distributes_each_family_only_to_its_selected_peer() {
    let (_tmp, db, _router) = setup();
    scoped_policy(&db);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let rows = doc["servers"].as_array_mut().unwrap();
        for (i, row) in rows.iter_mut().enumerate() {
            let cfg = &mut row["config"];
            let address = if i == 0 {
                "10.10.0.2/32"
            } else {
                "fd12:3::2/128"
            };
            cfg["peers"] = json!([{"id":"default","is_router":true,"address":"192.168.200.2/32"},
                {"id":"selected","address":address}]);
            cfg["client"]["peer_id"] = json!("selected");
            cfg["routing"]["zones"] = json!([{"order":i+2,"name":format!("peer {i}"),"enabled":true,
                "domains":["shared.test"],"include_subdomains":false}]);
        }
        rows[0]["config"]["routing"]["zones"]
            .as_array_mut()
            .unwrap()
            .push(json!({
            "order":1,"route":"direct","enabled":true,"ips":["2001:db8:22::2"],
            "source_ips":["fd12:ab::/64"]}));
        Ok(())
    })
    .unwrap();
    let request = dns_request(&db, Operation::Apply).unwrap().unwrap();
    assert_eq!(request.dual_stack, ["shared.test"]);
    let v4addr = "203.0.113.41";
    let v6addr = "2001:db8:22::2";
    let snapshot = DnsSnapshot {
        request,
        answers: BTreeMap::from([(
            "shared.test".into(),
            vec![v4addr.parse().unwrap(), v6addr.parse().unwrap()],
        )]),
    };
    let doc = nfqws2_awg_profile::read(&db).unwrap();
    let plan = plan::compile(&doc, Some(&snapshot), false).unwrap();
    let selects = |src: &str, dest: &str| {
        plan.flows()
            .find(|(s, _)| {
                s.source.contains(src.parse().unwrap()) && s.dest.contains(dest.parse().unwrap())
            })
            .map(|(_, iface)| iface)
    };
    assert_eq!(selects("192.168.2.4", v4addr), Some("awg0"));
    assert_eq!(selects("fd12:ac::4", v6addr), Some("awg1"));
    assert_eq!(selects("fd12:ab::2", v6addr), None);
}

#[test]
fn dns_receipt_checks_families_limits_and_keeps_old_ipv4_json_readable() {
    let mut sample: DnsSnapshot = serde_json::from_value(json!({
        "request":{"names":["vpn.test"],"revision":3},
        "answers":{"vpn.test":["203.0.113.1"]}
    }))
    .unwrap();
    assert!(sample.validate(3).is_ok());
    sample
        .answers
        .get_mut("vpn.test")
        .unwrap()
        .push("2001:db8::5".parse().unwrap());
    assert!(sample.validate(3).is_err());
    sample.request.dual_stack.push("vpn.test".into());
    assert!(sample.validate(3).is_ok());
    sample.request.ipv6_only.push("vpn.test".into());
    assert!(sample.validate(3).is_err());
    sample.request.dual_stack.clear();
    assert!(sample.validate(3).is_err());
    sample.answers.get_mut("vpn.test").unwrap().remove(0);
    assert!(sample.validate(3).is_ok());
    sample.request.ipv6_only.push("vpn.test".into());
    assert!(sample.validate(3).is_err());
    sample.request.ipv6_only = vec!["other.test".into()];
    assert!(sample.validate(3).is_err());
    sample.request.ipv6_only.clear();
    sample.request.dual_stack = vec!["vpn.test".into()];
    let ips = sample.answers.get_mut("vpn.test").unwrap();
    ips.clear();
    for n in 1..=16 {
        ips.push(format!("192.0.2.{n}").parse().unwrap());
        ips.push(format!("2001:db8::{n}").parse().unwrap());
    }
    assert!(sample.validate(3).is_ok());
    sample
        .answers
        .get_mut("vpn.test")
        .unwrap()
        .push("2001:db8::42".parse().unwrap());
    assert!(sample.validate(3).is_err());
}

#[test]
fn largest_dual_stack_receipts_fit_the_recovery_read_budget() {
    // Deliberately overstate the actual bound: committed may not contain
    // selections/offline rows, a checkpoint has only stops, and an actual
    // policy JSON cannot consist entirely of bytes needing escaping.
    let addr = "2001:db80:abcd:abcd:abcd:abcd:abcd:abcd";
    let prefix = format!("{addr}/128");
    let selector = json!({"source":prefix,"dest":prefix});
    let ifaces: Vec<_> = (0..8).map(|i| format!("awg{i:012}")).collect();
    let target = json!({"id":"s".repeat(128),"public_key":"\0".repeat(44),"mtu":9000});
    let targets = ifaces
        .iter()
        .map(|i| (i.clone(), target.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut plan = json!({"prefixes":{},"killswitch":true,"offline":ifaces,"revision":u64::MAX,"targets":targets,
        "scoped":vec![json!([selector,ifaces[0]]);128],"reserves":vec![json!([selector,ifaces[1..]]);128],
        "selected":vec![json!([selector,ifaces[1]]);128]});
    let names: Vec<_> = (0..32)
        .map(|i| format!("{}{i:02}", "x".repeat(251)))
        .collect();
    let answers = names
        .iter()
        .map(|n| (n.clone(), vec![addr; 32]))
        .collect::<BTreeMap<_, _>>();
    let eager = json!({"snapshot":{"request":{"revision":u64::MAX,"names":names,"dual_stack":names},"answers":answers},"source_hash":"e".repeat(64)});
    let observed = json!({"policy":"\"".repeat(32<<10),"hash":"c".repeat(64),
        "members":vec![json!({"zone":2047,"ip":addr,"until":u64::MAX});128]});
    for (field, value) in [("dns", eager), ("learned", observed)] {
        plan[field] = value;
        let p: Snapshot = serde_json::from_value(plan.clone()).unwrap();
        let journal = Journal {
            boot: BOOT.into(),
            installed: p.clone(),
            committed: p.clone(),
            preparing: vec![p; LEGACY_PREPARATIONS + 1],
            expires: u64::MAX,
        };
        let bytes = serde_json::to_vec(&journal).unwrap().len() + 1;
        assert!(
            bytes as u64 <= RECEIPT_LIMIT,
            "{field} receipt consumes {bytes} bytes"
        );
        plan.as_object_mut().unwrap().remove(field);
    }
}
