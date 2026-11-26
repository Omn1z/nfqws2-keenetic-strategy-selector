use super::*;

#[test]
fn fw3_migrates_a_live_legacy_receipt_and_restores_the_lan_zone_after_reload() {
    let (_tmp, db, f) = setup();
    let now = nfqws2_awg_profile::now();
    for op in [Operation::Apply, Operation::Commit] {
        action(&db, &f, op, now).unwrap();
    }
    f.0.lock().unwrap().openwrt = "fw3";
    action(&db, &f, Operation::Refresh, now).unwrap();
    let owned = {
        let mut fw = f.0.lock().unwrap();
        let filter = fw.firewall.get_mut("filter").unwrap();
        assert_eq!(filter.len(), 1);
        let rule = filter.pop_first().unwrap();
        assert!(rule.contains("-A zone_lan_forward -d 203.0.113.0/24 -o awg0"));
        rule
    };
    assert!(!inspect(&db, &f).unwrap().active);
    action(&db, &f, Operation::Refresh, now).unwrap();
    assert!(f.0.lock().unwrap().firewall["filter"].contains(&owned));
    action(&db, &f, Operation::Teardown, now).unwrap();
    assert!(f
        .0
        .lock()
        .unwrap()
        .firewall
        .values()
        .all(BTreeSet::is_empty));
}

struct Fw4 {
    routes: Fake,
    rules: Mutex<BTreeMap<String, BTreeSet<String>>>,
}

#[test]
fn fw4_renamed_zone_and_pending_trial_preserve_foreign_ownership_and_deadline() {
    let (_tmp, db, routes) = setup();
    routes.0.lock().unwrap().openwrt = "fw4";
    let fw = Fw4 { routes, rules: Default::default() };
    operate_at(&db, &fw, Operation::Apply, 10, peer).unwrap();
    let old = Journal::read(&db).unwrap();
    assert!(old.installed.fw4_zone.is_none());
    assert!(!serde_json::to_string(old.installed.as_ref()).unwrap().contains("fw4_zone"));
    let tag = r#"iifname "eth9" drop comment "admin""#;
    let collision = r#"ip daddr 203.0.113.0/24 oifname "awg0" accept comment "n2s-awg-cidr""#;
    let mut rules = fw.rules.lock().unwrap();
    // The old chain is now a different network, but its own admin rules
    // must survive. An identical tagged grant at the new location is not
    // ours: the persisted previous generation never claimed forward_home.
    rules.get_mut("forward_lan").unwrap().insert(tag.into());
    rules.insert("forward_home".into(), BTreeSet::from([tag.into(), collision.into()]));
    drop(rules);
    fw.routes.0.lock().unwrap().renamed_zone = true;
    assert!(operate_at(&db, &fw, Operation::FirewallReload, 11, peer).is_err());
    assert_eq!(fw.rules.lock().unwrap()["forward_lan"], BTreeSet::from([tag.into()]));
    assert!(fw.rules.lock().unwrap().get_mut("forward_home").unwrap().remove(collision));
    assert!(operate_at(&db, &fw, Operation::FirewallReload, 12, |_, _| Err(io::ErrorKind::NotConnected.into())).is_err());
    assert_eq!(fw.rules.lock().unwrap()["forward_home"], BTreeSet::from([tag.into()]));
    assert_eq!(Journal::read(&db).unwrap(), old);
    operate_at(&db, &fw, Operation::FirewallReload, 13, peer).unwrap();
    let rebound = Journal::read(&db).unwrap();
    assert_eq!(rebound.installed.fw4_zone.as_deref(), Some("home"));
    assert_eq!(rebound.expires, old.expires);
    assert!(rebound.preparing.is_empty());
    assert_eq!(schedule_with_fw4_chain(&db).unwrap().1.as_deref(), Some("forward_home"));
    operate_at(&db, &fw, Operation::Commit, 14, peer).unwrap();
    operate_at(&db, &fw, Operation::Suspend, 15, peer).unwrap();
    assert!(Journal::read(&db).unwrap().committed.fw4_zone.is_none());
    operate_at(&db, &fw, Operation::Recover, 16, peer).unwrap();
    assert!(inspect(&db, &fw).unwrap().active);
    operate_at(&db, &fw, Operation::Teardown, 17, peer).unwrap();
    let rules = fw.rules.lock().unwrap();
    for chain in ["forward_lan", "forward_home"] {
        assert_eq!(rules[chain], BTreeSet::from([tag.into()]));
    }
}

#[test]
fn fw4_zone_name_is_one_bounded_fw4_identifier() {
    for z in ["office", "a-b", "f.8", "_IoT", "a/b"] {
        assert!(fw4::valid_zone(z));
    }
    for z in ["", "1", "a\nb", "a b", "x;y", "a*", "a\0", "/x", "a'", "a$"] {
        assert!(!fw4::valid_zone(z));
    }
    assert!(fw4::valid_zone(&"a".repeat(247)));
    assert!(!fw4::valid_zone(&"a".repeat(248)));
}

#[test]
fn fw4_conflicting_writer_under_reload_lock_is_never_adopted_or_deleted_by_rollback() {
    struct Race<'a>(&'a Fw4);
    impl Runner for Race<'_> {
        fn run(&self, bin: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
            if let ("sh", ["-c", script, "awg-fw4", _, add, _, _, _]) = (bin, args) {
                if *script == fw4::UPDATE && !add.is_empty() {
                    let mut rules = self.0.rules.lock().unwrap();
                    for line in add.lines() {
                        let (name, body) = line.split_once('\t').unwrap();
                        rules.entry(name.into()).or_default().insert(body.into());
                    }
                    return Ok("fw4-refused".into());
                }
            }
            self.0.run(bin, args, deadline)
        }
    }
    for rename in [false, true] {
        let (_tmp, db, routes) = setup();
        routes.0.lock().unwrap().openwrt = "fw4";
        let fw = Fw4 { routes, rules: Default::default() };
        if rename {
            operate_at(&db, &fw, Operation::Apply, 10, peer).unwrap();
            fw.routes.0.lock().unwrap().renamed_zone = true;
            fw.rules.lock().unwrap().remove("forward_lan");
        }
        let old = Journal::read(&db).unwrap();
        let op = if rename {Operation::FirewallReload} else {Operation::Apply};
        assert!(operate_at(&db, &Race(&fw), op, 11, peer).is_err());
        let chain = if rename {"forward_home"} else {"forward_lan"};
        assert_eq!(fw.rules.lock().unwrap()[chain].len(), 1);
        let now = Journal::read(&db).unwrap();
        assert_eq!(now.installed, old.installed);
        assert_eq!(now.expires, old.expires);
        assert!(now.preparing.is_empty());
        operate_at(&db, &fw, Operation::Teardown, 12, peer).unwrap();
        assert_eq!(fw.rules.lock().unwrap()[chain].len(), 1);
    }
}
impl Runner for Fw4 {
    fn run(&self, bin: &str, args: &[&str], end: Instant) -> io::Result<String> {
        match (bin, args) {
            ("nft", ["-a", "list", "chain", "inet", "fw4", chain]) => {
                let rules = self.rules.lock().unwrap();
                if *chain == "forward_lan" && self.routes.0.lock().unwrap().renamed_zone
                    && !rules.contains_key(*chain) {
                    return Err(io::ErrorKind::NotFound.into());
                }
                let mut text = format!("table inet fw4 {{\n\tchain {chain} {{ # handle 2\n");
                for (n, body) in rules.get(*chain).into_iter().flatten().enumerate() {
                    use std::fmt::Write;
                    writeln!(text, "\t\t{body} # handle {}", n + 10).unwrap();
                }
                Ok(text)
            }
            ("nft", ["list", "chains", "inet"]) => Ok("table inet fw4 {\n chain forward_home {\n }\n chain srcnat {\n }\n chain mangle_forward {\n }\n}\ntable inet admin {\n chain forward_lan {\n }\n}".into()),
            ("sh", ["-c", script, "awg-fw4", del, add, _, zone, _]) if *script == fw4::UPDATE => {
                if !add.is_empty() {
                    let actual = if self.routes.0.lock().unwrap().renamed_zone { "home" } else { "lan" };
                    if *zone != actual {return Err(io::ErrorKind::WouldBlock.into());}
                }
                let mut rules = self.rules.lock().unwrap();
                for (updates, remove) in [(del, true), (add, false)] {
                    for line in updates.lines() {
                        let (chain, body) = line.split_once('\t').unwrap();
                        let items = rules.entry(chain.into()).or_default();
                        assert!(if remove {
                            items.remove(body)
                        } else {
                            items.insert(body.into())
                        });
                    }
                }
                Ok(String::new())
            }
            ("iptables" | "ip6tables", _) => panic!("fw4 should use native nftables"),
            _ => self.routes.run(bin, args, end),
        }
    }
}

#[test]
fn fw3_renamed_lan_zone_retains_trial_and_leaves_admin_rules_untouched() {
    let (_tmp, db, f) = setup();
    f.0.lock().unwrap().openwrt = "fw3";
    action(&db, &f, Operation::Apply, 10).unwrap();
    let trial = Journal::read(&db).unwrap();
    assert!(trial.installed.fw4_zone.is_none());
    assert_eq!(scheduled(&db).unwrap(), Schedule::Fw3Trial(trial.expires));
    let admin = "-A zone_lan_forward -o wan1 -m comment --comment admin -j DROP";
    {
        let mut fw = f.0.lock().unwrap();
        fw.renamed_zone = true;
        fw.firewall.get_mut("filter").unwrap().insert(admin.into());
    }
    assert!(!inspect(&db, &f).unwrap().active);
    assert!(operate_at(&db, &f, Operation::Refresh, 11, |_, _| {
        Err(io::ErrorKind::NotConnected.into())
    })
    .is_err());
    assert_eq!(f.0.lock().unwrap().firewall["filter"], BTreeSet::from([admin.into()]));
    assert_eq!(Journal::read(&db).unwrap(), trial);
    action(&db, &f, Operation::Refresh, 12).unwrap();
    let rebound = Journal::read(&db).unwrap();
    assert_eq!(rebound.expires, trial.expires);
    assert_eq!(rebound.installed.fw4_zone.as_deref(), Some("home"));
    assert!(inspect(&db, &f).unwrap().active);
    assert!(f.0.lock().unwrap().firewall["filter"].iter().any(|rule| {
        rule.starts_with("-A zone_home_forward -d 203.0.113.0/24 -o awg0")
    }));
    action(&db, &f, Operation::Commit, 13).unwrap();
    action(&db, &f, Operation::Suspend, 14).unwrap();
    assert!(Journal::read(&db).unwrap().committed.fw4_zone.is_none());
    action(&db, &f, Operation::Recover, 15).unwrap();
    assert!(inspect(&db, &f).unwrap().active);
    f.0.lock().unwrap().renamed_zone = false;
    action(&db, &f, Operation::Refresh, 16).unwrap();
    assert!(inspect(&db, &f).unwrap().active);
    assert!(Journal::read(&db).unwrap().committed.fw4_zone.is_none());
    action(&db, &f, Operation::Teardown, 17).unwrap();
    assert_eq!(f.0.lock().unwrap().firewall["filter"], BTreeSet::from([admin.into()]));
}

#[test]
fn fw3_fresh_renamed_zone_rejects_unowned_matching_grant() {
    let (_tmp, db, f) = setup();
    let foreign = "-A zone_home_forward -d 203.0.113.0/24 -o awg0 -m comment --comment n2s-awg-cidr -j ACCEPT";
    {
        let mut fw = f.0.lock().unwrap();
        fw.openwrt = "fw3";
        fw.renamed_zone = true;
        fw.firewall.entry("filter".into()).or_default().insert(foreign.into());
    }
    assert!(action(&db, &f, Operation::Apply, 10).is_err());
    assert!(Journal::read(&db).unwrap().idle());
    assert_eq!(f.0.lock().unwrap().changes, 0);
    assert!(f.0.lock().unwrap().firewall.get_mut("filter").unwrap().remove(foreign));
    action(&db, &f, Operation::Apply, 11).unwrap();
    assert_eq!(Journal::read(&db).unwrap().installed.fw4_zone.as_deref(), Some("home"));
    action(&db, &f, Operation::Teardown, 12).unwrap();
    assert!(f.0.lock().unwrap().firewall["filter"].is_empty());
}

#[test]
fn fw3_rename_during_install_retires_the_unconfirmed_grant() {
    struct RenameOnWrite<'a>(&'a Fake);
    impl Runner for RenameOnWrite<'_> {
        fn run(&self, program: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
            let result = self.0.run(program, args, deadline);
            if let ("iptables", ["-w", "-t", "filter", "-A", "zone_lan_forward", ..]) =
                (program, args)
            {
                let Fake(firmware) = self.0;
                firmware.lock().unwrap().renamed_zone = true;
            }
            result
        }
    }
    let (_tmp, db, f) = setup();
    f.0.lock().unwrap().openwrt = "fw3";
    let error = operate_at(&db, &RenameOnWrite(&f), Operation::Apply, 10, peer).unwrap_err();
    assert!(error.to_string().contains("изменилась зона"));
    assert!(Journal::read(&db).unwrap().idle());
    let state = f.0.lock().unwrap();
    assert!(state.firewall.values().all(BTreeSet::is_empty));
    assert!(state.routes.is_empty());
    assert!(!state.rule);
}

#[test]
fn fw4_teardown_after_lan_zone_rename_removes_remaining_owned_objects() {
    let (_tmp, db, f) = setup();
    f.0.lock().unwrap().openwrt = "fw4";
    let fw = Fw4 {
        routes: f,
        rules: Default::default(),
    };
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &fw, op, 10, peer).unwrap();
    }
    fw.routes.0.lock().unwrap().renamed_zone = true;
    // Even if the former chain still exists, it no longer represents LAN.
    assert!(!inspect(&db, &fw).unwrap().active);
    fw.rules.lock().unwrap().remove("forward_lan");
    operate_at(&db, &fw, Operation::Refresh, 12, peer).unwrap();
    assert_eq!(Journal::read(&db).unwrap().committed.fw4_zone.as_deref(), Some("home"));
    operate_at(&db, &fw, Operation::Teardown, 13, peer).unwrap();
    assert!(fw.rules.lock().unwrap().values().all(BTreeSet::is_empty));
    assert!(fw.routes.0.lock().unwrap().routes.is_empty());
    assert!(!fw.routes.0.lock().unwrap().rule);
    assert!(Journal::read(&db).unwrap().idle());
}

#[test]
fn fw4_uses_zones_recovers_after_reload_and_preserves_foreign_rules() {
    let (_tmp, db, f) = setup();
    f.0.lock().unwrap().openwrt = "fw4";
    f.0.lock().unwrap().local = "2: eth0.2@eth0 inet 192.168.1.1/24 scope global eth0.2".into();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let zone = &mut doc["servers"][0]["config"]["routing"]["zones"][0];
        zone["source_ips"] = json!(["192.168.1.2"]);
        zone["ips"] = json!(["203.0.113.11"]);
        Ok(())
    })
    .unwrap();
    let fw = Fw4 {
        routes: f,
        rules: Default::default(),
    };
    let now = nfqws2_awg_profile::now();
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &fw, op, now, peer).unwrap();
    }
    let saved = fw.rules.lock().unwrap().clone();
    assert!(saved["forward_lan"].contains(
        r#"ip saddr 192.168.1.2 ip daddr 203.0.113.11 oifname "awg0" accept comment "n2s-awg-cidr""#
    ));
    let foreign = r#"oifname "awg1" counter drop comment "admin""#;
    *fw.rules.lock().unwrap() =
        BTreeMap::from([("forward_lan".into(), BTreeSet::from([foreign.into()]))]);
    assert!(!inspect(&db, &fw).unwrap().active);
    operate_at(&db, &fw, Operation::Refresh, now, peer).unwrap();
    assert!(inspect(&db, &fw).unwrap().ready);
    let duplicate_tag = r#"oifname "awg1" accept comment "n2s-awg-cidr""#;
    fw.rules
        .lock()
        .unwrap()
        .get_mut("forward_lan")
        .unwrap()
        .insert(duplicate_tag.into());
    assert!(inspect(&db, &fw).is_err());
    operate_at(&db, &fw, Operation::Teardown, now, peer).unwrap();
    let left = fw.rules.lock().unwrap();
    assert!(left["mangle_forward"].is_empty() && left["srcnat"].is_empty());
    assert_eq!(
        left["forward_lan"],
        BTreeSet::from([duplicate_tag.into(), foreign.into()])
    );
}

#[test]
fn fw4_event_reasserts_a_trial_without_extending_it_and_refuses_stale_identity_or_routes() {
    let (_dir, db, f) = setup();
    f.0.lock().unwrap().openwrt = "fw4";
    let router = Fw4 {routes: f, rules: Default::default()};
    operate_at(&db,&router,Operation::Apply,10,peer).unwrap();
    let original = Journal::read(&db).unwrap();
    let deadline = original.expires;
    assert!(scheduled_with_fw4(&db).unwrap().1);
    let rules = router.rules.lock().unwrap().clone();
    assert_eq!(rules.len(),3);
    let events = router.routes.0.lock().unwrap().changes;
    router.rules.lock().unwrap().clear();
    operate_at(&db,&router,Operation::FirewallReload,deadline,peer).unwrap();
    assert!(router.rules.lock().unwrap().is_empty());
    assert!(operate_at(&db,&router,Operation::FirewallReload,13,|_,_|Err(io::ErrorKind::NotConnected.into())).is_err());
    assert!(router.rules.lock().unwrap().is_empty());
    router.routes.0.lock().unwrap().rule=false;
    assert!(operate_at(&db,&router,Operation::FirewallReload,14,peer).is_err());
    assert!(router.rules.lock().unwrap().is_empty());
    router.routes.0.lock().unwrap().rule=true;
    struct LostAck<'a>(&'a Fw4);
    impl Runner for LostAck<'_> {
        fn run(&self, prog: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
            let reply = self.0.run(prog, args, deadline)?;
            if matches!(args, ["-c", script, "awg-fw4", ..] if *script == fw4::UPDATE) {
                return Err(io::ErrorKind::Interrupted.into());
            }
            Ok(reply)
        }
    }
    operate_at(&db,&LostAck(&router),Operation::FirewallReload,15,peer).unwrap();
    assert_eq!(*router.rules.lock().unwrap(),rules);
    assert_eq!(Journal::read(&db).unwrap(),original);
    assert_eq!(router.routes.0.lock().unwrap().changes,events);
    operate_at(&db,&router,Operation::Commit,16,peer).unwrap();
    let foreign = r#"oifname "eth0" drop comment "n2s-awg-cidr""#;
    let overwritten = BTreeMap::from([("forward_lan".into(),BTreeSet::from([foreign.into()]))]);
    *router.rules.lock().unwrap()=overwritten.clone();
    assert!(operate_at(&db,&router,Operation::FirewallReload,17,peer).is_err());
    assert_eq!(*router.rules.lock().unwrap(),overwritten);
    operate_at(&db,&router,Operation::Suspend,18,peer).unwrap();
    assert!(!scheduled_with_fw4(&db).unwrap().1);
    operate_at(&db,&router,Operation::FirewallReload,19,peer).unwrap();
    assert_eq!(*router.rules.lock().unwrap(),overwritten);
}

#[test]
fn fw4_event_reasserts_only_installed_rules_during_a_parked_transport_edit() {
    use nfqws2_awg_profile::{RoutedEndpointEdit, RoutedLegacyPredecessor, RoutedMtuChange};

    struct UnreachableDormant<'a> {
        router: &'a Fw4,
        blocked: Mutex<bool>,
    }
    impl Runner for UnreachableDormant<'_> {
        fn run(&self, bin: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
            if bin == "ip"
                && args == ["-4", "route", "get", "198.51.100.93"]
                && *self.blocked.lock().unwrap()
            {
                return Err(io::ErrorKind::NotConnected.into());
            }
            self.router.run(bin, args, deadline)
        }
    }

    const USED: &str = "198.51.100.10:443";
    const DORMANT: &str = "198.51.100.93:443";
    const SUCCESSOR: &str = "198.51.100.30:443";
    const NAME: &str = "routed-fw4.invalid:443";
    const TARGET: &str = "203.0.113.12";
    const OTHER: &str = "203.0.113.13";
    const SOURCE: &str = "192.168.1.7";
    const ADMIN: &str = r#"oifname "wan1" counter drop comment "admin""#;
    for named in [false, true] {
        let (_dir, db, routes) = setup();
        scoped_policy(&db);
        protect(&db);
        {
            let mut fw = routes.0.lock().unwrap();
            fw.openwrt = "fw4";
            fw.local = "2: eth0.2@eth0 inet 192.168.1.1/24 scope global eth0.2".into();
        }
        let fw = Fw4 {
            routes,
            rules: Default::default(),
        };
        let runner = UnreachableDormant {
            router: &fw,
            blocked: Mutex::new(false),
        };
        nfqws2_awg_profile::edit_document(&db, |doc| {
            let rows = doc["servers"].as_array_mut().unwrap();
            let cfg = &mut rows[0]["config"];
            cfg["install"] = json!("imported");
            cfg["mtu"] = json!(1420);
            cfg["endpoint"] = json!(if named { USED } else { DORMANT });
            if named {
                cfg["client"]
                    .as_object_mut()
                    .unwrap()
                    .remove("rust_managed");
            } else {
                cfg["client"]["rust_managed"] = json!(true);
                cfg["client"]["endpoint_backups"] = json!([USED]);
            }
            cfg["routing"]["zones"] =
                json!([{"order":1,"enabled":true,"ips":[TARGET],"source_ips":[SOURCE]}]);
            rows[1]["config"]["endpoint"] = json!("198.51.100.80:443");
            rows[1]["config"]["routing"]["zones"] =
                json!([{"order":2,"enabled":true,"ips":[OTHER],"source_ips":[SOURCE]}]);
            Ok(())
        })
        .unwrap();
        let sample = |cfg: &Value, iface: &str| {
            Ok(LivePeer {
                endpoint: if iface == "awg0" {
                    USED
                } else {
                    "198.51.100.80:443"
                }
                .parse()
                .unwrap(),
                ..both_peers(cfg, iface)?
            })
        };
        let now = nfqws2_awg_profile::now();
        for op in [Operation::Apply, Operation::Commit] {
            operate_at(&db, &runner, op, now, sample).unwrap();
        }
        let live = Journal::read(&db).unwrap();
        let change = RoutedMtuChange {
            id: live.committed.targets["awg0"].id.clone(),
            iface: "awg0".into(),
            revision: live.committed.revision,
            before: 1420,
            after: if named { 1420 } else { 1380 },
            nested_outer: None,
            nested_endpoint: None,
            implicit_before_mtu: None,
            legacy_mtu_before_recorded: false,
            nested_mtu_before_recorded: false,
            native_mtu_endpoint: (!named).then(|| USED.parse().unwrap()),
            legacy_predecessor: named.then(|| RoutedLegacyPredecessor {
                endpoint: USED.parse().unwrap(),
                receipt_sha256: [7; 32],
            }),
            endpoint_edit: named.then(|| RoutedEndpointEdit {
                before: USED.into(),
                after: NAME.into(),
                previous_reserve: None,
                resolved_before: vec![],
                resolved_after: [SUCCESSOR, DORMANT].map(|v| v.parse().unwrap()).into(),
            }),
        };
        let wan = ["wan0".into()];
        *runner.blocked.lock().unwrap() = true;
        validate_endpoint_edit_launch(&db, &runner, &change, &wan).unwrap();
        nfqws2_awg_profile::edit_document(&db, |doc| {
            let row = &mut doc["servers"][0];
            if named {
                row["config"]["endpoint"] = json!(NAME);
            } else {
                row["config"]["mtu"] = json!(change.after);
            }
            row["rust_pending_routed_mtu"] = json!(change);
            row["rust_pending_client_profile"] = json!(vec![7_u8; 32]);
            Ok(())
        })
        .unwrap();
        prepare_mtu_edit_with_wan(&db, &runner, &change, &wan).unwrap();
        let parked = Journal::read(&db).unwrap();
        let lease = mtu_edit::read(&db).unwrap().unwrap();
        let doc = nfqws2_awg_profile::read(&db).unwrap();
        assert!(lease.parked_fw4_proof(&doc, &parked).unwrap().is_some());
        let mut used_as_reserve = parked.clone();
        let other_selector = parked
            .installed
            .flows()
            .find(|(_, owner)| *owner == "awg1")
            .unwrap()
            .0;
        used_as_reserve
            .installed
            .reserves
            .push((other_selector, vec!["awg0".into()]));
        used_as_reserve
            .installed
            .selected
            .push((other_selector, Some("awg0".into())));
        used_as_reserve
            .installed
            .selected
            .sort_unstable_by_key(|(selector, _)| *selector);
        assert!(lease
            .parked_fw4_proof(&doc, &used_as_reserve)
            .unwrap()
            .is_none());

        let only_foreign = BTreeMap::from([("forward_lan".into(), BTreeSet::from([ADMIN.into()]))]);
        let mut expected = fw.rules.lock().unwrap().clone();
        expected
            .get_mut("forward_lan")
            .unwrap()
            .insert(ADMIN.into());
        *fw.rules.lock().unwrap() = only_foreign.clone();
        let reload = || {
            operate_with_redirect_and_mtu(
                &db,
                &runner,
                Operation::FirewallReload,
                None,
                None,
                |cfg, iface| {
                    if iface == "awg0" {
                        Err(io::ErrorKind::NotConnected.into())
                    } else {
                        sample(cfg, iface)
                    }
                },
                |_, _| panic!("fw4 may not authenticate or reopen a staged edit"),
            )
        };
        db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, &live, RECEIPT_LIMIT))
            .unwrap();
        assert!(reload().is_err());
        assert_eq!(*fw.rules.lock().unwrap(), only_foreign);
        db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, &parked, RECEIPT_LIMIT))
            .unwrap();

        let saved_stops = fw.routes.0.lock().unwrap().stops.clone();
        let target_stop = saved_stops
            .iter()
            .find(|s| s.dest.contains(TARGET.parse().unwrap()))
            .unwrap();
        fw.routes.0.lock().unwrap().stops.remove(target_stop);
        assert!(reload().is_err());
        assert_eq!(*fw.rules.lock().unwrap(), only_foreign);
        fw.routes.0.lock().unwrap().stops = saved_stops;
        let kernel_writes = fw.routes.0.lock().unwrap().changes;
        reload().unwrap();
        assert_eq!(*fw.rules.lock().unwrap(), expected);
        let state = fw.routes.0.lock().unwrap();
        assert_eq!(state.forward(SOURCE, TARGET), "blackhole");
        assert_eq!(state.forward(SOURCE, OTHER), "awg1");
        assert_eq!(state.changes, kernel_writes);
        assert_eq!(Journal::read(&db).unwrap(), parked);
        assert_eq!(mtu_edit::read(&db).unwrap().unwrap(), lease);
        assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), doc);
    }
}
