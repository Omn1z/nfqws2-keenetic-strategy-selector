use super::*;

#[test]
fn installer_releases_partial_intent_preserves_foreign_objects_and_verifies_prior_suspend() {
    use super::super::handoff::release_go_routing;
    let (_root, db, f) = setup();
    db.transaction(|tx| {
        tx.save_runtime(
            "awg-go-release.json",
            &json!({"boot":BOOT,"checkpoint":null}),
        )
    })
    .unwrap();
    action(&db, &f, Operation::Apply, 10).unwrap();
    release_go_routing(&db, &f, true).unwrap();
    let mut j = Journal::read(&db).unwrap();
    let mut second = j.installed.clone();
    second.prefixes = BTreeMap::from([("203.0.114.1/32".parse().unwrap(), "awg0".to_owned())]);
    j.preparing.push(second.clone());
    db.transaction(|tx| tx.save_runtime(RECEIPT, &j)).unwrap();
    let late = objects(&second)
        .into_iter()
        .find(|o| matches!(o, Object::Route(..)))
        .unwrap();
    kernel(&f).mutate(&late, true).unwrap();
    f.0.lock().unwrap().foreign_route = "192.0.2.55 dev foreign table 17842 proto static".into();
    let changes = f.0.lock().unwrap().changes;
    assert!(release_go_routing(&db, &f, false).is_err());
    assert_eq!(f.0.lock().unwrap().changes, changes);
    assert!(Journal::read(&db).unwrap() == j);
    f.0.lock().unwrap().foreign_route.clear();
    release_go_routing(&db, &f, false).unwrap();
    assert!(f.0.lock().unwrap().routes.is_empty() && Journal::read(&db).unwrap().idle());
    release_go_routing(&db, &f, false).unwrap();
    let old = objects(&j.installed)
        .into_iter()
        .find(|o| matches!(o, Object::Route(..)))
        .unwrap();
    kernel(&f).mutate(&old, true).unwrap();
    let changes = f.0.lock().unwrap().changes;
    assert!(release_go_routing(&db, &f, false).is_err());
    assert_eq!(f.0.lock().unwrap().changes, changes);
}

#[test]
fn installer_blocks_preexisting_native_intent_and_checks_a_clean_suspend() {
    use super::super::handoff::{prepare_after, release_go_routing};
    let (_root, db, f) = setup();
    action(&db, &f, Operation::Apply, 10).unwrap();
    db.transaction(|tx| {
        tx.save_runtime(
            "awg-go-release.json",
            &json!({"boot":BOOT,"checkpoint":null}),
        )
    })
    .unwrap();
    assert!(prepare_after(
        &db,
        &f,
        std::num::NonZeroU16::new(8090).unwrap(),
        || panic!("unexpected Go probe"),
        peer
    )
    .is_err());
    release_go_routing(&db, &f, true).unwrap();
    action(&db, &f, Operation::Suspend, 15).unwrap();
    release_go_routing(&db, &f, false).unwrap();
    assert!(Journal::read(&db).unwrap().idle());
}

#[test]
fn pure_go_blanket_requires_matching_precedence_mark_wan_exemptions_and_tunnel() {
    const RULES:&str="-A OUTPUT -j AWG2_MULTI\n-A PREROUTING -j AWG2_MULTI\n-A AWG2_MULTI -m mark --mark 0x20000000/0x20000000 -j RETURN\n-A AWG2_MULTI -d 127.0.0.0/8 -j RETURN\n-A AWG2_MULTI -d 10.0.0.0/8 -j RETURN\n-A AWG2_MULTI -d 172.16.0.0/12 -j RETURN\n-A AWG2_MULTI -d 192.168.0.0/16 -j RETURN\n-A AWG2_MULTI -d 100.64.0.0/10 -j RETURN\n-A AWG2_MULTI -d 198.51.100.10/32 -j RETURN\n-A AWG2_MULTI -g AWG2_TO_10100000\n-A AWG2_TO_10100000 -j MARK --set-xmark 0x10100000/0x1ff00000\n-A AWG2_TO_10100000 -j ACCEPT";
    struct Go(String, &'static str);
    impl Runner for Go {
        fn run(&self, program: &str, args: &[&str], _: Instant) -> io::Result<String> {
            Ok(match (program, args) {
                ("iptables", ["-t", "mangle", "-S"]) => self.0.clone(),
                ("ip", ["-o", "-N", "-4", "rule", "show"]) => {
                    "71: from all fwmark 0x10100000/0x1ff00000 lookup 901".into()
                }
                ("ip", ["-o", "-N", "-4", "route", "show", "table", "901"]) => {
                    format!("default dev {}", self.1)
                }
                _ => panic!("unrecognized read"),
            })
        }
    }
    let (_temp, db, _) = setup();
    let mut doc = nfqws2_awg_profile::read(&db).unwrap();
    doc["servers"][0]["config"]["routing"]["zones"] =
        json!([{"route":"tunnel","enabled":true,"domains":["*"]}]);
    doc["servers"][0]["config"]["endpoint"] = json!("198.51.100.10:443");
    let plan = plan::compile(&doc, None, false).unwrap();
    for (rules, dev, ok) in [
        (RULES.to_owned(), "awg0", true),
        (RULES.to_owned(), "awg3", false),
        (
            RULES.replace(
                "-A OUTPUT -j AWG2_MULTI",
                "-A OUTPUT -j RETURN\n-A OUTPUT -j AWG2_MULTI",
            ),
            "awg0",
            false,
        ),
        (
            RULES.replace("198.51.100.10/32", "198.51.100.0/24"),
            "awg0",
            false,
        ),
        (
            RULES.replace("0x10100000/0x1ff00000", "0x10100001/0x1ff00000"),
            "awg0",
            false,
        ),
    ] {
        let go = Go(rules, dev);
        assert_eq!(
            super::super::handoff::verify_go_default(
                &go,
                &kernel(&go),
                &plan,
                &crate::policy::current(&doc).unwrap()
            )
            .is_ok(),
            ok
        );
    }
}

#[test]
fn migration_checks_only_loaded_firewall_tables_and_detects_native_fw4_rules() {
    struct Probe {
        capabilities: &'static str,
        nft: &'static str,
    }
    impl Runner for Probe {
        fn run(&self, cmd: &str, args: &[&str], _: Instant) -> io::Result<String> {
            match (cmd, args) {
                ("sh", ["-c", s]) if s.contains("91-awg2-multi.sh") => Ok(self.capabilities.into()),
                (
                    "ip",
                    ["-o", "-N", "-4" | "-6", "rule", "show"]
                    | ["-o", "-N", "-4" | "-6", "route", "show", "table", "all"],
                ) => Ok(String::new()),
                ("iptables" | "ip6tables", ["-w", "-t", "filter", "-S"]) => Ok(String::new()),
                ("iptables-legacy", ["-w", "-t", "filter", "-S"]) => {
                    Ok("-A FORWARD -i awg0 -j ACCEPT".into())
                }
                ("nft", ["-t", "list", "ruleset"])
                    if self.capabilities.lines().any(|s| s == "nft") =>
                {
                    Ok(self.nft.into())
                }
                _ => panic!("unused or unverified backend {cmd} {args:?}"),
            }
        }
    }
    let mut p = Probe {
        capabilities: "ipv6\niptables\niptables:filter\nip6tables\nip6tables:filter",
        nft: "",
    };
    kernel(&p).check_go_handoff().unwrap();
    p.capabilities = "iptables\niptables:legacy\niptables:filter\nnft";
    assert!(kernel(&p).check_go_handoff().is_err());
    p.capabilities = "ipv6\nnft";
    kernel(&p).check_go_handoff().unwrap();
    for stale in [
        r#"iifname "br-lan" oifname "awg0" accept comment "nfqws2-awg2""#,
        r#"tcp dport 53 redirect to :5354"#,
        r#"oifname "awg2" masquerade"#,
    ] {
        p.nft = stale;
        assert!(kernel(&p).check_go_handoff().is_err());
    }
    p.capabilities = "";
    assert!(kernel(&p).check_go_handoff().is_err());
}

fn go_zones() -> (tempfile::TempDir, Store, Fake) {
    let (dir, db, kernel) = setup();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc.as_object_mut().unwrap().remove("routing_revision");
        let row = &mut doc["servers"][0];
        row["config"]["routing"]["active"] = json!(true);
        row["applied_config"] = row["config"].clone();
        row["applied_config"]["routing"]["active"] = json!(false);
        Ok(())
    })
    .unwrap();
    (dir, db, kernel)
}

#[test]
fn authenticated_direct_and_optional_nested_peers_restore_with_cold_standbys() {
    let (_dir, db, f) = setup();
    redundant_policy(&db, false);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let rows = doc["servers"].as_array_mut().unwrap();
        let outer = rows[0]["id"].clone();
        for (i, mode) in [(1, "automatic"), (2, "")] {
            rows[i]["config"]["client"]["double_tunnel_id"] = outer.clone();
            rows[i]["config"]["client"]["double_tunnel_mode"] = json!(mode);
        }
        rows[3]["config"]["client"]["standby"] = json!(true);
        rows[1]["config"]["routing"]["zones"] = json!([
            {"name":"through optional nested client","enabled":true,"ips":["203.0.113.8"],"fallback_tunnel_ids":["nested","profile"]}
        ]);
        Ok(())
    }).unwrap();
    for op in [Operation::Apply, Operation::Commit] {
        refresh_with(&db, &f, op, [ALL, ALL, None, None]).unwrap();
    }
    assert_eq!(path(&f, "203.0.113.1"), "awg0");
    assert_eq!(path(&f, "203.0.113.8"), "awg1");
    refresh_with(&db, &f, Operation::Refresh, [ALL, None, ALL, None]).unwrap();
    assert_eq!(path(&f, "203.0.113.8"), "awg2");
}

#[test]
fn installer_checks_old_trial_then_transfers_complete_live_sets_and_restores_after_reboot() {
    use crate::kernel::handoff as migration;
    use std::sync::atomic::{AtomicU64, Ordering};
    let (_tmp, db, firmware) = go_zones();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"]["domain_source"] = json!("dnsproxy");
        doc["servers"][0]["config"]["routing"]["zones"][0]["domains"] = json!(["unit.test"]);
        doc["servers"][0]["config"]["routing"]["zones"][0]["ips"] =
            json!(["203.0.113.0/24", "2001:db8:1234::/48"]);
        for key in ["config","applied_config"] {
            doc["servers"][0][key]["peers"] = json!([{"is_router":true,"address":"10.1.1.2/32,2001:db8::2/128","allowed_ips":"0.0.0.0/0,::/0"}]);
        }
        Ok(())
    })
    .unwrap();
    let policy = crate::policy::current(&nfqws2_awg_profile::read(&db).unwrap()).unwrap();
    let status = json!({"routing_config":policy,"routing_rules":policy.zones,
        "routing_state":{"revision":5,"ready":true,"applying":false},"servers":[{"id":"awg0","connected":true}]});
    struct Go<'a> {
        revision: AtomicU64,
        status: &'a Value,
        firmware: &'a Fake,
    }
    impl Runner for Go<'_> {
        fn run(&self, cmd: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
            match (cmd,args) {
                ("cat",["/proc/sys/kernel/random/boot_id"])=>Ok(BOOT.into()),
                ("cat",["/opt/var/run/nfqws2-strategy.pid"])=>Ok("31".into()),
                ("cat",["/proc/31/stat"])=>Ok(format!("31 (n2s) {} 200",["0";19].join(" "))),
                ("curl",_)=>{
                    let mut v=self.status.clone();
                    v["routing_state"]["revision"]=json!(self.revision.load(Ordering::Relaxed));
                    Ok(v.to_string())
                },
                ("iptables",["-t","mangle","-S","PREROUTING"])=>Ok("-A PREROUTING -j AWG2_MULTI".into()),
                ("iptables",["-t","mangle","-S","AWG2_MULTI"])=>Ok("-A AWG2_MULTI -m set --match-set awgm_000 dst -g AWG2_ACT10100000".into()),
                ("ipset",["save","awgm_000"])=>Ok("create awgm_000 hash:net family inet\nadd awgm_000 203.0.113.0/24\nadd awgm_000 198.51.100.31\nadd awgm_000 198.51.100.32 timeout 120".into()),
                _=>self.firmware.run(cmd,args,deadline),
            }
        }
    }
    let old = Go {
        revision: AtomicU64::new(5),
        status: &status,
        firmware: &firmware,
    };
    let port = 8090.try_into().unwrap();
    assert!(migration::prepare_after(
        &db,
        &old,
        port,
        || {
            old.revision.store(6, Ordering::Relaxed);
        },
        peer
    )
    .is_err());
    assert!(!migration::pending(&db).unwrap());
    assert!(migration::prepare_after(
        &db,
        &old,
        port,
        || {},
        |_, _| Err(io::Error::other("wrong UAPI key"))
    )
    .is_err());
    assert!(!migration::pending(&db).unwrap());
    firmware.0.lock().unwrap().foreign_rule = "68: from all lookup 17842".into();
    assert!(migration::prepare_after(&db, &old, port, || {}, peer).is_err());
    assert!(!migration::pending(&db).unwrap());
    firmware.0.lock().unwrap().foreign_rule =
        "71: from all fwmark 0x10100000/0x1ff00000 lookup 901".into();
    assert!(migration::prepare_after(&db, &old, port, || {}, peer).unwrap());
    assert!(migration::pending(&db).unwrap());
    firmware.0.lock().unwrap().foreign_rule.clear();
    let now = nfqws2_awg_profile::now();
    action(&db, &firmware, Operation::Apply, now).unwrap();
    assert!(!migration::pending(&db).unwrap());
    let trial = Journal::read(&db).unwrap().installed;
    assert!(trial.go_ipv4 && !trial.uses_family(plan::Family::V6));
    assert!(
        learn_answer(
            &db,
            &firmware,
            Answer {
                revision: trial.revision,
                zone: 0,
                qtype: 28,
                addresses: &["2001:db8:1234::10".parse().unwrap()],
                ttl: 60
            },
            peer,
            || Ok(())
        )
        .unwrap()
        .suppress
    );
    let journal = Journal::read(&db).unwrap();
    let saved = journal.installed.learned.as_ref().unwrap();
    assert_eq!(saved.members.len(), 2);
    assert_eq!(saved.members[0].until, u64::MAX);
    assert!(saved.members[1].until >= now + 119 && saved.members[1].until <= now + 120);
    assert_eq!(
        migration::check_trial(&db, &firmware).unwrap().connected,
        BTreeSet::from(["awg0".into()])
    );
    action(&db, &firmware, Operation::Commit, now + 2).unwrap();
    migration::finished(&db).unwrap();
    action(&db, &firmware, Operation::Suspend, now + 3).unwrap();
    firmware.0.lock().unwrap().boot = "34343434-3434-3434-3434-343434343434".into();
    action(&db, &firmware, Operation::Recover, now + 4).unwrap();
    let restored = Journal::read(&db).unwrap().installed;
    assert!(restored.go_ipv4 && !restored.uses_family(plan::Family::V6));
    assert_eq!(
        crate::policy::current(&nfqws2_awg_profile::read(&db).unwrap())
            .unwrap()
            .zones[0]
            .ips
            .len(),
        2
    );
    assert_eq!(
        Journal::read(&db)
            .unwrap()
            .installed
            .learned
            .as_ref()
            .unwrap()
            .members,
        saved.members
    );
}

#[test]
fn go_active_without_a_receipt_stays_idle_and_requires_an_explicit_trial_and_commit() {
    let (dir, db, f) = go_zones();
    let original = std::fs::read(dir.path().join("awg.json")).unwrap();
    let original_doc = nfqws2_awg_profile::read(&db).unwrap();
    let now = nfqws2_awg_profile::now();
    for occupied in [false, true] {
        f.0.lock().unwrap().foreign_rule = if occupied {
            "71: from all lookup 901"
        } else {
            ""
        }
        .into();
        for op in [Operation::Recover, Operation::Refresh, Operation::Suspend] {
            operate_at(&db, &f, op, now, |_, _| {
                panic!("a Go flag is not a confirmed Rust plan")
            })
            .unwrap();
        }
        assert_eq!(scheduled(&db).unwrap(), Schedule::Idle);
        assert!(db
            .read_runtime::<Value>(RECEIPT, RECEIPT_LIMIT)
            .is_err_and(|e| e.kind() == io::ErrorKind::NotFound));
        assert_eq!(
            std::fs::read(dir.path().join("awg.json")).unwrap(),
            original
        );
        assert_eq!(f.0.lock().unwrap().changes, 0);
    }
    f.0.lock().unwrap().foreign_rule = "999: from 192.0.2.7 lookup 100".into();
    action(&db, &f, Operation::Apply, now).unwrap();
    assert_eq!(scheduled(&db).unwrap(), Schedule::Expires(now + TRIAL));
    assert_eq!(
        nfqws2_awg_profile::read(&db).unwrap()["servers"],
        original_doc["servers"]
    );
    action(&db, &f, Operation::Recover, now + TRIAL + 1).unwrap();
    assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), original_doc);
    assert!(Journal::read(&db).unwrap().idle());
    assert!(f.0.lock().unwrap().routes.is_empty());

    let second = now + 200;
    action(&db, &f, Operation::Apply, second).unwrap();
    f.0.lock().unwrap().go_hook = true;
    assert!(action(&db, &f, Operation::Commit, second + 1).is_err());
    assert!(Journal::read(&db).unwrap().committed.empty());
    f.0.lock().unwrap().go_hook = false;
    action(&db, &f, Operation::Commit, second + 2).unwrap();
    action(&db, &f, Operation::Suspend, second + 3).unwrap();
    f.0.lock().unwrap().boot = "34343434-3434-3434-3434-343434343434".into();
    action(&db, &f, Operation::Recover, second + 4).unwrap();
    let status = inspect(&db, &f).unwrap();
    assert!(status.ready && status.active && !status.pending_commit);
    assert_eq!(
        f.0.lock().unwrap().foreign_rule,
        "999: from 192.0.2.7 lookup 100"
    );
}

#[test]
fn go_handoff_never_adopts_existing_kernel_objects_or_an_unverified_peer() {
    let (_dir, db, f) = go_zones();
    let original = nfqws2_awg_profile::read(&db).unwrap();
    for (rule, route, fw, hook) in [
        ("68: from all lookup 17842", "", "", false),
        (
            "",
            "203.0.113.0/24 dev awg0 table 17842 proto 242 scope link",
            "",
            false,
        ),
        (
            "71: from all fwmark 0x10100000/0x1ff00000 lookup 901",
            "",
            "",
            false,
        ),
        ("", "default dev awg5 table 964 proto static", "", false),
        ("", "", "-A PREROUTING -j AWG2_MULTI", false),
        ("", "", "-A FORWARD -i awg0 -j ACCEPT", false),
        ("", "", "-N N2S_AWGPPE_IN", false),
        ("", "", "-A FORWARD -j N2S_AWGPPE_FWD", false),
        (
            "",
            "",
            "-A N2S_AWGPPE_OUT -p tcp --tcp-flags SYN SYN -j PPE",
            false,
        ),
        ("", "", "", true),
    ] {
        {
            let mut fw_state = f.0.lock().unwrap();
            fw_state.foreign_rule = rule.into();
            fw_state.foreign_route = route.into();
            fw_state
                .firewall
                .insert("filter".into(), BTreeSet::from([fw.into()]));
            fw_state.go_hook = hook;
        }
        assert!(action(&db, &f, Operation::Apply, 42).is_err());
        assert_eq!(f.0.lock().unwrap().changes, 0);
        assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), original);
        assert!(db
            .read_runtime::<Value>(RECEIPT, RECEIPT_LIMIT)
            .is_err_and(|e| e.kind() == io::ErrorKind::NotFound));
    }
    f.0.lock().unwrap().go_hook = false;
    assert!(operate_at(&db, &f, Operation::Apply, 43, |_, _| Err(err(
        "mismatched live peer"
    )))
    .is_err());
    assert!(
        operate_at(&db, &f, Operation::Apply, 43, |_, _| Ok(LivePeer {
            ipv6_reachable: true,
            nested_mtu: None,
            prefer_ordinary: false,
            nested_transport: None,
            direct_backup: None,
            endpoint_predecessor: None,
            fresh_bound_ipv6_probe: None,
            active_replacement_peer: None,
            socket_mark: 0,
            endpoint: "198.51.100.1:443".parse().unwrap(),
            allowed: vec!["203.0.113.1/32".into()]
        }))
        .is_err()
    );
    assert_eq!(f.0.lock().unwrap().changes, 0);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["rust_static_routing"] = json!({"targets":[]});
        Ok(())
    })
    .unwrap();
    assert!(action(&db, &f, Operation::Apply, 44).is_err());
    assert!(Journal::read(&db).unwrap().idle());
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires Go fixtures and an offline Linux network namespace"]
fn go_implicit_full_handoff_distinguishes_actual_multi_and_single_ipv6() {
    use crate::kernel::handoff::{
        arm_parked_guard, candidate, check_trial, finish_parked_guard, finished,
        parked_trial_status, pending, prepare_after, release_go_routing, release_parked_guard,
        source_chain, ParkedTrialStatus,
    };
    use std::num::NonZeroU16;
    assert!(std::path::Path::new("/synthetic-guest").is_file());
    for (kind, var) in [("net", "N2S_PARENT_NET"), ("mnt", "N2S_PARENT_MNT")] {
        let parent = std::env::var(var).unwrap();
        let current = std::fs::read_link(format!("/proc/self/ns/{kind}")).unwrap();
        assert!(parent.starts_with(&format!("{kind}:[")));
        assert_ne!(current.to_str(), Some(parent.as_str()));
    }
    let db = Store::open(std::env::var("N2S_R102_GO_STORE").unwrap()).unwrap();
    let doc = nfqws2_awg_profile::read(&db).unwrap();
    let current = crate::policy::current(&doc).unwrap();
    let mode = std::env::var("N2S_R102_MODE").unwrap();
    assert_eq!(current.mode, "full");
    assert!(current.active && current.zones.is_empty());
    struct GoStatus {
        status: String,
        nft_fault: std::sync::atomic::AtomicU8,
        fail_after: Option<std::sync::atomic::AtomicU8>,
    }
    impl Runner for GoStatus {
        fn run_input(
            &self,
            program: &str,
            args: &[&str],
            input: &[u8],
            deadline: Instant,
        ) -> io::Result<String> {
            nfqws2_router_command::System.run_input(program, args, input, deadline)
        }

        fn run(&self, program: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
            if program == "curl" {
                assert!(args.contains(&"GET") && args.contains(&"http://127.0.0.1:32777/api/awg2"));
                if self.fail_after.as_ref().is_some_and(|remaining| {
                    remaining.fetch_sub(1, std::sync::atomic::Ordering::Relaxed) == 0
                }) {
                    return Err(io::ErrorKind::BrokenPipe.into());
                }
                return Ok(self.status.clone());
            }
            if program == "cat" && args == ["/opt/var/run/nfqws2-strategy.pid"] {
                return Ok(std::process::id().to_string());
            }
            if program == "ip"
                && args.starts_with(&["-4", "route", "add", "throw"])
                && self.nft_fault.load(std::sync::atomic::Ordering::Relaxed) == 5
            {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            let reply = nfqws2_router_command::System.run(program, args, deadline)?;
            if program == "iptables-nft" {
                match self.nft_fault.load(std::sync::atomic::Ordering::Relaxed) {
                    1 => return Err(io::ErrorKind::NotFound.into()),
                    2 => return Ok("malformed table".into()),
                    3 => return Ok(reply.replace("n2s-awg-cidr", "unexpected-ownership")),
                    4 => {
                        return Ok(format!(
                            "{reply}\n{}",
                            reply.lines().last().unwrap_or_default()
                        ))
                    }
                    _ => (),
                }
            }
            Ok(reply)
        }
    }
    let reconnected = std::env::var("N2S_R107_CONNECTED").unwrap_or_default();
    let active = mode == "multi";
    let run = GoStatus {
        status: json!({
            "routing_config": current,
            "routing_rules": [],
            "routing_state": {"ready":true,"applying":false,"revision":1},
            "servers":[{"id":"first","connected":reconnected == "first"},
                {"id":"reserve","connected":active || reconnected == "reserve"}]
        })
        .to_string(),
        nft_fault: std::sync::atomic::AtomicU8::new(0),
        fail_after: (mode == "refuse-restored-after-write")
            .then(|| std::sync::atomic::AtomicU8::new(2)),
    };
    let k = kernel(&run);
    let show = |table, chain| k.call("ip6tables", &["-t", table, "-S", chain]).unwrap();
    let v6 = || k.call("ip", &["-6", "route", "get", "2001:db8:102:99::1"]);
    let v4 = || k.call("ip", &["-4", "route", "get", "203.0.113.72"]);
    let allow_reserve = |cfg: &Value, iface: &str| {
        if iface == "awg0" {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        assert_eq!(iface, "awg1");
        let mut found = peer(cfg, "awg0")?;
        found.endpoint = cfg["endpoint"].as_str().unwrap().parse().unwrap();
        Ok(found)
    };
    let port = NonZeroU16::new(32777).unwrap();
    match mode.as_str() {
        "reject-unsafe-acceleration" | "reject-unknown-ppe-restore" => {
            assert!(pending(&db).unwrap());
            let before = k.listing(plan::Family::V4, &["rule", "show"]).unwrap();
            let result = arm_parked_guard(&db, &run, port.into());
            let reason = if mode == "reject-unsafe-acceleration" {
                "исходное ускорение Go"
            } else {
                "не подтверждены исходные настройки ускорения работающей Go-панели"
            };
            assert!(result.unwrap_err().to_string().contains(reason));
            assert!(crate::kernel::handoff::parked_guard::Armed::read(&db)
                .unwrap()
                .is_none());
            assert_eq!(
                k.listing(plan::Family::V4, &["rule", "show"]).unwrap(),
                before
            );
        }
        "reject-live-ppe-with-arm" => {
            assert!(pending(&db).unwrap());
            assert!(v4().is_err());
            assert!(v6().unwrap().contains("dev wan0"));
            let fail = operate(&db, &run, Operation::Recover, |_, _| {
                panic!("unverified PPE cannot recover the parked install")
            })
            .unwrap_err();
            assert!(fail.to_string().contains("исходное ускорение Go"));
            assert!(crate::kernel::handoff::parked_guard::Armed::read(&db)
                .unwrap()
                .is_some());
        }
        "release-restored-carrier" | "refuse-restored-carrier" | "refuse-restored-after-write" => {
            let (iface, mark) = match reconnected.as_str() {
                "first" => (Some("awg0"), "0x10100000"),
                "reserve" => (Some("awg1"), "0x10200000"),
                "" => match std::env::var("N2S_R109_STALE").unwrap().as_str() {
                    "first" => (Some("awg0"), "0x10100000"),
                    "reserve" => (None, "0x10100000"),
                    _ => panic!("test stale carrier required"),
                },
                _ => panic!("test connected carrier required"),
            };
            let go = k
                .call("iptables", &["-t", "mangle", "-S", "AWG2_MULTI"])
                .unwrap();
            let state = || k.listing(plan::Family::V4, &["rule", "show"]).unwrap();
            let before = state();
            assert!(before.contains("17842") && v4().is_err());
            let result = release_parked_guard(&db, &run, port.into());
            assert_eq!(
                go,
                k.call("iptables", &["-t", "mangle", "-S", "AWG2_MULTI"])
                    .unwrap()
            );
            let remains = crate::kernel::handoff::parked_guard::Armed::read(&db)
                .unwrap()
                .is_some();
            if mode != "release-restored-carrier" {
                assert!(result.is_err());
                assert!(remains && v4().is_err());
                assert_eq!(state(), before);
                return;
            }
            result.unwrap();
            assert!(!remains && !state().contains("17842"));
            let route = k.call("ip", &["-4", "route", "get", "203.0.113.72", "mark", mark]);
            if let Some(iface) = iface {
                assert!(route.unwrap().contains(&format!("dev {iface}")));
            } else {
                assert!(route.is_err());
            }
            assert!(v6().unwrap().contains("dev wan0"));
        }
        "arm-interrupted" => {
            assert!(pending(&db).unwrap());
            let go = k
                .call("iptables", &["-t", "mangle", "-S", "AWG2_MULTI"])
                .unwrap();
            run.nft_fault.store(5, std::sync::atomic::Ordering::Relaxed);
            assert!(arm_parked_guard(&db, &run, port.into()).is_err());
            run.nft_fault.store(0, std::sync::atomic::Ordering::Relaxed);
            assert!(Journal::read(&db).unwrap().idle());
            let partial = k.listing(plan::Family::V4, &["rule", "show"]).unwrap();
            assert!(partial.lines().any(|line| line.starts_with("67:")));
            assert!(!partial.lines().any(|line| line.starts_with("68:")));
            assert!(release_parked_guard(&db, &run, port.into()).is_ok());
            assert_eq!(
                go,
                k.call("iptables", &["-t", "mangle", "-S", "AWG2_MULTI"])
                    .unwrap()
            );
            assert!(crate::kernel::handoff::parked_guard::Armed::read(&db)
                .unwrap()
                .is_none());
            assert!(!k
                .listing(plan::Family::V4, &["rule", "show"])
                .unwrap()
                .lines()
                .any(|line| line.starts_with("67:")));
        }
        "decline-unguarded-arm" => {
            assert!(pending(&db).unwrap());
            let before = k.listing(plan::Family::V4, &["rule", "show"]).unwrap();
            assert!(v4().unwrap().contains("dev wan0"));
            assert!(!arm_parked_guard(&db, &run, port.into()).unwrap());
            assert!(crate::kernel::handoff::parked_guard::Armed::read(&db)
                .unwrap()
                .is_none());
            assert_eq!(
                k.listing(plan::Family::V4, &["rule", "show"]).unwrap(),
                before
            );
            assert!(v4().unwrap().contains("dev wan0"));
            assert!(v6().unwrap().contains("dev wan0"));
        }
        "arm-parked" => {
            assert!(pending(&db).unwrap());
            let go = k
                .call("iptables", &["-t", "mangle", "-S", "AWG2_MULTI"])
                .unwrap();
            assert!(arm_parked_guard(&db, &run, port.into()).unwrap());
            assert!(arm_parked_guard(&db, &run, port.into()).unwrap());
            assert_eq!(
                go,
                k.call("iptables", &["-t", "mangle", "-S", "AWG2_MULTI"])
                    .unwrap()
            );
            assert!(Journal::read(&db).unwrap().idle());
            assert!(v4().is_err());
            assert!(v6().unwrap().contains("dev wan0"));
        }
        "check-armed-gap" => {
            assert!(pending(&db).unwrap());
            assert!(Journal::read(&db).unwrap().idle());
            operate(&db, &run, Operation::Recover, |_, _| {
                panic!("guard-only handoff")
            })
            .unwrap();
            assert!(v4().is_err());
            assert!(v6().unwrap().contains("dev wan0"));
        }
        "rollback-armed" => {
            assert!(pending(&db).unwrap());
            let no_peer = |_: &Value, _: &str| panic!("no peer expected for pre-armed rollback");
            operate(&db, &run, Operation::Apply, no_peer).unwrap();
            let trial = Journal::read(&db).unwrap();
            operate_at(&db, &run, Operation::Recover, trial.expires + 1, no_peer).unwrap();
            assert_eq!(Journal::read(&db).unwrap(), trial);
            release_go_routing(&db, &run, true).unwrap();
            operate(&db, &run, Operation::Suspend, no_peer).unwrap();
            release_go_routing(&db, &run, false).unwrap();
            assert!(Journal::read(&db).unwrap().idle());
            assert!(v4().is_err());
            assert!(v6().unwrap().contains("dev wan0"));
            assert!(release_parked_guard(&db, &run, port.into()).is_err());
            assert!(v4().is_err());
        }
        "release-armed-after-go" => {
            let go = k
                .call("iptables", &["-t", "mangle", "-S", "AWG2_MULTI"])
                .unwrap();
            let before = k
                .listing(plan::Family::V6, &["route", "show", "table", "all"])
                .unwrap();
            assert!(v4().is_err());
            release_parked_guard(&db, &run, port.into()).unwrap();
            assert_eq!(
                go,
                k.call("iptables", &["-t", "mangle", "-S", "AWG2_MULTI"])
                    .unwrap()
            );
            assert_eq!(
                k.listing(plan::Family::V6, &["route", "show", "table", "all"])
                    .unwrap(),
                before
            );
            assert!(!k
                .listing(plan::Family::V4, &["rule", "show"])
                .unwrap()
                .contains("17842"));
            assert!(k
                .call(
                    "ip",
                    &["-4", "route", "get", "203.0.113.72", "mark", "0x10100000"]
                )
                .is_err());
        }
        "prepare-parked" | "reject-parked-source" => {
            assert_eq!(source_chain(&db, &run).unwrap(), "AWG2_MULTI");
            let routes = k
                .listing(plan::Family::V4, &["route", "show", "table", "all"])
                .unwrap();
            let prepared = prepare_after(
                &db,
                &run,
                port,
                || {},
                |_, _| panic!("positively absent links do not require UAPI"),
            );
            if mode == "prepare-parked" {
                assert!(prepared.unwrap());
                assert!(pending(&db).unwrap());
            } else {
                assert!(prepared.is_err());
                assert!(!pending(&db).unwrap());
            }
            assert!(Journal::read(&db).unwrap().idle());
            assert!(v6().unwrap().contains("dev wan0"));
            assert_eq!(
                k.listing(plan::Family::V4, &["route", "show", "table", "all"])
                    .unwrap(),
                routes
            );
        }
        "apply-parked-after-link-change" => {
            assert!(pending(&db).unwrap());
            let error = operate(&db, &run, Operation::Apply, |_, _| {
                panic!("a different link cannot authorize use of a parked proof")
            })
            .unwrap_err()
            .to_string();
            assert!(error.contains("интерфейс AWG появился"));
            assert!(Journal::read(&db).unwrap().idle());
            assert!(parked_trial_status(&db, &run).unwrap().is_none());
        }
        "commit-parked" | "expire-parked" | "commit-parked-unguarded" | "commit-armed" => {
            let no_peer = |_: &Value, _: &str| panic!("no forwarding during a parked trial");
            let guarded = mode != "commit-parked-unguarded";
            let check_v4 = || {
                if guarded {
                    assert!(v4().is_err());
                } else {
                    assert!(v4().unwrap().contains("dev wan0"));
                }
            };
            assert!(pending(&db).unwrap());
            operate(&db, &run, Operation::Apply, no_peer).unwrap();
            assert!(!pending(&db).unwrap());
            check_v4();
            assert!(v6().unwrap().contains("dev wan0"));
            let trial = Journal::read(&db).unwrap();
            assert!(trial.installed.go_ipv4);
            assert_eq!(trial.installed.killswitch, guarded);
            if guarded {
                assert_eq!(trial.installed.offline.len(), 2);
            } else {
                assert!(matches!(trial.installed.selected.as_slice(), [(_, None)]));
            }
            assert!(!trial.installed.fully_live());
            assert!(trial.committed.empty());
            assert!(check_trial(&db, &run).unwrap().parked);
            assert_eq!(
                parked_trial_status(&db, &run).unwrap(),
                Some(ParkedTrialStatus {
                    revision: trial.installed.revision,
                    pending_commit: true
                })
            );
            let state = inspect(&db, &run).unwrap();
            assert!(!state.active && !state.ready && state.pending_commit);
            if mode == "expire-parked" {
                operate_at(&db, &run, Operation::Recover, trial.expires + 1, no_peer).unwrap();
                assert!(Journal::read(&db).unwrap().idle());
                assert!(v4().unwrap().contains("dev wan0"));
                assert!(v6().unwrap().contains("dev wan0"));
                assert!(parked_trial_status(&db, &run).is_err());
                finished(&db).unwrap();
                return;
            }
            let mutate_fence = |op| {
                k.call(
                    "ip",
                    &[
                        "-4",
                        "route",
                        op,
                        "unreachable",
                        "default",
                        "metric",
                        "32000",
                        "table",
                        "17842",
                        "proto",
                        "242",
                    ],
                )
                .unwrap();
            };
            let mutate_foreign = |op| {
                k.call(
                    "ip",
                    &[
                        "-4",
                        "route",
                        op,
                        "203.0.113.72/32",
                        "dev",
                        "wan0",
                        "table",
                        "902",
                    ],
                )
                .unwrap();
            };
            if guarded {
                mutate_fence("del");
            } else {
                mutate_foreign("add");
            }
            assert!(parked_trial_status(&db, &run).is_err());
            assert!(operate(&db, &run, Operation::Commit, no_peer).is_err());
            assert_eq!(Journal::read(&db).unwrap(), trial);
            if guarded {
                mutate_fence("add");
            } else {
                mutate_foreign("del");
            }
            k.call("ip", &["link", "add", "awg0", "type", "dummy"])
                .unwrap();
            k.call("ip", &["link", "set", "awg0", "up"]).unwrap();
            operate(&db, &run, Operation::Commit, no_peer).unwrap();
            assert_eq!(
                parked_trial_status(&db, &run).unwrap(),
                Some(ParkedTrialStatus {
                    revision: trial.installed.revision,
                    pending_commit: false
                })
            );
            let sealed = Journal::read(&db).unwrap();
            assert!(!sealed.committed.empty() && sealed.committed.offline.is_empty());
            assert!(!sealed.installed.fully_live());
            check_v4();
            finished(&db).unwrap();
            if mode == "commit-armed" {
                operate(&db, &run, Operation::Suspend, no_peer).unwrap();
                assert!(v4().is_err());
                finish_parked_guard(&db, &run).unwrap();
            }
            let absent = |_: &Value, _: &str| Err(io::ErrorKind::WouldBlock.into());
            operate(&db, &run, Operation::Suspend, absent).unwrap();
            operate(&db, &run, Operation::Recover, absent).unwrap();
            check_v4();
            let primary = |cfg: &Value, iface: &str| {
                if iface != "awg0" {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                let mut live = peer(cfg, iface)?;
                live.endpoint = cfg["endpoint"].as_str().unwrap().parse().unwrap();
                Ok(live)
            };
            operate(&db, &run, Operation::Refresh, primary).unwrap();
            assert!(v4().unwrap().contains("dev awg0"));
            assert!(v6().unwrap().contains("dev wan0"));
            assert!(inspect(&db, &run).unwrap().active);
            operate(&db, &run, Operation::Teardown, absent).unwrap();
            k.call("ip", &["link", "del", "awg0"]).unwrap();
        }
        "single" => {
            assert_eq!(source_chain(&db, &run).unwrap(), "AWG2_MARK");
            assert!(show("filter", "FORWARD").contains("icmp6-adm-prohibited"));
            assert!(v6().unwrap().contains("dev wan0"));
        }
        "multi" => {
            assert_eq!(source_chain(&db, &run).unwrap(), "AWG2_MULTI");
            assert!(v6().unwrap().contains("dev wan0"));
            assert!(!show("filter", "FORWARD").contains("icmp6-adm-prohibited"));
            assert!(prepare_after(&db, &run, port, || {}, allow_reserve).unwrap());
            assert!(pending(&db).unwrap());
            assert!(Journal::read(&db).unwrap().idle());
            assert!(v6().unwrap().contains("dev wan0"));
        }
        "multi-after-disable" | "multi-without-authenticated-peer" => {
            assert_eq!(source_chain(&db, &run).unwrap(), "AWG2_MULTI");
            assert!(v6().unwrap().contains("dev wan0"));
            if mode == "multi-without-authenticated-peer" {
                assert!(doc["servers"].as_array().unwrap().iter().all(|row| {
                    row["config"]["enabled"] == true && row["config"]["client"]["enabled"] == true
                }));
            }
            let before = k
                .listing(plan::Family::V4, &["route", "show", "table", "all"])
                .unwrap();
            assert!(prepare_after(
                &db,
                &run,
                port,
                || {},
                |_, _| Err(io::ErrorKind::WouldBlock.into())
            )
            .is_err());
            assert!(!pending(&db).unwrap());
            assert!(Journal::read(&db).unwrap().idle());
            assert_eq!(source_chain(&db, &run).unwrap(), "AWG2_MULTI");
            assert_eq!(
                k.listing(plan::Family::V4, &["route", "show", "table", "all"])
                    .unwrap(),
                before
            );
        }
        "multi-with-native-v6" => {
            assert!(source_chain(&db, &run).is_err());
            assert!(v6().is_err());
            let guard = k
                .listing(plan::Family::V6, &["route", "show", "table", "17842"])
                .unwrap();
            assert!(guard.contains("unreachable default") || guard.contains("7 default"));
            let draft =
                plan::compile_effective(&doc, current, None, true, &[], plan::Layout::default())
                    .unwrap();
            let mut receipt = Journal::read(&db).unwrap();
            receipt.boot = boot_id(&k).unwrap();
            receipt.installed = draft.guards_only().into();
            receipt.committed = draft.into();
            db.transaction(|tx| tx.save_runtime(RECEIPT, &receipt))
                .unwrap();
            let failure = prepare_after(
                &db,
                &run,
                port,
                || panic!("native journal before trial"),
                |_, _| panic!("native journal before peer read"),
            )
            .unwrap_err()
            .to_string();
            assert!(failure.contains("собственный журнал Rust"));
            assert!(pending(&db).unwrap());
            let refusal = db
                .transaction(|tx| {
                    candidate(
                        &db,
                        tx,
                        &run,
                        &doc,
                        nfqws2_awg_profile::now(),
                        None,
                        |_, _| panic!("resident native journal must block use of a prior Go proof"),
                    )
                })
                .unwrap_err()
                .to_string();
            assert!(refusal.contains("собственный журнал Rust"));
            assert!(!pending(&db).unwrap());
            assert_eq!(Journal::read(&db).unwrap(), receipt);
            assert_eq!(
                k.listing(plan::Family::V6, &["route", "show", "table", "17842"])
                    .unwrap(),
                guard
            );
            assert!(v6().is_err());
            db.transaction(|tx| tx.delete_runtime(RECEIPT)).unwrap();
        }
        "late-go-ipv6-fence" => {
            assert!(pending(&db).unwrap());
            let filter = show("filter", "FORWARD");
            assert!(filter.contains("icmp6-adm-prohibited"));
            let error = operate(&db, &run, Operation::Apply, allow_reserve)
                .unwrap_err()
                .to_string();
            assert!(error.contains("активная политика IPv6"));
            assert_eq!(show("filter", "FORWARD"), filter);
            assert!(Journal::read(&db).unwrap().idle());
            assert!(v4().unwrap().contains("dev wan0"));
        }
        "rollback" | "commit" => {
            assert!(pending(&db).unwrap());
            operate(&db, &run, Operation::Apply, allow_reserve).unwrap();
            assert!(v4().unwrap().contains("dev awg1"));
            assert!(v6().unwrap().contains("dev wan0"));
            let actual = Journal::read(&db).unwrap();
            assert!(actual.installed.go_ipv4);
            assert!(actual.installed.full_endpoints.is_some());
            assert!(actual
                .installed
                .flows()
                .all(|(selector, _)| selector.dest.family() == plan::Family::V4));
            if mode == "rollback" {
                operate_at(
                    &db,
                    &run,
                    Operation::Recover,
                    actual.expires + 1,
                    allow_reserve,
                )
                .unwrap();
                assert!(Journal::read(&db).unwrap().idle());
                assert!(v4().unwrap().contains("dev wan0"));
                assert!(v6().unwrap().contains("dev wan0"));
            } else {
                for fault in 1..=4 {
                    run.nft_fault
                        .store(fault, std::sync::atomic::Ordering::Relaxed);
                    assert!(operate(&db, &run, Operation::Commit, allow_reserve).is_err());
                    assert_eq!(Journal::read(&db).unwrap(), actual);
                    assert!(v4().unwrap().contains("dev awg1"));
                }
                run.nft_fault.store(0, std::sync::atomic::Ordering::Relaxed);
                let old_rule = [
                    "FORWARD",
                    "-o",
                    "awg1",
                    "-m",
                    "comment",
                    "--comment",
                    "awg2-qa-old",
                    "-j",
                    "ACCEPT",
                ];
                let mutate_old = |action| {
                    let mut args = vec!["-w", "-t", "filter", action];
                    args.extend(old_rule);
                    k.call("iptables-nft", &args).unwrap();
                };
                mutate_old("-A");
                assert!(operate(&db, &run, Operation::Commit, allow_reserve).is_err());
                assert_eq!(Journal::read(&db).unwrap(), actual);
                mutate_old("-D");
                let mutate_hidden_old = |action| {
                    k.call(
                        "iptables-nft",
                        &[
                            "-w",
                            "-t",
                            "mangle",
                            action,
                            "PREROUTING",
                            "-i",
                            "lo",
                            "-m",
                            "comment",
                            "--comment",
                            "awg2-qa-hidden",
                            "-j",
                            "RETURN",
                        ],
                    )
                    .unwrap();
                };
                mutate_hidden_old("-A");
                assert!(operate(&db, &run, Operation::Commit, allow_reserve).is_err());
                assert_eq!(Journal::read(&db).unwrap(), actual);
                mutate_hidden_old("-D");
                operate(&db, &run, Operation::Commit, allow_reserve).unwrap();
                let committed = Journal::read(&db).unwrap().committed;
                assert!(committed.go_ipv4);
                let saved = nfqws2_awg_profile::read(&db).unwrap();
                assert_eq!(saved["servers"][1]["config"]["routing"]["active"], false);
                assert_eq!(
                    saved["servers"][0]["config"]["client"]["fallback_tunnel_ids"],
                    json!(["reserve"])
                );
                assert!(crate::policy::current(&saved).unwrap().zones.is_empty());
                operate(&db, &run, Operation::Suspend, allow_reserve).unwrap();
                assert!(v4().unwrap().contains("dev wan0"));
                operate(&db, &run, Operation::Recover, allow_reserve).unwrap();
                assert!(v4().unwrap().contains("dev awg1"));
                assert!(v6().unwrap().contains("dev wan0"));
                assert_eq!(Journal::read(&db).unwrap().committed, committed);
                operate(&db, &run, Operation::Teardown, allow_reserve).unwrap();
                let kept = k
                    .call("iptables-nft", &["-w", "-t", "filter", "-S", "FORWARD"])
                    .unwrap();
                assert!(kept.contains("qa-unrelated-rule"));
            }
        }
        _ => panic!("unknown fixture mode"),
    }
}
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires the stock Go public Apply fixture in an offline network namespace"]
fn stock_go_full_with_reserve_handoff_waits_for_inert_ipv6_residue_retirement() {
    use crate::kernel::handoff::{candidate, prepare_after, source_chain};
    use std::num::NonZeroU16;

    assert!(std::path::Path::new("/synthetic-guest").is_file());
    let parent = std::env::var("N2S_PARENT_NET").unwrap();
    let namespace = std::fs::read_link("/proc/self/ns/net").unwrap();
    assert_ne!(namespace.to_str(), Some(parent.as_str()));
    let db = Store::open(std::env::var("N2S_R167_GO_STORE").unwrap()).unwrap();
    let status = std::fs::read_to_string(std::env::var("N2S_R167_GO_STATUS").unwrap()).unwrap();
    struct RealGo(String);
    impl Runner for RealGo {
        fn run(&self, program: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
            match (program, args) {
                ("curl", _) => Ok(self.0.clone()),
                ("cat", ["/opt/var/run/nfqws2-strategy.pid"]) => Ok(std::process::id().to_string()),
                _ => nfqws2_router_command::System.run(program, args, deadline),
            }
        }

        fn run_input(
            &self,
            program: &str,
            args: &[&str],
            input: &[u8],
            deadline: Instant,
        ) -> io::Result<String> {
            nfqws2_router_command::System.run_input(program, args, input, deadline)
        }
    }
    let run = RealGo(status);
    let k = kernel(&run);
    let doc = nfqws2_awg_profile::read(&db).unwrap();
    let active = serde_json::from_str::<Value>(&run.0).unwrap();
    let connected = |cfg: &Value, iface: &str| {
        let id = if iface == "awg0" { "first" } else { "reserve" };
        let online = active["servers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == id && row["connected"] == true);
        if !online {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let mut result = peer(cfg, "awg0")?;
        result.endpoint = cfg["endpoint"].as_str().unwrap().parse().unwrap();
        result.allowed.push("::/0".into());
        Ok(result)
    };
    let ordinary_v6 = || {
        k.call("ip", &["-6", "route", "get", "2001:db8:95:ff::72"])
            .unwrap()
    };
    let rules_v6 = || k.listing(plan::Family::V6, &["rule", "show"]).unwrap();
    let port = NonZeroU16::new(32777).unwrap();
    assert!(ordinary_v6().contains("dev wan0"));
    if std::env::var("N2S_R167_PHASE").unwrap() == "after-stop" {
        assert!(!rules_v6().contains("lookup 998"));
        for op in [Operation::Apply, Operation::Commit, Operation::Refresh] {
            operate(&db, &run, op, connected).unwrap();
            assert!(ordinary_v6().contains("dev wan0"));
            assert!(!rules_v6().contains("lookup 998"));
        }
        let journal = Journal::read(&db).unwrap();
        assert!(journal.committed.go_ipv4 && journal.installed.go_ipv4);
        assert!(journal.installed.uses_family(plan::Family::V4));
        assert!(!journal.installed.uses_family(plan::Family::V6));
        return;
    }

    let before = rules_v6();
    assert!(before.contains("lookup 998"));
    assert_eq!(source_chain(&db, &run).unwrap(), "AWG2_MULTI");
    let collision = |action| {
        k.call(
            "ip",
            &[
                "-6",
                "rule",
                action,
                "pref",
                "107",
                "fwmark",
                "0x12345678",
                "table",
                "998",
            ],
        )
        .unwrap()
    };
    collision("add");
    assert!(source_chain(&db, &run).is_err());
    collision("del");
    let mark = |action| {
        k.call(
            "ip6tables",
            &[
                "-w",
                "-t",
                "mangle",
                action,
                "OUTPUT",
                "-j",
                "MARK",
                "--set-xmark",
                "0x10000000/0x10000000",
            ],
        )
        .unwrap()
    };
    mark("-A");
    assert!(source_chain(&db, &run).is_err());
    mark("-D");
    assert!(prepare_after(&db, &run, port, || (), connected).unwrap());
    let error = db
        .transaction(|tx| {
            candidate(
                &db,
                tx,
                &run,
                &doc,
                nfqws2_awg_profile::now(),
                None,
                connected,
            )
        })
        .unwrap_err();
    assert!(error.to_string().contains("IPv6"));
    assert!(Journal::read(&db).unwrap().idle());
    assert!(prepare_after(&db, &run, port, || (), connected).unwrap());
    assert_eq!(rules_v6(), before);
    assert!(ordinary_v6().contains("dev wan0"));
}
