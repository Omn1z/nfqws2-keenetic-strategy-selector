use super::{ipv6::Dual, *};
use crate::kernel::routed_disable::{routed_profile_is_disabled, withdraw_fixture};
use nfqws2_awg_profile::NativeRemovalSeal;

const V4_PROBE: &str = "203.0.113.72";
const V6_PROBE: &str = "2001:db8:91:99::72";

fn fixture() -> (tempfile::TempDir, Store) {
    let (tmp, db, _) = setup();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"] = json!({"mode":"full","killswitch":true});
        let row = &mut doc["servers"][0];
        row["id"] = "main".into();
        let cfg = &mut row["config"];
        cfg["install"] = "imported".into();
        cfg["endpoint"] = "203.0.113.10:443".into();
        cfg["mtu"] = 1420.into();
        cfg["client"]["rust_managed"] = true.into();
        cfg["routing"] = json!({"mode":"full"});
        doc["active_id"] = "main".into();
        Ok(())
    })
    .unwrap();
    (tmp, db)
}

fn live(dual: bool) -> impl Fn(&Value, &str) -> io::Result<LivePeer> {
    move |cfg, iface| {
        let mut sample = peer(cfg, iface)?;
        sample.endpoint = cfg["endpoint"].as_str().unwrap().parse().unwrap();
        if dual {
            sample.allowed.push("::/0".into());
        }
        Ok(sample)
    }
}

fn seal(boot: &str) -> NativeRemovalSeal {
    NativeRemovalSeal {
        id: "main".into(),
        iface: "awg0".into(),
        boot: boot.into(),
        pid: 9200,
        started: 33,
        receipt_sha256: [0x92; 32],
        nested: None,
    }
}

fn disable(doc: &mut Value, server: bool) {
    let cfg = &mut doc["servers"][0]["config"];
    cfg["client"]["enabled"] = false.into();
    cfg["client"]["rust_managed"] = false.into();
    if server {
        cfg["enabled"] = false.into();
        cfg["routing"]["active"] = false.into();
    }
}

fn rearm(db: &Store) {
    nfqws2_awg_profile::edit_document(db, |doc| {
        let cfg = &mut doc["servers"][0]["config"];
        cfg["enabled"] = true.into();
        cfg["client"]["enabled"] = true.into();
        cfg["client"]["rust_managed"] = true.into();
        Ok(())
    })
    .unwrap();
}

fn prepare(db: &Store, run: &dyn Runner, dual: bool) -> Journal {
    for op in [Operation::Apply, Operation::Commit] {
        operate(db, run, op, live(dual)).unwrap();
    }
    Journal::read(db).unwrap()
}

#[test]
fn routed_full_disable_preserves_intent_for_both_commands_and_preexisting_ipv6_fence() {
    for server in [false, true] {
        for dual in [false, true] {
            let (_dir, db) = fixture();
            let run = Dual::default();
            let old = prepare(&db, &run, dual);
            assert_eq!(old.installed.selected.is_empty(), dual);
            let owner = seal(&old.boot);
            let observed = std::cell::Cell::new(0);
            withdraw_fixture(
                &db,
                &run,
                Some(&owner),
                &|| {
                    assert!(
                        nfqws2_awg_profile::read(&db)?["servers"][0]["config"]["client"]["enabled"]
                            == true
                    );
                    observed.set(observed.get() + 1);
                    Ok(())
                },
                |doc| {
                    disable(doc, server);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(observed.get(), 2);
            assert!(routed_profile_is_disabled(&db, None).unwrap());
            let saved = nfqws2_awg_profile::read(&db).unwrap();
            let cfg = &saved["servers"][0]["config"];
            assert_eq!(cfg["enabled"], !server);
            assert_eq!(cfg["routing"]["active"], !server);
            let out = Journal::read(&db).unwrap();
            assert_eq!(out.committed, old.committed);
            assert!(out.installed.empty());
            assert!(kernel(&run)
                .inventory(&out.claims(), false)
                .unwrap()
                .is_empty());

            if !server {
                // A second disable changes only availability after a prior native stop.
                withdraw_fixture(&db, &run, None, &|| Ok(()), |doc| {
                    disable(doc, true);
                    Ok(())
                })
                .unwrap();
            }

            let run = Dual::default();
            run.v4.0.lock().unwrap().boot = "91919191-9191-9191-9191-919191919191".into();
            operate(&db, &run, Operation::Recover, |_, _| {
                panic!("disabled full queried a peer")
            })
            .unwrap();
            assert!(Journal::read(&db).unwrap().installed.empty());
            assert!(routed_profile_is_disabled(&db, Some("main")).unwrap());

            rearm(&db);
            operate(&db, &run, Operation::Refresh, |_, _| {
                Err(io::ErrorKind::WouldBlock.into())
            })
            .unwrap();
            assert_eq!(
                run.v4.0.lock().unwrap().forward("10.99.0.2", V4_PROBE),
                "unreachable"
            );
            assert_eq!(
                run.v6.0.lock().unwrap().forward("2001:db8:91::2", V6_PROBE),
                "unreachable"
            );
            operate(&db, &run, Operation::Refresh, live(dual)).unwrap();
            assert_eq!(
                run.v4.0.lock().unwrap().forward("10.99.0.2", V4_PROBE),
                "awg0"
            );
            assert_eq!(
                run.v6.0.lock().unwrap().forward("2001:db8:91::2", V6_PROBE),
                if dual { "awg0" } else { "unreachable" }
            );
        }
    }
}

#[test]
fn routed_full_disable_rejects_unknown_exceptions_and_keeps_owned_policy_on_write_failure() {
    let (_dir, db) = fixture();
    let run = Dual::default();
    let old = prepare(&db, &run, false);
    let owner = seal(&old.boot);
    let before = nfqws2_awg_profile::read(&db).unwrap();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let mut unrelated = doc["servers"][0].clone();
        unrelated["id"] = "outside".into();
        unrelated["config"]["endpoint"] = "outside.invalid:443".into();
        unrelated["config"]["routing"]["active"] = false.into();
        doc["servers"].as_array_mut().unwrap().push(unrelated);
        Ok(())
    })
    .unwrap();
    assert_eq!(
        withdraw_fixture(
            &db,
            &run,
            Some(&owner),
            &|| panic!("stale full verified"),
            |_| panic!("unknown exception")
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::Unsupported
    );
    nfqws2_awg_profile::edit_document(&db, |doc| {
        *doc = before.clone();
        Ok(())
    })
    .unwrap();
    {
        let mut fw = run.v4.0.lock().unwrap();
        fw.fail_after = Some(fw.changes + 1);
    }
    assert!(
        withdraw_fixture(&db, &run, Some(&owner), &|| Ok(()), |doc| {
            disable(doc, false);
            Ok(())
        })
        .is_err()
    );
    assert_eq!(Journal::read(&db).unwrap(), old);
    assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), before);
    assert_eq!(
        kernel(&run).inventory(&old.claims(), true).unwrap(),
        objects(&old.installed)
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires no-NIC Linux with independent net and mount namespaces"]
fn routed_full_disable_withdraws_real_dual_or_fenced_rpdb_and_rearms_exact_owner() {
    assert!(std::path::Path::new("/synthetic-guest").is_file());
    for (kind, var) in [("net", "N2S_PARENT_NET"), ("mnt", "N2S_PARENT_MNT")] {
        let parent = std::env::var(var).unwrap();
        let current = std::fs::read_link(format!("/proc/self/ns/{kind}")).unwrap();
        assert!(parent.starts_with(&format!("{kind}:[")));
        assert_ne!(current.to_str(), Some(parent.as_str()));
    }

    let run = nfqws2_router_command::System;
    let k = kernel(&run);
    let dev = |family: &str, address: &str| -> Option<String> {
        let reply = k.call("ip", &[family, "route", "get", address]).ok()?;
        let mut words = reply.split_ascii_whitespace();
        words.find(|word| *word == "dev")?;
        Some(words.next()?.into())
    };
    for (server, dual) in [(false, true), (true, false)] {
        let (_dir, db) = fixture();
        let old = prepare(&db, &run, dual);
        assert_eq!(dev("-4", V4_PROBE).as_deref(), Some("awg0"));
        assert_eq!(dev("-6", V6_PROBE).as_deref(), dual.then_some("awg0"));
        let owner = seal(&old.boot);
        withdraw_fixture(&db, &run, Some(&owner), &|| Ok(()), |doc| {
            disable(doc, server);
            Ok(())
        })
        .unwrap();
        assert_eq!(dev("-4", V4_PROBE).as_deref(), Some("wan0"));
        assert_eq!(dev("-6", V6_PROBE).as_deref(), Some("wan0"));
        for family in [plan::Family::V4, plan::Family::V6] {
            let rules = k.listing(family, &["rule", "show"]).unwrap();
            assert!(!rules.contains("17842"));
        }
        operate(&db, &run, Operation::Suspend, live(dual)).unwrap();
        operate(&db, &run, Operation::Recover, |_, _| {
            panic!("disabled full queried a peer")
        })
        .unwrap();
        assert_eq!(dev("-4", V4_PROBE).as_deref(), Some("wan0"));
        rearm(&db);
        operate(&db, &run, Operation::Refresh, |_, _| {
            Err(io::ErrorKind::WouldBlock.into())
        })
        .unwrap();
        assert!(dev("-4", V4_PROBE).is_none() && dev("-6", V6_PROBE).is_none());
        operate(&db, &run, Operation::Refresh, live(dual)).unwrap();
        assert_eq!(dev("-4", V4_PROBE).as_deref(), Some("awg0"));
        assert_eq!(dev("-6", V6_PROBE).as_deref(), dual.then_some("awg0"));
        operate(&db, &run, Operation::Teardown, live(dual)).unwrap();
    }
}

fn with_full_reserve() -> (tempfile::TempDir, Store) {
    let (temp, db) = fixture();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let rows = doc["servers"].as_array_mut().unwrap();
        let mut reserve = rows[0].clone();
        reserve["id"] = "reserve".into();
        reserve["config"]["client_iface"] = "awg1".into();
        reserve["config"]["endpoint"] = "192.0.2.46:443".into();
        reserve["config"]["routing"]["active"] = false.into();
        rows[0]["config"]["client"]["fallback_tunnel_ids"] = json!(["reserve"]);
        rows.push(reserve);
        Ok(())
    })
    .unwrap();
    (temp, db)
}

fn full_reserve_peer(cfg: &Value, iface: &str) -> io::Result<LivePeer> {
    assert!(matches!(iface, "awg0" | "awg1"));
    live(true)(cfg, "awg0")
}

fn install_full_reserve(db: &Store, run: &dyn Runner) -> Journal {
    for op in [Operation::Apply, Operation::Commit] {
        operate(db, run, op, full_reserve_peer).unwrap();
    }
    let old = Journal::read(db).unwrap();
    assert_eq!(old.committed.targets.len(), 2);
    assert_eq!(old.committed.reserves.len(), 2);
    assert!(old.installed.selected.is_empty());
    assert_eq!(
        nfqws2_awg_profile::read(db).unwrap()["servers"][1]["config"]["routing"]["active"],
        false
    );
    old
}

fn fresh_full_peer(cfg: &Value, iface: &str, boot: &str) -> io::Result<LivePeer> {
    let mut peer = full_reserve_peer(cfg, iface)?;
    let reserve = iface == "awg1";
    let owner = NativeRemovalSeal {
        id: if reserve { "reserve" } else { "main" }.into(),
        iface: iface.into(),
        pid: if reserve { 9201 } else { 9200 },
        receipt_sha256: if reserve { [0x93; 32] } else { [0x92; 32] },
        ..seal(boot)
    };
    peer.active_replacement_peer = Some(Box::new(nfqws2_awg_profile::ActiveReplacementPeer {
        owner,
        fingerprint: if reserve { [0x33; 32] } else { [0x34; 32] },
        endpoint: peer.endpoint,
        socket_mark: peer.socket_mark,
        mtu: 1420,
        allowed: peer.allowed.clone(),
        underlay: None,
        nested_only: false,
    }));
    Ok(peer)
}

fn exercise_new_full_retirement(
    db: &Store,
    run: &dyn Runner,
    killswitch: bool,
    path: impl Fn(&str, &str) -> Option<String>,
    drop_primary: impl FnOnce(),
) {
    let before = nfqws2_awg_profile::read(db).unwrap();
    assert!(before["servers"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["config"]["routing"]["active"] != true));
    let boot = boot_id(&kernel(run)).unwrap();
    let sample = |cfg: &Value, iface: &str| fresh_full_peer(cfg, iface, &boot);
    for operation in [Operation::Apply, Operation::Commit] {
        assert_eq!(
            bare_full_commit_uses_go_response(db).unwrap(),
            operation == Operation::Commit,
        );
        operate(db, run, operation, sample).unwrap();
        assert_eq!(path("-4", V4_PROBE).as_deref(), Some("awg0"));
        assert_eq!(path("-6", V6_PROBE).as_deref(), Some("wan0"));
    }
    assert!(!bare_full_commit_uses_go_response(db).unwrap());
    let saved = nfqws2_awg_profile::read(db).unwrap();
    assert_eq!(saved["servers"][1], before["servers"][1]);
    assert_eq!(
        saved["servers"][0]["config"]["client"],
        before["servers"][0]["config"]["client"]
    );
    assert!(crate::policy::current(&saved).unwrap().zones.is_empty());
    let original = Journal::read(db).unwrap().committed;
    assert!(original.go_ipv4 && original.legacy_full.is_none());
    drop_primary();
    let carrier = |cfg: &Value, iface: &str| {
        if iface == "awg0" {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        sample(cfg, iface)
    };
    operate(db, run, Operation::Refresh, carrier).unwrap();
    assert_eq!(path("-4", V4_PROBE).as_deref(), Some("awg1"));
    assert_eq!(path("-6", V6_PROBE).as_deref(), Some("wan0"));
    let failed_over = Journal::read(db).unwrap();
    assert_eq!(
        failed_over.installed.active_reserves(),
        BTreeSet::from(["reserve"])
    );
    assert_eq!(failed_over.committed.revision, original.revision);
    assert_eq!(failed_over.committed.prefixes, original.prefixes);
    active_reserve(db);
    retire_go_full_reserve(db, run, &boot, killswitch, || {
        panic!("retiring the selected reserve cannot start a new peer")
    })
    .unwrap();
    let v4_after = (!killswitch).then_some("wan0");
    assert_eq!(path("-4", V4_PROBE).as_deref(), v4_after);
    assert_eq!(path("-6", V6_PROBE).as_deref(), Some("wan0"));
    assert_eq!(Journal::read(db).unwrap().committed, failed_over.committed);
    operate(db, run, Operation::Recover, carrier).unwrap();
    assert_eq!(path("-4", V4_PROBE).as_deref(), v4_after);
    assert_eq!(path("-6", V6_PROBE).as_deref(), Some("wan0"));
    operate(db, run, Operation::Teardown, carrier).unwrap();
}

#[test]
fn new_bare_full_reserve_uses_go_ipv4_only_with_two_exact_dual_native_owners() {
    for killswitch in [false, true] {
        let (_tmp, db) = with_full_reserve();
        configure_reserve_retirement(&db, killswitch);
        let run = DormantPrimary {
            router: Dual::default(),
            links: LINKS_WITHOUT_PRIMARY,
        };
        let path = |family: &str, address: &str| {
            let (kernel, source) = if family == "-4" {
                (&run.router.v4, "10.99.0.2")
            } else {
                (&run.router.v6, "2001:db8:91::2")
            };
            let iface = kernel.0.lock().unwrap().forward(source, address).to_owned();
            (iface != "unreachable").then_some(iface)
        };
        exercise_new_full_retirement(&db, &run, killswitch, path, || ());
    }
    for ineligible in ["wrong-owner", "out-of-date", "no-reserve-proof", "not-dual"] {
        let (_tmp, db) = with_full_reserve();
        let run = Dual::default();
        let boot = boot_id(&kernel(&run)).unwrap();
        operate(&db, &run, Operation::Apply, |cfg, iface| {
            let mut peer = fresh_full_peer(cfg, iface, &boot)?;
            if iface == "awg1" {
                match ineligible {
                    "wrong-owner" => {
                        peer.active_replacement_peer.as_mut().unwrap().owner.id = "other".into()
                    }
                    "out-of-date" => {
                        peer.active_replacement_peer.as_mut().unwrap().owner.boot = "bad".into()
                    }
                    "no-reserve-proof" => peer.active_replacement_peer = None,
                    _ => peer.ipv6_reachable = false,
                }
            }
            Ok(peer)
        })
        .unwrap();
        let plan = Journal::read(&db).unwrap().installed;
        assert!(
            !plan.go_ipv4 && plan.uses_family(plan::Family::V6),
            "{ineligible}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires the offline Linux network namespace for native full routes"]
fn new_bare_full_reserve_go_ipv4_follows_live_fib_through_selected_retirement() {
    assert!(std::path::Path::new("/synthetic-guest").is_file());
    for (kind, variable) in [("net", "N2S_PARENT_NET"), ("mnt", "N2S_PARENT_MNT")] {
        let parent = std::env::var(variable).unwrap();
        assert_ne!(
            std::fs::read_link(format!("/proc/self/ns/{kind}"))
                .unwrap()
                .to_str(),
            Some(parent.as_str())
        );
    }
    let run = nfqws2_router_command::System;
    for killswitch in [false, true] {
        let k = kernel(&run);
        k.call("ip", &["link", "add", "awg0", "type", "dummy"])
            .unwrap();
        k.call("ip", &["link", "set", "awg0", "up", "mtu", "1420"])
            .unwrap();
        let (_tmp, db) = with_full_reserve();
        configure_reserve_retirement(&db, killswitch);
        let before_v6 = k.listing(plan::Family::V6, &["rule", "show"]).unwrap();
        let path = |family: &str, address: &str| {
            assert_eq!(
                k.listing(plan::Family::V6, &["rule", "show"]).unwrap(),
                before_v6
            );
            k.call("ip", &[family, "route", "get", address])
                .ok()
                .and_then(|reply| {
                    reply
                        .split_ascii_whitespace()
                        .skip_while(|word| *word != "dev")
                        .nth(1)
                        .map(str::to_owned)
                })
        };
        exercise_new_full_retirement(&db, &run, killswitch, path, || {
            k.call("ip", &["link", "del", "awg0"]).unwrap();
        });
    }
}

#[test]
fn routed_full_reserve_disable_withdraws_policy_but_keeps_saved_ready_client() {
    for server in [false, true] {
        let (_temp, db) = with_full_reserve();
        let run = Dual::default();
        let old = install_full_reserve(&db, &run);
        let before = nfqws2_awg_profile::read(&db).unwrap();
        let check = |run: &Dual, expected| {
            assert_eq!(
                run.v4.0.lock().unwrap().forward("10.99.0.2", V4_PROBE),
                expected
            );
            assert_eq!(
                run.v6.0.lock().unwrap().forward("2001:db8:91::2", V6_PROBE),
                expected
            );
        };
        check(&run, "awg0");
        let owner = seal(&old.boot);
        withdraw_fixture(
            &db,
            &run,
            Some(&owner),
            &|| {
                assert_eq!(
                    nfqws2_awg_profile::read(&db)?["servers"][0]["config"]["client"]["enabled"],
                    true
                );
                Ok(())
            },
            |draft| {
                disable(draft, server);
                Ok(())
            },
        )
        .unwrap();
        check(&run, "wan0");
        let saved = nfqws2_awg_profile::read(&db).unwrap();
        assert_eq!(saved["servers"][1], before["servers"][1]);
        assert_eq!(
            saved["servers"][0]["config"]["client"]["fallback_tunnel_ids"],
            json!(["reserve"])
        );
        assert_eq!(saved["servers"][0]["config"]["client"]["enabled"], false);
        assert_eq!(saved["servers"][0]["config"]["enabled"], !server);
        assert_eq!(saved["servers"][0]["config"]["routing"]["active"], !server);
        assert!(routed_profile_is_disabled(&db, Some("main")).unwrap());
        let after = Journal::read(&db).unwrap();
        assert!(after.installed.empty());
        assert_eq!(after.committed, old.committed);
        let rebooted = Dual::default();
        rebooted.v4.0.lock().unwrap().boot = "93939393-9393-9393-9393-939393939393".into();
        operate(&db, &rebooted, Operation::Recover, |_, _| {
            panic!("withdrawn full queried a peer")
        })
        .unwrap();
        check(&rebooted, "wan0");
        assert_eq!(Journal::read(&db).unwrap().committed, old.committed);
        assert_eq!(
            nfqws2_awg_profile::read(&db).unwrap()["servers"][1],
            before["servers"][1]
        );
        rearm(&db);
        operate(&db, &rebooted, Operation::Refresh, full_reserve_peer).unwrap();
        check(&rebooted, "awg0");
    }
}

#[test]
fn routed_full_reserve_disable_refuses_an_independent_blanket_and_compensates_failed_write() {
    let (_temp, db) = with_full_reserve();
    let run = Dual::default();
    let old = install_full_reserve(&db, &run);
    let before = nfqws2_awg_profile::read(&db).unwrap();
    let owner = seal(&old.boot);
    nfqws2_awg_profile::edit_document(&db, |draft| {
        draft["servers"][1]["config"]["routing"]["active"] = true.into();
        Ok(())
    })
    .unwrap();
    assert_eq!(
        withdraw_fixture(
            &db,
            &run,
            Some(&owner),
            &|| panic!("unproved full substitute"),
            |_| panic!("unproved full substitute")
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::Unsupported
    );
    assert_eq!(Journal::read(&db).unwrap(), old);
    nfqws2_awg_profile::edit_document(&db, |draft| {
        *draft = before.clone();
        Ok(())
    })
    .unwrap();
    {
        let mut kernel = run.v4.0.lock().unwrap();
        kernel.fail_after = Some(kernel.changes + 1);
    }
    assert!(
        withdraw_fixture(&db, &run, Some(&owner), &|| Ok(()), |draft| {
            disable(draft, false);
            Ok(())
        })
        .is_err()
    );
    assert_eq!(Journal::read(&db).unwrap(), old);
    assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), before);
    assert_eq!(
        kernel(&run).inventory(&old.claims(), true).unwrap(),
        objects(&old.installed)
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires no-NIC Linux with independent net and mount namespaces"]
fn routed_full_reserve_disable_withdraws_real_native_defaults_keeps_independent_link() {
    verify_full_reserve_real_fib(false, "N2S_R99_REAL_FIB");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires no-NIC Linux with independent net and mount namespaces"]
fn routed_full_reserve_disable_withdraws_defaults_already_on_real_independent_link() {
    verify_full_reserve_real_fib(true, "N2S_R100_REAL_FIB");
}

#[cfg(target_os = "linux")]
fn verify_full_reserve_real_fib(on_reserve: bool, enable: &str) {
    assert!(std::path::Path::new("/synthetic-guest").is_file());
    for (kind, var) in [("net", "N2S_PARENT_NET"), ("mnt", "N2S_PARENT_MNT")] {
        let parent = std::env::var(var).unwrap();
        let current = std::fs::read_link(format!("/proc/self/ns/{kind}")).unwrap();
        assert!(parent.starts_with(&format!("{kind}:[")));
        assert_ne!(current.to_str(), Some(parent.as_str()));
    }
    if std::env::var_os(enable).is_none() {
        return;
    }
    let run = nfqws2_router_command::System;
    let k = kernel(&run);
    let route = |family, address| {
        let reply = k.call("ip", &[family, "route", "get", address]).unwrap();
        reply
            .split_ascii_whitespace()
            .skip_while(|word| *word != "dev")
            .nth(1)
            .unwrap()
            .to_owned()
    };
    let reserve_addresses = || {
        ["-4", "-6"].map(|af| {
            k.call("ip", &["-o", af, "addr", "show", "dev", "awg1"])
                .unwrap()
        })
    };
    for server in [false, true] {
        let (_temp, db) = with_full_reserve();
        let old = if on_reserve {
            select_full_reserve(&db, &run)
        } else {
            install_full_reserve(&db, &run)
        };
        let held = reserve_addresses();
        assert!(held.iter().all(|data| !data.is_empty()));
        let carrier = if on_reserve { "awg1" } else { "awg0" };
        assert_eq!(route("-4", V4_PROBE), carrier);
        assert_eq!(route("-6", V6_PROBE), carrier);
        let owner = seal(&old.boot);
        withdraw_fixture(&db, &run, Some(&owner), &|| Ok(()), |draft| {
            disable(draft, server);
            Ok(())
        })
        .unwrap();
        k.call("ip", &["link", "set", "awg0", "down"]).unwrap();
        assert_eq!(route("-4", V4_PROBE), "wan0");
        assert_eq!(route("-6", V6_PROBE), "wan0");
        assert_eq!(reserve_addresses(), held);
        for family in [plan::Family::V4, plan::Family::V6] {
            let rules = k.listing(family, &["rule", "show"]).unwrap();
            assert!(!rules.contains("17842"));
        }
        operate(&db, &run, Operation::Recover, |_, _| {
            panic!("withdrawn blanket discovered a new owner")
        })
        .unwrap();
        assert_eq!(Journal::read(&db).unwrap().committed, old.committed);
        assert_eq!(reserve_addresses(), held);
        k.call("ip", &["link", "set", "awg0", "up"]).unwrap();
        rearm(&db);
        operate(&db, &run, Operation::Refresh, full_reserve_peer).unwrap();
        assert_eq!(route("-4", V4_PROBE), "awg0");
        assert_eq!(route("-6", V6_PROBE), "awg0");
        operate(&db, &run, Operation::Teardown, full_reserve_peer).unwrap();
    }
}

fn select_full_reserve(db: &Store, run: &dyn Runner) -> Journal {
    install_full_reserve(db, run);
    operate(db, run, Operation::Refresh, |cfg, iface| {
        if iface == "awg0" {
            Err(io::ErrorKind::WouldBlock.into())
        } else {
            full_reserve_peer(cfg, iface)
        }
    })
    .unwrap();
    let old = Journal::read(db).unwrap();
    assert_eq!(old.installed.selected.len(), 2);
    assert_eq!(old.installed.active_reserves(), BTreeSet::from(["reserve"]));
    old
}

#[test]
fn routed_full_reserve_disable_retires_logical_primary_after_both_defaults_failed_over() {
    for server in [false, true] {
        let (_temp, db) = with_full_reserve();
        let run = Dual::default();
        let old = select_full_reserve(&db, &run);
        let before = nfqws2_awg_profile::read(&db).unwrap();
        let owner = seal(&old.boot);
        let forwarded = |expected| {
            assert_eq!(
                run.v4.0.lock().unwrap().forward("10.99.0.2", V4_PROBE),
                expected
            );
            assert_eq!(
                run.v6.0.lock().unwrap().forward("2001:db8:91::2", V6_PROBE),
                expected
            );
        };
        forwarded("awg1");
        let disable_primary = || {
            withdraw_fixture(
                &db,
                &run,
                Some(&owner),
                &|| {
                    assert_eq!(
                        nfqws2_awg_profile::read(&db)?["servers"][0]["config"]["client"]["enabled"],
                        true
                    );
                    Ok(())
                },
                |draft| {
                    disable(draft, server);
                    Ok(())
                },
            )
        };
        {
            let mut kernel = run.v4.0.lock().unwrap();
            kernel.fail_after = Some(kernel.changes + 1);
        }
        assert!(disable_primary().is_err());
        assert_eq!(Journal::read(&db).unwrap(), old);
        assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), before);
        forwarded("awg1");
        disable_primary().unwrap();
        forwarded("wan0");
        let saved = nfqws2_awg_profile::read(&db).unwrap();
        assert_eq!(saved["servers"][1], before["servers"][1]);
        assert_eq!(
            saved["servers"][0]["config"]["client"]["fallback_tunnel_ids"],
            json!(["reserve"])
        );
        assert_eq!(saved["servers"][0]["config"]["client"]["enabled"], false);
        assert_eq!(saved["servers"][0]["config"]["enabled"], !server);
        assert_eq!(saved["servers"][0]["config"]["routing"]["active"], !server);
        assert!(Journal::read(&db).unwrap().installed.empty());
        operate(&db, &run, Operation::Recover, |_, _| {
            panic!("withdrawn full restarted on reserve")
        })
        .unwrap();
        assert_eq!(Journal::read(&db).unwrap().committed, old.committed);
        forwarded("wan0");
    }
}

#[test]
fn routed_full_reserve_disable_declines_a_partial_family_handover() {
    let (_temp, db) = with_full_reserve();
    let run = Dual::default();
    install_full_reserve(&db, &run);
    operate(&db, &run, Operation::Refresh, |cfg, iface| {
        if iface == "awg0" {
            live(false)(cfg, iface)
        } else {
            full_reserve_peer(cfg, iface)
        }
    })
    .unwrap();
    let before = Journal::read(&db).unwrap();
    assert_eq!(before.installed.selected.len(), 1);
    let saved = nfqws2_awg_profile::read(&db).unwrap();
    let owner = seal(&before.boot);
    let writes = run.v4.0.lock().unwrap().changes;
    assert_eq!(
        withdraw_fixture(
            &db,
            &run,
            Some(&owner),
            &|| panic!("partial prior full"),
            |_| panic!("partial prior full")
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::Unsupported
    );
    assert_eq!(Journal::read(&db).unwrap(), before);
    assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), saved);
    assert_eq!(run.v4.0.lock().unwrap().changes, writes);
}

fn configure_reserve_retirement(db: &Store, killswitch: bool) {
    nfqws2_awg_profile::edit_document(db, |doc| {
        doc["routing"]["killswitch"] = killswitch.into();
        Ok(())
    })
    .unwrap();
}

fn active_reserve(db: &Store) {
    nfqws2_awg_profile::edit_document(db, |doc| {
        doc["active_id"] = "reserve".into();
        Ok(())
    })
    .unwrap();
}

fn disable_full_reserve(db: &Store, run: &dyn Runner, boot: &str, server: bool) -> io::Result<()> {
    use crate::kernel::routed_disable::withdraw_direct_reserve_fixture;
    let owner = NativeRemovalSeal {
        id: "reserve".into(),
        iface: "awg1".into(),
        pid: 9201,
        receipt_sha256: [0x93; 32],
        ..seal(boot)
    };
    withdraw_direct_reserve_fixture(
        db,
        run,
        &owner,
        &|_| panic!("there is no new forwarding authority"),
        |doc| {
            let cfg = &mut doc["servers"][1]["config"];
            cfg["client"]["enabled"] = false.into();
            cfg["client"]["rust_managed"] = false.into();
            if server {
                cfg["enabled"] = false.into();
                cfg["routing"]["active"] = false.into();
            }
            Ok(())
        },
    )
}

struct DormantPrimary {
    router: Dual,
    links: &'static str,
}
impl Runner for DormantPrimary {
    fn run(&self, program: &str, args: &[&str], until: Instant) -> io::Result<String> {
        if program == "ip" && args == ["-o", "link", "show"] {
            return Ok(self.links.into());
        }
        self.router.run(program, args, until)
    }
}

const LINKS_WITHOUT_PRIMARY: &str =
    "1: lo: <LOOPBACK,UP> mtu 65536\n2: awg1: <UP> mtu 1420\n3: wan0: <UP> mtu 1500\n";

#[test]
fn routed_full_reserve_disable_parks_absent_primary_and_recovers_only_after_handshake() {
    for server in [false, true] {
        let (_temp, db) = with_full_reserve();
        let run = DormantPrimary {
            router: Dual::default(),
            links: LINKS_WITHOUT_PRIMARY,
        };
        let before = select_full_reserve(&db, &run);
        active_reserve(&db);
        let saved = nfqws2_awg_profile::read(&db).unwrap();
        let path = |family| {
            if family == plan::Family::V4 {
                run.router
                    .v4
                    .0
                    .lock()
                    .unwrap()
                    .forward("10.99.0.2", V4_PROBE)
                    .to_owned()
            } else {
                run.router
                    .v6
                    .0
                    .lock()
                    .unwrap()
                    .forward("2001:db8:91::2", V6_PROBE)
                    .to_owned()
            }
        };
        for family in [plan::Family::V4, plan::Family::V6] {
            assert_eq!(path(family), "awg1");
        }
        {
            let mut kernel = run.router.v4.0.lock().unwrap();
            kernel.fail_after = Some(kernel.changes + 1);
        }
        assert!(disable_full_reserve(&db, &run, &before.boot, server).is_err());
        assert_eq!(Journal::read(&db).unwrap(), before);
        assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), saved);
        for family in [plan::Family::V4, plan::Family::V6] {
            assert_eq!(path(family), "awg1");
        }
        disable_full_reserve(&db, &run, &before.boot, server).unwrap();
        for family in [plan::Family::V4, plan::Family::V6] {
            assert_eq!(path(family), "unreachable");
        }
        let out = Journal::read(&db).unwrap();
        assert_eq!(out.committed, before.committed);
        assert_eq!(out.installed.targets.len(), 1);
        assert!(out.installed.reserves.is_empty());
        assert!(out
            .installed
            .selected
            .iter()
            .all(|(_, selected)| selected.is_none()));
        let after = nfqws2_awg_profile::read(&db).unwrap();
        assert_eq!(after["servers"][0], saved["servers"][0]);
        assert_eq!(after["servers"][1]["config"]["enabled"], !server);
        assert_eq!(after["servers"][1]["config"]["client"]["enabled"], false);
        assert_eq!(after["servers"][1]["config"]["routing"]["active"], false);
        operate(&db, &run, Operation::Recover, |_, iface| {
            assert_eq!(iface, "awg0");
            Err(io::ErrorKind::WouldBlock.into())
        })
        .unwrap();
        for family in [plan::Family::V4, plan::Family::V6] {
            assert_eq!(path(family), "unreachable");
        }
        operate(&db, &run, Operation::Refresh, |cfg, iface| {
            assert_eq!(iface, "awg0");
            full_reserve_peer(cfg, iface)
        })
        .unwrap();
        for family in [plan::Family::V4, plan::Family::V6] {
            assert_eq!(path(family), "awg0");
        }
    }
}

#[test]
fn routed_full_reserve_disable_requires_positive_absence_of_the_primary_link() {
    for links in [
        "",
        "bad reply\n",
        "1: lo: <UP> mtu 65536\n2: awg0@wan0: <UP> mtu 1420\n",
    ] {
        let (_temp, db) = with_full_reserve();
        let run = DormantPrimary {
            router: Dual::default(),
            links,
        };
        let before = select_full_reserve(&db, &run);
        active_reserve(&db);
        let saved = nfqws2_awg_profile::read(&db).unwrap();
        let result = disable_full_reserve(&db, &run, &before.boot, false).unwrap_err();
        assert!(matches!(
            result.kind(),
            io::ErrorKind::InvalidData | io::ErrorKind::WouldBlock
        ));
        assert_eq!(Journal::read(&db).unwrap(), before);
        assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), saved);
    }
}

/// Go synthetic multi full does not have an IPv6 table. Native full retains
/// its existing explicit IPv6 outage fence even with the Kill Switch off.
#[test]
fn routed_full_reserve_disable_native_ipv6_fence_differs_from_go_multi_wan_with_killswitch_off() {
    let (_temp, db) = with_full_reserve();
    configure_reserve_retirement(&db, false);
    let run = DormantPrimary {
        router: Dual::default(),
        links: LINKS_WITHOUT_PRIMARY,
    };
    let before = select_full_reserve(&db, &run);
    active_reserve(&db);
    assert_eq!(
        run.router
            .v6
            .0
            .lock()
            .unwrap()
            .forward("2001:db8:91::2", V6_PROBE),
        "awg1"
    );
    disable_full_reserve(&db, &run, &before.boot, false).unwrap();
    assert_eq!(
        run.router
            .v4
            .0
            .lock()
            .unwrap()
            .forward("10.99.0.2", V4_PROBE),
        "wan0"
    );
    assert_eq!(
        run.router
            .v6
            .0
            .lock()
            .unwrap()
            .forward("2001:db8:91::2", V6_PROBE),
        "unreachable"
    );
    let installed = Journal::read(&db).unwrap().installed;
    assert!(!installed.killswitch);
    assert!(
        !objects(&installed).contains(&Object::FullGuard(crate::kernel::full::Guard::Fence(
            plan::Family::V4
        )))
    );
    assert!(
        objects(&installed).contains(&Object::FullGuard(crate::kernel::full::Guard::Fence(
            plan::Family::V6
        )))
    );
}

fn go_full_fixture(killswitch: bool) -> (tempfile::TempDir, Store) {
    let (temp, db, _) = setup();
    for (address, endpoint) in [
        ("198.18.95.4", "203.0.113.10"),
        ("198.18.95.5", "192.0.2.46"),
    ] {
        nfqws2_awg_profile::import(&db, &format!(
            "[Interface]\nPrivateKey = {KEY}\nAddress = {address}/32\nMTU = 1420\n\n[Peer]\nPublicKey = {KEY}\nEndpoint = {endpoint}:443\nAllowedIPs = 0.0.0.0/0\n"
        ), "fixture").unwrap();
    }
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"] = json!({"mode":"full","killswitch":killswitch});
        let rows = doc["servers"].as_array_mut().unwrap();
        rows.remove(0);
        for (index, (row, id)) in rows.iter_mut().zip(["main", "reserve"]).enumerate() {
            row["id"] = id.into();
            row["config"]["client_iface"] = format!("awg{index}").into();
            row["config"]["client"]["enabled"] = true.into();
            row["config"]["client"]["rust_managed"] = true.into();
            row["config"]["routing"] = json!({"mode":"full","active":index == 0});
        }
        rows[0]["config"]["client"]["fallback_tunnel_ids"] = json!(["reserve"]);
        doc["active_id"] = "main".into();
        Ok(())
    })
    .unwrap();
    (temp, db)
}

fn selected_go_full_reserve(db: &Store, run: &dyn Runner) -> Journal {
    let doc = nfqws2_awg_profile::read(db).unwrap();
    let k = kernel(run);
    let intent = plan::compile_effective(
        &doc,
        crate::policy::current(&doc).unwrap(),
        None,
        true,
        &[],
        plan::Layout {
            go_ipv4: true,
            implicit_go_full_revision: doc["routing_revision"].as_u64(),
            ..Default::default()
        },
    )
    .unwrap();
    let live = plan::resolve_on(
        &doc,
        intent,
        false,
        None,
        Some(plan::Verification::Read(&k)),
        |cfg, iface| {
            if iface == "awg1" {
                full_reserve_peer(cfg, iface)
            } else {
                Err(io::ErrorKind::WouldBlock.into())
            }
        },
    )
    .unwrap();
    let mut installed = live.plan;
    k.select_firewall(&mut installed).unwrap();
    k.guard(&installed, &live.endpoints).unwrap();
    assert_eq!(installed.active_reserves(), BTreeSet::from(["reserve"]));
    assert!(installed.go_ipv4);
    let mut committed = installed.clone();
    committed.selected.clear();
    let journal = Journal {
        boot: boot_id(&k).unwrap(),
        installed: installed.into(),
        committed: committed.into(),
        ..Default::default()
    };
    db.transaction(|tx| transition(db, tx, run, &Journal::default(), &journal, None))
        .unwrap();
    active_reserve(db);
    journal
}

fn go_full_primary(db: &Store, boot: &str) -> nfqws2_awg_profile::ActiveReplacementPeer {
    let doc = nfqws2_awg_profile::read(db).unwrap();
    let (_, endpoint, fingerprint) =
        nfqws2_awg_profile::active_replacement_underlay_identity(&doc, "main").unwrap();
    nfqws2_awg_profile::ActiveReplacementPeer {
        owner: seal(boot),
        endpoint,
        fingerprint,
        socket_mark: 0,
        mtu: 1420,
        allowed: vec!["0.0.0.0/0".into(), "::/0".into()],
        underlay: None,
        nested_only: false,
    }
}

fn retire_go_full_reserve(
    db: &Store,
    run: &dyn Runner,
    boot: &str,
    server: bool,
    held: impl Fn() -> io::Result<nfqws2_awg_profile::ActiveReplacementPeer>,
) -> io::Result<()> {
    let owner = NativeRemovalSeal {
        id: "reserve".into(),
        iface: "awg1".into(),
        pid: 9201,
        receipt_sha256: [0x93; 32],
        ..seal(boot)
    };
    crate::kernel::routed_disable::withdraw_direct_reserve_fixture(
        db,
        run,
        &owner,
        &|id| {
            assert_eq!(id, "main");
            held()
        },
        |doc| {
            let cfg = &mut doc["servers"][1]["config"];
            cfg["client"]["enabled"] = false.into();
            cfg["client"]["rust_managed"] = false.into();
            if server {
                cfg["enabled"] = false.into();
                cfg["routing"]["active"] = false.into();
            }
            Ok(())
        },
    )
}

fn operate_after_go_full_reserve(
    db: &Store,
    run: &dyn Runner,
    op: Operation,
    fresh: bool,
    owner: impl Fn() -> Option<nfqws2_awg_profile::ActiveReplacementPeer>,
) -> io::Result<()> {
    operate_with_native_ownership(
        db,
        run,
        op,
        (None, None, false, None),
        |cfg, iface| {
            assert_eq!(iface, "awg0");
            if fresh {
                full_reserve_peer(cfg, iface)
            } else {
                Err(io::ErrorKind::WouldBlock.into())
            }
        },
        |_, _| panic!("no routed MTU transaction"),
        GoFullPrimaryRecovery {
            wan: &["wan0".into()],
            probe: &|id| {
                assert_eq!(id, "main");
                Ok(owner())
            },
        },
    )
    .map(drop)
}

#[test]
fn go_full_retains_only_currently_owned_stale_primary_across_refresh_and_reboot() {
    const NEW_BOOT: &str = "72727272-7272-7272-7272-727272727272";
    for killswitch in [false, true] {
        let (_tmp, db) = go_full_fixture(killswitch);
        let run = DormantPrimary {
            router: Dual::default(),
            links: "1: lo: <UP> mtu 65536\n2: awg0: <UP> mtu 1420\n3: awg1: <UP> mtu 1420\n",
        };
        let old = selected_go_full_reserve(&db, &run);
        let stale = go_full_primary(&db, &old.boot);
        let check = |expected: &str| {
            assert_eq!(
                run.router
                    .v4
                    .0
                    .lock()
                    .unwrap()
                    .forward("10.99.0.2", V4_PROBE),
                expected
            );
            assert_eq!(
                run.router
                    .v6
                    .0
                    .lock()
                    .unwrap()
                    .forward("2001:db8:91::2", V6_PROBE),
                "wan0"
            );
        };
        check("awg1");
        assert!(retire_go_full_reserve(&db, &run, &old.boot, false, || {
            Err(io::ErrorKind::NotFound.into())
        })
        .is_err());
        assert_eq!(Journal::read(&db).unwrap(), old);
        check("awg1");
        retire_go_full_reserve(&db, &run, &old.boot, true, || Ok(stale.clone())).unwrap();
        check("awg0");
        operate_after_go_full_reserve(&db, &run, Operation::Refresh, false, || Some(stale.clone()))
            .unwrap();
        check("awg0");
        operate_after_go_full_reserve(&db, &run, Operation::Refresh, true, || {
            panic!("ordinary authenticated peer must take priority")
        })
        .unwrap();
        check("awg0");
        operate_after_go_full_reserve(&db, &run, Operation::Refresh, false, || None).unwrap();
        let unavailable = if killswitch { "unreachable" } else { "wan0" };
        check(unavailable);

        for revision in [old.committed.revision + 1, old.committed.revision] {
            nfqws2_awg_profile::edit_document(&db, |doc| {
                doc["routing_revision"] = revision.into();
                Ok(())
            })
            .unwrap();
            if revision != old.committed.revision {
                operate_after_go_full_reserve(&db, &run, Operation::Refresh, false, || {
                    panic!("stale authority cannot be inferred from a new draft")
                })
                .unwrap();
                check(unavailable);
            }
        }

        *run.router.v4.0.lock().unwrap() = Firmware {
            boot: NEW_BOOT.into(),
            ..Default::default()
        };
        *run.router.v6.0.lock().unwrap() = Firmware {
            boot: NEW_BOOT.into(),
            ..Default::default()
        };
        operate_after_go_full_reserve(&db, &run, Operation::Recover, false, || Some(stale.clone()))
            .unwrap();
        check(unavailable);
        let mut renewed = stale;
        renewed.owner.boot = NEW_BOOT.into();
        renewed.owner.pid += 3;
        renewed.owner.receipt_sha256 = [0x91; 32];
        operate_after_go_full_reserve(&db, &run, Operation::Recover, false, || {
            Some(renewed.clone())
        })
        .unwrap();
        check("awg0");
        assert_eq!(
            Journal::read(&db).unwrap().committed.prefixes,
            old.committed.prefixes
        );
        assert_eq!(
            Journal::read(&db).unwrap().committed.reserves,
            old.committed.reserves
        );
        assert!(
            operate_after_go_full_reserve(&db, &run, Operation::Apply, false, || {
                panic!("stale proof cannot authorize a new Apply")
            })
            .is_err()
        );
        check("awg0");
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires no-NIC Linux with independent net and mount namespaces"]
fn go_full_stale_primary_keeps_actual_forwarding_only_while_owned() {
    assert!(std::path::Path::new("/synthetic-guest").is_file());
    for (kind, variable) in [("net", "N2S_PARENT_NET"), ("mnt", "N2S_PARENT_MNT")] {
        let parent = std::env::var(variable).unwrap();
        let current = std::fs::read_link(format!("/proc/self/ns/{kind}")).unwrap();
        assert!(parent.starts_with(&format!("{kind}:[")));
        assert_ne!(current.to_str(), Some(parent.as_str()));
    }
    let run = nfqws2_router_command::System;
    for killswitch in [false, true] {
        let k = kernel(&run);
        let make_primary = || {
            k.call("ip", &["link", "add", "awg0", "type", "dummy"])
                .unwrap();
            k.call("ip", &["link", "set", "awg0", "up", "mtu", "1420"])
                .unwrap();
        };
        let route = |family, address| {
            k.call("ip", &[family, "route", "get", address])
                .ok()
                .and_then(|reply| {
                    reply
                        .split_ascii_whitespace()
                        .skip_while(|word| *word != "dev")
                        .nth(1)
                        .map(str::to_owned)
                })
        };
        let check = |wanted| {
            assert_eq!(route("-4", V4_PROBE).as_deref(), wanted);
            assert_eq!(route("-6", V6_PROBE).as_deref(), Some("wan0"));
        };
        make_primary();
        let (_tmp, db) = go_full_fixture(killswitch);
        let old = selected_go_full_reserve(&db, &run);
        let stale = go_full_primary(&db, &old.boot);
        assert!(retire_go_full_reserve(&db, &run, &old.boot, false, || {
            Err(io::ErrorKind::NotFound.into())
        })
        .is_err());
        check(Some("awg1"));
        retire_go_full_reserve(&db, &run, &old.boot, true, || Ok(stale.clone())).unwrap();
        check(Some("awg0"));
        operate_after_go_full_reserve(&db, &run, Operation::Refresh, false, || Some(stale.clone()))
            .unwrap();
        check(Some("awg0"));
        operate_after_go_full_reserve(&db, &run, Operation::Refresh, true, || {
            panic!("ordinary fresh handshake already confirmed")
        })
        .unwrap();
        check(Some("awg0"));
        k.call("ip", &["link", "del", "awg0"]).unwrap();
        operate_after_go_full_reserve(&db, &run, Operation::Refresh, false, || None).unwrap();
        check((!killswitch).then_some("wan0"));
        make_primary();
        operate_after_go_full_reserve(&db, &run, Operation::Recover, false, || None).unwrap();
        check((!killswitch).then_some("wan0"));
        let mut restarted = stale;
        restarted.owner.pid += 10;
        restarted.owner.receipt_sha256 = [0x27; 32];
        operate_after_go_full_reserve(&db, &run, Operation::Recover, false, || {
            Some(restarted.clone())
        })
        .unwrap();
        check(Some("awg0"));
        operate_after_go_full_reserve(&db, &run, Operation::Suspend, false, || None).unwrap();
        operate_after_go_full_reserve(&db, &run, Operation::Recover, false, || {
            Some(restarted.clone())
        })
        .unwrap();
        check(Some("awg0"));
        operate_after_go_full_reserve(&db, &run, Operation::Teardown, false, || None).unwrap();
        k.call("ip", &["link", "del", "awg0"]).unwrap();
    }
}

#[test]
fn go_implicit_full_reserve_disable_matches_each_family_without_native_ipv6_ownership() {
    for (server, killswitch, ready) in [
        (false, false, false),
        (false, true, true),
        (true, false, true),
        (true, true, false),
    ] {
        let (_temp, db) = go_full_fixture(killswitch);
        let run = DormantPrimary {
            router: Dual::default(),
            links: if ready {
                "1: lo: <UP> mtu 65536\n2: awg0: <UP> mtu 1420\n3: awg1: <UP> mtu 1420\n"
            } else {
                LINKS_WITHOUT_PRIMARY
            },
        };
        let before = selected_go_full_reserve(&db, &run);
        let saved = nfqws2_awg_profile::read(&db).unwrap();
        let peer = go_full_primary(&db, &before.boot);
        let route = || {
            run.router
                .v4
                .0
                .lock()
                .unwrap()
                .forward("10.99.0.2", V4_PROBE)
                .to_owned()
        };
        assert_eq!(route(), "awg1");
        if ready {
            run.router.v4.0.lock().unwrap().watch_flow = Some(("10.99.0.2", V4_PROBE));
            let mut foreign = peer.clone();
            foreign.allowed.clear();
            assert!(retire_go_full_reserve(
                &db,
                &run,
                &before.boot,
                server,
                || Ok(foreign.clone())
            )
            .is_err());
            assert_eq!(Journal::read(&db).unwrap(), before);
            assert_eq!(route(), "awg1");
            let observations = std::cell::Cell::new(0);
            assert!(retire_go_full_reserve(&db, &run, &before.boot, server, || {
                let reads = observations.get() + 1;
                observations.set(reads);
                if reads >= 3 {
                    Err(io::ErrorKind::WouldBlock.into())
                } else {
                    Ok(peer.clone())
                }
            })
            .is_err());
            assert!(observations.get() >= 3);
            assert_eq!(Journal::read(&db).unwrap(), before);
            assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), saved);
            assert_eq!(route(), "awg1");
        }
        retire_go_full_reserve(&db, &run, &before.boot, server, || {
            assert!(ready, "absent device cannot authenticate");
            Ok(peer.clone())
        })
        .unwrap();
        let after = Journal::read(&db).unwrap();
        let stored = nfqws2_awg_profile::read(&db).unwrap();
        assert_eq!(after.committed, before.committed);
        assert!(after.installed.go_ipv4 && after.installed.reserves.is_empty());
        assert!(!after.installed.uses_family(plan::Family::V6));
        assert_eq!(stored["servers"][0], saved["servers"][0]);
        assert_eq!(stored["servers"][1]["config"]["enabled"], !server);
        assert_eq!(stored["servers"][1]["config"]["client"]["enabled"], false);
        assert_eq!(stored["servers"][1]["config"]["routing"]["active"], false);
        assert_eq!(
            route(),
            if ready {
                "awg0"
            } else if killswitch {
                "unreachable"
            } else {
                "wan0"
            }
        );
        assert_eq!(
            run.router
                .v6
                .0
                .lock()
                .unwrap()
                .forward("2001:db8:91::2", V6_PROBE),
            "wan0"
        );
        assert!(!run.router.v4.0.lock().unwrap().leaked);
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires no-NIC Linux with independent net and mount namespaces"]
fn go_implicit_full_reserve_disable_preserves_real_ipv6_wan_and_v4_owner() {
    assert!(std::path::Path::new("/synthetic-guest").is_file());
    for (kind, variable) in [("net", "N2S_PARENT_NET"), ("mnt", "N2S_PARENT_MNT")] {
        let parent = std::env::var(variable).unwrap();
        let current = std::fs::read_link(format!("/proc/self/ns/{kind}")).unwrap();
        assert!(parent.starts_with(&format!("{kind}:[")));
        assert_ne!(current.to_str(), Some(parent.as_str()));
    }
    let run = nfqws2_router_command::System;
    for server in [false, true] {
        for killswitch in [false, true] {
            for ready in [false, true] {
                let k = kernel(&run);
                let lookup = |family, address| {
                    k.call("ip", &[family, "route", "get", address])
                        .ok()
                        .and_then(|reply| {
                            reply
                                .split_ascii_whitespace()
                                .skip_while(|word| *word != "dev")
                                .nth(1)
                                .map(str::to_owned)
                        })
                };
                if ready {
                    k.call("ip", &["link", "add", "awg0", "type", "dummy"])
                        .unwrap();
                    k.call("ip", &["link", "set", "awg0", "up", "mtu", "1420"])
                        .unwrap();
                }
                let (_temp, db) = go_full_fixture(killswitch);
                let old = selected_go_full_reserve(&db, &run);
                let peer = go_full_primary(&db, &old.boot);
                let before = nfqws2_awg_profile::read(&db).unwrap();
                assert_eq!(lookup("-4", V4_PROBE).as_deref(), Some("awg1"));
                assert_eq!(lookup("-6", V6_PROBE).as_deref(), Some("wan0"));
                let v6_before = k.listing(plan::Family::V6, &["rule", "show"]).unwrap();
                if ready {
                    assert!(retire_go_full_reserve(&db, &run, &old.boot, server, || {
                        Err(io::ErrorKind::WouldBlock.into())
                    })
                    .is_err());
                    assert_eq!(lookup("-4", V4_PROBE).as_deref(), Some("awg1"));
                    assert_eq!(Journal::read(&db).unwrap(), old);
                }
                retire_go_full_reserve(&db, &run, &old.boot, server, || {
                    assert!(ready);
                    Ok(peer.clone())
                })
                .unwrap();
                k.call("ip", &["link", "set", "awg1", "down"]).unwrap();
                let wanted = if ready {
                    Some("awg0")
                } else {
                    (!killswitch).then_some("wan0")
                };
                let check_paths = || {
                    assert_eq!(lookup("-4", V4_PROBE).as_deref(), wanted);
                    assert_eq!(lookup("-6", V6_PROBE).as_deref(), Some("wan0"));
                    assert_eq!(
                        k.listing(plan::Family::V6, &["rule", "show"]).unwrap(),
                        v6_before
                    );
                };
                check_paths();
                let saved = nfqws2_awg_profile::read(&db).unwrap();
                assert_eq!(saved["servers"][0], before["servers"][0]);
                assert_eq!(saved["servers"][1]["config"]["enabled"], !server);
                assert_eq!(saved["servers"][1]["config"]["client"]["enabled"], false);
                assert_eq!(Journal::read(&db).unwrap().committed, old.committed);
                let sample = |cfg: &Value, iface: &str| {
                    assert_eq!(iface, "awg0");
                    if ready {
                        full_reserve_peer(cfg, iface)
                    } else {
                        Err(io::ErrorKind::WouldBlock.into())
                    }
                };
                operate(&db, &run, Operation::Recover, sample).unwrap();
                check_paths();
                operate(&db, &run, Operation::Teardown, sample).unwrap();
                k.call("ip", &["link", "set", "awg1", "up"]).unwrap();
                if ready {
                    k.call("ip", &["link", "del", "awg0"]).unwrap();
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires no-NIC Linux with independent net and mount namespaces"]
fn routed_full_reserve_disable_preserves_real_fences_with_physically_absent_primary() {
    assert!(std::path::Path::new("/synthetic-guest").is_file());
    for (kind, var) in [("net", "N2S_PARENT_NET"), ("mnt", "N2S_PARENT_MNT")] {
        let parent = std::env::var(var).unwrap();
        let current = std::fs::read_link(format!("/proc/self/ns/{kind}")).unwrap();
        assert!(parent.starts_with(&format!("{kind}:[")));
        assert_ne!(current.to_str(), Some(parent.as_str()));
    }
    if std::env::var_os("N2S_R101_REAL_FIB").is_none() {
        return;
    }
    let run = nfqws2_router_command::System;
    for server in [false, true] {
        for killswitch in [false, true] {
            let k = kernel(&run);
            let route = |family, address| {
                let reply = k.call("ip", &[family, "route", "get", address]).ok()?;
                reply
                    .split_ascii_whitespace()
                    .skip_while(|word| *word != "dev")
                    .nth(1)
                    .map(str::to_owned)
            };
            let (_temp, db) = with_full_reserve();
            configure_reserve_retirement(&db, killswitch);
            let old = select_full_reserve(&db, &run);
            active_reserve(&db);
            k.call("ip", &["link", "del", "awg0"]).unwrap();
            assert_eq!(route("-4", V4_PROBE).as_deref(), Some("awg1"));
            assert_eq!(route("-6", V6_PROBE).as_deref(), Some("awg1"));
            let before = nfqws2_awg_profile::read(&db).unwrap();
            disable_full_reserve(&db, &run, &old.boot, server).unwrap();
            k.call("ip", &["link", "set", "awg1", "down"]).unwrap();
            assert_eq!(
                route("-4", V4_PROBE).as_deref(),
                (!killswitch).then_some("wan0")
            );
            assert_eq!(route("-6", V6_PROBE), None);
            for family in [plan::Family::V4, plan::Family::V6] {
                let rules = k.listing(family, &["rule", "show"]).unwrap();
                assert!(rules.contains("17842"));
                let table = k
                    .listing(family, &["route", "show", "table", "17842"])
                    .unwrap();
                assert!(!table.contains("dev awg0") && !table.contains("dev awg1"));
            }
            let after = nfqws2_awg_profile::read(&db).unwrap();
            assert_eq!(after["servers"][0], before["servers"][0]);
            assert_eq!(after["servers"][1]["config"]["client"]["enabled"], false);
            assert_eq!(after["servers"][1]["config"]["enabled"], !server);
            assert_eq!(Journal::read(&db).unwrap().committed, old.committed);
            operate(&db, &run, Operation::Recover, |_, iface| {
                assert_eq!(iface, "awg0");
                Err(io::ErrorKind::WouldBlock.into())
            })
            .unwrap();
            assert_eq!(
                route("-4", V4_PROBE).as_deref(),
                (!killswitch).then_some("wan0")
            );
            assert_eq!(route("-6", V6_PROBE), None);

            k.call("ip", &["link", "add", "awg0", "type", "dummy"])
                .unwrap();
            k.call("ip", &["link", "set", "awg0", "up"]).unwrap();
            k.call(
                "ip",
                &[
                    "-6",
                    "addr",
                    "add",
                    "fd00:91::2/128",
                    "dev",
                    "awg0",
                    "nodad",
                ],
            )
            .unwrap();
            operate(&db, &run, Operation::Refresh, |cfg, iface| {
                assert_eq!(iface, "awg0");
                full_reserve_peer(cfg, iface)
            })
            .unwrap();
            assert_eq!(route("-4", V4_PROBE).as_deref(), Some("awg0"));
            assert_eq!(route("-6", V6_PROBE).as_deref(), Some("awg0"));
            operate(&db, &run, Operation::Teardown, full_reserve_peer).unwrap();
            k.call("ip", &["link", "set", "awg1", "up"]).unwrap();
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires the offline IPv4-only full reserve packet comparison guest"]
fn new_ipv4_only_bare_full_preserves_owned_ipv6_filter_until_selected_reserve_retires() {
    assert!(std::path::Path::new("/synthetic-guest").is_file());
    let parent = std::env::var("N2S_PARENT_NET").unwrap();
    assert_ne!(
        std::fs::read_link("/proc/self/ns/net").unwrap().to_str(),
        Some(parent.as_str())
    );
    let killswitch = std::env::var("N2S_FULL_KILLSWITCH").unwrap() == "1";
    let server = std::env::var("N2S_FULL_RETIRE").unwrap() == "disable";
    let run = nfqws2_router_command::System;
    let k = kernel(&run);
    let (tmp, db) = with_full_reserve();
    configure_reserve_retirement(&db, killswitch);
    let boot = boot_id(&kernel(&run)).unwrap();
    let live = |cfg: &Value, iface: &str| {
        let mut sample = fresh_full_peer(cfg, iface, &boot)?;
        sample.ipv6_reachable = false;
        sample.allowed = vec!["0.0.0.0/0".into()];
        sample.active_replacement_peer.as_mut().unwrap().allowed = sample.allowed.clone();
        Ok(sample)
    };
    let foreign = |operation| {
        k.call(
            "ip6tables",
            &[
                "-w",
                "-t",
                "filter",
                operation,
                "FORWARD",
                "-d",
                "2001:db8:95:abcd::4",
                "-m",
                "comment",
                "--comment",
                "qa-independent-ipv6",
                "-j",
                "ACCEPT",
            ],
        )
        .unwrap();
    };
    foreign("-A");
    let target6 = "2001:db8:95:ff::72";
    let target4 = "203.0.113.72";
    let packet_went_out = |family: &str, iface: &str, address: &str| {
        let shield = if family == "-6" {
            "ip6tables"
        } else {
            "iptables"
        };
        let counter_rule = |operation| {
            k.call(
                shield,
                &[
                    "-w",
                    "-t",
                    "mangle",
                    operation,
                    "POSTROUTING",
                    "-o",
                    iface,
                    "-d",
                    address,
                    "-j",
                    "RETURN",
                ],
            )
            .unwrap()
        };
        counter_rule("-A");
        let _ = k.call(
            "ip",
            &[
                "netns", "exec", "qalan", "ping", family, "-c", "1", "-W", "1", address,
            ],
        );
        let counters = k
            .call(
                shield,
                &["-w", "-t", "mangle", "-L", "POSTROUTING", "-n", "-v", "-x"],
            )
            .unwrap();
        let matched = counters.lines().find_map(|line| {
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            (fields.len() >= 9
                && fields[2] == "RETURN"
                && fields[6] == iface
                && fields[8].contains(address))
            .then(|| fields[0].parse::<u64>().unwrap())
        });
        counter_rule("-D");
        matched.unwrap() > 0
    };
    let inspect = |stage: &str| {
        let v6_wan = packet_went_out("-6", "wan0", target6);
        let v6_local_to_wan = k
            .call("ip", &["-6", "route", "get", target6])
            .is_ok_and(|route| route.contains("dev wan0"));
        assert!(
            v6_local_to_wan,
            "{stage}: legacy FORWARD filter affected router-local IPv6"
        );
        assert!(!k
            .call("ip", &["-6", "rule", "show"])
            .unwrap()
            .contains("17842"));
        foreign("-C");
        eprintln!("RUST_IPV4_ONLY_PHASE {stage} v6_wan={v6_wan}");
        v6_wan
    };
    assert!(inspect("before-apply"));
    operate(&db, &run, Operation::Apply, live).unwrap();
    assert!(!inspect("after-apply"));
    operate(&db, &run, Operation::Commit, live).unwrap();
    assert!(!inspect("after-commit"));
    let committed = Journal::read(&db).unwrap().committed;
    assert!(committed.go_ipv4);
    assert_eq!(committed.go_multi_v6_reject.as_deref(), Some("wan0"));
    assert!(packet_went_out("-4", "awg0", target4));
    k.call("ip", &["link", "del", "awg0"]).unwrap();
    let reserve = |cfg: &Value, iface: &str| {
        if iface == "awg0" {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        live(cfg, iface)
    };
    operate(&db, &run, Operation::Refresh, reserve).unwrap();
    assert!(packet_went_out("-4", "awg1", target4));
    assert!(!inspect("reserve-active"));
    active_reserve(&db);
    let before = nfqws2_awg_profile::read(&db).unwrap();
    let journal = Journal::read(&db).unwrap();
    assert_eq!(
        journal.installed.go_multi_v6_reject.as_deref(),
        Some("wan0")
    );
    if !server && !killswitch {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct LoseFilterAck(AtomicBool);
        impl Runner for LoseFilterAck {
            fn run(&self, program: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
                let reply = nfqws2_router_command::System.run(program, args, deadline)?;
                if program == "ip6tables"
                    && args.contains(&"-D")
                    && args.contains(&"icmp6-adm-prohibited")
                    && !self.0.swap(true, Ordering::Relaxed)
                {
                    return Err(io::ErrorKind::BrokenPipe.into());
                }
                Ok(reply)
            }
        }
        let failed = LoseFilterAck(AtomicBool::new(false));
        assert!(
            retire_go_full_reserve(&db, &failed, &boot, server, || panic!(
                "the old primary is physically absent"
            ))
            .is_err()
        );
        assert!(failed.0.load(Ordering::Relaxed));
        assert_eq!(Journal::read(&db).unwrap(), journal);
        assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), before);
        assert!(packet_went_out("-4", "awg1", target4));
        assert!(!inspect("failed-retirement-compensated"));
    }
    retire_go_full_reserve(&db, &run, &boot, server, || {
        panic!("the old primary is physically absent")
    })
    .unwrap();
    assert_ne!(packet_went_out("-4", "wan0", target4), killswitch);
    assert!(inspect("reserve-retired"));
    let released = Journal::read(&db).unwrap();
    assert!(
        released.installed.go_multi_v6_reject.is_none()
            && released.committed.go_multi_v6_reject.is_none()
    );
    assert_eq!(released.committed.prefixes, journal.committed.prefixes);
    let after = nfqws2_awg_profile::read(&db).unwrap();
    assert_eq!(after["servers"][0], before["servers"][0]);
    assert_eq!(after["servers"][1]["config"]["enabled"], !server);
    assert_eq!(after["servers"][1]["config"]["client"]["enabled"], false);
    operate(&db, &run, Operation::Recover, reserve).unwrap();
    assert!(inspect("recover"));
    operate(&db, &run, Operation::Teardown, live).unwrap();
    foreign("-C");
    foreign("-D");
    drop(tmp);
    eprintln!("RUST_IPV4_ONLY_RESERVE_ORACLE_COMPLETE");
}
