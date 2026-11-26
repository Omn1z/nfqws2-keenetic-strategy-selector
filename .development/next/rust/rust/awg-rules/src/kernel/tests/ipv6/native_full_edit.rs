use super::*;
use nfqws2_awg_profile::{
    RoutedEndpointEdit, RoutedEndpointLaunch, RoutedMtuChange, RoutedMtuPeer,
};
use std::net::SocketAddr;

fn full_fixture(db: &Store, endpoint: &str, mtu: u16, shared: bool) {
    nfqws2_awg_profile::edit_document(db, |doc| {
        doc["routing"] = json!({"mode":"full","killswitch":true});
        let cfg = &mut doc["servers"][0]["config"];
        cfg["routing"] = json!({"mode":"full"});
        cfg["install"] = json!("imported");
        cfg["mtu"] = json!(mtu);
        cfg["endpoint"] = json!(endpoint);
        cfg["client"]["rust_managed"] = json!(true);
        if shared {
            cfg["client"]["endpoint_backups"] = json!(["198.51.100.10:8443"]);
        }
        Ok(())
    })
    .unwrap();
}

fn edit_change(db: &Store, before: &str, after: &str, mtu: u16) -> RoutedMtuChange {
    let confirmed = Journal::read(db).unwrap().committed;
    RoutedMtuChange {
        id: confirmed.targets["awg0"].id.clone(),
        iface: "awg0".into(),
        revision: confirmed.revision,
        before: mtu,
        after: mtu,
        legacy_mtu_before_recorded: false,
        nested_mtu_before_recorded: false,
        native_mtu_endpoint: None,
        implicit_before_mtu: None,
        nested_outer: None,
        nested_endpoint: None,
        legacy_predecessor: None,
        endpoint_edit: Some(RoutedEndpointEdit {
            before: before.into(),
            after: after.into(),
            previous_reserve: None,
            resolved_before: vec![],
            resolved_after: vec![],
        }),
    }
}

fn stage(db: &Store, change: &RoutedMtuChange, endpoint: &str) {
    nfqws2_awg_profile::edit_document(db, |doc| {
        let row = &mut doc["servers"][0];
        row["config"]["endpoint"] = json!(endpoint);
        if change.before != change.after {
            let forward = endpoint == change.endpoint_edit.as_ref().unwrap().after;
            row["config"]["mtu"] = json!(if forward { change.after } else { change.before });
        }
        row["rust_pending_routed_mtu"] = json!(change);
        Ok(())
    })
    .unwrap();
}

fn at_endpoint(endpoint: &str) -> impl FnMut(&Value, &str) -> io::Result<LivePeer> + '_ {
    move |cfg, iface| {
        Ok(LivePeer {
            endpoint: endpoint.parse().unwrap(),
            ..dual_peer(cfg, iface)?
        })
    }
}

fn enter_legacy_forward_reject(db: &Store, router: &dyn Runner, endpoint: &str, now: u64) {
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(db, router, op, now, at_endpoint(endpoint)).unwrap();
    }
    // The installed native receipt is our fixture predecessor. Recover an
    // independently confirmed Rust-owned snapshot of the old Go layout.
    let mut j = Journal::read(db).unwrap();
    let legacy = &mut j.committed;
    legacy.go_ipv4 = true;
    legacy.legacy_probe = true;
    legacy.legacy_full = Some(plan::LegacyFull::ForwardReject {
        wan: "wan0".into(),
        ipv6_endpoint: false,
    });
    legacy.prefixes.remove(&Family::V6.any());
    db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, &j, RECEIPT_LIMIT))
        .unwrap();
    operate_at(db, router, Operation::Recover, now, |cfg, iface| {
        let mut live = at_endpoint(endpoint)(cfg, iface)?;
        live.ipv6_reachable = false;
        Ok(live)
    })
    .unwrap();
    let j = Journal::read(db).unwrap();
    assert_eq!(j.installed.legacy_full, j.committed.legacy_full);
    assert_eq!(j.installed.probe_iface(), Some("awg0"));
}

fn enter_legacy_dual(db: &Store, router: &dyn Runner, endpoint: &str, now: u64) {
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(db, router, op, now, at_endpoint(endpoint)).unwrap();
    }
    let mut j = Journal::read(db).unwrap();
    j.committed.legacy_full = Some(plan::LegacyFull::Dual);
    j.committed.legacy_probe = true;
    db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, &j, RECEIPT_LIMIT))
        .unwrap();
    operate_at(db, router, Operation::Recover, now, at_endpoint(endpoint)).unwrap();
    let j = Journal::read(db).unwrap();
    assert_eq!(j.installed.legacy_full, Some(plan::LegacyFull::Dual));
    assert_eq!(j.installed.probe_iface(), Some("awg0"));
}

fn with_probe(
    endpoint: &str,
    outcome: Option<bool>,
) -> impl FnMut(&Value, &str) -> io::Result<LivePeer> + '_ {
    move |cfg, iface| Ok(at_endpoint(endpoint)(cfg, iface)?.with_fresh_bound_ipv6_probe(outcome))
}

#[test]
fn routed_legacy_dual_uses_only_bound_probe_then_settles_both_outcomes() {
    const OLD: &str = "198.51.100.10:443";
    const NEW: &str = "198.51.100.30:8443";
    for success in [false, true] {
        let (_temp, db, _) = setup();
        let router = Dual::default();
        let wan = ["wan0".into()];
        let now = nfqws2_awg_profile::now();
        full_fixture(&db, OLD, 1420, false);
        router.v4.0.lock().unwrap().mtu.insert("awg0".into(), 1420);
        enter_legacy_dual(&db, &router, OLD, now);
        let edit = edit_change(&db, OLD, NEW, 1420);
        router.v6.0.lock().unwrap().foreign_route =
            "default via fe80::1 dev wan1 table main".into();
        assert!(validate_endpoint_edit_launch(&db, &router, &edit, &wan).is_err());
        router.v6.0.lock().unwrap().foreign_route.clear();
        assert_eq!(
            validate_endpoint_edit_launch(&db, &router, &edit, &wan).unwrap(),
            RoutedEndpointLaunch::Primary
        );
        stage(&db, &edit, NEW);
        prepare_mtu_edit_with_wan(&db, &router, &edit, &wan).unwrap();
        assert!(legacy_dual_probe_target(&db, &router).unwrap().is_none());
        let v6 = || {
            router
                .v6
                .0
                .lock()
                .unwrap()
                .forward("fd02::5", "2620:fe::fe")
                .to_owned()
        };
        assert_eq!(v6(), "unreachable");
        operate_with_redirect_and_mtu(
            &db,
            &router,
            Operation::Recover,
            None,
            None,
            with_probe(NEW, Some(true)),
            proved,
        )
        .unwrap();
        // A witness supplied before the owned bound path could exist cannot settle.
        assert!(pending_mtu_edit(&db).unwrap());
        assert_eq!(v6(), "unreachable");
        let j = Journal::read(&db).unwrap();
        assert_eq!(j.installed.full_endpoints.as_ref().unwrap().len(), 2);
        assert_eq!(j.committed.full_endpoints.as_ref().unwrap().len(), 1);
        assert_eq!(j.installed.probe_iface(), Some("awg0"));
        assert_eq!(
            legacy_dual_probe_target(&db, &router).unwrap(),
            Some(("awg0".into(), NEW.parse().unwrap()))
        );
        router.v4.0.lock().unwrap().boot = "34343434-3434-3434-3434-343434343434".into();
        assert!(legacy_dual_probe_target(&db, &router).unwrap().is_none());
        router.v4.0.lock().unwrap().boot = BOOT.into();
        operate_with_redirect_and_mtu(
            &db,
            &router,
            Operation::Recover,
            None,
            None,
            with_probe(NEW, None),
            proved,
        )
        .unwrap();
        assert!(pending_mtu_edit(&db).unwrap());
        assert_eq!(v6(), "unreachable");
        if !success {
            router.v6.0.lock().unwrap().foreign_route =
                "default via fe80::1 dev wan1 table main".into();
            assert!(operate_with_redirect_and_mtu(
                &db,
                &router,
                Operation::Recover,
                None,
                None,
                with_probe(NEW, Some(false)),
                proved
            )
            .is_err());
            assert_eq!(v6(), "unreachable");
            router.v6.0.lock().unwrap().foreign_route.clear();
        }
        let late = json!(mtu_edit::read(&db).unwrap().unwrap());
        let finish = || {
            operate_with_redirect_and_mtu(
                &db,
                &router,
                Operation::Recover,
                None,
                None,
                with_probe(NEW, Some(success)),
                proved,
            )
        };
        finish().unwrap();
        let done = Journal::read(&db).unwrap();
        assert_eq!(done.committed.legacy_full, Some(plan::LegacyFull::Dual));
        assert_eq!(
            done.installed.legacy_full,
            Some(if success {
                plan::LegacyFull::Dual
            } else {
                plan::LegacyFull::ForwardReject {
                    wan: "wan0".into(),
                    ipv6_endpoint: false,
                }
            })
        );
        assert_eq!(done.installed.full_endpoints, done.committed.full_endpoints);
        assert_eq!(done.installed.full_endpoints.as_ref().unwrap().len(), 1);
        assert!(!pending_mtu_edit(&db).unwrap());
        if !success {
            kernel(&router).verify_ipv6_reject(&done.installed).unwrap();
            // Crash after the FIB acknowledged the downgrade and before row cleanup.
            stage(&db, &edit, NEW);
            db.transaction(|tx| tx.save_runtime_bounded("awg-routed-mtu.json", &late, 4096))
                .unwrap();
            finish().unwrap();
            assert_eq!(v6(), "unreachable");
            assert!(pending_mtu_edit(&db).unwrap());
            finish().unwrap();
            assert!(!pending_mtu_edit(&db).unwrap());
            let next = edit_change(&db, NEW, OLD, 1420);
            assert_eq!(
                validate_endpoint_edit_launch(&db, &router, &next, &wan).unwrap(),
                RoutedEndpointLaunch::Primary
            );
            stage(&db, &next, OLD);
            prepare_mtu_edit_with_wan(&db, &router, &next, &wan).unwrap();
            assert_eq!(v6(), "unreachable");
            for _ in 0..2 {
                operate_with_redirect_and_mtu(
                    &db,
                    &router,
                    Operation::Recover,
                    None,
                    None,
                    with_probe(OLD, Some(false)),
                    proved,
                )
                .unwrap();
            }
            assert!(!pending_mtu_edit(&db).unwrap());
            operate_at(
                &db,
                &router,
                Operation::LegacyWatchdog,
                now,
                at_endpoint(OLD),
            )
            .unwrap();
        }
        assert_eq!(v6(), "awg0");
    }
}

fn proved(change: &RoutedMtuChange, live: &LivePeer) -> io::Result<Option<RoutedMtuPeer>> {
    Ok(Some(RoutedMtuPeer {
        iface: change.iface.clone(),
        outer_id: String::new(),
        outer_iface: String::new(),
        endpoint: live.endpoint,
        effective_mtu: change.after,
        socket_mark: live.socket_mark,
    }))
}

#[test]
fn routed_native_full_numeric_endpoint_stages_and_retires_only_unshared_throws() {
    const OLD: &str = "198.51.100.10:443";
    const NEW: &str = "198.51.100.30:8443";
    let (_temp, db, _) = setup();
    let router = Dual::default();
    let wan = ["wan0".into()];
    let now = nfqws2_awg_profile::now();
    full_fixture(&db, OLD, 1420, false);
    router.v4.0.lock().unwrap().mtu.insert("awg0".into(), 1420);
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &router, op, now, at_endpoint(OLD)).unwrap();
    }
    let change = edit_change(&db, OLD, NEW, 1420);
    for family in [&router.v4, &router.v6] {
        let mut f = family.0.lock().unwrap();
        f.watch_flow = Some(("192.168.1.5", "9.9.9.9"));
    }
    let snapshot = |committed: bool| {
        let j = Journal::read(&db).unwrap();
        (if committed { j.committed } else { j.installed })
            .full_endpoints
            .clone()
            .unwrap()
    };
    let old_ip = OLD.parse::<SocketAddr>().unwrap().ip();
    let new_ip = NEW.parse::<SocketAddr>().unwrap().ip();
    let only_old = [old_ip].into();
    let both = [old_ip, new_ip].into();
    let only_new = [new_ip].into();
    assert_eq!(snapshot(true), only_old);
    assert!(validate_endpoint_edit_launch(&db, &router, &change, &["other-wan".into()]).is_err());
    router.v4.0.lock().unwrap().foreign_rule = "55: from all to 198.51.100.0/24 lookup 500".into();
    assert!(validate_endpoint_edit_launch(&db, &router, &change, &wan).is_err());
    router.v4.0.lock().unwrap().foreign_rule.clear();
    assert_eq!(
        validate_endpoint_edit_launch(&db, &router, &change, &wan).unwrap(),
        RoutedEndpointLaunch::Primary
    );

    stage(&db, &change, NEW);
    // Recovery before prepare cannot materialize a throw from the raw config.
    operate_with_redirect_and_mtu(
        &db,
        &router,
        Operation::Recover,
        None,
        None,
        at_endpoint(NEW),
        |_, _| panic!("no full replacement was authorized before the first park"),
    )
    .unwrap();
    assert_eq!(snapshot(false), only_old);
    assert!(prepare_mtu_edit_with_wan(&db, &router, &change, &["other-wan".into()]).is_err());
    assert_eq!(snapshot(false), only_old);
    prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
    assert_eq!(snapshot(false), both);
    assert_eq!(snapshot(true), only_old);
    let mut interrupted = Journal::read(&db).unwrap();
    interrupted.preparing.push(interrupted.installed.clone());
    db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, &interrupted, RECEIPT_LIMIT))
        .unwrap();
    operate_with_redirect_and_mtu(
        &db,
        &router,
        Operation::Recover,
        None,
        None,
        at_endpoint(OLD),
        |_, _| panic!("previous endpoint cannot authenticate the replacement"),
    )
    .unwrap();
    assert_eq!(snapshot(false), both);
    assert_eq!(snapshot(true), only_old);
    assert_eq!(
        router
            .v4
            .0
            .lock()
            .unwrap()
            .forward("192.168.1.5", "9.9.9.9"),
        "unreachable"
    );

    validate_endpoint_edit(&db, &router, &change, &wan).unwrap();
    stage(&db, &change, OLD);
    prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
    operate_with_redirect_and_mtu(
        &db,
        &router,
        Operation::Recover,
        None,
        None,
        at_endpoint(OLD),
        proved,
    )
    .unwrap();
    assert_eq!(snapshot(false), only_old);
    assert_eq!(snapshot(true), only_old);
    assert!(!pending_mtu_edit(&db).unwrap());

    stage(&db, &change, NEW);
    prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
    operate_with_redirect_and_mtu(
        &db,
        &router,
        Operation::Recover,
        None,
        None,
        at_endpoint(NEW),
        proved,
    )
    .unwrap();
    assert_eq!(snapshot(false), only_new);
    assert_eq!(snapshot(true), only_new);
    assert_eq!(
        Journal::read(&db).unwrap().committed.revision,
        change.revision
    );
    assert!(!pending_mtu_edit(&db).unwrap());
    assert!(!router.v4.0.lock().unwrap().leaked);

    let back = edit_change(&db, NEW, OLD, 1420);
    stage(&db, &back, OLD);
    prepare_mtu_edit_with_wan(&db, &router, &back, &wan).unwrap();
    operate_with_redirect_and_mtu(
        &db,
        &router,
        Operation::Recover,
        None,
        None,
        at_endpoint(OLD),
        proved,
    )
    .unwrap();
    full_fixture(&db, OLD, 1420, true);
    stage(&db, &change, NEW);
    prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
    operate_with_redirect_and_mtu(
        &db,
        &router,
        Operation::Recover,
        None,
        None,
        at_endpoint(NEW),
        proved,
    )
    .unwrap();
    assert_eq!(snapshot(false), both);
    assert_eq!(snapshot(true), both);
}

#[test]
fn routed_legacy_full_ipv4_endpoint_keeps_the_exact_forward_reject_until_ack() {
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Wan<'a> {
        router: &'a Dual,
        default_drift: AtomicBool,
        endpoint_drift: AtomicBool,
    }
    impl Runner for Wan<'_> {
        fn run(&self, cmd: &str, args: &[&str], end: Instant) -> io::Result<String> {
            if cmd == "ip"
                && args == ["-o", "-N", "-4", "route", "show", "table", "main"]
                && self.default_drift.load(Ordering::Relaxed)
            {
                return Ok("default via 192.0.2.1 dev wrong-wan".into());
            }
            if cmd == "ip"
                && matches!(args, ["-4", "route", "get", "198.51.100.30", ..])
                && self.endpoint_drift.load(Ordering::Relaxed)
            {
                return Ok("198.51.100.30 via 192.0.2.1 dev wrong-wan".into());
            }
            self.router.run(cmd, args, end)
        }
    }
    const OLD: &str = "198.51.100.10:443";
    const NEW: &str = "198.51.100.30:8443";
    let (_temp, db, _) = setup();
    let router = Dual::default();
    let run = Wan {
        router: &router,
        default_drift: AtomicBool::new(false),
        endpoint_drift: AtomicBool::new(false),
    };
    let wan = ["wan0".into()];
    let now = nfqws2_awg_profile::now();
    full_fixture(&db, OLD, 1420, false);
    router.v4.0.lock().unwrap().mtu.insert("awg0".into(), 1420);
    enter_legacy_forward_reject(&db, &run, OLD, now);
    let edit = edit_change(&db, OLD, NEW, 1420);
    let premature_family = edit_change(&db, OLD, "[2001:db8:f00::2]:443", 1420);
    assert!(validate_endpoint_edit_launch(&db, &run, &premature_family, &wan).is_err());
    run.default_drift.store(true, Ordering::Relaxed);
    assert!(validate_endpoint_edit_launch(&db, &run, &edit, &wan).is_err());
    run.default_drift.store(false, Ordering::Relaxed);
    run.endpoint_drift.store(true, Ordering::Relaxed);
    assert!(
        validate_endpoint_edit_launch(&db, &run, &edit, &["wan0".into(), "wrong-wan".into()])
            .is_err()
    );
    run.endpoint_drift.store(false, Ordering::Relaxed);
    assert_eq!(
        validate_endpoint_edit_launch(&db, &run, &edit, &wan).unwrap(),
        RoutedEndpointLaunch::Primary
    );

    let original = Journal::read(&db).unwrap().committed;
    let check = |active: bool| {
        let j = Journal::read(&db).unwrap();
        assert_eq!(j.installed.legacy_full, original.legacy_full);
        assert_eq!(j.committed.legacy_full, original.legacy_full);
        assert_eq!(j.installed.probe_iface(), active.then_some("awg0"));
        kernel(&run).verify_ipv6_reject(&j.installed).unwrap();
    };
    stage(&db, &edit, NEW);
    prepare_mtu_edit_with_wan(&db, &run, &edit, &wan).unwrap();
    check(false);
    run.default_drift.store(true, Ordering::Relaxed);
    assert!(operate_with_redirect_and_mtu(
        &db,
        &run,
        Operation::Recover,
        None,
        None,
        at_endpoint(NEW),
        proved
    )
    .is_err());
    check(false);
    run.default_drift.store(false, Ordering::Relaxed);
    operate_with_redirect_and_mtu(
        &db,
        &run,
        Operation::Recover,
        None,
        None,
        at_endpoint(NEW),
        |_, _| Ok(None),
    )
    .unwrap();
    check(false);
    validate_endpoint_edit(&db, &run, &edit, &wan).unwrap();
    stage(&db, &edit, OLD);
    prepare_mtu_edit_with_wan(&db, &run, &edit, &wan).unwrap();
    operate_with_redirect_and_mtu(
        &db,
        &run,
        Operation::Recover,
        None,
        None,
        at_endpoint(OLD),
        proved,
    )
    .unwrap();
    check(true);
    assert_eq!(
        Journal::read(&db).unwrap().committed.full_endpoints,
        original.full_endpoints
    );

    stage(&db, &edit, NEW);
    prepare_mtu_edit_with_wan(&db, &run, &edit, &wan).unwrap();
    run.endpoint_drift.store(true, Ordering::Relaxed);
    operate_with_redirect_and_mtu(
        &db,
        &run,
        Operation::Recover,
        None,
        None,
        at_endpoint(NEW),
        proved,
    )
    .unwrap();
    check(false);
    run.endpoint_drift.store(false, Ordering::Relaxed);
    // The sample advertises IPv6 reachability, which cannot change the saved
    // legacy IPv6 guard while this transaction owns the target.
    operate_with_redirect_and_mtu(
        &db,
        &run,
        Operation::Recover,
        None,
        None,
        at_endpoint(NEW),
        proved,
    )
    .unwrap();
    check(true);
    assert!(!pending_mtu_edit(&db).unwrap());
    operate_at(&db, &run, Operation::LegacyWatchdog, now, at_endpoint(NEW)).unwrap();
    assert_eq!(
        Journal::read(&db).unwrap().installed.legacy_full,
        Some(plan::LegacyFull::Dual)
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn routed_native_full_endpoint_on_isolated_linux_tables() {
    for (kind, var) in [("net", "N2S_PARENT_NET"), ("mnt", "N2S_PARENT_MNT")] {
        let parent = std::env::var(var).unwrap();
        assert!(parent.starts_with(&format!("{kind}:[")));
        let current = std::fs::read_link(format!("/proc/self/ns/{kind}")).unwrap();
        assert_ne!(current.to_str().unwrap(), parent);
    }
    let router = nfqws2_router_command::System;
    let k = kernel(&router);
    let wan = ["wan0".into()];
    let actual_mtu = || {
        k.call("cat", &["/sys/class/net/awg0/mtu"])
            .unwrap()
            .trim()
            .parse::<u16>()
            .unwrap()
    };
    let set_mtu = |mtu: u16| {
        k.call(
            "ip",
            &["link", "set", "dev", "awg0", "mtu", &mtu.to_string()],
        )
        .unwrap();
    };
    let mtu = actual_mtu();
    let disposition = |af: &str, ip: &str| {
        k.call("ip", &[af, "route", "get", ip])
            .ok()
            .and_then(|path| {
                let mut words = path.split_ascii_whitespace();
                words.find(|word| *word == "dev")?;
                words.next().map(str::to_owned)
            })
    };
    for (af, before, after, payload, target_mtu, starts_v6_fenced) in [
        (
            "-4",
            "203.0.113.10:443",
            "203.0.113.30:8443",
            "9.9.9.9",
            mtu,
            false,
        ),
        (
            "-6",
            "[2001:db8:f00::1]:443",
            "[2001:db8:f00::2]:8443",
            "2620:fe::fe",
            mtu,
            false,
        ),
        (
            "-4",
            "203.0.113.10:443",
            "203.0.113.30:8443",
            "9.9.9.9",
            1340,
            false,
        ),
        (
            "-4",
            "203.0.113.10:443",
            "203.0.113.30:8443",
            "9.9.9.9",
            1330,
            true,
        ),
        (
            "-4",
            "203.0.113.10:443",
            "203.0.113.30:8443",
            "9.9.9.9",
            mtu,
            true,
        ),
    ] {
        let (_dir, db, _) = setup();
        full_fixture(&db, before, mtu, false);
        let now = nfqws2_awg_profile::now();
        for op in [Operation::Apply, Operation::Commit] {
            operate_at(&db, &router, op, now, |cfg, iface| {
                let mut peer = at_endpoint(before)(cfg, iface)?;
                if starts_v6_fenced {
                    peer.ipv6_reachable = false;
                    peer.allowed.retain(|prefix| prefix != "::/0");
                }
                Ok(peer)
            })
            .unwrap();
        }
        if starts_v6_fenced {
            assert_eq!(disposition("-6", "2620:fe::fe"), None);
        }
        let old_ip = before.parse::<SocketAddr>().unwrap().ip().to_string();
        let new_ip = after.parse::<SocketAddr>().unwrap().ip().to_string();
        assert_eq!(disposition(af, &old_ip).as_deref(), Some("wan0"));
        assert_eq!(disposition(af, &new_ip).as_deref(), Some("awg0"));
        let mut change = edit_change(&db, before, after, mtu);
        change.after = target_mtu;
        assert_eq!(
            validate_endpoint_edit_launch(&db, &router, &change, &wan).unwrap(),
            RoutedEndpointLaunch::Primary
        );
        stage(&db, &change, after);
        prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
        assert_eq!(disposition(af, &old_ip).as_deref(), Some("wan0"));
        assert_eq!(disposition(af, &new_ip).as_deref(), Some("wan0"));
        assert_eq!(disposition(af, payload), None);
        let recover = |observed| {
            operate_with_redirect_and_mtu(
                &db,
                &router,
                Operation::Recover,
                None,
                None,
                at_endpoint(observed),
                |change, live| {
                    let mut peer = proved(change, live)?.unwrap();
                    peer.effective_mtu = actual_mtu();
                    Ok(Some(peer))
                },
            )
            .unwrap();
        };
        if target_mtu != mtu || starts_v6_fenced {
            let waiting = || {
                assert_eq!(disposition(af, payload), None);
                assert_eq!(disposition("-6", "2620:fe::fe"), None);
                assert!(pending_mtu_edit(&db).unwrap());
            };
            if target_mtu != mtu {
                recover(after);
                waiting();
                set_mtu(target_mtu);
            }
            recover(before);
            waiting();
        }
        recover(after);
        assert_eq!(disposition(af, &old_ip).as_deref(), Some("awg0"));
        assert_eq!(disposition(af, &new_ip).as_deref(), Some("wan0"));
        assert_eq!(disposition(af, payload).as_deref(), Some("awg0"));
        if starts_v6_fenced {
            assert!(!pending_mtu_edit(&db).unwrap());
            assert_eq!(disposition("-6", "2620:fe::fe"), None);
            operate_at(&db, &router, Operation::Refresh, now, at_endpoint(after)).unwrap();
            assert_eq!(disposition("-6", "2620:fe::fe").as_deref(), Some("awg0"));
        }
        if target_mtu != mtu {
            assert_eq!(disposition("-6", "2620:fe::fe").as_deref(), Some("awg0"));
            let expected_mss = format!("--set-mss {}", target_mtu - 40);
            for firewall in ["iptables", "ip6tables"] {
                let mss = k
                    .call(firewall, &["-w", "-t", "mangle", "-S", "FORWARD"])
                    .unwrap();
                assert!(mss
                    .lines()
                    .any(|line| line.contains("awg0") && line.ends_with(&expected_mss)));
            }
            assert!(!pending_mtu_edit(&db).unwrap());
        }
        operate_at(&db, &router, Operation::Teardown, now, at_endpoint(after)).unwrap();
        if target_mtu != mtu {
            set_mtu(mtu);
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn native_full_fixed_mtu_checks_real_families_and_supports_pending_undo() {
    use super::combined_edit::require_isolated_namespaces;
    require_isolated_namespaces();
    fixed_mtu_on_isolated_linux(false);
    fixed_mtu_on_isolated_linux(true);
}

#[cfg(target_os = "linux")]
fn fixed_mtu_on_isolated_linux(undo: bool) {
    use super::combined_edit::{physical_mtu, set_physical_mtu};
    use nfqws2_awg_profile::DIRECT_SOCKET_MARK;
    const ENDPOINT: &str = "203.0.113.10:443";
    const OTHER_PORT: &str = "203.0.113.10:8443";
    const NEXT_MTU: u16 = 1320;
    let router = nfqws2_router_command::System;
    let k = kernel(&router);
    let (_dir, db, _) = setup();
    let wan = ["wan0".into()];
    let now = nfqws2_awg_profile::now();
    let old_mtu = physical_mtu(&k);
    full_fixture(&db, ENDPOINT, old_mtu, false);
    let sample = |endpoint: &'static str, v6_ready: bool| {
        move |cfg: &Value, iface: &str| {
            let mut peer = at_endpoint(endpoint)(cfg, iface)?;
            peer.socket_mark = DIRECT_SOCKET_MARK;
            if !v6_ready {
                peer.ipv6_reachable = false;
                peer.allowed.retain(|prefix| prefix != "::/0");
            }
            Ok(peer)
        }
    };
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &router, op, now, sample(ENDPOINT, !undo)).unwrap();
    }
    let original = Journal::read(&db).unwrap().committed;
    let mut change = edit_change(&db, ENDPOINT, ENDPOINT, old_mtu);
    change.endpoint_edit = None;
    change.native_mtu_endpoint = Some(ENDPOINT.parse().unwrap());
    change.after = NEXT_MTU;
    let path = |family, ip| {
        let row = k.call("ip", &[family, "route", "get", ip]).ok()?;
        let mut words = row.split_ascii_whitespace();
        words.find(|word| *word == "dev")?;
        words.next().map(str::to_owned)
    };
    let v4 = || path("-4", "9.9.9.9");
    let v6 = || path("-6", "2620:fe::fe");
    assert_eq!(v4().as_deref(), Some("awg0"));
    assert_eq!(v6().as_deref(), (!undo).then_some("awg0"));
    let check_launch = || {
        assert_eq!(
            validate_endpoint_edit_launch(&db, &router, &change, &wan).unwrap(),
            RoutedEndpointLaunch::Primary
        );
    };
    let prepare = |mtu: u16| {
        nfqws2_awg_profile::edit_document(&db, |doc| {
            let row = &mut doc["servers"][0];
            row["config"]["mtu"] = json!(mtu);
            row["rust_pending_routed_mtu"] = json!(change);
            Ok(())
        })
        .unwrap();
        prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
    };
    let check_throws = || {
        let journal = Journal::read(&db).unwrap();
        assert_eq!(journal.committed.full_endpoints, original.full_endpoints);
        assert_eq!(journal.installed.full_endpoints, original.full_endpoints);
        assert_eq!(journal.committed.revision, original.revision);
        assert_eq!(path("-4", "203.0.113.10").as_deref(), Some("wan0"));
    };
    let waiting = || {
        assert_eq!(v4(), None);
        assert_eq!(v6(), None);
        assert!(pending_mtu_edit(&db).unwrap());
        check_throws();
    };
    let recover = |endpoint| {
        operate_with_redirect_and_mtu(
            &db,
            &router,
            Operation::Recover,
            None,
            None,
            sample(endpoint, true),
            |edit, live| {
                let mut peer = proved(edit, live)?.unwrap();
                peer.effective_mtu = physical_mtu(&k);
                Ok(Some(peer))
            },
        )
        .unwrap();
    };
    check_launch();
    prepare(NEXT_MTU);
    waiting();
    let wanted = if undo {
        set_physical_mtu(&k, NEXT_MTU);
        check_launch();
        prepare(old_mtu);
        old_mtu
    } else {
        NEXT_MTU
    };
    recover(ENDPOINT);
    waiting();
    set_physical_mtu(&k, wanted);
    recover(OTHER_PORT);
    waiting();
    recover(ENDPOINT);
    check_throws();
    assert!(!pending_mtu_edit(&db).unwrap());
    assert_eq!(v4().as_deref(), Some("awg0"));
    assert_eq!(v6().as_deref(), (!undo).then_some("awg0"));
    if undo {
        operate_at(
            &db,
            &router,
            Operation::Refresh,
            now,
            sample(ENDPOINT, true),
        )
        .unwrap();
        assert_eq!(v6().as_deref(), Some("awg0"));
    }
    let mss = format!("--set-mss {}", wanted - 40);
    for firewall in ["iptables", "ip6tables"] {
        let rules = k
            .call(firewall, &["-w", "-t", "mangle", "-S", "FORWARD"])
            .unwrap();
        assert!(rules
            .lines()
            .any(|line| line.contains("awg0") && line.ends_with(&mss)));
    }
    operate_at(
        &db,
        &router,
        Operation::Teardown,
        now,
        sample(ENDPOINT, true),
    )
    .unwrap();
    set_physical_mtu(&k, old_mtu);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn native_permanent_full_fixed_mtu_checks_real_dual_guards() {
    use super::combined_edit::{physical_mtu, require_isolated_namespaces, set_physical_mtu};
    use nfqws2_awg_profile::{RoutedImplicitMtu, RoutedMtuOuter};
    use sha2::{Digest, Sha256};
    use std::cell::Cell;

    const ENDPOINT: &str = "[2001:db8:f00::12]:443";
    const IP: &str = "2001:db8:f00::12";
    const BEFORE: u16 = 1420;
    const AFTER: u16 = 1360;
    const MARK: u32 = 0xa0000000;
    require_isolated_namespaces();
    let router = nfqws2_router_command::System;
    let k = kernel(&router);
    let wan = ["wan0".into()];
    let physical_before = physical_mtu(&k);
    let outer_before = k.call("cat", &["/sys/class/net/awg2/mtu"]).unwrap();
    let motion = |op| {
        let mut commands = [
            vec!["-6", "addr", op, "fd13::99/128", "dev", "awg2"],
            vec![
                "-6",
                "route",
                op,
                "2001:db8:f00::12/128",
                "dev",
                "awg2",
                "src",
                "fd13::99",
                "table",
                "828",
                "proto",
                "99",
            ],
            vec![
                "-6",
                "rule",
                op,
                "pref",
                "60",
                "fwmark",
                "0xa0000000",
                "lookup",
                "828",
            ],
            vec![
                "-6",
                "rule",
                op,
                "pref",
                "61",
                "fwmark",
                "0xa0000000",
                "prohibit",
            ],
        ];
        if op == "del" {
            commands.reverse();
        }
        for args in commands {
            k.call("ip", &args).unwrap();
        }
    };
    motion("add");
    let path = |family, ip| {
        let row = k.call("ip", &[family, "route", "get", ip]).ok()?;
        let mut words = row.split_ascii_whitespace();
        words.find(|word| *word == "dev")?;
        words.next().map(str::to_owned)
    };
    let v4 = || path("-4", "9.9.9.9");
    let v6 = || path("-6", "2620:fe::fe");
    let marked = || {
        let route = k
            .call("ip", &["-6", "route", "get", IP, "mark", "0xa0000000"])
            .unwrap();
        assert!(route.contains("dev awg2") && route.contains("src fd13::99"));
    };
    for actual in [1280, 1270] {
        let (_dir, db, _) = setup();
        full_fixture(&db, ENDPOINT, 0, false);
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["routing"]["killswitch"] = json!(false);
            let rows = doc["servers"].as_array_mut().unwrap();
            let mut outer = rows[0].clone();
            outer["id"] = json!("outer");
            outer["config"]["client_iface"] = json!("awg2");
            outer["config"]["endpoint"] = json!("198.51.100.88:443");
            rows.push(outer);
            let inner = &mut rows[0]["config"];
            inner["routing"]["mtu"] = json!(BEFORE);
            inner["client"]["double_tunnel_mode"] = json!("permanent");
            inner["client"]["double_tunnel_id"] = json!("outer");
            Ok(())
        })
        .unwrap();
        k.call(
            "ip",
            &[
                "link",
                "set",
                "dev",
                "awg2",
                "mtu",
                &(actual + 80).to_string(),
            ],
        )
        .unwrap();
        set_physical_mtu(&k, actual);
        let endpoint = Cell::new(ENDPOINT.parse().unwrap());
        // At 1280, reproduce a previously fenced IPv6 path. At 1270,
        // an otherwise ready peer must still fail the physical MTU limit.
        let v6_reachable = Cell::new(actual < 1280);
        let live = |cfg: &Value, iface: &str| {
            let mut base = dual_peer(cfg, iface)?;
            if !v6_reachable.get() {
                base.allowed.retain(|prefix| prefix != "::/0");
            }
            Ok(LivePeer {
                endpoint: endpoint.get(),
                socket_mark: MARK,
                nested_mtu: Some(physical_mtu(&k)),
                ipv6_reachable: v6_reachable.get(),
                ..base
            })
        };
        let now = nfqws2_awg_profile::now();
        for op in [Operation::Apply, Operation::Commit] {
            operate_at(&db, &router, op, now, live).unwrap();
        }
        let original = Journal::read(&db).unwrap().committed;
        assert!(original.killswitch);
        assert_eq!(v4().as_deref(), Some("awg0"));
        assert_eq!(v6(), None);
        let change = RoutedMtuChange {
            endpoint_edit: None,
            after: AFTER,
            nested_mtu_before_recorded: true,
            implicit_before_mtu: Some(RoutedImplicitMtu::Zero),
            nested_outer: Some(RoutedMtuOuter {
                id: "outer".into(),
                iface: "awg2".into(),
                peer_key_sha256: Sha256::digest("01".repeat(32)).into(),
            }),
            nested_endpoint: Some(ENDPOINT.into()),
            ..edit_change(&db, ENDPOINT, ENDPOINT, BEFORE)
        };
        let launch = || {
            assert_eq!(
                validate_endpoint_edit_launch(&db, &router, &change, &wan).unwrap(),
                RoutedEndpointLaunch::Primary
            );
        };
        let stage = |mtu| {
            nfqws2_awg_profile::edit_document(&db, |doc| {
                let row = &mut doc["servers"][0];
                row["config"]["mtu"] = json!(mtu);
                row["rust_pending_routed_mtu"] = json!(change);
                Ok(())
            })
            .unwrap();
            prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
        };
        let check_throws = || {
            let current = Journal::read(&db).unwrap();
            assert_eq!(current.installed.full_endpoints, original.full_endpoints);
            assert_eq!(current.committed.full_endpoints, original.full_endpoints);
            marked();
        };
        let pending = || {
            assert!(pending_mtu_edit(&db).unwrap());
            assert_eq!((v4(), v6()), (None, None));
            check_throws();
        };
        let recover = |owned: bool| {
            operate_with_redirect_and_mtu(
                &db,
                &router,
                Operation::Recover,
                None,
                None,
                live,
                |_, _| {
                    Ok(owned.then(|| RoutedMtuPeer {
                        iface: "awg0".into(),
                        outer_id: "outer".into(),
                        outer_iface: "awg2".into(),
                        endpoint: endpoint.get(),
                        effective_mtu: physical_mtu(&k),
                        socket_mark: MARK,
                    }))
                },
            )
            .unwrap();
        };
        launch();
        stage(AFTER);
        pending();
        operate_at(&db, &router, Operation::Suspend, now, live).unwrap();
        recover(false);
        pending();
        launch();
        stage(0);
        v6_reachable.set(true);
        endpoint.set("[2001:db8:f00::12]:8443".parse().unwrap());
        recover(true);
        pending();
        endpoint.set(ENDPOINT.parse().unwrap());
        recover(true);
        assert!(!pending_mtu_edit(&db).unwrap());
        assert_eq!(v4().as_deref(), Some("awg0"));
        assert_eq!(v6(), None);
        assert_eq!(
            nfqws2_awg_profile::read(&db).unwrap()["servers"][0]["config"]["mtu"],
            0
        );
        check_throws();
        operate_at(&db, &router, Operation::Refresh, now, live).unwrap();
        assert_eq!(v6().as_deref(), (actual >= 1280).then_some("awg0"));
        operate_at(&db, &router, Operation::Teardown, now, live).unwrap();
    }
    motion("del");
    set_physical_mtu(&k, physical_before);
    k.call(
        "ip",
        &["link", "set", "dev", "awg2", "mtu", outer_before.trim()],
    )
    .unwrap();
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn routed_legacy_full_endpoint_on_isolated_linux_tables() {
    for (kind, var) in [("net", "N2S_PARENT_NET"), ("mnt", "N2S_PARENT_MNT")] {
        let parent = std::env::var(var).unwrap();
        assert!(parent.starts_with(&format!("{kind}:[")));
        assert_ne!(
            std::fs::read_link(format!("/proc/self/ns/{kind}"))
                .unwrap()
                .to_str(),
            Some(parent.as_str())
        );
    }
    const OLD: &str = "203.0.113.10:443";
    const NEW: &str = "203.0.113.30:8443";
    let (_dir, db, _) = setup();
    let router = nfqws2_router_command::System;
    let k = kernel(&router);
    let mtu = k
        .call("cat", &["/sys/class/net/awg0/mtu"])
        .unwrap()
        .trim()
        .parse::<u16>()
        .unwrap();
    let wan = ["wan0".into()];
    let now = nfqws2_awg_profile::now();
    full_fixture(&db, OLD, mtu, false);
    enter_legacy_forward_reject(&db, &router, OLD, now);
    let edit = edit_change(&db, OLD, NEW, mtu);
    let reject = || {
        k.call("ip6tables", &["-w", "-t", "filter", "-S", "FORWARD"])
            .unwrap()
    };
    let before = reject();
    assert!(before.contains("-o wan0") && before.contains("-j REJECT"));
    assert_eq!(
        validate_endpoint_edit_launch(&db, &router, &edit, &wan).unwrap(),
        RoutedEndpointLaunch::Primary
    );
    stage(&db, &edit, NEW);
    prepare_mtu_edit_with_wan(&db, &router, &edit, &wan).unwrap();
    assert_eq!(reject(), before);
    assert!(k.call("ip", &["-4", "route", "get", "9.9.9.9"]).is_err());
    for endpoint in ["203.0.113.10", "203.0.113.30"] {
        let route = k.call("ip", &["-4", "route", "get", endpoint]).unwrap();
        assert!(route.contains("dev wan0"));
    }
    operate_with_redirect_and_mtu(
        &db,
        &router,
        Operation::Recover,
        None,
        None,
        at_endpoint(NEW),
        proved,
    )
    .unwrap();
    assert!(k
        .call("ip", &["-4", "route", "get", "203.0.113.10"])
        .unwrap()
        .contains("dev awg0"));
    assert!(k
        .call("ip", &["-4", "route", "get", "203.0.113.30"])
        .unwrap()
        .contains("dev wan0"));
    assert_eq!(reject(), before);
    assert!(!pending_mtu_edit(&db).unwrap());
    operate_at(&db, &router, Operation::Teardown, now, at_endpoint(NEW)).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn routed_legacy_dual_endpoint_probe_is_bound_and_gates_ipv6_fib() {
    for (kind, var) in [("net", "N2S_PARENT_NET"), ("mnt", "N2S_PARENT_MNT")] {
        let parent = std::env::var(var).unwrap();
        assert!(parent.starts_with(&format!("{kind}:[")));
        assert_ne!(
            std::fs::read_link(format!("/proc/self/ns/{kind}"))
                .unwrap()
                .to_str(),
            Some(parent.as_str())
        );
    }
    const OLD: &str = "203.0.113.10:443";
    const NEW: &str = "203.0.113.30:8443";
    for success in [false, true] {
        let (_dir, db, _) = setup();
        let router = nfqws2_router_command::System;
        let k = kernel(&router);
        let mtu = k
            .call("cat", &["/sys/class/net/awg0/mtu"])
            .unwrap()
            .trim()
            .parse::<u16>()
            .unwrap();
        let wan = ["wan0".into()];
        let now = nfqws2_awg_profile::now();
        full_fixture(&db, OLD, mtu, false);
        enter_legacy_dual(&db, &router, OLD, now);
        let edit = edit_change(&db, OLD, NEW, mtu);
        validate_endpoint_edit_launch(&db, &router, &edit, &wan).unwrap();
        stage(&db, &edit, NEW);
        prepare_mtu_edit_with_wan(&db, &router, &edit, &wan).unwrap();
        assert!(legacy_dual_probe_target(&db, &router).unwrap().is_none());
        operate_with_redirect_and_mtu(
            &db,
            &router,
            Operation::Recover,
            None,
            None,
            with_probe(NEW, None),
            proved,
        )
        .unwrap();
        assert!(k
            .call("ip", &["-4", "route", "get", "9.9.9.9"])
            .unwrap()
            .contains("dev awg0"));
        assert!(k
            .call("ip", &["-6", "route", "get", "2620:fe::fe"])
            .is_err());
        assert!(k
            .call("ip", &["-6", "route", "get", "2606:4700:4700::1111"])
            .is_err());
        assert!(k
            .call(
                "ip",
                &["-6", "route", "get", "2606:4700:4700::1111", "oif", "awg0"]
            )
            .unwrap()
            .contains("dev awg0"));
        assert_eq!(
            legacy_dual_probe_target(&db, &router).unwrap(),
            Some(("awg0".into(), NEW.parse().unwrap()))
        );
        operate_with_redirect_and_mtu(
            &db,
            &router,
            Operation::Recover,
            None,
            None,
            with_probe(NEW, Some(success)),
            proved,
        )
        .unwrap();
        assert!(!pending_mtu_edit(&db).unwrap());
        assert!(k
            .call("ip", &["-4", "route", "get", "203.0.113.10"])
            .unwrap()
            .contains("dev awg0"));
        let j = Journal::read(&db).unwrap();
        if success {
            assert!(k
                .call("ip", &["-6", "route", "get", "2620:fe::fe"])
                .unwrap()
                .contains("dev awg0"));
        } else {
            k.verify_ipv6_reject(&j.installed).unwrap();
        }
        assert_eq!(j.committed.legacy_full, Some(plan::LegacyFull::Dual));
        operate_at(&db, &router, Operation::Teardown, now, at_endpoint(NEW)).unwrap();
    }
}
