use super::*;
use nfqws2_awg_profile::{
    RoutedEndpointEdit, RoutedEndpointLaunch, RoutedImplicitMtu, RoutedMtuChange, RoutedMtuOuter,
    RoutedMtuPeer,
};
use std::cell::Cell;

#[derive(Clone, Copy, PartialEq, Eq)]
enum CandidateWan {
    Reachable,
    DifferentMarkedDevice,
    Missing,
    LostAfterParking,
}

struct CrossFamilyWan<'a> {
    kernel: &'a Dual,
    candidate: Mutex<CandidateWan>,
}

impl Runner for CrossFamilyWan<'_> {
    fn run(&self, program: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
        if let ("ip", ["-6", "route", "get", address @ "2001:db8:68::10", mark @ ..]) =
            (program, args)
        {
            if matches!(mark, [] | ["mark", "0x20000000"]) {
                let wanted = *self.candidate.lock().unwrap();
                let parked = || {
                    self.kernel
                        .v4
                        .0
                        .lock()
                        .unwrap()
                        .forward("192.168.1.7", "203.0.113.10")
                        == "blackhole"
                };
                if wanted == CandidateWan::Missing
                    || wanted == CandidateWan::LostAfterParking && parked()
                {
                    return Err(io::ErrorKind::NotConnected.into());
                }
                let device = if wanted == CandidateWan::DifferentMarkedDevice && !mark.is_empty() {
                    "wan0"
                } else {
                    "wan6"
                };
                return Ok(format!("{address} dev {device}"));
            }
        }
        self.kernel.run(program, args, deadline)
    }
}

#[test]
fn direct_cross_family_pair_can_undo_after_the_new_wan_disappears() {
    use nfqws2_awg_profile::DIRECT_SOCKET_MARK;

    const OLD: &str = "198.51.100.10:443";
    const NEW: &str = "[2001:db8:68::10]:51820";
    const V4_PAYLOAD: &str = "203.0.113.10";
    const V6_PAYLOAD: &str = "2001:db8:69::10";
    const OTHER: &str = "203.0.113.11";
    const LEARNED: &str = "2001:db8:69::11";
    const SOURCE: &str = "192.168.1.7";
    let wan = ["wan0".into(), "wan6".into()];
    for failure in [
        CandidateWan::Reachable,
        CandidateWan::Missing,
        CandidateWan::LostAfterParking,
    ] {
        let (dir, db, _) = setup();
        let router = Dual::default();
        let run = CrossFamilyWan {
            kernel: &router,
            candidate: Mutex::new(CandidateWan::Reachable),
        };
        let set_candidate = |value| *run.candidate.lock().unwrap() = value;
        scoped_policy(&db);
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["routing"] = json!({"mode":"zones","domain_source":"dnsproxy","killswitch":true});
            let rows = doc["servers"].as_array_mut().unwrap();
            for row in &mut *rows {
                row["config"]["peers"] = json!([{
                    "id":"router","is_router":true,"address":"10.21.0.2/32,fd21::2/128",
                    "allowed_ips":"0.0.0.0/0,::/0"
                }]);
            }
            let cfg = &mut rows[0]["config"];
            cfg["install"] = json!("imported");
            cfg["endpoint"] = json!(OLD);
            cfg["mtu"] = json!(1420);
            cfg["client"]["rust_managed"] = json!(true);
            cfg["routing"]["zones"] = json!([{
                "order":1,"enabled":true,"domains":["*.corp.example"],
                "ips":[V4_PAYLOAD,V6_PAYLOAD]
            }]);
            rows[1]["config"]["endpoint"] = json!("198.51.100.89:443");
            rows[1]["config"]["routing"]["zones"] =
                json!([{"order":2,"enabled":true,"ips":[OTHER]}]);
            Ok(())
        })
        .unwrap();
        let sample = |endpoint: &str| {
            let endpoint = endpoint.parse().unwrap();
            move |cfg: &Value, iface: &str| {
                let mut peer = dual_peer(cfg, iface)?;
                if iface == "awg0" {
                    peer.endpoint = endpoint;
                    peer.socket_mark = DIRECT_SOCKET_MARK;
                } else {
                    peer.endpoint = "198.51.100.89:443".parse().unwrap();
                }
                Ok(peer)
            }
        };
        let now = nfqws2_awg_profile::now();
        for op in [Operation::Apply, Operation::Commit] {
            operate_at(&db, &run, op, now, sample(OLD)).unwrap();
        }
        learn_answer(
            &db,
            &run,
            Answer {
                revision: 1,
                zone: 0,
                addresses: &[LEARNED.parse().unwrap()],
                ttl: 600,
                qtype: 28,
            },
            sample(OLD),
            || Ok(()),
        )
        .unwrap();
        let baseline = Journal::read(&db).unwrap().committed;
        let paths = |expected| {
            let v4 = router.v4.0.lock().unwrap();
            assert_eq!(v4.forward(SOURCE, V4_PAYLOAD), expected);
            assert_eq!(v4.forward(SOURCE, OTHER), "awg1");
            let v6 = router.v6.0.lock().unwrap();
            for destination in [V6_PAYLOAD, LEARNED] {
                assert_eq!(v6.forward("fd21::42", destination), expected);
            }
        };
        paths("awg0");
        let change = RoutedMtuChange {
            id: baseline.targets["awg0"].id.clone(),
            iface: "awg0".into(),
            revision: baseline.revision,
            before: 1420,
            after: 1340,
            native_mtu_endpoint: None,
            endpoint_edit: Some(RoutedEndpointEdit {
                before: OLD.into(),
                after: NEW.into(),
                previous_reserve: None,
                resolved_before: vec![],
                resolved_after: vec![],
            }),
            legacy_predecessor: None,
            legacy_mtu_before_recorded: false,
            nested_mtu_before_recorded: false,
            implicit_before_mtu: None,
            nested_outer: None,
            nested_endpoint: None,
        };
        let mut overlap = change.clone();
        overlap.endpoint_edit.as_mut().unwrap().after = format!("[{LEARNED}]:51820");
        assert!(validate_endpoint_edit_launch(&db, &run, &overlap, &wan).is_err());
        set_candidate(CandidateWan::DifferentMarkedDevice);
        assert!(validate_endpoint_edit_launch(&db, &run, &change, &wan).is_err());
        paths("awg0");
        assert!(!pending_mtu_edit(&db).unwrap());
        set_candidate(CandidateWan::Reachable);
        assert_eq!(
            validate_endpoint_edit_launch(&db, &run, &change, &wan).unwrap(),
            RoutedEndpointLaunch::Primary
        );

        let stage = |db: &Store, endpoint: &str, mtu, launched| {
            nfqws2_awg_profile::edit_document(db, |doc| {
                let row = &mut doc["servers"][0];
                row["config"]["endpoint"] = json!(endpoint);
                row["config"]["mtu"] = json!(mtu);
                row["rust_pending_routed_mtu"] = json!(change);
                if launched {
                    row.as_object_mut()
                        .unwrap()
                        .remove("rust_pending_client_profile");
                } else {
                    row["rust_pending_client_profile"] = json!(vec![7_u8; 32]);
                }
                Ok(())
            })
            .unwrap();
        };
        stage(&db, NEW, change.after, false);
        set_candidate(failure);
        let make_ready = prepare_mtu_edit_with_wan(&db, &run, &change, &wan);
        if failure == CandidateWan::Reachable {
            make_ready.unwrap();
        } else {
            assert_eq!(make_ready.unwrap_err().kind(), io::ErrorKind::NotConnected);
        }
        let before_park = failure == CandidateWan::Missing;
        paths(if before_park { "awg0" } else { "blackhole" });
        assert_eq!(pending_mtu_edit(&db).unwrap(), !before_park);
        let db = Store::open(dir.path()).unwrap();
        let (selected, retired, wanted) = if failure == CandidateWan::Reachable {
            (NEW, OLD, change.after)
        } else {
            set_candidate(CandidateWan::Missing);
            validate_endpoint_edit(&db, &run, &change, &wan).unwrap();
            stage(&db, OLD, change.before, false);
            prepare_mtu_edit_with_wan(&db, &run, &change, &wan).unwrap();
            (OLD, NEW, change.before)
        };
        paths("blackhole");
        let recover = |observed: &str, mtu, owned: bool| {
            operate_with_redirect_and_mtu(
                &db,
                &run,
                Operation::Recover,
                None,
                None,
                sample(observed),
                |saved, sample| {
                    assert_eq!(saved, &change);
                    Ok(owned.then(|| RoutedMtuPeer {
                        iface: "awg0".into(),
                        outer_id: String::new(),
                        outer_iface: String::new(),
                        endpoint: sample.endpoint,
                        effective_mtu: mtu,
                        socket_mark: sample.socket_mark,
                    }))
                },
            )
        };
        recover(selected, wanted, true).unwrap();
        paths("blackhole");
        stage(&db, selected, wanted, true);
        let _ = recover(retired, wanted, true);
        paths("blackhole");
        router
            .v4
            .0
            .lock()
            .unwrap()
            .mtu
            .insert("awg0".into(), wanted - 1);
        recover(selected, wanted, false).unwrap();
        recover(selected, wanted, true).unwrap();
        paths("blackhole");
        router
            .v4
            .0
            .lock()
            .unwrap()
            .mtu
            .insert("awg0".into(), wanted);
        recover(selected, wanted, true).unwrap();
        paths("awg0");
        let committed = Journal::read(&db).unwrap().committed;
        assert_eq!(committed.revision, baseline.revision);
        assert_eq!(committed.targets["awg0"].mtu, wanted);
        assert_eq!(committed.targets["awg1"], baseline.targets["awg1"]);
        assert_eq!(committed.mss["awg0"], wanted - 40);
        assert_eq!(
            committed.learned.as_ref().unwrap().members,
            baseline.learned.as_ref().unwrap().members
        );
        assert_eq!(
            committed.learned == baseline.learned,
            failure != CandidateWan::Reachable
        );
        assert!(!pending_mtu_edit(&db).unwrap());
    }
}

#[test]
fn permanent_single_full_fixed_mtu_keeps_existing_throws_and_both_default_fences() {
    const PRIMARY: &str = "[2001:db8:f00::1]:51820";
    const RESERVE: &str = "198.51.100.77:51820";
    const OUTER: &str = "198.51.100.88:443";
    const MARK: u32 = 0xa0000000;
    for (before_effective, after_effective, undo) in [(1290, 1270, false), (1270, 1290, true)] {
        let (dir, db, _) = setup();
        let router = Dual::default();
        *router.nested_outer.lock().unwrap() = "awg2".into();
        let now = nfqws2_awg_profile::now();
        let wan = ["wan0".into()];
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["routing"] = json!({"mode":"full","killswitch":false});
            let rows = doc["servers"].as_array_mut().unwrap();
            let mut outer = rows[0].clone();
            outer["id"] = json!("outer");
            outer["config"]["client_iface"] = json!("awg2");
            outer["config"]["endpoint"] = json!(OUTER);
            outer["config"]["routing"] = json!({"mode":"off"});
            rows.push(outer);
            let cfg = &mut rows[0]["config"];
            cfg["routing"] = json!({"mode":"full","mtu":1420});
            cfg["install"] = json!("imported");
            cfg["endpoint"] = json!(PRIMARY);
            cfg["mtu"] = json!(0);
            cfg["client"]["rust_managed"] = json!(true);
            cfg["client"]["double_tunnel_mode"] = json!("permanent");
            cfg["client"]["double_tunnel_id"] = json!("outer");
            cfg["client"]["endpoint_backups"] = json!([RESERVE]);
            Ok(())
        })
        .unwrap();
        let effective = Cell::new(before_effective);
        let sample = |cfg: &Value, iface: &str| {
            if iface == "awg2" {
                return Ok(LivePeer {
                    endpoint: OUTER.parse().unwrap(),
                    ..dual_peer(cfg, "awg1")?
                });
            }
            let mut peer = dual_peer(cfg, iface)?;
            peer.endpoint = PRIMARY.parse().unwrap();
            peer.socket_mark = MARK;
            peer.nested_mtu = Some(effective.get());
            Ok(peer)
        };
        let paths = |v4, v6| {
            assert_eq!(
                router
                    .v4
                    .0
                    .lock()
                    .unwrap()
                    .forward("192.168.1.5", "9.9.9.9"),
                v4
            );
            assert_eq!(
                router
                    .v6
                    .0
                    .lock()
                    .unwrap()
                    .forward("fd02::5", "2620:fe::fe"),
                v6
            );
        };
        for op in [Operation::Apply, Operation::Commit] {
            operate_at(&db, &router, op, now, sample).unwrap();
        }
        let baseline = Journal::read(&db).unwrap();
        assert!(baseline.committed.killswitch && baseline.committed.reserves.is_empty());
        paths("awg0", if undo { "unreachable" } else { "awg0" });
        let change = RoutedMtuChange {
            id: baseline.committed.targets["awg0"].id.clone(),
            iface: "awg0".into(),
            revision: baseline.committed.revision,
            before: 1420,
            after: 1360,
            native_mtu_endpoint: None,
            endpoint_edit: None,
            legacy_predecessor: None,
            legacy_mtu_before_recorded: false,
            nested_mtu_before_recorded: true,
            implicit_before_mtu: Some(RoutedImplicitMtu::Zero),
            nested_outer: Some(RoutedMtuOuter {
                id: "outer".into(),
                iface: "awg2".into(),
                peer_key_sha256: [1; 32],
            }),
            nested_endpoint: Some(PRIMARY.into()),
        };
        let mut reserve = change.clone();
        reserve.nested_endpoint = Some(RESERVE.into());
        assert_eq!(
            validate_endpoint_edit_launch(&db, &router, &reserve, &wan)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        let mut stale = baseline.clone();
        stale
            .installed
            .full_endpoints
            .as_mut()
            .unwrap()
            .remove(&"198.51.100.88".parse().unwrap());
        db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, &stale, RECEIPT_LIMIT))
            .unwrap();
        assert_ne!(
            validate_endpoint_edit_launch(&db, &router, &change, &wan)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, &baseline, RECEIPT_LIMIT))
            .unwrap();
        assert_eq!(
            validate_endpoint_edit_launch(&db, &router, &change, &wan).unwrap(),
            RoutedEndpointLaunch::Primary
        );

        let stage = |raw_mtu| {
            nfqws2_awg_profile::edit_document(&db, |doc| {
                let row = &mut doc["servers"][0];
                row["config"]["mtu"] = json!(raw_mtu);
                row["rust_pending_routed_mtu"] = json!(change);
                Ok(())
            })
            .unwrap();
        };
        stage(change.after);
        prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
        paths("unreachable", "unreachable");
        assert_eq!(
            Journal::read(&db).unwrap().installed.full_endpoints,
            baseline.installed.full_endpoints
        );
        if undo {
            validate_endpoint_edit(&db, &router, &change, &wan).unwrap();
            stage(0);
            prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
        }
        operate_at(&db, &router, Operation::Suspend, now, sample).unwrap();
        let db = Store::open(dir.path()).unwrap();
        let recover = |owned: bool| {
            operate_with_redirect_and_mtu(
                &db,
                &router,
                Operation::Recover,
                None,
                None,
                sample,
                |saved, live| {
                    assert_eq!(saved, &change);
                    Ok(owned.then(|| RoutedMtuPeer {
                        iface: "awg0".into(),
                        outer_id: "outer".into(),
                        outer_iface: "awg2".into(),
                        endpoint: live.endpoint,
                        effective_mtu: effective.get(),
                        socket_mark: MARK,
                    }))
                },
            )
        };
        recover(false).unwrap();
        paths("unreachable", "unreachable");
        assert!(pending_mtu_edit(&db).unwrap());
        effective.set(after_effective);
        let sysfs_mtu = |mtu| router.v4.0.lock().unwrap().mtu.insert("awg0".into(), mtu);
        sysfs_mtu(after_effective - 1);
        recover(true).unwrap();
        paths("unreachable", "unreachable");
        sysfs_mtu(after_effective);
        recover(true).unwrap();
        paths("awg0", "unreachable");
        let settled = Journal::read(&db).unwrap();
        assert_eq!(
            settled.installed.full_endpoints,
            baseline.installed.full_endpoints
        );
        assert_eq!(
            settled.committed.full_endpoints,
            baseline.committed.full_endpoints
        );
        assert_eq!(settled.installed.mss["awg0"], after_effective - 40);
        assert_eq!(
            settled.committed.targets["awg0"].mtu,
            if undo { change.before } else { change.after }
        );
        assert_eq!(settled.committed.revision, change.revision);
        assert!(!pending_mtu_edit(&db).unwrap());
        operate_at(&db, &router, Operation::Refresh, now, sample).unwrap();
        paths("awg0", if undo { "awg0" } else { "unreachable" });
    }
}

#[test]
fn provisional_native_mtu_reserve_keeps_the_unrecorded_full_tunnel_path() {
    const ENDPOINT: &str = "198.51.100.10:443";
    const RESERVE: &str = "198.51.100.20:8443";
    let (_dir, db, _) = setup();
    let router = Dual::default();
    let now = nfqws2_awg_profile::now();
    let wan = ["wan0".into()];
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"] = json!({"mode":"full","killswitch":true});
        let cfg = &mut doc["servers"][0]["config"];
        cfg["routing"] = json!({"mode":"full"});
        cfg["install"] = json!("imported");
        cfg["endpoint"] = json!(ENDPOINT);
        cfg["mtu"] = json!(1420);
        cfg["client"]["rust_managed"] = json!(true);
        cfg["client"]["endpoint_backups"] = json!([RESERVE]);
        Ok(())
    })
    .unwrap();
    let live = |cfg: &Value, iface: &str| {
        Ok(LivePeer {
            endpoint: ENDPOINT.parse().unwrap(),
            ..dual_peer(cfg, iface)?
        })
    };
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &router, op, now, live).unwrap();
    }
    let stable = Journal::read(&db).unwrap();
    let mut change = RoutedMtuChange {
        id: stable.committed.targets["awg0"].id.clone(),
        iface: "awg0".into(),
        revision: stable.committed.revision,
        before: 1420,
        after: 1380,
        nested_outer: None,
        nested_endpoint: None,
        legacy_predecessor: None,
        endpoint_edit: None,
        implicit_before_mtu: None,
        legacy_mtu_before_recorded: false,
        nested_mtu_before_recorded: false,
        native_mtu_endpoint: Some(RESERVE.parse().unwrap()),
    };
    assert_eq!(
        validate_endpoint_edit_launch(&db, &router, &change, &wan)
            .unwrap_err()
            .kind(),
        io::ErrorKind::Unsupported
    );
    let mut stale = stable.clone();
    stale.installed.revision += 1;
    db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, &stale, RECEIPT_LIMIT))
        .unwrap();
    assert_ne!(
        validate_endpoint_edit_launch(&db, &router, &change, &wan)
            .unwrap_err()
            .kind(),
        io::ErrorKind::Unsupported
    );
    db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, &stable, RECEIPT_LIMIT))
        .unwrap();
    assert!(!pending_mtu_edit(&db).unwrap());
    change.native_mtu_endpoint = None;
    assert_eq!(
        validate_endpoint_edit_launch(&db, &router, &change, &wan).unwrap(),
        RoutedEndpointLaunch::Primary
    );
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let row = &mut doc["servers"][0];
        row["config"]["mtu"] = json!(change.after);
        row["rust_pending_routed_mtu"] = json!(change);
        Ok(())
    })
    .unwrap();
    prepare_mtu_edit(&db, &router, &change).unwrap();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]
            .as_object_mut()
            .unwrap()
            .remove("rust_pending_routed_mtu");
        Ok(())
    })
    .unwrap();
    router
        .v4
        .0
        .lock()
        .unwrap()
        .mtu
        .insert("awg0".into(), change.after);
    operate_at(&db, &router, Operation::Recover, now, live).unwrap();
    assert_eq!(
        Journal::read(&db).unwrap().committed.targets["awg0"].mtu,
        change.after
    );
    assert!(!pending_mtu_edit(&db).unwrap());
}

#[test]
fn combined_native_full_supports_a_shared_ip_and_an_exact_implicit_mtu_undo() {
    const BEFORE: &str = "198.51.100.10:443";
    const AFTER: &str = "198.51.100.10:51820";
    let (dir, db, _) = setup();
    let router = Dual::default();
    let wan = ["wan0".into()];
    let now = nfqws2_awg_profile::now();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"] = json!({"mode":"full","killswitch":true});
        let cfg = &mut doc["servers"][0]["config"];
        cfg["routing"] = json!({"mode":"full","mtu":1420});
        cfg["install"] = json!("imported");
        cfg["endpoint"] = json!(BEFORE);
        cfg["client"]["rust_managed"] = json!(true);
        cfg.as_object_mut().unwrap().remove("mtu");
        Ok(())
    })
    .unwrap();
    let live = |endpoint: &str, v6: bool| {
        let endpoint = endpoint.parse().unwrap();
        move |cfg: &Value, iface: &str| {
            let mut sampled = LivePeer {
                endpoint,
                ..dual_peer(cfg, iface)?
            };
            if !v6 {
                sampled.ipv6_reachable = false;
                sampled.allowed.retain(|prefix| prefix != "::/0");
            }
            Ok(sampled)
        }
    };
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &router, op, now, live(BEFORE, true)).unwrap();
    }
    let baseline = Journal::read(&db).unwrap().committed;
    assert_eq!(baseline.targets["awg0"].mtu, 1420);
    let change = RoutedMtuChange {
        id: baseline.targets["awg0"].id.clone(),
        iface: "awg0".into(),
        revision: baseline.revision,
        before: 1420,
        after: 1380,
        nested_outer: None,
        nested_endpoint: None,
        legacy_predecessor: None,
        native_mtu_endpoint: None,
        legacy_mtu_before_recorded: false,
        nested_mtu_before_recorded: false,
        implicit_before_mtu: Some(RoutedImplicitMtu::Missing),
        endpoint_edit: Some(RoutedEndpointEdit {
            before: BEFORE.into(),
            after: AFTER.into(),
            previous_reserve: None,
            resolved_before: vec![],
            resolved_after: vec![],
        }),
    };
    operate_at(&db, &router, Operation::Refresh, now, live(BEFORE, false)).unwrap();
    let fenced = Journal::read(&db).unwrap();
    assert!(fenced.installed.flows().any(|(s, primary)| {
        s.dest.family() == Family::V6 && fenced.installed.effective(s, primary).is_none()
    }));
    assert_eq!(
        validate_endpoint_edit_launch(&db, &router, &change, &wan).unwrap(),
        RoutedEndpointLaunch::Primary
    );
    assert!(!pending_mtu_edit(&db).unwrap());
    operate_at(&db, &router, Operation::Refresh, now, live(BEFORE, true)).unwrap();
    let stable = Journal::read(&db).unwrap();
    let mut legacy = stable.clone();
    for plan in [&mut legacy.committed, &mut legacy.installed] {
        plan.legacy_full = Some(plan::LegacyFull::Dual);
        plan.legacy_probe = true;
    }
    db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, &legacy, RECEIPT_LIMIT))
        .unwrap();
    assert!(validate_endpoint_edit_launch(&db, &router, &change, &wan).is_err());
    db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, &stable, RECEIPT_LIMIT))
        .unwrap();
    assert_eq!(
        validate_endpoint_edit_launch(&db, &router, &change, &wan).unwrap(),
        RoutedEndpointLaunch::Primary
    );

    let stage = |db: &Store, forward| {
        nfqws2_awg_profile::edit_document(db, |doc| {
            let row = &mut doc["servers"][0];
            change.rewrite_combined_endpoint_mtu(row, forward)?;
            row["rust_pending_routed_mtu"] = json!(change);
            Ok(())
        })
        .unwrap();
    };
    stage(&db, true);
    prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
    let db = Store::open(dir.path()).unwrap();
    let paths = |expected: &str| {
        assert_eq!(
            router
                .v4
                .0
                .lock()
                .unwrap()
                .forward("192.168.1.5", "9.9.9.9"),
            expected
        );
        assert_eq!(
            router
                .v6
                .0
                .lock()
                .unwrap()
                .forward("fd02::5", "2620:fe::fe"),
            expected
        );
    };
    let sysfs_mtu = |mtu| router.v4.0.lock().unwrap().mtu.insert("awg0".into(), mtu);
    let recover = |endpoint, effective, v6| {
        operate_with_redirect_and_mtu(
            &db,
            &router,
            Operation::Recover,
            None,
            None,
            live(endpoint, v6),
            |saved, observed| {
                assert_eq!(saved, &change);
                Ok(Some(RoutedMtuPeer {
                    iface: "awg0".into(),
                    outer_id: String::new(),
                    outer_iface: String::new(),
                    endpoint: observed.endpoint,
                    effective_mtu: effective,
                    socket_mark: observed.socket_mark,
                }))
            },
        )
    };
    paths("unreachable");
    assert_eq!(
        Journal::read(&db).unwrap().installed.full_endpoints,
        baseline.full_endpoints
    );
    sysfs_mtu(change.before);
    recover(AFTER, change.after, true).unwrap();
    paths("unreachable");
    sysfs_mtu(change.after);
    recover(BEFORE, change.after, true).unwrap();
    paths("unreachable");
    recover(AFTER, change.after, false).unwrap();
    assert!(pending_mtu_edit(&db).unwrap());
    paths("unreachable");
    let mut receipt = json!(mtu_edit::read(&db).unwrap().unwrap());
    recover(AFTER, change.after, true).unwrap();
    paths("awg0");
    let installed = Journal::read(&db).unwrap().installed;
    assert_eq!(installed.full_endpoints, baseline.full_endpoints);
    assert_eq!(installed.mss["awg0"], change.after - 40);
    for family in [&router.v4, &router.v6] {
        let state = family.0.lock().unwrap();
        let rules = &state.firewall["mangle"];
        assert_eq!(
            rules
                .iter()
                .filter(|rule| rule.contains("TCPMSS") && rule.contains("1340"))
                .count(),
            2
        );
    }
    assert!(!pending_mtu_edit(&db).unwrap());

    receipt["endpoint_committed"] = json!(true);
    db.transaction(|tx| tx.save_runtime_bounded("awg-routed-mtu.json", &receipt, 4096))
        .unwrap();
    stage(&db, true);
    validate_endpoint_edit(&db, &router, &change, &wan).unwrap();
    stage(&db, false);
    assert!(
        nfqws2_awg_profile::read(&db).unwrap()["servers"][0]["config"]
            .get("mtu")
            .is_none()
    );
    prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
    paths("unreachable");
    sysfs_mtu(change.before);
    recover(BEFORE, change.before, true).unwrap();
    paths("awg0");
    assert_eq!(Journal::read(&db).unwrap().committed, baseline);
    assert!(!pending_mtu_edit(&db).unwrap());
}

#[test]
fn combined_native_full_ipv4_ack_keeps_the_ipv6_fence_through_recovery() {
    native_full_ipv4_ack_keeps_the_ipv6_fence_through_recovery(true);
}

#[test]
fn endpoint_only_native_full_ipv4_ack_keeps_the_ipv6_fence_through_recovery() {
    native_full_ipv4_ack_keeps_the_ipv6_fence_through_recovery(false);
}

#[test]
fn fixed_native_full_mtu_preserves_exact_transport_and_prior_ipv6_fence() {
    const PRIMARY: &str = "198.51.100.10:443";
    const WRONG_PORT: &str = "198.51.100.10:51820";
    for initial_ipv6 in [true, false] {
        for inverse in [false, true] {
            let (dir, db, _) = setup();
            let router = Dual::default();
            let wan = ["wan0".into()];
            let now = nfqws2_awg_profile::now();
            nfqws2_awg_profile::edit_document(&db, |doc| {
                doc["routing"] = json!({"mode":"full","killswitch":true});
                let cfg = &mut doc["servers"][0]["config"];
                cfg["routing"] = json!({"mode":"full","mtu":1420});
                cfg["install"] = json!("imported");
                cfg["endpoint"] = json!(PRIMARY);
                cfg["mtu"] = json!(0);
                cfg["client"]["rust_managed"] = json!(true);
                Ok(())
            })
            .unwrap();
            let live = |endpoint: &str, ipv6| {
                let endpoint = endpoint.parse().unwrap();
                move |cfg: &Value, iface: &str| {
                    let mut sample = LivePeer {
                        endpoint,
                        ipv6_reachable: ipv6,
                        ..dual_peer(cfg, iface)?
                    };
                    if !ipv6 {
                        sample.allowed.retain(|net| net != "::/0");
                    }
                    Ok(sample)
                }
            };
            for op in [Operation::Apply, Operation::Commit] {
                operate_at(&db, &router, op, now, live(PRIMARY, initial_ipv6)).unwrap();
            }
            let baseline = Journal::read(&db).unwrap().committed;
            let change = RoutedMtuChange {
                id: baseline.targets["awg0"].id.clone(),
                iface: "awg0".into(),
                revision: baseline.revision,
                before: 1420,
                after: 1380,
                nested_outer: None,
                nested_endpoint: None,
                endpoint_edit: None,
                legacy_predecessor: None,
                native_mtu_endpoint: Some(PRIMARY.parse().unwrap()),
                legacy_mtu_before_recorded: false,
                nested_mtu_before_recorded: false,
                implicit_before_mtu: Some(RoutedImplicitMtu::Zero),
            };
            assert_eq!(
                validate_endpoint_edit_launch(&db, &router, &change, &wan).unwrap(),
                RoutedEndpointLaunch::Primary
            );
            let stage = |db: &Store, raw_mtu| {
                nfqws2_awg_profile::edit_document(db, |doc| {
                    let row = &mut doc["servers"][0];
                    row["config"]["mtu"] = json!(raw_mtu);
                    row["rust_pending_routed_mtu"] = json!(change);
                    Ok(())
                })
                .unwrap();
            };
            stage(&db, change.after);
            if !initial_ipv6 {
                operate_at(&db, &router, Operation::Suspend, now, live(PRIMARY, false)).unwrap();
                assert!(pending_mtu_edit(&db).unwrap());
            }
            let db = Store::open(dir.path()).unwrap();
            prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
            let mtu = if inverse {
                validate_endpoint_edit(&db, &router, &change, &wan).unwrap();
                stage(&db, 0);
                prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
                change.before
            } else {
                change.after
            };
            let paths = |v4, v6| {
                assert_eq!(
                    router
                        .v4
                        .0
                        .lock()
                        .unwrap()
                        .forward("192.168.1.5", "9.9.9.9"),
                    v4
                );
                assert_eq!(
                    router
                        .v6
                        .0
                        .lock()
                        .unwrap()
                        .forward("fd02::5", "2620:fe::fe"),
                    v6
                );
            };
            let recover = |endpoint| {
                operate_with_redirect_and_mtu(
                    &db,
                    &router,
                    Operation::Recover,
                    None,
                    None,
                    live(endpoint, true),
                    |saved, live| {
                        assert_eq!(saved, &change);
                        Ok(Some(RoutedMtuPeer {
                            iface: saved.iface.clone(),
                            outer_id: String::new(),
                            outer_iface: String::new(),
                            endpoint: live.endpoint,
                            effective_mtu: mtu,
                            socket_mark: live.socket_mark,
                        }))
                    },
                )
                .unwrap();
            };
            let measured = |mtu| router.v4.0.lock().unwrap().mtu.insert("awg0".into(), mtu);
            measured(if inverse { change.after } else { change.before });
            recover(PRIMARY);
            paths("unreachable", "unreachable");
            measured(mtu);
            recover(WRONG_PORT);
            paths("unreachable", "unreachable");
            assert!(pending_mtu_edit(&db).unwrap());
            recover(PRIMARY);
            paths("awg0", if initial_ipv6 { "awg0" } else { "unreachable" });
            let settled = Journal::read(&db).unwrap();
            assert_eq!(settled.committed.revision, baseline.revision);
            assert_eq!(settled.committed.targets["awg0"].mtu, mtu);
            assert_eq!(settled.installed.mss["awg0"], mtu - 40);
            assert_eq!(settled.installed.full_endpoints, baseline.full_endpoints);
            assert_eq!(settled.committed.full_endpoints, baseline.full_endpoints);
            assert!(!pending_mtu_edit(&db).unwrap());
            if !initial_ipv6 {
                operate_at(&db, &router, Operation::Refresh, now, live(PRIMARY, true)).unwrap();
                paths("awg0", "awg0");
            }
        }
    }
}

fn native_full_ipv4_ack_keeps_the_ipv6_fence_through_recovery(change_mtu: bool) {
    const OLD: &str = "198.51.100.10:443";
    const NEW: &str = "198.51.100.30:51820";
    const V4_PAYLOAD: &str = "9.9.9.9";
    const V6_PAYLOAD: &str = "2620:fe::fe";

    let live = |endpoint: &str, ipv6: bool| {
        let endpoint = endpoint.parse().unwrap();
        move |cfg: &Value, iface: &str| {
            let mut sampled = dual_peer(cfg, iface)?;
            sampled.endpoint = endpoint;
            sampled.ipv6_reachable = ipv6;
            if !ipv6 {
                sampled.allowed.retain(|net| net != "::/0");
            }
            Ok(sampled)
        }
    };
    for suspend_before_prepare in [false, true] {
        let (dir, db, _) = setup();
        let router = Dual::default();
        let wan = ["wan0".into()];
        let now = nfqws2_awg_profile::now();
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["routing"] = json!({"mode":"full","killswitch":false});
            let cfg = &mut doc["servers"][0]["config"];
            cfg["routing"] = json!({"mode":"full"});
            cfg["install"] = json!("imported");
            cfg["endpoint"] = json!(OLD);
            cfg["mtu"] = json!(1420);
            cfg["client"]["rust_managed"] = json!(true);
            Ok(())
        })
        .unwrap();
        for op in [Operation::Apply, Operation::Commit] {
            operate_at(&db, &router, op, now, live(OLD, false)).unwrap();
        }
        let paths = |v4: &str, v6: &str| {
            assert_eq!(
                router
                    .v4
                    .0
                    .lock()
                    .unwrap()
                    .forward("192.168.1.5", V4_PAYLOAD),
                v4
            );
            assert_eq!(
                router.v6.0.lock().unwrap().forward("fd02::5", V6_PAYLOAD),
                v6
            );
        };
        paths("awg0", "unreachable");
        assert_eq!(scheduled(&db).unwrap(), Schedule::Failover);
        let baseline = Journal::read(&db).unwrap().committed;
        let change = RoutedMtuChange {
            id: baseline.targets["awg0"].id.clone(),
            iface: "awg0".into(),
            revision: baseline.revision,
            before: 1420,
            after: if change_mtu { 1380 } else { 1420 },
            nested_outer: None,
            nested_endpoint: None,
            endpoint_edit: Some(RoutedEndpointEdit {
                before: OLD.into(),
                after: NEW.into(),
                previous_reserve: None,
                resolved_before: vec![],
                resolved_after: vec![],
            }),
            legacy_predecessor: None,
            native_mtu_endpoint: None,
            legacy_mtu_before_recorded: false,
            nested_mtu_before_recorded: false,
            implicit_before_mtu: None,
        };
        assert_eq!(
            validate_endpoint_edit_launch(&db, &router, &change, &wan).unwrap(),
            RoutedEndpointLaunch::Primary
        );
        let current = Journal::read(&db).unwrap();
        let mut changed = current.clone();
        changed.installed.targets.get_mut("awg0").unwrap().mtu += 1;
        db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, &changed, RECEIPT_LIMIT))
            .unwrap();
        assert!(validate_endpoint_edit_launch(&db, &router, &change, &wan).is_err());
        db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, &current, RECEIPT_LIMIT))
            .unwrap();
        nfqws2_awg_profile::edit_document(&db, |doc| {
            let row = &mut doc["servers"][0];
            if change_mtu {
                change.rewrite_combined_endpoint_mtu(row, true)?;
            } else {
                row["config"]["endpoint"] = json!(NEW);
            }
            row["rust_pending_routed_mtu"] = json!(change);
            Ok(())
        })
        .unwrap();
        if suspend_before_prepare {
            operate_at(&db, &router, Operation::Suspend, now, live(OLD, false)).unwrap();
            assert!(Journal::read(&db).unwrap().installed.empty());
            assert!(pending_mtu_edit(&db).unwrap());
        }
        let db = Store::open(dir.path()).unwrap();
        prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
        if !suspend_before_prepare {
            paths("wan0", "unreachable");
            let mut lost_ack = Journal::read(&db).unwrap();
            lost_ack.preparing.push(lost_ack.installed.clone());
            db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, &lost_ack, RECEIPT_LIMIT))
                .unwrap();
            router.v6.0.lock().unwrap().watch_flow = Some(("fd02::5", V6_PAYLOAD));
        }
        let recover = |endpoint, ipv6| {
            operate_with_redirect_and_mtu(
                &db,
                &router,
                Operation::Recover,
                None,
                None,
                live(endpoint, ipv6),
                |saved, observed| {
                    assert_eq!(saved, &change);
                    Ok(Some(RoutedMtuPeer {
                        iface: "awg0".into(),
                        outer_id: String::new(),
                        outer_iface: String::new(),
                        endpoint: observed.endpoint,
                        effective_mtu: change.after,
                        socket_mark: observed.socket_mark,
                    }))
                },
            )
        };
        let wrong_mtu = if change_mtu {
            change.before
        } else {
            change.after + 20
        };
        router
            .v4
            .0
            .lock()
            .unwrap()
            .mtu
            .insert("awg0".into(), wrong_mtu);
        recover(NEW, true).unwrap();
        paths("wan0", "unreachable");
        assert!(pending_mtu_edit(&db).unwrap());
        router
            .v4
            .0
            .lock()
            .unwrap()
            .mtu
            .insert("awg0".into(), change.after);
        recover(OLD, true).unwrap();
        paths("wan0", "unreachable");
        recover(NEW, suspend_before_prepare).unwrap();
        paths("awg0", "unreachable");
        assert!(!router.v6.0.lock().unwrap().leaked);
        assert!(!pending_mtu_edit(&db).unwrap());
        let settled = Journal::read(&db).unwrap();
        assert_eq!(settled.committed.revision, baseline.revision);
        assert_eq!(settled.installed.mss["awg0"], change.after - 40);
        assert_eq!(
            settled.installed.full_endpoints,
            Some(["198.51.100.30".parse().unwrap()].into())
        );
        assert_eq!(scheduled(&db).unwrap(), Schedule::Failover);
        operate_at(&db, &router, Operation::Refresh, now, live(NEW, true)).unwrap();
        paths("awg0", "awg0");
        assert_eq!(scheduled(&db).unwrap(), Schedule::Audit);
    }
}
