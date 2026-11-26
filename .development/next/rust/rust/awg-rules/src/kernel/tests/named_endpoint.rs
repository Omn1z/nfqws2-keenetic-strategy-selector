use super::*;
use nfqws2_awg_profile::{
    RoutedEndpointEdit, RoutedEndpointLaunch, RoutedMtuChange, RoutedMtuPeer,
};
mod previous_reserve;

struct NamedWan<'a>(&'a Fake);

impl Runner for NamedWan<'_> {
    fn run(&self, cmd: &str, args: &[&str], end: Instant) -> io::Result<String> {
        if cmd == "ip" && args == ["-4", "route", "get", "198.51.100.93"] {
            return Err(io::ErrorKind::NotConnected.into());
        }
        self.0.run(cmd, args, end)
    }
}

#[test]
fn routed_named_endpoint_preserves_pins_and_same_tuple_generation() {
    const OLD: &str = "198.51.100.10:443";
    const NEW: &str = "localhost:443";
    const UNUSED: &str = "198.51.100.93:443";
    const PAYLOAD: &str = "203.0.113.12";
    let (_dir, db, router) = setup();
    let run = NamedWan(&router);
    let wan = ["wan0".into()];
    protect(&db);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let cfg = &mut doc["servers"][0]["config"];
        cfg["install"] = json!("imported");
        cfg["mtu"] = json!(1420);
        cfg["endpoint"] = json!(OLD);
        cfg["client"]["rust_managed"] = json!(true);
        Ok(())
    })
    .unwrap();
    router.0.lock().unwrap().mtu.insert("awg0".into(), 1420);
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &run, op, nfqws2_awg_profile::now(), peer).unwrap();
    }
    let confirmed = Journal::read(&db).unwrap().committed;
    let change = RoutedMtuChange {
        id: confirmed.targets["awg0"].id.clone(),
        iface: "awg0".into(),
        revision: confirmed.revision,
        before: 1420,
        after: 1420,
        nested_outer: None,
        nested_endpoint: None,
        legacy_predecessor: None,
        native_mtu_endpoint: None,
        legacy_mtu_before_recorded: false,
        nested_mtu_before_recorded: false,
        implicit_before_mtu: None,
        endpoint_edit: Some(RoutedEndpointEdit {
            before: OLD.into(),
            after: NEW.into(),
            previous_reserve: None,
            resolved_before: vec![],
            resolved_after: ["[2001:db8:42::7]:443", OLD, UNUSED]
                .map(|address| address.parse().unwrap())
                .into(),
        }),
    };
    let mut overlaps = change.clone();
    overlaps
        .endpoint_edit
        .as_mut()
        .unwrap()
        .resolved_after
        .push("203.0.113.25:443".parse().unwrap());
    assert!(validate_endpoint_edit_launch(&db, &run, &overlaps, &wan).is_err());
    assert_eq!(
        validate_endpoint_edit_launch(&db, &run, &change, &wan).unwrap(),
        RoutedEndpointLaunch::Primary
    );

    let stage = |raw: &str, marker: bool, retained_backup: bool| {
        nfqws2_awg_profile::edit_document(&db, |doc| {
            let row = &mut doc["servers"][0];
            row["config"]["endpoint"] = json!(raw);
            row["config"]["client"]["endpoint_backups"] = if retained_backup {
                json!(["198.51.100.93:8443"])
            } else {
                json!([])
            };
            if marker {
                row["rust_pending_routed_mtu"] = json!(change);
            } else {
                row.as_object_mut()
                    .unwrap()
                    .remove("rust_pending_routed_mtu");
            }
            Ok(())
        })
        .unwrap();
    };
    let exact_proof = |asked: &RoutedMtuChange, live: &LivePeer| {
        assert_eq!(asked, &change);
        assert_eq!(live.endpoint, OLD.parse().unwrap());
        Ok(Some(RoutedMtuPeer {
            iface: "awg0".into(),
            outer_id: String::new(),
            outer_iface: String::new(),
            endpoint: live.endpoint,
            effective_mtu: 1420,
            socket_mark: 0,
        }))
    };

    stage(NEW, true, false);
    prepare_mtu_edit_with_wan(&db, &run, &change, &wan).unwrap();
    assert_eq!(path(&router, PAYLOAD), "blackhole");
    validate_endpoint_edit(&db, &run, &change, &wan).unwrap();
    stage(OLD, true, false);
    prepare_mtu_edit_with_wan(&db, &run, &change, &wan).unwrap();
    operate_with_redirect_and_mtu(&db, &run, Operation::Recover, None, None, peer, exact_proof)
        .unwrap();
    assert_eq!(path(&router, PAYLOAD), "awg0");
    assert!(!pending_mtu_edit(&db).unwrap());

    stage(NEW, true, false);
    prepare_mtu_edit_with_wan(&db, &run, &change, &wan).unwrap();
    let mut late = json!(mtu_edit::read(&db).unwrap().unwrap());
    stage(NEW, false, false);
    let _ =
        operate_with_redirect_and_mtu(&db, &run, Operation::Recover, None, None, peer, |_, _| {
            panic!("unacknowledged named config must not prove the old generation")
        });
    assert_eq!(path(&router, PAYLOAD), "blackhole");
    stage(NEW, true, false);
    let _ =
        operate_with_redirect_and_mtu(&db, &run, Operation::Recover, None, None, peer, |_, _| {
            Ok(None)
        });
    assert_eq!(path(&router, PAYLOAD), "blackhole");

    stage(NEW, true, true);
    assert!(operate_with_redirect_and_mtu(
        &db,
        &run,
        Operation::Recover,
        None,
        None,
        peer,
        exact_proof,
    )
    .is_err());
    assert_eq!(path(&router, PAYLOAD), "blackhole");
    stage(NEW, true, false);
    operate_with_redirect_and_mtu(&db, &run, Operation::Recover, None, None, peer, exact_proof)
        .unwrap();
    assert_eq!(path(&router, PAYLOAD), "awg0");
    assert!(!pending_mtu_edit(&db).unwrap());
    assert_eq!(Journal::read(&db).unwrap().committed, confirmed);

    late["endpoint_committed"] = json!(true);
    db.transaction(|tx| tx.save_runtime_bounded("awg-routed-mtu.json", &late, 16_384))
        .unwrap();
    let writes = router.0.lock().unwrap().changes;
    operate_with_redirect_and_mtu(&db, &run, Operation::Recover, None, None, peer, exact_proof)
        .unwrap();
    assert_eq!(router.0.lock().unwrap().changes, writes);
    assert!(!pending_mtu_edit(&db).unwrap());
}

#[test]
fn routed_named_predecessor_uses_saved_pins_for_exact_undo_and_replay() {
    const OLD: &str = "localhost:443";
    const NEW: &str = "198.51.100.10:443";
    const UNUSED: &str = "198.51.100.93:443";
    const PAYLOAD: &str = "203.0.113.12";
    let (_dir, db, router) = setup();
    let run = NamedWan(&router);
    let wan = ["wan0".into()];
    protect(&db);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let cfg = &mut doc["servers"][0]["config"];
        cfg["install"] = json!("imported");
        cfg["mtu"] = json!(1420);
        cfg["endpoint"] = json!(OLD);
        cfg["client"]["rust_managed"] = json!(true);
        Ok(())
    })
    .unwrap();
    router.0.lock().unwrap().mtu.insert("awg0".into(), 1420);
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &run, op, nfqws2_awg_profile::now(), peer).unwrap();
    }
    let confirmed = Journal::read(&db).unwrap().committed;
    let change = RoutedMtuChange {
        id: confirmed.targets["awg0"].id.clone(),
        iface: "awg0".into(),
        revision: confirmed.revision,
        before: 1420,
        after: 1420,
        nested_outer: None,
        nested_endpoint: None,
        legacy_predecessor: None,
        native_mtu_endpoint: None,
        legacy_mtu_before_recorded: false,
        nested_mtu_before_recorded: false,
        implicit_before_mtu: None,
        endpoint_edit: Some(RoutedEndpointEdit {
            before: OLD.into(),
            after: NEW.into(),
            previous_reserve: None,
            resolved_before: [NEW, UNUSED, "[2001:db8:42::7]:443"]
                .map(|address| address.parse().unwrap())
                .into(),
            resolved_after: vec![],
        }),
    };
    assert_eq!(
        validate_endpoint_edit_launch(&db, &run, &change, &wan).unwrap(),
        RoutedEndpointLaunch::Primary
    );

    let stage = |raw: &str, marker: Option<&RoutedMtuChange>, shared: bool| {
        nfqws2_awg_profile::edit_document(&db, |doc| {
            let row = &mut doc["servers"][0];
            row["config"]["endpoint"] = json!(raw);
            row["config"]["client"]["endpoint_backups"] = if shared {
                json!(["198.51.100.93:8443"])
            } else {
                json!([])
            };
            if let Some(marker) = marker {
                row["rust_pending_routed_mtu"] = json!(marker);
            } else {
                row.as_object_mut()
                    .unwrap()
                    .remove("rust_pending_routed_mtu");
            }
            Ok(())
        })
        .unwrap();
    };
    let mut overlaps = change.clone();
    overlaps
        .endpoint_edit
        .as_mut()
        .unwrap()
        .resolved_before
        .push("203.0.113.25:443".parse().unwrap());
    stage(NEW, Some(&overlaps), false);
    assert!(validate_endpoint_edit(&db, &run, &overlaps, &wan).is_err());

    stage(NEW, Some(&change), false);
    prepare_mtu_edit_with_wan(&db, &run, &change, &wan).unwrap();
    assert_eq!(path(&router, PAYLOAD), "blackhole");
    let error = pending_endpoint_retry(&db, &change).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    let late = json!(mtu_edit::read(&db).unwrap().unwrap());
    let exact_proof = |asked: &RoutedMtuChange, live: &LivePeer| {
        assert_eq!(asked, &change);
        assert_eq!(live.endpoint, NEW.parse().unwrap());
        Ok(Some(RoutedMtuPeer {
            iface: "awg0".into(),
            outer_id: String::new(),
            outer_iface: String::new(),
            endpoint: live.endpoint,
            effective_mtu: 1420,
            socket_mark: 0,
        }))
    };
    stage(NEW, None, false);
    operate_with_redirect_and_mtu(&db, &run, Operation::Recover, None, None, peer, |_, _| {
        panic!("the unacknowledged literal may equal the old hostname's tuple")
    })
    .unwrap();
    assert_eq!(path(&router, PAYLOAD), "blackhole");

    stage(NEW, Some(&change), false);
    validate_endpoint_edit(&db, &run, &change, &wan).unwrap();
    stage(OLD, Some(&change), true);
    prepare_mtu_edit_with_wan(&db, &run, &change, &wan).unwrap();
    assert!(operate_with_redirect_and_mtu(
        &db,
        &run,
        Operation::Recover,
        None,
        None,
        peer,
        exact_proof,
    )
    .is_err());
    assert_eq!(path(&router, PAYLOAD), "blackhole");
    stage(OLD, Some(&change), false);
    operate_with_redirect_and_mtu(&db, &run, Operation::Recover, None, None, peer, exact_proof)
        .unwrap();
    assert_eq!(path(&router, PAYLOAD), "awg0");
    assert_eq!(Journal::read(&db).unwrap().committed, confirmed);
    assert!(!pending_mtu_edit(&db).unwrap());

    let mut pins = BTreeSet::new();
    plan::visit_endpoints_with_edit(
        &nfqws2_awg_profile::read(&db).unwrap(),
        false,
        Some(&change),
        |row| row["id"] == change.id,
        |_, _, ip| {
            pins.insert(ip);
        },
    )
    .unwrap();
    assert_eq!(
        pins,
        ["198.51.100.10", "198.51.100.93", "2001:db8:42::7"]
            .map(|ip| ip.parse().unwrap())
            .into()
    );
    db.transaction(|tx| tx.save_runtime_bounded("awg-routed-mtu.json", &late, 4096))
        .unwrap();
    let writes = router.0.lock().unwrap().changes;
    operate_with_redirect_and_mtu(&db, &run, Operation::Recover, None, None, peer, exact_proof)
        .unwrap();
    assert_eq!(router.0.lock().unwrap().changes, writes);
    assert!(!pending_mtu_edit(&db).unwrap());

    stage(NEW, Some(&change), false);
    prepare_mtu_edit_with_wan(&db, &run, &change, &wan).unwrap();
    operate_with_redirect_and_mtu(&db, &run, Operation::Recover, None, None, peer, exact_proof)
        .unwrap();
    assert_eq!(path(&router, PAYLOAD), "awg0");
    assert_eq!(Journal::read(&db).unwrap().committed, confirmed);
    assert!(!pending_mtu_edit(&db).unwrap());
}

#[test]
fn routed_distinct_hostnames_bind_only_the_matching_side_at_the_same_socket() {
    const OLD: &str = "localhost:443";
    const NEW: &str = "LOCALHOST:443";
    const ACTIVE: &str = "198.51.100.10:443";
    const OLD_EXTRA: &str = "198.51.100.93:443";
    const NEW_EXTRA: &str = "198.51.100.95:443";
    let (_dir, db, router) = setup();
    let run = NamedWan(&router);
    let wan = ["wan0".into()];
    protect(&db);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let cfg = &mut doc["servers"][0]["config"];
        cfg["install"] = json!("imported");
        cfg["mtu"] = json!(1420);
        cfg["endpoint"] = json!(OLD);
        cfg["client"]["rust_managed"] = json!(true);
        Ok(())
    })
    .unwrap();
    router.0.lock().unwrap().mtu.insert("awg0".into(), 1420);
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &run, op, nfqws2_awg_profile::now(), peer).unwrap();
    }
    let confirmed = Journal::read(&db).unwrap().committed;
    let change = RoutedMtuChange {
        id: confirmed.targets["awg0"].id.clone(),
        iface: "awg0".into(),
        revision: confirmed.revision,
        before: 1420,
        after: 1420,
        nested_outer: None,
        nested_endpoint: None,
        legacy_predecessor: None,
        native_mtu_endpoint: None,
        legacy_mtu_before_recorded: false,
        nested_mtu_before_recorded: false,
        implicit_before_mtu: None,
        endpoint_edit: Some(RoutedEndpointEdit {
            before: OLD.into(),
            after: NEW.into(),
            previous_reserve: None,
            resolved_before: [ACTIVE, OLD_EXTRA]
                .map(|address| address.parse().unwrap())
                .into(),
            resolved_after: [ACTIVE, NEW_EXTRA]
                .map(|address| address.parse().unwrap())
                .into(),
        }),
    };
    validate_endpoint_edit(&db, &run, &change, &wan).unwrap();
    for (name, extra) in [(NEW, "198.51.100.95"), (OLD, "198.51.100.93")] {
        nfqws2_awg_profile::edit_document(&db, |doc| {
            let row = &mut doc["servers"][0];
            row["config"]["endpoint"] = json!(name);
            row["rust_pending_routed_mtu"] = json!(change);
            Ok(())
        })
        .unwrap();
        prepare_mtu_edit_with_wan(&db, &run, &change, &wan).unwrap();
        let mut pins = BTreeSet::new();
        plan::visit_endpoints_with_edit(
            &nfqws2_awg_profile::read(&db).unwrap(),
            false,
            Some(&change),
            |row| row["id"] == change.id,
            |_, _, ip| {
                pins.insert(ip);
            },
        )
        .unwrap();
        assert_eq!(
            pins,
            ["198.51.100.10", extra]
                .map(|ip| ip.parse().unwrap())
                .into()
        );
        if name == NEW {
            validate_endpoint_edit(&db, &run, &change, &wan).unwrap();
        }
    }
    operate_with_redirect_and_mtu(
        &db,
        &run,
        Operation::Recover,
        None,
        None,
        peer,
        |saved, live| {
            assert_eq!(saved, &change);
            Ok(Some(RoutedMtuPeer {
                iface: "awg0".into(),
                outer_id: String::new(),
                outer_iface: String::new(),
                endpoint: live.endpoint,
                effective_mtu: 1420,
                socket_mark: 0,
            }))
        },
    )
    .unwrap();
    assert_eq!(path(&router, "203.0.113.12"), "awg0");
    assert!(!pending_mtu_edit(&db).unwrap());
    assert_eq!(Journal::read(&db).unwrap().committed, confirmed);
}
