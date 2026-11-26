use super::*;
use nfqws2_awg_profile::{
    RoutedEndpointEdit, RoutedEndpointLaunch, RoutedMtuChange, RoutedMtuPeer,
};

#[test]
fn combined_endpoint_mtu_requires_the_exact_pair_and_rebinds_only_unchanged_sources() {
    const OLD: &str = "198.51.100.10:443";
    const NEW: &str = "198.51.100.55:51820";
    const LEARNED: &str = "203.0.113.12";
    const SOURCE: &str = "192.168.1.7";
    const LIST_IP: &str = "203.0.113.14/32";
    let (dir, db, router) = fixture();
    let wan = ["wan0".into()];
    scoped_policy(&db);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let cfg = &mut doc["servers"][0]["config"];
        cfg["install"] = json!("imported");
        cfg["endpoint"] = json!(OLD);
        cfg["mtu"] = json!(1420);
        cfg["client"]["rust_managed"] = json!(true);
        cfg["routing"]["zones"] = json!([{
            "order":1,"name":"team","enabled":true,
            "domains":["*.corp.example","list:corp"],"ips":["203.0.113.10"],
            "source_ips":[SOURCE]
        }]);
        doc["servers"][1]["config"]["routing"]["zones"] = json!([{
            "order":2,"name":"other","enabled":true,"ips":["203.0.113.11"],
            "source_ips":[SOURCE]
        }]);
        Ok(())
    })
    .unwrap();
    let source =
        |db: &Store, ip: &str| crate::sources::stage(db, |_, _| Ok(vec![ip.into()])).unwrap();
    source(&db, LIST_IP);
    let now = nfqws2_awg_profile::now();
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &router, op, now, both_peers).unwrap();
    }
    let addresses = [LEARNED.parse().unwrap()];
    learn_client_answer(
        &db,
        &router,
        Answer {
            revision: 1,
            zone: 0,
            addresses: &addresses,
            ttl: 600,
            qtype: 1,
        },
        Some(SOURCE.parse().unwrap()),
        both_peers,
        || Ok(()),
    )
    .unwrap();
    let baseline = Journal::read(&db).unwrap().committed;
    assert!(baseline.local_sources.is_some());
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
        implicit_before_mtu: None,
        endpoint_edit: Some(RoutedEndpointEdit {
            before: OLD.into(),
            after: NEW.into(),
            previous_reserve: None,
            resolved_before: vec![],
            resolved_after: vec![],
        }),
    };
    let mut collision = change.clone();
    collision.endpoint_edit.as_mut().unwrap().after = format!("{LEARNED}:51820");
    assert!(validate_endpoint_edit_launch(&db, &router, &collision, &wan).is_err());
    let mut same_socket = change.clone();
    same_socket.endpoint_edit.as_mut().unwrap().after = OLD.into();
    assert!(validate_endpoint_edit_launch(&db, &router, &same_socket, &wan).is_err());
    let mut same_ip = change.clone();
    same_ip.endpoint_edit.as_mut().unwrap().after = "198.51.100.10:51820".into();
    assert!(validate_endpoint_edit_launch(&db, &router, &same_ip, &["wrong-wan".into()]).is_err());
    source(&db, "203.0.113.24/32");
    assert!(validate_endpoint_edit_launch(&db, &router, &change, &wan).is_err());
    source(&db, LIST_IP);
    assert_eq!(
        validate_endpoint_edit_launch(&db, &router, &change, &wan).unwrap(),
        RoutedEndpointLaunch::Primary
    );

    let stage = |db: &Store, endpoint: &str, mtu: u16| {
        nfqws2_awg_profile::edit_document(db, |doc| {
            let row = &mut doc["servers"][0];
            row["config"]["endpoint"] = json!(endpoint);
            row["config"]["mtu"] = json!(mtu);
            row["rust_pending_routed_mtu"] = json!(change);
            Ok(())
        })
        .unwrap();
    };
    let verify = |expected| {
        let fw = router.0.lock().unwrap();
        assert_eq!(fw.forward(SOURCE, "203.0.113.10"), expected);
        assert_eq!(fw.forward(SOURCE, LEARNED), expected);
        assert_eq!(fw.forward(SOURCE, "203.0.113.14"), expected);
        assert_eq!(fw.forward(SOURCE, "203.0.113.11"), "awg1");
    };
    stage(&db, NEW, change.before);
    assert!(prepare_mtu_edit_with_wan(&db, &router, &change, &wan).is_err());
    verify("awg0");
    stage(&db, NEW, change.after);
    prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
    verify("blackhole");
    assert_eq!(
        pending_endpoint_launch(&db, &router, &change, &wan)
            .unwrap_err()
            .kind(),
        io::ErrorKind::Unsupported
    );
    let db = Store::open(dir.path()).unwrap();
    let recover = |endpoint: &str, effective| {
        operate_with_redirect_and_mtu(
            &db,
            &router,
            Operation::Recover,
            None,
            None,
            |cfg, iface| {
                let mut live = both_peers(cfg, iface)?;
                if iface == "awg0" {
                    live.endpoint = endpoint.parse().unwrap();
                }
                Ok(live)
            },
            |saved, live| {
                assert_eq!(saved, &change);
                Ok(Some(RoutedMtuPeer {
                    iface: "awg0".into(),
                    outer_id: String::new(),
                    outer_iface: String::new(),
                    endpoint: live.endpoint,
                    effective_mtu: effective,
                    socket_mark: live.socket_mark,
                }))
            },
        )
    };
    router
        .0
        .lock()
        .unwrap()
        .mtu
        .insert("awg0".into(), change.after);
    recover(OLD, change.after).unwrap();
    verify("blackhole");
    router
        .0
        .lock()
        .unwrap()
        .mtu
        .insert("awg0".into(), change.before);
    recover(NEW, change.after).unwrap();
    verify("blackhole");
    router
        .0
        .lock()
        .unwrap()
        .mtu
        .insert("awg0".into(), change.after);
    recover(NEW, change.before).unwrap();
    verify("blackhole");
    source(&db, "203.0.113.24/32");
    assert!(recover(NEW, change.after).is_err());
    verify("blackhole");
    let mut parked_baseline = baseline.clone();
    parked_baseline.mss.remove("awg0");
    assert_eq!(Journal::read(&db).unwrap().committed, parked_baseline);
    source(&db, LIST_IP);
    let mut acknowledgement = json!(mtu_edit::read(&db).unwrap().unwrap());
    recover(NEW, change.after).unwrap();
    verify("awg0");
    let changed = Journal::read(&db).unwrap();
    assert_eq!(changed.committed.targets["awg0"].mtu, change.after);
    assert_eq!(changed.committed.mss["awg0"], change.after - 40);
    assert_eq!(changed.committed.targets["awg1"], baseline.targets["awg1"]);
    assert_eq!(
        changed.committed.learned.as_ref().unwrap().members,
        baseline.learned.as_ref().unwrap().members
    );
    assert_ne!(changed.committed.learned, baseline.learned);
    assert_ne!(changed.committed.local_sources, baseline.local_sources);
    assert_eq!(
        changed.committed.local_sources,
        changed.installed.local_sources
    );
    assert!(!pending_mtu_edit(&db).unwrap());

    // Replay the acknowledged forward generation without rewriting the FIB.
    acknowledgement["endpoint_committed"] = json!(true);
    db.transaction(|tx| tx.save_runtime_bounded("awg-routed-mtu.json", &acknowledgement, 4096))
        .unwrap();
    let writes = router.0.lock().unwrap().changes;
    recover(NEW, change.after).unwrap();
    assert_eq!(router.0.lock().unwrap().changes, writes);
    assert!(!pending_mtu_edit(&db).unwrap());

    // The forward receipt can also survive before clearing the row.
    db.transaction(|tx| tx.save_runtime_bounded("awg-routed-mtu.json", &acknowledgement, 4096))
        .unwrap();
    stage(&db, NEW, change.after);
    validate_endpoint_edit(&db, &router, &change, &wan).unwrap();
    stage(&db, OLD, change.after);
    assert!(prepare_mtu_edit_with_wan(&db, &router, &change, &wan).is_err());
    stage(&db, OLD, change.before);
    prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
    verify("blackhole");
    router
        .0
        .lock()
        .unwrap()
        .mtu
        .insert("awg0".into(), change.before);
    recover(NEW, change.before).unwrap();
    verify("blackhole");
    recover(OLD, change.before).unwrap();
    verify("awg0");
    assert_eq!(Journal::read(&db).unwrap().committed, baseline);
    assert!(!pending_mtu_edit(&db).unwrap());
}
