use super::*;

#[test]
fn routed_named_old_reserve_requires_exact_membership_for_lookup_free_undo() {
    const OLD: &str = "localhost:443";
    const NEW: &str = "198.51.100.30:443";
    const BACKUP: &str = "198.51.100.10:8443";
    const WRONG_PORT: &str = "198.51.100.10:9443";
    const INDEPENDENT: &str = "198.51.100.80:8443";
    const CAPTURED: &str = "203.0.113.25:8443";
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
        cfg["client"]["endpoint_backups"] = json!([BACKUP, INDEPENDENT]);
        Ok(())
    })
    .unwrap();
    router.0.lock().unwrap().mtu.insert("awg0".into(), 1420);
    let reserve = BACKUP.parse().unwrap();
    let old_live = |cfg: &Value, iface: &str| {
        Ok(LivePeer {
            endpoint: reserve,
            ..peer(cfg, iface)?
        })
    };
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &run, op, nfqws2_awg_profile::now(), old_live).unwrap();
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
            previous_reserve: Some(reserve),
            resolved_before: vec![],
            resolved_after: vec![],
        }),
    };
    validate_endpoint_edit(&db, &run, &change, &wan).unwrap();
    let mut forged = change.clone();
    forged.endpoint_edit.as_mut().unwrap().previous_reserve = Some(WRONG_PORT.parse().unwrap());
    assert!(validate_endpoint_edit(&db, &run, &forged, &wan).is_err());

    let stage = |raw, marker: &RoutedMtuChange, backup| {
        nfqws2_awg_profile::edit_document(&db, |doc| {
            let row = &mut doc["servers"][0];
            row["config"]["endpoint"] = json!(raw);
            row["config"]["client"]["endpoint_backups"] = json!([backup, INDEPENDENT]);
            row["rust_pending_routed_mtu"] = json!(marker);
            Ok(())
        })
        .unwrap();
    };
    forged.endpoint_edit.as_mut().unwrap().previous_reserve = Some(CAPTURED.parse().unwrap());
    stage(NEW, &forged, CAPTURED);
    // The reserved transport itself must pass geometry even with no DNS pins.
    assert!(validate_endpoint_edit(&db, &run, &forged, &wan).is_err());

    stage(NEW, &change, BACKUP);
    prepare_mtu_edit_with_wan(&db, &run, &change, &wan).unwrap();
    assert_eq!(path(&router, PAYLOAD), "blackhole");
    stage(NEW, &change, WRONG_PORT);
    assert!(validate_endpoint_edit(&db, &run, &change, &wan).is_err());
    stage(OLD, &change, WRONG_PORT);
    assert!(prepare_mtu_edit_with_wan(&db, &run, &change, &wan).is_err());
    stage(NEW, &change, BACKUP);
    validate_endpoint_edit(&db, &run, &change, &wan).unwrap();
    stage(OLD, &change, BACKUP);
    prepare_mtu_edit_with_wan(&db, &run, &change, &wan).unwrap();

    let mut claims = BTreeSet::new();
    plan::visit_endpoints_with_edit(
        &nfqws2_awg_profile::read(&db).unwrap(),
        false,
        Some(&change),
        |row| row["id"] == change.id,
        |_, _, ip| {
            claims.insert(ip);
        },
    )
    .unwrap();
    assert_eq!(
        claims,
        ["198.51.100.10", "198.51.100.80"]
            .map(|ip| ip.parse().unwrap())
            .into()
    );
    operate_with_redirect_and_mtu(&db, &run, Operation::Recover, None, None, peer, |_, _| {
        panic!("the former named primary's port cannot authenticate the selected reserve")
    })
    .unwrap();
    assert_eq!(path(&router, PAYLOAD), "blackhole");
    operate_with_redirect_and_mtu(
        &db,
        &run,
        Operation::Recover,
        None,
        None,
        old_live,
        |saved, live| {
            assert_eq!(saved, &change);
            assert_eq!(live.endpoint, reserve);
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
    assert_eq!(path(&router, PAYLOAD), "awg0");
    assert_eq!(Journal::read(&db).unwrap().committed, confirmed);
    assert!(!pending_mtu_edit(&db).unwrap());
}
