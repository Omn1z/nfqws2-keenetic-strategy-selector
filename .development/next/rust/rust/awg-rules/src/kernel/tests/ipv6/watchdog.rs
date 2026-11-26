use super::*;

fn deployed_peer(cfg: &Value, iface: &str) -> io::Result<LivePeer> {
    let wanted = match iface {
        "awg0" => "198.51.100.10:443",
        "awg1" => "198.51.100.11:443",
        _ => return Err(io::ErrorKind::NotConnected.into()),
    };
    assert_eq!(
        cfg["endpoint"], wanted,
        "use the deployed peer, not the draft"
    );
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
        endpoint: wanted.parse().unwrap(),
        allowed: vec!["0.0.0.0/0".into(), "::/0".into()],
    })
}

fn confirmed(killswitch: bool) -> (tempfile::TempDir, Store, Dual, u64) {
    let (dir, db, _) = setup();
    let router = Dual::default();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"] = json!({"mode":"full","killswitch":killswitch});
        let rows = doc["servers"].as_array_mut().unwrap();
        rows[0]["config"]["endpoint"] = json!("198.51.100.10:443");
        rows[0]["config"]["routing"] = json!({"mode":"full","active":true});
        let mut alternate = rows[0].clone();
        alternate["id"] = json!("alt");
        alternate["config"]["routing"]["active"] = json!(false);
        alternate["config"]["client_iface"] = json!("awg1");
        alternate["config"]["endpoint"] = json!("198.51.100.11:443");
        alternate["applied_config"] = alternate["config"].clone();
        alternate["config"]["endpoint"] = json!("198.51.100.12:443");
        let mut parked = alternate.clone();
        parked["id"] = json!("parked");
        parked["config"]["client"]["enabled"] = json!(false);
        for key in ["config", "applied_config"] {
            parked[key]["client_iface"] = json!("awg2");
        }
        rows.push(alternate);
        rows.push(parked);
        Ok(())
    })
    .unwrap();
    let doc = nfqws2_awg_profile::read(&db).unwrap();
    let intent = plan::compile_with_layout(
        &doc,
        None,
        true,
        &[],
        plan::Layout {
            legacy_full: Some(plan::LegacyFull::Dual),
            legacy_revision: doc["routing_revision"].as_u64(),
            ..Default::default()
        },
    )
    .unwrap();
    let k = kernel(&router);
    let resolved = plan::resolve_on(
        &doc,
        intent,
        false,
        None,
        Some(plan::Verification::Read(&k)),
        deployed_peer,
    )
    .unwrap();
    let old = Journal::default();
    let initial = Journal {
        boot: boot_id(&k).unwrap(),
        installed: resolved.plan.clone().into(),
        committed: resolved.plan.into(),
        ..Journal::default()
    };
    db.transaction(|tx| transition(&db, tx, &router, &old, &initial, None))
        .unwrap();
    (dir, db, router, nfqws2_awg_profile::now())
}

fn v4(router: &Dual) -> String {
    router
        .v4
        .0
        .lock()
        .unwrap()
        .forward("192.168.7.11", "9.9.9.9")
        .into()
}

#[test]
fn a_selected_dns_policy_requests_listeners_before_the_watchdog_changes_routes() {
    let (_dir, db, router, _) = confirmed(true);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][1]["config"]["routing"]["zones"] = json!([{
            "enabled":true,"route":"direct","source_ips":["192.168.7.11"],"domains":["office.test"]
        }]);
        Ok(())
    })
    .unwrap();
    assert!(!watchdog_needs_dns_listener(&db).unwrap());
    nfqws2_awg_profile::select(&db, "alt").unwrap();
    assert!(watchdog_needs_dns_listener(&db).unwrap());
    assert!(redirect_bridges(&db, true).unwrap().is_empty());
    assert_eq!(v4(&router), "awg0");
    nfqws2_awg_profile::select(&db, "parked").unwrap();
    assert!(!watchdog_needs_dns_listener(&db).unwrap());
}

#[test]
fn editor_selection_retargets_only_on_a_watchdog_tick_and_recovers_the_confirmed_owner() {
    let (_dir, db, router, now) = confirmed(true);
    let original = Journal::read(&db).unwrap();
    assert_eq!(scheduled(&db).unwrap(), Schedule::LegacyWatchdog);
    assert_eq!(v4(&router), "awg0");

    nfqws2_awg_profile::select(&db, "alt").unwrap();
    assert_eq!(v4(&router), "awg0");
    operate_at(
        &db,
        &router,
        Operation::LegacyWatchdog,
        now + 60,
        |cfg, iface| {
            let mut live = deployed_peer(cfg, iface)?;
            if iface == "awg1" {
                live.allowed = vec!["203.0.113.0/24".into()];
            }
            Ok(live)
        },
    )
    .unwrap();
    assert_eq!(v4(&router), "awg0");

    operate_at(
        &db,
        &router,
        Operation::LegacyWatchdog,
        now + 120,
        deployed_peer,
    )
    .unwrap();
    let live = Journal::read(&db).unwrap();
    assert_eq!(live.committed, original.committed);
    assert_eq!(live.expires, 0);
    assert!(live.preparing.is_empty());
    assert_eq!(v4(&router), "awg1");
    assert!(matches!(
        router
            .v6
            .0
            .lock()
            .unwrap()
            .forward("fd00::3", "2620:fe::fe"),
        "awg1" | "drop" | "unreachable"
    ));
    let doc = nfqws2_awg_profile::read(&db).unwrap();
    assert_eq!(doc["active_id"], "alt");
    assert_eq!(doc["servers"][0]["config"]["routing"]["active"], true);
    assert_eq!(doc["servers"][1]["config"]["routing"]["active"], false);
    assert_eq!(
        doc["servers"][1]["applied_config"]["routing"]["active"],
        false
    );
    assert_eq!(doc["rust_static_routing"]["targets"], json!(["alt"]));
    assert_eq!(
        doc["rust_static_routing"]["committed_targets"],
        json!(["awg0"])
    );

    nfqws2_awg_profile::select(&db, "parked").unwrap();
    operate_at(
        &db,
        &router,
        Operation::LegacyWatchdog,
        now + 180,
        deployed_peer,
    )
    .unwrap();
    assert_eq!(v4(&router), "awg1");
    operate_at(&db, &router, Operation::Recover, now + 181, deployed_peer).unwrap();
    assert_eq!(v4(&router), "awg0");
    assert_eq!(
        nfqws2_awg_profile::read(&db).unwrap()["active_id"],
        "parked"
    );
}

#[test]
fn a_failed_watchdog_transfer_restores_the_witnessed_route_and_leaves_no_intent() {
    let (_dir, db, router, now) = confirmed(true);
    let original = Journal::read(&db).unwrap();
    nfqws2_awg_profile::select(&db, "alt").unwrap();
    {
        let mut kernel = router.v4.0.lock().unwrap();
        kernel.fail_after = Some(kernel.changes + 1);
    }
    assert!(operate_at(
        &db,
        &router,
        Operation::LegacyWatchdog,
        now + 60,
        deployed_peer
    )
    .is_err());
    assert_eq!(v4(&router), "awg0");
    assert_eq!(Journal::read(&db).unwrap(), original);
    operate_at(
        &db,
        &router,
        Operation::LegacyWatchdog,
        now + 120,
        deployed_peer,
    )
    .unwrap();
    assert_eq!(v4(&router), "awg1");
}

#[test]
fn a_failed_transfer_away_from_an_unverified_peer_claims_the_ipv6_fence() {
    let (_dir, db, router, now) = confirmed(false);
    let origin = Journal::read(&db).unwrap().committed;
    nfqws2_awg_profile::select(&db, "alt").unwrap();
    operate_at(
        &db,
        &router,
        Operation::LegacyWatchdog,
        now + 60,
        deployed_peer,
    )
    .unwrap();
    assert_eq!(v4(&router), "awg1");
    assert_eq!(
        router
            .v6
            .0
            .lock()
            .unwrap()
            .forward("fd00::3", "2620:fe::fe"),
        "awg1"
    );
    assert!(!router.v6.0.lock().unwrap().fence);

    nfqws2_awg_profile::select(&db, "awg0").unwrap();
    {
        let mut kernel = router.v4.0.lock().unwrap();
        kernel.fail_after = Some(kernel.changes + 1);
    }
    let only_original = |cfg: &Value, iface: &str| {
        if iface == "awg1" {
            return Err(io::ErrorKind::NotConnected.into());
        }
        deployed_peer(cfg, iface)
    };
    assert!(operate_at(
        &db,
        &router,
        Operation::LegacyWatchdog,
        now + 120,
        only_original
    )
    .is_err());
    let parked = Journal::read(&db).unwrap();
    assert_eq!(parked.committed, origin);
    assert!(parked.preparing.is_empty());
    assert!(!parked.installed.fully_live());
    assert_ne!(v4(&router), "awg1");
    assert!(router.v6.0.lock().unwrap().fence);
    assert_eq!(
        router
            .v6
            .0
            .lock()
            .unwrap()
            .forward("fd00::3", "2620:fe::fe"),
        "unreachable"
    );
    operate_at(
        &db,
        &router,
        Operation::LegacyWatchdog,
        now + 180,
        only_original,
    )
    .unwrap();
    assert_eq!(v4(&router), "awg0");
    assert_eq!(
        router
            .v6
            .0
            .lock()
            .unwrap()
            .forward("fd00::3", "2620:fe::fe"),
        "awg0"
    );
}
