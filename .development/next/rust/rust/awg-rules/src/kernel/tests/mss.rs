use super::*;
use crate::kernel::plan::{Family, LegacyFull};

fn expected(family: Family, n: u16) -> BTreeSet<(Family, String)> {
    ["-i", "-o"].into_iter().map(|dir| (family, format!(
        "-A FORWARD {dir} awg0 -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment n2s-awg-cidr -j TCPMSS --set-mss {n}"
    ))).collect()
}

fn mss_lines(p: &Plan) -> BTreeSet<(Family, String)> {
    objects(p)
        .iter()
        .filter(|o| o.mss_rule())
        .map(|o| {
            let (_, chain, spec) = o.xtables().unwrap();
            (o.family(), format!("-A {chain} {}", spec.join(" ")))
        })
        .collect()
}

#[test]
fn keenetic_mss_matches_both_go_families_directions_and_nested_transport_mtu() {
    let (dir, db, _) = setup();
    let mut doc = nfqws2_awg_profile::read(&db).unwrap();
    doc["servers"][0]["config"]["mtu"] = json!(1420);
    let intent = plan::compile(&doc, None, false).unwrap();
    let device = dir.path().join("sys/class/net/awg0");
    std::fs::create_dir_all(&device).unwrap();
    let nested = |c: &Value, iface: &str| {
        let live = peer(c, iface)?;
        LivePeer::from_uapi(
            dir.path(),
            iface,
            live.endpoint,
            live.allowed,
            0xa000_0001,
            true,
        )
    };
    assert!(nested(&doc, "awg0").is_err());
    std::fs::write(device.join("mtu"), "7\n").unwrap();
    assert!(nested(&doc, "awg0").is_err());
    std::fs::write(device.join("mtu"), "1280\n").unwrap();
    let mut multi = plan::resolve(&doc, intent.clone(), false, None, peer)
        .unwrap()
        .plan;
    multi.go_ipv4 = true;
    assert_eq!(mss_lines(&multi), expected(Family::V4, 1380));
    let mut inner = plan::resolve(&doc, intent, false, None, nested)
        .unwrap()
        .plan;
    assert_eq!(inner.targets["awg0"].mtu, 1420);
    assert_eq!(mss_lines(&inner), expected(Family::V4, 1240));
    inner.legacy_full = Some(LegacyFull::Ipv4Only);
    assert_eq!(mss_lines(&inner), expected(Family::V4, 1240));
    let both = expected(Family::V4, 1240)
        .into_iter()
        .chain(expected(Family::V6, 1240))
        .collect();
    inner.legacy_full = Some(LegacyFull::ForwardReject {
        wan: "wan0".into(),
        ipv6_endpoint: false,
    });
    assert_eq!(mss_lines(&inner), both);
    inner.legacy_full = Some(LegacyFull::Dual);
    inner.prefixes.insert(Family::V6.any(), "awg0".into());
    assert_eq!(mss_lines(&inner), both);
    redundant_policy(&db, true);
    let doc = nfqws2_awg_profile::read(&db).unwrap();
    let intent = plan::compile(&doc, None, false).unwrap();
    let mut hot = plan::resolve(&doc, intent, false, None, |c, iface| {
        if matches!(iface, "awg0" | "awg1") {
            both_peers(c, iface)
        } else {
            Err(io::ErrorKind::NotConnected.into())
        }
    })
    .unwrap()
    .plan;
    assert!(hot.selected.is_empty());
    hot.go_ipv4 = true;
    let lines = mss_lines(&hot);
    assert_eq!(lines.len(), 4);
    assert_eq!(
        lines
            .iter()
            .filter(|(_, line)| line.contains(" awg1 "))
            .count(),
        2
    );
    assert!(mss_lines(&hot.guards_only()).is_empty());
}

#[test]
fn old_pmtu_receipt_survives_each_lost_ack_and_clean_stop_preserves_downgrade() {
    const FOREIGN: &str =
        "-A FORWARD -o awg0 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1190";
    for failed in 1..=3 {
        let (_dir, db, router) = setup();
        let doc = nfqws2_awg_profile::read(&db).unwrap();
        let mut legacy = plan::build(&db, &doc, None, false, &kernel(&router), peer)
            .unwrap()
            .0;
        legacy.mss.clear();
        let snapshot: Snapshot = legacy.into();
        let old = Journal {
            boot: BOOT.into(),
            installed: snapshot.clone(),
            committed: snapshot,
            ..Default::default()
        };
        assert!(!serde_json::to_string(&old).unwrap().contains("\"mss\""));
        let shape = objects(&old.installed);
        let old_mss = shape.iter().filter(|o| o.mss_rule()).collect::<Vec<_>>();
        let (_, _, spec) = old_mss[0].xtables().unwrap();
        assert_eq!(old_mss.len(), 1);
        assert!(spec.starts_with(&[
            "-d".into(),
            "203.0.113.0/24".into(),
            "-o".into(),
            "awg0".into()
        ]));
        assert_eq!(spec.last().unwrap(), "--clamp-mss-to-pmtu");
        db.transaction(|tx| switch_routes(&db, tx, &router, &Default::default(), &old, None))
            .unwrap();
        let before = {
            let mut fw = router.0.lock().unwrap();
            fw.firewall
                .get_mut("mangle")
                .unwrap()
                .insert(FOREIGN.into());
            fw.fail_after = Some(fw.changes + failed);
            fw.firewall.clone()
        };
        assert!(action(&db, &router, Operation::Refresh, 10).is_err());
        assert_eq!(router.0.lock().unwrap().firewall, before);
        assert_eq!(Journal::read(&db).unwrap(), old);
        let count = router.0.lock().unwrap().changes;
        action(&db, &router, Operation::Refresh, 11).unwrap();
        let new = Journal::read(&db).unwrap();
        assert_eq!(new.committed, new.installed);
        assert_eq!(new.installed.mss.len(), 1);
        {
            let fw = router.0.lock().unwrap();
            assert_eq!(
                fw.changes - count,
                3,
                "MSS update must keep the active route and lookup"
            );
            assert!(fw.firewall["mangle"].contains(FOREIGN));
        }
        // A failed downgrade of the dataplane reinstates both fixed rules
        // even when the old filter reached the kernel before the error.
        let current = router.0.lock().unwrap().firewall.clone();
        {
            let mut fw = router.0.lock().unwrap();
            fw.fail_after = Some(fw.changes + failed);
        }
        assert!(db
            .transaction(|tx| switch_routes(&db, tx, &router, &new, &old, None))
            .is_err());
        assert_eq!(router.0.lock().unwrap().firewall, current);
        assert_eq!(Journal::read(&db).unwrap(), new);
        action(&db, &router, Operation::Suspend, 12).unwrap();
        let suspended = Journal::read(&db).unwrap();
        assert!(suspended.installed.empty() && suspended.preparing.is_empty());
        assert_eq!(suspended.committed, old.committed);
        assert_eq!(
            router.0.lock().unwrap().firewall["mangle"],
            BTreeSet::from([FOREIGN.into()])
        );
    }
}

#[test]
fn routed_primary_port_edit_needs_exact_owned_tuple_and_kernel_ack() {
    use nfqws2_awg_profile::{RoutedEndpointEdit, RoutedMtuChange, RoutedMtuPeer};
    let (dir, db, router) = setup();
    protect(&db);
    const OLD: &str = "198.51.100.10:443";
    const NEW: &str = "198.51.100.10:51820";
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["config"]["mtu"] = json!(1420);
        doc["servers"][0]["config"]["endpoint"] = json!(OLD);
        Ok(())
    })
    .unwrap();
    let now = nfqws2_awg_profile::now();
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &router, op, now, peer).unwrap();
    }
    let baseline = Journal::read(&db).unwrap();
    let change = RoutedMtuChange {
        id: baseline.committed.targets["awg0"].id.clone(),
        iface: "awg0".into(),
        revision: baseline.committed.revision,
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
            resolved_after: vec![],
        }),
    };
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["config"]["endpoint"] = json!(NEW);
        doc["servers"][0]["rust_pending_routed_mtu"] = json!(change);
        doc["servers"][0]["rust_pending_client_profile"] = json!(vec![0_u8; 32]);
        Ok(())
    })
    .unwrap();
    router.0.lock().unwrap().mtu.insert("awg0".into(), 1420);
    assert_eq!(path(&router, "203.0.113.12"), "awg0");
    prepare_mtu_edit(&db, &router, &change).unwrap();
    assert_eq!(path(&router, "203.0.113.12"), "blackhole");
    let authority = mtu_edit::read(&db).unwrap().unwrap();
    let db = Store::open(dir.path()).unwrap();
    let desired = |config: &Value, iface: &str| {
        Ok(LivePeer {
            endpoint: NEW.parse().unwrap(),
            ..peer(config, iface)?
        })
    };
    let must_wait = |_: &RoutedMtuChange, _: &LivePeer| -> io::Result<Option<RoutedMtuPeer>> {
        panic!("must not consult process proof before the launch and exact port are known")
    };
    let recover = |peer, prove| {
        operate_with_redirect_and_mtu(&db, &router, Operation::Recover, None, None, peer, prove)
    };
    recover(desired, must_wait).unwrap();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]
            .as_object_mut()
            .unwrap()
            .remove("rust_pending_client_profile");
        Ok(())
    })
    .unwrap();
    operate_with_redirect_and_mtu(
        &db,
        &router,
        Operation::Recover,
        None,
        None,
        peer,
        must_wait,
    )
    .unwrap();
    // Same MTU and the expected public key are insufficient without the
    // generation receipt, even when the endpoint in UAPI changed.
    operate(&db, &router, Operation::Recover, desired).unwrap();
    assert_eq!(path(&router, "203.0.113.12"), "blackhole");
    let proof = |saved: &RoutedMtuChange, live: &LivePeer| {
        assert_eq!(saved, &change);
        Ok(Some(RoutedMtuPeer {
            iface: change.iface.clone(),
            outer_id: String::new(),
            outer_iface: String::new(),
            endpoint: live.endpoint,
            effective_mtu: 1420,
            socket_mark: live.socket_mark,
        }))
    };
    operate_with_redirect_and_mtu(
        &db,
        &router,
        Operation::Recover,
        None,
        None,
        desired,
        |saved, live| {
            let mut stale = proof(saved, live)?.unwrap();
            stale.endpoint = OLD.parse().unwrap();
            Ok(Some(stale))
        },
    )
    .unwrap();
    assert_eq!(path(&router, "203.0.113.12"), "blackhole");
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]
            .as_object_mut()
            .unwrap()
            .remove("rust_pending_routed_mtu");
        Ok(())
    })
    .unwrap();
    recover(desired, must_wait).unwrap();
    assert_eq!(path(&router, "203.0.113.12"), "blackhole");
    // An explicit rollback to the saved old tuple can restore its proved
    // owner. The same old peer was insufficient while the desired port was new.
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["config"]["endpoint"] = json!(OLD);
        Ok(())
    })
    .unwrap();
    operate_with_redirect_and_mtu(&db, &router, Operation::Recover, None, None, peer, proof)
        .unwrap();
    assert_eq!(path(&router, "203.0.113.12"), "awg0");
    assert!(!pending_mtu_edit(&db).unwrap());
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["config"]["endpoint"] = json!(NEW);
        doc["servers"][0]["rust_pending_routed_mtu"] = json!(change);
        Ok(())
    })
    .unwrap();
    prepare_mtu_edit(&db, &router, &change).unwrap();
    operate_with_redirect_and_mtu(&db, &router, Operation::Recover, None, None, desired, proof)
        .unwrap();
    assert_eq!(path(&router, "203.0.113.12"), "awg0");
    assert_eq!(Journal::read(&db).unwrap().committed, baseline.committed);
    assert!(nfqws2_awg_profile::pending_routed_mtu(
        &nfqws2_awg_profile::read(&db).unwrap()["servers"][0]
    )
    .unwrap()
    .is_none());
    assert!(!pending_mtu_edit(&db).unwrap());
    // The request already committed. A remaining acknowledgement record
    // must replay without a second FIB mutation.
    let mut replay = serde_json::to_value(authority).unwrap();
    replay["endpoint_committed"] = json!(true);
    db.transaction(|tx| tx.save_runtime("awg-routed-mtu.json", &replay))
        .unwrap();
    let writes = router.0.lock().unwrap().changes;
    operate_with_redirect_and_mtu(&db, &router, Operation::Refresh, None, None, desired, proof)
        .unwrap();
    assert_eq!(router.0.lock().unwrap().changes, writes);
    assert!(!pending_mtu_edit(&db).unwrap());

    // Crash after the forward FIB commit and its acknowledgement, but
    // before clearing the profile marker. The exact remembered port remains
    // a valid undo even if the next attempt to reinstall the FIB fails.
    db.transaction(|tx| tx.save_runtime("awg-routed-mtu.json", &replay))
        .unwrap();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["rust_pending_routed_mtu"] = json!(change);
        Ok(())
    })
    .unwrap();
    validate_endpoint_edit(&db, &router, &change, &[]).unwrap();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["config"]["endpoint"] = json!(OLD);
        Ok(())
    })
    .unwrap();
    prepare_mtu_edit(&db, &router, &change).unwrap();
    assert_eq!(path(&router, "203.0.113.12"), "blackhole");
    recover(desired, must_wait).unwrap();
    assert_eq!(path(&router, "203.0.113.12"), "blackhole");
    {
        let mut fw = router.0.lock().unwrap();
        fw.fail_after = Some(fw.changes + 1);
    }
    assert!(
        operate_with_redirect_and_mtu(&db, &router, Operation::Recover, None, None, peer, proof)
            .is_err(),
    );
    assert!(pending_mtu_edit(&db).unwrap());
    assert_eq!(path(&router, "203.0.113.12"), "blackhole");
    operate_with_redirect_and_mtu(&db, &router, Operation::Recover, None, None, peer, proof)
        .unwrap();
    assert_eq!(path(&router, "203.0.113.12"), "awg0");
    assert_eq!(Journal::read(&db).unwrap().committed, baseline.committed);
    let doc = nfqws2_awg_profile::read(&db).unwrap();
    assert_eq!(doc["servers"][0]["config"]["endpoint"], OLD);
    assert!(nfqws2_awg_profile::pending_routed_mtu(&doc["servers"][0])
        .unwrap()
        .is_none());
    assert!(!pending_mtu_edit(&db).unwrap());
}
