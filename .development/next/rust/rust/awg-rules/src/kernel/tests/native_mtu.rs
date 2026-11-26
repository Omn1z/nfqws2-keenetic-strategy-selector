use super::*;
use nfqws2_awg_profile::{
    RoutedDirectBackup, RoutedEndpointLaunch, RoutedImplicitMtu, RoutedMtuChange, RoutedMtuPeer,
};

const ENDPOINT: &str = "198.51.100.10:443";
const LEARNED: &str = "192.0.2.8";

struct UnsupportedWan<'a>(&'a Fake);

impl Runner for UnsupportedWan<'_> {
    fn run(&self, program: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
        if matches!(
            (program, args),
            ("ip", ["-4", "route", "get", "198.51.100.10"])
        ) {
            return Err(io::ErrorKind::Unsupported.into());
        }
        self.0.run(program, args, deadline)
    }
}

struct MissingPrimary<'a>(&'a Fake);

impl Runner for MissingPrimary<'_> {
    fn run(&self, program: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
        if program == "ip" && args == ["-4", "route", "get", "198.51.100.30"] {
            return Err(io::ErrorKind::NotConnected.into());
        }
        self.0.run(program, args, deadline)
    }
}

#[test]
fn routed_native_mtu_inverse_restores_dns_mss_and_the_original_raw_value() {
    let wan = ["wan0".into()];
    for forward_committed in [false, true] {
        let (dir, db, router) = setup();
        let now = nfqws2_awg_profile::now();
        protect(&db);
        router.0.lock().unwrap().local = "2: br0 inet 192.168.1.1/24 scope global".into();
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["routing"]["domain_source"] = json!("dnsproxy");
            let cfg = &mut doc["servers"][0]["config"];
            cfg["install"] = json!("imported");
            cfg["endpoint"] = json!(ENDPOINT);
            cfg["mtu"] = json!(0);
            cfg["routing"]["mtu"] = json!(1420);
            cfg["routing"]["zones"][0]["domains"] = json!(["same-transport.example"]);
            cfg["client"]["rust_managed"] = json!(true);
            Ok(())
        })
        .unwrap();
        for op in [Operation::Apply, Operation::Commit] {
            operate_at(&db, &router, op, now, peer).unwrap();
        }
        learn_answer(
            &db,
            &router,
            Answer {
                revision: 1,
                zone: 0,
                addresses: &[LEARNED.parse().unwrap()],
                ttl: 600,
                qtype: 1,
            },
            peer,
            || Ok(()),
        )
        .unwrap();
        let baseline = Journal::read(&db).unwrap().committed;
        let change = RoutedMtuChange {
            id: baseline.targets["awg0"].id.clone(),
            iface: "awg0".into(),
            revision: baseline.revision,
            before: 1420,
            after: 1380,
            nested_outer: None,
            nested_endpoint: None,
            legacy_predecessor: None,
            implicit_before_mtu: Some(RoutedImplicitMtu::Zero),
            legacy_mtu_before_recorded: false,
            nested_mtu_before_recorded: false,
            native_mtu_endpoint: Some(ENDPOINT.parse().unwrap()),
            endpoint_edit: None,
        };
        let mut wrong_endpoint = change.clone();
        wrong_endpoint.native_mtu_endpoint = Some("198.51.100.10:51820".parse().unwrap());
        assert!(validate_endpoint_edit_launch(&db, &router, &wrong_endpoint, &wan).is_err());
        assert_ne!(
            validate_endpoint_edit_launch(&db, &router, &change, &["other-wan".into()])
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            validate_endpoint_edit_launch(&db, &UnsupportedWan(&router), &change, &wan)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Other
        );
        assert_eq!(
            validate_endpoint_edit_launch(&db, &router, &change, &wan).unwrap(),
            RoutedEndpointLaunch::Primary
        );
        let stage = |db: &Store, raw: u16, launch_pending: bool| {
            nfqws2_awg_profile::edit_document(db, |doc| {
                let row = &mut doc["servers"][0];
                row["config"]["mtu"] = json!(raw);
                row["rust_pending_routed_mtu"] = json!(change);
                if launch_pending {
                    row["rust_pending_client_profile"] = json!(vec![8_u8; 32]);
                } else {
                    row.as_object_mut()
                        .unwrap()
                        .remove("rust_pending_client_profile");
                }
                Ok(())
            })
            .unwrap();
        };
        let set_mtu = |mtu| router.0.lock().unwrap().mtu.insert("awg0".into(), mtu);
        let confirm = |db: &Store, endpoint: &str, mtu| {
            operate_with_redirect_and_mtu(
                db,
                &router,
                Operation::Recover,
                None,
                None,
                peer,
                |saved, live| {
                    assert_eq!(saved, &change);
                    Ok(Some(RoutedMtuPeer {
                        iface: saved.iface.clone(),
                        outer_id: String::new(),
                        outer_iface: String::new(),
                        endpoint: endpoint.parse().unwrap(),
                        effective_mtu: mtu,
                        socket_mark: live.socket_mark,
                    }))
                },
            )
            .unwrap();
        };
        stage(&db, change.after, true);
        if forward_committed {
            prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
            assert_eq!(path(&router, LEARNED), "blackhole");
            set_mtu(change.after);
            stage(&db, change.after, false);
            let receipt = json!(mtu_edit::read(&db).unwrap().unwrap());
            confirm(&db, ENDPOINT, change.after);
            let applied = Journal::read(&db).unwrap().committed;
            assert_eq!(applied.mss["awg0"], change.after - 40);
            assert_ne!(
                applied.learned.as_ref().unwrap().hash,
                baseline.learned.as_ref().unwrap().hash
            );
            stage(&db, change.after, false);
            db.transaction(|tx| tx.save_runtime_bounded("awg-routed-mtu.json", &receipt, 4096))
                .unwrap();
        } else {
            set_mtu(change.before);
            assert!(!pending_mtu_edit(&db).unwrap());
        }
        let db = Store::open(dir.path()).unwrap();
        validate_endpoint_edit(&db, &router, &change, &wan).unwrap();
        stage(&db, change.before, true);
        assert!(prepare_mtu_edit_with_wan(&db, &router, &change, &wan).is_err());
        stage(&db, 0, true);
        prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
        confirm(&db, ENDPOINT, change.before);
        assert_eq!(path(&router, LEARNED), "blackhole");
        stage(&db, 0, false);
        set_mtu(change.after);
        confirm(&db, ENDPOINT, change.before);
        set_mtu(change.before);
        confirm(&db, "198.51.100.10:51820", change.before);
        assert!(pending_mtu_edit(&db).unwrap());
        assert_eq!(path(&router, LEARNED), "blackhole");
        let receipt = json!(mtu_edit::read(&db).unwrap().unwrap());
        confirm(&db, ENDPOINT, change.before);
        assert_eq!(path(&router, LEARNED), "awg0");
        assert_eq!(Journal::read(&db).unwrap().committed, baseline);
        assert_eq!(
            nfqws2_awg_profile::read(&db).unwrap()["servers"][0]["config"]["mtu"],
            0
        );
        assert!(!pending_mtu_edit(&db).unwrap());
        db.transaction(|tx| tx.save_runtime_bounded("awg-routed-mtu.json", &receipt, 4096))
            .unwrap();
        confirm(&db, ENDPOINT, change.before);
        assert_eq!(path(&router, LEARNED), "awg0");
        assert!(!pending_mtu_edit(&db).unwrap());
    }
}

#[test]
fn routed_native_mtu_keeps_authenticated_reserve_when_primary_has_no_wan() {
    const PRIMARY: &str = "198.51.100.30:443";
    const SAME_IP_OTHER_PORT: &str = "198.51.100.30:8443";
    const EARLY: &str = "203.0.113.9";
    let wan = ["wan0".into()];
    let primary = PRIMARY.parse().unwrap();
    let reserve = ENDPOINT.parse().unwrap();
    for reversing in [false, true] {
        let (dir, db, router) = setup();
        let now = nfqws2_awg_profile::now();
        let runner = MissingPrimary(&router);
        protect(&db);
        let set_backups = |db: &Store, addresses: &[&str]| {
            nfqws2_awg_profile::edit_document(db, |doc| {
                doc["servers"][0]["config"]["client"]["endpoint_backups"] = json!(addresses);
                Ok(())
            })
            .unwrap();
        };
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["routing"]["domain_source"] = json!("dnsproxy");
            let cfg = &mut doc["servers"][0]["config"];
            cfg["install"] = json!("imported");
            cfg["endpoint"] = json!(PRIMARY);
            cfg["mtu"] = json!(1420);
            cfg["routing"]["zones"][0]["domains"] = json!(["reserve.example"]);
            cfg["client"]["rust_managed"] = json!(true);
            Ok(())
        })
        .unwrap();
        set_backups(&db, &[ENDPOINT]);
        router.0.lock().unwrap().local = "2: br0 inet 192.168.1.1/24 scope global".into();
        for op in [Operation::Apply, Operation::Commit] {
            operate_at(&db, &router, op, now, peer).unwrap();
        }
        learn_answer(
            &db,
            &router,
            Answer {
                revision: 1,
                zone: 0,
                addresses: &[LEARNED.parse().unwrap()],
                ttl: 600,
                qtype: 1,
            },
            peer,
            || Ok(()),
        )
        .unwrap();
        let baseline = Journal::read(&db).unwrap().committed;
        let change = RoutedMtuChange {
            id: baseline.targets["awg0"].id.clone(),
            iface: "awg0".into(),
            revision: baseline.revision,
            before: 1420,
            after: 1380,
            nested_outer: None,
            nested_endpoint: None,
            legacy_predecessor: None,
            implicit_before_mtu: None,
            legacy_mtu_before_recorded: false,
            nested_mtu_before_recorded: false,
            native_mtu_endpoint: Some(reserve),
            endpoint_edit: None,
        };
        let stage = |db: &Store, mtu, launched| {
            nfqws2_awg_profile::edit_document(db, |doc| {
                let row = &mut doc["servers"][0];
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
        set_backups(&db, &[SAME_IP_OTHER_PORT]);
        assert!(validate_endpoint_edit_launch(&db, &runner, &change, &wan).is_err());
        set_backups(&db, &[ENDPOINT]);
        assert_eq!(
            validate_endpoint_edit_launch(&db, &runner, &change, &wan).unwrap(),
            RoutedEndpointLaunch::Primary
        );
        stage(&db, change.after, false);
        prepare_mtu_edit_with_wan(&db, &runner, &change, &wan).unwrap();
        assert_eq!(path(&router, EARLY), "blackhole");
        let mtu = if reversing {
            validate_endpoint_edit_launch(&db, &runner, &change, &wan).unwrap();
            stage(&db, change.before, false);
            prepare_mtu_edit_with_wan(&db, &runner, &change, &wan).unwrap();
            change.before
        } else {
            change.after
        };
        if reversing {
            let mut interrupted = Journal::read(&db).unwrap();
            interrupted.preparing.push(interrupted.installed.clone());
            db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, &interrupted, RECEIPT_LIMIT))
                .unwrap();
        } else {
            *router.0.lock().unwrap() = Firmware {
                boot: "34343434-3434-3434-3434-343434343434".into(),
                ..Firmware::default()
            };
        }
        let db = Store::open(dir.path()).unwrap();
        operate_at(&db, &runner, Operation::Recover, now, |_, _| {
            Err(io::ErrorKind::NotConnected.into())
        })
        .unwrap();
        assert!(Journal::read(&db).unwrap().preparing.is_empty());
        assert_eq!(path(&router, EARLY), "blackhole");
        assert_eq!(path(&router, LEARNED), "blackhole");
        assert!(pending_mtu_edit(&db).unwrap());

        let set_mtu = |actual| router.0.lock().unwrap().mtu.insert("awg0".into(), actual);
        let evidence = |endpoint, effective_mtu| RoutedMtuPeer {
            iface: "awg0".into(),
            outer_id: String::new(),
            outer_iface: String::new(),
            endpoint,
            effective_mtu,
            socket_mark: 0,
        };
        let recover = |proof: RoutedMtuPeer| {
            operate_with_redirect_and_mtu(
                &db,
                &runner,
                Operation::Recover,
                None,
                None,
                peer,
                |saved, _| {
                    assert_eq!(saved, &change);
                    Ok(Some(proof.clone()))
                },
            )
        };
        set_mtu(mtu);
        recover(evidence(reserve, mtu)).unwrap(); // The launch marker is still pending.
        stage(&db, mtu, true);
        set_mtu(if reversing { change.after } else { change.before });
        recover(evidence(reserve, mtu)).unwrap();
        set_mtu(mtu);
        recover(evidence(primary, mtu)).unwrap();
        assert_eq!(path(&router, EARLY), "blackhole");
        set_backups(&db, &[ENDPOINT, SAME_IP_OTHER_PORT]);
        assert!(recover(evidence(reserve, mtu)).is_err());
        assert_eq!(path(&router, LEARNED), "blackhole");
        set_backups(&db, &[ENDPOINT]);
        recover(evidence(reserve, mtu)).unwrap();
        assert!(!pending_mtu_edit(&db).unwrap());
        assert_eq!(path(&router, LEARNED), "awg0");
        let settled = Journal::read(&db).unwrap().committed;
        assert_eq!(settled.revision, baseline.revision);
        assert_eq!(settled.targets["awg0"].mtu, mtu);
        assert_eq!(settled.mss["awg0"], mtu - 40);
        assert_eq!(
            settled.learned.as_ref().unwrap().hash == baseline.learned.as_ref().unwrap().hash,
            reversing
        );
        assert_eq!(
            nfqws2_awg_profile::read(&db).unwrap()["servers"][0]["config"]["endpoint"],
            PRIMARY
        );
        operate_at(&db, &runner, Operation::Refresh, now, |cfg, iface| {
            Ok(peer(cfg, iface)?.with_direct_backup(Some(RoutedDirectBackup {
                primary,
                peer: evidence(reserve, mtu),
            })))
        })
        .unwrap();
        assert_eq!(path(&router, LEARNED), "awg0");
    }
}
