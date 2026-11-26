use super::*;
use nfqws2_awg_profile::{
    RoutedEndpointEdit, RoutedEndpointLaunch, RoutedImplicitMtu, RoutedLegacyPredecessor,
    RoutedMtuChange, RoutedMtuPeer,
};
use std::net::{IpAddr, SocketAddr};

struct WanPaths<'a> {
    router: &'a Fake,
    new_wan: Option<IpAddr>,
    marked_device: Mutex<Option<&'static str>>,
    captured: Mutex<Option<IpAddr>>,
}

impl Runner for WanPaths<'_> {
    fn run(&self, program: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
        if let ("ip", ["-4", "route", "get", dest, rest @ ..]) = (program, args) {
            let ip = dest.parse::<IpAddr>().unwrap();
            if rest.is_empty() && *self.captured.lock().unwrap() == Some(ip) {
                return Ok(format!("{dest} dev awg0"));
            }
            if rest == ["mark", "0x20000000"] {
                if let Some(iface) = *self.marked_device.lock().unwrap() {
                    return Ok(format!("{dest} dev {iface}"));
                }
            }
            if self.new_wan == Some(ip) && (rest.is_empty() || rest == ["mark", "0x20000000"]) {
                return Ok(format!("{dest} dev wan1"));
            }
        }
        self.router.run(program, args, deadline)
    }
}

#[test]
fn routed_inherited_port_edit_requires_exact_native_ack_in_both_directions() {
    inherited_edit(None, "198.51.100.10:51820", None, None);
}

#[test]
fn routed_inherited_ip_edit_requires_exact_native_ack_and_preserves_shared_claims() {
    inherited_edit(None, "198.51.100.30:443", None, None);
}

#[test]
fn routed_inherited_hostname_uses_one_sealed_pin_through_native_promotion_and_undo() {
    inherited_edit(Some("localhost:443"), "198.51.100.30:443", None, None);
    inherited_edit(Some("localhost:443"), "198.51.100.10:51820", None, None);
}

#[test]
fn routed_inherited_numeric_endpoint_uses_fresh_hostname_pins_without_losing_cold_fences() {
    inherited_edit(None, "198.51.100.30:443", Some("new.invalid:443"), None);
}

#[test]
fn routed_inherited_name_and_literal_at_same_udp_tuple_require_new_owner() {
    inherited_edit(Some("localhost:443"), "198.51.100.10:443", None, None);
    inherited_edit(None, "198.51.100.10:443", Some("new.invalid:443"), None);
}

#[test]
fn routed_inherited_joint_endpoint_mtu_requires_exact_pair_and_restores_sources() {
    inherited_edit(None, "198.51.100.30:51820", None, Some(1380));
    inherited_edit(None, "198.51.100.10:51820", None, Some(1380));
}

const MTU_ENDPOINT: &str = "198.51.100.10:443";
const MTU_LEARNED: &str = "192.0.2.8";

fn inherited_mtu_fixture(
    record_implicit: bool,
) -> (tempfile::TempDir, Store, Fake, Snapshot, RoutedMtuChange) {
    let (dir, db, router) = setup();
    let now = nfqws2_awg_profile::now();
    protect(&db);
    router.0.lock().unwrap().local = "2: br0 inet 192.168.1.1/24 scope global".into();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"]["domain_source"] = json!("dnsproxy");
        let cfg = &mut doc["servers"][0]["config"];
        cfg["install"] = json!("imported");
        cfg["endpoint"] = json!(MTU_ENDPOINT);
        if record_implicit {
            cfg.as_object_mut().unwrap().remove("mtu");
            cfg["routing"]["mtu"] = json!(1420);
        } else {
            cfg["mtu"] = json!(1420);
        }
        cfg["routing"]["zones"][0]["domains"] = json!(["handover.example"]);
        cfg["client"]
            .as_object_mut()
            .unwrap()
            .remove("rust_managed");
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
            addresses: &[MTU_LEARNED.parse().unwrap()],
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
        legacy_predecessor: Some(RoutedLegacyPredecessor {
            endpoint: MTU_ENDPOINT.parse().unwrap(),
            receipt_sha256: [7; 32],
        }),
        native_mtu_endpoint: None,
        legacy_mtu_before_recorded: record_implicit,
        nested_mtu_before_recorded: false,
        implicit_before_mtu: record_implicit.then_some(RoutedImplicitMtu::Missing),
        endpoint_edit: None,
    };
    (dir, db, router, baseline, change)
}

fn probe_inherited_mtu(
    db: &Store,
    router: &Fake,
    change: &RoutedMtuChange,
    endpoint: &str,
    mtu: u16,
) {
    operate_with_redirect_and_mtu(
        db,
        router,
        Operation::Recover,
        None,
        None,
        peer,
        |saved, live| {
            assert_eq!(saved, change);
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
}

fn acknowledge_native(db: &Store) {
    nfqws2_awg_profile::edit_document(db, |doc| {
        let row = &mut doc["servers"][0];
        row.as_object_mut()
            .unwrap()
            .remove("rust_pending_client_profile");
        row["config"]["client"]["rust_managed"] = json!(true);
        Ok(())
    })
    .unwrap();
}

#[test]
fn routed_inherited_mtu_edit_requires_exact_native_ack_at_the_same_endpoint() {
    let (dir, db, router, baseline, change) = inherited_mtu_fixture(false);
    let wan = ["wan0".into()];
    let mut wrong_pin = change.clone();
    wrong_pin.legacy_predecessor.as_mut().unwrap().endpoint = "198.51.100.20:443".parse().unwrap();
    assert!(validate_endpoint_edit_launch(&db, &router, &wrong_pin, &wan).is_err());
    assert!(validate_endpoint_edit_launch(&db, &router, &change, &["wrong-wan".into()]).is_err());
    assert_eq!(
        validate_endpoint_edit_launch(&db, &router, &change, &wan).unwrap(),
        RoutedEndpointLaunch::Primary
    );
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let row = &mut doc["servers"][0];
        row["config"]["mtu"] = json!(change.after);
        row["rust_pending_routed_mtu"] = json!(change);
        row["rust_pending_client_profile"] = json!(vec![7_u8; 32]);
        Ok(())
    })
    .unwrap();
    assert!(validate_endpoint_edit(&db, &router, &change, &wan).is_err());
    assert!(prepare_mtu_edit_with_wan(&db, &router, &change, &["wrong-wan".into()]).is_err());
    assert_eq!(path(&router, MTU_LEARNED), "awg0");
    assert!(!pending_mtu_edit(&db).unwrap());
    prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
    assert_eq!(path(&router, MTU_LEARNED), "blackhole");
    let db = Store::open(dir.path()).unwrap();
    let confirm = |endpoint: &str, mtu| probe_inherited_mtu(&db, &router, &change, endpoint, mtu);
    router
        .0
        .lock()
        .unwrap()
        .mtu
        .insert("awg0".into(), change.after);
    confirm(MTU_ENDPOINT, change.after);
    assert_eq!(path(&router, MTU_LEARNED), "blackhole");
    acknowledge_native(&db);
    confirm("198.51.100.10:51820", change.after);
    confirm(MTU_ENDPOINT, change.before);
    assert_eq!(path(&router, MTU_LEARNED), "blackhole");
    let receipt = json!(mtu_edit::read(&db).unwrap().unwrap());
    assert!(pending_mtu_edit(&db).unwrap());
    confirm(MTU_ENDPOINT, change.after);
    assert_eq!(path(&router, MTU_LEARNED), "awg0");
    let settled = Journal::read(&db).unwrap().committed;
    assert_eq!(settled.targets["awg0"].mtu, change.after);
    assert_eq!(settled.mss["awg0"], change.after - 40);
    assert_eq!(settled.revision, baseline.revision);
    let before = baseline.learned.as_ref().unwrap();
    let after = settled.learned.as_ref().unwrap();
    assert_ne!(after.hash, before.hash);
    assert_eq!(after.members, before.members);
    assert!(!pending_mtu_edit(&db).unwrap());
    assert!(receipt.get("endpoint_committed").is_none());
    db.transaction(|tx| tx.save_runtime_bounded("awg-routed-mtu.json", &receipt, 4096))
        .unwrap();
    confirm(MTU_ENDPOINT, change.after);
    assert_eq!(path(&router, MTU_LEARNED), "awg0");
    assert!(!pending_mtu_edit(&db).unwrap());
}

#[test]
fn routed_inherited_mtu_inverse_restores_exact_dns_mss_and_saved_mtu() {
    let wan = ["wan0".into()];
    for forward_committed in [false, true] {
        let (dir, db, router, baseline, change) = inherited_mtu_fixture(true);
        let set_mtu = |mtu| router.0.lock().unwrap().mtu.insert("awg0".into(), mtu);
        let save_forward = |launch_pending: bool| {
            nfqws2_awg_profile::edit_document(&db, |doc| {
                let row = &mut doc["servers"][0];
                row["config"]["mtu"] = json!(change.after);
                row["rust_pending_routed_mtu"] = json!(change);
                if launch_pending {
                    row["rust_pending_client_profile"] = json!(vec![7_u8; 32]);
                }
                Ok(())
            })
            .unwrap();
        };
        validate_endpoint_edit(&db, &router, &change, &wan).unwrap();
        save_forward(true);
        if forward_committed {
            prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
            set_mtu(change.after);
            acknowledge_native(&db);
            let authority = json!(mtu_edit::read(&db).unwrap().unwrap());
            probe_inherited_mtu(&db, &router, &change, MTU_ENDPOINT, change.after);
            assert_eq!(
                Journal::read(&db).unwrap().committed.mss["awg0"],
                change.after - 40
            );
            save_forward(false);
            db.transaction(|tx| tx.save_runtime_bounded("awg-routed-mtu.json", &authority, 4096))
                .unwrap();
        } else {
            set_mtu(change.before);
            assert!(!pending_mtu_edit(&db).unwrap());
        }

        let db = Store::open(dir.path()).unwrap();
        let mut changed_token = change.clone();
        changed_token.implicit_before_mtu = None;
        assert!(validate_endpoint_edit(&db, &router, &changed_token, &wan).is_err());
        validate_endpoint_edit(&db, &router, &change, &wan).unwrap();
        let save_old = |explicit: bool| {
            nfqws2_awg_profile::edit_document(&db, |doc| {
                let row = &mut doc["servers"][0];
                if explicit {
                    row["config"]["mtu"] = json!(change.before);
                } else {
                    row["config"].as_object_mut().unwrap().remove("mtu");
                }
                row["rust_pending_client_profile"] = json!(vec![8_u8; 32]);
                Ok(())
            })
            .unwrap();
        };
        save_old(true);
        assert!(prepare_mtu_edit_with_wan(&db, &router, &change, &wan).is_err());
        save_old(false);
        prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
        assert_eq!(path(&router, MTU_LEARNED), "blackhole");
        probe_inherited_mtu(&db, &router, &change, MTU_ENDPOINT, change.before);
        assert_eq!(path(&router, MTU_LEARNED), "blackhole");
        acknowledge_native(&db);
        set_mtu(change.after);
        probe_inherited_mtu(&db, &router, &change, MTU_ENDPOINT, change.before);
        assert_eq!(path(&router, MTU_LEARNED), "blackhole");
        set_mtu(change.before);
        probe_inherited_mtu(&db, &router, &change, "198.51.100.10:51820", change.before);
        assert!(pending_mtu_edit(&db).unwrap());
        assert_eq!(path(&router, MTU_LEARNED), "blackhole");

        let authority = json!(mtu_edit::read(&db).unwrap().unwrap());
        probe_inherited_mtu(&db, &router, &change, MTU_ENDPOINT, change.before);
        assert_eq!(path(&router, MTU_LEARNED), "awg0");
        assert_eq!(Journal::read(&db).unwrap().committed, baseline);
        assert!(
            nfqws2_awg_profile::read(&db).unwrap()["servers"][0]["config"]
                .get("mtu")
                .is_none()
        );
        assert!(!pending_mtu_edit(&db).unwrap());
        db.transaction(|tx| tx.save_runtime_bounded("awg-routed-mtu.json", &authority, 4096))
            .unwrap();
        probe_inherited_mtu(&db, &router, &change, MTU_ENDPOINT, change.before);
        assert_eq!(path(&router, MTU_LEARNED), "awg0");
        assert!(!pending_mtu_edit(&db).unwrap());
    }
}

fn inherited_edit(
    old_name: Option<&str>,
    new_endpoint: &str,
    new_name: Option<&str>,
    changed_mtu: Option<u16>,
) {
    const OLD: &str = "198.51.100.10:443";
    const PAYLOAD: &str = "203.0.113.12";
    const LEARNED: &str = "192.0.2.8";
    const LIST_IP: &str = "203.0.113.14/32";
    const CHANGED_LIST_IP: &str = "192.0.2.24/32";
    let wan = ["wan0".into(), "wan1".into()];
    let old_socket: SocketAddr = OLD.parse().unwrap();
    let new_socket: SocketAddr = new_endpoint.parse().unwrap();
    let old_config = old_name.unwrap_or(OLD);
    let new_config = new_name.unwrap_or(new_endpoint);
    let unused = SocketAddr::new("198.51.100.93".parse().unwrap(), new_socket.port());
    let aaaa = SocketAddr::new("2001:db8:34::93".parse().unwrap(), new_socket.port());
    let address_edit = old_socket.ip() != new_socket.ip();
    let same_socket = old_socket == new_socket;
    let named_edit = old_name.is_some() || new_name.is_some();
    let with_sources = address_edit || same_socket;
    let conflicting_mark = if address_edit { "wan0" } else { "wan1" };
    for restore in [false, true] {
        let (dir, db, router) = setup();
        let run = WanPaths {
            router: &router,
            new_wan: address_edit.then_some(new_socket.ip()),
            marked_device: Mutex::default(),
            captured: Mutex::default(),
        };
        let shared = if restore { new_socket } else { old_socket };
        protect(&db);
        nfqws2_awg_profile::edit_document(&db, |doc| {
            let cfg = &mut doc["servers"][0]["config"];
            cfg["install"] = json!("imported");
            cfg["endpoint"] = json!(old_config);
            cfg["mtu"] = json!(if changed_mtu.is_some() { 0 } else { 1420 });
            if changed_mtu.is_some() {
                cfg["routing"]["mtu"] = json!(1420);
            }
            cfg["client"]
                .as_object_mut()
                .unwrap()
                .remove("rust_managed");
            if with_sources {
                cfg["routing"]["zones"][0]["domains"] =
                    json!(["list:r50", "endpoint-regression.example"]);
                doc["routing"]["domain_source"] = json!("dnsproxy");
            }
            if address_edit {
                let mut independent = doc["servers"][0].clone();
                independent["id"] = json!("other-transport");
                independent["config"]["client_iface"] = json!("awg9");
                independent["config"]["endpoint"] = json!(SocketAddr::new(shared.ip(), 9998));
                independent["config"]["routing"]["zones"] = json!([]);
                doc["servers"].as_array_mut().unwrap().push(independent);
            }
            Ok(())
        })
        .unwrap();
        let source =
            |db: &Store, ip: &str| crate::sources::stage(db, |_, _| Ok(vec![ip.into()])).unwrap();
        if with_sources {
            router.0.lock().unwrap().local = "2: br0 inet 192.168.1.1/24 scope global".into();
            source(&db, LIST_IP);
        }
        let now = nfqws2_awg_profile::now();
        for op in [Operation::Apply, Operation::Commit] {
            operate_at(&db, &run, op, now, peer).unwrap();
        }
        if with_sources {
            learn_answer(
                &db,
                &run,
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
        }
        router.0.lock().unwrap().mtu.insert("awg0".into(), 1420);
        let committed = Journal::read(&db).unwrap().committed;
        let change = RoutedMtuChange {
            id: committed.targets["awg0"].id.clone(),
            iface: "awg0".into(),
            revision: committed.revision,
            before: 1420,
            after: changed_mtu.unwrap_or(1420),
            nested_outer: None,
            nested_endpoint: None,
            native_mtu_endpoint: None,
            legacy_mtu_before_recorded: false,
            nested_mtu_before_recorded: false,
            implicit_before_mtu: changed_mtu.map(|_| RoutedImplicitMtu::Zero),
            legacy_predecessor: Some(RoutedLegacyPredecessor {
                endpoint: old_socket,
                receipt_sha256: [7; 32],
            }),
            endpoint_edit: Some(RoutedEndpointEdit {
                before: old_config.into(),
                after: new_config.into(),
                previous_reserve: None,
                resolved_before: old_name.map(|_| old_socket).into_iter().collect(),
                resolved_after: if new_name.is_some() {
                    vec![aaaa, new_socket, unused]
                } else {
                    vec![]
                },
            }),
        };
        let mut forged = change.clone();
        let wrong_port = SocketAddr::new(old_socket.ip(), old_socket.port() + 1);
        forged.legacy_predecessor.as_mut().unwrap().endpoint =
            if same_socket { wrong_port } else { new_socket };
        assert!(validate_endpoint_edit_launch(&db, &run, &forged, &wan).is_err());
        forged.legacy_predecessor = change.legacy_predecessor.clone();
        forged.legacy_predecessor.as_mut().unwrap().receipt_sha256 = [0; 32];
        assert!(validate_endpoint_edit_launch(&db, &run, &forged, &wan).is_err());
        assert!(validate_endpoint_edit_launch(&db, &run, &change, &["other-wan".into()]).is_err());
        if old_name.is_some() {
            let mut altered = change.clone();
            altered.endpoint_edit.as_mut().unwrap().before = "other.invalid:443".into();
            assert!(validate_endpoint_edit_launch(&db, &run, &altered, &wan).is_err());
            let mut altered = change.clone();
            altered
                .endpoint_edit
                .as_mut()
                .unwrap()
                .resolved_before
                .push("198.51.100.11:443".parse().unwrap());
            assert!(validate_endpoint_edit_launch(&db, &run, &altered, &wan).is_err());
            if address_edit {
                let mut altered = change.clone();
                let learned = SocketAddr::new(LEARNED.parse().unwrap(), old_socket.port());
                altered.legacy_predecessor.as_mut().unwrap().endpoint = learned;
                altered.endpoint_edit.as_mut().unwrap().resolved_before = vec![learned];
                assert!(validate_endpoint_edit_launch(&db, &run, &altered, &wan).is_err());
            }
            let set_backups = |values: &[&str]| {
                nfqws2_awg_profile::edit_document(&db, |doc| {
                    doc["servers"][0]["config"]["client"]["endpoint_backups"] = json!(values);
                    Ok(())
                })
                .unwrap();
            };
            set_backups(&["198.51.100.10:5555"]);
            assert!(validate_endpoint_edit_launch(&db, &run, &change, &wan).is_err());
            set_backups(&[]);
        }
        if new_name.is_some() {
            assert_eq!(
                change.endpoint_edit.as_ref().unwrap().sockets().unwrap(),
                (old_socket, new_socket)
            );
            for captured in [PAYLOAD, LEARNED] {
                let mut alleged = change.clone();
                alleged
                    .endpoint_edit
                    .as_mut()
                    .unwrap()
                    .resolved_after
                    .push(SocketAddr::new(
                        captured.parse().unwrap(),
                        new_socket.port(),
                    ));
                assert!(validate_endpoint_edit_launch(&db, &run, &alleged, &wan).is_err());
            }
            let mut missing_a = change.clone();
            missing_a.endpoint_edit.as_mut().unwrap().resolved_after = vec![aaaa];
            assert!(validate_endpoint_edit_launch(&db, &run, &missing_a, &wan).is_err());
            let mut literals = change.clone();
            let edit = literals.endpoint_edit.as_mut().unwrap();
            edit.after = "[::ffff:198.51.100.10]:443".into();
            edit.resolved_after.clear();
            assert!(validate_endpoint_edit_launch(&db, &run, &literals, &wan).is_err());
        }
        if address_edit {
            let mut invalid = change.clone();
            for endpoint in ["203.0.113.12:443", "192.0.2.8:443", "[2001:db8::30]:443"] {
                invalid.endpoint_edit.as_mut().unwrap().after = endpoint.into();
                assert!(validate_endpoint_edit_launch(&db, &run, &invalid, &wan).is_err());
            }
        }
        if address_edit || named_edit {
            *run.marked_device.lock().unwrap() = Some(conflicting_mark);
            assert!(validate_endpoint_edit_launch(&db, &run, &change, &wan).is_err());
            *run.marked_device.lock().unwrap() = None;
        }
        if with_sources {
            assert!(committed.local_sources.is_some());
            source(&db, CHANGED_LIST_IP);
            assert!(validate_endpoint_edit_launch(&db, &run, &change, &wan).is_err());
            source(&db, LIST_IP);
        }
        assert_eq!(
            validate_endpoint_edit_launch(&db, &run, &change, &wan).unwrap(),
            RoutedEndpointLaunch::Primary
        );
        let stable = Journal::read(&db).unwrap();
        let mut stale = stable.clone();
        stale.installed.revision += 1;
        db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, &stale, RECEIPT_LIMIT))
            .unwrap();
        assert!(validate_endpoint_edit_launch(&db, &run, &change, &wan).is_err());
        db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, &stable, RECEIPT_LIMIT))
            .unwrap();
        assert_eq!(path(&router, PAYLOAD), "awg0");
        let stage = |db: &Store, endpoint: &str, marker: &RoutedMtuChange| {
            nfqws2_awg_profile::edit_document(db, |doc| {
                let row = &mut doc["servers"][0];
                if marker.combines_endpoint_mtu() {
                    marker.rewrite_combined_endpoint_mtu(row, endpoint == new_config)?;
                } else {
                    row["config"]["endpoint"] = json!(endpoint);
                }
                row["rust_pending_routed_mtu"] = json!(marker);
                row["rust_pending_client_profile"] = json!(vec![7_u8; 32]);
                Ok(())
            })
            .unwrap();
        };
        stage(&db, new_config, &change);
        if address_edit || named_edit {
            *run.marked_device.lock().unwrap() = Some(conflicting_mark);
            assert!(prepare_mtu_edit_with_wan(&db, &run, &change, &wan).is_err());
            assert_eq!(path(&router, PAYLOAD), "awg0");
            assert!(!pending_mtu_edit(&db).unwrap());
            *run.marked_device.lock().unwrap() = None;
        }
        let restore_before_prepare = restore && changed_mtu.is_some();
        if restore_before_prepare {
            validate_endpoint_edit(&db, &run, &change, &wan).unwrap();
            stage(&db, old_config, &change);
        }
        prepare_mtu_edit_with_wan(&db, &run, &change, &wan).unwrap();
        assert_eq!(path(&router, PAYLOAD), "blackhole");
        assert_eq!(
            pending_endpoint_launch(&db, &run, &change, &wan)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        let db = Store::open(dir.path()).unwrap();
        if restore && !restore_before_prepare {
            validate_endpoint_edit(&db, &run, &change, &wan).unwrap();
            stage(&db, old_config, &change);
            prepare_mtu_edit_with_wan(&db, &run, &change, &wan).unwrap();
        }
        if named_edit && address_edit {
            if restore {
                let mut interrupted = Journal::read(&db).unwrap();
                interrupted.preparing.push(interrupted.installed.clone());
                db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, &interrupted, RECEIPT_LIMIT))
                    .unwrap();
            } else {
                let mut fw = router.0.lock().unwrap();
                *fw = Firmware {
                    boot: "34343434-3434-3434-3434-343434343434".into(),
                    local: fw.local.clone(),
                    mtu: fw.mtu.clone(),
                    ..Firmware::default()
                };
            }
            let disconnected = |_: &Value, _: &str| Err(io::ErrorKind::NotConnected.into());
            if new_name.is_some() && !restore {
                *run.captured.lock().unwrap() = Some(unused.ip());
                nfqws2_awg_profile::edit_document(&db, |doc| {
                    let rows = doc["servers"].as_array_mut().unwrap();
                    let mut independent = rows[1].clone();
                    independent["id"] = json!("shares-unused-hostname-answer");
                    independent["config"]["client_iface"] = json!("awg8");
                    independent["config"]["endpoint"] = json!(SocketAddr::new(unused.ip(), 8443));
                    rows.push(independent);
                    Ok(())
                })
                .unwrap();
                assert!(operate_at(&db, &run, Operation::Recover, now, disconnected).is_err());
                nfqws2_awg_profile::edit_document(&db, |doc| {
                    doc["servers"].as_array_mut().unwrap().pop();
                    Ok(())
                })
                .unwrap();
                assert!(
                    operate_at(&db, &run, Operation::Recover, now, |cfg, iface| {
                        Ok(LivePeer {
                            endpoint: unused,
                            ..peer(cfg, iface)?
                        })
                    })
                    .is_err()
                );
            }
            operate_at(&db, &run, Operation::Recover, now, disconnected).unwrap();
            assert!(Journal::read(&db).unwrap().preparing.is_empty());
            assert_eq!(path(&router, PAYLOAD), "blackhole");
            *run.captured.lock().unwrap() = None;
        }
        let selected = if restore { OLD } else { new_endpoint };
        let selected_mtu = if restore { change.before } else { change.after };
        let set_mtu = |mtu| router.0.lock().unwrap().mtu.insert("awg0".into(), mtu);
        let live = |cfg: &Value, iface: &str| {
            Ok(LivePeer {
                endpoint: selected.parse().unwrap(),
                socket_mark: if address_edit || named_edit {
                    nfqws2_awg_profile::DIRECT_SOCKET_MARK
                } else {
                    0
                },
                ..peer(cfg, iface)?
            })
        };
        let closed = |_: &RoutedMtuChange, _: &LivePeer| -> io::Result<Option<RoutedMtuPeer>> {
            panic!("a still-inherited process or wrong port cannot authorize native forwarding")
        };
        let recover = |native_proof| {
            operate_with_redirect_and_mtu(
                &db,
                &run,
                Operation::Recover,
                None,
                None,
                live,
                native_proof,
            )
        };
        recover(closed).unwrap();
        nfqws2_awg_profile::edit_document(&db, |doc| {
            let row = &mut doc["servers"][0];
            // Even an incomplete launch acknowledgement cannot relabel Go.
            row.as_object_mut()
                .unwrap()
                .remove("rust_pending_client_profile");
            Ok(())
        })
        .unwrap();
        recover(closed).unwrap();
        assert_eq!(path(&router, PAYLOAD), "blackhole");

        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["servers"][0]["config"]["client"]["rust_managed"] = json!(true);
            Ok(())
        })
        .unwrap();
        if same_socket {
            stage(&db, if restore { old_config } else { new_config }, &change);
            recover(closed).unwrap();
            assert_eq!(path(&router, PAYLOAD), "blackhole");
            acknowledge_native(&db);
            // The observed tuple and native flag alone cannot establish the new config hash.
            operate_with_redirect_and_mtu(
                &db,
                &run,
                Operation::Recover,
                None,
                None,
                live,
                |_, _| Ok(None),
            )
            .unwrap();
            assert_eq!(path(&router, PAYLOAD), "blackhole");
            assert!(pending_mtu_edit(&db).unwrap());
        }
        let other = if same_socket {
            wrong_port
        } else if restore {
            new_socket
        } else {
            old_socket
        };
        operate_with_redirect_and_mtu(
            &db,
            &run,
            Operation::Recover,
            None,
            None,
            |cfg, iface| {
                Ok(LivePeer {
                    endpoint: other,
                    ..peer(cfg, iface)?
                })
            },
            closed,
        )
        .unwrap();
        let proof = |saved: &RoutedMtuChange, live: &LivePeer| {
            assert_eq!(saved, &change);
            Ok(Some(RoutedMtuPeer {
                iface: change.iface.clone(),
                outer_id: String::new(),
                outer_iface: String::new(),
                endpoint: live.endpoint,
                effective_mtu: selected_mtu,
                socket_mark: live.socket_mark,
            }))
        };
        operate_with_redirect_and_mtu(
            &db,
            &run,
            Operation::Recover,
            None,
            None,
            live,
            |saved, observed| {
                let mut old = proof(saved, observed)?.unwrap();
                old.endpoint = other;
                Ok(Some(old))
            },
        )
        .unwrap();
        assert_eq!(path(&router, PAYLOAD), "blackhole");
        let mut receipt = json!(mtu_edit::read(&db).unwrap().unwrap());
        let accept = |db: &Store| {
            operate_with_redirect_and_mtu(db, &run, Operation::Recover, None, None, live, proof)
        };
        if changed_mtu.is_some() {
            set_mtu(if restore { change.after } else { change.before });
            accept(&db).unwrap();
            assert_eq!(path(&router, PAYLOAD), "blackhole");
            set_mtu(selected_mtu);
        }
        if changed_mtu.is_some() && !restore {
            // A forward endpoint bit on its own cannot acknowledge a different MTU.
            let mut incomplete = receipt.clone();
            incomplete["endpoint_committed"] = json!(true);
            db.transaction(|tx| tx.save_runtime_bounded("awg-routed-mtu.json", &incomplete, 4096))
                .unwrap();
            nfqws2_awg_profile::edit_document(&db, |doc| {
                doc["servers"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("rust_pending_routed_mtu");
                Ok(())
            })
            .unwrap();
            recover(closed).unwrap();
            assert_eq!(path(&router, PAYLOAD), "blackhole");
            assert!(pending_mtu_edit(&db).unwrap());
            stage(&db, new_config, &change);
            acknowledge_native(&db);
            db.transaction(|tx| tx.save_runtime_bounded("awg-routed-mtu.json", &receipt, 4096))
                .unwrap();
        }
        if with_sources {
            source(&db, CHANGED_LIST_IP);
            assert!(accept(&db).is_err());
            assert_eq!(path(&router, PAYLOAD), "blackhole");
            source(&db, LIST_IP);
        }
        if address_edit {
            // This IP remains another enabled profile's independent underlay
            // while the selected native peer proves a different address.
            *run.captured.lock().unwrap() = Some(shared.ip());
            assert!(accept(&db).is_err());
            assert_eq!(path(&router, PAYLOAD), "blackhole");
            *run.captured.lock().unwrap() = None;
        }
        if new_name.is_some() && !restore {
            *run.captured.lock().unwrap() = Some(unused.ip());
        }
        accept(&db).unwrap();
        assert_eq!(path(&router, PAYLOAD), "awg0");
        let mut verified = Journal::read(&db).unwrap().committed;
        if with_sources {
            assert_eq!(path(&router, LEARNED), "awg0");
            assert_eq!(verified.local_sources == committed.local_sources, restore);
            verified.local_sources.clone_from(&committed.local_sources);
            source(&db, CHANGED_LIST_IP);
            assert!(local_sources_changed(&db).unwrap());
            source(&db, LIST_IP);
        }
        if changed_mtu.is_some() && !restore {
            assert_eq!(verified.targets["awg0"].mtu, change.after);
            assert_eq!(verified.mss["awg0"], change.after - 40);
            if let Some(after) = &verified.learned {
                let before = committed.learned.as_ref().unwrap();
                assert_ne!(after.hash, before.hash);
                assert_eq!(after.members, before.members);
            }
            verified.targets.get_mut("awg0").unwrap().mtu = change.before;
            verified.mss.clone_from(&committed.mss);
            verified.learned.clone_from(&committed.learned);
        }
        assert_eq!(verified, committed);
        assert_eq!(
            nfqws2_awg_profile::read(&db).unwrap()["servers"][0]["config"]["endpoint"],
            if restore { old_config } else { new_config }
        );
        assert!(!pending_mtu_edit(&db).unwrap());
        receipt["endpoint_committed"] = json!(!restore);
        db.transaction(|tx| tx.save_runtime_bounded("awg-routed-mtu.json", &receipt, 4096))
            .unwrap();
        let writes = router.0.lock().unwrap().changes;
        operate_with_redirect_and_mtu(&db, &run, Operation::Refresh, None, None, live, proof)
            .unwrap();
        assert_eq!(router.0.lock().unwrap().changes, writes);
        assert!(!pending_mtu_edit(&db).unwrap());

        if changed_mtu.is_some() && !restore {
            // Recreate the durable state left by a lost acknowledgement after forward FIB commit.
            stage(&db, new_config, &change);
            acknowledge_native(&db);
            db.transaction(|tx| tx.save_runtime_bounded("awg-routed-mtu.json", &receipt, 4096))
                .unwrap();
            validate_endpoint_edit(&db, &run, &change, &wan).unwrap();
            stage(&db, old_config, &change);
            prepare_mtu_edit_with_wan(&db, &run, &change, &wan).unwrap();
            acknowledge_native(&db);
            let accept_old = || {
                operate_with_redirect_and_mtu(
                    &db,
                    &run,
                    Operation::Recover,
                    None,
                    None,
                    peer,
                    |saved, observed| {
                        let mut prior = proof(saved, observed)?.unwrap();
                        prior.effective_mtu = change.before;
                        Ok(Some(prior))
                    },
                )
                .unwrap();
            };
            accept_old();
            assert_eq!(path(&router, PAYLOAD), "blackhole");
            set_mtu(change.before);
            accept_old();
            assert_eq!(path(&router, PAYLOAD), "awg0");
            assert_eq!(Journal::read(&db).unwrap().committed, committed);
            assert!(!pending_mtu_edit(&db).unwrap());
        }
        if changed_mtu.is_some() {
            assert_eq!(
                nfqws2_awg_profile::read(&db).unwrap()["servers"][0]["config"]["mtu"],
                0
            );
        }
    }
}
