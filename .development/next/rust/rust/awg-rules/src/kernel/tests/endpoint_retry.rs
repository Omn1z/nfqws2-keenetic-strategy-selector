use super::*;
use nfqws2_awg_profile::{RoutedDirectBackup, RoutedEndpointEdit, RoutedMtuChange, RoutedMtuPeer};
use std::{
    cell::Cell,
    net::SocketAddr,
    sync::atomic::{AtomicBool, Ordering},
};

struct PrimaryWan<'a> {
    router: &'a Fake,
    missing: AtomicBool,
}

impl Runner for PrimaryWan<'_> {
    fn run(&self, cmd: &str, args: &[&str], end: Instant) -> io::Result<String> {
        if cmd == "ip"
            && args == ["-4", "route", "get", "198.51.100.30"]
            && self.missing.load(Ordering::Relaxed)
        {
            return Err(io::ErrorKind::NotConnected.into());
        }
        self.router.run(cmd, args, end)
    }
}

#[derive(Clone, Copy)]
enum InitialPath {
    Wan,
    Missing,
    WrongDevice,
    Ambiguous,
    Timeout,
    Malformed,
}

struct InitialWan<'a> {
    router: &'a Fake,
    path: Mutex<InitialPath>,
}

impl Runner for InitialWan<'_> {
    fn run(&self, cmd: &str, args: &[&str], end: Instant) -> io::Result<String> {
        let state = *self.path.lock().unwrap();
        if cmd == "ip" && args == ["-4", "route", "get", "198.51.100.30"] {
            match state {
                InitialPath::Wan => (),
                InitialPath::Missing | InitialPath::Ambiguous => {
                    return Err(io::Error::other("route lookup failed"))
                }
                InitialPath::WrongDevice => return Ok("198.51.100.30 dev br0".into()),
                InitialPath::Timeout => return Err(io::ErrorKind::TimedOut.into()),
                InitialPath::Malformed => return Ok("unparseable route output".into()),
            }
        }
        if cmd == "ip"
            && matches!(
                args,
                [
                    "-o",
                    "-N",
                    "-4",
                    "route",
                    "show",
                    "table",
                    "all",
                    "match",
                    "198.51.100.30"
                ]
            )
        {
            return Ok(match state {
                InitialPath::Missing => "unreachable default table 200".into(),
                _ => "default via 192.0.2.1 dev wan0".into(),
            });
        }
        self.router.run(cmd, args, end)
    }
}

#[test]
fn initial_direct_endpoint_retry_proves_wan_absence_and_replays_before_new_launch() {
    const OLD: &str = "198.51.100.10:443";
    const NEW: &str = "198.51.100.30:51820";
    const RESERVE: &str = "198.51.100.44:8443";
    const OTHER: &str = "198.51.100.77:8443";
    const HOST: &str = "203.0.113.12";
    let (dir, db, router) = setup();
    let runner = InitialWan {
        router: &router,
        path: Mutex::new(InitialPath::Wan),
    };
    protect(&db);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let cfg = &mut doc["servers"][0]["config"];
        cfg["install"] = json!("imported");
        cfg["mtu"] = json!(1420);
        cfg["endpoint"] = json!(OLD);
        cfg["client"]["rust_managed"] = json!(true);
        cfg["client"]["endpoint_backups"] = json!([RESERVE, OTHER]);
        Ok(())
    })
    .unwrap();
    router.0.lock().unwrap().mtu.insert("awg0".into(), 1420);
    let now = nfqws2_awg_profile::now();
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &runner, op, now, peer).unwrap();
    }
    let original = Journal::read(&db).unwrap();
    let change = RoutedMtuChange {
        id: original.committed.targets["awg0"].id.clone(),
        iface: "awg0".into(),
        revision: original.committed.revision,
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
    let reserve = RESERVE.parse::<SocketAddr>().unwrap();
    let alt = OTHER.parse::<SocketAddr>().unwrap();
    let wan = ["wan0".into()];
    let set_path = |value| *runner.path.lock().unwrap() = value;
    let document = nfqws2_awg_profile::read(&db).unwrap();
    let writes = router.0.lock().unwrap().changes;
    assert_eq!(
        validate_endpoint_edit_with_backup(&db, &runner, &change, &wan).unwrap(),
        None
    );
    for (state, kind) in [
        (InitialPath::Timeout, io::ErrorKind::TimedOut),
        (InitialPath::Ambiguous, io::ErrorKind::Other),
        (InitialPath::Malformed, io::ErrorKind::InvalidData),
    ] {
        set_path(state);
        let error = validate_endpoint_edit_with_backup(&db, &runner, &change, &wan).unwrap_err();
        assert_eq!(error.kind(), kind);
    }
    for state in [InitialPath::WrongDevice, InitialPath::Missing] {
        set_path(state);
        assert_eq!(
            validate_endpoint_edit_with_backup(&db, &runner, &change, &wan).unwrap(),
            Some(reserve)
        );
    }
    assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), document);
    assert_eq!(Journal::read(&db).unwrap(), original);
    assert_eq!(router.0.lock().unwrap().changes, writes);
    assert_eq!(path(&router, HOST), "awg0");
    assert!(!pending_mtu_edit(&db).unwrap());
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["config"]["endpoint"] = json!(NEW);
        doc["servers"][0]["rust_pending_routed_mtu"] = json!(change);
        doc["servers"][0]["rust_pending_client_profile"] = json!(vec![0_u8; 32]);
        Ok(())
    })
    .unwrap();
    let db = Store::open(dir.path()).unwrap();
    assert_eq!(
        pending_endpoint_retry_with_wan(&db, &runner, &change, &wan).unwrap(),
        Some(reserve)
    );
    assert!(!pending_mtu_edit(&db).unwrap());
    set_path(InitialPath::Wan);
    assert!(prepare_endpoint_retry(&db, &runner, &change, reserve, &wan).is_err());
    assert_eq!(path(&router, HOST), "awg0");
    set_path(InitialPath::Missing);
    assert!(prepare_endpoint_retry(&db, &runner, &change, reserve, &["other-wan".into()]).is_err());
    assert_eq!(path(&router, HOST), "awg0");
    prepare_endpoint_retry(&db, &runner, &change, reserve, &wan).unwrap();
    assert_eq!(path(&router, HOST), "blackhole");
    let db = Store::open(dir.path()).unwrap();
    assert_eq!(
        pending_endpoint_retry_with_wan(&db, &runner, &change, &wan).unwrap(),
        Some(reserve)
    );
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["rust_pending_client_profile"] = json!("transport_refresh");
        Ok(())
    })
    .unwrap();
    assert_eq!(
        pending_endpoint_retry_with_wan(&db, &runner, &change, &wan).unwrap(),
        Some(reserve)
    );
    assert!(prepare_endpoint_retry(&db, &runner, &change, alt, &wan).is_err());
    prepare_endpoint_retry(&db, &runner, &change, reserve, &wan).unwrap();
    let selected = |cfg: &Value, iface: &str| {
        Ok(LivePeer {
            endpoint: reserve,
            ..peer(cfg, iface)?
        })
    };
    assert!(operate_with_redirect_and_mtu(
        &db,
        &runner,
        Operation::Recover,
        None,
        None,
        selected,
        |_, _| { panic!("cleanup phase cannot request FIB proof") }
    )
    .is_err());
    assert_eq!(path(&router, HOST), "blackhole");
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
        &runner,
        Operation::Recover,
        None,
        None,
        selected,
        |asked, live| {
            assert_eq!(asked, &change);
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
    assert_eq!(path(&router, HOST), "awg0");
    assert_eq!(Journal::read(&db).unwrap().committed, original.committed);
    assert!(!pending_mtu_edit(&db).unwrap());
}

#[test]
fn proved_direct_backup_keeps_routes_when_sole_primary_loses_wan() {
    const OLD: &str = "198.51.100.10:443";
    const PRIMARY: &str = "198.51.100.30:51820";
    const RESERVE: &str = "198.51.100.44:8443";
    const SOURCE: &str = "192.168.1.7";
    const PAYLOAD: &str = "203.0.113.10";
    const OTHER: &str = "203.0.113.11";
    const LEARNED: &str = "203.0.113.12";
    const MORE_DNS: &str = "203.0.113.13";
    let (_dir, db, router) = setup();
    let runner = PrimaryWan {
        router: &router,
        missing: AtomicBool::new(false),
    };
    scoped_policy(&db);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"]["domain_source"] = json!("dnsproxy");
        doc["routing"]["killswitch"] = json!(true);
        let cfg = &mut doc["servers"][0]["config"];
        cfg["install"] = json!("imported");
        cfg["mtu"] = json!(1420);
        cfg["endpoint"] = json!(OLD);
        cfg["client"]["rust_managed"] = json!(true);
        cfg["client"]["endpoint_backups"] = json!([RESERVE]);
        cfg["routing"]["zones"] = json!([
            {"order":1,"enabled":true,"ips":[PAYLOAD],"domains":["*.office.test"],"source_ips":[SOURCE]}
        ]);
        doc["servers"][1]["config"]["endpoint"] = json!("198.51.100.80:443");
        doc["servers"][1]["config"]["routing"]["zones"] = json!([
            {"order":2,"enabled":true,"ips":[OTHER],"source_ips":[SOURCE]}
        ]);
        Ok(())
    }).unwrap();
    {
        let mut fw = router.0.lock().unwrap();
        fw.local = "2: br0 inet 192.168.1.1/24 scope global".into();
        fw.mtu.insert("awg0".into(), 1420);
    }
    let endpoint = Cell::new(OLD.parse::<SocketAddr>().unwrap());
    let shares_primary = Cell::new(false);
    let has_witness = Cell::new(false);
    let primary = PRIMARY.parse::<SocketAddr>().unwrap();
    let reserve = RESERVE.parse::<SocketAddr>().unwrap();
    let evidence = || RoutedMtuPeer {
        iface: "awg0".into(),
        outer_id: String::new(),
        outer_iface: String::new(),
        endpoint: reserve,
        effective_mtu: 1420,
        socket_mark: 0,
    };
    let sample = |cfg: &Value, iface: &str| {
        let mut live = both_peers(cfg, iface)?;
        if iface == "awg0" {
            live.endpoint = endpoint.get();
            Ok(
                live.with_direct_backup(has_witness.get().then(|| RoutedDirectBackup {
                    primary,
                    peer: evidence(),
                })),
            )
        } else {
            live.endpoint = if shares_primary.get() {
                primary
            } else {
                "198.51.100.80:443".parse().unwrap()
            };
            Ok(live)
        }
    };
    let now = nfqws2_awg_profile::now();
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &runner, op, now, sample).unwrap();
    }
    let learn = |address: &str| {
        learn_client_answer(
            &db,
            &runner,
            Answer {
                revision: 1,
                zone: 0,
                addresses: &[address.parse().unwrap()],
                ttl: 600,
                qtype: 1,
            },
            Some(SOURCE.parse().unwrap()),
            sample,
            || Ok(()),
        )
    };
    learn(LEARNED).unwrap();
    let saved = Journal::read(&db).unwrap().committed;
    let change = RoutedMtuChange {
        id: saved.targets["awg0"].id.clone(),
        iface: "awg0".into(),
        revision: saved.revision,
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
            after: PRIMARY.into(),
            previous_reserve: None,
            resolved_before: vec![],
            resolved_after: vec![],
        }),
    };
    let wan = ["wan0".into()];
    validate_endpoint_edit(&db, &runner, &change, &wan).unwrap();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["config"]["endpoint"] = json!(PRIMARY);
        doc["servers"][0]["rust_pending_routed_mtu"] = json!(change);
        Ok(())
    })
    .unwrap();
    prepare_mtu_edit_with_wan(&db, &runner, &change, &wan).unwrap();
    runner.missing.store(true, Ordering::Relaxed);
    prepare_endpoint_retry(&db, &runner, &change, reserve, &wan).unwrap();
    let check = |expected| {
        let fw = router.0.lock().unwrap();
        assert_eq!(fw.forward(SOURCE, PAYLOAD), expected);
        assert_eq!(fw.forward(SOURCE, LEARNED), expected);
        assert_eq!(fw.forward(SOURCE, OTHER), "awg1");
    };
    check("blackhole");
    endpoint.set(reserve);
    let stale = operate_with_redirect_and_mtu(
        &db,
        &runner,
        Operation::Recover,
        None,
        None,
        sample,
        |_, _| Ok(None),
    );
    assert!(stale.is_err());
    check("blackhole");
    operate_with_redirect_and_mtu(
        &db,
        &runner,
        Operation::Recover,
        None,
        None,
        sample,
        |asked, live| {
            assert_eq!(asked, &change);
            assert_eq!(live.endpoint, reserve);
            Ok(Some(evidence()))
        },
    )
    .unwrap();
    check("awg0");
    assert_eq!(Journal::read(&db).unwrap().committed, saved);
    assert!(!pending_mtu_edit(&db).unwrap());
    let refresh = || operate_at(&db, &runner, Operation::Refresh, now, sample);
    assert!(refresh().is_err());
    has_witness.set(true);
    refresh().unwrap();
    learn(MORE_DNS).unwrap();
    assert_eq!(router.0.lock().unwrap().forward(SOURCE, MORE_DNS), "awg0");
    assert!(learn("198.51.100.30").is_err());

    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["config"]["client"]["endpoint_backups"] =
            json!([RESERVE, "198.51.100.30:8443"]);
        Ok(())
    })
    .unwrap();
    assert!(refresh().is_err());
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["config"]["client"]["endpoint_backups"] = json!([RESERVE]);
        doc["servers"][1]["config"]["endpoint"] = json!("198.51.100.30:443");
        Ok(())
    })
    .unwrap();
    assert!(refresh().is_err());
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][1]["config"]["endpoint"] = json!("198.51.100.80:443");
        Ok(())
    })
    .unwrap();
    shares_primary.set(true);
    assert!(refresh().is_err());
    shares_primary.set(false);
    refresh().unwrap();
    check("awg0");
}

#[test]
fn routed_direct_endpoint_retry_requires_exact_authorized_tuple_and_new_owner() {
    const OLD: &str = "198.51.100.10:443";
    const NEW: &str = "198.51.100.30:51820";
    const HOST: &str = "203.0.113.12";
    let (dir, db, router) = setup();
    protect(&db);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let config = &mut doc["servers"][0]["config"];
        config["install"] = json!("imported");
        config["mtu"] = json!(1420);
        config["endpoint"] = json!(OLD);
        config["client"]["rust_managed"] = json!(true);
        Ok(())
    })
    .unwrap();
    router.0.lock().unwrap().mtu.insert("awg0".into(), 1420);
    let now = nfqws2_awg_profile::now();
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &router, op, now, peer).unwrap();
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
            resolved_after: vec![],
        }),
    };
    let selected: SocketAddr = OLD.parse().unwrap();
    let primary: SocketAddr = NEW.parse().unwrap();
    let wan = ["wan0".into()];
    let backups = |db: &Store, entries: &[&str]| {
        nfqws2_awg_profile::edit_document(db, |doc| {
            doc["servers"][0]["config"]["client"]["endpoint_backups"] = json!(entries);
            Ok(())
        })
    };

    validate_endpoint_edit(&db, &router, &change, &wan).unwrap();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["config"]["endpoint"] = json!(NEW);
        doc["servers"][0]["rust_pending_routed_mtu"] = json!(change);
        doc["servers"][0]["rust_pending_client_profile"] = json!(vec![0_u8; 32]);
        Ok(())
    })
    .unwrap();
    prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
    assert_eq!(path(&router, HOST), "blackhole");
    backups(&db, &[OLD]).unwrap();
    assert_eq!(
        pending_endpoint_retry(&db, &change).unwrap_err().kind(),
        io::ErrorKind::Unsupported
    );
    assert!(prepare_endpoint_retry(&db, &router, &change, selected, &wan).is_err());
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]
            .as_object_mut()
            .unwrap()
            .remove("rust_pending_client_profile");
        Ok(())
    })
    .unwrap();
    assert_eq!(pending_endpoint_retry(&db, &change).unwrap(), None);
    let writes = router.0.lock().unwrap().changes;
    backups(&db, &["203.0.113.25:443"]).unwrap();
    assert!(prepare_endpoint_retry(
        &db,
        &router,
        &change,
        "203.0.113.25:443".parse().unwrap(),
        &wan
    )
    .is_err());
    assert!(prepare_endpoint_retry(&db, &router, &change, selected, &wan).is_err());
    backups(&db, &[OLD]).unwrap();
    let mut other_change = change.clone();
    other_change.endpoint_edit.as_mut().unwrap().after = "198.51.100.31:51820".into();
    assert!(prepare_endpoint_retry(&db, &router, &other_change, selected, &wan).is_err());
    assert!(prepare_endpoint_retry(&db, &router, &change, primary, &wan).is_err());
    assert!(
        prepare_endpoint_retry(&db, &router, &change, selected, &["other-wan".into()]).is_err()
    );
    assert_eq!(router.0.lock().unwrap().changes, writes);
    prepare_endpoint_retry(&db, &router, &change, selected, &wan).unwrap();
    assert_eq!(
        pending_endpoint_retry(&db, &change).unwrap(),
        Some(selected)
    );
    assert!(prepare_mtu_edit_with_wan(&db, &router, &change, &wan).is_err());

    let db = Store::open(dir.path()).unwrap();
    assert_eq!(
        pending_endpoint_retry(&db, &change).unwrap(),
        Some(selected)
    );
    let current_primary = |cfg: &Value, iface: &str| {
        Ok(LivePeer {
            endpoint: primary,
            ..peer(cfg, iface)?
        })
    };
    let assert_no_attempt =
        |_: &RoutedMtuChange, _: &LivePeer| -> io::Result<Option<RoutedMtuPeer>> {
            panic!("a tuple without durable authorization cannot request a proof")
        };
    operate_with_redirect_and_mtu(
        &db,
        &router,
        Operation::Recover,
        None,
        None,
        current_primary,
        assert_no_attempt,
    )
    .unwrap();
    assert_eq!(path(&router, HOST), "blackhole");
    // The old process can have the right tuple, key, interface and MTU.
    // Its independent process-generation proof still fails.
    operate_with_redirect_and_mtu(
        &db,
        &router,
        Operation::Recover,
        None,
        None,
        peer,
        |_, _| Ok(None),
    )
    .unwrap();
    assert_eq!(path(&router, HOST), "blackhole");

    backups(&db, &[]).unwrap();
    assert_eq!(
        pending_endpoint_retry(&db, &change).unwrap(),
        Some(selected)
    );
    operate_with_redirect_and_mtu(
        &db,
        &router,
        Operation::Recover,
        None,
        None,
        peer,
        assert_no_attempt,
    )
    .unwrap();
    assert_eq!(path(&router, HOST), "blackhole");
    prepare_endpoint_retry(&db, &router, &change, primary, &wan).unwrap();
    assert_eq!(pending_endpoint_retry(&db, &change).unwrap(), None);
    let alternate: SocketAddr = "198.51.100.44:51820".parse().unwrap();
    backups(&db, &["198.51.100.44:51820"]).unwrap();
    prepare_endpoint_retry(&db, &router, &change, alternate, &wan).unwrap();
    validate_endpoint_edit(&db, &router, &change, &wan).unwrap();
    let save_direction = |configured: &str| {
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["servers"][0]["config"]["endpoint"] = json!(configured);
            doc["servers"][0]["rust_pending_routed_mtu"] = json!(change);
            Ok(())
        })
        .unwrap();
    };
    save_direction(OLD);
    assert_eq!(
        pending_endpoint_retry(&db, &change).unwrap_err().kind(),
        io::ErrorKind::Unsupported
    );
    prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
    let still_retried = |cfg: &Value, iface: &str| {
        Ok(LivePeer {
            endpoint: alternate,
            ..peer(cfg, iface)?
        })
    };
    operate_with_redirect_and_mtu(
        &db,
        &router,
        Operation::Recover,
        None,
        None,
        still_retried,
        assert_no_attempt,
    )
    .unwrap();
    assert_eq!(path(&router, HOST), "blackhole");

    let evidence = |endpoint| RoutedMtuPeer {
        iface: change.iface.clone(),
        outer_id: String::new(),
        outer_iface: String::new(),
        endpoint,
        effective_mtu: 1420,
        socket_mark: 0,
    };
    operate_with_redirect_and_mtu(
        &db,
        &router,
        Operation::Recover,
        None,
        None,
        peer,
        |_, live| Ok(Some(evidence(live.endpoint))),
    )
    .unwrap();
    assert_eq!(path(&router, HOST), "awg0");
    assert!(!pending_mtu_edit(&db).unwrap());
    save_direction(NEW);
    prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
    backups(&db, &[OLD]).unwrap();
    prepare_endpoint_retry(&db, &router, &change, selected, &wan).unwrap();

    let authority = mtu_edit::read(&db).unwrap().unwrap();
    let prove = |asked: &RoutedMtuChange, live: &LivePeer| {
        assert_eq!(asked, &change);
        assert_eq!(live.endpoint, selected);
        Ok(Some(evidence(selected)))
    };
    operate_with_redirect_and_mtu(&db, &router, Operation::Recover, None, None, peer, prove)
        .unwrap();
    assert_eq!(path(&router, HOST), "awg0");
    assert_eq!(Journal::read(&db).unwrap().committed, confirmed);
    assert!(!pending_mtu_edit(&db).unwrap());
    let doc = nfqws2_awg_profile::read(&db).unwrap();
    assert_eq!(doc["servers"][0]["config"]["endpoint"], NEW);

    let mut ack = serde_json::to_value(authority).unwrap();
    ack["endpoint_committed"] = json!(true);
    db.transaction(|tx| tx.save_runtime("awg-routed-mtu.json", &ack))
        .unwrap();
    let writes = router.0.lock().unwrap().changes;
    operate_with_redirect_and_mtu(&db, &router, Operation::Refresh, None, None, peer, prove)
        .unwrap();
    assert_eq!(router.0.lock().unwrap().changes, writes);
    assert!(!pending_mtu_edit(&db).unwrap());
}
