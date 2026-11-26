use super::*;
use nfqws2_awg_profile::{
    RoutedEndpointEdit, RoutedEndpointLaunch, RoutedEndpointPredecessor, RoutedMtuChange,
    RoutedMtuPeer,
};
use sha2::{Digest, Sha256};
use std::{cell::Cell, net::SocketAddr};

#[derive(Clone, Copy)]
enum ReservePath {
    Missing,
    Wan,
    Timeout,
}

struct WaitingWan<'a> {
    router: &'a Fake,
    reserve: Mutex<ReservePath>,
}

impl Runner for WaitingWan<'_> {
    fn run(&self, cmd: &str, args: &[&str], end: Instant) -> io::Result<String> {
        if let ("ip", ["-4", "route", "get", addr @ ("198.51.100.30" | "198.51.100.44")]) =
            (cmd, args)
        {
            if *addr == "198.51.100.30" {
                return Err(io::Error::other("route lookup returned no path"));
            }
            match *self.reserve.lock().unwrap() {
                ReservePath::Missing => {
                    return Err(io::Error::other("route lookup returned no path"))
                }
                ReservePath::Timeout => return Err(io::ErrorKind::TimedOut.into()),
                ReservePath::Wan => (),
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
                    "198.51.100.30" | "198.51.100.44"
                ]
            )
        {
            return Ok(String::new());
        }
        self.router.run(cmd, args, end)
    }
}

#[test]
fn all_missing_numeric_endpoints_queue_and_keep_only_a_proved_predecessor() {
    const OLD: &str = "198.51.100.10:443";
    const NEW: &str = "198.51.100.30:51820";
    const RESERVE: &str = "198.51.100.44:8443";
    const SOURCE: &str = "192.168.1.7";
    const PAYLOAD: &str = "203.0.113.10";
    const OTHER: &str = "203.0.113.11";
    const LEARNED: &str = "203.0.113.12";
    let (dir, db, router) = setup();
    let runner = WaitingWan {
        router: &router,
        reserve: Mutex::new(ReservePath::Wan),
    };
    scoped_policy(&db);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"]["domain_source"] = json!("dnsproxy");
        doc["routing"]["killswitch"] = json!(true);
        let cfg = &mut doc["servers"][0]["config"];
        cfg["install"] = json!("imported");
        cfg["protocol"] = json!("wireguard");
        cfg["mtu"] = json!(1420);
        cfg["endpoint"] = json!(OLD);
        cfg["client"]["rust_managed"] = json!(true);
        cfg["client"]["peer_id"] = json!("fixture");
        cfg["client"]["endpoint_backups"] = json!([RESERVE]);
        cfg["peers"] = json!([{"id":"fixture","is_router":true,"name":"fixture",
            "private_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
            "address":"192.0.2.11/32","allowed_ips":"0.0.0.0/0"}]);
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
    let (prior, _) = nfqws2_awg_profile::peer_export(&db, "fixture", "conf").unwrap();
    let fingerprint: [u8; 32] = Sha256::digest(prior).into();
    let now = nfqws2_awg_profile::now();
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &runner, op, now, both_peers).unwrap();
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
    let wan = ["wan0".into()];
    let admission = || validate_endpoint_edit_launch(&db, &runner, &change, &wan);
    *runner.reserve.lock().unwrap() = ReservePath::Timeout;
    assert_eq!(admission().unwrap_err().kind(), io::ErrorKind::TimedOut);
    *runner.reserve.lock().unwrap() = ReservePath::Missing;
    assert_eq!(admission().unwrap(), RoutedEndpointLaunch::Waiting);
    assert_eq!(Journal::read(&db).unwrap(), original);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["config"]["endpoint"] = json!(NEW);
        doc["servers"][0]["rust_pending_routed_mtu"] = json!(change);
        doc["servers"][0]["rust_pending_client_profile"] = json!(fingerprint);
        Ok(())
    })
    .unwrap();
    let db = Store::open(dir.path()).unwrap();
    assert_eq!(
        pending_endpoint_launch(&db, &runner, &change, &wan).unwrap(),
        RoutedEndpointLaunch::Waiting
    );
    assert_eq!(scheduled(&db).unwrap(), Schedule::Restore);
    let proved = Cell::new(true);
    let endpoint = Cell::new(OLD.parse::<SocketAddr>().unwrap());
    let report = |current| RoutedMtuPeer {
        iface: "awg0".into(),
        outer_id: String::new(),
        outer_iface: String::new(),
        effective_mtu: 1420,
        endpoint: current,
        socket_mark: 0,
    };
    let sample = |cfg: &Value, iface: &str| {
        let mut live = both_peers(cfg, iface)?;
        if iface == "awg0" {
            live.endpoint = endpoint.get();
            Ok(
                live.with_endpoint_predecessor(proved.get().then(|| RoutedEndpointPredecessor {
                    edit: change.clone(),
                    peer: report(endpoint.get()),
                })),
            )
        } else {
            live.endpoint = "198.51.100.80:443".parse().unwrap();
            Ok(live)
        }
    };
    let route = |address| router.0.lock().unwrap().forward(SOURCE, address).to_owned();
    let writes = router.0.lock().unwrap().changes;
    operate_at(&db, &runner, Operation::Refresh, now, sample).unwrap();
    assert_eq!(route(PAYLOAD), "awg0");
    assert_eq!(route(OTHER), "awg1");
    assert_eq!(router.0.lock().unwrap().changes, writes);
    assert!(!pending_mtu_edit(&db).unwrap());
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
    assert_eq!(route(LEARNED), "awg0");
    assert!(learn("198.51.100.44").is_err());
    let confirmed = Journal::read(&db).unwrap().committed;
    assert!(operate_at(&db, &runner, Operation::Apply, now, sample).is_err());
    assert!(operate_at(&db, &runner, Operation::Commit, now, sample).is_err());

    operate_at(&db, &runner, Operation::Suspend, now, sample).unwrap();
    proved.set(false);
    router.0.lock().unwrap().boot = "34343434-3434-3434-3434-343434343434".into();
    operate_at(&db, &runner, Operation::Recover, now, sample).unwrap();
    assert_eq!(route(PAYLOAD), "blackhole");
    assert_eq!(route(LEARNED), "blackhole");
    assert_eq!(route(OTHER), "awg1");
    assert!(learn("203.0.113.14").is_err());
    proved.set(true);
    operate_at(&db, &runner, Operation::Refresh, now, sample).unwrap();
    assert_eq!(route(LEARNED), "awg0");
    assert!(!pending_mtu_edit(&db).unwrap());

    *runner.reserve.lock().unwrap() = ReservePath::Wan;
    assert_eq!(
        pending_endpoint_launch(&db, &runner, &change, &wan).unwrap(),
        RoutedEndpointLaunch::Alternate(reserve)
    );
    prepare_endpoint_retry(&db, &runner, &change, reserve, &wan).unwrap();
    assert_eq!(route(PAYLOAD), "blackhole");
    assert!(operate_at(&db, &runner, Operation::Refresh, now, sample).is_err());
    assert_eq!(route(PAYLOAD), "blackhole");
    assert!(pending_mtu_edit(&db).unwrap());
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]
            .as_object_mut()
            .unwrap()
            .remove("rust_pending_client_profile");
        Ok(())
    })
    .unwrap();
    endpoint.set(reserve);
    proved.set(false);
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
            Ok(Some(report(reserve)))
        },
    )
    .unwrap();
    assert_eq!(route(PAYLOAD), "awg0");
    assert_eq!(route(LEARNED), "awg0");
    assert_eq!(route(OTHER), "awg1");
    assert_eq!(Journal::read(&db).unwrap().committed, confirmed);
    assert!(!pending_mtu_edit(&db).unwrap());
}
