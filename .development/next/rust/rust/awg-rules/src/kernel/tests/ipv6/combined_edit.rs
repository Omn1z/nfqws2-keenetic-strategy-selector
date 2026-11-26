use super::*;
use nfqws2_awg_profile::{
    RoutedDirectBackup, RoutedEndpointEdit, RoutedEndpointLaunch, RoutedImplicitMtu,
    RoutedLegacyPredecessor, RoutedMtuChange, RoutedMtuOuter, RoutedMtuPeer, RoutedNestedTransport,
    DIRECT_SOCKET_MARK,
};

pub(super) fn require_isolated_namespaces() {
    for (kind, var) in [("net", "N2S_PARENT_NET"), ("mnt", "N2S_PARENT_MNT")] {
        let parent = std::env::var(var).unwrap();
        assert!(parent.starts_with(&format!("{kind}:[")));
        let current = std::fs::read_link(format!("/proc/self/ns/{kind}")).unwrap();
        assert_ne!(current.to_str(), Some(parent.as_str()));
    }
}

pub(super) fn physical_mtu(k: &Kernel<'_>) -> u16 {
    k.call("cat", &["/sys/class/net/awg0/mtu"])
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

pub(super) fn set_physical_mtu(k: &Kernel<'_>, mtu: u16) {
    k.call(
        "ip",
        &["link", "set", "dev", "awg0", "mtu", &mtu.to_string()],
    )
    .unwrap();
}

fn route_device(k: &Kernel<'_>, ip: &str) -> Option<String> {
    let line = k.call("ip", &["-4", "route", "get", ip]).ok()?;
    let mut parts = line.split_ascii_whitespace();
    parts.find(|part| *part == "dev")?;
    parts.next().map(str::to_owned)
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn fixed_permanent_nested_mtu_undo_preserves_real_marked_transport() {
    use sha2::{Digest, Sha256};

    // This guest has no raw socket capability. Keep the xtables/ipset
    // classifier in the existing model and exercise the RPDB and FIB live.
    #[derive(Default)]
    struct NestedFib(packed::Router);
    impl Runner for NestedFib {
        fn run(&self, program: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
            if matches!(program, "iptables" | "ipset") {
                self.0.run(program, args, deadline)
            } else {
                nfqws2_router_command::System.run(program, args, deadline)
            }
        }
        fn run_input(
            &self,
            program: &str,
            args: &[&str],
            input: &[u8],
            deadline: Instant,
        ) -> io::Result<String> {
            if matches!(program, "iptables-restore" | "ipset") {
                self.0.run_input(program, args, input, deadline)
            } else {
                nfqws2_router_command::System.run_input(program, args, input, deadline)
            }
        }
    }

    const ENDPOINT: &str = "[2001:db8:f00::1]:443";
    const OUTER: &str = "198.51.100.88:443";
    const PAYLOAD: &str = "203.0.113.50";
    const BEFORE: u16 = 1420;
    const AFTER: u16 = 1360;
    const MEASURED: u16 = 1320;
    const MARK: u32 = 0xa0000000;
    require_isolated_namespaces();
    let router = NestedFib::default();
    let k = kernel(&router);
    let wan = ["wan0".into()];
    let (_dir, db, _) = setup();
    protect(&db);
    let initial_mtu = physical_mtu(&k);
    let initial_outer_mtu = k.call("cat", &["/sys/class/net/awg2/mtu"]).unwrap();
    k.call("ip", &["link", "set", "dev", "awg2", "mtu", "1400"])
        .unwrap();
    set_physical_mtu(&k, MEASURED);
    let configure = |op| {
        k.call(
            "ip",
            &["-6", "route", op, "prohibit", "2001:db8:f00::1/128"],
        )
        .unwrap();
        k.call(
            "ip",
            &[
                "-6",
                "route",
                op,
                "2001:db8:f00::1/128",
                "dev",
                "awg2",
                "table",
                "828",
                "proto",
                "99",
            ],
        )
        .unwrap();
        k.call(
            "ip",
            &[
                "-6",
                "rule",
                op,
                "pref",
                "60",
                "fwmark",
                "0xa0000000",
                "lookup",
                "828",
            ],
        )
        .unwrap();
        k.call(
            "ip",
            &[
                "-6",
                "rule",
                op,
                "pref",
                "61",
                "fwmark",
                "0xa0000000",
                "prohibit",
            ],
        )
        .unwrap();
    };
    k.call(
        "ip",
        &["-6", "addr", "add", "fd13::2/128", "dev", "awg2", "nodad"],
    )
    .unwrap();
    configure("add");
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let rows = doc["servers"].as_array_mut().unwrap();
        let mut outer = rows[0].clone();
        outer["id"] = json!("outer");
        outer["config"]["client_iface"] = json!("awg2");
        outer["config"]["endpoint"] = json!(OUTER);
        outer["config"]["routing"]["zones"] = json!([]);
        rows.push(outer);
        let inner = &mut rows[0]["config"];
        inner["endpoint"] = json!(ENDPOINT);
        inner["install"] = json!("imported");
        inner["mtu"] = json!(0);
        inner["routing"]["mtu"] = json!(BEFORE);
        inner["client"]["rust_managed"] = json!(true);
        inner["client"]["double_tunnel_mode"] = json!("permanent");
        inner["client"]["double_tunnel_id"] = json!("outer");
        Ok(())
    })
    .unwrap();
    let now = nfqws2_awg_profile::now();
    let endpoint = ENDPOINT.parse().unwrap();
    let selected = std::cell::Cell::new(endpoint);
    let outer_endpoint = OUTER.parse().unwrap();
    let candidate = || RoutedMtuPeer {
        iface: "awg0".into(),
        outer_id: "outer".into(),
        outer_iface: "awg2".into(),
        endpoint: selected.get(),
        effective_mtu: physical_mtu(&k),
        socket_mark: MARK,
    };
    let live = |cfg: &Value, iface: &str| {
        let baseline = peer(cfg, "awg0")?;
        if iface == "awg2" {
            return Ok(LivePeer {
                endpoint: outer_endpoint,
                ..baseline
            });
        }
        assert_eq!(iface, "awg0");
        Ok(LivePeer {
            endpoint: selected.get(),
            socket_mark: MARK,
            nested_mtu: Some(physical_mtu(&k)),
            ..baseline
        }
        .with_nested_transport(Some(RoutedNestedTransport {
            peer: candidate(),
            outer_endpoint,
        })))
    };
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &router, op, now, live).unwrap();
    }
    let original = Journal::read(&db).unwrap().committed;
    let payload_path = || {
        let Some(classifier_mark) = router.0.packet_mark("10.99.0.5", PAYLOAD) else {
            return route_device(&k, PAYLOAD);
        };
        let (mark, _) = classifier_mark.split_once('/').unwrap();
        let row = k
            .call("ip", &["-4", "route", "get", PAYLOAD, "mark", mark])
            .ok()?;
        let mut words = row.split_ascii_whitespace();
        words.find(|word| *word == "dev")?;
        words.next().map(str::to_owned)
    };
    assert_eq!(payload_path().as_deref(), Some("awg0"));
    let change = RoutedMtuChange {
        id: original.targets["awg0"].id.clone(),
        iface: "awg0".into(),
        revision: original.revision,
        before: BEFORE,
        after: AFTER,
        legacy_mtu_before_recorded: false,
        nested_mtu_before_recorded: true,
        native_mtu_endpoint: None,
        implicit_before_mtu: Some(RoutedImplicitMtu::Zero),
        nested_outer: Some(RoutedMtuOuter {
            id: "outer".into(),
            iface: "awg2".into(),
            peer_key_sha256: Sha256::digest("01".repeat(32)).into(),
        }),
        nested_endpoint: Some(ENDPOINT.into()),
        legacy_predecessor: None,
        endpoint_edit: None,
    };
    let launch = |change: &RoutedMtuChange| {
        assert_eq!(
            validate_endpoint_edit_launch(&db, &router, change, &wan).unwrap(),
            RoutedEndpointLaunch::Primary
        );
    };
    let stage = |mtu: u16, change: &RoutedMtuChange, endpoint: Option<&str>| {
        nfqws2_awg_profile::edit_document(&db, |doc| {
            let row = &mut doc["servers"][0];
            row["config"]["mtu"] = json!(mtu);
            if let Some(endpoint) = endpoint {
                row["config"]["endpoint"] = json!(endpoint);
            }
            row["rust_pending_routed_mtu"] = json!(change);
            Ok(())
        })
        .unwrap();
        prepare_mtu_edit_with_wan(&db, &router, change, &wan).unwrap();
    };
    let check_transport = || {
        let ip = "2001:db8:f00::1";
        assert!(k.call("ip", &["-6", "route", "get", ip]).is_err());
        let marked = k
            .call("ip", &["-6", "route", "get", ip, "mark", "0xa0000000"])
            .unwrap();
        assert!(marked.contains("dev awg2"));
    };
    let waiting = || {
        assert_eq!(payload_path(), None);
        assert!(pending_mtu_edit(&db).unwrap());
        check_transport();
    };
    let reported_mtu = std::cell::Cell::new(MEASURED);
    let recover = |new_owner: bool| {
        operate_with_redirect_and_mtu(
            &db,
            &router,
            Operation::Recover,
            None,
            None,
            live,
            |_, _| {
                Ok(new_owner.then(|| RoutedMtuPeer {
                    effective_mtu: reported_mtu.get(),
                    ..candidate()
                }))
            },
        )
        .unwrap();
    };
    check_transport();
    launch(&change);
    stage(AFTER, &change, None);
    recover(false);
    waiting();
    launch(&change);
    stage(0, &change, None);
    recover(false);
    waiting();
    set_physical_mtu(&k, MEASURED - 10);
    recover(true);
    waiting();
    set_physical_mtu(&k, MEASURED);
    recover(true);
    assert!(!pending_mtu_edit(&db).unwrap());
    assert_eq!(payload_path().as_deref(), Some("awg0"));
    assert_eq!(
        nfqws2_awg_profile::read(&db).unwrap()["servers"][0]["config"]["mtu"],
        0
    );
    assert_eq!(Journal::read(&db).unwrap().committed, original);
    check_transport();
    let mss = k
        .call("iptables", &["-w", "-t", "mangle", "-S", "FORWARD"])
        .unwrap();
    assert!(mss
        .lines()
        .any(|line| line.contains("awg0") && line.ends_with("--set-mss 1280")));

    const BACKUP: &str = "[2001:db8:f00::7]:443";
    const BACKUP_IP: &str = "2001:db8:f00::7";
    const BACKUP_ROUTE: &str = "2001:db8:f00::7/128";
    let reserve: std::net::SocketAddr = BACKUP.parse().unwrap();
    let backups = |values: Value| {
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["servers"][0]["config"]["client"]["endpoint_backups"] = values;
            Ok(())
        })
        .unwrap();
    };
    let outer_route = |op, prefix| {
        k.call(
            "ip",
            &[
                "-6", "route", op, prefix, "dev", "awg2", "table", "828", "proto", "99",
            ],
        )
        .unwrap();
    };
    let block_wan = |op, prefix| {
        k.call("ip", &["-6", "route", op, "prohibit", prefix])
            .unwrap();
    };
    outer_route("add", BACKUP_ROUTE);
    backups(json!([BACKUP]));
    selected.set(reserve);
    let refresh = || operate_at(&db, &router, Operation::Refresh, now, live);
    refresh().unwrap();
    assert_eq!(payload_path().as_deref(), Some("awg0"));
    let marked = k
        .call(
            "ip",
            &["-6", "route", "get", BACKUP_IP, "mark", "0xa0000000"],
        )
        .unwrap();
    assert!(marked.contains("dev awg2"));

    selected.set(std::net::SocketAddr::new(reserve.ip(), 8443));
    refresh().unwrap();
    assert_eq!(payload_path(), None);
    selected.set(reserve);
    block_wan("add", BACKUP_ROUTE);
    assert!(k.call("ip", &["-6", "route", "get", BACKUP_IP]).is_err());
    refresh().unwrap();
    assert_eq!(payload_path(), None);
    block_wan("del", BACKUP_ROUTE);
    refresh().unwrap();
    assert_eq!(payload_path().as_deref(), Some("awg0"));

    let reserve_change = RoutedMtuChange {
        nested_endpoint: Some(BACKUP.into()),
        ..change.clone()
    };
    launch(&reserve_change);
    stage(AFTER, &reserve_change, None);
    recover(false);
    waiting();
    launch(&reserve_change);
    stage(0, &reserve_change, None);
    recover(false);
    waiting();
    block_wan("add", BACKUP_ROUTE);
    recover(true);
    waiting();
    block_wan("del", BACKUP_ROUTE);
    recover(true);
    assert!(!pending_mtu_edit(&db).unwrap());
    assert_eq!(payload_path().as_deref(), Some("awg0"));
    let doc = nfqws2_awg_profile::read(&db).unwrap();
    assert_eq!(doc["servers"][0]["config"]["mtu"], 0);
    assert_eq!(doc["servers"][0]["config"]["endpoint"], ENDPOINT);

    const SHARED_RESERVE: &str = "[2001:db8:f00::1]:8443";
    backups(json!([SHARED_RESERVE]));
    selected.set(SHARED_RESERVE.parse().unwrap());
    block_wan("del", "2001:db8:f00::1/128");
    refresh().unwrap();
    assert_eq!(payload_path().as_deref(), Some("awg0"));
    block_wan("add", "2001:db8:f00::1/128");
    refresh().unwrap();
    assert_eq!(payload_path(), None);
    selected.set(endpoint);
    backups(json!([]));
    outer_route("del", BACKUP_ROUTE);
    refresh().unwrap();
    assert_eq!(payload_path().as_deref(), Some("awg0"));

    const NEW_PORT: &str = "[2001:db8:f00::1]:6080";
    let combined = RoutedMtuChange {
        nested_mtu_before_recorded: false,
        nested_endpoint: None,
        endpoint_edit: Some(RoutedEndpointEdit {
            before: ENDPOINT.into(),
            after: NEW_PORT.into(),
            previous_reserve: None,
            resolved_before: vec![],
            resolved_after: vec![],
        }),
        ..change
    };
    launch(&combined);
    stage(AFTER, &combined, Some(NEW_PORT));
    recover(true);
    waiting();
    selected.set(NEW_PORT.parse().unwrap());
    recover(false);
    waiting();
    launch(&combined);
    stage(0, &combined, Some(ENDPOINT));
    recover(true);
    waiting();
    selected.set(endpoint);
    recover(true);
    assert_eq!(payload_path().as_deref(), Some("awg0"));
    assert!(!pending_mtu_edit(&db).unwrap());
    let restored = nfqws2_awg_profile::read(&db).unwrap();
    assert_eq!(restored["servers"][0]["config"]["endpoint"], ENDPOINT);
    assert_eq!(restored["servers"][0]["config"]["mtu"], 0);

    launch(&combined);
    stage(AFTER, &combined, Some(NEW_PORT));
    selected.set(NEW_PORT.parse().unwrap());
    recover(true);
    assert_eq!(payload_path().as_deref(), Some("awg0"));
    assert!(!pending_mtu_edit(&db).unwrap());
    check_transport();

    const NEW_ADDRESS: &str = "[2001:db8:f00::9]:6080";
    const NEW_IP: &str = "2001:db8:f00::9";
    const NEW_ROUTE: &str = "2001:db8:f00::9/128";
    const NEW_MTU: u16 = 1400;
    let distinct = RoutedMtuChange {
        before: AFTER,
        after: NEW_MTU,
        implicit_before_mtu: None,
        endpoint_edit: Some(RoutedEndpointEdit {
            before: NEW_PORT.into(),
            after: NEW_ADDRESS.into(),
            previous_reserve: None,
            resolved_before: vec![],
            resolved_after: vec![],
        }),
        ..combined
    };
    let selected_path = || k.call("ip", &["-6", "route", "get", NEW_IP, "mark", "0xa0000000"]);
    block_wan("add", NEW_ROUTE);
    outer_route("add", NEW_ROUTE);
    assert!(k.call("ip", &["-6", "route", "get", NEW_IP]).is_err());
    assert!(selected_path().unwrap().contains("dev awg2"));
    launch(&distinct);
    stage(NEW_MTU, &distinct, Some(NEW_ADDRESS));
    operate_at(&db, &router, Operation::Suspend, now, live).unwrap();
    recover(true);
    waiting();
    selected.set(NEW_ADDRESS.parse().unwrap());
    outer_route("del", NEW_ROUTE);
    assert!(selected_path().is_err());
    recover(true);
    waiting();
    outer_route("add", NEW_ROUTE);
    launch(&distinct);
    stage(AFTER, &distinct, Some(NEW_PORT));
    recover(true);
    waiting();
    selected.set(NEW_PORT.parse().unwrap());
    recover(true);
    assert_eq!(payload_path().as_deref(), Some("awg0"));
    assert!(!pending_mtu_edit(&db).unwrap());
    assert_eq!(
        nfqws2_awg_profile::read(&db).unwrap()["servers"][0]["config"]["endpoint"],
        NEW_PORT
    );
    launch(&distinct);
    stage(NEW_MTU, &distinct, Some(NEW_ADDRESS));
    selected.set(NEW_ADDRESS.parse().unwrap());
    const OLD_ROUTE: &str = "2001:db8:f00::1/128";
    outer_route("del", OLD_ROUTE);
    recover(true);
    assert_eq!(payload_path().as_deref(), Some("awg0"));
    assert!(!pending_mtu_edit(&db).unwrap());
    assert!(selected_path().unwrap().contains("dev awg2"));
    assert!(k
        .call(
            "ip",
            &[
                "-6",
                "route",
                "get",
                "2001:db8:f00::1",
                "mark",
                "0xa0000000"
            ],
        )
        .is_err());
    const V4_ENDPOINT: &str = "198.51.100.69:6080";
    const V4_IP: &str = "198.51.100.69";
    const V4_ROUTE: &str = "198.51.100.69/32";
    const V4_SOURCE: &str = "198.18.0.88";
    let v4_address = |op| {
        k.call("ip", &["-4", "addr", op, "198.18.0.88/32", "dev", "awg2"])
            .unwrap();
    };
    let v4_transport = |op| {
        k.call("ip", &["-4", "route", op, "prohibit", V4_ROUTE])
            .unwrap();
        k.call(
            "ip",
            &[
                "-4", "route", op, V4_ROUTE, "dev", "awg2", "src", V4_SOURCE, "table", "828",
                "proto", "99",
            ],
        )
        .unwrap();
        for (pref, action) in [("60", &["lookup", "828"][..]), ("61", &["prohibit"][..])] {
            let mut args = vec!["-4", "rule", op, "pref", pref, "fwmark", "0xa0000000"];
            args.extend_from_slice(action);
            k.call("ip", &args).unwrap();
        }
    };
    v4_address("add");
    v4_transport("add");
    assert!(route_device(&k, V4_IP).is_none());
    let v4_marked = k
        .call("ip", &["-4", "route", "get", V4_IP, "mark", "0xa0000000"])
        .unwrap();
    assert!(v4_marked.contains("dev awg2") && v4_marked.contains("src 198.18.0.88"));
    k.call("ip", &["link", "set", "dev", "awg2", "mtu", "1350"])
        .unwrap();
    set_physical_mtu(&k, 1270);
    reported_mtu.set(1270);
    refresh().unwrap();
    assert_eq!(payload_path().as_deref(), Some("awg0"));
    let cross = RoutedMtuChange {
        before: NEW_MTU,
        after: AFTER,
        endpoint_edit: Some(RoutedEndpointEdit {
            before: NEW_ADDRESS.into(),
            after: V4_ENDPOINT.into(),
            previous_reserve: None,
            resolved_before: vec![],
            resolved_after: vec![],
        }),
        ..distinct
    };
    let parked = || {
        assert_eq!(payload_path(), None);
        assert!(pending_mtu_edit(&db).unwrap());
    };
    launch(&cross);
    stage(AFTER, &cross, Some(V4_ENDPOINT));
    recover(true);
    parked();
    selected.set(V4_ENDPOINT.parse().unwrap());
    set_physical_mtu(&k, 1290);
    reported_mtu.set(1290);
    recover(false);
    parked();
    launch(&cross);
    stage(NEW_MTU, &cross, Some(NEW_ADDRESS));
    recover(true);
    parked();
    selected.set(NEW_ADDRESS.parse().unwrap());
    set_physical_mtu(&k, 1270);
    reported_mtu.set(1270);
    recover(true);
    assert_eq!(payload_path().as_deref(), Some("awg0"));
    assert!(!pending_mtu_edit(&db).unwrap());
    assert_eq!(physical_mtu(&k), 1270);
    launch(&cross);
    stage(AFTER, &cross, Some(V4_ENDPOINT));
    selected.set(V4_ENDPOINT.parse().unwrap());
    set_physical_mtu(&k, 1290);
    reported_mtu.set(1290);
    recover(true);
    assert_eq!(payload_path().as_deref(), Some("awg0"));
    assert!(!pending_mtu_edit(&db).unwrap());
    assert_eq!(physical_mtu(&k), 1290);
    operate_at(&db, &router, Operation::Teardown, now, live).unwrap();
    v4_transport("del");
    v4_address("del");
    outer_route("del", NEW_ROUTE);
    block_wan("del", NEW_ROUTE);
    outer_route("add", OLD_ROUTE);
    configure("del");
    k.call("ip", &["-6", "addr", "del", "fd13::2/128", "dev", "awg2"])
        .unwrap();
    k.call(
        "ip",
        &[
            "link",
            "set",
            "dev",
            "awg2",
            "mtu",
            initial_outer_mtu.trim(),
        ],
    )
    .unwrap();
    set_physical_mtu(&k, initial_mtu);
    assert_eq!(payload_path().as_deref(), Some("wan0"));
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn routed_combined_endpoint_mtu_keeps_the_real_fib_parked_until_the_exact_pair() {
    require_isolated_namespaces();
    combined_edit_with_real_routes(false);
    direct_cross_family_pair_with_independent_wan();
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn inherited_joint_endpoint_mtu_opens_real_routes_only_after_exact_native_ack() {
    require_isolated_namespaces();
    combined_edit_with_real_routes(true);
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn confirmed_static_dns_retry_preserves_real_route_ownership() {
    require_isolated_namespaces();
    for dual in [false, true] {
        static_dns_retry_on_real_fib(dual);
    }
}

fn static_dns_retry_on_real_fib(dual: bool) {
    use std::cell::Cell;

    const NAME: &str = "office.example.test";
    const OTHER_NAME: &str = "other.example.test";
    const EXTRA: &str = "admin.example.test";
    const ADDRESS: &str = "203.0.113.50";
    const EXTRA_ADDRESS: &str = "203.0.113.51";
    const ADDRESS_V6: &str = "2001:db8:70::50";
    const EXTRA_ADDRESS_V6: &str = "2001:db8:70::51";
    const UNRELATED: &str = "203.0.113.55";
    let router = nfqws2_router_command::System;
    let k = kernel(&router);
    let (_dir, db, _) = setup();
    protect(&db);
    if dual {
        k.call(
            "ip",
            &["-6", "addr", "add", "fd21::2/128", "dev", "awg0", "nodad"],
        )
        .unwrap();
    }
    let configure_name = |name| {
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["routing"]["domain_source"] = json!("resolve");
            let cfg = &mut doc["servers"][0]["config"];
            if dual {
                cfg["peers"] = json!([{
                    "id": "router", "is_router": true, "address": "10.21.0.2/32,fd21::2/128",
                    "allowed_ips": "0.0.0.0/0,::/0"
                }]);
            }
            let domains = if dual { vec![name, EXTRA] } else { vec![name] };
            cfg["routing"]["zones"] = json!([
                {"enabled": true, "route": "tunnel", "domains": domains, "include_subdomains": false}
            ]);
            Ok(())
        })
        .unwrap();
    };
    let live = |cfg: &Value, iface: &str| {
        if dual {
            dual_peer(cfg, iface)
        } else {
            peer(cfg, iface)
        }
    };
    configure_name(NAME);
    let request = dns_request(&db, Operation::Apply).unwrap().unwrap();
    let mut answers: std::collections::BTreeMap<_, _> =
        [(NAME.to_owned(), vec![ADDRESS.parse().unwrap()])].into();
    if dual {
        assert_eq!(request.names, [EXTRA, NAME]);
        assert_eq!(request.dual_stack, [EXTRA, NAME]);
        answers
            .get_mut(NAME)
            .unwrap()
            .push(ADDRESS_V6.parse().unwrap());
        answers.insert(
            EXTRA.to_owned(),
            vec![
                EXTRA_ADDRESS.parse().unwrap(),
                EXTRA_ADDRESS_V6.parse().unwrap(),
            ],
        );
    } else {
        assert_eq!(request.names, [NAME]);
    }
    let snapshot = DnsSnapshot { request, answers };
    let now = nfqws2_awg_profile::now();
    operate_with_dns_at(&db, &router, Operation::Apply, now, Some(&snapshot), live).unwrap();
    operate_at(&db, &router, Operation::Commit, now, live).unwrap();
    let original = Journal::read(&db).unwrap();
    let ticket = confirmed_static_dns_retry(&db, &snapshot.request)
        .unwrap()
        .unwrap();
    assert_eq!(ticket.snapshot(), &snapshot);
    let same_routes = || {
        assert_eq!(route_device(&k, ADDRESS).as_deref(), Some("awg0"));
        assert_eq!(route_device(&k, UNRELATED).as_deref(), Some("wan0"));
        if dual {
            assert_eq!(route_device(&k, EXTRA_ADDRESS).as_deref(), Some("awg0"));
            for address in [ADDRESS_V6, EXTRA_ADDRESS_V6] {
                let row = k.call("ip", &["-6", "route", "get", address]).unwrap();
                assert!(row.contains("dev awg0"));
            }
            let other = k
                .call("ip", &["-6", "route", "get", "2001:db8:70::55"])
                .unwrap();
            assert!(other.contains("dev wan0"));
        }
    };
    same_routes();
    let checks = Cell::new(0);
    let expired = apply_confirmed_static_dns_retry(&db, &router, &ticket, live, || {
        checks.set(checks.get() + 1);
        if checks.get() == 1 {
            Ok(())
        } else {
            Err(io::ErrorKind::TimedOut.into())
        }
    })
    .unwrap_err();
    assert_eq!(expired.kind(), io::ErrorKind::TimedOut);
    assert!(checks.get() >= 2);
    assert_eq!(Journal::read(&db).unwrap().installed, original.installed);
    same_routes();
    configure_name(OTHER_NAME);
    assert!(confirmed_static_dns_retry(&db, &snapshot.request)
        .unwrap()
        .is_none());
    assert!(apply_confirmed_static_dns_retry(&db, &router, &ticket, live, || Ok(())).is_err());
    assert_eq!(Journal::read(&db).unwrap().committed, original.committed);
    same_routes();
    configure_name(NAME);
    apply_confirmed_static_dns_retry(&db, &router, &ticket, live, || Ok(())).unwrap();
    same_routes();
    operate_at(&db, &router, Operation::Commit, now, live).unwrap();
    assert_eq!(Journal::read(&db).unwrap().committed, original.committed);
    operate_at(&db, &router, Operation::Teardown, now, live).unwrap();
    assert_eq!(route_device(&k, ADDRESS).as_deref(), Some("wan0"));
    if dual {
        k.call("ip", &["-6", "addr", "del", "fd21::2/128", "dev", "awg0"])
            .unwrap();
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn dormant_replacement_rebinds_confirmed_revision_without_real_route_writes() {
    const ROUTED_ADDRESS: &str = "203.0.113.50";
    const WAN_ADDRESS: &str = "192.0.2.50";
    const SOURCE: &str = "unused";
    const REPLACEMENT: &str = "replacement";

    struct ReadOnly;
    impl Runner for ReadOnly {
        fn run(&self, program: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
            assert!(
                !args.iter().any(|arg| matches!(
                    *arg,
                    "add" | "del" | "replace" | "flush" | "-A" | "-D" | "-I" | "-F"
                )),
                "metadata-only replacement attempted a kernel write"
            );
            nfqws2_router_command::System.run(program, args, deadline)
        }

        fn run_input(&self, _: &str, _: &[&str], _: &[u8], _: Instant) -> io::Result<String> {
            panic!("metadata-only replacement attempted a batch write")
        }
    }

    require_isolated_namespaces();
    let system = nfqws2_router_command::System;
    let k = kernel(&system);
    let (_dir, db, _) = setup();
    protect(&db);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let running = &mut doc["servers"][0]["config"];
        running["install"] = json!("imported");
        running["endpoint"] = json!("198.51.100.10:443");
        running["client"]["rust_managed"] = json!(true);
        let mut dormant = running.clone();
        dormant["endpoint"] = json!("");
        dormant["enabled"] = json!(false);
        dormant["client"] = json!({"enabled":false, "standby":true});
        dormant["client_iface"] = json!("awg20");
        dormant["routing"]["zones"] = json!([
            {"name":"Dormant", "enabled":false, "order":2, "ips":["192.0.2.50/32"]}
        ]);
        let mut replacement = dormant.clone();
        replacement["client_iface"] = json!("awg21");
        replacement["routing"]["zones"] = json!([]);
        doc["servers"].as_array_mut().unwrap().extend([
            json!({"id":SOURCE,"config":dormant}),
            json!({"id":REPLACEMENT,"config":replacement}),
        ]);
        Ok(())
    })
    .unwrap();
    let now = nfqws2_awg_profile::now();
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &system, op, now, peer).unwrap();
    }
    let before = Journal::read(&db).unwrap();
    assert_eq!(before.expires, 0);
    assert!(inspect(&db, &ReadOnly).unwrap().ready);
    let routes = || {
        ["-4", "-6"].map(|family| {
            (
                k.call("ip", &[family, "rule", "show"]).unwrap(),
                k.call("ip", &[family, "route", "show", "table", "all"])
                    .unwrap(),
            )
        })
    };
    let original_routes = routes();
    assert_eq!(route_device(&k, ROUTED_ADDRESS).as_deref(), Some("awg0"));
    assert_eq!(route_device(&k, WAN_ADDRESS).as_deref(), Some("wan0"));

    nfqws2_awg_profile::edit_document(&db, |doc| {
        let previous = doc.clone();
        let source = doc["servers"].as_array_mut().unwrap().remove(1);
        assert_eq!(source["id"], SOURCE);
        let mut rule = source["config"]["routing"]["zones"][0].clone();
        rule["tunnel_id"] = json!(REPLACEMENT);
        assert_eq!(doc["servers"][1]["id"], REPLACEMENT);
        doc["servers"][1]["config"]["routing"]["zones"] = json!([rule]);
        doc["routing_revision"] = json!(before.committed.revision + 1);
        stage_dormant_replacement(&db, &ReadOnly, &previous, doc, SOURCE, REPLACEMENT)
    })
    .unwrap();
    assert_eq!(Journal::read(&db).unwrap(), before);
    assert_eq!(routes(), original_routes);

    // Recover the saved profile change before the ordinary kernel audit.
    operate_at(&db, &ReadOnly, Operation::Recover, now, peer).unwrap();
    assert!(!finish_dormant_replacement(&db).unwrap());
    let after = Journal::read(&db).unwrap();
    assert_eq!(after.boot, before.boot);
    assert_eq!(after.installed.revision, before.installed.revision + 1);
    assert_eq!(after.committed.revision, before.committed.revision + 1);
    assert_eq!(objects(&after.installed), objects(&before.installed));
    assert_eq!(routes(), original_routes);
    assert!(inspect(&db, &ReadOnly).unwrap().ready);
    assert_eq!(route_device(&k, ROUTED_ADDRESS).as_deref(), Some("awg0"));
    assert_eq!(route_device(&k, WAN_ADDRESS).as_deref(), Some("wan0"));
    let doc = nfqws2_awg_profile::read(&db).unwrap();
    assert!(doc["servers"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["id"] != SOURCE));
    assert_eq!(
        doc["servers"][1]["config"]["routing"]["zones"][0]["tunnel_id"],
        REPLACEMENT
    );
    assert_eq!(doc["servers"][1]["config"]["client"]["standby"], true);
    operate_at(&db, &system, Operation::Teardown, now, peer).unwrap();
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn active_replacement_keeps_real_cidr_behind_kill_switch_through_failure() {
    require_isolated_namespaces();
    for saved_kill_switch in [true, false] {
        for multiple in [false, true] {
            real_cidr_replacement(saved_kill_switch, multiple, ReplacementOuter::None);
        }
    }
    for saved_kill_switch in [true, false] {
        real_cidr_replacement(saved_kill_switch, true, ReplacementOuter::Configured);
    }
}

#[test]
#[ignore = "requires isolated Linux namespaces and the synthetic named-WAN hosts fixture"]
fn active_named_replacement_keeps_real_cidr_behind_kill_switch_through_failure() {
    require_isolated_namespaces();
    assert!(std::path::Path::new("/synthetic-guest").is_file());
    real_cidr_replacement(true, false, ReplacementOuter::LiveNamed { source: true, target: true });
}

#[test]
#[ignore = "requires isolated Linux namespaces and the synthetic named-WAN hosts fixture"]
fn active_mixed_named_replacement_restores_both_saved_kill_switch_modes() {
    require_isolated_namespaces();
    assert!(std::path::Path::new("/synthetic-guest").is_file());
    for killswitch in [true, false] {
        for (source, target) in [(true, false), (false, true), (true, true)] {
            eprintln!("mixed named replacement: killswitch={killswitch} source={source} target={target}");
            real_cidr_replacement(killswitch, false, ReplacementOuter::LiveNamed { source, target });
        }
    }
}

#[test]
#[ignore = "requires isolated Linux namespaces and the synthetic named-WAN hosts fixture"]
fn active_replacement_launches_a_vacant_named_target_after_checked_endpoint_selection() {
    require_isolated_namespaces();
    assert!(std::path::Path::new("/synthetic-guest").is_file());
    for killswitch in [true, false] {
        real_cidr_replacement(killswitch, false, ReplacementOuter::ColdNamedTarget);
    }
}

#[test]
#[ignore = "requires isolated Linux namespaces and the synthetic named-WAN hosts fixture"]
fn active_replacement_defers_a_failed_named_target_with_exact_saved_guard() {
    require_isolated_namespaces();
    assert!(std::path::Path::new("/synthetic-guest").is_file());
    for killswitch in [true, false] {
        real_cidr_replacement(killswitch, false, ReplacementOuter::UnavailableNamedTarget);
    }
}

#[test]
#[ignore = "requires isolated Linux namespaces and the synthetic named-WAN hosts fixture"]
fn active_replacement_retries_deferred_name_at_fresh_own_endpoint() {
    require_isolated_namespaces();
    assert!(std::path::Path::new("/synthetic-guest").is_file());
    for killswitch in [true, false] {
        real_cidr_replacement(killswitch, false, ReplacementOuter::RotatedNamedTarget);
    }
}

#[test]
#[ignore = "requires isolated Linux namespaces and the synthetic named-WAN hosts fixture"]
fn active_replacement_defers_initially_unresolved_name_without_payload_authority() {
    require_isolated_namespaces();
    assert!(std::path::Path::new("/synthetic-guest").is_file());
    for killswitch in [true, false] {
        real_cidr_replacement(killswitch, false, ReplacementOuter::InitiallyUnresolvedNamedTarget);
    }
}

#[test]
#[ignore = "requires isolated Linux namespaces and the synthetic named-WAN hosts fixture"]
fn active_replacement_deferred_aaaa_only_still_requires_fresh_ipv4_owner() {
    require_isolated_namespaces();
    assert!(std::path::Path::new("/synthetic-guest").is_file());
    for killswitch in [true, false] {
        real_cidr_replacement(killswitch, false, ReplacementOuter::AaaaOnlyNamedTarget);
    }
}

#[test]
#[ignore = "requires isolated Linux namespaces and the synthetic named-WAN fixture"]
fn active_replacement_warm_ipv6_routes_only_after_exact_native_candidate() {
    require_isolated_namespaces();
    assert!(std::path::Path::new("/synthetic-guest").is_file());
    for killswitch in [true, false] {
        real_cidr_replacement(killswitch, false, ReplacementOuter::WarmAaaaNamedTarget);
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn active_replacement_accepts_a_cold_ordinary_target() {
    require_isolated_namespaces();
    for killswitch in [false, true] {
        real_cidr_replacement(killswitch, false, ReplacementOuter::ColdTarget);
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn active_replacement_starts_a_cold_target_for_live_dns() {
    require_isolated_namespaces();
    for killswitch in [false, true] {
        real_cidr_replacement(killswitch, false, ReplacementOuter::ColdDnsTarget);
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn active_replacement_defers_unavailable_ordinary_target() {
    require_isolated_namespaces();
    for killswitch in [false, true] {
        real_cidr_replacement(killswitch, false, ReplacementOuter::UnavailableTarget);
        real_cidr_replacement(killswitch, false, ReplacementOuter::UnavailableScopedTarget);
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn active_replacement_defers_unavailable_target_with_dns() {
    require_isolated_namespaces();
    for killswitch in [false, true] {
        real_cidr_replacement(killswitch, false, ReplacementOuter::UnavailableDnsTarget);
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn disabled_replacement_removes_only_confirmed_learned_routing() {
    require_isolated_namespaces();
    for killswitch in [false, true] {
        for state in [ReplacementOuter::DisabledDnsClient, ReplacementOuter::DisabledDnsServer] {
            real_cidr_replacement(killswitch, false, state);
        }
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn active_replacement_retires_nested_source_after_real_cidr_transfer() {
    require_isolated_namespaces();
    for saved_kill_switch in [true, false] {
        real_cidr_replacement(saved_kill_switch, true, ReplacementOuter::Nested);
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn active_replacement_holds_standby_outer_until_real_nested_source_retirement() {
    require_isolated_namespaces();
    for saved_kill_switch in [true, false] {
        real_cidr_replacement(saved_kill_switch, true, ReplacementOuter::NestedStandby);
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn active_replacement_preserves_shared_live_nested_outer_through_real_transfer() {
    require_isolated_namespaces();
    for saved_kill_switch in [true, false] {
        real_cidr_replacement(saved_kill_switch, true, ReplacementOuter::SharedNested);
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn active_replacement_transfers_direct_source_to_verified_nested_successor_real_fib() {
    require_isolated_namespaces();
    for saved_kill_switch in [true, false] {
        real_cidr_replacement(saved_kill_switch, true, ReplacementOuter::NestedTarget);
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn active_replacement_preserves_distinct_nested_outers_through_real_fib_transfer() {
    require_isolated_namespaces();
    for saved_kill_switch in [true, false] {
        real_cidr_replacement(saved_kill_switch, true, ReplacementOuter::DistinctNested);
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn active_replacement_holds_independent_standby_outer_through_real_nested_transfer() {
    require_isolated_namespaces();
    for saved_kill_switch in [true, false] {
        real_cidr_replacement(
            saved_kill_switch,
            true,
            ReplacementOuter::DistinctNestedStandby,
        );
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn active_replacement_switches_permanent_nested_marked_fib_under_both_saved_flags() {
    require_isolated_namespaces();
    for saved_kill_switch in [true, false] {
        real_cidr_replacement(
            saved_kill_switch,
            false,
            ReplacementOuter::DistinctPermanent,
        );
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn active_replacement_keeps_real_nested_only_permanent_paths_after_plain_loss() {
    require_isolated_namespaces();
    for saved_kill_switch in [true, false] {
        real_cidr_replacement(
            saved_kill_switch,
            false,
            ReplacementOuter::PermanentWithoutPlain,
        );
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn initial_permanent_policy_keeps_unselected_native_path_without_plain_wan() {
    require_isolated_namespaces();
    for saved_kill_switch in [true, false] {
        real_cidr_replacement(
            saved_kill_switch,
            false,
            ReplacementOuter::InitialPermanentWithoutPlain,
        );
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn active_replacement_protects_marked_direct_source_until_permanent_target_is_live() {
    require_isolated_namespaces();
    for saved_kill_switch in [true, false] {
        real_cidr_replacement(
            saved_kill_switch,
            false,
            ReplacementOuter::MixedPermanentTarget,
        );
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn active_replacement_retires_permanent_source_for_direct_packed_target() {
    require_isolated_namespaces();
    real_cidr_replacement(true, false, ReplacementOuter::MixedPermanentSource);
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn active_replacement_retires_permanent_source_for_direct_plain_target() {
    require_isolated_namespaces();
    real_cidr_replacement(false, false, ReplacementOuter::MixedPermanentSource);
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn active_replacement_preserves_real_source_selectors_and_guard_scope() {
    require_isolated_namespaces();
    for saved_kill_switch in [true, false] {
        real_cidr_replacement(saved_kill_switch, true, ReplacementOuter::SourceQualified);
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn active_replacement_preserves_real_redirect_and_replays_only_new_dns_revision() {
    require_isolated_namespaces();
    for saved_kill_switch in [true, false] {
        real_cidr_replacement(saved_kill_switch, false, ReplacementOuter::ObservedDns);
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn active_replacement_preserves_real_live_dns_rrset_with_fresh_scope() {
    require_isolated_namespaces();
    for saved_kill_switch in [true, false] {
        real_cidr_replacement(saved_kill_switch, false, ReplacementOuter::LiveObservedDns);
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn active_replacement_preserves_only_the_exact_live_client_dns_route() {
    require_isolated_namespaces();
    for saved_kill_switch in [true, false] {
        real_cidr_replacement(
            saved_kill_switch,
            false,
            ReplacementOuter::ClientObservedDns,
        );
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn firmware_mixed_policy_lifetime_and_replacement_on_real_packets() {
    require_isolated_namespaces();
    for killswitch in [true, false] {
        for replacement in [
            FirmwareReplacement::Warm,
            FirmwareReplacement::NxDomain,
            FirmwareReplacement::Changed,
        ] {
            real_firmware_lifetime(killswitch, replacement);
        }
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn explicit_mixed_firmware_names_accept_cold_proof_without_process_history() {
    require_isolated_namespaces();
    for killswitch in [true, false] {
        real_firmware_lifetime(killswitch, FirmwareReplacement::ChangedExplicit);
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn explicit_global_firmware_rrset_rotates_for_all_clients_without_history() {
    require_isolated_namespaces();
    for killswitch in [true, false] {
        real_firmware_lifetime(killswitch, FirmwareReplacement::ChangedGlobalExplicit);
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn explicit_global_firmware_nxdomain_retires_only_its_routes() {
    require_isolated_namespaces();
    for killswitch in [true, false] {
        real_firmware_lifetime(killswitch, FirmwareReplacement::GlobalNxDomain);
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn multiple_explicit_global_firmware_names_preserve_the_full_fresh_union() {
    require_isolated_namespaces();
    for killswitch in [true, false] {
        real_firmware_lifetime(killswitch, FirmwareReplacement::ChangedMultipleGlobal);
        real_firmware_lifetime(
            killswitch,
            FirmwareReplacement::ChangedMultipleGlobalNegative,
        );
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ArchiveScenario {
    Warm,
    Discovered,
    Recent,
    Both,
    NoHistory,
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn wildcard_firmware_replacement_reconstructs_the_two_go_archives() {
    require_isolated_namespaces();
    for killswitch in [false, true] {
        for scenario in [
            ArchiveScenario::Warm,
            ArchiveScenario::Discovered,
            ArchiveScenario::Recent,
            ArchiveScenario::Both,
            ArchiveScenario::NoHistory,
        ] {
            real_firmware_lifetime(killswitch, FirmwareReplacement::Archive(scenario));
        }
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn mixed_firmware_archive_pre_resolves_explicit_apex_and_discovered_wildcards() {
    require_isolated_namespaces();
    for killswitch in [false, true] {
        for scenario in [ArchiveScenario::Both, ArchiveScenario::NoHistory] {
            real_firmware_lifetime_with_archive(
                killswitch,
                FirmwareReplacement::Archive(scenario),
                FirmwareArchiveShape::ExplicitAndMask,
                None,
                false,
            );
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FirmwareArchiveShape {
    Masks,
    ExplicitAndMask,
    LegacySuffix,
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn legacy_firmware_suffix_recovers_its_apex_and_valid_discoveries() {
    require_isolated_namespaces();
    for killswitch in [false, true] {
        for scenario in [ArchiveScenario::Both, ArchiveScenario::NoHistory] {
            real_firmware_lifetime_with_archive(
                killswitch,
                FirmwareReplacement::Archive(scenario),
                FirmwareArchiveShape::LegacySuffix,
                None,
                false,
            );
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FirmwareReplacement {
    Warm,
    RetryRuntime,
    HeldRetryRuntime,
    TargetGlobalRetryRuntime,
    HeldColdRetry {
        shared: bool,
        negative: bool,
        newer: bool,
        withdraw_after_expiry: bool,
        paired_retry: bool,
        pair_first_positive: bool,
        pair_becomes_positive: bool,
    },
    NxDomain,
    Changed,
    ChangedExplicit,
    ChangedGlobalExplicit,
    GlobalNxDomain,
    ChangedMultipleGlobal,
    ChangedMultipleGlobalNegative,
    HeldOwner,
    ColdHeldOwner,
    UnavailableHeldOwner,
    RelocatedOwner,
    Archive(ArchiveScenario),
    HeldChanged,
    HeldNxDomain,
    TargetGlobal,
    TargetGlobalChanged,
    TargetGlobalNxDomain,
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn kernel_write_rejection_preserves_committed_transfer_for_retry() {
    require_isolated_namespaces();
    for killswitch in [false, true] {
        real_firmware_lifetime(killswitch, FirmwareReplacement::RetryRuntime);
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn kernel_write_rejection_saves_transfer_and_keeps_the_global_fib_live() {
    require_isolated_namespaces();
    for killswitch in [false, true] {
        for replacement in [
            FirmwareReplacement::HeldRetryRuntime,
            FirmwareReplacement::TargetGlobalRetryRuntime,
        ] {
            real_firmware_lifetime(killswitch, replacement);
        }
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn cold_target_keeps_the_independent_global_fib() {
    require_isolated_namespaces();
    for killswitch in [false, true] {
        real_firmware_lifetime(killswitch, FirmwareReplacement::ColdHeldOwner);
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn unavailable_target_keeps_the_independent_global_fib() {
    require_isolated_namespaces();
    for killswitch in [false, true] {
        real_firmware_lifetime(killswitch, FirmwareReplacement::UnavailableHeldOwner);
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn kernel_rejection_rechecks_cold_dns_on_the_already_global_receiver() {
    require_isolated_namespaces();
    for killswitch in [false, true] {
        for negative in [false, true] {
            real_firmware_lifetime(
                killswitch,
                FirmwareReplacement::HeldColdRetry {
                    shared: true,
                    negative,
                    newer: false,
                    withdraw_after_expiry: false,
                    paired_retry: false,
                    pair_first_positive: false,
                    pair_becomes_positive: false,
                },
            );
        }
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn kernel_rejection_rechecks_cold_dns_with_an_independent_global_peer() {
    require_isolated_namespaces();
    for killswitch in [false, true] {
        for negative in [false, true] {
            real_firmware_lifetime(
                killswitch,
                FirmwareReplacement::HeldColdRetry {
                    shared: false,
                    negative,
                    newer: false,
                    withdraw_after_expiry: false,
                    paired_retry: false,
                    pair_first_positive: false,
                    pair_becomes_positive: false,
                },
            );
        }
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn a_new_cold_dns_rrset_can_replace_pending_members_on_the_existing_global_receiver() {
    check_newer_rrset_after_rejection(true);
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn a_new_cold_dns_rrset_can_replace_pending_members_with_an_independent_global_peer() {
    check_newer_rrset_after_rejection(false);
}

fn check_newer_rrset_after_rejection(shared: bool) {
    require_isolated_namespaces();
    for killswitch in [false, true] {
        for negative in [false, true] {
            real_firmware_lifetime(
                killswitch,
                FirmwareReplacement::HeldColdRetry {
                    shared,
                    negative,
                    newer: true,
                    withdraw_after_expiry: false,
                    paired_retry: false,
                    pair_first_positive: false,
                    pair_becomes_positive: false,
                },
            );
        }
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn expired_positive_policy_hint_allows_fresh_nxdomain_without_disturbing_global_fib() {
    require_isolated_namespaces();
    for shared in [true, false] {
        for killswitch in [false, true] {
            real_firmware_lifetime(
                killswitch,
                FirmwareReplacement::HeldColdRetry {
                    shared,
                    negative: false,
                    newer: false,
                    withdraw_after_expiry: true,
                    paired_retry: false,
                    pair_first_positive: false,
                    pair_becomes_positive: false,
                },
            );
        }
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn a_cold_scoped_retry_uses_a_new_positive_and_the_same_named_negative() {
    require_isolated_namespaces();
    for shared in [true, false] {
        for killswitch in [false, true] {
            real_firmware_lifetime(
                killswitch,
                FirmwareReplacement::HeldColdRetry {
                    shared,
                    negative: false,
                    newer: true,
                    withdraw_after_expiry: false,
                    paired_retry: true,
                    pair_first_positive: false,
                    pair_becomes_positive: false,
                },
            );
        }
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn a_two_name_retry_uses_the_expiry_of_only_the_newly_negative_name() {
    require_isolated_namespaces();
    for shared in [true, false] {
        for killswitch in [false, true] {
            real_firmware_lifetime(
                killswitch,
                FirmwareReplacement::HeldColdRetry {
                    shared,
                    negative: false,
                    newer: true,
                    withdraw_after_expiry: false,
                    paired_retry: true,
                    pair_first_positive: true,
                    pair_becomes_positive: false,
                },
            );
        }
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn a_cold_scoped_retry_replaces_prior_negative_with_two_fresh_positive_answers() {
    require_isolated_namespaces();
    for shared in [true, false] {
        for killswitch in [false, true] {
            real_firmware_lifetime(
                killswitch,
                FirmwareReplacement::HeldColdRetry {
                    shared,
                    negative: false,
                    newer: true,
                    withdraw_after_expiry: false,
                    paired_retry: true,
                    pair_first_positive: false,
                    pair_becomes_positive: true,
                },
            );
        }
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn firmware_mixed_policy_never_writes_the_held_owner_fib() {
    require_isolated_namespaces();
    real_firmware_lifetime(true, FirmwareReplacement::HeldOwner);
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn unguarded_firmware_transfer_stops_only_the_exact_replaced_client() {
    require_isolated_namespaces();
    real_firmware_lifetime(false, FirmwareReplacement::HeldOwner);
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn scoped_firmware_transfer_keeps_held_slot_when_interface_order_changes() {
    require_isolated_namespaces();
    for killswitch in [true, false] {
        real_firmware_lifetime(killswitch, FirmwareReplacement::RelocatedOwner);
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn scoped_firmware_transfer_uses_fresh_positive_or_negative_without_touching_global_owner() {
    require_isolated_namespaces();
    for killswitch in [true, false] {
        for replacement in [
            FirmwareReplacement::HeldChanged,
            FirmwareReplacement::HeldNxDomain,
        ] {
            real_firmware_lifetime(killswitch, replacement);
        }
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn scoped_firmware_transfer_into_already_selected_global_target_keeps_global_fib() {
    require_isolated_namespaces();
    real_firmware_lifetime(true, FirmwareReplacement::TargetGlobal);
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn scoped_firmware_transfer_to_existing_global_validates_only_the_moved_client() {
    require_isolated_namespaces();
    real_firmware_lifetime(false, FirmwareReplacement::TargetGlobal);
    for killswitch in [true, false] {
        for replacement in [
            FirmwareReplacement::TargetGlobalChanged,
            FirmwareReplacement::TargetGlobalNxDomain,
        ] {
            real_firmware_lifetime(killswitch, replacement);
        }
    }
}

#[test]
#[ignore = "isolated packet sender for firmware_mixed_policy_lifetime_and_replacement_on_real_packets"]
fn firmware_mixed_lan_packet_sender() {
    require_isolated_namespaces();
    let source = std::env::var("N2S_R99_LAN_CLIENT").unwrap();
    let destination = std::env::var("N2S_R99_LAN_DEST").unwrap();
    assert!(matches!(source.as_str(), "192.168.71.40" | "192.168.71.90"));
    assert!(matches!(
        destination.as_str(),
        "198.18.7.24"
            | "198.18.7.44"
            | "198.18.8.55"
            | "198.18.8.77"
            | "198.18.9.93"
            | "198.18.9.95"
            | "198.18.9.96"
            | "198.18.9.97"
            | "198.18.9.98"
    ));
    std::net::UdpSocket::bind((source.as_str(), 0))
        .unwrap()
        .send_to(b"scoped routing fixture", (destination.as_str(), 42042))
        .unwrap();
}

fn real_firmware_lifetime(killswitch: bool, replacement: FirmwareReplacement) {
    real_firmware_lifetime_with_archive(
        killswitch, replacement, FirmwareArchiveShape::Masks, None, false,
    );
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn disabled_mixed_firmware_rearm_restores_only_currently_eligible_packet_paths() {
    require_isolated_namespaces();
    for killswitch in [false, true] {
        for expired in [false, true] {
            real_firmware_lifetime_with_archive(
                killswitch, FirmwareReplacement::Warm, FirmwareArchiveShape::Masks, Some(expired), false,
            );
        }
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn disabled_mixed_firmware_rearm_preserves_the_independent_dns_paths() {
    require_isolated_namespaces();
    for killswitch in [false, true] {
        for expired in [false, true] {
            real_firmware_lifetime_with_archive(
                killswitch, FirmwareReplacement::HeldOwner, FirmwareArchiveShape::Masks, Some(expired), false,
            );
        }
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn disabled_dns_rearm_preserves_three_transparent_lan_bridges() {
    require_isolated_namespaces();
    for killswitch in [false, true] {
        real_firmware_lifetime_with_archive(
            killswitch, FirmwareReplacement::HeldOwner, FirmwareArchiveShape::Masks, Some(false), true,
        );
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn exact_firmware_policy_renews_without_inventing_an_ingress_with_three_lan_bridges() {
    require_isolated_namespaces();
    for killswitch in [false, true] {
        real_firmware_lifetime_with_archive(
            killswitch, FirmwareReplacement::ChangedExplicit, FirmwareArchiveShape::Masks, None, true,
        );
    }
}

fn real_firmware_lifetime_with_archive(
    killswitch: bool,
    replacement: FirmwareReplacement,
    archive_shape: FirmwareArchiveShape,
    disabled: Option<bool>,
    multiple_bridges: bool,
) {
    use super::super::super::active_replacement::held_dns_objects;
    use nfqws2_awg_profile::{
        active_replacement_fingerprint, ActiveReplacementPeer, ActiveReplacementStage,
        NativeRemovalSeal,
    };
    use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

    const SOURCE: &str = "awg0";
    const TARGET: &str = "firmware-next";
    const TARGET_IFACE: &str = "awg31";
    const HELD: &str = "firmware-held";
    const HELD_ENDPOINT: &str = "198.51.100.13:443";
    const LAN: &str = "br-lease-test";
    const SECOND_LAN: &str = "br-bystander1";
    const THIRD_LAN: &str = "br-bystander2";
    const CLIENT_NS: &str = "lease-test";
    const CLIENT_LINK: &str = "lease-client";
    const INSIDE: &str = "192.168.71.40";
    const OUTSIDE: &str = "192.168.71.90";
    const SCOPED: &str = "198.18.7.24";
    const OTHER_SCOPED: &str = "198.18.7.44";
    const GLOBAL: &str = "198.18.8.55";
    const OTHER_GLOBAL: &str = "198.18.8.77";
    const NEW_A: &str = "198.18.9.93";
    const NEW_B: &str = "198.18.9.95";
    const PENDING_OTHER: &str = "198.18.9.96";
    const LATEST_A: &str = "198.18.9.97";
    const LATEST_B: &str = "198.18.9.98";
    const SCOPED_NAME: &str = "a.scoped.test";
    const OTHER_SCOPED_NAME: &str = "b.scoped.test";
    const GLOBAL_NAME: &str = "a.global.test";
    const OTHER_NAME: &str = "another.global.test";
    const CHAIN: &str = "N2S_TEST_LIFETIME";
    const OLD_ENDPOINT: &str = "198.51.100.10:443";
    const NEW_ENDPOINT: &str = "198.51.100.11:443";
    struct Fault {
        target_route: AtomicBool,
        reject_target_route: AtomicBool,
        retired_stop: AtomicBool,
        rotated: bool,
        global_change: bool,
        global_guard: bool,
        held: std::sync::Mutex<Option<HeldInventory>>,
    }
    struct HeldInventory {
        iface: String,
        table: String,
        shared: bool,
        objects: Vec<String>,
    }
    fn held_inventory(
        iface: &str,
        table: &str,
        shared: bool,
        deadline: Instant,
    ) -> io::Result<Vec<String>> {
        let system = nfqws2_router_command::System;
        let route = system.run("ip", &["-4", "route", "show", "table", table], deadline)?;
        let rpdb = system.run("ip", &["-4", "rule", "show"], deadline)?;
        let firewall = system.run("iptables-save", &[], deadline)?;
        let global = |line: &str| line.contains(GLOBAL) || line.contains("203.0.113.128/25");
        let mut items = vec![if shared {
            route
                .lines()
                .filter(|line| global(line))
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            route
        }];
        items.extend(
            rpdb.lines()
                .filter(|line| {
                    line.ends_with(&format!("lookup {table}")) && (!shared || global(line))
                        || line.starts_with("69:") && global(line)
                })
                .map(str::to_owned),
        );
        items.extend(
            firewall
                .lines()
                .filter(|line| line.split_ascii_whitespace().any(|word| word == iface))
                .filter(|line| {
                    !shared || global(line) || line.contains("TCPMSS") || line.contains(CHAIN)
                })
                .map(str::to_owned),
        );
        Ok(items)
    }
    impl Runner for Fault {
        fn run(&self, program: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
            if program == "ip"
                && matches!(args, ["-4", "route", "add" | "replace", ..])
                && args.contains(&TARGET_IFACE)
                && self.reject_target_route.swap(false, Relaxed)
            {
                let mut rejected = args.to_vec();
                rejected.extend(["via", "192.0.2.254"]);
                let check = std::process::Command::new(program)
                    .args(&rejected)
                    .output()?;
                assert!(!check.status.success());
                let reason = String::from_utf8_lossy(&check.stderr);
                assert!(
                    reason.contains("Nexthop has invalid gateway")
                        || reason.contains("RTNETLINK answers: Network is unreachable"),
                    "{reason}"
                );
                let error = nfqws2_router_command::System
                    .run(program, &rejected, deadline)
                    .unwrap_err();
                assert!(nfqws2_router_command::reported_failure(&error));
                return Err(error);
            }
            let result = nfqws2_router_command::System.run(program, args, deadline)?;
            if program == "ip"
                && matches!(
                    args,
                    ["-4", "route" | "rule", "add" | "replace" | "del", ..]
                )
                || program == "iptables"
                    && args
                        .iter()
                        .any(|arg| matches!(*arg, "-A" | "-D" | "-I" | "-R"))
            {
                if let Some(held) = self.held.lock().unwrap().as_ref() {
                    assert_eq!(
                        held_inventory(&held.iface, &held.table, held.shared, deadline)?,
                        held.objects,
                        "independent owner changed during {program} {args:?}"
                    );
                }
            }
            if program == "ip"
                && matches!(args, ["-4", "route", "add" | "replace", ..])
                && args.contains(&TARGET_IFACE)
                && self.target_route.swap(false, Relaxed)
            {
                let rules =
                    nfqws2_router_command::System.run("ip", &["-4", "rule", "show"], deadline)?;
                for dest in std::iter::once(SCOPED)
                    .chain(self.global_guard.then_some(GLOBAL))
                    .chain(self.rotated.then_some([NEW_A, NEW_B]).into_iter().flatten())
                {
                    let global =
                        dest == GLOBAL || self.global_change && matches!(dest, NEW_A | NEW_B);
                    assert!(rules.lines().any(|rule| rule.starts_with("69:")
                        && rule.contains(dest)
                        && rule.contains("blackhole")
                        && rule.contains(if global { "from all" } else { INSIDE })));
                }
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "lost route acknowledgement",
                ));
            }
            if program == "ip"
                && matches!(args, ["-4", "rule", "del", "pref", "69", ..])
                && args
                    .iter()
                    .any(|arg| arg.starts_with(if self.global_change { GLOBAL } else { SCOPED }))
                && self.retired_stop.swap(false, Relaxed)
            {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "lost retired Stop acknowledgement",
                ));
            }
            Ok(result)
        }
        fn run_input(
            &self,
            program: &str,
            args: &[&str],
            input: &[u8],
            deadline: Instant,
        ) -> io::Result<String> {
            nfqws2_router_command::System.run_input(program, args, input, deadline)
        }
    }
    let has_held = matches!(
        replacement,
        FirmwareReplacement::HeldOwner
            | FirmwareReplacement::ColdHeldOwner
            | FirmwareReplacement::UnavailableHeldOwner
            | FirmwareReplacement::RelocatedOwner
            | FirmwareReplacement::HeldChanged
            | FirmwareReplacement::HeldNxDomain
            | FirmwareReplacement::TargetGlobal
            | FirmwareReplacement::TargetGlobalChanged
            | FirmwareReplacement::TargetGlobalNxDomain
            | FirmwareReplacement::HeldRetryRuntime
            | FirmwareReplacement::TargetGlobalRetryRuntime
            | FirmwareReplacement::HeldColdRetry { .. }
    );
    let target_global = matches!(
        replacement,
        FirmwareReplacement::TargetGlobal
            | FirmwareReplacement::TargetGlobalChanged
            | FirmwareReplacement::TargetGlobalNxDomain
            | FirmwareReplacement::TargetGlobalRetryRuntime
            | FirmwareReplacement::HeldColdRetry { shared: true, .. }
    );
    let retry_runtime = matches!(
        replacement,
        FirmwareReplacement::RetryRuntime
            | FirmwareReplacement::HeldRetryRuntime
            | FirmwareReplacement::TargetGlobalRetryRuntime
            | FirmwareReplacement::HeldColdRetry { .. }
    );
    let cold_retry = matches!(replacement, FirmwareReplacement::HeldColdRetry { .. });
    let supersede = matches!(
        replacement,
        FirmwareReplacement::HeldColdRetry { newer: true, .. }
    );
    let retire_pending_dns = matches!(
        replacement,
        FirmwareReplacement::HeldColdRetry {
            withdraw_after_expiry: true,
            ..
        }
    );
    let paired_retry = matches!(
        replacement,
        FirmwareReplacement::HeldColdRetry {
            paired_retry: true,
            ..
        }
    );
    let other_was_positive = matches!(
        replacement,
        FirmwareReplacement::HeldColdRetry {
            pair_first_positive: true,
            ..
        }
    );
    let both_become_positive = matches!(
        replacement,
        FirmwareReplacement::HeldColdRetry {
            pair_becomes_positive: true,
            ..
        }
    );
    let relocated = has_held && replacement != FirmwareReplacement::HeldOwner;
    let held_iface = if target_global {
        TARGET_IFACE
    } else if relocated {
        "awg3"
    } else {
        "awg32"
    };
    let held_id = if target_global { TARGET } else { HELD };
    let archive_scenario = match replacement {
        FirmwareReplacement::Archive(scenario) => Some(scenario),
        _ => None,
    };
    let mixed_archive = archive_shape != FirmwareArchiveShape::Masks;
    let legacy_suffix = archive_shape == FirmwareArchiveShape::LegacySuffix;
    let other_name = if mixed_archive {
        "global.test"
    } else {
        OTHER_NAME
    };
    let archive_rotation = matches!(
        archive_scenario,
        Some(ArchiveScenario::Discovered | ArchiveScenario::Both)
    );
    let archive_retirement = matches!(
        archive_scenario,
        Some(ArchiveScenario::Discovered | ArchiveScenario::NoHistory)
    );
    let multiple_explicit = matches!(
        replacement,
        FirmwareReplacement::ChangedMultipleGlobal
            | FirmwareReplacement::ChangedMultipleGlobalNegative
    );
    let multiple = multiple_explicit || archive_scenario.is_some();
    let other_negative = replacement == FirmwareReplacement::ChangedMultipleGlobalNegative;
    let router = Fault {
        target_route: AtomicBool::new(false),
        reject_target_route: AtomicBool::new(false),
        retired_stop: AtomicBool::new(false),
        rotated: multiple_explicit
            || archive_rotation
            || matches!(
                replacement,
                FirmwareReplacement::Changed
                    | FirmwareReplacement::ChangedExplicit
                    | FirmwareReplacement::ChangedGlobalExplicit
                    | FirmwareReplacement::HeldChanged
                    | FirmwareReplacement::TargetGlobalChanged
                    | FirmwareReplacement::HeldColdRetry {
                        negative: false,
                        ..
                    }
            ),
        global_change: multiple_explicit
            || archive_rotation
            || archive_retirement
            || matches!(
                replacement,
                FirmwareReplacement::ChangedGlobalExplicit | FirmwareReplacement::GlobalNxDomain
            ),
        global_guard: killswitch || !has_held,
        held: std::sync::Mutex::new(None),
    };
    let explicit = multiple_explicit
        || paired_retry
        || matches!(
            replacement,
            FirmwareReplacement::ChangedExplicit
                | FirmwareReplacement::ChangedGlobalExplicit
                | FirmwareReplacement::GlobalNxDomain
        );
    let cold = archive_scenario.map_or(
        !matches!(
            replacement,
            FirmwareReplacement::Warm | FirmwareReplacement::RetryRuntime
        ) && !has_held
            || matches!(
                replacement,
                FirmwareReplacement::HeldChanged
                    | FirmwareReplacement::HeldNxDomain
                    | FirmwareReplacement::TargetGlobalChanged
                    | FirmwareReplacement::TargetGlobalNxDomain
                    | FirmwareReplacement::HeldColdRetry { .. }
            ),
        |_| archive_retirement,
    );
    let mut k = kernel(&router);
    k.deadline = Instant::now() + std::time::Duration::from_secs(90);
    let ip = |args: &[&str]| k.call("ip", args).unwrap();
    let fw = |args: &[&str]| k.call("iptables", args).unwrap();
    let start_target = || {
        ip(&["link", "add", TARGET_IFACE, "type", "dummy"]);
        ip(&["addr", "add", "10.31.0.2/32", "dev", TARGET_IFACE]);
        ip(&["link", "set", TARGET_IFACE, "up", "mtu", "1420"]);
    };
    if disabled.is_none() {
        start_target();
    }
    if has_held && !target_global {
        ip(&["link", "add", held_iface, "type", "dummy"]);
        ip(&["addr", "add", "10.32.0.2/32", "dev", held_iface]);
        ip(&["link", "set", held_iface, "up", "mtu", "1420"]);
    }
    ip(&["netns", "add", CLIENT_NS]);
    ip(&[
        "link",
        "add",
        LAN,
        "type",
        "veth",
        "peer",
        "name",
        CLIENT_LINK,
    ]);
    ip(&["link", "set", CLIENT_LINK, "netns", CLIENT_NS]);
    ip(&["addr", "add", "192.168.71.1/24", "dev", LAN]);
    ip(&["link", "set", LAN, "up"]);
    ip(&["-n", CLIENT_NS, "link", "set", CLIENT_LINK, "up"]);
    for addr in ["192.168.71.40/24", "192.168.71.90/24"] {
        ip(&["-n", CLIENT_NS, "addr", "add", addr, "dev", CLIENT_LINK]);
    }
    ip(&[
        "-n",
        CLIENT_NS,
        "route",
        "add",
        "default",
        "via",
        "192.168.71.1",
        "dev",
        CLIENT_LINK,
    ]);
    fw(&["-w", "-t", "mangle", "-N", CHAIN]);
    for destination in [
        SCOPED,
        OTHER_SCOPED,
        GLOBAL,
        NEW_A,
        NEW_B,
        PENDING_OTHER,
        LATEST_A,
        LATEST_B,
    ]
    .into_iter()
    .chain(multiple.then_some(OTHER_GLOBAL))
    {
        fw(&[
            "-w",
            "-t",
            "mangle",
            "-A",
            "POSTROUTING",
            "-p",
            "udp",
            "-d",
            destination,
            "--dport",
            "42042",
            "-j",
            CHAIN,
        ]);
    }
    for iface in [SOURCE, TARGET_IFACE, "wan0"]
        .into_iter()
        .chain((has_held && !target_global).then_some(held_iface))
    {
        fw(&[
            "-w", "-t", "mangle", "-A", CHAIN, "-o", iface, "-j", "RETURN",
        ]);
    }
    let check_packet = |client: &str, destination: &str, iface: &str| {
        fw(&["-w", "-t", "mangle", "-Z", CHAIN]);
        let child = std::process::Command::new("ip")
            .args(["netns", "exec", CLIENT_NS])
            .arg(std::env::current_exe().unwrap())
            .args([
                "firmware_mixed_lan_packet_sender",
                "--ignored",
                "--test-threads=1",
            ])
            .env("N2S_R99_LAN_CLIENT", client)
            .env("N2S_R99_LAN_DEST", destination)
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "{}",
            String::from_utf8_lossy(&child.stdout)
        );
        let end = Instant::now() + std::time::Duration::from_secs(1);
        loop {
            let observed = k.call("iptables-save", &["-c", "-t", "mangle"]).unwrap();
            let egress: Vec<_> = observed
                .lines()
                .filter_map(|line| {
                    let words = line.split_whitespace().collect::<Vec<_>>();
                    let [counts, "-A", CHAIN, "-o", iface, "-j", "RETURN"] = words.as_slice()
                    else {
                        return None;
                    };
                    (!counts.starts_with("[0:")).then_some(*iface)
                })
                .collect();
            if !egress.is_empty() || Instant::now() >= end {
                assert_eq!(
                    egress,
                    (!iface.is_empty())
                        .then_some(iface)
                        .into_iter()
                        .collect::<Vec<_>>(),
                    "client {client} to {destination}, cold={cold}, kill={killswitch}"
                );
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    };
    let check = |scoped, global| {
        check_packet(INSIDE, SCOPED, scoped);
        check_packet(OUTSIDE, SCOPED, "wan0");
        if paired_retry {
            check_packet(INSIDE, OTHER_SCOPED, scoped);
            check_packet(OUTSIDE, OTHER_SCOPED, "wan0");
        }
        check_packet(INSIDE, GLOBAL, global);
        check_packet(OUTSIDE, GLOBAL, global);
    };
    let check_other = |iface| {
        if multiple {
            check_packet(INSIDE, OTHER_GLOBAL, iface);
            check_packet(OUTSIDE, OTHER_GLOBAL, iface);
        }
    };
    let check_rotated = |inside| {
        for addr in [NEW_A, NEW_B] {
            check_packet(INSIDE, addr, inside);
            check_packet(
                OUTSIDE,
                addr,
                if router.global_change { inside } else { "wan0" },
            );
        }
    };

    let (_dir, db, _) = setup();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"]["killswitch"] = json!(killswitch);
        doc["routing"]["domain_source"] = json!("dnsproxy");
        let source = &mut doc["servers"][0]["config"];
        source["install"] = json!("imported");
        source["protocol"] = json!("wireguard");
        source["endpoint"] = json!(OLD_ENDPOINT);
        source["client"]["rust_managed"] = json!(true);
        source["client"]["peer_id"] = json!("router");
        source["peers"] = json!([{"id":"router","is_router":true,"address":"10.30.0.2/32",
            "private_key":format!("B{}=", "A".repeat(42)),"allowed_ips":["0.0.0.0/0"]}]);
        source["routing"]["zones"] = if explicit {
            json!([
                {"enabled":true,"order":1,"domains":[SCOPED_NAME],"include_subdomains":false,
                 "ips":["203.0.113.0/25"],"source_ips":[INSIDE]},
                {"enabled":true,"order":2,"domains":[format!("full:{GLOBAL_NAME}")],
                 "ips":["203.0.113.128/25"]}
            ])
        } else {
            json!([
                {"enabled":true,"order":1,"domains":["*.scoped.test"],"ips":["203.0.113.0/25"],"source_ips":[INSIDE]},
                {"enabled":true,"order":2,"domains":["*.global.test"],"ips":["203.0.113.128/25"]}
            ])
        };
        if paired_retry {
            source["routing"]["zones"][0]["domains"] = json!([SCOPED_NAME, OTHER_SCOPED_NAME]);
        }
        if archive_scenario.is_some() {
            source["routing"]["zones"][0]["domains"] = json!([SCOPED_NAME]);
            source["routing"]["zones"][0]["include_subdomains"] = json!(false);
        }
        if legacy_suffix {
            source["routing"]["zones"][1]["domains"] = json!([other_name]);
        } else if mixed_archive {
            source["routing"]["zones"][1]["domains"] = json!([other_name, "*.global.test"]);
            source["routing"]["zones"][1]["include_subdomains"] = json!(false);
        }
        if multiple_explicit {
            source["routing"]["zones"][1]["domains"] = json!([
                format!("full:{GLOBAL_NAME}"),
                format!("full:{OTHER_NAME}"),
                format!("full:{}", OTHER_NAME.to_ascii_uppercase()),
            ]);
        }
        let global = has_held.then(|| source["routing"]["zones"].as_array_mut().unwrap().pop().unwrap());
        let held = global.as_ref().filter(|_| !target_global).map(|global| {
            let mut held = source.clone();
            held["client_iface"] = json!(held_iface);
            held["endpoint"] = json!(HELD_ENDPOINT);
            held["peers"][0]["address"] = json!("10.32.0.2/32");
            held["routing"]["zones"] = json!([global]);
            held
        });
        let mut target = source.clone();
        target["client_iface"] = json!(TARGET_IFACE);
        target["endpoint"] = json!(NEW_ENDPOINT);
        target["client"]["standby"] = json!(false);
        if let Some(server_disabled) = disabled {
            target["enabled"] = json!(!server_disabled);
            target["client"]["enabled"] = json!(server_disabled);
            target["client"]["standby"] = json!(true);
        }
        target["peers"][0]["address"] = json!("10.31.0.2/32");
        target["routing"]["zones"] = if target_global { json!([global.unwrap()]) } else { json!([]) };
        doc["servers"].as_array_mut().unwrap().push(json!({ "id": TARGET, "config": target }));
        if let Some(held) = held {
            doc["servers"].as_array_mut().unwrap().push(json!({"id":HELD,"config":held}));
        }
        Ok(())
    }).unwrap();
    let live = |cfg: &Value, _: &str| {
        Ok(LivePeer {
            endpoint: cfg["endpoint"].as_str().unwrap().parse().unwrap(),
            socket_mark: DIRECT_SOCKET_MARK,
            ..peer(cfg, SOURCE)?
        })
    };
    let mut bridges = vec![LAN.to_owned()];
    if multiple_bridges {
        for name in [SECOND_LAN, THIRD_LAN] {
            ip(&["link", "add", name, "type", "dummy"]);
            ip(&["link", "set", name, "up"]);
            bridges.push(name.to_owned());
        }
        bridges.sort_unstable();
    }
    for op in [Operation::Apply, Operation::Commit] {
        operate_with_redirect(&db, &router, op, None, Some(&bridges), live).unwrap();
    }
    let revision = observation(&db).unwrap().unwrap().revision;
    let started = Instant::now();
    let inside = DnsOrigin {
        client: Some(INSIDE.parse().unwrap()),
        ingress: Some(LAN),
    };
    let global_client = if multiple_bridges { "192.168.72.90" } else { OUTSIDE };
    let global_lan = if multiple_bridges { SECOND_LAN } else { LAN };
    let outside = DnsOrigin {
        client: Some(global_client.parse().unwrap()),
        ingress: Some(global_lan),
    };
    let scoped = [SCOPED.parse().unwrap()];
    let other_scoped = [OTHER_SCOPED.parse().unwrap()];
    let global = [GLOBAL.parse().unwrap()];
    let other_global = [OTHER_GLOBAL.parse().unwrap()];
    for (zone, name, origin, addresses, ttl) in [
        (0, SCOPED_NAME, inside, &scoped[..], 2),
        (1, GLOBAL_NAME, outside, &global[..], 120),
    ]
    .into_iter()
    .chain(paired_retry.then_some((0, OTHER_SCOPED_NAME, inside, &other_scoped[..], 2)))
    .chain(multiple.then_some((1, other_name, outside, &other_global[..], 120)))
    {
        learn_named_client_answer(
            &db,
            &router,
            Answer {
                revision,
                zone,
                addresses,
                ttl,
                qtype: 1,
            },
            origin,
            name,
            live,
            || Ok(()),
        )
        .unwrap();
    }
    std::thread::sleep(std::time::Duration::from_millis(2300).saturating_sub(started.elapsed()));
    let receipt = Journal::read(&db).unwrap();
    assert!(receipt
        .installed
        .learned
        .as_ref()
        .unwrap()
        .members
        .iter()
        .all(|member| {
            member.until == super::super::super::active_replacement::RETAINED_FIRMWARE_MEMBER
        }));
    assert!(operate_firmware_refresh(&db, &router, Some(&bridges), live, |_, _| Ok(None)).unwrap());
    let old_global = if has_held { held_iface } else { SOURCE };
    let next_global = if has_held { held_iface } else { TARGET_IFACE };
    check(SOURCE, old_global);
    check_other(SOURCE);
    if router.rotated {
        check_rotated("wan0");
    }
    let before = nfqws2_awg_profile::read(&db).unwrap();
    let old = Journal::read(&db).unwrap();
    if has_held {
        let table = objects(&old.installed)
            .into_iter()
            .find_map(|object| match object {
                Object::Route(_, owner, table) if owner == held_iface => Some(table.to_string()),
                _ => None,
            })
            .unwrap();
        let observed = held_inventory(
            held_iface,
            &table,
            target_global,
            Instant::now() + std::time::Duration::from_secs(2),
        )
        .unwrap();
        *router.held.lock().unwrap() = Some(HeldInventory {
            iface: held_iface.into(),
            table,
            shared: target_global,
            objects: observed,
        });
    }
    let request = active_replacement_dns_revalidation(&db, SOURCE)
        .unwrap()
        .unwrap();
    let names = |zone| request.configured_firmware_names(zone).unwrap();
    assert_eq!(
        names(0),
        (explicit || archive_scenario.is_some()).then(|| {
            std::iter::once(SCOPED_NAME.to_string())
                .chain(paired_retry.then(|| OTHER_SCOPED_NAME.to_string()))
                .collect()
        })
    );
    assert_eq!(
        names(1),
        explicit.then(|| {
            [GLOBAL_NAME.to_string()]
                .into_iter()
                .chain(multiple.then(|| OTHER_NAME.to_string()))
                .collect()
        })
    );
    let no_client = DnsOrigin {
        client: None,
        ingress: Some(LAN),
    };
    let changed_addresses = [NEW_A.parse().unwrap(), NEW_B.parse().unwrap()];
    let other_pending = [PENDING_OTHER.parse().unwrap()];
    let mut proofs = vec![
        FirmwareDnsGroupProof {
            zone: 0,
            name: SCOPED_NAME,
            origin: inside,
            answer: match replacement {
                FirmwareReplacement::Warm
                | FirmwareReplacement::RetryRuntime
                | FirmwareReplacement::HeldRetryRuntime
                | FirmwareReplacement::TargetGlobalRetryRuntime
                | FirmwareReplacement::HeldOwner
                | FirmwareReplacement::ColdHeldOwner
                | FirmwareReplacement::UnavailableHeldOwner
                | FirmwareReplacement::RelocatedOwner
                | FirmwareReplacement::TargetGlobal => FirmwareDnsGroupAnswer::Addresses(&scoped),
                FirmwareReplacement::NxDomain
                | FirmwareReplacement::HeldNxDomain
                | FirmwareReplacement::TargetGlobalNxDomain
                | FirmwareReplacement::HeldColdRetry { negative: true, .. } => {
                    FirmwareDnsGroupAnswer::NxDomain
                }
                FirmwareReplacement::Changed
                | FirmwareReplacement::ChangedExplicit
                | FirmwareReplacement::HeldChanged
                | FirmwareReplacement::TargetGlobalChanged
                | FirmwareReplacement::HeldColdRetry {
                    negative: false, ..
                } => FirmwareDnsGroupAnswer::FreshAddresses {
                    addresses: &changed_addresses,
                    valid_until: Instant::now() + std::time::Duration::from_secs(30),
                },
                FirmwareReplacement::ChangedGlobalExplicit
                | FirmwareReplacement::GlobalNxDomain
                | FirmwareReplacement::ChangedMultipleGlobal
                | FirmwareReplacement::ChangedMultipleGlobalNegative
                | FirmwareReplacement::Archive(_) => FirmwareDnsGroupAnswer::FreshAddresses {
                    addresses: &scoped,
                    valid_until: Instant::now() + std::time::Duration::from_secs(30),
                },
            },
        },
        FirmwareDnsGroupProof {
            zone: 1,
            name: GLOBAL_NAME,
            origin: if explicit { no_client } else { outside },
            answer: if replacement == FirmwareReplacement::GlobalNxDomain {
                FirmwareDnsGroupAnswer::NxDomain
            } else if explicit {
                FirmwareDnsGroupAnswer::FreshAddresses {
                    addresses: if router.global_change {
                        &changed_addresses
                    } else {
                        &global
                    },
                    valid_until: Instant::now() + std::time::Duration::from_secs(30),
                }
            } else {
                FirmwareDnsGroupAnswer::Addresses(&global)
            },
        },
    ];
    let mut archive = FirmwareDnsArchive::default();
    if let Some(scenario) = archive_scenario {
        proofs.truncate(1);
        let queried = matches!(
            scenario,
            ArchiveScenario::Discovered | ArchiveScenario::Both
        );
        let replayed = matches!(scenario, ArchiveScenario::Recent | ArchiveScenario::Both);
        if queried {
            archive.discovered = [
                GLOBAL_NAME.into(),
                other_name.into(),
                SCOPED_NAME.into(),
                "foreign.invalid".into(),
            ]
            .into();
        }
        if replayed {
            archive.replay = [
                (GLOBAL_NAME.into(), vec![global[0], NEW_A.parse().unwrap()]),
                (other_name.into(), other_global.to_vec()),
                (SCOPED_NAME.into(), scoped.to_vec()),
            ]
            .into();
        }
        assert_eq!(
            request.archived_firmware_names(1, &archive).unwrap(),
            Some(
                queried
                    .then_some(GLOBAL_NAME.to_owned())
                    .into_iter()
                    .chain((queried || mixed_archive).then_some(other_name.to_owned()))
                    .collect(),
            )
        );
        if scenario == ArchiveScenario::Warm {
            for (name, addresses) in [(GLOBAL_NAME, &global), (OTHER_NAME, &other_global)] {
                proofs.push(FirmwareDnsGroupProof {
                    zone: 1,
                    name,
                    origin: outside,
                    answer: FirmwareDnsGroupAnswer::Addresses(addresses),
                });
            }
        } else if queried || mixed_archive {
            for (name, addresses) in [
                (GLOBAL_NAME, &changed_addresses[..]),
                (other_name, &other_global[..]),
            ]
            .into_iter()
            .filter(|&(name, _)| queried || name == other_name)
            {
                proofs.push(FirmwareDnsGroupProof {
                    zone: 1,
                    name,
                    origin: no_client,
                    answer: FirmwareDnsGroupAnswer::FreshAddresses {
                        addresses,
                        valid_until: Instant::now() + std::time::Duration::from_secs(30),
                    },
                });
            }
            assert!(request
                .clone()
                .revalidate_firmware_groups_with_archive(
                    &proofs[..proofs.len() - 1],
                    Some(&archive)
                )
                .is_err());
            if mixed_archive {
                let last = proofs.len() - 1;
                let name = std::mem::replace(&mut proofs[last].name, "foreign.invalid");
                assert!(request
                    .clone()
                    .revalidate_firmware_groups_with_archive(&proofs, Some(&archive))
                    .is_err());
                proofs[last].name = name;
            }
            if legacy_suffix {
                let last = proofs.len() - 1;
                proofs.swap(0, last);
                assert!(request
                    .clone()
                    .revalidate_firmware_groups_with_archive(&proofs, Some(&archive))
                    .is_err());
                proofs.swap(0, last);
                let previous = std::mem::replace(
                    &mut proofs[last].answer,
                    FirmwareDnsGroupAnswer::FreshAddresses {
                        addresses: &scoped,
                        valid_until: Instant::now() + std::time::Duration::from_secs(30),
                    },
                );
                assert!(request
                    .clone()
                    .revalidate_firmware_groups_with_archive(&proofs, Some(&archive))
                    .is_err());
                proofs[last].answer = previous;
                assert_eq!(Journal::read(&db).unwrap(), old);
            }
        }
    }
    if multiple_explicit {
        assert!(request.clone().revalidate_firmware_groups(&proofs).is_err());
        let other = FirmwareDnsGroupProof {
            zone: 1,
            name: OTHER_NAME,
            origin: no_client,
            answer: if other_negative {
                FirmwareDnsGroupAnswer::NxDomain
            } else {
                FirmwareDnsGroupAnswer::FreshAddresses {
                    addresses: &other_global,
                    valid_until: Instant::now() + std::time::Duration::from_secs(30),
                }
            },
        };
        for name in [GLOBAL_NAME, "unexpected.global.test"] {
            let bad = [
                FirmwareDnsGroupProof { ..proofs[0] },
                FirmwareDnsGroupProof { ..proofs[1] },
                FirmwareDnsGroupProof { name, ..other },
            ];
            assert!(request.clone().revalidate_firmware_groups(&bad).is_err());
        }
        let conflict = [
            FirmwareDnsGroupProof { ..proofs[0] },
            FirmwareDnsGroupProof { ..proofs[1] },
            FirmwareDnsGroupProof {
                answer: FirmwareDnsGroupAnswer::FreshAddresses {
                    addresses: &scoped,
                    valid_until: Instant::now() + std::time::Duration::from_secs(30),
                },
                ..other
            },
        ];
        assert!(request
            .clone()
            .revalidate_firmware_groups(&conflict)
            .is_err());
        let stale = [
            FirmwareDnsGroupProof { ..proofs[0] },
            FirmwareDnsGroupProof { ..proofs[1] },
            FirmwareDnsGroupProof {
                answer: FirmwareDnsGroupAnswer::FreshAddresses {
                    addresses: &other_global,
                    valid_until: Instant::now(),
                },
                ..other
            },
        ];
        assert_eq!(
            request
                .clone()
                .revalidate_firmware_groups(&stale)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::TimedOut
        );
        proofs.push(other);
    }
    if paired_retry {
        proofs.insert(
            1,
            FirmwareDnsGroupProof {
                zone: 0,
                name: OTHER_SCOPED_NAME,
                origin: inside,
                answer: if other_was_positive {
                    FirmwareDnsGroupAnswer::FreshAddresses {
                        addresses: &other_pending,
                        valid_until: Instant::now() + std::time::Duration::from_secs(30),
                    }
                } else {
                    FirmwareDnsGroupAnswer::NxDomain
                },
            },
        );
    }
    let proofs = if has_held {
        &proofs[..1 + usize::from(paired_retry)]
    } else {
        &proofs[..]
    };
    assert_eq!(request.held_profile(), has_held.then_some(held_id));
    if has_held {
        let archive = FirmwareDnsArchive {
            discovered: [GLOBAL_NAME.to_owned()].into(),
            replay: [(GLOBAL_NAME.to_owned(), global.to_vec())].into(),
        };
        assert!(request
            .archived_firmware_names(1, &archive)
            .unwrap()
            .is_none());
        for answer in [
            FirmwareDnsGroupAnswer::NxDomain,
            FirmwareDnsGroupAnswer::FreshAddresses {
                addresses: &changed_addresses,
                valid_until: Instant::now() + std::time::Duration::from_secs(30),
            },
        ] {
            let unrelated = [
                FirmwareDnsGroupProof { ..proofs[0] },
                FirmwareDnsGroupProof {
                    zone: 1,
                    name: GLOBAL_NAME,
                    origin: outside,
                    answer,
                },
            ];
            assert!(request
                .clone()
                .revalidate_firmware_groups(&unrelated)
                .is_err());
        }
    }
    let mut wrong = [
        FirmwareDnsGroupProof {
            zone: 0,
            name: SCOPED_NAME,
            origin: outside,
            answer: proofs[0].answer,
        },
        FirmwareDnsGroupProof {
            zone: 1,
            name: GLOBAL_NAME,
            origin: outside,
            answer: FirmwareDnsGroupAnswer::Addresses(&global),
        },
    ];
    if paired_retry {
        wrong[1] = FirmwareDnsGroupProof { ..proofs[1] };
    }
    let wrong = if has_held && !paired_retry {
        &mut wrong[..1]
    } else {
        &mut wrong[..]
    };
    assert!(request.clone().revalidate_firmware_groups(wrong).is_err());
    if !has_held {
        wrong[0].origin = inside;
        wrong[1].origin = no_client;
        assert!(request.clone().revalidate_firmware_groups(wrong).is_err());
        wrong[1].origin = outside;
    }
    if router.rotated {
        wrong[0].origin = inside;
        wrong[0].answer = FirmwareDnsGroupAnswer::FreshAddresses {
            addresses: &changed_addresses,
            valid_until: Instant::now(),
        };
        assert_eq!(
            request
                .clone()
                .revalidate_firmware_groups(wrong)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::TimedOut
        );
        wrong[0].answer = FirmwareDnsGroupAnswer::Addresses(&changed_addresses);
        assert!(request.clone().revalidate_firmware_groups(wrong).is_err());
        wrong[0].answer = FirmwareDnsGroupAnswer::FreshAddresses {
            addresses: &global,
            valid_until: Instant::now() + std::time::Duration::from_secs(30),
        };
        assert!(request.clone().revalidate_firmware_groups(wrong).is_err());
    }
    wrong[0].origin = DnsOrigin {
        ingress: Some("br-other"),
        ..inside
    };
    wrong[0].answer = proofs[0].answer;
    assert!(request.clone().revalidate_firmware_groups(wrong).is_err());
    let mut verified_proofs = proofs.to_vec();
    if multiple_bridges && replacement == FirmwareReplacement::ChangedExplicit {
        for proof in &mut verified_proofs {
            proof.origin.ingress = None;
        }
    }
    if multiple_bridges && disabled.is_some() {
        let mut proof = proofs.to_vec();
        proof[0].origin.ingress = None;
        assert!(request.clone().revalidate_firmware_groups(&proof).is_err());
    }
    let proofs = verified_proofs.as_slice();
    let proof = if archive_scenario.is_some_and(|scenario| scenario != ArchiveScenario::Warm) {
        assert!(request.clone().revalidate_firmware_groups(proofs).is_err());
        request.revalidate_firmware_groups_with_archive(proofs, Some(&archive))
    } else {
        request.revalidate_firmware_groups(proofs)
    }
    .unwrap();
    let allowed = |id: &str| -> Vec<String> {
        if !has_held {
            return vec!["0.0.0.0/0".into()];
        }
        if id == HELD {
            let mut allowed = vec!["203.0.113.128/25".into(), format!("{GLOBAL}/32")];
            if disabled.is_some() {
                allowed.push(format!("{LATEST_A}/32"));
            }
            return allowed;
        }
        let mut prefixes = vec!["203.0.113.0/25".into(), format!("{SCOPED}/32")];
        if paired_retry {
            prefixes.push(format!("{OTHER_SCOPED}/32"));
        }
        if id == TARGET && router.rotated {
            prefixes.extend([format!("{NEW_A}/32"), format!("{NEW_B}/32")]);
        }
        if id == TARGET && supersede {
            prefixes.extend([format!("{LATEST_A}/32"), format!("{LATEST_B}/32")]);
        }
        if id == TARGET && (other_was_positive || both_become_positive) {
            prefixes.push(format!("{PENDING_OTHER}/32"));
        }
        if id == TARGET && target_global {
            prefixes.extend(["203.0.113.128/25".into(), format!("{GLOBAL}/32")]);
        }
        prefixes
    };
    let witness = |id: &str, iface: &str, endpoint: &str, pid: u32| ActiveReplacementPeer {
        owner: NativeRemovalSeal {
            id: id.into(),
            iface: iface.into(),
            boot: old.boot.clone(),
            pid,
            started: u64::from(pid),
            receipt_sha256: [pid as u8; 32],
            nested: None,
        },
        fingerprint: if disabled.is_some() && id == TARGET {
            [0; 32]
        } else {
            active_replacement_fingerprint(&before, id).unwrap()
        },
        endpoint: endpoint.parse().unwrap(),
        socket_mark: DIRECT_SOCKET_MARK,
        mtu: 1420,
        allowed: allowed(id),
        underlay: None,
        nested_only: false,
    };
    let peers = [
        witness(SOURCE, SOURCE, OLD_ENDPOINT, 42),
        witness(TARGET, TARGET_IFACE, NEW_ENDPOINT, 43),
    ];
    let held = has_held.then(|| {
        if target_global {
            peers[1].clone()
        } else {
            witness(held_id, held_iface, HELD_ENDPOINT, 44)
        }
    });
    let mut after = before.clone();
    let mut zones = after["servers"][0]["config"]["routing"]["zones"].clone();
    for zone in zones.as_array_mut().unwrap() {
        zone["tunnel_id"] = json!(TARGET);
    }
    after["servers"].as_array_mut().unwrap().remove(0);
    let target = &mut after["servers"][0]["config"];
    if target_global {
        zones.as_array_mut().unwrap().extend(
            target["routing"]["zones"]
                .as_array()
                .unwrap()
                .iter()
                .cloned(),
        );
    }
    target["routing"]["zones"] = zones;
    target["routing"]["active"] = json!(true);
    target["client"]["standby"] = json!(false);
    after["active_id"] = json!(TARGET);
    after["routing_revision"] = json!(revision + 1);
    if let Some(expired) = disabled {
        let mut prior_global = held.as_ref().map(|held| {
            let old = Journal::read(&db).unwrap();
            held_dns_objects(&old.installed, &held.owner.iface)
        });
        db.transaction(|tx| {
            replace_active_profile_with_disabled_target(
                &db, tx, &router, (&before, &after), (TARGET, (&peers[0], held.as_ref()), &["wan0".into()]),
                &|| Ok(()), || Ok(()),
            )
        }).unwrap();
        ip(&["link", "set", SOURCE, "down"]);
        finish_active_replacement_retirement(&db, &peers[0].owner).unwrap();
        let remaining = if has_held { held_iface } else { "wan0" };
        check("wan0", remaining);
        assert_eq!(observation(&db).unwrap().is_some(), has_held);
        if let Some(prior) = prior_global.as_ref() {
            let current = Journal::read(&db).unwrap();
            assert_eq!(held_dns_objects(&current.installed, held_iface), *prior);
            let mut routing_witness = router.held.lock().unwrap().take().unwrap();
            let extra = [LATEST_A.parse().unwrap()];
            learn_named_client_answer(
                &db, &router,
                Answer { revision: current.committed.revision, zone: 1, addresses: &extra, ttl: 2, qtype: 1 },
                outside, "new.global.test", live, || Ok(()),
            ).unwrap();
            check_packet(INSIDE, LATEST_A, held_iface);
            check_packet(OUTSIDE, LATEST_A, held_iface);
            let learned = Journal::read(&db).unwrap();
            assert_eq!(
                learned.installed.learned.as_ref().unwrap().members.last().unwrap().until,
                super::super::super::active_replacement::RETAINED_FIRMWARE_MEMBER,
            );
            prior_global = Some(held_dns_objects(&learned.installed, held_iface));
            routing_witness.objects = held_inventory(
                held_iface, &routing_witness.table, routing_witness.shared, k.deadline,
            ).unwrap();
            *router.held.lock().unwrap() = Some(routing_witness);
        }
        let request = dormant_firmware_dns(&db).unwrap().unwrap();
        assert_eq!(request.transfer_stamp().1, revision);
        nfqws2_awg_profile::edit_document(&db, |doc| {
            let target = &mut doc["servers"][0]["config"];
            target["enabled"] = json!(true);
            target["client"]["enabled"] = json!(true);
            Ok(())
        }).unwrap();
        start_target();
        let mut witness = peers[1].clone();
        witness.fingerprint = active_replacement_fingerprint(
            &nfqws2_awg_profile::read(&db).unwrap(), TARGET,
        ).unwrap();
        let current = Instant::now();
        let future = current + std::time::Duration::from_secs(30);
        let until = if expired { current } else { future };
        fn hint<'a>(
            name: &'a str, client: &str, ingress: &'a str, addresses: &'a [std::net::IpAddr], until: Instant,
        ) -> DormantFirmwareAnswer<'a> {
            DormantFirmwareAnswer { name, client: client.parse().unwrap(), ingress, addresses, until }
        }
        let proof = request.previous_answers([
            hint(SCOPED_NAME, INSIDE, LAN, &scoped, until),
            hint(GLOBAL_NAME, global_client, global_lan, &global, until),
            hint(SCOPED_NAME, OUTSIDE, LAN, &scoped, future),
            hint(GLOBAL_NAME, OUTSIDE, "br-other", &global, future),
            hint(SCOPED_NAME, INSIDE, LAN, &changed_addresses, future),
        ]);
        operate_with_inputs(
            &db, &router, Operation::Refresh, nfqws2_awg_profile::now(),
            (Some(DnsInput::DormantRearm(&proof)), Some(&bridges)),
            |cfg, iface| live(cfg, iface).map(|p| {
                let native = held.as_ref().filter(|held| held.owner.iface == iface).unwrap_or(&witness);
                p.with_active_replacement_peer(Some(native.clone()))
            }),
            (|_, _| Ok(None), None),
        ).unwrap();
        let expected = if expired { "wan0" } else { TARGET_IFACE };
        check(expected, if has_held { held_iface } else { expected });
        check_rotated("wan0");
        let restored = Journal::read(&db).unwrap();
        assert_eq!(restored.installed.dns_bridges, bridges);
        assert_eq!(restored.committed.killswitch, killswitch);
        assert_eq!(restored.committed.revision, revision + 1);
        let members = restored.committed.learned.as_ref().unwrap().members.len();
        assert_eq!(members, if expired { 2 * usize::from(has_held) } else { 2 + usize::from(has_held) });
        if let Some(prior) = prior_global {
            assert_eq!(held_dns_objects(&restored.installed, held_iface), prior);
        }
        assert!(dormant_firmware_dns(&db).unwrap().is_none());
        *router.held.lock().unwrap() = None;
        operate_with_redirect(&db, &router, Operation::Teardown, None, Some(&bridges), live).unwrap();
        for destination in [SCOPED, OTHER_SCOPED, GLOBAL, NEW_A, NEW_B, PENDING_OTHER, LATEST_A, LATEST_B] {
            fw(&["-w", "-t", "mangle", "-D", "POSTROUTING", "-p", "udp",
                "-d", destination, "--dport", "42042", "-j", CHAIN]);
        }
        fw(&["-w", "-t", "mangle", "-F", CHAIN]);
        fw(&["-w", "-t", "mangle", "-X", CHAIN]);
        ip(&["netns", "del", CLIENT_NS]);
        ip(&["link", "del", TARGET_IFACE]);
        if has_held {
            ip(&["link", "del", held_iface]);
        }
        if multiple_bridges {
            for name in [SECOND_LAN, THIRD_LAN] {
                ip(&["link", "del", name]);
            }
        }
        ip(&["link", "set", SOURCE, "up"]);
        return;
    }
    let unavailable = replacement == FirmwareReplacement::UnavailableHeldOwner;
    let cold_launch = replacement == FirmwareReplacement::ColdHeldOwner;
    if cold_launch || unavailable {
        ip(&["link", "del", TARGET_IFACE]);
        let stage = |retained, provisional| {
            prepare_active_replacement_launch(
                &db,
                &router,
                ActiveReplacementStage {
                    before: &before,
                    after: &after,
                    source: &peers[0],
                    held: retained,
                    target: TARGET,
                    provisional,
                },
                &["wan0".into()],
                Some(&proof),
            )
        };
        assert!(stage(None, None).is_err());
        stage(held.as_ref(), None).unwrap();
        assert_eq!(Journal::read(&db).unwrap(), old);
        assert!(active_replacement_launch_cleanup(&db).unwrap().is_none());
        check(SOURCE, old_global);
        if cold_launch {
            start_target();
            stage(held.as_ref(), Some(&peers[1])).unwrap();
            let launch = active_replacement_launch_cleanup(&db).unwrap().unwrap();
            assert_eq!(launch.target, peers[1].owner);
            assert!(launch.stop);
            check(SOURCE, old_global);
        }
    }
    let replace_with = |retained: Option<&ActiveReplacementPeer>| {
        db.transaction(|tx| {
            if let Some(held) = retained {
                return replace_active_profile_with_held_dns(
                    &db,
                    tx,
                    &router,
                    &before,
                    &after,
                    (&peers, held, &["wan0".into()], &proof),
                    || Ok(()),
                );
            }
            replace_active_profile_with_dns(
                &db,
                tx,
                &router,
                &before,
                &after,
                (&peers, &["wan0".into()], Some(&proof)),
                || Ok(()),
            )
        })
    };
    let replace = || replace_with(held.as_ref());
    if unavailable {
        let held = held.as_ref().unwrap();
        let warning = defer_active_replacement_launch(
            &db,
            &router,
            ActiveReplacementStage {
                before: &before,
                after: &after,
                source: &peers[0],
                held: Some(held),
                target: TARGET,
                provisional: None,
            },
            &["wan0".into()],
            &|| Ok(()),
        )
        .unwrap()
        .unwrap();
        assert!(warning.contains("выбранное подключение пока не запустилось"));
        assert_eq!(
            pending_active_replacement_retirement(&db).unwrap().as_ref(),
            Some(&peers[0].owner)
        );
        ip(&["link", "set", SOURCE, "down"]);
        finish_active_replacement_retirement(&db, &peers[0].owner).unwrap();
        let out = if killswitch { "" } else { "wan0" };
        check(out, held_iface);
        let recover = |target: Option<&ActiveReplacementPeer>| {
            operate_with_redirect(
                &db,
                &router,
                Operation::Recover,
                None,
                Some(&bridges),
                |cfg, iface| {
                    let peer = if iface == held_iface {
                        Some(held)
                    } else {
                        target
                    };
                    Ok(live(cfg, iface)?.with_active_replacement_peer(peer.cloned()))
                },
            )
            .unwrap();
        };
        recover(None);
        check(out, held_iface);
        let pending = nfqws2_awg_profile::read(&db).unwrap();
        assert_eq!(pending["servers"][0]["config"]["routing"]["active"], true);
        assert_eq!(pending["servers"][1], before["servers"][2]);
        start_target();
        let mut wrong = peers[1].clone();
        wrong.fingerprint = [7; 32];
        recover(Some(&wrong));
        check(out, held_iface);
        recover(Some(&peers[1]));
        recover(Some(&peers[1]));
        assert!(!active_replacement_in_progress(&db).unwrap());
        assert!(observation(&db).unwrap().unwrap().ready);
        ip(&["link", "set", SOURCE, "up"]);
    } else if retry_runtime {
        if has_held {
            router.target_route.store(true, Relaxed);
            assert!(replace().is_err());
            assert!(!router.target_route.load(Relaxed));
            assert_eq!(Journal::read(&db).unwrap(), old);
            assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), before);
            check(SOURCE, old_global);
        }
        router.reject_target_route.store(true, Relaxed);
        let warning = replace().unwrap().unwrap();
        assert!(warning.contains("применение маршрутов будет повторено"));
        assert!(!router.reject_target_route.load(Relaxed));
        let saved = nfqws2_awg_profile::read(&db).unwrap();
        assert!(saved["servers"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["id"] != SOURCE));
        let pending = Journal::read(&db).unwrap();
        assert!(!pending.installed.fully_live());
        assert!(pending.committed.fully_live());
        assert!(!observation(&db).unwrap().unwrap().ready);
        assert!(pending_active_replacement_retirement(&db)
            .unwrap()
            .is_none());
        let held_path = if has_held { held_iface } else { "" };
        check("", held_path);
        if cold_retry && router.rotated {
            check_rotated("");
        }
        operate_with_redirect(
            &db,
            &router,
            Operation::Recover,
            None,
            Some(&bridges),
            |_, _| Err(io::ErrorKind::NotConnected.into()),
        )
        .unwrap();
        assert_eq!(Journal::read(&db).unwrap(), pending);
        check("", held_path);
        let revalidate_peer = |stale_iface: Option<&str>, config: &Value, iface: &str| {
            let mut native = if iface == TARGET_IFACE {
                peers[1].clone()
            } else {
                held.as_ref()
                    .filter(|peer| peer.owner.iface == iface)
                    .unwrap()
                    .clone()
            };
            if stale_iface == Some(iface) {
                native.owner.pid += 1;
            }
            Ok(live(config, iface)?.with_active_replacement_peer(Some(native)))
        };
        let recover = |stale_iface: Option<&str>| {
            operate_with_redirect(
                &db,
                &router,
                Operation::Recover,
                None,
                Some(&bridges),
                |config, iface| revalidate_peer(stale_iface, config, iface),
            )
            .unwrap();
        };
        if has_held {
            recover(Some(held_iface));
            assert_eq!(Journal::read(&db).unwrap(), pending);
            assert!(pending_active_replacement_retirement(&db)
                .unwrap()
                .is_none());
            check("", held_path);
        }
        recover(None);
        if cold_retry {
            assert_eq!(Journal::read(&db).unwrap(), pending);
            assert!(pending_active_replacement_retirement(&db)
                .unwrap()
                .is_none());
            check("", held_path);
            let request = pending_active_replacement_dns_retry(&db).unwrap().unwrap();
            let expected_names: Vec<_> = std::iter::once(SCOPED_NAME)
                .chain(paired_retry.then_some(OTHER_SCOPED_NAME))
                .collect();
            assert_eq!(request.names(), expected_names);
            let response = |answer| {
                std::iter::once(answer)
                    .chain(paired_retry.then_some(FirmwareDnsGroupAnswer::NxDomain))
                    .collect::<Vec<_>>()
            };
            let fresh_response = |answer, valid_until| {
                if both_become_positive {
                    vec![
                        answer,
                        FirmwareDnsGroupAnswer::FreshAddresses {
                            addresses: &other_pending,
                            valid_until,
                        },
                    ]
                } else {
                    response(answer)
                }
            };
            let good_until = Instant::now() + std::time::Duration::from_secs(30);
            assert!(request
                .clone()
                .revalidate(
                    &response(FirmwareDnsGroupAnswer::Addresses(&scoped)),
                    good_until
                )
                .is_err());
            let wrong_family = ["2001:db8::24".parse().unwrap()];
            let wrong = if router.rotated {
                FirmwareDnsGroupAnswer::NxDomain
            } else {
                FirmwareDnsGroupAnswer::FreshAddresses {
                    addresses: &wrong_family,
                    valid_until: good_until,
                }
            };
            assert!(request
                .clone()
                .revalidate(&response(wrong), good_until)
                .is_err());
            let answer = if router.rotated {
                FirmwareDnsGroupAnswer::FreshAddresses {
                    addresses: &changed_addresses,
                    valid_until: good_until,
                }
            } else {
                FirmwareDnsGroupAnswer::NxDomain
            };
            let end = Instant::now() + std::time::Duration::from_millis(50);
            let expired_answers = if other_was_positive {
                vec![
                    answer,
                    FirmwareDnsGroupAnswer::FreshAddresses {
                        addresses: &other_pending,
                        valid_until: good_until,
                    },
                ]
            } else {
                response(answer)
            };
            let expired = request.clone().revalidate(&expired_answers, end).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(60));
            assert_eq!(
                resume_active_replacement_dns_retry(&db, &router, &expired, |_, _| panic!(
                    "expired proof acquired peer"
                ))
                .unwrap_err()
                .kind(),
                io::ErrorKind::TimedOut
            );
            assert_eq!(Journal::read(&db).unwrap(), pending);
            let latest = [LATEST_A.parse().unwrap(), LATEST_B.parse().unwrap()];
            let answer = if supersede {
                FirmwareDnsGroupAnswer::FreshAddresses {
                    addresses: &latest,
                    valid_until: good_until,
                }
            } else {
                answer
            };
            if paired_retry {
                assert!(request.clone().revalidate(&[answer], good_until).is_err());
                assert!(request
                    .clone()
                    .revalidate(&[FirmwareDnsGroupAnswer::NxDomain, answer], good_until)
                    .is_err());
            }
            if other_was_positive {
                assert!(request
                    .clone()
                    .revalidate(&response(answer), good_until)
                    .is_err());
                check_packet(INSIDE, PENDING_OTHER, "");
                check_packet(OUTSIDE, PENDING_OTHER, "wan0");
            }
            let _other_hint_expired = other_was_positive.then(|| {
                super::super::super::active_replacement::age_pending_positive_dns_hint(
                    std::time::Duration::from_secs(21 * 60),
                )
            });
            let proof = request
                .revalidate(&fresh_response(answer, good_until), good_until)
                .unwrap();
            if supersede {
                assert!(
                    resume_active_replacement_dns_retry(&db, &router, &proof, |row, iface| {
                        revalidate_peer(Some(held_iface), row, iface)
                    })
                    .is_err()
                );
                assert_eq!(Journal::read(&db).unwrap(), pending);
                check("", held_path);

                router.reject_target_route.store(true, Relaxed);
                let rejected =
                    resume_active_replacement_dns_retry(&db, &router, &proof, |row, iface| {
                        revalidate_peer(None, row, iface)
                    })
                    .unwrap_err();
                assert!(
                    !router.reject_target_route.load(Relaxed),
                    "writer never reached a real route: {rejected:?}"
                );
                let projected = Journal::read(&db).unwrap();
                assert_ne!(projected, pending);
                if both_become_positive {
                    let reply = pending_active_replacement_dns_retry(&db).unwrap().unwrap();
                    let until = Instant::now() + std::time::Duration::from_secs(30);
                    let newly_negative = [
                        FirmwareDnsGroupAnswer::FreshAddresses {
                            addresses: &latest,
                            valid_until: until,
                        },
                        FirmwareDnsGroupAnswer::NxDomain,
                    ];
                    assert!(
                        reply.clone().revalidate(&newly_negative, until).is_err(),
                        "superseded negative receipt outlived the fresh positive answer"
                    );
                    let _aged =
                        super::super::super::active_replacement::age_pending_positive_dns_hint(
                            std::time::Duration::from_secs(21 * 60),
                        );
                    assert!(
                        reply.revalidate(&newly_negative, until).is_ok(),
                        "compensated positive writer did not record the new age"
                    );
                    check_packet(INSIDE, PENDING_OTHER, "");
                    check_packet(OUTSIDE, PENDING_OTHER, "wan0");
                }
                if other_was_positive {
                    let latest_other = pending_active_replacement_dns_retry(&db).unwrap().unwrap();
                    let deadline = Instant::now() + std::time::Duration::from_secs(30);
                    assert!(
                        latest_other
                            .revalidate(
                                &[
                                    FirmwareDnsGroupAnswer::NxDomain,
                                    FirmwareDnsGroupAnswer::FreshAddresses {
                                        addresses: &latest,
                                        valid_until: deadline,
                                    }
                                ],
                                deadline
                            )
                            .is_err(),
                        "latest first-name positive hint was ignored"
                    );
                }
                assert!(!observation(&db).unwrap().unwrap().ready);
                assert!(pending_active_replacement_retirement(&db)
                    .unwrap()
                    .is_none());
                for destination in [LATEST_A, LATEST_B] {
                    check_packet(INSIDE, destination, "");
                    check_packet(OUTSIDE, destination, "wan0");
                }
                recover(None);
                assert_eq!(Journal::read(&db).unwrap(), projected);
                assert!(pending_active_replacement_dns_retry(&db).unwrap().is_some());
                check("", held_path);
            }
            // A new, still-exact A response followed by a verified refusal
            // resets only the policy-hint clock, not the authoritative wire TTL.
            use super::super::super::active_replacement::age_pending_positive_dns_hint;
            let age = |minutes: u64| {
                age_pending_positive_dns_hint(std::time::Duration::from_secs(minutes * 60))
            };
            if retire_pending_dns {
                let _at_nineteen_minutes = age(19);
                let next_attempt = pending_active_replacement_dns_retry(&db).unwrap().unwrap();
                let until = Instant::now() + std::time::Duration::from_secs(30);
                let positive = next_attempt
                    .revalidate(
                        &[FirmwareDnsGroupAnswer::FreshAddresses {
                            addresses: &changed_addresses,
                            valid_until: until,
                        }],
                        until,
                    )
                    .unwrap();
                router.reject_target_route.store(true, Relaxed);
                assert!(resume_active_replacement_dns_retry(
                    &db,
                    &router,
                    &positive,
                    |row, iface| { revalidate_peer(None, row, iface) }
                )
                .is_err());
                assert!(!router.reject_target_route.load(Relaxed));
                assert_eq!(Journal::read(&db).unwrap(), pending);
                check("", held_path);
            }
            if retire_pending_dns {
                let _at_twenty_one_minutes = age(21);
                let request = pending_active_replacement_dns_retry(&db).unwrap().unwrap();
                assert!(
                    request
                        .revalidate(
                            &[FirmwareDnsGroupAnswer::NxDomain],
                            Instant::now() + std::time::Duration::from_secs(30),
                        )
                        .is_err(),
                    "renewed positive policy hint was ignored"
                );
            }
            let _after_renewed_hint_expires = retire_pending_dns.then(|| age(41));
            let good_until = Instant::now() + std::time::Duration::from_secs(30);
            let answer = if retire_pending_dns {
                FirmwareDnsGroupAnswer::NxDomain
            } else {
                answer
            };
            let answer = match answer {
                FirmwareDnsGroupAnswer::FreshAddresses { addresses, .. } => {
                    FirmwareDnsGroupAnswer::FreshAddresses {
                        addresses,
                        valid_until: good_until,
                    }
                }
                answer => answer,
            };
            let request = pending_active_replacement_dns_retry(&db).unwrap().unwrap();
            let proof = request
                .revalidate(&fresh_response(answer, good_until), good_until)
                .unwrap();
            resume_active_replacement_dns_retry(&db, &router, &proof, |row, iface| {
                revalidate_peer(None, row, iface)
            })
            .unwrap();
            assert!(pending_active_replacement_dns_retry(&db).unwrap().is_none());
        }
        assert!(observation(&db).unwrap().unwrap().ready);
        assert_eq!(
            pending_active_replacement_retirement(&db).unwrap().unwrap(),
            peers[0].owner
        );
    } else {
        if let Some(held) = &held {
            let mut mismatched = held.clone();
            mismatched.owner.pid = peers[0].owner.pid;
            assert!(replace_with(Some(&mismatched)).is_err());
            assert!(replace_with(None).is_err());
            assert_eq!(Journal::read(&db).unwrap(), old);
        }
        if router.rotated {
            let foreign = |verb| {
                k.call(
                    "ip",
                    &[
                        "-4",
                        "rule",
                        verb,
                        "pref",
                        "69",
                        "from",
                        if router.global_change { "all" } else { INSIDE },
                        "to",
                        NEW_A,
                        "blackhole",
                    ],
                )
                .unwrap();
            };
            foreign("add");
            assert!(replace().is_err());
            assert_eq!(Journal::read(&db).unwrap(), old);
            assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), before);
            foreign("del");
        }
        router.target_route.store(true, Relaxed);
        assert!(replace().is_err());
        assert!(!router.target_route.load(Relaxed));
        check(SOURCE, old_global);
        check_other(SOURCE);
        if router.rotated {
            check_rotated("wan0");
        }
        assert_eq!(Journal::read(&db).unwrap(), old);
        let scoped_guard = has_held && !killswitch;
        let lost_release = cold || scoped_guard;
        router.retired_stop.store(lost_release, Relaxed);
        assert_eq!(replace().unwrap().is_some(), lost_release);
        assert!(!router.retired_stop.load(Relaxed));
        if cold && !has_held {
            assert!(nfqws2_awg_profile::read(&db).unwrap()["servers"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row["id"] != SOURCE));
            assert!(!observation(&db).unwrap().unwrap().ready);
            operate_with_redirect(&db, &router, Operation::Recover, None, Some(&bridges), live)
                .unwrap();
        }
        if has_held && lost_release {
            assert!(pending_active_replacement_retirement(&db)
                .unwrap()
                .is_none());
            assert!(!observation(&db).unwrap().unwrap().ready);
            let held = held.as_ref().unwrap();
            let recover = |witness: Option<&ActiveReplacementPeer>| {
                operate_with_redirect(
                    &db,
                    &router,
                    Operation::Recover,
                    None,
                    Some(&bridges),
                    |row, iface| {
                        let native = if iface == held_iface {
                            witness
                        } else {
                            Some(&peers[1])
                        };
                        let native = native.ok_or(io::ErrorKind::NotConnected)?;
                        Ok(live(row, iface)?.with_active_replacement_peer(Some(native.clone())))
                    },
                )
                .unwrap();
            };
            let mut stale = held.clone();
            stale.owner.pid += 1;
            recover(Some(&stale));
            assert!(!observation(&db).unwrap().unwrap().ready);
            let parked = Journal::read(&db).unwrap();
            assert!(parked.installed.killswitch || !parked.installed.temporary_stops.is_empty());
            let scoped_path = if cold { "wan0" } else { "" };
            check(scoped_path, held_iface);
            if router.rotated {
                check_rotated("");
            }
            recover(None);
            check(scoped_path, held_iface);
            recover(Some(held));
        }
    }
    check(
        if cold && !router.global_change {
            "wan0"
        } else {
            TARGET_IFACE
        },
        if router.global_change && archive_scenario != Some(ArchiveScenario::Both) {
            "wan0"
        } else {
            next_global
        },
    );
    if retire_pending_dns {
        check_rotated("wan0");
    }
    if other_was_positive {
        check_packet(INSIDE, PENDING_OTHER, "wan0");
        check_packet(OUTSIDE, PENDING_OTHER, "wan0");
    }
    if both_become_positive {
        check_packet(INSIDE, PENDING_OTHER, TARGET_IFACE);
        check_packet(OUTSIDE, PENDING_OTHER, "wan0");
    }
    if supersede {
        check_rotated("wan0");
        for destination in [LATEST_A, LATEST_B] {
            check_packet(INSIDE, destination, TARGET_IFACE);
            check_packet(OUTSIDE, destination, "wan0");
        }
    } else if router.rotated && !retire_pending_dns {
        check_rotated(TARGET_IFACE);
    }
    check_other(
        if other_negative || !mixed_archive && archive_scenario == Some(ArchiveScenario::NoHistory)
        {
            "wan0"
        } else {
            TARGET_IFACE
        },
    );
    let committed = Journal::read(&db).unwrap();
    assert_eq!(committed.committed.killswitch, killswitch);
    assert!(committed.installed.temporary_stops.is_empty());
    assert_eq!(
        committed.committed.learned.as_ref().unwrap().members.len(),
        match replacement {
            FirmwareReplacement::HeldColdRetry {
                pair_becomes_positive: true,
                ..
            } => 4,
            FirmwareReplacement::Warm
            | FirmwareReplacement::RetryRuntime
            | FirmwareReplacement::HeldRetryRuntime
            | FirmwareReplacement::TargetGlobalRetryRuntime
            | FirmwareReplacement::HeldOwner
            | FirmwareReplacement::ColdHeldOwner
            | FirmwareReplacement::UnavailableHeldOwner
            | FirmwareReplacement::RelocatedOwner
            | FirmwareReplacement::TargetGlobal => 2,
            FirmwareReplacement::HeldColdRetry {
                withdraw_after_expiry: true,
                ..
            }
            | FirmwareReplacement::NxDomain
            | FirmwareReplacement::GlobalNxDomain
            | FirmwareReplacement::HeldNxDomain
            | FirmwareReplacement::TargetGlobalNxDomain
            | FirmwareReplacement::HeldColdRetry {
                negative: true,
                newer: false,
                ..
            } => 1,
            FirmwareReplacement::Changed
            | FirmwareReplacement::ChangedExplicit
            | FirmwareReplacement::ChangedGlobalExplicit
            | FirmwareReplacement::HeldChanged
            | FirmwareReplacement::TargetGlobalChanged
            | FirmwareReplacement::HeldColdRetry {
                negative: false, ..
            }
            | FirmwareReplacement::HeldColdRetry { newer: true, .. }
            | FirmwareReplacement::ChangedMultipleGlobalNegative => 3,
            FirmwareReplacement::ChangedMultipleGlobal => 4,
            FirmwareReplacement::Archive(ArchiveScenario::Warm | ArchiveScenario::Recent) => 3,
            FirmwareReplacement::Archive(ArchiveScenario::Discovered) => 4,
            FirmwareReplacement::Archive(ArchiveScenario::Both) => 5,
            FirmwareReplacement::Archive(ArchiveScenario::NoHistory) if mixed_archive => 2,
            FirmwareReplacement::Archive(ArchiveScenario::NoHistory) => 1,
        }
    );
    if cold_launch {
        let launch = active_replacement_launch_cleanup(&db).unwrap().unwrap();
        assert_eq!(launch.target, peers[1].owner);
        assert!(!launch.stop);
        finish_active_replacement_launch_cleanup(&db, &launch).unwrap();
    }
    if has_held && !unavailable {
        assert!(active_replacement_native_witness_needed(&db, held_iface).unwrap());
        assert_eq!(
            pending_active_replacement_retirement(&db).unwrap().unwrap(),
            peers[0].owner
        );
        let published = nfqws2_awg_profile::read(&db).unwrap();
        if target_global {
            let saved_global = |doc: &Value| {
                doc["servers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|row| row["id"] == TARGET)
                    .unwrap()["config"]["routing"]["zones"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|zone| zone["order"] == 2)
                    .cloned()
            };
            assert!(saved_global(&before).is_some());
            assert_eq!(saved_global(&published), saved_global(&before));
            assert_eq!(
                active_replacement_fingerprint(&published, TARGET).unwrap(),
                peers[1].fingerprint
            );
        } else {
            assert_eq!(
                published["servers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|row| row["id"] == HELD),
                before["servers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|row| row["id"] == HELD),
            );
        }
    }
    finish_active_replacement_retirement(&db, &peers[0].owner).unwrap();
    if relocated {
        let expected = if target_global {
            BTreeMap::from([(held_iface.into(), old.installed.scoped_slot(held_iface))])
        } else {
            BTreeMap::from([
                (held_iface.into(), old.installed.scoped_slot(held_iface)),
                (TARGET_IFACE.into(), old.installed.scoped_slot(SOURCE)),
            ])
        };
        assert_eq!(committed.installed.scoped_slots, expected,);
        assert!(
            operate_firmware_refresh(&db, &router, Some(&bridges), live, |_, _| Ok(None)).unwrap()
        );
        assert_eq!(Journal::read(&db).unwrap(), committed);
        check(if cold { "wan0" } else { TARGET_IFACE }, held_iface);
    }
    *router.held.lock().unwrap() = None;
    operate_with_redirect(
        &db,
        &router,
        Operation::Teardown,
        None,
        Some(&bridges),
        live,
    )
    .unwrap();
    for destination in [
        SCOPED,
        OTHER_SCOPED,
        GLOBAL,
        NEW_A,
        NEW_B,
        PENDING_OTHER,
        LATEST_A,
        LATEST_B,
    ]
    .into_iter()
    .chain(multiple.then_some(OTHER_GLOBAL))
    {
        fw(&[
            "-w",
            "-t",
            "mangle",
            "-D",
            "POSTROUTING",
            "-p",
            "udp",
            "-d",
            destination,
            "--dport",
            "42042",
            "-j",
            CHAIN,
        ]);
    }
    fw(&["-w", "-t", "mangle", "-F", CHAIN]);
    fw(&["-w", "-t", "mangle", "-X", CHAIN]);
    ip(&["netns", "del", CLIENT_NS]);
    ip(&["link", "del", TARGET_IFACE]);
    if has_held && !target_global {
        ip(&["link", "del", held_iface]);
    }
    if multiple_bridges {
        for name in [SECOND_LAN, THIRD_LAN] {
            ip(&["link", "del", name]);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReplacementOuter {
    None,
    ColdTarget,
    ColdDnsTarget,
    UnavailableTarget,
    UnavailableScopedTarget,
    UnavailableDnsTarget,
    DisabledDnsClient,
    DisabledDnsServer,
    Configured,
    Nested,
    NestedStandby,
    SharedNested,
    NestedTarget,
    DistinctNested,
    DistinctNestedStandby,
    DistinctPermanent,
    PermanentWithoutPlain,
    InitialPermanentWithoutPlain,
    MixedPermanentTarget,
    MixedPermanentSource,
    SourceQualified,
    ObservedDns,
    LiveObservedDns,
    ClientObservedDns,
    LiveNamed { source: bool, target: bool },
    ColdNamedTarget,
    UnavailableNamedTarget,
    RotatedNamedTarget,
    InitiallyUnresolvedNamedTarget,
    AaaaOnlyNamedTarget,
    WarmAaaaNamedTarget,
}

fn real_cidr_replacement(saved_kill_switch: bool, multiple: bool, state: ReplacementOuter) {
    use nfqws2_awg_profile::{
        active_replacement_fingerprint, active_replacement_nested_mtu,
        active_replacement_underlay_identity, nested_socket_selector, ActiveReplacementPeer,
        ActiveReplacementStage, ActiveReplacementUnderlay, NativeNestedRemovalScope,
        NativeRemovalSeal, ACTIVE_REPLACEMENT_FIELD,
    };
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};

    const SOURCE: &str = "awg0";
    const TARGET: &str = "replacement";
    const TARGET_IFACE: &str = "awg31";
    const OUTER: &str = "stable-outer";
    const OUTER_IFACE: &str = "awg32";
    const OUTER_ENDPOINT: &str = "198.51.100.12:443";
    const OUTER_ADDR: &str = "10.32.0.2";
    const TARGET_OUTER: &str = "independent-target-outer";
    const TARGET_OUTER_IFACE: &str = "awg33";
    const TARGET_OUTER_ENDPOINT: &str = "198.51.100.13:443";
    const TARGET_OUTER_ADDR: &str = "10.33.0.2";
    const INNER_IP: &str = "198.51.100.10";
    const INNER_ROUTE: &str = "198.51.100.10/32";
    const TARGET_INNER_IP: &str = "198.51.100.11";
    const TARGET_INNER_ROUTE: &str = "198.51.100.11/32";
    const OLD_ENDPOINT: &str = "198.51.100.10:443";
    const NEW_ENDPOINT: &str = "198.51.100.11:443";
    let new_endpoint = if state == ReplacementOuter::WarmAaaaNamedTarget {
        "[2001:db8:117::12]:443"
    } else {
        NEW_ENDPOINT
    };
    const UNSELECTED_IPV6: &str = "2001:db8:117::12";
    const UNSELECTED_IPV6_SOCKET: &str = "[2001:db8:117::12]:443";
    const DESTINATION: &str = "203.0.113.50";
    const SCOPE: &str = "203.0.113.0/24";
    const OTHER_DESTINATION: &str = "198.18.3.55";
    const OTHER_SCOPE: &str = "198.18.3.0/24";
    const LAN: &str = "br-lan-transfer";
    const LAN_ADDRESS: &str = "192.168.51.1/24";
    const INSIDE: &str = "192.168.51.40";
    const OUTSIDE: &str = "192.168.51.90";
    const SOURCE_SCOPE: &str = "192.168.51.32/27";
    const CLIENT_SCOPE: &str = "192.168.51.40";
    const DNS_BRIDGE: &str = "br-transfer";
    const DNS_DOMAIN: &str = "media.corp.example";
    const DNS_DESTINATION: &str = "198.18.4.24";
    const DNS_DESTINATION_TWO: &str = "198.18.4.55";
    let source_qualified = matches!(
        state,
        ReplacementOuter::SourceQualified | ReplacementOuter::UnavailableScopedTarget
    );
    let client_dns = state == ReplacementOuter::ClientObservedDns;
    let (named_source, named_target) = match state {
        ReplacementOuter::LiveNamed { source, target } => (source, target),
        ReplacementOuter::ColdNamedTarget
        | ReplacementOuter::UnavailableNamedTarget
        | ReplacementOuter::RotatedNamedTarget
        | ReplacementOuter::InitiallyUnresolvedNamedTarget
        | ReplacementOuter::AaaaOnlyNamedTarget
        | ReplacementOuter::WarmAaaaNamedTarget => {
            (false, true)
        }
        _ => (false, false),
    };
    let named = named_source || named_target;
    let source_scope = if client_dns {
        Some(CLIENT_SCOPE)
    } else {
        source_qualified.then_some(SOURCE_SCOPE)
    };
    let bridge = if client_dns { LAN } else { DNS_BRIDGE };
    let cold_dns = matches!(
        state,
        ReplacementOuter::ColdDnsTarget | ReplacementOuter::UnavailableDnsTarget
    );
    let disabled_dns = matches!(
        state,
        ReplacementOuter::DisabledDnsClient | ReplacementOuter::DisabledDnsServer
    );
    let live_dns = state == ReplacementOuter::LiveObservedDns || client_dns || cold_dns || disabled_dns;
    let observed_dns = state == ReplacementOuter::ObservedDns || live_dns;
    let unavailable_target = matches!(
        state,
        ReplacementOuter::UnavailableTarget
            | ReplacementOuter::UnavailableScopedTarget
            | ReplacementOuter::UnavailableDnsTarget
            | ReplacementOuter::UnavailableNamedTarget
            | ReplacementOuter::RotatedNamedTarget
            | ReplacementOuter::InitiallyUnresolvedNamedTarget
            | ReplacementOuter::AaaaOnlyNamedTarget
    );
    let cold_named = matches!(
        state, ReplacementOuter::ColdNamedTarget
            | ReplacementOuter::UnavailableNamedTarget
            | ReplacementOuter::RotatedNamedTarget
            | ReplacementOuter::InitiallyUnresolvedNamedTarget
            | ReplacementOuter::AaaaOnlyNamedTarget
            | ReplacementOuter::WarmAaaaNamedTarget
    );
    let cold_target = state == ReplacementOuter::ColdTarget || cold_named || unavailable_target || cold_dns;
    let aaaa_only = state == ReplacementOuter::AaaaOnlyNamedTarget;
    let warm_aaaa = state == ReplacementOuter::WarmAaaaNamedTarget;
    let initially_unresolved = state == ReplacementOuter::InitiallyUnresolvedNamedTarget || aaaa_only;
    let hot_only = (source_qualified || observed_dns || named) && !cold_target;
    let configured_outer = state != ReplacementOuter::None && !hot_only && !cold_target;
    let nested = matches!(
        state,
        ReplacementOuter::Nested
            | ReplacementOuter::NestedStandby
            | ReplacementOuter::SharedNested
            | ReplacementOuter::DistinctNested
            | ReplacementOuter::DistinctNestedStandby
            | ReplacementOuter::DistinctPermanent
            | ReplacementOuter::PermanentWithoutPlain
            | ReplacementOuter::InitialPermanentWithoutPlain
            | ReplacementOuter::MixedPermanentSource
    );
    let standby_outer = matches!(
        state,
        ReplacementOuter::NestedStandby | ReplacementOuter::DistinctNestedStandby
    );
    let nested_target = matches!(
        state,
        ReplacementOuter::SharedNested
            | ReplacementOuter::NestedTarget
            | ReplacementOuter::DistinctNested
            | ReplacementOuter::DistinctNestedStandby
            | ReplacementOuter::DistinctPermanent
            | ReplacementOuter::PermanentWithoutPlain
            | ReplacementOuter::InitialPermanentWithoutPlain
            | ReplacementOuter::MixedPermanentTarget
    );
    let has_nested_path = nested || nested_target;
    let distinct = matches!(
        state,
        ReplacementOuter::DistinctNested
            | ReplacementOuter::DistinctNestedStandby
            | ReplacementOuter::DistinctPermanent
            | ReplacementOuter::PermanentWithoutPlain
            | ReplacementOuter::InitialPermanentWithoutPlain
    );
    let initial = state == ReplacementOuter::InitialPermanentWithoutPlain;
    let lose_plain = state == ReplacementOuter::PermanentWithoutPlain || initial;
    let mixed = state == ReplacementOuter::MixedPermanentTarget;
    let reverse = state == ReplacementOuter::MixedPermanentSource;
    let permanent = state == ReplacementOuter::DistinctPermanent || lose_plain || mixed || reverse;
    let outer_for = |iface: &str| {
        if iface == TARGET_IFACE && distinct {
            (
                TARGET_OUTER,
                TARGET_OUTER_IFACE,
                TARGET_OUTER_ENDPOINT,
                TARGET_OUTER_ADDR,
            )
        } else {
            (OUTER, OUTER_IFACE, OUTER_ENDPOINT, OUTER_ADDR)
        }
    };

    fn scopes(multiple: bool) -> impl Iterator<Item = (&'static str, &'static str)> {
        std::iter::once((DESTINATION, SCOPE))
            .chain(multiple.then_some((OTHER_DESTINATION, OTHER_SCOPE)))
    }

    fn watched_scopes(
        multiple: bool,
        live_dns: bool,
    ) -> impl Iterator<Item = (&'static str, &'static str)> {
        scopes(multiple).chain(
            live_dns
                .then_some([
                    (DNS_DESTINATION, "198.18.4.24/32"),
                    (DNS_DESTINATION_TWO, "198.18.4.55/32"),
                ])
                .into_iter()
                .flatten(),
        )
    }

    fn source_route_device(k: &Kernel<'_>, addr: &str, source: &str) -> Option<String> {
        let route = k
            .call(
                "ip",
                &["-4", "route", "get", addr, "from", source, "iif", LAN],
            )
            .ok()?;
        let mut words = route.split_ascii_whitespace();
        words.find(|word| *word == "dev")?;
        words.next().map(str::to_owned)
    }

    fn has_stop(k: &Kernel<'_>, prefix: &str, source: Option<&str>) -> bool {
        let prefix = prefix.strip_suffix("/32").unwrap_or(prefix);
        k.call("ip", &["-4", "rule", "show"])
            .unwrap()
            .lines()
            .any(|line| {
                line.starts_with("69:")
                    && line.contains(prefix)
                    && line.contains("blackhole")
                    && source.is_none_or(|source| line.contains(source))
            })
    }

    struct CheckKillSwitch {
        fail_write: AtomicBool,
        fail_release: AtomicBool,
        audited: AtomicUsize,
        audit: AtomicBool,
        saved_kill_switch: bool,
        multiple: bool,
        original_direct_unguarded: bool,
        target_direct_unguarded: bool,
        source_scope: Option<&'static str>,
        live_dns: bool,
        marked: Option<packed::Router>,
    }

    impl CheckKillSwitch {
        fn path(&self, addr: &str, prefix: &str) -> (Option<String>, bool) {
            let k = kernel(&nfqws2_router_command::System);
            if self.source_scope.is_some() {
                assert_eq!(
                    source_route_device(&k, addr, OUTSIDE).as_deref(),
                    Some("wan0")
                );
                return (
                    source_route_device(&k, addr, INSIDE),
                    has_stop(&k, prefix, self.source_scope),
                );
            }
            let Some(mark) = self
                .marked
                .as_ref()
                .and_then(|classifier| classifier.packet_mark("192.168.1.42", addr))
            else {
                return (route_device(&k, addr), has_stop(&k, prefix, None));
            };
            let mark = mark.split('/').next().unwrap();
            let slot =
                (u32::from_str_radix(mark.trim_start_matches("0x"), 16).unwrap() >> 20) & 0xff;
            let table = (18000 + slot).to_string();
            let fence = k
                .call("ip", &["-4", "route", "show", "table", &table])
                .unwrap()
                .lines()
                .any(|line| line.starts_with("blackhole default"));
            let device = k
                .call("ip", &["-4", "route", "get", addr, "mark", mark])
                .ok()
                .and_then(|row| {
                    let mut words = row.split_ascii_whitespace();
                    words.find(|word| *word == "dev")?;
                    Some(words.next()?.to_owned())
                });
            (device, fence)
        }

        fn inspect_write(&self, changing_stop: bool) {
            if !self.audit.load(Relaxed) {
                return;
            }
            for (destination, prefix) in watched_scopes(self.multiple, self.live_dns) {
                let (device, fenced) = self.path(destination, prefix);
                let release = changing_stop
                    && (self.marked.is_none()
                        || self.original_direct_unguarded && device.as_deref() == Some(SOURCE)
                        || self.target_direct_unguarded && device.as_deref() == Some(TARGET_IFACE));
                assert!(fenced || release, "unguarded {prefix}");
                assert!(
                    matches!(device.as_deref(), Some(SOURCE | TARGET_IFACE))
                        || device.is_none() && fenced,
                    "unexpected route for {prefix}: {device:?}"
                );
            }
            self.audited.fetch_add(1, Relaxed);
        }
    }

    impl Runner for CheckKillSwitch {
        fn run(&self, program: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
            let system = nfqws2_router_command::System;
            if let Some(fw) = &self.marked {
                if matches!(program, "iptables" | "ipset") {
                    return fw.run(program, args, deadline);
                }
            }
            let result = system.run(program, args, deadline);
            if program == "ip"
                && matches!(
                    args,
                    ["-4", "route" | "rule", "add" | "del" | "replace", ..]
                )
            {
                let changing_stop = !self.saved_kill_switch
                    && (matches!(args, ["-4", "rule", "add" | "del", "pref", "69", ..])
                        || self.original_direct_unguarded
                            && matches!(
                                args,
                                ["-4", "route", "del", "blackhole", "default", "table", ..]
                            ));
                self.inspect_write(changing_stop);
                if result.is_ok()
                    && matches!(args, ["-4", "rule", "del", "pref", "69", ..])
                    && self.fail_release.swap(false, Relaxed)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "сбой после снятия временной защиты",
                    ));
                }
                if self.audit.load(Relaxed)
                    && result.is_ok()
                    && args[1] == "route"
                    && matches!(args[2], "add" | "replace")
                    && args.contains(&TARGET_IFACE)
                    && (self.marked.is_some() || !self.multiple || args.contains(&SCOPE))
                    && self.fail_write.swap(false, Relaxed)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "сбой после записи пути к заменяющему туннелю",
                    ));
                }
            }
            result
        }

        fn run_input(
            &self,
            program: &str,
            args: &[&str],
            input: &[u8],
            deadline: Instant,
        ) -> io::Result<String> {
            if let Some(fw) = &self.marked {
                if matches!(program, "iptables-restore" | "ipset") {
                    let result = fw.run_input(program, args, input, deadline);
                    self.inspect_write(false);
                    return result;
                }
            }
            nfqws2_router_command::System.run_input(program, args, input, deadline)
        }
    }

    let system = nfqws2_router_command::System;
    let k = kernel(&system);
    if source_scope.is_some() {
        k.call("ip", &["link", "add", LAN, "type", "dummy"])
            .unwrap();
        k.call("ip", &["addr", "add", LAN_ADDRESS, "dev", LAN])
            .unwrap();
        k.call("ip", &["link", "set", LAN, "up"]).unwrap();
    }
    if observed_dns && !client_dns {
        k.call("ip", &["link", "add", DNS_BRIDGE, "type", "dummy"])
            .unwrap();
        k.call("ip", &["link", "set", DNS_BRIDGE, "up"]).unwrap();
    }
    let plain_lost = AtomicBool::new(false);
    let block_plain = |verb: &str, dest: &str| {
        k.call(
            "ip",
            &["-4", "rule", verb, "pref", "65", "to", dest, "prohibit"],
        )
        .unwrap();
    };
    let (nested_mark, _) = nested_socket_selector(SOURCE).unwrap();
    let (target_mark, _) = nested_socket_selector(TARGET_IFACE).unwrap();
    let selector = |iface: &str| {
        let (mark, table) = nested_socket_selector(iface).unwrap();
        (format!("{mark:#x}"), table.to_string())
    };
    let nested_route = |verb: &str, iface: &str, dest: &str, source: &str| {
        let (_, table) = selector(iface);
        let (_, outer_iface, ..) = outer_for(iface);
        k.call(
            "ip",
            &[
                "-4",
                "route",
                verb,
                dest,
                "dev",
                outer_iface,
                "src",
                source,
                "table",
                &table,
                "proto",
                "99",
            ],
        )
        .unwrap();
    };
    let nested_rules = |verb: &str, iface: &str| {
        let (mark, table) = selector(iface);
        for family in std::iter::once("-4").chain(nested_target.then_some("-6")) {
            k.call(
                "ip",
                &[
                    family, "rule", verb, "pref", "60", "fwmark", &mark, "lookup", &table,
                ],
            )
            .unwrap();
            k.call(
                "ip",
                &[
                    family, "rule", verb, "pref", "61", "fwmark", &mark, "prohibit",
                ],
            )
            .unwrap();
        }
    };
    let check_nested = |iface: &str, dest: &str, source: &str| {
        let (mark, table) = selector(iface);
        let (_, outer_iface, ..) = outer_for(iface);
        let result = k
            .call("ip", &["-4", "route", "get", dest, "mark", &mark])
            .unwrap();
        let words: Vec<_> = result.split_ascii_whitespace().collect();
        assert!(
            words.windows(2).any(|w| w == ["dev", outer_iface]),
            "{result}"
        );
        assert!(
            words.windows(2).any(|w| w == ["table", table.as_str()]),
            "{result}"
        );
        assert!(words.windows(2).any(|w| w == ["src", source]), "{result}");
        assert_eq!(
            route_device(&k, dest).as_deref(),
            (!plain_lost.load(Relaxed)).then_some("wan0")
        );
    };
    let setup_outer = |iface: &str, addresses: [&str; 2]| {
        k.call("ip", &["link", "add", iface, "type", "dummy"])
            .unwrap();
        k.call("ip", &["link", "set", iface, "up", "mtu", "1420"])
            .unwrap();
        for address in addresses {
            k.call("ip", &["-4", "addr", "add", address, "dev", iface])
                .unwrap();
        }
    };
    if has_nested_path {
        setup_outer(OUTER_IFACE, ["10.32.0.2/32", "10.32.0.3/32"]);
        if distinct {
            setup_outer(TARGET_OUTER_IFACE, ["10.33.0.2/32", "10.33.0.3/32"]);
        }
        if nested {
            nested_route("add", SOURCE, INNER_ROUTE, OUTER_ADDR);
            nested_rules("add", SOURCE);
        }
    }
    let start_target = || {
        k.call("ip", &["link", "add", TARGET_IFACE, "type", "dummy"])
            .unwrap();
        k.call(
            "ip",
            &["-4", "addr", "add", "10.31.0.2/32", "dev", TARGET_IFACE],
        )
        .unwrap();
        k.call("ip", &["link", "set", TARGET_IFACE, "up", "mtu", "1420"])
            .unwrap();
    };
    start_target();
    let (_dir, db, _) = setup();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"]["killswitch"] = json!(saved_kill_switch);
        if observed_dns {
            doc["routing"]["domain_source"] = json!("dnsproxy");
        }
        let source = &mut doc["servers"][0]["config"];
        source["install"] = json!("imported");
        source["protocol"] = json!("wireguard");
        source["endpoint"] = json!(OLD_ENDPOINT);
        source["client"]["rust_managed"] = json!(true);
        source["client"]["peer_id"] = json!("router");
        source["peers"] = json!([{
            "id":"router","is_router":true,"address":"10.30.0.2/32",
            "private_key":format!("B{}=", "A".repeat(42)), "allowed_ips":["0.0.0.0/0"]
        }]);
        if multiple {
            source["client"]["double_tunnel_mode"] = json!("automatic");
            let zones = source["routing"]["zones"].as_array_mut().unwrap();
            if saved_kill_switch {
                zones[0]["ips"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!(OTHER_SCOPE));
            } else {
                zones.push(json!({"name":"second","enabled":true,"ips":[OTHER_SCOPE]}));
            }
        }
        if let Some(scope) = source_scope {
            for zone in source["routing"]["zones"].as_array_mut().unwrap() {
                zone["source_ips"] = json!([scope]);
            }
        }
        if observed_dns {
            source["routing"]["zones"][0]["order"] = json!(1);
            source["routing"]["zones"][0]["domains"] = json!(["*.corp.example"]);
        }
        if permanent && !mixed {
            source["client"]["double_tunnel_mode"] = json!("permanent");
        }
        if configured_outer && state != ReplacementOuter::NestedTarget && !mixed {
            source["client"]["double_tunnel_id"] = json!(OUTER);
        }
        let mut target = source.clone();
        target["client_iface"] = json!(TARGET_IFACE);
        target["endpoint"] = json!(NEW_ENDPOINT);
        target["client"]["standby"] = json!(warm_aaaa || !permanent && !hot_only && !cold_target);
        if disabled_dns {
            let disable_server = state == ReplacementOuter::DisabledDnsServer;
            target["enabled"] = json!(!disable_server);
            target["client"]["enabled"] = json!(disable_server);
            target["client"]["standby"] = json!(true);
        }
        if multiple {
            target["client"]["double_tunnel_mode"] = json!("last_resort");
        }
        if permanent {
            target["client"]["double_tunnel_mode"] =
                json!(if reverse { "automatic" } else { "permanent" });
        }
        if nested_target {
            target["client"]["double_tunnel_id"] = json!(outer_for(TARGET_IFACE).0);
        } else if nested {
            target["client"]["double_tunnel_id"] = json!("");
        }
        target["peers"][0]["address"] = json!("10.31.0.2/32");
        target["routing"]["zones"] = json!([]);
        let outer = configured_outer.then(|| {
            let mut outer = target.clone();
            outer["client_iface"] = json!(OUTER_IFACE);
            outer["endpoint"] = json!(OUTER_ENDPOINT);
            outer["client"]["standby"] = json!(!has_nested_path || standby_outer);
            outer["peers"][0]["address"] = json!("10.32.0.2/32");
            outer["client"]["double_tunnel_id"] = json!("");
            outer["client"]["double_tunnel_mode"] = json!("off");
            outer
        });
        let rows = doc["servers"].as_array_mut().unwrap();
        rows.push(json!({"id":TARGET,"config":target}));
        if let Some(outer) = outer {
            let second = distinct.then(|| {
                let mut target_outer = outer.clone();
                target_outer["client_iface"] = json!(TARGET_OUTER_IFACE);
                target_outer["endpoint"] = json!(TARGET_OUTER_ENDPOINT);
                target_outer["peers"][0]["address"] = json!("10.33.0.2/32");
                target_outer["client"]["standby"] = json!(false);
                target_outer
            });
            rows.push(json!({"id":OUTER,"config":outer}));
            if let Some(second) = second {
                rows.push(json!({"id":TARGET_OUTER,"config":second}));
            }
        }
        Ok(())
    })
    .unwrap();
    let before_apply = nfqws2_awg_profile::read(&db).unwrap();
    let source_mtu = if nested {
        let mtu = active_replacement_nested_mtu(&before_apply, SOURCE, 1420).unwrap();
        set_physical_mtu(&k, mtu);
        mtu
    } else {
        1420
    };
    let target_mtu = if nested_target {
        let mtu = active_replacement_nested_mtu(&before_apply, TARGET, 1420).unwrap();
        k.call(
            "ip",
            &["link", "set", TARGET_IFACE, "mtu", &mtu.to_string()],
        )
        .unwrap();
        mtu
    } else {
        1420
    };
    let live = |cfg: &Value, iface: &str| {
        assert!(matches!(iface, SOURCE | TARGET_IFACE));
        let endpoint = cfg["endpoint"].as_str().unwrap();
        let endpoint = (if named && endpoint.ends_with(".test:443") {
            if iface == SOURCE { OLD_ENDPOINT } else { new_endpoint }
        } else {
            endpoint
        }).parse().unwrap();
        let mut found = LivePeer {
            endpoint,
            socket_mark: DIRECT_SOCKET_MARK,
            ..peer(cfg, SOURCE)?
        };
        let nested_slot = if nested && iface == SOURCE {
            Some((nested_mark, source_mtu))
        } else if nested_target && iface == TARGET_IFACE {
            Some((target_mark, target_mtu))
        } else {
            None
        };
        if let Some((mark, mtu)) = nested_slot {
            let (outer, outer_iface, outer_endpoint, _) = outer_for(iface);
            found.socket_mark = mark;
            found.nested_mtu = Some(mtu);
            found.nested_transport = Some(RoutedNestedTransport {
                peer: RoutedMtuPeer {
                    iface: iface.into(),
                    outer_id: outer.into(),
                    outer_iface: outer_iface.into(),
                    endpoint,
                    effective_mtu: mtu,
                    socket_mark: mark,
                },
                outer_endpoint: outer_endpoint.parse().unwrap(),
            });
        }
        Ok(found)
    };
    let now = nfqws2_awg_profile::now();
    let router = CheckKillSwitch {
        fail_write: AtomicBool::new(true),
        fail_release: AtomicBool::new(false),
        audited: AtomicUsize::new(0),
        audit: AtomicBool::new(false),
        saved_kill_switch,
        multiple,
        original_direct_unguarded: mixed && !saved_kill_switch,
        target_direct_unguarded: reverse && !saved_kill_switch,
        source_scope,
        live_dns,
        marked: permanent.then(packed::Router::default),
    };
    let build_witnesses = |doc: &Value, boot: &str| {
        let witness = |id: &str, iface: &str, endpoint: &str, pid: u32| ActiveReplacementPeer {
            owner: NativeRemovalSeal {
                id: id.into(),
                iface: iface.into(),
                boot: boot.to_owned(),
                pid,
                started: u64::from(pid),
                receipt_sha256: [pid as u8; 32],
                nested: None,
            },
            fingerprint: if disabled_dns && id == TARGET {
                [0; 32]
            } else if (id == SOURCE && named_source) || (id == TARGET && named_target) {
                nfqws2_awg_profile::active_named_replacement_fingerprint(doc, id).unwrap()
            } else {
                active_replacement_fingerprint(doc, id).unwrap()
            },
            endpoint: endpoint.parse().unwrap(),
            socket_mark: DIRECT_SOCKET_MARK,
            mtu: 1420,
            allowed: vec!["0.0.0.0/0".into()],
            underlay: None,
            nested_only: false,
        };
        let mut peers = [
            witness(SOURCE, SOURCE, OLD_ENDPOINT, 42),
            witness(TARGET, TARGET_IFACE, new_endpoint, 43),
        ];
        if has_nested_path {
            let transport = |peer: &mut ActiveReplacementPeer, ip: &str, mark, mtu| {
                let (outer, outer_iface, _, source) = outer_for(&peer.owner.iface);
                let (iface, endpoint, fingerprint) =
                    active_replacement_underlay_identity(doc, outer).unwrap();
                let pid = if outer == OUTER { 44 } else { 45 };
                let underlay = ActiveReplacementUnderlay {
                    owner: NativeRemovalSeal {
                        id: outer.into(),
                        iface,
                        boot: boot.to_owned(),
                        pid,
                        started: u64::from(pid),
                        receipt_sha256: [pid as u8; 32],
                        nested: None,
                    },
                    fingerprint,
                    endpoint,
                    socket_mark: DIRECT_SOCKET_MARK,
                    mtu: 1420,
                    allowed: vec!["0.0.0.0/0".into()],
                };
                peer.owner.nested = Some(NativeNestedRemovalScope {
                    outer_iface: outer_iface.into(),
                    endpoint: ip.parse().unwrap(),
                    source: source.parse().unwrap(),
                });
                peer.underlay = Some(underlay);
                peer.nested_only = lose_plain;
                peer.socket_mark = mark;
                peer.mtu = mtu;
            };
            if nested {
                transport(&mut peers[0], INNER_IP, nested_mark, source_mtu);
            }
            if nested_target {
                transport(&mut peers[1], TARGET_INNER_IP, target_mark, target_mtu);
            }
        }
        peers
    };
    let prepare_target = || {
        nested_route(
            "add",
            TARGET_IFACE,
            TARGET_INNER_ROUTE,
            outer_for(TARGET_IFACE).3,
        );
        nested_rules("add", TARGET_IFACE);
    };
    let remove_plain_paths = || {
        for inner in [INNER_IP, TARGET_INNER_IP] {
            assert_eq!(route_device(&k, inner).as_deref(), Some("wan0"));
            block_plain("add", inner);
            assert!(route_device(&k, inner).is_none());
        }
        plain_lost.store(true, Relaxed);
    };
    if initial {
        prepare_target();
        remove_plain_paths();
        assert!(Journal::read(&db).unwrap().idle());
        let peers = build_witnesses(&before_apply, &boot_id(&k).unwrap());
        let mut observed = kernel(&router);
        let resolve = |prove_target| {
            let intent = plan::compile_effective(
                &before_apply,
                crate::policy::current(&before_apply).unwrap(),
                None,
                true,
                &[],
                Default::default(),
            )
            .unwrap();
            plan::resolve_on(
                &before_apply,
                intent,
                false,
                None,
                Some(plan::Verification::Read(&observed)),
                |row, iface| {
                    let peer = &peers[usize::from(iface == TARGET_IFACE)];
                    Ok(live(row, iface)?.with_active_replacement_peer(
                        (iface == SOURCE || prove_target).then(|| peer.clone()),
                    ))
                },
            )
            .unwrap()
        };
        let unknown = resolve(false);
        assert!(observed.guard(&unknown.plan, &unknown.endpoints).is_err());
        let ready = resolve(true);
        observed.guard(&ready.plan, &ready.endpoints).unwrap();
        assert_eq!(ready.plan.targets.len(), 1);
        assert!(ready.plan.targets.contains_key(SOURCE));
        // Install the resolved objects with the exact marked kernel paths
        // established by this fixture. No preceding journal is needed.
        for iface in [SOURCE, TARGET_IFACE] {
            let (mark, table) = nested_socket_selector(iface).unwrap();
            observed.nested_sockets.insert(mark, table);
        }
        let goal = objects(&ready.plan);
        synchronize(&observed, &BTreeSet::new(), &goal).unwrap();
        assert_eq!(observed.inventory(&goal, true).unwrap(), goal);
        observed.verify_forward(&ready.plan).unwrap();
        assert_eq!(router.path(DESTINATION, SCOPE), (Some(SOURCE.into()), true));
        check_nested(SOURCE, INNER_IP, OUTER_ADDR);
        check_nested(TARGET_IFACE, TARGET_INNER_IP, TARGET_OUTER_ADDR);
        synchronize(&observed, &goal, &BTreeSet::new()).unwrap();
        for (iface, dest, ip, src) in [
            (SOURCE, INNER_ROUTE, INNER_IP, OUTER_ADDR),
            (
                TARGET_IFACE,
                TARGET_INNER_ROUTE,
                TARGET_INNER_IP,
                TARGET_OUTER_ADDR,
            ),
        ] {
            nested_rules("del", iface);
            nested_route("del", iface, dest, src);
            block_plain("del", ip);
        }
        for iface in [TARGET_IFACE, OUTER_IFACE, TARGET_OUTER_IFACE] {
            k.call("ip", &["link", "del", iface]).unwrap();
        }
        set_physical_mtu(&k, 1420);
        return;
    }
    for op in [Operation::Apply, Operation::Commit] {
        if observed_dns {
            operate_with_redirect(&db, &router, op, None, Some(&[bridge.into()]), live).unwrap();
        } else {
            operate_at(&db, &router, op, now, live).unwrap();
        }
    }
    let dns_ips = [
        DNS_DESTINATION.parse().unwrap(),
        DNS_DESTINATION_TWO.parse().unwrap(),
    ];
    let renewed_dns = if live_dns {
        let revision = observation(&db).unwrap().unwrap().revision;
        let origin = DnsOrigin {
            client: client_dns.then(|| INSIDE.parse().unwrap()),
            ingress: Some(bridge),
        };
        if client_dns {
            learn_named_client_answer(
                &db,
                &router,
                Answer {
                    revision,
                    zone: 0,
                    addresses: &dns_ips,
                    ttl: 360,
                    qtype: 1,
                },
                origin,
                DNS_DOMAIN,
                live,
                || Ok(()),
            )
            .unwrap();
        } else {
            learn_archived_answer(
                &db,
                &router,
                ArchiveAnswer {
                    revision,
                    name: DNS_DOMAIN,
                    addresses: &dns_ips,
                    ttl: 360,
                    qtype: 1,
                },
                live,
                || Ok(()),
            )
            .unwrap();
        }
        if client_dns {
            let receipt = Journal::read(&db).unwrap();
            let basis = confirmed_firmware_refresh_basis(&db).unwrap().unwrap();
            assert_eq!(basis.revision(), revision);
            let refresh = || {
                operate_firmware_refresh(&db, &router, Some(&[bridge.into()]), live, |_, _| {
                    Ok(None)
                })
                .unwrap()
            };
            let carry = || {
                let carried = std::cell::Cell::new(false);
                basis
                    .continue_if_current(&db, || carried.set(true))
                    .unwrap();
                carried.get()
            };
            assert!(refresh());
            assert!(carry());

            let learned_prefix = Prefix::host(dns_ips[0]);
            let table = objects(&receipt.installed)
                .into_iter()
                .find_map(|object| match object {
                    Object::Route(prefix, iface, table)
                        if prefix == learned_prefix && iface == SOURCE =>
                    {
                        Some(table)
                    }
                    _ => None,
                })
                .unwrap();
            k.call(
                "ip",
                &[
                    "-4",
                    "route",
                    "del",
                    &learned_prefix.to_string(),
                    "table",
                    &table.to_string(),
                ],
            )
            .unwrap();
            assert!(!refresh());
            assert_eq!(Journal::read(&db).unwrap(), receipt);
            assert!(inspect(&db, &router).unwrap().ready);
            assert!(refresh());

            let original_doc = nfqws2_awg_profile::read(&db).unwrap();
            nfqws2_awg_profile::edit_document(&db, |doc| {
                doc["servers"][0]["name"] = json!("different profile configuration");
                Ok(())
            })
            .unwrap();
            assert_eq!(Journal::read(&db).unwrap(), receipt);
            assert!(!carry());
            nfqws2_awg_profile::edit_document(&db, |doc| {
                *doc = original_doc;
                doc["routing_revision"] = json!(revision + 1);
                Ok(())
            })
            .unwrap();
            assert!(confirmed_firmware_refresh_basis(&db).unwrap().is_none());
            nfqws2_awg_profile::edit_document(&db, |doc| {
                doc["routing_revision"] = json!(revision);
                Ok(())
            })
            .unwrap();

            let mut pending = receipt.clone();
            pending.expires = nfqws2_awg_profile::now() + 60;
            let save = |value: &Journal| {
                db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, value, RECEIPT_LIMIT))
                    .unwrap()
            };
            save(&pending);
            assert!(!carry());
            assert!(!refresh());
            save(&receipt);
            assert!(carry());
        }
        let requested = active_replacement_dns_revalidation(&db, SOURCE)
            .unwrap()
            .unwrap();
        let revalidate =
            |name, ips, ttl, source| requested.clone().revalidate_from(name, ips, ttl, source);
        assert!(revalidate(DNS_DOMAIN, &dns_ips[..1], 240, origin).is_err());
        assert!(revalidate("outside.example", &dns_ips, 240, origin).is_err());
        assert!(revalidate(DNS_DOMAIN, &dns_ips, 0, origin).is_err());
        if client_dns {
            assert_eq!(requested.client(), origin.client);
            assert!(requested
                .clone()
                .revalidate(DNS_DOMAIN, &dns_ips, 240)
                .is_err());
            assert!(revalidate(
                DNS_DOMAIN,
                &dns_ips,
                240,
                DnsOrigin {
                    client: Some(OUTSIDE.parse().unwrap()),
                    ..origin
                }
            )
            .is_err());
            assert!(revalidate(
                DNS_DOMAIN,
                &dns_ips,
                240,
                DnsOrigin {
                    ingress: Some(DNS_BRIDGE),
                    ..origin
                }
            )
            .is_err());
        }
        Some(revalidate(DNS_DOMAIN, &dns_ips, 240, origin).unwrap())
    } else {
        None
    };
    if nested_target {
        // The profile is still unselected while both actual RPDB pairs exist.
        prepare_target();
    }
    if lose_plain {
        remove_plain_paths();
    }
    let names = if named {
        nfqws2_awg_profile::edit_document(&db, |doc| {
            let rows = doc["servers"].as_array_mut().unwrap();
            if named_source {
                rows[0]["config"]["endpoint"] = json!("r111-source.test:443");
            }
            if named_target {
                rows[1]["config"]["endpoint"] = json!("r111-target.test:443");
            }
            Ok(())
        })
        .unwrap();
        if warm_aaaa {
            let request = warm_named_replacement_request(&db).unwrap().unwrap();
            assert_eq!(request.host(), "r111-target.test");
            let addresses = [
                new_endpoint.parse::<std::net::SocketAddr>().unwrap().ip(),
                "2001:db8:117::13".parse().unwrap(),
            ];
            assert!(request.authorize(&db, &addresses, Instant::now()).is_err());
            assert!(request.authorize(&db, &[addresses[0], "198.51.100.12".parse().unwrap()], Instant::now() + Duration::from_secs(12)).is_err());
            Some(request.authorize(&db, &addresses, Instant::now() + Duration::from_secs(12)).unwrap())
        } else if initially_unresolved {
            let document = nfqws2_awg_profile::read(&db).unwrap();
            let journal = Journal::read(&db).unwrap();
            let failure = NamedActiveReplacement::prepare_intent(
                &db, &document, SOURCE, TARGET, |_, _, _| Err(io::ErrorKind::TimedOut.into()),
            );
            assert_eq!(failure.err().unwrap().kind(), io::ErrorKind::TimedOut);
            assert_eq!(Journal::read(&db).unwrap(), journal);
            assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), document);
            Some(NamedActiveReplacement::prepare_intent(
                &db, &document, SOURCE, TARGET, |_, id, _| {
                    assert_eq!(id, TARGET);
                    Ok(aaaa_only.then(|| vec![UNSELECTED_IPV6_SOCKET.parse().unwrap()]))
                },
            ).unwrap().unwrap())
        } else {
            Some(prepare_named_active_replacement(&db, SOURCE, TARGET).unwrap().unwrap())
        }
    } else {
        None
    };
    let old = Journal::read(&db).unwrap();
    let before = nfqws2_awg_profile::read(&db).unwrap();
    let peers = build_witnesses(&before, &old.boot);
    let mut after = before.clone();
    let source = after["servers"].as_array_mut().unwrap().remove(0);
    let mut zones = source["config"]["routing"]["zones"]
        .as_array()
        .unwrap()
        .clone();
    for (index, rule) in zones.iter_mut().enumerate() {
        rule["tunnel_id"] = json!(TARGET);
        rule["order"] = json!(index + 1);
    }
    let target = &mut after["servers"][0]["config"];
    target["routing"]["zones"] = json!(zones);
    target["routing"]["active"] = json!(true);
    target["client"]["standby"] = json!(false);
    after["active_id"] = json!(TARGET);
    after["routing_revision"] = json!(old.committed.revision + 1);
    router.audit.store(true, Relaxed);
    let replace_with = |witnesses: &[ActiveReplacementPeer; 2]| {
        db.transaction(|tx| {
            if let Some(names) = &names {
                if warm_aaaa {
                    return replace_active_profile_with_warm_name(
                        &db, tx, &router, &before, &after,
                        (witnesses, &["wan0".into()], names, &|| Ok(())), || Ok(()),
                    );
                }
                return replace_active_profile_with_names(
                    &db, tx, &router, &before, &after,
                    (witnesses, &["wan0".into()], names), || Ok(()),
                );
            }
            replace_active_profile_with_dns(
                &db,
                tx,
                &router,
                &before,
                &after,
                (witnesses, &["wan0".into()], renewed_dns.as_ref()),
                || Ok(()),
            )
        })
    };
    let replace = || replace_with(&peers);
    let check_paths = |iface| {
        for (destination, prefix) in watched_scopes(multiple, live_dns) {
            let (dev, fenced) = router.path(destination, prefix);
            assert_eq!(dev.as_deref(), Some(iface));
            assert_eq!(
                fenced,
                saved_kill_switch
                    || permanent
                        && (!mixed || iface == TARGET_IFACE)
                        && (!reverse || iface == SOURCE)
            );
            if permanent {
                assert!(!has_stop(&k, prefix, None));
            }
        }
    };
    check_paths(SOURCE);
    if disabled_dns {
        router.audit.store(false, Relaxed);
        let withdraw = |before_write: &dyn Fn() -> io::Result<()>| {
            db.transaction(|tx| {
                replace_active_profile_with_disabled_target(
                    &db, tx, &router, (&before, &after),
                    (TARGET, (&peers[0], None), &["wan0".into()]),
                    &|| Ok(()), before_write,
                )
            })
        };
        assert_eq!(
            disabled_replacement_dns_redirects(&db, SOURCE).unwrap(),
            Some((old.installed.revision, vec![bridge.into()]))
        );
        assert!(withdraw(&|| Ok(())).is_err());
        k.call("ip", &["link", "del", TARGET_IFACE]).unwrap();
        assert!(withdraw(&|| Err(io::ErrorKind::Interrupted.into())).is_err());
        assert_eq!(Journal::read(&db).unwrap(), old);
        check_paths(SOURCE);
        withdraw(&|| Ok(())).unwrap();
        assert_eq!(
            pending_active_replacement_retirement(&db).unwrap().as_ref(),
            Some(&peers[0].owner)
        );
        k.call("ip", &["link", "set", SOURCE, "down"]).unwrap();
        finish_active_replacement_retirement(&db, &peers[0].owner).unwrap();
        assert!(inspect(&db, &router).unwrap().ready);
        assert!(observation(&db).unwrap().is_none());
        assert!(redirect_bridges(&db, false).unwrap().is_empty());
        let saved = nfqws2_awg_profile::read(&db).unwrap();
        assert_eq!(saved["servers"], after["servers"]);
        for (destination, prefix) in watched_scopes(multiple, live_dns) {
            assert_eq!(router.path(destination, prefix), (Some("wan0".into()), false));
        }
        assert!(!disabled_replacement_rearm_needs_dns(&db).unwrap());
        assert!(routed_profile_needs_rearm(&db, Some(TARGET)).unwrap());
        nfqws2_awg_profile::edit_document(&db, |doc| {
            let row = doc["servers"].as_array_mut().unwrap().iter_mut()
                .find(|row| row["id"] == TARGET).unwrap();
            row["config"]["enabled"] = json!(true);
            row["config"]["client"]["enabled"] = json!(true);
            Ok(())
        }).unwrap();
        start_target();
        let dormant = Journal::read(&db).unwrap();
        assert!(disabled_replacement_rearm_needs_dns(&db).unwrap());
        assert!(active_replacement_native_witness_needed(&db, TARGET_IFACE).unwrap());
        let current = nfqws2_awg_profile::read(&db).unwrap();
        let mut witness = peers[1].clone();
        witness.fingerprint = active_replacement_fingerprint(&current, TARGET).unwrap();
        let live_target = |cfg: &Value, iface: &str| {
            live(cfg, iface).map(|peer| peer.with_active_replacement_peer(Some(witness.clone())))
        };
        let names = [bridge.to_owned()];
        let learned = &old.committed.learned.as_ref().unwrap().members;
        let warm = state == ReplacementOuter::DisabledDnsClient;
        let clock = if warm { nfqws2_awg_profile::now() } else { learned[0].until };
        let refresh = |names, verify: bool| {
            operate_with_inputs_at(&db, &router, Operation::Refresh, clock, None, names,
                |cfg, iface| if verify { live_target(cfg, iface) } else { live(cfg, iface) })
        };
        assert!(refresh(None, true).is_err());
        assert!(refresh(Some(&names), false).is_err());
        assert_eq!(Journal::read(&db).unwrap(), dormant);
        refresh(Some(&names), true).unwrap();
        assert_eq!(redirect_bridges(&db, false).unwrap(), names);
        assert!(observation(&db).unwrap().unwrap().ready);
        assert!(!disabled_replacement_rearm_needs_dns(&db).unwrap());
        assert!(!routed_profile_needs_rearm(&db, Some(TARGET)).unwrap());
        let restored = Journal::read(&db).unwrap();
        assert_eq!(restored.committed.revision, dormant.committed.revision);
        assert_eq!(restored.committed.killswitch, saved_kill_switch);
        assert_eq!(restored.committed.learned.as_ref().unwrap().members,
            if warm { &learned[..] } else { &[] });
        if warm {
            check_paths(TARGET_IFACE);
        } else {
            assert_eq!(router.path(DESTINATION, SCOPE), (Some(TARGET_IFACE.into()), saved_kill_switch));
            for (destination, prefix) in watched_scopes(multiple, live_dns).skip(1) {
                assert_eq!(router.path(destination, prefix), (Some("wan0".into()), false));
            }
        }
        operate_at(&db, &router, Operation::Teardown, now, live).unwrap();
        k.call("ip", &["link", "del", TARGET_IFACE]).unwrap();
        k.call("ip", &["link", "set", SOURCE, "up"]).unwrap();
        k.call("ip", &["link", "del", DNS_BRIDGE]).unwrap();
        return;
    }
    if live_dns {
        assert!(db
            .transaction(|tx| replace_active_profile(
                &db,
                tx,
                &router,
                &before,
                &after,
                &peers,
                &["wan0".into()]
            ))
            .is_err());
        assert_eq!(router.audited.load(Relaxed), 0);
    }
    if lose_plain {
        // Native inner transport remains live. Loss of the independently
        // direct outer is a different failure and may never authorize writes.
        const NEW_OUTER_IP: &str = "198.51.100.13";
        assert_eq!(route_device(&k, NEW_OUTER_IP).as_deref(), Some("wan0"));
        block_plain("add", NEW_OUTER_IP);
        assert!(replace().is_err());
        assert_eq!(router.audited.load(Relaxed), 0);
        block_plain("del", NEW_OUTER_IP);
        let mut unproved = peers.clone();
        unproved[1].nested_only = false;
        assert!(replace_with(&unproved).is_err());
        assert_eq!(router.audited.load(Relaxed), 0);
    }
    if nested {
        check_nested(SOURCE, INNER_IP, OUTER_ADDR);
        nested_route("replace", SOURCE, INNER_ROUTE, "10.32.0.3");
        check_nested(SOURCE, INNER_IP, "10.32.0.3");
        assert!(replace().is_err());
        assert_eq!(router.audited.load(Relaxed), 0);
        assert_eq!(Journal::read(&db).unwrap(), old);
        nested_route("replace", SOURCE, INNER_ROUTE, OUTER_ADDR);
    }
    if nested_target {
        let mut wrong = peers.clone();
        if distinct {
            wrong[1].underlay = peers[0].underlay.clone();
        } else if nested {
            wrong[1].underlay.as_mut().unwrap().owner.started += 1;
        } else {
            wrong[1].underlay.as_mut().unwrap().owner.iface = "awg33".into();
        }
        assert!(replace_with(&wrong).is_err());
        check_nested(TARGET_IFACE, TARGET_INNER_IP, outer_for(TARGET_IFACE).3);
        let wrong_source = if distinct { "10.33.0.3" } else { "10.32.0.3" };
        nested_route("replace", TARGET_IFACE, TARGET_INNER_ROUTE, wrong_source);
        assert!(replace().is_err());
        assert_eq!(router.audited.load(Relaxed), 0);
        assert_eq!(Journal::read(&db).unwrap(), old);
        nested_route(
            "replace",
            TARGET_IFACE,
            TARGET_INNER_ROUTE,
            outer_for(TARGET_IFACE).3,
        );
    }
    if !saved_kill_switch && (!permanent || reverse) {
        let source = source_scope.unwrap_or("all");
        let foreign = |verb| {
            k.call(
                "ip",
                &[
                    "-4",
                    "rule",
                    verb,
                    "pref",
                    "69",
                    "from",
                    source,
                    "to",
                    SCOPE,
                    "blackhole",
                ],
            )
            .unwrap();
        };
        foreign("add");
        assert!(replace().is_err());
        assert_eq!(router.audited.load(Relaxed), 0);
        assert!(has_stop(&k, SCOPE, source_scope));
        assert_eq!(Journal::read(&db).unwrap(), old);
        foreign("del");
    }
    let before_failure = router.audited.load(Relaxed);
    assert!(replace().is_err());
    if initially_unresolved || warm_aaaa {
        assert!(router.fail_write.load(Relaxed));
        assert_eq!(router.audited.load(Relaxed), before_failure);
    } else {
        assert!(!router.fail_write.load(Relaxed));
        assert!(router.audited.load(Relaxed) > before_failure);
    }
    check_paths(SOURCE);
    if nested {
        check_nested(SOURCE, INNER_IP, OUTER_ADDR);
    }
    if nested_target {
        check_nested(TARGET_IFACE, TARGET_INNER_IP, outer_for(TARGET_IFACE).3);
    }
    assert_eq!(Journal::read(&db).unwrap(), old);
    assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), before);
    assert!(pending_active_replacement_retirement(&db)
        .unwrap()
        .is_none());
    if let Some(fw) = &router.marked {
        fw.fail_switch.store(true, Relaxed);
        assert!(replace().is_err());
        assert!(!fw.fail_switch.load(Relaxed));
        assert_eq!(Journal::read(&db).unwrap(), old);
        assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), before);
        check_paths(SOURCE);
    }

    // Start the next attempt with a vacant standby. The FIB remains real;
    // the authenticated process witnesses are supplied by the fixture.
    if !nested_target && !reverse && !hot_only {
        k.call("ip", &["link", "del", TARGET_IFACE]).unwrap();
    }
    let prepare = |provisional: Option<&ActiveReplacementPeer>| {
        let stage = ActiveReplacementStage {
            before: &before, after: &after, source: &peers[0],
            held: None, target: TARGET, provisional,
        };
        if cold_named {
            return prepare_named_active_replacement_launch(
                &db, &router, stage, &["wan0".into()], names.as_ref().unwrap(),
            ).map(|pin| assert_eq!(pin.endpoint, peers[1].endpoint));
        }
        prepare_active_replacement_launch(
            &db, &router, stage, &["wan0".into()], renewed_dns.as_ref(),
        )
        .map(|_| ())
    };
    if configured_outer || hot_only || initially_unresolved {
        assert!(prepare(None).is_err());
    } else {
        if cold_named {
            let overlap = NamedActiveReplacement::prepare(&db, &before, SOURCE, TARGET, |_, _, _| {
                Ok(vec![peers[1].endpoint, "203.0.113.50:443".parse().unwrap()])
            }).unwrap().unwrap();
            assert!(prepare_named_active_replacement_launch(
                &db, &router,
                ActiveReplacementStage {
                    before: &before, after: &after, source: &peers[0], held: None,
                    target: TARGET, provisional: None,
                },
                &["wan0".into()], &overlap,
            ).is_err());
            assert!(!active_replacement_in_progress(&db).unwrap());
            assert_eq!(Journal::read(&db).unwrap(), old);
        }
        prepare(None).unwrap();
    }
    assert!(active_replacement_launch_cleanup(&db).unwrap().is_none());
    check_paths(SOURCE);
    if unavailable_target {
        router.audit.store(false, Relaxed);
        let stage = || ActiveReplacementStage {
            before: &before, after: &after, source: &peers[0],
            held: None, target: TARGET, provisional: None,
        };
        let wan = ["wan0".into()];
        let warning = if let Some(names) = &names {
            // A present but unverified interface must forbid even the
            // deferred writer. The original guarded/unguarded FIB survives.
            start_target();
            assert!(defer_named_active_replacement_launch(
                &db, &router, stage(), &wan, names, &|| Ok(())
            ).is_err());
            assert_eq!(Journal::read(&db).unwrap(), old);
            assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), before);
            check_paths(SOURCE);
            k.call("ip", &["link", "del", TARGET_IFACE]).unwrap();
            if aaaa_only {
                let prohibit = |verb| {
                    k.call("ip", &["-6", "route", verb, "prohibit", UNSELECTED_IPV6]).unwrap();
                };
                prohibit("add");
                assert!(defer_named_active_replacement_launch(
                    &db, &router, stage(), &wan, names, &|| Ok(())
                ).is_err());
                assert_eq!(Journal::read(&db).unwrap(), old);
                assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), before);
                check_paths(SOURCE);
                prohibit("del");
            }
            defer_named_active_replacement_launch(
                &db, &router, stage(), &wan, names, &|| Ok(())
            )
        } else {
            defer_active_replacement_launch(
                &db, &router, stage(), &wan, &|| Ok(())
            )
        }.unwrap().unwrap();
        assert!(warning.contains(if initially_unresolved {
            "не удалось разрешить IPv4-адрес сервера"
        } else {
            "выбранное подключение пока не запустилось"
        }));
        let saved = nfqws2_awg_profile::read(&db).unwrap();
        assert_eq!(saved["routing_revision"], after["routing_revision"]);
        assert_eq!(saved["servers"], after["servers"]);
        if aaaa_only {
            let runtime: Value = db.read_runtime("awg-active-replacement.json", 64 << 10).unwrap();
            let named = &runtime["temporary_stop"]["named"];
            assert_eq!(named["claims"][1]["answers"], json!([UNSELECTED_IPV6_SOCKET]));
            assert_eq!(named["claims"][1]["unresolved"], true);
            assert_eq!(named["selected"].as_array().unwrap().len(), 2);
            assert!(named["selected"][1].is_null());
        }
        assert!(active_replacement_native_witness_needed(&db, TARGET_IFACE).unwrap());
        assert_eq!(
            pending_active_replacement_retirement(&db).unwrap().as_ref(),
            Some(&peers[0].owner)
        );
        assert!(finish_active_replacement_retirement(&db, &peers[1].owner).is_err());
        k.call("ip", &["link", "del", SOURCE]).unwrap();
        finish_active_replacement_retirement(&db, &peers[0].owner).unwrap();
        assert!(pending_active_replacement_retirement(&db).unwrap().is_none());
        assert!(active_replacement_in_progress(&db).unwrap());
        let pending_path = || {
            for (destination, prefix) in watched_scopes(multiple, live_dns) {
                let (dev, fenced) = router.path(destination, prefix);
                assert_eq!(dev.as_deref(), (!saved_kill_switch).then_some("wan0"));
                assert_eq!(fenced, saved_kill_switch);
            }
        };
        pending_path();
        operate_at(&db, &router, Operation::Recover, now, |_, _| {
            Err(io::ErrorKind::NotConnected.into())
        })
        .unwrap();
        pending_path();
        start_target();
        operate_at(&db, &router, Operation::Recover, now, live).unwrap();
        pending_path();
        if aaaa_only {
            let mut ipv6 = peers[1].clone();
            ipv6.endpoint = UNSELECTED_IPV6_SOCKET.parse().unwrap();
            operate_at(&db, &router, Operation::Recover, now, |cfg, iface| {
                let mut sample = live(cfg, iface)?;
                sample.endpoint = ipv6.endpoint;
                Ok(sample.with_active_replacement_peer(Some(ipv6.clone())))
            }).unwrap();
            pending_path();
        }
        let mut wrong = peers[1].clone();
        wrong.fingerprint = [1; 32];
        operate_at(&db, &router, Operation::Recover, now, |cfg, iface| {
            live(cfg, iface).map(|peer| peer.with_active_replacement_peer(Some(wrong.clone())))
        })
        .unwrap();
        pending_path();
        if cold_named {
            let mut wrong_socket = peers[1].clone();
            wrong_socket.endpoint.set_port(2443);
            operate_at(&db, &router, Operation::Recover, now, |cfg, iface| {
                let mut current = live(cfg, iface)?;
                current.endpoint = wrong_socket.endpoint;
                Ok(current.with_active_replacement_peer(Some(wrong_socket.clone())))
            }).unwrap();
            pending_path();
        }
        if state == ReplacementOuter::RotatedNamedTarget || initially_unresolved {
            const RAW: &str = "r111-target.test:443";
            const ROTATED_IP: &str = "198.51.100.12";
            let mut rotated = peers[1].clone();
            rotated.endpoint.set_ip(ROTATED_IP.parse().unwrap());
            let refreshed = |cfg: &Value, iface: &str| {
                let mut sample = live(cfg, iface)?;
                sample.endpoint = rotated.endpoint;
                Ok(sample.with_active_replacement_peer(Some(rotated.clone())))
            };
            let baseline = Journal::read(&db).unwrap();
            let saved = nfqws2_awg_profile::read(&db).unwrap();
            let previous = std::fs::read_to_string("/etc/hosts").unwrap();
            let changed = previous.replace("198.51.100.11 r111-target.test", "198.51.100.12 r111-target.test");
            assert_ne!(previous, changed);
            let revision = baseline.committed.revision;
            assert_eq!(
                named_reconnect_revision(&db, TARGET, TARGET_IFACE, RAW).unwrap(),
                Some(revision)
            );
            let lookup = |addresses| nfqws2_awg_profile::NamedReconnectTarget {
                id: TARGET, iface: TARGET_IFACE, raw: RAW, revision,
                selected: rotated.endpoint, addresses,
            };
            let sockets = [rotated.endpoint];
            validate_named_reconnect(&db, &router, lookup(&sockets), &wan).unwrap();
            let captured = [rotated.endpoint, "203.0.113.50:443".parse().unwrap()];
            assert!(validate_named_reconnect(&db, &router, lookup(&captured), &wan).is_err());
            assert!(prepare_deferred_named_rotation(&db, refreshed).unwrap().is_none());
            operate_at(&db, &router, Operation::Recover, now, refreshed).unwrap();
            pending_path();
            std::fs::write("/etc/hosts", format!("{changed}203.0.113.50 r111-target.test\n")).unwrap();
            let colliding = prepare_deferred_named_rotation(&db, refreshed).unwrap().unwrap();
            assert!(resume_deferred_named_rotation(&db, &router, &colliding, &wan, refreshed).is_err());
            pending_path();
            std::fs::write("/etc/hosts", &changed).unwrap();
            let proof = prepare_deferred_named_rotation(&db, refreshed).unwrap().unwrap();
            block_plain("add", ROTATED_IP);
            assert!(validate_named_reconnect(&db, &router, lookup(&sockets), &wan).is_err());
            assert!(resume_deferred_named_rotation(&db, &router, &proof, &wan, refreshed).is_err());
            pending_path();
            block_plain("del", ROTATED_IP);
            let foreign = |cfg: &Value, iface: &str| {
                let mut sample = refreshed(cfg, iface)?;
                let mut owner = rotated.clone();
                owner.owner.pid += 1;
                sample = sample.with_active_replacement_peer(Some(owner));
                Ok(sample)
            };
            assert!(resume_deferred_named_rotation(&db, &router, &proof, &wan, foreign).is_err());
            pending_path();
            assert_eq!(Journal::read(&db).unwrap(), baseline);
            assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), saved);
            resume_deferred_named_rotation(&db, &router, &proof, &wan, refreshed).unwrap();
            operate_at(&db, &router, Operation::Recover, now, refreshed).unwrap();
            assert_eq!(
                nfqws2_awg_profile::read(&db).unwrap()["servers"][0]["config"]["endpoint"],
                RAW
            );
            std::fs::write("/etc/hosts", previous).unwrap();
        } else {
            let authenticated = |cfg: &Value, iface: &str| {
                live(cfg, iface).map(|peer| peer.with_active_replacement_peer(Some(peers[1].clone())))
            };
            for _ in 0..2 {
                operate_at(&db, &router, Operation::Recover, now, authenticated).unwrap();
            }
        }
        check_paths(TARGET_IFACE);
        assert!(!active_replacement_in_progress(&db).unwrap());
        assert!(inspect(&db, &router).unwrap().ready);
        if cold_dns {
            assert!(observation(&db).unwrap().unwrap().ready);
            assert_eq!(redirect_bridges(&db, false).unwrap(), [bridge]);
        }
        operate_at(&db, &router, Operation::Teardown, now, live).unwrap();
        if cold_dns {
            k.call("ip", &["link", "del", DNS_BRIDGE]).unwrap();
        }
        k.call("ip", &["link", "del", TARGET_IFACE]).unwrap();
        k.call("ip", &["link", "add", SOURCE, "type", "dummy"]).unwrap();
        k.call("ip", &["link", "set", SOURCE, "up"]).unwrap();
        if source_qualified {
            k.call("ip", &["link", "del", LAN]).unwrap();
        }
        return;
    }
    if !nested_target && !reverse && !hot_only {
        start_target();
    }
    if !configured_outer && !hot_only {
        if cold_named {
            let mut unpinned = peers[1].clone();
            unpinned.endpoint.set_port(2443);
            assert!(prepare(Some(&unpinned)).is_err());
            assert!(!active_replacement_in_progress(&db).unwrap());
            check_paths(SOURCE);
        }
        prepare(Some(&peers[1])).unwrap();
        let provisional = active_replacement_launch_cleanup(&db).unwrap().unwrap();
        assert_eq!(provisional.target, peers[1].owner);
        assert!(provisional.stop);
    }
    check_paths(SOURCE);
    if warm_aaaa {
        let error = replace().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert!(!router.fail_write.load(Relaxed));
        assert_eq!(Journal::read(&db).unwrap(), old);
        assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), before);
        assert!(active_replacement_launch_cleanup(&db).unwrap().unwrap().stop);
        check_paths(SOURCE);
    }
    if (live_dns || named) && !saved_kill_switch {
        router.fail_release.store(true, Relaxed);
    }
    let before_commit = router.audited.load(Relaxed);
    let warning = replace().unwrap();
    if named && !saved_kill_switch {
        assert!(warning.is_some());
        assert!(!router.fail_release.load(Relaxed));
        assert!(active_replacement_native_witness_needed(&db, TARGET_IFACE).unwrap());
        assert_eq!(router.path(DESTINATION, SCOPE), (Some(TARGET_IFACE.into()), true));
        assert!(pending_active_replacement_retirement(&db).unwrap().is_none());
        let mut wrong = peers[1].clone();
        wrong.endpoint.set_port(2443);
        let incorrect = |cfg: &Value, iface: &str| {
            live(cfg, iface).map(|peer| peer.with_active_replacement_peer(Some(wrong.clone())))
        };
        operate_at(&db, &router, Operation::Recover, now, incorrect).unwrap();
        assert_eq!(router.path(DESTINATION, SCOPE), (None, true));
        assert!(pending_active_replacement_retirement(&db).unwrap().is_none());
        let authenticated = |cfg: &Value, iface: &str| {
            live(cfg, iface).map(|peer| peer.with_active_replacement_peer(Some(peers[1].clone())))
        };
        if warm_aaaa {
            k.call("ip", &["-6", "route", "add", "prohibit", UNSELECTED_IPV6]).unwrap();
        } else {
            block_plain("add", TARGET_INNER_IP);
        }
        operate_at(&db, &router, Operation::Recover, now, authenticated).unwrap();
        assert_eq!(router.path(DESTINATION, SCOPE), (None, true));
        if warm_aaaa {
            k.call("ip", &["-6", "route", "del", "prohibit", UNSELECTED_IPV6]).unwrap();
        } else {
            block_plain("del", TARGET_INNER_IP);
        }
        operate_at(&db, &router, Operation::Recover, now, authenticated).unwrap();
        operate_at(&db, &router, Operation::Recover, now, authenticated).unwrap();
        assert!(!active_replacement_native_witness_needed(&db, TARGET_IFACE).unwrap());
    }
    if live_dns && !saved_kill_switch {
        assert!(warning.is_some());
        assert!(!router.fail_release.load(Relaxed));
        let pending = observation(&db).unwrap().unwrap();
        assert!(!pending.ready);
        let learn = learn_archived_answer(
            &db,
            &router,
            ArchiveAnswer {
                revision: pending.revision,
                name: DNS_DOMAIN,
                addresses: &["198.18.4.41".parse().unwrap()],
                ttl: 60,
                qtype: 1,
            },
            live,
            || Ok(()),
        );
        assert_eq!(learn.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        for (destination, prefix) in watched_scopes(multiple, live_dns) {
            assert_eq!(
                router.path(destination, prefix),
                (Some(TARGET_IFACE.into()), true)
            );
        }
        operate_with_redirect(
            &db,
            &router,
            Operation::Recover,
            None,
            Some(&[bridge.into()]),
            live,
        )
        .unwrap();
    }
    assert!(router.audited.load(Relaxed) > before_commit);
    check_paths(TARGET_IFACE);
    let committed = Journal::read(&db).unwrap();
    assert_eq!(committed.committed.revision, old.committed.revision + 1);
    assert_eq!(committed.expires, 0);
    assert!(inspect(&db, &router).unwrap().ready);
    if client_dns {
        let prior = &old.committed.learned.as_ref().unwrap().members;
        let current = &committed.committed.learned.as_ref().unwrap().members;
        assert_eq!(current.len(), prior.len());
        assert!(prior.iter().zip(current).all(|(prior, next)| {
            prior.ip == next.ip && prior.zone == next.zone && next.until < prior.until
        }));
    }
    if reverse && !saved_kill_switch {
        assert!(committed.installed.marks.is_empty());
        assert!(committed.installed.permanent_fences.is_empty());
    } else if permanent {
        assert_ne!(
            old.installed.marks[SOURCE],
            committed.installed.marks[TARGET_IFACE]
        );
        assert_eq!(
            committed.installed.permanent_fences.contains(TARGET_IFACE),
            !reverse
        );
    }
    if configured_outer || hot_only {
        assert!(active_replacement_launch_cleanup(&db).unwrap().is_none());
    } else {
        assert!(pending_active_replacement_retirement(&db)
            .unwrap()
            .is_none());
        let adopted = active_replacement_launch_cleanup(&db).unwrap().unwrap();
        assert_eq!(adopted.target, peers[1].owner);
        assert!(!adopted.stop);
        finish_active_replacement_launch_cleanup(&db, &adopted).unwrap();
    }
    assert_eq!(
        pending_active_replacement_retirement(&db).unwrap().as_ref(),
        Some(&peers[0].owner)
    );
    let saved = nfqws2_awg_profile::read(&db).unwrap();
    let retained = saved[ACTIVE_REPLACEMENT_FIELD].get("retained_outer");
    if standby_outer {
        assert_eq!(
            retained,
            Some(&json!(peers[0].underlay.as_ref().unwrap().owner))
        );
    } else {
        assert!(retained.is_none());
    }
    assert_eq!(saved["routing"]["killswitch"], saved_kill_switch);
    assert_eq!(
        saved["servers"].as_array().unwrap().len(),
        1 + usize::from(configured_outer) + usize::from(distinct)
    );
    assert_eq!(saved["servers"][0]["id"], TARGET);
    assert_eq!(saved["servers"][0]["config"]["client"]["standby"], false);
    if configured_outer {
        assert_eq!(
            saved["servers"][0]["config"]["client"]["double_tunnel_id"],
            if nested && !nested_target {
                ""
            } else {
                outer_for(TARGET_IFACE).0
            }
        );
        assert_eq!(saved["servers"][1], before["servers"][2]);
        if distinct {
            assert_eq!(saved["servers"][2], before["servers"][3]);
        }
    }

    if nested {
        // The payload cutover has succeeded. The sealed departing process
        // still owns this transport until the native cleanup proves vacancy.
        check_nested(SOURCE, INNER_IP, OUTER_ADDR);
        nested_rules("del", SOURCE);
        nested_route("del", SOURCE, INNER_ROUTE, OUTER_ADDR);
        let (mark, _) = selector(SOURCE);
        let after = k.call("ip", &["-4", "route", "get", INNER_IP, "mark", &mark]);
        if lose_plain {
            assert!(after.is_err());
        } else {
            assert!(after.unwrap().contains("dev wan0"));
        }
    }
    finish_active_replacement_retirement(&db, &peers[0].owner).unwrap();
    if warm_aaaa {
        router.audit.store(false, Relaxed);
        let wan = ["wan0".to_owned()];
        assert!(established_warm_client(&db, Some(TARGET)).unwrap());
        assert_eq!(
            established_warm_owner(&db, TARGET_IFACE, peers[1].endpoint, &wan).unwrap(),
            Some(peers[1].owner.clone()),
        );
        assert!(established_warm_owner(&db, TARGET_IFACE, peers[1].endpoint, &["lan0".into()])
            .unwrap().is_none());
        let hosts = std::fs::read_to_string("/etc/hosts").unwrap();
        let hidden = hosts.lines().filter(|line| !line.contains("r111-target.test"))
            .map(|line| format!("{line}\n")).collect::<String>();
        std::fs::write("/etc/hosts", hidden).unwrap();
        let authenticated = |cfg: &Value, iface: &str| {
            live(cfg, iface).map(|sample| sample.with_active_replacement_peer(Some(peers[1].clone())))
        };
        operate_at(&db, &router, Operation::Refresh, now, authenticated).unwrap();
        assert_eq!(Journal::read(&db).unwrap(), committed);
        check_paths(TARGET_IFACE);
        let attachment_file = "awg-established-warm-name.json";
        let valid: Value = db.read_runtime(attachment_file, 4096).unwrap();
        db.transaction(|tx| tx.save_runtime_bounded(attachment_file, &json!([]), 4096)).unwrap();
        assert!(!established_warm_client(&db, None).unwrap());
        assert_eq!(Journal::read(&db).unwrap(), committed);
        check_paths(TARGET_IFACE);
        db.transaction(|tx| tx.save_runtime_bounded(attachment_file, &valid, 4096)).unwrap();
        k.call("ip", &["-4", "route", "del", SCOPE, "table", "17842", "dev", TARGET_IFACE]).unwrap();
        let guarded = || {
            let path = router.path(DESTINATION, SCOPE);
            assert_ne!(path.0.as_deref(), Some(TARGET_IFACE));
            assert_eq!(path.1, saved_kill_switch);
        };
        let saved = nfqws2_awg_profile::read(&db).unwrap();
        for changed in 0..3 {
            let mut wrong = peers[1].clone();
            match changed {
                0 => wrong.fingerprint[0] ^= 1,
                1 => wrong.owner.started += 1,
                _ => wrong.endpoint.set_port(wrong.endpoint.port() + 1),
            }
            let mismatched = |cfg: &Value, iface: &str| {
                live(cfg, iface).map(|sample| sample.with_active_replacement_peer(Some(wrong.clone())))
            };
            let accepted = db.transaction(|tx| crate::kernel::active_replacement::reassert_established_name(
                &db, tx, (&router, &kernel(&router)), &saved, &committed, mismatched,
            )).unwrap();
            assert!(!accepted);
            assert_eq!(Journal::read(&db).unwrap(), committed);
            guarded();
        }
        k.call("ip", &["-6", "route", "add", "prohibit", UNSELECTED_IPV6]).unwrap();
        assert!(operate_at(&db, &router, Operation::Refresh, now, authenticated).is_err());
        assert_eq!(Journal::read(&db).unwrap(), committed);
        guarded();
        k.call("ip", &["-6", "route", "del", "prohibit", UNSELECTED_IPV6]).unwrap();
        operate_at(&db, &router, Operation::Recover, now, authenticated).unwrap();
        assert_eq!(Journal::read(&db).unwrap(), committed);
        check_paths(TARGET_IFACE);
        std::fs::write("/etc/hosts", hosts).unwrap();
    }
    if named {
        let raw = nfqws2_awg_profile::read(&db).unwrap();
        assert_eq!(raw["servers"][0]["config"]["endpoint"],
                   if named_target { "r111-target.test:443" } else { NEW_ENDPOINT });
        for ip in [INNER_IP, TARGET_INNER_IP] {
            assert_eq!(route_device(&k, ip).as_deref(), Some("wan0"));
            assert!(k.call("ip", &["-4", "route", "get", ip, "mark", "0x20000000"])
                    .unwrap().contains("dev wan0 "));
        }
        router.audit.store(false, Relaxed);
        k.call("ip", &["link", "del", TARGET_IFACE]).unwrap();
        let outage = operate_at(&db, &router, Operation::Refresh, now, |_, _| {
            Err(io::ErrorKind::NotConnected.into())
        });
        if saved_kill_switch {
            outage.unwrap();
        } else {
            assert_eq!(outage.unwrap_err().kind(), io::ErrorKind::InvalidInput);
            assert!(!Journal::read(&db).unwrap().committed.empty());
        }
        assert_eq!(router.path(DESTINATION, SCOPE),
            ((!saved_kill_switch).then(|| "wan0".to_owned()), saved_kill_switch));
        start_target();
        operate_at(&db, &router, Operation::Refresh, now, live).unwrap();
        check_paths(TARGET_IFACE);
    }
    if observed_dns {
        let observe = observation(&db).unwrap().unwrap();
        assert!(observe.ready);
        assert_eq!(observe.revision, old.installed.revision + 1);
        let client = client_dns.then(|| INSIDE.parse().unwrap());
        assert_eq!(observe.policy.matched(DNS_DOMAIN, client), Some(0));
        assert_eq!(redirect_bridges(&db, false).unwrap(), [bridge]);
        let dns_path = || {
            if client_dns {
                source_route_device(&k, DNS_DESTINATION, INSIDE)
            } else {
                route_device(&k, DNS_DESTINATION)
            }
        };
        assert_eq!(
            dns_path().as_deref(),
            Some(if live_dns { TARGET_IFACE } else { "wan0" })
        );
        let replay = |revision| {
            learn_archived_answer(
                &db,
                &router,
                ArchiveAnswer {
                    revision,
                    name: DNS_DOMAIN,
                    addresses: &[DNS_DESTINATION.parse().unwrap()],
                    ttl: 60,
                    qtype: 1,
                },
                live,
                || Ok(()),
            )
        };
        assert!(replay(old.installed.revision).is_err());
        router.audit.store(false, Relaxed);
        if !live_dns {
            replay(observe.revision).unwrap();
        }
        assert_eq!(dns_path().as_deref(), Some(TARGET_IFACE));
        assert_eq!(redirect_bridges(&db, false).unwrap(), [bridge]);
        assert!(active_replacement_dns_redirects(&db, TARGET).is_err());
    }
    if nested_target {
        check_nested(TARGET_IFACE, TARGET_INNER_IP, outer_for(TARGET_IFACE).3);
        assert!(inspect(&db, &router).unwrap().ready);
    }
    assert!(nfqws2_awg_profile::read(&db)
        .unwrap()
        .get(ACTIVE_REPLACEMENT_FIELD)
        .is_none());
    router.audit.store(false, Relaxed);
    operate_at(&db, &router, Operation::Teardown, now, live).unwrap();
    for (destination, prefix) in watched_scopes(multiple, live_dns) {
        assert_eq!(route_device(&k, destination).as_deref(), Some("wan0"));
        assert!(!has_stop(&k, prefix, source_scope));
        if source_scope.is_some() {
            assert_eq!(
                source_route_device(&k, destination, INSIDE).as_deref(),
                Some("wan0")
            );
        }
    }
    if nested_target {
        check_nested(TARGET_IFACE, TARGET_INNER_IP, outer_for(TARGET_IFACE).3);
        nested_rules("del", TARGET_IFACE);
        nested_route(
            "del",
            TARGET_IFACE,
            TARGET_INNER_ROUTE,
            outer_for(TARGET_IFACE).3,
        );
    }
    k.call("ip", &["link", "del", TARGET_IFACE]).unwrap();
    if has_nested_path {
        k.call("ip", &["link", "del", OUTER_IFACE]).unwrap();
    }
    if distinct {
        k.call("ip", &["link", "del", TARGET_OUTER_IFACE]).unwrap();
    }
    if lose_plain {
        for inner in [INNER_IP, TARGET_INNER_IP] {
            block_plain("del", inner);
        }
    }
    if nested {
        set_physical_mtu(&k, 1420);
    }
    if source_scope.is_some() {
        k.call("ip", &["link", "del", LAN]).unwrap();
    }
    if observed_dns && !client_dns {
        k.call("ip", &["link", "del", DNS_BRIDGE]).unwrap();
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn rotated_static_dns_snapshot_retries_only_after_actual_fib_rollback() {
    require_isolated_namespaces();
    for initial in [false, true] {
        static_dns_snapshot_after_fib_failure(initial);
    }
}

fn static_dns_snapshot_after_fib_failure(initial: bool) {
    use std::sync::atomic::{AtomicBool, Ordering};

    const NAME: &str = "office.example.test";
    const BEFORE: &str = "203.0.113.50";
    const AFTER: &str = "203.0.113.51";
    const AFTER_ROUTE: &str = "203.0.113.51/32";

    struct FailAfterRoute(AtomicBool);
    impl Runner for FailAfterRoute {
        fn run(&self, program: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
            let output = nfqws2_router_command::System.run(program, args, deadline)?;
            if program == "ip"
                && matches!(args, ["-4", "route", "add", "table", _, AFTER_ROUTE, ..])
                && self.0.swap(false, Ordering::Relaxed)
            {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "имитация сбоя после записи маршрута",
                ));
            }
            Ok(output)
        }

        fn run_input(
            &self,
            program: &str,
            args: &[&str],
            input: &[u8],
            deadline: Instant,
        ) -> io::Result<String> {
            nfqws2_router_command::System.run_input(program, args, input, deadline)
        }
    }

    let router = FailAfterRoute(AtomicBool::new(false));
    let k = kernel(&router);
    let (_dir, db, _) = setup();
    protect(&db);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"]["domain_source"] = json!("resolve");
        doc["servers"][0]["config"]["routing"]["zones"] = json!([
            {"enabled": true, "route": "tunnel", "domains": [NAME], "include_subdomains": false}
        ]);
        Ok(())
    })
    .unwrap();
    let request = dns_request(&db, Operation::Apply).unwrap().unwrap();
    let snapshot = |address: &str| DnsSnapshot {
        request: request.clone(),
        answers: [(NAME.to_owned(), vec![address.parse().unwrap()])].into(),
    };
    let original = snapshot(BEFORE);
    let proposal = snapshot(AFTER);
    let now = nfqws2_awg_profile::now();
    if !initial {
        operate_with_dns_at(&db, &router, Operation::Apply, now, Some(&original), peer).unwrap();
        operate_at(&db, &router, Operation::Commit, now, peer).unwrap();
    }
    let baseline = Journal::read(&db).unwrap();
    let confirmed = confirmed_static_dns_retry(&db, &request).unwrap();
    let foreign = |operation| {
        k.call(
            "ip",
            &[
                "-6",
                "route",
                operation,
                "unreachable",
                "2001:db8:72::/64",
                "table",
                "17842",
            ],
        )
        .unwrap();
    };
    if initial {
        assert_eq!(baseline, Journal::default());
        assert!(confirmed.is_none());
        // An IPv4-only draft cannot adopt a foreign route from the IPv6 table.
        foreign("add");
        assert!(cold_static_dns_draft(&db, &router, &request).is_err());
        foreign("del");
    }
    let cold = cold_static_dns_draft(&db, &router, &request).unwrap();
    let fresh = || match (&confirmed, &cold) {
        (Some(ticket), None) if !initial => ManagedStaticDnsApply::Fresh(ticket, &proposal),
        (None, Some(draft)) if initial => ManagedStaticDnsApply::Cold(draft, &proposal),
        _ => panic!("неожиданное состояние до применения"),
    };
    let path = |ip| route_device(&k, ip);
    let original_kernel = || {
        ["-4", "-6"].map(|family| {
            (
                k.call("ip", &[family, "rule", "show"]).unwrap(),
                k.call("ip", &[family, "route", "show", "table", "all"])
                    .unwrap(),
            )
        })
    };
    let saved_kernel = original_kernel();
    let original_routes = |expected: &Journal| {
        assert_eq!(
            path(BEFORE).as_deref(),
            Some(if initial { "wan0" } else { "awg0" })
        );
        assert_eq!(path(AFTER).as_deref(), Some("wan0"));
        assert_eq!(original_kernel(), saved_kernel);
        assert_eq!(&Journal::read(&db).unwrap(), expected);
    };
    original_routes(&baseline);
    let apply = |input: ManagedStaticDnsApply<'_>, verify: fn() -> io::Result<()>| {
        apply_managed_static_dns_proposal(&db, &router, input, peer, verify)
    };
    let expired = apply(fresh(), || Err(io::ErrorKind::TimedOut.into())).unwrap_err();
    assert!(failed_static_dns_apply(&expired).is_none());
    original_routes(&baseline);
    router.0.store(true, Ordering::Relaxed);
    let write_error = apply(fresh(), || Ok(())).unwrap_err();
    assert!(!router.0.load(Ordering::Relaxed));
    assert_eq!(write_error.kind(), io::ErrorKind::BrokenPipe);
    let proof = failed_static_dns_apply(&write_error).unwrap();
    assert_eq!(proof.snapshot(), &proposal);
    assert_eq!(
        proof.baseline().map(|ticket| ticket.snapshot()),
        confirmed.as_ref().map(|_| &original)
    );
    assert_eq!(proof.cold_draft(), cold.as_ref());
    let mut restored = baseline.clone();
    if initial {
        restored.boot = boot_id(&k).unwrap();
        foreign("add");
        let conflict = apply(ManagedStaticDnsApply::Retry(proof), || Ok(())).unwrap_err();
        assert!(failed_static_dns_apply(&conflict).is_none());
        let routes = k
            .call("ip", &["-6", "route", "show", "table", "17842"])
            .unwrap();
        assert!(routes.contains("unreachable 2001:db8:72::/64"));
        foreign("del");
    }
    original_routes(&restored);
    apply(ManagedStaticDnsApply::Retry(proof), || Ok(())).unwrap();
    assert_eq!(path(BEFORE).as_deref(), Some("wan0"));
    assert_eq!(path(AFTER).as_deref(), Some("awg0"));
    let trial = Journal::read(&db).unwrap();
    assert_ne!(trial.expires, 0);
    assert_eq!(trial.committed, baseline.committed);
    operate_at(&db, &router, Operation::Commit, now, peer).unwrap();
    let committed = confirmed_static_dns_retry(&db, &request).unwrap().unwrap();
    assert_eq!(committed.snapshot(), &proposal);
    operate_at(&db, &router, Operation::Teardown, now, peer).unwrap();
    assert_eq!(path(AFTER).as_deref(), Some("wan0"));
}

fn direct_cross_family_pair_with_independent_wan() {
    const OLD: &str = "192.0.2.10:443";
    const NEW: &str = "[2001:db8:68::1]:8443";
    const NEW_IP: &str = "2001:db8:68::1";
    const NEW_ROUTE: &str = "2001:db8:68::1/128";
    const NEW_WAN: &str = "wan6qa";
    const MARK: &str = "0x20000000";
    const PAYLOAD: &str = "203.0.113.50";
    const NEXT_MTU: u16 = 1340;
    let router = nfqws2_router_command::System;
    let k = kernel(&router);
    let wan = ["wan0".into(), NEW_WAN.into()];
    let old_mtu = physical_mtu(&k);
    k.call("ip", &["link", "add", NEW_WAN, "type", "dummy"])
        .unwrap();
    k.call("ip", &["link", "set", NEW_WAN, "up"]).unwrap();
    k.call(
        "ip",
        &[
            "-6",
            "addr",
            "add",
            "2001:db8:69::2/128",
            "dev",
            NEW_WAN,
            "nodad",
        ],
    )
    .unwrap();
    let new_path = |available| {
        let args = if available {
            vec![
                "-6",
                "route",
                "replace",
                NEW_ROUTE,
                "dev",
                NEW_WAN,
                "src",
                "2001:db8:69::2",
            ]
        } else {
            vec!["-6", "route", "replace", "prohibit", NEW_ROUTE]
        };
        k.call("ip", &args).unwrap();
    };
    let mark_conflict = |op| {
        k.call(
            "ip",
            &["-6", "route", op, NEW_ROUTE, "dev", "wan0", "table", "829"],
        )
        .unwrap();
        k.call(
            "ip",
            &[
                "-6", "rule", op, "pref", "58", "fwmark", MARK, "lookup", "829",
            ],
        )
        .unwrap();
    };
    new_path(true);
    let (_dir, db, _) = setup();
    protect(&db);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let cfg = &mut doc["servers"][0]["config"];
        cfg["install"] = json!("imported");
        cfg["endpoint"] = json!(OLD);
        cfg["mtu"] = json!(old_mtu);
        cfg["client"]["rust_managed"] = json!(true);
        Ok(())
    })
    .unwrap();
    let live = |address: &'static str| {
        move |cfg: &Value, iface: &str| {
            Ok(LivePeer {
                endpoint: address.parse().unwrap(),
                socket_mark: DIRECT_SOCKET_MARK,
                ..peer(cfg, iface)?
            })
        }
    };
    let now = nfqws2_awg_profile::now();
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &router, op, now, live(OLD)).unwrap();
    }
    let path = || route_device(&k, PAYLOAD);
    let confirmed = Journal::read(&db).unwrap().committed;
    let edit = RoutedMtuChange {
        id: confirmed.targets["awg0"].id.clone(),
        iface: "awg0".into(),
        revision: confirmed.revision,
        before: old_mtu,
        after: NEXT_MTU,
        legacy_mtu_before_recorded: false,
        nested_mtu_before_recorded: false,
        native_mtu_endpoint: None,
        implicit_before_mtu: None,
        nested_outer: None,
        nested_endpoint: None,
        legacy_predecessor: None,
        endpoint_edit: Some(RoutedEndpointEdit {
            before: OLD.into(),
            after: NEW.into(),
            previous_reserve: None,
            resolved_before: vec![],
            resolved_after: vec![],
        }),
    };
    let launch = || validate_endpoint_edit_launch(&db, &router, &edit, &wan);
    let stage = |address, mtu| {
        nfqws2_awg_profile::edit_document(&db, |doc| {
            let row = &mut doc["servers"][0];
            row["config"]["endpoint"] = json!(address);
            row["config"]["mtu"] = json!(mtu);
            row["rust_pending_routed_mtu"] = json!(edit);
            Ok(())
        })
        .unwrap();
    };
    let park = || prepare_mtu_edit_with_wan(&db, &router, &edit, &wan);
    let recover = |observed, owned: bool| {
        operate_with_redirect_and_mtu(
            &db,
            &router,
            Operation::Recover,
            None,
            None,
            live(observed),
            |change, live| {
                Ok(owned.then(|| RoutedMtuPeer {
                    iface: change.iface.clone(),
                    outer_id: String::new(),
                    outer_iface: String::new(),
                    endpoint: live.endpoint,
                    effective_mtu: physical_mtu(&k),
                    socket_mark: live.socket_mark,
                }))
            },
        )
    };
    let marked_path = || {
        k.call("ip", &["-6", "route", "get", NEW_IP, "mark", MARK])
            .unwrap()
    };
    assert!(marked_path().contains(NEW_WAN));
    mark_conflict("add");
    assert!(marked_path().contains("dev wan0"));
    assert!(launch().is_err());
    assert_eq!(path().as_deref(), Some("awg0"));
    mark_conflict("del");
    assert_eq!(launch().unwrap(), RoutedEndpointLaunch::Primary);
    stage(NEW, NEXT_MTU);
    new_path(false);
    assert!(park().is_err());
    assert_eq!(path().as_deref(), Some("awg0"));
    assert!(!pending_mtu_edit(&db).unwrap());
    new_path(true);
    park().unwrap();
    assert_eq!(path(), None);
    new_path(false);
    assert_eq!(launch().unwrap(), RoutedEndpointLaunch::Primary);
    stage(OLD, old_mtu);
    park().unwrap();
    recover(OLD, false).unwrap();
    assert_eq!(path(), None);
    recover(OLD, true).unwrap();
    assert_eq!(path().as_deref(), Some("awg0"));
    assert!(!pending_mtu_edit(&db).unwrap());
    new_path(true);
    assert_eq!(launch().unwrap(), RoutedEndpointLaunch::Primary);
    stage(NEW, NEXT_MTU);
    park().unwrap();
    recover(NEW, true).unwrap();
    assert_eq!(path(), None);
    set_physical_mtu(&k, NEXT_MTU);
    recover(OLD, true).unwrap();
    assert_eq!(path(), None);
    recover(NEW, true).unwrap();
    assert_eq!(path().as_deref(), Some("awg0"));
    assert!(!pending_mtu_edit(&db).unwrap());
    assert!(marked_path().contains("src 2001:db8:69::2"));
    operate_at(&db, &router, Operation::Teardown, now, live(NEW)).unwrap();
    assert_eq!(path().as_deref(), Some("wan0"));
    k.call("ip", &["link", "del", NEW_WAN]).unwrap();
    set_physical_mtu(&k, old_mtu);
}

fn combined_edit_with_real_routes(inherited: bool) {
    const OLD: &str = "192.0.2.10:443";
    const NEW: &str = "192.0.2.30:8443";
    const PAYLOAD: &str = "203.0.113.50";
    const NEXT_MTU: u16 = 1340;
    let router = nfqws2_router_command::System;
    let k = kernel(&router);
    let wan = ["wan0".into()];
    let actual_mtu = || physical_mtu(&k);
    let set_mtu = |mtu| set_physical_mtu(&k, mtu);
    let path = |ip| route_device(&k, ip);
    let initial_mtu = actual_mtu();
    let old_mtu = if inherited { 1420 } else { initial_mtu };
    assert_ne!(old_mtu, NEXT_MTU);
    if inherited {
        set_mtu(old_mtu);
    }
    let (_dir, db, _) = setup();
    protect(&db);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let cfg = &mut doc["servers"][0]["config"];
        cfg["install"] = json!("imported");
        cfg["endpoint"] = json!(OLD);
        if inherited {
            cfg["mtu"] = json!(0);
            cfg["routing"]["mtu"] = json!(old_mtu);
            cfg["client"]
                .as_object_mut()
                .unwrap()
                .remove("rust_managed");
        } else {
            cfg["mtu"] = json!(old_mtu);
            cfg["client"]["rust_managed"] = json!(true);
        }
        Ok(())
    })
    .unwrap();
    let live = |endpoint: &'static str, mark| {
        move |cfg: &Value, iface: &str| {
            Ok(LivePeer {
                endpoint: endpoint.parse().unwrap(),
                socket_mark: mark,
                ..peer(cfg, iface)?
            })
        }
    };
    let initial_mark = if inherited { 0 } else { DIRECT_SOCKET_MARK };
    let now = nfqws2_awg_profile::now();
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &router, op, now, live(OLD, initial_mark)).unwrap();
    }
    assert_eq!(path(PAYLOAD).as_deref(), Some("awg0"));
    let stable = Journal::read(&db).unwrap().committed;
    let mut change = RoutedMtuChange {
        id: stable.targets["awg0"].id.clone(),
        iface: "awg0".into(),
        revision: stable.revision,
        before: old_mtu,
        after: NEXT_MTU,
        legacy_mtu_before_recorded: false,
        nested_mtu_before_recorded: false,
        native_mtu_endpoint: None,
        implicit_before_mtu: inherited.then_some(RoutedImplicitMtu::Zero),
        nested_outer: None,
        nested_endpoint: None,
        legacy_predecessor: inherited.then(|| RoutedLegacyPredecessor {
            endpoint: OLD.parse().unwrap(),
            receipt_sha256: [21; 32],
        }),
        endpoint_edit: None,
    };
    for (before, after, target_mtu) in [(OLD, NEW, NEXT_MTU), (NEW, OLD, old_mtu)]
        .into_iter()
        .take(if inherited { 1 } else { 2 })
    {
        change.endpoint_edit = Some(RoutedEndpointEdit {
            before: before.into(),
            after: after.into(),
            previous_reserve: None,
            resolved_before: vec![],
            resolved_after: vec![],
        });
        assert_eq!(
            validate_endpoint_edit_launch(&db, &router, &change, &wan).unwrap(),
            RoutedEndpointLaunch::Primary
        );
        nfqws2_awg_profile::edit_document(&db, |doc| {
            let row = &mut doc["servers"][0];
            row["config"]["endpoint"] = json!(after);
            row["config"]["mtu"] = json!(target_mtu);
            row["rust_pending_routed_mtu"] = json!(change);
            if inherited {
                row["rust_pending_client_profile"] = json!(vec![7_u8; 32]);
            }
            Ok(())
        })
        .unwrap();
        prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
        assert_eq!(path(PAYLOAD), None);
        let (previous_ip, selected_ip) = (
            before.split_once(':').unwrap().0,
            after.split_once(':').unwrap().0,
        );
        assert_eq!(path(previous_ip).as_deref(), Some("wan0"));
        assert_eq!(path(selected_ip).as_deref(), Some("wan0"));
        let recover = |observed| {
            operate_with_redirect_and_mtu(
                &db,
                &router,
                Operation::Recover,
                None,
                None,
                live(observed, DIRECT_SOCKET_MARK),
                |change, live| {
                    Ok(Some(RoutedMtuPeer {
                        iface: change.iface.clone(),
                        outer_id: String::new(),
                        outer_iface: String::new(),
                        endpoint: live.endpoint,
                        effective_mtu: actual_mtu(),
                        socket_mark: live.socket_mark,
                    }))
                },
            )
            .unwrap();
        };
        recover(after);
        assert_eq!(path(PAYLOAD), None);
        assert!(pending_mtu_edit(&db).unwrap());
        if inherited {
            nfqws2_awg_profile::edit_document(&db, |doc| {
                let row = &mut doc["servers"][0];
                row["config"]["client"]["rust_managed"] = json!(true);
                row.as_object_mut()
                    .unwrap()
                    .remove("rust_pending_client_profile");
                Ok(())
            })
            .unwrap();
            recover(after);
            assert_eq!(path(PAYLOAD), None);
            assert!(pending_mtu_edit(&db).unwrap());
        }
        set_mtu(target_mtu);
        recover(before);
        assert_eq!(path(PAYLOAD), None);
        assert!(pending_mtu_edit(&db).unwrap());
        recover(after);
        assert_eq!(path(PAYLOAD).as_deref(), Some("awg0"));
        assert_eq!(path(previous_ip).as_deref(), Some("wan0"));
        assert_eq!(path(selected_ip).as_deref(), Some("wan0"));
        assert!(!pending_mtu_edit(&db).unwrap());
        let mss = k
            .call("iptables", &["-w", "-t", "mangle", "-S", "FORWARD"])
            .unwrap();
        assert!(mss.lines().any(|line| {
            line.contains("awg0") && line.ends_with(&format!("--set-mss {}", target_mtu - 40))
        }));
        std::mem::swap(&mut change.before, &mut change.after);
    }
    let final_endpoint = if inherited { NEW } else { OLD };
    operate_at(
        &db,
        &router,
        Operation::Teardown,
        now,
        live(final_endpoint, DIRECT_SOCKET_MARK),
    )
    .unwrap();
    assert_eq!(path(PAYLOAD).as_deref(), Some("wan0"));
    if inherited {
        set_mtu(initial_mtu);
    }
    assert_eq!(actual_mtu(), initial_mtu);
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn inherited_named_endpoint_edit_checks_real_wan_and_pending_undo() {
    require_isolated_namespaces();
    for undo in [false, true] {
        inherited_endpoint_edit_with_real_routes(
            ("old-inherited.awg.test:443", "192.0.2.120:443"),
            ("192.0.2.123:8443", "192.0.2.123:8443"),
            undo,
        );
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn inherited_numeric_endpoint_edit_checks_real_pinned_wan_and_pending_undo() {
    require_isolated_namespaces();
    for undo in [false, true] {
        inherited_endpoint_edit_with_real_routes(
            ("192.0.2.120:443", "192.0.2.120:443"),
            ("new-inherited.awg.test:8443", "192.0.2.123:8443"),
            undo,
        );
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn inherited_endpoint_alias_requires_new_native_owner_on_the_real_fib() {
    require_isolated_namespaces();
    let named = ("old-inherited.awg.test:443", "192.0.2.120:443");
    let literal = ("192.0.2.120:443", "192.0.2.120:443");
    for (before, after) in [(named, literal), (literal, named)] {
        for undo in [false, true] {
            inherited_endpoint_edit_with_real_routes(before, after, undo);
        }
    }
}

fn inherited_endpoint_edit_with_real_routes(
    (before, old): (&'static str, &'static str),
    (after, new): (&'static str, &'static str),
    undo: bool,
) {
    const PAYLOAD: &str = "203.0.113.50";
    let router = nfqws2_router_command::System;
    let k = kernel(&router);
    let wan = ["wan0".into()];
    let (_dir, db, _) = setup();
    protect(&db);
    let mtu = physical_mtu(&k);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let cfg = &mut doc["servers"][0]["config"];
        cfg["install"] = json!("imported");
        cfg["endpoint"] = json!(before);
        cfg["mtu"] = json!(mtu);
        cfg["client"]
            .as_object_mut()
            .unwrap()
            .remove("rust_managed");
        Ok(())
    })
    .unwrap();
    let live = |endpoint: &'static str, mark| {
        move |cfg: &Value, iface: &str| {
            Ok(LivePeer {
                endpoint: endpoint.parse().unwrap(),
                socket_mark: mark,
                ..peer(cfg, iface)?
            })
        }
    };
    let now = nfqws2_awg_profile::now();
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &router, op, now, live(old, 0)).unwrap();
    }
    let original = Journal::read(&db).unwrap().committed;
    let old_udp: std::net::SocketAddr = old.parse().unwrap();
    let new_udp: std::net::SocketAddr = new.parse().unwrap();
    let change = RoutedMtuChange {
        id: original.targets["awg0"].id.clone(),
        iface: "awg0".into(),
        revision: original.revision,
        before: mtu,
        after: mtu,
        legacy_mtu_before_recorded: false,
        nested_mtu_before_recorded: false,
        native_mtu_endpoint: None,
        implicit_before_mtu: None,
        nested_outer: None,
        nested_endpoint: None,
        legacy_predecessor: Some(RoutedLegacyPredecessor {
            endpoint: old_udp,
            receipt_sha256: [39; 32],
        }),
        endpoint_edit: Some(RoutedEndpointEdit {
            before: before.into(),
            after: after.into(),
            previous_reserve: None,
            resolved_before: (before != old).then_some(old_udp).into_iter().collect(),
            resolved_after: (after != new).then_some(new_udp).into_iter().collect(),
        }),
    };
    let check_launch = || {
        assert_eq!(
            validate_endpoint_edit_launch(&db, &router, &change, &wan).unwrap(),
            RoutedEndpointLaunch::Primary
        );
    };
    let prepare = |endpoint, native| {
        nfqws2_awg_profile::edit_document(&db, |doc| {
            let row = &mut doc["servers"][0];
            row["config"]["endpoint"] = json!(endpoint);
            row["rust_pending_routed_mtu"] = json!(change);
            if native {
                row["config"]["client"]["rust_managed"] = json!(true);
                row.as_object_mut()
                    .unwrap()
                    .remove("rust_pending_client_profile");
            } else {
                row["rust_pending_client_profile"] = json!([7_u8; 32].as_slice());
            }
            Ok(())
        })
        .unwrap();
        prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
    };
    let check_wan = || {
        for socket in [old_udp, new_udp] {
            assert_eq!(
                route_device(&k, &socket.ip().to_string()).as_deref(),
                Some("wan0")
            );
        }
    };
    let waiting = || {
        assert_eq!(route_device(&k, PAYLOAD), None);
        assert!(pending_mtu_edit(&db).unwrap());
        check_wan();
    };
    let recover = |endpoint, mark| {
        operate_with_redirect_and_mtu(
            &db,
            &router,
            Operation::Recover,
            None,
            None,
            live(endpoint, mark),
            |change, live| {
                Ok(Some(RoutedMtuPeer {
                    iface: change.iface.clone(),
                    outer_id: String::new(),
                    outer_iface: String::new(),
                    endpoint: live.endpoint,
                    effective_mtu: physical_mtu(&k),
                    socket_mark: live.socket_mark,
                }))
            },
        )
        .unwrap();
    };
    assert_eq!(route_device(&k, PAYLOAD).as_deref(), Some("awg0"));
    check_launch();
    prepare(after, false);
    waiting();
    recover(old, 0);
    waiting();
    let (saved, selected, other) = if undo {
        check_launch();
        (before, old, new)
    } else {
        (after, new, old)
    };
    let wrong = if other == selected {
        "192.0.2.120:8443"
    } else {
        other
    };
    prepare(saved, true);
    recover(wrong, DIRECT_SOCKET_MARK);
    waiting();
    recover(selected, DIRECT_SOCKET_MARK);
    assert_eq!(route_device(&k, PAYLOAD).as_deref(), Some("awg0"));
    assert!(!pending_mtu_edit(&db).unwrap());
    assert_eq!(Journal::read(&db).unwrap().committed, original);
    assert_eq!(
        nfqws2_awg_profile::read(&db).unwrap()["servers"][0]["config"]["endpoint"],
        saved
    );
    check_wan();
    operate_at(
        &db,
        &router,
        Operation::Teardown,
        now,
        live(selected, DIRECT_SOCKET_MARK),
    )
    .unwrap();
    assert_eq!(route_device(&k, PAYLOAD).as_deref(), Some("wan0"));
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn inherited_mtu_ack_checks_the_real_link_and_keeps_the_same_transport_route() {
    require_isolated_namespaces();
    for restore_before in [false, true] {
        fixed_mtu_with_real_routes(restore_before, false, false);
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn native_mtu_inverse_restores_the_real_link_and_mss_at_the_same_endpoint() {
    require_isolated_namespaces();
    fixed_mtu_with_real_routes(true, true, false);
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn native_mtu_edit_keeps_the_verified_reserve_when_the_primary_has_no_wan() {
    require_isolated_namespaces();
    for restore_before in [false, true] {
        fixed_mtu_with_real_routes(restore_before, true, true);
    }
}

fn fixed_mtu_with_real_routes(restore_before: bool, native_owned: bool, active_reserve: bool) {
    const ENDPOINT: &str = "192.0.2.101:443";
    const TRANSPORT: &str = "192.0.2.101";
    const PRIMARY: &str = "192.0.2.102:443";
    const PRIMARY_IP: &str = "192.0.2.102";
    const PRIMARY_ROUTE: &str = "192.0.2.102/32";
    const PAYLOAD: &str = "203.0.113.50";
    const NEXT_MTU: u16 = 1350;
    let (_dir, db, _) = setup();
    protect(&db);
    let router = nfqws2_router_command::System;
    let k = kernel(&router);
    let actual_mtu = || physical_mtu(&k);
    let set_mtu = |mtu| set_physical_mtu(&k, mtu);
    let path = |ip| route_device(&k, ip);
    let old_mtu = actual_mtu();
    assert_ne!(old_mtu, NEXT_MTU);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let cfg = &mut doc["servers"][0]["config"];
        cfg["install"] = json!("imported");
        cfg["endpoint"] = json!(if active_reserve { PRIMARY } else { ENDPOINT });
        cfg["mtu"] = json!(old_mtu);
        if active_reserve {
            cfg["client"]["endpoint_backups"] = json!([ENDPOINT]);
        }
        if native_owned {
            cfg["client"]["rust_managed"] = json!(true);
        } else {
            cfg["client"]
                .as_object_mut()
                .unwrap()
                .remove("rust_managed");
        }
        Ok(())
    })
    .unwrap();
    let primary = PRIMARY.parse().unwrap();
    let selected = ENDPOINT.parse().unwrap();
    let evidence = |endpoint, socket_mark| RoutedMtuPeer {
        iface: "awg0".into(),
        outer_id: String::new(),
        outer_iface: String::new(),
        endpoint,
        effective_mtu: actual_mtu(),
        socket_mark,
    };
    let live = |mark| {
        move |cfg: &Value, iface: &str| {
            Ok(LivePeer {
                endpoint: selected,
                socket_mark: mark,
                ..peer(cfg, iface)?
            }
            .with_direct_backup(active_reserve.then(|| RoutedDirectBackup {
                primary,
                peer: evidence(selected, mark),
            })))
        }
    };
    let initial_mark = if native_owned { DIRECT_SOCKET_MARK } else { 0 };
    let now = nfqws2_awg_profile::now();
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &router, op, now, live(initial_mark)).unwrap();
    }
    if active_reserve {
        assert_eq!(path(PRIMARY_IP).as_deref(), Some("wan0"));
        k.call("ip", &["-4", "route", "add", "prohibit", PRIMARY_ROUTE])
            .unwrap();
        assert_eq!(path(PRIMARY_IP), None);
        operate_at(&db, &router, Operation::Refresh, now, live(initial_mark)).unwrap();
    }
    assert_eq!(path(PAYLOAD).as_deref(), Some("awg0"));
    let stable = Journal::read(&db).unwrap().committed;
    let change = RoutedMtuChange {
        id: stable.targets["awg0"].id.clone(),
        iface: "awg0".into(),
        revision: stable.revision,
        before: old_mtu,
        after: NEXT_MTU,
        legacy_mtu_before_recorded: !native_owned,
        nested_mtu_before_recorded: false,
        native_mtu_endpoint: native_owned.then_some(selected),
        implicit_before_mtu: None,
        nested_outer: None,
        nested_endpoint: None,
        legacy_predecessor: (!native_owned).then_some(RoutedLegacyPredecessor {
            endpoint: selected,
            receipt_sha256: [66; 32],
        }),
        endpoint_edit: None,
    };
    let wan = ["wan0".into()];
    assert_eq!(
        validate_endpoint_edit_launch(&db, &router, &change, &wan).unwrap(),
        RoutedEndpointLaunch::Primary
    );
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let row = &mut doc["servers"][0];
        row["config"]["mtu"] = json!(NEXT_MTU);
        row["rust_pending_routed_mtu"] = json!(change);
        row["rust_pending_client_profile"] = json!(vec![7_u8; 32]);
        Ok(())
    })
    .unwrap();
    prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
    let waiting = || {
        assert_eq!(path(PAYLOAD), None);
        assert_eq!(path(TRANSPORT).as_deref(), Some("wan0"));
        if active_reserve {
            assert_eq!(path(PRIMARY_IP), None);
        }
        assert!(pending_mtu_edit(&db).unwrap());
    };
    waiting();
    operate_with_redirect_and_mtu(
        &db,
        &router,
        Operation::Recover,
        None,
        None,
        live(initial_mark),
        |_, _| panic!("the retiring owner cannot acknowledge its successor"),
    )
    .unwrap();
    waiting();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let row = &mut doc["servers"][0];
        row["config"]["client"]["rust_managed"] = json!(true);
        row.as_object_mut()
            .unwrap()
            .remove("rust_pending_client_profile");
        Ok(())
    })
    .unwrap();
    let desired_mtu = if restore_before {
        set_mtu(NEXT_MTU);
        assert_eq!(
            validate_endpoint_edit_launch(&db, &router, &change, &wan).unwrap(),
            RoutedEndpointLaunch::Primary
        );
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["servers"][0]["config"]["mtu"] = json!(old_mtu);
            Ok(())
        })
        .unwrap();
        prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
        old_mtu
    } else {
        NEXT_MTU
    };
    let recover = || {
        operate_with_redirect_and_mtu(
            &db,
            &router,
            Operation::Recover,
            None,
            None,
            live(DIRECT_SOCKET_MARK),
            |_, live| Ok(Some(evidence(live.endpoint, live.socket_mark))),
        )
        .unwrap();
    };
    recover();
    waiting();
    set_mtu(desired_mtu);
    recover();
    assert!(!pending_mtu_edit(&db).unwrap());
    assert_eq!(path(PAYLOAD).as_deref(), Some("awg0"));
    assert_eq!(path(TRANSPORT).as_deref(), Some("wan0"));
    if active_reserve {
        assert_eq!(path(PRIMARY_IP), None);
        operate_at(
            &db,
            &router,
            Operation::Refresh,
            now,
            live(DIRECT_SOCKET_MARK),
        )
        .unwrap();
        assert_eq!(path(PAYLOAD).as_deref(), Some("awg0"));
    }
    let expected_mss = format!("--set-mss {}", desired_mtu - 40);
    let mss = k
        .call("iptables", &["-w", "-t", "mangle", "-S", "FORWARD"])
        .unwrap();
    assert!(mss
        .lines()
        .any(|line| line.contains("awg0") && line.ends_with(&expected_mss)));
    operate_at(
        &db,
        &router,
        Operation::Teardown,
        now,
        live(DIRECT_SOCKET_MARK),
    )
    .unwrap();
    if active_reserve {
        k.call("ip", &["-4", "route", "del", "prohibit", PRIMARY_ROUTE])
            .unwrap();
        assert_eq!(path(PRIMARY_IP).as_deref(), Some("wan0"));
    }
    set_mtu(old_mtu);
    assert_eq!(path(PAYLOAD).as_deref(), Some("wan0"));
}
