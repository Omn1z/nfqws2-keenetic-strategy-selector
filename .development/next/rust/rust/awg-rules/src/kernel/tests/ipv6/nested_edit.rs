use super::*;
use crate::kernel::tests::packed::marked_recovery::ProtectedRouter;
use nfqws2_awg_profile::{
    RoutedEndpointEdit, RoutedEndpointLaunch, RoutedImplicitMtu, RoutedMtuChange, RoutedMtuOuter,
    RoutedMtuPeer, RoutedNestedTransport,
};
use std::{
    cell::Cell,
    net::{IpAddr, SocketAddr},
};

#[test]
fn routed_nested_cross_family_ip_edit_rechecks_outer_and_keeps_dns_and_ipv6_guards() {
    for reserve in [false, true] {
        exercise_nested_endpoint_families(reserve, None);
    }
}

#[test]
fn permanent_nested_cross_family_endpoint_mtu_replays_without_opening_low_mtu_ipv6() {
    exercise_nested_endpoint_families(false, Some(1360));
}

#[derive(Default)]
struct NestedOnlyRouter(ProtectedRouter, Mutex<bool>, Mutex<Option<u16>>);

impl Runner for NestedOnlyRouter {
    fn run(&self, program: &str, args: &[&str], end: Instant) -> io::Result<String> {
        match (program, args) {
            ("ip", ["-4", "route", "get", address @ ("198.51.100.77" | "198.51.100.78")])
                if *self.1.lock().unwrap() =>
            {
                return Ok(format!("{address} dev wan0"));
            }
            (
                "ip",
                ["-4" | "-6", "route", "get", "198.51.100.77" | "198.51.100.78" | "2001:db8:f00::1"],
            ) => {
                return Err(io::ErrorKind::NotConnected.into());
            }
            (
                "ip",
                ["-4" | "-6", "route", "get", addr @ ("198.51.100.77" | "198.51.100.78" | "2001:db8:f00::1"), "mark", "0xa0000000"],
            ) => {
                return Ok(format!("{addr} dev awg2 table 828"));
            }
            ("ip", ["-o", "-N", "-4" | "-6", "rule", "show"]) => {
                let mut rules = if args[2] == "-4" {
                    self.0.run(program, args, end)?
                } else {
                    String::new()
                };
                rules.push_str(
                    "\n60: from all fwmark 0xa0000000 lookup 828\n61: from all fwmark 0xa0000000 8",
                );
                return Ok(rules);
            }
            ("cat", ["/sys/class/net/awg0/mtu"]) => {
                return Ok(self.2.lock().unwrap().unwrap_or(1310).to_string());
            }
            _ => (),
        }
        self.0.run(program, args, end)
    }

    fn run_input(
        &self,
        program: &str,
        args: &[&str],
        input: &[u8],
        end: Instant,
    ) -> io::Result<String> {
        self.0.run_input(program, args, input, end)
    }
}

struct TransportWan<'a> {
    router: &'a dyn Runner,
    addresses: &'a [IpAddr],
    available: Mutex<bool>,
}

impl Runner for TransportWan<'_> {
    fn run(&self, program: &str, args: &[&str], end: Instant) -> io::Result<String> {
        if let ("ip", ["-4" | "-6", "route", "get", destination]) = (program, args) {
            if destination
                .parse()
                .is_ok_and(|address| self.addresses.contains(&address))
            {
                return if *self.available.lock().unwrap() {
                    Ok(format!("{destination} dev wan0"))
                } else {
                    Err(io::ErrorKind::NotConnected.into())
                };
            }
        }
        self.router.run(program, args, end)
    }

    fn run_input(
        &self,
        program: &str,
        args: &[&str],
        input: &[u8],
        end: Instant,
    ) -> io::Result<String> {
        self.router.run_input(program, args, input, end)
    }
}

#[test]
fn permanent_fixed_nested_mtu_undo_requires_the_exact_owned_generation_at_same_clamp() {
    exercise_fixed_nested_mtu(None);
}

#[test]
fn permanent_nested_port_and_mtu_edit_waits_for_exact_owner_at_equal_clamp() {
    exercise_paired_nested_edit("198.51.100.77:51821");
}

#[test]
fn permanent_nested_ip_and_mtu_edit_rechecks_both_transports_and_shared_paths() {
    exercise_paired_nested_edit("198.51.100.78:51821");
}

fn exercise_paired_nested_edit(after: &str) {
    const BEFORE: &str = "198.51.100.77:51820";
    const OUTER: &str = "198.51.100.88:443";
    const OTHER: &str = "198.51.100.89:443";
    const TARGET: &str = "203.0.113.10";
    const UNRELATED: &str = "203.0.113.11";
    const LEARNED: &str = "203.0.113.17";
    const CLAMP: u16 = 1310;
    const MARK: u32 = 0xa0000000;

    for reverse in [false, true] {
        let (dir, db, _) = setup();
        let router = NestedOnlyRouter::default();
        let wan = ["wan0".into()];
        let now = nfqws2_awg_profile::now();
        scoped_policy(&db);
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["routing"] = json!({"mode":"zones","domain_source":"dnsproxy","killswitch":true});
            let rows = doc["servers"].as_array_mut().unwrap();
            let mut outer = rows[1].clone();
            outer["id"] = json!("outer");
            outer["config"]["client_iface"] = json!("awg2");
            outer["config"]["endpoint"] = json!(OUTER);
            outer["config"]["routing"]["zones"] = json!([]);
            rows.push(outer);
            let inner = &mut rows[0]["config"];
            inner["install"] = json!("imported");
            inner["mtu"] = json!(0);
            inner["endpoint"] = json!(BEFORE);
            inner["client"]["rust_managed"] = json!(true);
            inner["client"]["double_tunnel_mode"] = json!("permanent");
            inner["client"]["double_tunnel_id"] = json!("outer");
            inner["routing"]["mtu"] = json!(1420);
            inner["routing"]["zones"] =
                json!([{"enabled":true,"ips":[TARGET],"domains":["*.office.test"]}]);
            rows[1]["config"]["endpoint"] = json!(OTHER);
            rows[1]["config"]["routing"]["zones"] = json!([{"enabled":true,"ips":[UNRELATED]}]);
            Ok(())
        })
        .unwrap();

        let live = Cell::new(BEFORE.parse::<SocketAddr>().unwrap());
        let evidence = || RoutedMtuPeer {
            iface: "awg0".into(),
            outer_id: "outer".into(),
            outer_iface: "awg2".into(),
            endpoint: live.get(),
            effective_mtu: CLAMP,
            socket_mark: MARK,
        };
        let sample = |cfg: &Value, iface: &str| {
            let mut peer = dual_peer(cfg, iface)?;
            if iface == "awg0" {
                peer.socket_mark = MARK;
                peer.endpoint = live.get();
                peer.nested_mtu = Some(CLAMP);
                let current = cfg["endpoint"].as_str().and_then(|raw| raw.parse().ok());
                Ok(
                    peer.with_nested_transport((current == Some(live.get())).then(|| {
                        RoutedNestedTransport {
                            peer: evidence(),
                            outer_endpoint: OUTER.parse().unwrap(),
                        }
                    })),
                )
            } else {
                peer.endpoint = cfg["endpoint"].as_str().unwrap().parse().unwrap();
                Ok(peer)
            }
        };
        for op in [Operation::Apply, Operation::Commit] {
            operate_at(&db, &router, op, now, sample).unwrap();
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
            sample,
            || Ok(()),
        )
        .unwrap();
        let baseline = Journal::read(&db).unwrap().committed;
        let change = RoutedMtuChange {
            id: baseline.targets["awg0"].id.clone(),
            iface: "awg0".into(),
            revision: baseline.revision,
            before: 1420,
            after: 1360,
            nested_outer: Some(RoutedMtuOuter {
                id: "outer".into(),
                iface: "awg2".into(),
                peer_key_sha256: [1; 32],
            }),
            endpoint_edit: Some(RoutedEndpointEdit {
                before: BEFORE.into(),
                after: after.into(),
                previous_reserve: None,
                resolved_before: vec![],
                resolved_after: vec![],
            }),
            nested_endpoint: None,
            legacy_predecessor: None,
            native_mtu_endpoint: None,
            legacy_mtu_before_recorded: false,
            nested_mtu_before_recorded: false,
            implicit_before_mtu: Some(RoutedImplicitMtu::Zero),
        };
        let paths = |expected| {
            for address in [TARGET, LEARNED] {
                assert_eq!(router.0.forward("192.168.1.42", address), expected);
            }
            assert_eq!(router.0.forward("192.168.1.42", UNRELATED), "awg1");
        };
        let other_endpoint = |db: &Store, endpoint: &str| {
            nfqws2_awg_profile::edit_document(db, |doc| {
                doc["servers"][1]["config"]["endpoint"] = json!(endpoint);
                Ok(())
            })
            .unwrap();
        };
        let stage = |db: &Store, endpoint, mtu, launching| {
            nfqws2_awg_profile::edit_document(db, |doc| {
                let row = &mut doc["servers"][0];
                row["config"]["endpoint"] = json!(endpoint);
                row["config"]["mtu"] = json!(mtu);
                row["rust_pending_routed_mtu"] = json!(change);
                if launching {
                    row["rust_pending_client_profile"] = json!(vec![7_u8; 32]);
                } else {
                    row.as_object_mut()
                        .unwrap()
                        .remove("rust_pending_client_profile");
                }
                Ok(())
            })
            .unwrap();
        };

        let mut invalid = change.clone();
        invalid.endpoint_edit.as_mut().unwrap().after = BEFORE.into();
        assert!(validate_endpoint_edit_launch(&db, &router, &invalid, &wan).is_err());
        invalid.endpoint_edit.as_mut().unwrap().after = format!("{LEARNED}:51821");
        assert!(validate_endpoint_edit_launch(&db, &router, &invalid, &wan).is_err());

        let shared_after =
            SocketAddr::new(after.parse::<SocketAddr>().unwrap().ip(), 8443).to_string();
        other_endpoint(&db, shared_after.as_str());
        assert!(validate_endpoint_edit_launch(&db, &router, &change, &wan).is_err());
        *router.1.lock().unwrap() = true;
        validate_endpoint_edit(&db, &router, &change, &wan).unwrap();
        *router.1.lock().unwrap() = false;
        other_endpoint(&db, OTHER);
        validate_endpoint_edit(&db, &router, &change, &wan).unwrap();

        stage(&db, after, change.after, true);
        other_endpoint(&db, shared_after.as_str());
        assert!(prepare_mtu_edit_with_wan(&db, &router, &change, &wan).is_err());
        paths("awg0");
        other_endpoint(&db, OTHER);
        prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
        paths("drop");
        let db = Store::open(dir.path()).unwrap();
        let (endpoint, raw_mtu) = if reverse {
            live.set(after.parse().unwrap());
            other_endpoint(&db, "198.51.100.77:8443");
            assert!(validate_endpoint_edit(&db, &router, &change, &wan).is_err());
            other_endpoint(&db, OTHER);
            validate_endpoint_edit(&db, &router, &change, &wan).unwrap();
            stage(&db, BEFORE, change.after, true);
            assert!(prepare_mtu_edit_with_wan(&db, &router, &change, &wan).is_err());
            stage(&db, BEFORE, 0, true);
            prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
            (BEFORE, 0)
        } else {
            (after, change.after)
        };
        let confirm = |owned: bool| {
            operate_with_redirect_and_mtu(
                &db,
                &router,
                Operation::Recover,
                None,
                None,
                sample,
                |saved, _| {
                    assert_eq!(saved, &change);
                    Ok(owned.then(evidence))
                },
            )
        };
        confirm(true).unwrap(); // Interrupted before launch acknowledgement.
        paths("drop");
        stage(&db, endpoint, raw_mtu, false);
        if !reverse && live.get().ip() != endpoint.parse::<SocketAddr>().unwrap().ip() {
            operate_at(&db, &router, Operation::Suspend, now, sample).unwrap();
            let shared_retiring = SocketAddr::new(live.get().ip(), 8443).to_string();
            other_endpoint(&db, shared_retiring.as_str());
            assert!(confirm(true).is_err());
            other_endpoint(&db, OTHER);
            confirm(true).unwrap(); // Reinstall fences even if the retired path still responds.
        } else {
            let _ = confirm(true); // A valid mark on the retired UDP tuple is insufficient.
        }
        paths("drop");
        live.set(endpoint.parse().unwrap());
        confirm(false).unwrap(); // Exact port and clamp without owned new profile are insufficient.
        paths("drop");
        let shared = SocketAddr::new(live.get().ip(), 8443).to_string();
        other_endpoint(&db, shared.as_str());
        let _ = confirm(true);
        paths("drop");
        assert!(pending_mtu_edit(&db).unwrap());
        other_endpoint(&db, OTHER);
        confirm(true).unwrap();
        paths("awg0");
        assert!(!pending_mtu_edit(&db).unwrap());
        let committed = Journal::read(&db).unwrap().committed;
        assert_eq!(committed.revision, baseline.revision);
        assert_eq!(
            committed.targets["awg0"].mtu,
            if reverse { 1420 } else { change.after }
        );
        assert_eq!(committed.mss["awg0"], CLAMP - 40);
        let learned = committed.learned.as_ref().unwrap();
        assert_eq!(learned.members, baseline.learned.as_ref().unwrap().members);
        assert_eq!(
            learned.hash == baseline.learned.as_ref().unwrap().hash,
            reverse
        );
        let stored = nfqws2_awg_profile::read(&db).unwrap();
        assert_eq!(stored["servers"][0]["config"]["endpoint"], endpoint);
        assert_eq!(stored["servers"][0]["config"]["mtu"], raw_mtu);
    }
}

#[test]
fn permanent_nested_mtu_edit_binds_configured_primary_and_wan_for_active_reserve() {
    exercise_fixed_nested_mtu(Some("[2001:db8:f00::1]:51820"));
    exercise_fixed_nested_mtu(Some("198.51.100.77:51821"));
}

fn exercise_fixed_nested_mtu(reserve: Option<&str>) {
    const ENDPOINT: &str = "198.51.100.77:51820";
    const OUTER: &str = "198.51.100.88:443";
    const TARGET: &str = "203.0.113.10";
    const OTHER: &str = "203.0.113.11";
    const LEARNED: &str = "203.0.113.17";
    const MARK: u32 = 0xa0000000;
    let endpoint: SocketAddr = reserve.unwrap_or(ENDPOINT).parse().unwrap();
    for (reverse, park_first) in [(false, true), (true, true), (true, false)] {
        let (dir, db, _) = setup();
        let router = NestedOnlyRouter::default();
        let reserve_address = reserve.map(|_| endpoint.ip());
        let run = TransportWan {
            router: &router,
            addresses: reserve_address.as_slice(),
            available: Mutex::new(true),
        };
        let reserve_wan = |available| *run.available.lock().unwrap() = available;
        let wan = ["wan0".into()];
        let now = nfqws2_awg_profile::now();
        scoped_policy(&db);
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["routing"] = json!({"mode":"zones","domain_source":"dnsproxy","killswitch":true});
            let rows = doc["servers"].as_array_mut().unwrap();
            let mut outer = rows[1].clone();
            outer["id"] = json!("outer");
            outer["config"]["client_iface"] = json!("awg2");
            outer["config"]["endpoint"] = json!(OUTER);
            outer["config"]["routing"]["zones"] = json!([]);
            rows.push(outer);
            let cfg = &mut rows[0]["config"];
            cfg["install"] = json!("imported");
            cfg["mtu"] = json!(0);
            cfg["endpoint"] = json!(ENDPOINT);
            cfg["client"]["rust_managed"] = json!(true);
            cfg["client"]["double_tunnel_mode"] = json!("permanent");
            cfg["client"]["double_tunnel_id"] = json!("outer");
            if let Some(reserve) = reserve {
                cfg["client"]["endpoint_backups"] = json!([reserve]);
            }
            cfg["routing"]["mtu"] = json!(1420);
            cfg["routing"]["zones"] =
                json!([{"enabled":true,"ips":[TARGET],"domains":["*.office.test"]}]);
            rows[1]["config"]["endpoint"] = json!("198.51.100.89:443");
            rows[1]["config"]["routing"]["zones"] = json!([{"enabled":true,"ips":[OTHER]}]);
            Ok(())
        })
        .unwrap();
        let effective = Cell::new(1310);
        let selected = Cell::new(endpoint);
        let evidence = |mtu| RoutedMtuPeer {
            iface: "awg0".into(),
            outer_id: "outer".into(),
            outer_iface: "awg2".into(),
            endpoint: selected.get(),
            effective_mtu: mtu,
            socket_mark: MARK,
        };
        let sample = |cfg: &Value, iface: &str| {
            let mut peer = dual_peer(cfg, iface)?;
            if iface == "awg0" {
                peer.socket_mark = MARK;
                peer.endpoint = selected.get();
                peer.nested_mtu = Some(effective.get());
                Ok(peer.with_nested_transport(Some(RoutedNestedTransport {
                    peer: evidence(effective.get()),
                    outer_endpoint: OUTER.parse().unwrap(),
                })))
            } else {
                peer.endpoint = "198.51.100.89:443".parse().unwrap();
                Ok(peer)
            }
        };
        for op in [Operation::Apply, Operation::Commit] {
            operate_at(&db, &run, op, now, sample).unwrap();
        }
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
            sample,
            || Ok(()),
        )
        .unwrap();
        let baseline = Journal::read(&db).unwrap().committed;
        let change = RoutedMtuChange {
            id: baseline.targets["awg0"].id.clone(),
            iface: "awg0".into(),
            revision: baseline.revision,
            before: 1420,
            after: if reverse { 1380 } else { 1280 },
            nested_outer: Some(RoutedMtuOuter {
                id: "outer".into(),
                iface: "awg2".into(),
                peer_key_sha256: [1; 32],
            }),
            nested_endpoint: Some(reserve.unwrap_or(ENDPOINT).into()),
            legacy_predecessor: None,
            native_mtu_endpoint: None,
            legacy_mtu_before_recorded: false,
            nested_mtu_before_recorded: true,
            implicit_before_mtu: Some(RoutedImplicitMtu::Zero),
            endpoint_edit: None,
        };
        let stage = |db: &Store, raw, marker: &RoutedMtuChange, pending| {
            nfqws2_awg_profile::edit_document(db, |doc| {
                let row = &mut doc["servers"][0];
                row["config"]["mtu"] = json!(raw);
                row["rust_pending_routed_mtu"] = json!(marker);
                if pending {
                    row["rust_pending_client_profile"] = json!(vec![7_u8; 32]);
                } else {
                    row.as_object_mut()
                        .unwrap()
                        .remove("rust_pending_client_profile");
                }
                Ok(())
            })
            .unwrap();
        };
        let set_primary = |db: &Store, primary: &str| {
            nfqws2_awg_profile::edit_document(db, |doc| {
                doc["servers"][0]["config"]["endpoint"] = json!(primary);
                Ok(())
            })
            .unwrap();
        };
        let mut wrong_pin = change.clone();
        wrong_pin.nested_endpoint = Some(SocketAddr::new(endpoint.ip(), 51822).to_string());
        assert!(validate_endpoint_edit_launch(&db, &run, &wrong_pin, &wan).is_err());
        if reserve.is_some() {
            reserve_wan(false);
            assert!(validate_endpoint_edit_launch(&db, &run, &change, &wan).is_err());
            reserve_wan(true);
            set_primary(&db, &format!("{TARGET}:51820"));
            assert!(validate_endpoint_edit_launch(&db, &run, &change, &wan).is_err());
            set_primary(&db, ENDPOINT);
        }
        assert_eq!(
            validate_endpoint_edit_launch(&db, &run, &change, &wan).unwrap(),
            RoutedEndpointLaunch::Primary
        );
        let mut historical = change.clone();
        historical.nested_mtu_before_recorded = false;
        historical.implicit_before_mtu = None;
        stage(&db, 0, &historical, true);
        assert!(prepare_mtu_edit_with_wan(&db, &run, &historical, &wan).is_err());
        stage(&db, change.after, &change, true);
        let paths = |wanted| {
            assert_eq!(router.0.forward("192.168.1.42", TARGET), wanted);
            assert_eq!(router.0.forward("192.168.1.42", LEARNED), wanted);
            assert_eq!(router.0.forward("192.168.1.42", OTHER), "awg1");
        };
        if reserve.is_some() {
            reserve_wan(false);
            assert!(prepare_mtu_edit_with_wan(&db, &run, &change, &wan).is_err());
            paths("awg0");
            assert!(!pending_mtu_edit(&db).unwrap());
            reserve_wan(true);
        }
        if park_first {
            prepare_mtu_edit_with_wan(&db, &run, &change, &wan).unwrap();
            paths("drop");
        } else {
            assert!(!pending_mtu_edit(&db).unwrap());
            paths("awg0");
        }
        let db = Store::open(dir.path()).unwrap();
        let raw = if reverse {
            validate_endpoint_edit(&db, &run, &change, &wan).unwrap();
            stage(&db, change.before, &change, true);
            assert!(prepare_mtu_edit_with_wan(&db, &run, &change, &wan).is_err());
            stage(&db, 0, &change, true);
            prepare_mtu_edit_with_wan(&db, &run, &change, &wan).unwrap();
            0
        } else {
            change.after
        };
        paths("drop");
        let receipt = json!(mtu_edit::read(&db).unwrap().unwrap());
        assert_eq!(
            receipt
                .get("recorded_nested_primary")
                .and_then(Value::as_str),
            reserve.map(|_| ENDPOINT)
        );
        let confirm = |proof: RoutedMtuPeer| {
            operate_with_redirect_and_mtu(
                &db,
                &run,
                Operation::Recover,
                None,
                None,
                sample,
                |saved, _| {
                    assert_eq!(saved, &change);
                    Ok(Some(proof.clone()))
                },
            )
        };
        confirm(evidence(effective.get())).unwrap(); // The launch is not yet acknowledged.
        paths("drop");
        stage(&db, raw, &change, false);
        operate_at(&db, &run, Operation::Recover, now, sample).unwrap();
        paths("drop"); // Same authenticated outer and live clamp cannot substitute for native config proof.
        let actual = if reverse { 1310 } else { 1280 };
        effective.set(actual);
        *router.2.lock().unwrap() = Some(actual);
        let mut wrong_outer = evidence(actual);
        wrong_outer.outer_iface = "awg3".into();
        confirm(wrong_outer).unwrap();
        paths("drop");
        selected.set(SocketAddr::new(endpoint.ip(), 51822));
        let wrong_port = confirm(evidence(actual));
        if reserve.is_none() {
            // A socket on the wrong port cannot claim the primary's nested-only exemption.
            assert_eq!(wrong_port.unwrap_err().kind(), io::ErrorKind::NotConnected);
        }
        paths("drop");
        selected.set(endpoint);
        if let Some(reserve) = reserve {
            let set_backups = |backups: Value| {
                nfqws2_awg_profile::edit_document(&db, |doc| {
                    doc["servers"][0]["config"]["client"]["endpoint_backups"] = backups;
                    Ok(())
                })
                .unwrap();
            };
            set_backups(json!([]));
            assert!(prepare_mtu_edit_with_wan(&db, &run, &change, &wan).is_err());
            confirm(evidence(actual)).unwrap();
            paths("drop");
            set_backups(json!([reserve]));

            set_primary(&db, "198.51.100.78:51820");
            assert!(prepare_mtu_edit_with_wan(&db, &run, &change, &wan).is_err());
            confirm(evidence(actual)).unwrap();
            paths("drop");
            set_primary(&db, ENDPOINT);

            reserve_wan(false);
            // The opposite-family transport can fail closed without returning
            // an error from the IPv4 payload's ordinary endpoint guard.
            let _ = confirm(evidence(actual));
            paths("drop");
            assert!(pending_mtu_edit(&db).unwrap());
            reserve_wan(true);
        }
        let outer_key = |key: &str| {
            nfqws2_awg_profile::edit_document(&db, |doc| {
                doc["servers"][2]["config"]["public_key"] = json!(key);
                Ok(())
            })
            .unwrap();
        };
        outer_key("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=");
        confirm(evidence(actual)).unwrap();
        paths("drop");
        outer_key(KEY);
        *router.2.lock().unwrap() = Some(actual - 1);
        confirm(evidence(actual)).unwrap();
        paths("drop");
        *router.2.lock().unwrap() = Some(actual);
        confirm(evidence(actual)).unwrap();
        paths("awg0");
        assert!(!pending_mtu_edit(&db).unwrap());
        let confirmed = Journal::read(&db).unwrap().committed;
        assert_eq!(confirmed.revision, baseline.revision);
        assert_eq!(
            confirmed.targets["awg0"].mtu,
            if reverse { change.before } else { change.after }
        );
        assert_eq!(confirmed.mss["awg0"], actual - 40);
        let learned = confirmed.learned.as_ref().unwrap();
        assert_eq!(learned.members, baseline.learned.as_ref().unwrap().members);
        assert_eq!(
            learned.hash == baseline.learned.as_ref().unwrap().hash,
            reverse
        );
        assert_eq!(
            nfqws2_awg_profile::read(&db).unwrap()["servers"][0]["config"]["mtu"],
            raw
        );
        db.transaction(|tx| tx.save_runtime_bounded("awg-routed-mtu.json", &receipt, 4096))
            .unwrap();
        confirm(evidence(actual)).unwrap();
        assert!(!pending_mtu_edit(&db).unwrap());
        paths("awg0");
    }
}

#[test]
fn permanent_numeric_primary_uses_only_its_proved_nested_underlay() {
    const OLD: &str = "[2001:db8:f00::1]:51820";
    const NEW: &str = "198.51.100.77:51820";
    const PAYLOAD: &str = "203.0.113.10";
    const OTHER_PAYLOAD: &str = "203.0.113.11";
    const LEARNED: &str = "203.0.113.17";
    const MARK: u32 = 0xa0000000;
    let (_dir, db, _) = setup();
    let router = NestedOnlyRouter::default();
    scoped_policy(&db);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"] = json!({"mode":"zones","domain_source":"dnsproxy","killswitch":true});
        let rows = doc["servers"].as_array_mut().unwrap();
        let mut outer = rows[1].clone();
        outer["id"] = json!("outer");
        outer["config"]["client_iface"] = json!("awg2");
        outer["config"]["endpoint"] = json!("198.51.100.88:443");
        outer["config"]["routing"]["zones"] = json!([]);
        rows.push(outer);
        let main = &mut rows[0]["config"];
        main["install"] = json!("imported");
        main["mtu"] = json!(1420);
        main["endpoint"] = json!(OLD);
        main["client"]["rust_managed"] = json!(true);
        main["client"]["double_tunnel_mode"] = json!("permanent");
        main["client"]["double_tunnel_id"] = json!("outer");
        main["peers"] = json!([{"id":"client","is_router":true,"address":"10.21.0.2/32,fd21::2/128","allowed_ips":"0.0.0.0/0,::/0"}]);
        main["routing"]["zones"] = json!([{"order":1,"enabled":true,"ips":[PAYLOAD],"domains":["*.office.test"],"fallback_tunnel_ids":["branch"]}]);
        rows[1]["config"]["endpoint"] = json!("198.51.100.89:443");
        rows[1]["config"]["routing"]["zones"] = json!([{"order":2,"enabled":true,"ips":[OTHER_PAYLOAD]}]);
        Ok(())
    }).unwrap();
    let endpoint = Cell::new(OLD.parse::<SocketAddr>().unwrap());
    let outer_proof = Cell::new(Some("outer"));
    let shares_live_address = Cell::new(false);
    let shares_outer_address = Cell::new(false);
    let owned = |outer_id: &str, endpoint| RoutedMtuPeer {
        iface: "awg0".into(),
        outer_id: outer_id.into(),
        outer_iface: "awg2".into(),
        endpoint,
        effective_mtu: 1310,
        socket_mark: MARK,
    };
    let sample = |cfg: &Value, iface: &str| {
        let mut peer = dual_peer(cfg, iface)?;
        if iface == "awg0" {
            peer.endpoint = endpoint.get();
            peer.nested_mtu = Some(1310);
            peer.socket_mark = MARK;
            Ok(
                peer.with_nested_transport(outer_proof.get().map(|outer| RoutedNestedTransport {
                    peer: owned(outer, endpoint.get()),
                    outer_endpoint: if shares_outer_address.get() {
                        SocketAddr::new(endpoint.get().ip(), 8443)
                    } else {
                        "198.51.100.88:443".parse().unwrap()
                    },
                })),
            )
        } else {
            peer.endpoint = if shares_live_address.get() {
                NEW
            } else {
                "198.51.100.89:443"
            }
            .parse()
            .unwrap();
            Ok(peer)
        }
    };
    let now = nfqws2_awg_profile::now();
    // The initial transport uses IPv6 while this policy carries IPv4. A
    // shared outer direct claim still needs its independent IPv6 lookup.
    shares_outer_address.set(true);
    assert!(operate_at(&db, &router, Operation::Apply, now, sample).is_err());
    shares_outer_address.set(false);
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &router, op, now, sample).unwrap();
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
        sample,
        || Ok(()),
    )
    .unwrap();
    let baseline = Journal::read(&db).unwrap().committed;
    let paths = |expected| {
        assert_eq!(router.0.forward("192.168.1.42", PAYLOAD), expected);
        assert_eq!(router.0.forward("192.168.1.42", OTHER_PAYLOAD), "awg1");
        assert_eq!(router.0.forward("192.168.1.42", LEARNED), expected);
    };
    paths("awg0");
    for missing in [None, Some("other-outer")] {
        outer_proof.set(missing);
        operate_at(&db, &router, Operation::Refresh, now, sample).unwrap();
        paths("drop");
    }
    outer_proof.set(Some("outer"));
    operate_at(&db, &router, Operation::Refresh, now, sample).unwrap();
    paths("awg0");
    let change = RoutedMtuChange {
        id: baseline.targets["awg0"].id.clone(),
        iface: "awg0".into(),
        revision: baseline.revision,
        before: 1420,
        after: 1420,
        nested_outer: Some(RoutedMtuOuter {
            id: "outer".into(),
            iface: "awg2".into(),
            peer_key_sha256: [1; 32],
        }),
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
    let wan = ["wan0".into()];
    let backup = |value: Value| {
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["servers"][0]["config"]["client"]["endpoint_backups"] = value;
            Ok(())
        })
    };
    backup(json!([NEW])).unwrap();
    endpoint.set(NEW.parse().unwrap());
    *router.1.lock().unwrap() = true;
    operate_at(&db, &router, Operation::Refresh, now, sample).unwrap();
    paths("awg0");
    assert_eq!(Journal::read(&db).unwrap().committed, baseline);

    endpoint.set("198.51.100.77:8443".parse().unwrap());
    operate_at(&db, &router, Operation::Refresh, now, sample).unwrap();
    paths("drop");
    endpoint.set(NEW.parse().unwrap());
    *router.1.lock().unwrap() = false;
    assert!(operate_at(&db, &router, Operation::Recover, now, sample).is_err());
    paths("drop");

    endpoint.set(OLD.parse().unwrap());
    backup(json!([])).unwrap();
    operate_at(&db, &router, Operation::Refresh, now, sample).unwrap();
    paths("awg0");

    backup(json!(["198.51.100.77:8443"])).unwrap();
    assert!(validate_endpoint_edit(&db, &router, &change, &wan).is_err());
    backup(json!([])).unwrap();
    validate_endpoint_edit(&db, &router, &change, &wan).unwrap();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["config"]["endpoint"] = json!(NEW);
        doc["servers"][0]["rust_pending_routed_mtu"] = json!(change);
        Ok(())
    })
    .unwrap();
    prepare_mtu_edit_with_wan(&db, &router, &change, &wan).unwrap();
    paths("drop");
    endpoint.set(NEW.parse().unwrap());
    let recover = || {
        operate_with_redirect_and_mtu(
            &db,
            &router,
            Operation::Recover,
            None,
            None,
            sample,
            |asked, peer| {
                assert_eq!(asked, &change);
                Ok(Some(owned("outer", peer.endpoint)))
            },
        )
    };
    shares_live_address.set(true);
    assert!(recover().is_err());
    paths("drop");
    assert!(pending_mtu_edit(&db).unwrap());
    shares_live_address.set(false);
    // The outer owns no payload selector and may roam from its configured
    // address. Its current direct claim still needs plain WAN.
    shares_outer_address.set(true);
    assert!(recover().is_err());
    paths("drop");
    assert!(pending_mtu_edit(&db).unwrap());
    *router.1.lock().unwrap() = true;
    recover().unwrap();
    paths("awg0");
    assert!(!pending_mtu_edit(&db).unwrap());

    operate_at(&db, &router, Operation::Suspend, now, sample).unwrap();
    shares_outer_address.set(false);
    *router.1.lock().unwrap() = false;
    outer_proof.set(None);
    operate_at(&db, &router, Operation::Recover, now, sample).unwrap();
    paths("drop");
    outer_proof.set(Some("outer"));
    operate_at(&db, &router, Operation::Refresh, now, sample).unwrap();
    paths("awg0");
    let restored = Journal::read(&db).unwrap().committed;
    assert_eq!(restored.revision, baseline.revision);
    assert_eq!(restored.learned, baseline.learned);
    assert_eq!(restored.reserves, baseline.reserves);
}

fn exercise_nested_endpoint_families(reserve: bool, paired_mtu: Option<u16>) {
    const V4_WIRE: &str = "198.51.100.77:51820";
    const V6_WIRE: &str = "[2001:db8:f00::1]:51820";
    const V4_PAYLOAD: &str = "203.0.113.10";
    const V6_PAYLOAD: &str = "2001:db8:40::10";
    const V4_LEARNED: &str = "203.0.113.17";
    const V6_LEARNED: &str = "2001:db8:40::17";
    const NESTED_MARK: u32 = 0xa0000000;
    const CONFIGURED_MTU: u16 = 1420;
    // The same 1350-byte outer gives 1290/1270 bytes after v4/v6 overhead.
    const EFFECTIVE_V4: u16 = 1290;
    const EFFECTIVE_V6: u16 = 1270;
    let (dir, db, _) = setup();
    let router = Dual::default();
    let nested_addresses = [V4_WIRE, V6_WIRE].map(|raw| raw.parse::<SocketAddr>().unwrap().ip());
    let paired = paired_mtu.is_some();
    let run = TransportWan {
        router: &router,
        addresses: if paired { &nested_addresses } else { &[] },
        available: Mutex::new(false),
    };
    let configured_mtu = |raw: &str| {
        if raw == V6_WIRE {
            paired_mtu.unwrap_or(CONFIGURED_MTU)
        } else {
            CONFIGURED_MTU
        }
    };
    *router.nested_outer.lock().unwrap() = "awg2".into();
    scoped_policy(&db);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"] = json!({"mode":"zones","domain_source":"dnsproxy","killswitch":true});
        let rows = doc["servers"].as_array_mut().unwrap();
        rows[1]["config"]["routing"]["zones"] = json!([]);
        let mut outer = rows[1].clone();
        outer["id"] = json!("outer");
        outer["config"]["endpoint"] = json!("198.51.100.88:443");
        outer["config"]["client_iface"] = json!("awg2");
        rows.push(outer);
        for row in &mut *rows {
            row["config"]["client"]["rust_managed"] = json!(true);
            row["config"]["peers"] = json!([{
                "id":"router","is_router":true,"address":"10.21.0.2/32,fd21::2/128",
                "allowed_ips":"0.0.0.0/0,::/0"
            }]);
        }
        let config = &mut rows[0]["config"];
        config["endpoint"] = json!(V4_WIRE);
        config["mtu"] = json!(CONFIGURED_MTU);
        config["client"]["double_tunnel_mode"] =
            json!(if paired { "permanent" } else { "automatic" });
        if paired {
            config["install"] = json!("imported");
        }
        config["client"]["double_tunnel_id"] = json!("outer");
        config["routing"]["zones"] = json!([{
            "enabled":true,"ips":[V4_PAYLOAD,V6_PAYLOAD],"domains":["*.office.test"],
            "fallback_tunnel_ids":if reserve { vec!["branch"] } else { vec![] }
        }]);
        Ok(())
    })
    .unwrap();

    let live = Cell::new((
        V4_WIRE.parse::<SocketAddr>().unwrap(),
        EFFECTIVE_V4,
        NESTED_MARK,
    ));
    let sample = |cfg: &Value, iface: &str| {
        let mut peer = dual_peer(cfg, iface)?;
        if iface == "awg0" {
            let (endpoint, mtu, mark) = live.get();
            peer.endpoint = endpoint;
            peer.nested_mtu = Some(mtu);
            peer.socket_mark = mark;
            let saved: Option<SocketAddr> =
                cfg["endpoint"].as_str().and_then(|raw| raw.parse().ok());
            if paired && saved == Some(endpoint) {
                peer = peer.with_nested_transport(Some(RoutedNestedTransport {
                    peer: RoutedMtuPeer {
                        iface: iface.into(),
                        outer_id: "outer".into(),
                        outer_iface: "awg2".into(),
                        endpoint,
                        effective_mtu: mtu,
                        socket_mark: mark,
                    },
                    outer_endpoint: "198.51.100.88:443".parse().unwrap(),
                }));
            }
        } else {
            peer.endpoint = "198.51.100.89:443".parse().unwrap();
        }
        Ok(peer)
    };
    let now = nfqws2_awg_profile::now();
    let legs = [
        (V4_WIRE, V6_WIRE, EFFECTIVE_V6),
        (V6_WIRE, V4_WIRE, EFFECTIVE_V4),
    ];
    let edit = |plan: &Plan, before: &str, after: &str| RoutedMtuChange {
        id: plan.targets["awg0"].id.clone(),
        iface: "awg0".into(),
        revision: plan.revision,
        before: configured_mtu(before),
        after: configured_mtu(after),
        nested_outer: Some(RoutedMtuOuter {
            id: "outer".into(),
            iface: "awg2".into(),
            peer_key_sha256: [1; 32],
        }),
        nested_endpoint: None,
        native_mtu_endpoint: None,
        legacy_predecessor: None,
        legacy_mtu_before_recorded: false,
        nested_mtu_before_recorded: false,
        implicit_before_mtu: None,
        endpoint_edit: Some(RoutedEndpointEdit {
            before: before.into(),
            after: after.into(),
            previous_reserve: None,
            resolved_before: vec![],
            resolved_after: vec![],
        }),
    };
    if paired {
        let doc = nfqws2_awg_profile::read(&db).unwrap();
        let members = [V4_LEARNED, V6_LEARNED].map(|address| crate::kernel::learning::Member {
            zone: 0,
            ip: address.parse().unwrap(),
            until: now + 600,
        });
        let intent = plan::compile_effective(
            &doc,
            crate::sources::current(&db, &doc).unwrap(),
            None,
            false,
            &members,
            plan::Layout::default(),
        )
        .unwrap();
        let k = kernel(&run);
        let baseline = plan::resolve_on(
            &doc,
            intent,
            false,
            None,
            Some(plan::Verification::Read(&k)),
            sample,
        )
        .unwrap()
        .plan;
        assert!(baseline.fully_live() && baseline.protected("awg0"));
        assert!(baseline.full_endpoints.is_none() && baseline.reserves.is_empty());
        assert!(!baseline.marks.is_empty());
        let old_hash = baseline.learned.as_ref().unwrap().hash.clone();
        let routes = |plan: &Plan, v4: bool, v6: bool| {
            let paths = objects(plan);
            for (family, destinations, live) in [
                (Family::V4, [V4_PAYLOAD, V4_LEARNED], v4),
                (Family::V6, [V6_PAYLOAD, V6_LEARNED], v6),
            ] {
                for address in destinations.map(|raw| raw.parse().unwrap()) {
                    assert!(plan.flows().any(|(selector, primary)| {
                        selector.dest.contains(address)
                            && plan.effective(selector, primary) == live.then_some("awg0")
                    }));
                }
                if !live {
                    assert!(paths.contains(&Object::MarkFence(family, 0)));
                }
            }
        };
        let mut journal = Journal {
            installed: baseline.clone().into(),
            committed: baseline.into(),
            ..Default::default()
        };
        for (before, after, effective) in legs {
            let change = edit(&journal.committed, before, after);
            let mut doc = nfqws2_awg_profile::read(&db).unwrap();
            doc["rust_static_routing"] = json!({
                "revision":change.revision, "committed_revision":change.revision,
                "committed_targets":[change.id], "pending_commit":false
            });
            let row = &mut doc["servers"][0];
            row["config"]["endpoint"] = json!(after);
            row["config"]["mtu"] = json!(change.after);
            row["rust_pending_routed_mtu"] = json!(change);
            let authority = db
                .transaction(|tx| mtu_edit::recover_authority(tx, &doc, &journal))
                .unwrap();
            let db = Store::open(dir.path()).unwrap();
            let auth = mtu_edit::read(&db).unwrap().unwrap();
            assert_eq!(Some(&auth), authority.as_ref());
            let proof = auth.proof(&doc, &journal).unwrap();
            let desired: SocketAddr = after.parse().unwrap();
            let recover = |owned: bool| {
                let mut prove = |asked: &RoutedMtuChange, live: &LivePeer| {
                    assert_eq!(asked, &change);
                    assert_eq!(live.endpoint, desired);
                    Ok(owned.then(|| RoutedMtuPeer {
                        iface: "awg0".into(),
                        outer_id: "outer".into(),
                        outer_iface: "awg2".into(),
                        endpoint: desired,
                        effective_mtu: effective,
                        socket_mark: NESTED_MARK,
                    }))
                };
                let resolved = plan::resolve_with_mtu_edit(
                    &doc,
                    journal.committed.as_ref().clone(),
                    true,
                    None,
                    Some(plan::Verification::Read(&k)),
                    plan::EditContext::Applying(&proof, &mut prove),
                    sample,
                )
                .unwrap();
                k.guard(&resolved.plan, &resolved.endpoints).unwrap();
                resolved
            };
            let stale = recover(true);
            assert!(!stale.mtu_verified);
            routes(&stale.plan, false, false);
            router
                .v4
                .0
                .lock()
                .unwrap()
                .mtu
                .insert("awg0".into(), effective);
            live.set((desired, effective, NESTED_MARK));
            let unowned = recover(false);
            assert!(!unowned.mtu_verified);
            routes(&unowned.plan, false, false);
            *router.nested_outer.lock().unwrap() = "awg1".into();
            assert!(!recover(true).mtu_verified);
            *router.nested_outer.lock().unwrap() = "awg2".into();
            let verified = recover(true);
            assert!(verified.mtu_verified);
            let mut active = verified.plan;
            routes(&active, true, effective >= 1280);
            assert_eq!(active.targets["awg0"].mtu, change.after);
            assert_eq!(active.mss["awg0"], effective - 40);
            mtu_edit::rebind_dns(&db, &doc, &journal.committed, &mut active, "awg0").unwrap();
            let learned = active.learned.as_ref().unwrap();
            assert_eq!(learned.members, members);
            assert_eq!(learned.hash == old_hash, after == V4_WIRE);
            assert_eq!(active.revision, change.revision);
            journal.installed = active.clone().into();
            active.selected.clear();
            journal.committed = active.into();
            db.transaction(mtu_edit::clear).unwrap();
        }
        return;
    }
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &run, op, now, sample).unwrap();
    }
    for (address, qtype) in [(V4_LEARNED, 1), (V6_LEARNED, 28)] {
        let learned = learn_answer(
            &db,
            &run,
            Answer {
                revision: 1,
                zone: 0,
                addresses: &[address.parse().unwrap()],
                ttl: 600,
                qtype,
            },
            sample,
            || Ok(()),
        )
        .unwrap();
        assert!(!learned.suppress);
    }
    let original = Journal::read(&db).unwrap();
    let committed = &original.committed;
    assert_eq!(committed.learned.as_ref().unwrap().members.len(), 2);
    assert_eq!(!committed.reserves.is_empty(), reserve);
    let paths = |v4, v6| {
        let fw4 = router.v4.0.lock().unwrap();
        for address in [V4_PAYLOAD, V4_LEARNED] {
            assert_eq!(fw4.forward("192.168.1.42", address), v4, "{address}");
        }
        let fw6 = router.v6.0.lock().unwrap();
        for address in [V6_PAYLOAD, V6_LEARNED] {
            assert_eq!(fw6.forward("fd21::42", address), v6, "{address}");
        }
    };
    paths("awg0", "awg0");
    let wan = ["wan0".into()];
    let unavailable = if reserve { "awg1" } else { "blackhole" };

    for (before, after, effective) in legs {
        let change = edit(committed, before, after);
        assert!(validate_endpoint_edit(&db, &run, &change, &["other-wan".into()]).is_err());
        // Coexisting arbitrary early rules and duplicate reserved selectors
        // must fail even when the configured nested transport is recognized.
        for foreign in [
            "\n59: from all lookup 920",
            "\n60: from all fwmark 0xa0000000 lookup 828",
        ] {
            *router.extra_rpdb.lock().unwrap() = foreign.into();
            assert!(validate_endpoint_edit(&db, &run, &change, &wan).is_err());
        }
        router.extra_rpdb.lock().unwrap().clear();
        validate_endpoint_edit(&db, &run, &change, &wan).unwrap();
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["servers"][0]["config"]["endpoint"] = json!(after);
            doc["servers"][0]["rust_pending_routed_mtu"] = json!(change);
            Ok(())
        })
        .unwrap();
        prepare_mtu_edit_with_wan(&db, &run, &change, &wan).unwrap();
        operate_with_redirect_and_mtu(&db, &run, Operation::Recover, None, None, sample, |_, _| {
            panic!("retired tuple cannot verify the new transport")
        })
        .unwrap();
        paths(unavailable, unavailable);

        let desired = after.parse().unwrap();
        let proof = |pending: &RoutedMtuChange, peer: &LivePeer| {
            assert_eq!(pending, &change);
            assert_eq!(peer.endpoint, desired);
            Ok(Some(RoutedMtuPeer {
                iface: "awg0".into(),
                outer_id: "outer".into(),
                outer_iface: "awg2".into(),
                endpoint: desired,
                effective_mtu: effective,
                socket_mark: peer.socket_mark,
            }))
        };
        let recover = || {
            operate_with_redirect_and_mtu(&db, &run, Operation::Recover, None, None, sample, proof)
        };
        let previous_mtu = live.get().1;
        router
            .v4
            .0
            .lock()
            .unwrap()
            .mtu
            .insert("awg0".into(), effective);
        live.set((desired, previous_mtu, NESTED_MARK));
        recover().unwrap();
        paths(unavailable, unavailable);
        live.set((desired, effective, NESTED_MARK + 1));
        recover().unwrap();
        paths(unavailable, unavailable);
        live.set((desired, effective, NESTED_MARK));
        *router.nested_outer.lock().unwrap() = "awg1".into();
        recover().unwrap();
        paths(unavailable, unavailable);
        *router.nested_outer.lock().unwrap() = "awg2".into();
        recover().unwrap();

        let v6 = if effective >= 1280 {
            "awg0"
        } else {
            unavailable
        };
        paths("awg0", v6);
        let restored = Journal::read(&db).unwrap();
        assert_eq!(restored.committed.revision, committed.revision);
        assert_eq!(restored.committed.targets, committed.targets);
        assert_eq!(restored.committed.reserves, committed.reserves);
        assert_eq!(restored.committed.learned, committed.learned);
        assert_eq!(restored.installed.mss["awg0"], effective - 40);
        assert!(!pending_mtu_edit(&db).unwrap());
        operate_at(&db, &run, Operation::Refresh, now, sample).unwrap();
        paths("awg0", v6);
    }
}
