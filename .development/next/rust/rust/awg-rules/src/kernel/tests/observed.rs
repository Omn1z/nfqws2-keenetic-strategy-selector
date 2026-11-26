use super::*;
use std::net::IpAddr;
mod combined_edit;

fn fixture() -> (tempfile::TempDir, Store, Fake) {
    let (dir, db, fake) = setup();
    nfqws2_awg_profile::edit_document(&db, |d|{
        d["routing"]["domain_source"]=json!("dnsproxy");
        d["routing"]["killswitch"]=json!(true);
        d["servers"][0]["config"]["routing"]["zones"]=json!([
            {"name":"direct","enabled":true,"route":"direct","domains":["cdn.example"],"include_subdomains":false},
            {"name":"work","enabled":true,"route":"tunnel","domains":["*.corp.example"],"source_ips":["192.168.1.0/24"]}]);
        Ok(())
    }).unwrap();
    fake.0.lock().unwrap().local = "2: br0 inet 192.168.1.1/24 scope global".into();
    (dir, db, fake)
}
fn learn(db: &Store, f: &Fake, zone: usize, ips: &[&str]) -> io::Result<bool> {
    let revision = observation(db)?.unwrap().revision;
    let addresses: Vec<IpAddr> = ips.iter().map(|ip| ip.parse().unwrap()).collect();
    let qtype = if addresses.iter().all(IpAddr::is_ipv6) {
        28
    } else {
        1
    };
    learn_answer(
        db,
        f,
        Answer {
            revision,
            zone,
            addresses: &addresses,
            ttl: 60,
            qtype,
        },
        peer,
        || Ok(()),
    )
    .map(|v| v.suppress)
}

#[test]
fn archive_dns_keeps_configured_source_priority_and_scoped_cdn_guard() {
    let (_tmp, db, f) = fixture();
    nfqws2_awg_profile::edit_document(&db, |d| {
        d["servers"][0]["config"]["routing"]["zones"] = json!([
            {"order":1,"enabled":true,"route":"direct","domains":["work.corp.example"],
             "source_ips":["192.168.1.7"]},
            {"order":2,"enabled":true,"route":"tunnel","domains":["*.corp.example"],
             "source_ips":["192.168.1.0/24"]},
            {"order":3,"enabled":true,"route":"direct","domains":["work.corp.example"],
             "source_ips":["2001:db8::7"]}
        ]);
        Ok(())
    })
    .unwrap();
    let now = nfqws2_awg_profile::now();
    action(&db, &f, Operation::Apply, now).unwrap();
    action(&db, &f, Operation::Commit, now).unwrap();
    let revision = observation(&db).unwrap().unwrap().revision;
    let (fresh, cdn): (IpAddr, IpAddr) = (
        "203.0.113.53".parse().unwrap(),
        "188.114.96.3".parse().unwrap(),
    );
    let before_change = std::cell::Cell::new(0);
    learn_archived_answer(
        &db,
        &f,
        ArchiveAnswer {
            revision,
            name: "work.corp.example",
            addresses: &[fresh, cdn],
            ttl: 37,
            qtype: 1,
        },
        peer,
        || {
            before_change.set(before_change.get() + 1);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(before_change.get(), 1);
    let forward = |source, destination| f.0.lock().unwrap().forward(source, destination).to_owned();
    assert_eq!(forward("192.168.1.7", "203.0.113.53"), "wan0");
    assert_eq!(forward("192.168.1.8", "203.0.113.53"), "awg0");
    assert_eq!(forward("192.168.2.8", "203.0.113.53"), "wan0");
    assert_eq!(forward("192.168.1.7", "188.114.96.3"), "awg0");
    assert_eq!(forward("192.168.1.8", "203.0.113.99"), "wan0");
    let journal = Journal::read(&db).unwrap();
    let members = &journal.installed.learned.as_ref().unwrap().members;
    assert_eq!(
        members.iter().map(|m| (m.zone, m.ip)).collect::<Vec<_>>(),
        [(0, fresh), (1, cdn), (1, fresh)]
    );
    assert!(members
        .iter()
        .all(|m| { (now + 37..=nfqws2_awg_profile::now() + 37).contains(&m.until) }));
    assert_eq!(
        db.read::<Value>(crate::discoveries::FILE)
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound,
    );
}

#[test]
fn routed_mtu_edit_holds_only_the_changed_peer_and_rebinds_live_dns() {
    const FOREIGN: &str =
        "-A FORWARD -o adminvpn -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1190";
    for resume_before_park in [false, true] {
        let (dir, db, f) = fixture();
        scoped_policy(&db);
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["servers"][0]["config"]["mtu"] = json!(1420);
            doc["servers"][0]["config"]["routing"]["zones"] = json!([
                {"order":1,"name":"team","enabled":true,"domains":["*.corp.example"],
                 "ips":["203.0.113.10"],"source_ips":["192.168.1.7"]}
            ]);
            doc["servers"][1]["config"]["routing"]["zones"] = json!([
                {"order":2,"name":"other team","enabled":true,"ips":["203.0.113.11"],"source_ips":["192.168.1.7"]}
            ]);
            Ok(())
        }).unwrap();
        let now = nfqws2_awg_profile::now();
        for op in [Operation::Apply, Operation::Commit] {
            operate_at(&db, &f, op, now, both_peers).unwrap();
        }
        let learn = |db: &Store, ip: &str| {
            let addresses = [ip.parse().unwrap()];
            learn_client_answer(
                db,
                &f,
                Answer {
                    revision: 1,
                    zone: 0,
                    addresses: &addresses,
                    ttl: 600,
                    qtype: 1,
                },
                Some("192.168.1.7".parse().unwrap()),
                both_peers,
                || Ok(()),
            )
        };
        learn(&db, "203.0.113.12").unwrap();
        let save = Journal::read(&db).unwrap();
        let change = nfqws2_awg_profile::RoutedMtuChange {
            id: save.committed.targets["awg0"].id.clone(),
            iface: "awg0".into(),
            revision: 1,
            before: 1420,
            after: 1380,
            nested_outer: None,
            nested_endpoint: None,
            legacy_predecessor: None,
            native_mtu_endpoint: None,
            legacy_mtu_before_recorded: false,
            nested_mtu_before_recorded: false,
            implicit_before_mtu: None,
            endpoint_edit: None,
        };
        {
            let mut fw = f.0.lock().unwrap();
            fw.mtu.insert("awg0".into(), change.before);
            fw.firewall
                .get_mut("mangle")
                .unwrap()
                .insert(FOREIGN.to_owned());
            fw.watch_flow = Some(("192.168.1.7", "203.0.113.12"));
        }
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["routing_revision"] = json!(2);
            doc["servers"][0]["config"]["mtu"] = json!(change.after);
            doc["servers"][0]["rust_pending_routed_mtu"] = json!(change);
            Ok(())
        })
        .unwrap();
        if resume_before_park {
            // The panel can exit after storing the desired wire config but
            // before creating the independent kernel authorization.
            operate_at(&db, &f, Operation::Recover, now + 1, both_peers).unwrap();
        } else {
            let mut wrong = change.clone();
            wrong.revision += 1;
            assert!(prepare_mtu_edit(&db, &f, &wrong).is_err());
            assert!(!pending_mtu_edit(&db).unwrap());
            prepare_mtu_edit(&db, &f, &change).unwrap();
        }
        let verify = |expected: &str| {
            let fw = f.0.lock().unwrap();
            assert_eq!(fw.forward("192.168.1.7", "203.0.113.10"), expected);
            assert_eq!(fw.forward("192.168.1.7", "203.0.113.12"), expected);
            assert_eq!(fw.forward("192.168.1.7", "203.0.113.11"), "awg1");
            assert!(fw.firewall["mangle"].contains(FOREIGN));
            assert!(!fw.leaked);
        };
        verify("blackhole");
        assert!(pending_mtu_edit(&db).unwrap());
        assert_eq!(scheduled(&db).unwrap(), Schedule::Restore);
        assert_eq!(
            Journal::read(&db).unwrap().committed.learned,
            save.committed.learned
        );
        assert!(learn(&db, "203.0.113.13").is_err());
        assert_eq!(
            nfqws2_awg_profile::read(&db).unwrap()["servers"][0]["config"]["routing"]["active"],
            true
        );
        assert!(operate_at(&db, &f, Operation::Apply, now + 2, both_peers).is_err());
        // Profile marker defeats a false positive even at the desired MTU.
        f.0.lock().unwrap().mtu.insert("awg0".into(), change.after);
        operate_at(&db, &f, Operation::Recover, now + 3, both_peers).unwrap();
        verify("blackhole");
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["servers"][0]
                .as_object_mut()
                .unwrap()
                .remove("rust_pending_routed_mtu");
            Ok(())
        })
        .unwrap();
        let db = Store::open(dir.path()).unwrap();
        f.0.lock().unwrap().mtu.insert("awg0".into(), change.before);
        operate_at(&db, &f, Operation::Recover, now + 4, both_peers).unwrap();
        verify("blackhole");
        f.0.lock().unwrap().mtu.insert("awg0".into(), change.after);
        operate_at(&db, &f, Operation::Recover, now + 5, |cfg, iface| {
            if iface == "awg0" {
                return Err(io::ErrorKind::NotConnected.into());
            }
            both_peers(cfg, iface)
        })
        .unwrap();
        verify("blackhole");
        operate_at(&db, &f, Operation::Recover, now + 6, |cfg, iface| {
            let mut peer = both_peers(cfg, iface)?;
            if iface == "awg0" {
                peer.allowed = vec!["203.0.113.10/32".into()];
            }
            Ok(peer)
        })
        .unwrap();
        verify("blackhole");
        operate_at(&db, &f, Operation::Recover, now + 7, both_peers).unwrap();
        verify("awg0");
        assert!(!pending_mtu_edit(&db).unwrap());
        let restored = Journal::read(&db).unwrap();
        assert_eq!(restored.committed.revision, 1);
        assert_eq!(restored.committed.targets["awg0"].mtu, 1380);
        assert_eq!(
            restored.committed.targets["awg1"],
            save.committed.targets["awg1"]
        );
        assert_eq!(restored.committed.mss["awg0"], 1340);
        assert_eq!(
            restored.committed.learned.as_ref().unwrap().members,
            save.committed.learned.as_ref().unwrap().members
        );
        learn(&db, "203.0.113.13").unwrap();
        assert_eq!(
            f.0.lock().unwrap().forward("192.168.1.7", "203.0.113.13"),
            "awg0"
        );
    }
}

#[test]
fn routed_ip_edit_preserves_learned_dns_and_reserves() {
    routed_ip_edit("198.51.100.10:443", "198.51.100.55:51820", false);
}

#[test]
fn routed_cross_family_ip_edit_preserves_ipv4_payload_routes_and_reserves() {
    routed_ip_edit("198.51.100.10:443", "[2001:db8::55]:51820", false);
    routed_ip_edit("[2001:db8::55]:51820", "198.51.100.10:443", false);
}

#[test]
fn routed_ip_edit_undo_recovers_without_a_forward_authority_or_installed_plan() {
    routed_ip_edit("198.51.100.10:443", "[2001:db8::55]:51820", true);
}

struct EndpointWan<'a>(&'a Fake);
impl Runner for EndpointWan<'_> {
    fn run(&self, program: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
        if let ("ip", ["-6", "route", "get", address]) = (program, args) {
            let ip = address.parse::<std::net::Ipv6Addr>().unwrap();
            return Ok(format!("{ip} dev wan6"));
        }
        self.0.run(program, args, deadline)
    }
}

fn routed_ip_edit(before: &str, after: &str, undo: bool) {
    use nfqws2_awg_profile::{RoutedEndpointEdit, RoutedMtuChange, RoutedMtuPeer};
    use std::net::SocketAddr;

    const SOURCE: &str = "192.168.1.7";
    const STATIC: &str = "203.0.113.10";
    const OTHER: &str = "203.0.113.11";
    const LEARNED: &str = "203.0.113.12";
    let reserves = json!(["198.51.100.21:443", "[2001:db8::21]:8443"]);
    let (_dir, db, router) = fixture();
    let runner = EndpointWan(&router);
    scoped_policy(&db);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["config"]["endpoint"] = json!(before);
        doc["servers"][0]["config"]["client"]["endpoint_backups"] = reserves.clone();
        doc["servers"][0]["config"]["mtu"] = json!(1420);
        doc["servers"][0]["config"]["routing"]["zones"] = json!([{
            "order":1,"name":"main","enabled":true,"domains":["*.corp.example"],
            "ips":[STATIC],"source_ips":[SOURCE],"fallback_tunnel_ids":["branch"]
        }]);
        doc["servers"][1]["config"]["routing"]["zones"] = json!([{
            "order":2,"name":"other","enabled":true,"ips":[OTHER],"source_ips":[SOURCE]
        }]);
        Ok(())
    })
    .unwrap();
    router.0.lock().unwrap().mtu.insert("awg0".into(), 1420);
    let old_peer = |cfg: &Value, iface: &str| {
        let mut live = both_peers(cfg, iface)?;
        if iface == "awg0" {
            live.endpoint = before.parse().unwrap();
        }
        Ok(live)
    };
    let now = nfqws2_awg_profile::now();
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &runner, op, now, old_peer).unwrap();
    }
    learn_client_answer(
        &db,
        &runner,
        Answer {
            revision: 1,
            zone: 0,
            addresses: &[LEARNED.parse().unwrap()],
            ttl: 600,
            qtype: 1,
        },
        Some(SOURCE.parse().unwrap()),
        old_peer,
        || Ok(()),
    )
    .unwrap();
    let baseline = Journal::read(&db).unwrap();
    assert!(!baseline.committed.reserves.is_empty());
    assert!(!baseline
        .committed
        .learned
        .as_ref()
        .unwrap()
        .members
        .is_empty());
    assert!(!baseline.committed.uses_family(plan::Family::V6));
    let change = |after: &str| RoutedMtuChange {
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
            before: before.into(),
            after: after.into(),
            previous_reserve: None,
            resolved_before: vec![],
            resolved_after: vec![],
        }),
    };
    let desired = change(after);
    let wan_v4 = ["wan0".into()];
    let wan_v6 = ["wan6".into()];
    let wans = |endpoint: &str| {
        if endpoint.parse::<SocketAddr>().unwrap().is_ipv6() {
            (&wan_v6, &wan_v4)
        } else {
            (&wan_v4, &wan_v6)
        }
    };
    let (wan, wrong_wan) = wans(after);
    let writes = router.0.lock().unwrap().changes;
    let original = nfqws2_awg_profile::read(&db).unwrap();
    for invalid in ["203.0.113.11:443", "203.0.113.12:443"] {
        assert!(validate_endpoint_edit(&db, &runner, &change(invalid), &wan_v4).is_err());
    }
    assert!(validate_endpoint_edit(&db, &runner, &desired, wrong_wan).is_err());
    validate_endpoint_edit(&db, &runner, &desired, wan).unwrap();
    assert_eq!(router.0.lock().unwrap().changes, writes);
    assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), original);
    assert_eq!(Journal::read(&db).unwrap(), baseline);

    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["config"]["endpoint"] = json!(after);
        doc["servers"][0]["rust_pending_routed_mtu"] = json!(desired);
        Ok(())
    })
    .unwrap();
    let (selected, superseded) = if undo {
        operate_at(&db, &runner, Operation::Suspend, now, old_peer).unwrap();
        assert!(Journal::read(&db).unwrap().installed.empty());
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["routing_revision"] = json!(2);
            Ok(())
        })
        .unwrap();
        let (old_wan, wrong_wan) = wans(before);
        assert!(validate_endpoint_edit(&db, &runner, &desired, wrong_wan).is_err());
        validate_endpoint_edit(&db, &runner, &desired, old_wan).unwrap();
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["servers"][0]["config"]["endpoint"] = json!(before);
            doc["servers"][0]["rust_pending_client_profile"] = json!(vec![0_u8; 32]);
            Ok(())
        })
        .unwrap();
        assert!(validate_endpoint_edit(&db, &runner, &desired, old_wan).is_err());
        (before, after)
    } else {
        (after, before)
    };
    let (wan, wrong_wan) = wans(selected);
    let writes = router.0.lock().unwrap().changes;
    assert!(prepare_mtu_edit(&db, &runner, &desired).is_err());
    assert!(prepare_mtu_edit_with_wan(&db, &runner, &desired, wrong_wan).is_err());
    assert!(!pending_mtu_edit(&db).unwrap());
    assert_eq!(router.0.lock().unwrap().changes, writes);
    if undo {
        // Restart after the restored row was saved but before either park.
        operate_at(&db, &runner, Operation::Recover, now, old_peer).unwrap();
        assert!(pending_mtu_edit(&db).unwrap());
    }
    prepare_mtu_edit_with_wan(&db, &runner, &desired, wan).unwrap();
    assert!(pending_mtu_edit(&db).unwrap());
    {
        let fw = router.0.lock().unwrap();
        assert_ne!(fw.forward(SOURCE, STATIC), "awg0");
        assert_ne!(fw.forward(SOURCE, LEARNED), "awg0");
        assert_eq!(fw.forward(SOURCE, OTHER), "awg1");
    }
    let new_peer = |cfg: &Value, iface: &str| {
        let mut live = both_peers(cfg, iface)?;
        if iface == "awg0" {
            live.endpoint = selected.parse().unwrap();
        }
        Ok(live)
    };
    let stale_peer = |cfg: &Value, iface: &str| {
        let mut live = both_peers(cfg, iface)?;
        if iface == "awg0" {
            live.endpoint = superseded.parse().unwrap();
        }
        Ok(live)
    };
    if undo {
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["servers"][0]
                .as_object_mut()
                .unwrap()
                .remove("rust_pending_client_profile");
            Ok(())
        })
        .unwrap();
    }
    operate_with_redirect_and_mtu(
        &db,
        &runner,
        Operation::Recover,
        None,
        None,
        stale_peer,
        |_, _| panic!("unchanged peer tuple cannot prove the new address"),
    )
    .unwrap();
    assert_ne!(router.0.lock().unwrap().forward(SOURCE, LEARNED), "awg0");
    operate_with_redirect_and_mtu(
        &db,
        &runner,
        Operation::Recover,
        None,
        None,
        new_peer,
        |stored, live| {
            assert_eq!(stored, &desired);
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
    let restored = Journal::read(&db).unwrap();
    assert_eq!(restored.committed, baseline.committed);
    assert_eq!(restored.installed, baseline.installed);
    assert!(!pending_mtu_edit(&db).unwrap());
    let doc = nfqws2_awg_profile::read(&db).unwrap();
    assert!(nfqws2_awg_profile::pending_routed_mtu(&doc["servers"][0])
        .unwrap()
        .is_none());
    assert_eq!(doc["servers"][0]["config"]["endpoint"], selected);
    assert_eq!(doc["routing_revision"], if undo { 2 } else { 1 });
    assert_eq!(
        doc["servers"][0]["config"]["client"]["endpoint_backups"],
        reserves
    );
    let fw = router.0.lock().unwrap();
    assert_eq!(fw.forward(SOURCE, STATIC), "awg0");
    assert_eq!(fw.forward(SOURCE, LEARNED), "awg0");
    assert_eq!(fw.forward(SOURCE, OTHER), "awg1");
}

#[test]
fn two_clients_on_different_tunnels_can_resolve_the_same_destination_during_outage() {
    let (_dir, db, fw) = fixture();
    scoped_policy(&db);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        for (index, source) in ["192.168.1.7", "192.168.1.8"].iter().enumerate() {
            doc["servers"][index]["config"]["routing"]["zones"] = json!([{
                "order":index+1,"route":"tunnel","enabled":true,"domains":["*.work.test"],
                "ips":["203.0.113.8"],"source_ips":[source]
            }]);
        }
        Ok(())
    })
    .unwrap();
    let now = nfqws2_awg_profile::now();
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &fw, op, now, both_peers).unwrap();
    }
    let connected = |v: &Value, iface: &str| {
        if iface == "awg1" {
            return Err(io::ErrorKind::NotConnected.into());
        }
        both_peers(v, iface)
    };
    let ips = ["203.0.113.8".parse().unwrap()];
    let answer = |zone, source: Option<IpAddr>| {
        learn_client_answer(
            &db,
            &fw,
            Answer {
                revision: 1,
                zone,
                addresses: &ips,
                ttl: 60,
                qtype: 1,
            },
            source,
            connected,
            || Ok(()),
        )
    };
    assert!(answer(0, Some("192.168.1.7".parse().unwrap())).is_ok());
    for other in [
        None,
        Some("192.168.1.8".parse().unwrap()),
        Some("2001:db8::8".parse().unwrap()),
    ] {
        assert!(answer(1, other).is_err());
    }
}

#[test]
fn source_snapshot_roundtrips_large_domain_lists_and_static_geoip_uses_packed_routes() {
    let (_tmp, db, _) = fixture();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"]["killswitch"] = json!(false);
        doc["servers"][0]["config"]["routing"]["zones"] = json!([{
            "enabled":true, "route":"tunnel", "domains":["geosite:test", "geoip:test"]
        }]);
        Ok(())
    })
    .unwrap();
    crate::sources::stage(&db, |kind, _| {
        Ok(if kind == "geosite" {
            (0..3500)
                .map(|i| format!("office-{i}.example.test"))
                .collect()
        } else {
            (0u32..600)
                .map(|i| std::net::Ipv4Addr::from(0xcb00_7100 + i).to_string())
                .collect()
        })
    })
    .unwrap();
    let doc = nfqws2_awg_profile::read(&db).unwrap();
    let routing = crate::sources::current(&db, &doc).unwrap();
    let plan =
        plan::compile_effective(&doc, routing, None, false, &[], Default::default()).unwrap();
    assert!(plan.packed);
    assert_eq!(plan.prefixes.len(), 600);
    let stored = serde_json::to_value(plan.learned.as_ref().unwrap()).unwrap();
    assert!(stored["policy"].as_str().unwrap().starts_with("zlib:"));
    let restored = plan.learned.unwrap().routing().unwrap();
    assert_eq!(restored.zones[0].domains.len(), 3500);
    assert!(restored.zones[0].source_key.is_some());
    crate::sources::stage(&db, |kind, _| {
        Ok(if kind == "geoip" {
            restored.zones[0].ips.clone()
        } else {
            Vec::new()
        })
    })
    .unwrap();
    let plan = plan::compile_effective(
        &doc,
        crate::sources::current(&db, &doc).unwrap(),
        None,
        false,
        &[],
        Default::default(),
    )
    .unwrap();
    assert!(plan.packed && plan.learned.is_none() && plan.prefixes.len() == 600);
}

#[test]
fn slow_source_lookup_cannot_overwrite_a_concurrent_refresh_with_the_same_refs() {
    use std::{sync::mpsc, thread, time::Duration};
    let (_dir, db, _) = fixture();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["config"]["routing"]["zones"][0]["domains"] = json!(["list:Office"]);
        Ok(())
    })
    .unwrap();
    let timeout = Duration::from_secs(5);
    for (fast, slow) in [
        ("first.test", "stale.test"),
        ("second.test", "first.test"),
        ("third.test", "third.test"),
    ] {
        let (entered, started) = mpsc::channel();
        let (release, resume) = mpsc::channel();
        thread::scope(|threads| {
            let db_ref = &db;
            let pending = threads.spawn(move || {
                crate::sources::stage(db_ref, |_, _| {
                    entered.send(()).unwrap();
                    resume.recv_timeout(timeout).unwrap();
                    Ok(vec![slow.to_owned()])
                })
            });
            started.recv_timeout(timeout).unwrap();
            crate::sources::stage(&db, |_, _| Ok(vec![fast.to_owned()])).unwrap();
            release.send(()).unwrap();
            let result = pending.join().unwrap();
            if slow == fast {
                result.unwrap();
            } else {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
            }
        });
        let current =
            crate::sources::current(&db, &nfqws2_awg_profile::read(&db).unwrap()).unwrap();
        assert_eq!(current.zones[0].domains, [fast]);
    }
}

#[test]
fn local_sources_keep_their_go_history_identity_and_freeze_the_applied_generation() {
    let (_dir, db, f) = fixture();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let z = &mut doc["servers"][0]["config"]["routing"]["zones"][1];
        z["domains"] = json!(["list:Office", "geosite:Example", "geoip:Example"]);
        Ok(())
    })
    .unwrap();
    let stage = |suffix: &str| {
        crate::sources::stage(&db, |kind, _name| {
            Ok(match kind {
                "list" => vec![format!("*.{suffix}"), format!("*.{suffix}")],
                "geosite" => vec!["full:intranet.test".into()],
                "geoip" => vec!["203.0.113.81/32".into()],
                _ => unreachable!(),
            })
        })
    };
    let now = nfqws2_awg_profile::now();
    stage("office.test").unwrap();
    operate_at(&db, &f, Operation::Apply, now, peer).unwrap();
    let raw = crate::policy::current(&nfqws2_awg_profile::read(&db).unwrap()).unwrap();
    assert_eq!(raw.zones[1].domains[0], "list:Office");
    let key = crate::discoveries::rule_key(&raw.zones[1]).unwrap();
    let client = Some("192.168.1.9".parse().unwrap());
    let installed = observation(&db).unwrap().unwrap();
    assert_eq!(installed.policy.matched("a.office.test", client), Some(1));
    assert_eq!(installed.policy.history_key(1), Some(key.as_str()));
    learn(&db, &f, 1, &["203.0.113.82"]).unwrap();
    stage("changed.test").unwrap();
    assert!(operate_at(&db, &f, Operation::Commit, now + 1, peer).is_err());
    assert_eq!(
        observation(&db)
            .unwrap()
            .unwrap()
            .policy
            .matched("a.changed.test", client),
        None
    );
    stage("office.test").unwrap();
    operate_at(&db, &f, Operation::Commit, now + 2, peer).unwrap();
    assert!(has_local_sources(&db).unwrap());
    assert!(!local_sources_changed(&db).unwrap());
    stage("changed.test").unwrap();
    assert!(local_sources_changed(&db).unwrap());
    operate_at(&db, &f, Operation::ReloadSources, now + 3, peer).unwrap();
    let refreshed = observation(&db).unwrap().unwrap();
    assert_eq!(refreshed.trial_expires, 0);
    assert_eq!(refreshed.policy.matched("a.office.test", client), None);
    assert_eq!(refreshed.policy.matched("a.changed.test", client), Some(1));
    assert_eq!(refreshed.policy.history_key(1), Some(key.as_str()));
    assert!(!local_sources_changed(&db).unwrap());
}

#[test]
fn saved_sni_flag_uses_dns_for_explicit_zones_and_restores_committed_masks() {
    let (_dir, db, f) = fixture();
    scoped_policy(&db);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"]["sni_routing"] = json!(true);
        doc["servers"][0]["config"]["routing"]["zones"] = json!([
            {"order":1,"route":"tunnel","enabled":true,"domains":["*.corp.test"],"source_ips":["192.168.1.7"]}
        ]);
        doc["servers"][1]["config"]["routing"]["zones"] = json!([
            {"order":2,"route":"tunnel","enabled":true,"domains":["*.corp.test"]}
        ]);
        Ok(())
    }).unwrap();
    let now = nfqws2_awg_profile::now();
    let operate = |op, at| operate_at(&db, &f, op, at, both_peers);
    assert!(needs_dns_listener(&db).unwrap());
    assert!(dns_request(&db, Operation::Apply).unwrap().is_none());
    operate(Operation::Apply, now).unwrap();
    let observe = |source: &str| {
        let state = observation(&db).unwrap().unwrap();
        let name = "library.corp.test";
        let client = Some(source.parse().unwrap());
        let zone = state.policy.matched(name, client).unwrap();
        let destination = "203.0.113.40".parse().unwrap();
        assert!(state
            .policy
            .matched("library.corp.test.invalid", client)
            .is_none());
        let result = learn_answer(
            &db,
            &f,
            Answer {
                revision: state.revision,
                zone,
                addresses: &[destination],
                ttl: 600,
                qtype: 1,
            },
            both_peers,
            || Ok(()),
        )
        .unwrap();
        assert_eq!(result.accepted, [destination]);
    };
    observe("192.168.1.7");
    observe("192.168.1.8");
    operate(Operation::Commit, now + 1).unwrap();
    let forward = |client: &str| {
        f.0.lock()
            .unwrap()
            .forward(client, "203.0.113.40")
            .to_owned()
    };
    assert_eq!(forward("192.168.1.7"), "awg0");
    assert_eq!(forward("192.168.1.8"), "awg1");
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing_revision"] = json!(2);
        doc["servers"][0]["config"]["routing"]["zones"] = json!([
            {"route":"tunnel","enabled":true,"domains":["*.replacement.test"]}
        ]);
        doc["servers"][1]["config"]["routing"]["zones"] = json!([]);
        Ok(())
    })
    .unwrap();
    operate(Operation::Apply, now + 2).unwrap();
    assert_eq!(forward("192.168.1.7"), "wan0");
    operate(Operation::Recover, now + 93).unwrap();
    let recovered = observation(&db).unwrap().unwrap();
    assert_eq!(recovered.revision, 1);
    assert_eq!(recovered.policy.matched("library.corp.test", None), Some(1));
    assert!(recovered
        .policy
        .matched("new.replacement.test", None)
        .is_none());
    assert_eq!(forward("192.168.1.8"), "awg1");
    assert_eq!(
        nfqws2_awg_profile::read(&db).unwrap()["routing"]["sni_routing"],
        true
    );
}

#[test]
fn full_mode_foreign_routes_and_blanket_rules_stay_outside_the_zone_path() {
    for (mode, active, zone) in [
        ("full", false, json!(null)),
        (
            "zones",
            true,
            json!({"enabled":true,"domains":["*.corp.test"]}),
        ),
        ("zones", false, json!({"enabled":true,"domains":["*"]})),
        ("zones", false, json!({"enabled":true,"ips":["::/0"]})),
        ("zones", false, json!(null)),
    ] {
        let (_dir, db, f) = setup();
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["routing"] = json!({"mode":mode,"sni_routing":true,"domain_source":"dnsproxy"});
            let zones: Vec<_> = zone.as_object().map(|_| zone.clone()).into_iter().collect();
            doc["servers"][0]["config"]["routing"] =
                json!({"mode":mode,"active":active,"zones":zones});
            Ok(())
        })
        .unwrap();
        if active {
            f.0.lock().unwrap().foreign_rule =
                "71: from all fwmark 0x10100000/0x1ff00000 lookup 901".into();
        }
        assert!(action(&db, &f, Operation::Apply, 10).is_err());
        assert!(Journal::read(&db).unwrap().idle());
        assert_eq!(f.0.lock().unwrap().changes, 0);
    }
}

#[test]
fn wildcard_with_an_ip_keeps_its_destination_set_and_only_learns_with_a_matcher() {
    let (_dir, db, f) = fixture();
    let run = |op, at| action(&db, &f, op, at);
    nfqws2_awg_profile::edit_document(&db,|doc|{
        doc["routing"]["sni_routing"]=json!(true);
        doc["servers"][0]["config"]["routing"]["zones"]=json!([{"enabled":true,"route":"tunnel","domains":["*"],"ips":["203.0.113.29","0.0.0.0/0"]}]);
        Ok(())
    }).unwrap();
    assert!(!needs_dns_listener(&db).unwrap());
    run(Operation::Apply, 11).unwrap();
    assert_eq!(
        f.0.lock().unwrap().forward("192.168.0.2", "203.0.113.29"),
        "awg0"
    );
    assert_eq!(
        f.0.lock().unwrap().forward("192.168.0.2", "9.9.9.9"),
        "wan0"
    );
    run(Operation::Teardown, 12).unwrap();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["config"]["routing"]["zones"][0]["domains"] = json!(["*", "*.org.test"]);
        Ok(())
    })
    .unwrap();
    assert!(needs_dns_listener(&db).unwrap());
    run(Operation::Apply, 13).unwrap();
    let db_state = observation(&db).unwrap().unwrap();
    assert!(db_state
        .policy
        .matched("outside.test", Some("192.168.3.4".parse().unwrap()))
        .is_some());
    assert_eq!(
        f.0.lock().unwrap().forward("192.168.0.2", "9.9.9.9"),
        "wan0"
    );
}

#[test]
fn full_mode_keeps_source_only_rules_on_multi_policy_after_normalization() {
    let (_directory, db, _) = setup();
    let mut doc = nfqws2_awg_profile::read(&db).unwrap();
    doc["servers"][0]["config"]["endpoint"] = json!("198.51.100.10:443");
    let mut policy = crate::policy::current(&doc).unwrap();
    policy.mode = "full".into();
    let owner = policy.zones[0].tunnel_id.clone();
    policy.zones = ["192.168.1.3", "192.168.1.8"]
        .map(|src| crate::Zone {
            enabled: true,
            tunnel_id: owner.clone(),
            route: "tunnel".into(),
            source_ips: vec![src.into()],
            ..Default::default()
        })
        .to_vec();
    let plan = plan::compile_effective(&doc, policy.clone(), None, false, &[], Default::default())
        .unwrap();
    let forwarded = |src: &str| {
        plan.flows().any(|(s, _)| {
            plan.matches_source(s, src.parse().unwrap())
                && s.dest.contains("9.9.9.9".parse().unwrap())
        })
    };
    assert!(plan.go_ipv4 && plan.ordered_default && plan.legacy_full.is_none());
    assert!(forwarded("192.168.1.3") && forwarded("192.168.1.8"));
    assert!(!forwarded("192.168.1.9"));
    for z in &mut policy.zones {
        z.route = "direct".into();
    }
    let direct =
        plan::compile_effective(&doc, policy, None, false, &[], Default::default()).unwrap();
    assert!(direct.empty() && direct.full_endpoints.is_none());
}

#[test]
fn explicit_full_profile_uses_go_multi_policy_without_implicit_default() {
    let (_dir, db, f) = setup();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"] = json!({"mode":"full","sni_routing":true,"domain_source":"dnsproxy"});
        doc["servers"][0]["config"]["routing"]=json!({"mode":"full","zones":[
            {"route":"direct","order":1,"enabled":true,"ips":["203.0.113.11"]},
            {"route":"tunnel","order":2,"enabled":true,"ips":["203.0.113.11","203.0.113.17"],"domains":["*.corp.test"]}]});
        Ok(())
    }).unwrap();
    assert!(needs_dns_listener(&db).unwrap());
    action(&db, &f, Operation::Apply, 10).unwrap();
    action(&db, &f, Operation::Commit, 11).unwrap();
    let receipt = Journal::read(&db).unwrap();
    assert!(receipt.installed.full_endpoints.is_none());
    assert_eq!(
        nfqws2_awg_profile::read(&db).unwrap()["routing"]["mode"],
        "full"
    );
    let fw = f.0.lock().unwrap();
    for (dst, want) in [
        ("203.0.113.11", "wan0"),
        ("203.0.113.17", "awg0"),
        ("8.8.8.8", "wan0"),
    ] {
        assert_eq!(fw.forward("192.168.0.2", dst), want);
    }
}

#[test]
fn domain_only_sni_zone_requires_an_enabled_connection_or_reserve_before_apply() {
    let (_dir, db, f) = fixture();
    scoped_policy(&db);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"]["sni_routing"] = json!(true);
        doc["servers"][0]["config"]["client"]["enabled"] = json!(false);
        doc["servers"][0]["config"]["routing"]["zones"] = json!([
            {"enabled":true,"domains":["*.corp.test"]}
        ]);
        doc["servers"][1]["config"]["routing"]["zones"] = json!([]);
        Ok(())
    })
    .unwrap();
    let now = nfqws2_awg_profile::now();
    assert!(action(&db, &f, Operation::Apply, now).is_err());
    assert_eq!(f.0.lock().unwrap().changes, 0);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["config"]["routing"]["zones"][0]["fallback_tunnel_ids"] =
            json!(["branch"]);
        Ok(())
    })
    .unwrap();
    operate_at(&db, &f, Operation::Apply, now, both_peers).unwrap();
    let observation = observation(&db).unwrap().unwrap();
    assert_eq!(observation.policy.matched("app.corp.test", None), Some(0));
    let ip = "203.0.113.41".parse().unwrap();
    learn_answer(
        &db,
        &f,
        Answer {
            revision: observation.revision,
            zone: 0,
            addresses: &[ip],
            ttl: 60,
            qtype: 1,
        },
        both_peers,
        || Ok(()),
    )
    .unwrap();
    assert_eq!(path(&f, "203.0.113.41"), "awg1");
}

#[test]
fn first_dns_answer_in_trial_is_confirmed_and_survives_restart_and_draft_edits() {
    let (_dir, db, f) = fixture();
    let now = nfqws2_awg_profile::now();
    assert!(observation(&db).unwrap().is_none());
    action(&db, &f, Operation::Apply, now).unwrap();
    let active = observation(&db).unwrap().unwrap();
    assert!(active.ready);
    assert_eq!(active.block_aaaa, [1]);
    assert_eq!(
        active
            .policy
            .matched("build.corp.example", Some("192.168.1.42".parse().unwrap())),
        Some(1)
    );
    assert_eq!(
        active
            .policy
            .matched("build.corp.example", Some("10.0.1.2".parse().unwrap())),
        None
    );
    assert!(!learn(&db, &f, 1, &["203.0.113.9"]).unwrap());
    assert_eq!(path(&f, "203.0.113.9"), "awg0");
    assert_eq!(
        f.0.lock().unwrap().forward("10.0.1.2", "203.0.113.9"),
        "wan0"
    );
    action(&db, &f, Operation::Commit, now + 1).unwrap();
    let changes = f.0.lock().unwrap().changes;
    learn(&db, &f, 1, &["203.0.113.9"]).unwrap();
    assert_eq!(changes, f.0.lock().unwrap().changes);
    edit_net(&db, "198.51.100.11/32");
    learn(&db, &f, 1, &["203.0.113.18"]).unwrap();
    assert_eq!(path(&f, "203.0.113.18"), "awg0");
    action(&db, &f, Operation::Suspend, now + 2).unwrap();
    assert!(!observation(&db).unwrap().unwrap().ready);
    action(&db, &f, Operation::Recover, now + 3).unwrap();
    assert_eq!(path(&f, "203.0.113.18"), "awg0");
    action(&db, &f, Operation::Refresh, now + 1000).unwrap();
    assert_eq!(path(&f, "203.0.113.9"), "wan0");
    action(&db, &f, Operation::Teardown, now + 1001).unwrap();
    assert!(observation(&db).unwrap().is_none());
}

#[test]
fn ipv4_only_tunnel_suppresses_aaaa_and_failed_updates_preserve_the_old_routes() {
    let (_dir, db, f) = fixture();
    let now = nfqws2_awg_profile::now();
    action(&db, &f, Operation::Apply, now).unwrap();
    action(&db, &f, Operation::Commit, now + 1).unwrap();
    assert!(learn(&db, &f, 1, &["2001:db8::9"]).unwrap());
    // ANY and service-binding answers can carry both families in a single
    // reply. Do not release a usable IPv6 address on an IPv4-only tunnel.
    for qtype in [1, 64, 65, 255] {
        let applied = learn_answer(
            &db,
            &f,
            Answer {
                revision: 1,
                zone: 1,
                qtype,
                ttl: 60,
                addresses: &[
                    "203.0.113.18".parse().unwrap(),
                    "2001:db8::9".parse().unwrap(),
                ],
            },
            peer,
            || panic!("a suppressed reply changed the FIB"),
        )
        .unwrap();
        assert!(applied.suppress && applied.accepted.is_empty());
    }
    assert!(!learn(&db, &f, 1, &["203.0.113.9"]).unwrap());
    learn(&db, &f, 0, &["104.16.5.6"]).unwrap();
    let saved = Journal::read(&db).unwrap();
    assert_eq!(saved.committed.learned.as_ref().unwrap().members.len(), 1);
    for bad in ["192.168.1.1", "198.51.100.10", "127.0.0.1"] {
        assert!(learn(&db, &f, 1, &["203.0.113.18", bad]).is_err(), "{bad}");
        assert_eq!(Journal::read(&db).unwrap().committed, saved.committed);
    }
    assert_eq!(path(&f, "203.0.113.9"), "awg0");
    assert_eq!(path(&f, "203.0.113.18"), "wan0");
}

#[test]
fn adding_an_address_keeps_the_existing_lookup_live_even_without_killswitch() {
    let (_dir, db, f) = fixture();
    nfqws2_awg_profile::edit_document(&db, |d| {
        d["routing"]["killswitch"] = json!(false);
        Ok(())
    })
    .unwrap();
    let now = nfqws2_awg_profile::now();
    action(&db, &f, Operation::Apply, now).unwrap();
    action(&db, &f, Operation::Commit, now + 1).unwrap();
    learn(&db, &f, 1, &["203.0.113.8"]).unwrap();
    f.0.lock().unwrap().watch_flow = Some(("192.168.1.42", "203.0.113.8"));
    learn(&db, &f, 1, &["203.0.113.12"]).unwrap();
    assert!(!f.0.lock().unwrap().leaked);
}

#[test]
fn expired_dns_members_cannot_prevent_killswitch_recovery_after_rekey() {
    let (_dir, db, f) = fixture();
    let now = nfqws2_awg_profile::now();
    action(&db, &f, Operation::Apply, now).unwrap();
    learn(&db, &f, 1, &["203.0.113.7"]).unwrap();
    action(&db, &f, Operation::Commit, now + 1).unwrap();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["config"]["public_key"] =
            json!("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=");
        Ok(())
    })
    .unwrap();
    *f.0.lock().unwrap() = Firmware {
        boot: "34343434-3434-3434-3434-343434343434".into(),
        local: "2: br0 inet 192.168.1.1/24 scope global".into(),
        ..Default::default()
    };
    let err = action(&db, &f, Operation::Recover, now + 1000).unwrap_err();
    assert!(err.to_string().contains("профили динамических зон"));
    assert_eq!(path(&f, "203.0.113.7"), "blackhole");
    assert_eq!(path(&f, "203.0.113.8"), "wan0");
}

#[test]
fn a_parked_destination_does_not_block_answers_for_another_network() {
    let (_dir, db, f) = fixture();
    let now = nfqws2_awg_profile::now();
    action(&db, &f, Operation::Apply, now).unwrap();
    learn(&db, &f, 1, &["203.0.113.7"]).unwrap();
    action(&db, &f, Operation::Commit, now + 1).unwrap();
    let apply_answer = |ip: IpAddr| {
        learn_answer(
            &db,
            &f,
            Answer {
                revision: 1,
                zone: 1,
                addresses: &[ip],
                ttl: 60,
                qtype: 1,
            },
            |cfg, iface| {
                let mut live = peer(cfg, iface)?;
                live.allowed = vec!["203.0.113.8/32".into()];
                Ok(live)
            },
            || Ok(()),
        )
    };
    let healthy = "203.0.113.8".parse().unwrap();
    assert_eq!(apply_answer(healthy).unwrap().accepted, [healthy]);
    assert_eq!(path(&f, "203.0.113.7"), "blackhole");
    assert_eq!(path(&f, "203.0.113.8"), "awg0");
    assert!(apply_answer("203.0.113.7".parse().unwrap()).is_err());
}
#[test]
fn scoped_defaults_keep_first_match_before_and_after_learning_and_restart() {
    let (_tmp, db, f) = setup();
    f.0.lock().unwrap().local = "2: br0 inet 192.168.1.1/24 scope global".into();
    nfqws2_awg_profile::edit_document(&db, |d| {
        d["routing"] = json!({"mode":"zones","domain_source":"resolve","killswitch":true});
        let c = &mut d["servers"][0]["config"];
        c["endpoint"] = json!("198.51.100.10:51820");
        c["routing"]["zones"] = json!([
            {"enabled":true,"route":"direct","domains":["full:office.example"]},
            {"enabled":true,"route":"tunnel","source_ips":["192.168.1.20"],"domains":["*"]},
            {"enabled":true,"route":"direct","source_ips":["192.168.1.0/24"],"ips":["0.0.0.0/0"]},
            {"enabled":true,"route":"tunnel","ips":["203.0.113.8"]}
        ]);
        Ok(())
    })
    .unwrap();
    action(&db, &f, Operation::Apply, 10).unwrap();
    action(&db, &f, Operation::Commit, 11).unwrap();
    let path = |src, dst| f.0.lock().unwrap().forward(src, dst).to_owned();
    assert_eq!(path("192.168.1.20", "9.9.9.9"), "awg0");
    assert_eq!(path("192.168.1.20", "198.51.100.10"), "wan0");
    assert_eq!(path("192.168.1.20", "100.64.1.1"), "wan0");
    assert_eq!(path("192.168.1.21", "203.0.113.8"), "wan0");
    assert_eq!(path("192.168.2.21", "203.0.113.8"), "awg0");
    learn_answer(
        &db,
        &f,
        Answer {
            revision: 1,
            zone: 0,
            addresses: &["9.9.9.9".parse().unwrap()],
            qtype: 1,
            ttl: 900,
        },
        peer,
        || Ok(()),
    )
    .unwrap();
    assert_eq!(path("192.168.1.20", "9.9.9.9"), "wan0");
    assert_eq!(path("192.168.1.20", "9.9.9.10"), "awg0");
    let current = crate::policy::current(&nfqws2_awg_profile::read(&db).unwrap()).unwrap();
    let clients = crate::kernel::handoff::dns_clients(&f, &current).unwrap();
    let ip: IpAddr = "192.168.1.20".parse().unwrap();
    let client = clients.iter().find(|c| c.address == ip).unwrap();
    let check = |addr: &str, zone| {
        crate::kernel::handoff::check_destination(&db, &f, addr.parse().unwrap(), zone, client)
    };
    assert!(check("9.9.9.9", 0).is_ok());
    assert!(check("9.9.9.10", 1).is_ok());
    assert!(check("9.9.9.9", 1).is_err());
    action(&db, &f, Operation::Suspend, 12).unwrap();
    f.0.lock().unwrap().boot = "34343434-3434-3434-3434-343434343434".into();
    action(&db, &f, Operation::Recover, 13).unwrap();
    assert_eq!(path("192.168.1.20", "9.9.9.9"), "wan0");
    assert_eq!(path("192.168.1.20", "9.9.9.10"), "awg0");
    action(&db, &f, Operation::Teardown, 14).unwrap();
    let state = f.0.lock().unwrap();
    assert!(
        state.marked_stops.is_empty() && state.marked_scoped.is_empty() && !state.main_specific
    );
}
