use super::*;
use crate::kernel::routed_disable::{project, validate_draft, withdraw_fixture};
use nfqws2_awg_profile::NativeRemovalSeal;
use serde_json::json;

fn live_peer(cfg: &Value, _: &str) -> io::Result<LivePeer> {
    peer(cfg, "awg0").map(|mut sample| {
        sample.endpoint = cfg["endpoint"].as_str().unwrap().parse().unwrap();
        sample
    })
}

fn fixture() -> (tempfile::TempDir, Store, Fake, Journal, Value) {
    let (tmp, db, fake) = setup();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"]["killswitch"] = true.into();
        let rows = doc["servers"].as_array_mut().unwrap();
        let primary = &mut rows[0];
        primary["id"] = "first".into();
        primary["config"]["client"]["rust_managed"] = true.into();
        primary["config"]["install"] = "imported".into();
        primary["config"]["endpoint"] = "192.0.2.10:443".into();
        primary["config"]["routing"]["zones"][0]["ips"] = json!(["203.0.113.64/27"]);
        let mut other = primary.clone();
        other["id"] = "other".into();
        other["config"]["client_iface"] = "awg1".into();
        other["config"]["endpoint"] = "192.0.2.20:443".into();
        other["config"]["routing"]["zones"][0]["name"] = "other".into();
        other["config"]["routing"]["zones"][0]["ips"] = json!(["198.51.100.64/27"]);
        rows.push(other);
        doc["active_id"] = "first".into();
        Ok(())
    })
    .unwrap();
    for operation in [
        super::super::Operation::Apply,
        super::super::Operation::Commit,
    ] {
        super::super::operate(&db, &fake, operation, live_peer).unwrap();
    }
    let original = Journal::read(&db).unwrap();
    let doc = nfqws2_awg_profile::read(&db).unwrap();
    (tmp, db, fake, original, doc)
}

fn disable(doc: &mut Value, index: usize, server: bool) {
    let row = &mut doc["servers"][index]["config"];
    row["client"]["enabled"] = false.into();
    row["client"]["rust_managed"] = false.into();
    if server {
        row["enabled"] = false.into();
        row["routing"]["active"] = false.into();
    }
}

#[test]
fn routed_disable_projection_rejects_draft_overlap_and_out_of_plan_dependents() {
    let (_tmp, _db, _fake, original, mut draft) = fixture();
    disable(&mut draft, 0, false);
    let mut altered = draft.clone();
    altered["servers"][0]["config"]["routing"]["zones"][0]["ips"] = json!(["198.51.100.0/24"]);
    assert_eq!(
        validate_draft(&altered, &original.committed)
            .unwrap_err()
            .kind(),
        io::ErrorKind::Unsupported
    );
    let mut dependent = draft["servers"][0].clone();
    dependent["id"] = "off-plan".into();
    dependent["config"]["routing"]["zones"] = json!([]);
    dependent["config"]["client"]["double_tunnel_id"] = "first".into();
    draft["servers"].as_array_mut().unwrap().push(dependent);
    assert_eq!(
        project(&draft, &original.committed).unwrap_err().kind(),
        io::ErrorKind::Unsupported
    );
}

fn seal() -> NativeRemovalSeal {
    NativeRemovalSeal {
        id: "first".into(),
        iface: "awg0".into(),
        boot: BOOT.into(),
        pid: 9002,
        started: 17,
        receipt_sha256: [0x22; 32],
        nested: None,
    }
}

#[test]
fn routed_disable_commits_flags_after_fib_and_recovers_across_boot_and_a_new_draft() {
    for server in [false, true] {
        let (_tmp, db, fake, original, doc) = fixture();
        let active = doc["servers"][0]["config"]["routing"]["active"].clone();
        let observations = std::cell::Cell::new(0);
        let verify = || {
            assert_eq!(
                nfqws2_awg_profile::read(&db)?["servers"][0]["config"]["client"]["enabled"],
                true
            );
            observations.set(observations.get() + 1);
            Ok(())
        };
        withdraw_fixture(&db, &fake, Some(&seal()), &verify, |draft| {
            disable(draft, 0, server);
            Ok(())
        })
        .unwrap();
        assert_eq!(observations.get(), 2);
        let saved = nfqws2_awg_profile::read(&db).unwrap();
        assert_eq!(saved["servers"][0]["config"]["client"]["enabled"], false);
        assert_eq!(
            saved["servers"][0]["config"]["client"]["rust_managed"],
            false
        );
        assert_eq!(
            saved["servers"][0]["config"]["routing"]["active"],
            if server { json!(false) } else { active.clone() }
        );
        assert_eq!(saved["servers"][0]["config"]["enabled"], !server);
        let result = Journal::read(&db).unwrap();
        assert_eq!(result.committed, original.committed);
        assert!(!result.installed.targets.contains_key("awg0"));
        assert_eq!(
            fake.0
                .lock()
                .unwrap()
                .forward("192.168.1.2", "198.51.100.72"),
            "awg1"
        );
        assert_eq!(
            fake.0
                .lock()
                .unwrap()
                .forward("192.168.1.2", "203.0.113.72"),
            "wan0"
        );

        let writes = fake.0.lock().unwrap().changes;
        operate(&db, &fake, Operation::Refresh, |config, iface| {
            assert_eq!(iface, "awg1");
            live_peer(config, iface)
        })
        .unwrap();
        assert_eq!(fake.0.lock().unwrap().changes, writes);

        // Change the unconfirmed draft after disabling. Cold recovery still
        // uses the previous confirmed prefix and exact surviving TUN.
        nfqws2_awg_profile::edit_document(&db, |draft| {
            draft["routing_revision"] = 2.into();
            draft["servers"][1]["config"]["routing"]["zones"][0]["ips"] =
                json!(["198.51.100.200/32"]);
            Ok(())
        })
        .unwrap();
        *fake.0.lock().unwrap() = Firmware {
            boot: "33333333-3333-3333-3333-333333333333".into(),
            ..Default::default()
        };
        operate(&db, &fake, Operation::Recover, |config, iface| {
            assert_eq!(iface, "awg1");
            live_peer(config, iface)
        })
        .unwrap();
        assert_eq!(
            fake.0
                .lock()
                .unwrap()
                .forward("192.168.1.2", "198.51.100.72"),
            "awg1"
        );
        assert_eq!(
            fake.0
                .lock()
                .unwrap()
                .forward("192.168.1.2", "198.51.100.200"),
            "wan0"
        );
        assert_eq!(
            fake.0
                .lock()
                .unwrap()
                .forward("192.168.1.2", "203.0.113.72"),
            "wan0"
        );
        assert_eq!(
            nfqws2_awg_profile::read(&db).unwrap()["servers"][0]["config"]["routing"]["active"],
            if server { json!(false) } else { active }
        );
        assert_eq!(Journal::read(&db).unwrap().committed, original.committed);
    }
}

#[test]
fn routed_disable_failed_writer_never_saves_flags_and_foreign_receipt_is_rejected() {
    let (_tmp, db, fake, original, document) = fixture();
    let deny = NativeRemovalSeal { pid: 1, ..seal() };
    assert!(withdraw_fixture(
        &db,
        &fake,
        Some(&deny),
        &|| panic!("foreign seal"),
        |_| panic!("foreign seal")
    )
    .is_err());
    assert_eq!(Journal::read(&db).unwrap(), original);
    {
        let mut fw = fake.0.lock().unwrap();
        fw.fail_after = Some(fw.changes + 1);
    }
    assert!(
        withdraw_fixture(&db, &fake, Some(&seal()), &|| Ok(()), |draft| {
            disable(draft, 0, true);
            Ok(())
        })
        .is_err()
    );
    assert_eq!(Journal::read(&db).unwrap(), original);
    assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), document);
    assert_eq!(
        fake.0
            .lock()
            .unwrap()
            .forward("192.168.1.2", "203.0.113.72"),
        "awg0"
    );
    assert_eq!(
        fake.0
            .lock()
            .unwrap()
            .forward("192.168.1.2", "198.51.100.72"),
        "awg1"
    );
}

#[test]
fn routed_disable_rearm_keeps_unrelated_route_until_exact_peer_is_ready() {
    let (_tmp, db, fake, original, _) = fixture();
    withdraw_fixture(&db, &fake, Some(&seal()), &|| Ok(()), |draft| {
        disable(draft, 0, false);
        Ok(())
    })
    .unwrap();
    assert!(routed_profile_is_disabled(&db, Some("first")).unwrap());
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["config"]["client"]["enabled"] = true.into();
        doc["servers"][0]["config"]["client"]["rust_managed"] = true.into();
        Ok(())
    })
    .unwrap();
    let waiting = |cfg: &Value, iface: &str| {
        if iface == "awg0" {
            Err(io::ErrorKind::WouldBlock.into())
        } else {
            live_peer(cfg, iface)
        }
    };
    for _ in 0..2 {
        operate(&db, &fake, Operation::Refresh, waiting).unwrap();
        assert_eq!(
            fake.0
                .lock()
                .unwrap()
                .forward("192.168.1.2", "198.51.100.72"),
            "awg1"
        );
        assert_eq!(
            fake.0
                .lock()
                .unwrap()
                .forward("192.168.1.2", "203.0.113.72"),
            "blackhole"
        );
    }
    operate(&db, &fake, Operation::Refresh, live_peer).unwrap();
    assert_eq!(
        fake.0
            .lock()
            .unwrap()
            .forward("192.168.1.2", "203.0.113.72"),
        "awg0"
    );
    assert_eq!(Journal::read(&db).unwrap(), original);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires a no-NIC Linux guest and separate network/mount namespaces"]
fn routed_disable_withdraws_only_the_owned_real_fib_and_rearms_after_handshake() {
    // Guard every live shell action with the synthetic guest environment.
    assert!(std::path::Path::new("/synthetic-guest").is_file());
    for (kind, var) in [("net", "N2S_PARENT_NET"), ("mnt", "N2S_PARENT_MNT")] {
        let parent = std::env::var(var).unwrap();
        let current = std::fs::read_link(format!("/proc/self/ns/{kind}")).unwrap();
        assert!(parent.starts_with(&format!("{kind}:[")));
        assert_ne!(current.to_str(), Some(parent.as_str()));
    }

    // This guest exercises actual RPDB and FIB. Its legacy firewall is
    // modeled so no real netfilter compatibility module is required.
    struct RealFib(Fake);
    impl Runner for RealFib {
        fn run(&self, program: &str, args: &[&str], end: Instant) -> io::Result<String> {
            if matches!(program, "iptables" | "ip6tables" | "sh") {
                self.0.run(program, args, end)
            } else {
                nfqws2_router_command::System.run(program, args, end)
            }
        }
    }

    let (_tmp, db, fake, _, _) = fixture();
    db.transaction(|tx| tx.delete_runtime(RECEIPT)).unwrap();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc.as_object_mut().unwrap().remove("rust_static_routing");
        for row in doc["servers"].as_array_mut().unwrap() {
            row["config"]["routing"]["active"] = false.into();
        }
        doc["servers"][1]["config"]["routing"]["zones"][0]["ips"] = json!(["203.0.113.128/27"]);
        Ok(())
    })
    .unwrap();
    let run = RealFib(fake);
    run.0 .0.lock().unwrap().firewall.clear();
    let k = kernel(&run);
    let first = "203.0.113.72";
    let unrelated = "203.0.113.136";
    let device = |address: &str| -> Option<String> {
        let output = k.call("ip", &["-4", "route", "get", address]).ok()?;
        let mut words = output.split_ascii_whitespace();
        words.find(|word| *word == "dev")?;
        Some(words.next()?.into())
    };
    for op in [Operation::Apply, Operation::Commit] {
        operate(&db, &run, op, live_peer).unwrap();
    }
    assert_eq!(device(first).as_deref(), Some("awg0"));
    assert_eq!(device(unrelated).as_deref(), Some("awg1"));
    let owner = NativeRemovalSeal {
        boot: boot_id(&k).unwrap(),
        ..seal()
    };
    let mut count = 0;
    let observations = std::cell::Cell::new(Vec::new());
    withdraw_fixture(
        &db,
        &run,
        Some(&owner),
        &|| {
            let mut values = observations.take();
            values.push(device(first));
            assert_eq!(device(unrelated).as_deref(), Some("awg1"));
            observations.set(values);
            Ok(())
        },
        |doc| {
            count += 1;
            disable(doc, 0, false);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(count, 1);
    assert_eq!(
        observations.take(),
        [Some("awg0".into()), Some("wan0".into())]
    );
    assert_eq!(device(unrelated).as_deref(), Some("awg1"));
    k.call("ip", &["link", "set", "awg0", "down"]).unwrap();
    operate(&db, &run, Operation::Suspend, live_peer).unwrap();
    operate(&db, &run, Operation::Recover, |cfg, iface| {
        assert_eq!(iface, "awg1");
        live_peer(cfg, iface)
    })
    .unwrap();
    assert_eq!(device(first).as_deref(), Some("wan0"));
    assert_eq!(device(unrelated).as_deref(), Some("awg1"));
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["config"]["client"]["enabled"] = true.into();
        doc["servers"][0]["config"]["client"]["rust_managed"] = true.into();
        Ok(())
    })
    .unwrap();
    operate(&db, &run, Operation::Refresh, |cfg, iface| {
        if iface == "awg0" {
            Err(io::ErrorKind::WouldBlock.into())
        } else {
            live_peer(cfg, iface)
        }
    })
    .unwrap();
    assert!(device(first).is_none());
    assert_eq!(device(unrelated).as_deref(), Some("awg1"));
    k.call("ip", &["link", "set", "awg0", "up"]).unwrap();
    operate(&db, &run, Operation::Refresh, live_peer).unwrap();
    assert_eq!(device(first).as_deref(), Some("awg0"));
    assert_eq!(device(unrelated).as_deref(), Some("awg1"));
    operate(&db, &run, Operation::Teardown, live_peer).unwrap();
}

fn fixture_reserve(killswitch: bool) -> (tempfile::TempDir, Store, Fake) {
    let (temp, db, fake) = setup();
    for (address, endpoint) in [("198.18.95.4", "192.0.2.10"), ("198.18.95.5", "192.0.2.20")] {
        nfqws2_awg_profile::import(&db, &format!(
            "[Interface]\nPrivateKey = {KEY}\nAddress = {address}/32\nMTU = 1420\n\n[Peer]\nPublicKey = {KEY}\nEndpoint = {endpoint}:443\nAllowedIPs = 0.0.0.0/0\n"
        ), "fixture").unwrap();
    }
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"] = json!({"mode":"zones","killswitch":killswitch});
        let rows = doc["servers"].as_array_mut().unwrap();
        rows.remove(0);
        for (index, (id, prefix)) in [("first", "203.0.113.64/27"), ("other", "198.51.100.64/27")]
            .into_iter()
            .enumerate()
        {
            let row = &mut rows[index];
            row["id"] = id.into();
            row["config"]["client_iface"] = format!("awg{index}").into();
            row["config"]["client"]["enabled"] = true.into();
            row["config"]["client"]["rust_managed"] = true.into();
            row["config"]["routing"] = json!({"mode":"zones","active":true,"zones":[{
                "name":id, "enabled":true, "ips":[prefix],
                "fallback_tunnel_ids": if index == 0 { vec!["other"] } else { vec![] }
            }]});
        }
        doc["active_id"] = "first".into();
        Ok(())
    })
    .unwrap();
    (temp, db, fake)
}

fn confirm_reserve(db: &Store, run: &dyn Runner) -> Journal {
    for operation in [Operation::Apply, Operation::Commit] {
        operate(db, run, operation, live_peer).unwrap();
    }
    let confirmed = Journal::read(db).unwrap();
    assert_eq!(confirmed.committed.reserves.len(), 1);
    assert_eq!(confirmed.committed.targets.len(), 2);
    confirmed
}

fn reserve_sample(db: &Store, boot: &str) -> nfqws2_awg_profile::ActiveReplacementPeer {
    let doc = nfqws2_awg_profile::read(db).unwrap();
    nfqws2_awg_profile::ActiveReplacementPeer {
        owner: NativeRemovalSeal {
            id: "other".into(),
            iface: "awg1".into(),
            boot: boot.into(),
            pid: 9003,
            started: 18,
            receipt_sha256: [0x23; 32],
            nested: None,
        },
        fingerprint: nfqws2_awg_profile::active_replacement_fingerprint(&doc, "other").unwrap(),
        endpoint: "192.0.2.20:443".parse().unwrap(),
        socket_mark: 0,
        mtu: 1420,
        allowed: vec!["0.0.0.0/0".into()],
        underlay: None,
        nested_only: false,
    }
}

#[test]
fn routed_disable_transfers_to_independent_confirmed_reserve_and_rearms_without_gap() {
    use crate::kernel::routed_disable::withdraw_direct_reserve_fixture;
    let from = "192.168.1.2";
    let primary = "203.0.113.72";
    let independent = "198.51.100.72";
    for (server, killswitch) in [(false, false), (false, true), (true, false), (true, true)] {
        let (_temp, db, fake) = fixture_reserve(killswitch);
        let original = confirm_reserve(&db, &fake);
        let doc = nfqws2_awg_profile::read(&db).unwrap();
        fake.0.lock().unwrap().watch_flow = Some((from, primary));
        let proof = reserve_sample(&db, BOOT);
        let samples = std::cell::Cell::new(0);
        withdraw_direct_reserve_fixture(
            &db,
            &fake,
            &seal(),
            &|id| {
                assert_eq!(id, "other");
                assert_eq!(
                    nfqws2_awg_profile::read(&db)?["servers"][0]["config"]["client"]["enabled"],
                    true
                );
                samples.set(samples.get() + 1);
                Ok(proof.clone())
            },
            |draft| {
                disable(draft, 0, server);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(samples.get(), 3);
        let saved = nfqws2_awg_profile::read(&db).unwrap();
        assert_eq!(saved["servers"][1], doc["servers"][1]);
        assert_eq!(
            saved["servers"][0]["config"]["routing"]["zones"],
            doc["servers"][0]["config"]["routing"]["zones"]
        );
        assert_eq!(saved["servers"][0]["config"]["routing"]["active"], !server);
        assert_eq!(saved["servers"][0]["config"]["enabled"], !server);
        assert_eq!(saved["servers"][0]["config"]["client"]["enabled"], false);
        let result = Journal::read(&db).unwrap();
        assert_eq!(result.committed, original.committed);
        assert!(!result.installed.targets.contains_key("awg0"));
        let assert_reserve = |fake: &Fake| {
            let fw = fake.0.lock().unwrap();
            assert_eq!(fw.forward(from, primary), "awg1");
            assert_eq!(fw.forward(from, independent), "awg1");
            assert!(!fw.leaked);
        };
        assert_reserve(&fake);
        let survivor = |cfg: &Value, iface: &str| {
            assert_eq!(iface, "awg1");
            live_peer(cfg, iface)
        };
        operate(&db, &fake, Operation::Refresh, survivor).unwrap();
        assert_eq!(Journal::read(&db).unwrap(), result);
        assert_reserve(&fake);
        *fake.0.lock().unwrap() = Firmware {
            boot: "34343434-3434-3434-3434-343434343434".into(),
            ..Default::default()
        };
        operate(&db, &fake, Operation::Recover, survivor).unwrap();
        assert_reserve(&fake);
        nfqws2_awg_profile::edit_document(&db, |edit| {
            edit["servers"][0] = doc["servers"][0].clone();
            Ok(())
        })
        .unwrap();
        fake.0.lock().unwrap().watch_flow = Some((from, primary));
        operate(&db, &fake, Operation::Refresh, |cfg, iface| {
            if iface == "awg0" {
                Err(io::ErrorKind::WouldBlock.into())
            } else {
                live_peer(cfg, iface)
            }
        })
        .unwrap();
        assert_reserve(&fake);
        operate(&db, &fake, Operation::Refresh, live_peer).unwrap();
        let fw = fake.0.lock().unwrap();
        assert_eq!(fw.forward(from, primary), "awg0");
        assert_eq!(fw.forward(from, independent), "awg1");
        assert!(!fw.leaked);
    }
}

#[test]
fn routed_disable_never_publishes_when_reserve_proof_is_wrong_or_changes_after_fib() {
    use crate::kernel::routed_disable::withdraw_direct_reserve_fixture;
    for wrong in ["owner", "grant", "port", "after"] {
        let (_temp, db, fake) = fixture_reserve(false);
        let original = confirm_reserve(&db, &fake);
        let doc = nfqws2_awg_profile::read(&db).unwrap();
        fake.0.lock().unwrap().watch_flow = Some(("192.168.1.2", "203.0.113.72"));
        let proof = reserve_sample(&db, BOOT);
        let samples = std::cell::Cell::new(0);
        let result = withdraw_direct_reserve_fixture(
            &db,
            &fake,
            &seal(),
            &|_| {
                let mut witness = proof.clone();
                let seen = samples.get() + 1;
                samples.set(seen);
                match wrong {
                    "owner" => witness.owner.pid = seal().pid,
                    "grant" => witness.allowed = vec!["198.51.100.64/27".into()],
                    "port" => witness.endpoint.set_port(444),
                    "after" if seen == 3 => witness.owner.started += 1,
                    _ => (),
                }
                Ok(witness)
            },
            |draft| {
                disable(draft, 0, false);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(Journal::read(&db).unwrap(), original);
        assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), doc);
        let fw = fake.0.lock().unwrap();
        assert_eq!(fw.forward("192.168.1.2", "203.0.113.72"), "awg0");
        assert_eq!(fw.forward("192.168.1.2", "198.51.100.72"), "awg1");
        assert!(!fw.leaked);
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires a no-NIC Linux guest and separate network/mount namespaces"]
fn routed_disable_transfers_reserve_in_real_fib_without_dropping_the_live_lookup() {
    use crate::kernel::routed_disable::withdraw_direct_reserve_fixture;
    assert!(std::path::Path::new("/synthetic-guest").is_file());
    for (kind, var) in [("net", "N2S_PARENT_NET"), ("mnt", "N2S_PARENT_MNT")] {
        let parent = std::env::var(var).unwrap();
        let current = std::fs::read_link(format!("/proc/self/ns/{kind}")).unwrap();
        assert!(parent.starts_with(&format!("{kind}:[")));
        assert_ne!(current.to_str(), Some(parent.as_str()));
    }

    if std::env::var_os("N2S_R95_REAL_FIB").is_none() {
        return;
    }
    use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
    static SYSTEM: nfqws2_router_command::System = nfqws2_router_command::System;
    const PRIMARY: &str = "203.0.113.72";
    const OTHER: &str = "198.51.100.72";
    fn device(address: &str, end: Instant) -> io::Result<String> {
        let route = SYSTEM.run("ip", &["-4", "route", "get", address], end)?;
        route
            .split_ascii_whitespace()
            .skip_while(|word| *word != "dev")
            .nth(1)
            .map(str::to_owned)
            .ok_or_else(|| io::ErrorKind::InvalidData.into())
    }
    struct WatchFib {
        firewall: Fake,
        watching: AtomicBool,
        replaced: AtomicBool,
    }
    impl Runner for WatchFib {
        fn run(&self, command: &str, args: &[&str], end: Instant) -> io::Result<String> {
            let output = if matches!(command, "iptables" | "ip6tables" | "sh") {
                self.firewall.run(command, args, end)?
            } else {
                SYSTEM.run(command, args, end)?
            };
            if self.watching.load(Relaxed) {
                if args.starts_with(&["-4", "route", "replace"]) {
                    self.replaced.store(true, Relaxed);
                }
                assert_eq!(device(OTHER, end)?, "awg1");
                assert!(matches!(device(PRIMARY, end)?.as_str(), "awg0" | "awg1"));
            }
            Ok(output)
        }
    }
    for disable_server in [false, true] {
        let (_temp, db, firewall) = fixture_reserve(false);
        let run = WatchFib {
            firewall,
            watching: false.into(),
            replaced: false.into(),
        };
        let k = kernel(&run);
        let end = k.deadline;
        let confirmed = confirm_reserve(&db, &run);
        let boot = boot_id(&k).unwrap();
        let before = nfqws2_awg_profile::read(&db).unwrap();
        let owner = NativeRemovalSeal {
            boot: boot.clone(),
            ..seal()
        };
        let reserve = reserve_sample(&db, &boot);
        assert_eq!(device(PRIMARY, end).unwrap(), "awg0");
        assert_eq!(device(OTHER, end).unwrap(), "awg1");
        run.watching.store(true, Relaxed);
        withdraw_direct_reserve_fixture(&db, &run, &owner, &|_| Ok(reserve.clone()), |doc| {
            disable(doc, 0, disable_server);
            Ok(())
        })
        .unwrap();
        assert!(run.replaced.load(Relaxed));
        assert_eq!(device(PRIMARY, end).unwrap(), "awg1");
        assert_eq!(device(OTHER, end).unwrap(), "awg1");
        let saved = nfqws2_awg_profile::read(&db).unwrap();
        assert_eq!(saved["servers"][1], before["servers"][1]);
        assert_eq!(saved["servers"][0]["config"]["enabled"], !disable_server);
        assert_eq!(
            saved["servers"][0]["config"]["routing"]["active"],
            !disable_server
        );
        assert_eq!(saved["servers"][0]["config"]["client"]["enabled"], false);
        assert_eq!(
            saved["rust_static_routing"]["active_reserves"],
            json!(["other"])
        );
        assert_eq!(Journal::read(&db).unwrap().committed, confirmed.committed);
        k.call("ip", &["link", "set", "awg0", "down"]).unwrap();
        operate(&db, &run, Operation::Refresh, |config, iface| {
            assert_eq!(iface, "awg1");
            live_peer(config, iface)
        })
        .unwrap();
        assert_eq!(device(PRIMARY, end).unwrap(), "awg1");
        run.watching.store(false, Relaxed);
        operate(&db, &run, Operation::Teardown, live_peer).unwrap();
        k.call("ip", &["link", "set", "awg0", "up"]).unwrap();
    }
}

#[test]
fn routed_disable_restores_only_authenticated_old_paths_after_persistent_reserve_loss() {
    use crate::kernel::routed_disable::withdraw_direct_reserve_fixture;
    let (_temp, db, fake) = fixture_reserve(true);
    let original = confirm_reserve(&db, &fake);
    let before = nfqws2_awg_profile::read(&db).unwrap();
    let proof = reserve_sample(&db, BOOT);
    let observations = std::cell::Cell::new(0);
    fake.0.lock().unwrap().watch_flow = Some(("192.168.1.2", "203.0.113.72"));
    let result = withdraw_direct_reserve_fixture(
        &db,
        &fake,
        &seal(),
        &|_| {
            observations.set(observations.get() + 1);
            if observations.get() >= 3 {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            Ok(proof.clone())
        },
        |doc| {
            disable(doc, 0, false);
            Ok(())
        },
    );
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
    let after = Journal::read(&db).unwrap();
    assert_eq!(after.committed, original.committed);
    assert_eq!(
        nfqws2_awg_profile::read(&db).unwrap()["servers"],
        before["servers"]
    );
    {
        let fw = fake.0.lock().unwrap();
        assert_eq!(fw.forward("192.168.1.2", "203.0.113.72"), "awg0");
        assert_eq!(fw.forward("192.168.1.2", "198.51.100.72"), "blackhole");
        assert!(!fw.leaked);
    }
    operate(&db, &fake, Operation::Refresh, live_peer).unwrap();
    assert_eq!(Journal::read(&db).unwrap(), original);
}

fn fixture_selected_reserve(killswitch: bool) -> (tempfile::TempDir, Store, Fake) {
    let (temp, db, fake) = fixture_reserve(killswitch);
    nfqws2_awg_profile::import(&db, &format!(
        "[Interface]\nPrivateKey = {KEY}\nAddress = 198.18.96.6/32\nMTU = 1420\n\n[Peer]\nPublicKey = {KEY}\nEndpoint = 192.0.2.21:443\nAllowedIPs = 0.0.0.0/0\n"
    ), "fixture").unwrap();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let rows = doc["servers"].as_array_mut().unwrap();
        rows[0]["config"]["routing"]["zones"][0]["fallback_tunnel_ids"] = json!(["other", "next"]);
        rows[2]["id"] = "next".into();
        rows[2]["config"]["client_iface"] = "awg2".into();
        rows[2]["config"]["client"]["enabled"] = true.into();
        rows[2]["config"]["client"]["rust_managed"] = true.into();
        rows[2]["config"]["routing"] = json!({"mode":"zones","active":true,"zones":[{
            "name":"next-own","enabled":true,"ips":["203.0.113.160/27"]
        }]});
        doc["active_id"] = "other".into();
        Ok(())
    })
    .unwrap();
    (temp, db, fake)
}

fn primary_offline(cfg: &Value, iface: &str) -> io::Result<LivePeer> {
    if iface == "awg0" {
        Err(io::ErrorKind::WouldBlock.into())
    } else {
        live_peer(cfg, iface)
    }
}

fn selected_first(db: &Store, run: &dyn Runner) -> Journal {
    for operation in [Operation::Apply, Operation::Commit] {
        operate(db, run, operation, live_peer).unwrap();
    }
    operate(db, run, Operation::Refresh, primary_offline).unwrap();
    let confirmed = Journal::read(db).unwrap();
    assert_eq!(confirmed.committed.reserves.len(), 1);
    assert_eq!(confirmed.committed.targets.len(), 3);
    assert_eq!(
        confirmed.installed.active_reserves(),
        std::collections::BTreeSet::from(["other"])
    );
    confirmed
}

fn next_witness(db: &Store, boot: &str) -> nfqws2_awg_profile::ActiveReplacementPeer {
    let doc = nfqws2_awg_profile::read(db).unwrap();
    let mut observed = reserve_sample(db, boot);
    observed.owner.id = "next".into();
    observed.owner.iface = "awg2".into();
    observed.owner.pid += 1;
    observed.owner.receipt_sha256 = [0x24; 32];
    observed.endpoint.set_ip("192.0.2.21".parse().unwrap());
    observed.fingerprint =
        nfqws2_awg_profile::active_replacement_fingerprint(&doc, "next").unwrap();
    observed
}

fn outage(boot: &str) -> nfqws2_awg_profile::RoutedDirectOutage {
    nfqws2_awg_profile::RoutedDirectOutage {
        owner: NativeRemovalSeal {
            boot: boot.into(),
            ..seal()
        },
        endpoint: "192.0.2.10:443".parse().unwrap(),
        socket_mark: 0,
        mtu: 1420,
    }
}

#[test]
fn routed_disable_selected_reserve_hands_over_only_covered_flows_to_next_choice() {
    use crate::kernel::routed_disable::withdraw_selected_reserve_fixture;
    const SOURCE: &str = "192.168.1.2";
    const MOVED: &str = "203.0.113.72";
    const REMOVED: &str = "198.51.100.72";
    const KEPT: &str = "203.0.113.168";
    for server in [false, true] {
        let (_tmp, db, fake) = fixture_selected_reserve(false);
        let before = selected_first(&db, &fake);
        let doc = nfqws2_awg_profile::read(&db).unwrap();
        let first = reserve_sample(&db, BOOT);
        let next = next_witness(&db, BOOT);
        let unavailable = outage(BOOT);
        fake.0.lock().unwrap().watch_flow = Some((SOURCE, MOVED));
        let seen = std::cell::Cell::new(0);
        withdraw_selected_reserve_fixture(
            &db,
            &fake,
            &first.owner,
            &|id| {
                assert_eq!(id, "next");
                Ok(next.clone())
            },
            &|id| {
                assert_eq!(id, "first");
                seen.set(seen.get() + 1);
                Ok(unavailable.clone())
            },
            |draft| {
                disable(draft, 1, server);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(seen.get(), 3);
        let after = Journal::read(&db).unwrap();
        assert_eq!(after.committed, before.committed);
        assert!(!after.installed.targets.contains_key("awg1"));
        let saved = nfqws2_awg_profile::read(&db).unwrap();
        assert_eq!(saved["servers"][0], doc["servers"][0]);
        assert_eq!(saved["servers"][2], doc["servers"][2]);
        assert_eq!(saved["servers"][1]["config"]["enabled"], !server);
        assert_eq!(saved["servers"][1]["config"]["routing"]["active"], !server);
        assert_eq!(saved["servers"][1]["config"]["client"]["enabled"], false);
        assert_eq!(
            saved["rust_static_routing"]["active_reserves"],
            json!(["next"])
        );
        assert_eq!(
            saved["rust_static_routing"]["reserve_chains"]["first"],
            json!([["other", "next"]])
        );
        let assert_routes = |expected| {
            let fw = fake.0.lock().unwrap();
            assert_eq!(fw.forward(SOURCE, MOVED), expected);
            assert_eq!(fw.forward(SOURCE, REMOVED), "wan0");
            assert_eq!(fw.forward(SOURCE, KEPT), "awg2");
            assert!(!fw.leaked);
        };
        assert_routes("awg2");
        operate(&db, &fake, Operation::Refresh, primary_offline).unwrap();
        assert_eq!(Journal::read(&db).unwrap(), after);
        *fake.0.lock().unwrap() = Firmware {
            boot: "35353535-3535-3535-3535-353535353535".into(),
            ..Default::default()
        };
        operate(&db, &fake, Operation::Recover, primary_offline).unwrap();
        assert_routes("awg2");
        operate(&db, &fake, Operation::Refresh, live_peer).unwrap();
        assert_routes("awg0");
    }
}

#[test]
fn routed_disable_selected_reserve_rejects_wrong_outage_and_unattested_next() {
    use crate::kernel::routed_disable::withdraw_selected_reserve_fixture;
    for trouble in [
        "primary recovered",
        "foreign primary",
        "no next",
        "wrong next grant",
        "status changed",
    ] {
        let (_temp, db, fake) = fixture_selected_reserve(false);
        let before = selected_first(&db, &fake);
        let doc = nfqws2_awg_profile::read(&db).unwrap();
        let first = reserve_sample(&db, BOOT);
        let mut next = next_witness(&db, BOOT);
        let mut unavailable = outage(BOOT);
        if trouble == "foreign primary" {
            unavailable.owner.receipt_sha256 = next.owner.receipt_sha256;
        }
        if trouble == "wrong next grant" {
            next.allowed = vec!["203.0.113.160/27".into()];
        }
        let reads = std::cell::Cell::new(0);
        let result = withdraw_selected_reserve_fixture(
            &db,
            &fake,
            &first.owner,
            &|_| {
                if trouble == "no next" {
                    Err(io::ErrorKind::WouldBlock.into())
                } else {
                    Ok(next.clone())
                }
            },
            &|_| {
                reads.set(reads.get() + 1);
                if trouble == "primary recovered" || trouble == "status changed" && reads.get() == 3
                {
                    Err(io::ErrorKind::WouldBlock.into())
                } else {
                    Ok(unavailable.clone())
                }
            },
            |draft| {
                disable(draft, 1, false);
                Ok(())
            },
        );
        assert!(result.is_err(), "{trouble}");
        assert_eq!(Journal::read(&db).unwrap(), before, "{trouble}");
        assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), doc, "{trouble}");
        let fw = fake.0.lock().unwrap();
        assert_eq!(fw.forward("192.168.1.2", "203.0.113.72"), "awg1");
        assert_eq!(fw.forward("192.168.1.2", "198.51.100.72"), "awg1");
        assert_eq!(fw.forward("192.168.1.2", "203.0.113.168"), "awg2");
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires a no-NIC Linux guest and separate network/mount namespaces"]
fn routed_disable_selected_reserve_keeps_real_fib_for_second_choice() {
    verify_selected_reserve_real_fib(None, "N2S_R96_REAL_FIB");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires a no-NIC Linux guest and separate network/mount namespaces"]
fn routed_disable_selected_standby_keeps_real_fib_for_second_choice() {
    verify_selected_reserve_real_fib(Some(StandbyPlacement::Connection), "N2S_R97_REAL_FIB");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires a no-NIC Linux guest and separate network/mount namespaces"]
fn routed_disable_selected_zone_standby_keeps_real_fib_for_second_choice() {
    verify_selected_reserve_real_fib(Some(StandbyPlacement::Zone), "N2S_R98_REAL_FIB");
}

#[cfg(target_os = "linux")]
fn verify_selected_reserve_real_fib(standby: Option<StandbyPlacement>, enable: &str) {
    use crate::kernel::routed_disable::withdraw_selected_reserve_fixture;
    use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
    assert!(std::path::Path::new("/synthetic-guest").is_file());
    for (kind, var) in [("net", "N2S_PARENT_NET"), ("mnt", "N2S_PARENT_MNT")] {
        let parent = std::env::var(var).unwrap();
        let current = std::fs::read_link(format!("/proc/self/ns/{kind}")).unwrap();
        assert!(parent.starts_with(&format!("{kind}:[")));
        assert_ne!(current.to_str(), Some(parent.as_str()));
    }
    if std::env::var_os(enable).is_none() {
        return;
    }
    static SYSTEM: nfqws2_router_command::System = nfqws2_router_command::System;
    const MOVED: &str = "203.0.113.72";
    const REMOVED: &str = "198.51.100.72";
    const KEPT: &str = "203.0.113.168";
    fn device(destination: &str, until: Instant) -> io::Result<String> {
        let record = SYSTEM.run("ip", &["-4", "route", "get", destination], until)?;
        record
            .split_ascii_whitespace()
            .skip_while(|part| *part != "dev")
            .nth(1)
            .map(str::to_owned)
            .ok_or_else(|| io::ErrorKind::InvalidData.into())
    }
    struct Physical {
        firewall: Fake,
        watch: AtomicBool,
        replaced: AtomicBool,
        withdrawn: AtomicBool,
    }
    impl Runner for Physical {
        fn run(&self, program: &str, args: &[&str], until: Instant) -> io::Result<String> {
            let output = if matches!(program, "iptables" | "ip6tables" | "sh") {
                self.firewall.run(program, args, until)?
            } else {
                SYSTEM.run(program, args, until)?
            };
            if self.watch.load(Relaxed) {
                if args.starts_with(&["-4", "route", "replace"])
                    && args.contains(&"203.0.113.64/27")
                {
                    self.replaced.store(true, Relaxed);
                }
                if args.starts_with(&["-4", "route", "del"]) && args.contains(&"198.51.100.64/27") {
                    self.withdrawn.store(true, Relaxed);
                }
                assert!(matches!(device(MOVED, until)?.as_str(), "awg1" | "awg2"));
                assert_eq!(device(KEPT, until)?, "awg2");
            }
            Ok(output)
        }
    }
    for server in [false, true] {
        let (_temp, db, firewall) = if let Some(placement) = standby {
            fixture_selected_standby(placement)
        } else {
            fixture_selected_reserve(false)
        };
        let run = Physical {
            firewall,
            watch: false.into(),
            replaced: false.into(),
            withdrawn: false.into(),
        };
        let k = kernel(&run);
        let deadline = k.deadline;
        let before = selected_first(&db, &run);
        if let Some(placement) = standby {
            let saved = nfqws2_awg_profile::read(&db).unwrap();
            assert_eq!(
                saved["servers"][1]["config"]["routing"]["active"],
                placement.explicit_zone()
            );
        }
        let boot = boot_id(&k).unwrap();
        let retiring = reserve_sample(&db, &boot);
        let retained = next_witness(&db, &boot);
        assert_eq!(device(MOVED, deadline).unwrap(), "awg1");
        assert_eq!(
            device(REMOVED, deadline).unwrap(),
            if standby.is_some() { "wan0" } else { "awg1" }
        );
        assert_eq!(device(KEPT, deadline).unwrap(), "awg2");
        run.watch.store(true, Relaxed);
        withdraw_selected_reserve_fixture(
            &db,
            &run,
            &retiring.owner,
            &|_| Ok(retained.clone()),
            &|_| Ok(outage(&boot)),
            |doc| {
                disable(doc, 1, server);
                Ok(())
            },
        )
        .unwrap();
        assert!(run.replaced.load(Relaxed));
        assert_eq!(run.withdrawn.load(Relaxed), standby.is_none());
        assert_eq!(device(MOVED, deadline).unwrap(), "awg2");
        assert_eq!(device(REMOVED, deadline).unwrap(), "wan0");
        assert_eq!(device(KEPT, deadline).unwrap(), "awg2");
        assert_eq!(Journal::read(&db).unwrap().committed, before.committed);
        if let Some(placement) = standby {
            let saved = nfqws2_awg_profile::read(&db).unwrap();
            assert_eq!(
                saved["servers"][1]["config"]["routing"]["active"],
                placement.explicit_zone() && !server
            );
            assert_eq!(saved["servers"][1]["config"]["client"]["enabled"], false);
            assert_eq!(saved["servers"][1]["config"]["enabled"], !server);
        }
        k.call("ip", &["link", "set", "awg1", "down"]).unwrap();
        operate(&db, &run, Operation::Refresh, primary_offline).unwrap();
        assert_eq!(device(MOVED, deadline).unwrap(), "awg2");
        run.watch.store(false, Relaxed);
        operate(&db, &run, Operation::Teardown, primary_offline).unwrap();
        k.call("ip", &["link", "set", "awg1", "up"]).unwrap();
    }
}

#[derive(Clone, Copy, PartialEq)]
enum StandbyPlacement {
    Connection,
    Zone,
    Both,
}

impl StandbyPlacement {
    fn explicit_zone(self) -> bool {
        self != Self::Connection
    }
}

fn fixture_selected_standby(placement: StandbyPlacement) -> (tempfile::TempDir, Store, Fake) {
    let (temp, db, fake) = fixture_selected_reserve(false);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let rows = doc["servers"].as_array_mut().unwrap();
        if placement != StandbyPlacement::Zone {
            rows[0]["config"]["client"]["fallback_tunnel_ids"] = json!(["other", "next"]);
        }
        if !placement.explicit_zone() {
            rows[0]["config"]["routing"]["zones"][0]["fallback_tunnel_ids"] = json!([]);
        }
        rows[1]["config"]["client"]["standby"] = true.into();
        rows[1]["config"]["routing"]["active"] = false.into();
        rows[1]["config"]["routing"]["zones"] = json!([]);
        Ok(())
    })
    .unwrap();
    (temp, db, fake)
}

#[test]
fn routed_disable_selected_standby_keeps_confirmed_connection_order_and_second_reserve() {
    use crate::kernel::routed_disable::withdraw_selected_reserve_fixture;
    for server in [false, true] {
        for placement in [
            StandbyPlacement::Connection,
            StandbyPlacement::Zone,
            StandbyPlacement::Both,
        ] {
            let (_tmp, db, fake) = fixture_selected_standby(placement);
            let explicit_zone_fallback = placement.explicit_zone();
            let before = selected_first(&db, &fake);
            let doc = nfqws2_awg_profile::read(&db).unwrap();
            assert_eq!(
                doc["servers"][1]["config"]["routing"]["active"],
                explicit_zone_fallback
            );
            let retiring = reserve_sample(&db, BOOT);
            let retained = next_witness(&db, BOOT);
            fake.0.lock().unwrap().watch_flow = Some(("192.168.1.2", "203.0.113.72"));
            withdraw_selected_reserve_fixture(
                &db,
                &fake,
                &retiring.owner,
                &|_| Ok(retained.clone()),
                &|_| Ok(outage(BOOT)),
                |doc| {
                    disable(doc, 1, server);
                    Ok(())
                },
            )
            .unwrap();
            let after = Journal::read(&db).unwrap();
            assert_eq!(after.committed, before.committed);
            assert_eq!(after.installed.targets.len(), 2);
            assert!(!after.installed.targets.contains_key("awg1"));
            let saved = nfqws2_awg_profile::read(&db).unwrap();
            assert_eq!(saved["servers"][0], doc["servers"][0]);
            assert_eq!(saved["servers"][2], doc["servers"][2]);
            assert_eq!(saved["servers"][1]["config"]["client"]["standby"], true);
            assert_eq!(saved["servers"][1]["config"]["client"]["enabled"], false);
            assert_eq!(
                saved["servers"][1]["config"]["routing"]["active"],
                explicit_zone_fallback && !server
            );
            assert_eq!(saved["servers"][1]["config"]["enabled"], !server);
            assert_eq!(
                saved["rust_static_routing"]["active_reserves"],
                json!(["next"])
            );
            let check = || {
                let live = fake.0.lock().unwrap();
                assert_eq!(live.forward("192.168.1.2", "203.0.113.72"), "awg2");
                assert_eq!(live.forward("192.168.1.2", "203.0.113.168"), "awg2");
                assert_eq!(live.forward("192.168.1.2", "198.51.100.72"), "wan0");
                assert!(!live.leaked);
            };
            check();
            operate(&db, &fake, Operation::Refresh, primary_offline).unwrap();
            assert_eq!(Journal::read(&db).unwrap(), after);
            if placement == StandbyPlacement::Zone {
                nfqws2_awg_profile::edit_document(&db, |draft| {
                    draft["routing_revision"] = 2.into();
                    draft["servers"][0]["config"]["routing"]["zones"][0]["fallback_tunnel_ids"] =
                        json!(["next", "other"]);
                    Ok(())
                })
                .unwrap();
            }
            *fake.0.lock().unwrap() = Firmware {
                boot: "36363636-3636-3636-3636-363636363636".into(),
                ..Default::default()
            };
            operate(&db, &fake, Operation::Recover, |cfg, iface| {
                assert_ne!(iface, "awg1");
                primary_offline(cfg, iface)
            })
            .unwrap();
            check();
            assert_eq!(Journal::read(&db).unwrap().committed, before.committed);
        }
    }
}

#[test]
fn routed_disable_selected_standby_rejects_unrelated_demand_or_unconfirmed_parent_order() {
    use crate::kernel::routed_disable::withdraw_selected_reserve_fixture;
    for drift in ["other dependent", "connection order", "zone order"] {
        let placement = if drift == "zone order" {
            StandbyPlacement::Zone
        } else {
            StandbyPlacement::Both
        };
        let (_tmp, db, fake) = fixture_selected_standby(placement);
        let before = selected_first(&db, &fake);
        let retiring = reserve_sample(&db, BOOT);
        nfqws2_awg_profile::edit_document(&db, |doc| {
            let rows = doc["servers"].as_array_mut().unwrap();
            if drift == "other dependent" {
                let mut other = rows[1].clone();
                other["id"] = "other-demand".into();
                other["config"]["client_iface"] = "awg3".into();
                other["config"]["routing"]["active"] = false.into();
                other["config"]["client"]["fallback_tunnel_ids"] = json!(["other"]);
                rows.push(other);
            } else if drift == "connection order" {
                rows[0]["config"]["client"]["fallback_tunnel_ids"] = json!(["next", "other"]);
            } else {
                rows[0]["config"]["routing"]["zones"][0]["fallback_tunnel_ids"] =
                    json!(["next", "other"]);
            }
            Ok(())
        })
        .unwrap();
        let unchanged = nfqws2_awg_profile::read(&db).unwrap();
        let writes = fake.0.lock().unwrap().changes;
        let result = withdraw_selected_reserve_fixture(
            &db,
            &fake,
            &retiring.owner,
            &|_| panic!("unconfirmed graph"),
            &|_| panic!("unconfirmed graph"),
            |doc| {
                disable(doc, 1, false);
                Ok(())
            },
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
        assert_eq!(Journal::read(&db).unwrap(), before);
        assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), unchanged);
        assert_eq!(fake.0.lock().unwrap().changes, writes);
    }
}
