#[cfg(target_os = "linux")]
use super::packed::Router;
use super::{packed::marked_recovery::ProtectedRouter, *};
use crate::kernel::routed_disable::{
    routed_profile_is_disabled, withdraw_fixture, withdraw_mixed_direct_fixture,
};
use nfqws2_awg_profile::{
    NativeNestedRemovalScope, NativeRemovalSeal, RoutedMtuPeer, RoutedNestedTransport,
    RoutedPermanentHold,
};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

const NESTED_IP: &str = "203.0.113.10";
const OUTER_SOURCE: &str = "198.18.93.2";
const INNER_DST: &str = "203.0.113.72";
const DIRECT_DST: &str = "203.0.113.136";

fn fixture() -> (tempfile::TempDir, Store) {
    let (dir, db, _) = setup();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"] = json!({"mode":"zones"});
        let rows = doc["servers"].as_array_mut().unwrap();
        let inner = &mut rows[0];
        inner["id"] = "inner".into();
        inner["config"]["install"] = "imported".into();
        inner["config"]["endpoint"] = format!("{NESTED_IP}:443").into();
        inner["config"]["mtu"] = 1420.into();
        inner["config"]["client"]["rust_managed"] = true.into();
        inner["config"]["routing"] = json!({
            "mode":"zones","zones":[{"name":"inner","enabled":true,"ips":["203.0.113.64/27"]}]
        });
        let mut direct = inner.clone();
        direct["id"] = "direct".into();
        direct["config"]["endpoint"] = "192.0.2.45:443".into();
        direct["config"]["client_iface"] = "awg1".into();
        direct["config"]["routing"] = json!({
            "mode":"zones","zones":[{"name":"direct","enabled":true,"ips":["203.0.113.128/27"]}]
        });
        let mut outer = direct.clone();
        outer["id"] = "outer".into();
        outer["config"]["endpoint"] = "192.0.2.44:443".into();
        outer["config"]["client_iface"] = "awg2".into();
        outer["config"]["routing"] = json!({"mode":"off"});
        inner["config"]["client"]["double_tunnel_mode"] = "permanent".into();
        inner["config"]["client"]["double_tunnel_id"] = "outer".into();
        rows.extend([direct, outer]);
        doc["active_id"] = "inner".into();
        Ok(())
    })
    .unwrap();
    (dir, db)
}

fn live(cfg: &Value, iface: &str) -> io::Result<LivePeer> {
    let mut peer = peer(cfg, "awg0")?;
    peer.endpoint = cfg["endpoint"].as_str().unwrap().parse().unwrap();
    if iface == "awg0" {
        peer.socket_mark = 0xa0000000;
        peer.nested_mtu = Some(1290);
        peer.nested_transport = Some(RoutedNestedTransport {
            peer: RoutedMtuPeer {
                iface: iface.into(),
                outer_id: "outer".into(),
                outer_iface: "awg2".into(),
                endpoint: peer.endpoint,
                socket_mark: peer.socket_mark,
                effective_mtu: 1290,
            },
            outer_endpoint: "192.0.2.44:443".parse().unwrap(),
        });
    } else {
        assert_eq!(iface, "awg1");
    }
    Ok(peer)
}

fn seal(boot: &str) -> NativeRemovalSeal {
    NativeRemovalSeal {
        id: "inner".into(),
        iface: "awg0".into(),
        boot: boot.into(),
        pid: 9300,
        started: 50,
        receipt_sha256: [0x93; 32],
        nested: Some(NativeNestedRemovalScope {
            outer_iface: "awg2".into(),
            endpoint: NESTED_IP.parse().unwrap(),
            source: OUTER_SOURCE.parse().unwrap(),
        }),
    }
}

fn prepare(db: &Store, run: &dyn Runner) -> Journal {
    for operation in [Operation::Apply, Operation::Commit] {
        operate(db, run, operation, live).unwrap();
    }
    Journal::read(db).unwrap()
}

fn disable(doc: &mut Value, server: bool) {
    let cfg = &mut doc["servers"][0]["config"];
    cfg["client"]["enabled"] = false.into();
    cfg["client"]["rust_managed"] = false.into();
    if server {
        cfg["enabled"] = false.into();
        cfg["routing"]["active"] = false.into();
    }
}

#[derive(Default)]
struct MixedModel {
    router: ProtectedRouter,
    nested: AtomicBool,
    without_plain_path: AtomicBool,
}

impl Runner for MixedModel {
    fn run(&self, command: &str, args: &[&str], end: Instant) -> io::Result<String> {
        if command == "ip" {
            if args == ["-4", "route", "get", NESTED_IP, "mark", "0xa0000000"] {
                return if self.nested.load(Relaxed) {
                    Ok(format!("{NESTED_IP} dev awg2 table 828 src {OUTER_SOURCE}"))
                } else {
                    Err(io::ErrorKind::NotFound.into())
                };
            }
            if args == ["-4", "route", "get", NESTED_IP] && self.without_plain_path.load(Relaxed) {
                return Err(io::ErrorKind::NotFound.into());
            }
        }
        let mut output = self.router.run(command, args, end)?;
        if command == "ip"
            && args == ["-o", "-N", "-4", "rule", "show"]
            && self.nested.load(Relaxed)
        {
            output.push_str("\n60: from all fwmark 0xa0000000 lookup 828\n61: from all fwmark 0xa0000000 prohibit\n");
        }
        Ok(output)
    }

    fn run_input(
        &self,
        command: &str,
        args: &[&str],
        input: &[u8],
        end: Instant,
    ) -> io::Result<String> {
        self.router.run_input(command, args, input, end)
    }
}

#[test]
fn routed_mixed_disable_keeps_direct_slot_through_compensation_and_reboot() {
    for server in [false, true] {
        let (_dir, db) = fixture();
        let run = MixedModel::default();
        run.nested.store(true, Relaxed);
        let old = prepare(&db, &run);
        let direct_slot = old.installed.marks["awg1"];
        let marked_direct = format!("{:#x}", 0x10000000 | (u32::from(direct_slot) << 20));
        let owner = seal(&old.boot);
        let src = "10.19.0.1";
        let direct_before = run.router.router.packet_mark(src, DIRECT_DST);
        assert!(direct_before.is_some());
        assert!(run.router.router.packet_mark(src, INNER_DST).is_some());
        let before = nfqws2_awg_profile::read(&db).unwrap();
        run.router.router.fail_switch.store(true, Relaxed);
        assert!(
            withdraw_fixture(&db, &run, Some(&owner), &|| Ok(()), |doc| {
                disable(doc, server);
                Ok(())
            })
            .is_err()
        );
        assert_eq!(Journal::read(&db).unwrap(), old);
        assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), before);
        assert_eq!(
            run.router.router.packet_mark(src, DIRECT_DST),
            direct_before
        );

        withdraw_fixture(
            &db,
            &run,
            Some(&owner),
            &|| {
                assert_eq!(
                    run.router.router.packet_mark(src, DIRECT_DST),
                    direct_before
                );
                Ok(())
            },
            |doc| {
                disable(doc, server);
                Ok(())
            },
        )
        .unwrap();
        run.nested.store(false, Relaxed);
        let after = Journal::read(&db).unwrap();
        assert_eq!(after.committed, old.committed);
        assert_eq!(after.installed.marks.keys().collect::<Vec<_>>(), ["awg1"]);
        assert_eq!(after.installed.marks["awg1"], direct_slot);
        assert!(run.router.router.packet_mark(src, INNER_DST).is_none());
        assert_eq!(
            run.router.router.packet_mark(src, DIRECT_DST),
            direct_before
        );
        assert!(run
            .run(
                "ip",
                &["-4", "route", "get", DIRECT_DST, "mark", &marked_direct],
                Instant::now()
            )
            .unwrap()
            .contains("dev awg1"));
        let saved = nfqws2_awg_profile::read(&db).unwrap();
        assert_eq!(saved["servers"][0]["config"]["routing"]["active"], !server);
        assert_eq!(saved["servers"][0]["config"]["enabled"], !server);
        assert_eq!(saved["servers"][1], before["servers"][1]);
        assert_eq!(saved["servers"][2], before["servers"][2]);
        assert!(routed_profile_is_disabled(&db, Some("inner")).unwrap());

        // A dormant sole literal may lose its unrelated plain WAN after
        // native retirement. The activated destination set still excludes it.
        let reboot = MixedModel::default();
        reboot.router.router.ip.0.lock().unwrap().boot =
            "93939393-9393-9393-9393-939393939393".into();
        reboot.without_plain_path.store(true, Relaxed);
        operate(&db, &reboot, Operation::Recover, |cfg, iface| {
            assert_eq!(iface, "awg1");
            live(cfg, iface)
        })
        .unwrap();
        assert_eq!(
            Journal::read(&db).unwrap().installed.marks["awg1"],
            direct_slot
        );
        assert!(reboot.router.router.packet_mark(src, INNER_DST).is_none());
        assert_eq!(
            reboot.router.router.packet_mark(src, DIRECT_DST),
            direct_before
        );
        if !server {
            // A matching authenticated live direct claim still has to pass
            // the ordinary WAN guard even if the retired inner owned its raw spelling.
            assert!(operate(&db, &reboot, Operation::Refresh, |cfg, iface| {
                let mut result = live(cfg, iface)?;
                result.endpoint = format!("{NESTED_IP}:444").parse().unwrap();
                Ok(result)
            })
            .is_err());
            assert_eq!(
                reboot.router.router.packet_mark(src, DIRECT_DST),
                direct_before
            );
        }
    }
}

fn direct_seal(boot: &str) -> NativeRemovalSeal {
    NativeRemovalSeal {
        id: "direct".into(),
        iface: "awg1".into(),
        pid: 9301,
        receipt_sha256: [0x94; 32],
        nested: None,
        ..seal(boot)
    }
}

fn retained(boot: &str) -> RoutedPermanentHold {
    RoutedPermanentHold {
        owner: seal(boot),
        outer_owner: NativeRemovalSeal {
            id: "outer".into(),
            iface: "awg2".into(),
            pid: 9302,
            receipt_sha256: [0x95; 32],
            nested: None,
            ..seal(boot)
        },
        endpoint: format!("{NESTED_IP}:443").parse().unwrap(),
        outer_endpoint: "192.0.2.44:443".parse().unwrap(),
        effective_mtu: 1290,
    }
}

fn disable_direct(doc: &mut Value, server: bool) {
    let cfg = &mut doc["servers"][1]["config"];
    cfg["client"]["enabled"] = false.into();
    cfg["client"]["rust_managed"] = false.into();
    if server {
        cfg["enabled"] = false.into();
        cfg["routing"]["active"] = false.into();
    }
}

#[test]
fn routed_mixed_direct_disable_requires_exact_retained_transport_when_plain_wan_is_absent() {
    for server in [false, true] {
        let (_dir, db) = fixture();
        let run = MixedModel::default();
        run.nested.store(true, Relaxed);
        run.without_plain_path.store(true, Relaxed);
        let old = prepare(&db, &run);
        let owner = direct_seal(&old.boot);
        let proof = retained(&old.boot);
        let src = "10.19.0.2";
        let prior_mark = run.router.router.packet_mark(src, INNER_DST);
        assert!(prior_mark.is_some() && run.router.router.packet_mark(src, DIRECT_DST).is_some());
        let before = nfqws2_awg_profile::read(&db).unwrap();
        let mut wrong = proof.clone();
        wrong.owner.nested.as_mut().unwrap().source = "198.18.93.13".parse().unwrap();
        assert!(
            withdraw_mixed_direct_fixture(&db, &run, &owner, &|_| Ok(wrong.clone()), |doc| {
                disable_direct(doc, server);
                Ok(())
            })
            .is_err()
        );
        assert_eq!(Journal::read(&db).unwrap(), old);
        assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), before);

        nfqws2_awg_profile::edit_document(&db, |doc| {
            let mut other = doc["servers"][2].clone();
            other["id"] = "observed-elsewhere".into();
            other["config"]["client_iface"] = "awg3".into();
            other["config"]["endpoint"] = format!("{NESTED_IP}:444").into();
            doc["servers"].as_array_mut().unwrap().push(other);
            Ok(())
        })
        .unwrap();
        assert!(
            withdraw_mixed_direct_fixture(&db, &run, &owner, &|_| Ok(proof.clone()), |doc| {
                disable_direct(doc, server);
                Ok(())
            })
            .is_err()
        );
        assert_eq!(Journal::read(&db).unwrap(), old);
        nfqws2_awg_profile::edit_document(&db, |doc| {
            *doc = before.clone();
            Ok(())
        })
        .unwrap();

        run.router.router.fail_switch.store(true, Relaxed);
        assert!(
            withdraw_mixed_direct_fixture(&db, &run, &owner, &|_| Ok(proof.clone()), |doc| {
                disable_direct(doc, server);
                Ok(())
            })
            .is_err()
        );
        assert_eq!(Journal::read(&db).unwrap(), old);
        assert_eq!(run.router.router.packet_mark(src, INNER_DST), prior_mark);
        let captures = std::cell::Cell::new(0);
        assert!(withdraw_mixed_direct_fixture(
            &db,
            &run,
            &owner,
            &|_| {
                let count = captures.get() + 1;
                captures.set(count);
                let mut state = proof.clone();
                if count == 3 {
                    state.outer_owner.started += 1;
                }
                Ok(state)
            },
            |doc| {
                disable_direct(doc, server);
                Ok(())
            }
        )
        .is_err());
        assert_eq!(Journal::read(&db).unwrap(), old);
        assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), before);
        withdraw_mixed_direct_fixture(
            &db,
            &run,
            &owner,
            &|id| {
                assert_eq!(id, "inner");
                assert_eq!(run.router.router.packet_mark(src, INNER_DST), prior_mark);
                Ok(proof.clone())
            },
            |doc| {
                disable_direct(doc, server);
                Ok(())
            },
        )
        .unwrap();
        let after = Journal::read(&db).unwrap();
        assert_eq!(
            after.installed.marks,
            BTreeMap::from([("awg0".into(), old.installed.marks["awg0"])])
        );
        assert_eq!(after.committed, old.committed);
        assert_eq!(run.router.router.packet_mark(src, INNER_DST), prior_mark);
        assert!(run.router.router.packet_mark(src, DIRECT_DST).is_none());
        let saved = nfqws2_awg_profile::read(&db).unwrap();
        assert_eq!(saved["servers"][0], before["servers"][0]);
        assert_eq!(saved["servers"][2], before["servers"][2]);
        assert_eq!(saved["servers"][1]["config"]["enabled"], !server);
        assert_eq!(saved["servers"][1]["config"]["routing"]["active"], !server);
        assert_eq!(saved["servers"][1]["config"]["client"]["enabled"], false);
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires no-NIC Linux with isolated network and mount namespaces"]
fn routed_mixed_disable_preserves_a_real_marked_direct_fib_and_independent_outer() {
    real_mixed(false, false);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires no-NIC Linux with isolated network and mount namespaces"]
fn routed_mixed_direct_disable_preserves_real_nested_path_without_plain_wan() {
    real_mixed(true, true);
}

#[cfg(target_os = "linux")]
fn real_mixed(direct: bool, no_wan: bool) {
    assert!(std::path::Path::new("/synthetic-guest").is_file());
    for (kind, var) in [("net", "N2S_PARENT_NET"), ("mnt", "N2S_PARENT_MNT")] {
        let parent = std::env::var(var).unwrap();
        let current = std::fs::read_link(format!("/proc/self/ns/{kind}")).unwrap();
        assert!(parent.starts_with(&format!("{kind}:[")));
        assert_ne!(current.to_str(), Some(parent.as_str()));
    }
    struct Real(Router);
    impl Runner for Real {
        fn run(&self, program: &str, args: &[&str], end: Instant) -> io::Result<String> {
            if matches!(program, "iptables" | "ipset") {
                self.0.run(program, args, end)
            } else {
                nfqws2_router_command::System.run(program, args, end)
            }
        }
        fn run_input(
            &self,
            program: &str,
            args: &[&str],
            bytes: &[u8],
            end: Instant,
        ) -> io::Result<String> {
            if matches!(program, "iptables-restore" | "ipset") {
                self.0.run_input(program, args, bytes, end)
            } else {
                nfqws2_router_command::System.run_input(program, args, bytes, end)
            }
        }
    }
    let run = Real(Router::default());
    let k = kernel(&run);
    let marked = |destination: &str, selected: &str| {
        let line = k
            .call("ip", &["-4", "route", "get", destination, "mark", selected])
            .unwrap();
        line.split_ascii_whitespace()
            .skip_while(|field| *field != "dev")
            .nth(1)
            .unwrap()
            .to_string()
    };
    let apply_socket = |op| {
        for af in ["-4", "-6"] {
            k.call(
                "ip",
                &[
                    af,
                    "rule",
                    op,
                    "pref",
                    "60",
                    "fwmark",
                    "0xa0000000",
                    "table",
                    "828",
                ],
            )
            .unwrap();
            k.call(
                "ip",
                &[
                    af,
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
            k.call(
                "ip",
                &[
                    af,
                    "route",
                    op,
                    "blackhole",
                    "default",
                    "metric",
                    "1000",
                    "table",
                    "828",
                    "proto",
                    "99",
                ],
            )
            .unwrap();
        }
        k.call(
            "ip",
            &[
                "-4",
                "route",
                op,
                &format!("{NESTED_IP}/32"),
                "dev",
                "awg2",
                "src",
                OUTER_SOURCE,
                "table",
                "828",
                "proto",
                "99",
            ],
        )
        .unwrap();
    };
    k.call(
        "ip",
        &[
            "-4",
            "addr",
            "add",
            &format!("{OUTER_SOURCE}/32"),
            "dev",
            "awg2",
        ],
    )
    .unwrap();
    k.call(
        "ip",
        &[
            "-4",
            "route",
            "add",
            "203.0.113.53/32",
            "dev",
            "awg2",
            "src",
            OUTER_SOURCE,
        ],
    )
    .unwrap();
    apply_socket("add");
    let plain = |op| {
        k.call(
            "ip",
            &[
                "-4",
                "rule",
                op,
                "pref",
                "65",
                "to",
                &format!("{NESTED_IP}/32"),
                "prohibit",
            ],
        )
        .unwrap();
    };
    if no_wan {
        plain("add");
    }
    let (_dir, db) = fixture();
    let old = prepare(&db, &run);
    let inner_mark = super::super::marked::mark(old.installed.marks["awg0"]);
    let direct_mark = super::super::marked::mark(old.installed.marks["awg1"]);
    let owner = seal(&old.boot);
    assert_eq!(marked(INNER_DST, &inner_mark), "awg0");
    assert_eq!(marked(DIRECT_DST, &direct_mark), "awg1");
    if direct {
        let before = run.0.packet_mark("10.19.0.2", INNER_DST);
        let proof = retained(&old.boot);
        withdraw_mixed_direct_fixture(
            &db,
            &run,
            &direct_seal(&old.boot),
            &|id| {
                assert_eq!(id, "inner");
                assert_eq!(marked(NESTED_IP, "0xa0000000"), "awg2");
                assert_eq!(marked(INNER_DST, &inner_mark), "awg0");
                Ok(proof.clone())
            },
            |doc| {
                disable_direct(doc, false);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(marked(DIRECT_DST, &direct_mark), "wan0");
        assert_eq!(marked(INNER_DST, &inner_mark), "awg0");
        assert_eq!(run.0.packet_mark("10.19.0.2", INNER_DST), before);
        assert!(run.0.packet_mark("10.19.0.2", DIRECT_DST).is_none());
        assert_eq!(marked("203.0.113.53", "0"), "awg2");
        operate(&db, &run, Operation::Suspend, live).unwrap();
        operate(&db, &run, Operation::Recover, |cfg, iface| {
            assert_eq!(iface, "awg0");
            live(cfg, iface)
        })
        .unwrap();
        assert_eq!(marked(INNER_DST, &inner_mark), "awg0");
        assert_eq!(marked(NESTED_IP, "0xa0000000"), "awg2");
        operate(&db, &run, Operation::Teardown, live).unwrap();
        plain("del");
        apply_socket("del");
        k.call(
            "ip",
            &["-4", "route", "del", "203.0.113.53/32", "dev", "awg2"],
        )
        .unwrap();
        k.call(
            "ip",
            &[
                "-4",
                "addr",
                "del",
                &format!("{OUTER_SOURCE}/32"),
                "dev",
                "awg2",
            ],
        )
        .unwrap();
        return;
    }
    let before = run.0.packet_mark("10.19.0.2", DIRECT_DST);
    withdraw_fixture(
        &db,
        &run,
        Some(&owner),
        &|| {
            assert_eq!(marked(NESTED_IP, "0xa0000000"), "awg2");
            assert_eq!(marked(DIRECT_DST, &direct_mark), "awg1");
            Ok(())
        },
        |doc| {
            disable(doc, false);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(marked(DIRECT_DST, &direct_mark), "awg1");
    assert_eq!(marked(INNER_DST, &inner_mark), "wan0");
    assert_eq!(run.0.packet_mark("10.19.0.2", DIRECT_DST), before);
    assert!(run.0.packet_mark("10.19.0.2", INNER_DST).is_none());
    apply_socket("del");
    k.call(
        "ip",
        &[
            "-4",
            "rule",
            "add",
            "pref",
            "65",
            "to",
            &format!("{NESTED_IP}/32"),
            "prohibit",
        ],
    )
    .unwrap();
    operate(&db, &run, Operation::Suspend, live).unwrap();
    operate(&db, &run, Operation::Recover, |cfg, iface| {
        assert_eq!(iface, "awg1");
        live(cfg, iface)
    })
    .unwrap();
    assert_eq!(marked(DIRECT_DST, &direct_mark), "awg1");
    assert_eq!(marked("203.0.113.53", "0"), "awg2");
    operate(&db, &run, Operation::Teardown, live).unwrap();
    k.call(
        "ip",
        &[
            "-4",
            "rule",
            "del",
            "pref",
            "65",
            "to",
            &format!("{NESTED_IP}/32"),
            "prohibit",
        ],
    )
    .unwrap();
    k.call(
        "ip",
        &["-4", "route", "del", "203.0.113.53/32", "dev", "awg2"],
    )
    .unwrap();
    k.call(
        "ip",
        &[
            "-4",
            "addr",
            "del",
            &format!("{OUTER_SOURCE}/32"),
            "dev",
            "awg2",
        ],
    )
    .unwrap();
}
