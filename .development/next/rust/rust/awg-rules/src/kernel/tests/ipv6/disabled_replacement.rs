use super::{combined_edit::require_isolated_namespaces, *};
use nfqws2_awg_profile::{
    active_replacement_fingerprint, ActiveReplacementPeer, NativeRemovalSeal, DIRECT_SOCKET_MARK,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};

const SOURCE: &str = "awg0";
const TARGET: &str = "desired-disabled";
const TARGET_IFACE: &str = "awg31";
const HELD: &str = "kept-owner";
const HELD_IFACE: &str = "awg2";
const NETNS: &str = "inactive-replacement-client";
const LAN: &str = "br142";
const CLIENT: &str = "client142";
const INSIDE: &str = "192.168.71.40";
const OUTSIDE: &str = "192.168.71.90";
const SCOPED: &str = "198.18.7.24";
const GLOBAL: &str = "198.18.8.55";
const RETAINED: &str = "198.18.8.77";
const CHAIN: &str = "N2S_R142_WITNESS";

struct System {
    protect: AtomicBool,
}

impl Runner for System {
    fn run(&self, program: &str, args: &[&str], end: Instant) -> io::Result<String> {
        if self.protect.load(Relaxed)
            && ["add", "del", "replace", "-A", "-D", "-I"]
                .iter()
                .any(|op| args.contains(op))
        {
            assert!(!args
                .iter()
                .any(|arg| arg.contains(RETAINED) || *arg == HELD_IFACE));
        }
        nfqws2_router_command::System.run(program, args, end)
    }
    fn run_input(
        &self,
        program: &str,
        args: &[&str],
        input: &[u8],
        end: Instant,
    ) -> io::Result<String> {
        nfqws2_router_command::System.run_input(program, args, input, end)
    }
}

fn profile_fixture(
    kill: bool,
    server_disabled: bool,
    with_held: bool,
) -> (tempfile::TempDir, Store) {
    let (temp, db, _) = setup();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"] = json!({"mode":"zones", "killswitch":kill, "sni_routing":false});
        let cfg = &mut doc["servers"][0]["config"];
        cfg["install"] = json!("imported");
        cfg["protocol"] = json!("wireguard");
        cfg["endpoint"] = json!("198.51.100.10:443");
        cfg["client"]["rust_managed"] = json!(true);
        cfg["client"]["peer_id"] = json!("router");
        cfg["peers"] = json!([{"id":"router","is_router":true,"address":"10.30.0.2/32",
            "private_key":format!("B{}=", "A".repeat(42)),"allowed_ips":["0.0.0.0/0"]}]);
        cfg["routing"] = json!({"mode":"zones","zones":[
            {"enabled":true,"order":1,"source_ips":[format!("{INSIDE}/32")],"ips":[format!("{SCOPED}/32")]},
            {"enabled":true,"order":2,"ips":[format!("{GLOBAL}/32")]}
        ]});
        let mut target = cfg.clone();
        target["client_iface"] = json!(TARGET_IFACE);
        target["endpoint"] = json!("198.51.100.11:443");
        target["client"]["enabled"] = json!(server_disabled);
        target["enabled"] = json!(!server_disabled);
        target["client"]["standby"] = json!(true);
        target["routing"]["zones"] = json!([]);
        let mut held = cfg.clone();
        held["client_iface"] = json!(HELD_IFACE);
        held["endpoint"] = json!("198.51.100.12:443");
        held["routing"]["zones"] = json!([{"enabled":true,"order":3,"ips":[format!("{RETAINED}/32")]}]);
        let rows = doc["servers"].as_array_mut().unwrap();
        rows.push(json!({"id":TARGET,"config":target}));
        if with_held {
            rows.push(json!({"id":HELD,"config":held}));
        }
        Ok(())
    }).unwrap();
    (temp, db)
}

fn test_flow(run: &System, from: &str, to: &str, expected: &str) {
    let k = kernel(run);
    k.call("iptables", &["-w", "-t", "mangle", "-Z", CHAIN])
        .unwrap();
    let child = std::process::Command::new("ip")
        .args(["netns", "exec", NETNS])
        .arg(std::env::current_exe().unwrap())
        .args([
            "firmware_mixed_lan_packet_sender",
            "--ignored",
            "--test-threads=1",
        ])
        .env("N2S_R99_LAN_CLIENT", from)
        .env("N2S_R99_LAN_DEST", to)
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "{}",
        String::from_utf8_lossy(&child.stdout)
    );
    let end = Instant::now() + std::time::Duration::from_secs(1);
    loop {
        let rules = k.call("iptables-save", &["-c", "-t", "mangle"]).unwrap();
        let used = rules
            .lines()
            .filter_map(|row| {
                let columns = row.split_whitespace().collect::<Vec<_>>();
                match columns.as_slice() {
                    [counts, "-A", CHAIN, "-o", iface, "-j", "RETURN"]
                        if !counts.starts_with("[0:") =>
                    {
                        Some(*iface)
                    }
                    _ => None,
                }
            })
            .collect::<Vec<_>>();
        if !used.is_empty() || Instant::now() >= end {
            assert_eq!(used, [expected], "{from} to {to}");
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn disabled_replacement_moves_desired_rules_and_keeps_the_other_native_fib() {
    disabled_replacement(true);
}

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn disabled_replacement_saves_the_sole_routed_owner() {
    disabled_replacement(false);
}

fn disabled_replacement(with_held: bool) {
    require_isolated_namespaces();
    let run = System {
        protect: AtomicBool::new(false),
    };
    let ip = |args: &[&str]| kernel(&run).call("ip", args).unwrap();
    let fw = |args: &[&str]| kernel(&run).call("iptables", args).unwrap();
    ip(&["netns", "add", NETNS]);
    ip(&["link", "add", LAN, "type", "veth", "peer", "name", CLIENT]);
    ip(&["link", "set", CLIENT, "netns", NETNS]);
    ip(&["addr", "add", "192.168.71.1/24", "dev", LAN]);
    ip(&["link", "set", LAN, "up"]);
    ip(&["-n", NETNS, "link", "set", CLIENT, "up"]);
    for address in ["192.168.71.40/24", "192.168.71.90/24"] {
        ip(&["-n", NETNS, "addr", "add", address, "dev", CLIENT]);
    }
    ip(&[
        "-n",
        NETNS,
        "route",
        "add",
        "default",
        "via",
        "192.168.71.1",
        "dev",
        CLIENT,
    ]);
    fw(&["-w", "-t", "mangle", "-N", CHAIN]);
    for dest in [SCOPED, GLOBAL, RETAINED] {
        fw(&[
            "-w",
            "-t",
            "mangle",
            "-A",
            "POSTROUTING",
            "-p",
            "udp",
            "-d",
            dest,
            "--dport",
            "42042",
            "-j",
            CHAIN,
        ]);
    }
    for iface in [SOURCE, TARGET_IFACE, HELD_IFACE, "wan0"] {
        fw(&[
            "-w", "-t", "mangle", "-A", CHAIN, "-o", iface, "-j", "RETURN",
        ]);
    }
    for kill in [false, true] {
        for server_disabled in [false, true] {
            ip(&["link", "set", SOURCE, "up"]);
            let (_temp, db) = profile_fixture(kill, server_disabled, with_held);
            let held_path = if with_held { HELD_IFACE } else { "wan0" };
            let live = |cfg: &Value, _: &str| {
                Ok(LivePeer {
                    endpoint: cfg["endpoint"].as_str().unwrap().parse().unwrap(),
                    socket_mark: DIRECT_SOCKET_MARK,
                    ..peer(cfg, SOURCE)?
                })
            };
            for mode in [Operation::Apply, Operation::Commit] {
                operate(&db, &run, mode, live).unwrap();
            }
            let check_paths = |moved| {
                test_flow(&run, INSIDE, SCOPED, moved);
                test_flow(&run, OUTSIDE, SCOPED, "wan0");
                for client in [INSIDE, OUTSIDE] {
                    test_flow(&run, client, GLOBAL, moved);
                    test_flow(&run, client, RETAINED, held_path);
                }
            };
            check_paths(SOURCE);
            let before = nfqws2_awg_profile::read(&db).unwrap();
            let before_journal = Journal::read(&db).unwrap();
            let witness = |id: &str, iface: &str| {
                let owned = before["servers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|row| row["id"] == id)
                    .unwrap();
                let n = if id == SOURCE { 1 } else { 2 };
                ActiveReplacementPeer {
                    owner: NativeRemovalSeal {
                        id: id.into(),
                        iface: iface.into(),
                        boot: before_journal.boot.clone(),
                        pid: 420 + u32::from(n),
                        started: 777 + u64::from(n),
                        receipt_sha256: [n; 32],
                        nested: None,
                    },
                    fingerprint: active_replacement_fingerprint(&before, id).unwrap(),
                    endpoint: owned["config"]["endpoint"]
                        .as_str()
                        .unwrap()
                        .parse()
                        .unwrap(),
                    socket_mark: DIRECT_SOCKET_MARK,
                    mtu: 1420,
                    allowed: vec!["0.0.0.0/0".into()],
                    underlay: None,
                    nested_only: false,
                }
            };
            let source = witness(SOURCE, SOURCE);
            let held = with_held.then(|| witness(HELD, HELD_IFACE));
            let mut after = before.clone();
            let rows = after["servers"].as_array_mut().unwrap();
            let removed = rows.remove(0);
            let mut zones = removed["config"]["routing"]["zones"].clone();
            for zone in zones.as_array_mut().unwrap() {
                zone["tunnel_id"] = json!(TARGET);
            }
            rows[0]["config"]["routing"]["zones"] = zones;
            rows[0]["config"]["routing"]["active"] = json!(true);
            rows[0]["config"]["client"]["standby"] = json!(false);
            after["active_id"] = json!(TARGET);
            after["routing_revision"] = json!(before_journal.committed.revision + 1);
            let apply = |verify: &dyn Fn() -> io::Result<()>| {
                db.transaction(|tx| {
                    replace_active_profile_with_disabled_target(
                        &db,
                        tx,
                        &run,
                        (&before, &after),
                        (TARGET, (&source, held.as_ref()), &["wan0".into()]),
                        verify,
                        || Ok(()),
                    )
                })
            };
            ip(&["link", "add", TARGET_IFACE, "type", "dummy"]);
            assert!(apply(&|| Ok(())).is_err());
            assert_eq!(Journal::read(&db).unwrap(), before_journal);
            assert!(nfqws2_awg_profile::read(&db).unwrap() == before);
            ip(&["link", "del", TARGET_IFACE]);
            run.protect.store(true, Relaxed);
            if !server_disabled {
                let checks = AtomicUsize::new(0);
                let failed = apply(&|| {
                    if checks.fetch_add(1, Relaxed) == 1 {
                        return Err(io::ErrorKind::Interrupted.into());
                    }
                    Ok(())
                });
                assert!(failed.is_err());
                assert_eq!(checks.load(Relaxed), 2, "{failed:?}");
                let rollback = Journal::read(&db).unwrap();
                assert_eq!(rollback.committed, before_journal.committed);
                if kill {
                    assert!(rollback.installed.offline.contains(SOURCE));
                } else {
                    assert!(!rollback.installed.targets.contains_key(SOURCE));
                }
                assert!(!active_replacement_in_progress(&db).unwrap());
                let still_saved = nfqws2_awg_profile::read(&db).unwrap();
                assert!(still_saved["servers"] == before["servers"]);
                assert_eq!(still_saved["active_id"], SOURCE);
                test_flow(&run, INSIDE, RETAINED, held_path);
                operate(&db, &run, Operation::Recover, live).unwrap();
                assert_eq!(Journal::read(&db).unwrap(), before_journal);
            }
            apply(&|| Ok(())).unwrap();
            run.protect.store(false, Relaxed);
            check_paths("wan0");
            assert_eq!(
                pending_active_replacement_retirement(&db).unwrap(),
                Some(source.owner.clone())
            );
            let mut stale = source.owner.clone();
            stale.started += 1;
            assert!(finish_active_replacement_retirement(&db, &stale).is_err());
            ip(&["link", "set", SOURCE, "down"]);
            finish_active_replacement_retirement(&db, &source.owner).unwrap();
            let saved = nfqws2_awg_profile::read(&db).unwrap();
            assert!(saved["servers"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row["id"] != SOURCE));
            assert_eq!(saved["active_id"], TARGET);
            assert!(saved["servers"][0] == after["servers"][0]);
            if with_held {
                assert!(saved["servers"][1] == before["servers"][2]);
            }
            assert!(!legacy_active(&saved));
            operate(&db, &run, Operation::Recover, live).unwrap();
            check_paths("wan0");
            let current = Journal::read(&db).unwrap();
            assert_eq!(current.committed.killswitch, kill);
            assert_eq!(
                current
                    .committed
                    .targets
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                with_held
                    .then_some(HELD_IFACE)
                    .into_iter()
                    .collect::<Vec<_>>()
            );
            let dormant = nfqws2_awg_profile::read(&db).unwrap();
            assert_eq!(
                dormant["rust_static_routing"]["disabled_replacements"],
                json!([TARGET])
            );
            assert_eq!(dormant["servers"][0]["config"]["routing"]["active"], true);
            assert!(inspect(&db, &run).unwrap().ready);
            assert!(!crate::kernel::routed_disable::link_names(&kernel(&run))
                .unwrap()
                .contains(TARGET_IFACE));
            assert!(routed_profile_is_disabled(&db, Some(TARGET)).unwrap());
            assert!(routed_profile_is_disabled(&db, None).unwrap());
            assert_eq!(
                scheduled(&db).unwrap(),
                if with_held {
                    Schedule::Audit
                } else {
                    Schedule::Idle
                }
            );
            nfqws2_awg_profile::edit_document(&db, |doc| {
                let profile = &mut doc["servers"][0]["config"];
                profile["enabled"] = json!(true);
                profile["client"]["enabled"] = json!(true);
                profile["client"]["rust_managed"] = json!(true);
                Ok(())
            })
            .unwrap();
            let armed = nfqws2_awg_profile::read(&db).unwrap();
            if !with_held && kill && !server_disabled {
                let mut previous_boot = current.clone();
                previous_boot.boot = "07070707-0707-0707-0707-070707070707".into();
                assert_ne!(previous_boot.boot, current.boot);
                db.transaction(|tx| {
                    tx.save_runtime_bounded(RECEIPT, &previous_boot, RECEIPT_LIMIT)?;
                    nfqws2_awg_profile::edit_document_locked(tx, |doc| {
                        doc["rust_static_routing"]["boot"] = json!(previous_boot.boot);
                        Ok(())
                    })
                })
                .unwrap();
                operate(&db, &run, Operation::Recover, live).unwrap();
                assert_eq!(Journal::read(&db).unwrap(), current);
                assert!(nfqws2_awg_profile::read(&db).unwrap() == armed);
                // A process can stop after claiming the new boot but before
                // restamping the intentionally empty installed projection.
                let mut reset = current.clone();
                reset.installed = Snapshot::default();
                db.transaction(|tx| {
                    tx.save_runtime_bounded(RECEIPT, &reset, RECEIPT_LIMIT)?;
                    nfqws2_awg_profile::edit_document_locked(tx, |doc| {
                        doc["rust_static_routing"]["boot"] = json!(previous_boot.boot);
                        Ok(())
                    })
                })
                .unwrap();
                assert_eq!(scheduled(&db).unwrap(), Schedule::Restore);
                operate(&db, &run, Operation::Recover, live).unwrap();
                assert_eq!(Journal::read(&db).unwrap(), current);
                assert!(nfqws2_awg_profile::read(&db).unwrap() == armed);
                check_paths("wan0");
            }
            assert_eq!(scheduled(&db).unwrap(), Schedule::Restore);
            assert!(active_replacement_native_witness_needed(&db, TARGET_IFACE).unwrap());
            assert_eq!(
                active_replacement_native_witness_needed(&db, HELD_IFACE).unwrap(),
                with_held
            );
            assert!(!active_replacement_native_witness_needed(&db, SOURCE).unwrap());
            assert!(!routed_profile_is_disabled(&db, None).unwrap());
            assert!(routed_profile_needs_rearm(&db, None).unwrap());
            assert!(routed_profile_needs_rearm(&db, Some(TARGET)).unwrap());
            run.protect.store(true, Relaxed);
            assert_eq!(
                operate(&db, &run, Operation::Refresh, live)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::WouldBlock
            );
            assert_eq!(Journal::read(&db).unwrap(), current);
            assert!(nfqws2_awg_profile::read(&db).unwrap() == armed);
            if !server_disabled {
                check_paths("wan0");
            }
            ip(&["link", "add", TARGET_IFACE, "type", "dummy"]);
            ip(&["link", "set", TARGET_IFACE, "up"]);
            let resumed = ActiveReplacementPeer {
                owner: NativeRemovalSeal {
                    id: TARGET.into(),
                    iface: TARGET_IFACE.into(),
                    boot: current.boot.clone(),
                    pid: 423,
                    started: 780,
                    receipt_sha256: [3; 32],
                    nested: None,
                },
                fingerprint: active_replacement_fingerprint(&armed, TARGET).unwrap(),
                endpoint: armed["servers"][0]["config"]["endpoint"]
                    .as_str()
                    .unwrap()
                    .parse()
                    .unwrap(),
                socket_mark: DIRECT_SOCKET_MARK,
                mtu: 1420,
                allowed: vec!["0.0.0.0/0".into()],
                underlay: None,
                nested_only: false,
            };
            let confirmed = |cfg: &Value, iface: &str| {
                let witness = match iface {
                    TARGET_IFACE => &resumed,
                    HELD_IFACE => held.as_ref().ok_or(io::ErrorKind::NotFound)?,
                    _ => return Err(io::ErrorKind::NotFound.into()),
                };
                Ok(live(cfg, iface)?.with_active_replacement_peer(Some(witness.clone())))
            };
            let probes = AtomicUsize::new(0);
            assert_eq!(
                operate(&db, &run, Operation::Recover, |cfg, iface| {
                    let mut sample = confirmed(cfg, iface)?;
                    if iface == TARGET_IFACE && probes.fetch_add(1, Relaxed) == 1 {
                        sample
                            .active_replacement_peer
                            .as_mut()
                            .unwrap()
                            .owner
                            .started += 1;
                    }
                    Ok(sample)
                })
                .unwrap_err()
                .kind(),
                io::ErrorKind::WouldBlock
            );
            assert_eq!(Journal::read(&db).unwrap(), current);
            assert!(nfqws2_awg_profile::read(&db).unwrap() == armed);
            if !with_held && !server_disabled {
                let foreign = [
                    "-4",
                    "route",
                    "add",
                    "blackhole",
                    "198.18.8.55/32",
                    "table",
                    "17842",
                    "proto",
                    "217",
                ];
                ip(&foreign);
                assert!(operate(&db, &run, Operation::Recover, confirmed).is_err());
                assert_eq!(Journal::read(&db).unwrap(), current);
                assert!(nfqws2_awg_profile::read(&db).unwrap() == armed);
                assert!(
                    ip(&["-4", "route", "list", "table", "17842", "proto", "217"])
                        .contains("198.18.8.55")
                );
                let mut remove = foreign;
                remove[2] = "del";
                ip(&remove);
            }
            operate(&db, &run, Operation::Recover, confirmed).unwrap();
            let rearmed = Journal::read(&db).unwrap();
            let mut restored = nfqws2_awg_profile::read(&db).unwrap();
            assert_eq!(rearmed.committed.revision, current.committed.revision);
            assert!(restored["servers"] == armed["servers"]);
            assert_eq!(restored["routing_revision"], armed["routing_revision"]);
            assert!(restored["rust_static_routing"]["disabled_replacements"].is_null());
            assert!(!routed_profile_needs_rearm(&db, Some(TARGET)).unwrap());
            assert_eq!(scheduled(&db).unwrap(), Schedule::Audit);
            check_paths(TARGET_IFACE);

            if !server_disabled {
                // Recreate a power cutoff after FIB and owner stamp, before
                // the prepared route journal commits. Existing held objects
                // must never be written again during the recovery.
                restored["rust_static_routing"]["disabled_replacements"] = json!([TARGET]);
                if !with_held {
                    // Once the receipt is committed, cleanup alone is enough.
                    nfqws2_awg_profile::edit_document(&db, |doc| {
                        *doc = restored.clone();
                        Ok(())
                    })
                    .unwrap();
                    assert_eq!(scheduled(&db).unwrap(), Schedule::Restore);
                    operate(&db, &run, Operation::Refresh, confirmed).unwrap();
                    assert_eq!(Journal::read(&db).unwrap(), rearmed);
                    assert!(
                        nfqws2_awg_profile::read(&db).unwrap()["rust_static_routing"]
                            ["disabled_replacements"]
                            .is_null()
                    );
                }
                let mut interrupted = current.clone();
                interrupted.preparing.push(rearmed.installed.clone());
                db.transaction(|tx| {
                    tx.save_runtime_bounded(RECEIPT, &interrupted, RECEIPT_LIMIT)?;
                    nfqws2_awg_profile::edit_document_locked(tx, |doc| {
                        *doc = restored.clone();
                        Ok(())
                    })
                })
                .unwrap();
                operate(&db, &run, Operation::Recover, live).unwrap();
                assert_eq!(Journal::read(&db).unwrap(), current);
                assert!(nfqws2_awg_profile::read(&db).unwrap() == armed);
                check_paths("wan0");
                operate(&db, &run, Operation::Recover, confirmed).unwrap();
                assert_eq!(Journal::read(&db).unwrap(), rearmed);
                check_paths(TARGET_IFACE);
            }
            run.protect.store(false, Relaxed);
            operate(&db, &run, Operation::Teardown, live).unwrap();
            ip(&["link", "del", TARGET_IFACE]);
            assert!(!inspect(&db, &run).unwrap().ready);
            let stopped = nfqws2_awg_profile::read(&db).unwrap();
            assert!(stopped["rust_static_routing"].is_null());
            assert_eq!(stopped["servers"][0]["config"]["routing"]["active"], false);
        }
    }
    for dest in [SCOPED, GLOBAL, RETAINED] {
        fw(&[
            "-w",
            "-t",
            "mangle",
            "-D",
            "POSTROUTING",
            "-p",
            "udp",
            "-d",
            dest,
            "--dport",
            "42042",
            "-j",
            CHAIN,
        ]);
    }
    fw(&["-w", "-t", "mangle", "-F", CHAIN]);
    fw(&["-w", "-t", "mangle", "-X", CHAIN]);
    ip(&["netns", "del", NETNS]);
}
