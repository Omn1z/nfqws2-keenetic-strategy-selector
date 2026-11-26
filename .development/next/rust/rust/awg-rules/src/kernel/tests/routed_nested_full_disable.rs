use super::{ipv6::Dual, *};
use crate::kernel::routed_disable::{routed_profile_is_disabled, withdraw_fixture};
use nfqws2_awg_profile::{NativeNestedRemovalScope, NativeRemovalSeal};

const ENDPOINT: &str = "203.0.113.10";
const SOURCE: &str = "198.18.92.2";
#[cfg(target_os = "linux")]
const OUTER_USE: &str = "203.0.113.53";
#[cfg(target_os = "linux")]
const V4_PAYLOAD: &str = "203.0.113.72";
#[cfg(target_os = "linux")]
const V6_PAYLOAD: &str = "2001:db8:92:99::72";

fn fixture() -> (tempfile::TempDir, Store) {
    let (tmp, db, _) = setup();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"] = json!({"mode":"full"});
        let rows = doc["servers"].as_array_mut().unwrap();
        let row = &mut rows[0];
        row["id"] = "inner".into();
        let cfg = &mut row["config"];
        cfg["install"] = "imported".into();
        cfg["endpoint"] = format!("{ENDPOINT}:443").into();
        cfg["mtu"] = 1420.into();
        cfg["client"]["rust_managed"] = true.into();
        cfg["routing"] = json!({"mode":"full"});
        let mut outer = row.clone();
        outer["id"] = "outer".into();
        outer["config"]["client_iface"] = "awg1".into();
        outer["config"]["endpoint"] = "192.0.2.44:443".into();
        outer["config"]["routing"] = json!({"mode":"off","active":false});
        row["config"]["client"]["double_tunnel_mode"] = "permanent".into();
        row["config"]["client"]["double_tunnel_id"] = "outer".into();
        rows.push(outer);
        doc["active_id"] = "inner".into();
        Ok(())
    })
    .unwrap();
    (tmp, db)
}

fn live(dual: bool) -> impl Fn(&Value, &str) -> io::Result<LivePeer> {
    move |cfg, iface| {
        assert_eq!(iface, "awg0");
        let mut sample = peer(cfg, iface)?;
        sample.endpoint = cfg["endpoint"].as_str().unwrap().parse().unwrap();
        sample.nested_mtu = Some(if dual { 1290 } else { 1270 });
        sample.socket_mark = 0xa0000000;
        sample.allowed.push("::/0".into());
        Ok(sample)
    }
}

fn seal(boot: &str) -> NativeRemovalSeal {
    NativeRemovalSeal {
        id: "inner".into(),
        iface: "awg0".into(),
        boot: boot.into(),
        pid: 9200,
        started: 33,
        receipt_sha256: [0x92; 32],
        nested: Some(NativeNestedRemovalScope {
            outer_iface: "awg1".into(),
            endpoint: ENDPOINT.parse().unwrap(),
            source: SOURCE.parse().unwrap(),
        }),
    }
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

fn prepare(db: &Store, run: &dyn Runner, dual: bool) -> Journal {
    for op in [Operation::Apply, Operation::Commit] {
        operate(db, run, op, live(dual)).unwrap();
    }
    Journal::read(db).unwrap()
}

struct Nested(Dual);

impl Runner for Nested {
    fn run(&self, command: &str, args: &[&str], end: Instant) -> io::Result<String> {
        if command == "ip" && matches!(args, ["-4", "route", "get", ENDPOINT, "mark", "0xa0000000"])
        {
            return Ok(format!("{ENDPOINT} dev awg1 table 828 src {SOURCE}"));
        }
        let mut output = self.0.run(command, args, end)?;
        if command == "ip" && matches!(args, ["-o", "-N", "-4" | "-6", "rule", "show"]) {
            output.push_str("\n60: from all fwmark 0xa0000000 lookup 828\n61: from all fwmark 0xa0000000 prohibit\n");
        }
        Ok(output)
    }
}

#[test]
fn routed_nested_full_disable_checks_exact_outer_flags_and_source_before_withdrawal() {
    for server in [false, true] {
        let (_dir, db) = fixture();
        let run = Nested(Dual::default());
        let old = prepare(&db, &run, !server);
        let owner = seal(&old.boot);
        let before = nfqws2_awg_profile::read(&db).unwrap();
        let wrong_source = NativeRemovalSeal {
            nested: Some(NativeNestedRemovalScope {
                source: "198.18.92.13".parse().unwrap(),
                ..owner.nested.clone().unwrap()
            }),
            ..owner.clone()
        };
        assert!(
            withdraw_fixture(&db, &run, Some(&wrong_source), &|| Ok(()), |doc| {
                disable(doc, server);
                Ok(())
            })
            .is_err()
        );
        assert_eq!(Journal::read(&db).unwrap(), old);
        assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), before);
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["servers"][1]["config"]["client"]["standby"] = true.into();
            Ok(())
        })
        .unwrap();
        assert!(withdraw_fixture(
            &db,
            &run,
            Some(&owner),
            &|| panic!("standby not verified"),
            |_| panic!("standby cannot retire")
        )
        .is_err());
        nfqws2_awg_profile::edit_document(&db, |doc| {
            *doc = before.clone();
            Ok(())
        })
        .unwrap();

        withdraw_fixture(&db, &run, Some(&owner), &|| Ok(()), |doc| {
            disable(doc, server);
            Ok(())
        })
        .unwrap();
        let saved = nfqws2_awg_profile::read(&db).unwrap();
        assert_eq!(saved["servers"][1], before["servers"][1]);
        let cfg = &saved["servers"][0]["config"];
        assert_eq!(cfg["enabled"], !server);
        assert_eq!(cfg["routing"]["active"], !server);
        assert_eq!(cfg["client"]["enabled"], false);
        assert_eq!(cfg["client"]["double_tunnel_id"], "outer");
        assert!(routed_profile_is_disabled(&db, Some("inner")).unwrap());
        let after = Journal::read(&db).unwrap();
        assert_eq!(after.committed, old.committed);
        assert!(after.installed.empty());
        // Startup may finish the inner retirement even if the outer is now
        // separately offline. Never reinstall this disabled policy.
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["servers"][1]["config"]["client"]["enabled"] = false.into();
            Ok(())
        })
        .unwrap();
        let reboot = Dual::default();
        reboot.v4.0.lock().unwrap().boot = "92929292-9292-9292-9292-929292929292".into();
        operate(&db, &reboot, Operation::Recover, |_, _| {
            panic!("disabled inner peer queried")
        })
        .unwrap();
        assert!(Journal::read(&db).unwrap().installed.empty());
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires no-NIC Linux with isolated network and mount namespaces"]
fn routed_nested_full_disable_withdraws_real_payload_and_preserves_independent_outer() {
    assert!(std::path::Path::new("/synthetic-guest").is_file());
    for (kind, var) in [("net", "N2S_PARENT_NET"), ("mnt", "N2S_PARENT_MNT")] {
        let parent = std::env::var(var).unwrap();
        let current = std::fs::read_link(format!("/proc/self/ns/{kind}")).unwrap();
        assert!(parent.starts_with(&format!("{kind}:[")));
        assert_ne!(current.to_str(), Some(parent.as_str()));
    }
    let run = nfqws2_router_command::System;
    let k = kernel(&run);
    let dev = |af: &str, ip: &str, mark: bool| {
        let mut args = vec![af, "route", "get", ip];
        if mark {
            args.extend(["mark", "0xa0000000"]);
        }
        let text = k.call("ip", &args).ok()?;
        let mut words = text.split_ascii_whitespace();
        words.find(|word| *word == "dev")?;
        Some(words.next()?.to_string())
    };
    let socket_objects = |op: &str| {
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
                &format!("{ENDPOINT}/32"),
                "src",
                SOURCE,
                "dev",
                "awg1",
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
        &["-4", "addr", "add", &format!("{SOURCE}/32"), "dev", "awg1"],
    )
    .unwrap();
    k.call(
        "ip",
        &[
            "-4",
            "route",
            "add",
            &format!("{OUTER_USE}/32"),
            "src",
            SOURCE,
            "dev",
            "awg1",
        ],
    )
    .unwrap();
    for (server, dual) in [(false, true), (true, false)] {
        socket_objects("add");
        let (_dir, db) = fixture();
        let old = prepare(&db, &run, dual);
        let owner = seal(&old.boot);
        assert_eq!(dev("-4", ENDPOINT, true).as_deref(), Some("awg1"));
        assert_eq!(dev("-4", V4_PAYLOAD, false).as_deref(), Some("awg0"));
        assert_eq!(
            dev("-6", V6_PAYLOAD, false).as_deref(),
            dual.then_some("awg0")
        );
        let observations = std::cell::Cell::new(0);
        withdraw_fixture(
            &db,
            &run,
            Some(&owner),
            &|| {
                assert_eq!(dev("-4", OUTER_USE, false).as_deref(), Some("awg1"));
                assert_eq!(dev("-4", ENDPOINT, true).as_deref(), Some("awg1"));
                observations.set(observations.get() + 1);
                Ok(())
            },
            |doc| {
                disable(doc, server);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(observations.get(), 2);
        assert_eq!(dev("-4", V4_PAYLOAD, false).as_deref(), Some("wan0"));
        assert_eq!(dev("-6", V6_PAYLOAD, false).as_deref(), Some("wan0"));
        for family in [plan::Family::V4, plan::Family::V6] {
            let rules = k.listing(family, &["rule", "show"]).unwrap();
            assert!(!rules.contains("17842") && rules.contains("828"));
        }
        // Match the separate native owner retirement step after publication.
        socket_objects("del");
        k.call("ip", &["link", "set", "awg0", "down"]).unwrap();
        operate(&db, &run, Operation::Recover, |_, _| {
            panic!("disabled nested peer queried")
        })
        .unwrap();
        assert_eq!(dev("-4", OUTER_USE, false).as_deref(), Some("awg1"));
        k.call("ip", &["link", "set", "awg0", "up"]).unwrap();
    }
    k.call(
        "ip",
        &[
            "-4",
            "route",
            "del",
            &format!("{OUTER_USE}/32"),
            "dev",
            "awg1",
        ],
    )
    .unwrap();
    k.call(
        "ip",
        &["-4", "addr", "del", &format!("{SOURCE}/32"), "dev", "awg1"],
    )
    .unwrap();
}
