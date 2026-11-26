use super::*;
use nfqws2_awg_profile::NamedReconnectTarget;
use std::net::SocketAddr;

const RAW: &str = "pending.example:443";
const OLD: &str = "198.51.100.10:443";

fn setup_named(db: &Store, run: &dyn Runner, sourced: bool) -> String {
    nfqws2_awg_profile::edit_document(db, |doc| {
        let row = &mut doc["servers"][0]["config"];
        row["install"] = json!("imported");
        row["endpoint"] = json!(OLD);
        row["client"]["rust_managed"] = json!(true);
        if sourced {
            row["routing"]["zones"][0]["source_ips"] = json!(["192.168.1.0/24"]);
            row["routing"]["zones"][0]["domains"] = json!(["list:corporate"]);
        }
        Ok(())
    })
    .unwrap();
    if sourced {
        crate::sources::stage(db, |_, _| Ok(vec!["192.0.2.15/32".into()])).unwrap();
    }
    let now = nfqws2_awg_profile::now();
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(db, run, op, now, peer).unwrap();
    }
    // Model the already imported name without any actual DNS resolution.
    nfqws2_awg_profile::edit_document(db, |doc| {
        doc["servers"][0]["config"]["endpoint"] = json!(RAW);
        Ok(())
    })
    .unwrap();
    let mut journal = Journal::read(db).unwrap();
    if sourced {
        let doc = nfqws2_awg_profile::read(db).unwrap();
        let effective = crate::sources::current(db, &doc).unwrap();
        let source = crate::sources::Generation::from_policy(&doc, &effective).unwrap();
        journal.committed.local_sources.clone_from(&source);
        journal.installed.local_sources = source;
        db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, &journal, RECEIPT_LIMIT))
            .unwrap();
    }
    journal.committed.targets["awg0"].id.clone()
}

fn target<'a>(id: &'a str, addresses: &'a [SocketAddr]) -> NamedReconnectTarget<'a> {
    NamedReconnectTarget {
        id,
        iface: "awg0",
        raw: RAW,
        revision: 1,
        selected: addresses[0],
        addresses,
    }
}

#[test]
fn named_reconnect_keeps_old_state_on_collision_wrong_wan_or_stale_policy() {
    let (_dir, db, router) = setup();
    protect(&db);
    router.0.lock().unwrap().local = "2: br0 inet 192.168.1.1/24 scope global".into();
    let id = setup_named(&db, &router, true);
    let stable = Journal::read(&db).unwrap();
    let doc = nfqws2_awg_profile::read(&db).unwrap();
    let changes = router.0.lock().unwrap().changes;
    let wan = ["wan0".into()];
    let safe = [
        "198.51.100.30:443".parse().unwrap(),
        "198.51.100.31:443".parse().unwrap(),
    ];
    assert_eq!(
        named_reconnect_revision(&db, &id, "awg0", RAW).unwrap(),
        Some(1)
    );
    assert_eq!(
        named_reconnect_revision(&db, "unrelated", "awg9", RAW).unwrap(),
        None
    );
    assert!(named_reconnect_revision(&db, &id, "awg1", RAW).is_err());
    assert!(named_reconnect_revision(&db, &id, "awg0", "changed.example:443").is_err());
    validate_named_reconnect(&db, &router, target(&id, &safe), &wan).unwrap();
    assert!(
        validate_named_reconnect(&db, &router, target(&id, &safe), &["wrong-wan".into()]).is_err()
    );

    let scoped_collision = [safe[0], "192.0.2.15:443".parse().unwrap()];
    assert!(
        validate_named_reconnect(&db, &router, target(&id, &scoped_collision), &wan)
            .unwrap_err()
            .to_string()
            .contains("пересекает")
    );
    let mut old_claim = stable.clone();
    let selector = plan::Selector {
        source: old_claim.committed.scoped[0].0.source,
        dest: "198.51.100.31/32".parse().unwrap(),
    };
    old_claim.committed.scoped.push((selector, "awg0".into()));
    old_claim.committed.scoped.sort_unstable();
    db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, &old_claim, RECEIPT_LIMIT))
        .unwrap();
    assert!(
        validate_named_reconnect(&db, &router, target(&id, &safe), &wan)
            .unwrap_err()
            .to_string()
            .contains("пересекает")
    );
    db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, &stable, RECEIPT_LIMIT))
        .unwrap();

    let mut learned = stable.clone();
    let source = crate::sources::current(&db, &doc).unwrap();
    learned.committed.learned = Some(
        learning::Saved::new(
            &source,
            "a".repeat(64),
            &[learning::Member {
                zone: 0,
                ip: safe[1].ip(),
                until: nfqws2_awg_profile::now() + 100,
            }],
        )
        .unwrap(),
    );
    db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, &learned, RECEIPT_LIMIT))
        .unwrap();
    assert!(
        validate_named_reconnect(&db, &router, target(&id, &safe), &wan)
            .unwrap_err()
            .to_string()
            .contains("пересекает")
    );
    db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, &stable, RECEIPT_LIMIT))
        .unwrap();

    let mut catch_all = stable.clone();
    for plan in [&mut catch_all.committed, &mut catch_all.installed] {
        plan.go_ipv4 = true;
        plan.ordered_default = true;
    }
    db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, &catch_all, RECEIPT_LIMIT))
        .unwrap();
    assert_eq!(
        named_reconnect_revision(&db, &id, "awg0", RAW).unwrap(),
        None
    );
    assert!(validate_named_reconnect(&db, &router, target(&id, &safe), &wan).is_err());
    db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, &stable, RECEIPT_LIMIT))
        .unwrap();

    let mut wrong_pin = target(&id, &safe);
    wrong_pin.selected = safe[1];
    assert!(validate_named_reconnect(&db, &router, wrong_pin, &wan).is_err());
    router.0.lock().unwrap().foreign_rule = "55: from all lookup 500".into();
    assert!(validate_named_reconnect(&db, &router, target(&id, &safe), &wan).is_err());
    router.0.lock().unwrap().foreign_rule.clear();
    router.0.lock().unwrap().boot = "34343434-3434-3434-3434-343434343434".into();
    assert!(validate_named_reconnect(&db, &router, target(&id, &safe), &wan).is_err());
    router.0.lock().unwrap().boot = BOOT.into();
    assert_eq!(router.0.lock().unwrap().changes, changes);
    assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), doc);
    assert_eq!(Journal::read(&db).unwrap(), stable);

    crate::sources::stage(&db, |_, _| Ok(vec!["198.51.100.31/32".into()])).unwrap();
    assert!(validate_named_reconnect(&db, &router, target(&id, &safe), &wan).is_err());
    assert_eq!(Journal::read(&db).unwrap(), stable);
    assert_eq!(router.0.lock().unwrap().changes, changes);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing_revision"] = json!(2);
        Ok(())
    })
    .unwrap();
    assert!(named_reconnect_revision(&db, &id, "awg0", RAW).is_err());
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn named_reconnect_checks_real_unchanged_fib_without_opening_new_paths() {
    for (kind, var) in [("net", "N2S_PARENT_NET"), ("mnt", "N2S_PARENT_MNT")] {
        let parent = std::env::var(var).unwrap();
        assert!(parent.starts_with(&format!("{kind}:[")));
        assert_ne!(
            std::fs::read_link(format!("/proc/self/ns/{kind}"))
                .unwrap()
                .to_str(),
            Some(parent.as_str())
        );
    }
    let (_dir, db, _) = setup();
    let kernel = nfqws2_router_command::System;
    let id = setup_named(&db, &kernel, false);
    let k = super::kernel(&kernel);
    let current = || k.listing(plan::Family::V4, &["rule", "show"]).unwrap();
    let before = current();
    let safe = ["192.0.2.30:443".parse().unwrap()];
    let wan = ["wan0".into()];
    assert!(k
        .call("ip", &["-4", "route", "get", "192.0.2.30"])
        .unwrap()
        .contains("dev wan0"));
    validate_named_reconnect(&db, &kernel, target(&id, &safe), &wan).unwrap();
    assert!(validate_named_reconnect(&db, &kernel, target(&id, &safe), &["br0".into()]).is_err());
    let captured = [safe[0], "203.0.113.7:443".parse().unwrap()];
    assert!(validate_named_reconnect(&db, &kernel, target(&id, &captured), &wan).is_err());
    assert_eq!(current(), before);
    operate_at(
        &db,
        &kernel,
        Operation::Teardown,
        nfqws2_awg_profile::now(),
        peer,
    )
    .unwrap();
    assert_eq!(
        named_reconnect_revision(&db, &id, "awg0", RAW).unwrap(),
        None
    );
}
