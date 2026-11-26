use super::*;
use crate::kernel::{
    learning::{Member, Saved},
    plan::Target,
    Prefix, RECEIPT,
};
use nfqws2_store::Store;
use serde_json::json;
use std::net::Ipv4Addr;

const BOOT: &str = "11111111-2222-3333-4444-555555555555";

#[test]
fn old_route_map_and_partial_intent_upgrade_without_losing_ownership() {
    let plan = json!({"prefixes":{"77.0.0.1/32":"awg0","77.0.1.0/24":"awg0",
        "2001:db8::1/128":"awg1"},"targets":{},"revision":3});
    let legacy = json!({"boot":BOOT,"installed":plan,"committed":plan,
        "preparing":[plan,{"prefixes":{},"targets":{},"revision":2}],"expires":200});
    let old: Journal = serde_json::from_value(legacy).unwrap();
    assert!(Arc::ptr_eq(&old.installed.0, &old.committed.0));
    assert!(Arc::ptr_eq(&old.installed.0, &old.preparing[0].0));
    let frozen = old.clone();
    let mut candidate = old.clone();
    candidate.installed.prefixes.clear();
    assert_eq!(frozen.installed.prefixes.len(), 3);
    assert_eq!(candidate.committed.prefixes.len(), 3);
    assert!(!Arc::ptr_eq(&candidate.installed.0, &candidate.committed.0));
    let encoded = serde_json::to_value(&old).unwrap();
    let body = &encoded[1];
    assert_eq!(body["generations"].as_array().unwrap().len(), 2);
    assert_eq!(body["installed"], body["committed"]);
    assert_eq!(body["preparing"], json!([0, 1]));
    assert_eq!(
        body["generations"][0]["prefixes"],
        json!([
            "awg0",
            u32::from(Ipv4Addr::new(77, 0, 0, 1)),
            "77.0.1.0/24",
            "awg1",
            "2001:db8::1/128"
        ])
    );
    assert_eq!(serde_json::from_value::<Journal>(encoded).unwrap(), old);
}

#[test]
fn corrupt_or_oversized_ref_lists_and_route_runs_are_rejected() {
    let good = serde_json::to_value(Journal::default()).unwrap();
    for (key, value) in [
        ("installed", json!(1000)),
        ("committed", json!(-1)),
        ("preparing", json!(vec![0; MAX_INTENTS + 1])),
        (
            "generations",
            json!(vec![good[1]["generations"][0].clone(); MAX_GENERATIONS + 1]),
        ),
        (
            "generations",
            json!([good[1]["generations"][0], good[1]["generations"][0]]),
        ),
        (
            "generations",
            json!([good[1]["generations"][0],{"prefixes":[],"targets":{},"revision":88}]),
        ),
        ("extra", json!(true)),
    ] {
        let mut bad = good.clone();
        bad[1][key] = value;
        assert!(serde_json::from_value::<Journal>(bad).is_err(), "{key}");
    }
    let mut duplicate = good.clone();
    duplicate[1]["generations"] = json!([good[1]["generations"][0], good[1]["generations"][0]]);
    duplicate[1]["committed"] = json!(1);
    assert!(serde_json::from_value::<Journal>(duplicate).is_err());
    for input in [
        json!([1]),
        json!(["awg0"]),
        json!(["awg0", "awg1", 1]),
        json!(["awg0", 1, 1]),
        json!(["awg0", 2, 1]),
        json!(["awg0", 1, "awg0", 2]),
        json!(["wg0", 1]),
        json!(["awg0", 1u64 << 32]),
    ] {
        let mut bad = good.clone();
        bad[1]["generations"][0]["prefixes"] = input;
        assert!(serde_json::from_value::<Journal>(bad).is_err());
    }
    let json = serde_json::to_vec(&good).unwrap();
    assert!(serde_json::from_slice::<Journal>(&json[..json.len() - 1]).is_err());
    assert!(serde_json::from_value::<Journal>(json!([99, good[1]])).is_err());
}

#[test]
fn one_zone_65536_hosts_and_ttls_reopen_as_one_generation_after_interruption() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(temp.path()).unwrap();
    let mut plan = Plan {
        packed: true,
        go_ipv4: true,
        revision: 7,
        ..Plan::default()
    };
    plan.targets.insert(
        "awg0".into(),
        Target {
            id: "router".into(),
            public_key: "x".repeat(44),
            mtu: 1400,
        },
    );
    plan.assign_marks(&Default::default()).unwrap();
    let mut members = Vec::new();
    for n in 0..65_536_u32 {
        let ip = Ipv4Addr::from(u32::from(Ipv4Addr::new(77, 0, 0, 1)) + n * 2);
        plan.prefixes.insert(Prefix::host(ip), "awg0".into());
        members.push(Member {
            zone: 0,
            ip: ip.into(),
            until: 1_800_000_000 + u64::from(n),
        });
    }
    let routing = crate::Routing {
        mode: "zones".into(),
        zones: vec![crate::Zone {
            enabled: true,
            domains: vec!["example.test".into()],
            tunnel_id: "router".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    plan.learned = Some(Saved::new(&routing, "a".repeat(64), &members).unwrap());
    drop(members);
    plan.check_handoff_size().unwrap();
    let snapshot = Snapshot::from(plan);
    let payload = snapshot.size().unwrap();
    assert!(payload * 3 > (8 << 20), "exercise the old three-copy limit");
    let before = Journal {
        boot: BOOT.into(),
        installed: snapshot.clone(),
        committed: snapshot.clone(),
        preparing: vec![snapshot; LEGACY_PREPARATIONS],
        expires: 0,
    };
    db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, &before, RECEIPT_LIMIT))
        .unwrap();
    let bytes = std::fs::metadata(temp.path().join(".store/runtime").join(RECEIPT))
        .unwrap()
        .len();
    assert!(
        bytes <= payload + 256,
        "{bytes} bytes on disk for {payload} bytes of route data"
    );
    drop(before);
    let reopened = Journal::read(&db).unwrap();
    assert_eq!(reopened.installed.prefixes.len(), 65536);
    assert_eq!(
        reopened.installed.learned.as_ref().unwrap().members.len(),
        65536
    );
    assert!(reopened
        .preparing
        .iter()
        .chain([&reopened.committed])
        .all(|candidate| Arc::ptr_eq(&candidate.0, &reopened.installed.0)));
    let mut trial = reopened.clone();
    trial.installed.revision += 1;
    trial.preparing.clear();
    // Cut the write just before the complete replacement. The previous
    // readable intent (including all TTLs) must still authorize recovery.
    assert!(db
        .transaction(|tx| tx.save_runtime_bounded(RECEIPT, &trial, bytes))
        .is_err());
    assert_eq!(Journal::read(&db).unwrap(), reopened);
    db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, &trial, RECEIPT_LIMIT))
        .unwrap();
    let persisted = Journal::read(&db).unwrap();
    assert_eq!(persisted.installed.revision, 8);
    assert_eq!(persisted.committed.revision, 7);
    assert!(!Arc::ptr_eq(&persisted.installed.0, &persisted.committed.0));
}

#[test]
fn oversized_generation_cannot_replace_the_previous_receipt() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(temp.path()).unwrap();
    let old = Journal {
        boot: BOOT.into(),
        ..Default::default()
    };
    db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, &old, RECEIPT_LIMIT))
        .unwrap();
    let mut next = old.clone();
    next.installed.targets.insert(
        "awg0".into(),
        Target {
            id: "X".repeat(GENERATION_LIMIT as usize),
            public_key: String::new(),
            mtu: 1400,
        },
    );
    assert!(next.installed.check_handoff_size().is_err());
    assert!(db
        .transaction(|tx| tx.save_runtime_bounded(RECEIPT, &next, RECEIPT_LIMIT))
        .is_err());
    assert_eq!(Journal::read(&db).unwrap(), old);
}
