use super::*;
use serde_json::json;
#[test]
fn history_is_bound_to_current_semantic_rule_and_is_never_kernel_confirmation() {
    let tmp = tempfile::tempdir().unwrap();
    let db = Store::open(tmp.path()).unwrap();
    let zone = json!({"name":"test","route":"tunnel","domains":["corp.example","list:Local","regexp:^srv[0-9]+\\.net$","a##.test"],"tunnel_id":"awg0","enabled":true});
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["config"]["routing"] =
            json!({"mode":"zones","zones":[zone.clone(),zone.clone()]});
        Ok(())
    })
    .unwrap();
    let session = Recent::default();
    let initial = snapshot(&db, |_, _| unreachable!(), false, false, 0, &session).unwrap();
    let key = initial.rules[0].rule_key.clone();
    let rec = |d: &str, n: i64| json!({"rule_key":key,"domain":d,"ips":["::ffff:192.0.2.1","192.0.2.1","::"],"source":"dns","source_ips":[],"first_seen":1,"last_seen":n,"additional":true,"confirmed":true});
    std::fs::write(tmp.path().join(FILE),json!({"version":1,"entries":[rec("a.corp.example",1),rec("wrong.org",2),rec("srv3.net",4),rec("ab1.test",3),rec("other.example",5)]}).to_string()).unwrap();
    let snap = snapshot(
        &db,
        |kind, name| {
            assert_eq!((kind, name), ("list", "Local"));
            Ok(vec!["other.example".into()])
        },
        false,
        false,
        3,
        &session,
    )
    .unwrap();
    assert!(Arc::ptr_eq(&snap.rules[0].entries, &snap.rules[1].entries));
    let rows = &snap.rules[0].entries;
    assert_eq!(
        rows.iter().map(|r| r.domain.as_str()).collect::<Vec<_>>(),
        ["other.example", "srv3.net", "ab1.test", "a.corp.example"]
    );
    assert!(
        !rows[0].additional
            && rows[3].additional
            && rows.iter().all(|r| !r.confirmed && r.ips == ["192.0.2.1"])
    );
    assert!(!snap.ready);
    std::fs::write(
        tmp.path().join(FILE),
        json!({"version":2,"entries":[]}).to_string(),
    )
    .unwrap();
    assert!(snapshot(&db, |_, _| unreachable!(), false, false, 0, &session).is_err());
}
#[test]
fn key_normalizes_sets_but_preserves_fallback_order_and_list_case() {
    let z:Zone=serde_json::from_value(json!({"route":"tunnel","domains":["EXAMPLE.ORG","list:Upper","example.org"],"fallback_tunnel_ids":["b","a"]})).unwrap();
    let expected = rule_key(&z).unwrap();
    assert_eq!(
        expected,
        "957b338b9bf8ad2202c47e3474b9b1f29021991facedfc9d1e1336e09d5a1c5d"
    );
    let mut z = z;
    z.domains.swap(0, 1);
    z.name = "renamed".into();
    assert_eq!(rule_key(&z).unwrap(), expected);
    z.fallback_tunnel_ids.reverse();
    assert_ne!(rule_key(&z).unwrap(), expected);
    z.fallback_tunnel_ids.reverse();
    z.domains[0] = "list:upper".into();
    assert_ne!(rule_key(&z).unwrap(), expected);
}

#[test]
fn live_confirmations_merge_with_go_ips_and_expire_on_same_revision_reapply() {
    let tmp = tempfile::tempdir().unwrap();
    let db = Store::open(tmp.path()).unwrap();
    let zone: Zone = serde_json::from_value(
        json!({"name":"vpn","route":"tunnel","domains":["*.corp.example"],"enabled":true}),
    )
    .unwrap();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["config"]["routing"] =
            json!({"mode":"zones","domain_source":"dnsproxy","zones":[zone]});
        Ok(())
    })
    .unwrap();
    let policy = crate::observed::Policy::compile(
        &policy::current(&nfqws2_awg_profile::read(&db).unwrap()).unwrap(),
    )
    .unwrap();
    let key = policy
        .history_match(0, "a.corp.example")
        .unwrap()
        .0
        .to_owned();
    let old = json!({"rule_key":key,"domain":"a.corp.example","ips":["192.0.2.1"],"source":"dns","source_ips":["192.168.1.2"],"first_seen":1,"last_seen":2,"additional":true});
    std::fs::write(
        tmp.path().join(FILE),
        json!({"version":1,"entries":[old]}).to_string(),
    )
    .unwrap();
    let recent = Recent::default();
    let newer = "2001:db8::1".parse().unwrap();
    let read =
        |revision| snapshot(&db, |_, _| unreachable!(), true, true, revision, &recent).unwrap();
    recent.confirm(
        3,
        (&key, true),
        "a.corp.example",
        Some("192.168.1.3".parse().unwrap()),
        &[newer],
    );
    let snap = read(3);
    let row = &snap.rules[0].entries[0];
    assert!(!row.confirmed);
    assert_eq!(row.first_seen, 1);
    assert!(row.last_seen > 2 && row.additional);
    assert_eq!(row.ips, ["192.0.2.1", "2001:db8::1"]);
    assert_eq!(
        row.source_ips.as_ref().unwrap(),
        &["192.168.1.2", "192.168.1.3"]
    );
    recent.confirm(
        3,
        (&key, true),
        "a.corp.example",
        None,
        &["192.0.2.1".parse().unwrap()],
    );
    assert!(read(3).rules[0].entries[0].confirmed);
    assert!(!read(4).rules[0].entries[0].confirmed);
    recent.invalidate();
    assert!(!read(3).rules[0].entries[0].confirmed);
    recent.confirm(3, (&key, true), "a.corp.example", None, &[newer]);
    assert!(!read(3).rules[0].entries[0].confirmed);
    for n in 0..300 {
        recent.confirm(
            3,
            (&key, true),
            &format!("x{n}.corp.example"),
            None,
            &[newer],
        );
    }
    let snap = read(3);
    assert_eq!(snap.rules[0].entries.len(), 301);
}

#[test]
fn buffered_history_survives_restart_without_restoring_confirmation() {
    let dir = tempfile::tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    let address = "2001:db8::2".parse().unwrap();
    let name = "dns.example";
    let zone = json!({"route":"tunnel","domains":[name],"enabled":true});
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["config"]["routing"] = json!({"mode":"zones","zones":[zone]});
        Ok(())
    })
    .unwrap();
    let saved_policy = policy::current(&nfqws2_awg_profile::read(&db).unwrap()).unwrap();
    let key = rule_key(&saved_policy.zones[0]).unwrap();
    let recent = Recent::default();
    recent.confirm(4, (&key, false), name, None, &[address]);
    assert!(!dir.path().join(FILE).exists());
    recent.flush(&db).unwrap();
    assert!(
        snapshot(&db, |_, _| unreachable!(), true, true, 4, &recent)
            .unwrap()
            .rules[0]
            .entries[0]
            .confirmed
    );
    let wire: serde_json::Value = db.read(FILE).unwrap();
    let entry = &wire["entries"][0];
    assert_eq!(entry["rule_key"], key);
    assert_eq!(entry["additional"], false);
    assert!(entry.get("confirmed").is_none());
    let restarted = Recent::default();
    let record = snapshot(&db, |_, _| unreachable!(), true, true, 4, &restarted).unwrap();
    assert_eq!(record.rules[0].entries[0].ips, [address.to_string()]);
    assert!(!record.rules[0].entries[0].confirmed);
    recent.confirm(4, (&key, false), "different.example", None, &[address]);
    recent.reset_after_restore();
    recent.flush(&db).unwrap();
    assert_eq!(db.read::<serde_json::Value>(FILE).unwrap(), wire);
}
