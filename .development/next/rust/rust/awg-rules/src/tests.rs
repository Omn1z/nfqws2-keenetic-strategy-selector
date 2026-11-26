use super::*;
use nfqws2_awg_profile::{edit_document, read};
use nfqws2_store::Store;
use serde_json::{json, value::RawValue, Value};
use std::io;
fn fixture() -> Value {
    serde_json::from_str(include_str!("../tests/fixtures/go-routing.json")).unwrap()
}
fn raw(v: &Value) -> Box<RawValue> {
    RawValue::from_string(v.to_string()).unwrap()
}
fn db() -> (tempfile::TempDir, Store) {
    let d = tempfile::tempdir().unwrap();
    let db = Store::open(d.path()).unwrap();
    edit_document(&db, |doc| {
        doc["active_id"] = json!("local");
        doc["servers"][0]["id"] = json!("local");
        let c = &mut doc["servers"][0]["config"];
        c["endpoint"] = json!("vpn.example:443");
        c["public_key"] = fixture()["document"]["connections"][0]["server_public_key"].clone();
        c["protocol_version"] = json!("3.1");
        c["client_iface"] = json!("awg0");
        c["unknown_profile_extension"] = json!("preserve");
        Ok(())
    })
    .unwrap();
    (d, db)
}
fn preview_val(db: &Store, v: &Value) -> Value {
    serde_json::to_value(preview(db, &raw(v)).unwrap()).unwrap()
}
fn request(doc: &Value, hash: &Value, mode: &str) -> Value {
    json!({"document":doc,"mode":mode,"expected_policy_hash":hash})
}
fn do_import(db: &Store, v: &Value) -> io::Result<Value> {
    import(db, serde_json::from_value(v.clone()).unwrap())
}
#[test]
fn go_identity_and_policy_hash_roundtrip() {
    let source = fixture();
    let doc: Document = serde_json::from_value(source["document"].clone()).unwrap();
    let r = doc.connections[0].clone();
    r.validate().unwrap();
    assert_eq!(
        policy::policy_hash(&doc.routing, &identity::Refs::from([(r.id.clone(), r)])),
        source["policy_hash"]
    );
    let (_d, db) = db();
    let doc = &source["document"];
    let plan = preview_val(&db, &json!(doc.to_string()));
    assert_eq!(plan["connections"][0]["matched_tunnel_id"], "local");
    assert_eq!(plan["connections"][0]["state"], "matched");
    let result = do_import(&db, &request(doc, &plan["policy_hash"], "replace")).unwrap();
    assert_eq!(result["rule_count"], 1);
    assert_eq!(result["routing_revision"], 1);
    let state = read(&db).unwrap();
    assert_eq!(
        state["servers"][0]["config"]["unknown_profile_extension"],
        "preserve"
    );
    assert_eq!(state["servers"][0]["config"]["routing"]["active"], false);
    let document = serde_json::to_value(export(&db, None, |_, _| unreachable!()).unwrap()).unwrap();
    assert_eq!(document["routing"]["zones"][0]["include_subdomains"], true);
    assert_eq!(document["connections"][0]["ref"], "local");
    assert!(!document.to_string().contains("unknown_profile_extension"));
}
#[test]
fn copies_and_global_settings_preserve_profile_data_and_scoped_priority() {
    let (_d, db) = db();
    edit_document(&db,|doc|{
        let mut second=doc["servers"][0].clone();second["id"]=json!("spare");second["config"]["client_iface"]=json!("awg1");
        second["config"]["routing"]["zones"]=json!([{"name":"old","mode":"exclude","domains":["old.test"],"include_subdomains":false,"enabled":true}]);
        doc["servers"].as_array_mut().unwrap().push(second);Ok(())
    }).unwrap();
    assert_eq!(copy(&db, "spare").unwrap(), 1);
    let before = read(&db).unwrap();
    let r:Routing=serde_json::from_value(json!({"mode":"include","mtu":1390,"domain_source":"dnsproxy","zones":[{"name":"edited","domains":["edited.test"],"enabled":true}]})).unwrap();
    save_settings(&db, r).unwrap();
    let doc = read(&db).unwrap();
    assert_eq!(doc["routing"]["mode"], "zones");
    assert_eq!(doc["routing"]["mtu"], 1390);
    assert_eq!(
        doc["servers"][1]["config"]["routing"]["zones"],
        before["servers"][1]["config"]["routing"]["zones"]
    );
    assert_eq!(
        doc["servers"][0]["config"]["unknown_profile_extension"],
        "preserve"
    );
    let mut rules = policy::current(&doc).unwrap();
    rules.zones.reverse();
    save(&db, rules).unwrap();
    let after = read(&db).unwrap();
    assert_eq!(
        after["servers"][1]["config"]["routing"]["zones"][0]["order"],
        1
    );
    assert_eq!(
        after["servers"][1]["config"]["routing"]["zones"][0]["route"],
        "direct"
    );
    assert_eq!(
        after["servers"][1]["config"]["routing"]["zones"][0]["include_subdomains"],
        false
    );
    assert_eq!(after["routing_revision"], 3);
}
#[test]
fn lost_ack_append_is_idempotent_with_or_without_saved_editor_base_and_concurrent_edit_conflicts() {
    let (_d, db) = db();
    let src = fixture()["document"].clone();
    let plan = preview_val(&db, &src);
    let input = request(&src, &plan["policy_hash"], "append");
    let a = do_import(&db, &input).unwrap();
    let b = do_import(&db, &input).unwrap();
    assert_eq!(a, b);
    let plan = preview_val(&db, &src);
    let mut draft = request(&src, &plan["policy_hash"], "append");
    draft["base_routing"] = a["routing"].clone();
    let a = do_import(&db, &draft).unwrap();
    assert_eq!(a["rule_count"], 2);
    assert_eq!(do_import(&db, &draft).unwrap(), a);
    insert_top(&db, "priority", "client.test", "direct").unwrap();
    assert_eq!(
        do_import(&db, &draft).unwrap_err().kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(
        read(&db).unwrap()["servers"][0]["config"]["routing"]["zones"][0]["domains"],
        json!(["client.test"])
    );
}
#[test]
fn changed_identity_requires_selection_and_preserves_waiting() {
    let (_d, db) = db();
    let source = fixture()["document"].clone();
    edit_document(&db, |doc| {
        let mut row = doc["servers"][0].clone();
        row["id"] = json!("second");
        doc["servers"].as_array_mut().unwrap().push(row);
        Ok(())
    })
    .unwrap();
    edit_document(&db, |doc| {
        doc["servers"][0]["config"]["endpoint"] = json!("changed.test:443");
        Ok(())
    })
    .unwrap();
    let plan = preview_val(&db, &source);
    assert_eq!(plan["connections"][0]["state"], "missing");
    let mut req = request(&source, &plan["policy_hash"], "replace");
    assert!(do_import(&db, &req).is_err());
    req["mappings"] = json!({"source":"local"});
    req["mapping_fingerprints"] = json!({"source":"different"});
    assert!(do_import(&db, &req).is_err());
    req["mappings"] = json!({"source":""});
    req["mapping_fingerprints"] = json!({});
    let result = do_import(&db, &req).unwrap();
    assert_eq!(result["waiting_rule_count"], 1);
    let state = read(&db).unwrap();
    let id = state["pending_rules"][0]["tunnel_id"].as_str().unwrap();
    assert!(id.starts_with("pending-import-"));
    assert_eq!(
        state["connection_refs"][id]["fingerprint"],
        source["connections"][0]["fingerprint"]
    );
    let again = serde_json::to_value(export(&db, None, |_, _| unreachable!()).unwrap()).unwrap();
    assert_eq!(again["connections"][0]["ref"], id);
}
#[test]
fn drafts_expand_snapshot_sources_and_reject_invalid_documents_without_mutation() {
    let (d, db) = db();
    let source = fixture()["document"].clone();
    let mut r: Routing = serde_json::from_value(source["routing"].clone()).unwrap();
    r.zones[0].tunnel_id = "local".into();
    r.zones[0].domains = vec!["list:saved".into(), "GeoIP:private".into()];
    let mut visited = Vec::new();
    let doc = export(&db, Some(r.clone()), |kind, key| {
        visited.push((kind.to_owned(), key.to_owned()));
        Ok(vec![if kind == "list" {
            "example.org"
        } else {
            "192.0.2.0/24"
        }
        .into()])
    })
    .unwrap();
    assert_eq!(doc.routing.zones[0].domains, ["example.org"]);
    assert!(doc.routing.zones[0].ips.contains(&"192.0.2.0/24".into()));
    assert_eq!(visited.len(), 2);
    assert!(export(&db, Some(r), |_, _| Ok(vec!["geosite:nested".into()])).is_err());
    let file = d.path().join("awg.json");
    let before = std::fs::read(&file).unwrap();
    let mut invalid = source.clone();
    invalid["routing"]["zones"][0]["ips"] = json!(["bad input"]);
    assert!(preview(&db, &raw(&invalid)).is_err());
    let duplicate = source
        .to_string()
        .replace("\"version\":1", "\"version\":1,\"version\":1");
    assert!(preview(&db, &raw(&json!(duplicate))).is_err());
    let mut unknown = source.clone();
    unknown["routing"]["unused"] = json!(true);
    assert!(preview(&db, &raw(&unknown)).is_err());
    assert_eq!(before, std::fs::read(file).unwrap());
}
