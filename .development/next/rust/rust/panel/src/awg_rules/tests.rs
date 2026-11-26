use super::*;
use axum::{
    body::{to_bytes, Body},
    http::Request,
    Router,
};
use std::io::Write;
use tower::ServiceExt;
#[tokio::test]
async fn routing_http_off_noop_legacy_refusal_and_idle_shutdown() {
    let tmp = tempfile::tempdir().unwrap();
    let state = crate::http::AppState::open(
        nfqws2_config::Config {
            data_dir: tmp.path().join("db").display().to_string(),
            ..Default::default()
        },
        tmp.path(),
        true,
    )
    .unwrap();
    kernel::restore(&state).await;
    let app = crate::http::router(state.clone());
    query(&app, "POST", "apply", String::new(), 200).await;
    query(&app, "POST", "commit", String::new(), 400).await;
    query(&app, "POST", "teardown", String::new(), 200).await;
    nfqws2_awg_profile::edit_document(&state.store, |doc| {
        doc["routing"] = json!({"mode":"full"});
        doc["servers"][0]["config"]["routing"]["active"] = json!(true);
        Ok(())
    })
    .unwrap();
    query(&app, "POST", "apply", String::new(), 400).await;
    query(&app, "POST", "teardown", String::new(), 400).await;
    assert_eq!(
        nfqws2_awg_profile::read(&state.store).unwrap()["servers"][0]["config"]["routing"]
            ["active"],
        true
    );
    tokio::time::timeout(std::time::Duration::from_secs(2), kernel::shutdown(&state))
        .await
        .unwrap();
}
async fn query(app: &Router, method: &str, path: &str, body: String, code: u16) -> Value {
    let req = Request::builder()
        .method(method)
        .uri(format!("/api/awg2/routing/{path}"))
        .body(Body::from(body))
        .unwrap();
    let response = app.clone().oneshot(req).await.unwrap();
    let actual = response.status();
    let bytes = to_bytes(response.into_body(), 3 << 20).await.unwrap();
    assert_eq!(actual.as_u16(), code, "{}", String::from_utf8_lossy(&bytes));
    if code == 413 {
        return Value::Null;
    }
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn apply_with_no_configured_dns_preserves_the_saved_policy() {
    let root = tempfile::tempdir().unwrap();
    let state = crate::http::AppState::open(
        nfqws2_config::Config {
            data_dir: root.path().join("db").display().to_string(),
            ..Default::default()
        },
        root.path(),
        true,
    )
    .unwrap();
    let app = crate::http::router(state.clone());
    std::fs::create_dir(root.path().join("etc")).unwrap();
    std::fs::write(root.path().join("etc/resolv.conf"), "# empty\n").unwrap();
    query(
        &app,
        "POST",
        "config",
        json!({"mode":"zones","domain_source":"resolve","zones":[{
            "name":"office","tunnel_id":"awg0","order":1,"route":"tunnel","mode":"include",
            "domains":["office.example"],"include_subdomains":false,"enabled":true
        }]})
        .to_string(),
        200,
    )
    .await;
    let previous = nfqws2_awg_profile::read(&state.store).unwrap();
    let error = query(&app, "POST", "apply", String::new(), 400).await;
    assert!(error.to_string().contains("resolv.conf"), "{error}");
    assert_eq!(nfqws2_awg_profile::read(&state.store).unwrap(), previous);
    let status =
        nfqws2_awg_rules::kernel::inspect(&state.store, &nfqws2_router_command::System).unwrap();
    assert!(!status.active && !status.pending_commit);
    query(
        &app,
        "POST",
        "config",
        json!({"mode":"zones","domain_source":"dnsproxy","zones":[{
            "name":"office","enabled":true,"tunnel_id":"awg0","domains":["*.office.example"]
        }]})
        .to_string(),
        200,
    )
    .await;
    let error = query(&app, "POST", "apply", String::new(), 400).await;
    assert!(error.to_string().contains("DNS-сервер панели"), "{error}");
    let status =
        nfqws2_awg_rules::kernel::inspect(&state.store, &nfqws2_router_command::System).unwrap();
    assert!(!status.active && !status.pending_commit);
    kernel::shutdown(&state).await;
}
#[tokio::test]
async fn http_routing_snapshot_import_and_concurrent_editor_edits() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir(root.join("lists")).unwrap();
    let mut gz = flate2::write::GzEncoder::new(
        File::create(root.join("lists/my.list.gz")).unwrap(),
        flate2::Compression::fast(),
    );
    gz.write_all(b"# note\nexample.test\n192.0.2.15\n").unwrap();
    gz.finish().unwrap();
    let state = crate::http::AppState::open(
        nfqws2_config::Config {
            data_dir: root.join("db").display().to_string(),
            nfqws2_conf: root.join("nfqws2.conf").display().to_string(),
            ..Default::default()
        },
        root,
        true,
    )
    .unwrap();
    let app = crate::http::router(state);
    let st = query(
        &app,
        "POST",
        "rules/insert-top",
        json!({"domain":"list:my","route":"direct"}).to_string(),
        200,
    )
    .await;
    assert_eq!(st["routing_rules"][0]["domains"], json!(["list:my"]));
    assert_eq!(st["routing_state"]["ready"], false);
    let exported = query(&app, "GET", "rules/export", String::new(), 200).await;
    assert_eq!(
        exported["routing"]["zones"][0]["domains"],
        json!(["example.test"])
    );
    assert_eq!(
        exported["routing"]["zones"][0]["ips"],
        json!(["192.0.2.15"])
    );
    let st = query(
        &app,
        "POST",
        "rules/import/preview",
        json!({"document":exported.to_string()}).to_string(),
        200,
    )
    .await;
    let hash = &st["policy_hash"];
    let req=json!({"document":exported,"expected_policy_hash":hash,"mode":"replace","mappings":{"awg0":""}}).to_string();
    query(
        &app,
        "POST",
        "rules/insert-top",
        json!({"domain":"critical.test","route":"tunnel"}).to_string(),
        200,
    )
    .await;
    query(&app, "POST", "rules/import", req, 409).await;
    query(
        &app,
        "POST",
        "rules/import",
        r#"{"document":{},"mappings":{"a":"1","a":"2"}}"#.into(),
        400,
    )
    .await;
    query(&app, "POST", "rules/import", " ".repeat((8 << 20) + 1), 413).await;
    let src = query(&app, "GET", "rules/export", String::new(), 200).await;
    let st = query(
        &app,
        "POST",
        "rules/import/preview",
        json!({"document":src}).to_string(),
        200,
    )
    .await;
    let imported=query(&app,"POST","rules/import",json!({"document":src,"expected_policy_hash":st["policy_hash"],"mode":"replace","mappings":{"awg0":""}}).to_string(),200).await;
    assert_eq!(imported["waiting_rule_count"], 2);
}

#[tokio::test]
async fn deleted_optional_list_preserves_other_entries_in_discovery_history() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir(root.join("lists")).unwrap();
    let config = nfqws2_config::Config {
        data_dir: root.join("db").display().to_string(),
        nfqws2_conf: root.join("nfqws2.conf").display().to_string(),
        ..Default::default()
    };
    let app = crate::http::router(crate::http::AppState::open(config, root, true).unwrap());
    let zone = json!({"enabled":true,"name":"office","tunnel_id":"awg0","domains":["office.example","list:deleted"],"include_subdomains":false});
    query(
        &app,
        "POST",
        "config",
        json!({"mode":"zones","zones":[zone]}).to_string(),
        200,
    )
    .await;
    let initial = query(&app, "GET", "discovered", String::new(), 200).await;
    let key = &initial["rules"][0]["rule_key"];
    let rows: Vec<_> = ["office.example", "unrelated.example"].into_iter().map(|name|
        json!({"rule_key":key,"domain":name,"ips":["192.0.2.8"],"source":"dns","first_seen":1,"last_seen":2,"additional":false})
    ).collect();
    std::fs::write(
        root.join("db/awg-routing-learned.json"),
        json!({"version":1,"entries":rows}).to_string(),
    )
    .unwrap();
    let result = query(&app, "GET", "discovered", String::new(), 200).await;
    let entries = result["rules"][0]["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["domain"], "office.example");
    assert_eq!(entries[0]["confirmed"], false);
}
