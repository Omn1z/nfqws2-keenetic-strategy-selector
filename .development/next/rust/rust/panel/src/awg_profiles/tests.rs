use crate::http;
use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use serde_json::{json, Value};
use tower::ServiceExt;

use super::ENDPOINT_BACKUPS_REQUIRED;

#[tokio::test]
async fn add_server_accepts_go_optional_name_payloads() {
    let dir = tempfile::tempdir().unwrap();
    let state = http::AppState::open(
        nfqws2_config::Config {
            data_dir: dir.path().display().to_string(),
            ..Default::default()
        },
        dir.path(),
        true,
    )
    .unwrap();
    let app = http::router(state.clone());
    for (body, expected) in [
        ("", ""),
        ("null", ""),
        ("{}", ""),
        (r#"{"name":42}"#, ""),
        (r#"{"name":"bad"#, ""),
        (r#"{"name":"before","NAME":" named ","NaMe":null} true"#, "named"),
    ] {
        let request = Request::post("/api/awg2/servers")
            .body(Body::from(body))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::OK
        );
        let saved = nfqws2_awg_profile::read(&state.store).unwrap();
        let selected = saved["servers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == saved["active_id"])
            .unwrap();
        assert_eq!(selected["name"], expected);
    }
}

#[tokio::test]
async fn local_import_status_export_peers_and_firmware_error_through_router() {
    let dir = tempfile::tempdir().unwrap();
    let state = http::AppState::open(
        nfqws2_config::Config {
            data_dir: dir.path().display().to_string(),
            ..Default::default()
        },
        dir.path(),
        true,
    )
    .unwrap();
    let app = http::router(state.clone());
    let req = |method: &str, path: &str, body: Value| {
        Request::builder()
            .method(method)
            .uri(path)
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let send = |method: &str, path: &str, body: Value| {
        let fut = app.clone().oneshot(req(method, path, body));
        async move {
            let r = fut.await.unwrap();
            let (head, body) = r.into_parts();
            let bytes = to_bytes(body, 1 << 20).await.unwrap();
            (head, bytes)
        }
    };
    let api = |method: &str, path: &str, body: Value| {
        let r = send(method, path, body);
        async move {
            let (head, bytes) = r.await;
            assert_eq!(head.status, StatusCode::OK);
            serde_json::from_slice::<Value>(&bytes).unwrap()
        }
    };
    let private = format!("B{}=", "A".repeat(42));
    let public = format!("C{}=", "A".repeat(42));
    let conf=format!("[Interface]\nAddress = 10.0.0.7/32\nPrivateKey = {private}\n[Peer]\nPublicKey = {public}\nEndpoint = 192.0.2.11:777\nAllowedIPs = 10.0.0.0/24\n");
    let profile = api(
        "POST",
        "/api/awg2/import",
        json!({"name":"imported","conf":conf}),
    )
    .await;
    assert_ne!(profile["active_server_id"], "awg0");
    assert_eq!(profile["ssh_host_key_enrollment"], true);
    assert_eq!(
        send(
            "POST",
            "/api/awg2/status/refresh",
            json!({"trust_on_first_use":true,"server_id":"awg0"})
        )
        .await
        .0
        .status,
        StatusCode::FORBIDDEN
    );
    assert!(!profile.to_string().contains(&private));
    for path in ["/api/awg2/deploy", "/api/awg2/servers/absent/deploy"] {
        let response = api("POST", path, json!({})).await;
        assert_eq!(response["ok"], false);
        assert_eq!(response["result"]["listening"], false);
        assert!(response["error"].is_string());
        assert!(!response.to_string().contains(&private));
    }
    let batch = api(
        "POST",
        "/api/awg2/servers/deploy",
        json!({"ids":[" ",profile["active_server_id"]," unknown "]}),
    )
    .await;
    let items = batch["results"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["label"], "imported");
    assert_eq!(items[0]["ok"], false);
    assert_eq!(items[1]["id"], "unknown");
    assert_eq!(items[1]["label"], "");
    assert_eq!(
        items[1]["result"],
        json!({"ok":false,"method":"","wan_iface":"","listening":false,"handshake":false,"steps":null})
    );
    assert_eq!(
        send("POST", "/api/awg2/servers/deploy", json!({"ids":42}))
            .await
            .0
            .status,
        400
    );
    assert_eq!(
        send("POST", "/api/awg2/warp", json!({"accept_tos":false}))
            .await
            .0
            .status,
        400
    );
    assert_eq!(
        send(
            "POST",
            "/api/awg2/warp",
            json!({"accept_tos":true,"endpoint":"bad host:101"})
        )
        .await
        .0
        .status,
        400
    );
    assert_eq!(
        send("POST", "/api/awg2/config", json!({"mtu":9999}))
            .await
            .0
            .status,
        400
    );
    let updated = api(
        "POST",
        "/api/awg2/config",
        json!({"mtu":1350,"private_key":"forged value","peers":[]}),
    )
    .await;
    assert_eq!(updated["config"]["mtu"], 1350);
    assert_eq!(updated["config"]["peers"].as_array().unwrap().len(), 1);
    assert!(!updated.to_string().contains(&private));
    let failover = format!(
        "/api/awg2/servers/{}/failover",
        profile["active_server_id"].as_str().unwrap()
    );
    let policy=api("POST",&failover,json!({"standby":true,"fallback_tunnel_ids":["awg0"],"double_tunnel_id":"","double_tunnel_mode":"last_resort"})).await;
    assert_eq!(policy["config"]["client"]["standby"], true);
    let item = policy["servers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == profile["active_server_id"])
        .unwrap();
    assert_eq!(item["failover"]["active_tunnel_id"], "");
    assert_eq!(
        send(
            "POST",
            "/api/awg2/servers/awg0/failover",
            json!({"fallback_tunnel_ids":[profile["active_server_id"]]})
        )
        .await
        .0
        .status,
        400
    );
    let nested = api(
        "POST",
        &failover,
        json!({"double_tunnel_id":"awg0","double_tunnel_mode":"automatic"}),
    )
    .await;
    assert_eq!(nested["config"]["client"]["double_tunnel_id"], "awg0");
    assert_eq!(
        nested["config"]["client"]["double_tunnel_mode"],
        "automatic"
    );
    assert_eq!(
        send(
            "POST",
            &failover,
            json!({"double_tunnel_id":profile["active_server_id"]})
        )
        .await
        .0
        .status,
        400
    );
    let reset = api(
        "POST",
        &failover,
        json!({"standby":false,"fallback_tunnel_ids":[],"double_tunnel_id":""}),
    )
    .await;
    assert_eq!(reset["config"]["client"]["standby"], false);
    let backups = format!(
        "/api/awg2/servers/%20{}%20/endpoint-backups",
        profile["active_server_id"].as_str().unwrap()
    );
    for invalid in [Value::Null, json!({}), json!({"endpoint_backups": null})] {
        let (response, bytes) = send("POST", &backups, invalid).await;
        assert_eq!(response.status, 400);
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap()["error"],
            ENDPOINT_BACKUPS_REQUIRED
        );
    }
    assert_eq!(
        send("POST", &backups, json!({"endpoint_backups":["bad.test"]}))
            .await
            .0
            .status,
        400
    );
    let saved = api(
        "POST",
        &backups,
        json!({"ENDPOINT_BACKUPſ":[null,"192.0.2.77","[2001:db8::5]:443"],"unused":true}),
    )
    .await;
    assert_eq!(
        saved["config"]["client"]["endpoint_backups"],
        json!(["192.0.2.77:777", "[2001:db8::5]:443"])
    );
    let cleared = api("POST", &backups, json!({"endpoint_backups":[]})).await;
    assert!(cleared["config"]["client"]["endpoint_backups"].is_null());
    assert_eq!(
        api("POST", "/api/awg2/status/refresh", Value::Null).await["ok"],
        true
    );
    let mut recovery = profile["recovery_settings"].clone();
    recovery["retry_delay_seconds"] = json!(14);
    assert_eq!(
        api("POST", "/api/awg2/settings/recovery", recovery.clone()).await["recovery_settings"],
        recovery
    );
    let mut aliases = recovery.clone();
    aliases.as_object_mut().unwrap().remove("handshake_timeout_seconds");
    aliases["HANDſHAKE_TIMEOUT_ſECONDſ"] = json!(18);
    aliases["unknown"] = json!({"future":true});
    recovery["handshake_timeout_seconds"] = json!(18);
    assert_eq!(
        api("POST", "/api/awg2/settings/recovery", aliases).await["recovery_settings"],
        recovery
    );
    let before_rejected_recovery = recovery.clone();
    recovery["retry_delay_seconds"] = json!(31);
    let (head, body) = send("POST", "/api/awg2/settings/recovery", recovery).await;
    assert_eq!(head.status, 400);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["error"],
        "обычная пауза повторов: допустимо от 1 до 30 секунд"
    );
    assert_eq!(
        api("GET", "/api/awg2", Value::Null).await["recovery_settings"],
        before_rejected_recovery
    );
    let dash = api("GET", "/api/dashboard", Value::Null).await;
    assert_eq!(dash["awg"][0]["label"], "imported");
    assert_eq!(dash["awg"][0]["address"], "10.0.0.7/32");
    assert!(!dash.to_string().contains(&private));
    for format in ["conf", "vpn"] {
        let (head, bytes) = send(
            "GET",
            &format!("/api/awg2/peers/router/config?format={format}"),
            Value::Null,
        )
        .await;
        assert_eq!(head.status, 200);
        assert_eq!(head.headers[header::CACHE_CONTROL], "no-store");
        let text = std::str::from_utf8(&bytes).unwrap();
        if format == "conf" {
            assert!(text.contains(&private));
        } else {
            assert!(text.starts_with("vpn://"));
        }
    }
    assert_eq!(
        send("POST", "/api/awg2/client/up", json!({}))
            .await
            .0
            .status,
        400
    );
    assert_eq!(
        api("GET", "/api/awg2", Value::Null).await["config"]["client"]["enabled"],
        false
    );
    assert_eq!(
        api("POST", "/api/awg2/peers", json!({"name":"external"})).await["ok"],
        false
    );
    let mut cross = req("POST", "/api/awg2/client/down", json!({}));
    cross
        .headers_mut()
        .insert(header::ORIGIN, "https://other.test".parse().unwrap());
    cross
        .headers_mut()
        .insert(header::HOST, "router.test".parse().unwrap());
    assert_eq!(app.clone().oneshot(cross).await.unwrap().status(), 403);
    let new = api("POST", "/api/awg2/servers", json!({"name":"local"})).await;
    let id = new["active_server_id"].as_str().unwrap();
    let enabled = format!("/api/awg2/servers/{id}/enabled");
    assert_eq!(
        api("POST", &enabled, json!({"enabled":false})).await["config"]["enabled"],
        false
    );
    assert_eq!(
        api("POST", &enabled, json!({"enabled":true})).await["config"]["enabled"],
        true
    );
    assert_eq!(
        api("POST", "/api/awg2/status/refresh", Value::Null).await["ok"],
        false
    );
    let peer = api(
        "POST",
        "/api/awg2/peers",
        json!({"name":"new","id":"fixture"}),
    )
    .await;
    assert_eq!(peer["ok"], true);
    assert_eq!(peer["peer"]["private_key"], "");
    assert_eq!(peer["peer"]["psk"], "");
    assert_eq!(
        api("DELETE", "/api/awg2/peers/fixture", Value::Null).await["status"],
        "ok"
    );
    let delete = format!("/api/awg2/servers/{id}");
    assert_eq!(
        send("DELETE", &format!("{delete}?replacement_id="), Value::Null)
            .await
            .0
            .status,
        400
    );
    let removed = api(
        "DELETE",
        &format!("{delete}?replacement_id=awg0"),
        Value::Null,
    )
    .await;
    assert_eq!(removed["active_server_id"], "awg0");
    assert!(removed["connection_refs"].get(id).is_none());
    assert_eq!(removed["connection_refs"]["awg0"]["ref"], "awg0");

    let managed = api("POST", "/api/awg2/servers", json!({"name":"managed WG"})).await;
    nfqws2_awg_profile::edit_document(&state.store, |doc| {
        let row = doc["servers"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|r| r["id"] == managed["active_server_id"])
            .unwrap();
        let cfg = &mut row["config"];
        cfg["deployed_at"] = json!(100);
        cfg["native_vpn_tool"] = json!("wg");
        cfg["protocol"] = json!("wireguard");
        cfg["conn"]["host"] = json!("vpn.example.test");
        cfg["conn"]["known_key"] = json!("ssh-ed25519 ZGVmZW5zaXZlLWZpeHR1cmU=");
        Ok(())
    })
    .unwrap();
    let mut stable = Value::Null;
    for _ in 0..2 {
        let reply = api("POST", "/api/awg2/peers", json!({"name":"desktop"})).await;
        assert_eq!(reply["ok"], false); // The fixture root never starts SSH.
        assert_eq!(reply["peer"]["name"], "desktop");
        assert_eq!(reply["peer"]["private_key"], "");
        assert_eq!(reply["peer"]["psk"], "");
        if !stable.is_null() {
            assert_eq!(reply["peer"], stable);
        }
        stable = reply["peer"].clone();
    }
    let stored = api("GET", "/api/awg2", Value::Null).await;
    assert_eq!(stored["deployment_pending"], true);
    let path = format!("/api/awg2/peers/{}", stable["id"].as_str().unwrap());
    assert_eq!(send("DELETE", &path, Value::Null).await.0.status, 400);
}

#[tokio::test]
async fn delete_transfers_dormant_awg_dependencies_via_the_normal_panel_route() {
    let dir = tempfile::tempdir().unwrap();
    let state = http::AppState::open(
        nfqws2_config::Config {
            data_dir: dir.path().display().to_string(),
            ..Default::default()
        },
        dir.path(),
        true,
    )
    .unwrap();
    nfqws2_awg_profile::edit_document(&state.store, |doc| {
        let row = |id: &str| {
            let mut config = doc["servers"][0]["config"].clone();
            config.as_object_mut().unwrap().remove("client_iface");
            config["client"]["enabled"] = json!(false);
            config["routing"]["mode"] = json!("zones");
            json!({"id":id,"name":id,"config":config})
        };
        let mut source = row("source");
        let mut target = row("target");
        let mut consumer = row("consumer");
        let reserve_a = row("reserve-a");
        let reserve_b = row("reserve-b");
        source["config"]["client"]["fallback_tunnel_ids"] =
            json!(["reserve-a", "reserve-b", "missing-reserve"]);
        source["config"]["routing"]["zones"] = json!([
            {"id":"moved","name":"moved","order":1,"enabled":false,"ips":["203.0.113.1/32"]}
        ]);
        target["config"]["client"] = json!({
            "enabled":false,"peer_id":"draft-peer","standby":true,
            "fallback_tunnel_ids":["source","reserve-b"],"double_tunnel_id":"source",
            "double_tunnel_mode":"automatic"
        });
        target["config"]["endpoint"] = json!("192.0.2.61:8443");
        target["config"]["public_key"] = json!(format!("B{}=", "A".repeat(42)));
        target["applied_config"] = target["config"].clone();
        target["applied_config"]["endpoint"] = json!("192.0.2.60:443");
        target["applied_config"]["client"]["peer_id"] = json!("applied-peer");
        target["applied_config"]["applied_fixture_field"] = json!({"retained":true});
        target["config"]["routing"]["zones"] = json!([
            {"id":"stays","name":"stays","order":1,"enabled":true,"ips":["203.0.113.2/32"],
                "fallback_tunnel_ids":["source","reserve-b"]}
        ]);
        consumer["config"]["client"]["fallback_tunnel_ids"] =
            json!(["source", "reserve-b", "target"]);
        consumer["config"]["client"]["double_tunnel_id"] = json!("source");
        consumer["config"]["client"]["double_tunnel_mode"] = json!("preferred");
        *doc = json!({
            "routing_revision":41,"routing":{"mode":"zones","active":false},
            "servers":[source,target,consumer,reserve_a,reserve_b],
            "connection_refs":{
                "missing":{"ref":"old-alias","label":"Deferred","private_fixture":"excluded"},
                "unreferenced":{"ref":"unreferenced","label":"Old"}
            },
            "pending_rules":[
                {"id":"waiting","name":"waiting","tunnel_id":"source","order":2,
                    "waiting_for_connection":true,"enabled":false},
                {"id":"unrelated","name":"unrelated","tunnel_id":"missing","order":0,
                    "waiting_for_connection":true,"enabled":false}
            ]
        });
        Ok(())
    })
    .unwrap();
    let app = http::router(state.clone());
    let delete = |query: &str| {
        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/api/awg2/servers/source?{query}"))
            .body(Body::empty())
            .unwrap();
        app.clone().oneshot(request)
    };
    let before = nfqws2_awg_profile::read(&state.store).unwrap();
    assert_eq!(
        delete("replacement_id=target&replacement_id=consumer")
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(nfqws2_awg_profile::read(&state.store).unwrap(), before);

    let response = delete("replacement_id=%20target%20").await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let status: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1 << 20).await.unwrap()).unwrap();
    assert_eq!(status["active_server_id"], "target");
    assert_eq!(status["endpoint"], "192.0.2.60:443");
    assert_eq!(status["deployment_pending"], true);
    assert_eq!(status["routing_state"]["revision"], 42);
    assert_eq!(status["routing_config"]["active"], false);
    let servers = status["servers"].as_array().unwrap();
    assert_eq!(servers.len(), 4);
    assert_eq!(servers[0]["client_iface"], "awg1");
    assert_eq!(servers[1]["client_iface"], "awg2");
    assert_eq!(servers[0]["connected"], false);
    let refs = status["connection_refs"].as_object().unwrap();
    assert_eq!(refs.len(), 5);
    assert!(refs.get("source").is_none());
    assert!(refs.get("unreferenced").is_none());
    assert_eq!(refs["target"]["endpoint"], "192.0.2.61:8443");
    assert_eq!(refs["target"]["client_iface"], "awg1");
    assert_eq!(refs["target"]["fingerprint"].as_str().unwrap().len(), 32);
    assert_eq!(refs["missing"]["ref"], "missing");
    assert_eq!(refs["missing"]["label"], "Deferred");
    assert!(refs["missing"].get("private_fixture").is_none());
    let stored = nfqws2_awg_profile::read(&state.store).unwrap();
    let retained = stored["connection_refs"].as_object().unwrap();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained["missing"], refs["missing"]);
    let target = &stored["servers"][0];
    let applied = &target["applied_config"];
    let config = &target["config"];
    assert_eq!(config["endpoint"], "192.0.2.61:8443");
    assert_eq!(applied["endpoint"], "192.0.2.60:443");
    assert_eq!(applied["client"]["peer_id"], "applied-peer");
    assert_eq!(applied["applied_fixture_field"]["retained"], true);
    assert_eq!(applied["client"]["standby"], true);
    assert_eq!(applied["client"]["enabled"], false);
    assert_eq!(applied["routing"], config["routing"]);
    assert_eq!(
        config["client"]["fallback_tunnel_ids"],
        json!(["reserve-b", "reserve-a", "missing-reserve"])
    );
    assert_eq!(
        applied["client"]["fallback_tunnel_ids"],
        config["client"]["fallback_tunnel_ids"]
    );
    assert_eq!(config["client"]["double_tunnel_id"], "");
    assert_eq!(applied["client"]["double_tunnel_mode"], "automatic");
    let consumer = &stored["servers"][1]["config"]["client"];
    assert_eq!(
        consumer["fallback_tunnel_ids"],
        json!(["target", "reserve-b"])
    );
    assert_eq!(consumer["double_tunnel_id"], "target");
    assert_eq!(consumer["double_tunnel_mode"], "preferred");

    let rules = status["routing_rules"].as_array().unwrap();
    assert_eq!(rules.len(), 4);
    for (idx, (rule, expected)) in rules
        .iter()
        .zip(["moved", "stays", "waiting", "unrelated"])
        .enumerate()
    {
        assert_eq!(rule["name"], expected);
        assert_eq!(rule["order"], idx + 1);
    }
    assert_eq!(rules[0]["tunnel_id"], "target");
    assert_eq!(rules[0]["enabled"], false);
    assert_eq!(rules[1]["fallback_tunnel_ids"], json!(["reserve-b"]));
    assert_eq!(rules[2]["tunnel_id"], "target");
    assert_eq!(rules[2]["waiting_for_connection"], false);
    assert_eq!(rules[3]["tunnel_id"], "missing");
    assert_eq!(rules[3]["waiting_for_connection"], true);
    assert_eq!(
        delete("replacement_id=target").await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(nfqws2_awg_profile::read(&state.store).unwrap(), stored);
}
