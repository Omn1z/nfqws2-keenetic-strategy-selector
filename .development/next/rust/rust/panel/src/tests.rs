use crate::{assets, http, saved_addr, Serve};
use axum::{
    body::{to_bytes, Body},
    http::{header, HeaderMap, Request, StatusCode},
    Router,
};
use nfqws2_config::Config;
use serde_json::{json, Value};
use std::fs;
use tower::ServiceExt;

fn panel(dir: &tempfile::TempDir, forced_off: bool) -> Router {
    let config = Config {
        data_dir: dir.path().display().to_string(),
        version: "test".into(),
        ..Config::default()
    };
    http::router(http::AppState::open(config, dir.path(), forced_off).unwrap())
}
async fn request(
    app: &Router,
    method: &str,
    path: &str,
    body: &str,
    cookie: &str,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header(header::COOKIE, cookie)
        .body(Body::from(body.to_owned()))
        .unwrap();
    let response = app.clone().oneshot(req).await.unwrap();
    let (parts, body) = response.into_parts();
    (
        parts.status,
        parts.headers,
        to_bytes(body, 8 << 20).await.unwrap().to_vec(),
    )
}
async fn api(app: &Router, method: &str, path: &str, input: Value) -> Value {
    let (status, _, out) = request(app, method, path, &input.to_string(), "").await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&out));
    serde_json::from_slice(&out).unwrap()
}
#[tokio::test]
async fn editor_preserves_compressed_variants_and_protected_lists() {
    use std::io::Write;
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("engine");
    let lists = root.join("lists");
    fs::create_dir_all(&lists).unwrap();
    let gz = lists.join("test.list.gz");
    let mut compressed =
        flate2::write::GzEncoder::new(fs::File::create(&gz).unwrap(), flate2::Compression::fast());
    compressed.write_all(b"example.test\n").unwrap();
    compressed.finish().unwrap();
    let db = d.path().join("state");
    let cfg = Config {
        data_dir: db.display().to_string(),
        nfqws2_conf: root.join("nfqws2.conf").display().to_string(),
        ..Config::default()
    };
    let app = http::router(http::AppState::open(cfg, d.path(), true).unwrap());
    let url = "/api/nfqws2/file?kind=list&name=test.list";
    assert_eq!(
        api(&app, "GET", url, Value::Null).await["content"],
        "example.test\n"
    );
    assert_eq!(
        api(&app, "GET", "/api/nfqws2/files?kind=list", Value::Null).await["files"][0]["gz"],
        true
    );
    let input = json!({"kind":"list","name":"test.list","content":"a\r\n\r\n\r\nb"});
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/nfqws2/file/create",
            &input.to_string(),
            ""
        )
        .await
        .0,
        400
    );
    api(&app, "POST", "/api/nfqws2/file", input).await;
    assert_eq!(
        request(
            &app,
            "GET",
            "/api/nfqws2/file/download?kind=list&name=test.list",
            "",
            ""
        )
        .await
        .2,
        b"a\n\nb\n"
    );
    assert!(gz.exists());
    api(&app, "DELETE", url, Value::Null).await;
    assert!(!gz.exists() && !lists.join("test.list").exists());
    for file in ["auto.list", "user.list", "n2s_service_fixture.list"] {
        assert_eq!(
            request(
                &app,
                "DELETE",
                &format!("/api/nfqws2/file?kind=list&name={file}"),
                "",
                ""
            )
            .await
            .0,
            400
        );
    }
    let doc = api(
        &app,
        "POST",
        "/api/nfqws2/paths",
        json!({"kind":"conf","content":"# /etc/nfqws2/file"}),
    )
    .await;
    assert_eq!(doc["diagnostics"], json!([]));
}
#[tokio::test]
async fn gate_login_cookie_restart_and_logout() {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir_all(tmp.path().join("opt/etc")).unwrap();
    // Public crypt test vector, password "password".
    fs::write(
        tmp.path().join("opt/etc/shadow"),
        "user:$1$salt$qJH7.N4xYta3aEG/dfqo/0:0:0\n",
    )
    .unwrap();
    let app = panel(&tmp, false);
    for path in [
        "/api/config",
        "/api/auth/config",
        "/api/lists",
        "/api/unknown",
    ] {
        assert_eq!(request(&app, "GET", path, "", "").await.0, 401);
    }
    let state = api(&app, "GET", "/api/auth/status", Value::Null).await;
    assert_eq!(
        state,
        json!({"authed":false,"enabled":true,"version":"test"})
    );
    assert_eq!(
        request(&app, "POST", "/api/auth/login", "{", "").await.0,
        400
    );
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/auth/login",
            r#"{"user":"user","password":"bad"}"#,
            ""
        )
        .await
        .0,
        401
    );
    let (code, h, _) = request(
        &app,
        "POST",
        "/api/auth/login",
        r#"{"user":"user","password":"password"}"#,
        "",
    )
    .await;
    assert_eq!(code, 200);
    let cookie = h[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    assert_eq!(request(&app, "GET", "/api/config", "", cookie).await.0, 200);
    assert_eq!(
        request(&panel(&tmp, false), "GET", "/api/config", "", cookie)
            .await
            .0,
        401
    );
    assert_eq!(
        request(&app, "POST", "/api/auth/logout", "", cookie)
            .await
            .0,
        200
    );
    assert_eq!(request(&app, "GET", "/api/config", "", cookie).await.0, 401);
}
#[tokio::test]
async fn legacy_lists_strategies_and_history_survive_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let app = panel(&tmp, true);
    let saved = api(&app,"POST","/api/lists",json!({"name":"Сеть","domains":[" x ","x",""],"successful_strategies":[{"strategy_id":"old"}]})).await;
    let id = saved["id"].as_str().unwrap();
    assert_eq!(
        (id.len(), &saved["domains"], &saved["ips"]),
        (12, &json!(["x"]), &json!([]))
    );
    let updated = api(
        &app,
        "POST",
        "/api/lists",
        json!({"id":id,"name":"new","ips":["::1"]}),
    )
    .await;
    assert_eq!(
        updated["successful_strategies"],
        saved["successful_strategies"]
    );
    assert_eq!(updated["created_at"], saved["created_at"]);
    let restarted = panel(&tmp, true);
    assert_eq!(
        api(&restarted, "GET", &format!("/api/lists/{id}"), Value::Null).await,
        updated
    );
    assert_eq!(
        api(&restarted, "GET", "/api/lists", Value::Null).await,
        json!([updated])
    );
    assert_eq!(
        request(&app, "DELETE", "/api/lists/..%2Fsettings", "", "")
            .await
            .0,
        400
    );
    api(
        &restarted,
        "DELETE",
        &format!("/api/lists/{id}"),
        Value::Null,
    )
    .await;
    assert_eq!(
        request(&restarted, "GET", &format!("/api/lists/{id}"), "", "")
            .await
            .0,
        404
    );
    let sni = api(
        &app,
        "POST",
        "/api/strategies/sni",
        json!({"domains":[" a ","b","a"]}),
    )
    .await;
    assert_eq!(sni, json!({"domains":["a","b"]}));
    assert_eq!(
        api(&restarted, "GET", "/api/strategies/sni", Value::Null).await,
        sni
    );
    assert_eq!(
        request(&app, "POST", "/api/strategies", r#"{"args":"--new"}"#, "")
            .await
            .0,
        400
    );
    let strategy = api(
        &app,
        "POST",
        "/api/strategies",
        json!({"args":"--filter-tcp=443","source":"builtin"}),
    )
    .await;
    assert_eq!(strategy["source"], "custom");
    let strategies = api(&app, "GET", "/api/strategies", Value::Null).await;
    assert!(strategies.as_array().unwrap().contains(&strategy));
    api(
        &app,
        "DELETE",
        &format!("/api/strategies/{}", strategy["id"].as_str().unwrap()),
        Value::Null,
    )
    .await;
    let dir = tmp.path().join("runs");
    fs::create_dir(&dir).unwrap();
    for (id, started, status) in [("old", 1, "done"), ("recent", 2, "running")] {
        fs::write(
            dir.join(format!("{id}.json")),
            json!({"id":id,"started_at":started,"status":status}).to_string(),
        )
        .unwrap();
    }
    #[cfg(any(not(feature = "embedded-runs"), feature = "compact"))]
    if request(&restarted, "GET", "/api/runs", "", "").await.0 == StatusCode::SERVICE_UNAVAILABLE {
        let (code, _, body) = request(&restarted, "GET", "/api/runs/recent", "", "").await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert!(String::from_utf8(body)
            .unwrap()
            .contains("nfqws2-strategy-runs"));
        return;
    }
    let history = api(&restarted, "GET", "/api/runs", Value::Null).await;
    assert_eq!(
        history[0],
        api(&restarted, "GET", "/api/runs/recent", Value::Null).await
    );
    assert_eq!(history[0]["error"], "interrupted");
    assert_eq!(history[1]["status"], "done");
}
#[tokio::test]
async fn compressed_identity_head_and_private_assets() {
    use std::io::Read;
    let tmp = tempfile::tempdir().unwrap();
    let app = panel(&tmp, false);
    let (_, head, plain) = request(&app, "GET", "/deep/router/page", "", "").await;
    assert!(String::from_utf8_lossy(&plain).contains("<html"));
    assert_eq!(head[header::CACHE_CONTROL], "no-store");
    for (accept, gz) in [("*;q=1, gzip;q=0", false), ("br, gzip", true)] {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, accept.parse().unwrap());
        let response = assets::serve("GET".parse().unwrap(), "/".parse().unwrap(), h).await;
        assert_eq!(
            response.headers().contains_key(header::CONTENT_ENCODING),
            gz
        );
        let body = to_bytes(response.into_body(), 8 << 20).await.unwrap();
        if gz {
            let mut unpacked = Vec::new();
            flate2::read::GzDecoder::new(body.as_ref())
                .read_to_end(&mut unpacked)
                .unwrap();
            assert_eq!(unpacked, plain);
        } else {
            assert_eq!(body.as_ref(), plain);
        }
    }
    assert!(request(&app, "HEAD", "/", "", "").await.2.is_empty());
    assert_eq!(
        request(&app, "GET", "/modules/geo/nfqws2-geo", "", "")
            .await
            .0,
        404
    );
    assert_eq!(request(&app, "POST", "/", "", "").await.0, 405);
}
#[test]
fn cli_saved_ports_and_recovery() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(saved_addr(dir.path(), ":8090").unwrap(), ":8090");
    assert!(super::saved_panel_port(dir.path()).unwrap().is_none());
    fs::write(dir.path().join("ports.json"), r#"{"panel_port":8081}"#).unwrap();
    assert_eq!(saved_addr(dir.path(), "[::1]:80").unwrap(), "[::1]:8081");
    assert_eq!(
        super::saved_panel_port(dir.path()).unwrap().unwrap().get(),
        8081
    );
    for v in [
        "{}",
        r#"{"panel_port":0}"#,
        r#"{"panel_port":65536}"#,
        "bad",
    ] {
        fs::write(dir.path().join("ports.json"), v).unwrap();
        assert!(saved_addr(dir.path(), ":80").is_err());
    }
    let args = [
        "--ignore-saved-port",
        "-l",
        "127.0.0.1:0",
        "-d",
        "-log",
        "test.log",
    ];
    let opts = Serve::parse(args.into_iter().map(String::from)).unwrap();
    assert!(opts.ignore_saved && opts.daemon);
    assert!(Serve::parse(["-pid".into()].into_iter()).is_err());
}

#[tokio::test]
async fn dns_defaults_empty_lists_recovery_and_explicit_reset() {
    let dir = tempfile::tempdir().unwrap();
    let app = panel(&dir, true);
    let path = dir.path().join("dns.json");
    fs::write(&path, "[]").unwrap();
    assert_eq!(api(&app, "GET", "/api/dns", Value::Null).await, json!([]));
    let entry = api(
        &app,
        "POST",
        "/api/dns",
        json!({"name":" Test ","addr":"dns.example","type":" DoT "}),
    )
    .await;
    assert_eq!(entry["type"], "dot");
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/dns",
            r#"{"addr":"http://example.org","type":"doh","name":"bad"}"#,
            ""
        )
        .await
        .0,
        400
    );
    fs::write(&path, "broken").unwrap();
    assert_eq!(
        api(&app, "GET", "/api/dns", Value::Null).await,
        json!([entry])
    );
    api(
        &app,
        "DELETE",
        &format!("/api/dns/{}", entry["id"].as_str().unwrap()),
        Value::Null,
    )
    .await;
    assert_eq!(api(&app, "GET", "/api/dns", Value::Null).await, json!([]));
    let empty_dir = tempfile::tempdir().unwrap();
    let broken = empty_dir.path().join("dns.json");
    fs::write(&broken, "bad").unwrap();
    let broken_app = panel(&empty_dir, true);
    assert_eq!(request(&broken_app, "GET", "/api/dns", "", "").await.0, 503);
    assert_eq!(fs::read(&broken).unwrap(), b"bad");
    assert_eq!(
        api(&broken_app, "POST", "/api/dns/reset", Value::Null)
            .await
            .as_array()
            .unwrap()
            .len(),
        13
    );
}

#[tokio::test]
async fn settings_logs_and_dashboard_use_existing_file_and_proc_layout() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("settings.json"),
        r#"{"auth_enabled":false,"vendor_setting":43}"#,
    )
    .unwrap();
    let proc = dir.path().join("proc");
    fs::create_dir_all(proc.join("net")).unwrap();
    fs::write(proc.join("net/nf_conntrack"),concat!(
        "ipv6 10 udp 17 14 src=2001:db8::123 dst=2001:db8:2::1 dport=53 bytes=37 bytes=64 mac=02:01:02:03:04:05 slan\n",
        "ipv4 2 tcp 6 200 ESTABLISHED src=192.168.1.4 dst=198.51.100.1 sport=43500 dport=443 packets=1 bytes=60 src=198.51.100.1 dst=192.168.1.4 sport=443 dport=43500 packets=2 bytes=120 [ASSURED] mark=0 use=1\n",
        "ipv6 10 udp 17 14 src=2001:db8:2::1 dst=2001:db8::321 bytes=37 bytes=64 swan\n"
    )).unwrap();
    fs::write(proc.join("net/arp"),"IP address HW type Flags HW address Mask Device\n192.168.1.4 0x1 0x2 02:01:02:03:04:05 * br0\n").unwrap();
    let app = panel(&dir, false);
    let config = api(
        &app,
        "POST",
        "/api/system/settings",
        json!({"http_logs_enabled":false,"trace_mode":"always"}),
    )
    .await;
    assert_eq!(config["trace_mode"], "always");
    let stored: Value =
        serde_json::from_slice(&fs::read(dir.path().join("settings.json")).unwrap()).unwrap();
    assert_eq!(stored["vendor_setting"], 43);
    assert_eq!(stored["http_logs_disabled"], true);
    api(&app, "POST", "/api/logs/clear", Value::Null).await;
    assert_eq!(
        api(&app, "GET", "/api/logs", Value::Null).await["entries"],
        json!([])
    );
    let dash = api(&app, "GET", "/api/dashboard", Value::Null).await;
    assert_eq!(dash["conns"]["total"], 3);
    let clients = api(&app, "GET", "/api/devices", Value::Null).await;
    assert_eq!(clients["devices"], dash["top_devices"]);
    let devs = clients["devices"].as_array().unwrap();
    assert_eq!(devs.len(), 1);
    assert_eq!(devs[0]["total"], 2);
    assert_eq!(devs[0]["iface"], "br0");
    assert_eq!(devs[0]["ipv6"], json!(["2001:db8::123"]));
    assert!(dash["system"]["mem_total_kb"].is_number());
    assert_eq!(
        api(&app, "GET", "/api/connections", Value::Null).await["count"],
        3
    );
}

fn restore_request(archive: &[u8]) -> Request<Body> {
    let mut body = b"--boundary123\r\nContent-Disposition: form-data; name=\"archive\"; filename=\"selector.bak\"\r\nContent-Type: application/octet-stream\r\n\r\n".to_vec();
    body.extend_from_slice(archive);
    body.extend_from_slice(b"\r\n--boundary123--\r\n");
    Request::post("/api/system/restore")
        .header(
            header::CONTENT_TYPE,
            "multipart/form-data; boundary=boundary123",
        )
        .body(Body::from(body))
        .unwrap()
}
#[tokio::test]
async fn sealed_backup_restores_through_http_and_rejects_cross_origin_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let app = panel(&dir, true);
    let path = dir.path().join("portable.txt");
    let dns = api(&app, "GET", "/api/dnsserver", Value::Null).await;
    let update_dns = |base: Value, size| json!({"base_hash":base,"cache_size":size});
    let saved = api(
        &app,
        "POST",
        "/api/dnsserver/config",
        update_dns(dns["config_hash"].clone(), 80),
    )
    .await;
    assert_eq!(saved["config"]["cache_size"], 80);
    fs::write(&path, b"backup state").unwrap();
    let (code, headers, bytes) = request(&app, "POST", "/api/system/backup", "", "").await;
    assert_eq!(code, 200);
    assert_eq!(headers[header::CONTENT_TYPE], "application/octet-stream");
    assert!(bytes.starts_with(b"SLBAK1"));
    fs::write(&path, b"changed").unwrap();
    let changed = api(
        &app,
        "POST",
        "/api/dnsserver/config",
        update_dns(saved["config_hash"].clone(), 96),
    )
    .await;
    assert_eq!(changed["config"]["cache_size"], 96);
    let req = restore_request(&bytes);
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), 200);
    assert_eq!(fs::read(path).unwrap(), b"backup state");
    let restored = api(&app, "GET", "/api/dnsserver", Value::Null).await;
    assert_eq!(restored["config"]["cache_size"], 80);
    let updated = api(
        &app,
        "POST",
        "/api/dnsserver/config",
        update_dns(restored["config_hash"].clone(), 112),
    )
    .await;
    assert_eq!(updated["config"]["cache_size"], 112);
    let foreign = Request::post("/api/lists")
        .header(header::HOST, "router.local")
        .header(header::ORIGIN, "https://other.example")
        .body(Body::from("{}"))
        .unwrap();
    assert_eq!(app.oneshot(foreign).await.unwrap().status(), 403);
}
#[tokio::test]
async fn partial_backup_restore_reloads_committed_dns_and_preserves_history() {
    let dir = tempfile::tempdir().unwrap();
    let app = panel(&dir, true);
    let history = dir.path().join(nfqws2_awg_rules::discoveries::FILE);
    let before = br#"{"version":1,"entries":[]}"#;
    let current = br#"{"version":1,"entries": []}"#;
    fs::write(&history, before).unwrap();
    let obstruction = dir.path().join("zzz-last");
    fs::write(&obstruction, b"archive member").unwrap();
    let dns = api(&app, "GET", "/api/dnsserver", Value::Null).await;
    let before = api(
        &app,
        "POST",
        "/api/dnsserver/config",
        json!({"base_hash":dns["config_hash"],"cache_size":123}),
    )
    .await;
    let (code, _, archive) = request(&app, "POST", "/api/system/backup", "", "").await;
    assert_eq!(code, 200);
    let edited = api(
        &app,
        "POST",
        "/api/dnsserver/config",
        json!({"base_hash":before["config_hash"],"cache_size":124}),
    )
    .await;
    assert_eq!(edited["config"]["cache_size"], 124);
    fs::write(&history, current).unwrap();
    fs::remove_file(&obstruction).unwrap();
    fs::create_dir(&obstruction).unwrap();
    let failed = app
        .clone()
        .oneshot(restore_request(&archive))
        .await
        .unwrap();
    assert_eq!(failed.status(), 400);
    assert_eq!(fs::read(history).unwrap(), current);
    let actual = api(&app, "GET", "/api/dnsserver", Value::Null).await;
    assert_eq!(actual["config"]["cache_size"], 123);
}
#[tokio::test]
async fn forwarding_presets_and_validation_use_real_api() {
    let dir = tempfile::tempdir().unwrap();
    let app = panel(&dir, true);
    let view = api(&app, "GET", "/api/port-forwarding", Value::Null).await;
    assert_eq!(view["presets"].as_array().unwrap().len(), 7);
    assert_eq!(view["rules"], json!([]));
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/port-forwarding/rules",
            r#"{"preset_id":"delta-force","profile_id":"pc","device_ip":"bad"}"#,
            ""
        )
        .await
        .0,
        400
    );
    #[cfg(not(target_os = "linux"))]
    {
        let view=api(&app,"POST","/api/port-forwarding/rules",json!({"preset_id":"delta-force","profile_id":"pc","device_ip":"192.0.2.4","tcp":[{"start":22,"end":22}]})).await;
        let rule = &view["rules"][0];
        assert_eq!(rule["tcp"], json!([]));
        assert_eq!(rule["udp"], json!([{"start":3568,"end":3569}]));
        let path = format!(
            "/api/port-forwarding/rules/{}",
            rule["id"].as_str().unwrap()
        );
        let view = api(
            &app,
            "POST",
            &format!("{path}/enabled"),
            json!({"enabled":true}),
        )
        .await;
        assert_eq!(view["rules"][0]["enabled"], true);
        let restarted = panel(&dir, true);
        assert_eq!(
            api(&restarted, "DELETE", &path, Value::Null).await["rules"],
            json!([])
        );
    }
}
