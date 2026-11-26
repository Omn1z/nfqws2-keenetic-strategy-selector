use super::*;
use axum::{
    body::{to_bytes, Body},
    http::Request,
};
use nfqws2_config::{Config as PanelConfig, Resolver};
use tower::ServiceExt;

#[cfg(target_os = "linux")]
#[tokio::test]
async fn private_helper_channel_returns_only_a_live_selected_interface() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{UnixListener, UnixStream},
    };
    let root = tempfile::tempdir().unwrap();
    let dir = root.path();
    let cfg = PanelConfig {
        data_dir: dir.display().to_string(),
        ..PanelConfig::from_resolver(&Resolver::new_at(dir))
    };
    let state = crate::http::AppState::open(cfg, dir, true).unwrap();
    std::fs::create_dir_all(dir.join("sys/class/net/awg3")).unwrap();
    std::fs::create_dir_all(dir.join("var/run/amneziawg")).unwrap();
    let mock = UnixListener::bind(dir.join("var/run/amneziawg/awg3.sock")).unwrap();
    std::fs::write(dir.join("awg.json"),json!({"active_id":"first","servers":[{"id":"first","name":"Home","config":{"enabled":true,"endpoint":"192.0.2.1:443","client_iface":"awg3","peers":[]}}]}).to_string()).unwrap();
    std::fs::write(dir.join("tgproxy.json"), br#"{"awg_fallback":"awg:first"}"#).unwrap();
    let fixture = tokio::spawn(async move {
        for seconds in [0, 301] {
            let (mut peer, _) = mock.accept().await.unwrap();
            let mut query = Vec::new();
            peer.read_to_end(&mut query).await.unwrap();
            assert_eq!(query, b"get=1\n\n");
            let hs = nfqws2_awg_profile::now() - seconds;
            peer.write_all(format!("public_key=public-fixture\nendpoint=192.0.2.1:443\nlast_handshake_time_sec={hs}\nerrno=0\n\n").as_bytes()).await.unwrap();
        }
    });
    let bridge = fallback::Bridge::start(std::sync::Arc::downgrade(&state)).unwrap();
    let path = bridge.path.as_ref().unwrap();
    for expected in ["awg3", ""] {
        let mut peer = UnixStream::connect(path).await.unwrap();
        let mut iface = String::new();
        tokio::time::timeout(Duration::from_secs(3), peer.read_to_string(&mut iface))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(iface, expected);
    }
    fixture.await.unwrap();
}

#[tokio::test]
async fn compatible_go_profile_remains_enabled_for_automatic_restore() {
    let root = tempfile::tempdir().unwrap();
    let db = Store::open(root.path()).unwrap();
    let original = json!({
        "enabled":true,"port":31555,"secret":"00000000000000000000000000000001",
        "cfproxy":false,"cfproxy_h2_media":true,"sni_fronting":false,"fake_tls_domain":"",
        "pool_size":4,"dc_redirects":{"2":"192.0.2.20"},"link_host":"proxy.test",
        "proxy_protocol":true,"force_test_dc":true,"buffer_size":131072,
        "private_extension":"preserved"
    });
    let path = root.path().join(FILE);
    let encoded = serde_json::to_vec(&original).unwrap();
    std::fs::write(&path, &encoded).unwrap();
    let mut service = Service::open(&db).unwrap();
    let state = service.state.lock().await;
    assert!(state.cfg.enabled && state.cfg.transport.is_empty());
    assert!(state.error.is_empty() && state.cfg.requires_go().is_empty());
    assert!(state.cfg.force_test_dc && state.cfg.proxy_protocol);
    assert_eq!(state.cfg.port, 31555);
    assert_eq!(state.cfg.buffer_size, 131072);
    assert_eq!(state.cfg.pool_size, 4);
    assert_eq!(state.cfg.link_host, "proxy.test");
    assert_eq!(state.cfg.secret, original["secret"]);
    assert_eq!(
        state.cfg.dc_redirects.as_ref().unwrap()[&2].to_string(),
        "192.0.2.20"
    );
    drop(state);
    service.helper = root.path().join("uninstalled");
    let err = service
        .update(&db, "127.0.0.1:38200", Change::Restore, Default::default())
        .await
        .err()
        .unwrap();
    assert_eq!(err.0, StatusCode::FAILED_DEPENDENCY);
    assert_eq!(std::fs::read(path).unwrap(), encoded);
}

#[tokio::test]
async fn legacy_unsupported_settings_preserve_the_saved_configuration() {
    let root = tempfile::tempdir().unwrap();
    let db = Store::open(root.path()).unwrap();
    let legacy =
        br#"{"enabled":true,"secret":"00000000000000000000000000000000","transport":"unknown-example","fake_tls_domain":"site.example"}"#;
    let path = root.path().join(FILE);
    std::fs::write(&path, legacy).unwrap();
    let service = Service::open(&db).unwrap();
    let web = "127.0.0.1:37900";
    assert!(service
        .update(&db, web, Change::Restore, Default::default())
        .await
        .is_ok());
    assert!(!service.state.lock().await.cfg.enabled);
    let error = service
        .update(&db, web, Change::Enabled(true), Default::default())
        .await
        .err()
        .unwrap();
    assert_eq!(error.0, StatusCode::BAD_REQUEST);
    assert!(error.1.contains("неизвестный транспорт"));
    assert!(service.state.lock().await.child.is_none());
    assert_eq!(std::fs::read(&path).unwrap().as_slice(), legacy);
    service
        .update(&db, web, Change::Enabled(false), Default::default())
        .await
        .unwrap_or_else(|error| panic!("{}", error.1));
    let saved: Config = db.read(FILE).unwrap();
    assert_eq!(saved.fake_tls_domain, "site.example");
    assert!(!saved.enabled);
}

#[tokio::test]
async fn http_status_config_rotation_and_missing_worker() {
    let root = tempfile::tempdir().unwrap();
    let cfg = PanelConfig {
        data_dir: root.path().display().to_string(),
        ..PanelConfig::from_resolver(&Resolver::new_at(root.path()))
    };
    let mut state = crate::http::AppState::open(cfg, root.path(), true).unwrap();
    std::sync::Arc::get_mut(&mut state).unwrap().tgws.helper = root.path().join("missing");
    let app = crate::http::router(state.clone());
    let call = |method, uri: &'static str, body: Value| {
        let app = app.clone();
        async move {
            let request = Request::builder()
                .method(method)
                .uri(uri)
                .header(header::HOST, "panel.test:38200")
                .body(Body::from(body.to_string()))
                .unwrap();
            let response = app.oneshot(request).await.unwrap();
            let status = response.status();
            let body = to_bytes(response.into_body(), 65536).await.unwrap();
            (status, serde_json::from_slice::<Value>(&body).unwrap())
        }
    };
    let shared_path = root.path().join("tgproxy.json");
    let (code, v) = call("GET", "/api/proxy/awg-fallback", Value::Null).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(v, json!({"value":"off","servers":[]}));
    std::fs::write(
        &shared_path,
        br#"{"awg_fallback":"warp","private_extension":"preserve"}"#,
    )
    .unwrap();
    std::fs::write(root.path().join("awg.json"),json!({"active_id":"first","servers":[
        {"id":"first","name":"Home VPN","config":{"enabled":true,"endpoint":"192.0.2.1:123","client_iface":"awg3","peers":[],"secret":"never-return"}},
        {"id":"disabled","config":{"enabled":false,"endpoint":"192.0.2.5:123","peers":[]}}]}).to_string()).unwrap();
    let (code, v) = call("GET", "/api/proxy/awg-fallback", Value::Null).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(v["value"], "auto");
    assert_eq!(
        v["servers"],
        json!([{"id":"first","label":"Home VPN","client_iface":"awg3","connected":false}])
    );
    for sel in ["awg:first", "first", "auto", "off"] {
        let (code, v) = call("POST", "/api/proxy/awg-fallback", json!({"value":sel})).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(v["value"], sel);
        assert!(fallback::selected(&std::sync::Arc::downgrade(&state))
            .await
            .unwrap()
            .is_none());
        let stored: Value = serde_json::from_slice(&std::fs::read(&shared_path).unwrap()).unwrap();
        assert_eq!(
            stored,
            json!({"awg_fallback":sel,"private_extension":"preserve"})
        );
    }
    let (code, _) = call(
        "POST",
        "/api/proxy/awg-fallback",
        json!({"value":"awg:../../eth0"}),
    )
    .await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    std::fs::write(&shared_path, b"invalid").unwrap();
    let (code, _) = call("POST", "/api/proxy/awg-fallback", json!({"value":"auto"})).await;
    assert!(!code.is_success());
    assert_eq!(std::fs::read(shared_path).unwrap(), b"invalid");
    let (code, status) = call("GET", "/api/tgws", Value::Null).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(status["native"]["installed"], false);
    assert_eq!(status["upstream_version"], "1.11.2");
    assert_eq!(status["native"]["requires_go"], json!([]));
    assert_eq!(status["config"]["enabled"], false);
    assert_eq!(status["config"]["pool_size"], 4);
    assert_eq!(status["config"]["cfproxy"], true);
    assert_eq!(status["config"]["cfproxy_h2_media"], true);
    assert_eq!(
        status["config"]["dc_redirects"],
        json!({"2":"149.154.167.220","4":"149.154.167.220"})
    );
    let mut cfg = status["config"].clone();
    cfg["secret"] = "".into();
    cfg["port"] = json!(1434);
    let (code, changed) = call("POST", "/api/tgws/config", cfg).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(changed["config"]["port"], 1434);
    assert_eq!(changed["config"]["secret"], status["config"]["secret"]);
    assert!(changed["link"]
        .as_str()
        .unwrap()
        .contains("server=panel.test&port=1434"));
    let (code, _) = call("POST", "/api/tgws/start", json!({})).await;
    assert_eq!(code, StatusCode::FAILED_DEPENDENCY);
    let (code, rotated) = call("POST", "/api/tgws/secret", json!({})).await;
    assert_eq!(code, StatusCode::OK);
    assert_ne!(rotated["secret"], status["config"]["secret"]);
    let (code, stopped) = call("POST", "/api/tgws/stop", json!({})).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(stopped["running"], false);
    assert_eq!(stopped["config"]["enabled"], false);
    assert_eq!(stopped["config"]["secret"], rotated["secret"]);
    let (code, short) = call("POST", "/api/tgws/config", json!({"port":1555})).await;
    assert_eq!(code, StatusCode::OK);
    let cfg = &short["config"];
    assert_eq!(cfg["port"], 1555);
    assert_eq!(cfg["pool_size"], 0);
    assert_eq!(cfg["buffer_size"], 262144);
    assert_eq!(cfg["dc_redirects"], json!({}));
    assert_eq!(cfg["cfproxy"], false);
    assert_eq!(cfg["cfproxy_h2_media"], true);
    assert!(cfg["secret"] == rotated["secret"]);
}

#[tokio::test]
async fn startup_overlays_legacy_routes_and_preserves_extension_fields_on_update() {
    let dir = tempfile::tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    let write = |v: Value| db.transaction(|tx| tx.save(FILE, &v)).unwrap();
    let local = json!({"2":"192.0.2.2","3":"192.0.2.3"});
    write(json!({"dc_redirects":local,"unknown":{"value":7},"cfproxy":null}));
    let cfg = document::load(&db).unwrap();
    assert!(cfg.cfproxy);
    assert_eq!(
        serde_json::to_value(&cfg.dc_redirects).unwrap(),
        json!({"2":"192.0.2.2","3":"192.0.2.3","4":"149.154.167.220"})
    );
    let svc = Service::open(&db).unwrap();
    let stored: Value = db.read(FILE).unwrap();
    assert_eq!(stored["unknown"], json!({"value":7}));
    assert!(stored["secret"].as_str().is_some_and(|v| v.len() == 32));
    assert!(svc
        .update(&db, "127.0.0.1:9990", Change::Secret, Default::default())
        .await
        .is_ok());
    let rotated: Value = db.read(FILE).unwrap();
    assert!(rotated["secret"] != stored["secret"]);
    assert_eq!(rotated["unknown"], stored["unknown"]);
    for (raw, expected) in [
        (json!({"dc_redirects":null}), Value::Null),
        (
            json!({"transport":"direct_wss","dc_redirects":local}),
            local,
        ),
    ] {
        write(raw);
        assert_eq!(
            serde_json::to_value(document::load(&db).unwrap().dc_redirects).unwrap(),
            expected
        );
    }
}

#[tokio::test]
async fn mixed_case_legacy_controls_survive_load_and_http_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let file = root.join(FILE);
    std::fs::write(
        &file,
        br#"{
        "port":1431,"PORT":1430,"PoRt":null,
        "disable_secure":false,"DISABLE_SECURE":true,"CFPROXY":true,
        "CFPROXY_H2_MEDIA":false,"cfProxy_h2_media":null,"PROXY_PROTOCOL":true,
        "DC_REDIRECTS":null,"dc_redirects":{"3":"192.0.2.3"},
        "Dc_Redirects":{"5":"192.0.2.5"},"TRANSPORT":"extension",
        "PRIVATE_EXTENSION":{"preserved":7}
    }"#,
    )
    .unwrap();
    let state = crate::http::AppState::open(
        PanelConfig {
            data_dir: root.display().to_string(),
            ..PanelConfig::from_resolver(&Resolver::new_at(root))
        },
        root,
        true,
    )
    .unwrap();
    {
        let service = state.tgws.state.lock().await;
        let cfg = &service.cfg;
        assert_eq!(cfg.port, 1430);
        assert!(cfg.disable_secure && cfg.cfproxy && cfg.proxy_protocol);
        assert!(!cfg.cfproxy_h2_media && !cfg.h2_media());
        assert!(cfg.transport.is_empty());
        assert_eq!(
            serde_json::to_value(&cfg.dc_redirects).unwrap(),
            json!({"3":"192.0.2.3","5":"192.0.2.5"})
        );
    }

    let response = crate::http::router(state.clone())
        .oneshot(
            Request::post("/api/tgws/config")
                .body(Body::from(
                    r#"{
            "port":1430,"PORT":1440,"PoRt":null,"DISABLE_SECURE":false,"CFPROXY":true,
            "CFPROXY_H2_MEDIA":true,"cfProxy_h2_media":null,"PROXY_PROTOCOL":false,
            "ENABLED":true,"transport":"direct_wss"
        }"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let status: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 16384).await.unwrap()).unwrap();
    assert_eq!(status["config"]["port"], 1440);
    assert_eq!(status["config"]["disable_secure"], false);
    assert_eq!(status["config"]["proxy_protocol"], false);
    assert_eq!(status["config"]["cfproxy_h2_media"], true);
    assert_eq!(status["config"]["enabled"], false);
    assert!(state.tgws.state.lock().await.cfg.h2_media());
    let saved: Value = state.store.read(FILE).unwrap();
    assert_eq!(saved["PRIVATE_EXTENSION"], json!({"preserved":7}));
    assert_eq!(saved["TRANSPORT"], "extension");
    assert!(saved.get("transport").is_none() && saved.get("PORT").is_none());
}

#[tokio::test]
async fn saving_unchanged_go_settings_preserves_the_sparse_route_map_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    let path = dir.path().join(FILE);
    let raw = serde_json::to_vec(&json!({"secret":nfqws2_tgws_config::secret().unwrap(),"dc_redirects":{"3":"192.0.2.3"},"extra":27})).unwrap();
    std::fs::write(&path, &raw).unwrap();
    let svc = Service::open(&db).unwrap();
    let status_config = serde_json::to_value(&svc.state.lock().await.cfg).unwrap();
    assert_eq!(status_config["dc_redirects"].as_object().unwrap().len(), 3);
    let request = document::request(serde_json::from_value(status_config).unwrap())
        .unwrap_or_else(|_| panic!("valid status document"));
    assert!(svc
        .update(
            &db,
            "127.0.0.1:9990",
            Change::Config(Box::new(request)),
            Default::default()
        )
        .await
        .is_ok());
    assert!(std::fs::read(path).unwrap() == raw);
}

#[test]
fn legacy_unicode_field_aliases_and_earlier_duplicate_types_follow_go() {
    let dir = tempfile::tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    let path = dir.path().join(FILE);
    let valid = r#"{
        "PORT":-1,"port":1430,"ſni_fronting":true,
        "Cfproxy_worKer_domain":"worker.example",
        "dİsable_secure":true,"tranſport":"extension"
    }"#;
    std::fs::write(&path, valid).unwrap();
    let loaded = document::load(&db).unwrap();
    let request = document::request(serde_json::from_str(valid).unwrap())
        .unwrap_or_else(|_| panic!("valid mixed-case controls"));
    for cfg in [loaded, request] {
        assert_eq!(cfg.port, 1430);
        assert!(cfg.sni_fronting);
        assert_eq!(cfg.cfproxy_worker_domain, "worker.example");
        assert!(!cfg.disable_secure);
        assert!(cfg.transport.is_empty());
    }
    let current = document::load(&db).unwrap();
    document::persist(&db, &current, true).unwrap();
    let saved: Value = db.read(FILE).unwrap();
    assert_eq!(saved["dİsable_secure"], true);
    assert_eq!(saved["tranſport"], "extension");
    assert!(saved.get("ſni_fronting").is_none() && saved.get("Cfproxy_worKer_domain").is_none());

    for raw in [
        r#"{"PORT":"wrong","port":1430}"#,
        r#"{"ſni_fronting":"wrong","SNI_FRONTING":false}"#,
        r#"{"LinK_host":false,"link_host":"proxy.example"}"#,
    ] {
        std::fs::write(&path, raw).unwrap();
        assert!(document::load(&db).is_err());
        assert!(document::request(serde_json::from_str(raw).unwrap()).is_err());
    }
}

#[tokio::test]
async fn only_an_explicit_config_repair_replaces_a_damaged_file_and_preserves_its_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    let damaged = b"{\"port\":123";
    let path = dir.path().join(FILE);
    std::fs::write(&path, damaged).unwrap();
    let svc = Service::open(&db).unwrap();
    assert!(std::fs::read(&path).unwrap() == damaged);
    assert!(svc
        .update(&db, "127.0.0.1:9990", Change::Secret, Default::default())
        .await
        .is_err());
    let replacement = document::request(serde_json::from_value(json!({"port":3456})).unwrap())
        .unwrap_or_else(|_| panic!("valid replacement"));
    assert!(svc
        .update(
            &db,
            "127.0.0.1:9990",
            Change::Config(Box::new(replacement)),
            Default::default()
        )
        .await
        .is_ok());
    assert_eq!(document::load(&db).unwrap().port, 3456);
    let copy = std::fs::read_dir(dir.path().join(".store"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|ext| ext == "corrupt"))
        .unwrap();
    assert!(std::fs::read(copy).unwrap() == damaged);
}
