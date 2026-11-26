use super::*;

fn fixture_config(addr: SocketAddr) -> Value {
    let mut cfg = config::defaults();
    cfg["listen_host"] = json!(addr.ip().to_string());
    cfg["dns_port"] = json!(addr.port());
    cfg["awg_fallback"] = json!("off");
    cfg["scheduler_enabled"] = json!(false);
    cfg["fast_dns"] = json!(false);
    cfg["default_pool"] = json!([]);
    cfg["rules"] = json!([]);
    cfg
}

#[tokio::test]
async fn resolver_start_replaces_counters_but_live_edits_keep_cache_and_journal() {
    let dir = tempfile::tempdir().unwrap();
    let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    drop(socket);
    let (port, cert, calls, server) = local_doh().await;
    let mut raw = fixture_config(addr);
    raw["listen_host"] = json!(" 127.0.0.1 ");
    raw["default_upstream"] = json!({"address":format!("https://dns.test:{port}/dns-query"),"bootstrap_ips":["127.0.0.1"]});
    std::fs::write(dir.path().join("dnsserver.json"), raw.to_string()).unwrap();
    let shared = state(&dir);
    let app = crate::http::router(shared.clone());
    let start = || request(&app, "/api/dnsserver/start", Some(json!({})), 200);
    let query = || {
        request(
            &app,
            "/api/dnsserver/test",
            Some(json!({"domain":"cached.example","type":"A"})),
            200,
        )
    };
    let status = || request(&app, "/api/dnsserver", None, 200);
    let logs = || request(&app, "/api/dnsserver/logs", None, 200);
    assert_eq!(start().await["running"], true);
    let original = shared
        .dnsserver
        .state
        .lock()
        .await
        .active
        .as_ref()
        .unwrap()
        .engine();
    original.trust(cert.clone());
    assert_eq!(query().await["ok"], true);
    assert_eq!(query().await["cached"], true);
    let before = status().await;
    let initial_log = logs().await;
    assert_eq!(before["stats"]["queries"], 2);
    assert_eq!(before["cache"]["entries"], 1);
    assert_eq!(initial_log["entries"][0]["event"], "start");
    time::OffsetDateTime::parse(
        initial_log["entries"][0]["time"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    let mut form = before["config"].clone();
    form["base_hash"] = before["config_hash"].clone();
    let identical = request(&app, "/api/dnsserver/config", Some(form), 200).await;
    assert_eq!(identical["stats"], before["stats"]);
    assert_eq!(identical["cache"], before["cache"]);
    assert_eq!(start().await["stats"], before["stats"]);
    assert_eq!(logs().await["last_id"], initial_log["last_id"]);

    let set_logging = |enabled| {
        request(
            &app,
            "/api/dnsserver/logging",
            Some(json!({"enabled":enabled})),
            200,
        )
    };
    let disabled = set_logging(false).await;
    assert_eq!(disabled["enabled"], false);
    assert_eq!(
        disabled["entries"].as_array().unwrap().last().unwrap()["event"],
        "logging"
    );
    assert_eq!(query().await["cached"], true);
    assert_eq!(logs().await["last_id"], disabled["last_id"]);
    let enabled = set_logging(true).await;
    assert_eq!(enabled["enabled"], true);
    assert_eq!(enabled["instance_id"], initial_log["instance_id"]);
    let cleared = request(&app, "/api/dnsserver/cache/clear", Some(json!({})), 200).await;
    assert_eq!(cleared["stats"]["queries"], 3);
    assert_eq!(cleared["stats"]["cache_hits"], 2);
    assert_eq!(cleared["cache"]["entries"], 0);
    let latest = logs().await;
    let last = latest["entries"].as_array().unwrap().last().unwrap();
    assert_eq!(last["event"], "cache_clear");
    assert!(last["message"].as_str().unwrap().ends_with('1'));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let changed = request(
        &app,
        "/api/dnsserver/config",
        Some(json!({"base_hash":cleared["config_hash"],"cache_size":97})),
        200,
    )
    .await;
    assert_eq!(changed["running"], true);
    assert_eq!(changed["stats"]["queries"], 0);
    assert_eq!(changed["cache"]["capacity"], 97);
    assert_eq!(original.stats().queries, 3);
    let after = logs().await;
    assert_eq!(after["instance_id"], initial_log["instance_id"]);
    let entries = after["entries"].as_array().unwrap();
    assert_eq!(entries[entries.len() - 2]["event"], "stop");
    assert_eq!(entries[entries.len() - 1]["event"], "start");

    let fresh = shared
        .dnsserver
        .state
        .lock()
        .await
        .active
        .as_ref()
        .unwrap()
        .engine();
    fresh.trust(cert);
    assert_eq!(query().await["ok"], true);
    let stopped = request(&app, "/api/dnsserver/stop", Some(json!({})), 200).await;
    assert_eq!(stopped["running"], false);
    assert_eq!(stopped["stats"]["queries"], 1);
    assert_eq!(stopped["cache"]["entries"], 0);
    assert_eq!(start().await["stats"]["queries"], 0);
    shared.dnsserver.shutdown().await;
    server.abort();
}

#[tokio::test]
async fn occupied_saved_dns_retries_and_allows_runtime_neutral_settings() {
    let dir = tempfile::tempdir().unwrap();
    let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let mut raw = fixture_config(addr);
    raw["enabled"] = json!(true);
    std::fs::write(dir.path().join("dnsserver.json"), raw.to_string()).unwrap();
    let shared = state(&dir);
    let app = crate::http::router(shared.clone());
    supervise(&shared, Duration::from_millis(100));
    autostart(&shared).await;
    let failed = request(&app, "/api/dnsserver", None, 200).await;
    assert_eq!(failed["running"], false);
    assert_eq!(failed["config"]["enabled"], true);
    let err = failed["last_error"].as_str().unwrap();
    assert!(!err.is_empty());
    let log = request(&app, "/api/dnsserver/logs", None, 200).await;
    assert_eq!(log["entries"][0]["event"], "service");

    let logging = request(
        &app,
        "/api/dnsserver/logging",
        Some(json!({"enabled":false})),
        200,
    )
    .await;
    assert_eq!(logging["enabled"], false);
    let setting = request(
        &app,
        "/api/dnsserver/scheduler/method",
        Some(json!({"route":"nfqws","upstream":"https://dns.test/dns-query","enabled":false})),
        200,
    )
    .await;
    assert_eq!(
        setting["disabled_methods"][0]["upstream"],
        "https://dns.test/dns-query"
    );
    let still_failed = request(&app, "/api/dnsserver", None, 200).await;
    assert_eq!(still_failed["running"], false);
    assert_eq!(still_failed["last_error"], err);

    drop(socket);
    timeout(Duration::from_secs(3), async {
        loop {
            if shared
                .dnsserver
                .state
                .lock()
                .await
                .active
                .as_ref()
                .is_some_and(Active::running)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let recovered = request(&app, "/api/dnsserver", None, 200).await;
    assert_eq!(recovered["running"], true);
    assert_eq!(recovered["last_error"], "");
    assert_eq!(recovered["config"]["logging_enabled"], false);
    assert_eq!(
        recovered["config"]["disabled_methods"],
        setting["disabled_methods"]
    );
    request(&app, "/api/dnsserver/stop", Some(json!({})), 200).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(shared.dnsserver.state.lock().await.active.is_none());
    shared.dnsserver.shutdown().await;
}

#[tokio::test]
async fn current_listener_failure_recovers_before_next_tick() {
    let dir = tempfile::tempdir().unwrap();
    let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    drop(socket);
    let mut raw = fixture_config(addr);
    raw["enabled"] = json!(true);
    std::fs::write(dir.path().join("dnsserver.json"), raw.to_string()).unwrap();
    let shared = state(&dir);
    let app = crate::http::router(shared.clone());
    supervise(&shared, Duration::from_secs(900));
    autostart(&shared).await;
    let wake = &shared.dnsserver.listener_failed;
    let failed = {
        let state = shared.dnsserver.state.lock().await;
        let active = state.active.as_ref().unwrap();
        active.fail_for_test(wake);
        active.engine()
    };
    let recovered = timeout(Duration::from_secs(3), async {
        loop {
            if let Some(run) = &shared.dnsserver.state.lock().await.active {
                let engine = run.engine();
                if run.running() && !Arc::ptr_eq(&engine, &failed) {
                    break engine;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let events = request(&app, "/api/dnsserver/logs", None, 200).await;
    let entries = events["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 4);
    assert_eq!(entries[1]["event"], "service");
    assert_eq!(entries[1]["message"], "fixture listener failure");
    assert_eq!(entries[2]["event"], "stop");
    assert_eq!(entries[3]["event"], "start");
    wake.notify_one();
    tokio::time::sleep(Duration::from_millis(40)).await;
    let active = shared
        .dnsserver
        .state
        .lock()
        .await
        .active
        .as_ref()
        .unwrap()
        .engine();
    assert!(Arc::ptr_eq(&active, &recovered));

    request(&app, "/api/dnsserver/stop", Some(json!({})), 200).await;
    wake.notify_one();
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert!(shared.dnsserver.state.lock().await.active.is_none());
    shared.dnsserver.shutdown().await;
}
