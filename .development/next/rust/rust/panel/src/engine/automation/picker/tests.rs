use super::super::FILE;
use super::*;
use nfqws2_config::Config;
use std::{fs, path::Path, sync::atomic::AtomicUsize};

const TLS: &str =
    "--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello --lua-desync=multisplit:pos=1";
fn row(args: &str, score: u64) -> Value {
    json!({"strategy_id":"candidate","name":"winner","args":args,"coefficient":score,
        "targets_total":2,"targets_ok":2,"success":true})
}
fn state() -> (tempfile::TempDir, Shared, String) {
    let dir = tempfile::tempdir().unwrap();
    let conf = dir.path().join("nfqws2.conf");
    let original = "# preserved\nNFQWS_ARGS=\"--filter-tcp=80\"\nOTHER='keep'\n".to_owned();
    fs::write(&conf, &original).unwrap();
    let cfg = Config {
        data_dir: dir.path().join("data").display().to_string(),
        nfqws2_conf: conf.display().to_string(),
        ..Config::default()
    };
    let s = crate::http::AppState::open(cfg, dir.path(), true).unwrap();
    (dir, s, original)
}
fn save(s: &Shared, v: Value) {
    s.store.transaction(|tx| tx.save(FILE, &v)).unwrap();
}
#[test]
fn winner_rechecks_https_full_coverage_errors_and_stable_ties() {
    let mut incomplete = row(TLS, 900);
    incomplete["targets_ok"] = json!(1);
    let mut empty = row(TLS, 800);
    empty["targets_total"] = json!(0);
    empty["targets_ok"] = json!(0);
    let mut failed = row(TLS, 700);
    failed["error"] = json!("isolation failed");
    let mut first = row(TLS, 20);
    first["name"] = json!("first");
    let report = json!({"status":"done","results":[row("--filter-tcp=80 --lua-desync=fake",1000),incomplete,empty,failed,first,row(TLS,20)]});
    assert_eq!(winner(&report).unwrap()["name"], "first");
    assert!(winner(&json!({"status":"cancelled","results":[row(TLS,50)]})).is_err());
    assert!(winner(&json!({"status":"done","checks":[{"ok":true}],"results":[]})).is_err());
}
#[test]
fn reservation_is_exclusive_and_released_even_without_launch() {
    let picker = Picker::default();
    let first = picker.reserve().unwrap();
    assert!(picker.running());
    assert!(picker.reserve().is_err());
    drop(first);
    assert!(!picker.running());
    drop(picker.reserve().unwrap());
    picker.stopping.store(true, Ordering::Release);
    assert!(picker.reserve().is_err());
}
#[test]
fn invalid_or_disabled_result_never_writes_or_restarts() {
    let (_dir, s, original) = state();
    let calls = AtomicUsize::new(0);
    let restart = || {
        calls.fetch_add(1, Ordering::Relaxed);
        Ok(())
    };
    assert!(apply(
        &s,
        Reason::Manual,
        &row("--filter-tcp=80 --lua-desync=fake", 900),
        restart
    )
    .is_err());
    save(
        &s,
        json!({"auto_pick":true,"periodic_scan":true,"nfqws2_manual_off":true}),
    );
    for reason in [Reason::Manual, Reason::FirstBoot, Reason::Periodic] {
        assert!(apply(&s, reason, &row(TLS, 20), restart).is_err());
    }
    save(&s, json!({"auto_pick":false,"periodic_scan":true}));
    assert!(apply(&s, Reason::Periodic, &row(TLS, 20), restart).is_err());
    assert!(apply(&s, Reason::FirstBoot, &row(TLS, 20), restart).is_err());
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert_eq!(fs::read_to_string(&s.config.nfqws2_conf).unwrap(), original);
    assert!(!Path::new(&format!("{}.n2s.bak", s.config.nfqws2_conf)).exists());
}
#[test]
fn manual_selection_keeps_exact_backup_and_failure_keeps_success_history() {
    let (_dir, s, original) = state();
    save(
        &s,
        json!({"mode":"off","auto_pick":false,"last_pick_at":99,"last_pick_args":"old","last_pick_name":"old name","foreign":7}),
    );
    let result = apply(&s, Reason::Manual, &row(TLS, 20), || {
        Err(io::Error::other("fixture restart failure"))
    });
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("стратегия сохранена"));
    let next = fs::read_to_string(&s.config.nfqws2_conf).unwrap();
    assert_eq!(
        nfqws2_config::literal_shell_config_value(&next, "NFQWS_ARGS")
            .unwrap()
            .as_deref(),
        Some(TLS)
    );
    assert!(next.contains("OTHER='keep'"));
    assert_eq!(
        fs::read_to_string(format!("{}.n2s.bak", s.config.nfqws2_conf)).unwrap(),
        original
    );
    record(&s, Err("apply failed")).unwrap();
    let v = read(&s.store).unwrap();
    assert_eq!(v["last_pick_at"], 99);
    assert_eq!(v["last_pick_args"], "old");
    assert_eq!(v["last_pick_name"], "old name");
    assert_eq!(v["last_pick_error"], "apply failed");
    assert_eq!(v["foreign"], 7);
    record(&s, Ok(&row(TLS, 20))).unwrap();
    let v = read(&s.store).unwrap();
    assert_eq!(v["last_pick_args"], TLS);
    assert_eq!(v["last_pick_error"], "");
    assert_eq!(v["auto_pick"], false);
}
#[tokio::test]
async fn first_boot_preserves_an_existing_strategy_and_disabled_defaults() {
    let (_dir, s, original) = state();
    scheduled(s.clone(), true, false).await.unwrap();
    assert_eq!(read(&s.store).unwrap(), json!({}));
    save(&s, json!({"auto_pick":true,"mode":"off","foreign":9}));
    scheduled(s.clone(), true, false).await.unwrap();
    let v = read(&s.store).unwrap();
    assert!(v["last_pick_at"].as_u64().unwrap() > 0);
    assert_eq!(v["last_pick_args"], "(pre-existing)");
    assert_eq!(v["foreign"], 9);
    assert!(!s.auto_pick.running());
    assert_eq!(fs::read_to_string(&s.config.nfqws2_conf).unwrap(), original);
}

#[tokio::test]
async fn periodic_pick_uses_the_watchdog_sample_without_polling_the_peer_again() {
    let (_dir, s, _) = state();
    save(
        &s,
        json!({"mode":"on","auto_pick":true,"periodic_scan":true,"interval_h":1,"last_pick_at":1}),
    );
    fs::write(Path::new(&s.config.data_dir).join("awg.json"), "{").unwrap();
    assert!(super::super::link(&s).is_err());
    scheduled(s.clone(), false, false).await.unwrap();
    assert!(!s.auto_pick.running());
    assert!(!s.active_test.load(Ordering::Acquire));

    // A foreign acceleration journal stops the synthetic worker before any network action.
    let data = Path::new(&s.config.data_dir);
    fs::write(data.join("awg-acceleration-state.json"), "{}").unwrap();
    scheduled(s.clone(), false, true).await.unwrap();
    let worker = s.auto_pick.task.lock().unwrap().take().unwrap();
    worker.await.unwrap();
    assert!(read(&s.store).unwrap()["last_pick_error"]
        .as_str()
        .unwrap()
        .contains("PPE"));
    assert!(!s.active_test.load(Ordering::Acquire));
}
#[tokio::test]
async fn http_route_rejects_manual_stop_without_a_body_or_worker() {
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;
    let (_dir, s, _) = state();
    save(&s, json!({"nfqws2_manual_off":true}));
    let router = crate::http::router(s.clone());
    let response = router
        .oneshot(
            Request::post("/api/nfqws2/automation/pick-now")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let data: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert!(data["error"].as_str().unwrap().contains("выключен вручную"));
    assert!(!s.auto_pick.running());
    assert!(!s.active_test.load(Ordering::Acquire));
}
