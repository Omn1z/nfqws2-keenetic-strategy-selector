use super::*;
use nfqws2_config::Resolver;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};

struct Fixture {
    queue: PathBuf,
    calls: Mutex<Vec<String>>,
    fail_start: AtomicBool,
    lingering_rule: AtomicBool,
}
impl Runner for Fixture {
    fn run(&self, prog: &str, args: &[&str], _: Instant) -> io::Result<String> {
        assert!(matches!(prog, "iptables" | "ip6tables"));
        assert!(args.ends_with(&["-t", "mangle", "-S"]));
        if self.lingering_rule.load(Ordering::Relaxed) {
            Ok("-A FORWARD -j NFQUEUE --queue-num 321".into())
        } else {
            Ok("-A TEST -j NFQUEUE --queue-num 123".into())
        }
    }
}
impl Commands for Fixture {
    fn available(&self, _: &Config) -> io::Result<()> {
        Ok(())
    }
    fn init(&self, cfg: &Config, action: &str, _: Instant) -> io::Result<()> {
        self.calls.lock().unwrap().push(action.into());
        match action {
            "start" => {
                assert!(!PathBuf::from(format!("{}.run", cfg.nfqws2_conf)).exists());
                assert!(
                    fs::read_to_string(&cfg.nfqws2_conf)?.contains("ISP_INTERFACE=\"eth1 eth2\"")
                );
                fs::write(&self.queue, b"321 48 0\n")?;
                if self.fail_start.load(Ordering::Relaxed) {
                    return Err(invalid("fixture start failed"));
                }
            }
            "stop" => fs::write(&self.queue, b"")?,
            "firewall_stop" => {}
            _ => panic!("unexpected init verb"),
        }
        Ok(())
    }
}
fn fixture(root: &Path) -> (Config, Store, Fixture) {
    let mut cfg = Config::from_resolver(&Resolver::new_at(root));
    cfg.nfqws2_conf = root.join("nfqws2.conf").to_string_lossy().into_owned();
    cfg.data_dir = root.join("data").to_string_lossy().into_owned();
    fs::write(
        &cfg.nfqws2_conf,
        "ISP_INTERFACE=\"eth1,eth2\"\nNFQUEUE_NUM=321\n",
    )
    .unwrap();
    let db = Store::open(&cfg.data_dir).unwrap();
    let queue = root.join("proc/net/netfilter/nfnetlink_queue");
    fs::create_dir_all(queue.parent().unwrap()).unwrap();
    fs::write(&queue, "").unwrap();
    (
        cfg,
        db,
        Fixture {
            queue,
            calls: Default::default(),
            fail_start: Default::default(),
            lingering_rule: Default::default(),
        },
    )
}
#[test]
fn first_manual_stop_persists_a_state_go_can_reload() {
    let root = tempfile::tempdir().unwrap();
    let (cfg, db, ops) = fixture(root.path());
    let proc = root.path().join("proc");
    let engine = RouterEngine {
        proc: &proc,
        commands: &ops,
    };
    let file = Path::new(&cfg.data_dir).join(AUTOMATION);
    assert!(!manual_off(&db).unwrap());
    assert!(!file.exists());
    change(&db, &cfg, &engine, Action::Stop).unwrap();
    let reopened = Store::open(&cfg.data_dir).unwrap();
    assert!(manual_off(&reopened).unwrap());
    assert_eq!(
        reopened.read::<Value>(AUTOMATION).unwrap(),
        json!({
            "mode":"off", "interval_h":24, "nfqws2_manual_off":true
        })
    );
}
#[test]
fn normal_operations_preserve_other_automation_fields_and_verify_the_owned_queue() {
    let root = tempfile::tempdir().unwrap();
    let (cfg, db, ops) = fixture(root.path());
    db.transaction(|tx| {
        tx.save(
            AUTOMATION,
            &json!({"mode":"auto","interval_h":7,"last_pick":{"id":"x"}}),
        )
    })
    .unwrap();
    let proc = root.path().join("proc");
    let engine = RouterEngine {
        proc: &proc,
        commands: &ops,
    };
    change(&db, &cfg, &engine, Action::Start).unwrap();
    assert!(engine.running(&cfg));
    change(&db, &cfg, &engine, Action::Start).unwrap();
    change(&db, &cfg, &engine, Action::Restart).unwrap();
    change(&db, &cfg, &engine, Action::Stop).unwrap();
    assert!(!engine.running(&cfg));
    assert!(change(&db, &cfg, &engine, Action::Restart).is_err());
    assert_eq!(
        db.read::<Value>(AUTOMATION).unwrap(),
        json!({"mode":"auto","interval_h":7,"last_pick":{"id":"x"},"nfqws2_manual_off":true})
    );
    assert_eq!(
        *ops.calls.lock().unwrap(),
        [
            "start",
            "stop",
            "firewall_stop",
            "start",
            "stop",
            "firewall_stop"
        ]
    );
    change(&db, &cfg, &engine, Action::Start).unwrap();
    assert!(!manual_off(&db).unwrap());
}
#[test]
fn interrupted_start_and_firewall_cleanup_keep_manual_off() {
    let root = tempfile::tempdir().unwrap();
    let (cfg, db, ops) = fixture(root.path());
    let proc = root.path().join("proc");
    let engine = RouterEngine {
        proc: &proc,
        commands: &ops,
    };
    persist(&db, true).unwrap();
    ops.fail_start.store(true, Ordering::Relaxed);
    assert!(change(&db, &cfg, &engine, Action::Start).is_err());
    assert!(!engine.running(&cfg));
    assert!(manual_off(&db).unwrap());
    assert_eq!(
        *ops.calls.lock().unwrap(),
        ["start", "stop", "firewall_stop"]
    );
    ops.lingering_rule.store(true, Ordering::Relaxed);
    assert!(change(&db, &cfg, &engine, Action::RestoreOff)
        .unwrap_err()
        .to_string()
        .contains("NFQUEUE"));
    assert!(manual_off(&db).unwrap());
}
#[test]
fn firewall_rule_verification_ignores_comments_and_other_queues() {
    for line in [
        "-A c -j NFQUEUE --queue-num 300",
        "-A c --queue-balance 299:301 -j NFQUEUE",
    ] {
        assert!(queue_rule(line, 300));
    }
    for line in [
        r#"-A c --comment "-j NFQUEUE --queue-num 300" -j ACCEPT"#,
        "-A c -j NFQUEUE --queue-num 301",
        "-N NFQUEUE",
    ] {
        assert!(!queue_rule(line, 300));
    }
}
#[tokio::test]
async fn normal_http_entry_points_keep_acceleration_and_unknown_services_intact() {
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;
    let root = tempfile::tempdir().unwrap();
    let (cfg, db, _) = fixture(root.path());
    let journal = Path::new(&cfg.data_dir).join("awg-acceleration-state.json");
    fs::write(&journal, "fixture-owned-by-Go").unwrap();
    let state = crate::http::AppState::open(cfg, root.path(), true).unwrap();
    let app = crate::http::router(state.clone());
    for path in [
        "/api/nfqws2/start",
        "/api/nfqws2/stop",
        "/api/services/restart",
    ] {
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .body(Body::from(
                r#"{"services":["tgws","socks5","fixture","nfqws2"]}"#,
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 200);
        let body: Value =
            serde_json::from_slice(&to_bytes(resp.into_body(), 4096).await.unwrap()).unwrap();
        if path.ends_with("restart") {
            assert_eq!(body["results"].as_array().unwrap().len(), 4);
            assert!(body["results"]
                .as_array()
                .unwrap()
                .iter()
                .all(|item| item["ok"] == false));
        } else {
            assert_eq!(body["ok"], false);
            assert!(body["detail"].as_str().unwrap().contains("PPE"));
        }
    }
    assert_eq!(fs::read_to_string(journal).unwrap(), "fixture-owned-by-Go");
    assert!(!manual_off(&db).unwrap());
    persist(&db, true).unwrap();
    restore_manual_off(&state).await;
    assert!(state.watchdog.lock().unwrap().retry_stop);
    persist(&db, false).unwrap();
    restore_manual_off(&state).await;
    assert!(!state.watchdog.lock().unwrap().retry_stop);
}
