use super::*;
use axum::{
    body::{to_bytes, Body},
    http::Request,
};
use nfqws2_config::Config;
use tower::ServiceExt;

const TARGET: &str = r#"{"target":{"host":"example.test","blocked":false,"verdict":"ok","code":403,"size":1,"ttfb_ms":3,"speed_bps":200}}"#;
// This subprocess only implements the helper pipe protocol. No test starts
// curl, installs firewall rules, or attempts to contact a domain.
fn fixture(mode: &str) -> Command {
    #[cfg(windows)]
    let mut cmd = {
        let mut command = Command::new("powershell");
        command.args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            r#"
            $null=[Console]::ReadLine()
            [Console]::WriteLine($env:N2S_BC_FIXTURE_TARGET)
            if ($env:N2S_BC_FIXTURE_MODE -eq 'wait') {
                $null=[Console]::ReadLine()
                [Console]::WriteLine('{"status":"cancelled"}')
            } elseif ($env:N2S_BC_FIXTURE_MODE -eq 'error') {
                [Console]::WriteLine('{"status":"error","error":"isolated rule missing"}')
                exit 1
            } elseif ($env:N2S_BC_FIXTURE_MODE -eq 'done') {
                [Console]::WriteLine('{"status":"done"}')
            }
        "#,
        ]);
        command
    };
    #[cfg(not(windows))]
    let mut cmd = {
        let mut command = Command::new("sh");
        command.args([
            "-c",
            r#"
            IFS= read -r job
            printf '%s\n' "$N2S_BC_FIXTURE_TARGET"
            case "$N2S_BC_FIXTURE_MODE" in
                wait) IFS= read -r cancel; printf '%s\n' '{"status":"cancelled"}' ;;
                error) printf '%s\n' '{"status":"error","error":"isolated rule missing"}'; exit 1 ;;
                done) printf '%s\n' '{"status":"done"}' ;;
            esac
        "#,
        ]);
        command
    };
    cmd.env("N2S_BC_FIXTURE_TARGET", TARGET)
        .env("N2S_BC_FIXTURE_MODE", mode);
    cmd
}
fn app(dir: &tempfile::TempDir, mode: &'static str) -> (Shared, Router) {
    let marker = dir.path().join("verified-recovery");
    let state = crate::http::AppState::open(
        Config {
            data_dir: dir.path().display().to_string(),
            ..Config::default()
        },
        dir.path(),
        true,
    )
    .unwrap();
    let app = Router::new()
        .route(
            "/api/blockcheck",
            post(
                move |State(s): State<Shared>, ApiJson(req): ApiJson<Start>| {
                    #[cfg(windows)]
                    let mut recovery = {
                        let mut cmd = Command::new("powershell");
                        cmd.args([
                            "-NoProfile",
                            "-NonInteractive",
                            "-Command",
                            "[IO.File]::WriteAllText($env:N2S_BC_TEST_MARKER,'ok')",
                        ]);
                        cmd
                    };
                    #[cfg(not(windows))]
                    let mut recovery = {
                        let mut cmd = Command::new("sh");
                        cmd.args(["-c", "printf ok > \"$N2S_BC_TEST_MARKER\""]);
                        cmd
                    };
                    recovery.env("N2S_BC_TEST_MARKER", &marker);
                    start_with(s, req, fixture(mode), Some(recovery))
                },
            ),
        )
        .route("/api/blockcheck/{id}", get(status))
        .route("/api/blockcheck/{id}/cancel", post(cancel))
        .with_state(state.clone());
    (state, app)
}
async fn req(app: &Router, method: &str, path: &str, body: &str) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body = to_bytes(resp.into_body(), 10000).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}
async fn finished(app: &Router, path: &str) -> Value {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        loop {
            let (code, r) = req(app, "GET", path, "").await;
            assert_eq!(code, 200);
            if r["status"] != "running" {
                return r;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap()
}
#[tokio::test]
async fn start_poll_cancel_and_shutdown_wait_for_child_exit() {
    let dir = tempfile::tempdir().unwrap();
    let (state, app) = app(&dir, "wait");
    let (code, job) = req(
        &app,
        "POST",
        "/api/blockcheck",
        r#"{"targets":["example.test"," example.test ",""],"threads":12}"#,
    )
    .await;
    assert_eq!(code, 200);
    assert_eq!(job["total"], 1);
    assert_eq!(job["threads"], 1);
    let path = format!("/api/blockcheck/{}", job["id"].as_str().unwrap());
    assert_eq!(req(&app, "GET", &path, "").await.1["status"], "running");
    assert_eq!(
        req(
            &app,
            "POST",
            "/api/blockcheck",
            r#"{"targets":["example.test"]}"#
        )
        .await
        .0,
        400
    );
    let cancel = format!("{path}/cancel");
    assert_eq!(
        req(&app, "POST", &cancel, "").await.1["status"],
        "cancelling"
    );
    assert_eq!(finished(&app, &path).await["status"], "cancelled");
    assert_eq!(req(&app, "POST", &cancel, "").await.0, 400);
    let (_, next) = req(
        &app,
        "POST",
        "/api/blockcheck",
        r#"{"targets":["example.test"]}"#,
    )
    .await;
    assert_eq!(req(&app, "GET", &path, "").await.1["status"], "cancelled");
    tokio::time::timeout(
        std::time::Duration::from_secs(15),
        state.blockcheck.shutdown(),
    )
    .await
    .unwrap();
    assert!(!state.active_test.load(Ordering::Acquire));
    let path = format!("/api/blockcheck/{}", next["id"].as_str().unwrap());
    assert_eq!(finished(&app, &path).await["status"], "cancelled");
}
#[tokio::test]
async fn terminal_verification_rejects_partial_results_and_reads_saved_list() {
    for mode in ["done", "error", "abnormal"] {
        let dir = tempfile::tempdir().unwrap();
        let (state, app) = app(&dir, mode);
        let list = data::save_list(
            &state.store,
            data::List {
                name: "saved".into(),
                domains: Some(vec!["example.test".into()]),
                ..Default::default()
            },
        )
        .unwrap();
        let (code, job) = req(
            &app,
            "POST",
            "/api/blockcheck",
            &json!({"list_id":list.id,"threads":2}).to_string(),
        )
        .await;
        assert_eq!(code, 200);
        assert_eq!(job["list_name"], "saved");
        let path = format!("/api/blockcheck/{}", job["id"].as_str().unwrap());
        let r = finished(&app, &path).await;
        assert_eq!(
            dir.path().join("verified-recovery").exists(),
            mode == "abnormal"
        );
        assert!(r["finished_at"].is_number());
        if mode == "done" {
            assert_eq!(r["status"], "done");
            assert_eq!(r["targets"][0]["code"], 403);
        } else {
            assert_eq!(r["status"], "error");
            assert_eq!(r["done"], 0);
            assert!(r["targets"].as_array().unwrap().is_empty());
        }
        assert_eq!(req(&app, "GET", "/api/blockcheck/missing", "").await.0, 404);
    }
}
