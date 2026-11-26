use super::*;
use axum::{body::to_bytes, http::Request};
use tower::ServiceExt;
fn fixture(mode: &str) -> Command {
    #[cfg(windows)]
    let mut cmd = {
        let mut cmd = Command::new("powershell");
        cmd.args(["-NoProfile","-NonInteractive","-Command",r#"
        if ($env:N2S_TRACE_FIXTURE -eq 'missing') {
            [Console]::Error.WriteLine('{"need_install":true,"package":"tcpdump"}'); exit 0
        }
        [Console]::Error.WriteLine('{"ready":true,"iface":"br0"}')
        switch ($env:N2S_TRACE_FIXTURE) {
            'wait' { $null=[Console]::ReadLine(); [Console]::Error.WriteLine('{"status":"cancelled","elapsed_ms":15}') }
            'trace' { [Console]::Error.WriteLine('{"events":[{"kind":"new"}],"elapsed_ms":10}'); [Console]::Error.WriteLine('{"status":"done","conns":[]}') }
            'hello' { [Console]::Error.WriteLine('{"status":"done","observations":{"192.0.2.80":{"headers":2,"record_bytes":150}}}') }
            'records' { [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $stream=[IO.File]::Open($env:N2S_TRACE_ARCHIVE,'Open','Read',[IO.FileShare]'ReadWrite,Delete'); $stream.CopyTo([Console]::OpenStandardOutput()); $stream.Dispose(); [Console]::Error.WriteLine($env:N2S_TRACE_REPORT) }
            'pcap' {
                $data=[Convert]::FromBase64String('1MOyoQIABAAAAAAAAAAAAP//AAABAAAA')
                [Console]::OpenStandardOutput().Write($data,0,$data.Length)
                [Console]::Error.WriteLine('{"status":"done","size_bytes":24,"packets":0,"dropped":0}')
            }
            'broken' { [Console]::Error.WriteLine('{"status":"done","size_bytes":100}') }
        }
        "#]);
        cmd
    };
    #[cfg(not(windows))]
    let mut cmd = {
        let mut cmd = Command::new("sh");
        cmd.args(["-c",r#"
        if [ "$N2S_TRACE_FIXTURE" = missing ]; then echo '{"need_install":true,"package":"tcpdump"}' >&2; exit 0; fi
        echo '{"ready":true,"iface":"br0"}' >&2
        case "$N2S_TRACE_FIXTURE" in
            wait) IFS= read -r cancel; echo '{"status":"cancelled","elapsed_ms":15}' >&2 ;;
            trace) echo '{"events":[{"kind":"new"}],"elapsed_ms":10}' >&2; echo '{"status":"done","conns":[]}' >&2 ;;
            hello) echo '{"status":"done","observations":{"192.0.2.80":{"headers":2,"record_bytes":150}}}' >&2 ;;
            records) cat "$N2S_TRACE_ARCHIVE"; printf '%s\n' "$N2S_TRACE_REPORT" >&2 ;;
            pcap) printf '\324\303\262\241\002\000\004\000\000\000\000\000\000\000\000\000\377\377\000\000\001\000\000\000'; echo '{"status":"done","size_bytes":24,"packets":0,"dropped":0}' >&2 ;;
            broken) echo '{"status":"done","size_bytes":100}' >&2 ;;
        esac
        "#]);
        cmd
    };
    cmd.env("N2S_TRACE_FIXTURE", mode);
    cmd
}
fn state(dir: &tempfile::TempDir) -> Shared {
    crate::http::AppState::open(
        nfqws2_config::Config {
            data_dir: dir.path().display().to_string(),
            ..Default::default()
        },
        dir.path(),
        true,
    )
    .unwrap()
}
async fn job(s: &Shared, fixture_mode: &str, mode: &'static str) -> Value {
    launch(
        &s.trace,
        fixture(fixture_mode),
        "192.0.2.4".parse().unwrap(),
        mode,
        3,
    )
    .await
    .unwrap_or_else(|e| panic!("{}", e.1))
    .0
}
async fn poll(s: &Shared, mode: &str, id: &str) -> Value {
    timeout(Duration::from_secs(5), async {
        loop {
            let v = status(s, mode, id).unwrap_or_else(|e| panic!("{}", e.1)).0;
            if v["status"] != "running" {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}
#[tokio::test]
async fn packet_download_is_complete_independent_and_unavailable_on_error() {
    let dir = tempfile::tempdir().unwrap();
    let s = state(&dir);
    assert_eq!(job(&s, "missing", "pcap").await["need_install"], true);
    for mode in ["pcap", "broken"] {
        let r = job(&s, mode, "pcap").await;
        let id = r["id"].as_str().unwrap();
        let r = poll(&s, "pcap", id).await;
        let app = crate::http::router(s.clone());
        let fetch = || {
            app.clone().oneshot(
                Request::builder()
                    .uri(format!("/api/pcap/{id}/download"))
                    .body(Body::empty())
                    .unwrap(),
            )
        };
        if mode == "broken" {
            assert_eq!(r["status"], "error");
            assert_eq!(fetch().await.unwrap().status(), 404);
            continue;
        }
        let (a, b) = tokio::join!(fetch(), fetch());
        for resp in [a.unwrap(), b.unwrap()] {
            assert_eq!(resp.status(), 200);
            assert_eq!(
                resp.headers()[header::CONTENT_TYPE],
                "application/vnd.tcpdump.pcap"
            );
            assert_eq!(resp.headers()[header::CONTENT_LENGTH], "24");
            assert!(resp.headers()[header::CONTENT_DISPOSITION]
                .to_str()
                .unwrap()
                .contains("pcap-192.0.2.4"));
            let bytes = to_bytes(resp.into_body(), 24).await.unwrap();
            assert_eq!(&bytes[..4], b"\xd4\xc3\xb2\xa1");
        }
    }
}
#[tokio::test]
async fn tls_observations_remain_metadata_across_the_http_api() {
    let dir = tempfile::tempdir().unwrap();
    let s = state(&dir);
    let doc = job(&s, "hello", "hello").await;
    let id = doc["id"].as_str().unwrap();
    assert_eq!(doc["metadata_only"], true);
    assert_eq!(
        poll(&s, "hello", id).await["observations"]["192.0.2.80"]["headers"],
        2
    );
    let app = crate::http::router(s);
    let response = app
        .clone()
        .oneshot(
            Request::get(format!("/api/blobcap/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let view: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(view["candidates"], json!([]));
    assert_eq!(view["iface"], "br0");
    let download = app
        .oneshot(
            Request::get(format!("/api/pcap/{id}/download"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(download.status(), StatusCode::NOT_FOUND);
}
#[tokio::test]
async fn save_selected_capture_uses_the_matching_private_range_and_validates_the_filename() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let s = state(&dir);
    let app = crate::http::router(s.clone());
    let records =
        ["one.example", "two.example"].map(|sni| nfqws2_blobs::generate(sni, &[], 0).unwrap());
    let mut file = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
    let mut rows = Vec::new();
    for (bytes, sni) in records.iter().zip(["one.example", "two.example"]) {
        let (valid, detail) = nfqws2_blobs::validate(bytes);
        rows.push(
            json!({"src_ip":"192.0.2.4","dst_ip":"192.0.2.80","dst_port":443,
            "sni":sni,"size":bytes.len(),"valid":valid,"detail":detail}),
        );
        file.write_all(bytes).unwrap();
    }
    file.flush().unwrap();
    let run = |rows: Vec<Value>| {
        let mut cmd = fixture("records");
        cmd.env("N2S_TRACE_ARCHIVE", file.path()).env(
            "N2S_TRACE_REPORT",
            json!({"status":"done","candidates":rows}).to_string(),
        );
        launch(&s.trace, cmd, "192.0.2.4".parse().unwrap(), "hello", 3)
    };
    let mut incorrect = rows.clone();
    incorrect[0]["size"] = json!(100);
    let broken = run(incorrect).await.unwrap_or_else(|e| panic!("{}", e.1)).0;
    let broken_id = broken["id"].as_str().unwrap();
    let summary = poll(&s, "hello", broken_id).await;
    assert_eq!(summary["status"], "error");
    assert_eq!(summary["candidates"], json!([]));
    let doc = run(rows.clone())
        .await
        .unwrap_or_else(|e| panic!("{}", e.1))
        .0;
    let id = doc["id"].as_str().unwrap();
    let summary = poll(&s, "hello", id).await;
    assert_eq!(summary["status"], "done", "{}", summary["error"]);
    let status = app
        .clone()
        .oneshot(
            Request::get(format!("/api/blobcap/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = to_bytes(status.into_body(), 4096).await.unwrap();
    let view: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(view["candidates"], json!(rows));
    assert_eq!(view["metadata_only"], false);
    let post = |id: &str, body: Value| {
        app.clone().oneshot(
            Request::post(format!("/api/blobcap/{id}/save"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
    };
    let name = "chosen.bin";
    let target = dir.path().join("blobs").join(name);
    for (id, body) in [
        ("missing", json!({"name":name,"index":0})),
        (broken_id, json!({"name":name,"index":0})),
        (id, json!({"index":-1,"name":name})),
        (id, json!({"index":2,"name":name})),
        (id, json!({"index":1,"name":"../outside.bin"})),
        (id, json!({"index":1,"name":""})),
    ] {
        assert_eq!(post(id, body).await.unwrap().status(), 400);
    }
    assert!(!target.exists());
    assert!(!dir.path().join("outside.bin").exists());
    let resp = post(id, json!({"index":1,"name":name})).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = to_bytes(resp.into_body(), 2048).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap(),
        json!({"name":name,"path":target})
    );
    assert_eq!(std::fs::read(&target).unwrap(), records[1]);
    assert_eq!(post(id, json!({"name":name})).await.unwrap().status(), 200);
    assert_eq!(std::fs::read(target).unwrap(), records[0]);
}
#[tokio::test]
async fn trace_snapshot_cancel_concurrency_shutdown_and_eviction() {
    let dir = tempfile::tempdir().unwrap();
    let s = state(&dir);
    let first = job(&s, "trace", "trace").await;
    let first = first["id"].as_str().unwrap();
    assert_eq!(poll(&s, "trace", first).await["events"][0]["kind"], "new");
    let running = job(&s, "wait", "trace").await;
    let id = running["id"].as_str().unwrap();
    assert!(launch(
        &s.trace,
        fixture("wait"),
        "192.0.2.4".parse().unwrap(),
        "pcap",
        5
    )
    .await
    .is_err());
    let app = crate::http::router(s.clone());
    let cancel = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/trace/{id}/cancel"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cancel.status(), 200);
    assert_eq!(poll(&s, "trace", id).await["status"], "cancelled");
    for _ in 0..2 {
        let r = job(&s, "wait", "pcap").await;
        s.trace.shutdown().await;
        assert_eq!(
            poll(&s, "pcap", r["id"].as_str().unwrap()).await["status"],
            "cancelled"
        );
    }
    assert!(status(&s, "trace", first).is_err());
    assert!(!s.trace.busy.load(Ordering::Acquire));
}
