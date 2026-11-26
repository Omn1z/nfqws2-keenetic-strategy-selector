use super::*;
use axum::{body::to_bytes, http::Request};
use nfqws2_config::{Config, Resolver};
use std::fs;
use tower::ServiceExt;

async fn request(
    api: &Router,
    method: &str,
    url: &str,
    content: &str,
    data: Vec<u8>,
) -> (StatusCode, Vec<u8>) {
    let request = Request::builder()
        .method(method)
        .uri(url)
        .header(header::CONTENT_TYPE, content)
        .body(Body::from(data))
        .unwrap();
    let res = api.clone().oneshot(request).await.unwrap();
    let status = res.status();
    (
        status,
        to_bytes(res.into_body(), 40 << 20).await.unwrap().to_vec(),
    )
}
fn form(name: &str, bytes: &[u8]) -> Vec<u8> {
    let mut out=format!("--blob-upload\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n\r\n").into_bytes();
    out.extend_from_slice(bytes);
    out.extend_from_slice(b"\r\n--blob-upload--\r\n");
    out
}
const MULTIPART: &str = "multipart/form-data; boundary=blob-upload";
fn j(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}

#[tokio::test]
async fn blob_and_strategy_archives_roundtrip_through_http() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config {
        data_dir: dir.path().to_string_lossy().into_owned(),
        system_blobs_dir: dir.path().join("system").to_string_lossy().into_owned(),
        ..Config::from_resolver(&Resolver::new_at(dir.path()))
    };
    let state = crate::http::AppState::open(cfg, dir.path(), true).unwrap();
    let api = crate::http::router(state);
    let (status, res) = request(
        &api,
        "POST",
        "/api/blobs",
        MULTIPART,
        form("sample.bin", b"abc\0def"),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(j(&res)["name"], "sample.bin");
    let (status, zip) = request(&api, "GET", "/api/blobs/export", "", Vec::new()).await;
    assert_eq!(status, 200);
    assert_eq!(
        request(&api, "DELETE", "/api/blobs/sample.bin", "", vec![])
            .await
            .0,
        200
    );
    let (_, res) = request(&api, "GET", "/api/blobs", "", vec![]).await;
    assert_eq!(j(&res)["trash"], json!(["sample.bin"]));
    assert_eq!(
        request(&api, "POST", "/api/blobs/sample.bin/restore", "", vec![])
            .await
            .0,
        200
    );
    let (status, res) = request(
        &api,
        "POST",
        "/api/blobs/zip",
        MULTIPART,
        form("archive.zip", &zip),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(j(&res)["imported"], 1);
    let existing = dir.path().join("blobs").join("sample.bin");
    assert_eq!(fs::read(&existing).unwrap(), b"abc\0def");
    let strategy =
        json!({"name":"sample","l7":"tls","args":format!("--blob=payload:@{}",existing.display())});
    let (status, zip) = request(
        &api,
        "POST",
        "/api/strategies/export",
        "application/json",
        strategy.to_string().into_bytes(),
    )
    .await;
    assert_eq!(status, 200);
    fs::remove_file(&existing).unwrap();
    let (status, res) = request(
        &api,
        "POST",
        "/api/strategies/import",
        MULTIPART,
        form("strategy.zip", &zip),
    )
    .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&res));
    assert_eq!(j(&res)["source"], "custom");
    assert_eq!(j(&res)["args"], strategy["args"]);
    assert_eq!(fs::read(existing).unwrap(), b"abc\0def");

    let generate =
        json!({"name":"hello.bin","sni":"api.example.test","alpn":["h2"],"min_version":772});
    assert_eq!(
        request(
            &api,
            "POST",
            "/api/blobs/generate",
            "application/json",
            generate.to_string().into_bytes()
        )
        .await
        .0,
        200
    );
    let (status, res) = request(&api, "GET", "/api/blobs/hello.bin/validate", "", vec![]).await;
    assert_eq!(status, 200);
    assert_eq!(j(&res)["valid"], true);
    assert!(j(&res)["detail"]
        .as_str()
        .unwrap()
        .contains("api.example.test"));
}
#[tokio::test]
async fn imports_strategy_from_go_archive_zip() {
    // Produced by the same archive/zip.Writer used by the Go panel,
    // including deflated entries with data descriptors.
    let fixture = include_bytes!("../../tests/fixtures/legacy-strategy.zip");
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let cfg = Config {
        data_dir: root.to_string_lossy().into_owned(),
        ..Config::from_resolver(&Resolver::new_at(root))
    };
    let api = crate::http::router(crate::http::AppState::open(cfg, root, true).unwrap());
    let (status, body) = request(
        &api,
        "POST",
        "/api/strategies/import",
        MULTIPART,
        form("legacy.zip", fixture),
    )
    .await;
    assert_eq!(status, 200);
    let strategy = j(&body);
    assert_eq!(strategy["name"], "from Go");
    let path = root.join("blobs").join("sample.bin");
    assert_eq!(
        strategy["args"],
        format!("--blob=sample:@{}", path.display())
    );
    assert_eq!(fs::read(path).unwrap(), b"legacy\0blob");
}

#[tokio::test]
async fn rejects_truncated_and_oversized_uploads_before_replacing_blob() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let cfg = Config {
        data_dir: root.to_string_lossy().into_owned(),
        ..Config::from_resolver(&Resolver::new_at(root))
    };
    let api = crate::http::router(crate::http::AppState::open(cfg, root, true).unwrap());
    fs::create_dir_all(root.join("blobs")).unwrap();
    fs::write(root.join("blobs/keep"), b"old").unwrap();
    let mut partial = form("keep", b"replacement");
    partial.truncate(partial.len() - 14);
    assert_eq!(
        request(&api, "POST", "/api/blobs", MULTIPART, partial)
            .await
            .0,
        400
    );
    assert_eq!(
        request(
            &api,
            "POST",
            "/api/blobs",
            MULTIPART,
            form("keep", &vec![0; MAX_UPLOAD as usize + 1])
        )
        .await
        .0,
        413
    );
    assert_eq!(fs::read(root.join("blobs/keep")).unwrap(), b"old");
}
