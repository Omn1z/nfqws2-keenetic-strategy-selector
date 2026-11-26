use super::*;
use axum::{
    body::{to_bytes, Body},
    http::Request,
};
use nfqws2_config::{Config, Resolver};
use tower::ServiceExt;

async fn request(
    api: &Router,
    method: &str,
    uri: &str,
    content: &str,
    body: &str,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", content)
        .body(Body::from(body.to_owned()))
        .unwrap();
    let res = api.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn uploaded_file_is_only_published_after_complete_form() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let cfg = Config {
        data_dir: root.to_string_lossy().into(),
        ..Config::from_resolver(&Resolver::new_at(root))
    };
    let state = crate::http::AppState::open(cfg, root, true).unwrap();
    let router = crate::http::router(state.clone());
    let content = "multipart/form-data; boundary=sample";
    let form = "--sample\r\nContent-Disposition: form-data; name=\"file\"; filename=\"source.txt\"\r\n\r\ndemo.test\n192.0.2.0/24\n\r\n--sample\r\nContent-Disposition: form-data; name=\"kind\"\r\n\r\ntext\r\n--sample--\r\n";
    let (status, _) = request(&router, "POST", "/api/geo", content, form).await;
    assert_eq!(status, StatusCode::OK);
    let interrupted = form
        .replace("demo.test", "replacement.test")
        .replace("--sample--\r\n", "");
    assert_eq!(
        request(&router, "POST", "/api/geo", content, &interrupted)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        fs::read_to_string(root.join("geo/source.txt")).unwrap(),
        "demo.test\n192.0.2.0/24\n"
    );
    assert_eq!(fs::read_dir(root.join("geo")).unwrap().count(), 1);

    let query = r#"{"geo":"source.txt","category":"ALL","limit":1}"#;
    let (_, files) = request(&router, "GET", "/api/geo", "application/json", "").await;
    assert_eq!(files[0]["name"], "source.txt");
    if backend::available() {
        assert_eq!(files[0]["categories"], json!([{"name":"all","count":2}]));
        let (status, result) = request(
            &router,
            "POST",
            "/api/geo/resolve",
            "application/json",
            query,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(result, json!({"targets":["demo.test"]}));
        let (status, list) = request(
            &router,
            "POST",
            "/api/geo/import",
            "application/json",
            r#"{"geo":"source.txt","category":"ALL"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(list["domains"], json!(["demo.test"]));
        assert_eq!(list["ips"], json!(["192.0.2.0/24"]));
    } else {
        assert!(files[0]["categories"].is_null());
        assert!(!request(
            &router,
            "POST",
            "/api/geo/resolve",
            "application/json",
            query
        )
        .await
        .0
        .is_success());
    }
    assert_eq!(
        request(
            &router,
            "POST",
            "/api/geo/resolve",
            "application/json",
            r#"{"geo":"../settings.json"}"#
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(
            &router,
            "DELETE",
            "/api/geo/source.txt",
            "application/json",
            ""
        )
        .await
        .0,
        StatusCode::OK
    );
    assert!(!root.join("geo/source.txt").exists());
    let (_, empty) = request(&router, "GET", "/api/geo", "application/json", "").await;
    assert_eq!(empty, json!([]));
}

#[tokio::test]
async fn upload_uses_the_first_regular_kind_field_or_a_nonempty_query_override() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let cfg = Config {
        data_dir: root.to_string_lossy().into(),
        ..Config::from_resolver(&Resolver::new_at(root))
    };
    let state = crate::http::AppState::open(cfg, root, true).unwrap();
    let router = crate::http::router(state);
    let content = "multipart/form-data; boundary=geo";
    let site = "\x0a\x0b\x0a\x02RU\x12\x05\x12\x03abc";
    let form = format!(concat!(
        "--geo\r\nContent-Disposition: form-data; name=\"file\"; filename=\"site.dat\"\r\n\r\n{}\r\n",
        "--geo\r\nContent-Disposition: form-data; name=\"kind\"; filename=\"extra.bin\"\r\n\r\n{}\r\n",
        "--geo\r\nContent-Disposition: form-data; name=\"kind\"\r\n\r\ngeosite\r\n",
        "--geo\r\nContent-Disposition: form-data; name=\"kind\"\r\n\r\ngeoip\r\n--geo--\r\n"
    ), site, "x".repeat(80));
    for (uri, expected) in [
        ("/api/geo", "geosite"),
        ("/api/geo?kind=", "geosite"),
        ("/api/geo?kind=geoip", "geoip"),
    ] {
        let (status, saved) = request(&router, "POST", uri, content, &form).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(saved["kind"], expected);
        assert_eq!(
            fs::read(root.join("geo/site.dat")).unwrap(),
            site.as_bytes()
        );
        let (_, files) = request(&router, "GET", "/api/geo", "application/json", "").await;
        assert_eq!(files[0]["kind"], expected);
        if expected == "geosite" && backend::available() {
            assert_eq!(files[0]["categories"], json!([{"name":"ru","count":1}]));
        }
    }
}

#[tokio::test]
async fn settings_updates_preserve_counters() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::write(
        root.join("geo_auto.json"),
        r#"{"enabled":false,"last_geoip_len":40,"last_fetched_at":7}"#,
    )
    .unwrap();
    let cfg = Config {
        data_dir: root.to_string_lossy().into(),
        ..Config::from_resolver(&Resolver::new_at(root))
    };
    let api = crate::http::router(crate::http::AppState::open(cfg, root, true).unwrap());
    let (status, saved) = request(
        &api,
        "POST",
        "/api/geo/auto",
        "application/json",
        r#"{"enabled":true,"interval_hours":0,"last_geoip_len":0,"last_fetched_at":0}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(saved["last_geoip_len"], 40);
    assert_eq!(saved["last_fetched_at"], 7);
    assert_eq!(saved["enabled"], true);
    assert_eq!(saved["interval_hours"], 24);
    assert_eq!(
        request(&api, "GET", "/api/geo/auto", "application/json", "")
            .await
            .1,
        saved
    );
}

#[test]
fn routing_snapshots_merge_real_databases_and_reject_corruption() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let state = crate::http::AppState::open(
        Config {
            data_dir: root.to_string_lossy().into(),
            ..Config::from_resolver(&Resolver::new_at(root))
        },
        root,
        true,
    )
    .unwrap();
    let field = |tag: u8, bytes: &[u8]| {
        assert!(bytes.len() < 128);
        [&[tag, bytes.len() as u8][..], bytes].concat()
    };
    let database = |key: &str, names: &[&str]| {
        let mut group = field(10, key.as_bytes());
        for name in names {
            group.extend(field(
                18,
                &[&[8, 3][..], &field(18, name.as_bytes())].concat(),
            ));
        }
        field(10, &group)
    };
    let geo = dir(&state.config.data_dir).unwrap();
    let meta = br#"{"a.dat":"geosite","b.dat":"geosite","c.dat":"geosite"}"#;
    fs::write(root.join(META), meta).unwrap();
    fs::write(geo.join("a.dat"), database("OTHER", &["else.test"])).unwrap();
    fs::write(geo.join("b.dat"), database("GROUP", &["1.test", "2.test"])).unwrap();
    fs::write(geo.join("c.dat"), database("group", &["2.test", "3.test"])).unwrap();
    if backend::available() {
        assert_eq!(
            routing_entries(&state.config.data_dir, "geosite", "GROUP").unwrap(),
            ["1.test", "2.test", "3.test"]
        );
        assert!(
            backend::bounded_extract(&geo.join("b.dat"), "geosite", "group", 1, 2 << 20).is_err()
        );
        assert!(backend::bounded_extract(&geo.join("c.dat"), "geosite", "group", 10, 2).is_err());
        assert_eq!(
            backend::bounded_extract(&geo.join("c.dat"), "geosite", "group", 2, 12)
                .unwrap()
                .unwrap(),
            ["2.test", "3.test"]
        );
        assert!(routing_entries(&state.config.data_dir, "geosite", "unknown")
            .unwrap()
            .is_empty());
    } else {
        assert!(routing_entries(&state.config.data_dir, "geosite", "GROUP").is_err());
    }
    fs::write(geo.join("c.dat"), [10, 128]).unwrap();
    assert!(routing_entries(&state.config.data_dir, "geosite", "GROUP").is_err());
    assert_eq!(fs::read(root.join(META)).unwrap(), meta);
    fs::write(root.join(META), br#"{"../wrong":"geosite"}"#).unwrap();
    assert!(routing_entries(&state.config.data_dir, "geosite", "GROUP").is_err());
}

#[test]
fn snapshot_quota_counts_decoded_utf8_and_accepts_empty_categories() {
    if !backend::available() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let file = temp.path().join("list.txt");
    let values = ["a\\\"b", "а\tб", "x\u{1}y"];
    fs::write(&file, values.join("\n")).unwrap();
    let bytes = values.iter().map(|v| v.len()).sum::<usize>();
    let extract = |count, bytes| backend::bounded_extract(&file, "text", "all", count, bytes);
    assert_eq!(extract(3, bytes).unwrap().unwrap(), values);
    assert_eq!(extract(0, bytes).unwrap().unwrap(), values);
    assert!(extract(2, bytes).is_err());
    assert!(extract(3, bytes - 1).is_err());
    fs::write(&file, "# empty\n").unwrap();
    assert!(extract(1, 0).unwrap().unwrap().is_empty());
    assert!(backend::bounded_extract(&file, "text", "missing", 1, 0)
        .unwrap()
        .is_none());
}
