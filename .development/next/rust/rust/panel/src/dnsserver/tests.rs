use super::*;
use axum::{
    body::{to_bytes, Body, Bytes},
    http::{Request, Response},
};
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::{
    convert::Infallible,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};
use tokio_rustls::{
    rustls::{pki_types::PrivatePkcs8KeyDer, ServerConfig},
    TlsAcceptor,
};
use tower::ServiceExt;
#[cfg(target_os = "linux")]
mod client_scope;
mod doh_failover;
mod lifecycle;
mod static_retry;
#[tokio::test]
async fn downloaded_filter_restores_blocks_and_survives_failed_manual_update() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = dir.path().join("dns-blocklists");
    std::fs::create_dir(&catalog).unwrap();
    let content = (0..1200)
        .map(|i| format!("||cached{i}.example^\n"))
        .collect::<String>()
        + "||rewrite.example^$dnsrewrite=1.2.3.4\n";
    std::fs::write(catalog.join("adguard-dns.txt"), &content).unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = target.local_addr().unwrap();
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = closed.local_addr().unwrap();
    drop(target);
    drop(closed);
    let mut cfg = config::defaults();
    cfg["listen_host"] = json!("127.0.0.1");
    cfg["dns_port"] = json!(addr.port());
    cfg["default_upstream"] =
        json!({"address":format!("https://{upstream}/dns-query"),"bootstrap_ips":["127.0.0.1"]});
    cfg["default_pool"] = json!([]);
    cfg["rules"] = json!([]);
    cfg["filtering"] =
        json!({"enabled":true,"lists":["adguard-dns"],"custom_rules":[],"allowlist":[]});
    std::fs::write(dir.path().join("dnsserver.json"), cfg.to_string()).unwrap();
    let shared = state(&dir);
    let app = crate::http::router(shared.clone());
    request(&app, "/api/dnsserver/start", Some(json!({})), 200).await;
    let query = nfqws2_dns::build_query("child.cached17.example", 1, 93).unwrap();
    let engine = shared
        .dnsserver
        .state
        .lock()
        .await
        .active
        .as_ref()
        .unwrap()
        .engine();
    assert_eq!(
        engine
            .exchange(&query, "test", "udp", None)
            .await
            .unwrap()
            .hit
            .unwrap()
            .source,
        "adguard-dns"
    );
    let status = request(&app, "/api/dnsserver", None, 200).await;
    assert_eq!(status["filtering"]["ready"], true);
    assert_eq!(status["filtering"]["rules"], 1200);
    assert_eq!(status["filtering"]["ignored_rules"], 1);
    assert_eq!(status["filtering"]["approximate"], true);
    request(
        &app,
        "/api/dnsserver/filtering/update",
        Some(json!({})),
        200,
    )
    .await;
    timeout(Duration::from_secs(8), async {
        loop {
            let st = request(&app, "/api/dnsserver", None, 200).await;
            if st["filtering"]["updating"] == false
                && st["filtering"]["last_error"]
                    .as_str()
                    .is_some_and(|s| !s.is_empty())
            {
                assert_eq!(st["filtering"]["ready"], true);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        engine
            .exchange(&query, "test", "udp", None)
            .await
            .unwrap()
            .hit
            .unwrap()
            .domain,
        "child.cached17.example"
    );
    assert_eq!(
        std::fs::read_to_string(catalog.join("adguard-dns.txt")).unwrap(),
        content
    );
    shared.dnsserver.shutdown().await;
}
#[tokio::test]
async fn stopped_dns_reports_the_configured_endpoint_without_opening_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config::defaults();
    cfg["listen_host"] = json!("::1");
    cfg.as_object_mut().unwrap().remove("dns_port");
    std::fs::write(dir.path().join("dnsserver.json"), cfg.to_string()).unwrap();

    async fn check(s: &Shared, expected: &str) {
        let app = crate::http::router(s.clone());
        let status = request(&app, "/api/dnsserver", None, 200).await;
        assert_eq!(status["listen_host"], "::1");
        assert_eq!(status["endpoints"]["dns"], expected);
        assert_eq!(status["running"], false);
        let summary = s.dnsserver.dashboard().await;
        assert_eq!(summary["endpoint"], expected);
        assert_eq!(summary["running"], false);
        assert_eq!(s.dnsserver.routing_nameserver().unwrap(), None);
    }

    let s = state(&dir);
    check(&s, "[::1]:5355").await;
    let socket = TcpListener::bind("[::1]:0").await.unwrap();
    let next = socket.local_addr().unwrap();
    drop(socket);
    s.dnsserver
        .change_port(next.port())
        .await
        .map_err(|e| e.1)
        .unwrap();
    let _tcp = TcpListener::bind(next).await.unwrap();
    let _udp = UdpSocket::bind(next).await.unwrap();
    check(&s, &next.to_string()).await;
    let reopened = state(&dir);
    autostart(&reopened).await;
    check(&reopened, &next.to_string()).await;
}

#[tokio::test]
async fn moving_dns_only_releases_old_endpoint_after_both_new_sockets_and_store_are_ready() {
    let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = first.local_addr().unwrap();
    drop(first);
    let busy = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = busy.local_addr().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config::defaults();
    cfg["listen_host"] = json!("127.0.0.1");
    cfg["dns_port"] = json!(a.port());
    std::fs::write(dir.path().join("dnsserver.json"), cfg.to_string()).unwrap();
    let shared = state(&dir);
    assert_eq!(shared.dnsserver.routing_nameserver().unwrap(), None);
    assert!(shared.dnsserver.change_port(b.port()).await.is_err());
    assert_eq!(shared.dnsserver.port().await, a.port());
    let app = crate::http::router(shared.clone());
    request(&app, "/api/dnsserver/start", Some(json!({})), 200).await;
    assert_eq!(shared.dnsserver.routing_nameserver().unwrap(), Some(a));
    assert!(shared.dnsserver.change_port(b.port()).await.is_err());
    assert!(TcpStream::connect(a).await.is_ok());
    drop(busy);
    assert!(shared.dnsserver.change_port(b.port()).await.is_ok());
    assert_eq!(shared.dnsserver.routing_nameserver().unwrap(), Some(b));
    assert!(TcpStream::connect(a).await.is_err());
    assert!(TcpStream::connect(b).await.is_ok());
    shared.dnsserver.shutdown().await;
    let reopened = state(&dir);
    assert!(reopened.dnsserver.routing_nameserver().is_err());
    assert_eq!(reopened.dnsserver.port().await, b.port());
    autostart(&reopened).await;
    assert_eq!(reopened.dnsserver.routing_nameserver().unwrap(), Some(b));
    assert!(TcpStream::connect(b).await.is_ok());
    reopened.dnsserver.shutdown().await;
}

async fn request(app: &axum::Router, path: &str, data: Option<Value>, code: u16) -> Value {
    let req = Request::builder()
        .method(if data.is_some() { "POST" } else { "GET" })
        .uri(path)
        .body(Body::from(data.map_or(String::new(), |v| v.to_string())))
        .unwrap();
    let response = app.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 2 << 20).await.unwrap();
    assert_eq!(status.as_u16(), code, "{}", String::from_utf8_lossy(&bytes));
    serde_json::from_slice(&bytes).unwrap()
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
#[tokio::test]
async fn stopped_dns_reports_independent_awg_routes_in_status_and_schedule() {
    let dir = tempfile::tempdir().unwrap();
    let mut raw = config::defaults();
    raw["default_pool"] = json!([]);
    raw["awg_fallback"] = json!("auto");
    std::fs::write(dir.path().join("dnsserver.json"), raw.to_string()).unwrap();
    let mut shared = state(&dir);
    Arc::get_mut(&mut shared).unwrap().dnsserver.vpn = Arc::new(vpn::Source::with(|| {
        let tunnel = |id: &str, available| vpn::Route {
            id: format!("awg:{id}"),
            name: id.to_owned(),
            interface: format!("awg-{id}"),
            available,
            index: 0,
        };
        Ok(vec![tunnel("down", false), tunnel("up", true)])
    }));
    let app = crate::http::router(shared.clone());
    let status = request(&app, "/api/dnsserver", None, 200).await;
    assert_eq!(status["running"], false);
    let routes = status["routes"].as_array().unwrap();
    let schedule = request(&app, "/api/dnsserver/scheduler", None, 200).await;
    assert_eq!(schedule["effective_candidate_count"], 1);
    assert_eq!(schedule["reason"], "single_candidate");
    let candidates = schedule["candidates"].as_array().unwrap();
    assert_eq!(candidates[0]["route"], "awg:up");
    for (id, reason) in [
        ("nfqws", Some("сервис выключен")),
        ("awg:down", Some("туннель выключен или восстанавливается")),
        ("awg:up", None),
    ] {
        let route = routes.iter().find(|row| row["id"] == id).unwrap();
        let candidate = candidates.iter().find(|row| row["route"] == id).unwrap();
        assert_eq!(route["available"], reason.is_none());
        assert_eq!(candidate["available"], route["available"]);
        assert_eq!(route["error"].as_str(), reason);
        assert_eq!(candidate["last_error"], reason.unwrap_or_default());
    }
    assert_eq!(schedule["tracked_pairs"], 0);
    assert!(shared.dnsserver.state.lock().await.active.is_none());
}
#[tokio::test]
async fn portable_dns_transfer_previews_commits_retries_and_rejects_stale_changes() {
    let dir = tempfile::tempdir().unwrap();
    let mut original = config::defaults();
    original["listen_host"] = json!("127.0.0.1");
    original["legacy_private_extension"] = json!("must-remain-local");
    std::fs::write(dir.path().join("dnsserver.json"), original.to_string()).unwrap();
    let app = crate::http::router(state(&dir));
    let mut doc = request(&app, "/api/dnsserver/export", None, 200).await;
    assert!(doc["config"].get("legacy_private_extension").is_none());
    assert!(doc.get("connections").is_none());
    doc["config"]["cache_size"] = json!(64);
    let preview = request(
        &app,
        "/api/dnsserver/import/preview",
        Some(json!({"document":doc.to_string()})),
        200,
    )
    .await;
    assert_eq!(preview["listener"]["host"], "127.0.0.1");
    assert_eq!(preview["config"]["cache_size"], 64);
    assert_eq!(
        request(&app, "/api/dnsserver", None, 200).await["config"]["cache_size"],
        original["cache_size"]
    );
    let body = json!({"document":doc,"base_hash":preview["base_hash"]});
    for _ in 0..2 {
        assert_eq!(
            request(&app, "/api/dnsserver/import", Some(body.clone()), 200).await["config"]
                ["cache_size"],
            64
        );
    }
    doc["config"]["cache_size"] = json!(80);
    request(
        &app,
        "/api/dnsserver/import",
        Some(json!({"document":doc,"base_hash":preview["base_hash"]})),
        409,
    )
    .await;
    doc["config"]["unknown_property"] = json!(true);
    request(
        &app,
        "/api/dnsserver/import/preview",
        Some(json!({"document":doc})),
        400,
    )
    .await;
    let duplicate = doc
        .to_string()
        .replacen("\"version\":1", "\"version\":1,\"version\":1", 1);
    request(
        &app,
        "/api/dnsserver/import/preview",
        Some(json!({"document":duplicate})),
        400,
    )
    .await;
    assert_eq!(
        request(&app, "/api/dnsserver", None, 200).await["config"]["cache_size"],
        64
    );
}

#[tokio::test]
async fn disabled_dns_reports_verified_recovery_once_per_process_and_keeps_user_rules() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dnsserver.json");
    let mut saved = config::defaults();
    saved["enabled"] = json!(false);
    saved["dns_port"] = json!(5553);
    saved["rules"] = json!([]);
    saved["logging_enabled"] = json!(false);
    saved["disabled_methods"] =
        json!([{"route":"nfqws", "upstream":"https://dns.example/dns-query"}]);
    std::fs::write(&path, saved.to_string()).unwrap();
    let healthy = state(&dir);
    let expected = healthy.dnsserver.status().await;
    assert!(expected.get("config_warning").is_none());
    assert_eq!(expected["config_hash"].as_str().unwrap().len(), 64);
    drop(healthy);

    std::fs::write(&path, b"{truncated").unwrap();
    let recovered = state(&dir);
    let app = crate::http::router(recovered.clone());
    let status = request(&app, "/api/dnsserver", None, 200).await;
    assert_eq!(status["config_warning"], RECOVERED_WARNING);
    assert_eq!(status["config_error"], "");
    assert_eq!(status["running"], false);
    assert_eq!(status["config"], expected["config"]);
    assert_eq!(status["config_hash"], expected["config_hash"]);
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(&path).unwrap()).unwrap(),
        saved
    );
    drop(app);
    drop(recovered);

    let restarted = state(&dir);
    assert!(restarted
        .dnsserver
        .status()
        .await
        .get("config_warning")
        .is_none());
    let primary = path.clone();
    restarted
        .dnsserver
        .with_config_restore(move || std::fs::write(primary, b"{invalid"))
        .await
        .map_err(|e| e.1)
        .unwrap();
    let status = restarted.dnsserver.status().await;
    assert_eq!(status["config_warning"], RECOVERED_WARNING);
    assert_eq!(status["config_hash"], expected["config_hash"]);
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(path).unwrap()).unwrap(),
        saved
    );
}

#[tokio::test]
async fn portable_dns_recovery_cannot_overwrite_a_concurrent_repair() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dnsserver.json");
    std::fs::write(&path, b"corrupt").unwrap();
    let app = crate::http::router(state(&dir));
    let damaged = request(&app, "/api/dnsserver", None, 200).await;
    assert_eq!(damaged["config_hash"], "");
    assert!(!damaged["config_error"].as_str().unwrap().is_empty());
    assert_eq!(damaged["last_error"], damaged["config_error"]);
    assert!(damaged.get("config_warning").is_none());
    request(&app, "/api/dnsserver/stop", Some(json!({})), 409).await;
    assert_eq!(std::fs::read(&path).unwrap(), b"corrupt");
    let mut cfg = config::defaults();
    cfg["listen_host"] = json!("127.0.0.1");
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    cfg["dns_port"] = json!(socket.local_addr().unwrap().port());
    drop(socket);
    let doc = json!({"format":"nfqws2-strategy-dnsserver","version":1,"exported_at":"2026-01-03T14:22:05Z","config":cfg});
    let preview = request(
        &app,
        "/api/dnsserver/import/preview",
        Some(json!({"document":doc})),
        200,
    )
    .await;
    cfg["cache_size"] = json!(56);
    std::fs::write(&path, cfg.to_string()).unwrap();
    request(
        &app,
        "/api/dnsserver/import",
        Some(json!({"document":doc,"base_hash":preview["base_hash"]})),
        409,
    )
    .await;
    let latest = request(&app, "/api/dnsserver", None, 200).await;
    assert_eq!(latest["config_error"], "");
    assert_eq!(latest["config_hash"].as_str().unwrap().len(), 64);
    assert!(latest.get("config_warning").is_none());
    assert_eq!(latest["config"]["cache_size"], 56);

    let damaged_dir = tempfile::tempdir().unwrap();
    std::fs::write(damaged_dir.path().join("dnsserver.json"), b"corrupt").unwrap();
    let app = crate::http::router(state(&damaged_dir));
    let imported = request(
        &app,
        "/api/dnsserver/import",
        Some(json!({"document":doc,"base_hash":preview["base_hash"]})),
        200,
    )
    .await;
    assert_eq!(imported["config_error"], "");
    assert_eq!(
        imported["config_warning"],
        "Сохранённые настройки DNS заменены проверенным импортом"
    );
    assert_eq!(imported["config_hash"].as_str().unwrap().len(), 64);
}

#[tokio::test]
async fn stale_form_corruption_and_port_conflict_preserve_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let occupied = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = occupied.local_addr().unwrap();
    let mut initial = config::defaults();
    initial["dns_port"] = json!(addr.port());
    initial["listen_host"] = json!("127.0.0.1");
    let file = dir.path().join("dnsserver.json");
    std::fs::write(&file, initial.to_string()).unwrap();
    let shared = state(&dir);
    let app = crate::http::router(shared);
    let st = request(&app, "/api/dnsserver", None, 200).await;
    assert_eq!(st["running"], false);
    request(
        &app,
        "/api/dnsserver/config",
        Some(json!({"base_hash":"old","enabled":true})),
        409,
    )
    .await;
    request(&app, "/api/dnsserver/start", Some(json!({})), 400).await;
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(file).unwrap()).unwrap(),
        initial
    );
    let _tcp = TcpListener::bind(addr)
        .await
        .expect("partial bind released");
    let oldhash = st["config_hash"].clone();
    request(
        &app,
        "/api/dnsserver/logging",
        Some(json!({"enabled":false})),
        200,
    )
    .await;
    let st = request(
        &app,
        "/api/dnsserver/config",
        Some(json!({"base_hash":oldhash,"cache_size":177,"dns_port":53})),
        200,
    )
    .await;
    assert_eq!(st["config"]["dns_port"], addr.port());
    assert_eq!(st["config"]["logging_enabled"], false);
    let bad = tempfile::tempdir().unwrap();
    std::fs::write(bad.path().join("dnsserver.json"), b"{invalid").unwrap();
    let app = crate::http::router(state(&bad));
    let st = request(&app, "/api/dnsserver", None, 200).await;
    assert!(!st["config_error"].as_str().unwrap().is_empty());
    request(&app, "/api/dnsserver/stop", Some(json!({})), 409).await;
    assert_eq!(
        std::fs::read(bad.path().join("dnsserver.json")).unwrap(),
        b"{invalid"
    );
}
async fn local_doh() -> LocalDoh {
    local_doh_protocol(false).await
}
type LocalDoh = (
    u16,
    tokio_rustls::rustls::pki_types::CertificateDer<'static>,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
);

async fn local_doh_protocol(h2: bool) -> LocalDoh {
    controlled_doh(h2, None).await
}

pub(super) struct DohGate {
    seen: tokio::sync::Semaphore,
    reply: tokio::sync::Semaphore,
}

impl DohGate {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            seen: tokio::sync::Semaphore::new(0),
            reply: tokio::sync::Semaphore::new(0),
        })
    }

    pub(super) async fn next_request(&self) {
        timeout(Duration::from_secs(3), self.seen.acquire())
            .await
            .expect("DNS upstream did not receive the request")
            .unwrap()
            .forget();
    }

    pub(super) fn release(&self, replies: usize) {
        self.reply.add_permits(replies);
    }
}

pub(super) async fn controlled_doh(h2: bool, gate: Option<Arc<DohGate>>) -> LocalDoh {
    scripted_doh(h2, gate, |wire, name, kind| {
        wire[2] = 0x81;
        wire[3] = 0x80;
        wire[7] = 1;
        if kind == 28 {
            wire.extend([192, 12, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
            wire.extend(
                "2001:db8::18"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets(),
            );
        } else {
            wire.extend([192, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
            wire.extend(if name == "dns.test" {
                [127, 0, 0, 1]
            } else {
                [192, 0, 2, 18]
            });
        }
    })
    .await
}

pub(super) async fn scripted_doh(
    h2: bool,
    gate: Option<Arc<DohGate>>,
    response: impl Fn(&mut Vec<u8>, &str, u16) + Send + Sync + 'static,
) -> LocalDoh {
    let doh = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let key =
        rcgen::generate_simple_self_signed(vec!["dns.test".into(), "127.0.0.1".into()]).unwrap();
    serve_doh(doh, &key, h2, gate, "/dns-query", response)
}

fn serve_doh(
    doh: TcpListener,
    key: &rcgen::CertifiedKey<rcgen::KeyPair>,
    h2: bool,
    gate: Option<Arc<DohGate>>,
    path: &'static str,
    response: impl Fn(&mut Vec<u8>, &str, u16) + Send + Sync + 'static,
) -> LocalDoh {
    serve_doh_by_question(doh, key, h2, move |_, _, _| gate.clone(), path, response)
}

fn serve_doh_by_question(
    doh: TcpListener,
    key: &rcgen::CertifiedKey<rcgen::KeyPair>,
    h2: bool,
    gate: impl Fn(&[u8], &str, u16) -> Option<Arc<DohGate>> + Send + Sync + 'static,
    path: &'static str,
    response: impl Fn(&mut Vec<u8>, &str, u16) + Send + Sync + 'static,
) -> LocalDoh {
    let port = doh.local_addr().unwrap().port();
    let cert = key.cert.der().clone();
    let mut tls = ServerConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.clone()],
        PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()).into(),
    )
    .unwrap();
    if h2 {
        tls.alpn_protocols = vec![b"h2".to_vec()];
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let gate = Arc::new(gate);
    let response = Arc::new(response);
    let server = tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        loop {
            let (socket, _) = doh.accept().await.unwrap();
            let tls = acceptor.clone();
            let calls = count.clone();
            let gate = gate.clone();
            let response = response.clone();
            tokio::spawn(async move {
                let Ok(socket) = tls.accept(socket).await else {
                    return;
                };
                let service = service_fn(move |q: Request<hyper::body::Incoming>| {
                    let calls = calls.clone();
                    let gate = gate.clone();
                    let response = response.clone();
                    async move {
                        assert_eq!(q.method(), "POST");
                        assert_eq!(q.uri().path_and_query().unwrap().as_str(), path);
                        assert_eq!(
                            q.version(),
                            if h2 {
                                axum::http::Version::HTTP_2
                            } else {
                                axum::http::Version::HTTP_11
                            }
                        );
                        assert_eq!(q.headers()["content-type"], "application/dns-message");
                        let mut wire = q.collect().await.unwrap().to_bytes().to_vec();
                        let (name, kind) = nfqws2_dns::query_domain(&wire).unwrap();
                        if kind != 2 {
                            calls.fetch_add(1, Ordering::SeqCst);
                        }
                        if let Some(gate) = gate(&wire, &name, kind) {
                            gate.seen.add_permits(1);
                            gate.reply.acquire().await.unwrap().forget();
                        }
                        response(&mut wire, &name, kind);
                        Ok::<_, Infallible>(
                            Response::builder()
                                .header("content-type", "application/dns-message")
                                .body(Full::new(Bytes::from(wire)))
                                .unwrap(),
                        )
                    }
                });
                if h2 {
                    let _ = hyper::server::conn::http2::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(TokioIo::new(socket), service)
                    .await;
                } else {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(socket), service)
                        .await;
                }
            });
        }
    });
    (port, cert, calls, server)
}

#[tokio::test]
async fn dns_shares_an_active_request_and_cache_clear_starts_a_new_generation() {
    let gate = DohGate::new();
    let (port, cert, calls, server) = controlled_doh(true, Some(gate.clone())).await;
    let mut raw = config::defaults();
    raw["scheduler_enabled"] = json!(false);
    raw["awg_fallback"] = json!("off");
    raw["rules"] = json!([]);
    raw["default_pool"] = json!([]);
    raw["filtering"]["enabled"] = json!(false);
    raw["cache_size"] = json!(64);
    raw["default_upstream"] = json!({"address":format!("https://dns.test:{port}/dns-query"),"bootstrap_ips":["127.0.0.1"]});
    let diag = Arc::new(Mutex::new(Diagnostics::new(true)));
    let engine = Engine::new(
        Config::from_value(&raw).unwrap(),
        diag.clone(),
        Default::default(),
        shadow::Environment::unavailable(),
        Arc::new(vpn::Source::with(|| Ok(Vec::new()))),
        Default::default(),
    );
    engine.trust(cert);
    let start = |name: &'static str, id| {
        let engine = engine.clone();
        tokio::spawn(async move {
            let wire = nfqws2_dns::build_query(name, 1, id).unwrap();
            engine.exchange(&wire, "test", "udp", None).await.unwrap()
        })
    };

    let leader = start("burst.example", 1);
    gate.next_request().await;
    let second = nfqws2_dns::build_query("bUrSt.example", 1, 2).unwrap();
    let mut follower = std::pin::pin!(engine.exchange(&second, "test", "tcp", None));
    let pending = std::future::poll_fn(|cx| {
        std::task::Poll::Ready(std::future::Future::poll(follower.as_mut(), cx).is_pending())
    })
    .await;
    assert!(pending);
    leader.abort();
    assert!(matches!(leader.await, Err(error) if error.is_cancelled()));
    gate.reply.add_permits(1);
    let answer = timeout(Duration::from_secs(3), follower)
        .await
        .unwrap()
        .unwrap();
    assert!(answer.shared && !answer.answer.cached);
    assert_eq!(&answer.answer.wire[..2], &second[..2]);
    assert_eq!(&answer.answer.wire[12..second.len()], &second[12..]);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let cached = engine.exchange(&second, "test", "udp", None).await.unwrap();
    assert!(cached.answer.cached && !cached.shared);
    assert_eq!(cached.route, answer.route);
    assert_eq!(cached.upstream, answer.upstream);
    {
        let stats = engine.stats();
        assert_eq!(stats.shared_responses, 1);
        assert_eq!(stats.cache_hits, 1);
        assert_eq!(
            diag.lock().unwrap().logs(0)["entries"][0]["event"],
            "shared"
        );
    }

    let before = start("clear.example", 3);
    gate.next_request().await;
    assert_eq!(engine.cache.clear(), 1);
    let after = start("clear.example", 4);
    gate.next_request().await;
    gate.reply.add_permits(1);
    let before = timeout(Duration::from_secs(3), before)
        .await
        .unwrap()
        .unwrap();
    assert!(!before.shared);
    assert_eq!(engine.cache.status().entries, 0);
    gate.reply.add_permits(1);
    let after = timeout(Duration::from_secs(3), after)
        .await
        .unwrap()
        .unwrap();
    assert!(!after.shared);
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(engine.cache.status().entries, 1);

    let abandoned = start("abandoned.example", 5);
    gate.next_request().await;
    abandoned.abort();
    assert!(matches!(abandoned.await, Err(error) if error.is_cancelled()));
    let next = start("abandoned.example", 6);
    gate.next_request().await;
    gate.reply.add_permits(2);
    assert!(
        !timeout(Duration::from_secs(3), next)
            .await
            .unwrap()
            .unwrap()
            .shared
    );
    assert_eq!(calls.load(Ordering::SeqCst), 5);
    server.abort();
}
#[tokio::test]
async fn route_snapshot_uses_the_configured_listener_and_respects_dns_filtering() {
    use nfqws2_awg_rules::kernel::Operation;
    let (port, cert, calls, server) = local_doh().await;
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = config::defaults();
    config["listen_host"] = json!("127.0.0.1");
    config["dns_port"] = json!(listener.local_addr().unwrap().port());
    drop(listener);
    config["default_upstream"] = json!({"address":format!("https://dns.test:{port}/dns-query"),"bootstrap_ips":["127.0.0.1"]});
    config["default_pool"] = json!([]);
    config["rules"] = json!([]);
    config["filtering"] = json!({"enabled":true,"lists":[],"custom_rules":[{"domain":"blocked.example","category":"ads"}],"allowlist":[]});
    std::fs::write(dir.path().join("dnsserver.json"), config.to_string()).unwrap();
    let shared = state(&dir);
    let app = crate::http::router(shared.clone());
    request(&app, "/api/dnsserver/start", Some(json!({})), 200).await;
    shared
        .dnsserver
        .state
        .lock()
        .await
        .active
        .as_ref()
        .unwrap()
        .engine()
        .trust(cert);
    for (name, allowed) in [("office.example", true), ("blocked.example", false)] {
        let zone = json!({"enabled":true,"name":"office","tunnel_id":"awg0","domains":[name],"include_subdomains":false});
        let config = json!({"mode":"zones","domain_source":"resolve","zones":[zone]});
        request(&app, "/api/awg2/routing/config", Some(config), 200).await;
        let clone = shared.clone();
        let snapshot = tokio::task::spawn_blocking(move || {
            crate::awg_rules::kernel::snapshot(&clone, Operation::Apply)
        })
        .await
        .unwrap();
        if allowed {
            assert_eq!(
                snapshot.unwrap().unwrap().answers[name],
                [std::net::Ipv4Addr::new(192, 0, 2, 18)]
            );
        } else {
            assert!(snapshot.unwrap_err().to_string().contains(name));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
    shared.dnsserver.shutdown().await;
    server.abort();
}

#[tokio::test]
async fn failed_manual_exact_dns_apply_uses_fresh_managed_answers_with_ephemeral_authority() {
    use crate::awg_rules::kernel::{prepare_failed_apply_for_test, publish_failed_dns_for_test};
    use nfqws2_awg_rules::{kernel::Operation, observed::Policy};
    use std::sync::atomic::AtomicBool;

    const NAME: &str = "first.office.test";
    let fresh = Arc::new(AtomicBool::new(false));
    let switched = fresh.clone();
    let (port, cert, calls, upstream) = scripted_doh(true, None, move |wire, name, kind| {
        assert_eq!(kind, 1);
        wire[2] = 0x81;
        wire[3] = 0x80;
        wire[7] = 1;
        if name == NAME && switched.load(Ordering::SeqCst) {
            let alias = nfqws2_dns::build_query("edge.office.test", 1, 0).unwrap();
            let alias = &alias[12..alias.len() - 4];
            wire.extend([192, 12, 0, 5, 0, 1, 0, 0, 0, 7]);
            wire.extend((alias.len() as u16).to_be_bytes());
            wire.extend(alias);
        } else {
            let ttl = match name {
                "expired.office.test" => 0,
                "short.office.test" => 1,
                _ => 45,
            };
            let octet = if name == NAME { 10 } else { 18 };
            wire.extend([192, 12, 0, 1, 0, 1, 0, 0, 0, ttl, 0, 4, 192, 0, 2, octet]);
        }
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let mut config = config::defaults();
    config["listen_host"] = json!("127.0.0.1");
    config["dns_port"] = json!(addr.port());
    config["scheduler_enabled"] = json!(false);
    config["fast_dns"] = json!(false);
    config["awg_fallback"] = json!("off");
    config["cache_size"] = json!(32);
    config["default_upstream"] =
        json!({"address":"https://127.0.0.1:1/dns-query","bootstrap_ips":["127.0.0.1"]});
    config["default_pool"] = json!([]);
    config["rules"] = json!([{"enabled":true,"domain":"office.test","include_subdomains":true,
        "upstream":{"address":format!("https://dns.test:{port}/dns-query"),"bootstrap_ips":["127.0.0.1"]}}]);
    config["filtering"] = json!({"enabled":true,"lists":[],"custom_rules":[{"domain":"blocked.office.test","category":"ads"}],"allowlist":[]});
    std::fs::write(dir.path().join("dnsserver.json"), config.to_string()).unwrap();
    let shared = state(&dir);
    let app = crate::http::router(shared.clone());
    request(&app, "/api/dnsserver/start", Some(json!({})), 200).await;
    let running = shared
        .dnsserver
        .state
        .lock()
        .await
        .active
        .as_ref()
        .unwrap()
        .engine();
    running.trust(cert);

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = nfqws2_dns::build_query(NAME, 1, 4).unwrap();
    let ask = || async {
        client.send_to(&query, addr).await.unwrap();
        let mut buf = [0; 512];
        let (length, _) = timeout(Duration::from_secs(3), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        buf[..length].to_vec()
    };
    assert_eq!(
        nfqws2_dns::route_answer(&ask().await)
            .unwrap()
            .unwrap()
            .addresses,
        ["192.0.2.10".parse::<std::net::IpAddr>().unwrap()]
    );
    let failure = || {
        let old =
            serde_json::from_value(json!({"mode":"zones","domain_source":"dnsproxy","zones":[
                {"enabled":true,"domains":["*.office.test"]}
            ]}))
            .unwrap();
        publish_failed_dns_for_test(&shared, Policy::compile(&old).unwrap()).unwrap();
    };
    failure();
    fresh.store(true, Ordering::SeqCst);
    assert_eq!(ask().await, nfqws2_dns::response_error(&query, 2));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let draft = |names: &[&str]| {
        request(
            &app,
            "/api/awg2/routing/config",
            Some(json!({
                "mode":"zones","domain_source":"resolve","zones":[{
                    "enabled":true,"name":"office","tunnel_id":"awg0","domains":names,"include_subdomains":false
                }]
            })),
            200,
        )
    };
    let names = [
        NAME,
        "second.office.test",
        "third.office.test",
        "fourth.office.test",
    ];
    draft(names.as_slice()).await;
    let clone = shared.clone();
    assert!(
        tokio::task::spawn_blocking(move || crate::awg_rules::kernel::snapshot(
            &clone,
            Operation::Apply
        ))
        .await
        .unwrap()
        .is_err()
    );
    let prepare = || {
        let clone = shared.clone();
        tokio::task::spawn_blocking(move || prepare_failed_apply_for_test(&clone))
    };
    let start = Instant::now();
    let before = running.stats().queries;
    let lookups_before = calls.load(Ordering::SeqCst);
    let cache_before = running.cache.status().entries;
    let (snapshot, expiry, proof) = prepare().await.unwrap().unwrap();
    assert_eq!(snapshot.answers.len(), 4);
    for host in names {
        assert_eq!(
            snapshot.answers[host],
            ["192.0.2.18".parse::<std::net::IpAddr>().unwrap()]
        );
    }
    assert!(expiry >= start + Duration::from_secs(7));
    assert!(expiry <= Instant::now() + Duration::from_secs(7));
    assert_eq!(calls.load(Ordering::SeqCst) - lookups_before, 5);
    assert_eq!(running.cache.status().entries, cache_before);
    assert_eq!(running.stats().queries, before);
    proof(&shared).unwrap();
    failure();
    assert_eq!(
        proof(&shared).unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );

    for (host, kind) in [
        ("blocked.office.test", io::ErrorKind::PermissionDenied),
        ("expired.office.test", io::ErrorKind::InvalidData),
    ] {
        draft(&[host]).await;
        let error = prepare()
            .await
            .unwrap()
            .err()
            .expect("unusable answer must not seed a route");
        assert_eq!(error.kind(), kind);
    }
    draft(&["short.office.test"]).await;
    let (_, expiry, expired) = prepare().await.unwrap().unwrap();
    tokio::time::sleep_until(expiry.into()).await;
    assert_eq!(
        expired(&shared).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    draft(&[NAME]).await;
    let (_, _, replaced) = prepare().await.unwrap().unwrap();
    running.stopped.send_replace(true);
    assert_eq!(
        replaced(&shared).unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    shared.dnsserver.shutdown().await;
    upstream.abort();
}

#[tokio::test]
async fn managed_archive_dns_uses_named_vpn_pool_filters_and_shared_slots_without_client_stats() {
    struct NoClient;
    impl RouteObserver for NoClient {
        fn select(&self, _: &str, _: Option<std::net::IpAddr>) -> io::Result<Option<RouteMatch>> {
            panic!("archive resolver attempted client route observation")
        }

        fn install(
            &self,
            _: RouteMatch,
            _: &str,
            _: DnsOrigin<'_>,
            _: &RouteAnswer,
        ) -> io::Result<(bool, u64)> {
            panic!("archive resolver attempted to install a client route")
        }
    }

    let (port, cert, calls, server) = local_doh().await;
    let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://dns.test:{port}/dns-query");
    let mut raw = config::defaults();
    raw["route_mode"] = json!("vpn_only");
    raw["awg_fallback"] = json!("main");
    raw["scheduler_enabled"] = json!(false);
    raw["fast_dns"] = json!(false);
    raw["default_pool"] = json!([]);
    raw["default_upstream"] = json!({"address":format!("https://127.0.0.1:{}/dns-query", unused.local_addr().unwrap().port())});
    raw["rules"] = json!([{"enabled":true,"domain":"archive.test","include_subdomains":true,"upstream":{"address":url,"bootstrap_ips":["127.0.0.1"]}}]);
    raw["filtering"] = json!({"enabled":true,"lists":[],"allowlist":["allowed.archive.test"],"custom_rules":[
        {"domain":"blocked.archive.test","category":"ads"}, {"domain":"192.0.2.18","category":"ads"}
    ]});
    raw["shadow_dns"] =
        json!({"enabled":true,"domains":[{"domain":"allowed.archive.test"}],"servers":[]});
    let schedule = Arc::new(scheduler::Schedule::default());
    let observer = Arc::new(routing::Observer::default());
    observer.register(Arc::new(NoClient));
    let engine = Engine::new(
        Config::from_value(&raw).unwrap(),
        Arc::new(Mutex::new(Diagnostics::new(true))),
        schedule.clone(),
        shadow::Environment::unavailable(),
        Arc::new(vpn::Source::with(|| Ok(vec![loopback_route("main")]))),
        observer,
    );
    engine.trust(cert);
    let q = |name| nfqws2_dns::build_query(name, 1, 4).unwrap();
    assert!(engine
        .archive_reply(&q("blocked.archive.test"))
        .await
        .unwrap()
        .is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(engine
        .archive_reply(&q("target.archive.test"))
        .await
        .unwrap()
        .is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // Archive lookups use the ordinary physical slot even with no client origin.
    let busy = schedule
        .slots
        .acquire_many(scheduler::LIMIT as u32)
        .await
        .unwrap();
    let owner = engine.clone();
    let allowed = q("allowed.archive.test");
    let job = tokio::spawn(async move { owner.archive_reply(&allowed).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(!job.is_finished());
    drop(busy);
    let reply = timeout(Duration::from_secs(3), job)
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .unwrap();
    let route = nfqws2_dns::route_answer(&reply).unwrap().unwrap();
    assert_eq!(route.addresses, [std::net::IpAddr::from([192, 0, 2, 18])]);
    // Explicit Shadow is attempted and its unavailable-provider fallback shares the live 30s cap.
    assert_eq!(route.ttl, 30);
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    engine
        .methods
        .apply(std::collections::HashSet::from([scheduler::key(
            "awg:main", &url,
        )]));
    assert!(engine
        .archive_reply(&q("allowed.archive.test"))
        .await
        .is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(timeout(Duration::from_millis(50), unused.accept())
        .await
        .is_err());
    assert_eq!(engine.stats().queries, 0);
    assert_eq!(engine.cache.status().entries, 0);
    server.abort();
}

#[tokio::test]
async fn cached_answers_observe_each_client_before_delivery_and_retry_after_route_failure() {
    use std::net::IpAddr;
    use std::sync::atomic::AtomicBool;
    struct Observer {
        calls: AtomicUsize,
        fail: AtomicBool,
        retire: AtomicBool,
        generation: AtomicUsize,
    }
    impl RouteObserver for Observer {
        fn select(&self, name: &str, client: Option<IpAddr>) -> io::Result<Option<RouteMatch>> {
            assert_ne!(name, "blocked.test", "routing received a filtered answer");
            let target = client.filter(|v| v.is_loopback()).map(|_| RouteMatch {
                revision: self.generation.load(Ordering::SeqCst) as u64,
                generation: 1,
                zone: 0,
            });
            Ok(target)
        }
        fn install(
            &self,
            target: RouteMatch,
            _: &str,
            _: DnsOrigin<'_>,
            answer: &RouteAnswer,
        ) -> io::Result<(bool, u64)> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail.swap(false, Ordering::SeqCst) {
                return Err(io::Error::other("test: route unavailable"));
            }
            let installed = self.generation.fetch_add(1, Ordering::SeqCst) as u64 + 1;
            // Retiring the policy independently leaves this write's original
            // receipt stale. A successful FIB replacement returns its new epoch.
            let revision = if self.retire.swap(false, Ordering::SeqCst) {
                target.revision
            } else {
                installed
            };
            assert!(!answer.addresses.is_empty());
            Ok((answer.qtype == 28, revision))
        }
    }
    let (port, cert, upstream, server) = local_doh().await;
    let observer = Arc::new(Observer {
        calls: Default::default(),
        fail: AtomicBool::new(true),
        retire: Default::default(),
        generation: Default::default(),
    });
    let dir = tempfile::tempdir().unwrap();
    let mut config = config::defaults();
    let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = reserved.local_addr().unwrap();
    drop(reserved);
    config["listen_host"] = json!("127.0.0.1");
    config["dns_port"] = json!(addr.port());
    config["default_upstream"] = json!({"address":format!("https://dns.test:{port}/dns-query"),"bootstrap_ips":["127.0.0.1"]});
    config["default_pool"] = json!([]);
    config["rules"] = json!([]);
    config["filtering"] = json!({"enabled":true,"lists":[],"custom_rules":[{"domain":"blocked.test","category":"ads"}],"allowlist":[]});
    std::fs::write(dir.path().join("dnsserver.json"), config.to_string()).unwrap();
    let shared = state(&dir);
    shared.dnsserver.set_route_observer(observer.clone());
    let app = crate::http::router(shared.clone());
    request(&app, "/api/dnsserver/start", Some(json!({})), 200).await;
    let engine = shared
        .dnsserver
        .state
        .lock()
        .await
        .active
        .as_ref()
        .unwrap()
        .engine();
    engine.trust(cert);
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.connect(addr).await.unwrap();
    let query = |kind| nfqws2_dns::build_query("office.test", kind, 97).unwrap();
    let ask = |wire: Vec<u8>| {
        let sock = &udp;
        async move {
            sock.send(&wire).await.unwrap();
            let mut buf = vec![0; 512];
            let n = timeout(Duration::from_secs(5), sock.recv(&mut buf))
                .await
                .unwrap()
                .unwrap();
            buf.truncate(n);
            buf
        }
    };
    assert_eq!(ask(query(1)).await[3] & 15, 2);
    let retry = ask(query(1)).await;
    assert_eq!(retry[3] & 15, 0);
    assert_eq!(retry[7], 1);
    observer.retire.store(true, Ordering::SeqCst);
    assert_eq!(
        ask(query(1)).await[3] & 15,
        2,
        "changed policy released an old answer"
    );
    let nodata = ask(query(28)).await;
    assert_eq!(nodata, nfqws2_dns::response_error(&query(28), 0));
    let other = engine
        .exchange(
            &query(28),
            "client",
            "tcp",
            Some("192.0.2.3".parse().unwrap()),
        )
        .await
        .unwrap();
    assert!(other.answer.cached);
    assert_eq!(
        nfqws2_dns::resolved_addresses(&other.answer.wire, 28).unwrap(),
        ["2001:db8::18".parse::<IpAddr>().unwrap()]
    );
    let blocked = ask(nfqws2_dns::build_query("blocked.test", 1, 98).unwrap()).await;
    assert_eq!(blocked[3] & 15, 3);
    assert_eq!(upstream.load(Ordering::SeqCst), 2);
    assert_eq!(observer.calls.load(Ordering::SeqCst), 4);
    shared.dnsserver.shutdown().await;
    server.abort();
}
#[tokio::test]
async fn trusted_doh_serves_udp_tcp_and_panel_with_isolated_pools_and_live_cache() {
    let (port, cert, calls, server) = local_doh().await;
    let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = reserved.local_addr().unwrap();
    drop(reserved);
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config::defaults();
    cfg["listen_host"] = json!("127.0.0.1");
    cfg["dns_port"] = json!(addr.port());
    cfg["default_upstream"] = json!({"address":format!("https://dns.test:{port}/dns-query"),"bootstrap_ips":["127.0.0.1"]});
    cfg["default_pool"] = json!([{"address":format!("https://untrusted.test:{port}/dns-query"),"bootstrap_ips":["127.0.0.1"]}]);
    cfg["filtering"] = json!({"enabled":true,"lists":[],"custom_rules":[{"domain":"blocked.example","category":"ads"}],"allowlist":["allow.blocked.example"]});
    cfg["shadow_dns"] = json!({"enabled":true,"domains":[{"domain":"isp.example","include_subdomains":true}],"servers":[]});
    cfg["rules"] = json!([{"enabled":true,"domain":"private.test","include_subdomains":true,"upstream":{"address":format!("https://untrusted.test:{port}/dns-query"),"bootstrap_ips":["127.0.0.1"]}}]);
    std::fs::write(dir.path().join("dnsserver.json"), cfg.to_string()).unwrap();
    let mut shared = state(&dir);
    Arc::get_mut(&mut shared).unwrap().dnsserver.isp = shadow::Environment::unavailable();
    let app = crate::http::router(shared.clone());
    let st = request(&app, "/api/dnsserver/start", Some(json!({})), 200).await;
    assert_eq!(st["endpoints"]["dns"], addr.to_string());
    shared
        .dnsserver
        .state
        .lock()
        .await
        .active
        .as_ref()
        .unwrap()
        .engine()
        .trust(cert);
    let q = nfqws2_dns::build_query("home.example", 1, 12).unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.connect(addr).await.unwrap();
    udp.send(&q).await.unwrap();
    let mut wire = [0; 512];
    let size = timeout(Duration::from_secs(8), udp.recv(&mut wire))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        nfqws2_dns::first_ipv4(&wire[..size]).unwrap().to_string(),
        "192.0.2.18"
    );
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    let mut q = nfqws2_dns::build_query("HOME.example", 1, 90).unwrap();
    for id in [90u16, 91] {
        q[..2].copy_from_slice(&id.to_be_bytes());
        tcp.write_u16(q.len() as u16).await.unwrap();
        tcp.write_all(&q).await.unwrap();
    }
    for id in [90u16, 91] {
        let size = timeout(Duration::from_secs(8), tcp.read_u16())
            .await
            .unwrap()
            .unwrap() as usize;
        tcp.read_exact(&mut wire[..size]).await.unwrap();
        assert_eq!(&wire[..2], &id.to_be_bytes());
        assert_eq!(&wire[12..q.len()], &q[12..]);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let st = request(
        &app,
        "/api/dnsserver/test",
        Some(json!({"domain":"home.example","type":"A"})),
        200,
    )
    .await;
    assert_eq!(st["ok"], true);
    assert_eq!(st["cached"], true);
    assert!(st["answers"][0].as_str().unwrap().contains("192.0.2.18"));
    let st = request(
        &app,
        "/api/dnsserver/test",
        Some(json!({"domain":"child.private.test"})),
        200,
    )
    .await;
    assert_eq!(st["ok"], false);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "wrong TLS name cannot reach either HTTP endpoint"
    );
    let st = request(&app, "/api/dnsserver", None, 200).await;
    assert_eq!(st["cache"]["entries"], 1);
    assert_eq!(st["stats"]["cache_hits"], 3);
    assert_eq!(st["stats"]["failures"], 1);
    let st = request(&app, "/api/dnsserver/logs", None, 200).await;
    let entries = st["entries"].as_array().unwrap();
    let final_events: Vec<_> = entries
        .iter()
        .filter_map(|entry| entry["event"].as_str())
        .filter(|kind| !matches!(*kind, "attempt_error" | "canceled"))
        .collect();
    assert_eq!(
        final_events,
        ["start", "answer", "cache", "cache", "cache", "error"]
    );
    assert!(entries.iter().any(|entry| {
        entry["event"] == "attempt_error"
            && entry["domain"] == "child.private.test"
            && entry["source"] == "diagnostic"
    }));
    let st = request(
        &app,
        "/api/dnsserver/test",
        Some(json!({"domain":"sub.blocked.example"})),
        200,
    )
    .await;
    assert_eq!(st["blocked"], true);
    assert_eq!(st["route"], "blocked");
    assert_eq!(st["block_rule"], "blocked.example");
    assert_eq!(st["answers"], json!([]));
    let st = request(
        &app,
        "/api/dnsserver/filtering/update",
        Some(json!({})),
        200,
    )
    .await;
    assert_eq!(st["stats"]["blocked_ads"], 1);
    assert_eq!(st["filtering"]["ready"], true);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let st = request(&app, "/api/dnsserver/scheduler", None, 200).await;
    assert_eq!(st["effective"], true);
    assert_eq!(
        st["candidates"][0]["upstream"],
        cfg["default_upstream"]["address"]
    );
    assert!(st["candidates"][0]["successes"].as_u64().unwrap() >= 1);
    let st = request(
        &app,
        "/api/dnsserver/scheduler?domain=child.private.test",
        None,
        200,
    )
    .await;
    assert_eq!(st["reason"], "single_candidate");
    assert_eq!(st["pool_source"], "private.test");
    request(
        &app,
        "/api/dnsserver/shadow/diagnostics",
        Some(json!({"enabled":true})),
        200,
    )
    .await;
    let st = request(
        &app,
        "/api/dnsserver/scheduler?domain=up.isp.example",
        None,
        200,
    )
    .await;
    assert_eq!(st["reason"], "shadow");
    assert_eq!(st["candidates"], json!([]));
    let st = request(
        &app,
        "/api/dnsserver/test",
        Some(json!({"domain":"up.isp.example"})),
        200,
    )
    .await;
    assert_eq!(st["ok"], true);
    assert_eq!(st["route"], "nfqws");
    assert!(
        st["answers"][0]
            .as_str()
            .unwrap()
            .split_ascii_whitespace()
            .nth(1)
            == Some("30")
    );
    let st = request(&app, "/api/dnsserver", None, 200).await;
    assert_eq!(st["shadow_dns"]["fallback_active"], true);
    assert_eq!(
        st["shadow_dns"]["diagnostics"]["attempts"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(!st["shadow_dns"]["diagnostics"]
        .to_string()
        .contains("up.isp.example"));
    for confirm in [false, true] {
        request(
            &app,
            "/api/dnsserver/shadow/renew",
            Some(json!({"confirm":confirm})),
            400,
        )
        .await;
    }
    for url in [
        &cfg["default_upstream"]["address"],
        &cfg["default_pool"][0]["address"],
    ] {
        request(
            &app,
            "/api/dnsserver/scheduler/method",
            Some(json!({"upstream":url,"route":"nfqws","enabled":false})),
            200,
        )
        .await;
    }
    let st = request(&app, "/api/dnsserver/scheduler", None, 200).await;
    assert_eq!(st["reason"], "no_candidates");
    let st = request(
        &app,
        "/api/dnsserver/test",
        Some(json!({"domain":"home.example"})),
        200,
    )
    .await;
    assert_eq!(st["cached"], true);
    let st = request(
        &app,
        "/api/dnsserver/test",
        Some(json!({"domain":"allow.blocked.example"})),
        200,
    )
    .await;
    assert_eq!(st["ok"], false);
    assert_ne!(st["blocked"], true);
    let url = &cfg["default_upstream"]["address"];
    request(
        &app,
        "/api/dnsserver/scheduler/method",
        Some(json!({"upstream":url,"route":"nfqws","enabled":true})),
        200,
    )
    .await;
    let st = request(
        &app,
        "/api/dnsserver/test",
        Some(json!({"domain":"allow.blocked.example"})),
        200,
    )
    .await;
    assert_eq!(st["ok"], true);
    assert_eq!(st["blocked"], false);
    let st = request(&app, "/api/dnsserver/cache/clear", Some(json!({})), 200).await;
    assert_eq!(st["cache"]["entries"], 0);
    let st = request(&app, "/api/dnsserver/stop", Some(json!({})), 200).await;
    assert_eq!(st["running"], false);
    assert!(TcpStream::connect(addr).await.is_err());
    server.abort();
    assert_eq!(
        state(&dir).dnsserver.status().await["config"]["enabled"],
        false
    );
}
#[tokio::test]
async fn changing_method_policy_cancels_an_active_handshake_and_timeout_reports_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "https://dns.test:{}/dns-query",
        listener.local_addr().unwrap().port()
    );
    let mut raw = config::defaults();
    raw["default_upstream"] = json!({"address":url,"bootstrap_ips":["127.0.0.1"]});
    raw["timeout_seconds"] = json!(1);
    raw["scheduler_enabled"] = json!(false);
    raw["fast_dns"] = json!(false);
    let cfg = Config::from_value(&raw).unwrap();
    let diag = Arc::new(Mutex::new(Diagnostics::new(true)));
    let engine = Engine::new(
        cfg,
        diag.clone(),
        Default::default(),
        Arc::new(shadow::Environment::new(vec![])),
        Arc::new(vpn::Source::with(|| Ok(vec![]))),
        Default::default(),
    );
    engine.trust(
        rcgen::generate_simple_self_signed(vec!["dns.test".into()])
            .unwrap()
            .cert
            .der()
            .clone(),
    );
    let engine2 = engine.clone();
    let pending = tokio::spawn(async move {
        engine2
            .exchange(
                &nfqws2_dns::build_query("home.test", 1, 88).unwrap(),
                "client",
                "udp",
                None,
            )
            .await
    });
    let (_socket, _) = timeout(Duration::from_secs(2), listener.accept())
        .await
        .unwrap()
        .unwrap();
    engine.methods.apply(std::collections::HashSet::from([url]));
    engine.methods.apply(Default::default());
    let outcome = timeout(Duration::from_secs(1), pending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(outcome.err().unwrap().kind(), io::ErrorKind::Interrupted);
    let query = nfqws2_dns::build_query("home.test", 1, 89).unwrap();
    let outcome = engine.exchange(&query, "client", "udp", None).await;
    assert_eq!(outcome.err().unwrap().kind(), io::ErrorKind::TimedOut);
    let log = diag.lock().unwrap().logs(0);
    let entries = log["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 4);
    assert_eq!(entries[0]["event"], "canceled");
    assert_eq!(entries[0]["count"], 1);
    assert_eq!(entries[1]["event"], "error");
    assert_eq!(entries[2]["event"], "attempt_error");
    assert_eq!(entries[3]["event"], "error");
}
#[tokio::test]
async fn dns_race_counts_only_dispatched_cancellations_after_returning_slots() {
    let losing = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let queued = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gate = DohGate::new();
    let (port, cert, _, server) = controlled_doh(false, Some(gate.clone())).await;
    let mut raw = config::defaults();
    raw["scheduler_enabled"] = json!(false);
    raw["fast_dns"] = json!(false);
    raw["rules"] = json!([]);
    raw["default_upstream"] = json!({"address":format!("https://127.0.0.1:{port}/dns-query")});
    raw["default_pool"] = json!([
        {"address":format!("https://{}/dns-query", losing.local_addr().unwrap())},
        {"address":format!("https://{}/dns-query", queued.local_addr().unwrap())},
    ]);
    let diag = Arc::new(Mutex::new(Diagnostics::new(true)));
    let schedule = Arc::new(scheduler::Schedule::default());
    let busy = schedule.slots.acquire_many(30).await.unwrap();
    let engine = Engine::new(
        Config::from_value(&raw).unwrap(),
        diag.clone(),
        schedule.clone(),
        shadow::Environment::unavailable(),
        Arc::new(vpn::Source::with(|| Ok(vec![]))),
        Default::default(),
    );
    engine.trust(cert);
    let pending = tokio::spawn(async move {
        let query = nfqws2_dns::build_query("queued.example", 28, 12).unwrap();
        engine
            .exchange(&query, "client", "tcp", Some("192.0.2.19".parse().unwrap()))
            .await
    });
    gate.next_request().await;
    let (_socket, _) = timeout(Duration::from_secs(2), losing.accept())
        .await
        .unwrap()
        .unwrap();
    gate.reply.add_permits(1);
    pending.await.unwrap().unwrap();
    assert_eq!(schedule.slots.available_permits(), 2);
    assert!(timeout(Duration::from_millis(20), queued.accept())
        .await
        .is_err());
    drop(busy);
    server.abort();

    let log = diag.lock().unwrap().logs(0);
    let entries = log["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["level"], "debug");
    assert_eq!(entries[0]["event"], "canceled");
    assert_eq!(entries[0]["domain"], "queued.example");
    assert_eq!(entries[0]["qtype"], "AAAA");
    assert_eq!(entries[0]["count"], 1);
    assert_eq!(entries[0]["source"], "client");
    assert_eq!(entries[0]["transport"], "tcp");
    assert_eq!(entries[0]["client_ip"], "192.0.2.19");
    assert_eq!(entries[1]["event"], "answer");
}

#[tokio::test]
async fn dns_race_journals_failed_provider_with_request_origin_before_winning() {
    let failure = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let failure_address = format!("https://127.0.0.1:{}", failure.local_addr().unwrap().port());
    let failure_task = tokio::spawn(async move {
        let (socket, _) = failure.accept().await.unwrap();
        drop(socket);
    });
    let gate = DohGate::new();
    let (port, cert, _, server) = controlled_doh(false, Some(gate.clone())).await;
    let mut raw = config::defaults();
    raw["scheduler_enabled"] = json!(false);
    raw["rules"] = json!([]);
    raw["default_upstream"] =
        json!({"address":format!("{failure_address}/private-fixture?token=value")});
    raw["default_pool"] = json!([{"address":format!("https://127.0.0.1:{port}/dns-query")}]);
    let diag = Arc::new(Mutex::new(Diagnostics::new(true)));
    let engine = Engine::new(
        Config::from_value(&raw).unwrap(),
        diag.clone(),
        Default::default(),
        shadow::Environment::unavailable(),
        Arc::new(vpn::Source::with(|| Ok(vec![]))),
        Default::default(),
    );
    engine.trust(cert);
    let client = "192.0.2.41".parse().unwrap();
    let wire = nfqws2_dns::build_query("race.example", 1, 71).unwrap();
    let pending = {
        let engine = engine.clone();
        let wire = wire.clone();
        tokio::spawn(async move { engine.exchange(&wire, "client", "udp", Some(client)).await })
    };
    gate.next_request().await;
    timeout(Duration::from_secs(3), async {
        loop {
            if diag.lock().unwrap().logs(0)["last_id"] == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("failed provider did not reach the DNS journal");
    gate.reply.add_permits(1);
    let result = pending.await.unwrap().unwrap();
    assert_eq!(
        result.upstream,
        format!("https://127.0.0.1:{port}/dns-query")
    );
    let cached = engine
        .exchange(&wire, "diagnostic", "api", None)
        .await
        .unwrap();
    assert!(cached.answer.cached);
    failure_task.await.unwrap();
    server.abort();

    let log = diag.lock().unwrap().logs(0);
    let entries = log["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0]["level"], "warn");
    assert_eq!(entries[0]["event"], "attempt_error");
    assert_eq!(entries[0]["domain"], "race.example");
    assert_eq!(entries[0]["qtype"], "A");
    assert_eq!(entries[0]["route"], "nfqws");
    assert_eq!(entries[0]["upstream"], format!("{failure_address}/…"));
    assert_eq!(entries[0]["source"], "client");
    assert_eq!(entries[0]["transport"], "udp");
    assert_eq!(entries[0]["client_ip"], client.to_string());
    assert!(entries[0]["duration_ms"].is_u64());
    assert_eq!(entries[1]["event"], "answer");
    assert_eq!(entries[2]["event"], "cache");
    assert!(!log.to_string().contains("private-fixture"));
    assert!(!log.to_string().contains("token=value"));
}

#[tokio::test]
async fn background_probe_uses_an_unmeasured_configured_provider_and_stops() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://dns.test:{}", listener.local_addr().unwrap().port());
    let mut raw = config::defaults();
    raw["rules"] = json!([]);
    raw["timeout_seconds"] = json!(1);
    raw["default_upstream"] =
        json!({"address":format!("{url}/private?token=fixture"),"bootstrap_ips":["127.0.0.1"]});
    raw["default_pool"] = json!([{"address":format!("{url}/b"),"bootstrap_ips":["127.0.0.1"]}]);
    let cfg = Config::from_value(&raw).unwrap();
    let history = Arc::new(scheduler::Schedule::default());
    let diagnostics = Arc::new(Mutex::new(Diagnostics::new(true)));
    let engine = Engine::new(
        cfg,
        diagnostics.clone(),
        history.clone(),
        Arc::new(shadow::Environment::new(vec![])),
        Arc::new(vpn::Source::with(|| Ok(vec![]))),
        Default::default(),
    );
    engine.trust(
        rcgen::generate_simple_self_signed(vec!["dns.test".into()])
            .unwrap()
            .cert
            .der()
            .clone(),
    );
    let (socket, _) = timeout(Duration::from_secs(8), listener.accept())
        .await
        .unwrap()
        .unwrap();
    drop(socket);
    timeout(Duration::from_secs(2), async {
        loop {
            let snapshot = history.snapshot(&engine.cfg, "", true, &[vpn::Route::system()]);
            if snapshot["candidates"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["probe_failures"] == 1)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        history.snapshot(&engine.cfg, "", true, &[vpn::Route::system()])["active_probes"],
        0
    );
    let diag = diagnostics.lock().unwrap();
    assert_eq!(engine.stats().queries, 0);
    let log = diag.logs(0);
    let rows = log["entries"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["level"], "warn");
    assert_eq!(rows[0]["event"], "attempt_error");
    assert_eq!(rows[0]["domain"], ".");
    assert_eq!(rows[0]["qtype"], "NS");
    assert_eq!(rows[0]["source"], "probe");
    assert_eq!(rows[0]["upstream"], format!("{url}/…"));
    assert_eq!(rows[0]["route"], "nfqws");
    assert!(rows[0]["message"]
        .as_str()
        .unwrap()
        .starts_with("Фоновая проверка: "));
    assert!(!log.to_string().contains("token=fixture"));
    drop(engine);
}
#[test]
fn existing_defaults_are_normalized_and_protected() {
    let base = config::defaults();
    assert_eq!(
        config::hash(&base),
        "7cde500be57cae6dc65a4e5eb8e67c659a40420a9758695ed513c166202582c1"
    );
    let cfg = Config::from_value(&base).unwrap();
    let mut legacy = base.clone();
    legacy["default_upstream"]["bootstrap_ips"] = Value::Null;
    legacy.as_object_mut().unwrap().remove("rules");
    assert!(Config::from_value(&legacy).unwrap().rules.is_empty());
    assert_eq!(
        config::display_upstream("https://dns.test/dns-query?key=placeholder"),
        "https://dns.test/dns-query"
    );
    assert_eq!(
        config::display_upstream("https://dns.test/customer-id"),
        "https://dns.test/…"
    );
    assert!(config::merged(&base, json!({"rules":[false]})).is_err());
    assert_eq!(cfg.servers("www.claude.com").0, "claude.com");
    assert_eq!(cfg.servers("notclaude.com").0, "default");
    assert!(cfg.check_runtime().is_ok());
    let mut edit =
        json!({"dns_port":53,"logging_enabled":false,"disabled_methods":[],"cache_size":80});
    let next = config::merged(&base, edit.clone()).unwrap();
    assert_eq!(next["dns_port"], 5355);
    assert_eq!(next["logging_enabled"], true);
    assert_eq!(next["cache_size"], 80);
    edit["route_mode"] = json!("vpn_only");
    assert_eq!(
        Config::from_value(&config::merged(&base, edit).unwrap())
            .unwrap()
            .check_runtime()
            .is_ok(),
        cfg!(target_os = "linux")
    );
}

#[test]
fn go_dns_import_canonicalizes_mapped_ipv4_before_validation_and_deduplication() {
    let mut raw = config::defaults();
    raw["listen_host"] = json!(" ::ffff:127.0.0.1 ");
    raw["route_mode"] = json!(" vpn_only ");
    raw["default_upstream"] = json!({
        "address":"https://[::ffff:192.0.2.53]:443",
        "bootstrap_ips":["::ffff:192.0.2.53", "192.0.2.53"]
    });
    let normal = Config::from_value(&raw).unwrap();
    assert_eq!(normal.listen_host, "127.0.0.1");
    assert_eq!(normal.route_mode, "vpn_only");
    assert_eq!(
        normal.default_upstream.address,
        "https://192.0.2.53/dns-query"
    );
    assert_eq!(
        normal.default_upstream.bootstrap_ips,
        ["192.0.2.53".parse::<std::net::IpAddr>().unwrap()]
    );

    raw["default_upstream"]["bootstrap_ips"] = json!(["::ffff:224.0.0.1"]);
    assert!(Config::from_value(&raw).is_err());
}

fn loopback_route(id: &str) -> vpn::Route {
    let mut route = vpn::Route::system();
    route.id = format!("awg:{id}");
    #[cfg(target_os = "linux")]
    {
        route.interface = "lo".to_owned();
        route.index = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
        assert_ne!(route.index, 0);
    }
    route
}

#[tokio::test]
async fn dns_inventory_preserves_go_slots_and_ignores_duplicate_route_ids() {
    let cfg = Config::from_value(&config::defaults()).unwrap();
    let source = vpn::Source::with(|| {
        let mut rows = vec![loopback_route("0"); 3];
        rows.extend((1..130).map(|i| loopback_route(&i.to_string())));
        Ok(rows)
    });
    let routes = source.eligible(&cfg).await.unwrap();
    assert_eq!(routes.len(), 127);
    assert_eq!(routes.first().unwrap().id, "nfqws");
    assert_eq!(routes.last().unwrap().id, "awg:125");
}

#[tokio::test]
async fn dns_race_reaches_route_33_after_the_first_32_device_bindings_fail() {
    let source = Arc::new(vpn::Source::with(|| {
        let mut routes: Vec<_> = (0..32)
            .map(|i| {
                let mut route = loopback_route(&format!("missing-{i}"));
                route.interface = "n2s-missing".into();
                route.index = u32::MAX;
                route
            })
            .collect();
        routes.push(loopback_route("winner"));
        Ok(routes)
    }));
    let (port, cert, calls, server) = local_doh().await;
    let mut raw = config::defaults();
    raw["route_mode"] = json!("vpn_only");
    raw["awg_fallback"] = json!("auto");
    raw["scheduler_enabled"] = json!(true);
    raw["fast_dns"] = json!(false);
    raw["default_pool"] = json!([]);
    raw["rules"] = json!([]);
    raw["default_upstream"] = json!({"address":format!("https://127.0.0.1:{port}/dns-query")});
    let cfg = Config::from_value(&raw).unwrap();
    let routes = source.eligible(&cfg).await.unwrap();
    assert_eq!(routes.len(), 33);
    let schedule = Arc::new(scheduler::Schedule::default());
    let engine = Engine::new(
        cfg.clone(),
        Arc::new(Mutex::new(Diagnostics::new(true))),
        schedule.clone(),
        shadow::Environment::unavailable(),
        source,
        Default::default(),
    );
    engine.trust(cert);
    // Occupy all but one shared slot. Every unavailable interface must
    // release its slot before the last candidate can reach the DoH server.
    assert_eq!(schedule.slots.available_permits(), 32);
    let busy = schedule.slots.acquire_many(31).await.unwrap();
    let wire = nfqws2_dns::build_query("tail.example", 1, 7).unwrap();
    let reply = timeout(
        Duration::from_secs(4),
        engine.exchange(&wire, "test", "udp", None),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(reply.route, "awg:winner");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let snapshot = schedule.snapshot(&cfg, "tail.example", true, &routes);
    let rows = snapshot["candidates"].as_array().unwrap();
    assert_eq!(rows.iter().filter(|r| r["failures"] == 1).count(), 32);
    assert_eq!(rows.iter().filter(|r| r["successes"] == 1).count(), 1);
    assert_eq!(schedule.slots.available_permits(), 1);
    drop(busy);
    server.abort();
}

#[tokio::test]
async fn vpn_only_bootstraps_provider_by_literal_doh_and_verifies_its_tls_name() {
    let (port, cert, calls, server) = local_doh_protocol(true).await;
    let route = loopback_route("main");
    let online = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let peer = online.clone();
    let source = Arc::new(vpn::Source::with(move || {
        let mut route = route.clone();
        route.available = peer.load(Ordering::SeqCst);
        Ok(vec![loopback_route("other"), route])
    }));
    let mut raw = config::defaults();
    raw["route_mode"] = json!("vpn_only");
    raw["awg_fallback"] = json!("main");
    raw["scheduler_enabled"] = json!(false);
    raw["rules"] = json!([]);
    raw["default_pool"] = json!([]);
    let url = format!("https://dns.test:{port}/dns-query");
    raw["default_upstream"] = json!({"address":url});
    raw["disabled_methods"] = json!([
        {"route":"awg:main","upstream":"https://1.1.1.1/dns-query"},
        {"route":"awg:main","upstream":"https://8.8.8.8/dns-query"}
    ]);
    let diag = Arc::new(Mutex::new(Diagnostics::new(true)));
    let engine = Engine::new(
        Config::from_value(&raw).unwrap(),
        diag,
        Default::default(),
        shadow::Environment::unavailable(),
        source,
        Default::default(),
    );
    engine.trust(cert);
    engine
        .transport
        .bootstrap_fixture(vec![format!("https://127.0.0.1:{port}/dns-query")]);
    let query = nfqws2_dns::build_query("subscriber.example", 1, 33).unwrap();
    let answer = timeout(
        Duration::from_secs(5),
        engine.exchange(&query, "test", "udp", None),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(answer.route, "awg:main");
    assert_eq!(
        nfqws2_dns::first_ipv4(&answer.answer.wire)
            .unwrap()
            .octets(),
        [192, 0, 2, 18]
    );
    assert_eq!(engine.stats().awg_success, 1);
    assert_eq!(engine.stats().nfqws_success, 0);
    engine
        .methods
        .apply(std::collections::HashSet::from([scheduler::key(
            "awg:main", &url,
        )]));
    let new = nfqws2_dns::build_query("new.example", 1, 34).unwrap();
    assert!(engine.exchange(&new, "test", "udp", None).await.is_err());
    engine.methods.apply(Default::default());
    online.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(2010)).await;
    assert_eq!(
        engine
            .exchange(&new, "test", "tcp", None)
            .await
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::NotConnected
    );
    let cached = engine.exchange(&query, "test", "udp", None).await.unwrap();
    assert!(cached.answer.cached);
    assert_eq!(cached.route, "awg:main");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    server.abort();
}

#[tokio::test]
async fn vpn_policy_never_substitutes_wan_for_strict_or_a_missing_device() {
    let source = vpn::Source::with(|| Ok(vec![loopback_route("other")]));
    let mut cfg = Config::from_value(&config::defaults()).unwrap();
    cfg.route_mode = "vpn_only".into();
    for name in ["offline", "off"] {
        cfg.awg_fallback = name.into();
        assert_eq!(
            source.eligible(&cfg).await.unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
    }
    cfg.awg_fallback = "auto".into();
    assert_eq!(source.eligible(&cfg).await.unwrap()[0].id, "awg:other");
    cfg.route_mode = "auto".into();
    assert_eq!(source.eligible(&cfg).await.unwrap().len(), 2);
    cfg.awg_fallback = "other".into();
    let routes = source.eligible(&cfg).await.unwrap();
    assert_eq!(
        routes.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
        ["nfqws", "awg:other"]
    );
    let (port, cert, calls, server) = local_doh().await;
    let mut route = loopback_route("other");
    route.interface = "n2s-no-if-142".into();
    route.index = u32::MAX;
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let transport = transport::Doh::new(false);
    transport.trust(cert);
    let up = config::Upstream {
        address: format!("https://dns.test:{port}/dns-query"),
        bootstrap_ips: vec![addr.ip()],
    };
    let query = nfqws2_dns::build_query("a.example", 1, 2).unwrap();
    let policy = scheduler::Policy::new(Default::default());
    let deadline = || tokio::time::Instant::now() + Duration::from_secs(2);
    transport
        .exchange(
            &up,
            &query,
            &vpn::Route::system(),
            &policy,
            deadline(),
            false,
        )
        .await
        .unwrap();
    let e = transport
        .exchange(&up, &query, &route, &policy, deadline(), false)
        .await
        .unwrap_err();
    if cfg!(not(target_os = "linux")) {
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "VPN attempt reused a WAN TLS connection"
    );
    assert!(super::network::exchange(addr, route.device(), &query)
        .await
        .is_err());
    #[cfg(target_os = "linux")]
    {
        route.interface = "lo".into();
        let e = super::network::tcp(addr, route.device()).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotConnected);
        let e = super::network::exchange(addr, route.device(), &query)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotConnected);
    }
    server.abort();
}
mod legacy_switches;
#[cfg(target_os = "linux")]
mod openwrt_startup;
