use super::*;
use tokio_rustls::rustls::pki_types::CertificateDer;

async fn start_panel(
    dir: &tempfile::TempDir,
    upstream: Value,
    cert: CertificateDer<'static>,
) -> (axum::Router, Arc<Engine>) {
    let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dns_port = reserved.local_addr().unwrap().port();
    drop(reserved);
    let mut config = config::defaults();
    config["listen_host"] = json!("127.0.0.1");
    config["dns_port"] = json!(dns_port);
    config["default_upstream"] = upstream;
    config["default_pool"] = json!([]);
    config["rules"] = json!([]);
    config["awg_fallback"] = json!("off");
    config["fast_dns"] = json!(false);
    config["scheduler_enabled"] = json!(false);
    config["timeout_seconds"] = json!(1);
    std::fs::write(dir.path().join("dnsserver.json"), config.to_string()).unwrap();
    let shared = state(dir);
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
    (app, engine)
}

fn named_upstream(port: u16) -> Value {
    json!({
        "address": format!("https://dns.test:{port}/dns-query"),
        "bootstrap_ips": ["127.0.0.2", "127.0.0.1"]
    })
}

async fn resolve(app: &axum::Router, domain: &str) {
    let result = request(
        app,
        "/api/dnsserver/test",
        Some(json!({"domain":domain,"type":"A"})),
        200,
    )
    .await;
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["route"], "nfqws");
    assert_eq!(result["cached"], false);
    assert!(result["answers"][0]
        .as_str()
        .unwrap()
        .contains("192.0.2.18"));
}

#[tokio::test]
async fn stalled_doh_ip_leaves_time_for_second_ip_and_keeps_preference() {
    let (port, cert, healthy_calls, healthy) = local_doh_protocol(true).await;
    let first = TcpListener::bind(("127.0.0.2", port)).await.unwrap();
    let stalled_calls = Arc::new(AtomicUsize::new(0));
    let calls = stalled_calls.clone();
    let stalled = tokio::spawn(async move {
        loop {
            let (mut socket, _) = first.accept().await.unwrap();
            calls.fetch_add(1, Ordering::SeqCst);
            let _ = tokio::io::copy(&mut socket, &mut tokio::io::sink()).await;
        }
    });

    let dir = tempfile::tempdir().unwrap();
    let (app, engine) = start_panel(&dir, named_upstream(port), cert).await;
    resolve(&app, "stalled.example").await;
    assert_eq!(stalled_calls.load(Ordering::SeqCst), 1);
    assert_eq!(healthy_calls.load(Ordering::SeqCst), 1);

    engine.transport.clear_idle();
    resolve(&app, "fresh.example").await;
    assert_eq!(stalled_calls.load(Ordering::SeqCst), 1);
    assert_eq!(healthy_calls.load(Ordering::SeqCst), 2);
    stalled.abort();
    healthy.abort();
}

#[tokio::test]
async fn invalid_dns_from_first_doh_ip_retries_whole_exchange_on_second_ip() {
    let healthy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = healthy_listener.local_addr().unwrap().port();
    let first = TcpListener::bind(("127.0.0.2", port)).await.unwrap();
    let key = rcgen::generate_simple_self_signed(vec!["dns.test".into()]).unwrap();
    let (_, _, invalid_calls, invalid) =
        serve_doh(first, &key, true, None, "/dns-query", |wire, _, _| {
            wire[0] ^= 1;
            wire[2..4].copy_from_slice(&[0x81, 0x80]);
        });
    let (_, cert, healthy_calls, healthy) = serve_doh(
        healthy_listener,
        &key,
        true,
        None,
        "/dns-query",
        ipv4_answer,
    );

    let dir = tempfile::tempdir().unwrap();
    let (app, engine) = start_panel(&dir, named_upstream(port), cert).await;
    resolve(&app, "invalid-first.example").await;
    assert_eq!(invalid_calls.load(Ordering::SeqCst), 1);
    assert_eq!(healthy_calls.load(Ordering::SeqCst), 1);

    engine.transport.clear_idle();
    resolve(&app, "preferred-second.example").await;
    assert_eq!(invalid_calls.load(Ordering::SeqCst), 1);
    assert_eq!(healthy_calls.load(Ordering::SeqCst), 2);
    invalid.abort();
    healthy.abort();
}

fn ipv4_answer(wire: &mut Vec<u8>, _: &str, _: u16) {
    wire[2..4].copy_from_slice(&[0x81, 0x80]);
    wire[7] = 1;
    wire.extend([192, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 18]);
}

#[tokio::test]
async fn literal_doh_uses_normalized_authority_and_preserves_saved_bootstrap_list() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let misplaced = TcpListener::bind(("127.0.0.2", port)).await.unwrap();
    let tls = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let path = "/custom-doh?case=numeric";
    let (_, cert, calls, server) = serve_doh(listener, &tls, true, None, path, ipv4_answer);
    let dir = tempfile::tempdir().unwrap();
    let (app, _) = start_panel(
        &dir,
        json!({
            "address": format!("https://[::ffff:127.0.0.1]:{port}{path}"),
            "bootstrap_ips": ["127.0.0.2"]
        }),
        cert,
    )
    .await;
    resolve(&app, "literal-provider.example").await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let status = request(&app, "/api/dnsserver", None, 200).await;
    assert_eq!(
        status["config"]["default_upstream"],
        json!({
            "address": format!("https://127.0.0.1:{port}{path}"),
            "bootstrap_ips": ["127.0.0.2"]
        })
    );
    tokio::select! {
        biased;
        _ = misplaced.accept() => panic!("connection used an unrelated bootstrap IP"),
        _ = std::future::ready(()) => {}
    }
    server.abort();
}
