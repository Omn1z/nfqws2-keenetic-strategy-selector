use super::*;
use axum::{
    body::{to_bytes, Body},
    http::Request,
};
use nfqws2_config::Resolver;
use std::path::Path;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{timeout, Duration},
};
use tower::ServiceExt;

fn setup(root: &Path) -> Shared {
    let cfg = nfqws2_config::Config {
        data_dir: root.display().to_string(),
        listen_addr: "127.0.0.1:8090".into(),
        ..nfqws2_config::Config::from_resolver(&Resolver::new_at(root))
    };
    crate::http::AppState::open(cfg, root, true).unwrap()
}

async fn api(s: &Shared, path: &str, method: &str, body: Value) -> (u16, Value) {
    let req = Request::builder()
        .method(method)
        .uri(format!("/api/socks5{path}"))
        .header("Content-Type", "application/json")
        .header("Host", "router.test:8090")
        .body(Body::from(body.to_string()))
        .unwrap();
    let reply = crate::http::router(s.clone()).oneshot(req).await.unwrap();
    let status = reply.status().as_u16();
    let value =
        serde_json::from_slice(&to_bytes(reply.into_body(), 1 << 20).await.unwrap()).unwrap();
    (status, value)
}
async fn handshake(port: u16, methods: &[u8]) -> (TcpStream, u8) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(&[5, methods.len() as u8]).await.unwrap();
    stream.write_all(methods).await.unwrap();
    let mut answer = [0; 2];
    stream.read_exact(&mut answer).await.unwrap();
    assert_eq!(answer[0], 5);
    (stream, answer[1])
}

#[tokio::test]
async fn legacy_socks_link_uses_request_host_then_profile_then_outbound_address() {
    let dir = tempfile::tempdir().unwrap();
    let state = setup(dir.path());
    let no_header = HeaderMap::new();
    assert_eq!(
        view(&state, &no_header).await.0["link"],
        format!(
            "tg://socks?server={}&port=1080",
            nfqws2_tgws_config::local_link_host()
        )
    );
    let (_, saved) = api(&state, "/config", "POST", json!({"link_host":"relay.test"})).await;
    assert_eq!(saved["link"], "tg://socks?server=router.test&port=1080");
    assert_eq!(
        view(&state, &no_header).await.0["link"],
        "tg://socks?server=relay.test&port=1080"
    );
}
#[tokio::test]
async fn status_and_dashboard_report_latest_vpn_dc() {
    let temp = tempfile::tempdir().unwrap();
    let state = setup(temp.path());
    let counters = &state.socks5.stats;
    assert_eq!(counters.snapshot()["last_dc"], 0);
    for relay in [Some(1), Some(3), None] {
        let _active = counters.begin();
        counters.connected(relay);
    }
    let (code, status) = api(&state, "", "GET", json!({})).await;
    assert_eq!(code, 200);
    let stats = &status["stats"];
    assert_eq!(stats["last_dc"], 3);
    assert_eq!(
        stats["connections"],
        json!({
            "total": 3, "active": 0, "direct": 1, "bad": 0, "telegram": 2
        })
    );
    assert_eq!(&state.socks5.dashboard().await["stats"], stats);
    let _active = counters.begin();
    counters.connected(Some(0));
    assert_eq!(counters.snapshot()["last_dc"], 0);
    assert_eq!(counters.snapshot()["connections"]["telegram"], 3);
}

#[tokio::test]
async fn credentials_tcp_relay_stats_and_stop() {
    let temp = tempfile::tempdir().unwrap();
    let state = setup(temp.path());
    let echo = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    let fixture = tokio::spawn(async move {
        let (mut s, _) = echo.accept().await.unwrap();
        let mut received = Vec::new();
        s.read_to_end(&mut received).await.unwrap();
        s.write_all(&received).await.unwrap();
    });
    let port = TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let (code, data) = api(
        &state,
        "/config",
        "POST",
        json!({"enabled":true,"transport":"direct","port":port,"user":"a b","pass":"p&"}),
    )
    .await;
    assert_eq!(code, 200);
    assert_eq!(data["running"], false);
    assert!(data["link"]
        .as_str()
        .unwrap()
        .contains("user=a+b&pass=p%26"));
    assert_eq!(
        api(&state, "/start", "POST", json!({})).await.1["running"],
        true
    );
    assert!(state
        .socks5
        .inner
        .lock()
        .await
        .live
        .as_ref()
        .unwrap()
        .listener
        .local_addr()
        .unwrap()
        .ip()
        .is_unspecified());
    let (_, method) = handshake(port, &[0]).await;
    assert_eq!(method, 255);
    let (mut bad, method) = handshake(port, &[2]).await;
    assert_eq!(method, 2);
    bad.write_all(&[1, 1, b'x', 1, b'y']).await.unwrap();
    let mut response = [0; 2];
    bad.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [1, 1]);
    let (mut client, method) = handshake(port, &[0, 2]).await;
    assert_eq!(method, 2);
    client.write_all(b"\x01\x03a b\x02p&").await.unwrap();
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [1, 0]);
    client
        .write_all(b"\x05\x01\x00\x03\x09localhost")
        .await
        .unwrap();
    client.write_u16(echo_port).await.unwrap();
    let mut addr = [0; 10];
    client.read_exact(&mut addr).await.unwrap();
    assert_eq!(&addr[..4], &[5, 0, 0, 1]);
    client.write_all(b"echo\x00data").await.unwrap();
    client.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    timeout(Duration::from_secs(3), client.read_to_end(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(echoed, b"echo\0data");
    fixture.await.unwrap();
    let (mut idle, _) = handshake(port, &[2]).await;
    let (code, data) = api(&state, "/stop", "POST", json!({})).await;
    assert_eq!(code, 200);
    assert_eq!(data["stats"]["traffic"]["bytes_up"], 9);
    assert_eq!(data["stats"]["traffic"]["bytes_down"], 9);
    assert_eq!(data["stats"]["connections"]["bad"], 2);
    assert_eq!(data["stats"]["connections"]["direct"], 1);
    assert_eq!(data["stats"]["connections"]["telegram"], 0);
    assert_eq!(data["stats"]["last_dc"], 0);
    assert_eq!(data["stats"]["connections"]["active"], 0);
    assert_eq!(idle.read(&mut response).await.unwrap_or(0), 0);
    assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
}

#[tokio::test]
async fn authenticated_legacy_named_relay_preserves_go_reply_and_counters() {
    let temp = tempfile::tempdir().unwrap();
    let state = setup(temp.path());
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    let fixture = tokio::spawn(async move {
        let (mut socket, _) = echo.accept().await.unwrap();
        let mut payload = [0; 4];
        socket.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"echo");
        socket.write_all(&payload).await.unwrap();
    });
    let port = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    assert_eq!(
        api(
            &state,
            "/config",
            "POST",
            json!({"enabled":true,"port":port,"user":"u","pass":"p"}),
        )
        .await
        .0,
        200
    );
    assert_eq!(
        api(&state, "/start", "POST", json!({})).await.1["running"],
        true
    );

    let (mut client, method) = handshake(port, &[0, 2]).await;
    assert_eq!(method, 2);
    client.write_all(b"\x01\x01u\x01p").await.unwrap();
    let mut credentials = [0; 2];
    client.read_exact(&mut credentials).await.unwrap();
    assert_eq!(credentials, [1, 0]);
    client
        .write_all(b"\x05\x01\x00\x03\x09localhost")
        .await
        .unwrap();
    client.write_u16(echo_port).await.unwrap();
    let mut reply = [0; 10];
    client.read_exact(&mut reply).await.unwrap();
    let [hi, lo] = echo_port.to_be_bytes();
    assert_eq!(reply, [5, 0, 0, 1, 127, 0, 0, 1, hi, lo]);

    client.write_all(b"echo").await.unwrap();
    let mut echoed = Vec::new();
    timeout(Duration::from_secs(3), client.read_to_end(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(echoed, b"echo");
    fixture.await.unwrap();
    let (code, status) = api(&state, "/stop", "POST", json!({})).await;
    assert_eq!(code, 200);
    let stats = &status["stats"];
    assert_eq!(
        stats["connections"],
        json!({"total":1,"active":0,"direct":1,"bad":0,"telegram":0})
    );
    assert_eq!(stats["traffic"]["bytes_up"], 4);
    assert_eq!(stats["traffic"]["bytes_down"], 4);
}

#[tokio::test]
async fn preserves_legacy_transport_and_healthy_listener_after_conflict() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let occupied = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let busy = occupied.local_addr().unwrap().port();
    let port = TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let legacy = json!({"enabled":true,"port":port,"dc_redirects":{"2":"192.0.2.1"}});
    let old = serde_json::to_vec(&legacy).unwrap();
    std::fs::write(root.join(FILE), &old).unwrap();
    let state = setup(root);
    assert!(auto_start(&state).await.is_ok());
    let (_, status) = api(&state, "", "GET", json!({})).await;
    assert_eq!(status["running"], true);
    assert_eq!(status["transport"], "telegram_wss");
    assert_eq!(std::fs::read(root.join(FILE)).unwrap(), old);
    assert_eq!(api(&state, "/start", "POST", json!({})).await.0, 200);
    assert_eq!(
        api(&state, "/config", "POST", json!({"port":busy})).await.0,
        400
    );
    assert_eq!(
        api(&state, "/config", "POST", json!({"port":8090})).await.0,
        400
    );
    assert_eq!(
        api(
            &state,
            "/config",
            "POST",
            json!({"port":port,"user":"only"})
        )
        .await
        .0,
        400
    );
    let (mut client, method) = handshake(port, &[0]).await;
    assert_eq!(method, 0);
    client.write_all(&[5, 3, 0, 1]).await.unwrap();
    let mut prohibited = [0; 10];
    timeout(Duration::from_secs(1), client.read_exact(&mut prohibited))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(prohibited[1], 7);
    let saved = state.store.read::<Config>(FILE).unwrap();
    assert_eq!(saved.port, port);
    assert!(saved.transport.is_empty());
    assert!(saved.enabled);
    state.socks5.shutdown().await;
    let reloaded = setup(root);
    assert!(auto_start(&reloaded).await.is_ok());
    assert_eq!(
        api(&reloaded, "", "GET", json!({})).await.1["running"],
        true
    );
    reloaded.socks5.shutdown().await;
}

#[tokio::test]
async fn legacy_tcp_connect_sends_go_bind_reply_even_when_upstream_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let state = setup(dir.path());
    let refused = tokio::net::TcpSocket::new_v4().unwrap();
    refused.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let [hi, lo] = refused.local_addr().unwrap().port().to_be_bytes();
    let port = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    assert_eq!(
        api(&state, "/config", "POST", json!({"port":port})).await.0,
        200
    );
    assert_eq!(api(&state, "/start", "POST", json!({})).await.0, 200);
    let (mut client, method) = handshake(port, &[2]).await;
    assert_eq!(method, 0);
    client
        .write_all(&[5, 1, 42, 1, 127, 0, 0, 1, hi, lo])
        .await
        .unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(3), client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, [5, 0, 0, 1, 127, 0, 0, 1, hi, lo]);
    assert_eq!(state.socks5.stats.snapshot()["connections"]["direct"], 1);
    state.socks5.shutdown().await;
}

#[tokio::test]
async fn disabled_settings_do_not_reserve_ports_and_auth_changes_keep_one_listener() {
    let dir = tempfile::tempdir().unwrap();
    let state = setup(dir.path());
    let (_, fresh) = api(&state, "", "GET", json!({})).await;
    assert_eq!(fresh["transport"], "telegram_wss");
    assert!(fresh["config"].get("transport").is_none());
    assert_eq!(fresh["running"], false);
    let (code, saved) = api(&state, "/config", "POST", json!({"port":8090})).await;
    assert_eq!(code, 200);
    assert_eq!(saved["running"], false);
    assert_eq!(api(&state, "/start", "POST", json!({})).await.0, 400);
    assert!(state.socks5.inner.lock().await.live.is_none());
    let port = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    assert_eq!(
        api(&state, "/config", "POST", json!({"port":port})).await.0,
        200
    );
    assert_eq!(api(&state, "/start", "POST", json!({})).await.0, 200);
    let listener = state
        .socks5
        .inner
        .lock()
        .await
        .live
        .as_ref()
        .unwrap()
        .listener
        .clone();
    for auth in [true, false] {
        let mut cfg = json!({"port":port});
        if auth {
            cfg["user"] = "test".into();
            cfg["pass"] = "fixture".into();
        }
        assert_eq!(api(&state, "/config", "POST", cfg).await.0, 200);
        let manager = state.socks5.inner.lock().await;
        let current = &manager.live.as_ref().unwrap().listener;
        let address = current.local_addr().unwrap();
        assert!(address.ip().is_unspecified());
        assert_eq!(address.port(), port);
        assert!(Arc::ptr_eq(&listener, current));
    }
    state.socks5.shutdown().await;
    assert!(local_client("::ffff:192.168.0.2".parse().unwrap()));
    assert!(!local_client("::ffff:198.51.100.3".parse().unwrap()));
    assert!(!local_client("2001:db8::1".parse().unwrap()));
}

#[tokio::test]
async fn live_proxy_accepts_new_clients_while_existing_handshakes_are_open() {
    let dir = tempfile::tempdir().unwrap();
    let state = setup(dir.path());
    let port = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    assert_eq!(
        api(&state, "/config", "POST", json!({"port":port})).await.0,
        200
    );
    assert_eq!(api(&state, "/start", "POST", json!({})).await.0, 200);
    let mut clients = Vec::new();
    for _ in 0..129 {
        let (tcp, method) = timeout(Duration::from_secs(3), handshake(port, &[0]))
            .await
            .unwrap();
        assert_eq!(method, 0);
        clients.push(tcp);
    }
    state.socks5.shutdown().await;
    assert_eq!(clients.len(), 129);
}
