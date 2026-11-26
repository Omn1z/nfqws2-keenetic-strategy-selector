use super::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
#[test]
fn validate_urls_interfaces_and_route_priority() {
    let mut o = Options {
        url: "https://example.org/sample".into(),
        ..Default::default()
    };
    o.validate().unwrap();
    assert!(o.iface.is_empty());
    assert_eq!(o.max_bytes, 10 << 20);
    o.max_bytes = 4096 << 20;
    o.timeout_ms = 180_000;
    o.validate().unwrap();
    assert_eq!(o.max_bytes, 4096 << 20);
    for url in [
        "file:///tmp/key",
        "http://a@example.org",
        "example.org:80",
        "https://invalid\\example.org",
    ] {
        o.url = url.into();
        assert!(o.validate().is_err());
    }
    o.url = "http://example.org/".into();
    o.iface = "eth0".into();
    assert!(o.validate().is_err());
    let route = |name: &str, metric: u32| {
        format!("{name} 00000000 0100007F 0003 0 0 {metric} 00000000 0 0 0\n")
    };
    assert_eq!(
        wan(&(route("awg0", 0) + &route("eth2", 100) + &route("ppp0", 5))),
        Some("ppp0")
    );
    let link_default = "ppp0 00000000 00000000 0001 0 0 1 00000000 0 0 0\n";
    assert_eq!(
        wan(&(link_default.to_owned() + &route("eth2", 100))),
        Some("eth2")
    );
    assert_eq!(wan(link_default), Some("ppp0"));
}
#[tokio::test]
async fn downloads_two_local_samples_with_bounded_bodies_and_ndjson_result() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/test", l.local_addr().unwrap());
    let server = tokio::spawn(async move {
        for i in 0..4 {
            let (mut c, _) = l.accept().await.unwrap();
            let mut first = [0; 1024];
            let n = c.read(&mut first).await.unwrap();
            let request = String::from_utf8_lossy(&first[..n]).to_ascii_lowercase();
            assert!(request.contains("range: bytes=0-2"));
            assert!(!request.contains("accept-encoding:"));
            let response: &[u8] = if i % 2 == 0 {
                assert!(request.starts_with("get /test "));
                b"HTTP/1.1 302 Found\r\nLocation: ./folder/../data?sample=1\r\nContent-Length: 0\r\n\r\n"
            } else {
                assert!(request.starts_with("get /data?sample=1 "));
                b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nabcdefgh"
            };
            c.write_all(response).await.unwrap();
        }
    });
    let o = Options {
        url,
        iface: "awg1".into(),
        max_bytes: 3,
        timeout_ms: 3000,
    };
    let (tx, mut rx) = mpsc::channel(12);
    measure(&o, Binding::Loopback, Some(Binding::Loopback), &tx)
        .await
        .unwrap();
    drop(tx);
    let mut events = Vec::new();
    while let Some(v) = rx.recv().await {
        events.push(serde_json::from_slice::<Value>(&v).unwrap());
    }
    assert_eq!(events[0]["phase"], "init");
    let result = &events.last().unwrap()["result"];
    assert_eq!(result["via_direct"]["http_status"], 200, "{events:?}");
    assert_eq!(result["via_tunnel"]["rx_bytes"], 3);
    assert_eq!(result["comparable"], true);
    assert!(events
        .iter()
        .any(|event| event["phase"] == "direct_progress" && event["bytes"] == 3));
    server.await.unwrap();
}
