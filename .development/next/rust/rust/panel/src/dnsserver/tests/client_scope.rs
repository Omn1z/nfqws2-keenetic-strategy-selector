use super::*;
use tokio::net::TcpSocket;

#[tokio::test]
#[ignore = "requires an isolated Linux network with fixture addresses"]
async fn udp_and_tcp_accept_only_peers_in_the_bound_interface_subnet() {
    let target = TcpListener::bind("192.168.25.1:0").await.unwrap();
    let addr = target.local_addr().unwrap();
    drop(target);
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config::defaults();
    cfg["listen_host"] = json!("192.168.25.1");
    cfg["dns_port"] = json!(addr.port());
    cfg["default_upstream"] = json!({"address":"https://127.0.0.1:1/dns-query"});
    cfg["default_pool"] = json!([]);
    cfg["rules"] = json!([]);
    cfg["fast_dns"] = json!(false);
    cfg["scheduler_enabled"] = json!(false);
    cfg["filtering"] = json!({
        "enabled":true,"lists":[],"custom_rules":[{"domain":"closed.example","category":"ads"}],"allowlist":[]
    });
    std::fs::write(dir.path().join("dnsserver.json"), cfg.to_string()).unwrap();
    let shared = state(&dir);
    let app = crate::http::router(shared.clone());
    request(&app, "/api/dnsserver/start", Some(json!({})), 200).await;

    let query = nfqws2_dns::build_query("closed.example", 1, 77).unwrap();
    let mut reply = [0; 512];
    let udp = UdpSocket::bind("192.168.25.2:0").await.unwrap();
    udp.connect(addr).await.unwrap();
    udp.send(&query).await.unwrap();
    let size = timeout(Duration::from_secs(3), udp.recv(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert!(size >= 12);
    assert_eq!(reply[3] & 15, 3);

    let socket = TcpSocket::new_v4().unwrap();
    socket.bind("192.168.25.2:0".parse().unwrap()).unwrap();
    let mut tcp = socket.connect(addr).await.unwrap();
    tcp.write_u16(query.len() as u16).await.unwrap();
    tcp.write_all(&query).await.unwrap();
    let size = timeout(Duration::from_secs(3), tcp.read_u16())
        .await
        .unwrap()
        .unwrap() as usize;
    assert!(size >= 12 && size <= reply.len());
    tcp.read_exact(&mut reply[..size]).await.unwrap();
    assert_eq!(reply[3] & 15, 3);

    let outside = "192.168.25.130:0".parse::<SocketAddr>().unwrap();
    let udp = UdpSocket::bind(outside).await.unwrap();
    udp.connect(addr).await.unwrap();
    udp.send(&query).await.unwrap();
    assert!(timeout(Duration::from_millis(250), udp.recv(&mut reply))
        .await
        .is_err());

    let socket = TcpSocket::new_v4().unwrap();
    socket.bind(outside).unwrap();
    let mut tcp = socket.connect(addr).await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(3), tcp.read(&mut reply))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    let status = request(&app, "/api/dnsserver", None, 200).await;
    assert_eq!(status["stats"]["queries"], 2);
    assert_eq!(status["stats"]["last_client_ip"], "192.168.25.2");
    shared.dnsserver.shutdown().await;
}
