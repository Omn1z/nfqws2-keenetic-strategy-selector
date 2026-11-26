use super::*;
use crate::crypto::{self, Transport};
use ctr::cipher::StreamCipher;
use futures_util::StreamExt;
use socket2::SockRef;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::{
    rustls::{pki_types::PrivatePkcs8KeyDer, RootCertStore, ServerConfig},
    TlsAcceptor,
};
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::handshake::server::{Request, Response},
};
use tokio_util::either::Either;

pub(crate) fn origin(names: Vec<String>) -> (RootCertStore, ServerConfig) {
    fixture_origin(rcgen::CertificateParams::new(names).unwrap())
}
pub(crate) fn fixture_origin(params: rcgen::CertificateParams) -> (RootCertStore, ServerConfig) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap().der().clone();
    let mut roots = RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let server = ServerConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert],
        PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )
    .unwrap();
    (roots, server)
}

#[tokio::test]
async fn legacy_configured_websocket_applies_go_socket_defaults() {
    const HOST: &str = "socket-options.test";
    let (roots, server) = origin(vec![HOST.into()]);
    let tls = relay::tls_config(roots).unwrap();
    let server = TlsAcceptor::from(Arc::new(server));
    for (legacy, plain) in [(true, true), (true, false), (false, true), (false, false)] {
        for warm_buffer in [None, Some(16 * 1024)] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let peer = listener.local_addr().unwrap();
            let baseline = TcpStream::connect(peer).await.unwrap();
            let _baseline_peer = listener.accept().await.unwrap();
            if let Some(buffer) = warm_buffer {
                relay::configure_socket(&baseline, buffer);
            }
            let baseline = SockRef::from(&baseline);
            let mut relays = Relays::new(tls.clone(), Default::default(), legacy);
            relays.connector.peer = Some(peer);

            let path = if warm_buffer.is_some() {
                "/apiws?dc=2&dst=149.154.167.51"
            } else {
                "/apiws"
            };
            let upstream = async {
                let (socket, _) = listener.accept().await.unwrap();
                let stream = if plain {
                    Either::Left(socket)
                } else {
                    let secure = server.accept(socket).await.unwrap();
                    assert_eq!(secure.get_ref().1.server_name(), Some(HOST));
                    Either::Right(secure)
                };
                #[allow(clippy::result_large_err)]
                let ws = accept_hdr_async(stream, |request: &Request, response: Response| {
                    assert_eq!(request.headers()["Host"], HOST);
                    assert_eq!(request.uri().to_string(), path);
                    Ok(response)
                });
                ws.await.unwrap()
            };
            let (ws, _upstream) = timeout(Duration::from_secs(3), async {
                tokio::join!(
                    relays.connector.open(HOST, path, warm_buffer, plain),
                    upstream
                )
            })
            .await
            .unwrap();
            let ws = ws.unwrap();
            let tcp = nfqws2_tgws_transport::socket(&ws);
            let socket = SockRef::from(tcp);
            assert!(tcp.nodelay().unwrap());
            assert_eq!(
                socket.keepalive().unwrap(),
                legacy || baseline.keepalive().unwrap()
            );
            assert_eq!(
                socket.recv_buffer_size().unwrap(),
                baseline.recv_buffer_size().unwrap()
            );
            assert_eq!(
                socket.send_buffer_size().unwrap(),
                baseline.send_buffer_size().unwrap()
            );
            #[cfg(target_os = "linux")]
            if legacy {
                assert_eq!(
                    socket.tcp_keepalive_time().unwrap(),
                    Duration::from_secs(15)
                );
                assert_eq!(
                    socket.tcp_keepalive_interval().unwrap(),
                    Duration::from_secs(15)
                );
                assert_eq!(socket.tcp_keepalive_retries().unwrap(), 9);
            }
        }
    }
}

#[tokio::test]
async fn nine_second_upgrade_succeeds_for_foreground_worker_and_web_but_expires_in_warm_pool() {
    for route in ["worker", "web", "warm"] {
        let host = if route == "web" {
            "kws2.relay.example.test"
        } else {
            "worker.example.test"
        };
        let (roots, server) = origin(vec![host.into()]);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut relays = Relays::new(relay::tls_config(roots).unwrap(), Default::default(), true);
        relays.connector.peer = Some(listener.local_addr().unwrap());
        let cfg = Config {
            pool_size: i64::from(route == "warm"),
            cfproxy: true,
            cfproxy_user_domains: Some(vec!["relay.example.test".into()]),
            cfproxy_worker_domains: Some(vec!["worker.example.test".into()]),
            ..Default::default()
        };
        let stats = Stats::default();
        let connect = async {
            match route {
                "worker" => {
                    relays
                        .worker(2, false, &cfg, &stats, &[1; 64], |_| ())
                        .await
                }
                "web" => relays.web(2, false, &cfg, &stats, &[1; 64], |_| ()).await,
                _ => {
                    relays.warm(2, tcp_destination(2, false).unwrap(), &cfg);
                    let mut slot = relays.workers.lock().unwrap().remove(&2).unwrap();
                    slot.checkout.take().unwrap().send(()).unwrap();
                    (&mut slot.task).await.unwrap()
                }
            }
        };
        let upstream = async {
            let tcp = listener.accept().await.unwrap().0;
            let tls = TlsAcceptor::from(Arc::new(server))
                .accept(tcp)
                .await
                .unwrap();
            assert_eq!(tls.get_ref().1.server_name(), Some(host));
            // Delay only the upgrade on a verified loopback connection. Time
            // is resumed before polling I/O to avoid virtual-time TCP races.
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(9)).await;
            tokio::task::yield_now().await;
            tokio::time::resume();
            #[allow(clippy::result_large_err)]
            let ws = accept_hdr_async(tls, |req: &Request, res: Response| {
                assert_eq!(req.headers()["Host"], host);
                Ok(res)
            })
            .await;
            if route != "warm" {
                if let Ok(mut ws) = ws {
                    let init = ws.next().await;
                    assert!(matches!(init,Some(Ok(Message::Binary(b))) if b.as_ref()==[1;64]));
                }
            }
        };
        let (ws, ()) = tokio::join!(connect, upstream);
        assert_eq!(ws.is_some(), route != "warm", "{route}");
        relays.stop().await;
    }
}
#[tokio::test]
async fn worker_reserve_shares_media_and_primary_and_is_closed_on_shutdown() {
    let host = "worker.example.test";
    let (roots, server) = origin(vec![host.into()]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut relays = Relays::new(relay::tls_config(roots).unwrap(), Default::default(), true);
    relays.connector.peer = Some(listener.local_addr().unwrap());
    let (send, mut accepted) = tokio::sync::mpsc::channel(4);
    let server = tokio::spawn(async move {
        let accept = TlsAcceptor::from(Arc::new(server));
        while let Ok((socket, _)) = listener.accept().await {
            let tls = accept.accept(socket).await.unwrap();
            #[allow(clippy::result_large_err)]
            let ws = accept_hdr_async(tls, |req: &Request, mut res: Response| {
                assert_eq!(req.uri().to_string(), "/apiws?dc=2&dst=149.154.167.51");
                res.headers_mut()
                    .insert("Sec-WebSocket-Protocol", "binary".parse().unwrap());
                Ok(res)
            })
            .await
            .unwrap();
            if send.send(ws).await.is_err() {
                break;
            }
        }
    });
    let mut cfg = Config {
        cfproxy: false,
        cfproxy_worker_domains: Some(vec![host.into()]),
        pool_size: 3,
        ..Config::default()
    };
    cfg.dc_redirects = Some(
        [1, 3, 4, 5, 203]
            .into_iter()
            .map(|id| (id, "192.0.2.1".parse().unwrap()))
            .collect(),
    );
    cfg.normalize().unwrap();
    relays.warm_workers(&cfg);
    relays.warm_workers(&cfg);
    let mut origin = timeout(Duration::from_secs(3), accepted.recv())
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(2), async {
        while !relays.workers.lock().unwrap()[&2]
            .ready
            .load(Ordering::Acquire)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(relays.workers.lock().unwrap().len(), 1);
    let stats = Stats::default();
    let ws = relays
        .worker(-2, false, &cfg, &stats, &[8; 64], |_| ())
        .await
        .unwrap();
    assert_eq!(
        origin.next().await.unwrap().unwrap().into_data().as_ref(),
        &[8; 64]
    );
    assert_eq!(stats.cf_hits.load(Ordering::Relaxed), 1);
    let mut replacement = timeout(Duration::from_secs(3), accepted.recv())
        .await
        .unwrap()
        .unwrap();
    drop(ws);
    relays.stop().await;
    timeout(Duration::from_secs(2), replacement.next())
        .await
        .unwrap();
    assert!(relays.workers.lock().unwrap().is_empty());
    server.abort();
}

#[tokio::test]
async fn a_cold_worker_fallback_dials_once_without_scheduling_a_refill() {
    let host = "worker.example.test";
    let (roots, server) = origin(vec![host.into()]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut relays = Relays::new(relay::tls_config(roots).unwrap(), Default::default(), true);
    relays.connector.peer = Some(listener.local_addr().unwrap());
    let cfg = Config {
        cfproxy_worker_domains: Some(vec![host.into()]),
        pool_size: 1,
        ..Config::default()
    };
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let tls = TlsAcceptor::from(Arc::new(server))
            .accept(socket)
            .await
            .unwrap();
        assert_eq!(tls.get_ref().1.server_name(), Some(host));
        #[allow(clippy::result_large_err)]
        let mut ws = accept_hdr_async(tls, |req: &Request, res: Response| {
            assert_eq!(req.uri().to_string(), "/apiws?dc=2&dst=149.154.167.51");
            Ok(res)
        })
        .await
        .unwrap();
        assert_eq!(
            ws.next().await.unwrap().unwrap().into_data().as_ref(),
            &[7; 64]
        );
        assert!(timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err());
    });
    let stats = Stats::default();
    let ws = timeout(
        Duration::from_secs(3),
        relays.worker(2, false, &cfg, &stats, &[7; 64], |_| ()),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(relays.workers.lock().unwrap().is_empty());
    timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stats.cf_hits.load(Ordering::Relaxed), 0);
    assert_eq!(stats.cf_misses.load(Ordering::Relaxed), 1);
    drop(ws);
    relays.stop().await;
}
#[tokio::test]
async fn media_rejects_mismatched_certificate_and_missing_alpn_before_sending_native_data() {
    for (name, alpn) in [
        ("wrong.example.test", true),
        ("kws2.media.example.test", false),
    ] {
        let (roots, mut server) = origin(vec![name.into()]);
        if alpn {
            server.alpn_protocols = vec![b"h2".to_vec()];
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut relays = Relays::new(relay::tls_config(roots).unwrap(), Default::default(), true);
        relays.connector.peer = Some(listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            if let Ok(mut stream) = TlsAcceptor::from(Arc::new(server)).accept(socket).await {
                let mut b = [0; 1];
                assert!(stream.read(&mut b).await.unwrap_or(0) == 0);
            }
        });
        let cfg = Config {
            cfproxy: true,
            cfproxy_h2_media: true,
            cfproxy_user_domains: Some(vec!["media.example.test".into()]),
            ..Config::default()
        };
        let stats = Stats::default();
        assert!(relays.media(-2, &cfg, &stats).await.is_none());
        assert_eq!(stats.h2_requests.load(Ordering::Relaxed), 0);
        assert_eq!(stats.json()["h2"]["errors"], 1);
        assert!(relays.media(-2, &cfg, &stats).await.is_none());
        assert_eq!(stats.json()["h2"]["errors"], 1);
        server.await.unwrap();
    }
}
#[tokio::test]
async fn h2_polls_again_with_the_same_encrypted_packet_after_an_empty_reply() {
    let (roots, mut origin) = origin(vec!["kws2.media.example.test".into()]);
    origin.alpn_protocols = vec![b"h2".to_vec()];
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut relays = Relays::new(relay::tls_config(roots).unwrap(), Default::default(), true);
    relays.connector.peer = Some(upstream.local_addr().unwrap());
    let upstream = tokio::spawn(async move {
        let (tcp, _) = upstream.accept().await.unwrap();
        let tls = TlsAcceptor::from(Arc::new(origin))
            .accept(tcp)
            .await
            .unwrap();
        let mut conn = h2::server::handshake(tls).await.unwrap();
        let mut seen = 0;
        while let Some(Ok((req, mut respond))) = conn.accept().await {
            if req.method() == http::Method::HEAD {
                respond
                    .send_response(http::Response::new(()), true)
                    .unwrap();
                continue;
            }
            seen += 1;
            let seq = seen;
            tokio::spawn(async move {
                let mut read = req.into_body();
                let mut bytes = vec![];
                while let Some(chunk) = read.data().await {
                    let c = chunk.unwrap();
                    read.flow_control().release_capacity(c.len()).unwrap();
                    bytes.extend_from_slice(&c);
                }
                assert_eq!(bytes, vec![7; 24]);
                let status = if seq == 1 { 200 } else { 429 };
                respond
                    .send_response(
                        http::Response::builder().status(status).body(()).unwrap(),
                        true,
                    )
                    .unwrap();
            });
        }
    });
    let cfg = Config {
        cfproxy: true,
        cfproxy_h2_media: true,
        cfproxy_user_domains: Some(vec!["media.example.test".into()]),
        ..Config::default()
    };
    let stats = Stats::default();
    let lane = relays.media(-2, &cfg, &stats).await.unwrap();
    let (head, mut send, mut receive) = crypto::client_fixture(&[5; 16], -2, 0xee);
    let session = Transport::client(head, &[5; 16]).unwrap();
    let listen = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(listen.local_addr().unwrap())
        .await
        .unwrap();
    let (tcp, _) = listen.accept().await.unwrap();
    let app = async {
        let mut packet = vec![7; 28];
        packet[..4].copy_from_slice(&24u32.to_le_bytes());
        send.apply_keystream(&mut packet);
        client.write_all(&packet).await.unwrap();
        let mut reply = [0; 8];
        client.read_exact(&mut reply).await.unwrap();
        receive.apply_keystream(&mut reply);
        assert_eq!(&reply[4..], &(-429i32).to_le_bytes());
    };
    let (r, ()) = timeout(Duration::from_secs(4), async {
        tokio::join!(
            crate::media::bridge(tcp, session, lane, &stats, |error| {
                assert_eq!(error, crate::diagnostics::H2Terminal::Http(429));
            }),
            app
        )
    })
    .await
    .unwrap();
    r.unwrap();
    assert_eq!(stats.h2_replays.load(Ordering::Relaxed), 1);
    assert_eq!(stats.h2_requests.load(Ordering::Relaxed), 2);
    relays.stop().await;
    upstream.abort();
}
#[tokio::test]
async fn pending_h2_head_releases_the_last_shared_handshake_slot_after_alpn() {
    let host = "kws2.media.example.test";
    let (roots, mut server) = origin(vec![host.into()]);
    server.alpn_protocols = vec![b"h2".to_vec()];
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer = listener.local_addr().unwrap();
    let (head, received) = oneshot::channel();
    let (release, wait) = oneshot::channel();
    let server = tokio::spawn(async move {
        let tls = TlsAcceptor::from(Arc::new(server))
            .accept(listener.accept().await.unwrap().0)
            .await
            .unwrap();
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        let mut conn = h2::server::handshake(tls).await.unwrap();
        let (req, mut respond) = conn.accept().await.unwrap().unwrap();
        assert_eq!(req.method(), http::Method::HEAD);
        head.send(()).unwrap();
        wait.await.unwrap();
        respond
            .send_response(http::Response::new(()), true)
            .unwrap();
        while conn.accept().await.is_some() {}
    });
    let slots = Handshakes::default();
    let mut held = Vec::new();
    for _ in 0..3 {
        held.push(slots.acquire().await.unwrap());
    }
    let tls = relay::tls_config(roots).unwrap();
    let origins = crate::media::Origins::default();
    let stats = Stats::default();
    let open = origins.get(host, &tls, &slots, TcpStream::connect(peer), &stats);
    let another_setup = async {
        received.await.unwrap();
        let permit = slots.acquire().await;
        release.send(()).unwrap();
        permit
    };
    let (lane, concurrent) = tokio::join!(open, another_setup);
    concurrent.expect("slow HTTP preflight consumed the last handshake slot");
    drop(lane.unwrap());
    origins.stop().await;
    server.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn h2_setup_timeout_cools_only_that_dc_for_thirty_seconds_from_expiry() {
    use tokio::time::{advance, Instant};
    let origins = crate::media::Origins::default();
    let stats = Stats::default();
    let start = Instant::now();
    // Multiple origin candidates share the outer eight-second deadline.
    let stalled = |deadline, _| async move {
        assert_eq!(deadline, start + Duration::from_secs(8));
        tokio::time::sleep(Duration::from_secs(5)).await;
        std::future::pending::<Option<()>>().await
    };
    assert!(origins.setup(2, &stats, stalled).await.is_none());
    assert_eq!(start.elapsed(), Duration::from_secs(8));
    let blocked = |_, _| async { panic!("attempted an origin during DC cooldown") };
    assert!(origins.setup::<(), _>(2, &stats, blocked).await.is_none());
    assert_eq!(
        origins.setup(4, &stats, |_, _| async { Some(4) }).await,
        Some(4)
    );
    advance(Duration::from_secs(29)).await;
    assert!(origins.setup::<(), _>(2, &stats, blocked).await.is_none());
    advance(Duration::from_secs(1)).await;
    assert_eq!(
        origins.setup(2, &stats, |_, _| async { Some(2) }).await,
        Some(2)
    );

    // Immediate refusal, full handshake queue and caller cancellation finish
    // before the setup deadline and permit immediate selection on the same DC.
    assert!(origins
        .setup::<(), _>(4, &stats, |_, _| async { None })
        .await
        .is_none());
    assert!(timeout(
        Duration::from_secs(1),
        origins.setup::<(), _>(4, &stats, |_, _| std::future::pending())
    )
    .await
    .is_err());
    assert_eq!(
        origins.setup(4, &stats, |_, _| async { Some(4) }).await,
        Some(4)
    );
    assert_eq!(stats.json()["h2"]["errors"], 0);
}

#[tokio::test(start_paused = true)]
async fn h2_group_deadline_counts_only_active_origin_setup() {
    let host = "kws2.media.example.test";
    let (roots, _) = origin(vec![host.into()]);
    let tls = relay::tls_config(roots).unwrap();
    let slots = Handshakes::default();
    let origins = crate::media::Origins::default();
    let stats = Stats::default();
    let attempt = |_, opening: Arc<AtomicBool>| {
        let (origins, tls, slots, stats) = (&origins, &tls, &slots, &stats);
        async move {
            let result = origins
                .get(
                    host,
                    tls,
                    slots,
                    async {
                        opening.store(true, Ordering::Relaxed);
                        std::future::pending().await
                    },
                    stats,
                )
                .await;
            opening.store(false, Ordering::Relaxed);
            result.ok()
        }
    };

    assert!(origins.setup(2, &stats, attempt).await.is_none());
    assert_eq!(stats.json()["h2"]["errors"], 1);
    assert!(origins
        .setup::<(), _>(2, &stats, |_, _| async {
            panic!("active timeout did not impose DC cooldown")
        })
        .await
        .is_none());
    assert_eq!(stats.json()["h2"]["errors"], 1);

    // The expired attempt leaves the origin available to other callers. Hold
    // its lock through another group's deadline without starting a second dial.
    let polled = AtomicBool::new(false);
    let mut holder = Box::pin(origins.get(
        host,
        &tls,
        &slots,
        async {
            polled.store(true, Ordering::Relaxed);
            std::future::pending().await
        },
        &stats,
    ));
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(std::future::Future::poll(holder.as_mut(), &mut context).is_pending());
    assert!(polled.load(Ordering::Relaxed));
    assert!(origins.setup(3, &stats, attempt).await.is_none());
    assert_eq!(stats.json()["h2"]["errors"], 1);
    drop(holder);

    assert!(
        timeout(Duration::from_secs(1), origins.setup(4, &stats, attempt))
            .await
            .is_err()
    );
    assert_eq!(stats.json()["h2"]["errors"], 1);
    assert_eq!(
        origins.setup(4, &stats, |_, _| async { Some(4) }).await,
        Some(4)
    );
}

#[tokio::test]
async fn media_uses_verified_h2_on_one_socket_and_delivers_concurrent_replies_and_native_errors() {
    use bytes::Bytes;
    use tokio::sync::Notify;
    let host = "kws2.media.example.test";
    let (roots, mut server) = origin(vec![host.into()]);
    server.alpn_protocols = vec![b"h2".to_vec()];
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut relays = Relays::new(relay::tls_config(roots).unwrap(), Default::default(), true);
    relays.connector.peer = Some(listener.local_addr().unwrap());
    let ready = Arc::new(Notify::new());
    let worker = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let stream = TlsAcceptor::from(Arc::new(server))
            .accept(socket)
            .await
            .unwrap();
        assert_eq!(stream.get_ref().1.server_name(), Some(host));
        let mut conn = h2::server::handshake(stream).await.unwrap();
        while let Some(Ok((req, mut respond))) = conn.accept().await {
            let gate = ready.clone();
            assert_eq!(req.uri().authority().unwrap().as_str(), host);
            assert_eq!(req.uri().path(), "/api");
            assert_eq!(
                req.headers()[http::header::USER_AGENT],
                "Go-http-client/2.0"
            );
            if req.method() == http::Method::HEAD {
                respond
                    .send_response(
                        http::Response::builder().status(405).body(()).unwrap(),
                        true,
                    )
                    .unwrap();
                continue;
            }
            tokio::spawn(async move {
                assert_eq!(req.method(), http::Method::POST);
                assert_eq!(req.headers()["content-type"], "application/octet-stream");
                let mut incoming = req.into_body();
                let mut buffer = vec![];
                while let Some(v) = incoming.data().await {
                    let v = v.unwrap();
                    incoming.flow_control().release_capacity(v.len()).unwrap();
                    buffer.extend_from_slice(&v);
                }
                assert_eq!(buffer.len(), 24);
                let id = buffer[23];
                if id == 3 {
                    respond
                        .send_response(
                            http::Response::builder().status(404).body(()).unwrap(),
                            true,
                        )
                        .unwrap();
                    return;
                }
                if id == 1 {
                    gate.notified().await;
                }
                let mut body = respond
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                body.send_data(Bytes::from(vec![id; 8]), true).unwrap();
                if id == 2 {
                    gate.notify_one();
                }
            });
        }
    });
    let mut cfg = Config {
        cfproxy: true,
        cfproxy_h2_media: true,
        cfproxy_user_domains: Some(vec!["media.example.test".into()]),
        ..Config::default()
    };
    cfg.normalize().unwrap();
    cfg.cfproxy_user_domains = Some(Vec::new());
    relays
        .catalog
        .fixture(b"media.example.test\nb.example.test\nc.example.test");
    relays.catalog.promote(2, "media.example.test".into(), &cfg);
    let stats = Stats::default();
    assert!(relays.media(2, &cfg, &stats).await.is_none());
    assert!(relays.media(-10002, &cfg, &stats).await.is_none());
    let lane = relays.media(-2, &cfg, &stats).await.unwrap();
    let mut busy = Vec::new();
    for _ in 0..4 {
        busy.push(relays.connector.slots.acquire().await.unwrap());
    }
    // A live H2 connection needs no TLS setup permit to accept another channel.
    let second = timeout(Duration::from_millis(250), relays.media(-2, &cfg, &stats))
        .await
        .unwrap()
        .unwrap();
    drop(busy);
    assert!(Arc::ptr_eq(&lane, &second));
    drop(second);
    let retired = Arc::downgrade(&lane);
    relays
        .catalog
        .fixture(b"a.example.test\nb.example.test\nc.example.test");
    relays.prune_media(&cfg).await;
    assert_eq!(retired.strong_count(), 2);
    let (head, mut send, mut receive) = crypto::client_fixture(&[7; 16], -2, 0xee);
    let session = Transport::client(head, &[7; 16]).unwrap();
    let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(local.local_addr().unwrap())
        .await
        .unwrap();
    let (remote, _) = local.accept().await.unwrap();
    let (report, diagnostics) = oneshot::channel();
    let run = crate::media::bridge(remote, session, lane, &stats, |error| {
        assert_eq!(error, crate::diagnostics::H2Terminal::Http(404));
        report.send(()).unwrap();
    });
    let send_packet = |id: u8, cipher: &mut crate::crypto::Cipher| {
        let mut bytes = vec![0; 28];
        bytes[..4].copy_from_slice(&24u32.to_le_bytes());
        bytes[27] = id;
        cipher.apply_keystream(&mut bytes);
        bytes
    };
    let app = async {
        for id in [1, 2] {
            client.write_all(&send_packet(id, &mut send)).await.unwrap();
        }
        let mut replies = vec![];
        for _ in 0..2 {
            let mut answer = [0; 12];
            client.read_exact(&mut answer).await.unwrap();
            receive.apply_keystream(&mut answer);
            assert_eq!(&answer[..4], &8u32.to_le_bytes());
            assert!(answer[4..].iter().all(|b| *b == answer[4]));
            replies.push(answer[4]);
        }
        replies.sort();
        assert_eq!(replies, [1, 2]);
        client.write_all(&send_packet(3, &mut send)).await.unwrap();
        let mut err = [0; 8];
        client.read_exact(&mut err).await.unwrap();
        receive.apply_keystream(&mut err);
        assert_eq!(&err[..4], &4u32.to_le_bytes());
        assert_eq!(&err[4..], &(-404i32).to_le_bytes());
    };
    let (res, ()) = timeout(Duration::from_secs(5), async { tokio::join!(run, app) })
        .await
        .unwrap();
    res.unwrap();
    diagnostics.await.unwrap();
    assert_eq!(stats.h2_tcp.load(Ordering::Relaxed), 1);
    assert_eq!(stats.h2_requests.load(Ordering::Relaxed), 3);
    assert_eq!(stats.h2_replays.load(Ordering::Relaxed), 0);
    assert_eq!(stats.h2_errors.load(Ordering::Relaxed), 1);
    // The existing stream finished on the obsolete origin. Pruning now retires
    // its TCP connection without waiting for the general idle timeout.
    relays.prune_media(&cfg).await;
    assert!(retired.upgrade().is_none());
    relays.stop().await;
    worker.abort();
}

#[tokio::test(start_paused = true)]
async fn direct_cf_and_h2_share_four_setup_slots_without_marking_an_origin_unhealthy() {
    let (roots, _) = origin(vec!["local.example.test".into()]);
    let pool = pool::Pool::legacy(2, relay::tls_config(roots).unwrap(), 8192);
    let relays = &pool.relays;
    let mut busy = Vec::new();
    for _ in 0..4 {
        busy.push(relays.connector.slots.acquire().await.unwrap());
    }
    let stats = Stats::default();
    let direct = pool
        .direct
        .dial("local.example.test", "/apiws", 8192, None, |_| async {
            panic!("unexpected TCP setup")
        });
    let cf = relays
        .connector
        .open("local.example.test", "/apiws", None, false);
    let h2 = relays.h2.get(
        "kws2.local.example.test",
        &relays.connector.tls,
        &relays.connector.slots,
        async { panic!("unexpected H2 setup") },
        &stats,
    );
    let (direct, cf, h2) = tokio::join!(direct, cf, h2);
    for kind in [
        direct.err().unwrap().kind(),
        cf.err().unwrap().kind(),
        h2.err().unwrap().kind(),
    ] {
        assert_eq!(kind, io::ErrorKind::WouldBlock);
    }
    assert_eq!(stats.json()["h2"]["errors"], 0);
    drop(busy);
    let next = relays
        .h2
        .get(
            "kws2.local.example.test",
            &relays.connector.tls,
            &relays.connector.slots,
            async { Err(io::ErrorKind::ConnectionAborted.into()) },
            &stats,
        )
        .await;
    assert_eq!(next.err().unwrap().kind(), io::ErrorKind::ConnectionAborted);
    assert_eq!(stats.json()["h2"]["errors"], 1);
    let cooling = relays
        .h2
        .get(
            "kws2.local.example.test",
            &relays.connector.tls,
            &relays.connector.slots,
            async { panic!("retried the failed origin during its cooldown") },
            &stats,
        )
        .await;
    assert_eq!(
        cooling.err().unwrap().kind(),
        io::ErrorKind::ConnectionRefused
    );
    assert_eq!(stats.json()["h2"]["errors"], 1);
    pool.stop().await;
}
#[tokio::test]
async fn operator_worker_and_named_cf_front_verify_identity_and_use_their_own_framing() {
    for (worker, plain) in [(true, false), (false, false), (true, true), (false, true)] {
        let host = if worker {
            "worker.example.test"
        } else {
            "kws2.relay.example.test"
        };
        let (roots, server) = origin(vec![host.into()]);
        let roots = if plain { RootCertStore::empty() } else { roots };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut relays = Relays::new(relay::tls_config(roots).unwrap(), Default::default(), true);
        relays.connector.peer = Some(listener.local_addr().unwrap());
        let mut cfg = Config {
            pool_size: 0,
            disable_secure: plain,
            cfproxy: true,
            cfproxy_h2_media: false,
            cfproxy_worker_domains: Some(vec!["worker.example.test".into()]),
            cfproxy_user_domains: Some(vec!["relay.example.test".into()]),
            ..Config::default()
        };
        cfg.normalize().unwrap();
        assert!(cfg.requires_go().is_empty());
        let server = tokio::spawn(async move {
            let origin = TlsAcceptor::from(Arc::new(server));
            let (socket, _) = listener.accept().await.unwrap();
            let socket = if plain {
                tokio_util::either::Either::Right(socket)
            } else {
                let tls = origin.accept(socket).await.unwrap();
                assert_eq!(tls.get_ref().1.server_name(), Some(host));
                tokio_util::either::Either::Left(tls)
            };
            #[allow(clippy::result_large_err)]
            let mut ws = accept_hdr_async(socket, |req: &Request, mut res: Response| {
                assert_eq!(req.headers()["Host"], host);
                assert_eq!(
                    req.uri().to_string(),
                    if worker {
                        "/apiws?dc=2&dst=149.154.167.40"
                    } else {
                        "/apiws"
                    }
                );
                res.headers_mut()
                    .insert("Sec-WebSocket-Protocol", "binary".parse().unwrap());
                Ok(res)
            })
            .await
            .unwrap();
            let head = ws.next().await.unwrap().unwrap().into_data();
            let (tag, dc, mut receive, mut send) =
                crypto::upstream_fixture(head.as_ref().try_into().unwrap());
            assert_eq!((tag, dc), (0xee, -2));
            let mut bytes = ws.next().await.unwrap().unwrap().into_data().to_vec();
            receive.apply_keystream(&mut bytes);
            assert_eq!(
                bytes,
                if worker {
                    b"x".to_vec()
                } else {
                    b"\x04\0\0\0test".to_vec()
                }
            );
            let mut answer = b"fixture reply".to_vec();
            send.apply_keystream(&mut answer);
            ws.send(Message::binary(answer)).await.unwrap();
            ws.close(None).await.unwrap();
        });
        let dc = if worker { -10002 } else { -2 };
        let (head, mut send, mut recv) = crypto::client_fixture(&[3; 16], dc, 0xee);
        let session = Transport::client(head, &[3; 16]).unwrap();
        let stats = Stats::default();
        assert!(relays
            .web(dc, true, &cfg, &stats, &session.init, |_| ())
            .await
            .is_none());
        let ws = if worker {
            relays
                .worker(dc, true, &cfg, &stats, &session.init, |_| ())
                .await
        } else {
            relays
                .web(dc, false, &cfg, &stats, &session.init, |_| ())
                .await
        }
        .unwrap();
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(local.local_addr().unwrap())
            .await
            .unwrap();
        let (socket, _) = local.accept().await.unwrap();
        let app = async {
            let mut bytes = if worker {
                b"x".to_vec()
            } else {
                b"\x04\0\0\0test".to_vec()
            };
            send.apply_keystream(&mut bytes);
            client.write_all(&bytes).await.unwrap();
            let mut answer = [0; 13];
            client.read_exact(&mut answer).await.unwrap();
            recv.apply_keystream(&mut answer);
            assert_eq!(&answer, b"fixture reply");
        };
        let (res, ()) = timeout(Duration::from_secs(3), async {
            let mode = if worker {
                relay::BridgeMode::LegacyWorker
            } else {
                relay::BridgeMode::Legacy
            };
            tokio::join!(
                relay::bridge_initialized(socket, ws, session, &stats, mode, None),
                app
            )
        })
        .await
        .unwrap();
        res.unwrap();
        server.await.unwrap();
        assert_eq!(stats.cf.load(Ordering::Relaxed), 1);
        assert_eq!(stats.cf_misses.load(Ordering::Relaxed), 0);
        relays.stop().await;
    }
}
#[tokio::test]
async fn configured_worker_uploads_one_masked_frame_for_each_bounded_raw_read() {
    use crate::tests::read_masked_frame;
    use tokio::sync::Semaphore;

    const HOST: &str = "worker.example.test";
    const LARGE: usize = 65_536;
    const SMALL: usize = 16_384;
    const TAIL: usize = 9;
    for admitted in [true, false] {
        let slots = Arc::new(Semaphore::new(1));
        let occupied = (!admitted).then(|| slots.try_acquire().unwrap());
        let read_limit = if admitted { LARGE } else { SMALL };
        let (roots, server) = origin(vec![HOST.into()]);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut relays = Relays::new(relay::tls_config(roots).unwrap(), Default::default(), true);
        relays.connector.peer = Some(listener.local_addr().unwrap());
        let mut cfg = Config {
            pool_size: 0,
            cfproxy_worker_domains: Some(vec![HOST.into()]),
            ..Config::default()
        };
        cfg.normalize().unwrap();

        let mut payload: Vec<_> = (0..LARGE + TAIL).map(|byte| (byte % 251) as u8).collect();
        // Arbitrary Worker bytes do not wait for a complete MTProto packet.
        payload[..4].copy_from_slice(&100_000u32.to_le_bytes());
        let mut ciphertext = payload.clone();
        let held = Arc::clone(&slots);
        let (init_read, peer_ready) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let tls = TlsAcceptor::from(Arc::new(server))
                .accept(socket)
                .await
                .unwrap();
            assert_eq!(tls.get_ref().1.server_name(), Some(HOST));
            #[allow(clippy::result_large_err)]
            let mut ws = accept_hdr_async(tls, |req: &Request, mut response: Response| {
                assert_eq!(req.headers()["Host"], HOST);
                assert_eq!(req.uri().to_string(), "/apiws?dc=2&dst=149.154.167.40");
                response
                    .headers_mut()
                    .insert("Sec-WebSocket-Protocol", "binary".parse().unwrap());
                Ok(response)
            })
            .await
            .unwrap();
            let init = ws.next().await.unwrap().unwrap().into_data();
            let (tag, dc, mut receive, _) =
                crypto::upstream_fixture(init.as_ref().try_into().unwrap());
            assert_eq!((tag, dc), (0xee, -2));
            let mut wire = ws.into_inner();
            init_read.send(()).unwrap();
            for chunk in payload.chunks(read_limit) {
                let (head, mut bytes) = timeout(
                    Duration::from_secs(1),
                    read_masked_frame(&mut wire, read_limit),
                )
                .await
                .expect("raw data frame is immediately available");
                assert_eq!(head, 0x82);
                receive.apply_keystream(&mut bytes);
                assert_eq!(bytes, chunk);
                assert_eq!(held.available_permits(), 0);
            }
            // Both data frames arrive before EOF. A status Close must still
            // relay its two bytes even with a bounded codec output buffer.
            wire.write_all(b"\x88\x05\x03\xe8bye").await.unwrap();
            wire.flush().await.unwrap();
            assert_eq!(
                timeout(Duration::from_secs(1), read_masked_frame(&mut wire, 2))
                    .await
                    .expect("the bounded codec flushes the verified Close"),
                (0x88, vec![3, 232])
            );
        });
        let key = [45; 16];
        let (init, mut encrypt, _) = crypto::client_fixture(&key, -10002, 0xee);
        let session = Transport::client(init, &key).unwrap();
        let stats = Stats::default();
        let ws = relays
            .worker(-10002, true, &cfg, &stats, &session.init, |_| ())
            .await
            .unwrap();
        timeout(Duration::from_secs(1), peer_ready)
            .await
            .unwrap()
            .unwrap();
        let (mut client, socket) = tokio::io::duplex(ciphertext.len());
        encrypt.apply_keystream(&mut ciphertext);
        client.write_all(&ciphertext).await.unwrap();
        timeout(Duration::from_secs(3), async {
            relay::bridge_with_frame_slots(
                socket,
                ws,
                session,
                &stats,
                relay::BridgeMode::LegacyWorker,
                None,
                &slots,
            )
            .await
            .unwrap();
            server.await.unwrap();
        })
        .await
        .unwrap();
        assert_eq!(stats.up.load(Ordering::Relaxed), (LARGE + TAIL) as u64);
        assert_eq!(stats.cf.load(Ordering::Relaxed), 1);
        assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
        assert_eq!(slots.available_permits(), usize::from(admitted));
        drop(occupied);
        relays.stop().await;
    }
}

#[tokio::test]
async fn cf_web_reports_one_decline_and_promotes_the_next_verified_origin() {
    const FIRST: &str = "first.catalog.example.test";
    const SECOND: &str = "second.catalog.example.test";
    const PACKET: &[u8] = b"\x04\0\0\0test";
    const DC: i16 = -2;
    for legacy in [true, false] {
        let (roots, server) = origin(vec![format!("kws2.{FIRST}"), format!("kws2.{SECOND}")]);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut cfg = Config {
            transport: if legacy {
                String::new()
            } else {
                "direct_wss".into()
            },
            pool_size: 0,
            cfproxy_user_domains: Some(vec![FIRST.into(), SECOND.into()]),
            ..Config::default()
        };
        cfg.normalize().unwrap();
        let mut pool = crate::pool::Pool::with_handshakes(
            0,
            relay::tls_config(roots).unwrap(),
            cfg.buffer_size,
            legacy,
            Default::default(),
        );
        pool.relays.connector.peer = Some(listener.local_addr().unwrap());
        pool.relays.catalog.promote(2, FIRST.into(), &cfg);
        let diagnostics = pool.capture_diagnostics();
        let stats = Stats::default();
        assert!(pool
            .relays
            .web(-10002, true, &cfg, &stats, &[0; 64], |event| pool
                .report_diagnostic(event))
            .await
            .is_none());

        let upstream = tokio::spawn(async move {
            let accept = TlsAcceptor::from(Arc::new(server));
            for (base, decline) in [(FIRST, true), (SECOND, false), (SECOND, false)] {
                let expected = format!("kws2.{base}");
                let tls = accept
                    .accept(listener.accept().await.unwrap().0)
                    .await
                    .unwrap();
                assert_eq!(tls.get_ref().1.server_name(), Some(expected.as_str()));
                #[allow(clippy::result_large_err)]
                let ws = accept_hdr_async(tls, |req: &Request, mut response: Response| {
                    assert_eq!(req.headers()["Host"], expected);
                    assert_eq!(req.uri().path(), "/apiws");
                    if decline {
                        return Err(http::Response::builder()
                            .status(503)
                            .header("X-Private", "untrusted.example.test")
                            .body(Some("untrusted response body".into()))
                            .unwrap());
                    }
                    response
                        .headers_mut()
                        .insert("Sec-WebSocket-Protocol", "binary".parse().unwrap());
                    Ok(response)
                })
                .await;
                if decline {
                    assert!(ws.is_err());
                    continue;
                }
                let mut ws = ws.unwrap();
                let init = ws.next().await.unwrap().unwrap().into_data();
                let (tag, dc, mut decrypt, _) =
                    crypto::upstream_fixture(init.as_ref().try_into().unwrap());
                assert_eq!((tag, dc), (0xee, DC));
                let mut data = ws.next().await.unwrap().unwrap().into_data().to_vec();
                decrypt.apply_keystream(&mut data);
                assert_eq!(data, PACKET);
                ws.close(None).await.unwrap();
            }
        });
        timeout(Duration::from_secs(4), async {
            for preferred in [FIRST, SECOND] {
                assert_eq!(pool.relays.catalog.ordered(2, &cfg)[0], preferred);
                let key = [42; 16];
                let (init, mut cipher, _) = crypto::client_fixture(&key, DC, 0xee);
                let session = Transport::client(init, &key).unwrap();
                let (mut client, stream) = tokio::io::duplex(64);
                let mut packet = PACKET.to_vec();
                cipher.apply_keystream(&mut packet);
                client.write_all(&packet).await.unwrap();
                let ws = pool
                    .relays
                    .web(DC, false, &cfg, &stats, &session.init, |event| {
                        pool.report_diagnostic(event)
                    })
                    .await
                    .unwrap();
                relay::bridge_initialized(
                    stream,
                    ws,
                    session,
                    &stats,
                    relay::BridgeMode::Legacy,
                    None,
                )
                .await
                .unwrap();
            }
            upstream.await.unwrap();
        })
        .await
        .unwrap();
        if legacy {
            assert_eq!(
                diagnostics.try_recv().unwrap(),
                Event::WebUpgradeRejected {
                    dc: DC,
                    status: 503
                }
            );
        }
        assert!(diagnostics.try_recv().is_err());
        assert_eq!(stats.cf.load(Ordering::Relaxed), 2);
        assert_eq!(stats.up.load(Ordering::Relaxed), 2 * PACKET.len() as u64);
    }
}

#[tokio::test]
async fn foreground_worker_reports_http_decline_and_still_relays_on_next_origin() {
    use crate::diagnostics::Event;

    const FIRST: &str = "first.worker.example.test";
    const SECOND: &str = "second.worker.example.test";
    const PAYLOAD: &[u8] = b"worker raw bytes";
    for (legacy, test, dc, status) in [
        (true, false, -2, 429),
        (true, true, -10002, 403),
        (false, false, -2, 429),
    ] {
        let (roots, server) = origin(vec![FIRST.into(), SECOND.into()]);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut cfg = Config {
            pool_size: 0,
            cfproxy_worker_domains: Some(vec![FIRST.into(), SECOND.into()]),
            ..Config::default()
        };
        cfg.normalize().unwrap();
        let mut pool = crate::pool::Pool::with_handshakes(
            0,
            relay::tls_config(roots).unwrap(),
            cfg.buffer_size,
            legacy,
            Default::default(),
        );
        pool.relays.connector.peer = Some(listener.local_addr().unwrap());
        let diagnostics = pool.capture_diagnostics();
        let peers = tokio::spawn(async move {
            let accept = TlsAcceptor::from(Arc::new(server));
            let mut tried = Vec::new();
            for decline in [true, false] {
                let tls = accept
                    .accept(listener.accept().await.unwrap().0)
                    .await
                    .unwrap();
                let name = tls.get_ref().1.server_name().unwrap().to_owned();
                assert!(matches!(name.as_str(), FIRST | SECOND));
                assert!(!tried.contains(&name));
                let dst = if test {
                    "149.154.167.40"
                } else {
                    "149.154.167.51"
                };
                #[allow(clippy::result_large_err)]
                let ws = accept_hdr_async(tls, |req: &Request, mut res: Response| {
                    assert_eq!(req.headers()["Host"], name);
                    assert_eq!(req.uri().to_string(), format!("/apiws?dc=2&dst={dst}"));
                    if decline {
                        return Err(http::Response::builder()
                            .status(status)
                            .header("Location", "https://unrelated.example.test/")
                            .body(Some("untrusted body".into()))
                            .unwrap());
                    }
                    res.headers_mut()
                        .insert("Sec-WebSocket-Protocol", "binary".parse().unwrap());
                    Ok(res)
                })
                .await;
                tried.push(name);
                if decline {
                    assert!(ws.is_err());
                    continue;
                }
                let mut ws = ws.unwrap();
                let init = ws.next().await.unwrap().unwrap().into_data();
                let (tag, dc, mut decrypt, _) =
                    crypto::upstream_fixture(init.as_ref().try_into().unwrap());
                assert_eq!((tag, dc), (0xee, -2));
                let mut received = ws.next().await.unwrap().unwrap().into_data().to_vec();
                decrypt.apply_keystream(&mut received);
                assert_eq!(received, PAYLOAD);
                ws.close(None).await.unwrap();
            }
        });
        let key = [41; 16];
        let (init, mut encrypt, _) = crypto::client_fixture(&key, dc, 0xee);
        let session = Transport::client(init, &key).unwrap();
        let mut bytes = PAYLOAD.to_vec();
        encrypt.apply_keystream(&mut bytes);
        let (mut client, stream) = tokio::io::duplex(64);
        client.write_all(&bytes).await.unwrap();
        let stats = Stats::default();
        timeout(Duration::from_secs(4), async {
            let ws = pool
                .relays
                .worker(dc, test, &cfg, &stats, &session.init, |event| {
                    pool.report_diagnostic(event)
                })
                .await
                .unwrap();
            relay::bridge_initialized(
                stream,
                ws,
                session,
                &stats,
                relay::BridgeMode::LegacyWorker,
                None,
            )
            .await
            .unwrap();
            peers.await.unwrap();
        })
        .await
        .unwrap();
        if legacy {
            assert_eq!(
                diagnostics.try_recv().unwrap(),
                Event::WorkerUpgradeRejected { dc, test, status }
            );
        }
        assert!(diagnostics.try_recv().is_err());
        assert_eq!(stats.cf.load(Ordering::Relaxed), 1);
        assert_eq!(stats.up.load(Ordering::Relaxed), PAYLOAD.len() as u64);
    }
}

#[tokio::test]
async fn worker_failure_after_relay_init_does_not_report_fallback_exhaustion() {
    let (roots, _) = origin(vec!["worker.example.test".into()]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cfg = Config {
        cfproxy: false,
        disable_secure: true,
        cfproxy_worker_domains: Some(vec!["worker.example.test".into()]),
        pool_size: 0,
        ..Config::default()
    };
    let mut pool = crate::pool::Pool::legacy(0, relay::tls_config(roots).unwrap(), cfg.buffer_size);
    pool.relays.connector.peer = Some(listener.local_addr().unwrap());
    let diagnostics = pool.capture_diagnostics();
    let (init, _, _) = crypto::client_fixture(&[3; 16], -10002, 0xee);
    let session = Transport::client(init, &[3; 16]).unwrap();
    let (_client, stream) = tokio::io::duplex(1024);
    let stats = Stats::default();
    let worker = async {
        let (tcp, _) = listener.accept().await.unwrap();
        #[allow(clippy::result_large_err)]
        let mut ws = accept_hdr_async(tcp, |_: &Request, mut response: Response| {
            response
                .headers_mut()
                .insert("Sec-WebSocket-Protocol", "binary".parse().unwrap());
            Ok(response)
        })
        .await
        .unwrap();
        assert_eq!(ws.next().await.unwrap().unwrap().into_data().len(), 64);
        // End an established bridge via a transport error.
        drop(ws);
    };
    let (result, ()) = timeout(Duration::from_secs(3), async {
        tokio::join!(
            crate::legacy::fallback(stream, session, &cfg, &pool, &stats),
            worker
        )
    })
    .await
    .unwrap();
    assert!(result.is_err());
    assert_eq!(stats.cf.load(Ordering::Relaxed), 1);
    assert!(matches!(
        diagnostics.try_recv().unwrap(),
        crate::diagnostics::Event::WsSessionClosed(crate::diagnostics::WsSessionClosed {
            end: crate::diagnostics::WsEnd::Flow(crate::diagnostics::WsLeg::UpstreamRead, _),
            ..
        })
    ));
    assert!(diagnostics.try_recv().is_err());
}

#[tokio::test]
async fn configured_wss_certificate_error_never_retries_over_plaintext() {
    let (roots, cert) = origin(vec!["different.example".into()]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut relays = Relays::new(relay::tls_config(roots).unwrap(), Default::default(), true);
    relays.connector.peer = Some(listener.local_addr().unwrap());
    let cfg = Config {
        cfproxy: false,
        cfproxy_worker_domains: Some(vec!["worker.example".into()]),
        pool_size: 0,
        ..Config::default()
    };
    let serve = async {
        let (tcp, _) = listener.accept().await.unwrap();
        assert!(TlsAcceptor::from(Arc::new(cert)).accept(tcp).await.is_err());
        assert!(timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err());
    };
    let stats = Stats::default();
    let cfg = Config {
        pool_size: 0,
        ..cfg
    };
    let (_, ws) = tokio::join!(
        serve,
        relays.worker(2, false, &cfg, &stats, &[0; 64], |_| ())
    );
    assert!(ws.is_none());
    assert_eq!(stats.cf_misses.load(Ordering::Relaxed), 1);
    assert!(relays.workers.lock().unwrap().is_empty());
}
#[tokio::test]
async fn catalog_uses_plain_websocket_only_on_explicit_request_and_skips_test_dc_and_h2() {
    let domains = ["one.test", "two.test", "three.test"];
    let names = domains.map(|d| format!("kws2.{d}"));
    for plain in [true, false] {
        let (roots, server) = origin(names.to_vec());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut relays = Relays::new(relay::tls_config(roots).unwrap(), Default::default(), true);
        relays.connector.peer = Some(listener.local_addr().unwrap());
        relays.catalog.fixture(domains.join("\n").as_bytes());
        let mut cfg = Config {
            cfproxy: true,
            disable_secure: plain,
            pool_size: 0,
            ..Config::default()
        };
        cfg.normalize().unwrap();
        assert!(cfg.requires_go().is_empty() && cfg.uses_upstream_catalog());
        assert_eq!(cfg.h2_media(), !plain);
        let stats = Stats::default();
        let (head, _, _) = crypto::client_fixture(&[3; 16], 2, 0xee);
        let init = Transport::client(head, &[3; 16]).unwrap().init;
        assert!(relays
            .web(10002, true, &cfg, &stats, &init, |_| ())
            .await
            .is_none());
        if plain {
            assert!(relays.media(-2, &cfg, &stats).await.is_none());
        }
        let names = names.clone();
        let handle = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let sock = if plain {
                tokio_util::either::Either::Right(tcp)
            } else {
                let tls = TlsAcceptor::from(Arc::new(server))
                    .accept(tcp)
                    .await
                    .unwrap();
                assert!(names
                    .iter()
                    .any(|n| Some(n.as_str()) == tls.get_ref().1.server_name()));
                tokio_util::either::Either::Left(tls)
            };
            #[allow(clippy::result_large_err)]
            let mut ws = accept_hdr_async(sock, |req: &Request, mut res: Response| {
                assert!(names.iter().any(|n| n.as_str() == req.headers()["Host"]));
                assert_eq!(req.uri().path(), "/apiws");
                res.headers_mut()
                    .insert("Sec-WebSocket-Protocol", "binary".parse().unwrap());
                Ok(res)
            })
            .await
            .unwrap();
            assert_eq!(
                ws.next().await.unwrap().unwrap().into_data().as_ref(),
                &init
            );
        });
        timeout(Duration::from_secs(3), async {
            assert!(relays
                .web(2, false, &cfg, &stats, &init, |_| ())
                .await
                .is_some());
            handle.await.unwrap();
        })
        .await
        .unwrap();
        assert_eq!(stats.cf.load(Ordering::Relaxed), 1);
        relays.stop().await;
    }
}
