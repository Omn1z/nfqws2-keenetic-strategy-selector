use super::*;
use crate::tests::test_tls;
use tokio::{net::TcpListener, sync::mpsc, time::advance};
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::{
        handshake::server::{Request, Response},
        protocol::Role,
    },
};

#[test]
fn legacy_refill_waits_for_the_batch_and_only_penalizes_unavailable_routes() {
    use std::io::ErrorKind;
    let mut refill = Refill::default();
    let now = Instant::now();
    let one = Duration::from_secs(1);
    assert!(refill.begin(3, now));
    assert_eq!(
        refill.complete(Some(Err(ErrorKind::ConnectionRefused)), now),
        None
    );
    assert_eq!(refill.complete(Some(Err(ErrorKind::WouldBlock)), now), None);
    assert!(!refill.begin(3, now));
    assert_eq!(refill.failures, 0);
    assert_eq!(
        refill.complete(Some(Err(ErrorKind::WouldBlock)), now),
        Some(RefillDiagnostic::NetworkFailure(1))
    );
    assert_eq!(refill.failures, 1);
    assert!(!refill.begin(3, now));

    assert!(refill.begin(2, now + one));
    assert_eq!(
        refill.complete(Some(Err(ErrorKind::WouldBlock)), now + one),
        None
    );
    assert_eq!(refill.complete(None, now + one), None);
    assert_eq!(refill.failures, 1);
    assert_eq!(refill.retry_at, Some(now + 2 * one));

    assert!(refill.begin(2, now + 2 * one));
    assert_eq!(
        refill.complete(Some(Err(ErrorKind::ConnectionRefused)), now + 2 * one),
        None
    );
    assert_eq!(
        refill.complete(Some(Err(ErrorKind::TimedOut)), now + 2 * one),
        Some(RefillDiagnostic::NetworkFailure(2))
    );
    assert_eq!(refill.failures, 2);
    assert_eq!(refill.retry_at, Some(now + 4 * one));

    assert!(refill.begin(2, now + 4 * one));
    assert_eq!(
        refill.complete(Some(Err(ErrorKind::ConnectionRefused)), now + 4 * one),
        None
    );
    assert_eq!(refill.complete(Some(Ok(())), now + 4 * one), None);
    assert_eq!(refill.failures, 0);
    assert!(refill.retry_at.is_none());
    assert!(refill.begin(2, now + 4 * one));
}

#[test]
fn refill_event_requires_a_whole_failed_batch() {
    use std::{io::ErrorKind, sync::mpsc::sync_channel};
    for first in [
        None,
        Some(Ok(())),
        Some(Err(ErrorKind::WouldBlock)),
        Some(Err(ErrorKind::TimedOut)),
    ] {
        let refill = Arc::new(Mutex::new(Refill::default()));
        assert!(refill.lock().unwrap().begin(2, Instant::now()));
        let (send, receive) = sync_channel(2);
        let mut first_attempt = Attempt::new(Some(refill.clone()), Some(send.clone()), -10_002);
        first_attempt.complete(first);
        assert!(receive.try_recv().is_err());
        let mut last = Attempt::new(Some(refill), Some(send), -10_002);
        last.complete(Some(Err(ErrorKind::TimedOut)));
        assert_eq!(
            receive.try_recv().ok(),
            first
                .is_some_and(|item| item.is_err())
                .then_some(Event::Refill {
                    dc: -10_002,
                    seconds: 1
                })
        );
        assert!(receive.try_recv().is_err());
    }
}

#[tokio::test(start_paused = true)]
async fn legacy_refill_reports_setup_capacity_once_per_whole_queue_only_cycle() {
    use std::{io::ErrorKind, sync::mpsc::sync_channel};
    let refill = Arc::new(Mutex::new(Refill::default()));
    let (send, receive) = sync_channel(2);
    let one = Duration::from_secs(1);
    for _ in 0..2 {
        let now = Instant::now();
        assert!(refill.lock().unwrap().begin(2, now));
        let mut first = Attempt::new(Some(refill.clone()), Some(send.clone()), -10_002);
        first.complete(Some(Err(ErrorKind::WouldBlock)));
        assert!(receive.try_recv().is_err());
        let mut last = Attempt::new(Some(refill.clone()), Some(send.clone()), -10_002);
        last.complete(Some(Err(ErrorKind::WouldBlock)));
        assert_eq!(
            receive.try_recv().unwrap(),
            Event::RefillCapacity { dc: -10_002 }
        );
        assert!(receive.try_recv().is_err());
        {
            let state = refill.lock().unwrap();
            assert_eq!(state.retry_at, Some(now + one));
            assert_eq!(state.failures, 0);
        }
        advance(one).await;
    }
    assert!(receive.try_recv().is_err());
}

// Local socket readiness must not cause Tokio's paused clock to jump to a timer.
async fn poll_with_clock_frozen<F: std::future::Future>(future: F) -> F::Output {
    tokio::pin!(future);
    let limit = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        assert!(
            std::time::Instant::now() < limit,
            "fixture did not make progress"
        );
        tokio::select! {
            biased;
            result = &mut future => return result,
            _ = tokio::task::yield_now() => {}
        }
    }
}

#[tokio::test(start_paused = true)]
async fn legacy_refill_retries_at_its_deadline_between_periodic_ticks() {
    use futures_util::FutureExt;
    let (roots, tls) = test_tls();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = Endpoint {
        peer: Peer::Direct(listener.local_addr().unwrap()),
        managed: false,
        host: "telegram.test".into(),
        path: "/apiws",
    };
    let pool = Arc::new(Pool::legacy(1, relay::tls_config(roots).unwrap(), 8192));
    let start = Instant::now();
    let maintenance = {
        let pool = pool.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = interval.tick() => pool.maintain(),
                    _ = pool.wait_for_refill_retry() => pool.maintain(),
                }
            }
        })
    };
    pool.warm(2, endpoint);
    let (failed, _) = poll_with_clock_frozen(listener.accept()).await.unwrap();
    advance(Duration::from_millis(230)).await;
    drop(failed);
    let retry = poll_with_clock_frozen(async {
        loop {
            if let Some(deadline) = pool.next_refill_retry() {
                return deadline;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert_eq!(retry, start + Duration::from_millis(1230));

    advance(Duration::from_millis(999)).await;
    assert!(listener.accept().now_or_never().is_none());
    advance(Duration::from_millis(1)).await;
    let (tcp, _) = poll_with_clock_frozen(listener.accept()).await.unwrap();
    assert_eq!(Instant::now(), retry);
    let _peer = poll_with_clock_frozen(async {
        let secure = tls.accept(tcp).await.unwrap();
        #[allow(clippy::result_large_err)]
        accept_hdr_async(secure, |_: &Request, mut reply: Response| {
            reply
                .headers_mut()
                .insert("Sec-WebSocket-Protocol", "binary".parse().unwrap());
            Ok(reply)
        })
        .await
        .unwrap()
    })
    .await;
    poll_with_clock_frozen(async {
        while !pool
            .slots
            .lock()
            .unwrap()
            .iter()
            .any(|slot| slot.ready.load(Ordering::Acquire))
        {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(pool.next_refill_retry().is_none());
    maintenance.abort();
    let _ = maintenance.await;
    pool.stop().await;
}

#[tokio::test(start_paused = true)]
async fn legacy_retry_deadline_ignores_active_full_and_retired_routes() {
    use futures_util::FutureExt;
    let (roots, _) = test_tls();
    let mut pool = Pool::legacy(1, relay::tls_config(roots).unwrap(), 8192);
    pool.capacity = 2;
    let now = Instant::now();
    let early = now + Duration::from_millis(250);
    let late = now + Duration::from_secs(1);
    let vpn = Endpoint {
        peer: Peer::Vpn {
            target: Telegram::web(1, false).unwrap(),
            iface: "awg1".into(),
            broker: "unused-fixture".into(),
        },
        managed: false,
        host: "telegram.test".into(),
        path: "/apiws",
    };
    let direct = Endpoint {
        peer: Peer::Direct("127.0.0.1:1".parse().unwrap()),
        ..vpn.clone()
    };
    let insert = |dc, endpoint, retry_at| {
        let refill = Arc::new(Mutex::new(Refill {
            retry_at: Some(retry_at),
            wake: Some(pool.refill_wake.clone()),
            ..Default::default()
        }));
        pool.routes.lock().unwrap().insert(
            dc,
            Route {
                endpoint,
                refill: Some(refill.clone()),
            },
        );
        refill
    };
    let retired = insert(1, vpn.clone(), early);
    insert(2, direct, late);
    assert_eq!(pool.next_refill_retry(), Some(early));
    retired.lock().unwrap().pending = 1;
    assert_eq!(pool.next_refill_retry(), Some(late));
    retired.lock().unwrap().pending = 0;

    pool.slots.lock().unwrap().push(Slot {
        dc: 1,
        endpoint: vpn,
        ready: Arc::new(AtomicBool::new(true)),
        checkout: None,
        task: tokio::spawn(std::future::pending()),
    });
    assert_eq!(pool.next_refill_retry(), Some(late));
    pool.capacity = 1;
    assert!(pool.next_refill_retry().is_none());
    assert!(pool.wait_for_refill_retry().now_or_never().is_none());
    pool.forget_vpn(1);
    assert_eq!(pool.next_refill_retry(), Some(late));
    advance(early - now).await;
    assert!(pool.wait_for_refill_retry().now_or_never().is_none());
    advance(late - early).await;
    assert_eq!(pool.wait_for_refill_retry().now_or_never(), Some(()));
}

#[tokio::test]
async fn cold_or_switched_vpn_returns_immediately_and_queues_only_the_selected_route() {
    use futures_util::FutureExt;
    let (roots, _) = test_tls();
    let pool = Pool::legacy(1, relay::tls_config(roots).unwrap(), 8192);
    // Hold every setup permit: a request waiting for a VPN dial can never finish.
    let _pending = pool.dials.acquire_many(4).await.unwrap();
    let route = |iface: &str| Endpoint {
        peer: Peer::Vpn {
            target: Telegram::web(1, false).unwrap(),
            iface: iface.into(),
            broker: "fixture-broker".into(),
        },
        managed: false,
        host: "kws1.web.telegram.org".into(),
        path: "/apiws",
    };
    let stats = Stats::default();
    assert!(matches!(
        pool.take_route(1, route("awg1"), &stats).now_or_never(),
        Some(None)
    ));
    // Even a ready slot may not be claimed after a profile switch.
    {
        let slots = pool.slots.lock().unwrap();
        assert_eq!(slots.len(), 1);
        slots[0].ready.store(true, Ordering::Release);
    }
    assert!(matches!(
        pool.take_route(1, route("awg2"), &stats).now_or_never(),
        Some(None)
    ));
    {
        let slots = pool.slots.lock().unwrap();
        assert_eq!(slots.len(), 1);
        assert!(slots[0].endpoint == route("awg2"));
    }
    assert_eq!(stats.pool_misses.load(Ordering::Relaxed), 2);
    assert_eq!(stats.pool_hits.load(Ordering::Relaxed), 0);
    pool.forget_vpn(1);
    pool.maintain();
    assert!(pool.slots.lock().unwrap().is_empty());
    pool.stop().await;
}

#[tokio::test]
async fn legacy_media_pool_retries_ordinary_hostname_on_the_same_route_and_test_path() {
    let media = "kws2-1.web.telegram.org";
    let ordinary = "kws2.web.telegram.org";
    let front = "sprinthost.ru";
    let (roots, server) =
        crate::configured::tests::origin(vec![media.into(), ordinary.into(), front.into()]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let route = Endpoint {
        peer: Peer::Direct(addr),
        managed: false,
        host: media.into(),
        path: "/apiws_test",
    };
    let stats = Arc::new(Stats::default());
    let mut pool = Pool::legacy(1, relay::tls_config(roots.clone()).unwrap(), 8192);
    pool.direct.identities(roots, Some(stats.clone())).unwrap();
    let upstream = tokio::spawn(async move {
        let accept = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        for (host, sni, success) in [
            (media, media, false),
            (media, front, false),
            (ordinary, ordinary, false),
            (ordinary, front, true),
        ] {
            let tls = accept
                .accept(listener.accept().await.unwrap().0)
                .await
                .unwrap();
            assert_eq!(tls.get_ref().1.server_name(), Some(sni));
            #[allow(clippy::result_large_err)]
            let result = accept_hdr_async(tls, |req: &Request, res: Response| {
                assert_eq!(req.headers()["Host"], host);
                assert_eq!(req.uri().path(), "/apiws_test");
                if success {
                    Ok(res)
                } else {
                    Err(http::Response::builder().status(403).body(None).unwrap())
                }
            })
            .await;
            if success {
                let mut ws = result.unwrap();
                assert_eq!(
                    ws.next().await.unwrap().unwrap(),
                    Message::binary(b"media".as_slice())
                );
                return;
            }
            assert!(result.is_err());
        }
    });
    timeout(Duration::from_secs(4), async {
        pool.warm(-10002, route.clone());
        while !pool
            .slots
            .lock()
            .unwrap()
            .iter()
            .any(|s| s.ready.load(Ordering::Acquire))
        {
            tokio::task::yield_now().await;
        }
        let mut ws = pool.take_route(-10002, route, &stats).await.unwrap();
        ws.send(Message::binary(b"media".as_slice())).await.unwrap();
        upstream.await.unwrap();
    })
    .await
    .unwrap();
    pool.stop().await;
    assert_eq!(stats.pool_hits.load(Ordering::Relaxed), 1);
    assert_eq!(stats.fronting.load(Ordering::Relaxed), 1);
}

#[tokio::test(start_paused = true)]
async fn unused_sockets_answer_pings_require_pongs_and_expire_at_two_minutes() {
    for acknowledge in [false, true] {
        let (client, server) = tokio::io::duplex(1024);
        let ws = WebSocketStream::from_raw_socket(
            Wire::after_upgrade(tokio::io::BufReader::new(client)),
            Role::Client,
            None,
        )
        .await;
        let mut peer = WebSocketStream::from_raw_socket(server, Role::Server, None).await;
        let ready = Arc::new(AtomicBool::new(false));
        let (_send, mut recv) = oneshot::channel();
        let owned = ready.clone();
        let job = tokio::spawn(async move { idle(ws, &owned, &mut recv, true).await });
        tokio::task::yield_now().await;
        assert!(ready.load(Ordering::Acquire));
        peer.send(Message::Ping(b"test".as_slice().into()))
            .await
            .unwrap();
        assert_eq!(
            peer.next().await.unwrap().unwrap(),
            Message::Pong(b"test".as_slice().into())
        );
        advance(Duration::from_secs(25)).await;
        assert_eq!(
            peer.next().await.unwrap().unwrap(),
            Message::Ping(b"tgws".as_slice().into())
        );
        assert!(!ready.load(Ordering::Acquire));
        if acknowledge {
            peer.flush().await.unwrap();
            tokio::task::yield_now().await;
            assert!(ready.load(Ordering::Acquire));
            advance(Duration::from_secs(95)).await;
        } else {
            advance(Duration::from_secs(10)).await;
        }
        assert!(job.await.unwrap().is_none());
    }
}

#[tokio::test(start_paused = true)]
async fn legacy_idle_keeps_quiet_healthy_sockets_and_detects_remote_close() {
    use futures_util::FutureExt;
    for remote_close in [false, true] {
        let (client, server) = tokio::io::duplex(1024);
        let ws = WebSocketStream::from_raw_socket(
            Wire::after_upgrade(tokio::io::BufReader::new(client)),
            Role::Client,
            None,
        )
        .await;
        let mut peer = WebSocketStream::from_raw_socket(server, Role::Server, None).await;
        let (send, mut recv) = oneshot::channel();
        let ready = Arc::new(AtomicBool::new(false));
        let worker_ready = ready.clone();
        let task = tokio::spawn(async move { idle(ws, &worker_ready, &mut recv, false).await });
        tokio::task::yield_now().await;
        advance(Duration::from_secs(95)).await;
        assert!(peer.next().now_or_never().is_none());
        assert!(ready.load(Ordering::Acquire));
        if remote_close {
            peer.close(None).await.unwrap();
        }
        send.send(()).unwrap();
        assert_eq!(task.await.unwrap().is_none(), remote_close);
    }
}

#[tokio::test]
async fn legacy_idle_checkout_preserves_data_and_ping_before_first_active_read() {
    for ping in [false, true] {
        let (client, server) = tokio::io::duplex(1024);
        let ws = WebSocketStream::from_raw_socket(
            Wire::after_upgrade(tokio::io::BufReader::new(client)),
            Role::Client,
            None,
        )
        .await;
        let mut peer = WebSocketStream::from_raw_socket(server, Role::Server, None).await;
        if ping {
            peer.send(Message::Ping(b"ping".as_slice().into()))
                .await
                .unwrap();
        }
        peer.send(Message::binary(b"ready".as_slice()))
            .await
            .unwrap();
        let (send, mut recv) = oneshot::channel();
        let ready = Arc::new(AtomicBool::new(false));
        let flag = ready.clone();
        let job = tokio::spawn(async move { idle(ws, &flag, &mut recv, false).await });
        while !ready.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        tokio::task::yield_now().await;
        send.send(()).unwrap();
        let mut ws = job
            .await
            .unwrap()
            .expect("idle data caused a healthy WebSocket to be discarded");
        if ping {
            assert_eq!(
                ws.next().await.unwrap().unwrap(),
                Message::Ping(b"ping".as_slice().into())
            );
        }
        assert_eq!(
            ws.next().await.unwrap().unwrap(),
            Message::binary(b"ready".as_slice())
        );
    }
}

#[tokio::test(start_paused = true)]
async fn legacy_idle_rejects_truncated_header_at_checkout() {
    use tokio::io::AsyncWriteExt;
    let (client, mut peer) = tokio::io::duplex(1024);
    let ws = WebSocketStream::from_raw_socket(
        Wire::after_upgrade(tokio::io::BufReader::new(client)),
        Role::Client,
        None,
    )
    .await;
    peer.write_all(&[0x82]).await.unwrap();
    peer.shutdown().await.unwrap();
    let (send, mut recv) = oneshot::channel();
    send.send(()).unwrap();
    assert!(idle(ws, &AtomicBool::new(false), &mut recv, false)
        .await
        .is_none());
}

#[tokio::test(start_paused = true)]
async fn legacy_idle_checkout_preserves_pending_header_byte_after_probe() {
    use tokio::io::AsyncWriteExt;
    let (client, mut peer) = tokio::io::duplex(1024);
    let ws = WebSocketStream::from_raw_socket(
        Wire::after_upgrade(tokio::io::BufReader::new(client)),
        Role::Client,
        None,
    )
    .await;
    peer.write_all(&[0x82]).await.unwrap();
    let (send, mut recv) = oneshot::channel();
    send.send(()).unwrap();
    let before = Instant::now();
    let mut ws = idle(ws, &AtomicBool::new(false), &mut recv, false)
        .await
        .expect("a quiet partial header is still healthy");
    assert!(before.elapsed() >= LEGACY_IDLE_PROBE);
    peer.write_all(b"\x04body").await.unwrap();
    assert_eq!(
        ws.next().await.unwrap().unwrap(),
        Message::binary(b"body".as_slice())
    );
}

#[tokio::test]
async fn pinned_legacy_websocket_reserves_with_go_socket_defaults() {
    const HOST: &str = "kws2.web.telegram.org";
    const WARM_BUFFER: i64 = 16 * 1024;
    let (roots, server) = crate::configured::tests::origin(vec![HOST.into()]);
    let server = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    for legacy in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = listener.local_addr().unwrap();
        let baseline = TcpStream::connect(peer).await.unwrap();
        let _baseline_peer = listener.accept().await.unwrap();
        relay::configure_socket(&baseline, if legacy { WARM_BUFFER } else { 8192 });
        let baseline = socket2::SockRef::from(&baseline);
        let mut pool = Pool::with_handshakes(
            1,
            relay::tls_config(roots.clone()).unwrap(),
            WARM_BUFFER,
            legacy,
            Default::default(),
        );
        pool.direct.identities(roots.clone(), None).unwrap();
        let endpoint = Endpoint {
            managed: true,
            peer: Peer::Direct(peer),
            host: HOST.into(),
            path: "/apiws",
        };
        let stats = Stats::default();
        let upstream = async {
            let (tcp, _) = listener.accept().await.unwrap();
            let secure = server.accept(tcp).await.unwrap();
            assert_eq!(secure.get_ref().1.server_name(), Some(HOST));
            #[allow(clippy::result_large_err)]
            let ws = accept_hdr_async(secure, |req: &Request, res: Response| {
                assert_eq!(req.headers()["Host"], HOST);
                assert_eq!(req.uri().path(), "/apiws");
                Ok(res)
            });
            ws.await.unwrap()
        };
        let checkout = async {
            pool.warm(2, endpoint.clone());
            while !pool.slots.lock().unwrap()[0].ready.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
            pool.take(2, &stats).await.unwrap()
        };
        let ((ws, route), _upstream) = timeout(Duration::from_secs(3), async {
            tokio::join!(checkout, upstream)
        })
        .await
        .unwrap();
        assert!(route == endpoint);
        let tcp = nfqws2_tgws_transport::socket(&ws);
        assert_eq!(tcp.peer_addr().unwrap(), peer);
        assert!(tcp.nodelay().unwrap());
        let socket = socket2::SockRef::from(tcp);
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
        pool.stop().await;
    }
}

#[tokio::test]
async fn direct_pool_checks_out_matching_unused_tls_sockets_only_once() {
    let (roots, server) = test_tls();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = Endpoint {
        managed: false,
        peer: Peer::Direct(listener.local_addr().unwrap()),
        host: "telegram.test".into(),
        path: "/apiws",
    };
    let (send, mut accepted) = mpsc::channel(4);
    let listener_task = tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let secure = server.accept(tcp).await.unwrap();
            #[allow(clippy::result_large_err)]
            let ws = accept_hdr_async(secure, |req: &Request, mut res: Response| {
                assert_eq!(req.headers()["Host"], "telegram.test");
                assert_eq!(req.uri().path(), "/apiws");
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
    let stats = Stats::default();
    let pool = Pool::new(1, relay::tls_config(roots).unwrap(), 8192);
    pool.warm(2, endpoint.clone());
    let mut first = timeout(Duration::from_secs(3), accepted.recv())
        .await
        .unwrap()
        .unwrap();
    first
        .send(Message::Ping(b"1".as_slice().into()))
        .await
        .unwrap();
    assert_eq!(
        first.next().await.unwrap().unwrap(),
        Message::Pong(b"1".as_slice().into())
    );
    assert!(pool.take(-2, &stats).await.is_none());
    assert!(pool.take(10002, &stats).await.is_none());
    let (mut client, route) = pool.take(2, &stats).await.unwrap();
    assert!(route == endpoint);
    client.send(Message::binary(vec![42])).await.unwrap();
    assert_eq!(
        first.next().await.unwrap().unwrap(),
        Message::binary(vec![42])
    );
    assert!(pool.take(2, &stats).await.is_none());
    pool.warm(2, endpoint.clone());
    let mut next = timeout(Duration::from_secs(3), accepted.recv())
        .await
        .unwrap()
        .unwrap();
    next.close(None).await.unwrap();
    timeout(Duration::from_secs(3), async {
        while !pool.slots.lock().unwrap()[0].task.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(pool.take(2, &stats).await.is_none());
    assert_eq!(stats.json()["ws"]["pool_hits"], 1);
    assert_eq!(stats.json()["ws"]["pool_misses"], 4);
    pool.stop().await;
    listener_task.abort();
}

#[tokio::test]
async fn zero_pool_is_lazy_and_stop_aborts_queued_and_inflight_tls_dials() {
    let (roots, _) = test_tls();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let route = Endpoint {
        managed: false,
        peer: Peer::Direct(listener.local_addr().unwrap()),
        host: "telegram.test".into(),
        path: "/apiws_test",
    };
    let tls = relay::tls_config(roots).unwrap();
    let disabled = Pool::new(0, tls.clone(), 8192);
    disabled.warm(10002, route.clone());
    let stats = Stats::default();
    assert!(disabled.take(10002, &stats).await.is_none());
    assert_eq!(stats.json()["ws"]["pool_misses"], 0);
    assert!(timeout(Duration::from_millis(30), listener.accept())
        .await
        .is_err());
    let pool = Pool::new(16, tls, 8192);
    pool.warm(10002, route.clone());
    let _first = timeout(Duration::from_secs(2), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let _second = timeout(Duration::from_secs(2), listener.accept())
        .await
        .unwrap()
        .unwrap();
    assert!(timeout(Duration::from_millis(30), listener.accept())
        .await
        .is_err());
    pool.warm(-2, route);
    {
        let slots = pool.slots.lock().unwrap();
        assert_eq!(slots.len(), 16);
        assert_eq!(slots.iter().filter(|slot| slot.dc == -2).count(), 1);
    }
    timeout(Duration::from_secs(2), pool.stop()).await.unwrap();
    assert!(pool.slots.lock().unwrap().is_empty());
}

#[tokio::test]
async fn legacy_reserves_each_dc_and_replenishes_closed_sessions_without_a_caller() {
    let (roots, server) = test_tls();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let route = Endpoint {
        managed: false,
        peer: Peer::Direct(listener.local_addr().unwrap()),
        host: "telegram.test".into(),
        path: "/apiws",
    };
    let (out, mut accepted) = mpsc::channel(8);
    let task = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let stream = server.accept(socket).await.unwrap();
            #[allow(clippy::result_large_err)]
            let ws = accept_hdr_async(stream, |_: &Request, mut res: Response| {
                res.headers_mut()
                    .insert("Sec-WebSocket-Protocol", "binary".parse().unwrap());
                Ok(res)
            })
            .await
            .unwrap();
            if out.send(ws).await.is_err() {
                break;
            }
        }
    });
    let pool = Pool::legacy(2, relay::tls_config(roots).unwrap(), 8192);
    pool.warm(2, route.clone());
    pool.warm(-2, route.clone());
    pool.warm(2, route);
    let mut connections = vec![];
    for _ in 0..4 {
        connections.push(
            timeout(Duration::from_secs(3), accepted.recv())
                .await
                .unwrap()
                .unwrap(),
        );
    }
    assert_eq!(pool.slots.lock().unwrap().len(), 4);
    // The server's final 101 may still be queued on the client socket.
    // Confirm that both route batches completed before observing idle rotation.
    timeout(Duration::from_secs(3), async {
        while !pool
            .slots
            .lock()
            .unwrap()
            .iter()
            .all(|slot| slot.ready.load(Ordering::Acquire))
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    connections[0].close(None).await.unwrap();
    let _replacement = timeout(Duration::from_secs(5), accepted.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pool.slots.lock().unwrap().len(), 4);
    pool.stop().await;
    task.abort();
}
#[tokio::test]
async fn pool_targets_above_sixteen_grow_lazily_and_respect_budget() {
    for legacy in [false, true] {
        check_large_pool(legacy).await;
    }
}
async fn check_large_pool(legacy: bool) {
    let (roots, server) = test_tls();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer = listener.local_addr().unwrap();
    let (out, mut accepted) = mpsc::channel(24);
    let listener_task = tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let tls = server.accept(tcp).await.unwrap();
            #[allow(clippy::result_large_err)]
            let ws = accept_hdr_async(tls, |_: &Request, mut res: Response| {
                res.headers_mut()
                    .insert("Sec-WebSocket-Protocol", "binary".parse().unwrap());
                Ok(res)
            })
            .await
            .unwrap();
            if out.send(ws).await.is_err() {
                break;
            }
        }
    });
    let tls = relay::tls_config(roots).unwrap();
    let mut pool = if legacy {
        Pool::legacy(usize::MAX, tls, 8192)
    } else {
        Pool::new(usize::MAX, tls, 8192)
    };
    pool.capacity = 20;
    pool.warm(
        2,
        Endpoint {
            managed: false,
            peer: Peer::Direct(peer),
            host: "telegram.test".into(),
            path: "/apiws",
        },
    );
    for _ in 0..20 {
        pool.maintain();
    }
    assert_eq!(pool.slots.lock().unwrap().len(), 4);
    let mut held = vec![];
    timeout(Duration::from_secs(8),async {
        while held.len()<20 {
            tokio::select!{ Some(ws)=accepted.recv()=>held.push(ws),_=sleep(Duration::from_millis(5))=>pool.maintain() }
        }
    }).await.unwrap();
    pool.maintain();
    assert_eq!(pool.slots.lock().unwrap().len(), 20);
    pool.stop().await;
    listener_task.abort();
}
