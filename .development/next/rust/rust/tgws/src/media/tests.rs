use super::*;
use crate::{configured::tests::origin, crypto, relay};
use ctr::cipher::StreamCipher;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

async fn echo_origin(host: &'static str) -> (TlsConnector, std::net::SocketAddr, JoinHandle<()>) {
    test_origin(host, |_, mut response| {
        let mut body = response
            .send_response(http::Response::new(()), false)
            .unwrap();
        body.send_data(Bytes::from_static(b"good"), true).unwrap();
    })
    .await
}

async fn test_origin(
    host: &'static str,
    post: impl Fn(http::Request<h2::RecvStream>, h2::server::SendResponse<Bytes>) + Send + 'static,
) -> (TlsConnector, std::net::SocketAddr, JoinHandle<()>) {
    let (roots, mut server) = origin(vec![host.into()]);
    server.alpn_protocols = vec![b"h2".to_vec()];
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let socket = listener.accept().await.unwrap().0;
        let tls = tokio_rustls::TlsAcceptor::from(Arc::new(server))
            .accept(socket)
            .await
            .unwrap();
        assert_eq!(tls.get_ref().1.server_name(), Some(host));
        let mut conn = h2::server::handshake(tls).await.unwrap();
        while let Some(Ok((request, mut response))) = conn.accept().await {
            if request.method() == Method::HEAD {
                response
                    .send_response(http::Response::new(()), true)
                    .unwrap();
            } else {
                assert_eq!(request.method(), Method::POST);
                post(request, response);
            }
        }
    });
    (relay::tls_config(roots).unwrap(), address, upstream)
}

#[tokio::test]
async fn legacy_h2_preflight_applies_go_outgoing_socket_defaults() {
    const HOST: &str = "kws2.socket-options.test";
    for legacy in [false, true] {
        let (tls, address, server) = test_origin(HOST, |_, _| panic!("expected only HEAD")).await;
        let tcp = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
        tcp.set_nonblocking(true).unwrap();
        assert_eq!(tcp.peer_addr().unwrap(), address);
        let socket = socket2::SockRef::from(&tcp);
        let keepalive = socket.keepalive().unwrap();
        let recv_buffer = socket.recv_buffer_size().unwrap();
        let send_buffer = socket.send_buffer_size().unwrap();
        let lane = timeout(Duration::from_secs(3), async {
            let connected = connect_h2(
                HOST,
                &tls,
                std::future::ready(TcpStream::from_std(tcp)),
                legacy,
            )
            .await
            .unwrap();
            // Check the configured socket before the HTTP/2 driver takes ownership.
            let tcp = connected.get_ref().0;
            let socket = socket2::SockRef::from(tcp);
            assert!(tcp.nodelay().unwrap());
            assert_eq!(socket.keepalive().unwrap(), legacy || keepalive);
            assert_eq!(socket.recv_buffer_size().unwrap(), recv_buffer);
            assert_eq!(socket.send_buffer_size().unwrap(), send_buffer);
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
            Lane::open(HOST, connected, Arc::default()).await.unwrap()
        })
        .await
        .unwrap();
        drop(lane);
        server.abort();
    }
}

#[tokio::test]
async fn terminal_h2_reply_survives_upload_eof_within_its_original_timeout() {
    let host = "kws2.media.example.test";
    for drain in [true, false] {
        let (tls, address, server) = test_origin(host, |_, mut reply| {
            let response = http::Response::builder().status(404).body(()).unwrap();
            reply.send_response(response, true).unwrap();
        })
        .await;
        let stats = Stats::default();
        let slots = crate::handshakes::Handshakes::default();
        let origins = Origins::for_profile(true);
        let lane = origins
            .get(host, &tls, &slots, TcpStream::connect(address), &stats)
            .await
            .unwrap();
        let key = [7; 16];
        let (head, mut send, mut receive) = crypto::client_fixture(&key, -2, 0xee);
        let transport = crypto::Transport::client(head, &key).unwrap();
        let (mut client, socket) = tokio::io::duplex(1);
        let (reported, classified) = tokio::sync::oneshot::channel();
        let mut run = Box::pin(bridge(socket, transport, lane, &stats, |error| {
            assert_eq!(error, H2Terminal::Http(404));
            reported.send(()).unwrap();
        }));
        let upload = async {
            let mut packet = [7; 28];
            packet[..4].copy_from_slice(&24u32.to_le_bytes());
            send.apply_keystream(&mut packet);
            client.write_all(&packet).await.unwrap();
            classified.await.unwrap();
            client.shutdown().await.unwrap();
        };
        timeout(Duration::from_secs(3), async {
            tokio::select! {
                result = &mut run => panic!("bridge closed before upload EOF: {result:?}"),
                () = upload => {}
            }
        })
        .await
        .unwrap();
        // Force an EOF poll while the one-byte reply buffer is still full.
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(run.as_mut().poll(&mut context).is_pending());

        if drain {
            let mut reply = [0; 8];
            let (result, read) = timeout(Duration::from_secs(3), async {
                tokio::join!(&mut run, client.read_exact(&mut reply))
            })
            .await
            .unwrap();
            result.unwrap();
            read.unwrap();
            receive.apply_keystream(&mut reply);
            assert_eq!(&reply[..4], &4u32.to_le_bytes());
            assert_eq!(&reply[4..], &(-404i32).to_le_bytes());
            assert_eq!(stats.down.load(Ordering::Relaxed), 4);
        } else {
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(1)).await;
            assert!(run.as_mut().poll(&mut context).is_pending());
            timeout(Duration::from_secs(1), &mut run)
                .await
                .unwrap()
                .unwrap();
            tokio::time::resume();
            assert_eq!(stats.down.load(Ordering::Relaxed), 0);
        }
        assert_eq!(stats.h2_errors.load(Ordering::Relaxed), 1);
        drop(run);
        origins.stop().await;
        server.abort();
    }
}

#[tokio::test]
async fn h2_terminal_diagnostics_preserve_code_origin_and_other_lane_clients() {
    let host = "kws2.media.example.test";
    for expected in [
        H2Terminal::Http(403),
        H2Terminal::Http(404),
        H2Terminal::Http(429),
        H2Terminal::Http(444),
        H2Terminal::Payload(-404),
        H2Terminal::Payload(i32::MIN),
    ] {
        let requests = Arc::new(AtomicU8::new(0));
        let observed = requests.clone();
        let (tls, address, server) = test_origin(host, move |_, mut response| {
            if observed.fetch_add(1, Ordering::Relaxed) == 0 {
                match expected {
                    H2Terminal::Http(status) => {
                        let response_head = http::Response::builder()
                            .status(status)
                            .header("content-type", "text/html")
                            .body(())
                            .unwrap();
                        response.send_response(response_head, true).unwrap();
                    }
                    H2Terminal::Payload(code) => {
                        let mut body = response
                            .send_response(http::Response::new(()), false)
                            .unwrap();
                        body.send_data(Bytes::copy_from_slice(&code.to_le_bytes()), true)
                            .unwrap();
                    }
                }
            } else {
                let mut body = response
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                body.send_data(Bytes::from_static(b"good"), true).unwrap();
            }
        })
        .await;
        let stats = Stats::default();
        let slots = crate::handshakes::Handshakes::default();
        let origins = Origins::for_profile(true);
        timeout(Duration::from_secs(5), async {
            let lane = origins
                .get(host, &tls, &slots, TcpStream::connect(address), &stats)
                .await
                .unwrap();
            let key = [8; 16];
            let (init, mut send, mut receive) = crypto::client_fixture(&key, -2, 0xee);
            let session = crypto::Transport::client(init, &key).unwrap();
            let (mut client, socket) = tokio::io::duplex(64);
            let (report, reported) = tokio::sync::oneshot::channel();
            let app = async {
                let mut request = [5; 28];
                request[..4].copy_from_slice(&24u32.to_le_bytes());
                send.apply_keystream(&mut request);
                client.write_all(&request).await.unwrap();
                assert_eq!(reported.await.unwrap(), expected);
                let mut reply = [0; 8];
                client.read_exact(&mut reply).await.unwrap();
                receive.apply_keystream(&mut reply);
                assert_eq!(&reply[..4], &4u32.to_le_bytes());
                assert_eq!(&reply[4..], &expected.code().to_le_bytes());
            };
            let (result, ()) = tokio::join!(
                bridge(socket, session, lane.clone(), &stats, |error| {
                    report.send(error).unwrap();
                }),
                app
            );
            result.unwrap();
            assert!(lane.cooldown.lock().unwrap().is_none());

            let same = origins
                .get(
                    host,
                    &tls,
                    &slots,
                    async { panic!("unexpected redial") },
                    &stats,
                )
                .await
                .unwrap();
            assert!(Arc::ptr_eq(&same, &lane));
            exchange(same, &stats).await;
            assert_eq!(requests.load(Ordering::Relaxed), 2);
            assert_eq!(stats.h2_tcp.load(Ordering::Relaxed), 1);
            assert_eq!(stats.h2_requests.load(Ordering::Relaxed), 2);
            assert_eq!(stats.h2_errors.load(Ordering::Relaxed), 1);
            assert_eq!(stats.up.load(Ordering::Relaxed), 48);
            assert_eq!(stats.down.load(Ordering::Relaxed), 8);
        })
        .await
        .unwrap();
        origins.stop().await;
        server.abort();
    }
}

#[tokio::test]
async fn h2_terminal_result_survives_a_blocked_ordinary_reply_and_upload_eof() {
    let host = "kws2.media.example.test";
    for drain in [true, false] {
        let (send_request, mut requests) = tokio::sync::mpsc::unbounded_channel();
        let (tls, address, server) = test_origin(host, move |_, response| {
            send_request.send(response).unwrap();
        })
        .await;
        let stats = Stats::default();
        let slots = crate::handshakes::Handshakes::default();
        let origins = Origins::for_profile(true);
        let lane = origins
            .get(host, &tls, &slots, TcpStream::connect(address), &stats)
            .await
            .unwrap();
        let credits = lane.budget.requests.clone();
        let key = [7; 16];
        let (head, mut send, mut receive) = crypto::client_fixture(&key, -2, 0xee);
        let transport = crypto::Transport::client(head, &key).unwrap();
        let (mut client, socket) = tokio::io::duplex(1);
        let (report, classified) = tokio::sync::oneshot::channel();
        let mut run = Box::pin(bridge(socket, transport, lane, &stats, |error| {
            assert_eq!(error, H2Terminal::Http(404));
            report.send(()).unwrap();
        }));
        let mut wire = [0; 16];
        let arrange = async {
            let mut responders = Vec::new();
            for payload in [7, 8, 9] {
                let mut packet = [payload; 28];
                packet[..4].copy_from_slice(&24u32.to_le_bytes());
                send.apply_keystream(&mut packet);
                client.write_all(&packet).await.unwrap();
                responders.push(requests.recv().await.unwrap());
            }
            let [mut first, mut queued, mut terminal] = responders.try_into().unwrap();
            first
                .send_response(http::Response::new(()), false)
                .unwrap()
                .send_data(Bytes::from_static(b"good"), true)
                .unwrap();
            client.read_exact(&mut wire[..1]).await.unwrap();
            queued
                .send_response(http::Response::new(()), false)
                .unwrap()
                .send_data(Bytes::from_static(b"skip"), true)
                .unwrap();
            while credits.available_permits() != 63 {
                tokio::task::yield_now().await;
            }
            let error = http::Response::builder().status(404).body(()).unwrap();
            terminal.send_response(error, true).unwrap();
            classified.await.unwrap();
            client.shutdown().await.unwrap();
        };
        timeout(Duration::from_secs(3), async {
            tokio::select! {
                result = &mut run => panic!("bridge closed before native upload EOF: {result:?}"),
                () = arrange => {}
            }
        })
        .await
        .unwrap();
        assert_eq!(stats.h2_errors.load(Ordering::Relaxed), 1);
        assert_eq!(stats.down.load(Ordering::Relaxed), 0);

        if drain {
            let (result, read) = timeout(Duration::from_secs(3), async {
                tokio::join!(&mut run, client.read_exact(&mut wire[1..]))
            })
            .await
            .unwrap();
            result.unwrap();
            read.unwrap();
            receive.apply_keystream(&mut wire);
            assert_eq!(&wire[..8], b"\x04\0\0\0good");
            assert_eq!(&wire[8..12], &4u32.to_le_bytes());
            assert_eq!(&wire[12..], &(-404i32).to_le_bytes());
            assert_eq!(stats.down.load(Ordering::Relaxed), 8);
        } else {
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(1)).await;
            let mut context = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(run.as_mut().poll(&mut context).is_pending());
            timeout(Duration::from_secs(1), &mut run)
                .await
                .unwrap()
                .unwrap();
            tokio::time::resume();
            assert_eq!(stats.down.load(Ordering::Relaxed), 0);
        }
        drop(run);
        origins.stop().await;
        server.abort();
    }
}

#[tokio::test]
async fn h2_upload_eof_does_not_submit_an_unstarted_job() {
    let host = "kws2.media.example.test";
    let (tls, address, server) = test_origin(host, |_, _| {
        panic!("received a new POST after native EOF");
    })
    .await;
    let stats = Stats::default();
    let slots = crate::handshakes::Handshakes::default();
    let origins = Origins::for_profile(true);
    let lane = origins
        .get(host, &tls, &slots, TcpStream::connect(address), &stats)
        .await
        .unwrap();
    let key = [7; 16];
    let (head, mut send, _) = crypto::client_fixture(&key, -2, 0xee);
    let transport = crypto::Transport::client(head, &key).unwrap();
    let (mut client, socket) = tokio::io::duplex(64);
    let mut packet = [7; 28];
    packet[..4].copy_from_slice(&24u32.to_le_bytes());
    send.apply_keystream(&mut packet);
    client.write_all(&packet).await.unwrap();
    client.shutdown().await.unwrap();
    let error = bridge(socket, transport, lane, &stats, |_| {})
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(stats.h2_requests.load(Ordering::Relaxed), 0);
    origins.stop().await;
    server.abort();
}

#[tokio::test]
async fn long_response_preserves_ninety_idle_seconds_for_the_next_authorized_client() {
    let host = "kws2.media.example.test";
    let (requests, mut incoming) = tokio::sync::mpsc::unbounded_channel();
    let (tls, address, server) = test_origin(host, move |req, response| {
        let _ = requests.send((req, response));
    })
    .await;
    let stats = Arc::new(Stats::default());
    let slots = crate::handshakes::Handshakes::default();
    let origins = Origins::for_profile(true);
    let first = origins
        .get(host, &tls, &slots, TcpStream::connect(address), &stats)
        .await
        .unwrap();
    let cached = Arc::downgrade(&first);
    let counted = stats.clone();
    let client = tokio::spawn(async move { exchange(first, &counted).await });
    let (_, mut reply) = timeout(Duration::from_secs(3), incoming.recv())
        .await
        .unwrap()
        .unwrap();
    let elapse = async |seconds| {
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(seconds)).await;
        tokio::time::resume();
    };
    elapse(55).await;
    reply
        .send_response(http::Response::new(()), false)
        .unwrap()
        .send_data(Bytes::from_static(b"good"), true)
        .unwrap();
    timeout(Duration::from_secs(3), client)
        .await
        .unwrap()
        .unwrap();

    elapse(40).await;
    origins.prune(|_| true).await;
    let mut busy = Vec::new();
    for _ in 0..4 {
        busy.push(slots.acquire().await.unwrap());
    }
    let second = origins
        .get(
            host,
            &tls,
            &slots,
            async { panic!("an open connection can serve the second client") },
            &stats,
        )
        .await
        .unwrap();
    assert!(cached.ptr_eq(&Arc::downgrade(&second)));
    let counted = stats.clone();
    let client = tokio::spawn(async move { exchange(second, &counted).await });
    let (_, mut reply) = timeout(Duration::from_secs(3), incoming.recv())
        .await
        .unwrap()
        .unwrap();
    reply
        .send_response(http::Response::new(()), false)
        .unwrap()
        .send_data(Bytes::from_static(b"good"), true)
        .unwrap();
    timeout(Duration::from_secs(3), client)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stats.h2_requests.load(Ordering::Relaxed), 2);
    assert_eq!(stats.h2_tcp.load(Ordering::Relaxed), 1);

    elapse(91).await;
    origins.prune(|_| true).await;
    assert!(cached.upgrade().is_none());
    server.abort();
}

#[tokio::test]
async fn long_poll_returns_its_late_response_when_no_replay_needs_the_slot() {
    let host = "kws2.media.example.test";
    let (requests, mut incoming) = tokio::sync::mpsc::unbounded_channel();
    let (tls, address, server) = test_origin(host, move |req, response| {
        let _ = requests.send((req.into_body(), response));
    })
    .await;
    let stats = Arc::new(Stats::default());
    let origins = Origins::for_profile(true);
    let lane = origins
        .get(
            host,
            &tls,
            &Default::default(),
            TcpStream::connect(address),
            &stats,
        )
        .await
        .unwrap();
    let credits = lane.budget.requests.clone();
    let (head, mut encrypt, mut decrypt) = crypto::client_fixture(&[4; 16], -2, 0xee);
    let session = crypto::Transport::client(head, &[4; 16]).unwrap();
    let (mut client, socket) = tokio::io::duplex(128);
    let counted = stats.clone();
    let worker = tokio::spawn(async move { bridge(socket, session, lane, &counted, |_| {}).await });

    let body = [7; 24];
    let mut wire = framing::frame(&body, 0xee).unwrap();
    encrypt.apply_keystream(&mut wire);
    client.write_all(&wire).await.unwrap();
    let mut next_request = async || {
        let (mut request, response) = incoming.recv().await.unwrap();
        let mut bytes = Vec::new();
        while let Some(chunk) = request.data().await {
            let chunk = chunk.unwrap();
            request
                .flow_control()
                .release_capacity(chunk.len())
                .unwrap();
            bytes.extend_from_slice(&chunk);
        }
        assert_eq!(&bytes[..], &body);
        response
    };
    let mut poll = timeout(Duration::from_secs(5), async {
        next_request()
            .await
            .send_response(http::Response::new(()), true)
            .unwrap();
        next_request().await
    })
    .await
    .unwrap();
    assert_eq!(stats.h2_replays.load(Ordering::Relaxed), 1);
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(35)).await;
    tokio::task::yield_now().await;
    tokio::time::resume();
    assert_eq!(
        credits.available_permits(),
        63,
        "the long poll must remain active"
    );
    let mut reply = poll.send_response(http::Response::new(()), false).unwrap();
    reply.send_data(Bytes::from_static(b"late"), true).unwrap();
    let mut frame = [0; 8];
    timeout(Duration::from_secs(2), client.read_exact(&mut frame))
        .await
        .unwrap()
        .unwrap();
    decrypt.apply_keystream(&mut frame);
    assert_eq!(&frame[..4], &4u32.to_le_bytes());
    assert_eq!(&frame[4..], b"late");
    assert_eq!(stats.h2_replays.load(Ordering::Relaxed), 1);
    worker.abort();
    server.abort();
}

#[tokio::test]
async fn partially_buffered_h2_response_defers_replay_of_another_encrypted_request() {
    let host = "kws2.media.example.test";
    let (requests, mut incoming) = tokio::sync::mpsc::unbounded_channel();
    let (tls, address, server) = test_origin(host, move |request, response| {
        let tx = requests.clone();
        tokio::spawn(async move {
            let mut body = request.into_body();
            let mut bytes = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.unwrap();
                body.flow_control().release_capacity(chunk.len()).unwrap();
                bytes.extend_from_slice(&chunk);
            }
            assert_eq!(bytes.len(), 24);
            let _ = tx.send((bytes[23], response));
        });
    })
    .await;
    let stats = Arc::new(Stats::default());
    let origins = Origins::for_profile(true);
    let slots = crate::handshakes::Handshakes::default();
    let lane = origins
        .get(host, &tls, &slots, TcpStream::connect(address), &stats)
        .await
        .unwrap();
    let budget = lane.budget.download.clone();
    let capacity = budget.available_permits();
    let (head, mut send, mut receive) = crypto::client_fixture(&[9; 16], -2, 0xee);
    let session = crypto::Transport::client(head, &[9; 16]).unwrap();
    let (mut client, socket) = tokio::io::duplex(128);
    let counted = stats.clone();
    let worker = tokio::spawn(async move { bridge(socket, session, lane, &counted, |_| {}).await });
    timeout(Duration::from_secs(15), async {
        for id in [1, 2] {
            let mut bytes = vec![7; 28];
            bytes[..4].copy_from_slice(&24u32.to_le_bytes());
            bytes[27] = id;
            send.apply_keystream(&mut bytes);
            client.write_all(&bytes).await.unwrap();
        }
        let mut responses = BTreeMap::new();
        for _ in 0..2 {
            let (id, response) = incoming.recv().await.unwrap();
            responses.insert(id, response);
        }
        let mut reply = responses
            .remove(&2)
            .unwrap()
            .send_response(http::Response::new(()), false)
            .unwrap();
        reply.send_data(Bytes::from_static(b"half"), false).unwrap();
        while budget.available_permits() == capacity {
            tokio::task::yield_now().await;
        }
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(4)).await;
        tokio::task::yield_now().await;
        tokio::time::resume();
        assert_eq!(stats.h2_replays.load(Ordering::Relaxed), 0);
        reply.send_data(Bytes::from_static(b"done"), true).unwrap();
        let mut frame = [0; 12];
        client.read_exact(&mut frame).await.unwrap();
        receive.apply_keystream(&mut frame);
        assert_eq!(&frame[4..], b"halfdone");
        assert_eq!(incoming.recv().await.unwrap().0, 1);
        assert_eq!(stats.h2_replays.load(Ordering::Relaxed), 1);
    })
    .await
    .unwrap();
    worker.abort();
    server.abort();
}

#[tokio::test]
async fn exhausted_reply_budget_keeps_the_verified_h2_origin_available() {
    let host = "kws2.media.example.test";
    let (tls, address, upstream) = echo_origin(host).await;
    let stats = Stats::default();
    let origins = Origins::default();
    let slots = crate::handshakes::Handshakes::default();
    timeout(Duration::from_secs(5), async {
        let lane = origins
            .get(host, &tls, &slots, TcpStream::connect(address), &stats)
            .await
            .unwrap();
        let budget = &lane.budget.download;
        let capacity = budget.available_permits();
        // A full session cannot keep credits that it provisionally took from the origin.
        let small = Arc::new(Semaphore::new(3));
        let stage = AtomicU8::new(0);
        let packet = Bytes::from_static(&[1; 24]);
        assert!(matches!(
            lane.post(packet.clone(), &stage, &small).await,
            Err(Failure::ReplyBufferFull)
        ));
        assert_eq!(budget.available_permits(), capacity);
        assert_eq!(small.available_permits(), 3);

        // Simulate other sessions already holding the origin's response credits.
        let busy = budget
            .clone()
            .acquire_many_owned(capacity as u32)
            .await
            .unwrap();
        let (init, mut send, _) = crypto::client_fixture(&[9; 16], -2, 0xee);
        let transport = crypto::Transport::client(init, &[9; 16]).unwrap();
        let (mut app, socket) = tokio::io::duplex(128);
        let mut framed = [1; 28];
        framed[..4].copy_from_slice(&24u32.to_le_bytes());
        send.apply_keystream(&mut framed);
        app.write_all(&framed).await.unwrap();
        assert!(bridge(socket, transport, lane.clone(), &stats, |_| {})
            .await
            .is_err());
        assert_eq!(stats.h2_errors.load(Ordering::Relaxed), 1);
        drop(busy);

        let same = origins
            .get(
                host,
                &tls,
                &slots,
                async { panic!("unexpected redial") },
                &stats,
            )
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&lane, &same));
        let reply = same
            .post(packet, &stage, &Arc::new(Semaphore::new(4)))
            .await
            .unwrap();
        assert_eq!(reply.data, b"good");
        drop(reply);
        assert_eq!(budget.available_permits(), capacity);
        assert_eq!(stats.h2_tcp.load(Ordering::Relaxed), 1);
    })
    .await
    .unwrap();
    origins.stop().await;
    upstream.abort();
}

async fn exchange(lane: Arc<Lane>, stats: &Stats) {
    let key = [9; 16];
    let (init, mut send, mut receive) = crypto::client_fixture(&key, -2, 0xee);
    let transport = crypto::Transport::client(init, &key).unwrap();
    let (mut client, socket) = tokio::io::duplex(128);
    let app = async move {
        // An unencrypted native message has no automatic media replay.
        let mut frame = [0; 28];
        frame[..4].copy_from_slice(&24u32.to_le_bytes());
        frame[20..24].copy_from_slice(&4u32.to_le_bytes());
        send.apply_keystream(&mut frame);
        client.write_all(&frame).await.unwrap();
        let mut response = [0; 8];
        client.read_exact(&mut response).await.unwrap();
        receive.apply_keystream(&mut response);
        assert_eq!(&response[..4], &4u32.to_le_bytes());
        assert_eq!(&response[4..], b"good");
    };
    let _ = tokio::join!(bridge(socket, transport, lane, stats, |_| {}), app);
}

#[tokio::test]
async fn go_origins_use_independent_http2_credits_while_native_shares_its_budget() {
    let credits = |lane: &Lane| {
        [
            lane.budget.requests.available_permits(),
            lane.budget.upload.available_permits(),
            lane.budget.download.available_permits(),
        ]
    };
    let capacity = [64, 32 << 20, 32 << 20];
    for legacy in [true, false] {
        let a = "kws1.first.example.test";
        let b = "kws2.second.example.test";
        let (tls_a, addr_a, server_a) = echo_origin(a).await;
        let (tls_b, addr_b, server_b) = echo_origin(b).await;
        let stats = Stats::default();
        let origins = Origins::for_profile(legacy);
        let slots = Default::default();
        timeout(Duration::from_secs(5), async {
            let first = origins
                .get(a, &tls_a, &slots, TcpStream::connect(addr_a), &stats)
                .await
                .unwrap();
            let second = origins
                .get(b, &tls_b, &slots, TcpStream::connect(addr_b), &stats)
                .await
                .unwrap();
            assert_eq!(Arc::ptr_eq(&first.budget, &second.budget), !legacy);
            assert_eq!(credits(&first), capacity);
            let mut held = Vec::new();
            for (pool, limit) in [
                &first.budget.requests,
                &first.budget.upload,
                &first.budget.download,
            ]
            .into_iter()
            .zip(capacity)
            {
                held.push(pool.clone().try_acquire_many_owned(limit as u32).unwrap());
            }
            assert_eq!(credits(&first), [0; 3]);
            assert_eq!(credits(&second), if legacy { capacity } else { [0; 3] });
            let independent = exchange(second.clone(), &stats);
            tokio::pin!(independent);
            if legacy {
                independent.as_mut().await;
            } else {
                assert!(timeout(Duration::from_millis(25), independent.as_mut())
                    .await
                    .is_err());
            }
            drop(held);
            if !legacy {
                independent.await;
            }
            exchange(first.clone(), &stats).await;
            assert_eq!(credits(&first), capacity);
            assert_eq!(credits(&second), capacity);
            assert_eq!(stats.h2_requests.load(Ordering::Relaxed), 2);
            assert_eq!(stats.h2_tcp.load(Ordering::Relaxed), 2);
        })
        .await
        .unwrap();
        origins.stop().await;
        server_a.abort();
        server_b.abort();
    }
}
