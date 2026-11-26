use super::*;
use ctr::cipher::StreamCipher;
use futures_util::{SinkExt, StreamExt};
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{timeout, Duration},
};
use tokio_rustls::{
    rustls::{pki_types::PrivatePkcs8KeyDer, RootCertStore, ServerConfig},
    TlsAcceptor,
};
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::{
        handshake::server::{Request, Response},
        Message,
    },
};

#[tokio::test]
async fn only_complete_invalid_mtproto_headers_increment_bad_connections() {
    let mut cfg = Config::default();
    cfg.normalize().unwrap();
    let invalid = crypto::client_fixture(&cfg.key().unwrap(), 2, 0x99).0;
    let (roots, _) = test_tls();
    let mut pool = pool::Pool::legacy(0, relay::tls_config(roots).unwrap(), cfg.buffer_size);
    let diagnostics = pool.capture_diagnostics();
    let pool = Arc::new(pool);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stats = Arc::new(Stats::default());
    for (proxy, masking, bytes, rejected) in [
        (false, "", &b"short"[..], false),
        (true, "", &b"invalid\r\n"[..], false),
        (
            false,
            "origin.example.test",
            &b"GET / HTTP/1.0\r\n\r\n"[..],
            false,
        ),
        (false, "", &invalid[..], true),
    ] {
        cfg.proxy_protocol = proxy;
        cfg.fake_tls_domain = masking.into();
        let (mut client, (server, _)) = tokio::try_join!(
            TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept()
        )
        .unwrap();
        client.write_all(bytes).await.unwrap();
        client.shutdown().await.unwrap();
        relay::client(
            server,
            Arc::new(cfg.clone()),
            stats.clone(),
            None,
            pool.clone(),
        )
        .await;
        assert_eq!(
            diagnostics.try_recv().ok(),
            rejected.then_some(diagnostics::Event::BadHandshake)
        );
    }
    let connections = &stats.json()["connections"];
    assert_eq!(connections["total"], 4);
    assert_eq!(connections["active"], 0);
    assert_eq!(connections["bad"], 1);
}

#[tokio::test]
async fn proxy_header_preserves_the_handshake_and_pipelined_payload() {
    let limit = format!("PROXY {}\r\n", "x".repeat(99));
    for header in [
        "",
        "PROXY UNKNOWN\r\n",
        "PROXY TCP4 192.0.2.1 192.0.2.2 50000 443\r\n",
        &limit,
    ] {
        let init = [0xa5; 64];
        let data = [header.as_bytes(), &init, b"following packet"].concat();
        let mut stream = &data[..];
        assert_eq!(
            relay::read_init(&mut stream, !header.is_empty())
                .await
                .unwrap(),
            init
        );
        assert_eq!(stream, b"following packet");
    }
    for header in [
        "PROXY UNKNOWN\n".into(),
        "GET / HTTP/1.0\r\n".into(),
        format!("PROXY {}\r\n", "x".repeat(100)),
    ] {
        assert!(relay::read_init(&mut header.as_bytes(), true)
            .await
            .is_err());
    }
}

#[test]
fn authentication_and_lengths_reject_unknown_targets_and_unbounded_packets() {
    let (init, _, _) = crypto::client_fixture(&[13; 16], 2, 0xdd);
    assert!(crypto::Transport::client(init, &[12; 16]).is_err());
    for (dc, tag) in [(0, 0xdd), (8, 0xee), (3, 12)] {
        assert!(
            crypto::Transport::client(crypto::client_fixture(&[13; 16], dc, tag).0, &[13; 16])
                .is_err()
        );
    }
    assert_eq!(crypto::packet_len(&[0x82], 0xef).unwrap(), 8);
    assert!(crypto::packet_len(&[0xff; 4], 0xee).is_err());
}
#[test]
fn test_datacenter_wire_vector_preserves_media_and_normalizes_the_relay() {
    // Independently derived AES-CTR vector, with an ascending pre-key and
    // IV, a repeated 0x0d secret, and the encrypted DC -10002 trailer.
    let mut init = std::array::from_fn(|i| i as u8 + 2);
    init[56..].copy_from_slice(&[0xa7, 0xa4, 0xc3, 0xff, 0x5f, 0x14, 0xcc, 0xcb]);
    let session = crypto::Transport::client(init, &[13; 16]).unwrap();
    assert_eq!(session.dc, -10002);
    let (tag, dc, _, _) = crypto::upstream_fixture(session.init);
    assert_eq!((tag, dc), (0xdd, -2));
    for dc in [-10203, 10203] {
        let (head, _, _) = crypto::client_fixture(&[13; 16], dc, 0xee);
        let session = crypto::Transport::client(head, &[13; 16]).unwrap();
        assert_eq!(crypto::upstream_fixture(session.init).1, dc % 10000);
    }
}
pub(super) fn test_tls() -> (RootCertStore, TlsAcceptor) {
    let key = rcgen::generate_simple_self_signed(vec!["telegram.test".into()]).unwrap();
    let cert = key.cert.der().clone();
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
        PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()).into(),
    )
    .unwrap();
    let tls = TlsAcceptor::from(Arc::new(server));
    (roots, tls)
}

#[tokio::test]
async fn legacy_websocket_clean_upload_eof_sends_masked_empty_close() {
    use relay::BridgeMode;

    let (roots, tls) = test_tls();
    let connector = relay::tls_config(roots).unwrap();
    for (mode, partial, expect_close) in [
        (BridgeMode::Legacy, &b""[..], true),
        (BridgeMode::LegacyWorker, &b""[..], true),
        (BridgeMode::Native, &b""[..], false),
        (BridgeMode::Native, &b"\x04\0"[..], false),
        (BridgeMode::Native, &b"\x04\0\0\0x"[..], false),
    ] {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = upstream.local_addr().unwrap();
        let tls = tls.clone();
        let (init_seen, session_ready) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let (socket, _) = upstream.accept().await.unwrap();
            let secure = tls.accept(socket).await.unwrap();
            #[allow(clippy::result_large_err)]
            let mut ws = accept_hdr_async(secure, |_: &Request, mut response: Response| {
                response
                    .headers_mut()
                    .insert("Sec-WebSocket-Protocol", "binary".parse().unwrap());
                Ok(response)
            })
            .await
            .unwrap();
            let init = ws.next().await.unwrap().unwrap().into_data();
            assert_eq!(init.len(), 64);
            let mut wire = ws.into_inner();
            init_seen.send(()).unwrap();
            if expect_close {
                let mut frame = [0; 6];
                wire.read_exact(&mut frame).await.unwrap();
                assert_eq!(frame[..2], [0x88, 0x80], "{mode:?}");
            }
            let mut extra = [0];
            match wire.read(&mut extra).await {
                Ok(0) => {}
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {}
                result => panic!("unexpected bytes after local EOF in {mode:?}: {result:?}"),
            }
        });
        let ws = relay::upgrade(
            TcpStream::connect(address).await.unwrap(),
            "telegram.test",
            "/apiws",
            &connector,
        )
        .await
        .unwrap();
        let (mut client, socket) = tokio::io::duplex(64);
        let key = [37; 16];
        let (init, mut encrypt, _) = crypto::client_fixture(&key, 2, 0xee);
        let session = crypto::Transport::client(init, &key).unwrap();
        let stats = Arc::new(Stats::default());
        let counters = stats.clone();
        let bridge =
            tokio::spawn(
                async move { relay::bridge(socket, ws, session, &counters, mode, None).await },
            );
        timeout(Duration::from_secs(2), session_ready)
            .await
            .unwrap()
            .unwrap();
        let mut data = partial.to_vec();
        encrypt.apply_keystream(&mut data);
        client.write_all(&data).await.unwrap();
        client.shutdown().await.unwrap();

        let result = timeout(Duration::from_secs(2), bridge)
            .await
            .unwrap()
            .unwrap();
        if mode == BridgeMode::LegacyWorker {
            result.unwrap();
        } else {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        }
        timeout(Duration::from_secs(2), peer)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stats.up.load(Ordering::Relaxed), data.len() as u64);
        assert_eq!(stats.down.load(Ordering::Relaxed), 0);
    }
}

#[tokio::test]
async fn legacy_websocket_eof_flushes_bounded_partial_ciphertext_before_close() {
    let (roots, tls) = test_tls();
    let connector = relay::tls_config(roots).unwrap();
    for (tag, tail, preceding_packet) in [
        (0xee, &b"\x04\0"[..], None),
        (0xee, &b"\x04\0\0\0"[..], None),
        (0xee, &b"\x04\0\0\0x"[..], None),
        (0xef, &b"\x7f\x80"[..], None),
        (0xdd, &b"\x04\0\0\0x"[..], Some(&b"\x04\0\0\0good"[..])),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let tls = tls.clone();
        let peer = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let secure = tls.accept(tcp).await.unwrap();
            #[allow(clippy::result_large_err)]
            let mut ws = accept_hdr_async(secure, |_: &Request, mut response: Response| {
                response
                    .headers_mut()
                    .insert("Sec-WebSocket-Protocol", "binary".parse().unwrap());
                Ok(response)
            })
            .await
            .unwrap();
            let init = ws.next().await.unwrap().unwrap().into_data();
            let (upstream_tag, dc, mut decrypt, _) =
                crypto::upstream_fixture(init.as_ref().try_into().unwrap());
            assert_eq!((upstream_tag, dc), (tag, 2));
            for expected in preceding_packet.into_iter().chain([tail]) {
                let Message::Binary(encrypted) = ws.next().await.unwrap().unwrap() else {
                    panic!("missing complete binary message before Close");
                };
                let mut plain = encrypted.to_vec();
                decrypt.apply_keystream(&mut plain);
                assert_eq!(plain, expected);
            }
            assert_eq!(ws.next().await.unwrap().unwrap(), Message::Close(None));
        });
        let ws = relay::upgrade(
            TcpStream::connect(address).await.unwrap(),
            "telegram.test",
            "/apiws",
            &connector,
        )
        .await
        .unwrap();
        let (mut client, socket) = tokio::io::duplex(64);
        let key = [40; 16];
        let (init, mut encrypt, _) = crypto::client_fixture(&key, 2, tag);
        let session = crypto::Transport::client(init, &key).unwrap();
        let mut bytes = preceding_packet.unwrap_or_default().to_vec();
        bytes.extend_from_slice(tail);
        encrypt.apply_keystream(&mut bytes);
        client.write_all(&bytes).await.unwrap();
        client.shutdown().await.unwrap();

        let stats = Stats::default();
        let result = timeout(
            Duration::from_secs(2),
            relay::bridge(socket, ws, session, &stats, relay::BridgeMode::Legacy, None),
        )
        .await
        .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        timeout(Duration::from_secs(2), peer)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stats.up.load(Ordering::Relaxed), bytes.len() as u64);
        assert_eq!(stats.down.load(Ordering::Relaxed), 0);
    }
}

pub(crate) async fn read_masked_frame(
    wire: &mut (impl AsyncRead + Unpin),
    limit: usize,
) -> (u8, Vec<u8>) {
    let first = wire.read_u8().await.unwrap();
    let second = wire.read_u8().await.unwrap();
    assert_ne!(second & 0x80, 0, "client frame must be masked");
    let length = match second & 0x7f {
        126 => usize::from(wire.read_u16().await.unwrap()),
        127 => usize::try_from(wire.read_u64().await.unwrap()).unwrap(),
        short => usize::from(short),
    };
    assert!(length <= limit);
    let mut mask = [0; 4];
    wire.read_exact(&mut mask).await.unwrap();
    let mut payload = vec![0; length];
    wire.read_exact(&mut payload).await.unwrap();
    for (index, value) in payload.iter_mut().enumerate() {
        *value ^= mask[index % 4];
    }
    (first, payload)
}

#[tokio::test]
async fn legacy_websocket_eof_finishes_fragmented_packet_before_close() {
    let (roots, tls) = test_tls();
    let connector = relay::tls_config(roots).unwrap();
    for copied in [16384, 16384 + 9, 32768 + 11] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let tls = tls.clone();
        // The declared packet exceeds the staged single-frame limit.
        let mut plain = 300_000u32.to_le_bytes().to_vec();
        plain.resize(copied, 42);
        let expected = plain.clone();
        let (init_seen, ready) = tokio::sync::oneshot::channel();
        let (fragment_seen, first_sent) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let stream = tls.accept(tcp).await.unwrap();
            #[allow(clippy::result_large_err)]
            let mut ws = accept_hdr_async(stream, |_: &Request, mut response: Response| {
                response
                    .headers_mut()
                    .insert("Sec-WebSocket-Protocol", "binary".parse().unwrap());
                Ok(response)
            })
            .await
            .unwrap();
            let init = ws.next().await.unwrap().unwrap().into_data();
            let (tag, dc, mut decrypt, _) =
                crypto::upstream_fixture(init.as_ref().try_into().unwrap());
            assert_eq!((tag, dc), (0xee, 2));
            let mut wire = ws.into_inner();
            init_seen.send(()).unwrap();

            let mut chunks = expected.chunks_exact(16384);
            let mut observed_first = Some(fragment_seen);
            for chunk in &mut chunks {
                let (header, mut bytes) = read_masked_frame(&mut wire, 16384).await;
                assert_eq!(header, if observed_first.is_some() { 0x02 } else { 0x00 });
                decrypt.apply_keystream(&mut bytes);
                assert_eq!(bytes, chunk);
                if let Some(seen) = observed_first.take() {
                    seen.send(()).unwrap();
                }
            }
            let (header, mut bytes) = read_masked_frame(&mut wire, 16384).await;
            assert_eq!(header, 0x80, "tail must be a final continuation");
            decrypt.apply_keystream(&mut bytes);
            assert_eq!(bytes, chunks.remainder());
            let (header, empty) = read_masked_frame(&mut wire, 0).await;
            assert_eq!(header, 0x88);
            assert!(empty.is_empty());
            match wire.read(&mut [0]).await {
                Ok(0) => {}
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {}
                result => panic!("unexpected data after Close: {result:?}"),
            }
        });
        let ws = relay::upgrade(
            TcpStream::connect(address).await.unwrap(),
            "telegram.test",
            "/apiws",
            &connector,
        )
        .await
        .unwrap();
        let key = [41; 16];
        let (init, mut encrypt, _) = crypto::client_fixture(&key, 2, 0xee);
        let session = crypto::Transport::client(init, &key).unwrap();
        encrypt.apply_keystream(&mut plain);
        let (mut client, socket) = tokio::io::duplex(16384);
        let app = async {
            ready.await.unwrap();
            client.write_all(&plain[..16384]).await.unwrap();
            first_sent.await.unwrap();
            client.write_all(&plain[16384..]).await.unwrap();
            client.shutdown().await.unwrap();
        };
        let stats = Stats::default();
        let (result, ()) = timeout(Duration::from_secs(4), async {
            tokio::join!(
                relay::bridge(socket, ws, session, &stats, relay::BridgeMode::Legacy, None),
                app
            )
        })
        .await
        .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        timeout(Duration::from_secs(2), peer)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stats.up.load(Ordering::Relaxed), copied as u64);
        assert_eq!(stats.down.load(Ordering::Relaxed), 0);
    }
}

#[tokio::test]
async fn legacy_websocket_stages_large_packets_as_single_masked_fin_frames() {
    staged_legacy_websocket_wire(70_000, 49_001).await;
}

#[tokio::test]
async fn legacy_websocket_stages_weighted_256k_packets_as_masked_fin_frames() {
    staged_legacy_websocket_wire((256 << 10) - 4, 139_001).await;
}

async fn staged_legacy_websocket_wire(body: u32, partial: usize) {
    let (roots, tls) = test_tls();
    let connector = relay::tls_config(roots).unwrap();
    let mut pool = pool::Pool::legacy(0, connector.clone(), 8192);
    let diagnostics = pool.capture_diagnostics();
    let stats = Stats::default();
    let mut total_up = 0;
    for tag in [0xef, 0xee, 0xdd] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let tls = tls.clone();
        let header = if tag == 0xef {
            let words = (body / 4).to_le_bytes();
            [0xff, words[0], words[1], words[2]]
        } else {
            (body | 0x8000_0000).to_le_bytes()
        };
        let mut packet = header.to_vec();
        packet.extend((0..body).map(|index| (index % 251) as u8));
        let mut plaintext = packet.clone();
        plaintext.extend_from_slice(&packet[..partial]);
        let (init_seen, ready) = tokio::sync::oneshot::channel();
        let (frame_seen, complete) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let stream = tls.accept(tcp).await.unwrap();
            assert_eq!(stream.get_ref().1.server_name(), Some("telegram.test"));
            #[allow(clippy::result_large_err)]
            let mut ws = accept_hdr_async(stream, |req: &Request, mut response: Response| {
                assert_eq!(req.headers()["Host"], "telegram.test");
                assert_eq!(req.uri().path(), "/apiws");
                response
                    .headers_mut()
                    .insert("Sec-WebSocket-Protocol", "binary".parse().unwrap());
                Ok(response)
            })
            .await
            .unwrap();
            let init = ws.next().await.unwrap().unwrap().into_data();
            let (wire_tag, dc, mut decrypt, _) =
                crypto::upstream_fixture(init.as_ref().try_into().unwrap());
            assert_eq!((wire_tag, dc), (tag, 2));
            let mut wire = ws.into_inner();
            init_seen.send(()).unwrap();

            let (header, mut payload) = read_masked_frame(&mut wire, packet.len()).await;
            assert_eq!(header, 0x82);
            decrypt.apply_keystream(&mut payload);
            assert_eq!(payload, packet);
            frame_seen.send(()).unwrap();

            let (header, mut payload) = read_masked_frame(&mut wire, partial).await;
            assert_eq!(header, 0x82);
            decrypt.apply_keystream(&mut payload);
            assert_eq!(payload, packet[..partial]);
            let (header, empty) = read_masked_frame(&mut wire, 0).await;
            assert_eq!(header, 0x88);
            assert!(empty.is_empty());
            match wire.read(&mut [0]).await {
                Ok(0) => {}
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {}
                result => panic!("unexpected data after Close: {result:?}"),
            }
        });
        let mut ws = relay::upgrade(
            TcpStream::connect(address).await.unwrap(),
            "telegram.test",
            "/apiws",
            &connector,
        )
        .await
        .unwrap();
        let key = [44; 16];
        let (init, mut encrypt, _) = crypto::client_fixture(&key, 2, tag);
        let session = crypto::Transport::client(init, &key).unwrap();
        encrypt.apply_keystream(&mut plaintext);
        let (mut client, socket) = tokio::io::duplex(8192);
        let app = async {
            ready.await.unwrap();
            let (packet, tail) = plaintext.split_at(body as usize + 4);
            // Split the transport header and body before the large wire write.
            client.write_all(&packet[..1]).await.unwrap();
            client.write_all(&packet[1..]).await.unwrap();
            complete.await.unwrap();
            client.write_all(tail).await.unwrap();
            client.shutdown().await.unwrap();
        };
        let slots = tokio::sync::Semaphore::new(2);
        let bridge = async {
            nfqws2_tgws_transport::active::write(ws.send(Message::binary(session.init.to_vec())))
                .await
                .unwrap();
            relay::bridge_with_frame_slots(
                socket,
                ws,
                session,
                &stats,
                relay::BridgeMode::Legacy,
                Some(&pool),
                &slots,
            )
            .await
        };
        let (result, ()) = timeout(Duration::from_secs(4), async { tokio::join!(bridge, app) })
            .await
            .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        timeout(Duration::from_secs(2), peer)
            .await
            .unwrap()
            .unwrap();
        total_up += plaintext.len() as u64;
        assert_eq!(stats.up.load(Ordering::Relaxed), total_up);
        assert_eq!(stats.down.load(Ordering::Relaxed), 0);
        assert_eq!(slots.available_permits(), 2);
        use crate::diagnostics::{Event, WsCause, WsEnd, WsLeg, WsTraffic};
        let Event::WsSessionClosed(session) = diagnostics.try_recv().unwrap() else {
            panic!("expected the active session's close record");
        };
        assert_eq!(session.end, WsEnd::Flow(WsLeg::ClientRead, WsCause::Eof));
        assert_eq!(session.upload.bytes, plaintext.len() as u64);
        assert!(session.upload.units > 1);
        assert_eq!(session.download, WsTraffic::default());
        assert!(diagnostics.try_recv().is_err());
    }
}

#[tokio::test]
async fn legacy_peer_close_echoes_valid_empty_or_status_over_tls() {
    use relay::BridgeMode;

    let (roots, tls) = test_tls();
    let connector = relay::tls_config(roots).unwrap();
    for (mode, payload, expected) in [
        (BridgeMode::Legacy, &b""[..], Some(0)),
        (BridgeMode::Legacy, &b"\x03\xe8"[..], Some(2)),
        (BridgeMode::LegacyWorker, &b"\x03\xe9"[..], Some(2)),
        (BridgeMode::Native, &b"\x03\xe8"[..], None),
        (BridgeMode::Legacy, &b"\x03\xed"[..], None),
    ] {
        check_peer_close_over_tls(tls.clone(), &connector, mode, payload.to_vec(), expected).await;
    }
}

#[tokio::test]
async fn legacy_peer_close_echoes_only_original_status_for_utf8_reasons_over_tls() {
    use relay::BridgeMode;

    let (roots, tls) = test_tls();
    let connector = relay::tls_config(roots).unwrap();
    let max = format!("{}я!", "🧪".repeat(30));
    assert_eq!(max.len(), 123);
    for (mode, code, reason, expected) in [
        (BridgeMode::Legacy, 1001u16, "ухожу".as_bytes(), Some(2)),
        (BridgeMode::LegacyWorker, 4000, max.as_bytes(), Some(2)),
        (
            BridgeMode::Legacy,
            1002,
            &b"Protocol violation"[..],
            Some(2),
        ),
        (BridgeMode::Legacy, 1005, &b"Protocol violation"[..], None),
        (BridgeMode::Legacy, 1000, &b"\xff"[..], None),
        (BridgeMode::Native, 1001, "ухожу".as_bytes(), None),
    ] {
        let mut payload = code.to_be_bytes().to_vec();
        payload.extend_from_slice(reason);
        check_peer_close_over_tls(tls.clone(), &connector, mode, payload, expected).await;
    }
}

async fn check_peer_close_over_tls(
    tls: TlsAcceptor,
    connector: &tokio_rustls::TlsConnector,
    mode: relay::BridgeMode,
    payload: Vec<u8>,
    expected_length: Option<usize>,
) {
    let invalid_reason = payload.len() > 2 && std::str::from_utf8(&payload[2..]).is_err();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let secure = tls.accept(socket).await.unwrap();
        #[allow(clippy::result_large_err)]
        let mut ws = accept_hdr_async(secure, |_: &Request, mut response: Response| {
            response
                .headers_mut()
                .insert("Sec-WebSocket-Protocol", "binary".parse().unwrap());
            Ok(response)
        })
        .await
        .unwrap();
        assert_eq!(ws.next().await.unwrap().unwrap().into_data().len(), 64);
        let mut wire = ws.into_inner();
        let mut close = vec![0x88, payload.len() as u8];
        close.extend_from_slice(&payload);
        let (header, rest) = close.split_at(3.min(close.len()));
        wire.write_all(header).await.unwrap();
        wire.flush().await.unwrap();
        wire.write_all(rest).await.unwrap();
        wire.flush().await.unwrap();
        if let Some(n) = expected_length {
            let mut reply = [0; 8];
            wire.read_exact(&mut reply[..6 + n]).await.unwrap();
            assert_eq!(reply[..2], [0x88, 0x80 | n as u8]);
            for (i, expected) in payload[..n].iter().enumerate() {
                assert_eq!(reply[i + 6] ^ reply[2 + i % 4], *expected);
            }
        }
        match wire.read(&mut [0]).await {
            Ok(0) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {}
            result => panic!("unexpected bytes after peer Close in {mode:?}: {result:?}"),
        }
    });
    let ws = relay::upgrade(
        TcpStream::connect(address).await.unwrap(),
        "telegram.test",
        "/apiws",
        connector,
    )
    .await
    .unwrap();
    let (mut client, socket) = tokio::io::duplex(64);
    let key = [38; 16];
    let (init, _, _) = crypto::client_fixture(&key, 2, 0xee);
    let session = crypto::Transport::client(init, &key).unwrap();
    let stats = Stats::default();
    let result = timeout(
        Duration::from_secs(2),
        relay::bridge(socket, ws, session, &stats, mode, None),
    )
    .await
    .unwrap();
    if invalid_reason {
        assert!(result.is_err());
    } else {
        result.unwrap();
    }
    timeout(Duration::from_secs(2), upstream)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
    assert_eq!(stats.up.load(Ordering::Relaxed), 0);
    assert_eq!(stats.down.load(Ordering::Relaxed), 0);
}

struct PendingWriter {
    stream: tokio::io::DuplexStream,
    attempted: Arc<tokio::sync::Notify>,
}

const CLIENT_WRITE_FAILURE: &str = "fixture client write failed";

struct FailingClientWriter {
    stream: tokio::io::DuplexStream,
    bytes: Arc<std::sync::Mutex<Vec<u8>>>,
}

impl AsyncRead for FailingClientWriter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buffer)
    }
}

impl AsyncWrite for FailingClientWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.bytes.lock().unwrap().extend_from_slice(buf);
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            CLIENT_WRITE_FAILURE,
        )))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn failed_legacy_client_write_sends_empty_masked_close_over_tls() {
    use relay::BridgeMode;

    const REPLY: &[u8] = b"valid Telegram reply";
    let (roots, tls) = test_tls();
    let connector = relay::tls_config(roots).unwrap();
    for mode in [
        BridgeMode::Legacy,
        BridgeMode::LegacyWorker,
        BridgeMode::Native,
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let upstream = async {
            let (socket, _) = listener.accept().await.unwrap();
            let secure = tls.accept(socket).await.unwrap();
            #[allow(clippy::result_large_err)]
            let mut ws = accept_hdr_async(secure, |req: &Request, res: Response| {
                assert_eq!(req.headers()["Host"], "telegram.test");
                assert_eq!(req.uri().path(), "/apiws");
                Ok(res)
            })
            .await
            .unwrap();
            let init = ws.next().await.unwrap().unwrap().into_data();
            let (tag, dc, _, mut send) =
                crypto::upstream_fixture(init.as_ref().try_into().unwrap());
            assert_eq!((tag, dc), (0xee, 2));
            let mut reply = REPLY.to_vec();
            send.apply_keystream(&mut reply);
            ws.send(Message::binary(reply)).await.unwrap();
            let mut wire = ws.into_inner();
            if mode != BridgeMode::Native {
                let mut close = [0; 6];
                wire.read_exact(&mut close).await.unwrap();
                assert_eq!(close[..2], [0x88, 0x80]);
            }
            match wire.read(&mut [0]).await {
                Ok(0) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {}
                result => panic!("unexpected extra output after failed client write: {result:?}"),
            }
        };
        let (mut client, socket) = tokio::io::duplex(64);
        let key = [43; 16];
        let (init, _, mut recv) = crypto::client_fixture(&key, 2, 0xee);
        let session = crypto::Transport::client(init, &key).unwrap();
        let stats = Stats::default();
        let delivered = Arc::new(std::sync::Mutex::new(Vec::new()));
        let proxy = async {
            let ws = relay::upgrade(
                TcpStream::connect(address).await.unwrap(),
                "telegram.test",
                "/apiws",
                &connector,
            )
            .await
            .unwrap();
            relay::bridge(
                FailingClientWriter {
                    stream: socket,
                    bytes: delivered.clone(),
                },
                ws,
                session,
                &stats,
                mode,
                None,
            )
            .await
        };
        let (result, ()) = timeout(Duration::from_secs(3), async {
            tokio::join!(proxy, upstream)
        })
        .await
        .unwrap();
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(error.to_string(), CLIENT_WRITE_FAILURE);
        let mut attempted = std::mem::take(&mut *delivered.lock().unwrap());
        recv.apply_keystream(&mut attempted);
        assert_eq!(attempted, REPLY);
        assert_eq!(stats.up.load(Ordering::Relaxed), 0);
        assert_eq!(stats.down.load(Ordering::Relaxed), REPLY.len() as u64);
        assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
    }
}

impl AsyncRead for PendingWriter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buffer)
    }
}

impl AsyncWrite for PendingWriter {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        self.attempted.notify_one();
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[tokio::test(start_paused = true)]
async fn failed_legacy_client_write_skips_busy_upload_and_bounds_idle_close() {
    use crate::diagnostics::{Event, WsCause, WsEnd, WsLeg, WsTraffic};
    use nfqws2_tgws_transport::active::Wire;
    use tokio::time::Instant;
    use tokio_tungstenite::{tungstenite::protocol::Role, WebSocketStream};

    for upload_in_progress in [true, false] {
        let mut pool =
            pool::Pool::legacy(0, relay::tls_config(RootCertStore::empty()).unwrap(), 8192);
        let diagnostics = pool.capture_diagnostics();
        let (mut remote, stream) = tokio::io::duplex(64);
        let attempted = Arc::new(tokio::sync::Notify::new());
        let wire = Wire::after_upgrade(tokio::io::BufReader::new(PendingWriter {
            stream,
            attempted: attempted.clone(),
        }));
        let ws = WebSocketStream::from_raw_socket(wire, Role::Client, None).await;
        let (mut client, socket) = tokio::io::duplex(64);
        let key = [41; 16];
        let (init, mut encrypt, _) = crypto::client_fixture(&key, 2, 0xee);
        let session = crypto::Transport::client(init, &key).unwrap();
        let (_, _, _, mut remote_send) = crypto::upstream_fixture(session.init);
        let bridge = tokio::spawn(async move {
            let stats = Stats::default();
            let client = FailingClientWriter {
                stream: socket,
                bytes: Default::default(),
            };
            let error = relay::bridge_initialized(
                client,
                ws,
                session,
                &stats,
                relay::BridgeMode::Legacy,
                Some(&pool),
            )
            .await
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
            assert_eq!(error.to_string(), CLIENT_WRITE_FAILURE);
            (
                stats.up.load(Ordering::Relaxed),
                stats.down.load(Ordering::Relaxed),
            )
        });
        if upload_in_progress {
            let mut encrypted = *b"\x04\0\0\0test";
            encrypt.apply_keystream(&mut encrypted);
            client.write_all(&encrypted).await.unwrap();
            timeout(Duration::from_millis(1), attempted.notified())
                .await
                .unwrap();
        }
        let mut response = *b"\x82\x05reply";
        remote_send.apply_keystream(&mut response[2..]);
        let started = Instant::now();
        remote.write_all(&response).await.unwrap();
        let expected = if upload_in_progress {
            Duration::ZERO
        } else {
            timeout(Duration::from_millis(1), attempted.notified())
                .await
                .unwrap();
            Duration::from_millis(100)
        };
        let (up, down) = timeout(expected + Duration::from_millis(1), bridge)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(started.elapsed(), expected);
        assert_eq!(up, if upload_in_progress { 8 } else { 0 });
        assert_eq!(down, 5);
        let Event::WsSessionClosed(report) = diagnostics.try_recv().unwrap() else {
            panic!("expected the active session's close record");
        };
        assert_eq!(report.end, WsEnd::Flow(WsLeg::ClientWrite, WsCause::Closed));
        assert_eq!(report.upload.bytes, up);
        assert_eq!(report.download, WsTraffic { bytes: 5, units: 1 });
        assert_eq!(report.tenths, if upload_in_progress { 0 } else { 1 });
        assert!(diagnostics.try_recv().is_err());
        assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
        assert_eq!(remote.read(&mut [0]).await.unwrap(), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn legacy_websocket_planned_stop_reports_active_counters_once() {
    use crate::diagnostics::{Event, WsEnd, WsTraffic};
    use nfqws2_tgws_transport::active::Wire;
    use tokio_tungstenite::{tungstenite::protocol::Role, WebSocketStream};

    let (mut remote, stream) = tokio::io::duplex(64);
    let ws = WebSocketStream::from_raw_socket(
        Wire::after_upgrade(tokio::io::BufReader::new(stream)),
        Role::Client,
        None,
    )
    .await;
    let (mut client, socket) = tokio::io::duplex(64);
    let key = [47; 16];
    let (init, mut encrypt, _) = crypto::client_fixture(&key, 2, 0xee);
    let session = crypto::Transport::client(init, &key).unwrap();
    let mut pool = pool::Pool::legacy(0, relay::tls_config(RootCertStore::empty()).unwrap(), 8192);
    let diagnostics = pool.capture_diagnostics();
    let pool = Arc::new(pool);
    let worker_pool = pool.clone();
    let bridge = tokio::spawn(async move {
        let stats = Stats::default();
        relay::bridge_initialized(
            socket,
            ws,
            session,
            &stats,
            relay::BridgeMode::Legacy,
            Some(&worker_pool),
        )
        .await
    });
    let mut payload = *b"\x04\0\0\0test";
    encrypt.apply_keystream(&mut payload);
    client.write_all(&payload).await.unwrap();
    let (frame, data) = timeout(Duration::from_secs(1), read_masked_frame(&mut remote, 8))
        .await
        .unwrap();
    assert_eq!((frame, data.len()), (0x82, 8));
    tokio::time::advance(Duration::from_millis(150)).await;
    pool.mark_planned_stop();
    bridge.abort();
    assert!(bridge.await.unwrap_err().is_cancelled());
    let Event::WsSessionClosed(report) = diagnostics.try_recv().unwrap() else {
        panic!("expected the active session's close record");
    };
    assert_eq!(report.end, WsEnd::Stopped);
    assert_eq!(report.upload, WsTraffic { bytes: 8, units: 2 });
    assert_eq!(report.download, WsTraffic::default());
    assert_eq!(report.tenths, 2);
    assert!(diagnostics.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn legacy_peer_close_skips_blocked_upload_and_bounds_idle_echo() {
    use nfqws2_tgws_transport::active::Wire;
    use tokio::time::Instant;
    use tokio_tungstenite::{tungstenite::protocol::Role, WebSocketStream};

    for (upload_in_progress, pending_pong, close) in [
        (true, false, &b"\x88\x02\x03\xe8"[..]),
        (false, false, &b"\x88\x02\x03\xe8"[..]),
        (true, false, &b"\x88\x05\x03\xe8bye"[..]),
        (false, false, &b"\x88\x05\x03\xe8bye"[..]),
        (false, true, &b"\x88\x05\x03\xe8bye"[..]),
    ] {
        let (mut remote, stream) = tokio::io::duplex(64);
        let attempted = Arc::new(tokio::sync::Notify::new());
        let wire = Wire::after_upgrade(tokio::io::BufReader::new(PendingWriter {
            stream,
            attempted: attempted.clone(),
        }));
        let ws = WebSocketStream::from_raw_socket(wire, Role::Client, None).await;
        let (mut client, socket) = tokio::io::duplex(64);
        let key = [39; 16];
        let (init, mut encrypt, _) = crypto::client_fixture(&key, 2, 0xee);
        let session = crypto::Transport::client(init, &key).unwrap();
        let bridge = tokio::spawn(async move {
            let stats = Stats::default();
            relay::bridge_initialized(socket, ws, session, &stats, relay::BridgeMode::Legacy, None)
                .await
                .unwrap();
            stats.up.load(Ordering::Relaxed)
        });
        if upload_in_progress {
            let mut encrypted = *b"\x04\0\0\0test";
            encrypt.apply_keystream(&mut encrypted);
            client.write_all(&encrypted).await.unwrap();
            timeout(Duration::from_millis(1), attempted.notified())
                .await
                .unwrap();
        }
        if pending_pong {
            remote.write_all(b"\x89\x01?").await.unwrap();
            timeout(Duration::from_millis(1), attempted.notified())
                .await
                .unwrap();
        }
        let started = Instant::now();
        remote.write_all(close).await.unwrap();
        let limit = if upload_in_progress || pending_pong {
            Duration::from_millis(1)
        } else {
            timeout(Duration::from_millis(1), attempted.notified())
                .await
                .unwrap();
            Duration::from_millis(150)
        };
        let bytes_uploaded = timeout(limit, bridge).await.unwrap().unwrap();
        assert_eq!(bytes_uploaded, if upload_in_progress { 8 } else { 0 });
        assert_eq!(
            started.elapsed(),
            if upload_in_progress || pending_pong {
                Duration::ZERO
            } else {
                Duration::from_millis(100)
            }
        );
        assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
        assert_eq!(remote.read(&mut [0]).await.unwrap(), 0);
    }
}

#[tokio::test]
async fn tls_wss_fixture_authenticates_and_relays_a_fragmented_message() {
    let (roots, tls) = test_tls();
    let upstream = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = upstream.local_addr().unwrap();
    let scripted = tokio::spawn(async move {
        let (socket, _) = upstream.accept().await.unwrap();
        assert!(tls.accept(socket).await.is_err());
        let (socket, _) = upstream.accept().await.unwrap();
        let stream = tls.accept(socket).await.unwrap();
        // The upstream header callback fixes the response error type.
        #[allow(clippy::result_large_err)]
        let mut ws = accept_hdr_async(stream, |req: &Request, mut res: Response| {
            assert_eq!(req.uri().path(), "/apiws");
            assert_eq!(req.headers()["Host"], "telegram.test");
            res.headers_mut()
                .insert("Sec-WebSocket-Protocol", "binary".parse().unwrap());
            Ok(res)
        })
        .await
        .unwrap();
        let init = ws.next().await.unwrap().unwrap().into_data();
        let (tag, dc, mut receive, mut send) =
            crypto::upstream_fixture(init.as_ref().try_into().unwrap());
        assert_eq!((tag, dc), (0xdd, -2));
        let mut bytes = ws.next().await.unwrap().unwrap().into_data().to_vec();
        receive.apply_keystream(&mut bytes);
        assert_eq!(bytes.len(), 24580);
        assert_eq!(&bytes[..4], &24576u32.to_le_bytes());
        assert!(bytes[4..].iter().all(|&b| b == 71));
        let mut answer = b"router fixture echo".to_vec();
        send.apply_keystream(&mut answer);
        ws.send(Message::binary(answer)).await.unwrap();
        let _ = ws.close(None).await;
    });
    let wrong = relay::tls_config(RootCertStore::empty()).unwrap();
    assert!(relay::upgrade(
        TcpStream::connect(addr).await.unwrap(),
        "telegram.test",
        "/apiws",
        &wrong
    )
    .await
    .is_err());
    use nfqws2_tgws_config::fallback::{after_direct, Telegram};
    let primary = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unavailable = primary.local_addr().unwrap();
    drop(primary);
    let direct = match TcpStream::connect(unavailable).await {
        Err(e) => Err(e),
        Ok(_) => panic!("unexpected local listener"),
    };
    let target = Telegram::web(1, false);
    let (ws, vpn) = after_direct(direct, target, |endpoint| async move {
        assert_eq!(Some(endpoint), target);
        relay::upgrade(
            TcpStream::connect(addr).await?,
            "telegram.test",
            "/apiws",
            &relay::tls_config(roots)?,
        )
        .await
        .map(Some)
    })
    .await
    .unwrap();
    assert!(vpn);
    assert_eq!(
        after_direct(
            Err::<u8, _>(io::ErrorKind::ConnectionRefused.into()),
            target,
            |_| async { Ok(None) }
        )
        .await
        .unwrap_err()
        .kind(),
        io::ErrorKind::ConnectionRefused
    );
    let never = |_: Telegram| async { panic!("unexpected tunnel dial") };
    assert_eq!(
        after_direct(Ok(1u8), target, never).await.unwrap(),
        (1, false)
    );
    assert!(after_direct(
        Err::<u8, _>(io::ErrorKind::NotConnected.into()),
        Telegram::web(2, false),
        never
    )
    .await
    .is_err());
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let secret = [42; 16];
    let (init, mut send, mut recv) = crypto::client_fixture(&secret, -2, 0xdd);
    let stats = Arc::new(Stats::default());
    let st = stats.clone();
    let job = tokio::spawn(async move {
        relay::bridge(
            server,
            ws,
            crypto::Transport::client(init, &secret).unwrap(),
            &st,
            relay::BridgeMode::Native,
            None,
        )
        .await
    });
    let mut payload = 24576u32.to_le_bytes().to_vec();
    payload.resize(24580, 71);
    send.apply_keystream(&mut payload);
    client.write_all(&payload).await.unwrap();
    let mut answer = [0; 19];
    timeout(Duration::from_secs(4), client.read_exact(&mut answer))
        .await
        .unwrap()
        .unwrap();
    recv.apply_keystream(&mut answer);
    assert_eq!(&answer, b"router fixture echo");
    assert_eq!(stats.up.load(Ordering::Relaxed), 24580);
    assert_eq!(stats.down.load(Ordering::Relaxed), 19);
    scripted.await.unwrap();
    drop(client);
    let _ = job.await.unwrap();
}
