use super::*;
use crate::configured::tests::origin as certificate;
use ctr::cipher::StreamCipher;
use ring::hmac;
use std::sync::Arc;
use tokio::{
    net::TcpListener,
    time::{timeout, Duration},
};
use tokio_rustls::{
    rustls::{pki_types::ServerName, ClientConnection},
    TlsAcceptor,
};
const HOST: &str = "origin.example.test";
fn config() -> Config {
    let mut cfg = Config {
        fake_tls_domain: HOST.into(),
        cfproxy: false,
        pool_size: 0,
        ..Config::default()
    };
    cfg.normalize().unwrap();
    cfg
}
fn hello(name: &str) -> Vec<u8> {
    let (roots, _) = certificate(vec![name.into()]);
    let tls = relay::tls_config(roots).unwrap();
    let mut client = ClientConnection::new(
        tls.config().clone(),
        ServerName::try_from(name.to_owned()).unwrap(),
    )
    .unwrap();
    let mut bytes = Vec::new();
    client.write_tls(&mut bytes).unwrap();
    bytes
}
fn sign(bytes: &mut [u8], key: &[u8; 16], time: u32) {
    bytes[11..43].fill(0);
    let mac = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), bytes);
    bytes[11..43].copy_from_slice(mac.as_ref());
    for (a, b) in bytes[39..43].iter_mut().zip(time.to_le_bytes()) {
        *a ^= b;
    }
}
#[test]
fn ee_accepts_only_a_matching_mac_and_fresh_timestamp() {
    let mut bytes = hello(HOST);
    let stamp = 1_800_000_000u32;
    let key = [19; 16];
    sign(&mut bytes, &key, stamp);
    for delta in [-120i64, 0, 120] {
        assert!(matches!(
            ee::reply(&bytes, &key, (i64::from(stamp) + delta) as u64),
            Ok(ee::Reply::Authenticated(_))
        ));
    }
    for delta in [-121i64, 121] {
        assert!(matches!(
            ee::reply(&bytes, &key, (i64::from(stamp) + delta) as u64),
            Ok(ee::Reply::Expired)
        ));
    }
    assert!(matches!(
        ee::reply(&bytes, &[17; 16], u64::from(stamp)),
        Ok(ee::Reply::Unauthenticated)
    ));
    bytes[11] ^= 1;
    assert!(matches!(
        ee::reply(&bytes, &key, u64::from(stamp)),
        Ok(ee::Reply::Unauthenticated)
    ));
}

#[tokio::test]
async fn expired_ee_can_only_forward_a_valid_legacy_hello_to_the_configured_https_origin() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    for (mode, malformed, stamp, forwarded) in [
        ("", false, now - 600, true),
        ("", false, now + 600, true),
        ("", true, now - 600, false),
        ("direct_wss", false, now - 600, false),
    ] {
        let mut cfg = config();
        cfg.transport = mode.into();
        let mut wire = hello(HOST);
        if malformed {
            wire[43] = 255; // invalid legacy_session_id length
        }
        sign(&mut wire, &cfg.key().unwrap(), stamp);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut sender = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let socket = listener.accept().await.unwrap().0;
        sender.write_all(&wire).await.unwrap();
        sender.shutdown().await.unwrap();
        match receive(socket, &cfg).await {
            Ok(Handshake::Https(client, req)) if forwarded => {
                assert_eq!(req.destination(), (HOST, 443));
                let (target, mut upstream) = tokio::io::duplex(4096);
                req.relay_to(client, target).await.unwrap();
                let mut sent = vec![];
                upstream.read_to_end(&mut sent).await.unwrap();
                assert_eq!(sent, wire);
            }
            Err(_) if !forwarded => {}
            _ => panic!("expired EE must never open an MTProto session"),
        }
        let mut answer = vec![];
        sender.read_to_end(&mut answer).await.unwrap();
        assert!(
            answer.is_empty(),
            "expired EE received an MTProto ServerHello"
        );
    }
}

#[tokio::test]
async fn fragmented_client_hello_requires_complete_bounded_tls_records() {
    let complete = hello(HOST);
    let first = &complete[5..6]; // split the handshake header itself over records
    let rest = &complete[6..];
    let mut split = vec![22, 3, 1, 0, 1, first[0], 22, 3, 1];
    split.extend_from_slice(&(rest.len() as u16).to_be_bytes());
    split.extend_from_slice(rest);
    assert_eq!(read_hello(&mut &split[1..], true).await.unwrap(), split);
    assert!(origin::Request::parse(split.clone(), &config()).is_ok());
    assert!(read_hello(&mut &split[1..], false).await.is_err());
    assert!(read_hello(&mut &split[1..split.len() - 1], true)
        .await
        .is_err());
    split[6] = 23;
    assert!(read_hello(&mut &split[1..], true).await.is_err());
    for header in [
        &[3, 1, 0, 0][..],                  // empty record
        &[3, 1, 64, 1],                     // oversized initial record
        &[3, 1, 0, 4, 1, 0xff, 0xff, 0xff], // oversized message
        &[3, 1, 0, 4, 1, 0, 0, 0],          // too short for ClientHello
    ] {
        assert_eq!(
            read_hello(&mut &header[..], true).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}

#[tokio::test]
async fn authenticated_legacy_record_layer_streams_go_lengths_and_discards_ccs() {
    let app: Vec<_> = (0..u16::MAX).map(|n| n as u8).collect();
    let mut records = vec![20, 3, 1, 0, 0, 20, 3, 2, 16, 1];
    records.extend([0x11; 4097]);
    records.extend([23, 3, 1, 0xff, 0xff]);
    records.extend_from_slice(&app);
    records.extend([21, 3, 3, 0, 2, 1, 0]);
    let mut received = Vec::new();
    let end = records::unwrap_records(records.as_slice(), &mut received, true)
        .await
        .unwrap_err();
    assert_eq!(end.kind(), io::ErrorKind::InvalidData);
    assert_eq!(received, app);

    for head in [[23, 3, 1, 0, 1], [20, 3, 3, 0, 0], [23, 3, 3, 64, 1]] {
        let mut received = Vec::new();
        let error = records::unwrap_records(head.as_slice(), &mut received, false)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(received.is_empty());
    }
}

#[tokio::test]
async fn ee_authenticates_server_and_inner_mtproto_and_streams_records_in_both_directions() {
    let mut cfg = config();
    cfg.proxy_protocol = true;
    let key = cfg.key().unwrap();
    let mut hello = hello(HOST);
    sign(
        &mut hello,
        &key,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32,
    );
    let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer = local.local_addr().unwrap();
    let server = async {
        let (socket, _) = local.accept().await.unwrap();
        let Handshake::Session {
            mut io,
            mut session,
            pump,
        } = receive(socket, &cfg).await.unwrap()
        else {
            panic!("EE session expected")
        };
        assert_eq!((session.dc, session.tag), (-2, 0xdd));
        let mut body = [0; 4];
        io.read_exact(&mut body).await.unwrap();
        session.client_in.apply_keystream(&mut body);
        assert_eq!(&body, b"data");
        let mut answer = *b"seen";
        session.client_out.apply_keystream(&mut answer);
        io.write_all(&answer).await.unwrap();
        drop(io);
        pump.unwrap().finish().await;
    };
    let app = async {
        let mut tcp = TcpStream::connect(peer).await.unwrap();
        tcp.write_all(b"PROXY UNKNOWN\r\n").await.unwrap();
        tcp.write_all(&hello).await.unwrap();
        let mut server = vec![0; 138];
        tcp.read_exact(&mut server).await.unwrap();
        assert_eq!(&server[..11], &[22, 3, 3, 0, 122, 2, 0, 0, 118, 3, 3]);
        assert_eq!(&server[44..76], &hello[44..76]);
        assert_eq!(&server[127..136], &[20, 3, 3, 0, 1, 1, 23, 3, 3]);
        let n = usize::from(u16::from_be_bytes([server[136], server[137]]));
        assert!((1900..=2100).contains(&n));
        server.resize(138 + n, 0);
        tcp.read_exact(&mut server[138..]).await.unwrap();
        let value = server[11..43].to_vec();
        server[11..43].fill(0);
        let mut ctx = hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA256, &key));
        ctx.update(&hello[11..43]);
        ctx.update(&server);
        assert_eq!(value, ctx.sign().as_ref());
        let (init, mut enc, mut dec) = crate::crypto::client_fixture(&key, -2, 0xdd);
        let mut body = *b"data";
        enc.apply_keystream(&mut body);
        tcp.write_all(&[20, 3, 3, 0, 1, 1, 23, 3, 3, 0, 0, 23, 3, 3, 0, 17])
            .await
            .unwrap();
        tcp.write_all(&init[..17]).await.unwrap();
        tcp.write_all(&[23, 3, 3, 0, 51]).await.unwrap();
        tcp.write_all(&init[17..]).await.unwrap();
        tcp.write_all(&body).await.unwrap();
        let mut answer = [0; 9];
        tcp.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer[..5], &[23, 3, 3, 0, 4]);
        dec.apply_keystream(&mut answer[5..]);
        assert_eq!(&answer[5..], b"seen");
    };
    timeout(Duration::from_secs(3), async {
        tokio::join!(server, app);
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn plaintext_returns_the_configured_301_without_an_upstream_connection() {
    let cfg = config();
    let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer = local.local_addr().unwrap();
    let client = async {
        let mut tcp = TcpStream::connect(peer).await.unwrap();
        tcp.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let mut text = String::new();
        tcp.read_to_string(&mut text).await.unwrap();
        assert_eq!(text,format!("HTTP/1.1 301 Moved Permanently\r\nLocation: https://{HOST}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"));
    };
    let server = async {
        assert!(matches!(
            receive(local.accept().await.unwrap().0, &cfg).await,
            Ok(Handshake::Redirected)
        ));
    };
    timeout(Duration::from_secs(3), async {
        tokio::join!(client, server);
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn standard_https_passthrough_uses_one_origin_and_the_client_validates_its_certificate() {
    const ALIAS: &str = "alias.example.test";
    for (transport, client_name, cert_name) in [
        ("direct_wss", HOST, HOST),
        ("direct_wss", HOST, "wrong.example.test"),
        ("", ALIAS, ALIAS),
        ("", ALIAS, HOST),
        // rustls sends a ClientHello without SNI for an IP identity.
        ("", "192.0.2.1", "192.0.2.1"),
    ] {
        let valid = client_name == cert_name;
        let (roots, server) = certificate(vec![cert_name.into()]);
        let mut tls = relay::tls_config(roots).unwrap();
        let fragmented = transport.is_empty() && client_name == ALIAS;
        if fragmented {
            let mut client_cfg = tls.config().as_ref().clone();
            client_cfg.max_fragment_size = Some(64);
            tls = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));
        }
        let mut cfg = config();
        cfg.transport = transport.into();
        let (client, mut source) = tokio::io::duplex(16384);
        let (target, upstream) = tokio::io::duplex(16384);
        let gateway = async {
            assert_eq!(source.read_u8().await.unwrap(), 22);
            let hello = read_hello(&mut source, cfg.transport.is_empty())
                .await
                .unwrap();
            let first_record_len = 5 + usize::from(u16::from_be_bytes([hello[3], hello[4]]));
            assert_eq!(hello.len() > first_record_len, fragmented);
            assert!(matches!(
                ee::reply(&hello, &cfg.key().unwrap(), 0),
                Ok(ee::Reply::Unauthenticated)
            ));
            let request = origin::Request::parse(hello, &cfg).unwrap();
            assert_eq!(request.destination(), (HOST, 443));
            let _ = request.relay_to(source, target).await;
        };
        let webserver = async {
            let accept = TlsAcceptor::from(Arc::new(server));
            let tls = accept.accept(upstream).await;
            if !valid {
                assert!(tls.is_err());
                return;
            }
            let mut tls = tls.unwrap();
            let sni = client_name
                .parse::<std::net::IpAddr>()
                .is_err()
                .then_some(client_name);
            assert_eq!(tls.get_ref().1.server_name(), sni);
            let mut req = [0; 18];
            tls.read_exact(&mut req).await.unwrap();
            assert_eq!(&req, b"GET / HTTP/1.0\r\n\r\n");
            tls.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                .await
                .unwrap();
            tls.shutdown().await.unwrap();
        };
        let app = async {
            let conn = tls
                .connect(ServerName::try_from(client_name).unwrap(), client)
                .await;
            if !valid {
                assert!(conn.is_err());
                return;
            }
            let mut conn = conn.unwrap();
            conn.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
            let mut reply = String::new();
            conn.read_to_string(&mut reply).await.unwrap();
            assert!(reply.ends_with("\r\n\r\nOK"));
        };
        timeout(Duration::from_secs(3), async {
            tokio::join!(gateway, webserver, app);
        })
        .await
        .unwrap();
    }
}
#[test]
fn native_requires_matching_sni_and_both_profiles_require_a_real_hello_and_configured_origin() {
    let mut cfg = config();
    let mut malformed = hello(HOST);
    malformed[5] = 2;
    for transport in ["", "direct_wss"] {
        cfg.transport = transport.into();
        for bytes in [malformed.clone(), vec![0; 64], vec![]] {
            assert!(origin::Request::parse(bytes, &cfg).is_err());
        }
        for name in ["different.example.test", "192.0.2.1"] {
            assert_eq!(
                origin::Request::parse(hello(name), &cfg).is_ok(),
                transport.is_empty()
            );
        }
    }
    cfg.transport.clear();
    for domain in ["", "localhost", "127.0.0.1", "alias.example.test:8443"] {
        cfg.fake_tls_domain = domain.into();
        assert!(origin::Request::parse(hello(HOST), &cfg).is_err());
    }
}

#[tokio::test(start_paused = true)]
async fn legacy_dials_for_ten_seconds_and_closes_both_sides_at_the_first_eof() {
    for (mode, dial_seconds) in [("", 10), ("direct_wss", 5)] {
        let mut cfg = config();
        cfg.transport = mode.into();
        for client_fin in [true, false] {
            let hello = hello(HOST);
            let request = origin::Request::parse(hello.clone(), &cfg).unwrap();
            assert_eq!(request.dial_timeout(), Duration::from_secs(dial_seconds));
            let (mut client, source) = tokio::io::duplex(4096);
            let (target, mut upstream) = tokio::io::duplex(4096);
            let task = tokio::spawn(async move { request.relay_to(source, target).await });
            let mut initial = vec![0; hello.len()];
            upstream.read_exact(&mut initial).await.unwrap();
            assert_eq!(initial, hello);

            let (first, other) = if client_fin {
                (&mut client, &mut upstream)
            } else {
                (&mut upstream, &mut client)
            };
            first.shutdown().await.unwrap();
            let mut buf = [0; 6];
            assert_eq!(other.read(&mut buf).await.unwrap(), 0);
            if mode.is_empty() {
                timeout(Duration::from_millis(1), task)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                assert_eq!(first.read(&mut buf).await.unwrap(), 0);
            } else {
                assert!(!task.is_finished());
                let record = [23, 3, 3, 0, 1, 42];
                other.write_all(&record).await.unwrap();
                first.read_exact(&mut buf).await.unwrap();
                assert_eq!(buf, record);
                other.shutdown().await.unwrap();
                task.await.unwrap().unwrap();
            }
        }
    }
}
