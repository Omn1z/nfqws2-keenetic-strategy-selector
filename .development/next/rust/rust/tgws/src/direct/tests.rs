use super::*;
use crate::configured::tests::origin;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_rustls::{rustls::server::Acceptor, LazyConfigAcceptor, TlsAcceptor};
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::handshake::server::{Request, Response},
};

#[tokio::test]
async fn empty_roots_disable_alternate_sni_and_reject_tls_before_http() {
    let domain = "kws2.web.telegram.org";
    let roots = RootCertStore::empty();
    let (_, server) = origin(vec![domain.into(), GO_SNI.into()]);
    let mut direct = Direct::new(
        relay::tls_config(roots.clone()).unwrap(),
        Default::default(),
        false,
    );
    direct
        .identities(roots, Some(Arc::new(Stats::default())))
        .unwrap();
    assert!(direct.alternate.is_none());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer = listener.local_addr().unwrap();
    let server = async {
        let (tcp, _) = listener.accept().await.unwrap();
        assert!(TlsAcceptor::from(Arc::new(server))
            .accept(tcp)
            .await
            .is_err());
    };
    let client = direct.dial(domain, "/apiws", 8192, None, |_| TcpStream::connect(peer));
    let (result, ()) = timeout(Duration::from_secs(4), async {
        tokio::join!(client, server)
    })
    .await
    .unwrap();
    assert!(result.is_err());
}

#[tokio::test(start_paused = true)]
async fn media_refill_stops_at_first_queue_timeout_and_keeps_network_failure() {
    use futures_util::FutureExt;
    let (roots, _) = origin(vec!["media.example.test".into()]);
    let slots = crate::handshakes::Handshakes::default();
    let mut direct = Direct::new(
        relay::tls_config(roots.clone()).unwrap(),
        slots.clone(),
        false,
    );
    let stats = Arc::new(Stats::default());
    direct.identities(roots, Some(stats.clone())).unwrap();
    direct.report_legacy_errors(stats.clone());
    let mut held = Vec::new();
    for _ in 0..3 {
        held.push(slots.acquire().await.unwrap());
    }
    let (refuse, trigger) = tokio::sync::oneshot::channel();
    let mut first_socket = Some(trigger);
    let refill = direct.dial_domains(
        "media.example.test",
        Some("ordinary.example.test"),
        "/apiws_test",
        8192,
        None,
        |_| {
            let trigger = first_socket
                .take()
                .expect("only the first attempt may dial");
            async {
                trigger.await.unwrap();
                Err(io::ErrorKind::ConnectionRefused.into())
            }
        },
    );
    tokio::pin!(refill);
    assert!(refill.as_mut().now_or_never().is_none());

    // A competing session takes the last slot as soon as the first dial
    // fails. Both the alternate SNI and the next hostname would need it.
    let competitor = slots.acquire();
    tokio::pin!(competitor);
    assert!(competitor.as_mut().now_or_never().is_none());
    refuse.send(()).unwrap();
    assert!(refill.as_mut().now_or_never().is_none());
    held.push(competitor.await.unwrap());
    tokio::time::advance(Duration::from_secs(1)).await;
    match refill.now_or_never() {
        Some(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused),
        _ => panic!("refill should retain its network failure after a single queue wait"),
    }
    assert_eq!(stats.errors.load(Ordering::Relaxed), 1);
}

#[test]
fn stock_ip_certificate_requires_matching_peer_and_opted_in_fronted_dc() {
    // No socket is opened to this address: pass the kernel-observed peer as
    // an argument to the identical policy used for real connections.
    let stock = IpAddr::from([149, 154, 167, 220]);
    let wrong = IpAddr::from([192, 0, 2, 3]);
    let cert = rcgen::generate_simple_self_signed(vec![stock.to_string()])
        .unwrap()
        .cert;
    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let pki = WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(tokio_rustls::rustls::crypto::ring::default_provider()),
    )
    .build()
    .unwrap();
    let front = ServerName::try_from(GO_SNI).unwrap();
    for (domain, path, enabled, redirect, ok) in [
        ("kws2.web.telegram.org", "/apiws", true, Some(stock), true),
        (
            "kws4-1.web.telegram.org",
            "/apiws_test",
            true,
            Some(stock),
            true,
        ),
        ("kws2.web.telegram.org", "/apiws", false, Some(stock), false),
        ("kws2.web.telegram.org", "/apiws", true, None, true),
        ("kws2.web.telegram.org", "/other", true, Some(stock), false),
        ("kws3.web.telegram.org", "/apiws", true, Some(stock), false),
        ("relay.example.test", "/apiws", true, Some(stock), false),
    ] {
        let service = stock_service(domain, path).filter(|_| enabled);
        let verifier = VerifyAuthority {
            pki: pki.clone(),
            name: ServerName::try_from(domain).unwrap(),
            managed_ip: redirect_identity(redirect, stock, service).unwrap(),
            fronted_sibling: service.map(|dc| sibling_authority(domain, dc).unwrap()),
        };
        assert_eq!(
            verifier
                .verify_server_cert(cert.der(), &[], &front, &[], UnixTime::now())
                .is_ok(),
            ok
        );
    }
    assert!(redirect_identity(Some(stock), wrong, Some(2)).is_err());
    let awg_front = IpAddr::from([149, 154, 174, 100]);
    assert_eq!(
        redirect_identity(None, awg_front, Some(1)).unwrap(),
        Some(awg_front)
    );
    assert_eq!(
        redirect_identity(None, awg_front, Some(3)).unwrap(),
        Some(awg_front)
    );
    assert_eq!(redirect_identity(None, awg_front, Some(5)).unwrap(), None);
    assert_eq!(redirect_identity(None, wrong, Some(1)).unwrap(), None);
}

#[tokio::test]
async fn successful_sni_is_tried_first_until_the_other_mode_recovers() {
    let domain = "kws2-1.web.telegram.org";
    let (roots, server) = origin(vec![domain.into(), GO_SNI.into()]);
    let mut direct = Direct::new(
        relay::tls_config(roots.clone()).unwrap(),
        Default::default(),
        false,
    );
    let stats = Arc::new(Stats::default());
    direct.identities(roots, Some(stats.clone())).unwrap();
    direct.report_legacy_errors(stats.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let accept = TlsAcceptor::from(Arc::new(server));
        for (name, ok) in [
            (domain, false),
            (GO_SNI, true),
            (GO_SNI, false),
            (domain, true),
            (domain, true),
        ] {
            let tls = accept
                .accept(listener.accept().await.unwrap().0)
                .await
                .unwrap();
            assert_eq!(tls.get_ref().1.server_name(), Some(name));
            #[allow(clippy::result_large_err)]
            let ws = accept_hdr_async(tls, |req: &Request, mut res: Response| {
                assert_eq!(req.headers()["Host"], domain);
                assert_eq!(req.uri().path(), "/apiws_test");
                if !ok {
                    return Err(http::Response::builder().status(403).body(None).unwrap());
                }
                res.headers_mut()
                    .insert("Sec-WebSocket-Protocol", "binary".parse().unwrap());
                Ok(res)
            })
            .await;
            assert_eq!(ws.is_ok(), ok);
        }
    });
    timeout(Duration::from_secs(4), async {
        for _ in 0..3 {
            drop(
                direct
                    .dial(domain, "/apiws_test", 8192, None, |_| {
                        TcpStream::connect(peer)
                    })
                    .await
                    .unwrap(),
            );
        }
        upstream.await.unwrap();
    })
    .await
    .unwrap();
    assert_eq!(stats.fronting.load(Ordering::Relaxed), 1);
    assert_eq!(stats.errors.load(Ordering::Relaxed), 2);
}
#[tokio::test]
async fn alternate_sni_authenticates_an_authorized_identity_before_any_request() {
    let authority = "kws2.web.telegram.org";
    for (cert_name, trusted, managed, success) in [
        (authority, true, false, true),
        ("kws2-1.web.telegram.org", true, false, true),
        ("kws2-1.web.telegram.org", false, false, false),
        ("kws3-1.web.telegram.org", true, false, false),
        (GO_SNI, true, false, true),
        (GO_SNI, false, false, false),
        ("other.example.test", true, false, false),
        (authority, false, false, false),
        ("127.0.0.1", true, true, true),
        ("127.0.0.2", true, true, false),
        ("127.0.0.1", false, true, false),
        ("127.0.0.1", true, false, false),
    ] {
        let (mut roots, cert) = origin(vec![cert_name.into()]);
        if !trusted {
            roots = origin(vec!["different.example".into()]).0;
        }
        let stats = Arc::new(Stats::default());
        let mut direct = Direct::new(
            relay::tls_config(roots.clone()).unwrap(),
            Default::default(),
            false,
        );
        direct.identities(roots, Some(stats.clone())).unwrap();
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = local.local_addr().unwrap();
        let server = tokio::spawn(async move {
            // Initial normal route unavailable; the second attempt keeps
            // the same socket peer and presents the alternate TLS SNI.
            drop(local.accept().await.unwrap().0);
            let (tcp, _) = local.accept().await.unwrap();
            let Ok(tls) = TlsAcceptor::from(Arc::new(cert)).accept(tcp).await else {
                return false;
            };
            assert_eq!(tls.get_ref().1.server_name(), Some(GO_SNI));
            #[allow(clippy::result_large_err)]
            let ws = accept_hdr_async(tls, |req: &Request, mut res: Response| {
                assert_eq!(req.headers()["Host"], authority);
                res.headers_mut()
                    .insert("Sec-WebSocket-Protocol", "binary".parse().unwrap());
                Ok(res)
            })
            .await;
            ws.is_ok()
        });
        let test = async {
            let ws = direct
                .dial(
                    authority,
                    "/apiws",
                    8192,
                    managed.then(|| peer.ip()),
                    |_| TcpStream::connect(peer),
                )
                .await;
            assert_eq!(ws.is_ok(), success);
            assert_eq!(server.await.unwrap(), success);
        };
        timeout(Duration::from_secs(3), test).await.unwrap();
        assert_eq!(stats.fronting.load(Ordering::Relaxed), u64::from(success));
    }
}

#[tokio::test]
async fn front_identity_is_scoped_to_opt_in_telegram_ws_and_certificate_validity() {
    const DC: &str = "kws2.web.telegram.org";
    for (name, path, alternate, expired) in [
        (DC, "/apiws", false, false),
        ("example.test", "/apiws", true, false),
        ("kws6.web.telegram.org", "/apiws", true, false),
        (DC, "/other", true, false),
        (DC, "/apiws_test", true, true),
    ] {
        let mut params = rcgen::CertificateParams::new(vec![GO_SNI.to_owned()]).unwrap();
        if expired {
            params.not_before = rcgen::date_time_ymd(2000, 1, 1);
            params.not_after = rcgen::date_time_ymd(2001, 1, 1);
        }
        let (roots, cert) = crate::configured::tests::fixture_origin(params);
        let mut direct = Direct::new(
            relay::tls_config(roots.clone()).unwrap(),
            Default::default(),
            false,
        );
        direct
            .identities(roots, alternate.then(|| Arc::new(Stats::default())))
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            assert!(TlsAcceptor::from(Arc::new(cert)).accept(tcp).await.is_err());
        });
        timeout(Duration::from_secs(3), async {
            let tcp = TcpStream::connect(addr).await.unwrap();
            assert!(direct
                .upgrade(tcp, name, path, alternate, None)
                .await
                .is_err());
            server.await.unwrap();
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn legacy_alternate_sni_accepts_expired_untrusted_front_only_for_telegram_ws() {
    const DC: &str = "kws2.web.telegram.org";
    for (host, path, enabled, alternate, expected) in [
        (DC, "/apiws", true, true, true),
        (DC, "/apiws_test", true, true, true),
        (DC, "/apiws", false, true, false),
        (DC, "/apiws", true, false, false),
        (DC, "/other", true, true, false),
        ("relay.example.test", "/apiws", true, true, false),
    ] {
        let mut params = rcgen::CertificateParams::new(vec!["other.example.test".into()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2000, 1, 1);
        params.not_after = rcgen::date_time_ymd(2001, 1, 1);
        let (_, cert) = crate::configured::tests::fixture_origin(params);
        let roots = RootCertStore::empty();
        let mut direct = Direct::new(
            relay::tls_config(roots.clone()).unwrap(),
            Default::default(),
            true,
        );
        direct
            .identities(roots, enabled.then(|| Arc::new(Stats::default())))
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = async {
            let (tcp, _) = listener.accept().await.unwrap();
            let incoming = LazyConfigAcceptor::new(Acceptor::default(), tcp)
                .await
                .unwrap();
            let wanted_sni = if expected { GO_SNI } else { host };
            assert_eq!(incoming.client_hello().server_name(), Some(wanted_sni));
            let stream = incoming.into_stream(Arc::new(cert)).await;
            if !expected {
                assert!(stream.is_err());
                return;
            }
            #[allow(clippy::result_large_err)]
            let accept = accept_hdr_async(
                stream.unwrap(),
                |request: &Request, mut response: Response| {
                    assert_eq!(request.headers()["Host"], host);
                    assert_eq!(request.uri().path(), path);
                    response
                        .headers_mut()
                        .insert("Sec-WebSocket-Protocol", "binary".parse().unwrap());
                    Ok(response)
                },
            );
            assert!(accept.await.is_ok());
        };
        let client = async {
            let tcp = TcpStream::connect(addr).await.unwrap();
            assert_eq!(
                direct
                    .upgrade(tcp, host, path, alternate, Some(addr.ip()))
                    .await
                    .is_ok(),
                expected
            );
        };
        timeout(Duration::from_secs(3), async {
            tokio::join!(server, client)
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn legacy_ordinary_sni_requires_the_hostname_even_for_a_saved_ip() {
    let (roots, cert) = origin(vec!["127.0.0.1".into()]);
    let mut direct = Direct::new(
        relay::tls_config(roots.clone()).unwrap(),
        Default::default(),
        true,
    );
    direct.identities(roots, None).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = async {
        let (tcp, _) = listener.accept().await.unwrap();
        assert!(TlsAcceptor::from(Arc::new(cert)).accept(tcp).await.is_err());
    };
    let client = async {
        let tcp = TcpStream::connect(addr).await.unwrap();
        assert!(direct
            .upgrade(
                tcp,
                "kws2.web.telegram.org",
                "/apiws",
                false,
                Some(addr.ip())
            )
            .await
            .is_err());
    };
    timeout(Duration::from_secs(3), async {
        tokio::join!(server, client)
    })
    .await
    .unwrap();
}
