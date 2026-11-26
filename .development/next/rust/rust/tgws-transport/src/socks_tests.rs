use super::*;
use ctr::cipher::{KeyIvInit, StreamCipher};
use tokio::{
    net::TcpListener,
    time::{timeout, Duration},
};
use tokio_rustls::{
    rustls::{pki_types::PrivatePkcs8KeyDer, ServerConfig},
    TlsAcceptor,
};
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::handshake::server::{Request, Response},
};

fn init(dc: i32, tag: u8) -> [u8; 64] {
    let mut wire = std::array::from_fn(|i| i as u8 + 17);
    let mut plaintext = wire;
    plaintext[56..60].fill(tag);
    plaintext[60..].copy_from_slice(&dc.to_le_bytes());
    let mut aes =
        ctr::Ctr128BE::<aes::Aes256>::new_from_slices(&wire[8..40], &wire[40..56]).unwrap();
    aes.apply_keystream(&mut plaintext);
    wire[56..].copy_from_slice(&plaintext[56..]);
    wire
}
#[test]
fn reads_signed_socks_datacenter_and_preserves_opaque_transport_tags() {
    for tag in [0xef, 0xee, 0xdd] {
        assert_eq!(socks_dc(&init(-4, tag), 2, true), Some(4));
    }
    for (dc, tag) in [(0, 0xdd), (6, 0xee), (i32::MIN, 0xef)] {
        assert_eq!(socks_dc(&init(dc, tag), 2, true), Some(2));
    }
    assert_eq!(socks_dc(&init(1, 0x00), 2, false), Some(1));
    assert_eq!(socks_dc(&init(1, 0x00), 2, true), None);
}
#[tokio::test]
async fn verified_socks_wss_sends_init_verbatim_and_subpacket_writes_without_delay() {
    let key = rcgen::generate_simple_self_signed(vec!["kws4.web.telegram.org".into()]).unwrap();
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
    let listen = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listen.local_addr().unwrap();
    let start = init(-4, 0xee);
    let server = tokio::spawn(async move {
        let tls = TlsAcceptor::from(Arc::new(server));
        let (socket, _) = listen.accept().await.unwrap();
        assert!(tls.accept(socket).await.is_err());
        let (socket, _) = listen.accept().await.unwrap();
        let io = tls.accept(socket).await.unwrap();
        #[allow(clippy::result_large_err)]
        let mut ws = accept_hdr_async(io, |req: &Request, mut reply: Response| {
            assert_eq!(req.uri().path(), "/apiws");
            assert_eq!(req.headers()["Host"], "kws4.web.telegram.org");
            reply
                .headers_mut()
                .insert("Sec-WebSocket-Protocol", "binary".parse().unwrap());
            Ok(reply)
        })
        .await
        .unwrap();
        assert_eq!(
            ws.next().await.unwrap().unwrap().into_data().as_ref(),
            &start
        );
        assert_eq!(
            ws.next().await.unwrap().unwrap().into_data().as_ref(),
            b"xy"
        );
        ws.send(Message::binary(b"pong".to_vec())).await.unwrap();
        ws.send(Message::text("ёж")).await.unwrap();
        ws.close(None).await.unwrap();
    });
    let trusted = tls_config(roots).unwrap();
    assert!(upgrade(
        TcpStream::connect(addr).await.unwrap(),
        "kws3.web.telegram.org",
        "/apiws",
        &trusted
    )
    .await
    .is_err());
    let ws = upgrade(
        TcpStream::connect(addr).await.unwrap(),
        "kws4.web.telegram.org",
        "/apiws",
        &trusted,
    )
    .await
    .unwrap();
    let listen = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let mut local = TcpStream::connect(listen.local_addr().unwrap())
        .await
        .unwrap();
    let (socket, _) = listen.accept().await.unwrap();
    let up = AtomicU64::default();
    let down = AtomicU64::default();
    let relay = transparent(socket, ws, &start, &up, &down);
    let client = async {
        local.write_all(b"xy").await.unwrap();
        let mut data = [0; 8];
        local.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, "pongёж".as_bytes());
    };
    let (result, ()) = timeout(Duration::from_secs(3), async {
        tokio::join!(relay, client)
    })
    .await
    .unwrap();
    result.unwrap();
    server.await.unwrap();
    assert_eq!(
        (up.load(Ordering::Relaxed), down.load(Ordering::Relaxed)),
        (2, 8)
    );
}
