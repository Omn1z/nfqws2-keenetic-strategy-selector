//! Verified binary WebSocket transport shared by the Telegram MTProto and SOCKS5 clients.
use futures_util::{SinkExt, StreamExt};
use portable_atomic::AtomicU64;
use std::{
    io,
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};
pub mod active;
mod handshakes;
mod listener;
mod upgrade;
pub use handshakes::Handshakes;
pub use listener::bind_wildcard;
use tokio_rustls::{
    rustls::{pki_types::ServerName, ClientConfig, RootCertStore},
    TlsConnector,
};
use tokio_tungstenite::{tungstenite::Message, WebSocketStream};
pub use upgrade::ws_rejection_status;

pub const MAX_PACKET: usize = 8 << 20;
const MAX_WS_MESSAGE: usize = 16 << 20;
pub fn tls() -> io::Result<TlsConnector> {
    tls_config(nfqws2_tls_roots::load()?)
}
pub fn tls_config(roots: RootCertStore) -> io::Result<TlsConnector> {
    let cfg = ClientConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(io::Error::other)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(cfg)))
}
use tokio_util::either::Either;
type Socket = Either<tokio_rustls::client::TlsStream<TcpStream>, TcpStream>;
pub type Ws = WebSocketStream<active::Wire<BufReader<Socket>>>;
pub fn socket(ws: &Ws) -> &TcpStream {
    match ws.get_ref().socket.get_ref() {
        Either::Left(tls) => tls.get_ref().0,
        Either::Right(tcp) => tcp,
    }
}
pub async fn upgrade(
    tcp: TcpStream,
    domain: &str,
    path: &str,
    tls: &TlsConnector,
) -> io::Result<Ws> {
    let name = ServerName::try_from(domain.to_string()).map_err(io::Error::other)?;
    let secure = tls.connect(name, tcp).await?;
    upgrade_tls(secure, domain, path).await
}
pub async fn upgrade_tls(
    secure: tokio_rustls::client::TlsStream<TcpStream>,
    domain: &str,
    path: &str,
) -> io::Result<Ws> {
    websocket(Either::Left(secure), "wss", domain, path).await
}
pub async fn upgrade_plain(tcp: TcpStream, domain: &str, path: &str) -> io::Result<Ws> {
    websocket(Either::Right(tcp), "ws", domain, path).await
}
async fn websocket(stream: Socket, scheme: &str, domain: &str, path: &str) -> io::Result<Ws> {
    upgrade::client(stream, &format!("{scheme}://{domain}{path}")).await
}
pub fn configure_socket(stream: &TcpStream, buffer_size: i64) {
    let socket = socket2::SockRef::from(stream);
    let window = buffer_size.clamp(4096, i64::from(i32::MAX)) as usize;
    let _ = stream.set_nodelay(true);
    let _ = socket.set_recv_buffer_size(window);
    let _ = socket.set_send_buffer_size(window);
}

/// Apply Go's outgoing TCP defaults while leaving OS buffer sizing intact.
pub fn configure_tcp_fallback(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    let interval = Duration::from_secs(15);
    let keepalive = socket2::TcpKeepalive::new().with_time(interval);
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "emscripten",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "visionos",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "windows",
        target_os = "cygwin",
        target_os = "nuttx",
        all(target_os = "wasi", not(target_env = "p1")),
    ))]
    let keepalive = keepalive.with_interval(interval).with_retries(9);
    let _ = socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive);
}

#[cfg(test)]
#[tokio::test]
async fn tcp_fallback_preserves_system_buffers_and_enables_go_keepalive() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (_server, _) = listener.accept().await.unwrap();
    let socket = socket2::SockRef::from(&client);
    let receive = socket.recv_buffer_size().unwrap();
    let send = socket.send_buffer_size().unwrap();

    configure_tcp_fallback(&client);

    assert_eq!(socket.recv_buffer_size().unwrap(), receive);
    assert_eq!(socket.send_buffer_size().unwrap(), send);
    assert!(client.nodelay().unwrap());
    assert!(socket.keepalive().unwrap());
    #[cfg(target_os = "linux")]
    {
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

/// Recover the DC hint from a stream already selected for Telegram.
/// A client without a trusted network or credentials must speak Obfuscated2.
pub fn socks_dc(init: &[u8; 64], ip_guess: u8, require_tag: bool) -> Option<u8> {
    use ctr::cipher::{KeyIvInit, StreamCipher};
    let mut clear = *init;
    let mut aes =
        ctr::Ctr128BE::<aes::Aes256>::new_from_slices(&init[8..40], &init[40..56]).unwrap();
    aes.apply_keystream(&mut clear);
    if require_tag
        && ![0xdd, 0xee, 0xef]
            .iter()
            .any(|tag| clear[56..60] == [*tag; 4])
    {
        return None;
    }
    let dc = i32::from_le_bytes(clear[60..].try_into().unwrap()).unsigned_abs();
    Some(if (1..=5).contains(&dc) {
        dc as u8
    } else {
        ip_guess
    })
}
/// A SOCKS client already encrypts its stream end to end. Forward its first
/// 64 bytes verbatim and flush partial TCP reads as individual binary messages.
pub async fn transparent(
    tcp: TcpStream,
    mut ws: Ws,
    init: &[u8; 64],
    up: &AtomicU64,
    down: &AtomicU64,
) -> io::Result<()> {
    active::write(ws.send(Message::binary(init.to_vec()))).await?;
    let mut active = ws.get_ref().active();
    let (mut reader, mut writer) = tcp.into_split();
    let (mut sink, mut incoming) = ws.split();
    let upload = async {
        let mut buf = vec![0; 65536];
        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                return Ok(());
            }
            up.fetch_add(n as u64, Ordering::Relaxed);
            active::write(sink.send(Message::binary(buf[..n].to_vec()))).await?;
        }
    };
    let download = async {
        while let Some(bytes) = active.next_data(&mut incoming).await? {
            down.fetch_add(bytes.len() as u64, Ordering::Relaxed);
            writer.write_all(&bytes).await?;
        }
        writer.shutdown().await
    };
    tokio::select! {res=upload=>res,res=download=>res}
}
#[cfg(test)]
mod socks_tests;
