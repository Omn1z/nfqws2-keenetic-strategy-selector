use super::{invalid, Config, Counters};
use nfqws2_tgws_config::fallback::{connect_named, connect_public, public_relay_ip, Telegram};
use nfqws2_tgws_transport::configure_socket;
use portable_atomic::AtomicU64;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::atomic::Ordering,
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::{timeout, timeout_at, Instant},
};

const TIMEOUT: Duration = Duration::from_secs(15);
const LEGACY_DIAL: Duration = Duration::from_secs(10);
enum Target {
    Addr(IpAddr),
    Domain(String),
}
impl Target {
    fn telegram_dc(&self) -> Option<u8> {
        let ip = match self {
            Self::Addr(ip) => *ip,
            Self::Domain(host) => host.parse::<IpAddr>().ok()?,
        };
        let IpAddr::V4(ip) = ip.to_canonical() else {
            return None;
        };
        // A SOCKS CONNECT to an unrelated address must never send its first
        // 64 bytes to Telegram. Classify only Telegram's DC networks.
        match ip.octets() {
            [149, 154, 160..=163 | 172..=175, _] => Some(1),
            [149, 154, 164..=167, _] => Some(2),
            [149, 154, 168..=171, _] => Some(3),
            [91, 108, 56..=59, _] => Some(5),
            [91, 108, 8..=11, _] => Some(3),
            [91, 108, 12..=15, _] => Some(4),
            [91, 108, 4..=7 | 16..=19 | 20..=23, _]
            | [91, 105, 192..=193, _]
            | [185, 76, 151, _] => Some(2),
            _ => None,
        }
    }
    // Used only after the fallback connector has accepted this destination.
    // DC1 and DC3 share a web frontend IP; only the hostname identifies the DC.
    fn vpn_dc(&self) -> u8 {
        let ip = match self {
            Self::Addr(ip) => *ip,
            Self::Domain(name) => {
                let name = name.strip_suffix('.').unwrap_or(name);
                if let Some((server, domain)) = name.split_once('.') {
                    if domain.eq_ignore_ascii_case("web.telegram.org") {
                        let server = server.strip_suffix("-1").unwrap_or(server);
                        for (label, dc) in [("kws1", 1), ("kws3", 3), ("kws5", 5)] {
                            if server.eq_ignore_ascii_case(label) {
                                return dc;
                            }
                        }
                    }
                }
                let Ok(ip) = name.parse::<IpAddr>() else {
                    return 0;
                };
                ip
            }
        };
        match ip.to_canonical() {
            IpAddr::V4(ip) => match ip.octets() {
                [149, 154, 175, 50] => 1,
                [149, 154, 175, 100] => 3,
                [149, 154, 171, 5] | [149, 154, 170, 100] => 5,
                _ => 0,
            },
            _ => 0,
        }
    }
}
async fn octets(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let n = stream.read_u8().await?;
    let mut v = vec![0; n as usize];
    stream.read_exact(&mut v).await?;
    Ok(v)
}
async fn handshake(client: &mut TcpStream, cfg: &Config) -> io::Result<(Target, u16)> {
    let legacy = cfg.transport() == "telegram_wss";
    if client.read_u8().await? != 5 {
        return Err(invalid("SOCKS5 version"));
    }
    let methods = octets(client).await?;
    let method = if cfg.user.is_empty() { 0 } else { 2 };
    if (method != 0 || !legacy) && !methods.contains(&method) {
        client.write_all(&[5, 255]).await?;
        return Err(invalid("SOCKS5 auth method"));
    }
    client.write_all(&[5, method]).await?;
    if method == 2 {
        let version = client.read_u8().await?;
        if legacy && version != 1 {
            return Err(invalid("SOCKS5 credentials version"));
        }
        let user = octets(client).await?;
        let pass = octets(client).await?;
        let matches = user.ct_eq(cfg.user.as_bytes()) & pass.ct_eq(cfg.pass.as_bytes());
        let ok = version == 1 && bool::from(matches);
        client.write_all(&[1, u8::from(!ok)]).await?;
        if !ok {
            return Err(invalid("SOCKS5 credentials"));
        }
    }
    let mut header = [0u8; 4];
    client.read_exact(&mut header).await?;
    if header[1] != 1 || legacy && header[0] != 5 {
        reply(client, 7, None).await?;
        return Err(invalid("SOCKS5 supports TCP CONNECT"));
    }
    if !legacy && (header[0] != 5 || header[2] != 0) {
        reply(client, 1, None).await?;
        return Err(invalid("invalid SOCKS5 request header"));
    }
    let target = match header[3] {
        1 => Target::Addr(IpAddr::V4(Ipv4Addr::from(client.read_u32().await?))),
        4 => {
            let mut ip = [0; 16];
            client.read_exact(&mut ip).await?;
            Target::Addr(IpAddr::V6(Ipv6Addr::from(ip)))
        }
        3 => {
            let raw = octets(client).await?;
            if raw.is_empty() {
                reply(client, 8, None).await?;
                return Err(invalid("empty target"));
            }
            Target::Domain(String::from_utf8(raw).map_err(|_| invalid("invalid target"))?)
        }
        _ => {
            reply(client, 8, None).await?;
            return Err(invalid("SOCKS5 address type"));
        }
    };
    let port = client.read_u16().await?;
    Ok((target, port))
}
async fn reply(client: &mut TcpStream, code: u8, addr: Option<SocketAddr>) -> io::Result<()> {
    let addr = addr.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
    let mut data = Vec::with_capacity(22);
    data.extend_from_slice(&[5, code, 0]);
    match addr.ip() {
        IpAddr::V4(ip) => {
            data.push(1);
            data.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            data.push(4);
            data.extend_from_slice(&ip.octets());
        }
    }
    data.extend_from_slice(&addr.port().to_be_bytes());
    client.write_all(&data).await
}
async fn pipe(
    mut from: impl AsyncRead + Unpin,
    mut to: impl AsyncWrite + Unpin,
    counter: &AtomicU64,
    buffer: usize,
    legacy: bool,
) -> io::Result<()> {
    let mut buf = vec![0; buffer];
    loop {
        let n = from.read(&mut buf).await?;
        if n == 0 {
            return to.shutdown().await;
        }
        if legacy {
            counter.fetch_add(n as u64, Ordering::Relaxed);
            to.write_all(&buf[..n]).await?;
            continue;
        }
        let mut remaining = &buf[..n];
        while !remaining.is_empty() {
            let written = to.write(remaining).await?;
            if written == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            counter.fetch_add(written as u64, Ordering::Relaxed);
            remaining = &remaining[written..];
        }
    }
}
pub(super) async fn serve(
    mut client: TcpStream,
    cfg: &Config,
    stats: &Counters,
    owner: std::sync::Weak<crate::http::AppState>,
    telegram_only: bool,
) {
    let _active = stats.begin();
    configure_socket(&client, cfg.buffer_size);
    let (target, port) = match timeout(TIMEOUT, handshake(&mut client, cfg)).await {
        Ok(Ok(pair)) => pair,
        _ => {
            stats.bad.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    let legacy = cfg.transport() == "telegram_wss";
    let telegram = legacy.then(|| target.telegram_dc()).flatten();
    if telegram_only && telegram.is_none() {
        let _ = reply(&mut client, 2, None).await;
        return;
    }
    if legacy {
        // The Go clients expect this reply before the upstream connection or
        // any attempt to read a Telegram preface.
        if reply(&mut client, 0, Some(([127, 0, 0, 1], port).into()))
            .await
            .is_err()
        {
            return;
        }
        if let Some(guess) = telegram {
            let mut init = [0; 64];
            if !timeout(TIMEOUT, client.read_exact(&mut init))
                .await
                .is_ok_and(|result| result.is_ok())
            {
                return;
            }
            let Some(dc) = nfqws2_tgws_transport::socks_dc(&init, guess, telegram_only) else {
                return;
            };
            stats.connected(Some(dc));
            if let Ok(ws) = telegram_socket(dc, cfg, &owner, telegram_only).await {
                let _ =
                    nfqws2_tgws_transport::transparent(client, ws, &init, &stats.up, &stats.down)
                        .await;
            }
            return;
        }
        stats.connected(None);
    }
    let deadline = Instant::now() + if legacy { LEGACY_DIAL } else { TIMEOUT };
    let direct = timeout_at(deadline, async {
        match &target {
            Target::Addr(ip) => TcpStream::connect((*ip, port)).await,
            Target::Domain(host) if legacy => connect_named(host, port, deadline).await,
            Target::Domain(host) => TcpStream::connect((host.as_str(), port)).await,
        }
    })
    .await
    .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()));
    let endpoint = match &target {
        Target::Addr(ip) => Telegram::address(*ip, port),
        Target::Domain(host) => Telegram::host(host, port),
    };
    let result = if legacy {
        direct.map(|socket| (socket, false))
    } else {
        nfqws2_tgws_config::fallback::after_direct(direct, endpoint, |endpoint| async move {
            let Some(iface) = crate::tgws::fallback::selected(&owner).await? else {
                return Ok(None);
            };
            endpoint.connect(&iface).await.map(Some)
        })
        .await
    };
    let (upstream, vpn) = match result {
        Ok(v) => v,
        Err(e) => {
            let code = match e.kind() {
                io::ErrorKind::ConnectionRefused => 5,
                io::ErrorKind::TimedOut => 6,
                _ => 4,
            };
            if !legacy {
                let _ = reply(&mut client, code, None).await;
            }
            return;
        }
    };
    configure_socket(&upstream, cfg.buffer_size);
    if !legacy
        && reply(&mut client, 0, upstream.local_addr().ok())
            .await
            .is_err()
    {
        return;
    }
    if !legacy {
        stats.connected(vpn.then(|| target.vpn_dc()));
    }
    let buffer = if legacy {
        65536
    } else {
        cfg.buffer_size.clamp(4096, 16384) as usize
    };
    let (from_client, to_client) = client.into_split();
    let (from_server, to_server) = upstream.into_split();
    let upload = pipe(from_client, to_server, &stats.up, buffer, legacy);
    let download = pipe(from_server, to_client, &stats.down, buffer, legacy);
    if legacy {
        let _ = tokio::select! { result = upload => result, result = download => result };
    } else {
        let _ = tokio::try_join!(upload, download);
    }
}
async fn telegram_socket(
    dc: u8,
    cfg: &Config,
    owner: &std::sync::Weak<crate::http::AppState>,
    telegram_only: bool,
) -> io::Result<nfqws2_tgws_transport::Ws> {
    let slots = owner
        .upgrade()
        .ok_or(io::ErrorKind::NotConnected)?
        .tgws
        .handshakes()?
        .clone();
    static TLS: std::sync::OnceLock<tokio_rustls::TlsConnector> = std::sync::OnceLock::new();
    let tls = match TLS.get() {
        Some(t) => t,
        None => {
            let connector = nfqws2_tgws_transport::tls()?;
            TLS.get_or_init(|| connector)
        }
    };
    let domain = format!("kws{dc}.web.telegram.org");
    let fixed = nfqws2_tgws_config::fallback::Telegram::web(i16::from(dc), false);
    let upgrade = |socket: TcpStream| {
        configure_socket(&socket, cfg.buffer_size);
        nfqws2_tgws_transport::upgrade(socket, &domain, "/apiws", tls)
    };
    let initial = async {
        let socket = if let Some(ip) = cfg
            .dc_redirects
            .get(&i32::from(dc))
            .copied()
            .filter(|ip| !telegram_only || public_relay_ip(*ip))
        {
            TcpStream::connect((ip, 443)).await?
        } else if let (Some(front), Some(iface)) = (
            fixed,
            crate::tgws::fallback::selected(owner).await.ok().flatten(),
        ) {
            front.connect(&iface).await?
        } else {
            TcpStream::connect((Ipv4Addr::new(149, 154, 167, 220), 443)).await?
        };
        upgrade(socket).await
    };
    let budget = Duration::from_secs(5);
    if let Ok(_permit) = slots.acquire().await {
        if let Ok(Ok(ws)) = timeout(budget, initial).await {
            return Ok(ws);
        }
    }
    let _permit = slots.acquire().await?;
    let deadline = Instant::now() + budget;
    timeout_at(deadline, async {
        let socket = telegram_named_socket(&domain, 443, telegram_only, deadline).await?;
        upgrade(socket).await
    })
    .await
    .map_err(|_| io::ErrorKind::TimedOut)?
}

async fn telegram_named_socket(
    domain: &str,
    port: u16,
    telegram_only: bool,
    deadline: Instant,
) -> io::Result<TcpStream> {
    if telegram_only {
        connect_public(domain, port, deadline).await
    } else {
        connect_named(domain, port, deadline).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn telegram_named_fallback_keeps_the_existing_scope_and_setup_deadline() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let refused = telegram_named_socket("127.0.0.1", address.port(), true, deadline)
            .await
            .unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::InvalidInput);
        let socket = timeout_at(
            deadline,
            telegram_named_socket("127.0.0.1", address.port(), false, deadline),
        )
        .await
        .unwrap()
        .unwrap();
        let (_upstream, peer) = timeout_at(deadline, listener.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(socket.local_addr().unwrap(), peer);
        assert_eq!(socket.peer_addr().unwrap(), address);
    }

    #[tokio::test]
    async fn external_no_auth_legacy_scope_rejects_direct_targets_before_dialing() {
        use tokio::net::TcpListener;
        let incoming = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = incoming.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let stats = Counters::default();
            for _ in 0..2 {
                let (client, _) = incoming.accept().await.unwrap();
                serve(
                    client,
                    &Config::default(),
                    &stats,
                    std::sync::Weak::new(),
                    true,
                )
                .await;
            }
            stats.snapshot()
        });
        let forbidden = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = forbidden.local_addr().unwrap().port();
        for request in [
            b"\x05\x01\x00\x01\x7f\x00\x00\x01".as_slice(),
            b"\x05\x01\x00\x03\x09localhost".as_slice(),
        ] {
            let mut client = TcpStream::connect(endpoint).await.unwrap();
            client.write_all(&[5, 1, 0]).await.unwrap();
            let mut greeting = [0; 2];
            client.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 0]);
            client.write_all(request).await.unwrap();
            client.write_u16(port).await.unwrap();
            let mut response = [0; 10];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [5, 2, 0, 1, 0, 0, 0, 0, 0, 0]);
        }
        assert_eq!(server.await.unwrap()["connections"]["direct"], 0);
        assert!(timeout(Duration::from_millis(50), forbidden.accept())
            .await
            .is_err());
    }

    #[test]
    fn legacy_wss_classifies_dc_networks_and_preserves_other_targets() {
        for (s, dc) in [
            ("149.154.167.51", Some(2)),
            ("::ffff:91.108.13.17", Some(4)),
            ("185.76.151.9", Some(2)),
            ("91.108.99.246", None),
            ("149.154.249.9", None),
            ("185.76.18.1", None),
            ("127.0.0.1", None),
            ("www.example.test", None),
        ] {
            assert_eq!(Target::Domain(s.into()).telegram_dc(), dc);
            if let Ok(ip) = s.parse() {
                assert_eq!(Target::Addr(ip).telegram_dc(), dc);
            }
        }
    }

    #[test]
    fn identifies_only_unambiguous_vpn_datacenters() {
        for (name, expected) in [
            ("KWS1.WEB.TELEGRAM.ORG.", 1),
            ("kws3-1.web.telegram.org", 3),
            ("kws5.web.telegram.org", 5),
            ("::ffff:149.154.175.50", 1),
            ("149.154.175.100", 3),
            ("149.154.171.5", 5),
            ("149.154.170.100", 5),
            ("149.154.174.100", 0),
            ("kws1.example.test", 0),
        ] {
            assert_eq!(Target::Domain(name.into()).vpn_dc(), expected, "{name}");
            if let Ok(ip) = name.parse() {
                assert_eq!(Target::Addr(ip).vpn_dc(), expected, "{name}");
            }
        }
    }

    #[tokio::test]
    async fn relay_counts_bytes_accepted_before_peer_disconnects() {
        let count = AtomicU64::default();
        let (writer, mut reader) = tokio::io::duplex(3);
        let relay = pipe(&b"abcdef"[..], writer, &count, 64, false);
        let peer = async move {
            let mut buf = [0; 3];
            reader.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"abc");
        };
        let (result, ()) = tokio::join!(relay, peer);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(count.load(Ordering::Relaxed), 3);
    }
}
