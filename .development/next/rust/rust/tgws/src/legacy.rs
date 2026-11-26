//! Transport selected by existing Go profiles which have no `transport` field.
use crate::{
    crypto::{Cipher, Transport},
    diagnostics::Event,
    pool::{Endpoint, Peer, Pool},
    relay::{self, BridgeMode},
    Stats,
};
use ctr::cipher::StreamCipher;
use nfqws2_tgws_config::{fallback::Telegram, Config};
use portable_atomic::{AtomicU64, Ordering};
use std::{
    collections::HashMap,
    future::Future,
    io,
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::{timeout, Instant},
};

pub(super) fn tcp_destination(dc: i16, test: bool) -> Option<Ipv4Addr> {
    Some(match (test, dc.unsigned_abs() % 10000) {
        (false, 1) => Ipv4Addr::new(149, 154, 175, 50),
        (false, 2) => Ipv4Addr::new(149, 154, 167, 51),
        (false, 3) => Ipv4Addr::new(149, 154, 175, 100),
        (false, 4) => Ipv4Addr::new(149, 154, 167, 91),
        (false, 5) => Ipv4Addr::new(149, 154, 171, 5),
        (false, 203) => Ipv4Addr::new(91, 105, 192, 100),
        (true, 1) => Ipv4Addr::new(149, 154, 175, 10),
        (true, 2) => Ipv4Addr::new(149, 154, 167, 40),
        (true, 3) => Ipv4Addr::new(149, 154, 175, 117),
        _ => return None,
    })
}

#[derive(Default)]
pub(super) struct Backoff {
    entries: Mutex<HashMap<SocketAddr, Retry>>,
}
#[derive(Default)]
struct Retry {
    probe: Arc<tokio::sync::Mutex<()>>,
    failures: u8,
    until: Option<Instant>,
}
impl Backoff {
    fn probe(&self, dst: SocketAddr) -> io::Result<tokio::sync::OwnedMutexGuard<()>> {
        let mut entries = self.entries.lock().unwrap();
        let retry = entries.entry(dst).or_default();
        if retry.until.is_some_and(|t| t > Instant::now()) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        retry
            .probe
            .clone()
            .try_lock_owned()
            .map_err(|_| io::ErrorKind::WouldBlock.into())
    }
    async fn connect(
        &self,
        dst: SocketAddr,
        init: &[u8; 64],
        report_failure: impl FnOnce(u64),
    ) -> io::Result<TcpStream> {
        let setup = async {
            let mut remote = TcpStream::connect(dst).await?;
            nfqws2_tgws_transport::configure_tcp_fallback(&remote);
            write_init(&mut remote, init).await?;
            Ok(remote)
        };
        self.run_probe(dst, setup, report_failure).await
    }

    async fn run_probe<T>(
        &self,
        dst: SocketAddr,
        setup: impl Future<Output = io::Result<T>>,
        report_failure: impl FnOnce(u64),
    ) -> io::Result<T> {
        // Dropping a canceled dial always releases its slot and does not
        // penalize the DC. Established bridges do not hold this guard.
        let probe = self.probe(dst)?;
        let result = timeout(Duration::from_secs(10), setup)
            .await
            .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()));
        let delay = {
            let mut entries = self.entries.lock().unwrap();
            if result.is_ok() {
                entries.remove(&dst);
                None
            } else {
                let retry = entries.get_mut(&dst).unwrap();
                let seconds = (30u64 << retry.failures.min(7)).min(3600);
                retry.failures = (retry.failures + 1).min(8);
                retry.until = Some(Instant::now() + Duration::from_secs(seconds));
                Some(seconds)
            }
        };
        drop(probe);
        if let Some(seconds) = delay {
            report_failure(seconds);
        }
        result
    }
}

async fn write_init(remote: &mut (impl AsyncWrite + Unpin), init: &[u8; 64]) -> io::Result<()> {
    if remote.write(init).await? != init.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short TCP fallback initializer write",
        ));
    }
    Ok(())
}

async fn copy_stream(
    mut input: impl AsyncRead + Unpin,
    mut output: impl AsyncWrite + Unpin,
    mut decrypt: Cipher,
    mut encrypt: Cipher,
    counter: &AtomicU64,
) -> io::Result<()> {
    let mut buf = vec![0; 16384];
    loop {
        let n = input.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        counter.fetch_add(n as u64, Ordering::Relaxed);
        decrypt.apply_keystream(&mut buf[..n]);
        encrypt.apply_keystream(&mut buf[..n]);
        output.write_all(&buf[..n]).await?;
    }
}

pub(super) async fn bridge_tcp(
    client: impl AsyncRead + AsyncWrite + Unpin,
    remote: TcpStream,
    session: Transport,
    stats: &Stats,
) -> io::Result<()> {
    let (from_client, to_client) = tokio::io::split(client);
    let (from_dc, to_dc) = remote.into_split();
    tokio::select! {
        result = copy_stream(from_client, to_dc, session.client_in, session.server_out, &stats.up) => result,
        result = copy_stream(from_dc, to_client, session.server_in, session.client_out, &stats.down) => result,
    }
}

pub(super) fn warm_routes(pool: &Pool, cfg: &Config) {
    if let Some(routes) = &cfg.dc_redirects {
        for (&number, &ip) in routes {
            for dc in [number as i16, -(number as i16)] {
                let test = cfg.force_test_dc;
                pool.warm(pool_dc(dc, test), route(dc, ip, test));
            }
        }
    }
}

fn pool_dc(dc: i16, test: bool) -> i16 {
    // Explicit test headers and the force-test profile share one warm bucket.
    dc % 10000 + if test { dc.signum() * 10000 } else { 0 }
}

fn route(dc: i16, ip: std::net::IpAddr, test: bool) -> Endpoint {
    Endpoint {
        peer: Peer::Direct((ip, 443).into()),
        managed: true,
        host: relay::ws_domains(dc).remove(0),
        path: if test { "/apiws_test" } else { "/apiws" },
    }
}

fn vpn_front(dc: i16, test: bool) -> Option<(Telegram, &'static str)> {
    // The Go background pool uses the same fixed AWG web frontend for the
    // test environment. The WS path selects the corresponding Telegram DC.
    let normalized = dc % 10000;
    let target = Telegram::web(normalized, false)?;
    let path = if test || dc.unsigned_abs() >= 10000 {
        "/apiws_test"
    } else {
        "/apiws"
    };
    Some((target, path))
}

async fn pooled_route(
    dc: i16,
    test: bool,
    cfg: &Config,
    broker: Option<&Path>,
) -> Option<Endpoint> {
    let number = i32::from(dc.unsigned_abs() % 10000);
    if let Some(&ip) = cfg.dc_redirects.as_ref().and_then(|r| r.get(&number)) {
        return Some(route(dc, ip, test));
    }
    let (target, path) = vpn_front(dc, test)?;
    let broker = broker?;
    let iface = relay::vpn_iface(broker).await.ok()??;
    Some(Endpoint {
        peer: Peer::Vpn {
            target,
            iface,
            broker: broker.to_owned(),
        },
        managed: false,
        host: relay::ws_domains(dc).remove(0),
        path,
    })
}

pub(super) async fn serve(
    tcp: impl AsyncRead + AsyncWrite + Unpin,
    session: Transport,
    cfg: &Config,
    pool: &Pool,
    stats: &Stats,
    broker: Option<&Path>,
) -> io::Result<()> {
    let dc = session.dc;
    let test = cfg.force_test_dc || dc.unsigned_abs() >= 10000;
    if cfg.pool_size > 0 {
        let key = pool_dc(dc, test);
        if let Some(endpoint) = pooled_route(dc, test, cfg, broker).await {
            let vpn = matches!(endpoint.peer, Peer::Vpn { .. });
            if let Some(ws) = pool.take_route(key, endpoint, stats).await {
                relay::configure_socket(nfqws2_tgws_transport::socket(&ws), cfg.buffer_size);
                stats.ws.fetch_add(1, Ordering::Relaxed);
                if vpn {
                    stats.vpn.fetch_add(1, Ordering::Relaxed);
                }
                let _ =
                    relay::bridge(tcp, ws, session, stats, BridgeMode::Legacy, Some(pool)).await;
                return Ok(());
            }
        } else {
            pool.forget_vpn(key);
        }
    }
    fallback(tcp, session, cfg, pool, stats).await
}
pub(super) async fn fallback(
    tcp: impl AsyncRead + AsyncWrite + Unpin,
    session: Transport,
    cfg: &Config,
    pool: &Pool,
    stats: &Stats,
) -> io::Result<()> {
    let dc = session.dc;
    let test = cfg.force_test_dc || dc.unsigned_abs() >= 10000;
    if let Some(ws) = pool
        .relays
        .worker(dc, test, cfg, stats, &session.init, |event| {
            pool.report_diagnostic(event)
        })
        .await
    {
        return relay::bridge_initialized(
            tcp,
            ws,
            session,
            stats,
            BridgeMode::LegacyWorker,
            Some(pool),
        )
        .await;
    }
    if let Some(lane) = pool.relays.media(dc, cfg, stats).await {
        stats.cf.fetch_add(1, Ordering::Relaxed);
        stats.h2.fetch_add(1, Ordering::Relaxed);
        return crate::media::bridge(tcp, session, lane, stats, |error| {
            pool.report_diagnostic(Event::H2Transport(error));
        })
        .await;
    }
    if let Some(ws) = pool
        .relays
        .web(dc, test, cfg, stats, &session.init, |event| {
            pool.report_diagnostic(event)
        })
        .await
    {
        return relay::bridge_initialized(tcp, ws, session, stats, BridgeMode::Legacy, Some(pool))
            .await;
    }
    let remote = async {
        let dst = tcp_destination(dc, test).ok_or(io::ErrorKind::NotFound)?;
        pool.legacy_tcp
            .connect((dst, 443).into(), &session.init, |seconds| {
                pool.report_diagnostic(Event::TcpFallbackFailed { dc, test, seconds });
            })
            .await
    }
    .await
    .inspect_err(|_| pool.report_diagnostic(Event::NoFallback { dc, test }))?;
    stats.tcp.fetch_add(1, Ordering::Relaxed);
    let _ = bridge_tcp(tcp, remote, session, stats).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    #[tokio::test]
    async fn exhausted_test_route_reports_once_without_dialing_production() {
        let cfg = Config {
            cfproxy_worker_domains: Some(vec!["worker.example.test".into()]),
            ..Config::default()
        };
        let (roots, _) = crate::tests::test_tls();
        let mut pool = Pool::legacy(0, relay::tls_config(roots).unwrap(), cfg.buffer_size);
        let diagnostics = pool.capture_diagnostics();
        let key = [7; 16];
        let dc = -10203;
        let (init, _, _) = crate::crypto::client_fixture(&key, dc, 0xdd);
        let session = Transport::client(init, &key).unwrap();
        let (_client, stream) = tokio::io::duplex(1024);
        let error = fallback(stream, session, &cfg, &pool, &Stats::default())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert_eq!(
            diagnostics.try_recv().unwrap(),
            Event::NoFallback { dc, test: true }
        );
        assert!(diagnostics.try_recv().is_err());
    }
    #[test]
    fn explicit_and_forced_test_share_the_same_media_or_ordinary_pool() {
        for dc in [1i16, 2, 203, -1, -2, -203] {
            assert_eq!(pool_dc(dc, false), dc);
            let explicit = dc + dc.signum() * 10000;
            assert_eq!(pool_dc(dc, true), explicit);
            assert_eq!(pool_dc(explicit, true), explicit);
        }
    }

    #[test]
    fn cancelled_probe_releases_the_dc_without_advancing_backoff() {
        let backoff = Backoff::default();
        let addr = "127.0.0.1:443".parse().unwrap();
        let in_flight = backoff.probe(addr).unwrap();
        assert_eq!(
            backoff.probe(addr).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(in_flight);
        let _retry = backoff.probe(addr).unwrap();
        let entries = backoff.entries.lock().unwrap();
        assert_eq!(entries[&addr].failures, 0);
        assert!(entries[&addr].until.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_fallback_reports_only_failed_probes_and_preserves_backoff_on_cancel() {
        let backoff = Backoff::default();
        let dst = "127.0.0.1:443".parse().unwrap();
        let (send, reports) = std::sync::mpsc::channel();
        let report = |seconds| send.send(seconds).unwrap();
        let refused = || std::future::ready(Err::<(), _>(io::ErrorKind::ConnectionRefused.into()));
        for seconds in [30, 60, 120, 240, 480, 960, 1920, 3600, 3600] {
            let error = backoff.run_probe(dst, refused(), report).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
            assert_eq!(reports.try_recv().unwrap(), seconds);
            let deferred = backoff.run_probe(dst, refused(), report).await.unwrap_err();
            assert_eq!(deferred.kind(), io::ErrorKind::WouldBlock);
            assert!(reports.try_recv().is_err());
            tokio::time::advance(Duration::from_secs(seconds)).await;
        }

        let retry_after = backoff.entries.lock().unwrap()[&dst].until;
        let mut active =
            Box::pin(backoff.run_probe(dst, std::future::pending::<io::Result<()>>(), report));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(active.as_mut().poll(&mut context).is_pending());
        let deferred = backoff.run_probe(dst, refused(), report).await.unwrap_err();
        assert_eq!(deferred.kind(), io::ErrorKind::WouldBlock);
        drop(active);
        assert!(reports.try_recv().is_err());
        assert_eq!(backoff.entries.lock().unwrap()[&dst].until, retry_after);

        backoff
            .run_probe(dst, std::future::ready(Ok(())), report)
            .await
            .unwrap();
        assert!(reports.try_recv().is_err());
        let error = backoff
            .run_probe(dst, std::future::pending::<io::Result<()>>(), report)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(reports.try_recv().unwrap(), 30);
        assert!(reports.try_recv().is_err());
    }

    #[tokio::test]
    async fn tcp_fallback_rejects_a_short_initializer_and_reports_the_probe_failure() {
        let backoff = Backoff::default();
        let dst = "127.0.0.1:443".parse().unwrap();
        let (mut remote, mut peer) = tokio::io::duplex(63);
        let (send, reports) = std::sync::mpsc::channel();
        let error = backoff
            .run_probe(dst, write_init(&mut remote, &[7; 64]), |seconds| {
                send.send(seconds).unwrap();
            })
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
        assert_eq!(reports.try_recv().unwrap(), 30);
        assert!(reports.try_recv().is_err());
        drop(remote);
        let mut written = Vec::new();
        peer.read_to_end(&mut written).await.unwrap();
        assert_eq!(written, [7; 63]);
    }

    #[test]
    fn test_dc_fallback_never_uses_production_ips() {
        assert_eq!(
            tcp_destination(-10002, true),
            Some(Ipv4Addr::new(149, 154, 167, 40))
        );
        assert_eq!(
            tcp_destination(2, false),
            Some(Ipv4Addr::new(149, 154, 167, 51))
        );
        assert_eq!(
            tcp_destination(203, false),
            Some(Ipv4Addr::new(91, 105, 192, 100))
        );
        for dc in [4, -10005, 203] {
            assert!(tcp_destination(dc, true).is_none());
        }
        let endpoint = route(-10002, Ipv4Addr::LOCALHOST.into(), true);
        assert_eq!(endpoint.host, "kws2-1.web.telegram.org");
        assert_eq!(endpoint.path, "/apiws_test");
    }

    #[tokio::test]
    async fn tcp_fallback_relays_partial_packets_and_both_cipher_directions() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dst = upstream.local_addr().unwrap();
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(local.local_addr().unwrap())
            .await
            .unwrap();
        let (proxy, _) = local.accept().await.unwrap();
        let (init, mut send, mut receive) = crate::crypto::client_fixture(&[7; 16], -3, 0xdd);
        let session = Transport::client(init, &[7; 16]).unwrap();
        let backoff = Backoff::default();
        let remote = backoff.connect(dst, &session.init, |_| {}).await.unwrap();
        let (mut server, _) = upstream.accept().await.unwrap();
        let mut head = [0; 64];
        server.read_exact(&mut head).await.unwrap();
        let (tag, dc, mut upstream_in, mut upstream_out) = crate::crypto::upstream_fixture(head);
        assert_eq!((tag, dc), (0xdd, -3));
        let stats = Stats::default();
        let exchange = async {
            for plain in [b"x".as_slice(), b"additional bytes"] {
                let mut bytes = plain.to_vec();
                send.apply_keystream(&mut bytes);
                client.write_all(&bytes).await.unwrap();
                server.read_exact(&mut bytes).await.unwrap();
                upstream_in.apply_keystream(&mut bytes);
                assert_eq!(bytes, plain);
                upstream_out.apply_keystream(&mut bytes);
                server.write_all(&bytes).await.unwrap();
                client.read_exact(&mut bytes).await.unwrap();
                receive.apply_keystream(&mut bytes);
                assert_eq!(bytes, plain);
            }
            drop(client);
        };
        let (result, ()) = timeout(Duration::from_secs(3), async {
            tokio::join!(bridge_tcp(proxy, remote, session, &stats), exchange)
        })
        .await
        .unwrap();
        result.unwrap();
        assert_eq!(stats.up.load(Ordering::Relaxed), 17);
        assert_eq!(stats.down.load(Ordering::Relaxed), 17);
        drop(upstream);
        assert!(backoff.connect(dst, &[0; 64], |_| {}).await.is_err());
        assert_eq!(
            backoff
                .connect(dst, &[0; 64], |_| {})
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
    }
    #[test]
    fn test_environment_uses_only_its_web_path_and_never_production_tcp() {
        for dc in [1, 3, 5] {
            let target = Telegram::web(dc, false).unwrap();
            for id in [dc, -dc, 10000 + dc, -10000 - dc] {
                assert_eq!(vpn_front(id, true), Some((target, "/apiws_test")));
                assert_eq!(
                    vpn_front(id, false).unwrap().1,
                    if id.unsigned_abs() >= 10000 {
                        "/apiws_test"
                    } else {
                        "/apiws"
                    }
                );
                assert_ne!(tcp_destination(id, true), tcp_destination(id, false));
            }
        }
        for dc in [2, -4, 203, 10002, -10203] {
            assert!(vpn_front(dc, true).is_none());
        }
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn signed_test_dc_gets_the_test_route_only_from_a_ready_local_vpn_broker() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broker");
        let cfg = Config {
            dc_redirects: Some(Default::default()),
            ..Config::default()
        };
        assert!(pooled_route(-10001, true, &cfg, Some(&path))
            .await
            .is_none());
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let serve = async {
            let (mut peer, _) = listener.accept().await.unwrap();
            peer.write_all(b"awg0").await.unwrap();
        };
        let (route, ()) = tokio::join!(pooled_route(-10001, true, &cfg, Some(&path)), serve);
        let route = route.unwrap();
        assert_eq!(route.path, "/apiws_test");
        assert_eq!(route.host, "kws1-1.web.telegram.org");
        assert!(!route.managed);
        assert!(
            matches!(route.peer, Peer::Vpn {target,iface,..} if target==Telegram::web(1,false).unwrap() && iface=="awg0")
        );
    }
}
