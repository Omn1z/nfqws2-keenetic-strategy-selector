//! Forward DNS redirected from Keenetic LAN bridges to the router's resolver.
use super::{
    network,
    routing::{DnsOrigin, Observer},
    runtime::{Bound, Handler},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};
use tokio::{
    task::JoinHandle,
    time::{timeout, Instant},
};

const ROUTE_PREPARE_TIMEOUT: Duration = Duration::from_secs(2);
pub(super) const FIRMWARE_RESOLVER: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53));

pub(super) async fn forward(
    upstream: SocketAddr,
    observer: &Observer,
    client: IpAddr,
    bridge: Option<&str>,
    query: &[u8],
) -> io::Result<Option<Vec<u8>>> {
    let (domain, kind) = nfqws2_dns::query_domain(query)?;
    // EDNS Client Subnet is chosen by the sender. Keep the socket peer as the
    // identity and confirm the same selection when upstream returns.
    let captured = observer.capture_redirect(
        &domain,
        DnsOrigin {
            client: Some(client),
            ingress: bridge,
        },
    );
    if kind == 28 {
        let deadline = Instant::now() + ROUTE_PREPARE_TIMEOUT;
        let early = match &captured {
            Ok(Some(captured)) => captured.before_firmware_aaaa(&domain, deadline).await?,
            _ => None,
        };
        if let Some(reply) = observer
            .suppress_aaaa(early.as_ref(), &domain, query, deadline)
            .await?
        {
            return Ok(Some(reply));
        }
    }
    let Ok(Ok(mut answer)) = timeout(
        Duration::from_secs(4),
        network::exchange_redirected(upstream, query),
    )
    .await
    else {
        // Transparent firmware forwarding drops requests without a valid upstream reply.
        return Ok(None);
    };
    let received = Instant::now();
    let deadline = received + ROUTE_PREPARE_TIMEOUT;
    // A stale policy is reported only when the firmware returned an answer.
    let (selection, waited) = match captured? {
        Some(query) => {
            let (selection, waited) = query.after_firmware(&domain, deadline).await?;
            (Some(selection), waited)
        }
        None => (None, false),
    };
    observer
        .prepare_selected(
            selection,
            &domain,
            query,
            &mut answer,
            super::routing::RouteTiming {
                deadline,
                waited_from: waited.then_some(received),
                firmware_received: Some(received),
            },
            None,
        )
        .await?;
    Ok(Some(answer))
}

struct Listener {
    ifindex: u32,
    job: JoinHandle<io::Result<()>>,
}
impl Drop for Listener {
    fn drop(&mut self) {
        self.job.abort();
    }
}
#[derive(Default)]
pub(super) struct Listeners(BTreeMap<String, Listener>);

#[cfg(target_os = "linux")]
fn interface(name: &str) -> io::Result<u32> {
    let name = std::ffi::CString::new(name)?;
    // if_nametoindex reads only the supplied NUL-terminated device name.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(index)
    }
}
#[cfg(not(target_os = "linux"))]
fn interface(_: &str) -> io::Result<u32> {
    Err(io::ErrorKind::Unsupported.into())
}

fn bind(name: &str, index: u32, port: u16) -> io::Result<Bound> {
    use socket2::{Domain, Protocol, Socket, Type};
    let pair = |ipv6: bool| -> io::Result<Bound> {
        let addr = SocketAddr::new(
            if ipv6 {
                std::net::Ipv6Addr::UNSPECIFIED.into()
            } else {
                Ipv4Addr::UNSPECIFIED.into()
            },
            port,
        );
        let socket = |ty, protocol, addr: SocketAddr| -> io::Result<Socket> {
            let fd = Socket::new(Domain::for_address(addr), ty, Some(protocol))?;
            if ipv6 {
                fd.set_only_v6(false)?;
            }
            if ty == Type::STREAM {
                fd.set_reuse_address(true)?;
            }
            network::bind_device(&fd, (name, index))?;
            fd.set_nonblocking(true)?;
            fd.bind(&addr.into())?;
            Ok(fd)
        };
        let tcp = socket(Type::STREAM, Protocol::TCP, addr)?;
        tcp.listen(64)?;
        let bound = tcp
            .local_addr()?
            .as_socket()
            .ok_or(io::ErrorKind::AddrNotAvailable)?;
        let udp = socket(Type::DGRAM, Protocol::UDP, bound)?;
        Ok(Bound {
            tcp: tokio::net::TcpListener::from_std(tcp.into())?,
            udp: Arc::new(tokio::net::UdpSocket::from_std(udp.into())?),
        })
    };
    match pair(true) {
        Err(e) if e.raw_os_error() == Some(libc::EAFNOSUPPORT) => pair(false),
        other => other,
    }
}
impl Listeners {
    pub(super) fn active(&self) -> bool {
        self.0
            .iter()
            .any(|(name, listener)| name != "lo" && !listener.job.is_finished())
    }

    pub(super) async fn reconcile(
        &mut self,
        bridges: &[String],
        observer: &Arc<Observer>,
    ) -> io::Result<()> {
        let mut wanted = BTreeSet::new();
        for name in bridges {
            if !nfqws2_awg_rules::kernel::valid_dns_bridge(name) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "неверное имя LAN-моста",
                ));
            }
            wanted.insert(name.as_str());
        }
        if !wanted.is_empty() {
            wanted.insert("lo");
        }
        let mut additions = Vec::new();
        for name in &wanted {
            let index = interface(name)?;
            if !self
                .0
                .get(*name)
                .is_some_and(|l| l.ifindex == index && !l.job.is_finished())
            {
                additions.push((name.to_string(), index, bind(name, index, 5354)?));
            }
        }
        // Keep serving the old set of bridges until every new socket is bound.
        let mut retired = Vec::new();
        for (name, ifindex, sockets) in additions {
            let job = tokio::spawn(sockets.serve(Handler::Intercept {
                upstream: FIRMWARE_RESOLVER,
                observer: observer.clone(),
                bridge: (name != "lo").then(|| Arc::from(name.as_str())),
            }));
            if let Some(previous) = self.0.insert(name, Listener { ifindex, job }) {
                retired.push(previous);
            }
        }
        let removed: Vec<_> = self
            .0
            .keys()
            .filter(|name| !wanted.contains(name.as_str()))
            .cloned()
            .collect();
        for name in removed {
            if let Some(previous) = self.0.remove(&name) {
                retired.push(previous);
            }
        }
        for mut previous in retired {
            previous.job.abort();
            let _ = (&mut previous.job).await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnsserver::{RouteAnswer, RouteMatch, RouteObserver};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpStream, UdpSocket},
    };

    #[tokio::test]
    async fn archived_dns_requires_live_transparent_lan_and_managed_dns_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let app = crate::http::AppState::open(
            nfqws2_config::Config {
                data_dir: dir.path().display().to_string(),
                ..Default::default()
            },
            dir.path(),
            true,
        )
        .unwrap();
        let dns = &app.dnsserver;
        assert!(dns.archive_resolver().is_none());
        let listener = || Listener {
            ifindex: 1,
            job: tokio::spawn(std::future::pending::<io::Result<()>>()),
        };
        dns.redirects.lock().await.0.insert("lo".into(), listener());
        assert!(dns.archive_resolver().is_none());
        dns.redirects
            .lock()
            .await
            .0
            .insert("br-test".into(), listener());
        assert!(dns.archive_resolver().is_some_and(|resolver| {
            resolver.same(&crate::dnsserver::ArchiveResolver::firmware())
        }));
        {
            let mut state = dns.state.lock().await;
            state.raw["enabled"] = serde_json::Value::Bool(true);
            state.raw["route_mode"] = serde_json::json!("vpn_only");
        }
        assert!(dns.routing_nameserver().is_err());
        assert!(dns.archive_resolver().is_none());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn device_bound_listener_accepts_both_families_on_one_local_port() {
        // Binding to loopback keeps this probe isolated from the production
        // DNS port even when the test executable runs on a real router.
        let sockets = bind("lo", interface("lo").unwrap(), 0).unwrap();
        let local = sockets.tcp.local_addr().unwrap();
        for host in [
            IpAddr::from(Ipv4Addr::LOCALHOST),
            IpAddr::from(std::net::Ipv6Addr::LOCALHOST),
        ] {
            if host.is_ipv6() && local.is_ipv4() {
                continue;
            }
            let peer = SocketAddr::new(host, local.port());
            let udp = UdpSocket::bind(SocketAddr::new(host, 0)).await.unwrap();
            udp.send_to(b"test", peer).await.unwrap();
            let mut raw = [0; 4];
            let (_, sender) = timeout(Duration::from_secs(2), sockets.udp.recv_from(&mut raw))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&raw, b"test");
            assert_eq!(sender.ip().to_canonical(), host);
            let _stream = TcpStream::connect(peer).await.unwrap();
            let (_, sender) = timeout(Duration::from_secs(2), sockets.tcp.accept())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(sender.ip().to_canonical(), host);
        }
    }

    #[tokio::test]
    async fn transparent_tcp_forwards_only_one_query_per_connection() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = upstream.local_addr().unwrap();
        let queries = Arc::new(AtomicUsize::new(0));
        let count = queries.clone();
        let upstream_task = tokio::spawn(async move {
            let mut buf = [0; 512];
            loop {
                let (size, peer) = upstream.recv_from(&mut buf).await.unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                let reply = nfqws2_dns::response_error(&buf[..size], 0);
                upstream.send_to(&reply, peer).await.unwrap();
            }
        });
        let listener = Bound::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let local = listener.tcp.local_addr().unwrap();
        let service = tokio::spawn(listener.serve(Handler::Intercept {
            upstream: server,
            observer: Arc::new(Observer::default()),
            bridge: None,
        }));

        let first = nfqws2_dns::build_query("first.example", 1, 71).unwrap();
        let second = nfqws2_dns::build_query("second.example", 1, 72).unwrap();
        let mut frames = Vec::new();
        for query in [&first, &second] {
            frames.extend_from_slice(&(query.len() as u16).to_be_bytes());
            frames.extend_from_slice(query);
        }
        timeout(Duration::from_secs(3), async {
            let mut tcp = TcpStream::connect(local).await.unwrap();
            tcp.write_all(&frames).await.unwrap();
            let mut reply = vec![0; tcp.read_u16().await.unwrap() as usize];
            tcp.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, nfqws2_dns::response_error(&first, 0));

            // TCP implementations may reset a close with unread input.
            let closed = tcp.read_u8().await.unwrap_err();
            assert!(matches!(
                closed.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
            ));
            assert_eq!(queries.load(Ordering::SeqCst), 1);
        })
        .await
        .unwrap();
        service.abort();
        upstream_task.abort();
    }

    #[tokio::test]
    async fn transparent_dns_upstream_timeout_is_silent_for_udp_and_closes_tcp() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener = Bound::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let local = listener.tcp.local_addr().unwrap();
        let service = tokio::spawn(listener.serve(Handler::Intercept {
            upstream: upstream.local_addr().unwrap(),
            observer: Arc::new(Observer::default()),
            bridge: None,
        }));
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut tcp = TcpStream::connect(local).await.unwrap();
        let udp_query = nfqws2_dns::build_query("udp.example", 1, 81).unwrap();
        let tcp_query = nfqws2_dns::build_query("tcp.example", 1, 82).unwrap();
        udp.send_to(&udp_query, local).await.unwrap();
        tcp.write_u16(tcp_query.len() as u16).await.unwrap();
        tcp.write_all(&tcp_query).await.unwrap();
        let mut buf = [0; 512];
        let forwarded = timeout(Duration::from_secs(3), async {
            let mut seen = BTreeSet::new();
            for _ in 0..2 {
                let (size, _) = upstream.recv_from(&mut buf).await.unwrap();
                seen.insert(nfqws2_dns::query_domain(&buf[..size]).unwrap().0);
            }
            seen
        })
        .await
        .unwrap();
        assert_eq!(
            forwarded,
            BTreeSet::from(["tcp.example".to_owned(), "udp.example".to_owned()])
        );

        let closed = timeout(Duration::from_secs(6), tcp.read_u8())
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(closed.kind(), io::ErrorKind::UnexpectedEof);
        assert!(timeout(Duration::from_millis(50), udp.recv_from(&mut buf))
            .await
            .is_err());
        service.abort();
    }

    #[tokio::test]
    async fn transparent_dns_checks_the_captured_policy_after_a_firmware_reply() {
        use crate::awg_rules::kernel::{
            hold_dns_operation_for_test, install_route_observer_for_test,
            waiting_dns_queries_for_test, DnsPublicationFixture,
        };
        use nfqws2_awg_rules::kernel::Operation;

        #[derive(Clone, Copy, Eq, PartialEq)]
        enum Outcome {
            Refreshed,
            Unreadable,
            Obsolete,
            Deadline,
            NoFirmwareReply,
        }

        fn positive(query: &[u8]) -> Vec<u8> {
            let mut answer = nfqws2_dns::response_error(query, 0);
            answer[7] = 1;
            answer.extend_from_slice(&[192, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 15]);
            answer
        }

        for outcome in [
            Outcome::Refreshed,
            Outcome::Unreadable,
            Outcome::Obsolete,
            Outcome::Deadline,
            Outcome::NoFirmwareReply,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let app = crate::http::AppState::open(
                nfqws2_config::Config {
                    data_dir: dir.path().display().to_string(),
                    ..Default::default()
                },
                dir.path(),
                true,
            )
            .unwrap();
            install_route_observer_for_test(&app);
            let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let listener = Bound::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let local = listener.tcp.local_addr().unwrap();
            let service = tokio::spawn(listener.serve(Handler::Intercept {
                upstream: upstream.local_addr().unwrap(),
                observer: app.dnsserver.observer.clone(),
                bridge: Some("br-test".into()),
            }));
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            udp.connect(local).await.unwrap();
            let mut tcp = TcpStream::connect(local).await.unwrap();
            let udp_query = nfqws2_dns::build_query("udp.outside.test", 1, 81).unwrap();
            let tcp_query = nfqws2_dns::build_query("tcp.outside.test", 1, 82).unwrap();
            udp.send(&udp_query).await.unwrap();
            tcp.write_u16(tcp_query.len() as u16).await.unwrap();
            tcp.write_all(&tcp_query).await.unwrap();

            let mut buf = [0; 512];
            let mut forwarded = BTreeMap::new();
            for _ in 0..2 {
                let (size, peer) = timeout(Duration::from_secs(2), upstream.recv_from(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
                let query = buf[..size].to_vec();
                let name = nfqws2_dns::query_domain(&query).unwrap().0;
                assert!(forwarded.insert(name, (query, peer)).is_none());
            }
            assert!(forwarded.contains_key("udp.outside.test"));
            assert!(forwarded.contains_key("tcp.outside.test"));
            let op = if matches!(outcome, Outcome::Obsolete | Outcome::NoFirmwareReply) {
                Operation::Apply
            } else {
                Operation::Refresh
            };
            let mut finish = Some(hold_dns_operation_for_test(&app, op));
            if outcome != Outcome::NoFirmwareReply {
                for (query, peer) in forwarded.values() {
                    upstream.send_to(&positive(query), peer).await.unwrap();
                }
            }

            if matches!(
                outcome,
                Outcome::Refreshed | Outcome::Unreadable | Outcome::Deadline
            ) {
                timeout(Duration::from_secs(1), async {
                    while waiting_dns_queries_for_test(&app) != 2 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
            }
            match outcome {
                Outcome::Refreshed => finish.take().unwrap()(DnsPublicationFixture::Ready).unwrap(),
                Outcome::Unreadable => {
                    assert!(finish.take().unwrap()(DnsPublicationFixture::Unreadable).is_err())
                }
                _ => (),
            }

            if outcome == Outcome::NoFirmwareReply {
                let e = timeout(Duration::from_secs(6), tcp.read_u8())
                    .await
                    .unwrap()
                    .unwrap_err();
                assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
                assert!(timeout(Duration::from_millis(50), udp.recv(&mut buf))
                    .await
                    .is_err());
            } else {
                let expected = |query: &[u8]| {
                    if outcome == Outcome::Refreshed {
                        positive(query)
                    } else {
                        nfqws2_dns::response_error(query, 2)
                    }
                };
                let budget = if outcome == Outcome::Deadline {
                    Duration::from_secs(3)
                } else {
                    Duration::from_secs(1)
                };
                let n = timeout(budget, udp.recv(&mut buf)).await.unwrap().unwrap();
                assert_eq!(&buf[..n], expected(&udp_query));
                let response = timeout(budget, async {
                    let mut packet = vec![0; tcp.read_u16().await.unwrap() as usize];
                    tcp.read_exact(&mut packet).await.unwrap();
                    packet
                })
                .await
                .unwrap();
                assert_eq!(response, expected(&tcp_query));
            }
            assert_eq!(waiting_dns_queries_for_test(&app), 0);
            if let Some(finish) = finish {
                finish(DnsPublicationFixture::Ready).unwrap();
            }
            service.abort();
        }
    }

    #[tokio::test]
    async fn transparent_dns_route_deadline_returns_servfail_and_releases_waiters() {
        use std::sync::Mutex;
        use tokio::sync::{oneshot, Notify};

        struct Gate {
            installs: AtomicUsize,
            started: Notify,
            release: Mutex<Option<oneshot::Receiver<()>>>,
        }

        impl RouteObserver for Gate {
            fn select(&self, _: &str, _: Option<IpAddr>) -> io::Result<Option<RouteMatch>> {
                Ok(Some(RouteMatch {
                    zone: 0,
                    revision: 1,
                    generation: 1,
                }))
            }

            fn blocks_aaaa(&self, _: RouteMatch) -> io::Result<bool> {
                Ok(true)
            }

            fn install(
                &self,
                _: RouteMatch,
                _: &str,
                _: DnsOrigin<'_>,
                answer: &RouteAnswer,
            ) -> io::Result<(bool, u64)> {
                assert_eq!(answer.addresses, [IpAddr::from([192, 0, 2, 15])]);
                if self.installs.fetch_add(1, Ordering::SeqCst) == 0 {
                    let release = self.release.lock().unwrap().take().unwrap();
                    self.started.notify_one();
                    release.blocking_recv().map_err(io::Error::other)?;
                }
                Ok((false, 1))
            }
        }

        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            for _ in 0..3 {
                let mut buf = [0; 512];
                let (n, peer) = upstream.recv_from(&mut buf).await.unwrap();
                assert_eq!(nfqws2_dns::query_domain(&buf[..n]).unwrap().1, 1);
                let mut reply = nfqws2_dns::response_error(&buf[..n], 0);
                reply[7] = 1;
                reply.extend_from_slice(&[192, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 15]);
                upstream.send_to(&reply, peer).await.unwrap();
            }
        });
        let (release, wait) = oneshot::channel();
        let gate = Arc::new(Gate {
            installs: AtomicUsize::new(0),
            started: Notify::new(),
            release: Mutex::new(Some(wait)),
        });
        let observer = Arc::new(Observer::default());
        observer.register(gate.clone());
        let listener = Bound::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let local = listener.tcp.local_addr().unwrap();
        let service = tokio::spawn(listener.serve(Handler::Intercept {
            upstream: server,
            observer,
            bridge: None,
        }));

        let a = nfqws2_dns::build_query("office.test", 1, 71).unwrap();
        let aaaa = nfqws2_dns::build_query("office.test", 28, 72).unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sent = Instant::now();
        udp.send_to(&a, local).await.unwrap();
        timeout(Duration::from_secs(3), gate.started.notified())
            .await
            .unwrap();

        // Keep one real installation running past its lease. TCP and a local
        // AAAA synthesis must time out behind it without starting more work.
        let mut tcp = TcpStream::connect(local).await.unwrap();
        tcp.write_u16(a.len() as u16).await.unwrap();
        tcp.write_all(&a).await.unwrap();
        let aaaa_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        aaaa_client.send_to(&aaaa, local).await.unwrap();
        timeout(Duration::from_secs(4), async {
            let mut buf = [0; 512];
            let (n, _) = udp.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], &nfqws2_dns::response_error(&a, 2));
            assert!(sent.elapsed() >= Duration::from_secs(2));
            let n = tcp.read_u16().await.unwrap() as usize;
            tcp.read_exact(&mut buf[..n]).await.unwrap();
            assert_eq!(&buf[..n], &nfqws2_dns::response_error(&a, 2));
            let (n, _) = aaaa_client.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], &nfqws2_dns::response_error(&aaaa, 2));
        })
        .await
        .unwrap();
        assert_eq!(gate.installs.load(Ordering::SeqCst), 1);

        release.send(()).unwrap();
        udp.send_to(&a, local).await.unwrap();
        let mut buf = [0; 512];
        let (n, _) = timeout(Duration::from_secs(3), udp.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        nfqws2_dns::validate_answer(&a, &buf[..n]).unwrap();
        assert_eq!(
            nfqws2_dns::first_ipv4(&buf[..n]).unwrap(),
            Ipv4Addr::new(192, 0, 2, 15)
        );
        assert_eq!(gate.installs.load(Ordering::SeqCst), 2);
        timeout(Duration::from_secs(1), upstream_task)
            .await
            .unwrap()
            .unwrap();
        service.abort();
    }

    #[tokio::test]
    async fn ipv4_only_aaaa_is_confirmed_and_traced_without_contacting_upstream() {
        #[derive(Default)]
        struct Gate {
            confirmed: AtomicUsize,
            traces: AtomicUsize,
            replaced: AtomicBool,
        }
        const TARGET: RouteMatch = RouteMatch {
            revision: 2,
            generation: 1,
            zone: 1,
        };
        impl RouteObserver for Gate {
            fn select(
                &self,
                domain: &str,
                client: Option<IpAddr>,
            ) -> io::Result<Option<RouteMatch>> {
                assert_eq!(client, Some(Ipv4Addr::LOCALHOST.into()));
                let revision = TARGET.revision + u64::from(self.replaced.load(Ordering::SeqCst));
                Ok((domain == "office.test").then_some(RouteMatch { revision, ..TARGET }))
            }
            fn blocks_aaaa(&self, target: RouteMatch) -> io::Result<bool> {
                assert_eq!(target, TARGET);
                Ok(true)
            }
            fn install(
                &self,
                target: RouteMatch,
                _: &str,
                _: DnsOrigin<'_>,
                answer: &RouteAnswer,
            ) -> io::Result<(bool, u64)> {
                assert_eq!(target, TARGET);
                assert_eq!(answer.qtype, 28);
                assert!(answer.addresses.is_empty());
                if self.confirmed.fetch_add(1, Ordering::SeqCst) == 1 {
                    self.replaced.store(true, Ordering::SeqCst);
                }
                Ok((true, TARGET.revision))
            }
            fn record_reply(
                &self,
                _: &str,
                _: DnsOrigin<'_>,
                target: Option<RouteMatch>,
                reply: &[u8],
                suppressed: bool,
            ) {
                assert_eq!(target, Some(TARGET));
                assert!(suppressed);
                assert!(nfqws2_dns::trace_answer(reply).unwrap().sinkholed);
                self.traces.fetch_add(1, Ordering::SeqCst);
            }
        }

        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = upstream.local_addr().unwrap();
        let gate = Arc::new(Gate::default());
        let observer = Observer::default();
        observer.register(gate.clone());
        let query = nfqws2_dns::build_query("office.test", 28, 12).unwrap();
        let response = timeout(
            Duration::from_secs(1),
            forward(server, &observer, Ipv4Addr::LOCALHOST.into(), None, &query),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert_eq!(response, nfqws2_dns::response_error(&query, 0));
        assert_eq!(gate.confirmed.load(Ordering::SeqCst), 1);
        assert_eq!(gate.traces.load(Ordering::SeqCst), 1);
        // The next confirmation loses its generation while it waits for the
        // route writer. It must neither send an answer nor report a block.
        assert!(
            forward(server, &observer, Ipv4Addr::LOCALHOST.into(), None, &query)
                .await
                .is_err()
        );
        assert_eq!(gate.confirmed.load(Ordering::SeqCst), 2);
        assert_eq!(gate.traces.load(Ordering::SeqCst), 1);
        let mut bytes = [0; 512];
        assert_eq!(
            upstream.try_recv_from(&mut bytes).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[tokio::test]
    async fn ipv4_only_aaaa_waits_for_the_captured_refresh_without_forwarding() {
        use crate::dnsserver::{DeliverySelection, RedirectEpoch, RouteWriterBusy};
        use std::sync::Mutex;
        use tokio::sync::watch;

        #[derive(Clone, Copy)]
        enum Publication {
            Refreshing,
            Ready,
            Replaced,
            Unavailable,
        }

        const EPOCH: RedirectEpoch = RedirectEpoch {
            replacement: 1,
            revision: Some(6),
            zone: Some(0),
            suppress_aaaa: true,
            unavailable: false,
        };
        const TARGET: RouteMatch = RouteMatch {
            revision: 7,
            generation: 2,
            zone: 0,
        };

        struct Gate {
            publication: Mutex<Publication>,
            changed: watch::Sender<()>,
            attempts: AtomicUsize,
            traced: AtomicUsize,
        }
        impl RouteObserver for Gate {
            fn select(&self, _: &str, _: Option<IpAddr>) -> io::Result<Option<RouteMatch>> {
                unreachable!("redirected queries retain their ingress")
            }

            fn capture_redirect(
                &self,
                name: &str,
                origin: DnsOrigin<'_>,
            ) -> (Option<RedirectEpoch>, io::Result<Option<RouteMatch>>) {
                assert_eq!(name, "office.test");
                assert_eq!(origin.client, Some(Ipv4Addr::LOCALHOST.into()));
                assert_eq!(origin.ingress, Some("br-test"));
                let unavailable =
                    matches!(*self.publication.lock().unwrap(), Publication::Unavailable);
                (
                    Some(RedirectEpoch {
                        unavailable,
                        ..EPOCH
                    }),
                    Err(io::ErrorKind::WouldBlock.into()),
                )
            }

            fn select_redirect_for_delivery(
                &self,
                _: &str,
                _: DnsOrigin<'_>,
                epoch: RedirectEpoch,
            ) -> io::Result<DeliverySelection> {
                if epoch.unavailable {
                    return Err(io::ErrorKind::NotFound.into());
                }
                assert!(epoch == EPOCH);
                match *self.publication.lock().unwrap() {
                    Publication::Refreshing => {
                        Ok(DeliverySelection::Pending(self.changed.subscribe()))
                    }
                    Publication::Ready => Ok(DeliverySelection::Ready(Some(TARGET))),
                    Publication::Replaced | Publication::Unavailable => {
                        Err(io::ErrorKind::NotFound.into())
                    }
                }
            }

            fn blocks_aaaa(&self, target: RouteMatch) -> io::Result<bool> {
                assert_eq!(target, TARGET);
                Ok(true)
            }

            fn install(
                &self,
                target: RouteMatch,
                _: &str,
                _: DnsOrigin<'_>,
                answer: &RouteAnswer,
            ) -> io::Result<(bool, u64)> {
                assert_eq!(target, TARGET);
                assert_eq!(answer.qtype, 28);
                assert!(answer.addresses.is_empty());
                if self.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Err(io::Error::new(io::ErrorKind::WouldBlock, RouteWriterBusy));
                }
                Ok((true, target.revision))
            }

            fn record_reply(
                &self,
                _: &str,
                _: DnsOrigin<'_>,
                _: Option<RouteMatch>,
                _: &[u8],
                suppressed: bool,
            ) {
                assert!(suppressed);
                self.traced.fetch_add(1, Ordering::SeqCst);
            }
        }

        for completion in [
            Publication::Ready,
            Publication::Replaced,
            Publication::Refreshing,
            Publication::Unavailable,
        ] {
            let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let unavailable = matches!(completion, Publication::Unavailable);
            let gate = Arc::new(Gate {
                publication: Mutex::new(if unavailable {
                    completion
                } else {
                    Publication::Refreshing
                }),
                changed: watch::Sender::new(()),
                attempts: AtomicUsize::new(0),
                traced: AtomicUsize::new(0),
            });
            let observer = Arc::new(Observer::default());
            observer.register(gate.clone());
            let listener = Bound::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let local = listener.tcp.local_addr().unwrap();
            let service = tokio::spawn(listener.serve(Handler::Intercept {
                upstream: upstream.local_addr().unwrap(),
                observer,
                bridge: Some("br-test".into()),
            }));
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            udp.connect(local).await.unwrap();
            let mut tcp = TcpStream::connect(local).await.unwrap();
            let query = nfqws2_dns::build_query("office.test", 28, 18).unwrap();
            udp.send(&query).await.unwrap();
            tcp.write_u16(query.len() as u16).await.unwrap();
            tcp.write_all(&query).await.unwrap();
            let mut raw = [0; 512];
            if !unavailable {
                timeout(Duration::from_secs(1), async {
                    while gate.changed.receiver_count() != 2 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                assert_eq!(
                    udp.try_recv(&mut raw).unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
                if !matches!(completion, Publication::Refreshing) {
                    *gate.publication.lock().unwrap() = completion;
                    gate.changed.send_replace(());
                }
            }
            let ready = matches!(completion, Publication::Ready);
            let expected = nfqws2_dns::response_error(&query, if ready { 0 } else { 2 });
            timeout(Duration::from_secs(3), async {
                let len = udp.recv(&mut raw).await.unwrap();
                assert_eq!(&raw[..len], expected);
                let len = tcp.read_u16().await.unwrap() as usize;
                tcp.read_exact(&mut raw[..len]).await.unwrap();
                assert_eq!(&raw[..len], expected);
            })
            .await
            .unwrap();
            assert_eq!(gate.attempts.load(Ordering::SeqCst), 3 * usize::from(ready));
            assert_eq!(gate.traced.load(Ordering::SeqCst), 2 * usize::from(ready));
            assert_eq!(gate.changed.receiver_count(), 0);
            assert_eq!(
                upstream.try_recv_from(&mut raw).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            service.abort();
        }
    }

    #[tokio::test]
    async fn upstream_replies_cannot_cross_a_policy_replacement() {
        #[derive(Default)]
        struct Gate {
            updated: AtomicBool,
            installed: AtomicUsize,
        }
        impl RouteObserver for Gate {
            fn select(&self, name: &str, client: Option<IpAddr>) -> io::Result<Option<RouteMatch>> {
                assert_eq!(client, Some(Ipv4Addr::LOCALHOST.into()));
                let updated = self.updated.load(Ordering::SeqCst);
                if name == "outside.test" || name == "new.test" && !updated {
                    return Ok(None);
                }
                Ok(Some(RouteMatch {
                    revision: 1 + u64::from(updated),
                    generation: 1 + u64::from(updated && name == "retired.test"),
                    zone: 0,
                }))
            }

            fn install(
                &self,
                target: RouteMatch,
                _: &str,
                _: DnsOrigin<'_>,
                answer: &RouteAnswer,
            ) -> io::Result<(bool, u64)> {
                assert_eq!(target.revision, 2);
                assert_eq!(target.generation, 1);
                assert_eq!(answer.addresses, [IpAddr::from([192, 0, 2, 15])]);
                self.installed.fetch_add(1, Ordering::SeqCst);
                Ok((false, target.revision))
            }
        }

        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = upstream.local_addr().unwrap();
        let gate = Arc::new(Gate::default());
        let observer = Observer::default();
        observer.register(gate.clone());
        for (domain, rejected, truncated) in [
            ("retired.test", true, false),
            ("retired.test", true, true),
            ("new.test", true, false),
            ("steady.test", false, false),
            ("outside.test", false, false),
        ] {
            gate.updated.store(false, Ordering::SeqCst);
            let query = nfqws2_dns::build_query(domain, 1, 9).unwrap();
            let resolver = async {
                let mut wire = [0; 512];
                let (n, peer) = upstream.recv_from(&mut wire).await.unwrap();
                assert_eq!(nfqws2_dns::query_domain(&wire[..n]).unwrap().0, domain);
                gate.updated.store(true, Ordering::SeqCst);
                let mut reply = nfqws2_dns::response_error(&wire[..n], 0);
                reply[7] = 1;
                reply.extend_from_slice(&[192, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 15]);
                if truncated {
                    reply[2] |= 2;
                }
                upstream.send_to(&reply, peer).await.unwrap();
            };
            let (reply, ()) = timeout(Duration::from_secs(2), async {
                tokio::join!(
                    forward(server, &observer, Ipv4Addr::LOCALHOST.into(), None, &query),
                    resolver
                )
            })
            .await
            .unwrap();
            if rejected {
                assert!(reply
                    .unwrap_err()
                    .to_string()
                    .contains("политика DNS изменилась"));
            } else {
                assert_eq!(
                    nfqws2_dns::first_ipv4(&reply.unwrap().unwrap()).unwrap(),
                    Ipv4Addr::new(192, 0, 2, 15)
                );
            }
        }
        assert_eq!(gate.installed.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_udp_only_firmware_resolver_preserves_tc_on_both_client_transports() {
        struct Gate;
        impl RouteObserver for Gate {
            fn select(&self, _: &str, _: Option<IpAddr>) -> io::Result<Option<RouteMatch>> {
                Ok(Some(RouteMatch {
                    revision: 1,
                    generation: 1,
                    zone: 0,
                }))
            }

            fn install(
                &self,
                _: RouteMatch,
                _: &str,
                _: DnsOrigin<'_>,
                _: &RouteAnswer,
            ) -> io::Result<(bool, u64)> {
                panic!("a truncated RRset must not confirm any route")
            }
        }
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let firmware = upstream.local_addr().unwrap();
        let tcp_monitor = tokio::net::TcpListener::bind(firmware).await.unwrap();
        let observer = Arc::new(Observer::default());
        observer.register(Arc::new(Gate));
        let bound = Bound::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let proxy = bound.tcp.local_addr().unwrap();
        let panel = tokio::spawn(bound.serve(Handler::Intercept {
            upstream: firmware,
            observer,
            bridge: None,
        }));

        let resolver = async {
            for partial_rrset in [false, true] {
                let mut buf = [0; 512];
                let (n, peer) = upstream.recv_from(&mut buf).await.unwrap();
                let mut reply = nfqws2_dns::response_error(&buf[..n], 0);
                reply[2] |= 2;
                if partial_rrset {
                    reply[7] = 1;
                    reply.extend_from_slice(&[
                        192, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 15,
                    ]);
                }
                upstream.send_to(&reply, peer).await.unwrap();
            }
        };
        let clients = async {
            let query = nfqws2_dns::build_query("office.test", 1, 42).unwrap();
            let mut expected = nfqws2_dns::response_error(&query, 0);
            expected[2] |= 2;
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            udp.send_to(&query, proxy).await.unwrap();
            let mut raw = [0; 512];
            let (n, source) = udp.recv_from(&mut raw).await.unwrap();
            assert_eq!(source, proxy);
            assert_eq!(&raw[..n], expected);

            let mut tcp = TcpStream::connect(proxy).await.unwrap();
            tcp.write_u16(query.len() as u16).await.unwrap();
            tcp.write_all(&query).await.unwrap();
            let n = tcp.read_u16().await.unwrap() as usize;
            tcp.read_exact(&mut raw[..n]).await.unwrap();
            assert_eq!(&raw[..n], expected);
        };
        timeout(Duration::from_secs(2), async {
            tokio::select! {
                _ = async { tokio::join!(resolver, clients) } => (),
                _ = tcp_monitor.accept() => panic!("the intercept tried TCP to firmware"),
            }
        })
        .await
        .unwrap();
        panel.abort();
        let _ = panel.await;
    }

    /// Router DNS and the panel's own resolver are separate listeners. Both
    /// client transports must pass through the route gate before replying.
    #[tokio::test]
    async fn intercepted_udp_and_tcp_use_the_socket_peer_and_wait_for_route_confirmation() {
        #[derive(Default)]
        struct Gate(AtomicUsize);
        impl RouteObserver for Gate {
            fn select_on(
                &self,
                domain: &str,
                origin: DnsOrigin<'_>,
            ) -> io::Result<Option<RouteMatch>> {
                assert_eq!(origin.client, Some(Ipv4Addr::LOCALHOST.into()));
                if origin.ingress == Some("br-test") {
                    self.select(domain, origin.client)
                } else {
                    Ok(None)
                }
            }
            fn select(
                &self,
                domain: &str,
                client: Option<IpAddr>,
            ) -> io::Result<Option<RouteMatch>> {
                assert_eq!(domain, "office.test");
                assert_eq!(client, Some(Ipv4Addr::LOCALHOST.into()));
                Ok(Some(RouteMatch {
                    zone: 0,
                    revision: 1,
                    generation: 1,
                }))
            }
            fn install(
                &self,
                _: RouteMatch,
                _: &str,
                origin: DnsOrigin<'_>,
                answer: &RouteAnswer,
            ) -> io::Result<(bool, u64)> {
                assert_eq!(origin.ingress, Some("br-test"));
                assert_eq!(answer.addresses, [IpAddr::from([192, 0, 2, 15])]);
                if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Err(io::Error::other("route busy"));
                }
                Ok((false, 1))
            }
        }
        let mut query = nfqws2_dns::build_query("office.test", 1, 71).unwrap();
        query[11] = 1;
        // OPT with a full-length IPv4 ECS value for a different device.
        let subnet = [
            0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 12, 0, 8, 0, 8, 0, 1, 32, 0, 192, 0, 2, 47,
        ];
        query.extend_from_slice(&subnet);
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            for _ in 0..4 {
                let mut buf = [0; 512];
                let (n, peer) = upstream.recv_from(&mut buf).await.unwrap();
                assert_eq!(&buf[n - subnet.len()..n], &subnet);
                let mut reply = nfqws2_dns::response_error(&buf[..n], 0);
                reply[7] = 1;
                reply.extend_from_slice(&[192, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 15]);
                upstream.send_to(&reply, peer).await.unwrap();
            }
        });
        let gate = Arc::new(Gate::default());
        let observer = Arc::new(Observer::default());
        observer.register(gate.clone());
        let listener = Bound::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let local = listener.tcp.local_addr().unwrap();
        let service = tokio::spawn(listener.serve(Handler::Intercept {
            upstream: server,
            observer: observer.clone(),
            bridge: Some(Arc::from("br-test")),
        }));
        timeout(Duration::from_secs(5), async {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            udp.send_to(&query, local).await.unwrap();
            let mut buf = [0; 512];
            let n = udp.recv(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], &nfqws2_dns::response_error(&query, 2));
            let mut tcp = TcpStream::connect(local).await.unwrap();
            tcp.write_u16(query.len() as u16).await.unwrap();
            tcp.write_all(&query).await.unwrap();
            let mut reply = vec![0; tcp.read_u16().await.unwrap() as usize];
            tcp.read_exact(&mut reply).await.unwrap();
            nfqws2_dns::validate_answer(&query, &reply).unwrap();
            assert_eq!(
                nfqws2_dns::first_ipv4(&reply).unwrap(),
                Ipv4Addr::new(192, 0, 2, 15)
            );
            // The same peer and ECS bytes without the expected device binding
            // may use DNS, but cannot confirm per-device destinations.
            for ingress in [Some("br-other"), None] {
                let reply = forward(
                    server,
                    &observer,
                    Ipv4Addr::LOCALHOST.into(),
                    ingress,
                    &query,
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(
                    nfqws2_dns::first_ipv4(&reply).unwrap(),
                    Ipv4Addr::new(192, 0, 2, 15)
                );
            }
            upstream_task.await.unwrap();
        })
        .await
        .unwrap();
        assert_eq!(gate.0.load(Ordering::SeqCst), 2);
        service.abort();
        let _ = service.await;
    }
}
