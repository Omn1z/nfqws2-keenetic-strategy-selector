use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Request, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::Deserialize;
use std::{
    collections::HashMap,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::RangeInclusive,
    sync::{atomic::Ordering, Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{lookup_host, TcpSocket, TcpStream},
    runtime::{Builder, Runtime},
    time::{sleep, timeout, timeout_at},
};
use tokio_rustls::{
    client::TlsStream,
    rustls::{pki_types::ServerName, ClientConfig, RootCertStore},
    TlsConnector,
};

const MAX_WIRE: usize = u16::MAX as usize;

#[derive(Clone, Deserialize)]
pub(super) struct Server {
    pub id: String,
    pub name: String,
    transport: String,
    addr: String,
}

struct Stack {
    runtime: LookupRuntime,
    doh: Arc<ClientConfig>,
    dot: Arc<ClientConfig>,
    reserved: RangeInclusive<u16>,
}

type Cached = Arc<OnceLock<Result<Ipv4Addr, String>>>;
pub(super) struct Resolver {
    stack: Option<Result<Stack, String>>,
    cache: Mutex<HashMap<(String, String), Cached>>,
    system: OnceLock<Result<LookupRuntime, String>>,
}

fn invalid(message: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

struct LookupRuntime(Option<Runtime>);

impl LookupRuntime {
    fn new() -> io::Result<Self> {
        Ok(Self(Some(
            Builder::new_multi_thread()
                .worker_threads(1)
                .max_blocking_threads(8)
                .enable_all()
                .build()?,
        )))
    }

    fn get(&self) -> &Runtime {
        self.0.as_ref().unwrap()
    }

    fn query<T: Send + 'static>(
        &self,
        deadline: Instant,
        control: &super::Control,
        query: impl Future<Output = io::Result<T>> + Send + 'static,
    ) -> io::Result<T> {
        if control.cancel.load(Ordering::Acquire) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "прогон отменён"));
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "истекло время ответа DNS",
            ));
        }
        let runtime = self.get();
        let mut task = AbortOnDrop(runtime.spawn(async move {
            timeout_at(deadline.into(), query)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "истекло время ответа DNS"))?
        }));
        runtime.block_on(async {
            tokio::select! {
                resolved = &mut task.0 => resolved.map_err(io::Error::other)?,
                _ = async {
                    while !control.cancel.load(Ordering::Acquire) {
                        sleep(Duration::from_millis(25)).await;
                    }
                } => Err(io::Error::new(io::ErrorKind::Interrupted, "прогон отменён")),
            }
        })
    }
}

impl Drop for LookupRuntime {
    fn drop(&mut self) {
        // A timed-out system lookup may still be in the OS resolver. It must
        // not hold this one-run helper open after all its jobs have ended.
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_timeout(Duration::from_millis(100));
        }
    }
}

impl Stack {
    fn new(roots: RootCertStore, reserved: RangeInclusive<u16>) -> io::Result<Self> {
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut doh = config.clone();
        doh.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Self {
            runtime: LookupRuntime::new()?,
            doh: Arc::new(doh),
            dot: Arc::new(config),
            reserved,
        })
    }

    fn resolve(
        &self,
        server: &Server,
        host: String,
        control: &super::Control,
        deadline: Option<Instant>,
    ) -> io::Result<Ipv4Addr> {
        let normal = Instant::now()
            + Duration::from_secs(if server.transport.eq_ignore_ascii_case("dot") {
                6
            } else {
                8
            });
        let (https, tls) = (self.doh.clone(), self.dot.clone());
        let reserved = self.reserved.clone();
        let server = server.clone();
        self.runtime.query(
            deadline.map_or(normal, |limit| limit.min(normal)),
            control,
            async move {
                let query = nfqws2_dns::build_query(&host, 1, nfqws2_dns::transaction_id()?)?;
                let raw = match server.transport.to_ascii_lowercase().as_str() {
                    "doh" => doh(&https, &server.addr, &query, &reserved).await?,
                    "dot" => dot(&tls, &server.addr, &query, &reserved).await?,
                    _ => return Err(invalid("неизвестный тип DNS")),
                };
                nfqws2_dns::validate_answer(&query, &raw)?;
                nfqws2_dns::first_ipv4(&raw)
            },
        )
    }
}

impl Resolver {
    pub(super) fn new(reserved: Option<RangeInclusive<u16>>) -> Self {
        Self {
            stack: reserved.map(|reserved| {
                nfqws2_tls_roots::load()
                    .and_then(|roots| Stack::new(roots, reserved))
                    .map_err(|e| e.to_string())
            }),
            cache: Mutex::default(),
            system: OnceLock::new(),
        }
    }

    pub(super) fn resolve(
        &self,
        server: Option<&Server>,
        host: &str,
        control: &super::Control,
    ) -> Result<Option<Ipv4Addr>, String> {
        let Some(server) = server else {
            return Ok(None);
        };
        if host.trim_matches(['[', ']']).parse::<IpAddr>().is_ok() {
            return Ok(None);
        }
        let stack = self
            .stack
            .as_ref()
            .expect("saved DNS is enabled")
            .as_ref()
            .map_err(Clone::clone)?;
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let cell = self
            .cache
            .lock()
            .unwrap()
            .entry((server.id.clone(), host.clone()))
            .or_default()
            .clone();
        cell.get_or_init(|| {
            stack
                .resolve(server, host, control, None)
                .map_err(|e| e.to_string())
        })
        .clone()
        .map(Some)
    }

    pub(super) fn redirect_address(
        &self,
        server: Option<&Server>,
        host: &str,
        deadline: Instant,
        control: &super::Control,
    ) -> io::Result<Ipv4Addr> {
        if let Some(server) = server {
            let stack = self
                .stack
                .as_ref()
                .expect("saved DNS is enabled")
                .as_ref()
                .map_err(invalid)?;
            let host = host.trim_end_matches('.').to_ascii_lowercase();
            let key = (server.id.clone(), host.clone());
            let cell = self.cache.lock().unwrap().get(&key).cloned();
            if let Some(answer) = cell.as_ref().and_then(|cell| cell.get()) {
                return answer.clone().map_err(invalid);
            }
            // Another job may have started a fresh lookup under a longer
            // lease. Do not let its synchronous cache wait overrun this hop.
            let address = stack.resolve(server, host, control, Some(deadline))?;
            self.cache
                .lock()
                .unwrap()
                .entry(key)
                .or_insert_with(|| Arc::new(OnceLock::from(Ok(address))));
            return Ok(address);
        }
        let runtime = self
            .system
            .get_or_init(|| LookupRuntime::new().map_err(|e| e.to_string()))
            .as_ref()
            .map_err(invalid)?;
        let host = host.to_owned();
        runtime.query(deadline, control, async move {
            lookup_host((host.as_str(), 443))
                .await?
                .find_map(|addr| match addr.ip().to_canonical() {
                    IpAddr::V4(ip) => Some(ip),
                    IpAddr::V6(_) => None,
                })
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "у HTTPS-адреса нет IPv4"))
        })
    }
}

fn resolver_socket(address: SocketAddr, reserved: &RangeInclusive<u16>) -> io::Result<TcpSocket> {
    // DoH may use the same destination port as a probe. Bind before connecting
    // so resolver packets cannot be counted in a candidate's source-port slot.
    let bind = |port| {
        let (socket, ip) = if address.is_ipv4() {
            (TcpSocket::new_v4()?, IpAddr::from(Ipv4Addr::UNSPECIFIED))
        } else {
            (TcpSocket::new_v6()?, IpAddr::from(Ipv6Addr::UNSPECIFIED))
        };
        socket.bind(SocketAddr::new(ip, port))?;
        Ok::<_, io::Error>(socket)
    };
    for _ in 0..4 {
        match bind(0) {
            Ok(socket) if !reserved.contains(&socket.local_addr()?.port()) => return Ok(socket),
            Ok(_) => (),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::AddrInUse | io::ErrorKind::AddrNotAvailable
                ) =>
            {
                break
            }
            Err(e) => return Err(e),
        }
    }
    // The kernel may allocate sequentially from a range covered by the
    // matrix. After those attempts, try explicit high ports from both sides.
    let first = u32::from(*reserved.start());
    let last = u32::from(*reserved.end());
    let upper = (last + 1).max(32768)..=u32::from(u16::MAX);
    let lower = 32768..first;
    for port in upper.take(32).chain(lower.rev().take(32)) {
        match bind(port as u16) {
            Ok(socket) => return Ok(socket),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::AddrInUse
                        | io::ErrorKind::AddrNotAvailable
                        | io::ErrorKind::PermissionDenied
                ) => {}
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "не удалось выделить порт вне тестовой матрицы",
    ))
}

async fn tls(
    config: &Arc<ClientConfig>,
    host: &str,
    port: u16,
    reserved: &RangeInclusive<u16>,
) -> io::Result<TlsStream<TcpStream>> {
    let name = ServerName::try_from(host.to_owned()).map_err(invalid)?;
    let mut error = io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "DNS-сервер не имеет адреса",
    );
    for addr in lookup_host((host, port)).await?.take(16) {
        let socket = match resolver_socket(addr, reserved) {
            Ok(socket) => socket,
            Err(e) => {
                error = e;
                continue;
            }
        };
        match timeout(Duration::from_secs(2), socket.connect(addr)).await {
            Ok(Ok(tcp)) => return TlsConnector::from(config.clone()).connect(name, tcp).await,
            Ok(Err(e)) => error = e,
            Err(_) => error = io::ErrorKind::TimedOut.into(),
        }
    }
    Err(error)
}

async fn doh(
    config: &Arc<ClientConfig>,
    addr: &str,
    query: &[u8],
    reserved: &RangeInclusive<u16>,
) -> io::Result<Vec<u8>> {
    let uri: Uri = addr.parse().map_err(invalid)?;
    let authority = uri
        .authority()
        .filter(|a| !a.as_str().contains('@'))
        .ok_or_else(|| invalid("неверный адрес DoH"))?;
    if uri.scheme_str() != Some("https") {
        return Err(invalid("DoH требует HTTPS"));
    }
    let stream = tls(
        config,
        authority.host().trim_matches(['[', ']']),
        authority.port_u16().unwrap_or(443),
        reserved,
    )
    .await?;
    let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
    let req = Request::post(if h2 {
        addr
    } else {
        uri.path_and_query().map_or("/", |p| p.as_str())
    })
    .header("host", authority.as_str())
    .header("content-type", "application/dns-message")
    .header("accept", "application/dns-message")
    .body(Full::new(Bytes::copy_from_slice(query)))
    .map_err(invalid)?;
    let stream = TokioIo::new(stream);
    let (response, driver) = if h2 {
        let (mut send, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .handshake(stream)
            .await
            .map_err(invalid)?;
        let task = AbortOnDrop(tokio::spawn(connection));
        (send.send_request(req).await, task)
    } else {
        let (mut send, connection) = hyper::client::conn::http1::handshake(stream)
            .await
            .map_err(invalid)?;
        let task = AbortOnDrop(tokio::spawn(connection));
        (send.send_request(req).await, task)
    };
    let _driver = driver;
    let mut response = response.map_err(invalid)?;
    if response.status() != hyper::StatusCode::OK {
        return Err(invalid(format!("DoH HTTP {}", response.status())));
    }
    let mut raw = Vec::new();
    while let Some(frame) = response.body_mut().frame().await {
        if let Ok(data) = frame.map_err(invalid)?.into_data() {
            if raw.len() + data.len() > MAX_WIRE {
                return Err(invalid("слишком длинный ответ DoH"));
            }
            raw.extend_from_slice(&data);
        }
    }
    Ok(raw)
}

struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn dot(
    config: &Arc<ClientConfig>,
    addr: &str,
    query: &[u8],
    reserved: &RangeInclusive<u16>,
) -> io::Result<Vec<u8>> {
    let (host, port) = if addr.parse::<IpAddr>().is_ok() {
        (addr.to_owned(), 853)
    } else {
        let authority = addr
            .parse::<hyper::http::uri::Authority>()
            .map_err(invalid)?;
        if authority.as_str().contains('@') {
            return Err(invalid("неверный адрес DoT"));
        }
        (
            authority.host().trim_matches(['[', ']']).to_owned(),
            authority.port_u16().unwrap_or(853),
        )
    };
    let mut stream = tls(config, &host, port, reserved).await?;
    stream.write_u16(query.len() as u16).await?;
    stream.write_all(query).await?;
    let len = stream.read_u16().await?;
    let mut raw = vec![0; len as usize];
    stream.read_exact(&mut raw).await?;
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matrix::Control;
    use std::sync::atomic::AtomicUsize;
    use tokio::net::TcpListener;
    use tokio_rustls::{
        rustls::{pki_types::PrivatePkcs8KeyDer, ServerConfig},
        TlsAcceptor,
    };

    fn reply(mut query: Vec<u8>, address: [u8; 4], mismatched: bool) -> Vec<u8> {
        assert!(query.ends_with(&[0, 1, 0, 1]));
        if mismatched {
            query[0] ^= 0xff;
        }
        query[2..4].copy_from_slice(&[0x81, 0x80]);
        query[6..8].copy_from_slice(&[0, 1]);
        query.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4]);
        query.extend_from_slice(&address);
        query
    }

    #[test]
    fn matrix_saved_dns_uses_verified_doh_and_dot_caches_results_and_rejects_wrong_reply() {
        let issued = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let cert = issued.cert.der().clone();
        let key = PrivatePkcs8KeyDer::from(issued.signing_key.serialize_der());
        let acceptor = TlsAcceptor::from(Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert.clone()], key.into())
                .unwrap(),
        ));
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let resolver = Resolver {
            stack: Some(Ok(Stack::new(roots, 50000..=51799).unwrap())),
            cache: Mutex::default(),
            system: OnceLock::new(),
        };
        let runtime = resolver
            .stack
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap()
            .runtime
            .get();
        let served = Arc::new(AtomicUsize::new(0));
        let provider = |transport: &str, bad: bool, hosts: &[&str]| {
            let listener = runtime.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
            let endpoint = listener.local_addr().unwrap();
            let https = transport == "doh";
            let acceptor = acceptor.clone();
            let served = served.clone();
            let hosts: Vec<_> = hosts.iter().copied().map(str::to_owned).collect();
            runtime.spawn(async move {
                for host in hosts {
                    let (socket, source) = listener.accept().await.unwrap();
                    assert!(!(50000..=51799).contains(&source.port()));
                    let mut stream = acceptor.accept(socket).await.unwrap();
                    served.fetch_add(1, Ordering::Relaxed);
                    if https {
                        let mut header = Vec::new();
                        while !header.ends_with(b"\r\n\r\n") {
                            header.push(stream.read_u8().await.unwrap());
                            assert!(header.len() < 4096);
                        }
                        let header = String::from_utf8(header).unwrap().to_ascii_lowercase();
                        assert!(header.starts_with("post /dns-query?scope=test http/1.1\r\n"));
                        assert!(header.contains("content-type: application/dns-message\r\n"));
                        let len = header
                            .lines()
                            .find_map(|line| line.strip_prefix("content-length: "))
                            .unwrap()
                            .parse()
                            .unwrap();
                        let mut query = vec![0; len];
                        stream.read_exact(&mut query).await.unwrap();
                        assert_eq!(nfqws2_dns::query_domain(&query).unwrap(), (host, 1));
                        let response = reply(query, [192, 0, 2, 1], bad);
                        stream
                            .write_all(
                                format!(
                                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                                    response.len()
                                )
                                .as_bytes(),
                            )
                            .await
                            .unwrap();
                        stream.write_all(&response).await.unwrap();
                    } else {
                        let len = stream.read_u16().await.unwrap();
                        let mut query = vec![0; len as usize];
                        stream.read_exact(&mut query).await.unwrap();
                        assert_eq!(nfqws2_dns::query_domain(&query).unwrap(), (host, 1));
                        let response = reply(query, [192, 0, 2, 2], bad);
                        stream.write_u16(response.len() as u16).await.unwrap();
                        stream.write_all(&response).await.unwrap();
                    }
                    stream.shutdown().await.unwrap();
                }
            });
            Server {
                id: format!("{transport}-{bad}"),
                name: "Signed local fixture".into(),
                transport: transport.into(),
                addr: if https {
                    format!("https://{endpoint}/dns-query?scope=test")
                } else {
                    endpoint.to_string()
                },
            }
        };
        let doh = provider("doh", false, &["example.test", "next.fixture.net"]);
        let dot = provider("dot", false, &["example.test"]);
        let invalid = provider("dot", true, &["example.test"]);
        let control = Control::new(2, false);
        for host in ["example.test", "Example.Test."] {
            assert_eq!(
                resolver.resolve(Some(&doh), host, &control).unwrap(),
                Some(Ipv4Addr::new(192, 0, 2, 1))
            );
            assert_eq!(
                resolver.resolve(Some(&dot), host, &control).unwrap(),
                Some(Ipv4Addr::new(192, 0, 2, 2))
            );
            assert!(resolver.resolve(Some(&invalid), host, &control).is_err());
        }
        assert_eq!(
            resolver.resolve(None, "example.test", &control).unwrap(),
            None
        );
        assert_eq!(
            resolver.resolve(Some(&doh), "192.0.2.3", &control).unwrap(),
            None
        );
        assert_eq!(served.load(Ordering::Relaxed), 3);
        assert_eq!(
            resolver
                .redirect_address(
                    Some(&doh),
                    "next.fixture.net",
                    Instant::now() + Duration::from_secs(3),
                    &control
                )
                .unwrap(),
            Ipv4Addr::new(192, 0, 2, 1)
        );
        assert_eq!(
            resolver
                .redirect_address(
                    Some(&doh),
                    "not-issued.fixture.net",
                    Instant::now(),
                    &control
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(served.load(Ordering::Relaxed), 4);
    }

    #[test]
    fn matrix_saved_dns_cannot_allocate_a_source_port_in_a_matrix_slot() {
        let addr = "127.0.0.1:443".parse().unwrap();
        let error = resolver_socket(addr, &(1..=65535)).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::AddrNotAvailable);
    }

    #[test]
    fn matrix_saved_dns_can_bind_below_a_reserved_ephemeral_range() {
        let addr = "127.0.0.1:443".parse().unwrap();
        let socket = resolver_socket(addr, &(49152..=u16::MAX)).unwrap();
        let port = socket.local_addr().unwrap().port();
        assert!((1024..49152).contains(&port));
    }
}
