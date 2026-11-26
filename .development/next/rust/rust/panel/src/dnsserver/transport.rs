use super::{
    config::Upstream,
    fast_dns,
    scheduler::{self, Policy},
    vpn::Route,
};
use axum::{
    body::Bytes,
    http::{header, Request, Uri},
};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    body::{Body, Frame, Incoming, SizeHint},
    client::conn::{http1, http2},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::{
    collections::HashMap,
    convert::Infallible,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::time::{timeout_at, Instant as TokioInstant};
#[cfg(test)]
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::{
    rustls::{pki_types::ServerName, ClientConfig, RootCertStore},
    TlsConnector,
};

pub(super) enum Sender {
    Http1(http1::SendRequest<RequestBody>),
    Http2(http2::SendRequest<RequestBody>),
}
impl Sender {
    fn is_closed(&self) -> bool {
        match self {
            Self::Http1(s) => s.is_closed(),
            Self::Http2(s) => s.is_closed(),
        }
    }
    pub async fn send_request(
        &mut self,
        req: Request<Full<Bytes>>,
    ) -> io::Result<axum::http::Response<Incoming>> {
        self.send_with_dispatch(req, None).await
    }
    async fn send_with_dispatch(
        &mut self,
        req: Request<Full<Bytes>>,
        dispatch: Option<&Arc<Dispatch>>,
    ) -> io::Result<axum::http::Response<Incoming>> {
        let mut req = req.map(|body| RequestBody {
            body,
            dispatch: dispatch.cloned(),
        });
        let response = match self {
            Self::Http1(s) => {
                // A direct HTTP/1.1 connection uses origin form. HTTP/2
                // receives the original URI for :scheme and :authority.
                *req.uri_mut() = req
                    .uri()
                    .path_and_query()
                    .ok_or_else(|| io::Error::other("у DoH запроса нет пути"))?
                    .as_str()
                    .parse()
                    .map_err(io::Error::other)?;
                s.send_request(req).await
            }
            Self::Http2(s) => s.send_request(req).await,
        };
        response.map_err(io::Error::other)
    }
}

#[derive(Default)]
struct Dispatch(AtomicU8);

impl Dispatch {
    fn observed(&self) -> bool {
        self.0.load(Ordering::Acquire) == 1
    }

    fn discard(&self) {
        self.0.store(2, Ordering::Release);
    }
}

pub(super) struct RequestBody {
    body: Full<Bytes>,
    dispatch: Option<Arc<Dispatch>>,
}

impl Body for RequestBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let frame = Pin::new(&mut self.body).poll_frame(cx);
        if let Some(dispatch) = &self.dispatch {
            // Hyper has reached the DNS payload on the authenticated HTTP
            // connection. Merely queuing it does not prove a network attempt.
            if matches!(frame, Poll::Ready(Some(Ok(ref frame))) if frame.is_data()) {
                let _ = dispatch
                    .0
                    .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire);
            }
        }
        frame
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
}
#[derive(Clone, PartialEq, Eq, Hash)]
struct Provider {
    address: String,
    route: String,
    index: u32,
}
type IdleConnections = HashMap<(Provider, SocketAddr), (Instant, Sender)>;
const MAX_IP_CURSORS: usize = 256;
const MIN_IP_ATTEMPT: Duration = Duration::from_millis(400);

#[derive(Debug)]
struct ManagedUpstreamTimeout;

impl std::fmt::Display for ManagedUpstreamTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", io::Error::from(io::ErrorKind::TimedOut))
    }
}

impl std::error::Error for ManagedUpstreamTimeout {}

pub(crate) fn is_managed_upstream_timeout(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|source| source.is::<ManagedUpstreamTimeout>())
}

pub struct Doh {
    tls: tokio::sync::OnceCell<TlsConnector>,
    idle: Mutex<IdleConnections>,
    ip_cursors: Mutex<HashMap<Provider, usize>>,
    pub(super) fast: Option<Arc<fast_dns::Cache>>,
    host_cache: nfqws2_dns::Resolver,
    #[cfg(test)]
    bootstrap_fixture: tokio::sync::OnceCell<Vec<String>>,
}
impl Doh {
    pub fn new(fast: bool) -> Self {
        Self {
            tls: Default::default(),
            idle: Default::default(),
            ip_cursors: Default::default(),
            host_cache: nfqws2_dns::Resolver::new(256, 300, Duration::from_secs(4)),
            fast: fast.then(|| Arc::new(fast_dns::Cache::default())),
            #[cfg(test)]
            bootstrap_fixture: Default::default(),
        }
    }
    #[cfg(test)]
    pub(super) fn trust(&self, cert: CertificateDer<'static>) {
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        assert!(self.tls.set(tls_config(roots).unwrap()).is_ok());
    }
    #[cfg(test)]
    pub(super) fn clear_idle(&self) {
        self.idle.lock().unwrap().clear();
    }
    #[cfg(test)]
    pub(super) fn bootstrap_fixture(&self, urls: Vec<String>) {
        assert!(self.bootstrap_fixture.set(urls).is_ok());
    }
    async fn endpoint_addresses(
        &self,
        server: &Upstream,
        uri: &Uri,
        route: &Route,
        methods: &Policy,
    ) -> io::Result<Vec<SocketAddr>> {
        let host = uri.host().unwrap().trim_matches(['[', ']']);
        let port = uri.port_u16().unwrap_or(443);
        let at_port = |ip| SocketAddr::new(ip, port);
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![at_port(ip)]);
        }
        if !server.bootstrap_ips.is_empty() {
            return Ok(server.bootstrap_ips.iter().copied().map(at_port).collect());
        }
        if let Some(fast) = &self.fast {
            return Ok(fast
                .lookup(route, host)
                .await?
                .iter()
                .copied()
                .map(at_port)
                .collect());
        }
        Ok(self
            .cached_bootstrap(route, methods, host)
            .await?
            .into_iter()
            .map(at_port)
            .collect())
    }
    pub(super) fn refresh_failed(&self, server: &Upstream, route: &Route) {
        if let Some((cache, host)) = self.fast.as_ref().zip(fast_dns::provider_host(server)) {
            cache.refresh_soon(route, &host);
        }
    }
    async fn cached_bootstrap(
        &self,
        route: &Route,
        methods: &Policy,
        host: &str,
    ) -> io::Result<Vec<IpAddr>> {
        let query = nfqws2_dns::build_query(host, 1, nfqws2_dns::transaction_id()?)?;
        let scope = format!("{}@{}:{}", route.id, route.index, route.interface);
        let answer = self
            .host_cache
            .exchange_async(&query, &scope, || {
                self.bootstrap_reply(&query, route, methods)
            })
            .await?;
        Ok(nfqws2_dns::resolved_addresses(&answer.wire, 1)?
            .into_iter()
            .take(16)
            .collect())
    }
    pub(super) async fn bootstrap_addresses(
        &self,
        host: &str,
        route: &Route,
        methods: &Policy,
    ) -> io::Result<Vec<IpAddr>> {
        let query = nfqws2_dns::build_query(host, 1, nfqws2_dns::transaction_id()?)?;
        let reply = self.bootstrap_reply(&query, route, methods).await?;
        nfqws2_dns::resolved_addresses(&reply, 1)
    }
    async fn bootstrap_reply(
        &self,
        query: &[u8],
        route: &Route,
        methods: &Policy,
    ) -> io::Result<Vec<u8>> {
        let endpoints = ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"].into_iter();
        #[cfg(test)]
        let endpoints: Box<dyn Iterator<Item = &str> + Send> = match self.bootstrap_fixture.get() {
            Some(fixture) => Box::new(fixture.iter().map(String::as_str)),
            None => Box::new(endpoints),
        };
        for address in endpoints {
            let key = scheduler::key(&route.id, address);
            let Ok(mut lease) = methods.begin(&key) else {
                continue;
            };
            let resolver = Upstream {
                address: address.into(),
                bootstrap_ips: vec![],
            };
            // Both bootstrap endpoints carry a literal IP. This request never
            // reenters the hostname cache or uses the system DNS resolver.
            let deadline = TokioInstant::now() + Duration::from_secs(1);
            let attempt =
                Box::pin(self.exchange(&resolver, query, route, methods, deadline, false));
            tokio::select! {
                biased;
                _ = lease.canceled.changed() => continue,
                result = attempt => if let Ok(reply) = result {
                    if nfqws2_dns::resolved_addresses(&reply, 1).is_ok_and(|ips| !ips.is_empty()) {
                        return Ok(reply);
                    }
                }
            }
        }
        Err(io::Error::other(
            "независимый DoH на выбранном маршруте недоступен; укажите bootstrap IP",
        ))
    }
    pub(super) async fn connect_pinned(
        &self,
        host: &str,
        addresses: impl IntoIterator<Item = SocketAddr, IntoIter: Send> + Send,
        route: &Route,
    ) -> io::Result<Sender> {
        let tls = self
            .tls
            .get_or_try_init(|| async {
                tokio::task::spawn_blocking(load_tls)
                    .await
                    .map_err(io::Error::other)?
            })
            .await?;
        let name = ServerName::try_from(host.to_owned()).map_err(io::Error::other)?;
        let mut last = io::Error::other("у DoH-сервера нет доступных адресов");
        for addr in addresses {
            let socket = match super::network::tcp(addr, route.device()).await {
                Ok(s) => s,
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            let stream = match tls.connect(name.clone(), socket).await {
                Ok(s) => s,
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            if stream.get_ref().1.alpn_protocol() == Some(b"h2") {
                let (sender, conn) = http2::Builder::new(TokioExecutor::new())
                    .max_header_list_size(16 * 1024)
                    .handshake(TokioIo::new(stream))
                    .await
                    .map_err(io::Error::other)?;
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                return Ok(Sender::Http2(sender));
            }
            let (sender, conn) = http1::Builder::new()
                .max_buf_size(16 * 1024)
                .handshake(TokioIo::new(stream))
                .await
                .map_err(io::Error::other)?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            return Ok(Sender::Http1(sender));
        }
        Err(last)
    }
    pub async fn exchange(
        &self,
        server: &Upstream,
        wire: &[u8],
        route: &Route,
        methods: &Policy,
        deadline: TokioInstant,
        confirm_managed_timeout: bool,
    ) -> io::Result<Vec<u8>> {
        let uri: Uri = server.address.parse().map_err(io::Error::other)?;
        let addresses = timeout_at(
            deadline,
            self.endpoint_addresses(server, &uri, route, methods),
        )
        .await
        .map_err(|_| io::ErrorKind::TimedOut)??;
        let n = addresses.len();
        let provider = Provider {
            address: server.address.clone(),
            route: route.id.clone(),
            index: route.index,
        };
        let start = if n > 1 {
            self.ip_cursors
                .lock()
                .unwrap()
                .get(&provider)
                .copied()
                .unwrap_or(0)
                % n
        } else {
            0
        };
        let mut last = io::Error::other("у DoH-сервера нет доступных адресов");
        let mut all_http_timeouts = confirm_managed_timeout;
        for i in 0..n {
            let now = TokioInstant::now();
            if now >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let index = (start + i) % n;
            let remaining = (n - i) as u32;
            // A TCP/TLS stall or unsuccessful full reply leaves time for the other IPs.
            let ip_budget = ((deadline - now) / remaining).max(MIN_IP_ATTEMPT);
            let dispatch = confirm_managed_timeout.then(|| Arc::new(Dispatch::default()));
            let attempt = timeout_at(
                deadline.min(now + ip_budget),
                self.exchange_at(
                    &uri,
                    wire,
                    route,
                    (&provider, addresses[index]),
                    dispatch.as_ref(),
                ),
            )
            .await;
            all_http_timeouts &= attempt.is_err() && dispatch.is_some_and(|sent| sent.observed());
            if TokioInstant::now() >= deadline {
                return Err(if all_http_timeouts && i + 1 == n {
                    io::Error::new(io::ErrorKind::TimedOut, ManagedUpstreamTimeout)
                } else {
                    io::ErrorKind::TimedOut.into()
                });
            }
            match attempt {
                Ok(Ok(answer)) => {
                    if n > 1 {
                        self.prefer_ip(&provider, index);
                    }
                    return Ok(answer);
                }
                Ok(Err(e)) => last = e,
                Err(_) => last = io::ErrorKind::TimedOut.into(),
            }
            if n > 1 {
                self.prefer_ip(&provider, (index + 1) % n);
            }
        }
        Err(if all_http_timeouts && n > 0 {
            io::Error::new(io::ErrorKind::TimedOut, ManagedUpstreamTimeout)
        } else {
            last
        })
    }

    fn prefer_ip(&self, provider: &Provider, index: usize) {
        let mut cursors = self.ip_cursors.lock().unwrap();
        if let Some(cursor) = cursors.get_mut(provider) {
            *cursor = index;
        } else {
            if cursors.len() >= MAX_IP_CURSORS {
                let evicted = cursors.keys().next().unwrap().clone();
                cursors.remove(&evicted);
            }
            cursors.insert(provider.clone(), index);
        }
    }

    async fn exchange_at(
        &self,
        uri: &Uri,
        wire: &[u8],
        route: &Route,
        (provider, addr): (&Provider, SocketAddr),
        dispatch: Option<&Arc<Dispatch>>,
    ) -> io::Result<Vec<u8>> {
        let key = (provider.clone(), addr);
        let idle = {
            let mut pool = self.idle.lock().unwrap();
            let reusable = |at: &Instant, sender: &Sender| {
                at.elapsed() < Duration::from_secs(30) && !sender.is_closed()
            };
            match pool.get(&key) {
                Some((at, sender @ Sender::Http2(stream))) if reusable(at, sender) => {
                    Some((*at, Sender::Http2(stream.clone())))
                }
                _ => pool
                    .remove(&key)
                    .filter(|(at, sender)| reusable(at, sender)),
            }
        };
        // An upstream may silently close its keep-alive connection between requests.
        let reuse = idle.is_some();
        let mut sender = if let Some((_, sender)) = idle {
            sender
        } else {
            self.connect_pinned(uri.host().unwrap().trim_matches(['[', ']']), [addr], route)
                .await?
        };
        let send = || {
            Request::post(uri.clone())
                .header(header::HOST, uri.authority().unwrap().as_str())
                .header(header::CONTENT_TYPE, "application/dns-message")
                .header(header::ACCEPT, "application/dns-message")
                .body(Full::new(Bytes::copy_from_slice(wire)))
                .map_err(io::Error::other)
        };
        let response = match sender.send_with_dispatch(send()?, dispatch).await {
            Ok(r) => r,
            Err(_) if reuse => {
                // Failed reusable streams and their reconnects cannot prove
                // this address failed solely at the upstream reply deadline.
                if let Some(dispatch) = dispatch {
                    dispatch.discard();
                }
                sender = self
                    .connect_pinned(uri.host().unwrap().trim_matches(['[', ']']), [addr], route)
                    .await?;
                sender.send_request(send()?).await?
            }
            Err(e) => return Err(e),
        };
        if response.status() != axum::http::StatusCode::OK {
            return Err(io::Error::other(format!("DoH HTTP {}", response.status())));
        }
        if !response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(';')
                    .next()
                    .unwrap()
                    .trim()
                    .eq_ignore_ascii_case("application/dns-message")
            })
        {
            return Err(io::Error::other("неверный тип ответа DoH"));
        }
        let bytes = Limited::new(response.into_body(), 65535)
            .collect()
            .await
            .map_err(|e| io::Error::other(e.to_string()))?
            .to_bytes();
        nfqws2_dns::validate_answer(wire, &bytes)?;
        let mut idle = self.idle.lock().unwrap();
        idle.retain(|_, (t, s)| t.elapsed() < Duration::from_secs(30) && !s.is_closed());
        if idle.len() < 8 && !sender.is_closed() {
            idle.insert(key, (Instant::now(), sender));
        }
        Ok(bytes.to_vec())
    }
}
fn load_tls() -> io::Result<TlsConnector> {
    tls_config(nfqws2_tls_roots::load()?)
}
fn tls_config(roots: RootCertStore) -> io::Result<TlsConnector> {
    let mut cfg = ClientConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(io::Error::other)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsConnector::from(Arc::new(cfg)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn numeric_doh_authorities_win_over_bootstrap_for_both_ip_families() {
        let route = Route::system();
        let methods = Policy::new(Default::default());
        for fast in [false, true] {
            let transport = Doh::new(fast);
            for (host, expected) in [
                ("127.0.0.1", vec!["127.0.0.1:8443"]),
                ("[::1]", vec!["[::1]:8443"]),
                ("dns.test", vec!["127.0.0.2:8443", "[::2]:8443"]),
            ] {
                let upstream = Upstream {
                    address: format!("https://{host}:8443/custom-doh?mode=manual"),
                    bootstrap_ips: vec!["127.0.0.2".parse().unwrap(), "::2".parse().unwrap()],
                };
                let uri = upstream.address.parse().unwrap();
                let addresses = transport
                    .endpoint_addresses(&upstream, &uri, &route, &methods)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|addr| addr.to_string())
                    .collect::<Vec<_>>();
                assert_eq!(addresses, expected);
            }
        }
    }
}
