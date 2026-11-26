//! The same publisher, bundled mirror and hourly refresh as the Go service.
//! Reads the catalog only for an enabled CF profile without operator domains.
use bytes::Bytes;
use flate2::read::MultiGzDecoder;
use http::{header, Request, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioIo;
use nfqws2_tgws_config::{fallback::connect_named, valid_domain, Config};
use rand::seq::SliceRandom;
use std::{
    collections::{BTreeMap, HashSet},
    future::Future,
    io::{self, Read},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    net::TcpStream,
    task::JoinHandle,
    time::{interval, timeout, timeout_at, Instant, MissedTickBehavior},
};
use tokio_rustls::{rustls::pki_types::ServerName, TlsConnector};

const HOST: &str = "raw.githubusercontent.com";
const PATH: &str = "/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt";
// Matches the upstream revision embedded by the Go helper.
const USER_AGENT: &str = "n2s-tgws/1.11.2";
const PIN: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(185, 199, 109, 133)),
    443,
);
const LIMIT: usize = 64 << 10;
const GZIP_WIRE_LIMIT: usize = 2 * LIMIT;

pub(super) struct Catalog {
    current: Arc<Mutex<Published>>,
    task: Mutex<Option<JoinHandle<()>>>,
}
struct Published {
    domains: Vec<String>,
    preferred: BTreeMap<u16, String>,
}
impl Published {
    fn selected<'a>(&'a self, cfg: &'a Config) -> &'a [String] {
        if cfg.uses_upstream_catalog() {
            &self.domains
        } else {
            cfg.cfproxy_user_domains.as_deref().unwrap_or_default()
        }
    }
    fn replace(&mut self, next: Vec<String>) {
        if next.len() == self.domains.len() {
            let old: HashSet<_> = self.domains.iter().collect();
            if next.iter().all(|domain| old.contains(domain)) {
                return;
            }
        }
        self.domains = next;
        self.preferred.clear();
    }
}
impl Default for Catalog {
    fn default() -> Self {
        Self {
            current: Arc::new(Mutex::new(Published {
                domains: include_str!("catalog-defaults.txt")
                    .lines()
                    .map(str::to_owned)
                    .collect(),
                preferred: Default::default(),
            })),
            task: Default::default(),
        }
    }
}
impl Catalog {
    #[cfg(test)]
    pub fn fixture(&self, body: &[u8]) {
        self.current.lock().unwrap().replace(parse(body).unwrap());
    }
    pub fn ordered(&self, dc: u16, cfg: &Config) -> Vec<String> {
        let mut state = self.current.lock().unwrap();
        let mut result = state.selected(cfg).to_vec();
        result.shuffle(&mut rand::rng());
        if let Some(first) = result.first() {
            let preferred = state.preferred.entry(dc).or_insert_with(|| first.clone());
            if let Some(i) = result.iter().position(|s| s == preferred) {
                result.swap(0, i);
            }
        }
        result
    }
    pub fn contains(&self, domain: &str, cfg: &Config) -> bool {
        self.current
            .lock()
            .unwrap()
            .selected(cfg)
            .iter()
            .any(|name| name == domain)
    }
    pub fn promote(&self, dc: u16, base: String, cfg: &Config) {
        let mut state = self.current.lock().unwrap();
        if state.selected(cfg).contains(&base) {
            state.preferred.insert(dc, base);
        }
    }
    pub fn start(&self, tls: TlsConnector, report_failure: impl Fn() + Send + Sync + 'static) {
        let mut slot = self.task.lock().unwrap();
        if slot.is_some() {
            return;
        }
        let current = self.current.clone();
        *slot = Some(tokio::spawn(async move {
            let mut ticks = interval(Duration::from_secs(3600));
            ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                ticks.tick().await;
                refresh_once(
                    &current,
                    |peer, deadline| {
                        let tls = &tls;
                        async move {
                            let socket = match peer {
                                Some(addr) => {
                                    timeout(Duration::from_secs(5), TcpStream::connect(addr))
                                        .await
                                        .map_err(|_| io::ErrorKind::TimedOut)??
                                }
                                None => connect_named(HOST, 443, deadline).await?,
                            };
                            fetch(socket, HOST, tls).await
                        }
                    },
                    &report_failure,
                )
                .await;
            }
        }));
    }
    pub async fn stop(&self) {
        let task = self.task.lock().unwrap().take();
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
    }
}

async fn refresh_once<F: Future<Output = io::Result<Vec<String>>>>(
    current: &Mutex<Published>,
    mut request: impl FnMut(Option<SocketAddr>, Instant) -> F,
    report_failure: impl FnOnce(),
) {
    for peer in [Some(PIN), None] {
        let deadline = Instant::now() + Duration::from_secs(10);
        if let Ok(Ok(domains)) = timeout_at(deadline, request(peer, deadline)).await {
            current.lock().unwrap().replace(domains);
            return;
        }
    }
    report_failure();
}

// The publisher's legacy wire format shifts ASCII letters and maps the .com
// suffix to .co.uk. Other suffixes are published literally.
fn parse(body: &[u8]) -> io::Result<Vec<String>> {
    if body.len() > LIMIT {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut seen = HashSet::new();
    let mut domains = Vec::new();
    for line in std::str::from_utf8(body)
        .map_err(io::Error::other)?
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        if !line.is_ascii() {
            continue;
        }
        let domain = if let Some(label) = line.strip_suffix(".com") {
            let shift = (label.bytes().filter(u8::is_ascii_alphabetic).count() % 26) as u8;
            let mut s: String = label
                .bytes()
                .map(|v| {
                    let b = v.to_ascii_lowercase();
                    if b.is_ascii_lowercase() {
                        char::from(b'a' + (b - b'a' + 26 - shift) % 26)
                    } else {
                        char::from(b)
                    }
                })
                .collect();
            s.push_str(".co.uk");
            s
        } else {
            line.to_ascii_lowercase()
        };
        if valid_domain(&domain) && seen.insert(domain.clone()) {
            domains.push(domain);
        }
    }
    if domains.len() < 3 {
        Err(io::Error::other("CF relay catalog is incomplete"))
    } else {
        Ok(domains)
    }
}
async fn fetch(socket: TcpStream, host: &str, tls: &TlsConnector) -> io::Result<Vec<String>> {
    let name = ServerName::try_from(host.to_owned()).map_err(io::Error::other)?;
    let stream = tls.connect(name, socket).await?;
    let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
        .max_buf_size(16 << 10)
        .handshake(TokioIo::new(stream))
        .await
        .map_err(io::Error::other)?;
    let request = async {
        let req = Request::get(PATH)
            .header(header::HOST, host)
            .header(header::USER_AGENT, USER_AGENT)
            .header(header::CACHE_CONTROL, "no-cache")
            .header(header::ACCEPT, "text/plain")
            .header(header::ACCEPT_ENCODING, "gzip")
            .header(header::CONNECTION, "close")
            .body(Empty::<Bytes>::new())
            .map_err(io::Error::other)?;
        let mut response = sender.send_request(req).await.map_err(io::Error::other)?;
        let h = response.headers();
        let gzip = match h.get(header::CONTENT_ENCODING) {
            Some(v) if v.as_bytes().eq_ignore_ascii_case(b"gzip") => true,
            Some(v) if !v.as_bytes().eq_ignore_ascii_case(b"identity") => {
                return Err(io::Error::other("unsupported CF relay catalog encoding"));
            }
            _ => false,
        };
        let wire_limit = if gzip { GZIP_WIRE_LIMIT } else { LIMIT };
        if response.status() != StatusCode::OK
            || h.get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| {
                    v.split(';')
                        .next()
                        .is_some_and(|v| v.trim().eq_ignore_ascii_case("text/html"))
                })
            || h.get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()?.parse::<usize>().ok())
                .is_some_and(|n| n > wire_limit)
        {
            return Err(io::Error::other("invalid CF relay catalog response"));
        }
        let mut body = Vec::new();
        while let Some(frame) = response.body_mut().frame().await {
            if let Ok(data) = frame.map_err(io::Error::other)?.into_data() {
                if data.len() > wire_limit - body.len() {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                body.extend_from_slice(&data);
            }
        }
        if gzip {
            let mut decoded = Vec::new();
            MultiGzDecoder::new(body.as_slice())
                .take(LIMIT as u64 + 1)
                .read_to_end(&mut decoded)?;
            return parse(&decoded);
        }
        parse(&body)
    };
    tokio::pin!(request);
    tokio::select! {biased;result=&mut request=>result,result=connection=>{
        result.map_err(io::Error::other)?;request.await
    }}
}
#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn refresh_reports_once_after_both_routes_fail_and_keeps_the_pool() {
        use std::{cell::Cell, future::ready};
        let catalog = Catalog::default();
        let previous = catalog.current.lock().unwrap().domains.clone();
        let mut attempts = Vec::new();
        let failures = Cell::new(0);
        let report = || failures.set(failures.get() + 1);
        refresh_once(
            &catalog.current,
            |peer, _| {
                attempts.push(peer);
                ready(Err(io::ErrorKind::PermissionDenied.into()))
            },
            report,
        )
        .await;
        assert_eq!(attempts, [Some(PIN), None]);
        assert_eq!(failures.get(), 1);
        assert_eq!(catalog.current.lock().unwrap().domains, previous);

        attempts.clear();
        refresh_once(
            &catalog.current,
            |peer, _| {
                attempts.push(peer);
                ready(if peer.is_some() {
                    Err(io::ErrorKind::PermissionDenied.into())
                } else {
                    parse(b"a.test\nb.test\nc.test")
                })
            },
            report,
        )
        .await;
        assert_eq!(attempts, [Some(PIN), None]);
        assert_eq!(failures.get(), 1);
        assert_eq!(
            catalog.current.lock().unwrap().domains,
            ["a.test", "b.test", "c.test"]
        );

        attempts.clear();
        refresh_once(
            &catalog.current,
            |peer, _| {
                attempts.push(peer);
                ready(parse(b"c.test\nd.test\ne.test"))
            },
            report,
        )
        .await;
        assert_eq!(attempts, [Some(PIN)]);
        assert_eq!(failures.get(), 1);
        assert_eq!(
            catalog.current.lock().unwrap().domains,
            ["c.test", "d.test", "e.test"]
        );
    }

    #[tokio::test]
    async fn cancelled_refresh_emits_no_pool_failure() {
        let catalog = Catalog::default();
        let current = catalog.current.clone();
        let (started, wait) = tokio::sync::oneshot::channel();
        let (report, result) = std::sync::mpsc::channel();
        let task = tokio::spawn(async move {
            let mut started = Some(started);
            refresh_once(
                &current,
                |peer, _| {
                    assert_eq!(peer, Some(PIN));
                    started.take().unwrap().send(()).unwrap();
                    std::future::pending()
                },
                || report.send(()).unwrap(),
            )
            .await;
        });
        wait.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(
            result.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Disconnected)
        );
    }
    #[test]
    fn retain_dc_choices_on_shuffle_and_drop_old_choices_when_the_publisher_changes_membership() {
        let catalog = Catalog::default();
        let cfg = Config::default();
        catalog.fixture(b"a.test\nb.test\nc.test");
        let first = catalog.ordered(2, &cfg).remove(0);
        assert_eq!(catalog.ordered(2, &cfg)[0], first);
        catalog.promote(2, "c.test".into(), &cfg);
        catalog.fixture(b"c.test\nb.test\na.test");
        assert_eq!(catalog.ordered(2, &cfg)[0], "c.test");
        catalog.fixture(b"a.test\nb.test\nd.test");
        assert!(catalog.current.lock().unwrap().preferred.is_empty());
        catalog.promote(2, "c.test".into(), &cfg);
        assert!(catalog.current.lock().unwrap().preferred.is_empty());
    }
    #[test]
    fn default_snapshot_and_publisher_format_follow_go() {
        let catalog = Catalog::default();
        let cfg = Config::default();
        let defaults = catalog.current.lock().unwrap().domains.clone();
        assert_eq!(defaults.len(), 20);
        assert!(defaults.iter().all(|d| valid_domain(d)));
        let entries =
            parse(b" # comment\nvirkgj.com\n  alpha.test\nALPHA.test\nbeta.test\nnot a domain")
                .unwrap();
        assert_eq!(entries[0], defaults[0]);
        assert_eq!(&entries[1..], ["alpha.test", "beta.test"]);
        assert!(parse(b"a.test\nb.test\na.test").is_err());
        assert!(parse(&vec![b'a'; LIMIT + 1]).is_err());
        let config = Config {
            cfproxy_user_domains: Some(vec!["home.example".into()]),
            ..cfg
        };
        assert_eq!(catalog.ordered(2, &config), ["home.example"]);
        assert!(!config.uses_upstream_catalog());
    }
    #[tokio::test]
    async fn only_verified_complete_http_success_can_replace_the_snapshot() {
        for (name, status, declared, ok) in [
            ("publisher.test", 200, 20, true),
            ("wrong.test", 200, 20, false),
            ("publisher.test", 302, 20, false),
            ("publisher.test", 200, 32, false),
            ("publisher.test", 200, LIMIT + 1, false),
        ] {
            let body = b"a.test\nb.test\nc.test".to_vec();
            let r = local_catalog(name, status, "identity", declared, body).await;
            assert_eq!(r.is_ok(), ok);
        }
    }

    fn gzip(body: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(body).unwrap();
        encoder.finish().unwrap()
    }

    #[tokio::test]
    async fn publisher_gzip_requires_a_complete_stream_within_both_size_limits() {
        let valid = b"a.test\nb.test\nc.test\n";
        let compressed = gzip(valid);
        let mut expanded = valid.to_vec();
        expanded.push(b'#');
        expanded.resize(LIMIT + 1, b'x');
        let expanding = gzip(&expanded);
        let expanding_len = expanding.len();
        for (body, declared, ok) in [
            (compressed.clone(), compressed.len(), true),
            (
                compressed[..compressed.len() - 1].to_vec(),
                compressed.len() - 1,
                false,
            ),
            (compressed.clone(), GZIP_WIRE_LIMIT + 1, false),
            (expanding, expanding_len, false),
        ] {
            let result = local_catalog("publisher.test", 200, "gzip", declared, body).await;
            if ok {
                assert_eq!(result.unwrap(), ["a.test", "b.test", "c.test"]);
            } else {
                assert!(result.is_err());
            }
        }
    }

    async fn local_catalog(
        name: &str,
        status: u16,
        encoding: &'static str,
        declared: usize,
        body: Vec<u8>,
    ) -> io::Result<Vec<String>> {
        let (roots, cert) = crate::configured::tests::origin(vec!["publisher.test".into()]);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = listener.local_addr().unwrap();
        let handler = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let Ok(tls) = tokio_rustls::TlsAcceptor::from(Arc::new(cert))
                .accept(stream)
                .await
            else {
                return false;
            };
            let mut stream = BufReader::new(tls);
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            assert_eq!(line, format!("GET {PATH} HTTP/1.1\r\n"));
            let mut headers = Vec::new();
            loop {
                line.clear();
                stream.read_line(&mut line).await.unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                headers.push(line.trim_end().to_owned());
            }
            assert!(headers.contains(&format!("user-agent: {USER_AGENT}")));
            assert!(headers.iter().any(|h| h == "accept-encoding: gzip"));
            let response = format!(
                "HTTP/1.1 {status} Test\r\nContent-Type: text/plain\r\nContent-Encoding: {encoding}\r\nContent-Length: {declared}\r\nConnection: close\r\n\r\n"
            );
            let stream = stream.get_mut();
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.write_all(&body).await;
            let _ = stream.shutdown().await;
            true
        });
        let tls = crate::relay::tls_config(roots).unwrap();
        let result = timeout(
            Duration::from_secs(2),
            fetch(TcpStream::connect(peer).await.unwrap(), name, &tls),
        )
        .await
        .unwrap();
        assert_eq!(handler.await.unwrap(), name == "publisher.test");
        result
    }
}
