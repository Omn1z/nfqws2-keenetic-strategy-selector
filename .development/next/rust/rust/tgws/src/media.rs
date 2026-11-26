//! An HTTP/2 origin is shared by sessions for one operator-specified hostname.
//! /api accepts the end-to-end MTProto message, not the obfuscated WS header.
use crate::{diagnostics::H2Terminal, Stats};
use bytes::Bytes;
use h2::client::SendRequest;
use http::{header::USER_AGENT, Method, Request};
use std::{
    collections::BTreeMap,
    future::Future,
    io,
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    net::TcpStream,
    sync::{Mutex, OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::{timeout_at, Instant},
};
use tokio_rustls::{rustls::pki_types::ServerName, TlsConnector};
mod framing;
mod session;
#[cfg(test)]
mod tests;
pub(super) use session::bridge;
const MAX: usize = 4 << 20;
const PARTIAL_UPLOAD_BYTES: usize = MAX + 256;
const REQUEST_TIME: Duration = Duration::from_secs(65);
const SETUP_TIME: Duration = Duration::from_secs(8);
const COOLDOWN: Duration = Duration::from_secs(30);
const USER_AGENT_VALUE: &str = "Go-http-client/2.0";
#[derive(Debug)]
enum Failure {
    Network(io::Error),
    Transport(H2Terminal),
    ReplyBufferFull,
}
impl From<io::Error> for Failure {
    fn from(e: io::Error) -> Self {
        Self::Network(e)
    }
}
impl From<h2::Error> for Failure {
    fn from(e: h2::Error) -> Self {
        Self::Network(io::Error::other(e))
    }
}

#[derive(Default)]
pub(super) struct Origins {
    hosts: Mutex<BTreeMap<String, Arc<Mutex<Origin>>>>,
    setup_retry: std::sync::Mutex<BTreeMap<u16, Instant>>,
    shared_budget: Option<Arc<Budget>>,
    legacy: bool,
}
struct Budget {
    requests: Arc<Semaphore>,
    upload: Arc<Semaphore>,
    download: Arc<Semaphore>,
    retirement: session::Retirement,
    partial_uploads: Option<Semaphore>,
}
impl Default for Budget {
    fn default() -> Self {
        Self {
            requests: Arc::new(Semaphore::new(64)),
            upload: Arc::new(Semaphore::new(32 << 20)),
            download: Arc::new(Semaphore::new(32 << 20)),
            retirement: Default::default(),
            partial_uploads: Some(Semaphore::new(PARTIAL_UPLOAD_BYTES)),
        }
    }
}
struct Origin {
    lane: Option<Arc<Lane>>,
    retry: Option<Instant>,
    budget: Arc<Budget>,
}
impl Origins {
    pub fn for_profile(legacy: bool) -> Self {
        Self {
            legacy,
            shared_budget: (!legacy).then(|| {
                Arc::new(Budget {
                    partial_uploads: None,
                    ..Budget::default()
                })
            }),
            ..Self::default()
        }
    }
    pub async fn setup<T, F: Future<Output = Option<T>>>(
        &self,
        dc: u16,
        stats: &Stats,
        candidates: impl FnOnce(Instant, Arc<AtomicBool>) -> F,
    ) -> Option<T> {
        if self
            .setup_retry
            .lock()
            .unwrap()
            .get(&dc)
            .is_some_and(|until| Instant::now() < *until)
        {
            return None;
        }
        let deadline = Instant::now() + SETUP_TIME;
        let opening = Arc::new(AtomicBool::new(false));
        match timeout_at(deadline, candidates(deadline, opening.clone())).await {
            Ok(result) => result,
            Err(_) => {
                if opening.load(Ordering::Relaxed) {
                    stats.h2_errors.fetch_add(1, Ordering::Relaxed);
                }
                self.setup_retry
                    .lock()
                    .unwrap()
                    .insert(dc, Instant::now() + COOLDOWN);
                None
            }
        }
    }
    pub async fn get(
        &self,
        host: &str,
        tls: &TlsConnector,
        handshakes: &crate::handshakes::Handshakes,
        connect: impl Future<Output = io::Result<TcpStream>>,
        stats: &Stats,
    ) -> io::Result<Arc<Lane>> {
        let slot = self
            .hosts
            .lock()
            .await
            .entry(host.into())
            .or_insert_with(|| {
                Arc::new(Mutex::new(Origin {
                    lane: None,
                    retry: None,
                    budget: self.shared_budget.clone().unwrap_or_default(),
                }))
            })
            .clone();
        let mut origin = slot.lock().await;
        if let Some(l) = origin.lane.as_ref() {
            if l.cooldown
                .lock()
                .unwrap()
                .is_some_and(|t| t > Instant::now())
            {
                return Err(io::ErrorKind::ConnectionRefused.into());
            }
            if !l.driver.is_finished() && !(Arc::strong_count(l) == 1 && l.stale()) {
                return Ok(l.clone());
            }
        }
        origin.lane.take();
        if origin.retry.is_some_and(|t| t > Instant::now()) {
            return Err(io::ErrorKind::ConnectionRefused.into());
        }
        let permit = handshakes.acquire().await?;
        // A cancellation at the shared DC deadline does not penalize this origin.
        let lane = async {
            let stream = connect_h2(host, tls, connect, self.legacy).await?;
            drop(permit);
            stats.h2_tcp.fetch_add(1, Ordering::Relaxed);
            Lane::open(host, stream, origin.budget.clone()).await
        }
        .await
        .inspect_err(|_| {
            origin.retry = Some(Instant::now() + COOLDOWN);
            stats.h2_errors.fetch_add(1, Ordering::Relaxed);
        })?;
        origin.retry = None;
        let lane = Arc::new(lane);
        origin.lane = Some(lane.clone());
        Ok(lane)
    }
    pub async fn stop(&self) {
        self.hosts.lock().await.clear();
        self.setup_retry.lock().unwrap().clear();
    }
    pub async fn prune(&self, current: impl Fn(&str) -> bool) {
        self.hosts.lock().await.retain(|name, host| {
            Arc::strong_count(host) > 1
                || host.try_lock().map_or(true, |origin| {
                    // A prior socket generation can still be delivering a
                    // buffered reply while this origin is being reconnected.
                    let retained_by_old_lane = self.shared_budget.is_none()
                        && Arc::strong_count(&origin.budget)
                            > 1 + usize::from(origin.lane.is_some());
                    origin.lane.as_ref().is_some_and(|lane| {
                        Arc::strong_count(lane) > 1
                            || name.split_once('.').is_some_and(|(_, base)| current(base))
                                && ((!lane.driver.is_finished() && !lane.stale())
                                    || lane
                                        .cooldown
                                        .lock()
                                        .unwrap()
                                        .is_some_and(|t| t > Instant::now()))
                    }) || origin.retry.is_some_and(|t| t > Instant::now())
                        || retained_by_old_lane
                })
        });
    }
}
pub(super) struct Lane {
    endpoint: http::Uri,
    sender: SendRequest<Bytes>,
    driver: JoinHandle<()>,
    budget: Arc<Budget>,
    last_stream_end: std::sync::Mutex<Instant>,
    cooldown: std::sync::Mutex<Option<Instant>>,
}
impl Drop for Lane {
    fn drop(&mut self) {
        self.driver.abort();
    }
}
struct StreamActivity<'a>(&'a std::sync::Mutex<Instant>);
impl Drop for StreamActivity<'_> {
    fn drop(&mut self) {
        *self.0.lock().unwrap() = Instant::now();
    }
}
async fn connect_h2(
    host: &str,
    tls: &TlsConnector,
    connect: impl Future<Output = io::Result<TcpStream>>,
    legacy: bool,
) -> io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let mut config = tls.config().as_ref().clone();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));
    let name = ServerName::try_from(host.to_owned()).map_err(io::Error::other)?;
    let socket = connect.await?;
    socket.set_nodelay(true)?;
    if legacy {
        nfqws2_tgws_transport::configure_tcp_fallback(&socket);
    }
    let tls = connector.connect(name, socket).await?;
    if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
        return Err(io::Error::other("relay did not negotiate HTTP/2"));
    }
    Ok(tls)
}
impl Lane {
    fn stale(&self) -> bool {
        self.last_stream_end.lock().unwrap().elapsed() >= Duration::from_secs(90)
    }
    async fn open(
        host: &str,
        tls: tokio_rustls::client::TlsStream<TcpStream>,
        budget: Arc<Budget>,
    ) -> io::Result<Self> {
        let mut settings = h2::client::Builder::new();
        settings
            .initial_window_size(256 << 10)
            .initial_connection_window_size((4 << 20) - 1)
            .max_header_list_size(64 << 10)
            .max_frame_size(16 << 10)
            .max_send_buffer_size(256 << 10)
            .enable_push(false);
        let (sender, connection) = settings.handshake(tls).await.map_err(io::Error::other)?;
        let endpoint = format!("https://{host}/api")
            .parse()
            .map_err(io::Error::other)?;
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let lane = Self {
            sender,
            endpoint,
            driver,
            budget,
            last_stream_end: std::sync::Mutex::new(Instant::now()),
            cooldown: Default::default(),
        };
        let mut send = lane
            .sender
            .clone()
            .ready()
            .await
            .map_err(io::Error::other)?;
        let head = Request::builder()
            .method(Method::HEAD)
            .uri(&lane.endpoint)
            .header(USER_AGENT, USER_AGENT_VALUE)
            .body(())
            .map_err(io::Error::other)?;
        let (response, _) = send.send_request(head, true).map_err(io::Error::other)?;
        let code = response.await.map_err(io::Error::other)?.status();
        if !(code.is_success() || matches!(code.as_u16(), 405 | 501)) {
            return Err(io::Error::other(
                "configured relay refused HTTP/2 preflight",
            ));
        }
        *lane.last_stream_end.lock().unwrap() = Instant::now();
        Ok(lane)
    }
    async fn post(
        &self,
        body: Bytes,
        state: &AtomicU8,
        channel: &Arc<Semaphore>,
    ) -> Result<Reply, Failure> {
        let mut sender = self.sender.clone().ready().await?;
        let req = Request::builder()
            .method(Method::POST)
            .uri(&self.endpoint)
            .header(USER_AGENT, USER_AGENT_VALUE)
            .header("content-type", "application/octet-stream")
            .header("accept-encoding", "identity")
            .header("content-length", body.len())
            .body(())
            .map_err(io::Error::other)?;
        let (resp, mut stream) = sender.send_request(req, false)?;
        let _activity = StreamActivity(&self.last_stream_end);
        stream.send_data(body, true)?;
        state.store(1, Ordering::Release);
        let res = resp.await?;
        state.store(2, Ordering::Release);
        let code = res.status().as_u16();
        if matches!(code, 403 | 404 | 429 | 444) {
            return Err(Failure::Transport(H2Terminal::Http(code)));
        }
        if code != 200 {
            return Err(io::Error::other("unexpected HTTP/2 status").into());
        }
        if res.headers().get("content-type").is_some_and(|v| {
            v.to_str()
                .map_or(true, |s| s.to_ascii_lowercase().contains("text/html"))
        }) || res.headers().get("content-encoding").is_some_and(|v| {
            v.to_str().map_or(true, |s| {
                !s.is_empty() && !s.eq_ignore_ascii_case("identity")
            })
        }) {
            return Err(
                io::Error::other("relay did not return an unencoded MTProto response").into(),
            );
        }
        let length = res
            .headers()
            .get("content-length")
            .map(|v| {
                v.to_str()
                    .ok()
                    .and_then(|v| v.parse::<usize>().ok())
                    .ok_or_else(|| io::Error::other("invalid response size"))
            })
            .transpose()?;
        if length.is_some_and(|n| n > MAX) {
            return Err(io::Error::other("HTTP/2 reply exceeds limit").into());
        }
        let mut stream = res.into_body();
        let mut reply = Reply::default();
        while let Some(chunk) = stream.data().await {
            let chunk = chunk?;
            if reply.data.len().saturating_add(chunk.len()) > MAX {
                return Err(io::Error::other("HTTP/2 reply exceeds limit").into());
            }
            if !chunk.is_empty() {
                for (total, budget) in [
                    (&mut reply.lane, &self.budget.download),
                    (&mut reply.channel, channel),
                ] {
                    let reservation = budget
                        .clone()
                        .try_acquire_many_owned(chunk.len() as u32)
                        .map_err(|_| Failure::ReplyBufferFull)?;
                    if let Some(held) = total {
                        held.merge(reservation);
                    } else {
                        *total = Some(reservation);
                    }
                }
                reply.data.extend_from_slice(&chunk);
                stream.flow_control().release_capacity(chunk.len())?;
            }
        }
        if length.is_some_and(|n| n != reply.data.len()) || reply.data.len() % 4 != 0 {
            return Err(io::Error::other("invalid HTTP/2 response length").into());
        }
        if let Ok(v) = <&[u8; 4]>::try_from(reply.data.as_slice()) {
            let code = i32::from_le_bytes(*v);
            if code < 0 {
                return Err(Failure::Transport(H2Terminal::Payload(code)));
            }
        }
        Ok(reply)
    }
}
#[derive(Default)]
struct Reply {
    data: Vec<u8>,
    lane: Option<OwnedSemaphorePermit>,
    channel: Option<OwnedSemaphorePermit>,
}
