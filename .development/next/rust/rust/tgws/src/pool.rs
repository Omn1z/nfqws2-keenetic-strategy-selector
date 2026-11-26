use crate::diagnostics::Event;
use crate::{relay, Stats};
use futures_util::{SinkExt, StreamExt};
use nfqws2_tgws_config::fallback::Telegram;
use nfqws2_tgws_transport::active::Wire;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::SyncSender,
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufRead, AsyncWrite},
    net::TcpStream,
    sync::{oneshot, Notify, Semaphore},
    task::JoinHandle,
    time::{sleep, sleep_until, timeout, Instant},
};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::{tungstenite::Message, WebSocketStream};

const LEGACY_IDLE_PROBE: Duration = Duration::from_millis(2);

/// The peer, TLS name and HTTP path of a successful direct upgrade.
#[derive(Clone, Eq, PartialEq)]
pub(super) struct Endpoint {
    pub peer: Peer,
    pub managed: bool,
    pub host: String,
    pub path: &'static str,
}

#[derive(Clone, Eq, PartialEq)]
pub(super) enum Peer {
    Direct(SocketAddr),
    Vpn {
        target: Telegram,
        iface: String,
        broker: PathBuf,
    },
}

impl Peer {
    async fn connect(&self) -> std::io::Result<TcpStream> {
        match self {
            Self::Direct(address) => TcpStream::connect(*address).await,
            Self::Vpn {
                target,
                iface,
                broker,
            } => {
                if relay::vpn_iface(broker).await?.as_ref() != Some(iface) {
                    return Err(std::io::ErrorKind::NotConnected.into());
                }
                target.connect(iface).await
            }
        }
    }
}

struct Slot {
    dc: i16,
    endpoint: Endpoint,
    ready: Arc<AtomicBool>,
    checkout: Option<oneshot::Sender<()>>,
    task: JoinHandle<Option<relay::Ws>>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Route {
    endpoint: Endpoint,
    refill: Option<Arc<Mutex<Refill>>>,
}

#[derive(Default)]
struct Refill {
    pending: usize,
    failures: u8,
    retry_at: Option<Instant>,
    connected: bool,
    failure: Option<std::io::ErrorKind>,
    cancelled: bool,
    wake: Option<Arc<Notify>>,
}

#[derive(Debug, PartialEq, Eq)]
enum RefillDiagnostic {
    NetworkFailure(u64),
    SetupCapacity,
}

impl Refill {
    fn begin(&mut self, pending: usize, now: Instant) -> bool {
        if self.pending > 0 || self.retry_at.is_some_and(|until| until > now) {
            return false;
        }
        self.pending = pending;
        self.retry_at = None;
        self.connected = false;
        self.failure = None;
        self.cancelled = false;
        true
    }

    fn complete(
        &mut self,
        outcome: Option<Result<(), std::io::ErrorKind>>,
        now: Instant,
    ) -> Option<RefillDiagnostic> {
        match outcome {
            Some(Ok(())) => self.connected = true,
            Some(Err(e)) if self.failure.is_none() || e != std::io::ErrorKind::WouldBlock => {
                self.failure = Some(e);
            }
            None => self.cancelled = true,
            _ => {}
        }
        self.pending -= 1;
        if self.pending > 0 {
            return None;
        }
        if self.connected {
            self.failures = 0;
            self.retry_at = None;
        } else if let Some(error) = self.failure {
            // A local queue timeout lets the bucket try again after one
            // second. Network failures increase the bucket's backoff once.
            let (delay, diagnostic) = if error == std::io::ErrorKind::WouldBlock {
                (1, RefillDiagnostic::SetupCapacity)
            } else {
                let delay = (1u64 << self.failures).min(3600);
                self.failures = (self.failures + 1).min(12);
                (delay, RefillDiagnostic::NetworkFailure(delay))
            };
            self.retry_at = Some(now + Duration::from_secs(delay));
            if let Some(wake) = &self.wake {
                wake.notify_one();
            }
            return (!self.cancelled).then_some(diagnostic);
        }
        None
    }
}

struct Attempt {
    refill: Option<Arc<Mutex<Refill>>>,
    pending: bool,
    diagnostics: Option<SyncSender<Event>>,
    dc: i16,
}

impl Attempt {
    fn new(
        refill: Option<Arc<Mutex<Refill>>>,
        diagnostics: Option<SyncSender<Event>>,
        dc: i16,
    ) -> Self {
        Self {
            pending: refill.is_some(),
            refill,
            diagnostics,
            dc,
        }
    }

    fn complete(&mut self, outcome: Option<Result<(), std::io::ErrorKind>>) {
        if let Some(refill) = self.refill.as_ref().filter(|_| self.pending) {
            let diagnostic = refill.lock().unwrap().complete(outcome, Instant::now());
            if let Some((send, diagnostic)) = self.diagnostics.as_ref().zip(diagnostic) {
                let event = match diagnostic {
                    RefillDiagnostic::NetworkFailure(seconds) => Event::Refill {
                        dc: self.dc,
                        seconds,
                    },
                    RefillDiagnostic::SetupCapacity => Event::RefillCapacity { dc: self.dc },
                };
                let _ = send.try_send(event);
            }
        }
        self.pending = false;
    }

    fn requeue(&mut self) -> bool {
        // Replace a dead idle socket promptly when the route has capacity.
        // If a round is still running, scheduled maintenance fills the gap.
        self.pending = self
            .refill
            .as_ref()
            .is_some_and(|refill| refill.lock().unwrap().begin(1, Instant::now()));
        self.pending
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        self.complete(None);
    }
}

struct SlotWait {
    ready: Arc<AtomicBool>,
    checkout: oneshot::Receiver<()>,
}

pub(super) struct Pool {
    limit: usize,
    slots: Mutex<Vec<Slot>>,
    dials: Arc<Semaphore>,
    pub direct: crate::direct::Direct,
    legacy_buffer: Option<i64>,
    routes: Mutex<BTreeMap<i16, Route>>,
    refill_wake: Arc<Notify>,
    capacity: usize,
    pub legacy_tcp: crate::legacy::Backoff,
    pub relays: crate::configured::Relays,
    pub https_origin: crate::inbound::Origin,
    diagnostics: Option<SyncSender<Event>>,
    planned_stop: AtomicBool,
}

impl Pool {
    #[cfg(test)]
    pub fn new(limit: usize, tls: TlsConnector, buffer_size: i64) -> Self {
        Self::with_handshakes(limit, tls, buffer_size, false, Default::default())
    }
    pub fn with_handshakes(
        limit: usize,
        tls: TlsConnector,
        buffer_size: i64,
        legacy: bool,
        handshakes: crate::handshakes::Handshakes,
    ) -> Self {
        Self {
            relays: crate::configured::Relays::new(tls.clone(), handshakes.clone(), legacy),
            limit,
            slots: Mutex::new(Vec::new()),
            dials: Arc::new(Semaphore::new(if legacy { 4 } else { 2 })),
            direct: crate::direct::Direct::new(tls, handshakes, legacy),
            legacy_buffer: legacy.then_some(buffer_size),
            routes: Mutex::default(),
            refill_wake: Arc::default(),
            capacity: capacity(buffer_size),
            legacy_tcp: Default::default(),
            https_origin: Default::default(),
            diagnostics: None,
            planned_stop: AtomicBool::new(false),
        }
    }
    pub(super) fn enable_diagnostics(&mut self) {
        self.diagnostics = crate::diagnostics::start();
    }
    pub(super) fn report_diagnostic(&self, event: Event) {
        if let Some(send) = &self.diagnostics {
            let _ = send.try_send(event);
        }
    }
    pub(super) fn mark_planned_stop(&self) {
        self.planned_stop.store(true, Ordering::Relaxed);
    }
    pub(super) fn is_planned_stop(&self) -> bool {
        self.planned_stop.load(Ordering::Relaxed)
    }
    pub(super) async fn drain_diagnostics(&self) {
        if let Some(send) = &self.diagnostics {
            crate::diagnostics::drain(send).await;
        }
    }
    #[cfg(test)]
    pub(super) fn capture_diagnostics(&mut self) -> std::sync::mpsc::Receiver<Event> {
        let (send, receive) = std::sync::mpsc::sync_channel(8);
        self.diagnostics = Some(send);
        receive
    }
    #[cfg(test)]
    pub fn legacy(limit: usize, tls: TlsConnector, buffer_size: i64) -> Self {
        Self::with_handshakes(limit, tls, buffer_size, true, Default::default())
    }

    pub async fn take(&self, dc: i16, stats: &Stats) -> Option<(relay::Ws, Endpoint)> {
        self.take_matching(dc, None, stats).await
    }

    pub async fn take_route(
        &self,
        dc: i16,
        endpoint: Endpoint,
        stats: &Stats,
    ) -> Option<relay::Ws> {
        let cached = self.take_matching(dc, Some(&endpoint), stats).await;
        self.warm(dc, endpoint);
        cached.map(|(ws, _)| ws)
    }

    pub fn forget_vpn(&self, dc: i16) {
        let mut routes = self.routes.lock().unwrap();
        routes.retain(|key, route| *key != dc || !matches!(route.endpoint.peer, Peer::Vpn { .. }));
        self.slots
            .lock()
            .unwrap()
            .retain(|slot| slot.dc != dc || !matches!(slot.endpoint.peer, Peer::Vpn { .. }));
        if self.legacy_buffer.is_some() {
            self.refill_wake.notify_one();
        }
    }

    async fn take_matching(
        &self,
        dc: i16,
        expected: Option<&Endpoint>,
        stats: &Stats,
    ) -> Option<(relay::Ws, Endpoint)> {
        if self.limit == 0 {
            return None;
        }
        loop {
            let next = {
                let mut slots = self.slots.lock().unwrap();
                slots.retain(|s| !s.task.is_finished());
                slots
                    .iter()
                    .position(|s| {
                        s.dc == dc
                            && expected.is_none_or(|e| e == &s.endpoint)
                            && s.ready.load(Ordering::Acquire)
                    })
                    .map(|i| slots.remove(i))
            };
            let Some(mut slot) = next else {
                stats.pool_misses.fetch_add(1, Ordering::Relaxed);
                return None;
            };
            if self.legacy_buffer.is_some() {
                self.refill_wake.notify_one();
            }
            let _ = slot.checkout.take()?.send(());
            if let Ok(Ok(Some(ws))) = timeout(Duration::from_secs(3), &mut slot.task).await {
                stats.pool_hits.fetch_add(1, Ordering::Relaxed);
                return Some((ws, slot.endpoint.clone()));
            }
        }
    }

    pub fn warm(&self, dc: i16, endpoint: Endpoint) {
        if self.limit == 0 {
            return;
        }
        if self.tracks_routes() {
            let mut routes = self.routes.lock().unwrap();
            if routes
                .get(&dc)
                .is_none_or(|route| route.endpoint != endpoint)
            {
                routes.insert(
                    dc,
                    Route {
                        endpoint: endpoint.clone(),
                        refill: self.legacy_buffer.is_some().then(|| {
                            Arc::new(Mutex::new(Refill {
                                wake: Some(self.refill_wake.clone()),
                                ..Default::default()
                            }))
                        }),
                    },
                );
                if self.legacy_buffer.is_some() {
                    self.refill_wake.notify_one();
                }
            }
        }
        self.refill(dc, endpoint, true);
    }

    fn tracks_routes(&self) -> bool {
        self.legacy_buffer.is_some() || self.limit > nfqws2_tgws_config::OLD_POOL_LIMIT as usize
    }

    pub fn maintain(&self) {
        let routes: Vec<_> = self
            .routes
            .lock()
            .unwrap()
            .iter()
            .map(|(&dc, route)| (dc, route.endpoint.clone()))
            .collect();
        for (dc, endpoint) in routes {
            self.refill(dc, endpoint, false);
        }
    }

    fn next_refill_retry(&self) -> Option<Instant> {
        if self.limit == 0 || self.legacy_buffer.is_none() {
            return None;
        }
        let routes = self.routes.lock().unwrap();
        let slots = self.slots.lock().unwrap();
        let active = slots.iter().filter(|slot| !slot.task.is_finished());
        if active.clone().count() >= self.capacity {
            return None;
        }
        routes
            .iter()
            .filter_map(|(&dc, route)| {
                let refill = route.refill.as_ref()?.lock().unwrap();
                if refill.pending != 0
                    || active.clone().filter(|slot| slot.dc == dc).count() >= self.limit
                {
                    return None;
                }
                refill.retry_at
            })
            .min()
    }

    pub async fn wait_for_refill_retry(&self) {
        loop {
            let changed = self.refill_wake.notified();
            if let Some(deadline) = self.next_refill_retry() {
                if deadline <= Instant::now() {
                    return;
                }
                tokio::select! { _ = changed => {}, _ = sleep_until(deadline) => {} }
            } else {
                changed.await;
            }
        }
    }

    fn refill(&self, dc: i16, endpoint: Endpoint, demand: bool) {
        let routes = self.routes.lock().unwrap();
        let route = routes.get(&dc);
        if self.tracks_routes() && route.is_none_or(|route| route.endpoint != endpoint) {
            return;
        }
        let mut slots = self.slots.lock().unwrap();
        slots.retain(|s| !s.task.is_finished() && (s.dc != dc || s.endpoint == endpoint));
        if demand
            && self.legacy_buffer.is_none()
            && !slots.is_empty()
            && slots.len() == self.limit.min(self.capacity)
            && !slots.iter().any(|s| s.dc == dc)
        {
            // Give a newly used DC one slot from the most represented DC.
            let mut counts = BTreeMap::new();
            for s in slots.iter() {
                *counts.entry(s.dc).or_insert(0usize) += 1;
            }
            let index = slots
                .iter()
                .enumerate()
                .max_by_key(|(_, s)| counts[&s.dc])
                .unwrap()
                .0;
            slots.remove(index);
        }
        // The Go profile's size is a target per DC, including distinct media
        // and test buckets. The native profile retains its global budget.
        let used = if self.legacy_buffer.is_some() {
            slots.iter().filter(|s| s.dc == dc).count()
        } else {
            slots.len()
        };
        let mut needed = self
            .limit
            .saturating_sub(used)
            .min(self.capacity.saturating_sub(slots.len()));
        if self.tracks_routes() {
            let pending = slots
                .iter()
                .filter(|s| s.dc == dc && !s.ready.load(Ordering::Acquire))
                .count();
            needed = needed.min(4usize.saturating_sub(pending));
        }
        let refill = route.and_then(|route| route.refill.as_ref());
        if needed == 0 || refill.is_some_and(|r| !r.lock().unwrap().begin(needed, Instant::now())) {
            return;
        }
        for _ in 0..needed {
            let (send, recv) = oneshot::channel();
            let ready = Arc::new(AtomicBool::new(false));
            slots.push(Slot {
                dc,
                endpoint: endpoint.clone(),
                ready: ready.clone(),
                checkout: Some(send),
                task: tokio::spawn(reserve(
                    endpoint.clone(),
                    self.direct.clone(),
                    self.dials.clone(),
                    SlotWait {
                        ready,
                        checkout: recv,
                    },
                    self.legacy_buffer,
                    dc < 0,
                    Attempt::new(refill.cloned(), self.diagnostics.clone(), dc),
                )),
            });
        }
    }

    pub async fn stop(&self) {
        self.relays.stop().await;
        let slots = std::mem::take(&mut *self.slots.lock().unwrap());
        for slot in &slots {
            slot.task.abort();
        }
        for mut slot in slots {
            let _ = (&mut slot.task).await;
        }
    }
}

fn capacity(buffer_size: i64) -> usize {
    // A saved target may exceed 16. Bound live resources independently of
    // the integer and leave room for accepted clients and other router services.
    let fd = std::fs::read_to_string("/proc/self/limits")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix("Max open files")?
                    .split_whitespace()
                    .next()?
                    .parse::<u64>()
                    .ok()
            })
        })
        .unwrap_or(1024);
    let mem = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            ["MemAvailable:", "MemFree:"].iter().find_map(|k| {
                s.lines().find_map(|l| {
                    l.strip_prefix(k)?
                        .split_whitespace()
                        .next()?
                        .parse::<u64>()
                        .ok()
                })
            })
        })
        .unwrap_or(512 * 1024);
    let socket_bytes = 4 * buffer_size.clamp(4096, i64::from(i32::MAX)) as u64 + 64 * 1024;
    let by_mem = mem.saturating_mul(1024) / 2 / socket_bytes;
    usize::try_from((fd - (fd / 2).min(128)).min(by_mem)).unwrap_or(usize::MAX)
}
async fn reserve(
    endpoint: Endpoint,
    direct: crate::direct::Direct,
    dials: Arc<Semaphore>,
    SlotWait {
        ready,
        mut checkout,
    }: SlotWait,
    legacy_buffer: Option<i64>,
    media: bool,
    mut attempt: Attempt,
) -> Option<relay::Ws> {
    let ordinary = if legacy_buffer.is_some() && media {
        endpoint
            .host
            .strip_suffix("-1.web.telegram.org")
            .map(|dc| format!("{dc}.web.telegram.org"))
    } else {
        None
    };
    let managed_ip = match endpoint.peer {
        Peer::Direct(addr) if endpoint.managed => Some(addr.ip()),
        _ => None,
    };
    loop {
        let dial = async {
            let _permit = dials.acquire().await.ok()?;
            Some(
                direct
                    .dial_domains(
                        &endpoint.host,
                        ordinary.as_deref(),
                        endpoint.path,
                        legacy_buffer.unwrap_or(8192),
                        managed_ip,
                        |_| async {
                            let tcp = endpoint.peer.connect().await?;
                            if legacy_buffer.is_some() {
                                nfqws2_tgws_transport::configure_tcp_fallback(&tcp);
                            }
                            Ok(tcp)
                        },
                    )
                    .await,
            )
        };
        let ws = tokio::select! {
            biased;
            _ = &mut checkout => return None,
            ws = dial => ws?,
        };
        attempt.complete(Some(ws.as_ref().map(|_| ()).map_err(std::io::Error::kind)));
        let selected = idle(ws.ok()?, &ready, &mut checkout, legacy_buffer.is_none()).await;
        ready.store(false, Ordering::Release);
        if selected.is_some() || checkout.is_terminated() || !attempt.requeue() {
            return selected;
        }
    }
}

pub(super) async fn idle<S: AsyncBufRead + AsyncWrite + Unpin>(
    mut ws: WebSocketStream<Wire<S>>,
    ready: &AtomicBool,
    checkout: &mut oneshot::Receiver<()>,
    probe_peer: bool,
) -> Option<WebSocketStream<Wire<S>>> {
    ready.store(true, Ordering::Release);

    let expires = sleep(Duration::from_secs(120));
    let probe = sleep(Duration::from_secs(25));
    tokio::pin!(expires, probe);
    if !probe_peer {
        // The Go pool peeks at the first frame while idle. Preserve even a
        // ping for the active session and never read past a pending data frame.
        let mut buffered = false;
        loop {
            tokio::select! {
                biased;
                _ = &mut expires => return None,
                open = ws.get_mut().peek_open(), if !buffered => {
                    if !open.ok()? { return None; }
                    buffered = true;
                }
                result = &mut *checkout => {
                    result.ok()?;
                    if !buffered && matches!(
                        timeout(LEGACY_IDLE_PROBE, ws.get_mut().peek_open()).await,
                        Ok(Ok(false) | Err(_))
                    ) {
                        return None;
                    }
                    return Some(ws);
                }
            }
        }
    }
    let mut awaiting_pong = false;
    loop {
        tokio::select! {
            biased;
            _ = &mut expires => return None,
            _ = &mut probe => {
                if awaiting_pong { return None; }
                ready.store(false, Ordering::Release);
                timeout(Duration::from_secs(2), ws.send(Message::Ping(b"tgws".as_slice().into()))).await.ok()?.ok()?;
                awaiting_pong = true;
                probe.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(10));
            }
            msg = ws.next() => match msg?.ok()? {
                Message::Ping(_) => { timeout(Duration::from_secs(2), ws.flush()).await.ok()?.ok()?; }
                Message::Pong(data) if awaiting_pong && data.as_ref() == b"tgws" => {
                    awaiting_pong = false;
                    ready.store(true, Ordering::Release);
                    probe.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(25));
                }
                Message::Pong(_) => {}
                _ => return None,
            },
            result = &mut *checkout, if !awaiting_pong => return result.ok().map(|_| ws),
        }
    }
}

#[cfg(test)]
mod tests;
