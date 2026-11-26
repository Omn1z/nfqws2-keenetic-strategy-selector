use super::{
    config::{display_upstream, Config},
    fast_dns,
    filtering::{Filter, Hit},
    lan::PeerScope,
    routing::ManagedDelivery,
    scheduler::{self, Candidate, Policy, Schedule},
    shadow,
    transport::Doh,
};
use futures_util::{
    future::{BoxFuture, Shared, WeakShared},
    FutureExt, StreamExt,
};
use nfqws2_dns::{
    query_domain, response_error, udp_answer, Answer, Lookup, PendingQuery, QueryKey, Resolver,
    Source,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, RwLock,
    },
    time::{Duration, Instant, SystemTime},
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Notify, Semaphore},
    task::{JoinHandle, JoinSet},
    time::{timeout_at, Instant as TokioInstant},
};

const CLIENT_REQUEST_TIMEOUT: Duration = Duration::from_secs(27);
const DIAGNOSTIC_REQUEST_TIMEOUT: Duration = Duration::from_secs(28);
const RESOLUTION_TIMEOUT: Duration = Duration::from_secs(25);

#[derive(Clone, Default, Serialize)]
pub struct Stats {
    pub queries: u64,
    pub cache_hits: u64,
    pub shared_responses: u64,
    pub nfqws_success: u64,
    pub awg_success: u64,
    pub shadow_success: u64,
    pub blocked_total: u64,
    pub blocked_ads: u64,
    pub blocked_trackers: u64,
    pub blocked_mixed: u64,
    pub failures: u64,
    pub last_domain: String,
    pub last_route: String,
    pub last_upstream: String,
    pub last_cached: bool,
    pub last_shared: bool,
    pub last_client_ip: String,
    pub last_source: String,
    pub last_transport: String,
    pub last_error: String,
}
const LOG_BYTES: usize = 128 * 1024;
#[derive(Default)]
pub struct Diagnostics {
    entries: VecDeque<(u64, Box<str>)>,
    bytes: usize,
    last: u64,
    dropped: u64,
    pub logging: bool,
    instance: u128,
}
impl Diagnostics {
    pub fn new(logging: bool) -> Self {
        Self {
            logging,
            instance: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
            ..Self::default()
        }
    }
    pub fn clear(&mut self) {
        self.entries.clear();
        self.bytes = 0;
        self.dropped = 0;
    }
    pub fn logs(&self, after: u64) -> Value {
        let entries: Vec<Value> = self
            .entries
            .iter()
            .filter(|(id, _)| *id > after)
            .map(|(_, raw)| serde_json::from_str(raw).expect("serialized DNS log"))
            .collect();
        json!({"instance_id":self.instance.to_string(),"enabled":self.logging,"bytes":self.bytes,"max_bytes":LOG_BYTES,"oldest_id":self.entries.front().map_or(0,|(id,_)|*id),"last_id":self.last,"dropped":self.dropped,"entries":entries})
    }
    pub(super) fn event(&mut self, level: &str, event: &str, message: impl Into<String>) {
        self.log(json!({"level":level,"event":event,"message":message.into()}));
    }
    pub(super) fn set_logging(&mut self, enabled: bool) {
        if !enabled {
            self.event("info", "logging", "Запись журнала DNS выключена");
        }
        self.logging = enabled;
        if enabled {
            self.event(
                "info",
                "logging",
                "Запись журнала DNS включена; предел 128 КБ",
            );
        }
    }
    fn log(&mut self, mut e: Value) {
        if !self.logging {
            return;
        }
        self.last += 1;
        e["id"] = json!(self.last);
        e["time"] = json!(OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_default());
        let encoded = serde_json::to_string(&e).unwrap().into_boxed_str();
        let size = encoded.len() + 1;
        while self.bytes + size > LOG_BYTES {
            let Some((_, entry)) = self.entries.pop_front() else {
                break;
            };
            self.bytes -= entry.len() + 1;
            self.dropped += 1;
        }
        if size <= LOG_BYTES {
            self.bytes += size;
            self.entries.push_back((self.last, encoded));
        }
    }
}
pub struct Engine {
    observer: Arc<super::routing::Observer>,
    pub(super) vpn: Arc<super::vpn::Source>,
    pub cfg: Config,
    pub cache: Resolver,
    inflight: Mutex<HashMap<QueryKey, WeakShared<QueryWork>>>,
    pub(super) transport: Doh,
    requests: Semaphore,
    pub(super) stopped: tokio::sync::watch::Sender<bool>,
    diag: Arc<Mutex<Diagnostics>>,
    stats: Mutex<Stats>,
    schedule: Arc<Schedule>,
    pub methods: Policy,
    pub filter: Option<Filter>,
    pub shadow: Option<shadow::Session>,
}
pub struct Outcome {
    pub answer: Answer,
    pub upstream: String,
    pub hit: Option<Hit>,
    pub route: String,
    pub shared: bool,
}

type QueryWork = BoxFuture<'static, Result<Arc<Answer>, Arc<io::Error>>>;

struct Request {
    wire: Vec<u8>,
    domain: String,
    kind: u16,
    origin: RequestOrigin,
    source: Option<Arc<super::catalog::Index>>,
    allow: bool,
}

struct RequestOrigin {
    source: String,
    transport: String,
    client: Option<IpAddr>,
}

#[derive(Clone, Copy)]
struct Attempt<'a> {
    domain: &'a str,
    kind: u16,
    origin: AttemptOrigin<'a>,
}

#[derive(Clone, Copy)]
enum AttemptOrigin<'a> {
    Client(&'a RequestOrigin),
    PeriodicProbe,
    Archive,
}

impl Attempt<'_> {
    fn entry(self, level: &str, event: &str) -> Value {
        let mut entry = json!({
            "level": level,
            "event": event,
            "domain": self.domain,
            "qtype": type_name(self.kind),
            "source": if matches!(self.origin, AttemptOrigin::Archive) { "archive" } else { "probe" },
        });
        if let AttemptOrigin::Client(origin) = self.origin {
            entry["source"] = json!(origin.source);
            entry["transport"] = json!(origin.transport);
            entry["client_ip"] = json!(origin
                .client
                .map(|client| client.to_string())
                .unwrap_or_default());
        }
        entry
    }
}

struct RaceJournal<'a> {
    diag: &'a Mutex<Diagnostics>,
    attempt: Attempt<'a>,
    canceled: AtomicUsize,
}

impl Drop for RaceJournal<'_> {
    fn drop(&mut self) {
        let count = *self.canceled.get_mut();
        if count > 0 {
            let mut diag = self.diag.lock().unwrap();
            if diag.logging {
                let mut entry = self.attempt.entry("debug", "canceled");
                entry["count"] = json!(count);
                diag.log(entry);
            }
        }
    }
}

struct Dispatched<'a> {
    canceled: &'a AtomicUsize,
    completed: bool,
}

impl Drop for Dispatched<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.canceled.fetch_add(1, Ordering::Relaxed);
        }
    }
}

enum Fetch {
    Cached(Answer),
    Shared {
        work: Shared<QueryWork>,
        joined: bool,
    },
    Direct {
        pending: PendingQuery,
        request: Request,
    },
}
impl Engine {
    pub(super) fn stats(&self) -> Stats {
        self.stats.lock().unwrap().clone()
    }
    #[cfg(test)]
    pub(super) fn trust(&self, cert: tokio_rustls::rustls::pki_types::CertificateDer<'static>) {
        self.transport.trust(cert);
    }
    pub fn new(
        cfg: Config,
        diag: Arc<Mutex<Diagnostics>>,
        schedule: Arc<Schedule>,
        wan: Arc<shadow::Environment>,
        vpn: Arc<super::vpn::Source>,
        observer: Arc<super::routing::Observer>,
    ) -> Arc<Self> {
        let probe = cfg.scheduler_enabled
            && (!cfg.default_pool.is_empty()
                || cfg.rules.iter().any(|r| r.enabled && !r.pool.is_empty())
                || cfg.awg_fallback != "off");
        let transport = Doh::new(cfg.fast_dns);
        let stopped = tokio::sync::watch::channel(false).0;
        let engine = Arc::new(Self {
            observer,
            vpn,
            shadow: shadow::Session::new(&cfg.shadow_dns, wan, stopped.clone()),
            filter: Filter::compile(&cfg.filtering),
            methods: Policy::new(scheduler::disabled(&cfg.disabled_methods)),
            schedule,
            cache: Resolver::new(
                cfg.cache_size,
                cfg.cache_ttl_seconds,
                Duration::from_secs(cfg.timeout_seconds),
            ),
            inflight: Default::default(),
            cfg,
            transport,
            requests: Semaphore::new(64),
            stopped,
            diag,
            stats: Mutex::new(Stats::default()),
        });
        if probe {
            Self::start_probes(&engine);
        }
        if let Some(cache) = &engine.transport.fast {
            fast_dns::start_workers(&engine, cache);
        }
        engine
    }
    fn start_warming(engine: &Arc<Self>) {
        if let Some(cache) = &engine.transport.fast {
            fast_dns::start_warming(engine, cache);
        }
    }
    fn start_probes(engine: &Arc<Self>) {
        let owner = Arc::downgrade(engine);
        let mut stop = engine.stopped.subscribe();
        tokio::spawn(async move {
            let period = scheduler::PROBE_INTERVAL;
            let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! { biased; _=stop.changed()=>return, _=ticks.tick()=>{} }
                let Some(engine) = owner.upgrade() else {
                    return;
                };
                let Ok(slot) = engine.schedule.slots.try_acquire() else {
                    continue;
                };
                let Ok(routes) = engine.vpn.eligible(&engine.cfg).await else {
                    continue;
                };
                let selected = engine.methods.read(|off| {
                    engine.schedule.next_probe(
                        &engine.cfg,
                        off,
                        engine.shadow.as_ref().map(|s| &s.matcher),
                        &routes,
                    )
                });
                let Some((domain, server)) = selected else {
                    continue;
                };
                let Ok(id) = nfqws2_dns::transaction_id() else {
                    continue;
                };
                let qtype = if domain == "." { 2 } else { 1 };
                let Ok(wire) = nfqws2_dns::build_query(domain, qtype, id) else {
                    continue;
                };
                let attempt = Attempt {
                    domain,
                    kind: qtype,
                    origin: AttemptOrigin::PeriodicProbe,
                };
                tokio::select! { biased; _=stop.changed()=>return, _=engine.measure(server,&wire,true,Some(attempt),None)=>{} }
                drop(slot);
            }
        });
    }
    async fn measure(
        &self,
        candidate: Candidate<'_>,
        wire: &[u8],
        tracked: bool,
        attempt: Option<Attempt<'_>>,
        canceled: Option<&AtomicUsize>,
    ) -> io::Result<Vec<u8>> {
        let probe = attempt.is_some_and(|a| matches!(a.origin, AttemptOrigin::PeriodicProbe));
        let key = candidate.key();
        let mut lease = self.methods.begin(&key)?;
        let work = async {
            let _slot = if probe {
                None
            } else {
                Some(
                    self.schedule
                        .slots
                        .acquire()
                        .await
                        .map_err(io::Error::other)?,
                )
            };
            let evidence = if tracked {
                Some(
                    self.schedule
                        .begin(&key, probe)
                        .ok_or(io::ErrorKind::Interrupted)?,
                )
            } else {
                None
            };
            // A candidate waiting for a shared slot has not started a network attempt.
            let mut dispatched = canceled.map(|canceled| Dispatched {
                canceled,
                completed: false,
            });
            let started = Instant::now();
            let deadline = TokioInstant::now() + Duration::from_secs(self.cfg.timeout_seconds);
            let outcome = self
                .transport
                .exchange(
                    candidate.server,
                    wire,
                    candidate.route,
                    &self.methods,
                    deadline,
                    attempt.is_some_and(|a| matches!(a.origin, AttemptOrigin::Archive)),
                )
                .await;
            if let Some(dispatched) = &mut dispatched {
                dispatched.completed = true;
            }
            let elapsed = started.elapsed();
            if let Err(error) = &outcome {
                self.transport
                    .refresh_failed(candidate.server, candidate.route);
                if let Some(attempt) = attempt {
                    self.record_attempt_failure(
                        attempt,
                        &candidate.route.id,
                        &display_upstream(&candidate.server.address),
                        elapsed,
                        error,
                    );
                }
            }
            if let Some(attempt) = evidence {
                attempt.finish(outcome.as_ref().err());
            }
            outcome
        };
        tokio::select! {biased; _=lease.canceled.changed()=>Err(io::Error::new(io::ErrorKind::Interrupted,"метод DNS выключен")),r=work=>r}
    }

    fn record_attempt_failure(
        &self,
        attempt: Attempt<'_>,
        route: &str,
        upstream: &str,
        elapsed: Duration,
        error: &io::Error,
    ) {
        let mut diag = self.diag.lock().unwrap();
        if !diag.logging {
            return;
        }
        let mut entry = attempt.entry("warn", "attempt_error");
        entry["upstream"] = json!(upstream);
        entry["route"] = json!(route);
        entry["duration_ms"] = json!(elapsed.as_millis() as u64);
        entry["message"] = if matches!(attempt.origin, AttemptOrigin::Client(_)) {
            json!(error.to_string())
        } else {
            json!(format!("Фоновая проверка: {error}"))
        };
        diag.log(entry);
    }

    async fn race(
        &self,
        wire: &[u8],
        attempt: Attempt<'_>,
    ) -> io::Result<(Vec<u8>, String, super::vpn::Route)> {
        let routes = self.vpn.eligible(&self.cfg).await?;
        let servers = self
            .methods
            .read(|off| self.schedule.order(&self.cfg, attempt.domain, off, &routes));
        let tracked = self.cfg.scheduler_enabled
            && servers.len() > 1
            && !matches!(attempt.origin, AttemptOrigin::Archive);
        let mut last = io::Error::other("нет доступного включённого DoH в выбранном пуле");
        // Pending futures and their slots drop before the journal summarizes cancellations.
        let journal = RaceJournal {
            diag: &self.diag,
            attempt,
            canceled: AtomicUsize::new(0),
        };
        let canceled = &journal.canceled;
        let mut pending = futures_util::stream::FuturesUnordered::new();
        let mut servers = servers.into_iter();
        let mut all_upstream_timeouts = true;
        loop {
            for candidate in servers.by_ref().take(scheduler::LIMIT - pending.len()) {
                pending.push(async move {
                    (
                        candidate.server,
                        candidate.route,
                        self.measure(candidate, wire, tracked, Some(attempt), Some(canceled))
                            .await,
                    )
                });
            }
            let Some((server, route, result)) = pending.next().await else {
                break;
            };
            match result {
                Ok(v) => return Ok((v, server.address.clone(), route.clone())),
                Err(e) => {
                    all_upstream_timeouts &= super::is_managed_upstream_timeout(&e);
                    last = e;
                }
            }
        }
        if !all_upstream_timeouts && super::is_managed_upstream_timeout(&last) {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Err(last)
    }
    async fn upstream_reply(
        &self,
        wire: &[u8],
        attempt: Attempt<'_>,
    ) -> io::Result<(Vec<u8>, Source)> {
        let mut outage = None;
        let shadow = self
            .shadow
            .as_ref()
            .filter(|s| s.matcher.matches(attempt.domain));
        let mut reply = None;
        if let Some(shadow) = shadow {
            match shadow
                .provider(
                    wire,
                    Duration::from_secs(self.cfg.timeout_seconds),
                    &self.schedule.slots,
                    |peer, elapsed, error| {
                        self.record_attempt_failure(attempt, "shadow", peer, elapsed, error);
                    },
                )
                .await
            {
                Ok((wire, peer)) => reply = Some((wire, peer, "shadow".to_owned())),
                Err(e) => outage = Some(e),
            }
        }
        let (mut answer, upstream, route) = match reply {
            Some(reply) => reply,
            None => match self.race(wire, attempt).await {
                Ok((wire, server, route)) => (wire, display_upstream(&server), route.id),
                Err(e) => {
                    return Err(if let Some(first) = outage {
                        io::Error::other(format!("{first}; резерв DNS Server: {e}"))
                    } else {
                        e
                    })
                }
            },
        };
        if outage.is_some() {
            nfqws2_dns::cap_ttls(&mut answer, 30)?;
        }
        nfqws2_dns::clip_negative_soa(&mut answer)?;
        Ok((answer, Source { route, upstream }))
    }

    async fn perform(&self, request: Request, pending: PendingQuery) -> io::Result<Answer> {
        let Request {
            wire,
            domain,
            kind,
            origin,
            source,
            allow,
        } = request;
        let attempt = Attempt {
            domain: &domain,
            kind,
            origin: AttemptOrigin::Client(&origin),
        };
        let (answer, upstream) = self.upstream_reply(&wire, attempt).await?;
        let cacheable = self.filter.as_ref().map_or(Ok(true), |filter| {
            filter
                .response_hit(&domain, kind, &answer, source.as_deref(), allow)
                .map(|hit| hit.is_none())
        })?;
        self.cache
            .finish(&wire, pending, answer, cacheable, Some(upstream))
    }

    async fn filter_source(&self) -> Option<Arc<super::catalog::Index>> {
        match self.filter.as_ref().and_then(|filter| filter.feed.as_ref()) {
            Some(feed) => feed.query_snapshot().await,
            None => None,
        }
    }

    pub(super) async fn archive_reply(&self, wire: &[u8]) -> io::Result<Option<Vec<u8>>> {
        let _slot = self
            .requests
            .try_acquire()
            .map_err(|_| io::Error::other("DNS-сервер занят"))?;
        let (domain, kind) = query_domain(wire)?;
        let mut stop = self.stopped.subscribe();
        if *stop.borrow() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let work = async {
            let source = self.filter_source().await;
            let (hit, allow) = self
                .filter
                .as_ref()
                .map(|filter| filter.evaluate(&domain, kind, source.as_deref()))
                .unwrap_or((None, false));
            if hit.is_some() {
                return Ok(None);
            }
            let attempt = Attempt {
                domain: &domain,
                kind,
                origin: AttemptOrigin::Archive,
            };
            let (reply, _) = self.upstream_reply(wire, attempt).await?;
            if let Some(filter) = &self.filter {
                if filter
                    .response_hit(&domain, kind, &reply, source.as_deref(), allow)?
                    .is_some()
                {
                    return Ok(None);
                }
            }
            Ok(Some(reply))
        };
        tokio::select! {
            biased;
            _ = stop.changed() => Err(io::ErrorKind::Interrupted.into()),
            reply = work => reply,
        }
    }

    fn share(self: &Arc<Self>, pending: PendingQuery, request: Request) -> Fetch {
        let Some(key) = pending.sharing_key().cloned() else {
            return Fetch::Direct { pending, request };
        };
        let mut flights = self.inflight.lock().unwrap();
        if let Some(work) = flights
            .get(&key)
            .and_then(WeakShared::upgrade)
            .filter(|work| work.peek().is_none())
        {
            return Fetch::Shared { work, joined: true };
        }
        if let Some(answer) = self.cache.recheck(&request.wire, &pending) {
            return Fetch::Cached(answer);
        }
        flights.retain(|_, work| work.upgrade().is_some_and(|work| work.peek().is_none()));
        if flights.len() >= 128 {
            return Fetch::Direct { pending, request };
        }
        // Each caller polls a clone. Keeping only a weak handle in the table
        // makes dropping the last caller cancel the upstream operation.
        let owner = self.clone();
        let work = async move {
            owner
                .perform(request, pending)
                .await
                .map(Arc::new)
                .map_err(Arc::new)
        }
        .boxed()
        .shared();
        flights.insert(key, work.downgrade().unwrap());
        Fetch::Shared {
            work,
            joined: false,
        }
    }

    async fn resolve(
        self: &Arc<Self>,
        wire: &[u8],
        scope: &str,
        question: (&str, u16),
        origin: RequestOrigin,
        source: Option<Arc<super::catalog::Index>>,
        allow: bool,
    ) -> io::Result<(Answer, bool)> {
        let fetch = match self.cache.begin(wire, scope)? {
            Lookup::Hit(answer) => Fetch::Cached(answer),
            Lookup::Miss(pending) => self.share(
                pending,
                Request {
                    wire: wire.to_vec(),
                    domain: question.0.to_owned(),
                    kind: question.1,
                    origin,
                    source,
                    allow,
                },
            ),
        };
        match fetch {
            Fetch::Cached(answer) => Ok((answer, false)),
            Fetch::Direct { request, pending } => {
                Ok((self.perform(request, pending).await?, false))
            }
            Fetch::Shared { work, joined } => {
                let answer = work.await.map_err(|e| io::Error::new(e.kind(), e))?;
                Ok((answer.for_request(wire)?, joined))
            }
        }
    }

    pub async fn exchange(
        self: &Arc<Self>,
        wire: &[u8],
        origin: &str,
        transport: &str,
        client: Option<IpAddr>,
    ) -> io::Result<Outcome> {
        self.exchange_on_socket(wire, origin, transport, client, false)
            .await
    }

    async fn exchange_on_socket(
        self: &Arc<Self>,
        wire: &[u8],
        origin: &str,
        transport: &str,
        client: Option<IpAddr>,
        remember_lan: bool,
    ) -> io::Result<Outcome> {
        let _slot = self
            .requests
            .try_acquire()
            .map_err(|_| io::Error::other("DNS-сервер занят"))?;
        let deadline = TokioInstant::now()
            + if transport == "api" {
                DIAGNOSTIC_REQUEST_TIMEOUT
            } else {
                CLIENT_REQUEST_TIMEOUT
            };
        let (domain, kind) = query_domain(wire)?;
        let (scope, _, _) = self.cfg.servers(&domain);
        let capture = (origin == "local"
            && client.is_some_and(|ip| ip.is_loopback())
            && matches!(transport, "udp" | "tcp")
            && matches!(kind, 1 | 28))
            .then(|| self.observer.capture_warm_transport(&domain))
            .flatten();
        let warm = if capture.is_some() {
            capture.zip(super::ArchiveResolver::pinned_managed(self.clone()).managed_origin_receipt())
        } else {
            None
        };
        let started = Instant::now();
        let mut upstream = String::new();
        let mut network_route = if self.cfg.route_mode == "vpn_only" {
            String::new()
        } else {
            "nfqws".to_owned()
        };
        let shadow = self
            .shadow
            .as_ref()
            .is_some_and(|s| s.matcher.matches(&domain));
        let mut stop = self.stopped.subscribe();
        if *stop.borrow() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let source = tokio::select! {
            biased;
            _ = stop.changed() => return Err(io::ErrorKind::Interrupted.into()),
            source = timeout_at(deadline, self.filter_source()) =>
                source.map_err(|_| io::ErrorKind::TimedOut)?,
        };
        let (mut hit, allow) = self
            .filter
            .as_ref()
            .map(|f| f.evaluate(&domain, kind, source.as_deref()))
            .unwrap_or((None, false));
        let blocked = || {
            nfqws2_dns::blocked_reply(wire).map(|wire| Answer {
                wire,
                cached: false,
                source: None,
                ttl_anchor: Instant::now(),
            })
        };
        let mut shared = false;
        let result = if hit.is_some() {
            blocked()
        } else {
            let work = timeout_at(
                deadline.min(TokioInstant::now() + RESOLUTION_TIMEOUT),
                self.resolve(
                    wire,
                    if shadow { "shadow" } else { scope },
                    (&domain, kind),
                    RequestOrigin {
                        source: origin.into(),
                        transport: transport.into(),
                        client,
                    },
                    source.clone(),
                    allow,
                ),
            );
            let result = tokio::select! {biased;_=stop.changed()=>return Err(io::ErrorKind::Interrupted.into()),r=work=>r.unwrap_or_else(|_|Err(io::ErrorKind::TimedOut.into()))};
            result.and_then(|(answer, joined)| {
                shared = joined;
                if let Some(source) = &answer.source {
                    upstream.clone_from(&source.upstream);
                    network_route.clone_from(&source.route);
                }
                if let Some(filter) = &self.filter {
                    hit = filter.response_hit(
                        &domain,
                        kind,
                        &answer.wire,
                        source.as_deref(),
                        allow,
                    )?;
                    if hit.is_some() {
                        return blocked();
                    }
                }
                Ok(answer)
            })
        };
        // Apply per-client policy to the delivered copy, after blocklists and
        // on cache hits as well. The upstream cache is shared by all clients.
        let result = match result {
            Ok(mut answer) if hit.is_none() => {
                if !answer.cached && !shared {
                    if let Some(((failure, resolver), source)) = warm.zip(answer.source.as_ref()) {
                        self.observer.observe_warm_transport(super::WarmDnsObservation {
                            failure,
                            name: &domain,
                            query: wire,
                            reply: &answer.wire,
                            anchor: answer.ttl_anchor,
                            resolver,
                            source,
                        });
                    }
                }
                let managed = if remember_lan {
                    super::routing::ManagedRecent::capture(self, source.as_ref())
                } else {
                    None
                };
                let delivery = ManagedDelivery {
                    deadline,
                    ttl_anchor: TokioInstant::from_std(answer.ttl_anchor),
                    recent: managed,
                };
                tokio::select! {
                    biased;
                    _ = stop.changed() => return Err(io::ErrorKind::Interrupted.into()),
                    result = self.observer.prepare(&domain, client, wire, &mut answer.wire, delivery) => result.map(|_|answer)
                }
            }
            result => result,
        };
        let cached = result.as_ref().is_ok_and(|r| r.cached);
        let shared = shared && result.is_ok() && !cached && hit.is_none();
        if hit.is_some() {
            upstream.clear();
        }
        let route = if hit.is_some() {
            "blocked"
        } else {
            network_route.as_str()
        };
        let client = client.map(|v| v.to_string()).unwrap_or_default();
        let error = result
            .as_ref()
            .err()
            .map(ToString::to_string)
            .unwrap_or_default();
        let mut s = self.stats.lock().unwrap();
        s.queries += 1;
        let fresh = result.is_ok() && !shared && !cached;
        s.nfqws_success += u64::from(route == "nfqws" && fresh);
        s.awg_success += u64::from(route.starts_with("awg:") && fresh);
        s.shadow_success += u64::from(route == "shadow" && fresh);
        if let Some(h) = &hit {
            s.blocked_total += 1;
            match h.category.as_str() {
                "ads" => s.blocked_ads += 1,
                "trackers" => s.blocked_trackers += 1,
                _ => s.blocked_mixed += 1,
            }
        }
        s.cache_hits += u64::from(cached);
        s.shared_responses += u64::from(shared);
        s.failures += u64::from(result.is_err());
        s.last_domain.clone_from(&domain);
        s.last_route = route.into();
        s.last_upstream.clone_from(&upstream);
        s.last_cached = cached;
        s.last_shared = shared;
        s.last_client_ip.clone_from(&client);
        s.last_source = origin.into();
        s.last_transport = transport.into();
        s.last_error.clone_from(&error);
        drop(s);
        let mut diag = self.diag.lock().unwrap();
        if diag.logging {
            let mut entry = json!({"level":if result.is_ok(){"info"}else{"error"},"event":if hit.is_some(){"blocked"}else if cached{"cache"}else if shared{"shared"}else if result.is_ok(){"answer"}else{"error"},"domain":domain,"qtype":type_name(kind),"source":origin,"transport":transport,"client_ip":client,"upstream":upstream,"route":route,"duration_ms":started.elapsed().as_millis() as u64,"message":if shared { "Ответ получен из совместного DNS-запроса" } else { &error }});
            if let Some(h) = &hit {
                h.annotate(&mut entry);
            }
            diag.log(entry);
        }
        result.map(|answer| Outcome {
            route: route.to_owned(),
            answer,
            upstream,
            hit,
            shared,
        })
    }
}
fn type_name(kind: u16) -> String {
    match kind {
        1 => "A",
        2 => "NS",
        28 => "AAAA",
        5 => "CNAME",
        64 => "SVCB",
        65 => "HTTPS",
        15 => "MX",
        16 => "TXT",
        _ => return format!("TYPE{kind}"),
    }
    .into()
}
pub struct Bound {
    pub(super) udp: Arc<UdpSocket>,
    pub(super) tcp: TcpListener,
}
#[derive(Clone)]
pub(super) enum Handler {
    Panel {
        live: Arc<RwLock<Arc<Engine>>>,
        peers: PeerScope,
    },
    Intercept {
        upstream: SocketAddr,
        observer: Arc<super::routing::Observer>,
        bridge: Option<Arc<str>>,
    },
}
pub struct Active {
    pub addr: SocketAddr,
    engine: Arc<RwLock<Arc<Engine>>>,
    failure: Arc<Mutex<Option<String>>>,
    job: JoinHandle<io::Result<()>>,
}
impl Active {
    pub fn engine(&self) -> Arc<Engine> {
        self.engine.read().unwrap().clone()
    }
    pub fn replace(&self, engine: Arc<Engine>) {
        Engine::start_warming(&engine);
        let previous = std::mem::replace(&mut *self.engine.write().unwrap(), engine);
        previous.stopped.send_replace(true);
    }
    pub fn running(&self) -> bool {
        !self.job.is_finished() && self.failure.lock().unwrap().is_none()
    }
    pub(super) fn failure(&self) -> Option<String> {
        self.failure.lock().unwrap().clone()
    }
    #[cfg(test)]
    pub(super) fn fail_for_test(&self, wake: &Notify) {
        self.job.abort();
        *self.failure.lock().unwrap() = Some("fixture listener failure".into());
        wake.notify_one();
    }
    pub async fn stop(mut self) {
        self.engine().stopped.send_replace(true);
        self.job.abort();
        let _ = (&mut self.job).await;
    }
}
impl Drop for Active {
    fn drop(&mut self) {
        self.engine().stopped.send_replace(true);
        self.job.abort();
    }
}
impl Bound {
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let tcp = TcpListener::bind(addr).await?;
        let udp = Arc::new(UdpSocket::bind(tcp.local_addr()?).await?);
        Ok(Self { udp, tcp })
    }
    pub fn start(self, engine: Arc<Engine>, wake: Arc<Notify>) -> Active {
        let addr = self.tcp.local_addr().unwrap();
        Engine::start_warming(&engine);
        let engine = Arc::new(RwLock::new(engine));
        let handler = Handler::Panel {
            live: engine.clone(),
            peers: PeerScope::for_host(addr.ip()),
        };
        let failure = Arc::new(Mutex::new(None));
        let recorded = failure.clone();
        let job = tokio::spawn(async move {
            let result = self.serve(handler).await;
            if let Err(error) = &result {
                *recorded.lock().unwrap() = Some(error.to_string());
                wake.notify_one();
            }
            result
        });
        Active {
            addr,
            engine,
            failure,
            job,
        }
    }
    pub(super) async fn serve(self, handler: Handler) -> io::Result<()> {
        let connections = Arc::new(Semaphore::new(128));
        let datagrams = Arc::new(Semaphore::new(64));
        let mut tasks = JoinSet::new();
        let mut buf = vec![0; 65535];
        loop {
            tokio::select! {
                accepted=self.tcp.accept()=>{
                    let (stream,peer)=accepted?;
                    if !handler.accepts(peer.ip()){continue;}
                    if let Ok(permit)=connections.clone().try_acquire_owned(){let handler=handler.clone();tasks.spawn(async move{let _slot=permit;let _=tcp_connection(stream,handler,peer.ip()).await;});}
                }
                recv=self.udp.recv_from(&mut buf)=>{
                    let (size,peer)=recv?;
                    if !handler.accepts(peer.ip()) || size<12 || buf[2]&0x80!=0{continue;}
                    if let Ok(permit)=datagrams.clone().try_acquire_owned(){
                        let q=buf[..size].to_vec();let handler=handler.clone();let udp=self.udp.clone();
                        tasks.spawn(async move {
                            let _slot = permit;
                            if query_domain(&q).is_err() { return; }
                            if let Some(response) = handler.reply(&q, peer.ip(), "udp").await {
                                let _ = udp.send_to(&udp_answer(&q, response), peer).await;
                            }
                        });
                    }
                }
                Some(_)=tasks.join_next(),if !tasks.is_empty()=>{}
            }
        }
    }
}
impl Handler {
    fn accepts(&self, client: IpAddr) -> bool {
        match self {
            Self::Panel { peers, .. } => peers.allows(client),
            // An intercept socket is bound to the LAN device itself, where a
            // client may legitimately use a globally routable IPv6 address.
            Self::Intercept { .. } => true,
        }
    }

    async fn reply(&self, q: &[u8], client: IpAddr, transport: &str) -> Option<Vec<u8>> {
        let client = client.to_canonical();
        let result = match self {
            Self::Panel { live, peers } => {
                let engine = live.read().unwrap().clone();
                let remote = !peers.local_origin(client);
                let origin = if remote { "client" } else { "local" };
                engine
                    .exchange_on_socket(q, origin, transport, Some(client), remote)
                    .await
                    .map(|v| Some(v.answer.wire))
            }
            Self::Intercept {
                upstream,
                observer,
                bridge,
            } => super::redirect::forward(*upstream, observer, client, bridge.as_deref(), q).await,
        };
        result.unwrap_or_else(|_| Some(response_error(q, 2)))
    }
}
async fn tcp_connection(mut stream: TcpStream, handler: Handler, client: IpAddr) -> io::Result<()> {
    // The transparent listener serves one query under a single wire deadline.
    let intercept_deadline = matches!(&handler, Handler::Intercept { .. })
        .then(|| TokioInstant::now() + Duration::from_secs(6));
    loop {
        let read_deadline =
            intercept_deadline.unwrap_or_else(|| TokioInstant::now() + Duration::from_secs(60));
        let q = timeout_at(read_deadline, async {
            let n = stream.read_u16().await?;
            if n < 12 {
                return Err(io::Error::other("короткий DNS пакет"));
            }
            let mut wire = vec![0; n as usize];
            stream.read_exact(&mut wire).await?;
            query_domain(&wire)?;
            Ok(wire)
        })
        .await??;
        let Some(response) = handler.reply(&q, client, "tcp").await else {
            return Ok(());
        };
        let write_deadline =
            intercept_deadline.unwrap_or_else(|| TokioInstant::now() + Duration::from_secs(5));
        if TokioInstant::now() >= write_deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if intercept_deadline.is_some() {
            // Send one complete DNS frame before closing with unread input.
            let _ = stream.set_nodelay(true);
            let mut frame = Vec::with_capacity(response.len() + 2);
            frame.extend_from_slice(&(response.len() as u16).to_be_bytes());
            frame.extend_from_slice(&response);
            return timeout_at(write_deadline, async {
                stream.write_all(&frame).await?;
                stream.shutdown().await
            })
            .await?;
        }
        timeout_at(write_deadline, async {
            stream.write_u16(response.len() as u16).await?;
            stream.write_all(&response).await
        })
        .await??;
    }
}

#[cfg(test)]
mod managed_replay_tests {
    use super::*;
    use crate::dnsserver::{
        routing::{
            ArchiveResolver, DnsOrigin, FailedRoute, Observer, RouteAnswer, RouteMatch,
            RouteObserver, RoutePublication,
        },
        tests::scripted_doh,
    };
    use std::sync::atomic::AtomicU64;

    const HOST: &str = "warm.office.test";
    const PEER: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 9));

    #[derive(Default)]
    struct Gate {
        generation: AtomicU64,
        failed_epoch: AtomicU64,
        resolver: Mutex<Option<ArchiveResolver>>,
        installs: Mutex<Vec<RouteAnswer>>,
        attempts: AtomicUsize,
    }

    impl Gate {
        fn failed_route(&self) -> Option<FailedRoute> {
            let epoch = self.failed_epoch.load(Ordering::SeqCst);
            (epoch > 1).then(|| FailedRoute {
                epoch,
                generation: self.generation.load(Ordering::SeqCst),
            })
        }
    }

    impl RouteObserver for Gate {
        fn select(&self, name: &str, client: Option<IpAddr>) -> io::Result<Option<RouteMatch>> {
            let generation = self.generation.load(Ordering::SeqCst);
            if generation == 0 || !name.ends_with(".office.test") || client != Some(PEER) {
                return Ok(None);
            }
            if let Some(failed) = self.failed_route() {
                return Err(io::Error::other(failed));
            }
            if self.failed_epoch.load(Ordering::SeqCst) == 1 {
                return Err(io::Error::other("operation still applying"));
            }
            Ok(Some(RouteMatch {
                revision: 4,
                generation,
                zone: 2,
            }))
        }

        fn replay_publication(&self) -> Option<RoutePublication> {
            (self.failed_epoch.load(Ordering::SeqCst) == 0).then(|| RoutePublication {
                generation: self.generation.load(Ordering::SeqCst),
                revision: 4,
            })
        }

        fn failed_reply_current(
            &self,
            failure: FailedRoute,
            _: &str,
            origin: DnsOrigin<'_>,
            resolver: &ArchiveResolver,
        ) -> bool {
            self.failed_route() == Some(failure)
                && origin.client == Some(PEER)
                && origin.ingress.is_none()
                && self
                    .resolver
                    .lock()
                    .unwrap()
                    .as_ref()
                    .is_some_and(|current| resolver.same(current))
        }

        fn recovered(&self, publication: RoutePublication, failure: FailedRoute) -> bool {
            self.replay_publication() == Some(publication)
                && publication.generation > failure.generation
        }

        fn replay_target(
            &self,
            publication: RoutePublication,
            name: &str,
            origin: DnsOrigin<'_>,
        ) -> io::Result<Option<RouteMatch>> {
            if self.replay_publication() != Some(publication) {
                return Err(io::ErrorKind::Interrupted.into());
            }
            self.select(name, origin.client)
        }

        fn archive_resolver(&self, publication: RoutePublication) -> Option<ArchiveResolver> {
            if self.replay_publication() == Some(publication) {
                self.resolver.lock().unwrap().clone()
            } else {
                None
            }
        }

        fn install(
            &self,
            _: RouteMatch,
            _: &str,
            _: DnsOrigin<'_>,
            _: &RouteAnswer,
        ) -> io::Result<(bool, u64)> {
            panic!("replayed routes must not record a client visit")
        }

        fn install_replayed(
            &self,
            target: RouteMatch,
            name: &str,
            origin: DnsOrigin<'_>,
            answer: &RouteAnswer,
            resolver: Option<&ArchiveResolver>,
        ) -> io::Result<(bool, u64)> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            assert_eq!(name, HOST);
            assert_eq!(origin.client, Some(PEER));
            assert_eq!(origin.ingress, None);
            let current = self.resolver.lock().unwrap();
            assert!(resolver
                .zip(current.as_ref())
                .is_some_and(|(a, b)| a.same(b)));
            assert_eq!(self.select(name, origin.client)?, Some(target));
            self.installs.lock().unwrap().push(RouteAnswer {
                qtype: answer.qtype,
                addresses: answer.addresses.clone(),
                ttl: answer.ttl,
            });
            Ok((false, target.revision))
        }
    }

    fn engine_fixture(
        port: u16,
        cert: &tokio_rustls::rustls::pki_types::CertificateDer<'static>,
        routes: &Arc<Observer>,
    ) -> Arc<Engine> {
        let mut raw = super::super::config::defaults();
        raw["route_mode"] = json!("auto");
        raw["awg_fallback"] = json!("off");
        raw["scheduler_enabled"] = json!(false);
        raw["cache_size"] = json!(8);
        raw["fast_dns"] = json!(false);
        raw["default_pool"] = json!([]);
        raw["rules"] = json!([]);
        raw["default_upstream"] = json!({"address":format!("https://dns.test:{port}/dns-query"),"bootstrap_ips":["127.0.0.1"]});
        raw["filtering"] = json!({"enabled":true,"lists":[],"custom_rules":[{"domain":"blocked.office.test","category":"ads"}],"allowlist":[]});
        let engine = Engine::new(
            Config::from_value(&raw).unwrap(),
            Arc::new(Mutex::new(Diagnostics::new(false))),
            Default::default(),
            shadow::Environment::unavailable(),
            Arc::new(super::super::vpn::Source::with(|| Ok(Vec::new()))),
            routes.clone(),
        );
        engine.trust(cert.clone());
        engine
    }

    fn socket_fixture(engine: Arc<Engine>) -> Handler {
        Handler::Panel {
            live: Arc::new(RwLock::new(engine)),
            peers: PeerScope::test_subnet(
                "192.168.1.1".parse().unwrap(),
                "255.255.255.0".parse().unwrap(),
            ),
        }
    }

    #[tokio::test]
    async fn managed_unmatched_lan_answers_replay_once_per_family_on_the_observed_engine() {
        let (port, cert, calls, upstream) = scripted_doh(true, None, |wire, _, kind| {
            wire[2] = 0x81;
            wire[3] = 0x80;
            wire[7] = 1;
            if kind == 1 {
                wire.extend([192, 12, 0, 1, 0, 1, 0, 0, 0, 45, 0, 4, 192, 0, 2, 16]);
            } else {
                wire.extend([192, 12, 0, 28, 0, 1, 0, 0, 0, 29, 0, 16]);
                wire.extend(
                    "2001:db8::16"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets(),
                );
            }
        })
        .await;
        let routes = Arc::new(Observer::default());
        let engine = || engine_fixture(port, &cert, &routes);
        let observed = engine();
        let gate = Arc::new(Gate::default());
        *gate.resolver.lock().unwrap() = Some(ArchiveResolver::managed(observed.clone()));
        routes.register(gate.clone());
        let handler = socket_fixture(observed.clone());
        assert!(handler.accepts(PEER));
        let local = "127.0.0.1".parse().unwrap();
        let query = |name: &str, kind, id| nfqws2_dns::build_query(name, kind, id).unwrap();
        for name in ["diagnostic.office.test", HOST] {
            observed
                .exchange(&query(name, 1, 1), "diagnostic", "api", None)
                .await
                .unwrap();
        }
        handler
            .reply(&query("internal.office.test", 1, 2), local, "udp")
            .await
            .unwrap();
        for id in [3, 4] {
            let answer = handler
                .reply(&query(HOST, 1, id), PEER, "udp")
                .await
                .unwrap();
            assert_eq!(
                nfqws2_dns::route_answer(&answer)
                    .unwrap()
                    .unwrap()
                    .addresses,
                ["192.0.2.16".parse::<IpAddr>().unwrap()]
            );
        }
        let v6 = handler
            .reply(&query(HOST, 28, 5), PEER, "tcp")
            .await
            .unwrap();
        assert_eq!(
            nfqws2_dns::route_answer(&v6).unwrap().unwrap().addresses,
            ["2001:db8::16".parse::<IpAddr>().unwrap()]
        );
        let blocked = handler
            .reply(&query("blocked.office.test", 1, 6), PEER, "udp")
            .await
            .unwrap();
        assert!(nfqws2_dns::route_answer(&blocked)
            .unwrap()
            .unwrap()
            .addresses
            .is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 4);

        gate.generation.store(1, Ordering::SeqCst);
        routes.schedule_replay(gate.replay_publication().unwrap());
        routes.finish_replay_for_test().await;
        {
            let mut installs = gate.installs.lock().unwrap();
            installs.sort_by_key(|answer| answer.qtype);
            assert_eq!(installs.len(), 2);
            assert!((39..=45).contains(&installs[0].ttl));
            assert!((23..=29).contains(&installs[1].ttl));
            assert_eq!(
                installs[0].addresses,
                ["192.0.2.16".parse::<IpAddr>().unwrap()]
            );
            assert_eq!(
                installs[1].addresses,
                ["2001:db8::16".parse::<IpAddr>().unwrap()]
            );
        }
        // Keep the old Engine alive to prove that a receipt needs the active
        // identity even when its former owner is still available to drain.
        let replacement = engine();
        *gate.resolver.lock().unwrap() = Some(ArchiveResolver::managed(replacement));
        gate.generation.store(2, Ordering::SeqCst);
        routes.schedule_replay(gate.replay_publication().unwrap());
        routes.finish_replay_for_test().await;
        assert_eq!(gate.installs.lock().unwrap().len(), 2);
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        upstream.abort();
    }

    #[tokio::test]
    async fn managed_failed_gate_preserves_servfail_and_replays_a_valid_reply_on_recovery() {
        let (port, cert, calls, upstream) = scripted_doh(true, None, |wire, name, _| {
            wire[2] = 0x81;
            wire[3] = 0x80;
            if name == "negative.office.test" {
                wire[3] = 0x83;
                return;
            }
            wire[7] = 1;
            if name == "malformed.office.test" {
                wire.extend([192, 12, 0, 1, 0, 1, 0, 0, 0, 45, 0, 3, 192, 0, 2]);
            } else {
                wire.extend([192, 12, 0, 1, 0, 1, 0, 0, 0, 45, 0, 4, 192, 0, 2, 16]);
            }
        })
        .await;
        let routes = Arc::new(Observer::default());
        let observed = engine_fixture(port, &cert, &routes);
        let handler = socket_fixture(observed.clone());
        assert!(handler.accepts(PEER));
        let gate = Arc::new(Gate::default());
        *gate.resolver.lock().unwrap() = Some(ArchiveResolver::managed(observed.clone()));
        routes.register(gate.clone());
        let query = |name: &str| nfqws2_dns::build_query(name, 1, 8).unwrap();
        let failed_reply = |wire: Vec<u8>| {
            let handler = &handler;
            async move {
                let answer = handler.reply(&wire, PEER, "udp").await.unwrap();
                assert_eq!(answer, nfqws2_dns::response_error(&wire, 2));
            }
        };
        gate.generation.store(1, Ordering::SeqCst);
        gate.failed_epoch.store(1, Ordering::SeqCst);
        failed_reply(query("applying.office.test")).await;
        gate.failed_epoch.store(40, Ordering::SeqCst);
        for name in [HOST, "negative.office.test", "malformed.office.test"] {
            failed_reply(query(name)).await;
        }
        let blocked = handler
            .reply(&query("blocked.office.test"), PEER, "udp")
            .await
            .unwrap();
        assert!(nfqws2_dns::route_answer(&blocked)
            .unwrap()
            .unwrap()
            .addresses
            .is_empty());
        let local = "127.0.0.1".parse().unwrap();
        handler
            .reply(&query("internal.office.test"), local, "udp")
            .await
            .unwrap();
        observed
            .exchange(&query("diagnostic.office.test"), "diagnostic", "api", None)
            .await
            .unwrap();

        let expired_name = "expired.office.test";
        let expired_query = query(expired_name);
        let mut expired_answer = nfqws2_dns::response_error(&expired_query, 0);
        expired_answer[7] = 1;
        expired_answer.extend([192, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 192, 0, 2, 16]);
        let receipt = super::super::routing::ManagedRecent::capture(&observed, None).unwrap();
        assert!(routes
            .prepare(
                expired_name,
                Some(PEER),
                &expired_query,
                &mut expired_answer,
                ManagedDelivery {
                    deadline: TokioInstant::now() + Duration::from_secs(8),
                    ttl_anchor: TokioInstant::now() - Duration::from_secs(2),
                    recent: Some(receipt),
                },
            )
            .await
            .is_err());
        assert_eq!(gate.attempts.load(Ordering::SeqCst), 0);
        let lookups = calls.load(Ordering::SeqCst);
        gate.generation.store(2, Ordering::SeqCst);
        gate.failed_epoch.store(0, Ordering::SeqCst);
        let recovered = gate.replay_publication().unwrap();
        routes.schedule_restored_replay(recovered);
        routes.finish_replay_for_test().await;
        {
            let installs = gate.installs.lock().unwrap();
            assert_eq!(installs.len(), 1);
            assert_eq!(installs[0].qtype, 1);
            assert_eq!(
                installs[0].addresses,
                ["192.0.2.16".parse::<IpAddr>().unwrap()]
            );
            assert!((39..=45).contains(&installs[0].ttl));
        }
        assert_eq!(gate.attempts.load(Ordering::SeqCst), 1);
        assert_eq!(calls.load(Ordering::SeqCst), lookups);
        routes.schedule_replay(recovered);
        routes.finish_replay_for_test().await;
        assert_eq!(gate.attempts.load(Ordering::SeqCst), 1);

        gate.generation.store(3, Ordering::SeqCst);
        gate.failed_epoch.store(41, Ordering::SeqCst);
        failed_reply(query(HOST)).await;
        assert_eq!(calls.load(Ordering::SeqCst), lookups);
        let replacement = engine_fixture(port, &cert, &routes);
        *gate.resolver.lock().unwrap() = Some(ArchiveResolver::managed(replacement));
        gate.generation.store(4, Ordering::SeqCst);
        gate.failed_epoch.store(0, Ordering::SeqCst);
        routes.schedule_restored_replay(gate.replay_publication().unwrap());
        routes.finish_replay_for_test().await;
        assert_eq!(gate.attempts.load(Ordering::SeqCst), 1);
        assert_eq!(calls.load(Ordering::SeqCst), lookups);
        gate.resolver.lock().unwrap().take();
        upstream.abort();
    }
}
