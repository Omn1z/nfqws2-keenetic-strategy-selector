mod diagnostics;
mod discovery;
mod inform;
mod inform_runtime;
mod lease_store;
mod leases;
mod network;
mod observer;
mod ppp;
mod renew;
pub(crate) use discovery::{defaults as wan_defaults, native as native_wan};
pub(crate) use ppp::interface_records;
#[cfg(test)]
mod tests;
use super::config::{domain, invalid};
use discovery::{Firmware, Peer, Source};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, VecDeque},
    io,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::{
    sync::{watch, Mutex as AsyncMutex, Semaphore},
    time::{timeout, timeout_at},
};

pub fn normalize(v: &mut Value) -> io::Result<()> {
    let mut indices = HashMap::new();
    let mut domains = Vec::<Value>::new();
    for r in v["domains"]
        .as_array()
        .ok_or_else(|| invalid("Shadow DNS: ожидался список доменов"))?
    {
        let raw = r["domain"].as_str().unwrap_or("").trim();
        let suffix = raw.strip_prefix("*.").or_else(|| raw.strip_prefix('.'));
        let pattern = suffix.unwrap_or(raw);
        let pattern = pattern.strip_suffix('.').unwrap_or(pattern);
        let mut has_literal = false;
        let mut parts = Vec::new();
        for label in pattern.split('.') {
            if label == "*" {
                parts.push("*".into());
                continue;
            }
            let p = domain(label)?;
            if p.contains('.') {
                return Err(invalid("Shadow DNS: недопустимая метка"));
            }
            has_literal = true;
            parts.push(p);
        }
        let name = parts.join(".");
        if !has_literal || name.len() > 253 {
            return Err(invalid("Shadow DNS: укажите доменную зону"));
        }
        let children = suffix.is_some() || r["include_subdomains"].as_bool().unwrap_or(false);
        if let Some(&i) = indices.get(&name) {
            if children {
                let row: &mut Value = &mut domains[i];
                row["include_subdomains"] = json!(true);
            }
        } else {
            indices.insert(name.clone(), domains.len());
            domains.push(json!({"domain":name,"include_subdomains":children}));
        }
    }
    if domains.is_empty() && v["enabled"] == true {
        return Err(invalid("Shadow DNS: добавьте хотя бы один домен"));
    }
    v["domains"] = Value::Array(domains);
    v["servers"] = json!([]);
    Ok(())
}
#[derive(Default)]
pub struct Matcher {
    children: HashMap<Box<str>, Matcher>,
    exact: bool,
    descendants: bool,
}
impl Matcher {
    pub fn compile(v: &Value) -> Option<Self> {
        if v["enabled"] != true {
            return None;
        }
        let mut root = Self::default();
        for r in v["domains"].as_array().into_iter().flatten() {
            let mut node = &mut root;
            for label in r["domain"].as_str().unwrap_or("").rsplit('.') {
                if !node.children.contains_key(label) {
                    node.children.insert(label.into(), Self::default());
                }
                node = node.children.get_mut(label).unwrap();
            }
            node.exact = true;
            node.descendants |= r["include_subdomains"] == true;
        }
        Some(root)
    }
    pub fn matches(&self, name: &str) -> bool {
        if self.descendants {
            return true;
        }
        if name.is_empty() {
            return self.exact;
        }
        let (rest, label) = name.rsplit_once('.').unwrap_or(("", name));
        self.children.get(label).is_some_and(|n| n.matches(rest))
            || self.children.get("*").is_some_and(|n| n.matches(rest))
    }
}

fn now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}
fn future(d: Duration) -> String {
    (OffsetDateTime::now_utc() + d)
        .format(&Rfc3339)
        .unwrap_or_default()
}
#[derive(Default)]
struct Log {
    scope: Option<watch::Sender<()>>,
    seq: u64,
    entries: VecDeque<Value>,
}
#[derive(Default)]
pub struct Diagnostics(Arc<Mutex<Log>>);
impl Diagnostics {
    pub fn set(&self, on: bool) {
        let mut l = self.0.lock().unwrap();
        if on {
            l.scope.get_or_insert_with(|| watch::channel(()).0);
        } else {
            l.scope = None;
            l.entries.clear();
        }
    }
    pub fn read(&self) -> Value {
        let l = self.0.lock().unwrap();
        let captured = OffsetDateTime::now_utc();
        let mut attempts = l.entries.clone();
        let mut in_progress = false;
        for attempt in &mut attempts {
            if attempt.get("finished_at").is_some() {
                continue;
            }
            in_progress = true;
            if let Some(started) = attempt["started_at"]
                .as_str()
                .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
            {
                let elapsed = (captured - started).whole_milliseconds().max(0);
                attempt["duration_ms"] = json!(u64::try_from(elapsed).unwrap_or(u64::MAX));
            }
        }
        let go_arch = match std::env::consts::ARCH {
            "aarch64" => "arm64",
            "x86_64" => "amd64",
            "x86" => "386",
            "mips" if cfg!(target_endian = "little") => "mipsle",
            "mips64" if cfg!(target_endian = "little") => "mips64le",
            "powerpc64" if cfg!(target_endian = "little") => "ppc64le",
            "powerpc64" => "ppc64",
            "loongarch64" => "loong64",
            arch => arch,
        };
        json!({"version":1,"enabled":l.scope.is_some(),"app_version":crate::VERSION,
            "platform":format!("{}/{go_arch}",std::env::consts::OS),
            "captured_at":captured.format(&Rfc3339).unwrap_or_default(),"in_progress":in_progress,"attempts":attempts})
    }
    fn begin(&self, stage: &str, message: &str) -> Event<'_> {
        let mut l = self.0.lock().unwrap();
        if l.scope.is_none() {
            return Event {
                log: self,
                id: None,
                started: Instant::now(),
            };
        }
        l.seq += 1;
        let id = l.seq;
        if l.entries.len() == 6 {
            l.entries.pop_front();
        }
        let first = diagnostics::row(stage, message, Duration::ZERO);
        l.entries.push_back(
            json!({"id":id,"started_at":now(),"duration_ms":0,"servers":[],"events":[first]}),
        );
        Event {
            log: self,
            id: Some(id),
            started: Instant::now(),
        }
    }
}
struct Event<'a> {
    log: &'a Diagnostics,
    id: Option<u64>,
    started: Instant,
}
impl Event<'_> {
    fn trace(&self) -> diagnostics::Trace {
        diagnostics::Trace::new(&self.log.0, self.id)
    }

    fn step(&self, stage: &str, message: &str) {
        self.trace().step(stage, message);
    }

    fn timed(&self, stage: &str, message: &str, duration: Duration) {
        self.trace().timed(stage, message, duration);
    }

    fn finish(mut self, peers: &[Peer], error: &str, retry: Duration) {
        self.timed(
            "discovery.result",
            &format!(
                "Допустимых DNS-серверов: {}; ошибка: {}",
                peers.len(),
                !error.is_empty()
            ),
            self.started.elapsed(),
        );
        self.record(
            peers.iter().map(|peer| peer.addr.to_string()).collect(),
            error,
            Some(retry),
        );
    }
    fn record(&mut self, servers: Vec<String>, error: &str, retry: Option<Duration>) {
        let Some(id) = self.id.take() else { return };
        let mut l = self.log.0.lock().unwrap();
        let Some(row) = l.entries.iter_mut().find(|v| v["id"] == id) else {
            return;
        };
        row["finished_at"] = json!(now());
        row["duration_ms"] =
            json!(u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX));
        let servers: Vec<_> = servers
            .into_iter()
            .filter_map(|server| {
                server
                    .parse::<std::net::SocketAddr>()
                    .ok()
                    .map(|server| server.to_string())
            })
            .take(8)
            .collect();
        row["servers"] = json!(servers);
        let error = diagnostics::message(error);
        if !error.is_empty() {
            row["error"] = json!(error);
        }
        if let Some(d) = retry {
            row["next_retry_at"] = json!(future(d));
        }
    }
}
impl Drop for Event<'_> {
    fn drop(&mut self) {
        self.record(Vec::new(), "проверка отменена", None);
    }
}

#[derive(Default)]
struct State {
    servers: Vec<String>,
    error: String,
    fallback: Option<Instant>,
    probing: bool,
    gen: u64,
}
struct Cached {
    updated: Instant,
    until: Instant,
    peers: Arc<[Peer]>,
    error: String,
    revision: Option<(u64, u64)>,
}

#[derive(Default)]
struct Discovery {
    cached: Option<Cached>,
    history: Vec<discovery::History>,
    history_loaded: bool,
    completed: Option<(Instant, io::Result<discovery::Evidence>)>,
}
pub struct Environment {
    source: Arc<dyn Source>,
    pub diagnostics: Diagnostics,
    renewal: renew::Renewal,
    observer: Arc<AsyncMutex<observer::Slot>>,
    leases: Option<Arc<lease_store::File>>,
    inform: Mutex<inform_runtime::Runtime>,
}
impl Environment {
    pub fn new(wan: Vec<String>) -> Self {
        Self {
            source: Arc::new(Firmware(wan.clone())),
            diagnostics: Default::default(),
            renewal: renew::Renewal::new(wan),
            observer: Default::default(),
            leases: None,
            inform: Default::default(),
        }
    }
    pub(super) fn with_lease_file(
        mut self,
        store: nfqws2_store::Store,
        router_root: &std::path::Path,
    ) -> Self {
        self.leases = Some(Arc::new(lease_store::File::new(
            store,
            router_root.to_owned(),
        )));
        self
    }
    #[cfg(test)]
    pub(super) fn unavailable() -> Arc<Self> {
        struct Offline;
        impl Source for Offline {
            fn read(&self, _: &[discovery::History]) -> io::Result<discovery::Evidence> {
                Err(io::ErrorKind::NotFound.into())
            }
        }
        Arc::new(Self {
            source: Arc::new(Offline),
            diagnostics: Default::default(),
            renewal: renew::Renewal::fixture(false),
            observer: Default::default(),
            leases: None,
            inform: Default::default(),
        })
    }
}
pub struct Session {
    pub matcher: Matcher,
    env: Arc<Environment>,
    cache: Arc<AsyncMutex<Discovery>>,
    state: Arc<Mutex<State>>,
    stopped: watch::Sender<bool>,
}
impl Session {
    #[cfg(test)]
    fn fixture(cfg: &Value, env: Arc<Environment>) -> Option<Self> {
        Self::new(cfg, env, watch::channel(false).0)
    }

    pub(super) fn new(
        cfg: &Value,
        env: Arc<Environment>,
        stopped: watch::Sender<bool>,
    ) -> Option<Self> {
        Some(Self {
            matcher: Matcher::compile(cfg)?,
            env,
            cache: Default::default(),
            state: Default::default(),
            stopped,
        })
    }
    pub fn status(&self) -> Value {
        let s = self.state.lock().unwrap();
        let mut v = json!({"enabled":true,"automatic":true,"servers":s.servers,"error":s.error,"fallback_active":s.fallback.is_some(),"renewal_available":self.env.renewal.available(),"diagnostics":self.env.diagnostics.read()});
        if let Some(t) = s.fallback {
            v["next_probe_at"] = json!(future(t.saturating_duration_since(Instant::now())));
        }
        v
    }
    async fn discover(&self, force: bool) -> io::Result<Arc<[Peer]>> {
        self.read_provider(force, None).await
    }

    async fn read_provider(
        &self,
        force: bool,
        manual: Option<&Event<'_>>,
    ) -> io::Result<Arc<[Peer]>> {
        let requested = Instant::now();
        let mut cache = self.cache.clone().lock_owned().await;
        let lifecycle = self.stopped.subscribe();
        if *lifecycle.borrow() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let mut slot = self.env.observer.clone().lock_owned().await;
        if *lifecycle.borrow() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let revision = slot.reader(&lifecycle).and_then(|reader| {
            let snapshot = reader.snapshot();
            (snapshot.sequence != 0).then(|| reader.revision(&snapshot))
        });
        if let Some(c) = cache.cached.as_ref().filter(|c| {
            (!force || c.updated >= requested) && c.until > Instant::now() && c.revision == revision
        }) {
            return if c.error.is_empty() {
                Ok(c.peers.clone())
            } else {
                Err(invalid(c.error.clone()))
            };
        }
        let event = manual.is_none().then(|| {
            self.env
                .diagnostics
                .begin("discovery.start", "Чтение DNS активного WAN")
        });
        let trail = manual.or(event.as_ref()).unwrap();
        let trace = trail.trace();
        let deadline = Instant::now() + Duration::from_secs(2);
        if cache.completed.as_ref().is_none_or(|(at, _)| {
            (force && *at < requested) || at.elapsed() >= Duration::from_secs(2)
        }) {
            let env = self.env.clone();
            // The worker retains the read gate, but only a live waiter may
            // publish cache state or consume a capture sequence.
            let trace = trace.clone();
            (cache, slot) = tokio::task::spawn_blocking(move || {
                let mut saved = env
                    .leases
                    .as_ref()
                    .map(|file| file.snapshot())
                    .unwrap_or_default();
                if !cache.history_loaded {
                    cache.history = std::mem::take(&mut saved.leases)
                        .into_iter()
                        .map(|(iface, lease)| discovery::History::from_saved(iface, lease))
                        .collect();
                    cache.history_loaded = true;
                }
                let known = env.inform.lock().unwrap().known(saved.targets);
                if env.leases.is_some() {
                    trace.step(
                        "state.loaded",
                        &format!(
                            "Сохранённые аренды: {}; известные DHCP-серверы: {}",
                            cache.history.len(),
                            known.len()
                        ),
                    );
                }
                let result = env
                    .source
                    .read_traced(&cache.history, &known, deadline, &trace);
                cache.completed = Some((Instant::now(), result));
                (cache, slot)
            })
            .await
            .map_err(io::Error::other)?;
        }
        if *lifecycle.borrow() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let (_, evidence) = cache.completed.take().unwrap();
        let previous = slot
            .reader(&lifecycle)
            .map(|reader| &reader.target.candidate);
        let target = evidence
            .as_ref()
            .ok()
            .and_then(|evidence| self.env.source.target(evidence, previous));
        let reader = match slot.reconcile(&lifecycle, target).await {
            Ok(reader) => reader,
            Err(error) if error.kind() == io::ErrorKind::Interrupted && *lifecycle.borrow() => {
                return Err(error)
            }
            Err(_) => {
                trail.step("native.capture", "Наблюдение штатного DHCP недоступно");
                None
            }
        };
        let snapshot = reader.as_ref().map(observer::Reader::snapshot);
        let mut revision = None;
        let mut receipt = None;
        if let Some((reader, snapshot)) = reader.as_ref().zip(snapshot.as_ref()) {
            let device = &reader.target.candidate.device;
            let started = snapshot.started.format(&Rfc3339).unwrap_or_default();
            let mut message = format!(
                "{device}: наблюдение с {started}; штатных REQUEST={}, связанных ответов={}",
                snapshot.requests, snapshot.sequence
            );
            if snapshot.sequence == 0 {
                message.push_str("; ожидается штатное обновление DHCP-аренды Keenetic (может занять несколько часов)");
            }
            if snapshot.failed {
                message.push_str("; ошибка чтения DHCP");
            }
            trail.step("native.capture", &message);
            if let Some(observed) = snapshot.receipt.as_ref() {
                let (outcome, dns, lease) = match &observed.observation {
                    renew::capture::Observation::Dns {
                        servers,
                        lease_seconds,
                        ..
                    } => ("ack", servers.len(), Some(*lease_seconds)),
                    renew::capture::Observation::AckNoDns => ("ack_no_dns", 0, None),
                    renew::capture::Observation::Nak => ("nak", 0, Some(0)),
                };
                let at = observed.observed_at.format(&Rfc3339).unwrap_or_default();
                let mut summary = format!("{device}: {outcome} в {at}; DNS={dns}");
                if let Some(lease) = lease {
                    summary.push_str(&format!("; срок аренды={lease} с"));
                }
                trail.step("native.capture.result", &summary);
                revision = Some(reader.revision(snapshot));
                receipt = Some((&reader.target, observed));
            }
        }
        if *lifecycle.borrow() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let persist = evidence
            .as_ref()
            .is_ok_and(discovery::Evidence::has_authority_for_leases);
        let mut target_update = None;
        let mut result = match evidence {
            Ok(evidence) => {
                let key = evidence.wan_key.clone();
                let discovered = evidence.finish_inform(receipt);
                cache.history = discovered.history;
                let input = inform_runtime::input(&key, &discovered.inform, discovered.source);
                let plan = self.env.inform.lock().unwrap().plan(
                    &discovered.inform,
                    input,
                    discovered.native_applied.as_ref().zip(revision),
                    tokio::time::Instant::now(),
                    &trace,
                );
                let selection = match plan {
                    inform::state::Plan::Ready(selection) => selection,
                    inform::state::Plan::Probe(attempt) if Instant::now() < deadline => {
                        let owner = attempt.wan().clone();
                        let exact_deadline = tokio::time::Instant::from_std(deadline);
                        let budget = deadline.saturating_duration_since(Instant::now());
                        let work = async {
                            let before = Instant::now();
                            let verified =
                                inform_runtime::confirmed(&self.env.source, &owner, deadline).await;
                            trail.timed(
                                "wan.verify",
                                &format!(
                                    "{}: текущий WAN для DHCPINFORM подтверждён={verified}",
                                    owner.iface
                                ),
                                before.elapsed(),
                            );
                            if !verified {
                                return Err(io::Error::from(io::ErrorKind::Interrupted));
                            }
                            inform_runtime::report_start(
                                trail,
                                &owner,
                                attempt.target().server,
                                budget,
                            );
                            let started = Instant::now();
                            let result = attempt.exchange(exact_deadline, &trace).await;
                            let elapsed = started.elapsed();
                            if result.is_ok()
                                && !inform_runtime::confirmed(&self.env.source, &owner, deadline)
                                    .await
                            {
                                trail.timed(
                                    "dhcp.finish",
                                    "Ответ DHCPINFORM отклонён после смены WAN",
                                    elapsed,
                                );
                                return Err(io::Error::from(io::ErrorKind::Interrupted));
                            }
                            Ok((result, elapsed))
                        };
                        let mut active = lifecycle.clone();
                        let retained_reader =
                            reader.as_ref().zip(snapshot.as_ref().map(|s| s.sequence));
                        let (measured, elapsed) = tokio::select! {
                            biased;
                            _ = inform_runtime::superseded(&mut active, retained_reader, exact_deadline) => return Err(io::ErrorKind::Interrupted.into()),
                            measured = work => measured?,
                        };
                        trail.timed(
                            "dhcp.finish",
                            match &measured {
                                Ok(_) => "Получен подтверждённый DHCP ACK",
                                Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                                    "Истекло окно ответа DHCPINFORM"
                                }
                                Err(_) => "Допустимый DHCP ACK не получен",
                            },
                            elapsed,
                        );
                        let selection = self.env.inform.lock().unwrap().state.finish_report(
                            attempt,
                            measured,
                            input,
                            tokio::time::Instant::now(),
                            exact_deadline,
                            |event| inform_runtime::report_discovery(&trace, event),
                        );
                        if let inform::state::Selection::Inform(options) = &selection {
                            if options.wan != owner
                                && !inform_runtime::confirmed(
                                    &self.env.source,
                                    &options.wan,
                                    deadline,
                                )
                                .await
                            {
                                return Err(io::ErrorKind::Interrupted.into());
                            }
                        }
                        if retained_reader.is_some_and(|(reader, baseline)| {
                            reader.snapshot().sequence != baseline
                        }) {
                            return Err(io::ErrorKind::Interrupted.into());
                        }
                        selection
                    }
                    inform::state::Plan::Probe(_) => inform::state::Selection::Fallback(None),
                };
                if !key.is_empty() {
                    target_update = Some((key, discovered.inform));
                }
                inform_runtime::apply(selection, discovered.result, &discovered.ppp)
            }
            Err(error) => Err(error),
        };
        let _publication = if let Some(file) = self.env.leases.clone().filter(|_| persist) {
            let leases = cache
                .history
                .iter()
                .rev()
                .take(lease_store::MAX_RECORDS)
                .map(|lease| (lease.iface.clone(), lease.to_saved()))
                .collect();
            let active = lifecycle.clone();
            let env = self.env.clone();
            // Serialize disk publication with ownership handoff, including when
            // the HTTP or DNS caller cancels while writing the shared receipt.
            tokio::task::spawn_blocking(move || {
                if !*active.borrow() {
                    let targets = target_update.and_then(|(key, proof)| {
                        let saved = file.snapshot().targets;
                        env.inform.lock().unwrap().targets(saved, &key, &proof)
                    });
                    let _ = file.update(leases, targets);
                }
                slot
            })
            .await
            .map_err(io::Error::other)?
        } else {
            slot
        };
        if *lifecycle.borrow() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        if let Ok(peers) = &mut result {
            let now = Instant::now();
            peers.retain(|peer| peer.expires.is_none_or(|expires| expires > now));
        }
        let (peers, error): (Arc<[Peer]>, String) = match result {
            Ok(v) if (1..=8).contains(&v.len()) => (v.into(), String::new()),
            Err(e) if e.kind() == io::ErrorKind::TimedOut => (
                Arc::from([]),
                "истекло время чтения DNS активного WAN".into(),
            ),
            Err(e) if e.kind() == io::ErrorKind::Unsupported => (
                Arc::from([]),
                "прошивка не поддерживает чтение DNS активного WAN".into(),
            ),
            _ => (
                Arc::from([]),
                "активный WAN не сообщил подходящий DNS провайдера".into(),
            ),
        };
        let interval = Duration::from_secs(if error.is_empty() { 60 } else { 30 });
        let now = Instant::now();
        let until = peers
            .iter()
            .filter_map(|p| p.expires)
            .fold(now + interval, Instant::min);
        cache.cached = Some(Cached {
            updated: now,
            until,
            peers: peers.clone(),
            error: error.clone(),
            revision,
        });
        if !force || !peers.is_empty() {
            self.state.lock().unwrap().servers = peers.iter().map(|p| p.addr.to_string()).collect();
        }
        if let Some(event) = event {
            event.finish(&peers, &error, until.saturating_duration_since(now));
        }
        if error.is_empty() {
            Ok(peers)
        } else {
            Err(invalid(error))
        }
    }
    pub(super) fn renewal_request(&self) -> io::Result<renew::Request<'_>> {
        renew::Request::new(self)
    }
    pub async fn provider(
        &self,
        query: &[u8],
        budget: Duration,
        slots: &Semaphore,
        on_failure: impl Fn(&str, Duration, &io::Error),
    ) -> io::Result<(Vec<u8>, String)> {
        let mut attempt = {
            let mut s = self.state.lock().unwrap();
            if s.fallback.is_some_and(|t| Instant::now() < t || s.probing) {
                return Err(invalid(s.error.clone()));
            }
            let recovery = s.fallback.is_some();
            if recovery {
                s.probing = true;
            }
            ProviderGuard {
                state: &self.state,
                generation: s.gen,
                recovery,
            }
        };
        let deadline = tokio::time::Instant::now() + budget;
        let work = async {
            let peers = self.discover(false).await?;
            let _slot = slots.acquire().await.map_err(io::Error::other)?;
            for (i, p) in peers.iter().enumerate() {
                let time = deadline.saturating_duration_since(tokio::time::Instant::now())
                    / (peers.len() - i) as u32;
                let started = Instant::now();
                let result = timeout(time, network::exchange(p, query))
                    .await
                    .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()));
                match result {
                    Ok(wire) => return Ok((wire, p.addr.to_string())),
                    Err(error) => on_failure(&p.addr.to_string(), started.elapsed(), &error),
                }
            }
            Err(io::Error::other(
                "DNS провайдера не вернул допустимый ответ через WAN",
            ))
        };
        let result = timeout_at(deadline, work)
            .await
            .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()));
        attempt.complete(result.as_ref().err());
        result
    }
}
struct ProviderGuard<'a> {
    state: &'a Mutex<State>,
    generation: u64,
    recovery: bool,
}
impl ProviderGuard<'_> {
    fn complete(&mut self, error: Option<&io::Error>) {
        let mut s = self.state.lock().unwrap();
        if s.gen != self.generation {
            return;
        }
        if let Some(err) = error {
            s.error = err.to_string();
            s.fallback = Some(Instant::now() + Duration::from_secs(30));
            s.gen = s.gen.wrapping_add(1);
        } else {
            if s.fallback.take().is_some() {
                s.gen = s.gen.wrapping_add(1);
            }
            s.error.clear();
        }
        s.probing = false;
        self.recovery = false;
    }
}
impl Drop for ProviderGuard<'_> {
    fn drop(&mut self) {
        if self.recovery {
            let mut s = self.state.lock().unwrap();
            if s.gen == self.generation {
                s.probing = false;
            }
        }
    }
}
