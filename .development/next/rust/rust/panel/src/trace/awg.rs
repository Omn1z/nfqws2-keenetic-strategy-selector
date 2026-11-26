use crate::http::{blocking, ApiError, ApiJson, Shared};
use axum::{
    extract::{Query, State},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use nfqws2_store::Store;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    net::IpAddr,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, Command},
    sync::{oneshot, Mutex as AsyncMutex},
    task::JoinHandle,
    time::{interval, timeout},
};
mod conntrack;
mod names;
mod ptr;
mod sni;
const CAP: usize = 5000;
const PACKAGE: &str = "nfqws2-strategy-trace";
type Targets = BTreeMap<String, String>;
fn wanted(db: &Store) -> io::Result<(bool, Targets)> {
    let d = nfqws2_awg_profile::read(db)?;
    let rows = d["servers"].as_array().into_iter().flatten();
    let mut map = Targets::new();
    let mut fallback = false;
    for (i, row) in rows.enumerate() {
        let c = &row["config"];
        let wire = if row["applied_config"].is_object() {
            &row["applied_config"]
        } else {
            c
        };
        if row["id"] == d["active_id"] {
            fallback = c["routing"]["trace_enabled"] == true;
        }
        if wire["endpoint"].as_str().is_none_or(|s| s.is_empty()) {
            continue;
        }
        let name = wire["client_iface"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("awg{i}"));
        if name
            .strip_prefix("awg")
            .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            && name.len() < 16
        {
            let id = row["id"].as_str().unwrap_or("");
            if id.is_empty() || id.len() > 128 {
                continue;
            }
            if map.insert(name, id.into()).is_some() {
                return Err(io::Error::other(
                    "несколько профилей используют один интерфейс AWG",
                ));
            }
        }
    }
    if map.len() > 64 {
        return Err(io::Error::other(
            "трассировка поддерживает до 64 настроенных интерфейсов AWG",
        ));
    }
    Ok((
        d["routing"]["trace_enabled"].as_bool().unwrap_or(fallback),
        map,
    ))
}
fn save(db: &Store, on: bool) -> io::Result<()> {
    nfqws2_awg_profile::edit_document(db, |d| {
        if !d["routing"].is_object() {
            let rows = d["servers"].as_array().unwrap();
            let source = rows
                .iter()
                .find(|r| r["id"] == d["active_id"])
                .or_else(|| rows.first());
            let mut routing = json!({});
            if let Some(row) = source {
                for k in ["mode", "mtu", "killswitch", "domain_source", "sni_routing"] {
                    if let Some(v) = row["config"]["routing"].get(k) {
                        routing[k] = v.clone();
                    }
                }
            }
            d["routing"] = routing;
        }
        d["routing"]["trace_enabled"] = json!(on);
        for row in d["servers"].as_array_mut().unwrap() {
            row["config"]["routing"]["trace_enabled"] = json!(on);
        }
        Ok(())
    })
}
#[derive(Deserialize, Serialize, Clone)]
struct Flow {
    src: IpAddr,
    dst: IpAddr,
    proto: String,
    sport: u16,
    dport: u16,
    event: String,
    packets: u64,
    bytes: u64,
    reply_bytes: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    state: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    unreplied: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    assured: bool,
}

#[derive(Clone)]
struct FlowRoute {
    decision: &'static str,
    rule: Option<usize>,
    reason: String,
    tunnel_id: String,
    tunnel_iface: String,
}
impl Flow {
    fn label(&self) -> String {
        match (self.proto.as_str(), self.dport) {
            ("udp", 443) => "QUIC udp/443".into(),
            ("tcp", 443) => "TLS tcp/443".into(),
            (proto @ ("tcp" | "udp"), port) if port > 0 => {
                format!("{}/{port}", proto.to_ascii_uppercase())
            }
            (proto, _) => proto.to_ascii_uppercase(),
        }
    }
}
#[derive(Serialize, Clone)]
struct Entry {
    ts: u64,
    kind: &'static str,
    decision: &'static str,
    reason: String,
    name: String,
    #[serde(flatten)]
    fields: Fields,
}
#[derive(Serialize, Clone)]
#[serde(untagged)]
enum Fields {
    Flow {
        #[serde(skip_serializing_if = "String::is_empty")]
        tunnel_id: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        tunnel_iface: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        rule: Option<usize>,
        #[serde(flatten)]
        flow: Flow,
    },
    Dns {
        #[serde(skip_serializing_if = "Option::is_none")]
        src: Option<IpAddr>,
        #[serde(skip_serializing_if = "Option::is_none")]
        dst: Option<IpAddr>,
        #[serde(skip_serializing_if = "str::is_empty")]
        qtype: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        rule: Option<usize>,
    },
    Sni {
        dst: IpAddr,
        #[serde(skip_serializing_if = "Option::is_none")]
        rule: Option<usize>,
    },
}
#[derive(Default, Serialize, Clone, Copy)]
pub(crate) struct TraceCounters {
    dns: u64,
    sni: u64,
    flow: u64,
    tunnel: u64,
    direct: u64,
    blocked: u64,
    cdn_skip: u64,
}
#[derive(Default)]
struct Ring {
    entries: VecDeque<Entry>,
    last: u64,
    recording: bool,
    limited: bool,
    observed: u64,
    conntrack: bool,
    error: String,
    sni_interfaces: u64,
    sni_error: String,
    sni_policy_error: String,
    sni_limited: bool,
    names: names::Names,
    ptr_backoff: BTreeMap<IpAddr, Instant>,
    counters: TraceCounters,
}
impl Ring {
    fn record(
        &mut self,
        kind: &'static str,
        decision: &'static str,
        entry: impl FnOnce(u64) -> Entry,
    ) {
        let count = match kind {
            "dns" => &mut self.counters.dns,
            "sni" => &mut self.counters.sni,
            "flow" => &mut self.counters.flow,
            _ => unreachable!("internal trace event kind"),
        };
        *count = count.saturating_add(1);
        let count = match decision {
            "tunnel" => &mut self.counters.tunnel,
            "direct" => &mut self.counters.direct,
            "blocked" => &mut self.counters.blocked,
            "cdn-skip" => &mut self.counters.cdn_skip,
            _ => unreachable!("internal routing decision"),
        };
        *count = count.saturating_add(1);
        if !self.recording {
            return;
        }
        // Keep the cursor exactly representable by the browser as a decimal number.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let ts = (now / 32000 * 32000).max(self.last.saturating_add(32000));
        self.last = ts;
        if self.entries.len() == CAP {
            self.entries.pop_front();
        }
        self.entries.push_back(entry(ts));
    }

    fn update(&mut self, v: Value, targets: &Targets) -> io::Result<Option<ptr::Request>> {
        if let Some(error) = v["error"].as_str() {
            return Err(io::Error::other(
                error.chars().take(220).collect::<String>(),
            ));
        }
        if v["ready"] == true {
            self.observed = v["observed_interfaces"].as_u64().unwrap_or(0).min(8);
            self.limited |= v["limited"] == true;
            return Ok(None);
        }
        let iface = v["iface"]
            .as_str()
            .ok_or_else(|| io::Error::other("неверное сообщение trace helper"))?;
        let Some(id) = targets.get(iface) else {
            return Ok(None);
        };
        let flow: Flow = serde_json::from_value(v["flow"].clone())?;
        if !matches!(flow.proto.as_str(), "tcp" | "udp" | "icmp" | "icmpv6")
            || !matches!(flow.event.as_str(), "new" | "replied" | "gone")
        {
            return Err(io::Error::other("неверное событие trace helper"));
        }
        let route = FlowRoute {
            decision: "tunnel",
            rule: None,
            reason: "Заголовок пакета на интерфейсе туннеля".into(),
            tunnel_id: id.clone(),
            tunnel_iface: iface.to_owned(),
        };
        Ok(self.flow(flow, route, ""))
    }

    fn flow(&mut self, flow: Flow, route: FlowRoute, detail: &str) -> Option<ptr::Request> {
        let name = self.names.get(flow.dst, Instant::now()).map(str::to_owned);
        let request =
            (self.recording && flow.event == "new" && name.is_none() && ptr::eligible(flow.dst))
                .then(|| ptr::Request {
                    flow: flow.clone(),
                    route: route.clone(),
                });
        self.record_flow(flow, route, name, detail);
        request
    }

    fn record_flow(&mut self, flow: Flow, route: FlowRoute, host: Option<String>, detail: &str) {
        let FlowRoute {
            decision,
            rule,
            mut reason,
            tunnel_id,
            tunnel_iface,
        } = route;
        if !detail.is_empty() {
            reason.push_str(", ");
            reason.push_str(detail);
        }
        if let Some(host) = &host {
            reason.push_str(", host=");
            reason.push_str(host);
        }
        self.record("flow", decision, |ts| Entry {
            ts,
            kind: "flow",
            decision,
            reason,
            name: host.unwrap_or_else(|| flow.label()),
            fields: Fields::Flow {
                tunnel_id,
                tunnel_iface,
                rule,
                flow,
            },
        });
    }

    fn defer_ptr(&mut self, ip: IpAddr, until: Instant) {
        const CAPACITY: usize = 4096;
        if self.ptr_backoff.len() == CAPACITY && !self.ptr_backoff.contains_key(&ip) {
            self.ptr_backoff.pop_first();
        }
        self.ptr_backoff.insert(ip, until);
    }

    fn resolved(&mut self, answer: ptr::Resolution, generation: u64) {
        if !self.recording || answer.generation != generation {
            return;
        }
        let ptr::Request { mut flow, route } = answer.request;
        let now = Instant::now();
        let address = flow.dst.to_canonical();
        if self.names.get(address, now).is_some() {
            return;
        }
        if let Some(host) = answer.host {
            self.ptr_backoff.remove(&address);
            self.names.remember(address, &host, now);
            flow.event = "host".into();
            self.record_flow(flow, route, Some(host), "Обратная DNS-запись");
        } else {
            self.defer_ptr(address, now + ptr::MISS);
        }
    }
    fn status(&self, installed: bool) -> Value {
        let source = if self.conntrack {
            "dns_and_conntrack"
        } else {
            "dns_and_tunnel_headers"
        };
        let mut v = json!({"enabled":self.recording,"count":self.entries.len(),"cap":CAP,"observed_interfaces":self.observed,"limited":self.limited || self.sni_limited,"source":source});
        if !self.error.is_empty() {
            v["error"] = json!(self.error);
        }
        if self.sni_interfaces != 0 {
            v["sni_interfaces"] = json!(self.sni_interfaces);
        }
        if !self.sni_policy_error.is_empty() {
            v["sni_error"] = json!(self.sni_policy_error);
        } else if !self.sni_error.is_empty() {
            v["sni_error"] = json!(self.sni_error);
        }
        if !installed && !self.conntrack {
            v["need_install"] = json!(true);
            v["package"] = json!(PACKAGE);
        }
        v
    }
}
struct Job {
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}
#[derive(Default)]
pub struct Service {
    job: AsyncMutex<Option<Job>>,
    ring: Arc<Mutex<Ring>>,
    resolver: ptr::Resolver,
    conntrack: conntrack::Source,
    sni: sni::Capture,
}
async fn stop(job: Option<Job>) {
    if let Some(j) = job {
        let _ = j.stop.send(());
        let _ = j.task.await;
    }
}
impl Service {
    pub(super) fn new(root: &Path) -> Self {
        let conntrack = conntrack::Source::new(root);
        let ring = Ring {
            conntrack: conntrack.available(),
            ..Ring::default()
        };
        Self {
            ring: Arc::new(Mutex::new(ring)),
            resolver: ptr::Resolver::new(root),
            conntrack,
            ..Self::default()
        }
    }

    pub(crate) fn publish_sni(
        &self,
        policy: io::Result<Option<nfqws2_awg_rules::kernel::LegacySni>>,
    ) {
        let (policy, error) = match policy {
            Ok(policy) => (policy, String::new()),
            Err(error) => (None, error.to_string().chars().take(220).collect()),
        };
        self.sni.publish(policy);
        self.ring.lock().unwrap().sni_policy_error = error;
    }

    pub async fn shutdown(&self) {
        self.sni.shutdown().await;
        let mut j = self.job.lock().await;
        stop(j.take()).await;
        self.ring.lock().unwrap().recording = false;
    }
    fn status(&self) -> Value {
        let installed = installed();
        self.ring.lock().unwrap().status(installed)
    }
    pub(crate) fn counters(&self) -> TraceCounters {
        self.ring.lock().unwrap().counters
    }

    pub(crate) fn record_dns(
        &self,
        name: &str,
        src: Option<IpAddr>,
        answer: &nfqws2_dns::TraceAnswer,
        suppressed: bool,
        decide: impl Fn(Option<IpAddr>) -> (&'static str, Option<usize>),
    ) {
        let mut ring = self.ring.lock().unwrap();
        let destinations = answer
            .addresses
            .iter()
            .copied()
            .map(Some)
            .chain(answer.addresses.is_empty().then_some(None));
        let now = Instant::now();
        for dst in destinations {
            if let Some(dst) = dst {
                ring.names.remember(dst, name, now);
            }
            let (decision, rule) = if suppressed || answer.sinkholed {
                ("blocked", None)
            } else {
                decide(dst)
            };
            ring.record("dns", decision, |ts| {
                let reason = match decision {
                    "blocked" if suppressed => "семейство адресов недоступно через туннель".into(),
                    "blocked" if dst.is_none() => {
                        "DNS upstream: пустой или отрицательный ответ".into()
                    }
                    "blocked" => "DNS upstream: null-route".into(),
                    "cdn-skip" => "общий CDN — глобальное исключение direct не добавлено".into(),
                    _ => rule.map_or_else(
                        || "нет совпадения".into(),
                        |n| format!("правило #{n} ({decision})"),
                    ),
                };
                let qtype = match answer.qtype {
                    1 => "A",
                    28 => "AAAA",
                    5 => "CNAME",
                    15 => "MX",
                    16 => "TXT",
                    33 => "SRV",
                    65 => "HTTPS",
                    _ => "",
                };
                Entry {
                    ts,
                    kind: "dns",
                    decision,
                    reason,
                    name: name.into(),
                    fields: Fields::Dns {
                        src,
                        dst,
                        qtype,
                        rule,
                    },
                }
            });
        }
    }
}
fn installed() -> bool {
    super::helper().is_ok_and(|path| path.is_file())
}
// fill_buf is cancellation-safe. Keep a bounded partial line between select!
// branches while profiles or the desired recording state are changing.
async fn frame(r: &mut (impl AsyncBufRead + Unpin), partial: &mut Vec<u8>) -> io::Result<Value> {
    loop {
        let bytes = r.fill_buf().await?;
        if bytes.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let n = bytes
            .iter()
            .position(|b| *b == b'\n')
            .map_or(bytes.len(), |i| i + 1);
        if n + partial.len() > 4096 {
            return Err(io::Error::other("сообщение trace helper превышает лимит"));
        }
        partial.extend_from_slice(&bytes[..n]);
        r.consume(n);
        if partial.last() == Some(&b'\n') {
            let v = serde_json::from_slice(partial)?;
            partial.clear();
            return Ok(v);
        }
    }
}
async fn reap(child: &mut Child) {
    child.stdin.take();
    if timeout(Duration::from_secs(2), child.wait()).await.is_err() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
}
async fn run(
    service: &Service,
    cmd: &mut Command,
    db: Store,
    dir: PathBuf,
    mut targets: Targets,
) -> io::Result<Job> {
    cmd.stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .kill_on_drop(true);
    let mut child = cmd.spawn()?;
    let mut reader = BufReader::new(child.stderr.take().unwrap());
    let mut partial = Vec::new();
    let ready = timeout(Duration::from_secs(4), frame(&mut reader, &mut partial)).await;
    let init = (|| {
        let msg = ready.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        if msg["ready"] != true {
            return Err(io::Error::other(
                msg["error"]
                    .as_str()
                    .unwrap_or("обновите пакет nfqws2-strategy-trace"),
            ));
        }
        let mut ring = service.ring.lock().unwrap();
        ring.limited = false;
        let _ = ring.update(msg, &targets)?;
        ring.recording = true;
        ring.error.clear();
        Ok::<_, io::Error>(())
    })();
    if let Err(e) = init {
        reap(&mut child).await;
        return Err(e);
    }
    let ring = service.ring.clone();
    let mut reverse = ptr::Queue::new(service.resolver.clone());
    let (send, mut recv) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(5));
        let path = dir.join("awg.json");
        let mut signature = None;
        let mut generation = 0u64;
        let outcome: io::Result<()> = async {
            loop {
                tokio::select! {
                    _ = &mut recv => return Ok(()),
                    message = frame(&mut reader,&mut partial) => {
                        let message = message?;
                        if message.get("error").is_some() || message["generation"].as_u64().unwrap_or(0) == generation {
                            let mut ring = ring.lock().unwrap();
                            if let Some(request) = ring.update(message, &targets)? {
                                reverse.request(&mut ring, request, generation);
                            }
                        }
                    }
                    answer = reverse.next(), if !reverse.is_empty() => {
                        if let Some(answer) = answer {
                            ring.lock().unwrap().resolved(answer, generation);
                        }
                    }
                    _ = tick.tick() => {
                        let stamp = tokio::fs::metadata(&path).await.ok()
                            .and_then(|v|v.modified().ok().map(|t|(v.len(),t)));
                        if stamp == signature { continue; }
                        let db = db.clone();
                        let (enabled,next) = tokio::task::spawn_blocking(move||wanted(&db)).await
                            .map_err(io::Error::other)??;
                        if !enabled { return Ok(()); }
                        if next != targets {
                            generation += 1;
                            let mut line = format!("set {generation}");
                            for name in next.keys(){ line.push(' '); line.push_str(name); }
                            line.push('\n');
                            let input = child.stdin.as_mut().unwrap();
                            timeout(Duration::from_secs(1),input.write_all(line.as_bytes())).await
                                .map_err(|_|io::Error::from(io::ErrorKind::TimedOut))??;
                            ring.lock().unwrap().observed = 0;
                            targets = next;
                        }
                        signature = stamp;
                    }
                }
            }
        }.await;
        reap(&mut child).await;
        let mut r = ring.lock().unwrap();
        r.observed = 0;
        if let Err(e) = outcome {
            r.error = e.to_string();
        } else {
            r.recording = false;
        }
    });
    Ok(Job { stop: send, task })
}
pub async fn configure(s: &Shared, enable: bool) -> Result<Value, ApiError> {
    let service = &s.trace.awg;
    let mut job = service.job.lock().await;
    configure_locked(s, enable, &mut job).await
}
async fn configure_locked(
    s: &Shared,
    enable: bool,
    job: &mut Option<Job>,
) -> Result<Value, ApiError> {
    let service = &s.trace.awg;
    if !enable {
        stop(job.take()).await;
    }
    let db = s.store.clone();
    let (was, targets) = blocking(move || wanted(&db)).await?;
    if !enable {
        service.ring.lock().unwrap().recording = false;
        if was {
            let db = s.store.clone();
            blocking(move || save(&db, false)).await?;
        }
        return Ok(service.status());
    }
    if job.as_ref().is_some_and(|j| !j.task.is_finished()) {
        return Ok(service.status());
    }
    stop(job.take()).await;
    if !was {
        let db = s.store.clone();
        blocking(move || save(&db, true)).await?;
    }
    {
        let mut ring = service.ring.lock().unwrap();
        ring.recording = true;
        ring.error.clear();
    }
    if service.conntrack.available() {
        *job = Some(conntrack::start(
            service,
            s.store.clone(),
            Path::new(&s.config.data_dir),
        ));
        return Ok(service.status());
    }
    service.ring.lock().unwrap().conntrack = false;
    let path = super::helper()?;
    if !path.is_file() {
        return Ok(service.status());
    }
    let mut cmd = Command::new(path);
    cmd.arg("awg").args(targets.keys());
    match run(
        service,
        &mut cmd,
        s.store.clone(),
        PathBuf::from(&s.config.data_dir),
        targets,
    )
    .await
    {
        Ok(task) => *job = Some(task),
        Err(e) => {
            service.ring.lock().unwrap().error = e.to_string();
        }
    }
    Ok(service.status())
}
pub async fn apply_policy(s: &Shared) -> Result<(), ApiError> {
    let mut job = s.trace.awg.job.lock().await;
    let enabled = match s.settings.trace_mode().as_str() {
        "always" => true,
        "off" => false,
        _ => return Ok(()),
    };
    configure_locked(s, enabled, &mut job).await.map(|_| ())
}
pub async fn restore(s: &Shared) {
    s.trace.awg.sni.start(s.trace.awg.ring.clone()).await;
    if let Err(e) = apply_policy(s).await {
        s.logs.append("awg2", "warn", &e.1);
    }
}
pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/awg2/trace", get(list))
        .route("/api/awg2/trace/status", get(status))
        .route("/api/awg2/trace/enabled", post(toggle))
        .route("/api/awg2/trace/clear", post(clear))
}
#[cfg(test)]
mod tests;
#[derive(Deserialize)]
struct Enabled {
    enabled: bool,
}
async fn toggle(
    State(s): State<Shared>,
    ApiJson(v): ApiJson<Enabled>,
) -> Result<Json<Value>, ApiError> {
    configure(&s, v.enabled).await.map(Json)
}
async fn status(State(s): State<Shared>) -> Json<Value> {
    Json(s.trace.awg.status())
}
async fn clear(State(s): State<Shared>) -> Json<Value> {
    let installed = installed();
    let mut r = s.trace.awg.ring.lock().unwrap();
    r.entries.clear();
    Json(r.status(installed))
}
#[derive(Deserialize)]
struct Since {
    since: Option<String>,
}
#[derive(Serialize)]
struct Snapshot<'a> {
    status: Value,
    entries: Vec<&'a Entry>,
}
async fn list(State(s): State<Shared>, Query(q): Query<Since>) -> Response {
    let since = q.since.and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    let installed = installed();
    let r = s.trace.awg.ring.lock().unwrap();
    Json(Snapshot {
        status: r.status(installed),
        entries: r.entries.iter().filter(|e| e.ts > since).collect(),
    })
    .into_response()
}
