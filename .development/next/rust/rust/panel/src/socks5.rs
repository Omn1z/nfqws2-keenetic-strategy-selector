mod protocol;
#[cfg(test)]
mod tests;

use crate::http::{blocking, ApiError, ApiJson, Shared};
use axum::{
    extract::State,
    http::{header, uri::Authority, HeaderMap},
    routing::{get, post},
    Json, Router,
};
use nfqws2_store::Store;
use portable_atomic::AtomicU64;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::TcpListener,
    sync::{oneshot, Mutex},
    task::{JoinHandle, JoinSet},
};

const FILE: &str = "socks5.json";
fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
struct Config {
    enabled: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    transport: String,
    port: u16,
    user: String,
    pass: String,
    buffer_size: i64,
    #[serde(deserialize_with = "redirects")]
    dc_redirects: BTreeMap<i32, IpAddr>,
    link_host: String,
}
fn redirects<'de, D: serde::Deserializer<'de>>(de: D) -> Result<BTreeMap<i32, IpAddr>, D::Error> {
    Ok(Option::<BTreeMap<i32, IpAddr>>::deserialize(de)?.unwrap_or_default())
}
impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: false,
            transport: String::new(),
            port: 1080,
            user: String::new(),
            pass: String::new(),
            buffer_size: 65536,
            dc_redirects: BTreeMap::new(),
            link_host: String::new(),
        }
    }
}
impl Config {
    fn transport(&self) -> &str {
        if self.transport.is_empty() {
            "telegram_wss"
        } else {
            &self.transport
        }
    }
    fn normalize(&mut self) {
        if self.port == 0 {
            self.port = 1080;
        }
        if self.buffer_size < 4096 {
            self.buffer_size = 65536;
        }
    }
    fn validate(&self, web: &str) -> io::Result<()> {
        if !matches!(self.transport(), "direct" | "telegram_wss") {
            return Err(invalid("неизвестный транспорт SOCKS5"));
        }
        if self.user.is_empty() != self.pass.is_empty()
            || self.user.len() > 255
            || self.pass.len() > 255
        {
            return Err(invalid(
                "укажите логин и пароль SOCKS5 длиной до 255 байт или оставьте оба пустыми",
            ));
        }
        if self
            .dc_redirects
            .keys()
            .any(|dc| !matches!(dc, 1..=5 | 203))
        {
            return Err(invalid("неизвестный DC"));
        }
        if self.enabled
            && web
                .rsplit_once(':')
                .and_then(|(_, p)| p.parse::<u16>().ok())
                == Some(self.port)
        {
            return Err(invalid("порт SOCKS5 занят веб-панелью"));
        }
        Ok(())
    }
}

#[derive(Default)]
struct Counters {
    total: AtomicU64,
    active: AtomicU64,
    direct: AtomicU64,
    telegram: AtomicU64,
    last_dc: AtomicU8,
    bad: AtomicU64,
    up: AtomicU64,
    down: AtomicU64,
    started: AtomicU64,
}
struct Active<'a>(&'a AtomicU64);
impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}
impl Counters {
    fn begin(&self) -> Active<'_> {
        self.total.fetch_add(1, Ordering::Relaxed);
        self.active.fetch_add(1, Ordering::Relaxed);
        Active(&self.active)
    }
    fn connected(&self, vpn_dc: Option<u8>) {
        if let Some(dc) = vpn_dc {
            self.last_dc.store(dc, Ordering::Relaxed);
            self.telegram.fetch_add(1, Ordering::Relaxed);
        } else {
            self.direct.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn snapshot(&self) -> Value {
        let value = |n: &AtomicU64| n.load(Ordering::Relaxed);
        let human = |n: u64| {
            let mut bytes = n as f64;
            for unit in ["B", "KB", "MB", "GB"] {
                if bytes < 1024.0 {
                    return format!("{bytes:.1}{unit}");
                }
                bytes /= 1024.0;
            }
            format!("{bytes:.1}TB")
        };
        let up = value(&self.up);
        let down = value(&self.down);
        json!({"connections":{"total":value(&self.total),"active":value(&self.active),"direct":value(&self.direct),"bad":value(&self.bad),"telegram":value(&self.telegram)},
               "traffic":{"bytes_up":up,"bytes_down":down,"human_up":human(up),"human_down":human(down)},"last_dc":self.last_dc.load(Ordering::Relaxed),"started_at":value(&self.started)})
    }
}
struct Live {
    listener: Arc<TcpListener>,
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}
impl Live {
    fn launch(
        listener: Arc<TcpListener>,
        cfg: Config,
        stats: Arc<Counters>,
        owner: std::sync::Weak<crate::http::AppState>,
    ) -> Self {
        let (stop, mut halted) = oneshot::channel();
        stats.started.store(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            Ordering::Relaxed,
        );
        let socket = listener.clone();
        let config = Arc::new(cfg);
        let task = tokio::spawn(async move {
            let mut clients = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    _ = &mut halted => break,
                    Some(_) = clients.join_next(), if !clients.is_empty() => {},
                    accepted = socket.accept() => {
                        match accepted {
                            Ok((tcp, peer)) => {
                                let cfg = config.clone();
                                let stats = stats.clone();
                                let owner=owner.clone();
                                clients.spawn(async move {
                                    let telegram_only = cfg.user.is_empty() && !local_client(peer.ip())
                                        && !direct_ipv6_client(&owner, &tcp, peer).await;
                                    if telegram_only && !cfg.transport.is_empty() {
                                        return;
                                    }
                                    protocol::serve(tcp, &cfg, &stats, owner, telegram_only).await;
                                });
                            }
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
                        }
                    }
                }
            }
            clients.shutdown().await;
        });
        Self {
            listener,
            stop,
            task,
        }
    }
    async fn close(self) {
        let _ = self.stop.send(());
        let _ = self.task.await;
    }
}
struct Manager {
    config: Config,
    live: Option<Live>,
}
enum Change {
    Restart,
    Restore,
    Set(Config),
    Toggle(bool),
}
pub struct Service {
    inner: Mutex<Manager>,
    stats: Arc<Counters>,
}
impl Service {
    pub(crate) async fn dashboard(&self) -> Value {
        let state = self.inner.lock().await;
        json!({"running":state.live.is_some(),"transport":state.config.transport(),"stats":self.stats.snapshot()})
    }
    pub fn open(db: &Store) -> io::Result<Self> {
        let mut config: Config = match db.read(FILE) {
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::NotFound
                        | io::ErrorKind::InvalidData
                        | io::ErrorKind::UnexpectedEof
                ) =>
            {
                Config::default()
            }
            other => other?,
        };
        config.normalize();
        Ok(Self {
            inner: Mutex::new(Manager { config, live: None }),
            stats: Default::default(),
        })
    }
    pub async fn shutdown(&self) {
        if let Some(live) = self.inner.lock().await.live.take() {
            live.close().await;
        }
    }

    async fn configure(&self, s: &Shared, change: Change) -> Result<(), ApiError> {
        let db = &s.store;
        let web = s.config.listen_addr.as_str();
        let mut state = self.inner.lock().await;
        let mut cfg = state.config.clone();
        let restart = matches!(change, Change::Restart);
        let persist = !matches!(change, Change::Restore | Change::Restart);
        let validate = !matches!(change, Change::Toggle(false));
        match change {
            Change::Set(mut new) => {
                let enabled = cfg.enabled;
                if new.transport.is_empty() {
                    new.transport.clone_from(&cfg.transport);
                }
                cfg = new;
                cfg.enabled = enabled;
            }
            Change::Toggle(enabled) => cfg.enabled = enabled,
            Change::Restore if !cfg.enabled => return Ok(()),
            Change::Restart if !cfg.enabled => return Err(invalid("прокси выключен").into()),
            Change::Restore | Change::Restart => {}
        }
        cfg.normalize();
        if validate {
            cfg.validate(web)?;
        }
        if !restart && cfg == state.config && cfg.enabled == state.live.is_some() {
            return Ok(());
        }
        let listener = if cfg.enabled {
            match &state.live {
                Some(old) if cfg.port == state.config.port => Some(old.listener.clone()),
                _ => Some(Arc::new(
                    nfqws2_tgws_transport::bind_wildcard(cfg.port).map_err(|e| {
                        invalid(format!("не удалось открыть порт {}: {e}", cfg.port))
                    })?,
                )),
            }
        } else {
            None
        };
        if persist {
            let store = db.clone();
            let saved = cfg.clone();
            blocking(move || store.transaction(|tx| tx.save(FILE, &saved))).await?;
        }
        if let Some(old) = state.live.take() {
            old.close().await;
        }
        state.live = listener
            .map(|socket| Live::launch(socket, cfg.clone(), self.stats.clone(), Arc::downgrade(s)));
        state.config = cfg;
        Ok(())
    }
}
fn local_client(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local(),
    }
}

async fn direct_ipv6_client(
    owner: &std::sync::Weak<crate::http::AppState>,
    tcp: &tokio::net::TcpStream,
    peer: SocketAddr,
) -> bool {
    let (Ok(SocketAddr::V6(local)), SocketAddr::V6(peer)) = (tcp.local_addr(), peer) else {
        return false;
    };
    let (local, peer) = (*local.ip(), *peer.ip());
    if local.octets()[0] & 0xe0 != 0x20 || peer.octets()[0] & 0xe0 != 0x20 {
        return false;
    }
    let Some(state) = owner.upgrade() else {
        return false;
    };
    tokio::task::spawn_blocking(move || {
        state
            .bridge_mac
            .same_ipv6_lan(&state.config.wan_ifaces, local, peer)
    })
    .await
    .unwrap_or(false)
}
pub async fn auto_start(s: &Shared) -> Result<(), ApiError> {
    s.socks5.configure(s, Change::Restore).await
}
pub(crate) async fn restart(s: &Shared) -> Result<(), ApiError> {
    s.socks5.configure(s, Change::Restart).await
}
fn escape(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else if b == b' ' {
            out.push('+');
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}
async fn view(s: &Shared, h: &HeaderMap) -> Json<Value> {
    let state = s.socks5.inner.lock().await;
    let cfg = &state.config;
    let header = h
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<Authority>().ok());
    let guessed;
    let host = if let Some(header) = &header {
        header.host().trim_matches(['[', ']'])
    } else if !cfg.link_host.is_empty() {
        &cfg.link_host
    } else {
        guessed = if cfg.transport.is_empty() {
            nfqws2_tgws_config::local_link_host()
        } else {
            s.config
                .listen_addr
                .parse::<SocketAddr>()
                .ok()
                .map(|a| a.ip().to_string())
                .unwrap_or_else(|| "127.0.0.1".into())
        };
        &guessed
    };
    let mut link = format!("tg://socks?server={}&port={}", escape(host), cfg.port);
    if !cfg.user.is_empty() {
        link.push_str(&format!(
            "&user={}&pass={}",
            escape(&cfg.user),
            escape(&cfg.pass)
        ));
    }
    Json(
        json!({"running":state.live.is_some(),"config":cfg,"stats":s.socks5.stats.snapshot(),"link":link,"transport":cfg.transport()}),
    )
}
async fn status(State(s): State<Shared>, h: HeaderMap) -> Json<Value> {
    view(&s, &h).await
}
async fn config(
    State(s): State<Shared>,
    h: HeaderMap,
    ApiJson(v): ApiJson<Config>,
) -> Result<Json<Value>, ApiError> {
    apply(s, h, Change::Set(v)).await
}
async fn apply(s: Shared, h: HeaderMap, change: Change) -> Result<Json<Value>, ApiError> {
    let worker = s.clone();
    // Finish persisted listener changes even when an HTTP client disconnects.
    tokio::spawn(async move { worker.socks5.configure(&worker, change).await })
        .await
        .map_err(|e| io::Error::other(e.to_string()))??;
    Ok(view(&s, &h).await)
}
pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/socks5", get(status))
        .route("/api/socks5/config", post(config))
        .route(
            "/api/socks5/start",
            post(|State(s): State<Shared>, h: HeaderMap| apply(s, h, Change::Toggle(true))),
        )
        .route(
            "/api/socks5/stop",
            post(|State(s): State<Shared>, h: HeaderMap| apply(s, h, Change::Toggle(false))),
        )
}
