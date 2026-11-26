use crate::http::{blocking, ApiError, ApiJson, Shared};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{header, uri::Authority, HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use nfqws2_store::Store;
use nfqws2_tgws_config::Config;
use serde_json::{json, Value};
use std::{io, path::PathBuf, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::Mutex,
    time::timeout,
};
mod diagnostics;
mod document;
pub(crate) mod fallback;
mod stats;
#[cfg(test)]
mod tests;
const FILE: &str = "tgws.json";
const PACKAGE: &str = "nfqws2-strategy-tgws";
fn bad(s: impl ToString) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, s.to_string())
}
enum Change {
    Restart,
    Config(Box<Config>),
    Enabled(bool),
    Restore,
    Secret,
}
struct Worker {
    _fallback: fallback::Bridge,
    fallback_capable: bool,
    final_stats: bool,
    previous_stats: Value,
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    diagnostics: diagnostics::Capture,
}
fn helper() -> io::Result<PathBuf> {
    let name = format!("nfqws2-tgws{}", std::env::consts::EXE_SUFFIX);
    #[cfg(feature = "compact")]
    {
        Ok(crate::assets::module_dir().join("tgws").join(name))
    }
    #[cfg(not(feature = "compact"))]
    {
        Ok(std::env::current_exe()?.with_file_name(name))
    }
}
impl Worker {
    async fn line(&mut self) -> io::Result<Value> {
        let mut bytes = Vec::new();
        let n = timeout(
            Duration::from_secs(5),
            (&mut self.output).take(8193).read_until(b'\n', &mut bytes),
        )
        .await
        .map_err(|_| io::Error::other("TG WS не ответил"))??;
        if n == 0 || n > 8192 || bytes.last() != Some(&b'\n') {
            return Err(io::Error::other(
                "TG WS остановлен или вернул некорректный ответ",
            ));
        }
        Ok(serde_json::from_slice(&bytes)?)
    }
    async fn launch(
        path: &std::path::Path,
        handshake_runtime: &std::path::Path,
        web: &str,
        cfg: &Config,
        owner: std::sync::Weak<crate::http::AppState>,
        previous_stats: &Value,
    ) -> io::Result<(Self, Value)> {
        let (_, webport) = web
            .rsplit_once(':')
            .ok_or_else(|| io::Error::other("неверный адрес панели"))?;
        if webport.parse::<u16>().ok() == Some(cfg.port) {
            return Err(io::Error::other("порт TG WS занят веб-панелью"));
        }
        let broker = fallback::Bridge::start(owner.clone())?;
        let mut child = Command::new(path)
            .kill_on_drop(true)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        let diagnostics = diagnostics::Capture::start(child.stderr.take().unwrap(), owner);
        let mut bytes = serde_json::to_vec(
            &json!({"listen":format!("0.0.0.0:{}",cfg.port),"config":cfg,"fallback_socket":broker.path,"handshake_runtime":handshake_runtime}),
        )?;
        bytes.push(b'\n');
        input.write_all(&bytes).await?;
        let mut worker = Self {
            _fallback: broker,
            fallback_capable: false,
            final_stats: false,
            previous_stats: previous_stats.clone(),
            child,
            input,
            output,
            diagnostics,
        };
        let ready = worker.line().await?;
        if ready["ready"] != true {
            return Err(io::Error::other(
                ready["error"]
                    .as_str()
                    .unwrap_or("TG WS не готов к приёму клиентов")
                    .to_string(),
            ));
        }
        if cfg.transport.is_empty() && ready["legacy_direct"] != true {
            let _ = worker.stop().await;
            return Err(io::Error::other("Для сохранённых маршрутов MTProto обновите пакет nfqws2-strategy-tgws вместе с панелью"));
        }
        if ready["shared_handshakes"] != true {
            let _ = worker.stop().await;
            return Err(io::Error::other("Для общей очереди SOCKS5 и MTProto обновите пакет nfqws2-strategy-tgws вместе с панелью"));
        }
        if cfg.configured_tls_relays() && ready["configured_tls_relays"] != true
            || cfg.uses_upstream_catalog() && ready["upstream_cf_catalog"] != true
            || cfg.disable_secure
                && cfg.uses_upstream_catalog()
                && ready["upstream_catalog_plain_ws"] != true
            || cfg.uses_alternate_sni()
                && ready[if cfg.transport.is_empty() {
                    "legacy_alternate_sni"
                } else {
                    "verified_alternate_sni"
                }] != true
            || !cfg.fake_tls_domain.is_empty() && ready["authenticated_ee_https"] != true
            || cfg.disable_secure
                && cfg.configured_tls_relays()
                && ready["configured_plain_ws"] != true
        {
            let _ = worker.stop().await;
            return Err(io::Error::other(
                "Для выбранного режима MTProto обновите модуль TG WS вместе с панелью",
            ));
        }
        if cfg.h2_media() && ready["configured_h2_media"] != true
            || cfg.pool_size > nfqws2_tgws_config::OLD_POOL_LIMIT
                && ready[if cfg.transport.is_empty() {
                    "legacy_large_pool"
                } else {
                    "native_large_pool"
                }] != true
        {
            let _ = worker.stop().await;
            return Err(io::Error::other(
                "Для выбранного HTTP/2 или размера пула обновите модуль TG WS вместе с панелью",
            ));
        }
        worker.fallback_capable = ready["vpn_fallback"] == true;
        worker.final_stats = ready["final_stats"] == true;
        Ok((
            worker,
            stats::cumulative(previous_stats, ready["stats"].clone())?,
        ))
    }
    async fn stats(&mut self) -> io::Result<Value> {
        self.input.write_all(b"status\n").await?;
        let sample = self.line().await?;
        stats::cumulative(&self.previous_stats, sample)
    }
    async fn stop(mut self) -> Option<Value> {
        let mut last = None;
        let graceful = async {
            if !self.final_stats {
                last = self.stats().await.ok();
            }
            self.input.write_all(b"stop\n").await?;
            if self.final_stats {
                let sample = self.line().await?;
                last = Some(stats::cumulative(&self.previous_stats, sample)?);
            }
            self.child.wait().await?;
            Ok::<(), io::Error>(())
        };
        if !matches!(timeout(Duration::from_secs(2), graceful).await, Ok(Ok(()))) {
            let _ = self.child.kill().await;
        }
        self.diagnostics.finish().await;
        last
    }
}
struct Current {
    cfg: Config,
    child: Option<Worker>,
    stats: Value,
    error: String,
}
impl Current {
    async fn stop(&mut self) {
        if let Some(child) = self.child.take() {
            if let Some(last) = child.stop().await {
                self.stats = last;
            }
            self.stats["connections"]["active"] = json!(0);
        }
    }
}
pub struct Service {
    state: Mutex<Current>,
    helper: PathBuf,
    handshake_runtime: PathBuf,
    handshakes: std::sync::OnceLock<nfqws2_tgws_transport::Handshakes>,
}
fn empty_stats() -> Value {
    json!({"connections":{"total":0,"active":0,"ws":0,"h2":0,"tcp_fallback":0,"cfproxy":0,"fronting":0,"bad":0,"masked":0},
    "traffic":{"bytes_up":0,"bytes_down":0,"human_up":"0.0B","human_down":"0.0B"},"ws":{"errors":0,"pool_hits":0,"pool_misses":0,"cf_pool_hits":0,"cf_pool_misses":0},
    "h2":{"tcp_connections":0,"requests":0,"errors":0,"replays":0},"started_at":0})
}
impl Service {
    pub(crate) fn handshakes(&self) -> io::Result<&nfqws2_tgws_transport::Handshakes> {
        if let Some(slots) = self.handshakes.get() {
            return Ok(slots);
        }
        let slots = nfqws2_tgws_transport::Handshakes::prepare(&self.handshake_runtime)?;
        Ok(self.handshakes.get_or_init(|| slots))
    }
    pub fn open(db: &Store) -> io::Result<Self> {
        let (mut cfg, mut error) = db.transaction(|tx| {
            let (mut cfg, mut error, create) = match document::load(db) {
                Ok(v) => {
                    let missing = v.secret.is_empty();
                    (v, String::new(), missing)
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    (Config::default(), String::new(), true)
                }
                Err(_) => (
                    Config::default(),
                    "Не удалось прочитать TG WS config".into(),
                    false,
                ),
            };
            match cfg.normalize() {
                Err(e) => error = e.to_string(),
                Ok(()) if create => document::save(tx, db, &cfg)?,
                Ok(()) => {}
            }
            Ok((cfg, error))
        })?;
        if cfg.enabled && (!error.is_empty() || !cfg.requires_go().is_empty()) {
            if error.is_empty() {
                error = format!(
                    "Для настроек «{}» требуется Go TG WS",
                    cfg.requires_go().join(", ")
                );
            }
            cfg.enabled = false;
        }
        Ok(Self {
            state: Mutex::new(Current {
                cfg,
                child: None,
                stats: empty_stats(),
                error,
            }),
            helper: helper()?,
            handshake_runtime: std::path::absolute(db.private_runtime_dir())?,
            handshakes: Default::default(),
        })
    }
    pub async fn shutdown(&self) {
        self.state.lock().await.stop().await;
    }
    async fn update(
        &self,
        db: &Store,
        web: &str,
        change: Change,
        owner: std::sync::Weak<crate::http::AppState>,
    ) -> Result<(), ApiError> {
        let mut state = self.state.lock().await;
        let mut cfg = state.cfg.clone();
        let restart = matches!(change, Change::Restart)
            || state.child.is_some() && matches!(change, Change::Enabled(true) | Change::Config(_));
        let remember_failed_start =
            matches!(change, Change::Enabled(true)) && !cfg.enabled && state.child.is_none();
        let persist = !matches!(change, Change::Restore | Change::Restart);
        let explicit_config = matches!(change, Change::Config(_));
        let stop = matches!(change, Change::Enabled(false));
        match change {
            Change::Config(mut v) => {
                let enabled = cfg.enabled;
                v.transport.clone_from(&cfg.transport);
                if v.secret.is_empty() {
                    v.secret.clone_from(&cfg.secret);
                }
                cfg = *v;
                cfg.enabled = enabled;
            }
            Change::Restore if !cfg.enabled => return Ok(()),
            Change::Restart if !cfg.enabled => return Err(bad("прокси выключен")),
            Change::Restore | Change::Restart => {}
            Change::Enabled(on) => cfg.enabled = on,
            Change::Secret => cfg.secret = nfqws2_tgws_config::secret()?,
        }
        if !stop {
            cfg.normalize().map_err(bad)?;
        }
        if cfg.enabled {
            let requires = cfg.requires_go();
            if !requires.is_empty() {
                return Err(bad(format!(
                    "Для настроек «{}» требуется Go TG WS",
                    requires.join(", ")
                )));
            }
            if !self.helper.is_file() {
                return Err(ApiError(
                    StatusCode::FAILED_DEPENDENCY,
                    format!("Для TG WS установите {PACKAGE}"),
                ));
            }
            self.handshakes().map_err(bad)?;
        }
        if !restart
            && cfg == state.cfg
            && cfg.enabled == state.child.is_some()
            && state.error.is_empty()
        {
            return Ok(());
        }
        let was_running = state.child.is_some();
        state.stop().await;
        let result = async {
            if cfg.enabled {
                let (child, stats) = Worker::launch(
                    &self.helper,
                    &self.handshake_runtime,
                    web,
                    &cfg,
                    owner.clone(),
                    &state.stats,
                )
                .await
                .map_err(|error| {
                    // Keep an explicit start request so saving a corrected
                    // configuration retries the worker. Persist only after ready.
                    if remember_failed_start {
                        state.cfg.enabled = true;
                    }
                    bad(error)
                })?;
                state.child = Some(child);
                state.stats = stats;
            }
            if persist {
                let saved = cfg.clone();
                let store = db.clone();
                blocking(move || document::persist(&store, &saved, explicit_config)).await?;
            }
            Ok::<(), ApiError>(())
        }
        .await;
        if let Err(e) = result {
            state.stop().await;
            state.error = e.1.clone();
            if was_running {
                match Worker::launch(
                    &self.helper,
                    &self.handshake_runtime,
                    web,
                    &state.cfg,
                    owner,
                    &state.stats,
                )
                .await
                {
                    Ok((child, stats)) => {
                        state.child = Some(child);
                        state.stats = stats;
                    }
                    Err(_) => state
                        .error
                        .push_str(". Перезапустить прежний TG WS не удалось"),
                }
            }
            return Err(ApiError(e.0, state.error.clone()));
        }
        state.cfg = cfg;
        state.error.clear();
        Ok(())
    }
}
pub async fn auto_start(s: &Shared) -> Result<(), ApiError> {
    s.tgws
        .update(
            &s.store,
            &s.config.listen_addr,
            Change::Restore,
            std::sync::Arc::downgrade(s),
        )
        .await
}
pub(crate) async fn restart(s: &Shared) -> Result<(), ApiError> {
    s.tgws
        .update(
            &s.store,
            &s.config.listen_addr,
            Change::Restart,
            std::sync::Arc::downgrade(s),
        )
        .await
}
async fn update(s: &Shared, change: Change) -> Result<(), ApiError> {
    let s = s.clone();
    tokio::spawn(async move {
        s.tgws
            .update(
                &s.store,
                &s.config.listen_addr,
                change,
                std::sync::Arc::downgrade(&s),
            )
            .await
    })
    .await
    .map_err(io::Error::other)?
}
pub(crate) async fn snapshot(s: &Shared, h: &HeaderMap) -> Json<Value> {
    let mut state = s.tgws.state.lock().await;
    if let Some(w) = state.child.as_mut() {
        match w.stats().await {
            Ok(stats) => state.stats = stats,
            Err(e) => {
                state.stop().await;
                state.error = e.to_string();
                state.stats["connections"]["active"] = json!(0);
            }
        }
    }
    let authority = h
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<Authority>().ok());
    let host = authority
        .as_ref()
        .map(|v| v.host().trim_matches(['[', ']']))
        .unwrap_or("");
    Json(
        json!({"running":state.child.is_some(),"upstream_version":nfqws2_tgws_config::UPSTREAM_VERSION,"config":state.cfg,"stats":state.stats,"link":state.cfg.link(host),
        "native":{"package":PACKAGE,"can_install":cfg!(feature="compact"),"installed":s.tgws.helper.is_file(),"requires_go":state.cfg.requires_go(),"last_error":state.error,"vpn_fallback":state.child.as_ref().map(|w|w.fallback_capable)}}),
    )
}
async fn status(State(s): State<Shared>, h: HeaderMap) -> Json<Value> {
    snapshot(&s, &h).await
}
async fn save(
    State(s): State<Shared>,
    h: HeaderMap,
    ApiJson(v): ApiJson<document::Fields>,
) -> Result<Json<Value>, ApiError> {
    update(&s, Change::Config(Box::new(document::request(v)?))).await?;
    Ok(snapshot(&s, &h).await)
}
async fn enable(s: Shared, h: HeaderMap, on: bool) -> Result<Json<Value>, ApiError> {
    update(&s, Change::Enabled(on)).await?;
    Ok(snapshot(&s, &h).await)
}
async fn rotate(State(s): State<Shared>) -> Result<Json<Value>, ApiError> {
    update(&s, Change::Secret).await?;
    Ok(Json(json!({"secret":s.tgws.state.lock().await.cfg.secret})))
}
pub fn routes() -> Router<Shared> {
    Router::new()
        .merge(fallback::routes())
        .route("/api/tgws", get(status))
        .route(
            "/api/tgws/config",
            post(save).layer(DefaultBodyLimit::max(64 << 10)),
        )
        .route(
            "/api/tgws/start",
            post(|State(s): State<Shared>, h: HeaderMap| enable(s, h, true)),
        )
        .route(
            "/api/tgws/stop",
            post(|State(s): State<Shared>, h: HeaderMap| enable(s, h, false)),
        )
        .route("/api/tgws/secret", post(rotate))
}
