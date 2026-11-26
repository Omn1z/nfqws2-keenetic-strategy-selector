use crate::{assets, data};
mod stream;
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, FromRequest, Path, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use nfqws2_auth::{login_cookie, session_token, Auth, LOGOUT_COOKIE};
use nfqws2_config::Config;
use nfqws2_store::Store;
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};
use std::{io, path::Path as FsPath, sync::Arc};
pub(crate) use stream::json_stream;

pub struct AppState {
    pub update: crate::update::Updater,
    pub restart: tokio::sync::watch::Sender<bool>,
    pub arpblock: crate::arpblock::Service,
    pub bridge_mac: crate::bridge_mac::Service,
    pub awg_runtime: Arc<nfqws2_awg_profile::runtime::Runtime>,
    pub route_kernel: crate::awg_rules::kernel::Service,
    pub awg_installer: tokio::sync::Mutex<()>,
    pub watchdog: std::sync::Mutex<crate::engine::automation::Health>,
    pub auto_pick: crate::engine::automation::Picker,
    pub speedtest: Arc<tokio::sync::Mutex<()>>,
    pub ports: crate::ports::Ports,
    pub config: Config,
    pub store: Store,
    pub auth: Auth,
    pub dnsserver: crate::dnsserver::Service,
    pub geo: crate::geo::GeoState,
    pub logs: nfqws2_monitor::LogBuffer,
    pub settings: crate::settings::Settings,
    pub monitor: crate::monitor::MonitorState,
    pub port_hook: std::path::PathBuf,
    pub backup_paths: Vec<std::path::PathBuf>,
    pub blockcheck: crate::blockcheck::BlockCheckState,
    pub runs: crate::runs::RunsState,
    pub trace: crate::trace::TraceState,
    pub socks5: crate::socks5::Service,
    pub tgws: crate::tgws::Service,
    pub proxy_fallback: crate::tgws::fallback::Cache,
    pub active_test: Arc<std::sync::atomic::AtomicBool>,
}
pub type Shared = Arc<AppState>;

impl AppState {
    #[cfg(test)]
    pub fn open(config: Config, router_root: &FsPath, forced_off: bool) -> io::Result<Shared> {
        Self::open_with_log(config, router_root, forced_off, None)
    }
    pub fn open_with_log(
        config: Config,
        router_root: &FsPath,
        forced_off: bool,
        log_path: Option<&FsPath>,
    ) -> io::Result<Shared> {
        let store = Store::open(&config.data_dir)?;
        let socks5 = crate::socks5::Service::open(&store)?;
        let tgws = crate::tgws::Service::open(&store)?;
        let auth = Auth::open(FsPath::new(&config.data_dir), router_root, forced_off)?;
        let proxy_log = log_path.map(|p| {
            let mut name = p.as_os_str().to_owned();
            name.push(".proxy");
            name.into()
        });
        let logs = nfqws2_monitor::LogBuffer::new(Box::new(std::io::stderr()), proxy_log);
        let settings = crate::settings::Settings::load(&store, &logs)?;
        let monitor = crate::monitor::MonitorState::new(router_root, &config.wan_ifaces);
        let backup_paths = crate::backup::system_paths(router_root);
        let port_hook = nfqws2_config::Resolver::new_at(router_root)
            .path(nfqws2_config::Key::PortForwardHook)
            .to_path_buf();
        let awg_runtime = Arc::new(nfqws2_awg_profile::runtime::Runtime::new(
            router_root,
            nfqws2_config::Resolver::new_at(router_root)
                .path(nfqws2_config::Key::AwgEngineDir)
                .join("amneziawg-go"),
        ));
        Ok(Arc::new(Self {
            update: Default::default(),
            restart: tokio::sync::watch::channel(false).0,
            arpblock: crate::arpblock::Service::new(router_root),
            bridge_mac: crate::bridge_mac::Service::new(router_root),
            awg_installer: Default::default(),
            route_kernel: crate::awg_rules::kernel::Service::new(router_root),
            watchdog: Default::default(),
            auto_pick: Default::default(),
            speedtest: Default::default(),
            awg_runtime: awg_runtime.clone(),
            ports: Default::default(),
            dnsserver: crate::dnsserver::Service::new(
                store.clone(),
                &config.data_dir,
                router_root,
                config.wan_ifaces.clone(),
                awg_runtime,
            ),
            config,
            store,
            auth,
            geo: Default::default(),
            logs,
            settings,
            monitor,
            port_hook,
            backup_paths,
            blockcheck: Default::default(),
            runs: Default::default(),
            trace: crate::trace::TraceState::new(router_root),
            socks5,
            tgws,
            proxy_fallback: Default::default(),
            active_test: Default::default(),
        }))
    }
}

pub struct ApiError(pub StatusCode, pub String);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": self.1}))).into_response()
    }
}
impl From<io::Error> for ApiError {
    fn from(err: io::Error) -> Self {
        let status = match err.kind() {
            io::ErrorKind::NotFound => StatusCode::NOT_FOUND,
            io::ErrorKind::InvalidInput => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        Self(status, err.to_string())
    }
}
pub struct ApiJson<T>(pub T);
impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for ApiJson<T> {
    type Rejection = ApiError;
    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|e| ApiError(e.status(), e.to_string()))?;
        serde_json::from_slice(&bytes)
            .map(Self)
            .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))
    }
}
pub async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "worker stopped".into()))?
        .map_err(Into::into)
}

pub fn router(state: Shared) -> Router {
    Router::new()
        .merge(crate::dns::routes())
        .merge(crate::dnsserver::routes())
        .merge(crate::editor::routes())
        .merge(crate::engine::routes())
        .merge(crate::geo::routes())
        .merge(crate::settings::routes())
        .merge(crate::monitor::routes())
        .merge(crate::packages::routes())
        .merge(crate::update::routes())
        .merge(crate::blobs::routes())
        .merge(crate::backup::routes())
        .merge(crate::portforward::routes())
        .merge(crate::ports::routes())
        .route("/api/system/restart", post(restart))
        .merge(crate::blockcheck::routes())
        .merge(crate::awg_profiles::routes())
        .merge(crate::awg_rules::routes())
        .route(
            "/api/nfqws2/paths",
            post(analyze_paths).layer(DefaultBodyLimit::max(2 << 20)),
        )
        .merge(crate::trace::routes())
        .merge(crate::socks5::routes())
        .merge(crate::tgws::routes())
        .merge(crate::arpblock::routes())
        .merge(crate::bridge_mac::routes())
        .route("/api/auth/status", get(status))
        .route("/api/auth/login", post(login))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/config", post(auth_config))
        .route(
            "/api/config",
            get(|State(s): State<Shared>| async move { Json(s.config.clone()) }),
        )
        .route("/api/lists", get(lists).post(save_list))
        .route("/api/lists/{id}", get(list).delete(delete_list))
        .route("/api/strategies", get(strategies).post(save_strategy))
        .route("/api/strategies/{id}", delete(delete_strategy))
        .route("/api/strategies/sni", get(sni).post(save_sni))
        .merge(crate::runs::routes())
        .fallback(assets::serve)
        .layer(DefaultBodyLimit::max(8 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), gate))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::settings::access_log,
        ))
        .with_state(state)
}

async fn restart(State(s): State<Shared>) -> Result<Json<Value>, ApiError> {
    if s.update.running() {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "идёт обновление панели".into(),
        ));
    }
    s.restart.send_replace(true);
    Ok(Json(json!({"status":"restarting"})))
}

pub(crate) fn token(headers: &HeaderMap) -> &str {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .map(session_token)
        .find(|s| !s.is_empty())
        .unwrap_or_default()
}
async fn gate(State(s): State<Shared>, req: Request, next: Next) -> Response {
    if req.uri().path().starts_with("/api/") && !req.method().is_safe() {
        if let Some(origin) = req.headers().get(header::ORIGIN) {
            let parsed = origin
                .to_str()
                .ok()
                .and_then(|s| s.parse::<axum::http::Uri>().ok());
            let host = req
                .headers()
                .get(header::HOST)
                .and_then(|h| h.to_str().ok());
            if !parsed.is_some_and(|uri| {
                matches!(uri.scheme_str(), Some("http" | "https"))
                    && uri
                        .authority()
                        .zip(host)
                        .is_some_and(|(a, h)| a.as_str().eq_ignore_ascii_case(h))
            }) {
                return ApiError(StatusCode::FORBIDDEN, "cross-origin request".into())
                    .into_response();
            }
        }
    }
    if s.auth.allows(req.uri().path(), token(req.headers())) {
        next.run(req).await
    } else {
        ApiError(StatusCode::UNAUTHORIZED, "unauthorized".into()).into_response()
    }
}
async fn status(State(s): State<Shared>, h: HeaderMap) -> Json<Value> {
    Json(
        json!({"enabled":s.auth.enabled(),"authed":s.auth.valid_session(token(&h)),"version":s.config.version}),
    )
}
#[derive(Deserialize)]
struct Credentials {
    user: String,
    password: String,
}
async fn login(
    State(s): State<Shared>,
    ApiJson(creds): ApiJson<Credentials>,
) -> Result<Response, ApiError> {
    let token = blocking(move || s.auth.login(&creds.user, &creds.password))
        .await?
        .ok_or_else(|| ApiError(StatusCode::UNAUTHORIZED, "неверный логин или пароль".into()))?;
    Ok(([(header::SET_COOKIE, login_cookie(&token))], ok()).into_response())
}
async fn logout(State(s): State<Shared>, h: HeaderMap) -> Response {
    s.auth.logout(token(&h));
    ([(header::SET_COOKIE, LOGOUT_COOKIE)], ok()).into_response()
}
#[derive(Deserialize)]
struct Toggle {
    enabled: bool,
}
async fn auth_config(
    State(s): State<Shared>,
    ApiJson(t): ApiJson<Toggle>,
) -> Result<Json<Value>, ApiError> {
    blocking(move || {
        s.auth.set_enabled(t.enabled)?;
        Ok(Json(json!({"enabled":s.auth.enabled()})))
    })
    .await
}
fn ok() -> Json<Value> {
    Json(json!({"status":"ok"}))
}
#[derive(Deserialize)]
struct EditorDocument {
    #[serde(default)]
    content: String,
    #[serde(default)]
    kind: String,
}
async fn analyze_paths(
    State(s): State<Shared>,
    ApiJson(doc): ApiJson<EditorDocument>,
) -> Result<Json<nfqws2_config::Analysis>, ApiError> {
    blocking(move || {
        Ok(Json(nfqws2_config::analyze_paths(
            &s.config,
            &doc.content,
            &doc.kind,
        )))
    })
    .await
}
async fn lists(State(s): State<Shared>) -> Result<Json<Vec<data::List>>, ApiError> {
    blocking(move || data::lists(&s.store).map(Json)).await
}
async fn list(
    State(s): State<Shared>,
    Path(id): Path<String>,
) -> Result<Json<data::List>, ApiError> {
    blocking(move || data::list(&s.store, &id).map(Json)).await
}
async fn save_list(
    State(s): State<Shared>,
    ApiJson(list): ApiJson<data::List>,
) -> Result<Json<data::List>, ApiError> {
    blocking(move || data::save_list(&s.store, list).map(Json)).await
}
async fn delete_list(
    State(s): State<Shared>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    blocking(move || data::delete_list(&s.store, &id)).await?;
    Ok(ok())
}
async fn strategies(State(s): State<Shared>) -> Result<Json<Vec<data::Strategy>>, ApiError> {
    blocking(move || data::strategies(&s.store).map(Json)).await
}
async fn save_strategy(
    State(s): State<Shared>,
    ApiJson(v): ApiJson<data::Strategy>,
) -> Result<Json<data::Strategy>, ApiError> {
    blocking(move || data::save_strategy(&s.store, v).map(Json)).await
}
async fn delete_strategy(
    State(s): State<Shared>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    blocking(move || data::delete_strategy(&s.store, &id)).await?;
    Ok(ok())
}
#[derive(Deserialize)]
struct Sni {
    domains: Option<Vec<String>>,
}
const SNI_FILE: &str = "sni_domains.json";
async fn sni(State(s): State<Shared>) -> Result<Json<Value>, ApiError> {
    blocking(move || Ok(Json(json!({"domains":data::or_default::<Option<Vec<String>>>(&s.store, SNI_FILE)?.unwrap_or_default()})))).await
}
async fn save_sni(
    State(s): State<Shared>,
    ApiJson(v): ApiJson<Sni>,
) -> Result<Json<Value>, ApiError> {
    blocking(move || {
        let domains = data::clean_lines(v.domains.unwrap_or_default());
        s.store.transaction(|tx| tx.save(SNI_FILE, &domains))?;
        Ok(Json(json!({"domains":domains})))
    })
    .await
}
