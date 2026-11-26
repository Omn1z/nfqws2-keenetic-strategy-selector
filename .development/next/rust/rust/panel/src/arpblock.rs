mod clients;
mod native;
mod parse;
mod revision;
#[cfg(test)]
mod tests;

use crate::http::{ApiError, ApiJson, Shared};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use clients::Client;
use parse::Topology;
use serde::{Deserialize, Serialize};
use std::{
    future::Future,
    io,
    path::Path,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, OwnedMutexGuard};

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}
fn bad(e: impl ToString) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, e.to_string())
}
#[derive(Clone, Serialize)]
struct Segment {
    id: String,
    name: String,
    address: String,
    members: Vec<String>,
    ssids: Vec<String>,
    enabled: bool,
    up: bool,
    eligible: bool,
    reason: String,
    home: bool,
}
#[derive(Clone, Serialize)]
struct View {
    platform: &'static str,
    supported: bool,
    reason: String,
    revision: String,
    segments: Vec<Segment>,
    clients: Vec<Client>,
    checked_at: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Change {
    segment: String,
    enabled: bool,
    revision: String,
}
pub trait Execute: Send + Sync + 'static {
    fn command(&self, arg: &str) -> impl Future<Output = io::Result<String>> + Send;
}
type Cache = Option<(Instant, View)>;
pub struct Service<B = native::Native> {
    platform: &'static str,
    reason: &'static str,
    backend: Arc<B>,
    cache: Arc<Mutex<Cache>>,
}
impl Service {
    pub fn new(root: &Path) -> Self {
        let (backend, platform, reason) = native::Native::detect(root);
        Self {
            platform,
            reason,
            backend: Arc::new(backend),
            cache: Default::default(),
        }
    }
}
impl<B: Execute> Service<B> {
    fn owned(&self) -> Self {
        Self {
            platform: self.platform,
            reason: self.reason,
            backend: self.backend.clone(),
            cache: self.cache.clone(),
        }
    }
    async fn inspect(&self) -> io::Result<(View, Topology)> {
        let mut view = View {
            platform: self.platform,
            supported: self.platform == "keenetic",
            reason: self.reason.into(),
            revision: String::new(),
            segments: Vec::new(),
            clients: Vec::new(),
            checked_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        if !view.supported {
            return Ok((view, Topology::default()));
        }
        let raw = self.backend.command("show running-config").await?;
        let cfg = parse::topology(&raw)?;
        // The revision contains only parsed topology. Router secrets and unknown
        // configuration fields never enter the digest or response.
        view.revision = revision::token(&cfg)?;
        for bridge in &cfg.bridges {
            let mut ssids = Vec::new();
            for ap in &cfg.aps {
                if !ap.ssid.is_empty()
                    && !ssids.contains(&ap.ssid)
                    && bridge.members.iter().any(|m| m == &ap.id || m == &ap.alias)
                {
                    ssids.push(ap.ssid.clone());
                }
            }
            let reason = bridge
                .eligible()
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default();
            let name = [&bridge.description, &bridge.alias, &bridge.id]
                .into_iter()
                .find(|v| !v.is_empty())
                .unwrap();
            view.segments.push(Segment {
                id: bridge.id.clone(),
                name: name.clone(),
                address: bridge.address.clone(),
                members: bridge.members.clone(),
                ssids,
                enabled: bridge.isolation.unwrap_or(false),
                up: bridge.up,
                eligible: reason.is_empty(),
                reason,
                home: bridge.id == "Bridge0" || bridge.alias == "Home",
            });
        }
        Ok((view, cfg))
    }
    async fn finish(&self, mut view: View, cfg: &Topology, cache: &mut Cache) -> View {
        if view.supported {
            match self.backend.command("show associations").await {
                Ok(associations) => {
                    let leases = self
                        .backend
                        .command("show ip dhcp bindings")
                        .await
                        .unwrap_or_else(|_| {
                            view.reason = "Адреса и имена клиентов недоступны".into();
                            String::new()
                        });
                    view.clients = clients::clients(cfg, &associations, &leases);
                }
                Err(_) => view.reason = "Не удалось прочитать Wi-Fi клиентов".into(),
            }
        }
        *cache = Some((Instant::now(), view.clone()));
        view
    }
    async fn view(&self) -> io::Result<View> {
        let mut cache = self.cache.lock().await;
        if let Some((at, v)) = &*cache {
            if at.elapsed() < Duration::from_secs(5) {
                return Ok(v.clone());
            }
        }
        let (view, cfg) = self.inspect().await?;
        Ok(self.finish(view, &cfg, &mut cache).await)
    }
    async fn apply_flag(&self, id: &str, enabled: bool) -> io::Result<(View, Topology)> {
        let negation = if enabled { "" } else { "no " };
        self.backend
            .command(&format!("interface {id} {negation}peer-isolation"))
            .await?;
        let (v, cfg) = self.inspect().await?;
        if !cfg
            .bridges
            .iter()
            .any(|b| b.id == id && b.isolation.unwrap_or(false) == enabled)
        {
            return Err(invalid("Keenetic не подтвердил изменение изоляции"));
        }
        self.backend.command("system configuration save").await?;
        Ok((v, cfg))
    }
    async fn mutate(
        self,
        mut cache: OwnedMutexGuard<Cache>,
        id: String,
        enabled: bool,
        previous: bool,
    ) -> Result<View, ApiError> {
        match self.apply_flag(&id, enabled).await {
            Ok((v, cfg)) => Ok(self.finish(v, &cfg, &mut cache).await),
            Err(e) => match self.apply_flag(&id, previous).await {
                Ok(_) => Err(bad(format!("{e}; предыдущая настройка восстановлена"))),
                Err(_) => Err(bad(format!(
                    "{e}; возврат настройки не подтверждён. Проверьте изоляцию сегмента в Keenetic"
                ))),
            },
        }
    }
    async fn change(&self, change: Change) -> Result<View, ApiError> {
        if !parse::bridge(&change.segment)
            || change.revision.len() != 64
            || !change.revision.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(bad(
                "нужны segment, enabled и revision текущей конфигурации",
            ));
        }
        let mut cache =
            tokio::time::timeout(Duration::from_secs(45), self.cache.clone().lock_owned())
                .await
                .map_err(|_| bad("контроллер занят"))?;
        *cache = None;
        let (view, cfg) = self.inspect().await.map_err(bad)?;
        if !view.supported {
            return Err(bad(view.reason));
        }
        if view.revision != change.revision {
            return Err(ApiError(
                StatusCode::CONFLICT,
                "настройки сегментов изменились; обновите данные и проверьте выбранный сегмент"
                    .into(),
            ));
        }
        let b = cfg
            .bridges
            .iter()
            .find(|b| b.id == change.segment)
            .ok_or_else(|| bad("сегмент не найден"))?;
        b.eligible().map_err(bad)?;
        let status = self
            .backend
            .command(&format!("show interface {}", b.id))
            .await
            .map_err(bad)?;
        b.confirm(&status).map_err(bad)?;
        let previous = b.isolation.unwrap_or(false);
        if previous == change.enabled {
            return Ok(self.finish(view, &cfg, &mut cache).await);
        }
        // Once mutation begins, verification or rollback must survive disconnect.
        tokio::spawn(
            self.owned()
                .mutate(cache, change.segment, change.enabled, previous),
        )
        .await
        .map_err(|_| bad("контроллер остановлен"))?
    }
}
async fn get_view(State(s): State<Shared>) -> Result<Json<View>, ApiError> {
    tokio::time::timeout(Duration::from_secs(20), s.arpblock.view())
        .await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "контроллер занят".into()))?
        .map(Json)
        .map_err(|e| ApiError(StatusCode::SERVICE_UNAVAILABLE, e.to_string()))
}
async fn set(State(s): State<Shared>, ApiJson(v): ApiJson<Change>) -> Result<Json<View>, ApiError> {
    s.arpblock.change(v).await.map(Json)
}
async fn no_store(req: axum::extract::Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    res.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    res
}
pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/arp-block", get(get_view))
        .route(
            "/api/arp-block/isolation",
            post(set).layer(DefaultBodyLimit::max(2048)),
        )
        .layer(middleware::from_fn(no_store))
}
