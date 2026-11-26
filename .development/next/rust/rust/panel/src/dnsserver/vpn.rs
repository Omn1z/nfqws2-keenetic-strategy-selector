use super::config::Config;
use nfqws2_awg_profile::runtime::Runtime;
use nfqws2_store::Store;
use serde::Serialize;
use std::{
    collections::HashSet,
    io,
    sync::Arc,
    time::{Duration, Instant},
};
// Go reserves DNS route slots 0 and 127 for NFQWS and Shadow DNS.
const AWG_ROUTES: usize = 126;
use tokio::sync::Mutex;

#[derive(Clone, Debug)]
pub(super) struct Route {
    pub id: String,
    pub name: String,
    pub interface: String,
    pub available: bool,
    pub index: u32,
}
#[derive(Serialize)]
pub(super) struct RouteStatus<'a> {
    id: &'a str,
    name: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    interface: &'a str,
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<&'static str>,
}
impl Route {
    pub fn system() -> Self {
        Self {
            id: "nfqws".into(),
            name: "Системный маршрут".into(),
            interface: String::new(),
            available: true,
            index: 0,
        }
    }
    pub fn allowed(&self, cfg: &Config) -> bool {
        if self.id == "nfqws" {
            cfg.route_mode != "vpn_only"
        } else {
            cfg.awg_fallback == "auto"
                || self.id.strip_prefix("awg:") == Some(cfg.awg_fallback.as_str())
        }
    }
    pub fn device(&self) -> Option<(&str, u32)> {
        (self.id != "nfqws").then_some((&self.interface, self.index))
    }
    pub fn status(&self, cfg: &Config, running: bool) -> RouteStatus<'_> {
        let error = match self.id.as_str() {
            "nfqws" if !running => Some("сервис выключен"),
            "nfqws" if cfg.route_mode == "vpn_only" => Some("DNS настроен только через VPN"),
            _ if !self.available => Some("туннель выключен или восстанавливается"),
            _ => None,
        };
        RouteStatus {
            id: &self.id,
            name: &self.name,
            interface: &self.interface,
            available: error.is_none(),
            error,
        }
    }
}
type Loader = dyn Fn() -> io::Result<Vec<Route>> + Send + Sync;
struct Discovery {
    loaded: Instant,
    routes: Arc<Vec<Route>>,
}
pub(super) struct Source {
    read: Arc<Loader>,
    cached: Arc<Mutex<Option<Discovery>>>,
}
impl Source {
    pub fn new(db: Store, awg: Arc<Runtime>) -> Self {
        Self::with(move || {
            Ok(nfqws2_awg_profile::dns_routes(&db, &awg)?
                .into_iter()
                .map(|r| Route {
                    id: format!("awg:{}", r.id),
                    name: r.label,
                    interface: r.iface,
                    available: r.ifindex.is_some(),
                    index: r.ifindex.unwrap_or(0),
                })
                .collect())
        })
    }
    pub fn with(read: impl Fn() -> io::Result<Vec<Route>> + Send + Sync + 'static) -> Self {
        Self {
            read: Arc::new(read),
            cached: Default::default(),
        }
    }
    pub async fn all(&self) -> io::Result<Arc<Vec<Route>>> {
        let cached = self.cached.clone().lock_owned().await;
        if let Some(hit) = cached
            .as_ref()
            .filter(|d| d.loaded.elapsed() < Duration::from_secs(2))
        {
            return Ok(hit.routes.clone());
        }
        let read = self.read.clone();
        // The blocking task retains the lock if an HTTP request is canceled.
        tokio::task::spawn_blocking(move || {
            let mut cached = cached;
            let mut routes = vec![Route::system()];
            let mut seen = HashSet::new();
            routes.extend(read()?.into_iter().filter(|route| {
                route.id.starts_with("awg:") && seen.insert(route.id.clone())
            }).take(AWG_ROUTES));
            let routes = Arc::new(routes);
            *cached = Some(Discovery {
                loaded: Instant::now(),
                routes: routes.clone(),
            });
            Ok(routes)
        })
        .await
        .map_err(io::Error::other)?
    }
    pub async fn eligible(&self, cfg: &Config) -> io::Result<Vec<Route>> {
        if cfg.awg_fallback == "off" && cfg.route_mode != "vpn_only" {
            return Ok(vec![Route::system()]);
        }
        let all = match self.all().await {
            Ok(v) => v,
            Err(_) if cfg.route_mode == "auto" => return Ok(vec![Route::system()]),
            Err(e) => return Err(e),
        };
        let list = all
            .iter()
            .filter(|r| r.available && r.allowed(cfg))
            .cloned()
            .collect::<Vec<_>>();
        if list.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "режим «только VPN»: выбранный туннель AWG недоступен или не подтвердил пир",
            ));
        }
        Ok(list)
    }
}
