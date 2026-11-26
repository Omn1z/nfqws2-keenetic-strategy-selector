//! The local DNS listener and panel controls share the same resolver and lifecycle.
mod catalog;
mod config;
mod fast_dns;
mod filtering;
mod lan;
mod network;
mod openwrt;
mod redirect;
mod routing;
pub(crate) use routing::{
    ActiveDnsRevalidation, ArchiveResolver, DeliverySelection, DnsOrigin, FailedRoute,
    ManagedOriginReceipt, RedirectEpoch, RouteAnswer, RouteMatch, RouteObserver, RoutePublication,
    RouteWriterBusy, WarmDnsObservation,
};
mod runtime;
mod scheduler;
mod shadow;
pub(crate) use lan::addresses as live_addresses;
pub(crate) use shadow::{interface_records, native_wan, wan_defaults};
#[cfg(test)]
mod tests;
mod transfer;
mod transport;
pub(crate) use transport::is_managed_upstream_timeout;
mod vpn;
use crate::http::{ApiError, ApiJson, Shared};
use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use config::{invalid, Config, FILE};
use nfqws2_store::Store;
use runtime::{Active, Bound, Diagnostics, Engine, Stats};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    sync::{Mutex as AsyncMutex, Notify},
    task::JoinHandle,
};
pub struct Service {
    observer: Arc<routing::Observer>,
    redirects: AsyncMutex<redirect::Listeners>,
    pub(crate) routing_history: Arc<nfqws2_awg_rules::discoveries::Recent>,
    vpn: Arc<vpn::Source>,
    catalog_dir: std::path::PathBuf,
    store: Store,
    wan: Vec<String>,
    openwrt: Arc<nfqws2_openwrt_dns::Manager>,
    state: AsyncMutex<StateData>,
    supervisor: Mutex<Option<JoinHandle<()>>>,
    listener_failed: Arc<Notify>,
    diag: Arc<Mutex<Diagnostics>>,
    schedule: Arc<scheduler::Schedule>,
    isp: Arc<shadow::Environment>,
}
struct StateData {
    saved_catalog: Option<catalog::Status>,
    configured_endpoint: Option<SocketAddr>,
    raw: Value,
    config_error: String,
    config_warning: Option<&'static str>,
    last_error: String,
    last_stats: Stats,
    active: Option<Active>,
}
impl StateData {
    fn stats(&self) -> Stats {
        self.active
            .as_ref()
            .map_or_else(|| self.last_stats.clone(), |run| run.engine().stats())
    }
    fn display_endpoint(&self) -> Option<SocketAddr> {
        match &self.active {
            Some(active) => Some(active.addr),
            None if self.config_error.is_empty() => self.configured_endpoint,
            None => None,
        }
    }
}
fn local_endpoint(cfg: &Config, wan: &[String]) -> io::Result<SocketAddr> {
    Ok(SocketAddr::new(
        lan::host(&cfg.listen_host, wan)?,
        cfg.dns_port,
    ))
}
fn saved_endpoint(raw: &Value, wan: &[String]) -> Option<SocketAddr> {
    Config::from_value(raw)
        .ok()
        .and_then(|cfg| local_endpoint(&cfg, wan).ok())
}
const RECOVERED_WARNING: &str = "Настройки DNS восстановлены из резервной копии";
const RETRY_PERIOD: Duration = Duration::from_secs(15);
fn worker_err(e: tokio::task::JoinError) -> ApiError {
    io::Error::other(e).into()
}
impl Service {
    pub(crate) fn restore_firmware_hints(&self, stamp: &str, publication: RoutePublication) {
        self.observer.restore_firmware_hints(stamp, publication);
    }

    pub(crate) fn park_firmware_hints(&self, old: RoutePublication, stamp: &str) {
        self.observer.park_firmware_hints(old, stamp);
    }

    pub(crate) fn dormant_firmware_hints(
        &self,
        request: &nfqws2_awg_rules::kernel::DormantFirmwareDns,
    ) -> io::Result<Option<nfqws2_awg_rules::kernel::DormantFirmwareProof>> {
        self.observer.dormant_firmware_hints(request)
    }

    pub(crate) fn has_live_firmware_hints(&self, publication: RoutePublication) -> bool {
        self.observer.has_live_firmware_hints(publication)
    }

    pub(crate) fn continue_firmware_hints(&self, old: RoutePublication, new: RoutePublication) {
        self.observer.continue_firmware_hints(old, new);
    }

    pub(crate) async fn revalidate_active_replacement(
        &self,
        request: nfqws2_awg_rules::kernel::ActiveDnsReplacement,
        publication: RoutePublication,
        deadline: tokio::time::Instant,
    ) -> io::Result<ActiveDnsRevalidation> {
        if !self
            .redirects
            .try_lock()
            .is_ok_and(|listeners| listeners.active())
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.observer
            .revalidate_active_replacement(request, publication, deadline)
            .await
    }

    pub(crate) async fn revalidate_pending_replacement(
        &self,
        request: nfqws2_awg_rules::kernel::ActiveReplacementDnsRetry,
        deadline: tokio::time::Instant,
        current: impl Fn() -> bool,
    ) -> io::Result<nfqws2_awg_rules::kernel::ActiveReplacementDnsRetryProof> {
        if !self
            .redirects
            .try_lock()
            .is_ok_and(|listeners| listeners.active())
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        routing::revalidate_pending_replacement(request, deadline, current).await
    }

    pub(crate) async fn set_routing_redirect(&self, bridges: &[String]) -> io::Result<()> {
        self.redirects
            .lock()
            .await
            .reconcile(bridges, &self.observer)
            .await
    }
    pub(crate) fn confirm_routing(
        &self,
        revision: u64,
        rule: (&str, bool),
        name: &str,
        client: Option<std::net::IpAddr>,
        ips: &[std::net::IpAddr],
    ) {
        self.routing_history
            .confirm(revision, rule, name, client, ips);
    }
    pub(crate) fn invalidate_routing_confirmations(&self) {
        self.routing_history.invalidate();
    }
    pub(crate) fn set_route_observer(&self, observer: Arc<dyn RouteObserver>) {
        self.observer.register(observer);
    }
    pub(crate) fn replay_recent_routes(&self, publication: RoutePublication) {
        self.observer.schedule_replay(publication);
    }
    pub(crate) fn replay_restored_routes(&self, publication: RoutePublication) {
        self.observer.schedule_restored_replay(publication);
    }
    pub(crate) fn archive_resolver(&self) -> Option<ArchiveResolver> {
        let state = self.state.try_lock().ok()?;
        if !state.config_error.is_empty() {
            return None;
        }
        if state.raw["enabled"] == true {
            let run = state.active.as_ref().filter(|run| run.running())?;
            let engine = run.engine();
            let ready = !*engine.stopped.borrow();
            return ready.then_some(ArchiveResolver::managed(engine));
        }
        drop(state);
        self.redirects
            .try_lock()
            .is_ok_and(|listeners| listeners.active())
            .then_some(ArchiveResolver::firmware())
    }
    pub(crate) fn flush_recent_routes(&self) -> io::Result<()> {
        self.observer.flush_recent(&self.store)
    }
    /// Use the local listener for routing lookups whenever its policy is
    /// enabled, including VPN-only upstreams and domain-specific DNS pools.
    pub(crate) fn routing_nameserver(&self) -> io::Result<Option<SocketAddr>> {
        Ok(self.routing_listener()?.map(|(addr, _)| addr))
    }

    pub(crate) fn routing_recovery_resolver(
        &self,
    ) -> io::Result<Option<(SocketAddr, ArchiveResolver)>> {
        self.routing_listener()?
            .map(|(addr, engine)| {
                if *engine.stopped.borrow() {
                    return Err(io::ErrorKind::Interrupted.into());
                }
                Ok((addr, ArchiveResolver::pinned_managed(engine)))
            })
            .transpose()
    }

    fn routing_listener(&self) -> io::Result<Option<(SocketAddr, Arc<Engine>)>> {
        let s = self
            .state
            .try_lock()
            .map_err(|_| io::Error::other("настройки DNS-сервера заняты"))?;
        if !s.config_error.is_empty() {
            return Err(io::Error::other(
                "проверьте сохранённые настройки DNS-сервера",
            ));
        }
        if s.raw["enabled"] != true {
            return Ok(None);
        }
        let listener = s
            .active
            .as_ref()
            .filter(|listener| listener.running())
            .ok_or_else(|| io::Error::other("настроенный DNS-сервер панели недоступен"))?;
        let mut address = listener.addr;
        if address.ip().is_unspecified() {
            address.set_ip(if address.is_ipv4() {
                std::net::Ipv4Addr::LOCALHOST.into()
            } else {
                std::net::Ipv6Addr::LOCALHOST.into()
            });
        }
        Ok(Some((address, listener.engine())))
    }
    pub fn new(
        store: Store,
        data_dir: &str,
        router_root: &std::path::Path,
        wan: Vec<String>,
        awg: Arc<nfqws2_awg_profile::runtime::Runtime>,
    ) -> Self {
        let (raw, config_error, config_warning) = match FILE.read_with_recovery(&store) {
            Ok((v, recovered)) => (v, String::new(), recovered.then_some(RECOVERED_WARNING)),
            Err(e) => (config::defaults(), e.to_string(), None),
        };
        let logging = raw["logging_enabled"].as_bool().unwrap_or(true);
        let configured_endpoint = if config_error.is_empty() {
            saved_endpoint(&raw, &wan)
        } else {
            None
        };
        let routing_history = Arc::new(nfqws2_awg_rules::discoveries::Recent::default());
        Self {
            observer: Arc::new(routing::Observer::open(
                &store,
                router_root,
                routing_history.clone(),
            )),
            redirects: Default::default(),
            routing_history,
            vpn: Arc::new(vpn::Source::new(store.clone(), awg)),
            catalog_dir: std::path::Path::new(data_dir).join("dns-blocklists"),
            isp: Arc::new(
                shadow::Environment::new(wan.clone()).with_lease_file(store.clone(), router_root),
            ),
            store,
            wan,
            openwrt: Arc::new(nfqws2_openwrt_dns::Manager::new(data_dir)),
            state: AsyncMutex::new(StateData {
                saved_catalog: None,
                configured_endpoint,
                raw,
                config_error,
                config_warning,
                last_error: String::new(),
                last_stats: Stats::default(),
                active: None,
            }),
            supervisor: Mutex::new(None),
            listener_failed: Arc::new(Notify::new()),
            diag: Arc::new(Mutex::new(Diagnostics::new(logging))),
            schedule: Default::default(),
        }
    }
    pub async fn shutdown(&self) {
        let mut state = self.state.lock().await;
        let supervisor = self.supervisor.lock().unwrap().take();
        if let Some(job) = supervisor {
            job.abort();
            let _ = job.await;
        }
        let _ = self.set_routing_redirect(&[]).await;
        if let Some(run) = state.active.take() {
            state.last_stats = run.engine().stats();
            run.stop().await;
            self.diag
                .lock()
                .unwrap()
                .event("info", "stop", "DNS остановлен");
        }
    }
    pub(crate) async fn port(&self) -> u16 {
        self.state.lock().await.raw["dns_port"]
            .as_u64()
            .and_then(|p| u16::try_from(p).ok())
            .unwrap_or(5355)
    }
    pub(crate) async fn change_port(&self, port: u16) -> Result<(), ApiError> {
        self.change(Edit::Port(port)).await
    }
    pub(crate) async fn dashboard(&self) -> Value {
        let state = self.state.lock().await;
        let active = state.active.as_ref();
        let stats = state.stats();
        json!({"enabled":state.raw["enabled"],"running":active.is_some_and(Active::running),
            "endpoint":state.display_endpoint().map(|a|a.to_string()).unwrap_or_default(),"stats":stats,
            "last_error":if state.config_error.is_empty(){&state.last_error}else{&state.config_error},
            "cache":{"entries":active.map_or(0,|a|a.engine().cache.status().entries),"capacity":state.raw["cache_size"],"ttl_seconds":state.raw["cache_ttl_seconds"]}})
    }
    async fn status(&self) -> Value {
        let routes = self
            .vpn
            .all()
            .await
            .unwrap_or_else(|_| Arc::new(vec![vpn::Route::system()]));
        let mut s = self.state.lock().await;
        let engine = s.active.as_ref().map(Active::engine);
        let filter = engine.as_ref().and_then(|r| r.filter.as_ref());
        if filter.is_none_or(|f| f.feed.is_none()) && s.saved_catalog.is_none() {
            let store = self.store.clone();
            s.saved_catalog = Some(
                tokio::task::spawn_blocking(move || catalog::saved(&store))
                    .await
                    .unwrap_or_default(),
            );
        }
        let cfg = Config::from_value(&s.raw).expect("configuration validated on load");
        let addr = s.display_endpoint();
        let running = s.active.as_ref().is_some_and(Active::running);
        let cache = s.active.as_ref().map(|r| r.engine().cache.status());
        let fast_dns = engine
            .as_ref()
            .and_then(|r| r.transport.fast.as_ref())
            .map_or_else(|| fast_dns::Status::inactive(cfg.fast_dns), |c| c.status());
        let error = if !s.config_error.is_empty() {
            &s.config_error
        } else if s.active.is_some() && !running {
            "остановлен обработчик DNS"
        } else {
            &s.last_error
        };
        let stats = s.stats();
        let hash = if s.config_error.is_empty() {
            config::hash(&s.raw)
        } else {
            String::new()
        };
        let mut status = json!({"config_hash":hash,"config_error":s.config_error,"config":cfg,"running":running,"listen_host":addr.map(|a|a.ip().to_string()).unwrap_or_default(),"endpoints":{"dns":addr.map(|a|a.to_string()).unwrap_or_default()},"last_error":error,"stats":stats,
            "cache":{"entries":cache.map_or(0,|c|c.entries),"capacity":cfg.cache_size,"ttl_seconds":cfg.cache_ttl_seconds},
            "filtering":filtering::status(&cfg.filtering,filter,s.saved_catalog.as_ref()),
            "shadow_dns":s.active.as_ref().and_then(|r|r.engine().shadow.as_ref().map(shadow::Session::status))
                .unwrap_or_else(||json!({"enabled":cfg.shadow_dns["enabled"],"automatic":true,"servers":[],"fallback_active":false,"renewal_available":false,"diagnostics":self.isp.diagnostics.read()})),
            "fast_dns":fast_dns,"routes":routes.iter().map(|r| r.status(&cfg, running)).collect::<Vec<_>>()});
        if let Some(warning) = s.config_warning {
            status["config_warning"] = json!(warning);
        }
        status
    }
    async fn change(&self, edit: Edit) -> Result<(), ApiError> {
        let mut state = self.state.lock().await;
        let before = state.active.as_ref().map(Active::engine);
        let result = self.change_locked(&mut state, edit).await;
        let after = state.active.as_ref().map(Active::engine);
        drop(state);
        let changed = match (&before, &after) {
            (Some(before), Some(after)) => !Arc::ptr_eq(before, after),
            (None, Some(_)) => true,
            (_, None) => false,
        };
        if result.is_ok() && changed {
            self.observer.replay_after_resolver_start();
        }
        result
    }
    /// Serialize archives with normal DNS edits while the saved configuration
    /// is reloaded. A later archive member can fail after DNS has committed.
    pub(crate) async fn with_config_restore<T: Send + 'static>(
        &self,
        restore: impl FnOnce() -> io::Result<T> + Send + 'static,
    ) -> Result<T, ApiError> {
        let mut state = self.state.lock().await;
        let db = self.store.clone();
        let (restored, config) = tokio::task::spawn_blocking(move || {
            let restored = restore();
            let config = FILE.read_with_recovery(&db);
            (restored, config)
        })
        .await
        .map_err(worker_err)?;
        let reload = match config {
            Ok((raw, recovered)) => {
                if recovered {
                    state.config_warning = Some(RECOVERED_WARNING);
                }
                if raw == state.raw && state.config_error.is_empty() {
                    Ok(())
                } else {
                    self.change_locked(&mut state, Edit::Restore(raw)).await
                }
            }
            Err(error) => Err(error.into()),
        };
        if let Err(ApiError(_, ref error)) = reload {
            state.config_error = error.clone();
            state.last_error =
                format!("не удалось загрузить восстановленные настройки DNS: {error}");
        }
        match (restored, reload) {
            (Ok(result), Ok(())) => Ok(result),
            (Err(error), Ok(())) => Err(error.into()),
            (Ok(_), Err(error)) => Err(error),
            (Err(restore), Err(ApiError(_, reload))) => {
                Err(io::Error::other(format!("{restore}\n{reload}")).into())
            }
        }
    }
    async fn change_locked(&self, state: &mut StateData, edit: Edit) -> Result<(), ApiError> {
        let recovering = !state.config_error.is_empty();
        if recovering && !matches!(edit, Edit::Import { .. } | Edit::Restore(_)) {
            return Err(ApiError(StatusCode::CONFLICT, state.config_error.clone()));
        }
        let mut next = state.raw.clone();
        match &edit {
            Edit::Import { raw, revision, .. } => {
                let healthy = !recovering
                    && (!state.raw["enabled"].as_bool().unwrap_or(false)
                        || state.active.as_ref().is_some_and(Active::running));
                if revision.len() != 64 || !revision.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(invalid("укажите base_hash из предварительной проверки").into());
                }
                if config::document_hash(raw, false) == config::document_hash(&state.raw, false)
                    && healthy
                {
                    return Ok(());
                }
                if config::document_hash(&state.raw, false) != *revision {
                    return Err(conflict());
                }
                next = raw.clone();
            }
            Edit::Form(form) => {
                if form["base_hash"].as_str() != Some(&config::hash(&next)) {
                    return Err(conflict());
                }
                next = config::merged(&next, form.clone())?;
            }
            Edit::Restore(raw) => next = raw.clone(),
            Edit::Enable(v) => next["enabled"] = json!(v),
            Edit::Logging(v) => next["logging_enabled"] = json!(v),
            Edit::Method(m, enabled) => {
                let mut methods = Config::from_value(&state.raw)?.disabled_methods;
                if *enabled {
                    methods.retain(|e| e != m);
                } else if !methods.contains(m) {
                    methods.push(m.clone());
                }
                next["disabled_methods"] = json!(methods);
            }
            Edit::Port(port) => next["dns_port"] = json!(port),
            Edit::Autostart => {}
        }
        let cfg = Config::from_value(&next)?;
        let live_edit = matches!(edit, Edit::Logging(_) | Edit::Method(..));
        // Reserve both transports before committing a port change even when
        // the listener is disabled. Keep both sockets until persistence ends.
        let moved = next["dns_port"] != state.raw["dns_port"]
            || next["listen_host"] != state.raw["listen_host"];
        let _probe = if (matches!(edit, Edit::Port(_))
            || matches!(edit, Edit::Import { .. }) && moved)
            && !cfg.enabled
            && next != state.raw
        {
            let addr = local_endpoint(&cfg, &self.wan)?;
            Some(
                Bound::bind(addr)
                    .await
                    .map_err(|e| invalid(format!("DNS listen {addr}: {e}")))?,
            )
        } else {
            None
        };
        let target = if cfg.enabled && !live_edit {
            cfg.check_runtime()?;
            let addr = local_endpoint(&cfg, &self.wan)?;
            let ip = addr.ip();
            for u in std::iter::once(&cfg.default_upstream)
                .chain(&cfg.default_pool)
                .chain(
                    cfg.rules
                        .iter()
                        .filter(|r| r.enabled)
                        .flat_map(|r| std::iter::once(&r.upstream).chain(&r.pool)),
                )
            {
                let uri = u
                    .address
                    .parse::<axum::http::Uri>()
                    .map_err(io::Error::other)?;
                if uri.port_u16().unwrap_or(443) == addr.port()
                    && (uri.host().unwrap().trim_matches(['[', ']']).parse() == Ok(ip)
                        || u.bootstrap_ips.contains(&ip))
                {
                    return Err(invalid("DoH upstream указывает на этот DNS-сервер").into());
                }
            }
            Some(addr)
        } else {
            None
        };
        let same_endpoint = state
            .active
            .as_ref()
            .is_some_and(|r| Some(r.addr) == target && r.running());
        let bound = if let Some(addr) = target.filter(|_| !same_endpoint) {
            Some(
                Bound::bind(addr)
                    .await
                    .map_err(|e| invalid(format!("DNS listen {addr}: {e}")))?,
            )
        } else {
            None
        };
        let unchanged = state.raw == next;
        let same_config = unchanged || Config::from_value(&state.raw)? == cfg;
        if !live_edit
            && !(same_endpoint && same_config && state.last_error.is_empty())
            && (!unchanged || matches!(edit, Edit::Enable(_) | Edit::Autostart))
        {
            let ow = self.openwrt.clone();
            tokio::task::spawn_blocking(move || {
                if let Some(b) = ow.current_binding()? {
                    if !target.is_some_and(|a| {
                        a.port() == b.endpoint.port && a.ip().to_string() == b.endpoint.host
                    }) {
                        ow.restore("")?;
                    }
                }
                Ok::<_, io::Error>(())
            })
            .await
            .map_err(worker_err)??;
        }
        if (!unchanged || recovering) && !matches!(edit, Edit::Restore(_)) {
            let store = self.store.clone();
            let previous = state.raw.clone();
            let updated = next.clone();
            let verify = match &edit {
                Edit::Import { verify, .. } => Some(verify.clone()),
                _ => None,
            };
            let saved = tokio::task::spawn_blocking(move || {
                let check = || {
                    if let Some(expected) = &verify {
                        let current =
                            nfqws2_awg_rules::public_refs(&nfqws2_awg_profile::read(&store)?)
                                .into_iter()
                                .filter(|r| !r.fingerprint.is_empty())
                                .collect::<Vec<_>>();
                        if &current != expected {
                            return Err(io::Error::new(
                                io::ErrorKind::AlreadyExists,
                                "AWG connections changed",
                            ));
                        }
                    }
                    Ok(())
                };
                if recovering {
                    return FILE
                        .replace_checked(&store, updated, || {
                            check()?;
                            match FILE.inspect(&store) {
                                Err(e) if e.kind() == io::ErrorKind::InvalidData => Ok(()),
                                Err(e) => Err(e),
                                Ok(_) => Err(io::Error::new(
                                    io::ErrorKind::AlreadyExists,
                                    "DNS configuration recovered concurrently",
                                )),
                            }
                        })
                        .map(drop);
                }
                FILE.edit(&store, |v| {
                    check()?;
                    if *v != previous {
                        return Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            "DNS configuration changed",
                        ));
                    }
                    *v = updated;
                    Ok(())
                })
            })
            .await
            .map_err(worker_err)?;
            if let Err(e) = saved {
                if e.kind() == io::ErrorKind::AlreadyExists {
                    let store = self.store.clone();
                    let (current, recovered) =
                        tokio::task::spawn_blocking(move || FILE.read_with_recovery(&store))
                            .await
                            .map_err(worker_err)??;
                    state.configured_endpoint = saved_endpoint(&current, &self.wan);
                    state.raw = current;
                    if recovered {
                        state.config_warning = Some(RECOVERED_WARNING);
                    }
                    state.config_error.clear();
                    return Err(conflict());
                }
                return Err(e.into());
            }
        }
        if live_edit {
            match edit {
                Edit::Logging(enabled) => self.diag.lock().unwrap().set_logging(enabled),
                Edit::Method(..) => {
                    if let Some(active) = &state.active {
                        let engine = active.engine();
                        engine
                            .methods
                            .apply(scheduler::disabled(&cfg.disabled_methods));
                        if let Some(cache) = &engine.transport.fast {
                            engine.methods.read(|off| cache.prune_disabled(&cfg, off));
                        }
                    }
                }
                _ => unreachable!("runtime-neutral DNS edit"),
            }
            state.raw = next;
            return Ok(());
        }

        let replace = same_endpoint && (!same_config || !state.last_error.is_empty());
        let starts = bound.is_some() || replace;
        let stops = state.active.is_some() && (starts || !same_endpoint);
        state.configured_endpoint = target.or_else(|| local_endpoint(&cfg, &self.wan).ok());
        {
            let mut diag = self.diag.lock().unwrap();
            if stops {
                diag.event("info", "stop", "DNS остановлен");
            }
            diag.logging = cfg.logging_enabled;
            if let Some(addr) = target.filter(|_| starts) {
                diag.event("info", "start", format!("DNS запущен на {addr}"));
            }
        }
        let old = if let Some(bound) = bound {
            state.active.replace(bound.start(
                Engine::new(
                    cfg,
                    self.diag.clone(),
                    self.schedule.clone(),
                    self.isp.clone(),
                    self.vpn.clone(),
                    self.observer.clone(),
                ),
                self.listener_failed.clone(),
            ))
        } else if same_endpoint {
            if replace {
                state.active.as_ref().unwrap().replace(Engine::new(
                    cfg,
                    self.diag.clone(),
                    self.schedule.clone(),
                    self.isp.clone(),
                    self.vpn.clone(),
                    self.observer.clone(),
                ));
            }
            None
        } else {
            state.active.take()
        };
        state.raw = next;
        state.saved_catalog = None;
        state.config_error.clear();
        if recovering && matches!(edit, Edit::Import { .. }) {
            state.config_warning = Some("Сохранённые настройки DNS заменены проверенным импортом");
        }
        state.last_error.clear();
        if let Some(old) = old {
            if state.active.is_none() {
                state.last_stats = old.engine().stats();
            }
            old.stop().await;
        }
        if let Some(active) = &state.active {
            catalog::start(&active.engine(), &self.catalog_dir, &self.store);
        }
        Ok(())
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        if let Some(job) = self.supervisor.get_mut().unwrap().take() {
            job.abort();
        }
    }
}
fn conflict() -> ApiError {
    ApiError(
        StatusCode::CONFLICT,
        "настройки DNS изменились; загрузите их повторно".into(),
    )
}
enum Edit {
    Import {
        raw: Value,
        revision: String,
        verify: Vec<nfqws2_awg_rules::Ref>,
    },
    Autostart,
    Restore(Value),
    Port(u16),
    Form(Value),
    Enable(bool),
    Logging(bool),
    Method(config::Method, bool),
}
pub async fn autostart(s: &Shared) {
    autostart_if_needed(s, Retry::Initial).await;
    supervise(s, RETRY_PERIOD);
}
enum Retry {
    Initial,
    Scheduled,
    ListenerFailed,
}
fn record_service_error(s: &Shared, state: &mut StateData, error: String) {
    s.logs.append("dns", "warn", &error);
    s.dnsserver
        .diag
        .lock()
        .unwrap()
        .event("error", "service", &error);
    state.last_error = error;
}
async fn autostart_if_needed(s: &Shared, trigger: Retry) {
    let mut state = s.dnsserver.state.lock().await;
    if !matches!(trigger, Retry::Initial)
        && (state.raw["enabled"] != true
            || !state.config_error.is_empty()
            || state.active.as_ref().is_some_and(Active::running))
    {
        return;
    }
    let failure = state.active.as_ref().and_then(Active::failure);
    // A notification from a retired listener can arrive during a rebind.
    // Only an error carried by the currently owned instance authorizes it.
    if matches!(trigger, Retry::ListenerFailed) && failure.is_none() {
        return;
    }
    if let Some(failure) = failure {
        record_service_error(s, &mut state, failure);
        if let Some(run) = state.active.take() {
            state.last_stats = run.engine().stats();
            run.stop().await;
            s.dnsserver
                .diag
                .lock()
                .unwrap()
                .event("info", "stop", "DNS остановлен");
        }
    }
    match s.dnsserver.change_locked(&mut state, Edit::Autostart).await {
        Ok(()) if state.active.as_ref().is_some_and(Active::running) => {
            drop(state);
            s.dnsserver.observer.replay_after_resolver_start();
        }
        Ok(()) => {}
        Err(ApiError(_, e)) => record_service_error(s, &mut state, e),
    }
}
fn supervise(s: &Shared, period: Duration) {
    let mut supervisor = s.dnsserver.supervisor.lock().unwrap();
    if supervisor.as_ref().is_some_and(|job| !job.is_finished()) {
        return;
    }
    let weak = Arc::downgrade(s);
    let listener_failed = s.dnsserver.listener_failed.clone();
    let start = tokio::time::Instant::now() + period;
    *supervisor = Some(tokio::spawn(async move {
        let mut tick = tokio::time::interval_at(start, period);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let trigger = tokio::select! {
                _ = tick.tick() => Retry::Scheduled,
                _ = listener_failed.notified() => Retry::ListenerFailed,
            };
            let Some(s) = weak.upgrade() else {
                return;
            };
            autostart_if_needed(&s, trigger).await;
        }
    }));
}
pub fn routes() -> Router<Shared> {
    Router::new()
        .merge(transfer::routes())
        .merge(openwrt::routes())
        .route("/api/dnsserver", get(status))
        .route("/api/dnsserver/config", post(config))
        .route("/api/dnsserver/start", post(start))
        .route("/api/dnsserver/stop", post(stop))
        .route("/api/dnsserver/test", post(test))
        .route("/api/dnsserver/scheduler", get(schedule))
        .route("/api/dnsserver/scheduler/method", post(method))
        .route("/api/dnsserver/shadow/diagnostics", post(shadow_logging))
        .route("/api/dnsserver/shadow/renew", post(refresh_shadow))
        .route("/api/dnsserver/filtering/update", post(update_filter))
        .route("/api/dnsserver/cache/clear", post(clear_cache))
        .route("/api/dnsserver/logging", post(logging))
        .route("/api/dnsserver/logs", get(logs))
        .route("/api/dnsserver/logs/clear", post(clear_logs))
}
#[derive(Default, Deserialize)]
struct DomainQuery {
    #[serde(default)]
    domain: String,
}
async fn schedule(
    State(s): State<Shared>,
    Query(q): Query<DomainQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let service = &s.dnsserver;
    let routes = service
        .vpn
        .all()
        .await
        .unwrap_or_else(|_| Arc::new(vec![vpn::Route::system()]));
    let st = service.state.lock().await;
    let cfg = Config::from_value(&st.raw)?;
    let name = if q.domain.trim().is_empty() {
        String::new()
    } else {
        config::domain(&q.domain)?
    };
    if shadow::Matcher::compile(&cfg.shadow_dns).is_some_and(|m| m.matches(&name)) {
        return Ok((
            [(header::CACHE_CONTROL, "no-store")],
            Json(
                json!({"enabled":cfg.scheduler_enabled,"effective":false,"reason":"shadow","domain":name,"pool_source":"shadow","effective_candidate_count":0,"candidates":[],"parallel_limit":scheduler::LIMIT}),
            ),
        ));
    }
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(service.schedule.snapshot(
            &cfg,
            &name,
            st.active.as_ref().is_some_and(Active::running),
            &routes,
        )),
    ))
}
#[derive(Deserialize)]
struct MethodToggle {
    upstream: String,
    route: String,
    enabled: bool,
}
async fn method(
    State(s): State<Shared>,
    ApiJson(v): ApiJson<MethodToggle>,
) -> Result<impl IntoResponse, ApiError> {
    let mut m = config::Method {
        upstream: v.upstream,
        route: v.route,
    };
    m.normalize()?;
    tokio::spawn(async move {
        s.dnsserver.change(Edit::Method(m, v.enabled)).await?;
        Ok((
            [(header::CACHE_CONTROL, "no-store")],
            Json(Config::from_value(&s.dnsserver.state.lock().await.raw)?),
        ))
    })
    .await
    .map_err(worker_err)?
}
async fn update_filter(State(s): State<Shared>) -> Result<Json<Value>, ApiError> {
    {
        let st = s.dnsserver.state.lock().await;
        if st.raw["filtering"]["enabled"] != true || st.active.as_ref().is_none_or(|r| !r.running())
        {
            return Err(invalid("DNS-сервис и фильтрация должны быть включены").into());
        }
        if let Some(feed) = st
            .active
            .as_ref()
            .unwrap()
            .engine()
            .filter
            .as_ref()
            .and_then(|f| f.feed.as_ref())
        {
            feed.request();
        }
    }
    Ok(Json(s.dnsserver.status().await))
}
async fn shadow_logging(
    State(s): State<Shared>,
    ApiJson(input): ApiJson<Toggle>,
) -> impl IntoResponse {
    s.dnsserver.isp.diagnostics.set(input.enabled);
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(s.dnsserver.status().await),
    )
}
#[derive(Deserialize)]
struct Confirmation {
    confirm: bool,
}
async fn refresh_shadow(
    State(s): State<Shared>,
    ApiJson(v): ApiJson<Confirmation>,
) -> Result<impl IntoResponse, ApiError> {
    if !v.confirm {
        return Err(invalid(
            "подтвердите обновление DHCP WAN: возможно краткое прерывание интернета",
        )
        .into());
    }
    let engine = s
        .dnsserver
        .state
        .lock()
        .await
        .active
        .as_ref()
        .filter(|a| a.running())
        .map(Active::engine)
        .ok_or_else(|| invalid("сначала включите DNS Server и Shadow DNS"))?;
    let session = engine
        .shadow
        .as_ref()
        .ok_or_else(|| invalid("сначала включите Shadow DNS"))?;
    let mut request = session
        .renewal_request()
        .map_err(|error| invalid(error.to_string()))?;
    let current = |state: &StateData| {
        state
            .active
            .as_ref()
            .is_some_and(|active| active.running() && Arc::ptr_eq(&active.engine(), &engine))
    };
    let mut lifetime = engine.stopped.subscribe();
    let work = async {
        if let Some(resolved) = request.already_resolved().await {
            return Ok(resolved);
        }
        let prepared = request
            .prepare()
            .await
            .map_err(|error| invalid(error.to_string()))?;
        let pending = {
            let state = s.dnsserver.state.lock().await;
            if !current(&state) {
                return Err(conflict());
            }
            request
                .send(prepared)
                .await
                .map_err(|error| invalid(error.to_string()))?
        };
        request
            .finish(pending)
            .await
            .map_err(|error| invalid(error.to_string()).into())
    };
    let result = tokio::select! {
        biased;
        _ = lifetime.wait_for(|stopped| *stopped) => Err(conflict()),
        result = work => result,
    };
    let result = match result {
        Ok(_) if !current(&*s.dnsserver.state.lock().await) => Err(conflict()),
        result => result,
    };
    match &result {
        Ok(value) => request.report(Some(value), ""),
        Err(error) => request.report(None, &error.1),
    }
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"ok":true,"result":result?})),
    ))
}
async fn status(State(s): State<Shared>) -> Json<Value> {
    Json(s.dnsserver.status().await)
}
async fn update(s: Shared, edit: Edit) -> Result<Json<Value>, ApiError> {
    tokio::spawn(async move {
        s.dnsserver.change(edit).await?;
        Ok(Json(s.dnsserver.status().await))
    })
    .await
    .map_err(worker_err)?
}
async fn config(
    State(s): State<Shared>,
    ApiJson(v): ApiJson<Value>,
) -> Result<Json<Value>, ApiError> {
    update(s, Edit::Form(v)).await
}
async fn start(State(s): State<Shared>) -> Result<Json<Value>, ApiError> {
    update(s, Edit::Enable(true)).await
}
async fn stop(State(s): State<Shared>) -> Result<Json<Value>, ApiError> {
    update(s, Edit::Enable(false)).await
}
async fn clear_cache(State(s): State<Shared>) -> Json<Value> {
    {
        let state = s.dnsserver.state.lock().await;
        let removed = state
            .active
            .as_ref()
            .map_or(0, |run| run.engine().cache.clear());
        s.dnsserver.diag.lock().unwrap().event(
            "info",
            "cache_clear",
            format!("Кэш ответов DNS очищен: удалено записей — {removed}"),
        );
    }
    Json(s.dnsserver.status().await)
}
#[derive(Deserialize)]
struct Toggle {
    enabled: bool,
}
async fn logging(
    State(s): State<Shared>,
    ApiJson(v): ApiJson<Toggle>,
) -> Result<Json<Value>, ApiError> {
    let _ = update(s.clone(), Edit::Logging(v.enabled)).await?;
    Ok(Json(s.dnsserver.diag.lock().unwrap().logs(0)))
}
#[derive(Deserialize)]
struct Logs {
    #[serde(default)]
    after: u64,
}
async fn logs(State(s): State<Shared>, Query(v): Query<Logs>) -> impl IntoResponse {
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(s.dnsserver.diag.lock().unwrap().logs(v.after)),
    )
}
async fn clear_logs(State(s): State<Shared>) -> Json<Value> {
    let mut diag = s.dnsserver.diag.lock().unwrap();
    diag.clear();
    Json(diag.logs(0))
}
#[derive(Deserialize)]
struct TestQuery {
    domain: String,
    #[serde(default, rename = "type")]
    kind: String,
}
async fn test(State(s): State<Shared>, ApiJson(input): ApiJson<TestQuery>) -> Json<Value> {
    let started = Instant::now();
    let mut v = json!({"ok":false,"domain":input.domain,"type":input.kind,"answers":[],"route":"","upstream":"","source":"diagnostic","transport":"api","cached":false,"shared":false,"duration_ms":0});
    let result = async {
        let name = config::domain(&input.domain)?;
        let kind = match input.kind.as_str() {
            "" | "A" => 1,
            "AAAA" => 28,
            "CNAME" => 5,
            "SVCB" => 64,
            "HTTPS" => 65,
            _ => return Err(invalid("тип должен быть A, AAAA, CNAME, HTTPS или SVCB")),
        };
        let wire = nfqws2_dns::build_query(&name, kind, nfqws2_dns::transaction_id()?)?;
        v["domain"] = json!(name);
        if input.kind.is_empty() {
            v["type"] = json!("A");
        }
        let engine = s
            .dnsserver
            .state
            .lock()
            .await
            .active
            .as_ref()
            .filter(|r| r.running())
            .map(Active::engine)
            .ok_or_else(|| invalid("DNS-сервис выключен или запускается"))?;
        let out = engine.exchange(&wire, "diagnostic", "api", None).await?;
        v["blocked"] = json!(out.hit.is_some());
        v["route"] = json!(out.route);
        if let Some(hit) = &out.hit {
            hit.annotate(&mut v);
        }
        v["upstream"] = json!(out.upstream);
        v["answers"] = json!(nfqws2_dns::answer_records(&out.answer.wire)?);
        v["cached"] = json!(out.answer.cached);
        v["shared"] = json!(out.shared);
        v["ok"] = json!(true);
        Ok::<_, io::Error>(())
    }
    .await;
    if let Err(e) = result {
        v["error"] = json!(e.to_string());
    }
    v["duration_ms"] = json!(started.elapsed().as_millis() as u64);
    Json(v)
}
