//! Refresh socket destinations for configured DoH providers on each eligible
//! route. HTTPS continues to authenticate the original provider hostname.
use super::{
    config::{Config, Upstream},
    runtime::Engine,
    scheduler,
    vpn::Route,
};
use axum::http::Uri;
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet},
    io,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::sync::{watch, Notify};

const CAPACITY: usize = 256;
const REFRESH: Duration = Duration::from_secs(3600);
const STALE: Duration = Duration::from_secs(3600);
const RETRY: Duration = Duration::from_secs(60);
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(4);
type Addresses = Arc<[IpAddr]>;
type Reply = Result<Addresses, Arc<str>>;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct Key {
    route: String,
    index: u32,
    host: String,
}
impl Key {
    fn new(route: &Route, host: &str) -> Self {
        Self {
            route: route.id.clone(),
            index: route.index,
            host: host.trim_end_matches('.').to_ascii_lowercase(),
        }
    }
}

struct Flight {
    sequence: u64,
    foreground: bool,
    running: bool,
    result: watch::Sender<Option<Reply>>,
}
struct Entry {
    route: Route,
    ips: Addresses,
    refreshed: Option<Instant>,
    expires: Instant,
    retry_at: Instant,
    last_used: Instant,
    last_error: Option<Arc<str>>,
    refresh_soon: bool,
    flight: Option<Flight>,
}
impl Entry {
    fn new(route: &Route, now: Instant) -> Self {
        Self {
            route: route.clone(),
            ips: Arc::from([]),
            refreshed: None,
            expires: now,
            retry_at: now,
            last_used: now,
            last_error: None,
            refresh_soon: false,
            flight: None,
        }
    }
    fn usable(&self, now: Instant) -> bool {
        !self.ips.is_empty() && now < self.expires + STALE
    }
    fn ready_to_refresh(&self, now: Instant) -> bool {
        self.flight.is_none()
            && now >= self.retry_at
            && (now >= self.expires || self.refresh_soon || self.last_error.is_some())
    }
    fn schedule(&mut self, sequence: &mut u64, foreground: bool) {
        if let Some(flight) = &mut self.flight {
            flight.foreground |= foreground;
        } else {
            *sequence = sequence.wrapping_add(1);
            self.flight = Some(Flight {
                sequence: *sequence,
                foreground,
                running: false,
                result: watch::channel(None).0,
            });
        }
    }
    fn discard(&mut self) {
        if let Some(flight) = self.flight.take() {
            flight
                .result
                .send_replace(Some(Err("метод DNS выключен или маршрут изменился".into())));
        }
    }
}
#[derive(Default)]
struct State {
    entries: HashMap<Key, Entry>,
    sequence: u64,
}
impl State {
    fn schedule(&mut self, key: &Key, foreground: bool) {
        self.entries
            .get_mut(key)
            .expect("scheduled DNS provider is registered")
            .schedule(&mut self.sequence, foreground);
    }
    fn retain(&mut self, mut keep: impl FnMut(&Key, &mut Entry) -> bool) {
        self.entries.retain(|key, entry| {
            let keep = keep(key, entry);
            if !keep {
                entry.discard();
            }
            keep
        });
    }
    fn register(&mut self, key: &Key, route: &Route, now: Instant, foreground: bool) -> bool {
        if self.entries.contains_key(key) {
            return true;
        }
        if self.entries.len() == CAPACITY {
            if !foreground {
                return false;
            }
            let evicted = self
                .entries
                .iter()
                .filter(|(_, entry)| {
                    entry
                        .flight
                        .as_ref()
                        .is_none_or(|f| !f.running && !f.foreground)
                })
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone());
            let Some(evicted) = evicted else { return false };
            self.entries.remove(&evicted).unwrap().discard();
        }
        self.entries.insert(key.clone(), Entry::new(route, now));
        true
    }
}

#[derive(Default)]
pub(super) struct Cache {
    state: Mutex<State>,
    wake: Notify,
}
struct Job {
    key: Key,
    route: Route,
    sequence: u64,
    canceled: watch::Receiver<Option<Reply>>,
}
enum Lookup {
    Ready(Addresses),
    Pending(watch::Receiver<Option<Reply>>),
}
#[derive(Default, Serialize)]
pub(super) struct Status {
    pub enabled: bool,
    entries: usize,
    ready: usize,
    refreshing: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_refresh_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_refresh_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_error: Option<String>,
}
impl Status {
    pub fn inactive(enabled: bool) -> Self {
        Self {
            enabled,
            ..Default::default()
        }
    }
}
impl Cache {
    fn request(&self, route: &Route, host: &str, now: Instant) -> io::Result<Lookup> {
        let key = Key::new(route, host);
        let mut state = self.state.lock().unwrap();
        if !state.register(&key, route, now, true) {
            return Err(io::Error::other("очередь bootstrap Fast DNS заполнена"));
        }
        let entry = state.entries.get_mut(&key).unwrap();
        entry.last_used = now;
        entry.route = route.clone();
        if !entry.ips.is_empty() && now < entry.expires {
            return Ok(Lookup::Ready(entry.ips.clone()));
        }
        let usable = entry.usable(now).then(|| entry.ips.clone());
        if (entry.flight.is_some() && usable.is_none()) || now >= entry.retry_at {
            state.schedule(&key, usable.is_none());
            self.wake.notify_one();
        }
        let entry = &state.entries[&key];
        if let Some(ips) = usable {
            return Ok(Lookup::Ready(ips));
        }
        entry
            .flight
            .as_ref()
            .map(|f| Lookup::Pending(f.result.subscribe()))
            .ok_or_else(|| {
                io::Error::other(
                    entry
                        .last_error
                        .as_deref()
                        .unwrap_or("bootstrap Fast DNS недоступен"),
                )
            })
    }
    pub async fn lookup(&self, route: &Route, host: &str) -> io::Result<Addresses> {
        match self.request(route, host, Instant::now())? {
            Lookup::Ready(addresses) => Ok(addresses),
            Lookup::Pending(mut receiver) => {
                let result = receiver
                    .wait_for(Option::is_some)
                    .await
                    .map_err(io::Error::other)?;
                result
                    .as_ref()
                    .unwrap()
                    .clone()
                    .map_err(|e| io::Error::other(e.to_string()))
            }
        }
    }
    pub fn refresh_soon(&self, route: &Route, host: &str) {
        let key = Key::new(route, host);
        let mut state = self.state.lock().unwrap();
        if let Some(entry) = state.entries.get_mut(&key) {
            entry.refresh_soon = true;
            if entry.ready_to_refresh(Instant::now()) {
                state.schedule(&key, false);
                self.wake.notify_one();
            }
        }
    }
    fn maintain(&self, cfg: &Config, off: &HashSet<String>, routes: &[Route], now: Instant) {
        let warm = targets(cfg, off, routes);
        let mut state = self.state.lock().unwrap();
        state.retain(|key, entry| {
            let current = routes.iter().find(|route| {
                route.id == key.route
                    && route.index == key.index
                    && route.available
                    && route.allowed(cfg)
            });
            let Some(route) = current.filter(|_| configured(cfg, off, key)) else {
                return false;
            };
            entry.route = route.clone();
            true
        });
        // Preserve declaration order and let foreground misses control eviction.
        for (key, route) in warm {
            if state.register(&key, &route, now, false) && state.entries[&key].ready_to_refresh(now)
            {
                state.schedule(&key, false);
                self.wake.notify_one();
            }
        }
        // A foreground cache miss may introduce a configured host past the warm target limit.
        let State { entries, sequence } = &mut *state;
        for entry in entries.values_mut().filter(|e| e.ready_to_refresh(now)) {
            entry.schedule(sequence, false);
            self.wake.notify_one();
        }
    }
    pub fn prune_disabled(&self, cfg: &Config, off: &HashSet<String>) {
        self.state
            .lock()
            .unwrap()
            .retain(|key, _| configured(cfg, off, key));
    }
    fn next(&self) -> Option<Job> {
        let mut state = self.state.lock().unwrap();
        let (key, entry) = state
            .entries
            .iter_mut()
            .filter(|(_, e)| e.flight.as_ref().is_some_and(|flight| !flight.running))
            .min_by_key(|(_, e)| {
                let f = e.flight.as_ref().unwrap();
                (!f.foreground, f.sequence)
            })?;
        let flight = entry.flight.as_mut().unwrap();
        flight.running = true;
        // Feed the other worker if several entries were scheduled before it woke.
        self.wake.notify_one();
        Some(Job {
            key: key.clone(),
            route: entry.route.clone(),
            sequence: flight.sequence,
            canceled: flight.result.subscribe(),
        })
    }
    fn complete(&self, job: &Job, result: io::Result<Vec<IpAddr>>, now: Instant) {
        let reply: Reply = result
            .and_then(|ips| {
                let mut seen = HashSet::new();
                let ips = ips
                    .into_iter()
                    .map(|ip| ip.to_canonical())
                    .filter(|ip| !ip.is_unspecified() && !ip.is_multicast() && seen.insert(*ip))
                    .take(16)
                    .collect::<Vec<_>>();
                if ips.is_empty() {
                    return Err(io::Error::other("bootstrap Fast DNS не вернул IP-адресов"));
                }
                Ok(ips.into())
            })
            .map_err(|e| {
                let mut msg = e.to_string();
                let end = msg.floor_char_boundary(512);
                msg.truncate(end);
                msg.into()
            });
        let mut state = self.state.lock().unwrap();
        let Some(entry) = state.entries.get_mut(&job.key) else {
            return;
        };
        if entry
            .flight
            .as_ref()
            .is_none_or(|f| f.sequence != job.sequence)
        {
            return;
        }
        entry.retry_at = now + RETRY;
        match &reply {
            Ok(ips) => {
                entry.ips = ips.clone();
                entry.refreshed = Some(now);
                entry.expires = now + REFRESH;
                entry.last_error = None;
                entry.refresh_soon = false;
            }
            Err(e) => entry.last_error = Some(e.clone()),
        }
        entry
            .flight
            .take()
            .unwrap()
            .result
            .send_replace(Some(reply));
    }
    pub fn status(&self) -> Status {
        let state = self.state.lock().unwrap();
        let now = Instant::now();
        let wall = SystemTime::now();
        let rfc = |at: Instant| {
            let when = if at >= now {
                wall.checked_add(at - now)
            } else {
                wall.checked_sub(now - at)
            }?;
            OffsetDateTime::from(when).format(&Rfc3339).ok()
        };
        let entries = state.entries.values();
        let next = entries
            .clone()
            .filter_map(|e| {
                if e.last_error.is_some()
                    || e.refresh_soon
                    || (now >= e.expires && e.retry_at > e.expires)
                {
                    Some(e.retry_at)
                } else {
                    e.refreshed.map(|_| e.expires)
                }
            })
            .min();
        Status {
            enabled: true,
            entries: state.entries.len(),
            ready: entries.clone().filter(|e| e.usable(now)).count(),
            refreshing: entries.clone().filter(|e| e.flight.is_some()).count(),
            last_refresh_at: entries
                .clone()
                .filter_map(|e| e.refreshed)
                .max()
                .and_then(rfc),
            next_refresh_at: next.and_then(rfc),
            last_error: entries
                .filter_map(|e| e.last_error.as_ref().map(|err| (e.retry_at, err)))
                .max_by_key(|(at, _)| *at)
                .map(|(_, err)| err.to_string()),
        }
    }
}

fn upstreams(cfg: &Config) -> impl Iterator<Item = &Upstream> {
    std::iter::once(&cfg.default_upstream)
        .chain(&cfg.default_pool)
        .chain(
            cfg.rules
                .iter()
                .filter(|r| r.enabled)
                .flat_map(|r| std::iter::once(&r.upstream).chain(&r.pool)),
        )
}
pub(super) fn provider_host(upstream: &Upstream) -> Option<String> {
    if !upstream.bootstrap_ips.is_empty() {
        return None;
    }
    let uri: Uri = upstream.address.parse().ok()?;
    let host = uri.host()?.trim_matches(['[', ']']).trim_end_matches('.');
    host.parse::<IpAddr>()
        .is_err()
        .then(|| host.to_ascii_lowercase())
}
fn configured(cfg: &Config, off: &HashSet<String>, key: &Key) -> bool {
    upstreams(cfg).any(|server| {
        provider_host(server).as_deref() == Some(key.host.as_str())
            && !off.contains(&scheduler::key(&key.route, &server.address))
    })
}
fn targets(cfg: &Config, off: &HashSet<String>, routes: &[Route]) -> Vec<(Key, Route)> {
    let mut seen = HashSet::new();
    upstreams(cfg)
        .filter_map(|server| Some((server, provider_host(server)?)))
        .flat_map(|(server, host)| {
            routes
                .iter()
                .filter(move |route| {
                    route.available
                        && route.allowed(cfg)
                        && !off.contains(&scheduler::key(&route.id, &server.address))
                })
                .map(move |route| (Key::new(route, &host), route.clone()))
        })
        .filter(|(key, _)| seen.insert(key.clone()))
        .take(CAPACITY)
        .collect()
}

pub(super) fn start_workers(engine: &Arc<Engine>, cache: &Arc<Cache>) {
    for _ in 0..2 {
        let owner = Arc::downgrade(engine);
        let shared = cache.clone();
        let mut stop = engine.stopped.subscribe();
        tokio::spawn(async move {
            loop {
                let Some(mut job) = shared.next() else {
                    tokio::select! { biased; _ = stop.changed() => return, _ = shared.wake.notified() => continue }
                };
                let Some(engine) = owner.upgrade() else {
                    return;
                };
                let allowed = engine.methods.read(|off| {
                    let allowed = configured(&engine.cfg, off, &job.key);
                    if !allowed {
                        shared.prune_disabled(&engine.cfg, off);
                    }
                    allowed
                });
                if !allowed {
                    continue;
                }
                let lookup = tokio::time::timeout(
                    LOOKUP_TIMEOUT,
                    engine.transport.bootstrap_addresses(
                        &job.key.host,
                        &job.route,
                        &engine.methods,
                    ),
                );
                let result = tokio::select! {
                    biased;
                    _ = stop.changed() => return,
                    _ = job.canceled.wait_for(Option::is_some) => continue,
                    result = lookup => result.map_err(|_| io::ErrorKind::TimedOut.into()).and_then(|v| v),
                };
                shared.complete(&job, result, Instant::now());
            }
        });
    }
}

pub(super) fn start_warming(engine: &Arc<Engine>, cache: &Arc<Cache>) {
    let owner = Arc::downgrade(engine);
    let shared = cache.clone();
    let mut stop = engine.stopped.subscribe();
    tokio::spawn(async move {
        loop {
            let Some(engine) = owner.upgrade() else {
                return;
            };
            let routes = tokio::select! {
                biased;
                _ = stop.changed() => return,
                routes = engine.vpn.eligible(&engine.cfg) => routes.unwrap_or_default(),
            };
            engine
                .methods
                .read(|off| shared.maintain(&engine.cfg, off, &routes, Instant::now()));
            drop(engine);
            tokio::select! { biased; _ = stop.changed() => return, _ = tokio::time::sleep(RETRY) => {} }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn shared_lookup_retains_usable_stale_addresses_and_retries() {
        let cache = Cache::default();
        let now = Instant::now();
        let route = Route::system();
        let host = "Endpoint.Example.";
        let Lookup::Pending(first) = cache.request(&route, host, now).unwrap() else {
            panic!("expected miss")
        };
        let Lookup::Pending(mut second) = cache.request(&route, "endpoint.example", now).unwrap()
        else {
            panic!("expected shared miss")
        };
        let job = cache.next().unwrap();
        assert!(cache.next().is_none());
        drop(first);
        let ip = "192.0.2.1".parse().unwrap();
        cache.complete(&job, Ok(vec![ip, ip, IpAddr::from([0, 0, 0, 0])]), now);
        let response = second.wait_for(Option::is_some).await.unwrap();
        assert_eq!(response.as_ref().unwrap().as_ref().unwrap().as_ref(), &[ip]);
        assert_eq!(cache.status().ready, 1);

        let refresh = now + REFRESH;
        let Lookup::Ready(stale) = cache.request(&route, host, refresh).unwrap() else {
            panic!("expected stale address")
        };
        assert_eq!(stale.as_ref(), &[ip]);
        let job = cache.next().unwrap();
        cache.complete(&job, Err(io::ErrorKind::TimedOut.into()), refresh);
        assert!(matches!(
            cache.request(&route, host, refresh + RETRY / 2).unwrap(),
            Lookup::Ready(_)
        ));
        assert!(cache.next().is_none());
        assert!(matches!(
            cache.request(&route, host, refresh + STALE).unwrap(),
            Lookup::Pending(_)
        ));
        let replacement = "192.0.2.2".parse().unwrap();
        cache.complete(
            &cache.next().unwrap(),
            Ok(vec![replacement]),
            refresh + STALE,
        );
        let Lookup::Ready(ready) = cache.request(&route, host, refresh + STALE).unwrap() else {
            panic!("expected refreshed address")
        };
        assert_eq!(ready.as_ref(), &[replacement]);
    }

    #[tokio::test]
    async fn only_enabled_automatic_providers_are_warmed_and_disabling_cancels_last_profile() {
        let mut raw = super::super::config::defaults();
        raw["route_mode"] = json!("vpn_only");
        raw["rules"] = json!([]);
        raw["default_upstream"] = json!({"address":"https://provider.example/dns-query"});
        raw["default_pool"] = json!([
            {"address":"https://provider.example/custom"},
            {"address":"https://manual.example/dns-query","bootstrap_ips":["192.0.2.1"]},
            {"address":"https://192.0.2.3/dns-query"}
        ]);
        let config = Config::from_value(&raw).unwrap();
        let mut tunnel = Route::system();
        tunnel.id = "awg:warp".into();
        tunnel.index = 11;
        tunnel.interface = "awg11".into();
        let routes = [Route::system(), tunnel.clone()];
        let mut off = HashSet::from([scheduler::key(
            &tunnel.id,
            "https://provider.example/dns-query",
        )]);
        let expected = targets(&config, &off, &routes);
        assert_eq!(expected.len(), 1);
        assert_eq!(expected[0].0, Key::new(&tunnel, "provider.example"));
        let cache = Cache::default();
        let now = Instant::now();
        cache.maintain(&config, &off, &routes, now);
        let job = cache.next().unwrap();
        let Lookup::Pending(mut rx) = cache.request(&tunnel, "provider.example", now).unwrap()
        else {
            panic!("expected active refresh")
        };
        cache.prune_disabled(&config, &off);
        assert_eq!(cache.status().entries, 1);
        off.insert(scheduler::key(
            &tunnel.id,
            "https://provider.example/custom",
        ));
        cache.prune_disabled(&config, &off);
        assert!(rx
            .wait_for(Option::is_some)
            .await
            .unwrap()
            .as_ref()
            .unwrap()
            .is_err());
        cache.complete(&job, Ok(vec!["192.0.2.10".parse().unwrap()]), now);
        assert_eq!(cache.status().entries, 0);
        assert!(targets(&config, &off, &routes).is_empty());
    }

    fn capacity_config() -> (Config, String) {
        let mut raw = super::super::config::defaults();
        raw["awg_fallback"] = json!("off");
        raw["default_upstream"] = json!({"address":"https://provider-0.example/dns-query"});
        raw["default_pool"] = json!([]);
        raw["rules"] = json!((1..=CAPACITY)
            .map(|i| json!({
                "enabled": true,
                "domain": format!("query-{i}.example"),
                "upstream": {"address": format!("https://provider-{i}.example/dns-query")}
            }))
            .collect::<Vec<_>>());
        (
            Config::from_value(&raw).unwrap(),
            format!("provider-{CAPACITY}.example"),
        )
    }

    #[test]
    fn warm_queue_keeps_its_bound_and_yields_to_foreground_misses() {
        let (config, tail) = capacity_config();
        let cache = Cache::default();
        let now = Instant::now();
        let routes = [Route::system()];
        cache.maintain(&config, &HashSet::new(), &routes, now);
        let first = cache.next().unwrap();
        assert_eq!(first.key.host, "provider-0.example");
        let Lookup::Pending(_) = cache.request(&routes[0], &tail, now + RETRY).unwrap() else {
            panic!("expected queued foreground miss")
        };
        let live = cache.next().unwrap();
        assert_eq!(live.key.host, tail);
        assert_eq!(cache.status().entries, CAPACITY);
        assert!(cache.state.lock().unwrap().entries.contains_key(&first.key));
    }

    #[test]
    fn maintenance_refreshes_a_foreground_entry_beyond_the_warm_limit() {
        let (config, tail) = capacity_config();
        let off = HashSet::new();
        let cache = Cache::default();
        let now = Instant::now();
        let routes = [Route::system()];
        let warm = targets(&config, &off, &routes);
        assert_eq!(warm.len(), CAPACITY);
        assert!(warm.iter().all(|(key, _)| key.host != tail));

        let initial = IpAddr::from([192, 0, 2, 1]);
        cache.maintain(&config, &off, &routes, now);
        for _ in 0..CAPACITY {
            let job = cache.next().unwrap();
            assert_ne!(job.key.host, tail);
            cache.complete(&job, Ok(vec![initial]), now);
        }
        assert!(cache.next().is_none());
        assert!(matches!(
            cache.request(&routes[0], &tail, now).unwrap(),
            Lookup::Pending(_)
        ));
        let foreground = cache.next().unwrap();
        assert_eq!(foreground.key.host, tail);
        cache.complete(&foreground, Ok(vec![initial]), now);

        cache.maintain(&config, &off, &routes, now + RETRY);
        assert_eq!(cache.status().entries, CAPACITY);
        assert!(cache.next().is_none());

        let refresh = now + REFRESH;
        cache.maintain(&config, &off, &routes, refresh);
        let key = Key::new(&routes[0], &tail);
        assert!(cache.state.lock().unwrap().entries[&key]
            .flight
            .as_ref()
            .is_some_and(|f| !f.foreground));
        let updated = IpAddr::from([192, 0, 2, 2]);
        for _ in 0..CAPACITY {
            let job = cache.next().unwrap();
            cache.complete(&job, Ok(vec![updated]), refresh);
        }
        let Lookup::Ready(answer) = cache.request(&routes[0], &tail, refresh).unwrap() else {
            panic!("expected refreshed address")
        };
        assert_eq!(answer.as_ref(), &[updated]);
        assert!(cache.next().is_none());
        assert_eq!(cache.status().entries, CAPACITY);
    }

    #[test]
    fn maintenance_rebinds_current_route_and_discards_late_reply_after_replacement() {
        let mut raw = super::super::config::defaults();
        raw["route_mode"] = json!("vpn_only");
        raw["default_upstream"] = json!({"address":"https://provider.example/dns-query"});
        raw["default_pool"] = json!([]);
        raw["rules"] = json!([]);
        let config = Config::from_value(&raw).unwrap();
        let host = "provider.example";
        let off = HashSet::new();
        let cache = Cache::default();
        let now = Instant::now();
        let old = Route {
            id: "awg:warp".into(),
            name: "AWG".into(),
            interface: "awg11".into(),
            available: true,
            index: 11,
        };
        let Lookup::Pending(waiter) = cache.request(&old, host, now).unwrap() else {
            panic!("expected foreground lookup")
        };
        let current = Route {
            interface: "renamed11".into(),
            ..old.clone()
        };
        cache.maintain(&config, &off, std::slice::from_ref(&current), now);
        let old_job = cache.next().unwrap();
        assert_eq!(old_job.route.interface, current.interface);
        let replacement = Route {
            interface: "awg12".into(),
            index: 12,
            ..current
        };
        cache.maintain(&config, &off, std::slice::from_ref(&replacement), now);
        assert!(waiter.borrow().as_ref().is_some_and(Result::is_err));
        assert!(old_job
            .canceled
            .borrow()
            .as_ref()
            .is_some_and(Result::is_err));
        cache.complete(&old_job, Ok(vec![IpAddr::from([192, 0, 2, 1])]), now);
        assert_eq!(cache.status().ready, 0);
        assert!(!cache
            .state
            .lock()
            .unwrap()
            .entries
            .contains_key(&old_job.key));

        let new_job = cache.next().unwrap();
        assert_eq!(new_job.key, Key::new(&replacement, host));
        assert_eq!(new_job.route.interface, replacement.interface);
        let updated = IpAddr::from([192, 0, 2, 2]);
        cache.complete(&new_job, Ok(vec![updated]), now);
        let Lookup::Ready(answer) = cache.request(&replacement, host, now).unwrap() else {
            panic!("expected replacement route address")
        };
        assert_eq!(answer.as_ref(), &[updated]);
        assert_eq!(cache.status().entries, 1);
    }
}
