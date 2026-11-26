use super::config::{Config, Method, Upstream};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    io,
    sync::Mutex,
    time::{Duration, Instant, SystemTime},
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::sync::{watch, Semaphore};

pub const LIMIT: usize = 32;
pub const PROBE_INTERVAL: Duration = Duration::from_secs(5);
const PROBE_RECHECK: Duration = Duration::from_secs(60);
const STALE: Duration = Duration::from_secs(300);
use super::vpn::Route;
pub fn key(route: &str, upstream: &str) -> String {
    if route == "nfqws" {
        upstream.to_owned()
    } else {
        format!("{route}\n{upstream}")
    }
}
#[derive(Clone)]
pub struct Candidate<'a> {
    pub route: &'a Route,
    pub server: &'a Upstream,
    score: f64,
    last_result: Option<Instant>,
}
impl<'a> Candidate<'a> {
    fn new(route: &'a Route, server: &'a Upstream) -> Self {
        Self {
            route,
            server,
            score: 0.,
            last_result: None,
        }
    }
    pub(super) fn key(&self) -> String {
        key(&self.route.id, &self.server.address)
    }
    fn enabled(&self, disabled: &HashSet<String>) -> bool {
        self.route.available && (disabled.is_empty() || !disabled.contains(&self.key()))
    }
}
fn pool<'a>(
    routes: &'a [Route],
    cfg: &Config,
    primary: &'a Upstream,
    others: &'a [Upstream],
) -> Vec<Candidate<'a>> {
    std::iter::once(primary)
        .chain(others)
        .flat_map(|s| {
            routes
                .iter()
                .filter(|r| r.allowed(cfg))
                .map(move |r| Candidate::new(r, s))
        })
        .collect()
}

// The legacy route ID also gates the native router's default network path.
// VPN policies are validated separately before this resolver can start.
pub struct Policy {
    state: Mutex<MethodState>,
}
struct MethodState {
    off: HashSet<String>,
    calls: HashMap<String, (u64, usize, watch::Sender<bool>)>,
    serial: u64,
    revision: u64,
}
pub struct Lease<'a> {
    policy: &'a Policy,
    key: &'a str,
    serial: u64,
    pub canceled: watch::Receiver<bool>,
}
impl Policy {
    pub fn new(off: HashSet<String>) -> Self {
        Self {
            state: Mutex::new(MethodState {
                off,
                calls: HashMap::new(),
                serial: 0,
                revision: 0,
            }),
        }
    }
    pub fn read<T>(&self, read: impl FnOnce(&HashSet<String>) -> T) -> T {
        read(&self.state.lock().unwrap().off)
    }
    pub(super) fn revision(&self) -> u64 {
        self.state.lock().unwrap().revision
    }
    pub(super) fn try_revision(&self) -> Option<u64> {
        self.state.try_lock().ok().map(|s| s.revision)
    }
    pub fn apply(&self, off: HashSet<String>) {
        let mut s = self.state.lock().unwrap();
        if s.off != off {
            s.revision = s.revision.wrapping_add(1);
        }
        s.calls.retain(|key, (_, _, cancel)| {
            if off.contains(key) {
                cancel.send_replace(true);
                false
            } else {
                true
            }
        });
        s.off = off;
    }
    pub fn begin<'a>(&'a self, key: &'a str) -> io::Result<Lease<'a>> {
        let mut s = self.state.lock().unwrap();
        if s.off.contains(key) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "метод DNS выключен",
            ));
        }
        s.serial = s.serial.wrapping_add(1);
        let serial = s.serial;
        let entry = s
            .calls
            .entry(key.to_owned())
            .or_insert_with(|| (serial, 0, watch::channel(false).0));
        entry.1 += 1;
        Ok(Lease {
            policy: self,
            key,
            serial: entry.0,
            canceled: entry.2.subscribe(),
        })
    }
}
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        let mut s = self.policy.state.lock().unwrap();
        if let Some((generation, count, _)) = s.calls.get_mut(self.key) {
            if *generation == self.serial {
                *count -= 1;
                if *count == 0 {
                    s.calls.remove(self.key);
                }
            }
        }
    }
}
pub fn disabled(methods: &[Method]) -> HashSet<String> {
    methods.iter().map(|m| key(&m.route, &m.upstream)).collect()
}
pub struct Schedule {
    history: Mutex<History>,
    pub slots: Semaphore,
}
impl Default for Schedule {
    fn default() -> Self {
        Self {
            history: Default::default(),
            slots: Semaphore::new(LIMIT),
        }
    }
}
#[derive(Default)]
struct History {
    entries: HashMap<String, Entry>,
    races: u64,
    cursor: usize,
    probe_active: bool,
    last_probe: Option<Instant>,
}
#[derive(Clone)]
struct Entry {
    reliability: f64,
    latency: f64,
    attempts: u64,
    successes: u64,
    failures: u64,
    consecutive: u64,
    last_error: String,
    attempt: Option<Instant>,
    result: Option<Instant>,
    probe: Option<Instant>,
    probing: bool,
    probe_attempts: u64,
    probe_successes: u64,
    probe_failures: u64,
}
impl Default for Entry {
    fn default() -> Self {
        Self {
            reliability: 0.5,
            latency: 500.,
            attempts: 0,
            successes: 0,
            failures: 0,
            consecutive: 0,
            last_error: String::new(),
            attempt: None,
            result: None,
            probe: None,
            probing: false,
            probe_attempts: 0,
            probe_successes: 0,
            probe_failures: 0,
        }
    }
}
impl Entry {
    fn score(&self) -> f64 {
        100. * self.reliability
            - (self.latency / 20.).min(80.)
            - (self.consecutive as f64 * 20.).min(100.)
    }
    fn record(&mut self, duration: Duration, error: Option<&io::Error>, now: Instant) {
        let stale = self.result.is_some_and(|t| now.duration_since(t) >= STALE);
        let first = self.result.is_none() || stale;
        if stale {
            self.reliability = 0.5;
            self.latency = 500.;
            self.consecutive = 0;
        }
        self.result = Some(now);
        if let Some(e) = error {
            self.failures += 1;
            self.consecutive += 1;
            self.reliability = if first { 0. } else { 0.8 * self.reliability };
            self.last_error = e.to_string().chars().take(128).collect();
        } else {
            let ms = duration.as_millis() as f64;
            self.latency = if self.successes == 0 || stale {
                ms
            } else {
                0.8 * self.latency + 0.2 * ms
            };
            self.reliability = if first {
                1.
            } else {
                0.8 * self.reliability + 0.2
            };
            self.consecutive = 0;
            self.successes += 1;
            self.last_error.clear();
        }
    }
}
impl History {
    fn can_probe(&self, now: Instant) -> bool {
        !self.probe_active && self.last_probe.is_none_or(|t| now - t >= PROBE_INTERVAL)
    }
    fn entry(&mut self, address: &str) -> &mut Entry {
        if !self.entries.contains_key(address) && self.entries.len() >= 2048 {
            if let Some(oldest) = self
                .entries
                .iter()
                .filter(|(_, e)| !e.probing)
                .min_by_key(|(_, e)| e.attempt)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        self.entries.entry(address.to_owned()).or_default()
    }
    fn rank(&self, list: &mut [Candidate<'_>]) -> bool {
        let default = Entry::default();
        for candidate in list.iter_mut() {
            let entry = self.entries.get(&candidate.key()).unwrap_or(&default);
            candidate.score = entry.score();
            candidate.last_result = entry.result;
        }
        list.sort_by(|a, b| b.score.total_cmp(&a.score));
        if self.races.wrapping_add(1).is_multiple_of(8) && list.len() > 1 {
            let slowest = list
                .iter()
                .enumerate()
                .min_by_key(|(_, u)| u.last_result)
                .unwrap()
                .0;
            list[..=slowest].rotate_right(1);
            return true;
        }
        false
    }
}
pub struct Attempt<'a> {
    owner: &'a Schedule,
    address: &'a str,
    probe: bool,
    start: Instant,
}
impl Attempt<'_> {
    pub fn finish(self, error: Option<&io::Error>) {
        let now = Instant::now();
        let mut history = self.owner.history.lock().unwrap();
        let entry = history.entry(self.address);
        entry.record(now - self.start, error, now);
        if self.probe {
            entry.probe_successes += u64::from(error.is_none());
            entry.probe_failures += u64::from(error.is_some());
        }
    }
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if self.probe {
            let mut history = self.owner.history.lock().unwrap();
            history.probe_active = false;
            if let Some(e) = history.entries.get_mut(self.address) {
                e.probing = false;
            }
        }
    }
}
impl Schedule {
    pub fn begin<'a>(&'a self, address: &'a str, probe: bool) -> Option<Attempt<'a>> {
        let mut history = self.history.lock().unwrap();
        let now = Instant::now();
        if probe {
            if !history.can_probe(now) {
                return None;
            }
            history.probe_active = true;
            history.last_probe = Some(now);
        }
        let e = history.entry(address);
        e.attempts += 1;
        e.attempt = Some(now);
        if probe {
            e.probing = true;
            e.probe = Some(now);
            e.probe_attempts += 1;
        }
        Some(Attempt {
            owner: self,
            address,
            probe,
            start: now,
        })
    }
    pub fn order<'a>(
        &self,
        cfg: &'a Config,
        name: &str,
        disabled: &HashSet<String>,
        routes: &'a [Route],
    ) -> Vec<Candidate<'a>> {
        let (_, primary, others) = cfg.servers(name);
        let mut list = pool(routes, cfg, primary, others);
        list.retain(|c| c.enabled(disabled));
        if cfg.scheduler_enabled && list.len() > 1 {
            let mut history = self.history.lock().unwrap();
            history.rank(&mut list);
            history.races = history.races.wrapping_add(1);
        }
        list
    }
    pub fn next_probe<'a>(
        &self,
        cfg: &'a Config,
        disabled: &HashSet<String>,
        shadow: Option<&super::shadow::Matcher>,
        routes: &'a [Route],
    ) -> Option<(&'a str, Candidate<'a>)> {
        if !cfg.scheduler_enabled {
            return None;
        }
        let routes: Vec<_> = routes
            .iter()
            .filter(|r| r.available && r.allowed(cfg))
            .collect();
        let candidates_for = |server: &'a Upstream| {
            routes.iter().copied().filter_map(move |route| {
                let candidate = Candidate::new(route, server);
                candidate.enabled(disabled).then_some(candidate)
            })
        };
        let mut seen = HashSet::new();
        let mut providers = Vec::new();
        let groups = std::iter::once((".", &cfg.default_upstream, &cfg.default_pool)).chain(
            cfg.rules
                .iter()
                .filter(|rule| rule.enabled)
                .map(|rule| (rule.domain.as_str(), &rule.upstream, &rule.pool)),
        );
        for (domain, primary, rest) in groups {
            if shadow.is_some_and(|m| m.matches(domain)) {
                continue;
            }
            let servers = std::iter::once(primary).chain(rest);
            if servers.clone().flat_map(candidates_for).take(2).count() < 2 {
                continue;
            }
            for server in servers {
                // The same URL has the same allowed routes across groups.
                // Keep its first representative, including its bootstrap IPs.
                if seen.insert(server.address.as_str()) {
                    providers.push((domain, server));
                }
            }
        }
        let candidates = providers
            .iter()
            .copied()
            .flat_map(|(domain, server)| candidates_for(server).map(move |c| (domain, c)));
        let total = if disabled.is_empty() {
            providers.len() * routes.len()
        } else {
            candidates.clone().count()
        };
        let mut h = self.history.lock().unwrap();
        let now = Instant::now();
        if total == 0 || !h.can_probe(now) {
            return None;
        }
        let cursor = h.cursor % total;
        let candidates = candidates.enumerate();
        let mut selected = None;
        let mut oldest = None;
        for (i, (domain, candidate)) in candidates
            .clone()
            .skip(cursor)
            .chain(candidates.take(cursor))
        {
            let entry = h.entries.get(&candidate.key());
            let result = entry.and_then(|e| e.result);
            if result.is_some_and(|t| now - t < PROBE_RECHECK) {
                continue;
            }
            let priority = (result, entry.and_then(|e| e.probe));
            if oldest.is_none_or(|previous| priority < previous) {
                oldest = Some(priority);
                selected = Some((i, domain, candidate));
                if priority == (None, None) {
                    break;
                }
            }
        }
        let (i, domain, candidate) = selected?;
        h.cursor = (i + 1) % total;
        Some((domain, candidate))
    }
    pub fn snapshot(&self, cfg: &Config, name: &str, running: bool, routes: &[Route]) -> Value {
        let excluded = disabled(&cfg.disabled_methods);
        let (source, primary, others) = cfg.servers(name);
        let (mut on, off): (Vec<_>, Vec<_>) = pool(routes, cfg, primary, others)
            .into_iter()
            .partition(|c| c.route.status(cfg, running).available && !excluded.contains(&c.key()));
        let n = on.len();
        let h = self.history.lock().unwrap();
        let effective = cfg.scheduler_enabled && n > 1;
        let exploring = effective && h.rank(&mut on);
        let candidates:Vec<_>=on.into_iter().chain(off).enumerate().map(|(i,c)|{
            let key = c.key();
            let e=if effective{h.entries.get(&key).cloned().unwrap_or_default()}else{Entry::default()};
            let disabled=excluded.contains(&key);let r=|x:f64|(x*100.).round()/100.;
            let route = c.route.status(cfg, running);
            json!({"position":if disabled{0}else{i+1},"route":c.route.id,"route_name":c.route.name,"upstream":c.server.address,"available":route.available,"disabled":disabled,
                "score":if effective{r(e.score())}else{0.},"reliability":if effective{e.reliability}else{0.},"latency_ms":if effective{r(e.latency)}else{0.},
                "latency_penalty":if effective{r((e.latency/20.).min(80.))}else{0.},"failure_penalty":(e.consecutive*20).min(100),
                "attempts":e.attempts,"successes":e.successes,"failures":e.failures,"consecutive_failures":e.consecutive,"last_error":route.error.unwrap_or(&e.last_error),
                "last_attempt_at":timestamp(e.attempt),"last_result_at":timestamp(e.result),"last_probe_at":timestamp(e.probe),"probing":e.probing&&!disabled,
                "probe_attempts":e.probe_attempts,"probe_successes":e.probe_successes,"probe_failures":e.probe_failures,"exploration":exploring && i==0})
        }).collect();
        let reason = if !cfg.scheduler_enabled {
            "disabled"
        } else if n == 0 {
            "no_candidates"
        } else if n == 1 {
            "single_candidate"
        } else {
            ""
        };
        json!({"enabled":cfg.scheduler_enabled,"effective":effective,"reason":reason,"effective_candidate_count":n,"domain":name,"pool_source":source,
            "parallel_limit":LIMIT,"tracked_pairs":if cfg.scheduler_enabled {h.entries.len()} else {0},"active_probes":usize::from(cfg.scheduler_enabled && h.probe_active),"probe_interval_seconds":5,"probe_recheck_seconds":60,"candidates":candidates,
            "formula":"100 × надёжность − min(80, задержка EWMA / 20) − min(100, 20 × ошибок подряд). Вес нового результата 20%. Отмена сохраняет прежнюю оценку."})
    }
}
fn timestamp(when: Option<Instant>) -> String {
    when.and_then(|t| SystemTime::now().checked_sub(t.elapsed()))
        .and_then(|v| OffsetDateTime::from(v).format(&Rfc3339).ok())
        .unwrap_or_default()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disabled_schedule_preserves_provider_first_order_without_showing_old_evidence() {
        let mut raw = crate::dnsserver::config::defaults();
        raw["default_upstream"] = json!({"address":"https://a.test/dns-query"});
        raw["default_pool"] = json!([{"address":"https://b.test/dns-query"}]);
        raw["rules"] = json!([]);
        raw["scheduler_enabled"] = json!(false);
        let cfg = Config::from_value(&raw).unwrap();
        let routes = [
            Route::system(),
            Route {
                id: "awg:warp".into(),
                ..Route::system()
            },
        ];
        let schedule = Schedule::default();
        let b = key("nfqws", &cfg.default_pool[0].address);
        schedule.begin(&b, false).unwrap().finish(None);
        let probe = schedule.begin(&b, true).unwrap();
        let ordered = schedule.order(&cfg, "ordinary.test", &HashSet::new(), &routes);
        let a = cfg.default_upstream.address.as_str();
        let b = cfg.default_pool[0].address.as_str();
        assert_eq!(
            ordered
                .iter()
                .map(|c| (c.route.id.as_str(), c.server.address.as_str()))
                .collect::<Vec<_>>(),
            [("nfqws", a), ("awg:warp", a), ("nfqws", b), ("awg:warp", b)]
        );
        let view = schedule.snapshot(&cfg, "ordinary.test", true, &routes);
        assert_eq!(view["reason"], "disabled");
        assert_eq!(view["tracked_pairs"], 0);
        assert_eq!(view["active_probes"], 0);
        assert!(view["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["attempts"] == 0
                && entry["probe_attempts"] == 0
                && entry["probing"] == false));
        drop(probe);
    }
    #[test]
    fn adaptive_order_follows_results_explores_and_resets_stale_scores() {
        let mut v = crate::dnsserver::config::defaults();
        v["default_upstream"] = json!({"address":"https://a.test"});
        v["default_pool"] = json!([{"address":"https://b.test"}]);
        let cfg = Config::from_value(&v).unwrap();
        let sched = Schedule::default();
        let a = &cfg.default_upstream.address;
        let b = &cfg.default_pool[0].address;
        let now = Instant::now();
        let failure = io::Error::other("upstream");
        let mut history = sched.history.lock().unwrap();
        history
            .entry(a)
            .record(Duration::from_millis(5), Some(&failure), now);
        history
            .entry(b)
            .record(Duration::from_millis(80), None, now);
        let e = history.entries.get(a).unwrap();
        assert_eq!((e.reliability, e.latency, e.consecutive), (0., 500., 1));
        drop(history);
        let off = HashSet::new();
        let routes = vec![Route::system()];
        for _ in 0..7 {
            assert_eq!(
                &sched.order(&cfg, "x.test", &off, &routes)[0].server.address,
                b
            );
        }
        let snap = sched.snapshot(&cfg, "", true, &routes);
        assert_eq!(snap["candidates"][0]["exploration"], true);
        assert_eq!(snap["effective_candidate_count"], 2);
        let mut h = sched.history.lock().unwrap();
        let e = h.entries.get_mut(a).unwrap();
        e.record(Duration::from_millis(40), None, now + STALE);
        assert_eq!((e.reliability, e.latency, e.consecutive), (1., 40., 0));
        drop(h);
        let blocked = HashSet::from([b.clone()]);
        assert!(sched.next_probe(&cfg, &blocked, None, &routes).is_none());
        assert_eq!(sched.order(&cfg, "home", &blocked, &routes).len(), 1);
    }
    #[test]
    fn probes_share_cadence_and_keep_the_first_competing_pool_for_each_pair() {
        let mut v = crate::dnsserver::config::defaults();
        v["default_upstream"] = json!({"address":"https://a.test/dns-query"});
        v["default_pool"] = json!([{"address":"https://b.test/dns-query"}]);
        v["rules"] = json!([
            {"domain":"special.test","enabled":true,
             "upstream":{"address":"https://a.test/dns-query","bootstrap_ips":["192.0.2.1"]},
             "pool":[{"address":"https://c.test/dns-query"}]},
            {"domain":"single.test","enabled":true,"upstream":{"address":"https://d.test/dns-query"}},
            {"domain":"shadow.test","enabled":true,"upstream":{"address":"https://e.test/dns-query"},
             "pool":[{"address":"https://f.test/dns-query"}]}
        ]);
        v["shadow_dns"] = json!({"enabled":true,"domains":[{"domain":"shadow.test"}]});
        let cfg = Config::from_value(&v).unwrap();
        let shadow = super::super::shadow::Matcher::compile(&cfg.shadow_dns).unwrap();
        let routes = [Route::system()];
        let off = HashSet::new();
        let schedule = Schedule::default();
        for (domain, upstream) in [
            (".", &cfg.default_upstream),
            (".", &cfg.default_pool[0]),
            ("special.test", &cfg.rules[0].pool[0]),
            (".", &cfg.default_upstream),
        ] {
            let (name, candidate) = schedule
                .next_probe(&cfg, &off, Some(&shadow), &routes)
                .unwrap();
            assert_eq!(name, domain);
            assert!(std::ptr::eq(candidate.server, upstream));
            let key = candidate.key();
            let attempt = schedule.begin(&key, true).unwrap();
            assert!(schedule.begin("other", true).is_none());
            drop(attempt);
            assert!(schedule
                .next_probe(&cfg, &off, Some(&shadow), &routes)
                .is_none());
            let snapshot = schedule.snapshot(&cfg, "", true, &routes);
            assert_eq!(snapshot["active_probes"], 0);
            assert_eq!(snapshot["candidates"][0]["probe_failures"], 0);
            schedule.history.lock().unwrap().last_probe = Some(Instant::now() - PROBE_INTERVAL);
        }
    }
    #[test]
    fn disabling_then_enabling_cancels_prior_leases_and_preserves_new_attempts() {
        let policy = Policy::new(HashSet::new());
        let old = policy.begin("dns").unwrap();
        let other = policy.begin("other").unwrap();
        policy.apply(HashSet::from(["dns".into()]));
        assert!(policy.begin("dns").is_err());
        policy.apply(HashSet::new());
        let new = policy.begin("dns").unwrap();
        drop(other);
        assert!(*old.canceled.borrow());
        assert!(!*new.canceled.borrow());
        drop(old);
        assert_eq!(policy.state.lock().unwrap().calls.len(), 1);
        drop(new);
        assert!(policy.state.lock().unwrap().calls.is_empty());
    }
}
