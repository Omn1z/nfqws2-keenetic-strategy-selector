use super::*;
#[cfg(any(target_os = "linux", test))]
mod endpoint_hints;
mod inherited_transport;
mod named_reconnect;
mod nested_policy;
pub use named_reconnect::{
    named_reconnect_profile, ClientRecoveryPass, NamedReconnectInput, NamedReconnectRequest,
    NamedReconnectTarget, ResolvedNamedReconnect,
};
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

const MAX_BACKUPS: usize = 8;
const PENDING_ENDPOINT_RESTART: &str = "rust_pending_endpoint_restart";

#[derive(Debug)]
pub struct EndpointBackupsPersistenceUncertain {
    save: io::Error,
    restore: io::Error,
}

impl std::fmt::Display for EndpointBackupsPersistenceUncertain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "не удалось подтвердить сохранение резервных IP или восстановить прежний файл; состояние на диске требует повторной проверки: {}. {}", self.save, self.restore)
    }
}

impl std::error::Error for EndpointBackupsPersistenceUncertain {}

fn commit_backup_row(db: &Store, id: &str, prior: &Value, next: &Value) -> io::Result<()> {
    db.transaction(|tx| {
        if find(&read(db)?, id)? != prior {
            return Err(invalid("подключение изменилось во время операции"));
        }
        let replace = |expected: &Value, replacement: &Value| {
            crate::edit_document_locked(tx, |doc| {
                if find(doc, id)? != expected {
                    return Err(invalid("подключение изменилось во время операции"));
                }
                let row = doc["servers"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|r| r["id"] == id)
                    .unwrap();
                *row = replacement.clone();
                Ok(())
            })
        };
        if let Err(save) = replace(prior, next) {
            // Directory sync can fail after a rename. Recheck and recover
            // the previous published row before touching the running peer.
            let restored = read(db).and_then(|doc| {
                if find(&doc, id)? == prior {
                    Ok(())
                } else {
                    replace(next, prior)
                }
            });
            if let Err(restore) = restored {
                return Err(io::Error::other(EndpointBackupsPersistenceUncertain {
                    save,
                    restore,
                }));
            }
            return Err(save);
        }
        Ok(())
    })
}

pub(super) fn pending_endpoint_restart(row: &Value) -> io::Result<Option<bool>> {
    row.get(PENDING_ENDPOINT_RESTART)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| invalid("неверная запись ожидающего переключения endpoint"))
        })
        .transpose()
}

pub(super) fn normalize(primary: &str, inputs: &[String]) -> io::Result<Vec<String>> {
    if inputs.is_empty() {
        return Ok(vec![]);
    }
    if inputs.len() > MAX_BACKUPS {
        return Err(invalid("резервных IP должно быть не больше восьми"));
    }
    let (host, port) = conf::endpoint(primary)?;
    let mut seen = HashSet::new();
    if let Ok(ip) = host.parse::<IpAddr>() {
        seen.insert(SocketAddr::new(ip.to_canonical(), port));
    }
    let mut out = Vec::new();
    for raw in inputs.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        let addr = raw
            .parse::<IpAddr>()
            .map(|ip| SocketAddr::new(ip, port))
            .or_else(|_| raw.parse::<SocketAddr>())
            .map_err(|_| invalid("резервный endpoint должен быть IPv4/IPv6 или IP:порт"))?;
        let ip = addr.ip().to_canonical();
        if addr.port() == 0 || ip.is_unspecified() || ip.is_multicast() || raw.contains('%') {
            return Err(invalid("неверный адрес или порт резервного endpoint"));
        }
        let addr = SocketAddr::new(ip, addr.port());
        if seen.insert(addr) {
            out.push(addr.to_string());
        }
    }
    Ok(out)
}
fn pool(row: &Value) -> Vec<String> {
    let primary = s(wire(row), "endpoint").trim();
    let mut out = vec![primary.to_owned()];
    if !row["config"]["client"]["endpoint_backups"].is_null() {
        // Old or damaged reserve lists never become dial targets. The primary
        // remains independently usable, like the previous router engine.
        if let Ok(saved) = serde_json::from_value::<Vec<String>>(
            row["config"]["client"]["endpoint_backups"].clone(),
        ) {
            if let Ok(valid) = normalize(primary, &saved) {
                out.extend(valid);
            }
        }
    }
    out
}

pub(super) fn mtu_endpoint_in_pool(row: &Value, endpoint: &str) -> bool {
    !endpoint.is_empty() && pool(row).iter().any(|saved| saved == endpoint)
}

pub(super) fn routed_mtu_endpoint(
    row: &Value,
    managed: &Managed,
    live: SocketAddr,
) -> Option<String> {
    let candidates = pool(row);
    let selected = managed
        .recovery
        .selected()
        .filter(|endpoint| candidates.iter().skip(1).any(|saved| saved == *endpoint));
    selected.map(str::to_owned).or_else(|| {
        let live = json!({"running":true,"endpoint":live});
        endpoint_index(&candidates, &live, crate::endpoint::cached_endpoint_address)
            .map(|index| candidates[index].clone())
    })
}

fn endpoint_index(
    pool: &[String],
    live: &Value,
    mut cached: impl FnMut(&str) -> Option<SocketAddr>,
) -> Option<usize> {
    if live["running"] != true || live["status_unavailable"] == true {
        return None;
    }
    fn canonical(addr: SocketAddr) -> Option<SocketAddr> {
        if addr.port() == 0 || matches!(addr, SocketAddr::V6(v6) if v6.scope_id() != 0) {
            return None;
        }
        Some(SocketAddr::new(addr.ip().to_canonical(), addr.port()))
    }
    fn literal(value: &str) -> Option<SocketAddr> {
        let value = value.trim();
        if value.contains('%') {
            return None;
        }
        canonical(value.parse().ok()?)
    }
    let current = literal(s(live, "endpoint"))?;
    // A matching saved literal wins even if the primary hostname currently
    // resolves to the same socket address. Do not resolve a name here.
    pool.iter()
        .position(|candidate| literal(candidate) == Some(current))
        .or_else(|| {
            pool.iter().position(|candidate| {
                conf::endpoint(candidate).is_ok_and(|(_, port)| port == current.port())
                    && cached(candidate).and_then(canonical) == Some(current)
            })
        })
}

fn authenticated_literal_reserve(pool: &[String], snapshot: Option<&Value>) -> bool {
    snapshot.is_some_and(|status| {
        status["connected"] == true
            && status["socket_mark"]
                .as_u64()
                .is_some_and(|mark| mark == 0 || mark == u64::from(crate::DIRECT_SOCKET_MARK))
            && endpoint_index(pool, status, |_| None).is_some_and(|index| index > 0)
    })
}

fn usable_endpoint_ip(ip: IpAddr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(ip) => !ip.is_broadcast() && !ip.is_link_local(),
        IpAddr::V6(ip) => !ip.is_unicast_link_local(),
    }
}

pub(super) fn canonical_transport(address: SocketAddr) -> Option<SocketAddr> {
    let ip = address.ip().to_canonical();
    (address.port() != 0
        && usable_endpoint_ip(ip)
        && !matches!(address, SocketAddr::V6(a) if a.scope_id() != 0))
    .then_some(SocketAddr::new(ip, address.port()))
}

pub(super) fn live_transport_endpoint(live: &Value) -> Option<SocketAddr> {
    if live["running"] != true || live["status_unavailable"] == true {
        return None;
    }
    let endpoint = s(live, "endpoint");
    if endpoint.contains('%') {
        return None;
    }
    canonical_transport(endpoint.parse().ok()?)
}

/// Return saved numeric transports and recent DNS results without resolving
/// names or reading the live state of a tunnel.
pub fn transport_endpoints(db: &Store) -> io::Result<Vec<SocketAddr>> {
    let doc = read(db)?;
    let mut addresses = std::collections::BTreeSet::new();
    for row in doc["servers"].as_array().into_iter().flatten() {
        if row["config"]["enabled"] != true {
            continue;
        }
        addresses.extend(super::settings::retiring_routed_transport(&doc, row));
        let pinned = super::settings::routed_hostname_addresses(&doc, row)?;
        let skip_primary = usize::from(pinned.is_some());
        addresses.extend(pinned.into_iter().flatten());
        for candidate in pool(row).into_iter().skip(skip_primary) {
            if candidate.contains('%') {
                continue;
            }
            if let Some(address) = candidate
                .parse::<SocketAddr>()
                .ok()
                .or_else(|| crate::endpoint::cached_endpoint_address(&candidate))
                .and_then(canonical_transport)
            {
                addresses.insert(address);
            }
        }
    }
    Ok(addresses.into_iter().collect())
}

/// A numeric UDP tuple selected for a validated client, together with any
/// inherited direct endpoints verified during this watchdog tick.
#[derive(Clone, Copy)]
pub struct TransportBypassProof<'a> {
    pub endpoint: SocketAddr,
    pub inherited: &'a [SocketAddr],
    pub deadline: Instant,
}

const REFRESH_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) struct InheritedTransports {
    addresses: Vec<SocketAddr>,
    expires: Instant,
}

pub(super) type TransportPreparation<'a> = (&'a RefreshTransport<'a>, &'a InheritedTransports);

impl InheritedTransports {
    pub(super) fn collect(read: impl FnOnce() -> io::Result<Vec<SocketAddr>>) -> io::Result<Self> {
        let expires = Instant::now() + Duration::from_secs(7);
        Ok(Self {
            addresses: read()?,
            expires,
        })
    }

    pub(super) fn prepare(
        &self,
        refresh: &RefreshTransport<'_>,
        endpoint: SocketAddr,
    ) -> io::Result<()> {
        let endpoint = canonical_transport(endpoint)
            .ok_or_else(|| invalid("неверный адрес транспортного endpoint"))?;
        let now = Instant::now();
        let mut deadline = now + REFRESH_TIMEOUT;
        if !self.addresses.is_empty() {
            if now >= self.expires {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            deadline = deadline.min(self.expires);
        }
        refresh(TransportBypassProof {
            endpoint,
            inherited: &self.addresses,
            deadline,
        })?;
        if Instant::now() >= deadline {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        Ok(())
    }

    fn prepare_probe(
        &self,
        tunnel: &mut dyn Tunnel,
        snapshot: Option<&Value>,
        pool: &[String],
        physical_wan: impl FnOnce(SocketAddr, u32) -> bool,
        prepare: impl FnOnce(SocketAddr) -> io::Result<()>,
    ) -> io::Result<()> {
        let endpoint = snapshot
            .and_then(|live| {
                live_transport_endpoint(live).filter(|address| {
                    self.addresses.contains(address)
                        || endpoint_index(pool, live, crate::endpoint::cached_endpoint_address)
                            .is_some()
                        || pool.iter().any(|item| {
                            conf::endpoint(item).is_ok_and(|(_, port)| port == address.port())
                        }) && live["socket_mark"]
                            .as_u64()
                            .and_then(|mark| u32::try_from(mark).ok())
                            .is_some_and(|mark| physical_wan(*address, mark))
                })
            })
            .ok_or_else(|| invalid("текущий endpoint клиента AWG не подтверждён"))?;
        prepare(endpoint)?;
        tunnel.probe_at(endpoint)
    }
}

pub(super) fn prepare_transport(
    transport: Option<TransportPreparation<'_>>,
    endpoint: SocketAddr,
) -> io::Result<()> {
    match transport {
        Some((refresh, inherited)) => inherited.prepare(refresh, endpoint),
        None => Ok(()),
    }
}

pub(super) fn check_recovery_row(db: &Store, row: &Value) -> io::Result<()> {
    if find(&read(db)?, s(row, "id"))? != row {
        return Err(io::Error::from(io::ErrorKind::WouldBlock));
    }
    Ok(())
}

impl Runtime {
    pub(super) fn routed_retry_hints(&self, candidates: &[String], wan: &[String]) -> Vec<bool> {
        #[cfg(target_os = "linux")]
        if self.root == std::path::Path::new("/") {
            return endpoint_hints::collect(candidates, wan);
        }
        #[cfg(not(target_os = "linux"))]
        let _ = (candidates, wan);
        Vec::new()
    }

    pub(super) fn capture_inherited_transport(
        &self,
        doc: &Value,
        owned: &HashMap<String, Managed>,
        wan: &[String],
    ) -> InheritedTransports {
        InheritedTransports {
            expires: Instant::now() + Duration::from_secs(7),
            addresses: self.inherited_transport_from(doc, owned, wan),
        }
    }

    pub(super) fn collect_transport(
        &self,
        db: &Store,
        wan: &[String],
        refresh: Option<&RefreshTransport<'_>>,
    ) -> io::Result<Option<InheritedTransports>> {
        refresh
            .map(|_| InheritedTransports::collect(|| self.inherited_transport_endpoints(db, wan)))
            .transpose()
    }
}
#[derive(Clone, Copy)]
struct PeerTiming {
    key_lifetime: u64,
    demand_timeout: u64,
}
impl Default for PeerTiming {
    fn default() -> Self {
        Self {
            key_lifetime: 180,
            demand_timeout: 20,
        }
    }
}
impl PeerTiming {
    fn from_config(config: &Value) -> Self {
        let upper = |field: &str, default| {
            s(&config["obf"], field)
                .rsplit('-')
                .next()
                .and_then(|v| v.parse::<u32>().ok())
                .filter(|&v| v > 0)
                .map(u64::from)
                .unwrap_or(default)
        };
        // The userspace engine discards keypairs at the upper bound of
        // RejectAfterTime. For data TX it initiates a new handshake after
        // KeepaliveTimeout + RekeyTimeout (with subsecond jitter).
        Self {
            key_lifetime: upper("reject_after_time", 180).max(180),
            demand_timeout: (upper("keepalive_timeout", 10) + upper("rekey_timeout", 5) + 1)
                .max(20),
        }
    }
}
#[derive(Default)]
pub(super) struct Recovery {
    pub(super) nested: nested_policy::State,
    candidate: String,
    inherited_endpoint_observed: bool,
    since: u64,
    probe_at: u64,
    attempt: u64,
    attempts: u32,
    verification: bool,
    timing: PeerTiming,
    last_tick: Option<Instant>,
    observed_at: u64,
    handshake: u64,
    rx: Option<u64>,
    tun_tx: Option<u64>,
    demand_since: u64,
    last_tx: u64,
    probe_sent: bool,
    healthy_at: u64,
    tried: u16,
    exhausted: bool,
    error: String,
    named_ticket: Option<std::sync::Arc<()>>,
    named_hint: Option<named_reconnect::NamedLookupHint>,
}
#[derive(PartialEq, Eq, Debug)]
enum Action {
    Wait,
    Probe,
    Reconnect,
}
impl Recovery {
    pub(super) fn at_numeric_reserve(endpoint: SocketAddr) -> Self {
        Self {
            candidate: endpoint.to_string(),
            ..Self::default()
        }
    }

    #[cfg(target_os = "linux")]
    pub(super) fn from_inherited(tunnel: &dyn Tunnel, row: &Value, doc: &Value) -> Self {
        let now = crate::now();
        let snapshot = tunnel.snapshot().ok();
        let mut state = Self {
            timing: PeerTiming::from_config(wire(row)),
            ..Self::default()
        };
        state.select_initial(&pool(row), true, snapshot.as_ref());
        if let Some(sample) = snapshot
            .as_ref()
            .filter(|sample| sample["connected"] == true)
        {
            state.observe(
                now,
                true,
                Some(sample),
                &crate::recovery_settings(&doc["recovery_settings"]),
            );
        }
        if tunnel.nested_iface().is_some() {
            state.nested.adopt_saved(now);
        }
        state
    }

    pub(super) fn authenticated(&self, now: u64) -> bool {
        self.since == 0 && self.recent(now) && self.nested.usable()
    }
    fn recent(&self, now: u64) -> bool {
        self.healthy_at > 0
            && now
                .checked_sub(self.healthy_at)
                .is_some_and(|age| age < self.timing.key_lifetime)
    }
    pub(super) fn needs_reserve(&self, now: u64, timeout: u64, has_endpoints: bool) -> bool {
        self.since != 0
            && (!has_endpoints || self.exhausted)
            && (self.attempts > 1 || self.attempts > 0 && now >= self.since.saturating_add(timeout))
    }
    pub(super) fn failed_start(now: u64, error: &io::Error) -> Self {
        let mut r = Self {
            since: now,
            ..Default::default()
        };
        r.attempted(now, &Err(io::Error::other(error.to_string())));
        r
    }
    pub(super) fn selected(&self) -> Option<&str> {
        (!self.candidate.is_empty()).then_some(self.candidate.as_str())
    }
    pub(super) fn remember_routed_mtu_endpoint(&mut self, endpoint: &str) {
        self.candidate = endpoint.to_owned();
    }
    pub(super) fn retry_at(&self, settings: &Value) -> u64 {
        if self.attempt == 0 {
            return 0;
        }
        let base = self.attempt
            + if self.verification {
                settings["handshake_timeout_seconds"].as_u64().unwrap()
            } else {
                0
            };
        let duration = base.saturating_sub(self.since);
        base + if duration < settings["fast_retry_seconds"].as_u64().unwrap() {
            0
        } else if duration < settings["slow_retry_after_seconds"].as_u64().unwrap() {
            settings["retry_delay_seconds"].as_u64().unwrap()
        } else {
            settings["slow_retry_delay_seconds"].as_u64().unwrap()
        }
    }
    pub(super) fn note_edit_failure(&mut self, now: u64, error: &io::Error) {
        if self.since == 0 {
            self.since = now;
        }
        self.attempted(now, &Err(io::Error::other(error.to_string())));
    }
    // Router clocks can jump when NTP starts. Preserve the elapsed age of
    // observations and deadlines using monotonic time. The raw UAPI handshake
    // remains untouched so that a wall-clock step cannot look like a new one.
    fn adjust_clock(&mut self, now: u64, tick: Instant) {
        let Some(previous) = self.last_tick.replace(tick) else {
            return;
        };
        let expected = self
            .observed_at
            .saturating_add(tick.duration_since(previous).as_secs());
        if now.abs_diff(expected) <= 2 {
            return;
        }
        for timestamp in [
            &mut self.observed_at,
            &mut self.healthy_at,
            &mut self.since,
            &mut self.attempt,
            &mut self.probe_at,
            &mut self.demand_since,
            &mut self.last_tx,
        ] {
            if *timestamp > 0 {
                *timestamp = now
                    .saturating_sub(expected.saturating_sub(*timestamp))
                    .max(1);
            }
        }
    }
    // Returns true while the TUN has sustained outbound demand without
    // authenticated input for at least the native peer-response timer.
    fn observe_traffic(&mut self, now: u64, v: &Value) -> bool {
        let hs = v["last_handshake"].as_u64().unwrap_or(0);
        let rx = v["rx_bytes"].as_u64();
        let tx = v["tun_tx_packets"].as_u64();
        let reset = rx.zip(self.rx).is_some_and(|(new, old)| new < old) || hs < self.handshake;
        let received = !reset && hs != 0 && rx.zip(self.rx).is_some_and(|(new, old)| new > old);
        let fresh_handshake =
            hs > self.handshake && hs <= now && now - hs < self.timing.key_lifetime;
        if received || fresh_handshake || reset {
            self.clear_probe();
            self.healthy_at = if received { now } else { 0 };
        }
        if hs <= now && (hs != self.handshake || self.rx.is_none() || reset) {
            self.healthy_at = self.healthy_at.max(hs);
        }
        if tx.zip(self.tun_tx).is_some_and(|(new, old)| new > old)
            && !received
            && !fresh_handshake
            && !reset
        {
            if self.last_tx == 0 || now.saturating_sub(self.last_tx) > 10 {
                self.demand_since = now;
            }
            self.last_tx = now;
        } else if now.saturating_sub(self.last_tx) > 10 || tx.is_none() || tx < self.tun_tx {
            self.last_tx = 0;
            self.demand_since = 0;
        }
        self.handshake = hs;
        self.rx = rx;
        self.tun_tx = tx;
        self.demand_since != 0
            && now.saturating_sub(self.demand_since) >= self.timing.demand_timeout
    }
    fn observe(
        &mut self,
        now: u64,
        live: bool,
        snapshot: Option<&Value>,
        settings: &Value,
    ) -> Action {
        if now.saturating_sub(self.observed_at) > 60 {
            // A suspended watchdog cannot prove continuous outbound traffic.
            self.clear_probe();
        }
        self.observed_at = now;
        let sample = snapshot.filter(|v| live && v["running"] == true);
        let demand = sample.is_some_and(|v| self.observe_traffic(now, v));
        if sample.is_some() && self.recent(now) && !demand {
            self.probe_at = 0;
            self.probe_sent = false;
            self.since = 0;
            self.attempt = 0;
            self.attempts = 0;
            self.verification = false;
            self.error.clear();
            self.tried = 0;
            self.exhausted = false;
            self.named_ticket = None;
            return Action::Wait;
        }
        if self.since == 0 && !(demand && self.recent(now)) {
            self.since = now;
        }
        if now < self.retry_at(settings) {
            return Action::Wait;
        }
        if !live || self.attempts > 0 {
            return Action::Reconnect;
        }
        let wait = settings["handshake_timeout_seconds"].as_u64().unwrap();
        if self.probe_at == 0 && sample.is_some() {
            self.probe_at = now;
            self.probe_sent = true;
            return Action::Probe;
        }
        let started = if self.probe_at != 0 {
            self.probe_at
        } else {
            self.since
        };
        if now.saturating_sub(started) < wait {
            Action::Wait
        } else {
            if self.since == 0 {
                self.since = started;
            }
            Action::Reconnect
        }
    }
    fn clear_probe(&mut self) {
        self.demand_since = 0;
        self.last_tx = 0;
        self.probe_at = 0;
        self.probe_sent = false;
    }
    fn activity(&self, live: &mut Value, now: u64) {
        let hs = live["last_handshake"].as_u64().unwrap_or(0);
        let same_peer = hs != 0
            && hs == self.handshake
            && live["running"] == true
            && live["rx_bytes"]
                .as_u64()
                .zip(self.rx)
                .is_some_and(|(new, old)| new >= old);
        let activity = if same_peer && self.healthy_at <= now {
            self.healthy_at
        } else if hs <= now {
            hs
        } else {
            0
        };
        live["last_peer_activity"] = json!(activity);
        live["checking_peer"] =
            json!(self.probe_sent && live["running"] == true && hs == self.handshake);
        if same_peer {
            live["connected"] = json!(self.authenticated(now));
        }
    }
    fn select_initial(&mut self, pool: &[String], inherited: bool, snapshot: Option<&Value>) {
        if !self.candidate.is_empty() {
            return;
        }
        if !inherited {
            self.candidate.clone_from(&pool[0]);
            return;
        }
        if self.inherited_endpoint_observed {
            return;
        }
        // The inherited tunnel authenticates the owner and both keys in
        // snapshot(). Wait for its first available sample before adoption.
        let Some(snapshot) =
            snapshot.filter(|v| v["running"] == true && v["status_unavailable"] != true)
        else {
            return;
        };
        self.inherited_endpoint_observed = true;
        if let Some(index) =
            endpoint_index(pool, snapshot, crate::endpoint::cached_endpoint_address)
        {
            self.candidate.clone_from(&pool[index]);
        }
    }
    fn retry_candidate(
        &mut self,
        pool: &[String],
        alive: bool,
        snapshot: Option<&Value>,
        hints: impl FnOnce() -> Vec<bool>,
    ) -> String {
        let rotate = if alive {
            snapshot.is_some_and(|sample| {
                sample["running"] == true && sample["status_unavailable"] != true
            })
        } else {
            self.attempts > 0
        };
        let Some(selected) = self.selected() else {
            // A roaming peer unrecognized by the literal pool or DNS cache
            // has not attempted the saved primary yet.
            return pool[0].clone();
        };
        if pool.len() == 1 || !rotate {
            // Repair a local UAPI read failure, or make the first retry of
            // a stopped engine, without spending an endpoint attempt.
            return selected.to_owned();
        }
        self.next(pool, &hints())
    }

    fn next(&mut self, pool: &[String], hints: &[bool]) -> String {
        let index = pool.iter().position(|s| s == &self.candidate).unwrap_or(0);
        self.tried |= 1 << index;
        if self.tried == ((1 << pool.len()) - 1) {
            self.exhausted = pool.len() > 1;
            self.tried = 0;
        }
        pool[(0..pool.len())
            .filter(|i| self.tried & (1 << i) == 0)
            .min_by_key(|&i| !hints.get(i).copied().unwrap_or(false))
            .unwrap_or(0)]
        .clone()
    }
    fn attempted(&mut self, now: u64, result: &io::Result<()>) {
        self.named_ticket = None;
        self.attempt = now;
        self.attempts = self.attempts.saturating_add(1);
        self.verification = result.is_ok();
        self.clear_probe();
        self.handshake = 0;
        self.rx = None;
        self.tun_tx = None;
        self.healthy_at = 0;
        self.error = result
            .as_ref()
            .err()
            .map(ToString::to_string)
            .unwrap_or_else(|| "ожидание handshake после переподключения".into());
    }
}

pub(super) struct RoutedRetryCycle<'a> {
    pub candidates: &'a [SocketAddr],
    pub authorized: Option<SocketAddr>,
    pub settings: &'a Value,
    pub now: u64,
    pub tick: Instant,
}

/// Continue the ordinary transport recovery cycle while route acknowledgement is pending.
pub(super) fn retry_routed_endpoint(
    cycle: RoutedRetryCycle<'_>,
    managed: &mut Managed,
    mut spec: Spec,
    prepare: impl Fn(SocketAddr) -> io::Result<()>,
    start: impl FnOnce(Spec) -> io::Result<Box<dyn Tunnel>>,
    hints: impl FnOnce(&[String]) -> Vec<bool>,
) -> io::Result<()> {
    let RoutedRetryCycle {
        candidates,
        authorized,
        settings,
        now,
        tick,
    } = cycle;
    let primary = *candidates.first().ok_or(io::ErrorKind::WouldBlock)?;
    let selected = authorized
        .filter(|endpoint| candidates.contains(endpoint))
        .unwrap_or(primary);
    if spec.iface != managed.iface
        || Sha256::digest(spec.conf.as_bytes()).as_slice() != managed.fingerprint
        || spec.permanent
        || spec.outer.is_some()
        || managed.tunnel.inherited()
        || managed.tunnel.nested_iface().is_some()
    {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    let alive = managed.tunnel.alive();
    let snapshot = alive.then(|| managed.tunnel.snapshot().ok()).flatten();
    let actual = snapshot.as_ref().and_then(live_transport_endpoint);
    if snapshot.as_ref().is_some_and(|sample| {
        !matches!(sample["socket_mark"].as_u64(), None | Some(0))
            && sample["socket_mark"] != crate::DIRECT_SOCKET_MARK
    }) {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    let replacing_removed = authorized.is_some_and(|endpoint| endpoint != selected);
    let replaying = actual.is_some_and(|endpoint| endpoint != selected);
    let recovery = &mut managed.recovery;
    recovery.remember_routed_mtu_endpoint(&selected.to_string());
    recovery.timing = PeerTiming::from_config(&conf::parse(&spec.conf, 0)?);
    recovery.adjust_clock(now, tick);
    let action = if replacing_removed || replaying {
        Action::Reconnect
    } else {
        recovery.observe(now, alive, snapshot.as_ref(), settings)
    };
    match action {
        Action::Wait => Ok(()),
        Action::Probe => {
            let result = prepare(selected).and_then(|()| managed.tunnel.probe_at(selected));
            if let Err(error) = &result {
                recovery.probe_sent = false;
                if error.kind() == io::ErrorKind::WouldBlock {
                    recovery.probe_at = 0;
                }
                recovery.error = error.to_string();
            }
            result
        }
        Action::Reconnect => {
            let (tried, exhausted) = (recovery.tried, recovery.exhausted);
            let next = if replacing_removed || replaying {
                selected
            } else {
                let pool = candidates
                    .iter()
                    .map(SocketAddr::to_string)
                    .collect::<Vec<_>>();
                recovery
                    .retry_candidate(&pool, alive, snapshot.as_ref(), || hints(&pool))
                    .parse()
                    .map_err(|_| invalid("неверный резервный endpoint AWG"))?
            };
            if let Err(error) = prepare(next).and_then(|()| managed.tunnel.stop()) {
                recovery.tried = tried;
                recovery.exhausted = exhausted;
                recovery.error = error.to_string();
                return Err(error);
            }
            spec.endpoint = next.to_string();
            recovery.remember_routed_mtu_endpoint(&spec.endpoint);
            managed.tunnel = Box::new(Stopped);
            let result = start(spec).map(|tunnel| managed.tunnel = tunnel);
            recovery.attempted(now, &result);
            result
        }
    }
}

pub(super) struct Stopped;
impl Tunnel for Stopped {
    fn is_stopped(&self) -> bool {
        true
    }
    fn alive(&mut self) -> bool {
        false
    }
    fn stop(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn probe(&mut self) -> io::Result<()> {
        Err(io::ErrorKind::NotConnected.into())
    }
    fn snapshot(&self) -> io::Result<Value> {
        Err(io::ErrorKind::NotConnected.into())
    }
}
impl Runtime {
    #[cfg(unix)]
    pub(crate) fn supplement_activity(
        &self,
        iface: &str,
        live: &mut Value,
        now: u64,
        response: &[u8],
    ) -> bool {
        let verified = live["nested_transport"] != true || self.nested_verified(iface);
        if let Ok(owned) = self.clients.0.try_lock() {
            if let Some(m) = owned.values().find(|m| m.iface == iface) {
                if !m.tunnel.matches_response(response) {
                    live["running"] = json!(false);
                    live["connected"] = json!(false);
                    live["status_unavailable"] = json!(true);
                    live["endpoint"] = json!("");
                    return false;
                }
                m.recovery.activity(live, now);
                if !verified {
                    live["connected"] = json!(false);
                }
                return true;
            }
        }
        let endpoint_verified = self.legacy_activity(iface, live, response);
        if !verified {
            live["connected"] = json!(false);
        }
        endpoint_verified
    }
    pub(super) fn retry_restore(&self, doc: &Value, row: &Value, reason: &io::Error) {
        let Ok(spec) = specification(doc, row) else {
            return;
        };
        let _ = self.arm_retry(spec, reason, || Ok(()));
    }
    pub(super) fn arm_retry(
        &self,
        spec: Spec,
        reason: &io::Error,
        register: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        let mut owned = self
            .clients
            .0
            .lock()
            .map_err(|_| invalid("менеджер туннелей недоступен"))?;
        if let std::collections::hash_map::Entry::Vacant(slot) = owned.entry(spec.id) {
            register()?;
            slot.insert(Managed {
                iface: spec.iface,
                fingerprint: Sha256::digest(spec.conf.as_bytes()).into(),
                tunnel: Box::new(Stopped),
                recovery: Recovery::failed_start(crate::now(), reason),
            });
        }
        Ok(())
    }
    pub fn has_managed_clients(&self) -> bool {
        self.legacy_due() || self.clients.0.try_lock().is_ok_and(|s| !s.is_empty())
    }

    pub(super) fn check_saved_nested(&self, managed: &mut Managed) {
        if managed.tunnel.nested_iface().is_none() || self.nested_verified(&managed.iface) {
            return;
        }
        let now = crate::now();
        let healthy = managed
            .tunnel
            .snapshot()
            .is_ok_and(|status| status["connected"] == true);
        let nested = &mut managed.recovery.nested;
        nested.adopt_saved(now);
        nested.check(
            now,
            managed.tunnel.as_mut(),
            &managed.iface,
            healthy,
            connection_check::outgoing_ip,
        );
        self.record_nested(&managed.iface, nested.verified());
    }
    pub fn recover_clients(&self, db: &Store, wan: &[String]) -> io::Result<Vec<String>> {
        self.recover_clients_inner(db, wan, None, None, None)
    }

    pub fn recover_clients_with_transport(
        &self,
        db: &Store,
        wan: &[String],
        refresh: impl Fn(TransportBypassProof<'_>) -> io::Result<()>,
    ) -> io::Result<Vec<String>> {
        self.recover_clients_inner(db, wan, Some(&refresh), None, None)
    }

    /// Retry durable edits under the caller's routing-operation lock.
    pub fn recover_clients_with_routing(
        &self,
        db: &Store,
        wan: &[String],
        refresh: impl Fn(TransportBypassProof<'_>) -> io::Result<()>,
        park: impl Fn(&RoutedMtuChange) -> io::Result<()>,
    ) -> io::Result<Vec<String>> {
        let _deployment = self.deployment_guard()?;
        self.recover_clients_inner(db, wan, Some(&refresh), Some(&park), None)
    }

    pub fn recover_clients_with_routing_retry(
        &self,
        db: &Store,
        wan: &[String],
        refresh: impl Fn(TransportBypassProof<'_>) -> io::Result<()>,
        park: impl Fn(&RoutedMtuChange) -> io::Result<()>,
        read_retry: impl Fn(&RoutedMtuChange) -> io::Result<Option<SocketAddr>>,
        prepare_retry: impl Fn(&RoutedMtuChange, SocketAddr) -> io::Result<()>,
    ) -> io::Result<Vec<String>> {
        self.recover_clients_with_routing_endpoint_launch(
            db,
            wan,
            refresh,
            park,
            |change| read_retry(change).map(RoutedEndpointLaunch::from_pin),
            prepare_retry,
        )
    }

    pub fn recover_clients_with_routing_endpoint_launch(
        &self,
        db: &Store,
        wan: &[String],
        refresh: impl Fn(TransportBypassProof<'_>) -> io::Result<()>,
        park: impl Fn(&RoutedMtuChange) -> io::Result<()>,
        read_retry: impl Fn(&RoutedMtuChange) -> io::Result<super::RoutedEndpointLaunch>,
        prepare_retry: impl Fn(&RoutedMtuChange, SocketAddr) -> io::Result<()>,
    ) -> io::Result<Vec<String>> {
        let _deployment = self.deployment_guard()?;
        self.recover_clients_inner(
            db,
            wan,
            Some(&refresh),
            Some(&park),
            Some(super::settings::RoutedRetryHooks {
                read: &read_retry,
                prepare: &prepare_retry,
            }),
        )
    }

    pub(super) fn recover_clients_inner(
        &self,
        db: &Store,
        wan: &[String],
        refresh: Option<&RefreshTransport<'_>>,
        park: Option<&super::settings::ParkRoutedMtu<'_>>,
        retry: Option<super::settings::RoutedRetryHooks<'_>>,
    ) -> io::Result<Vec<String>> {
        self.recover_clients_pass(db, wan, refresh, park, retry, None)
    }

    fn recover_clients_pass(
        &self,
        db: &Store,
        wan: &[String],
        refresh: Option<&RefreshTransport<'_>>,
        park: Option<&super::settings::ParkRoutedMtu<'_>>,
        retry: Option<super::settings::RoutedRetryHooks<'_>>,
        mut named: Option<&mut named_reconnect::Collector<'_>>,
    ) -> io::Result<Vec<String>> {
        let mut events = self.recover_saved_edits(db, wan, refresh, park, retry)?;
        let mut forget = Vec::new();
        if self.legacy_due() {
            let doc = read(db)?;
            let inherited = self.collect_transport(db, wan, refresh)?;
            self.restore_legacy(
                db,
                &doc,
                false,
                |spec| self.legacy_presence(spec),
                |spec| self.start_local_prepared(spec, wan, refresh.zip(inherited.as_ref())),
                &mut events,
            )?;
        }
        let mut owned = self
            .clients
            .0
            .lock()
            .map_err(|_| io::Error::other("менеджер туннелей недоступен"))?;
        if owned.is_empty() {
            return Ok(events);
        }
        let doc = read(db)?;
        let inherited_transports =
            refresh.map(|_| self.capture_inherited_transport(&doc, &owned, wan));
        let transport = refresh.zip(inherited_transports.as_ref());
        let prepare = |endpoint| prepare_transport(transport, endpoint);
        let launch = read_active_replacement_launch(db)?;
        let retained_outer = super::removal::retained_replacement_outer(&doc, &mut owned);
        let held_standby = launch
            .as_ref()
            .map(|lease| lease.target.id.as_str())
            .or(retained_outer.as_deref());
        let settings = crate::recovery_settings(&doc["recovery_settings"]);
        let graph = FailoverGraph::load(&doc)?;
        let now = crate::now();
        let peers = nested_policy::peers(&mut owned, now, &settings, &doc);
        for (id, m) in owned.iter_mut() {
            if held_standby == Some(id.as_str()) {
                continue;
            }
            let Ok(row) = find(&doc, id) else {
                if doc[ACTIVE_REPLACEMENT_FIELD]["id"] == *id {
                    // Only the route transaction can retire this sealed owner.
                    continue;
                }
                if !m.tunnel.inherited() {
                    m.tunnel.stop()?;
                }
                forget.push(id.clone());
                continue;
            };
            let client = &row["config"]["client"];
            if super::settings::awaiting_legacy_edit(row) {
                continue;
            }
            let inherited = m.tunnel.inherited() && client.get("rust_managed").is_none();
            let disabled = client["enabled"] == false || row["config"]["enabled"] == false;
            if disabled
                || client["enabled"] != true
                || !(client["rust_managed"] == true || inherited)
            {
                if m.tunnel.inherited() && disabled && routes_use(&doc, id) {
                    continue;
                }
                if !m.tunnel.inherited() || disabled {
                    m.tunnel.stop()?;
                }
                forget.push(id.clone());
                continue;
            }
            if super::settings::has_saved_edit(row) {
                continue;
            }
            if standalone(&doc, wire(row)).is_err() {
                continue;
            }
            let candidates = pool(row);
            let alive = m.tunnel.alive();
            let snapshot = if alive {
                m.tunnel.snapshot().ok()
            } else {
                None
            };
            let now = crate::now();
            let nesting = graph.nested(id);
            let reserves = nested_policy::reserves(&graph, &doc, id, &peers)?;
            let active_outer = m.tunnel.nested_iface().map(str::to_owned);
            if row.get(PENDING_ENDPOINT_RESTART).is_some() {
                if m.recovery.retry_at(&settings) <= now {
                    if let Err(error) =
                        self.apply_saved_endpoint(db, &doc, row, m, transport, |spec| {
                            self.start_local(spec, wan)
                        })
                    {
                        m.recovery.note_edit_failure(now, &error);
                        events.push(format!(
                            "{}: сохранённый список endpoint ожидает применения: {error}",
                            m.iface
                        ));
                    }
                }
                continue;
            }
            let resumed_direct = m.tunnel.resumed()
                && m.tunnel.nested_iface().is_none()
                && s(client, "double_tunnel_id").is_empty()
                && client["double_tunnel_mode"] != "permanent"
                && (candidates[0].parse::<SocketAddr>().is_ok()
                    || authenticated_literal_reserve(&candidates, snapshot.as_ref()));
            let resumed_nested = m.tunnel.resumed()
                && active_outer.is_some()
                && m.recovery.selected().is_none()
                && super::settings::permanent_nested_primary(row).is_some();
            let initial_sample = if resumed_nested {
                snapshot.as_ref().and_then(|sample| {
                    super::settings::verified_permanent_nested_resume(&doc, row, m, sample)
                })
            } else {
                snapshot.as_ref()
            };
            let r = &mut m.recovery;
            r.select_initial(
                &candidates,
                inherited || resumed_direct || resumed_nested,
                initial_sample,
            );
            r.timing = PeerTiming::from_config(wire(row));
            r.adjust_clock(now, Instant::now());
            let previously_recovering = r.since != 0;
            let mut action = r.observe(now, alive, snapshot.as_ref(), &settings);
            let timeout = settings["handshake_timeout_seconds"].as_u64().unwrap_or(20);
            let peer_healthy = alive && r.since == 0 && r.recent(now);
            if peer_healthy && r.candidate.is_empty() && !resumed_nested {
                r.candidate.clone_from(&candidates[0]);
            }
            let direct_failed = r.needs_reserve(now, timeout, false);
            let exhausted = r.needs_reserve(now, timeout, candidates.len() > 1);
            let outer = nesting
                .and_then(|(outer, _)| peers.get(outer))
                .filter(|p| p.direct);
            let choice = r.nested.choose(nested_policy::Inputs {
                mode: nesting.map(|(_, mode)| mode).or_else(|| {
                    (client["double_tunnel_mode"] == "permanent").then_some("permanent")
                }),
                outer: outer.map(|p| p.iface.as_str()),
                active: active_outer.as_deref(),
                peer_healthy,
                direct_failed,
                exhausted,
                reconnect: action == Action::Reconnect,
                reserves,
                now,
                timeout,
            });
            let mut wanted_outer = None;
            let mut direct_trial = false;
            match choice {
                nested_policy::Choice::Keep => {}
                nested_policy::Choice::Pause => {
                    self.record_nested(&m.iface, false);
                    if alive {
                        m.tunnel.stop()?;
                        if inherited {
                            set_enabled(db, id, row, true, None)?;
                        }
                        m.tunnel = Box::new(Stopped);
                    }
                    continue;
                }
                nested_policy::Choice::Check => {
                    r.nested.check(
                        now,
                        m.tunnel.as_mut(),
                        &m.iface,
                        peer_healthy,
                        connection_check::outgoing_ip,
                    );
                    self.record_nested(&m.iface, r.nested.verified());
                    if r.nested.verified() || !r.nested.failed(now, timeout) {
                        continue;
                    }
                    direct_trial = true;
                    action = Action::Reconnect;
                }
                nested_policy::Choice::Wait => {
                    if active_outer.is_some() {
                        self.record_nested(&m.iface, false);
                    }
                    continue;
                }
                nested_policy::Choice::Direct => {
                    direct_trial = true;
                    action = Action::Reconnect;
                }
                nested_policy::Choice::Outer => {
                    let (outer_id, _) = nesting.unwrap();
                    let spec = specification(&doc, find(&doc, outer_id)?)?;
                    wanted_outer = Some(NestedOuter::from_spec(&spec)?);
                    action = Action::Reconnect;
                }
            }
            if previously_recovering && r.since == 0 {
                events.push(format!(
                    "{}: подтверждён handshake или получены данные",
                    m.iface
                ));
            } else if !previously_recovering && r.since != 0 {
                events.push(format!("{}: начата проверка соединения", m.iface));
            }
            match action {
                Action::Wait => continue,
                Action::Probe => {
                    let result = match transport {
                        Some((refresh, inherited)) => inherited.prepare_probe(
                            m.tunnel.as_mut(),
                            snapshot.as_ref(),
                            &candidates,
                            |address, mark| self.verifies_live_wan(address, mark, wan),
                            |endpoint| {
                                let spec = saved_specification(&doc, row, false)?;
                                if spec.iface != m.iface
                                    || Sha256::digest(spec.conf.as_bytes()).as_slice()
                                        != m.fingerprint
                                {
                                    return Err(invalid(
                                        "активный профиль изменён: сначала отключите его",
                                    ));
                                }
                                check_recovery_row(db, row)?;
                                inherited.prepare(refresh, endpoint)?;
                                check_recovery_row(db, row)
                            },
                        ),
                        None => m.tunnel.probe(),
                    };
                    if let Err(e) = result {
                        r.probe_sent = false;
                        if e.kind() == io::ErrorKind::WouldBlock {
                            // No UAPI set was sent. Give the refresh another tick.
                            r.probe_at = 0;
                        }
                        r.error = e.to_string();
                    }
                }
                Action::Reconnect => {
                    let (tried, exhausted) = (r.tried, r.exhausted);
                    let mut deferred = false;
                    let result = (|| {
                        let mut spec = specification(&doc, row)?;
                        if Sha256::digest(spec.conf.as_bytes()).as_slice() != m.fingerprint {
                            return Err(invalid("активный профиль изменён: сначала отключите его"));
                        }
                        if (inherited || transport.is_some()) && find(&read(db)?, id)? != row {
                            return Err(invalid("профиль изменился до передачи управления"));
                        }
                        spec.endpoint = if wanted_outer.is_some() {
                            candidates[0].clone()
                        } else {
                            r.retry_candidate(&candidates, alive, snapshot.as_ref(), || {
                                #[cfg(target_os = "linux")]
                                if active_outer.is_none() {
                                    return endpoint_hints::collect(&candidates, wan);
                                }
                                Vec::new()
                            })
                        };
                        let selected = spec.endpoint.clone();
                        if let Some(collector) = named.as_deref_mut().filter(|_| {
                            !inherited
                                && wanted_outer.is_none()
                                && active_outer.is_none()
                                && named_reconnect_profile(row, &selected)
                        }) {
                            deferred = true;
                            if collector.collect(&doc, row, &spec, r, (tried, exhausted), alive)? {
                                return Ok(());
                            }
                            deferred = false;
                        }
                        if transport.is_some() {
                            let endpoint = match resolve_endpoint(&selected) {
                                Ok(endpoint) => endpoint,
                                Err(e) => {
                                    r.candidate = selected;
                                    return Err(e);
                                }
                            };
                            // Refresh while the previous engine still owns the
                            // interface, then pin the exact address we refreshed.
                            deferred = true;
                            prepare(endpoint)?;
                            check_recovery_row(db, row)?;
                            deferred = false;
                            spec.endpoint = endpoint.to_string();
                        }
                        // A failed launch still advances an expressly selected
                        // candidate so a dead primary cannot trap the pool.
                        r.candidate = selected;
                        if direct_trial {
                            r.nested.direct_trial(now, timeout);
                        }
                        m.tunnel.stop()?;
                        if inherited {
                            set_enabled(db, id, row, true, None)?;
                        }
                        self.record_nested(&m.iface, false);
                        r.nested.launched(now, wanted_outer.is_some());
                        spec.outer = wanted_outer;
                        m.tunnel = Box::new(Stopped);
                        m.tunnel = self.start_local(spec, wan)?;
                        Ok(())
                    })();
                    if deferred {
                        r.tried = tried;
                        r.exhausted = exhausted;
                        if let Err(error) = result {
                            r.error = error.to_string();
                        }
                        continue;
                    }
                    r.attempted(now, &result);
                    if let Err(e) = &result {
                        if r.nested.wants_outer() {
                            r.nested.start_failed(now, timeout, e);
                        }
                    }
                }
            }
        }
        for id in forget {
            owned.remove(&id);
        }
        failover::reconcile(
            &doc,
            &mut owned,
            crate::now(),
            &settings,
            &mut events,
            held_standby,
            |spec| self.start_local_prepared(spec, wan, transport),
        )?;
        Ok(events)
    }
    pub fn set_backups(
        &self,
        db: &Store,
        id: &str,
        inputs: &[String],
        wan: &[String],
    ) -> io::Result<()> {
        match self.set_backups_inner(db, id, inputs, wan, None)? {
            Some(warning) => Err(io::Error::other(warning)),
            None => Ok(()),
        }
    }

    pub fn set_backups_with_transport(
        &self,
        db: &Store,
        id: &str,
        inputs: &[String],
        wan: &[String],
        refresh: impl Fn(TransportBypassProof<'_>) -> io::Result<()>,
    ) -> io::Result<Option<String>> {
        self.set_backups_inner(db, id, inputs, wan, Some(&refresh))
    }

    fn set_backups_inner(
        &self,
        db: &Store,
        id: &str,
        inputs: &[String],
        wan: &[String],
        refresh: Option<&RefreshTransport<'_>>,
    ) -> io::Result<Option<String>> {
        let _deployment = self.deployment_guard()?;
        let id = id.trim();
        let mut owned = self
            .clients
            .0
            .lock()
            .map_err(|_| io::Error::other("менеджер туннелей недоступен"))?;
        let doc = read(db)?;
        let row = find(&doc, id)?;
        let primary = s(wire(row), "endpoint");
        let backups = normalize(primary, inputs)?;
        let routed_edit = super::settings::pending_routed_mtu(row)?;
        if routed_edit
            .as_ref()
            .and_then(|edit| edit.nested_endpoint.as_ref())
            .is_some_and(|endpoint| endpoint != primary && !backups.contains(endpoint))
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let restoring_reserve = routed_edit
            .as_ref()
            .and_then(|change| change.endpoint_edit.as_ref())
            .filter(|edit| row["config"]["endpoint"] == edit.before)
            .and_then(|edit| edit.previous_reserve);
        let native_mtu_endpoint = routed_edit
            .as_ref()
            .and_then(|edit| edit.native_mtu_endpoint);
        let inherited_named = routed_edit
            .as_ref()
            .filter(|edit| edit.inherits_named_endpoint());
        let held_reserve = restoring_reserve.or(native_mtu_endpoint
            .filter(|endpoint| super::settings::literal_transport(primary) != Some(*endpoint)));
        if held_reserve.is_some_and(|endpoint| !backups.contains(&endpoint.to_string())) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if restoring_reserve.is_some()
            || native_mtu_endpoint.is_some()
            || inherited_named.is_some()
            || routed_edit.as_ref().is_some_and(|change| {
                change.nested_mtu_before_recorded
                    || change.combines_nested_endpoint_mtu()
                    || super::settings::direct_forward_endpoint(row, change).is_some()
            })
        {
            // An outstanding routed edit owns any restart, including re-arming
            // the primary when the separately authorized retry loses its reserve.
            let mut committed = row.clone();
            committed["config"]["client"]["endpoint_backups"] = json!(backups);
            if inherited_named.is_some_and(|change| {
                !super::settings::routed_legacy_edit_profile(&committed, change)
            }) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            committed
                .as_object_mut()
                .unwrap()
                .remove(PENDING_ENDPOINT_RESTART);
            commit_backup_row(db, id, row, &committed)?;
            if let Some(m) = owned.get_mut(id) {
                m.recovery.tried = 0;
                m.recovery.exhausted = false;
            }
            return Ok(None);
        }
        let previous_pool = pool(row);
        let inherited = refresh.map(|_| self.capture_inherited_transport(&doc, &owned, wan));
        let transport = refresh.zip(inherited.as_ref());
        let mut pending = pending_endpoint_restart(row)?;
        if let Some(m) = owned.get_mut(id) {
            let client = &row["config"]["client"];
            if pending.is_none()
                && row["config"]["enabled"] == true
                && client["enabled"] == true
                && m.tunnel.alive()
            {
                let observed = m.tunnel.snapshot().ok().and_then(|status| {
                    endpoint_index(
                        &previous_pool,
                        &status,
                        crate::endpoint::cached_endpoint_address,
                    )
                });
                let previous = m
                    .recovery
                    .selected()
                    .filter(|ep| *ep != primary)
                    .or_else(|| observed.map(|i| previous_pool[i].as_str()));
                if previous
                    .is_some_and(|ep| ep != primary && !backups.iter().any(|saved| saved == ep))
                {
                    pending = Some(m.tunnel.nested_iface().is_some());
                }
            }
        } else if self.present(&iface(row, &doc)?)? {
            return Err(invalid("интерфейс управляется другим процессом"));
        }
        let mut committed = row.clone();
        committed["config"]["client"]["endpoint_backups"] = json!(backups);
        if let Some(nested) = pending {
            committed[PENDING_ENDPOINT_RESTART] = json!(nested);
        }
        commit_backup_row(db, id, row, &committed)?;
        if let Some(m) = owned.get_mut(id) {
            m.recovery.tried = 0;
            m.recovery.exhausted = false;
            if pending.is_some() {
                if let Err(error) =
                    self.apply_saved_endpoint(db, &doc, &committed, m, transport, |spec| {
                        self.start_local(spec, wan)
                    })
                {
                    m.recovery.note_edit_failure(crate::now(), &error);
                    return Ok(Some(format!("резервные IP сохранены; применить к работающему туннелю пока не удалось: {error}")));
                }
            }
        }
        Ok(None)
    }
    fn apply_saved_endpoint(
        &self,
        db: &Store,
        doc: &Value,
        row: &Value,
        managed: &mut Managed,
        transport: Option<TransportPreparation<'_>>,
        start: impl FnOnce(Spec) -> io::Result<Box<dyn Tunnel>>,
    ) -> io::Result<()> {
        let nested = pending_endpoint_restart(row)?
            .ok_or_else(|| invalid("нет ожидающего переключения endpoint"))?;
        if row.get(super::settings::PENDING_PROFILE).is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let mut spec = specification(doc, row)?;
        if spec.iface != managed.iface
            || Sha256::digest(spec.conf.as_bytes()).as_slice() != managed.fingerprint
        {
            return Err(invalid("активный профиль изменён: сначала отключите его"));
        }
        if nested || spec.permanent {
            let graph = FailoverGraph::load(doc)?;
            let (outer, _) = graph
                .nested(&spec.id)
                .ok_or_else(|| invalid("не задан внешний туннель AWG"))?;
            let outer = NestedOuter::from_spec(&specification(doc, find(doc, outer)?)?)?;
            if managed
                .tunnel
                .nested_iface()
                .is_some_and(|active| active != outer.iface)
            {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            spec.outer = Some(outer);
        }
        let selected = spec.endpoint.clone();
        check_recovery_row(db, row)?;
        if transport.is_some() {
            let endpoint = resolve_endpoint(&selected)?;
            prepare_transport(transport, endpoint)?;
            check_recovery_row(db, row)?;
            spec.endpoint = endpoint.to_string();
        }
        managed.tunnel.stop()?;
        let expected = if managed.tunnel.inherited() {
            set_enabled(db, &spec.id, row, true, None)?;
            find(&read(db)?, &spec.id)?.clone()
        } else {
            row.clone()
        };
        managed.tunnel = Box::new(Stopped);
        self.record_nested(&spec.iface, false);
        managed.tunnel = start(spec)?;
        managed.recovery = Recovery {
            candidate: selected,
            ..Default::default()
        };
        edit_document(db, |current| {
            let id = s(&expected, "id");
            if find(current, id)? != &expected {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            current["servers"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|r| r["id"] == id)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(PENDING_ENDPOINT_RESTART);
            Ok(())
        })
    }
    pub(crate) fn supplement_client(
        &self,
        row: &Value,
        live: &mut Value,
        settings: &Value,
        endpoint_verified: bool,
    ) {
        if live.is_null() {
            return;
        }
        if row["config"]["client"]["double_tunnel_mode"] == "permanent"
            && live["nested_transport"] != true
        {
            live["connected"] = json!(false);
        }
        if let Some(message) = self
            .legacy_status(s(row, "id"))
            .filter(|_| row["config"]["client"]["rust_managed"] != true)
        {
            live["migration_status"] = json!(message);
        }
        let pool = pool(row);
        if pool[0].is_empty() {
            return;
        }
        live["endpoint_primary"] = json!(pool[0]);
        live["endpoint_count"] = json!(pool.len());
        live["endpoint_candidate"] = json!(pool[0]);
        live["endpoint_index"] = json!(0);
        if let Ok(owned) = self.clients.0.try_lock() {
            if let Some(m) = owned.get(s(row, "id")) {
                let r = &m.recovery;
                r.activity(live, crate::now());
                if row["config"]["client"]["double_tunnel_mode"] == "permanent"
                    && (m.tunnel.nested_iface().is_none() || !r.nested.verified())
                {
                    live["connected"] = json!(false);
                }
                if !r.candidate.is_empty() {
                    live["endpoint_candidate"] = json!(r.candidate);
                    live["endpoint_index"] = json!(pool
                        .iter()
                        .position(|v| v == &r.candidate)
                        .map_or(-1, |i| i as i64));
                }
                live["recovering"] = json!(r.since != 0);
                live["retry_count"] = json!(r.attempts);
                live["retry_at"] = json!(r.retry_at(settings));
                if r.verification && r.attempt != 0 {
                    live["verification_until"] =
                        json!(r.attempt + settings["handshake_timeout_seconds"].as_u64().unwrap());
                }
                if !r.error.is_empty() {
                    live["recovery_error"] = json!(r.error);
                }
                if r.exhausted {
                    live["endpoint_pool_exhausted"] = json!(true);
                }
            }
        }
        if endpoint_verified {
            if let Some(index) =
                endpoint_index(&pool, live, crate::endpoint::cached_endpoint_address)
            {
                live["endpoint_candidate"] = json!(pool[index]);
                live["endpoint_index"] = json!(index);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn disabled_inherited_owner_retries_failed_stop_after_routing_release() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        struct PreviouslyOwned(Arc<AtomicUsize>);
        impl Tunnel for PreviouslyOwned {
            fn inherited(&self) -> bool {
                true
            }
            fn alive(&mut self) -> bool {
                true
            }
            fn stop(&mut self) -> io::Result<()> {
                if self.0.fetch_add(1, Ordering::Relaxed) == 0 {
                    return Err(io::ErrorKind::Interrupted.into());
                }
                Ok(())
            }
            fn probe(&mut self) -> io::Result<()> {
                panic!("disabled client was probed")
            }
            fn snapshot(&self) -> io::Result<Value> {
                panic!("disabled client was sampled")
            }
        }

        let tmp = tempfile::tempdir().unwrap();
        let db = Store::open(tmp.path()).unwrap();
        let runtime = Runtime::new(tmp.path(), tmp.path().join("unused-engine"));
        edit_document(&db, |doc| {
            let mut config = conf::parse(&crate::tests::input(), 0).unwrap();
            config["enabled"] = true.into();
            config["client"]["enabled"] = false.into();
            config["client"]["rust_managed"] = false.into();
            doc["servers"] = json!([{"id":"old","config":config}]);
            doc["active_id"] = "old".into();
            doc["rust_static_routing"] = json!({"targets":["old"]});
            Ok(())
        })
        .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        runtime.clients.0.lock().unwrap().insert(
            "old".into(),
            Managed {
                tunnel: Box::new(PreviouslyOwned(calls.clone())),
                iface: "awg0".into(),
                fingerprint: [0; 32],
                recovery: Default::default(),
            },
        );
        runtime.recover_clients(&db, &[]).unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        edit_document(&db, |doc| {
            doc.as_object_mut().unwrap().remove("rust_static_routing");
            Ok(())
        })
        .unwrap();
        assert_eq!(
            runtime.recover_clients(&db, &[]).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert!(runtime.clients.0.lock().unwrap().contains_key("old"));
        runtime.recover_clients(&db, &[]).unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert!(runtime.clients.0.lock().unwrap().is_empty());
    }

    use super::*;
    fn sample(hs: u64, rx: u64, packets: u64) -> Value {
        json!({"running":true,"last_handshake":hs,"rx_bytes":rx,"tun_tx_packets":packets})
    }

    #[test]
    fn staged_direct_retry_waits_for_failure_and_replays_authorized_sticky_reserve() {
        use std::{cell::Cell, sync::Arc};
        struct Device {
            live: Arc<Mutex<Value>>,
            probes: Arc<Mutex<u32>>,
            stops: Arc<Mutex<u32>>,
        }
        impl Tunnel for Device {
            fn alive(&mut self) -> bool {
                true
            }
            fn stop(&mut self) -> io::Result<()> {
                *self.stops.lock().unwrap() += 1;
                Ok(())
            }
            fn probe(&mut self) -> io::Result<()> {
                *self.probes.lock().unwrap() += 1;
                Ok(())
            }
            fn snapshot(&self) -> io::Result<Value> {
                Ok(self.live.lock().unwrap().clone())
            }
        }

        let primary: SocketAddr = "192.0.2.30:51820".parse().unwrap();
        let earlier: SocketAddr = "192.0.2.30:2408".parse().unwrap();
        let spare: SocketAddr = "[2001:db8::5]:2500".parse().unwrap();
        let pool = [primary, earlier, spare];
        let spec = Spec {
            id: "primary".into(),
            iface: "awg0".into(),
            conf: crate::tests::input(),
            endpoint: primary.to_string(),
            outer: None,
            permanent: false,
        };
        let fingerprint: [u8; 32] = Sha256::digest(spec.conf.as_bytes()).into();
        let live = Arc::new(Mutex::new(
            json!({"running":true,"endpoint":primary,"socket_mark":0,"last_handshake":0,"rx_bytes":0}),
        ));
        let probes = Arc::new(Mutex::new(0));
        let stops = Arc::new(Mutex::new(0));
        let device = || {
            Box::new(Device {
                live: live.clone(),
                probes: probes.clone(),
                stops: stops.clone(),
            }) as Box<dyn Tunnel>
        };
        let mut managed = Managed {
            iface: spec.iface.clone(),
            fingerprint,
            tunnel: device(),
            recovery: Default::default(),
        };
        let settings = crate::recovery_settings(&Value::Null);
        let tick = Instant::now();
        let authorized = Cell::new(None);
        let run = |managed: &mut Managed,
                   now: u64,
                   candidates: &[SocketAddr],
                   defer,
                   fail_launch| {
            retry_routed_endpoint(
                RoutedRetryCycle {
                    candidates,
                    authorized: authorized.get(),
                    settings: &settings,
                    now,
                    tick: tick + Duration::from_secs(now - 100),
                },
                managed,
                spec.clone(),
                |selected| {
                    if defer {
                        return Err(io::ErrorKind::WouldBlock.into());
                    }
                    authorized.set((selected != primary).then_some(selected));
                    Ok(())
                },
                |next| {
                    assert!(Sha256::digest(next.conf.as_bytes()).as_slice() == fingerprint);
                    if fail_launch {
                        return Err(io::ErrorKind::ConnectionRefused.into());
                    }
                    *live.lock().unwrap() = json!({"running":true,"endpoint":next.endpoint,"socket_mark":0,"last_handshake":0,"rx_bytes":0});
                    Ok(device())
                },
                |_| Vec::new(),
            )
        };
        let frozen_owner = managed.fingerprint;
        managed.fingerprint[0] ^= 1;
        assert!(run(&mut managed, 100, &pool, false, false).is_err());
        managed.fingerprint = frozen_owner;
        run(&mut managed, 100, &pool, false, false).unwrap();
        run(&mut managed, 119, &pool, false, false).unwrap();
        assert_eq!(*probes.lock().unwrap(), 1);
        assert_eq!(*stops.lock().unwrap(), 0);
        assert_eq!(
            run(&mut managed, 120, &pool, true, false)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(managed.recovery.tried, 0);
        assert_eq!(authorized.get(), None);
        assert_eq!(*stops.lock().unwrap(), 0);
        assert_eq!(
            run(&mut managed, 121, &pool, false, true)
                .unwrap_err()
                .kind(),
            io::ErrorKind::ConnectionRefused
        );
        assert_eq!(authorized.get(), Some(earlier));
        assert_eq!(*stops.lock().unwrap(), 1);
        run(&mut managed, 122, &pool, false, false).unwrap();
        assert_eq!(authorized.get(), Some(spare));
        assert!(!managed.recovery.exhausted);
        live.lock().unwrap()["last_handshake"] = json!(130);
        run(&mut managed, 131, &pool, false, false).unwrap();
        assert_eq!(
            managed.recovery.selected(),
            Some(spare.to_string().as_str())
        );
        assert_eq!(managed.recovery.tried, 0);

        // A reopened panel verifies the same numeric live candidate authorized
        // by routing, even with no process-local retry counter.
        managed.recovery = Default::default();
        run(&mut managed, 132, &pool, false, false).unwrap();
        assert_eq!(*stops.lock().unwrap(), 1);
        assert_eq!(
            managed.recovery.selected(),
            Some(spare.to_string().as_str())
        );
        live.lock().unwrap()["rx_bytes"] = json!(100);
        run(&mut managed, 319, &pool, false, false).unwrap();
        assert!(managed.recovery.authenticated(319));
        assert_eq!(authorized.get(), Some(spare));

        run(&mut managed, 320, &pool[..2], false, false).unwrap();
        assert_eq!(authorized.get(), None);
        assert_eq!(*stops.lock().unwrap(), 2);
        assert_eq!(
            managed.recovery.selected(),
            Some(primary.to_string().as_str())
        );
    }

    #[test]
    fn unlaunched_routed_primary_cannot_spend_predecessor_exhaustion_on_cold_failover() {
        let mut cfg = conf::parse(&crate::tests::input(), 0).unwrap();
        cfg["enabled"] = json!(true);
        cfg["client_iface"] = json!("awg0");
        cfg["endpoint"] = json!("192.0.2.2:2500");
        cfg["client"]["enabled"] = json!(true);
        cfg["client"]["rust_managed"] = json!(true);
        cfg["client"]["endpoint_backups"] = json!(["192.0.2.3:2500"]);
        cfg["client"]["fallback_tunnel_ids"] = json!(["reserve"]);
        let mut reserve = cfg.clone();
        reserve["client_iface"] = json!("awg1");
        reserve["client"]["standby"] = json!(true);
        reserve["client"]["fallback_tunnel_ids"] = json!([]);
        let change = RoutedMtuChange {
            id: "primary".into(),
            iface: "awg0".into(),
            revision: 7,
            before: 1420,
            after: 1420,
            nested_outer: None,
            nested_endpoint: None,
            endpoint_edit: Some(RoutedEndpointEdit {
                before: "192.0.2.1:2500".into(),
                after: "192.0.2.2:2500".into(),
                resolved_before: Vec::new(),
                resolved_after: Vec::new(),
                previous_reserve: None,
            }),
            legacy_predecessor: None,
            implicit_before_mtu: None,
            legacy_mtu_before_recorded: false,
            nested_mtu_before_recorded: false,
            native_mtu_endpoint: None,
        };
        let mut doc = json!({"servers":[{"id":"primary","config":cfg, "rust_pending_client_profile":vec![0_u8;32], "rust_pending_routed_mtu":change}, {"id":"reserve","config":reserve}]});
        let predecessor = Managed {
            iface: "awg0".into(),
            fingerprint: [0; 32],
            tunnel: Box::new(Stopped),
            recovery: Recovery {
                exhausted: true,
                since: 100,
                attempts: 2,
                ..Default::default()
            },
        };
        let mut owned = HashMap::from([("primary".into(), predecessor)]);
        let settings = crate::recovery_settings(&Value::Null);
        let mut events = Vec::new();
        failover::reconcile(&doc, &mut owned, 300, &settings, &mut events, None, |_| {
            unreachable!("old exhaustion must remain local to the previous generation")
        })
        .unwrap();
        assert!(!owned.contains_key("reserve"));
        doc["servers"][0]
            .as_object_mut()
            .unwrap()
            .remove(super::super::settings::PENDING_PROFILE);
        owned.get_mut("primary").unwrap().recovery = Recovery::default();
        failover::reconcile(&doc, &mut owned, 300, &settings, &mut events, None, |_| {
            unreachable!("new generation has not exhausted its endpoint pool")
        })
        .unwrap();
        let recovery = &mut owned.get_mut("primary").unwrap().recovery;
        recovery.since = 301;
        recovery.attempts = 2;
        recovery.exhausted = true;
        failover::reconcile(
            &doc,
            &mut owned,
            330,
            &settings,
            &mut events,
            None,
            |spec| {
                assert_eq!(spec.id, "reserve");
                Ok(Box::new(Stopped))
            },
        )
        .unwrap();
        assert!(owned.contains_key("reserve"));
    }

    #[test]
    fn recovery_and_backup_changes_wait_for_transport_refresh() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, TryLockError,
        };

        struct Device {
            probes: Arc<AtomicUsize>,
            stopped: Arc<AtomicUsize>,
            live: Value,
        }
        impl Tunnel for Device {
            fn alive(&mut self) -> bool {
                true
            }
            fn stop(&mut self) -> io::Result<()> {
                self.stopped.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            fn probe(&mut self) -> io::Result<()> {
                self.probes.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            fn snapshot(&self) -> io::Result<Value> {
                Ok(self.live.clone())
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        let runtime = Runtime::new(dir.path(), dir.path().join("no-engine"));
        let endpoint = "192.0.2.1:2408";
        let backup = "192.0.2.2:2408";
        let mut cfg = conf::parse(&crate::tests::input(), 0).unwrap();
        cfg["endpoint"] = json!(endpoint);
        cfg["client_iface"] = json!("awg0");
        cfg["enabled"] = json!(true);
        cfg["client"]["enabled"] = json!(true);
        cfg["client"]["rust_managed"] = json!(true);
        edit_document(&db, |doc| {
            doc["servers"] = json!([{"id":"primary","config":cfg}]);
            doc["active_id"] = json!("primary");
            Ok(())
        })
        .unwrap();
        let doc = read(&db).unwrap();
        let spec = specification(&doc, find(&doc, "primary").unwrap()).unwrap();
        let probes = Arc::new(AtomicUsize::new(0));
        let stopped = Arc::new(AtomicUsize::new(0));
        runtime.clients.0.lock().unwrap().insert(
            "primary".into(),
            Managed {
                iface: spec.iface,
                fingerprint: Sha256::digest(spec.conf.as_bytes()).into(),
                recovery: Default::default(),
                tunnel: Box::new(Device {
                    probes: Arc::clone(&probes),
                    stopped: Arc::clone(&stopped),
                    live: json!({"running":true,"endpoint":endpoint,"socket_mark":0}),
                }),
            },
        );

        let check_proof = |proof: TransportBypassProof<'_>| {
            assert_eq!(proof.endpoint.to_string(), endpoint);
            assert!(proof.inherited.is_empty());
            assert!(proof.deadline > Instant::now());
            assert!(matches!(
                runtime.clients.0.try_lock(),
                Err(TryLockError::WouldBlock)
            ));
        };
        let busy = |proof: TransportBypassProof<'_>| {
            check_proof(proof);
            Err(io::ErrorKind::WouldBlock.into())
        };
        runtime
            .recover_clients_with_transport(&db, &[], busy)
            .unwrap();
        assert_eq!(probes.load(Ordering::Relaxed), 0);
        runtime
            .recover_clients_with_transport(&db, &[], |proof| {
                check_proof(proof);
                assert_eq!(probes.load(Ordering::Relaxed), 0);
                Ok(())
            })
            .unwrap();
        assert_eq!(probes.load(Ordering::Relaxed), 1);

        runtime
            .clients
            .0
            .lock()
            .unwrap()
            .get_mut("primary")
            .unwrap()
            .recovery
            .attempts = 1;
        runtime
            .recover_clients_with_transport(&db, &[], busy)
            .unwrap();
        {
            let mut owned = runtime.clients.0.lock().unwrap();
            let recovery = &mut owned.get_mut("primary").unwrap().recovery;
            assert_eq!(recovery.attempts, 1);
            assert_eq!(recovery.candidate, endpoint);
            recovery.candidate = backup.into();
        }
        assert_eq!(probes.load(Ordering::Relaxed), 1);
        edit_document(&db, |doc| {
            doc["servers"][0]["config"]["client"]["endpoint_backups"] = json!([backup]);
            Ok(())
        })
        .unwrap();
        let warning = runtime
            .set_backups_with_transport(&db, "primary", &[], &[], |proof| {
                let saved = read(&db).unwrap();
                assert_eq!(
                    saved["servers"][0]["config"]["client"]["endpoint_backups"],
                    json!([])
                );
                assert_eq!(saved["servers"][0][PENDING_ENDPOINT_RESTART], false);
                busy(proof)
            })
            .unwrap();
        assert!(warning.unwrap().contains("сохранены"));
        assert_eq!(stopped.load(Ordering::Relaxed), 0);

        let saved = read(&db).unwrap();
        let row = find(&saved, "primary").unwrap();
        let mut owned = runtime.clients.0.lock().unwrap();
        let managed = owned.get_mut("primary").unwrap();
        let inherited = InheritedTransports::collect(|| Ok(vec![])).unwrap();
        let ready = |proof: TransportBypassProof<'_>| {
            check_proof(proof);
            Ok(())
        };
        let failed = runtime.apply_saved_endpoint(
            &db,
            &saved,
            row,
            managed,
            Some((&ready, &inherited)),
            |_| Err(io::ErrorKind::ConnectionRefused.into()),
        );
        assert_eq!(failed.unwrap_err().kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(stopped.load(Ordering::Relaxed), 1);
        assert_eq!(
            find(&read(&db).unwrap(), "primary").unwrap()[PENDING_ENDPOINT_RESTART],
            false
        );
        runtime
            .apply_saved_endpoint(
                &db,
                &saved,
                row,
                managed,
                Some((&ready, &inherited)),
                |spec| {
                    assert_eq!(spec.endpoint, endpoint);
                    assert_eq!(stopped.load(Ordering::Relaxed), 1);
                    Ok(Box::new(Device {
                        probes: Arc::clone(&probes),
                        stopped: Arc::clone(&stopped),
                        live: json!({"running":true,"endpoint":endpoint}),
                    }))
                },
            )
            .unwrap();
        assert_eq!(managed.recovery.selected(), Some(endpoint));
        assert!(read(&db).unwrap()["servers"][0]
            .get(PENDING_ENDPOINT_RESTART)
            .is_none());
    }

    #[test]
    fn expired_inherited_proofs_defer_the_refresh() {
        let endpoint = "192.0.2.1:2408".parse().unwrap();
        let inherited = InheritedTransports {
            addresses: vec!["192.0.2.2:2408".parse().unwrap()],
            expires: Instant::now(),
        };
        assert_eq!(
            inherited
                .prepare(&|_| panic!("stale proof"), endpoint)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn sustained_inner_tx_challenges_once_and_inbound_progress_cancels_it() {
        let settings = crate::recovery_settings(&Value::Null);
        for handshake_reply in [false, true] {
            let mut r = Recovery::default();
            for n in 0..=8 {
                let now = 100 + n * 5;
                let mut v = sample(100, 64, n);
                assert_eq!(
                    r.observe(now, true, Some(&v), &settings),
                    if n == 5 { Action::Probe } else { Action::Wait }
                );
                r.activity(&mut v, now);
                assert_eq!(v["last_peer_activity"], 100);
                assert_eq!(v["checking_peer"], n >= 5);
                assert!(!r.needs_reserve(now, 20, false));
            }
            let mut reply = if handshake_reply {
                sample(145, 64, 9)
            } else {
                sample(100, 96, 9)
            };
            assert_eq!(r.observe(145, true, Some(&reply), &settings), Action::Wait);
            r.activity(&mut reply, 145);
            assert_eq!(reply["checking_peer"], false);
            assert_eq!(reply["connected"], true);
            assert_eq!(reply["last_peer_activity"], 145);
        }
    }

    #[test]
    fn isolated_traffic_and_native_keepalives_do_not_restart_an_idle_peer() {
        let settings = crate::recovery_settings(&Value::Null);
        let mut r = Recovery::default();
        for n in 0..36 {
            let mut v = sample(100, 64, u64::from(n > 2));
            v["tx_bytes"] = json!(n * 128);
            assert_eq!(
                r.observe(100 + 5 * n, true, Some(&v), &settings),
                Action::Wait
            );
        }
        // The encrypted keepalive has to trigger a handshake once the native
        // key expires. A healthy idle peer can answer within the grace period.
        assert_eq!(
            r.observe(280, true, Some(&sample(100, 64, 1)), &settings),
            Action::Probe
        );
        assert_eq!(
            r.observe(295, true, Some(&sample(290, 96, 1)), &settings),
            Action::Wait
        );
        assert!(r.authenticated(295));

        let mut r = Recovery::default();
        for n in 0..=8 {
            let v = sample(100, 64, n.min(5));
            assert_eq!(
                r.observe(100 + n * 5, true, Some(&v), &settings),
                if n == 5 { Action::Probe } else { Action::Wait }
            );
        }
        assert!(!r.probe_sent);
        assert!(r.authenticated(145));
    }

    #[test]
    fn receiver_progress_with_an_old_handshake_is_healthy_but_counters_cannot_be_replayed() {
        let settings = crate::recovery_settings(&Value::Null);
        let mut r = Recovery::default();
        assert_eq!(
            r.observe(700, true, Some(&sample(100, 50, 60)), &settings),
            Action::Probe
        );
        let mut live = sample(100, 55, 61);
        assert_eq!(r.observe(705, true, Some(&live), &settings), Action::Wait);
        r.activity(&mut live, 705);
        assert_eq!(live["last_peer_activity"], 705);
        assert_eq!(live["connected"], true);
        let mut restarted = sample(100, 4, 2);
        restarted["connected"] = json!(false);
        r.activity(&mut restarted, 710);
        assert_eq!(restarted["last_peer_activity"], 100);
        assert_eq!(restarted["connected"], false);
        assert_eq!(
            r.observe(710, true, Some(&restarted), &settings),
            Action::Probe
        );
        assert!(!r.authenticated(710));
        r.attempted(730, &Ok(()));
        assert!(!r.probe_sent && r.rx.is_none() && r.tun_tx.is_none());
        assert_eq!(
            r.observe(735, true, Some(&sample(0, 10000, 80)), &settings),
            Action::Wait
        );
        assert!(!r.authenticated(735));
    }

    #[test]
    fn timer_ranges_and_wall_clock_steps_preserve_native_handshake_deadlines() {
        let cfg = json!({"obf":{"reject_after_time":"180-500","keepalive_timeout":"35","rekey_timeout":"5-8"}});
        let timing = PeerTiming::from_config(&cfg);
        assert_eq!((timing.key_lifetime, timing.demand_timeout), (500, 44));
        let settings = crate::recovery_settings(&Value::Null);
        let mut r = Recovery {
            timing,
            ..Default::default()
        };
        let tick = Instant::now();
        let live = sample(1000, 50, 10);
        r.adjust_clock(1000, tick);
        assert_eq!(r.observe(1000, true, Some(&live), &settings), Action::Wait);
        let wall = 7000;
        r.adjust_clock(wall, tick + std::time::Duration::from_secs(5));
        assert_eq!(r.observe(wall, true, Some(&live), &settings), Action::Wait);
        assert_eq!(r.healthy_at, wall - 5);
        r.adjust_clock(200, tick + std::time::Duration::from_secs(10));
        assert_eq!(r.observe(200, true, Some(&live), &settings), Action::Wait);
        let mut received = sample(1000, 55, 12);
        assert_eq!(
            r.observe(205, true, Some(&received), &settings),
            Action::Wait
        );
        r.activity(&mut received, 205);
        assert_eq!(received["last_peer_activity"], 205);
        assert_eq!(
            r.observe(704, true, Some(&received), &settings),
            Action::Wait
        );
        assert_eq!(
            r.observe(705, true, Some(&received), &settings),
            Action::Probe
        );
        assert_eq!(
            r.observe(724, true, Some(&received), &settings),
            Action::Wait
        );
        assert_eq!(
            r.observe(725, true, Some(&received), &settings),
            Action::Reconnect
        );
    }
    #[test]
    fn standby_starts_only_after_primary_failure_and_switches_only_on_verified_handshake() {
        struct Device(bool);
        impl Tunnel for Device {
            fn alive(&mut self) -> bool {
                self.0
            }
            fn stop(&mut self) -> io::Result<()> {
                self.0 = false;
                Ok(())
            }
            fn probe(&mut self) -> io::Result<()> {
                Ok(())
            }
            fn snapshot(&self) -> io::Result<Value> {
                Ok(json!({}))
            }
        }
        let tmp = tempfile::tempdir().unwrap();
        let db = Store::open(tmp.path()).unwrap();
        let runtime = Runtime::new(tmp.path(), tmp.path().join("no-engine"));
        let cfg = conf::parse(&crate::tests::input(), 0).unwrap();
        edit_document(&db, |d| {
            d["servers"] = json!(["P", "R", "D"]
                .into_iter()
                .enumerate()
                .map(|(i, id)| {
                    let mut c = cfg.clone();
                    c["client_iface"] = json!(format!("awg{i}"));
                    c["enabled"] = json!(true);
                    c["client"]["enabled"] = json!(true);
                    c["client"]["rust_managed"] = json!(true);
                    c["client"]["standby"] = json!(i > 0);
                    c["client"]["fallback_tunnel_ids"] = if id == "P" {
                        json!(["R", "D"])
                    } else {
                        json!([])
                    };
                    json!({"id":id,"config":c})
                })
                .collect::<Vec<_>>());
            d["active_id"] = json!("P");
            Ok(())
        })
        .unwrap();
        let doc = read(&db).unwrap();
        let now = crate::now();
        let settings = crate::recovery_settings(&Value::Null);
        let mut devices = runtime.clients.0.lock().unwrap();
        devices.insert(
            "P".into(),
            Managed {
                tunnel: Box::new(Device(true)),
                iface: "awg0".into(),
                fingerprint: [0; 32],
                recovery: Default::default(),
            },
        );
        let mut events = Vec::new();
        failover::reconcile(
            &doc,
            &mut devices,
            now,
            &settings,
            &mut events,
            None,
            |_| panic!("premature standby"),
        )
        .unwrap();
        let primary = &mut devices.get_mut("P").unwrap().recovery;
        for n in 0..=9 {
            let time = now - 45 + n * 5;
            let v = sample(now - 45, 64, n);
            assert_eq!(
                primary.observe(time, true, Some(&v), &settings),
                match n {
                    5 => Action::Probe,
                    9 => Action::Reconnect,
                    _ => Action::Wait,
                }
            );
            assert!(!primary.needs_reserve(time, 20, false));
        }
        primary.attempted(now, &Ok(()));
        failover::reconcile(&doc, &mut devices, now, &settings, &mut events, None, |s| {
            assert_eq!(s.id, "R");
            Ok(Box::new(Device(true)))
        })
        .unwrap();
        assert!(devices.contains_key("R") && !devices.contains_key("D"));
        drop(devices);
        assert_eq!(runtime.failover_view(&doc)["P"]["active_tunnel_id"], "");
        let mut devices = runtime.clients.0.lock().unwrap();
        devices.get_mut("R").unwrap().recovery.observe(
            now,
            true,
            Some(&json!({"running":true,"last_handshake":now,"rx_bytes":1})),
            &settings,
        );
        drop(devices);
        assert_eq!(runtime.failover_view(&doc)["P"]["active_tunnel_id"], "R");
        let mut devices = runtime.clients.0.lock().unwrap();
        devices.get_mut("P").unwrap().recovery.observe(
            now,
            true,
            Some(&json!({"running":true,"last_handshake":now,"rx_bytes":1})),
            &settings,
        );
        failover::reconcile(
            &doc,
            &mut devices,
            now,
            &settings,
            &mut events,
            None,
            |_| panic!("already recovered"),
        )
        .unwrap();
        assert!(!devices.contains_key("R"));
        drop(devices);
        assert_eq!(runtime.failover_view(&doc)["P"]["active_tunnel_id"], "P");
        assert_eq!(read(&db).unwrap(), doc);
    }
    #[test]
    fn canonical_backup_literals_and_original_port_are_bounded() {
        let v = vec![
            "192.0.2.1".into(),
            "[::ffff:192.0.2.2]:77".into(),
            "2001:db8::1".into(),
            "192.0.2.2:77".into(),
        ];
        assert_eq!(
            normalize("192.0.2.1:77", &v).unwrap(),
            ["192.0.2.2:77", "[2001:db8::1]:77"]
        );
        for s in [
            "backup.test",
            "224.0.0.1",
            "::",
            "[fe80::1%4]:99",
            "192.0.2.2:0",
        ] {
            assert!(normalize("one.test:80", &[s.into()]).is_err());
        }
        assert!(normalize("a.test:80", &vec!["192.0.2.1".into(); 9]).is_err());
    }
    #[test]
    fn inherited_recovery_seeds_from_a_verified_configured_literal_endpoint() {
        let pool = vec![
            "primary.example:51820".into(),
            "192.0.2.8:51821".into(),
            "[2001:db8::8]:51820".into(),
        ];
        let verified = json!({"running":true,"endpoint":"[::ffff:192.0.2.8]:51821"});
        let mut recovery = Recovery::default();
        recovery.select_initial(&pool, true, None);
        recovery.select_initial(
            &pool,
            true,
            Some(&json!({"running":false,"endpoint":pool[1]})),
        );
        recovery.select_initial(
            &pool,
            true,
            Some(&json!({"running":true,"status_unavailable":true,"endpoint":pool[1]})),
        );
        assert!(recovery.candidate.is_empty());
        recovery.select_initial(&pool, true, Some(&verified));
        assert_eq!(recovery.candidate, pool[1]);
        recovery.select_initial(
            &pool,
            true,
            Some(&json!({"running":true,"endpoint":pool[2]})),
        );
        assert_eq!(recovery.candidate, pool[1]);
        assert_eq!(recovery.next(&pool, &[]), pool[0]);

        for unset in [
            "192.0.2.8:51820",
            "192.0.2.9:51821",
            "[2001:db8::8%1]:51820",
            "primary.example:51820",
        ] {
            let mut recovery = Recovery::default();
            let unknown = json!({"running":true,"endpoint":unset});
            recovery.select_initial(&pool, true, Some(&unknown));
            assert!(recovery.selected().is_none());
            assert_eq!(
                recovery.retry_candidate(&pool, true, Some(&unknown), || {
                    panic!("unrecognized roaming endpoint has not tried the primary")
                }),
                pool[0]
            );
            assert_eq!(recovery.tried, 0);
        }
        let mut native = Recovery::default();
        native.select_initial(&pool, false, Some(&verified));
        assert_eq!(native.candidate, pool[0]);
    }

    #[test]
    fn resumed_named_profile_adopts_only_an_authenticated_literal_reserve() {
        let pool = ["primary.example:51820", "192.0.2.8:51821"].map(str::to_owned);
        let mut observed = json!({
            "running": true,
            "connected": true,
            "socket_mark": crate::DIRECT_SOCKET_MARK,
            "endpoint": "[::ffff:192.0.2.8]:51821"
        });
        let mut recovery = Recovery::default();
        recovery.select_initial(
            &pool,
            authenticated_literal_reserve(&pool, Some(&observed)),
            Some(&observed),
        );
        assert_eq!(recovery.selected(), Some(pool[1].as_str()));
        for (field, bad) in [
            ("endpoint", json!("192.0.2.8:51820")),
            ("connected", json!(false)),
            ("socket_mark", json!(0xa0000123_u32)),
            ("status_unavailable", json!(true)),
        ] {
            let original = observed[field].take();
            observed[field] = bad;
            assert!(!authenticated_literal_reserve(&pool, Some(&observed)));
            observed[field] = original;
        }
    }

    #[test]
    fn live_endpoint_matches_cache_by_port_after_trying_saved_literals() {
        let pool = ["vpn.example:51820", "192.0.2.4:51820", "[2001:db8::7]:443"].map(str::to_owned);
        let cache =
            |candidate: &str| (candidate == pool[0]).then(|| "192.0.2.3:51820".parse().unwrap());
        for (endpoint, index) in [
            ("[::ffff:192.0.2.3]:51820", Some(0)),
            ("192.0.2.3:443", None),
            ("192.0.2.8:51820", None),
            ("[2001:0db8::7]:443", Some(2)),
            ("[2001:db8::7%1]:443", None),
        ] {
            let live = json!({"running":true,"endpoint":endpoint});
            assert_eq!(endpoint_index(&pool, &live, cache), index);
        }
        let backup = json!({"running":true,"endpoint":"192.0.2.4:51820"});
        assert_eq!(
            endpoint_index(&pool, &backup, |_| panic!("saved literal precedes cache")),
            Some(1)
        );
    }

    #[test]
    fn endpoint_status_uses_verified_live_choice_without_replacing_retry_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = Runtime::new(dir.path(), dir.path().join("unused-engine"));
        let row = json!({"id":"vpn","config":{"endpoint":"vpn.example:51820",
            "client":{"endpoint_backups":["192.0.2.4", "192.0.2.5"]}}});
        let mut live = json!({"running":true,"endpoint":"192.0.2.5:51820"});
        let settings = crate::recovery_settings(&Value::Null);
        runtime.supplement_client(&row, &mut live, &settings, false);
        assert_eq!(live["endpoint_index"], 0);
        runtime.supplement_client(&row, &mut live, &settings, true);
        assert_eq!(live["endpoint_index"], 2);
        assert_eq!(live["endpoint_candidate"], "192.0.2.5:51820");

        runtime.clients.0.lock().unwrap().insert(
            "vpn".into(),
            Managed {
                tunnel: Box::new(Stopped),
                iface: "awg1".into(),
                fingerprint: [0; 32],
                recovery: Recovery {
                    candidate: "192.0.2.4:51820".into(),
                    ..Default::default()
                },
            },
        );
        runtime.supplement_client(&row, &mut live, &settings, true);
        assert_eq!(live["endpoint_index"], 2);
        assert_eq!(
            runtime.clients.0.lock().unwrap()["vpn"].recovery.selected(),
            Some("192.0.2.4:51820")
        );
        live["status_unavailable"] = true.into();
        runtime.supplement_client(&row, &mut live, &settings, true);
        assert_eq!(live["endpoint_index"], 1);
    }

    #[test]
    fn endpoint_hints_reorder_only_real_retries_and_do_not_exclude_silent_addresses() {
        let pool = ["192.0.2.1:2408", "192.0.2.2:2408", "192.0.2.3:2408"].map(str::to_owned);
        let mut r = Recovery {
            candidate: pool[0].clone(),
            ..Default::default()
        };
        let no_scan = || panic!("local engine repair must not run a network probe");
        assert_eq!(r.retry_candidate(&pool, false, None, no_scan), pool[0]);
        assert_eq!(r.retry_candidate(&pool, true, None, no_scan), pool[0]);
        let unavailable = json!({"running": true, "status_unavailable": true});
        assert_eq!(
            r.retry_candidate(&pool, true, Some(&unavailable), no_scan),
            pool[0]
        );
        assert_eq!(r.tried, 0);

        let live = json!({"running": true, "last_handshake": 0});
        let hints = || vec![false, false, true];
        r.candidate = r.retry_candidate(&pool, true, Some(&live), hints);
        assert_eq!(r.candidate, pool[2]);
        assert!(!r.authenticated(100) && !r.exhausted);
        assert_eq!(r.retry_candidate(&pool, true, None, no_scan), pool[2]);
        r.candidate = r.retry_candidate(&pool, true, Some(&live), hints);
        assert_eq!(r.candidate, pool[1]);
        assert!(!r.exhausted);
        r.candidate = r.retry_candidate(&pool, true, Some(&live), hints);
        assert!(r.exhausted);
    }

    #[test]
    fn handshake_observation_verifies_before_rotating_and_keeps_authenticated_backup() {
        let settings = crate::recovery_settings(&Value::Null);
        let mut r = Recovery::default();
        let pool = vec!["a:1".into(), "192.0.2.2:1".into(), "192.0.2.3:1".into()];
        let stale = json!({"running":true,"last_handshake":1,"rx_bytes":5});
        assert_eq!(r.observe(300, true, Some(&stale), &settings), Action::Probe);
        assert_eq!(r.observe(319, true, Some(&stale), &settings), Action::Wait);
        assert_eq!(
            r.observe(320, true, Some(&stale), &settings),
            Action::Reconnect
        );
        r.candidate = r.next(&pool, &[]);
        assert_eq!(r.candidate, pool[1]);
        r.attempted(320, &Ok(()));
        assert_eq!(r.retry_at(&settings), 340);
        assert_eq!(r.observe(339, true, None, &settings), Action::Wait);
        let fresh = json!({"running":true,"last_handshake":334,"rx_bytes":15});
        assert_eq!(r.observe(340, true, Some(&fresh), &settings), Action::Wait);
        assert_eq!(r.candidate, pool[1]);
        assert_eq!(r.attempts, 0);
        assert_eq!(r.observe(550, true, Some(&fresh), &settings), Action::Probe);
        assert_eq!(
            r.observe(571, true, Some(&fresh), &settings),
            Action::Reconnect
        );
        r.candidate = r.next(&pool, &[]);
        assert_eq!(r.candidate, pool[0]);
        r.candidate = r.next(&pool, &[]);
        assert_eq!(r.candidate, pool[2]);
        r.candidate = r.next(&pool, &[]);
        assert!(r.exhausted);
        assert_eq!(r.candidate, pool[0]);
        r.attempted(4200, &Err(invalid("unavailable")));
        assert_eq!(r.retry_at(&settings), 4290);
    }
}
