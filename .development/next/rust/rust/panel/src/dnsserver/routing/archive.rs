use super::{
    bounded::Bounded, ArchiveConfirmation, Confirmation, DnsOrigin, FailedRoute, Observer,
    RouteAnswer, RouteMatch, RouteObserver, RoutePublication, Selection,
};
use crate::dnsserver::{catalog::Index, network, redirect::FIRMWARE_RESOLVER, runtime::Engine};
use nfqws2_awg_rules::discoveries;
use nfqws2_awg_rules::kernel::FirmwareDnsArchive;
use nfqws2_config::{Key, Resolver};
use nfqws2_store::Store;
use serde::{de, Deserialize, Deserializer};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::OpenOptions,
    io::{self, BufReader, Read},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Weak},
    time::Duration,
};
use tokio::{
    task::JoinSet,
    time::{timeout_at, Instant},
};

const FILE: &str = "awg2_recent.json";
const FILE_LIMIT: u64 = 32 << 20;
const RECORD_LIMIT: usize = 4096;
const HISTORY_NAMES: usize = 128;
const WARMUP: Duration = Duration::from_secs(30);
const LOOKUPS: usize = 32;
const LOOKUP_LIMIT: Duration = Duration::from_secs(4);
const MANAGED_LOOKUP_LIMIT: Duration = Duration::from_secs(15);
const MAX_CNAME_LINKS: usize = 16;

pub(super) enum FirmwarePolicyLookup {
    Positive(Vec<IpAddr>, Instant),
    Negative,
    NegativeUntil(Instant),
}

#[derive(Clone)]
pub(crate) struct ArchiveResolver(Backend, Option<CatalogPin>);

/// Resolver authority retained by a failed static Apply without keeping an
/// old engine or its catalog alive after service replacement.
#[derive(Clone)]
pub(crate) struct ManagedOriginReceipt {
    engine: Weak<Engine>,
    catalog: CatalogPin,
    method_revision: u64,
}

impl ManagedOriginReceipt {
    pub(crate) fn same(&self, current: &ArchiveResolver) -> bool {
        let Some(engine) = self
            .engine
            .upgrade()
            .filter(|engine| !*engine.stopped.borrow())
        else {
            return false;
        };
        ArchiveResolver(
            Backend::Managed {
                engine,
                method_revision: Some(self.method_revision),
            },
            Some(self.catalog.clone()),
        )
        .same(current)
    }
}

#[derive(Clone)]
enum Backend {
    Firmware,
    Managed {
        engine: Arc<Engine>,
        method_revision: Option<u64>,
    },
}

#[derive(Clone)]
struct CatalogPin(Option<Weak<Index>>);

impl CatalogPin {
    fn snapshot(engine: &Engine) -> Option<Arc<Index>> {
        engine
            .filter
            .as_ref()
            .and_then(|filter| filter.feed.as_ref())
            .and_then(|feed| feed.snapshot())
    }

    fn matches(&self, active: Option<Arc<Index>>) -> bool {
        self.0.as_ref().map(Weak::as_ptr) == active.as_ref().map(Arc::as_ptr)
    }

    fn current(&self, engine: &Engine) -> bool {
        self.matches(Self::snapshot(engine))
    }

    fn try_current(&self, engine: &Engine) -> bool {
        match engine
            .filter
            .as_ref()
            .and_then(|filter| filter.feed.as_ref())
        {
            Some(feed) => feed
                .try_snapshot()
                .is_some_and(|active| self.matches(active)),
            None => self.matches(None),
        }
    }
}

/// A replay receipt for a previously answered, admitted LAN query. The
/// catalog may be refreshed without replacing the managed DNS engine.
#[derive(Clone)]
pub(in crate::dnsserver) struct ManagedRecent {
    engine: Weak<Engine>,
    catalog: CatalogPin,
    pub(super) failure: Option<FailedRoute>,
}

impl ManagedRecent {
    pub(in crate::dnsserver) fn capture(
        engine: &Arc<Engine>,
        catalog: Option<&Arc<Index>>,
    ) -> Option<Self> {
        let catalog = CatalogPin(catalog.map(Arc::downgrade));
        catalog.current(engine).then(|| Self {
            engine: Arc::downgrade(engine),
            catalog,
            failure: None,
        })
    }

    pub(super) fn resolver(&self) -> Option<ArchiveResolver> {
        let engine = self.engine.upgrade()?;
        if *engine.stopped.borrow() || !self.catalog.current(&engine) {
            return None;
        }
        Some(ArchiveResolver(
            Backend::Managed {
                engine,
                method_revision: None,
            },
            Some(self.catalog.clone()),
        ))
    }
}

impl ArchiveResolver {
    pub(super) async fn fresh_firmware_policy_ipv4(
        name: &str,
        deadline: Instant,
        current: impl Fn() -> bool,
    ) -> io::Result<FirmwarePolicyLookup> {
        Self::fresh_firmware_policy_ipv4_at(FIRMWARE_RESOLVER, name, deadline, current).await
    }

    async fn fresh_firmware_policy_ipv4_at(
        firmware: SocketAddr,
        name: &str,
        deadline: Instant,
        current: impl Fn() -> bool,
    ) -> io::Result<FirmwarePolicyLookup> {
        if !current() || Instant::now() >= deadline {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let query = nfqws2_dns::build_query(name, 1, 0)?;
        let wire = timeout_at(deadline, network::exchange_redirected(firmware, &query))
            .await
            .map_err(|_| io::ErrorKind::TimedOut)??;
        let received = Instant::now();
        if !current() || received >= deadline {
            return Err(io::ErrorKind::Interrupted.into());
        }
        nfqws2_dns::validate_answer(&query, &wire)?;
        let answer_count = u16::from_be_bytes([wire[6], wire[7]]);
        if answer_count == 0 && wire[3] & 15 == 3 {
            return Ok(FirmwarePolicyLookup::Negative);
        }
        let (_, addresses) = match nfqws2_dns::exact_address_step(&wire, 1) {
            Ok(found) => found,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let ttl = nfqws2_dns::address_negative_ttl(&wire, 1)?
                    .ok_or(io::ErrorKind::InvalidData)?;
                return Ok(FirmwarePolicyLookup::NegativeUntil(
                    received + Duration::from_secs(ttl.into()),
                ));
            }
            Err(error) => return Err(error),
        };
        let answer = nfqws2_dns::route_answer(&wire)?.ok_or(io::ErrorKind::InvalidData)?;
        if wire[3] & 15 != 0
            || addresses.is_empty()
            || answer.addresses != addresses
            || answer.ttl == 0
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(FirmwarePolicyLookup::Positive(
            addresses,
            received + Duration::from_secs(answer.ttl.into()),
        ))
    }

    pub(super) async fn fresh_firmware_ipv4(
        name: &str,
        deadline: Instant,
        current: impl Fn() -> bool,
    ) -> io::Result<Option<(RouteAnswer, Instant)>> {
        Self::firmware()
            .resolve_chain(FIRMWARE_RESOLVER, name, 1, deadline, current)
            .await
    }

    pub(in crate::dnsserver) fn firmware() -> Self {
        Self(Backend::Firmware, None)
    }

    pub(in crate::dnsserver) fn managed(engine: Arc<Engine>) -> Self {
        Self(
            Backend::Managed {
                engine,
                method_revision: None,
            },
            None,
        )
    }

    pub(in crate::dnsserver) fn pinned_managed(engine: Arc<Engine>) -> Self {
        let pin = CatalogPin(CatalogPin::snapshot(&engine).as_ref().map(Arc::downgrade));
        let method_revision = Some(engine.methods.revision());
        Self(
            Backend::Managed {
                engine,
                method_revision,
            },
            Some(pin),
        )
    }

    pub(crate) fn managed_origin_receipt(&self) -> Option<ManagedOriginReceipt> {
        let (
            Backend::Managed {
                engine,
                method_revision: Some(method_revision),
            },
            Some(catalog),
        ) = (&self.0, &self.1)
        else {
            return None;
        };
        Some(ManagedOriginReceipt {
            engine: Arc::downgrade(engine),
            catalog: catalog.clone(),
            method_revision: *method_revision,
        })
    }

    /// Internal exact-route preparation needs a fresh filtered reply without
    /// passing through client route delivery or the resolver cache.
    pub(crate) async fn fresh_managed_reply(&self, wire: &[u8]) -> io::Result<Vec<u8>> {
        let (
            Backend::Managed {
                engine,
                method_revision: Some(method_revision),
            },
            Some(catalog),
        ) = (&self.0, &self.1)
        else {
            return Err(io::ErrorKind::Unsupported.into());
        };
        let current = || {
            !*engine.stopped.borrow()
                && engine.methods.try_revision() == Some(*method_revision)
                && catalog.try_current(engine)
        };
        if !current() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let reply = engine.archive_reply(wire).await;
        if !current() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let reply = reply?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "DNS-ответ для маршрута заблокирован фильтром",
            )
        })?;
        nfqws2_dns::validate_forwarded_response(wire, &reply)?;
        Ok(reply)
    }

    pub(crate) fn same(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (Backend::Firmware, Backend::Firmware) => true,
            (
                Backend::Managed {
                    engine: a,
                    method_revision: first,
                },
                Backend::Managed {
                    engine: b,
                    method_revision: second,
                },
            ) => {
                Arc::ptr_eq(a, b)
                    && first
                        .iter()
                        .chain(second)
                        .all(|&revision| a.methods.try_revision() == Some(revision))
                    && self.1.as_ref().is_none_or(|pin| {
                        if first.is_some() {
                            pin.try_current(a)
                        } else {
                            pin.current(a)
                        }
                    })
                    && other.1.as_ref().is_none_or(|pin| {
                        if second.is_some() {
                            pin.try_current(b)
                        } else {
                            pin.current(b)
                        }
                    })
            }
            _ => false,
        }
    }

    pub(super) fn current(
        &self,
        observer: &dyn RouteObserver,
        publication: RoutePublication,
    ) -> bool {
        observer
            .archive_resolver(publication)
            .is_some_and(|current| self.same(&current))
    }

    async fn query(&self, firmware: SocketAddr, wire: &[u8]) -> io::Result<Option<Vec<u8>>> {
        match &self.0 {
            Backend::Firmware => network::exchange_redirected(firmware, wire).await.map(Some),
            Backend::Managed { engine, .. } => engine.archive_reply(wire).await,
        }
    }

    async fn resolve_chain(
        &self,
        firmware: SocketAddr,
        name: &str,
        kind: u16,
        deadline: Instant,
        current: impl Fn() -> bool,
    ) -> io::Result<Option<(RouteAnswer, Instant)>> {
        let mut chain = CnameChain::new(name);
        loop {
            if !current() {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let end = chain
                .expires
                .map_or(deadline, |expires| deadline.min(expires));
            if Instant::now() >= end {
                return Ok(None);
            }
            let query = nfqws2_dns::build_query(chain.name(), kind, 0)?;
            let reply = timeout_at(end, self.query(firmware, &query)).await;
            let received = Instant::now();
            if !current() {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let Ok(Ok(Some(wire))) = reply else {
                return Ok(None);
            };
            if received >= end {
                return Ok(None);
            }
            match chain.accept(&wire, kind, received) {
                Some(CnameStep::Resolved(answer, expires)) => return Ok(Some((answer, expires))),
                Some(CnameStep::Follow) => {}
                None => return Ok(None),
            }
        }
    }
}

struct CnameChain {
    names: Vec<String>,
    expires: Option<Instant>,
}

enum CnameStep {
    Resolved(RouteAnswer, Instant),
    Follow,
}

impl CnameChain {
    fn new(name: &str) -> Self {
        Self {
            names: vec![name.to_owned()],
            expires: None,
        }
    }

    fn name(&self) -> &str {
        self.names
            .last()
            .expect("CNAME chain retains its original name")
    }

    fn accept(&mut self, wire: &[u8], kind: u16, received: Instant) -> Option<CnameStep> {
        let mut answer = nfqws2_dns::route_answer(wire).ok()??;
        if answer.qtype != kind || answer.ttl == 0 {
            return None;
        }
        answer.addresses.retain(|ip| ip.is_ipv4() == (kind == 1));
        let expires = received + Duration::from_secs(answer.ttl.into());
        let expires = self
            .expires
            .map_or(expires, |earliest| earliest.min(expires));
        if expires <= received {
            return None;
        }
        if self.names.len() == 1 && !answer.addresses.is_empty() {
            return Some(CnameStep::Resolved(answer, expires));
        }

        let (aliases, terminal) = nfqws2_dns::exact_address_step(wire, kind).ok()?;
        let has_alias = !aliases.is_empty();
        for raw in aliases {
            let alias = hostname(&raw)?;
            if self.names.len() > MAX_CNAME_LINKS || self.names.contains(&alias) {
                return None;
            }
            self.names.push(alias);
        }
        if terminal.is_empty() && has_alias {
            self.expires = Some(expires);
            return Some(CnameStep::Follow);
        }
        answer
            .addresses
            .retain(|ip| terminal.binary_search(ip).is_ok());
        (!answer.addresses.is_empty()).then_some(CnameStep::Resolved(answer, expires))
    }
}

#[derive(Clone)]
pub(super) struct Source {
    store: Store,
    history: Arc<discoveries::Recent>,
    legacy: PathBuf,
    upstream: SocketAddr,
}

struct Candidate {
    name: String,
    learned: bool,
}

#[derive(Clone, Copy)]
enum Scope {
    Global(RouteMatch),
    History,
}

impl Source {
    pub(super) fn new(store: &Store, root: &Path, history: Arc<discoveries::Recent>) -> Self {
        Self {
            store: store.clone(),
            history,
            legacy: Resolver::new_at(root).path(Key::AwgSetDir).join(FILE),
            upstream: FIRMWARE_RESOLVER,
        }
    }

    fn observed_names(&self, history: Option<History>) -> Vec<Candidate> {
        // Copy observations before opening the disk snapshot. A concurrent
        // flush can promote the same name to disk, where it is deduplicated.
        let mut latest = BTreeMap::new();
        for (name, last_seen) in self.history.archive_names() {
            if let Some(name) = hostname(&name) {
                let rank = latest.entry(name).or_default();
                *rank = (true, last_seen).max(*rank);
            }
        }
        if let Some(history) = history {
            history.merge_names(&mut latest);
        }
        let mut ordered: Vec<_> = latest.into_iter().collect();
        ordered.sort_unstable_by(|(a, a_time), (b, b_time)| b_time.cmp(a_time).then(a.cmp(b)));
        ordered
            .into_iter()
            .take(HISTORY_NAMES)
            .map(|(name, (learned, _))| Candidate { name, learned })
            .collect()
    }

    fn read_history(&self) -> io::Result<Option<History>> {
        match self.store.read_limited(discoveries::FILE, FILE_LIMIT) {
            Ok(history) => Ok(Some(history)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub(super) fn firmware_archive(&self) -> io::Result<FirmwareDnsArchive> {
        let history = self.read_history()?;
        if history.as_ref().is_some_and(|history| history.version != 1) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let discovered = self
            .observed_names(history)
            .into_iter()
            .filter(|candidate| candidate.learned)
            .map(|candidate| candidate.name)
            .collect();
        let replay = match read_legacy::<LegacyAddresses>(&self.legacy) {
            Ok(replay) => replay.0,
            Err(error) if error.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => return Err(error),
        };
        Ok(FirmwareDnsArchive { discovered, replay })
    }

    fn names(&self) -> Vec<Candidate> {
        let mut names = self.observed_names(self.read_history().ok().flatten());
        let mut seen: BTreeSet<_> = names.iter().map(|entry| entry.name.clone()).collect();
        if let Ok(legacy) = legacy_names(&self.legacy) {
            names.extend(
                legacy
                    .0
                    .into_iter()
                    .filter(|name| seen.insert(name.clone()))
                    .map(|name| Candidate {
                        name,
                        learned: false,
                    }),
            );
        }
        names
    }

    pub(super) async fn warm_up(
        &self,
        routes: &Arc<Observer>,
        observer: &Arc<dyn RouteObserver>,
        publication: RoutePublication,
        resolver: &ArchiveResolver,
    ) -> bool {
        if !resolver.current(observer.as_ref(), publication) {
            return false;
        }
        let deadline = Instant::now() + WARMUP;
        let source = self.clone();
        let Ok(Ok(names)) = timeout_at(
            deadline,
            tokio::task::spawn_blocking(move || source.names()),
        )
        .await
        else {
            return true;
        };
        let mut names = names.into_iter();
        let mut jobs = JoinSet::new();
        while Instant::now() < deadline {
            for candidate in names.by_ref().take(LOOKUPS - jobs.len()) {
                let observer = observer.clone();
                let routes = routes.clone();
                let upstream = self.upstream;
                let resolver = resolver.clone();
                jobs.spawn(async move {
                    Self::warm_name(
                        upstream,
                        &routes,
                        &observer,
                        publication,
                        &resolver,
                        candidate,
                        deadline,
                    )
                    .await
                });
            }
            match timeout_at(deadline, jobs.join_next()).await {
                Ok(Some(Ok(true))) => {}
                Ok(Some(Ok(false) | Err(_))) => return false,
                Ok(None) | Err(_) => break,
            }
        }
        true
    }

    async fn warm_name(
        upstream: SocketAddr,
        routes: &Observer,
        observer: &Arc<dyn RouteObserver>,
        publication: RoutePublication,
        resolver: &ArchiveResolver,
        candidate: Candidate,
        deadline: Instant,
    ) -> bool {
        let name = &candidate.name;
        for kind in [1, 28] {
            if Instant::now() >= deadline {
                return true;
            }
            if !resolver.current(observer.as_ref(), publication) {
                return false;
            }
            let Ok(scope) = Self::scope(observer.as_ref(), publication, &candidate, kind) else {
                return false;
            };
            let Some(scope) = scope else { continue };
            let current = || {
                resolver.current(observer.as_ref(), publication)
                    && Self::scope(observer.as_ref(), publication, &candidate, kind).is_ok_and(
                        |selection| match (scope, selection) {
                            (Scope::History, Some(Scope::History)) => true,
                            (Scope::Global(target), Some(Scope::Global(current))) => {
                                current.generation == target.generation
                                    && current.zone == target.zone
                            }
                            _ => false,
                        },
                    )
            };
            let limit = match &resolver.0 {
                Backend::Firmware => LOOKUP_LIMIT,
                Backend::Managed { .. } => MANAGED_LOOKUP_LIMIT,
            };
            let Ok(reply) = resolver
                .resolve_chain(
                    upstream,
                    name,
                    kind,
                    deadline.min(Instant::now() + limit),
                    current,
                )
                .await
            else {
                return false;
            };
            if !current() {
                return false;
            }
            let Some((answer, expires)) = reply else {
                continue;
            };
            let deadline = deadline.min(Instant::now() + LOOKUP_LIMIT);
            match scope {
                Scope::History => {
                    let _ = routes
                        .confirm_history(
                            observer,
                            name,
                            answer,
                            ArchiveConfirmation {
                                publication,
                                deadline,
                                expires,
                                resolver,
                            },
                        )
                        .await;
                }
                Scope::Global(target) => {
                    let selection = Selection {
                        observer: observer.clone(),
                        origin: DnsOrigin {
                            client: None,
                            ingress: None,
                        },
                        target: Some(target),
                        kind: super::SelectionKind::Routed,
                    };
                    let _ = routes
                        .confirm(
                            &selection,
                            target,
                            name,
                            answer,
                            Confirmation::Replay {
                                publication,
                                deadline,
                                expires,
                                resolver: Some(resolver),
                            },
                        )
                        .await;
                }
            }
        }
        true
    }

    fn scope(
        observer: &dyn RouteObserver,
        publication: RoutePublication,
        candidate: &Candidate,
        qtype: u16,
    ) -> io::Result<Option<Scope>> {
        if candidate.learned {
            return observer
                .archive_history_matches(publication, &candidate.name, qtype)
                .map(|matches| matches.then_some(Scope::History));
        }
        observer
            .replay_target(
                publication,
                &candidate.name,
                DnsOrigin {
                    client: None,
                    ingress: None,
                },
            )
            .map(|target| target.map(Scope::Global))
    }
}

fn hostname(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let name = trimmed
        .strip_suffix('.')
        .unwrap_or(trimmed)
        .to_ascii_lowercase();
    if name.is_empty() || name.len() > 253 || name.parse::<IpAddr>().is_ok() {
        return None;
    }
    let wire = nfqws2_dns::build_query(&name, 1, 0).ok()?;
    (nfqws2_dns::query_domain(&wire).ok()?.0 == name).then_some(name)
}

#[derive(Deserialize)]
struct History {
    version: u8,
    entries: Bounded<HistoricalName, RECORD_LIMIT>,
}

#[derive(Deserialize)]
struct HistoricalName {
    domain: String,
    last_seen: i64,
    source: String,
    #[serde(default)]
    rule_key: String,
    #[serde(default)]
    ips: Option<HistoricalAddresses>,
}

struct HistoricalAddresses(bool);

impl<'de> Deserialize<'de> for HistoricalAddresses {
    fn deserialize<D: Deserializer<'de>>(input: D) -> Result<Self, D::Error> {
        struct Addresses;
        impl<'de> de::Visitor<'de> for Addresses {
            type Value = HistoricalAddresses;

            fn expecting(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
                out.write_str("a Go history address list")
            }

            fn visit_seq<A: de::SeqAccess<'de>>(
                self,
                mut list: A,
            ) -> Result<Self::Value, A::Error> {
                let mut valid = false;
                while let Some(address) = list.next_element::<String>()? {
                    valid |= address
                        .trim()
                        .parse::<IpAddr>()
                        .is_ok_and(|ip| !ip.to_canonical().is_unspecified());
                }
                Ok(HistoricalAddresses(valid))
            }
        }
        input.deserialize_seq(Addresses)
    }
}

impl History {
    fn merge_names(self, latest: &mut BTreeMap<String, (bool, i64)>) {
        if self.version != 1 {
            return;
        }
        for entry in self.entries.0 {
            if entry.last_seen <= 0 || !matches!(entry.source.as_str(), "dns" | "sni") {
                continue;
            }
            if let Some(name) = hostname(&entry.domain) {
                let valid = !entry.rule_key.is_empty()
                    && entry.rule_key.len() <= 128
                    && !entry
                        .rule_key
                        .chars()
                        .any(|c| c.is_control() || c.is_whitespace())
                    && entry.ips.is_some_and(|addresses| addresses.0);
                let seen = latest.entry(name).or_default();
                *seen = (*seen).max((valid, entry.last_seen));
            }
        }
    }
}

struct LegacyNames(BTreeSet<String>);

impl<'de> Deserialize<'de> for LegacyNames {
    fn deserialize<D: Deserializer<'de>>(input: D) -> Result<Self, D::Error> {
        struct Names;
        impl<'de> de::Visitor<'de> for Names {
            type Value = LegacyNames;

            fn expecting(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
                out.write_str("a bounded Go DNS archive map")
            }

            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut names = BTreeSet::new();
                let mut count = 0;
                while let Some(key) = map.next_key::<String>()? {
                    count += 1;
                    if count > RECORD_LIMIT {
                        return Err(de::Error::invalid_length(count, &self));
                    }
                    map.next_value::<de::IgnoredAny>()?;
                    if let Some(name) = hostname(&key) {
                        names.insert(name);
                    }
                }
                Ok(LegacyNames(names))
            }
        }
        input.deserialize_map(Names)
    }
}

fn legacy_names(path: &Path) -> io::Result<LegacyNames> {
    read_legacy(path)
}

struct LegacyAddresses(BTreeMap<String, Vec<IpAddr>>);

impl<'de> Deserialize<'de> for LegacyAddresses {
    fn deserialize<D: Deserializer<'de>>(input: D) -> Result<Self, D::Error> {
        struct Addresses;
        impl<'de> de::Visitor<'de> for Addresses {
            type Value = LegacyAddresses;

            fn expecting(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
                out.write_str("a bounded Go DNS archive")
            }

            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut replay = BTreeMap::new();
                let mut count = 0;
                while let Some(key) = map.next_key::<String>()? {
                    count += 1;
                    if count > RECORD_LIMIT {
                        return Err(de::Error::invalid_length(count, &self));
                    }
                    let raw = map.next_value::<Option<Bounded<String, 4096>>>()?;
                    let Some((name, raw)) = hostname(&key).zip(raw) else {
                        continue;
                    };
                    let mut addresses: Vec<_> = raw
                        .0
                        .into_iter()
                        .filter_map(|ip| ip.trim().parse::<IpAddr>().ok())
                        .map(|ip| ip.to_canonical())
                        .filter(|ip| ip.is_ipv4() && !ip.is_unspecified())
                        .collect();
                    addresses.sort_unstable();
                    addresses.dedup();
                    if !addresses.is_empty() && replay.insert(name, addresses).is_some() {
                        return Err(de::Error::custom("duplicate DNS archive name"));
                    }
                }
                Ok(LegacyAddresses(replay))
            }
        }
        input.deserialize_map(Addresses)
    }
}

fn read_legacy<T: serde::de::DeserializeOwned>(path: &Path) -> io::Result<T> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    if !path.symlink_metadata()?.is_file() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let file = options.open(path)?;
    let info = file.metadata()?;
    if !info.is_file() || info.len() > FILE_LIMIT {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut bytes = file.take(FILE_LIMIT + 1);
    let names = serde_json::from_reader(BufReader::new(&mut bytes))?;
    if bytes.limit() == 0 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    fn wire_name(host: &str) -> Vec<u8> {
        let query = nfqws2_dns::build_query(host, 1, 0).unwrap();
        query[12..query.len() - 4].to_vec()
    }

    fn add_soa(reply: &mut Vec<u8>, zone: &str, minimum: u32, malformed: bool) {
        reply[2] |= 4;
        reply[9] = 1;
        reply.extend(wire_name(zone));
        reply.extend([0, 6, 0, 1, 0, 0, 0, 29]);
        let mut soa = wire_name("ns.scoped.test");
        soa.extend(wire_name("hostmaster.scoped.test"));
        for value in [1_u32, 300, 60, 900, minimum] {
            soa.extend(value.to_be_bytes());
        }
        if malformed {
            soa.pop();
        }
        reply.extend(u16::try_from(soa.len()).unwrap().to_be_bytes());
        reply.extend(soa);
    }

    #[tokio::test]
    async fn cold_mixed_policy_uses_only_terminal_a_with_the_alias_ttl() {
        let firmware = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = firmware.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut packet = [0; 512];
            let (n, peer) = firmware.recv_from(&mut packet).await.unwrap();
            let mut reply = nfqws2_dns::response_error(&packet[..n], 0);
            reply[7] = 4;
            let alias = wire_name("a.cdn.example");
            reply.extend([192, 12, 0, 5, 0, 1, 0, 0, 0, 18]);
            reply.extend(u16::try_from(alias.len()).unwrap().to_be_bytes());
            reply.extend(&alias);
            for octet in [93, 95] {
                reply.extend(&alias);
                reply.extend([0, 1, 0, 1, 0, 0, 0, 37, 0, 4, 198, 18, 9, octet]);
            }
            reply.extend(wire_name("unrelated.example"));
            reply.extend([0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 198, 18, 9, 99]);
            firmware.send_to(&reply, peer).await.unwrap();
        });
        let now = Instant::now();
        let answer = ArchiveResolver::fresh_firmware_policy_ipv4_at(
            endpoint,
            "local.scoped.test",
            now + Duration::from_secs(1),
            || true,
        )
        .await
        .unwrap();
        let FirmwarePolicyLookup::Positive(addresses, expires) = answer else {
            panic!("expected terminal A")
        };
        assert_eq!(
            addresses,
            [
                IpAddr::from([198, 18, 9, 93]),
                IpAddr::from([198, 18, 9, 95])
            ]
        );
        assert!(
            expires >= now + Duration::from_secs(18)
                && expires <= Instant::now() + Duration::from_secs(18)
        );
        server.await.unwrap();
    }
    #[tokio::test]
    async fn cold_mixed_policy_distinguishes_verified_firmware_nxdomain_from_failure() {
        let firmware = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = firmware.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut packet = [0; 512];
            for rcode in [3, 2, 0] {
                let (len, address) = firmware.recv_from(&mut packet).await.unwrap();
                let response = nfqws2_dns::response_error(&packet[..len], rcode);
                firmware.send_to(&response, address).await.unwrap();
            }
        });
        let lookup = || {
            ArchiveResolver::fresh_firmware_policy_ipv4_at(
                endpoint,
                "local.scoped.test",
                Instant::now() + Duration::from_secs(1),
                || true,
            )
        };
        assert!(matches!(
            lookup().await.unwrap(),
            FirmwarePolicyLookup::Negative
        ));
        assert!(lookup().await.is_err());
        assert!(lookup().await.is_err());
        server.await.unwrap();
    }
    #[tokio::test]
    async fn cold_firmware_nodata_needs_an_enclosing_soa_and_its_original_ttl() {
        let firmware = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = firmware.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut packet = [0; 512];
            for (zone, minimum, malformed) in [
                ("scoped.test", 7, false),
                ("unrelated.test", 7, false),
                ("scoped.test", 0, false),
                ("scoped.test", 7, true),
            ] {
                let (len, peer) = firmware.recv_from(&mut packet).await.unwrap();
                let mut reply = nfqws2_dns::response_error(&packet[..len], 0);
                add_soa(&mut reply, zone, minimum, malformed);
                firmware.send_to(&reply, peer).await.unwrap();
            }
        });
        let lookup = || {
            ArchiveResolver::fresh_firmware_policy_ipv4_at(
                endpoint,
                "local.scoped.test",
                Instant::now() + Duration::from_secs(1),
                || true,
            )
        };
        let started = Instant::now();
        let FirmwarePolicyLookup::NegativeUntil(expires) = lookup().await.unwrap() else {
            panic!("expected authoritative NODATA");
        };
        let minimum = Duration::from_secs(7);
        assert!(expires >= started + minimum && expires <= Instant::now() + minimum);
        for _ in 0..3 {
            assert_eq!(
                lookup().await.err().unwrap().kind(),
                io::ErrorKind::InvalidData
            );
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn cold_firmware_cname_negative_needs_terminal_soa_and_earliest_ttl() {
        let firmware = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = firmware.local_addr().unwrap();
        let server = tokio::spawn(async move {
            fn add_cname(reply: &mut Vec<u8>, owner: &str, target: &str, ttl: u32) {
                reply.extend(wire_name(owner));
                reply.extend([0, 5, 0, 1]);
                reply.extend(ttl.to_be_bytes());
                let target = wire_name(target);
                reply.extend(u16::try_from(target.len()).unwrap().to_be_bytes());
                reply.extend(target);
            }
            let mut packet = [0; 512];
            for (rcode, zone, owner, target, ttl, contradictory) in [
                (0, "cdn.test", "mid.cdn.test", "leaf.cdn.test", 11, false),
                (3, "cdn.test", "mid.cdn.test", "leaf.cdn.test", 5, false),
                (0, "scoped.test", "mid.cdn.test", "leaf.cdn.test", 11, false),
                (3, "scoped.test", "mid.cdn.test", "leaf.cdn.test", 11, false),
                (3, "cdn.test", "unrelated.cdn.test", "leaf.cdn.test", 11, false),
                (3, "cdn.test", "mid.cdn.test", "leaf.cdn.test", 11, true),
                (3, "cdn.test", "mid.cdn.test", "local.scoped.test", 11, false),
            ] {
                let (len, peer) = firmware.recv_from(&mut packet).await.unwrap();
                let mut reply = nfqws2_dns::response_error(&packet[..len], rcode);
                reply[7] = 2 + u8::from(contradictory);
                add_cname(&mut reply, "local.scoped.test", "mid.cdn.test", 17);
                add_cname(&mut reply, owner, target, ttl);
                if contradictory {
                    reply.extend(wire_name(target));
                    reply.extend([0, 1, 0, 1, 0, 0, 0, 11, 0, 4, 198, 18, 9, 93]);
                }
                add_soa(&mut reply, zone, 7, false);
                firmware.send_to(&reply, peer).await.unwrap();
            }
        });
        let lookup = || {
            ArchiveResolver::fresh_firmware_policy_ipv4_at(
                endpoint,
                "local.scoped.test",
                Instant::now() + Duration::from_secs(1),
                || true,
            )
        };
        for seconds in [7, 5] {
            let started = Instant::now();
            let FirmwarePolicyLookup::NegativeUntil(expires) = lookup().await.unwrap() else {
                panic!("expected an authoritative terminal negative answer");
            };
            let ttl = Duration::from_secs(seconds);
            assert!(expires >= started + ttl && expires <= Instant::now() + ttl);
        }
        for _ in 0..5 {
            assert_eq!(
                lookup().await.err().unwrap().kind(),
                io::ErrorKind::InvalidData
            );
        }
        server.await.unwrap();
    }

    use super::*;
    use crate::dnsserver::routing::{RouteAnswer, RouteMatch};
    use std::sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Mutex,
    };
    use tokio::{net::UdpSocket, time::timeout};

    type Install = (String, u16, Vec<IpAddr>, u32);
    type HistoryInstall = (Install, Vec<usize>);

    struct Gate {
        generation: AtomicU64,
        allowed: AtomicBool,
        installs: Mutex<Vec<Install>>,
        history_installs: Mutex<Vec<HistoryInstall>>,
        policy: nfqws2_awg_rules::observed::Policy,
        resolver: Mutex<ArchiveResolver>,
    }

    impl Gate {
        fn new() -> Self {
            let routing = serde_json::from_value(serde_json::json!({
                "mode": "zones", "domain_source": "dnsproxy", "zones": [
                    { "enabled": true, "domains": ["device.office.test"], "source_ips": ["127.0.0.1"] },
                    { "enabled": true, "domains": ["raw*.office.test", "journal*.office.test", "dup*.office.test"] },
                    { "enabled": true, "domains": ["*"] }
                ]
            })).unwrap();
            Self {
                generation: AtomicU64::new(1),
                allowed: AtomicBool::new(true),
                installs: Mutex::new(Vec::new()),
                history_installs: Mutex::new(Vec::new()),
                policy: nfqws2_awg_rules::observed::Policy::compile(&routing).unwrap(),
                resolver: Mutex::new(ArchiveResolver::firmware()),
            }
        }
    }

    impl RouteObserver for Gate {
        fn select(&self, name: &str, client: Option<IpAddr>) -> io::Result<Option<RouteMatch>> {
            assert_eq!(client, None, "archives must use global selection");
            let generation = self.generation.load(Ordering::SeqCst);
            Ok(self.policy.matched(name, client).map(|zone| RouteMatch {
                revision: 2,
                generation,
                zone,
            }))
        }

        fn replay_publication(&self) -> Option<RoutePublication> {
            Some(RoutePublication {
                generation: self.generation.load(Ordering::SeqCst),
                revision: 4,
            })
        }

        fn archive_resolver(&self, publication: RoutePublication) -> Option<ArchiveResolver> {
            (self.replay_publication() == Some(publication) && self.allowed.load(Ordering::SeqCst))
                .then(|| self.resolver.lock().unwrap().clone())
        }

        fn replay_target(
            &self,
            publication: RoutePublication,
            name: &str,
            origin: DnsOrigin<'_>,
        ) -> io::Result<Option<RouteMatch>> {
            assert_eq!(
                origin.ingress, None,
                "archives must not supply a LAN bridge"
            );
            if self.archive_resolver(publication).is_none() {
                return Err(io::ErrorKind::Interrupted.into());
            }
            Ok(self
                .select(name, origin.client)?
                .filter(|target| self.policy.history_match(target.zone, name).is_some()))
        }

        fn install(
            &self,
            _: RouteMatch,
            _: &str,
            _: DnsOrigin<'_>,
            _: &RouteAnswer,
        ) -> io::Result<(bool, u64)> {
            panic!("archive probes must not count as client visits")
        }

        fn install_replayed(
            &self,
            target: RouteMatch,
            name: &str,
            origin: DnsOrigin<'_>,
            answer: &RouteAnswer,
            resolver: Option<&ArchiveResolver>,
        ) -> io::Result<(bool, u64)> {
            assert!(resolver.is_some_and(|resolver| resolver.same(&self.resolver.lock().unwrap())));
            assert_eq!(origin.client, None);
            assert_eq!(origin.ingress, None);
            assert_eq!(self.select(name, None)?, Some(target));
            self.installs.lock().unwrap().push((
                name.into(),
                answer.qtype,
                answer.addresses.clone(),
                answer.ttl,
            ));
            Ok((false, 2))
        }

        fn archive_history_matches(
            &self,
            publication: RoutePublication,
            name: &str,
            qtype: u16,
        ) -> io::Result<bool> {
            if self.archive_resolver(publication).is_none() {
                return Err(io::ErrorKind::Interrupted.into());
            }
            Ok(self.policy.archive_zones(name, qtype).next().is_some())
        }

        fn install_history(
            &self,
            publication: RoutePublication,
            resolver: &ArchiveResolver,
            name: &str,
            answer: &RouteAnswer,
        ) -> io::Result<()> {
            assert!(resolver.current(self, publication));
            let zones = self.policy.archive_zones(name, answer.qtype).collect();
            self.history_installs.lock().unwrap().push((
                (
                    name.into(),
                    answer.qtype,
                    answer.addresses.clone(),
                    answer.ttl,
                ),
                zones,
            ));
            Ok(())
        }
    }

    fn fixture(root: &Path, firmware: SocketAddr) -> Source {
        let db = Store::open(root.join("configured-data")).unwrap();
        let mut source = Source::new(&db, root, Default::default());
        assert_eq!(
            source.legacy,
            root.join("opt/etc/nfqws2-strategy/awg2_recent.json")
        );
        std::fs::create_dir_all(source.legacy.parent().unwrap()).unwrap();
        source.upstream = firmware;
        source
    }

    fn a_reply(q: &[u8], octet: u8, ttl: u8) -> Vec<u8> {
        let mut r = nfqws2_dns::response_error(q, 0);
        r[7] = 1;
        r.extend([192, 12, 0, 1, 0, 1, 0, 0, 0, ttl, 0, 4, 192, 0, 2, octet]);
        r
    }

    fn cname_reply(q: &[u8], target: &str, ttl: u32) -> Vec<u8> {
        let target = nfqws2_dns::build_query(target, 1, 0).unwrap();
        let target = &target[12..target.len() - 4];
        let mut r = nfqws2_dns::response_error(q, 0);
        r[7] = 1;
        r.extend([192, 12, 0, 5, 0, 1]);
        r.extend(ttl.to_be_bytes());
        r.extend((target.len() as u16).to_be_bytes());
        r.extend_from_slice(target);
        r
    }

    #[test]
    fn history_merge_selects_one_bounded_window_before_appending_raw_names() {
        let dir = tempfile::tempdir().unwrap();
        let archive = fixture(dir.path(), FIRMWARE_RESOLVER);
        let entries: Vec<_> = (0..HISTORY_NAMES + 2)
            .rev()
            .map(|i| {
                serde_json::json!({
                    "domain":format!("disk-{i:03}.test"),
                    "source":"dns", "last_seen":27, "rule_key":"old", "ips":["198.51.100.10"]
                })
            })
            .collect();
        let disk = serde_json::json!({"version":1,"entries":entries});
        archive
            .store
            .transaction(|tx| tx.save(discoveries::FILE, &disk))
            .unwrap();
        std::fs::write(&archive.legacy, br#"{"disk-129.test":[],"raw.test":[]}"#).unwrap();

        let key = "a".repeat(64);
        let next_key = "b".repeat(64);
        let address = ["198.51.100.11".parse().unwrap()];
        archive
            .history
            .confirm(4, (&key, false), "disk-129.test", None, &address);
        archive
            .history
            .confirm(4, (&next_key, false), "DISK-129.test.", None, &address);
        archive
            .history
            .confirm(4, (&key, false), "unsaved.test", None, &address);
        archive.history.invalidate();

        let names = archive.names();
        assert_eq!(names.len(), HISTORY_NAMES + 1);
        let newest: BTreeSet<_> = names[..2].iter().map(|entry| entry.name.as_str()).collect();
        assert_eq!(newest, BTreeSet::from(["disk-129.test", "unsaved.test"]));
        for (i, entry) in names[2..HISTORY_NAMES].iter().enumerate() {
            assert_eq!(entry.name, format!("disk-{i:03}.test"));
            assert!(entry.learned);
        }
        assert!(names[..2].iter().all(|entry| entry.learned));
        assert_eq!(names[HISTORY_NAMES].name, "raw.test");
        assert!(!names[HISTORY_NAMES].learned);

        archive.history.reset_after_restore();
        let restored = archive.names();
        assert!(!restored.iter().any(|entry| entry.name == "unsaved.test"));
        assert_eq!(restored[0].name, "disk-000.test");
        assert_eq!(restored[HISTORY_NAMES - 1].name, "disk-127.test");
        assert_eq!(restored[HISTORY_NAMES].name, "disk-129.test");
        assert!(!restored[HISTORY_NAMES].learned);
    }

    #[tokio::test]
    async fn unflushed_history_replays_fresh_answers_from_the_frozen_common_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let archive = fixture(dir.path(), server.local_addr().unwrap());
        let disk = serde_json::json!({"version":1,"entries":[
            {"domain":"disk.team.test","source":"dns","last_seen":10,"rule_key":"old",
             "ips":["198.51.100.90"]},
            {"domain":"dedup.team.test","source":"dns","last_seen":20,"rule_key":"another",
             "ips":["198.51.100.91"]}
        ]});
        let disk_path = dir.path().join("configured-data").join(discoveries::FILE);
        let raw = br#"{"dedup.team.test":["198.51.100.92"],"raw.team.test":["198.51.100.93"]}"#;
        archive
            .store
            .transaction(|tx| tx.save(discoveries::FILE, &disk))
            .unwrap();
        let saved = std::fs::read(&disk_path).unwrap();
        std::fs::write(&archive.legacy, raw).unwrap();
        let raw_path = archive.legacy.clone();
        let memory = archive.history.clone();
        let key = "a".repeat(64);
        let address = ["198.51.100.94".parse().unwrap()];
        for name in ["dedup.team.test", "unflushed.team.test"] {
            memory.confirm(
                4,
                (&key, false),
                name,
                Some("192.168.1.9".parse().unwrap()),
                &address,
            );
        }
        memory.invalidate();

        let firmware = tokio::spawn(async move {
            let mut seen = BTreeSet::new();
            let mut buf = [0; 512];
            for i in 0..3 {
                let (n, client) = server.recv_from(&mut buf).await.unwrap();
                let query = &buf[..n];
                let (name, kind) = nfqws2_dns::query_domain(query).unwrap();
                assert_eq!(kind, 1);
                assert!(seen.insert(name));
                if i == 0 {
                    memory.confirm(4, (&key, false), "late.team.test", None, &address);
                }
                server
                    .send_to(&a_reply(query, 53, 37), client)
                    .await
                    .unwrap();
            }
            assert!(
                timeout(Duration::from_millis(50), server.recv_from(&mut buf))
                    .await
                    .is_err()
            );
            seen
        });
        let mut gate = Gate::new();
        let routing = serde_json::from_value(serde_json::json!({
            "mode":"zones","domain_source":"dnsproxy","zones":[
                {"enabled":true,"domains":["*.team.test"],"source_ips":["192.168.1.0/24"]},
                {"enabled":true,"domains":["*.team.test"],"source_ips":["192.168.2.0/24"]}
            ]
        }))
        .unwrap();
        gate.policy = nfqws2_awg_rules::observed::Policy::compile(&routing).unwrap();
        let gate = Arc::new(gate);
        let routes = Arc::new(Observer {
            archive: Some(archive),
            ..Observer::default()
        });
        routes.register(gate.clone());
        routes.schedule_replay(gate.replay_publication().unwrap());
        let job = routes.replay.lock().unwrap().take().unwrap();
        timeout(Duration::from_secs(5), job).await.unwrap().unwrap();
        let queried = timeout(Duration::from_secs(5), firmware)
            .await
            .unwrap()
            .unwrap();
        let expected = BTreeSet::from([
            "dedup.team.test".into(),
            "disk.team.test".into(),
            "unflushed.team.test".into(),
        ]);
        assert_eq!(queried, expected);
        assert!(gate.installs.lock().unwrap().is_empty());
        let installs = gate.history_installs.lock().unwrap();
        assert_eq!(installs.len(), 3);
        let mut installed = BTreeSet::new();
        for ((name, kind, ips, ttl), zones) in installs.iter() {
            installed.insert(name.clone());
            assert_eq!(*kind, 1);
            assert_eq!(ips, &["192.0.2.53".parse::<IpAddr>().unwrap()]);
            assert!((30..=37).contains(ttl));
            assert_eq!(zones, &[0, 1]);
        }
        assert_eq!(installed, expected);
        assert_eq!(std::fs::read(disk_path).unwrap(), saved);
        assert_eq!(std::fs::read(raw_path).unwrap(), raw);
    }

    #[tokio::test]
    async fn valid_go_history_replays_scoped_rules_once_and_raw_names_remain_global() {
        let dir = tempfile::tempdir().unwrap();
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let archive = fixture(dir.path(), server.local_addr().unwrap());
        let old_wire = br#"{
            "known.team.test":["198.51.100.90"], "raw.team.test":["198.51.100.91"]
        }"#;
        std::fs::write(&archive.legacy, old_wire).unwrap();
        let history = serde_json::json!({"version":1,"entries":[
            {"domain":"known.team.test","source":"dns","last_seen":30,"rule_key":"old",
             "ips":["198.51.100.92"], "source_ips":["192.168.77.7"]},
            {"domain":"invalid-key.team.test","source":"sni","last_seen":20,"rule_key":"bad key",
             "ips":["198.51.100.93"]},
            {"domain":"invalid-address.team.test","source":"dns","last_seen":20,"rule_key":"old",
             "ips":["bad","::ffff:0.0.0.0"]},
            {"domain":"empty.team.test","source":"dns","last_seen":10,"rule_key":"old","ips":[]}
        ]});
        archive
            .store
            .transaction(|tx| tx.save(nfqws2_awg_rules::discoveries::FILE, &history))
            .unwrap();

        let firmware = tokio::spawn(async move {
            let mut buf = [0; 512];
            let (n, client) = server.recv_from(&mut buf).await.unwrap();
            let query = &buf[..n];
            assert_eq!(
                nfqws2_dns::query_domain(query).unwrap(),
                ("known.team.test".into(), 1)
            );
            server
                .send_to(&a_reply(query, 53, 37), client)
                .await
                .unwrap();
            assert!(
                timeout(Duration::from_millis(50), server.recv_from(&mut buf))
                    .await
                    .is_err()
            );
        });

        let mut gate = Gate::new();
        let routing = serde_json::from_value(serde_json::json!({
            "mode":"zones","domain_source":"dnsproxy","zones":[
                {"enabled":true,"domains":["*.team.test"],"source_ips":["192.168.1.0/24"]},
                {"enabled":true,"domains":["known.team.test"],"source_ips":["192.168.2.0/24"]},
                {"enabled":true,"domains":["*"],"source_ips":["192.168.1.7"]},
                {"enabled":false,"domains":["known.team.test"]},
                {"enabled":true,"waiting_for_connection":true,"domains":["known.team.test"]}
            ]
        }))
        .unwrap();
        gate.policy = nfqws2_awg_rules::observed::Policy::compile(&routing).unwrap();
        let gate = Arc::new(gate);
        let archive_path = archive.legacy.clone();
        let store = archive.store.clone();
        let routes = Arc::new(Observer {
            archive: Some(archive),
            ..Observer::default()
        });
        routes.register(gate.clone());
        routes.schedule_restored_replay(gate.replay_publication().unwrap());
        let job = routes.replay.lock().unwrap().take().unwrap();
        timeout(Duration::from_secs(5), job).await.unwrap().unwrap();
        timeout(Duration::from_secs(5), firmware)
            .await
            .unwrap()
            .unwrap();
        assert!(gate.installs.lock().unwrap().is_empty());
        let installed = gate.history_installs.lock().unwrap();
        let [((name, kind, ips, ttl), zones)] = installed.as_slice() else {
            panic!("expected one shared install, got {installed:?}");
        };
        assert_eq!(name, "known.team.test");
        assert_eq!(*kind, 1);
        assert_eq!(ips, &["192.0.2.53".parse::<IpAddr>().unwrap()]);
        assert!((30..=37).contains(ttl));
        assert_eq!(zones, &[0, 1]);
        assert_eq!(std::fs::read(&archive_path).unwrap(), old_wire);
        let saved: serde_json::Value = store.read(nfqws2_awg_rules::discoveries::FILE).unwrap();
        assert_eq!(saved, history);
    }

    #[test]
    fn archive_cname_chain_preserves_absolute_expiry_and_checks_total_links() {
        let origin = "raw.office.test";
        let target = "terminal.archive.test";
        let q = |name: &str| nfqws2_dns::build_query(name, 1, 9).unwrap();
        let now = Instant::now();
        let alias = cname_reply(&q(origin), target, 4);
        let terminal = a_reply(&q(target), 31, 120);
        let mut chain = CnameChain::new(origin);
        assert!(matches!(
            chain.accept(&alias, 1, now),
            Some(CnameStep::Follow)
        ));
        assert_eq!(chain.name(), target);
        let Some(CnameStep::Resolved(answer, expires)) =
            chain.accept(&terminal, 1, now + Duration::from_secs(3))
        else {
            panic!("fresh terminal RRset did not resolve the chain")
        };
        assert_eq!(answer.addresses, [IpAddr::from([192, 0, 2, 31])]);
        assert_eq!(expires, now + Duration::from_secs(4));
        assert!(chain.accept(&terminal, 1, expires).is_none());

        let mut chain = CnameChain::new(origin);
        for hop in 1..=MAX_CNAME_LINKS {
            let target = format!("hop-{hop}.archive.test");
            let wire = cname_reply(&q(chain.name()), &target, 60);
            assert!(matches!(
                chain.accept(&wire, 1, now),
                Some(CnameStep::Follow)
            ));
        }
        let over_limit = cname_reply(&q(chain.name()), "would-be-next.archive.test", 60);
        assert!(chain.accept(&over_limit, 1, now).is_none());
        let ready = a_reply(&q(chain.name()), 32, 60);
        assert!(matches!(
            chain.accept(&ready, 1, now),
            Some(CnameStep::Resolved(..))
        ));

        let mut chain = CnameChain::new(origin);
        assert!(matches!(
            chain.accept(&alias, 1, now),
            Some(CnameStep::Follow)
        ));
        let mut unavailable = cname_reply(&q(target), "example.archive.test", 20);
        unavailable[3] |= 3;
        assert!(chain.accept(&unavailable, 1, now).is_none());
        let incompatible = a_reply(&q(target), 32, 20);
        assert!(chain.accept(&incompatible, 28, now).is_none());
    }

    #[tokio::test]
    async fn firmware_archive_follows_reachable_cname_and_rejects_cross_packet_loop() {
        let dir = tempfile::tempdir().unwrap();
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let archive = fixture(dir.path(), server.local_addr().unwrap());
        std::fs::write(
            &archive.legacy,
            br#"{"raw.office.test":["198.51.100.45"],"raw-cycle.office.test":[]}"#,
        )
        .unwrap();
        let firmware = tokio::spawn(async move {
            let mut seen = BTreeSet::new();
            for _ in 0..6 {
                let mut buf = [0; 512];
                let (n, peer) = server.recv_from(&mut buf).await.unwrap();
                let q = &buf[..n];
                let (name, kind) = nfqws2_dns::query_domain(q).unwrap();
                assert!(
                    seen.insert((name.clone(), kind)),
                    "queried a CNAME loop again"
                );
                let wire = match (name.as_str(), kind) {
                    ("raw.office.test", 1) => cname_reply(q, "terminal.archive.test", 12),
                    ("terminal.archive.test", 1) => a_reply(q, 33, 90),
                    ("raw-cycle.office.test", 1) => cname_reply(q, "loop.archive.test", 12),
                    ("loop.archive.test", 1) => cname_reply(q, "raw-cycle.office.test", 12),
                    ("raw.office.test" | "raw-cycle.office.test", 28) => {
                        nfqws2_dns::response_error(q, 3)
                    }
                    _ => panic!("unexpected query in archived CNAME chain"),
                };
                server.send_to(&wire, peer).await.unwrap();
            }
            assert!(
                timeout(Duration::from_millis(50), server.recv_from(&mut [0; 512]))
                    .await
                    .is_err()
            );
        });

        let gate = Arc::new(Gate::new());
        let routes = Arc::new(Observer {
            archive: Some(archive),
            ..Observer::default()
        });
        routes.register(gate.clone());
        routes.schedule_replay(gate.replay_publication().unwrap());
        let job = routes.replay.lock().unwrap().take().unwrap();
        timeout(Duration::from_secs(5), job).await.unwrap().unwrap();
        timeout(Duration::from_secs(5), firmware)
            .await
            .unwrap()
            .unwrap();
        let installs = gate.installs.lock().unwrap();
        assert_eq!(installs.len(), 1);
        let (name, kind, addresses, ttl) = &installs[0];
        assert_eq!(name, "raw.office.test");
        assert_eq!(*kind, 1);
        assert_eq!(addresses, &[IpAddr::from([192, 0, 2, 33])]);
        assert!((8..=12).contains(ttl));
    }

    #[tokio::test]
    async fn managed_archive_follows_cname_via_live_engine_and_filters_alias_targets() {
        use crate::dnsserver::{config, runtime::Diagnostics, shadow, tests::scripted_doh, vpn};
        let dir = tempfile::tempdir().unwrap();
        let firmware = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let archive = fixture(dir.path(), firmware.local_addr().unwrap());
        std::fs::write(
            &archive.legacy,
            br#"{"raw.office.test":[],"raw-blocked.office.test":[]}"#,
        )
        .unwrap();
        let (port, cert, calls, server) = scripted_doh(true, None, |wire, name, kind| {
            *wire = match (name, kind) {
                ("raw.office.test", _) => cname_reply(wire, "terminal.archive.test", 25),
                ("raw-blocked.office.test", _) => cname_reply(wire, "blocked.alias.test", 25),
                ("terminal.archive.test", 1) => a_reply(wire, 34, 100),
                ("terminal.archive.test", 28) => {
                    let mut answer = nfqws2_dns::response_error(wire, 0);
                    answer[7] = 1;
                    answer.extend([192, 12, 0, 28, 0, 1, 0, 0, 0, 100, 0, 16]);
                    answer.extend(
                        "2001:db8::34"
                            .parse::<std::net::Ipv6Addr>()
                            .unwrap()
                            .octets(),
                    );
                    answer
                }
                _ => panic!("managed archive dialed a blocked or unexpected alias"),
            };
        })
        .await;
        let mut raw = config::defaults();
        raw["route_mode"] = serde_json::json!("vpn_only");
        raw["awg_fallback"] = serde_json::json!("main");
        raw["scheduler_enabled"] = serde_json::json!(false);
        raw["fast_dns"] = serde_json::json!(false);
        raw["default_pool"] = serde_json::json!([]);
        raw["rules"] = serde_json::json!([]);
        raw["default_upstream"] = serde_json::json!({"address":format!("https://dns.test:{port}/dns-query"),"bootstrap_ips":["127.0.0.1"]});
        raw["filtering"] = serde_json::json!({"enabled":true,"lists":[],"allowlist":[],"custom_rules":[{"domain":"blocked.alias.test","category":"ads"}]});
        let engine = Engine::new(
            config::Config::from_value(&raw).unwrap(),
            Arc::new(Mutex::new(Diagnostics::new(false))),
            Default::default(),
            shadow::Environment::unavailable(),
            Arc::new(vpn::Source::with(|| {
                Ok(vec![vpn::Route {
                    id: "awg:main".into(),
                    name: "main".into(),
                    interface: String::new(),
                    available: true,
                    index: 0,
                }])
            })),
            Default::default(),
        );
        engine.trust(cert);
        let gate = Arc::new(Gate::new());
        *gate.resolver.lock().unwrap() = ArchiveResolver::managed(engine.clone());
        let routes = Arc::new(Observer {
            archive: Some(archive),
            ..Observer::default()
        });
        routes.register(gate.clone());
        routes.schedule_replay(gate.replay_publication().unwrap());
        let job = routes.replay.lock().unwrap().take().unwrap();
        timeout(Duration::from_secs(5), job).await.unwrap().unwrap();
        {
            let installs = gate.installs.lock().unwrap();
            assert_eq!(installs.len(), 2);
            assert_eq!(installs[0].2, [IpAddr::from([192, 0, 2, 34])]);
            assert_eq!(installs[1].2, ["2001:db8::34".parse::<IpAddr>().unwrap()]);
            assert!(installs
                .iter()
                .all(|(name, _, _, ttl)| name == "raw.office.test" && (20..=25).contains(ttl)));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 6);
        assert_eq!(engine.stats().queries, 0);
        assert_eq!(engine.cache.status().entries, 0);
        assert!(
            timeout(Duration::from_millis(50), firmware.recv_from(&mut [0; 512]))
                .await
                .is_err()
        );
        server.abort();
    }

    #[tokio::test]
    async fn go_dns_archives_resolve_global_names_again_through_firmware() {
        let dir = tempfile::tempdir().unwrap();
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let archive = fixture(dir.path(), server.local_addr().unwrap());
        let old_wire = br#"{
            "RAW.office.test.":["198.51.100.90"], "dup.office.test":["198.51.100.91"],
            "device.office.test":["198.51.100.92"], "catchall.office.test":[], "bad/site.test":[]
        }"#;
        std::fs::write(&archive.legacy, old_wire).unwrap();
        let history = serde_json::json!({"version":1,"entries":[
            {"domain":"journal.office.test","source":"dns","last_seen":30,"ips":["198.51.100.93"],"source_ips":["127.0.0.2"]},
            {"domain":"dup.office.test","source":"sni","last_seen":20,"ips":["198.51.100.94"]},
            {"domain":"device.office.test","source":"dns","last_seen":10,"source_ips":["127.0.0.1"]},
            {"domain":"unknown.office.test","source":"dns","last_seen":1}
        ]});
        archive
            .store
            .transaction(|tx| tx.save(nfqws2_awg_rules::discoveries::FILE, &history))
            .unwrap();

        let firmware = tokio::spawn(async move {
            let mut seen = BTreeSet::new();
            for _ in 0..6 {
                let mut buf = [0; 512];
                let (n, client) = server.recv_from(&mut buf).await.unwrap();
                let (domain, kind) = nfqws2_dns::query_domain(&buf[..n]).unwrap();
                assert!(
                    seen.insert((domain.clone(), kind)),
                    "duplicate archive lookup"
                );
                let octet = match domain.as_str() {
                    "dup.office.test" => 10,
                    "journal.office.test" => 11,
                    "raw.office.test" => 12,
                    _ => panic!("query for name outside the explicit global policy"),
                };
                let reply = if kind == 1 {
                    a_reply(&buf[..n], octet, 47)
                } else if domain == "dup.office.test" {
                    let mut reply = nfqws2_dns::response_error(&buf[..n], 0);
                    reply[7] = 1;
                    reply.extend([192, 12, 0, 28, 0, 1, 0, 0, 0, 37, 0, 16]);
                    reply.extend(
                        "2001:db8::10"
                            .parse::<std::net::Ipv6Addr>()
                            .unwrap()
                            .octets(),
                    );
                    reply
                } else {
                    nfqws2_dns::response_error(&buf[..n], 3)
                };
                server.send_to(&reply, client).await.unwrap();
            }
            assert!(
                timeout(Duration::from_millis(50), server.recv_from(&mut [0; 512]))
                    .await
                    .is_err()
            );
        });

        let archive_path = archive.legacy.clone();
        let store = archive.store.clone();
        let gate = Arc::new(Gate::new());
        let routes = Arc::new(Observer {
            archive: Some(archive),
            ..Observer::default()
        });
        routes.register(gate.clone());
        routes.schedule_restored_replay(gate.replay_publication().unwrap());
        let job = routes.replay.lock().unwrap().take().unwrap();
        timeout(Duration::from_secs(5), job).await.unwrap().unwrap();
        timeout(Duration::from_secs(5), firmware)
            .await
            .unwrap()
            .unwrap();
        let mut installs = gate.installs.lock().unwrap();
        installs.sort_unstable();
        assert_eq!(installs.len(), 4);
        for ((name, kind, ips, ttl), (expected, family, address, maximum)) in installs.iter().zip([
            ("dup.office.test", 1, "192.0.2.10", 47),
            ("dup.office.test", 28, "2001:db8::10", 37),
            ("journal.office.test", 1, "192.0.2.11", 47),
            ("raw.office.test", 1, "192.0.2.12", 47),
        ]) {
            assert_eq!(name, expected);
            assert_eq!(*kind, family);
            assert_eq!(ips, &[address.parse::<IpAddr>().unwrap()]);
            assert!((maximum - 7..=maximum).contains(ttl));
        }
        assert_eq!(std::fs::read(&archive_path).unwrap(), old_wire);
        let saved: serde_json::Value = store.read(nfqws2_awg_rules::discoveries::FILE).unwrap();
        assert_eq!(saved, history);
        assert!(!routes.archive_pending.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn archive_fresh_reply_is_discarded_after_publication_or_resolver_change() {
        for (changed_publication, learned) in
            [(true, false), (false, false), (true, true), (false, true)]
        {
            let dir = tempfile::tempdir().unwrap();
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let archive = fixture(dir.path(), server.local_addr().unwrap());
            if learned {
                let history = serde_json::json!({"version":1,"entries":[
                    {"domain":"raw.office.test","source":"dns","last_seen":30,"rule_key":"old",
                     "ips":["198.51.100.4"]}
                ]});
                archive
                    .store
                    .transaction(|tx| tx.save(nfqws2_awg_rules::discoveries::FILE, &history))
                    .unwrap();
            } else {
                std::fs::write(&archive.legacy, br#"{"raw.office.test":["198.51.100.4"]}"#)
                    .unwrap();
            }
            let gate = Arc::new(Gate::new());
            let routes = Arc::new(Observer {
                archive: Some(archive),
                ..Observer::default()
            });
            routes.register(gate.clone());
            let old = gate.replay_publication().unwrap();
            routes.schedule_replay(old);
            let mut buf = [0; 512];
            let (n, peer) = timeout(Duration::from_secs(2), server.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(nfqws2_dns::query_domain(&buf[..n]).unwrap().1, 1);
            if changed_publication {
                gate.generation.store(2, Ordering::SeqCst);
                assert_eq!(gate.replay_publication().unwrap().revision, old.revision);
            } else {
                gate.allowed.store(false, Ordering::SeqCst);
            }
            server
                .send_to(&a_reply(&buf[..n], 9, 45), peer)
                .await
                .unwrap();
            let job = routes.replay.lock().unwrap().take().unwrap();
            timeout(Duration::from_secs(2), job).await.unwrap().unwrap();
            assert!(gate.installs.lock().unwrap().is_empty());
            assert!(gate.history_installs.lock().unwrap().is_empty());
            assert!(routes.archive_pending.load(Ordering::Relaxed));
            assert!(
                timeout(Duration::from_millis(50), server.recv_from(&mut buf))
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn managed_archive_restarts_with_live_engine_and_rejects_replaced_engine_reply() {
        use crate::dnsserver::{
            config,
            runtime::Diagnostics,
            shadow,
            tests::{controlled_doh, DohGate},
            vpn,
        };

        let dir = tempfile::tempdir().unwrap();
        let firmware = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let archive = fixture(dir.path(), firmware.local_addr().unwrap());
        std::fs::write(&archive.legacy, br#"{"raw.office.test":["198.51.100.45"]}"#).unwrap();
        let upstream_gate = DohGate::new();
        let (port, cert, calls, server) = controlled_doh(true, Some(upstream_gate.clone())).await;
        let engine = || {
            let mut raw = config::defaults();
            raw["route_mode"] = serde_json::json!("auto");
            raw["awg_fallback"] = serde_json::json!("off");
            raw["scheduler_enabled"] = serde_json::json!(false);
            raw["fast_dns"] = serde_json::json!(false);
            raw["default_pool"] = serde_json::json!([]);
            raw["rules"] = serde_json::json!([]);
            raw["default_upstream"] = serde_json::json!({"address":format!("https://dns.test:{port}/dns-query"),"bootstrap_ips":["127.0.0.1"]});
            let engine = Engine::new(
                config::Config::from_value(&raw).unwrap(),
                Arc::new(Mutex::new(Diagnostics::new(false))),
                Default::default(),
                shadow::Environment::unavailable(),
                Arc::new(vpn::Source::with(|| Ok(Vec::new()))),
                Default::default(),
            );
            engine.trust(cert.clone());
            engine
        };

        let gate = Arc::new(Gate::new());
        let routes = Arc::new(Observer {
            archive: Some(archive),
            ..Observer::default()
        });
        routes.register(gate.clone());
        let publication = gate.replay_publication().unwrap();
        gate.allowed.store(false, Ordering::SeqCst);
        routes.schedule_restored_replay(publication);
        assert!(routes.replay.lock().unwrap().is_none());

        let retired = engine();
        *gate.resolver.lock().unwrap() = ArchiveResolver::managed(retired.clone());
        gate.allowed.store(true, Ordering::SeqCst);
        routes.replay_after_resolver_start();
        upstream_gate.next_request().await;
        let old = routes.replay.lock().unwrap().take().unwrap();
        let current = engine();
        *gate.resolver.lock().unwrap() = ArchiveResolver::managed(current.clone());
        upstream_gate.release(1);
        timeout(Duration::from_secs(3), old).await.unwrap().unwrap();
        assert_eq!(gate.replay_publication(), Some(publication));
        assert!(gate.installs.lock().unwrap().is_empty());
        assert!(routes.archive_pending.load(Ordering::Relaxed));

        upstream_gate.release(2);
        routes.replay_after_resolver_start();
        let new = routes.replay.lock().unwrap().take().unwrap();
        timeout(Duration::from_secs(3), new).await.unwrap().unwrap();
        {
            let installs = gate.installs.lock().unwrap();
            assert_eq!(installs.len(), 2);
            assert_eq!(installs[0].2, [IpAddr::from([192, 0, 2, 18])]);
            assert_eq!(installs[1].2, ["2001:db8::18".parse::<IpAddr>().unwrap()]);
            assert!(installs
                .iter()
                .all(|installed| (50..=60).contains(&installed.3)));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(retired.stats().queries + current.stats().queries, 0);
        assert!(
            timeout(Duration::from_millis(50), firmware.recv_from(&mut [0; 512]))
                .await
                .is_err()
        );
        server.abort();
    }
}
