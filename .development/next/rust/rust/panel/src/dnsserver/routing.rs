pub(crate) use nfqws2_awg_rules::kernel::DnsOrigin;
pub(crate) use nfqws2_dns::RouteAnswer;
mod archive;
pub(super) use archive::ManagedRecent;
pub(crate) use archive::{ArchiveResolver, ManagedOriginReceipt};
mod bounded;
mod recent;
use std::{
    collections::VecDeque,
    io,
    net::IpAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, RwLock,
    },
    time::Duration,
};
use tokio::{
    sync::{watch, OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::{timeout_at, Instant},
};

pub(super) async fn revalidate_pending_replacement(
    request: nfqws2_awg_rules::kernel::ActiveReplacementDnsRetry,
    deadline: Instant,
    current: impl Fn() -> bool,
) -> io::Result<nfqws2_awg_rules::kernel::ActiveReplacementDnsRetryProof> {
    use nfqws2_awg_rules::kernel::FirmwareDnsGroupAnswer;
    let mut resolved = Vec::with_capacity(request.names().len());
    let mut expires = deadline;
    for name in request.names() {
        let answer = ArchiveResolver::fresh_firmware_policy_ipv4(name, expires, &current).await?;
        if let archive::FirmwarePolicyLookup::NegativeUntil(until) = &answer {
            expires = expires.min(*until);
        }
        resolved.push(answer);
    }
    let answers: Vec<_> = resolved
        .iter()
        .map(|answer| match answer {
            archive::FirmwarePolicyLookup::Positive(addresses, until) => {
                FirmwareDnsGroupAnswer::FreshAddresses {
                    addresses,
                    valid_until: until.into_std(),
                }
            }
            archive::FirmwarePolicyLookup::Negative
            | archive::FirmwarePolicyLookup::NegativeUntil(_) => FirmwareDnsGroupAnswer::NxDomain,
        })
        .collect();
    request.revalidate(&answers, expires.into_std())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RouteMatch {
    pub revision: u64,
    // Confirming a DNS address can advance revision without replacing policy.
    pub generation: u64,
    pub zone: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RoutePublication {
    pub generation: u64,
    pub revision: u64,
}

pub(crate) struct ActiveDnsRevalidation {
    pub(crate) proof: nfqws2_awg_rules::kernel::ActiveDnsReplacementProof,
    pub(crate) publication: RoutePublication,
    pub(crate) expires: Instant,
}

const FIRMWARE_HINT_LIMIT: usize = 128;
const FIRMWARE_POLICY_HINT_LIFETIME: Duration = Duration::from_secs(20 * 60);

#[derive(Clone)]
struct FirmwareHint {
    query: recent::SourceQuery,
    record: recent::Record,
    policy_expires: Option<Instant>,
}

impl FirmwareHint {
    fn usable_for_refresh(&self, now: Instant) -> bool {
        self.record.expires > now || self.policy_expires.is_some()
    }
}

/// A current, confirmed transparent DNS delivery can suggest a name for a
/// fresh check. This cache is independent of ordinary DNS replay and disk.
#[derive(Default)]
struct FirmwareHints {
    publication: Option<RoutePublication>,
    records: VecDeque<FirmwareHint>,
    dormant: Option<ParkedFirmwareHints>,
}

struct ParkedFirmwareHints {
    stamp: String,
    revision: u64,
    records: VecDeque<FirmwareHint>,
}

impl FirmwareHints {
    fn continue_after_rearm(&mut self, stamp: &str, next: RoutePublication, now: Instant) {
        if self.dormant.as_ref().is_none_or(|parked| {
            parked.stamp != stamp || parked.revision.checked_add(1) != Some(next.revision)
        }) {
            return;
        }
        let parked = self.dormant.take().unwrap();
        if self.publication.is_none_or(|current| current.revision != next.revision) {
            self.records.clear();
        }
        self.records.retain(|hint| hint.usable_for_refresh(now));
        for hint in parked.records {
            if self.records.len() >= FIRMWARE_HINT_LIMIT {
                break;
            }
            if hint.policy_expires.is_some_and(|deadline| deadline > now)
                && self.records.iter().all(|current| current.query != hint.query)
            {
                self.records.push_back(hint);
            }
        }
        self.publication = (!self.records.is_empty()).then_some(next);
    }

    fn has_live(&self, publication: RoutePublication, now: Instant) -> bool {
        self.publication == Some(publication)
            && self
                .records
                .iter()
                .any(|record| record.usable_for_refresh(now))
    }

    fn continue_after_refresh(
        &mut self,
        old: RoutePublication,
        new: RoutePublication,
        now: Instant,
    ) {
        if self.publication != Some(old)
            || old.revision != new.revision
            || old.generation.wrapping_add(1) != new.generation
        {
            return;
        }
        self.records.retain(|record| record.usable_for_refresh(now));
        self.publication = (!self.records.is_empty()).then_some(new);
    }

    fn record(&mut self, publication: RoutePublication, hint: FirmwareHint, now: Instant) {
        if self.publication != Some(publication) {
            self.records.clear();
            self.publication = Some(publication);
        }
        self.records
            .retain(|previous| previous.query != hint.query && previous.usable_for_refresh(now));
        self.records.push_front(hint);
        self.records.truncate(FIRMWARE_HINT_LIMIT);
    }

    fn snapshot(
        &self,
        publication: RoutePublication,
    ) -> Vec<(recent::SourceQuery, recent::Record)> {
        if self.publication != Some(publication) {
            return Vec::new();
        }
        self.records
            .iter()
            .map(|hint| (hint.query.clone(), hint.record.clone()))
            .collect()
    }

    fn policy_snapshot(&self, publication: RoutePublication) -> Vec<FirmwareHint> {
        if self.publication != Some(publication) {
            return Vec::new();
        }
        self.records
            .iter()
            .filter(|hint| hint.policy_expires.is_some())
            .cloned()
            .collect()
    }
}

fn firmware_rrset_hint(
    records: impl IntoIterator<Item = (recent::SourceQuery, recent::Record)>,
    bridges: &[String],
    client: Option<IpAddr>,
    expected: &[IpAddr],
    matches_name: impl Fn(&str) -> io::Result<bool>,
    now: Instant,
) -> io::Result<Option<(recent::SourceQuery, Instant)>> {
    for (query, mut record) in records {
        if query.kind != 1
            || query.client.is_loopback()
            || client.is_some_and(|client| client != query.client)
            || record.managed.is_some()
            || record.expires <= now
            || !query
                .ingress
                .as_ref()
                .is_some_and(|ingress| bridges.contains(ingress))
        {
            continue;
        }
        record.addresses.sort_unstable();
        record.addresses.dedup();
        if record.addresses == expected && matches_name(&query.name)? {
            return Ok(Some((query, record.expires)));
        }
    }
    Ok(None)
}

#[cfg(test)]
#[test]
fn live_firmware_revalidation_uses_only_the_complete_current_lan_scope() {
    let now = Instant::now();
    let expected = [
        "198.18.4.24".parse().unwrap(),
        "198.18.4.55".parse().unwrap(),
    ];
    let entry =
        |name: &str, ingress: Option<&str>, client: &str, addresses: Vec<IpAddr>, expires| {
            (
                recent::SourceQuery {
                    name: name.into(),
                    kind: 1,
                    ingress: ingress.map(str::to_owned),
                    client: client.parse().unwrap(),
                },
                recent::Record {
                    addresses,
                    expires,
                    managed: None,
                },
            )
        };
    let live = now + Duration::from_secs(8);
    let records = [
        entry(
            "expired.example",
            Some("br0"),
            "192.168.1.7",
            expected.to_vec(),
            now,
        ),
        entry(
            "elsewhere.example",
            Some("br1"),
            "192.168.1.7",
            expected.to_vec(),
            live,
        ),
        entry(
            "localhost.example",
            Some("br0"),
            "127.0.0.1",
            expected.to_vec(),
            live,
        ),
        entry(
            "partial.example",
            Some("br0"),
            "192.168.1.7",
            expected[..1].to_vec(),
            live,
        ),
        entry(
            "foreign.invalid",
            Some("br0"),
            "192.168.1.7",
            expected.to_vec(),
            live,
        ),
        entry(
            "known.example",
            Some("br0"),
            "192.168.1.7",
            expected.into_iter().rev().collect(),
            live,
        ),
    ];
    let classify = |name: &str| Ok(name.ends_with(".example"));
    let check = |records| {
        firmware_rrset_hint(records, &["br0".into()], None, &expected, classify, now).unwrap()
    };
    assert!(check(records[..5].to_vec()).is_none());
    assert_eq!(
        check(records.to_vec()).map(|(query, expires)| (query.name, expires)),
        Some(("known.example".into(), live))
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FailedRoute {
    pub epoch: u64,
    pub generation: u64,
}

impl std::fmt::Display for FailedRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("обновляется политика DNS-маршрутизации")
    }
}

impl std::error::Error for FailedRoute {}

#[derive(Debug)]
pub(crate) struct RouteWriterBusy;

impl std::fmt::Display for RouteWriterBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("работает другая операция маршрутизации")
    }
}

impl std::error::Error for RouteWriterBusy {}

pub(crate) enum DeliverySelection {
    Ready(Option<RouteMatch>),
    Pending(watch::Receiver<()>),
}

async fn wait_for_delivery(
    deadline: Instant,
    select: impl Fn() -> io::Result<DeliverySelection>,
) -> io::Result<(Option<RouteMatch>, bool)> {
    let mut waited = false;
    loop {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        match select()? {
            DeliverySelection::Ready(target) => return Ok((target, waited)),
            DeliverySelection::Pending(mut changed) => {
                waited = true;
                timeout_at(deadline, changed.changed())
                    .await
                    .map_err(|_| io::ErrorKind::TimedOut)?
                    .map_err(|_| replaced())?;
            }
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct RedirectEpoch {
    pub replacement: u64,
    pub revision: Option<u64>,
    pub zone: Option<usize>,
    pub suppress_aaaa: bool,
    pub unavailable: bool,
}

pub(super) struct ManagedDelivery {
    pub deadline: Instant,
    pub ttl_anchor: Instant,
    pub recent: Option<ManagedRecent>,
}

pub(crate) struct WarmDnsObservation<'a> {
    pub failure: FailedRoute,
    pub name: &'a str,
    pub query: &'a [u8],
    pub reply: &'a [u8],
    pub anchor: std::time::Instant,
    pub resolver: ManagedOriginReceipt,
    pub source: &'a nfqws2_dns::Source,
}

#[cfg(test)]
impl ManagedDelivery {
    fn test_request() -> Self {
        let now = Instant::now();
        Self {
            deadline: now + Duration::from_secs(8),
            ttl_anchor: now,
            recent: None,
        }
    }
}

pub(super) struct RouteTiming {
    pub deadline: Instant,
    pub waited_from: Option<Instant>,
    pub firmware_received: Option<Instant>,
}

pub(crate) trait RouteObserver: Send + Sync {
    fn capture_warm_transport(&self, _name: &str) -> Option<FailedRoute> {
        None
    }
    fn observe_warm_transport(&self, _observation: WarmDnsObservation<'_>) {}
    /// The query path uses an immutable snapshot. Selecting an unrelated
    /// domain must not read router configuration or start a blocking job.
    fn select(&self, name: &str, client: Option<IpAddr>) -> io::Result<Option<RouteMatch>>;
    fn select_on(&self, name: &str, origin: DnsOrigin<'_>) -> io::Result<Option<RouteMatch>> {
        self.select(name, origin.client)
    }
    fn select_managed_on(
        &self,
        name: &str,
        origin: DnsOrigin<'_>,
    ) -> io::Result<Option<RouteMatch>> {
        self.select_on(name, origin)
    }
    fn select_managed_for_delivery(
        &self,
        name: &str,
        origin: DnsOrigin<'_>,
    ) -> io::Result<DeliverySelection> {
        self.select_managed_on(name, origin)
            .map(DeliverySelection::Ready)
    }
    fn capture_redirect(
        &self,
        name: &str,
        origin: DnsOrigin<'_>,
    ) -> (Option<RedirectEpoch>, io::Result<Option<RouteMatch>>) {
        (None, self.select_on(name, origin))
    }
    fn select_redirect_for_delivery(
        &self,
        name: &str,
        origin: DnsOrigin<'_>,
        _epoch: RedirectEpoch,
    ) -> io::Result<DeliverySelection> {
        self.select_on(name, origin).map(DeliverySelection::Ready)
    }
    fn blocks_aaaa(&self, _target: RouteMatch) -> io::Result<bool> {
        Ok(false)
    }
    /// A short-lived, generation-scoped confirmation can bypass the writer.
    fn cached(
        &self,
        _target: RouteMatch,
        _name: &str,
        _origin: DnsOrigin<'_>,
        _answer: &RouteAnswer,
    ) -> io::Result<Option<bool>> {
        Ok(None)
    }
    /// Revalidate the selection and install its addresses before the reply
    /// is released. Return the NODATA decision and the generation whose
    /// routes the client can now use (a FIB replacement can advance it).
    fn install(
        &self,
        target: RouteMatch,
        name: &str,
        origin: DnsOrigin<'_>,
        answer: &RouteAnswer,
    ) -> io::Result<(bool, u64)>;
    fn replay_publication(&self) -> Option<RoutePublication> {
        None
    }
    fn firmware_hint_publication(
        &self,
        _target: RouteMatch,
        _name: &str,
        _origin: DnsOrigin<'_>,
    ) -> Option<RoutePublication> {
        None
    }
    fn mixed_firmware_policy(&self, _publication: RoutePublication) -> bool {
        false
    }
    fn archive_resolver(&self, _publication: RoutePublication) -> Option<ArchiveResolver> {
        None
    }
    fn failed_reply_current(
        &self,
        _failure: FailedRoute,
        _name: &str,
        _origin: DnsOrigin<'_>,
        _resolver: &ArchiveResolver,
    ) -> bool {
        false
    }
    fn recovered(&self, _publication: RoutePublication, _failure: FailedRoute) -> bool {
        false
    }
    fn replay_target(
        &self,
        _publication: RoutePublication,
        _name: &str,
        _origin: DnsOrigin<'_>,
    ) -> io::Result<Option<RouteMatch>> {
        Ok(None)
    }
    fn install_replayed(
        &self,
        target: RouteMatch,
        name: &str,
        origin: DnsOrigin<'_>,
        answer: &RouteAnswer,
        _resolver: Option<&ArchiveResolver>,
    ) -> io::Result<(bool, u64)> {
        self.install(target, name, origin, answer)
    }
    fn archive_history_matches(
        &self,
        _publication: RoutePublication,
        _name: &str,
        _qtype: u16,
    ) -> io::Result<bool> {
        Ok(false)
    }
    fn install_history(
        &self,
        _publication: RoutePublication,
        _resolver: &ArchiveResolver,
        _name: &str,
        _answer: &RouteAnswer,
    ) -> io::Result<()> {
        Err(replaced())
    }
    fn record_reply(
        &self,
        _name: &str,
        _origin: DnsOrigin<'_>,
        _target: Option<RouteMatch>,
        _reply: &[u8],
        _suppressed: bool,
    ) {
    }
}

pub(super) struct Observer {
    active: RwLock<Option<Arc<dyn RouteObserver>>>,
    writer: Arc<Semaphore>,
    recent: Mutex<recent::Recent>,
    firmware_hints: Mutex<FirmwareHints>,
    replay: Mutex<Option<JoinHandle<()>>>,
    archive: Option<archive::Source>,
    archive_pending: AtomicBool,
}
pub(super) struct Selection<'a> {
    observer: Arc<dyn RouteObserver>,
    origin: DnsOrigin<'a>,
    target: Option<RouteMatch>,
    kind: SelectionKind,
}

#[derive(Clone, Copy)]
enum SelectionKind {
    Managed,
    Routed,
    Redirect(RedirectEpoch),
}

impl Selection<'_> {
    fn current_target(&self, name: &str) -> io::Result<Option<RouteMatch>> {
        match self.kind {
            SelectionKind::Managed => self.observer.select_managed_on(name, self.origin),
            SelectionKind::Routed => self.observer.select_on(name, self.origin),
            SelectionKind::Redirect(epoch) => {
                match self
                    .observer
                    .select_redirect_for_delivery(name, self.origin, epoch)?
                {
                    DeliverySelection::Ready(target) => Ok(target),
                    DeliverySelection::Pending(_) => Err(replaced()),
                }
            }
        }
    }
}

pub(super) struct RedirectQuery<'a> {
    observer: Arc<dyn RouteObserver>,
    origin: DnsOrigin<'a>,
    epoch: Option<RedirectEpoch>,
    initial: io::Result<Option<RouteMatch>>,
}

impl<'a> RedirectQuery<'a> {
    pub(super) async fn before_firmware_aaaa(
        &self,
        name: &str,
        deadline: Instant,
    ) -> io::Result<Option<Selection<'a>>> {
        match self.epoch {
            Some(epoch) if epoch.suppress_aaaa => self
                .select_for_epoch(name, deadline, epoch)
                .await
                .map(|(selection, _)| Some(selection)),
            Some(_) => Ok(None),
            None => Ok(self.initial.as_ref().ok().map(|target| Selection {
                observer: self.observer.clone(),
                origin: self.origin,
                target: *target,
                kind: SelectionKind::Routed,
            })),
        }
    }

    async fn select_for_epoch(
        &self,
        name: &str,
        deadline: Instant,
        epoch: RedirectEpoch,
    ) -> io::Result<(Selection<'a>, bool)> {
        let (target, waited) = wait_for_delivery(deadline, || {
            self.observer
                .select_redirect_for_delivery(name, self.origin, epoch)
        })
        .await?;
        Ok((
            Selection {
                observer: self.observer.clone(),
                origin: self.origin,
                target,
                kind: SelectionKind::Redirect(epoch),
            },
            waited,
        ))
    }

    pub(super) async fn after_firmware(
        self,
        name: &str,
        deadline: Instant,
    ) -> io::Result<(Selection<'a>, bool)> {
        if let Some(epoch) = self.epoch {
            return self.select_for_epoch(name, deadline, epoch).await;
        }
        Ok((
            Selection {
                observer: self.observer,
                origin: self.origin,
                target: self.initial?,
                kind: SelectionKind::Routed,
            },
            false,
        ))
    }
}

#[derive(Clone, Copy)]
enum Confirmation<'a> {
    Query {
        deadline: Instant,
        expires: Option<Instant>,
    },
    Replay {
        publication: RoutePublication,
        deadline: Instant,
        expires: Instant,
        resolver: Option<&'a ArchiveResolver>,
    },
}

struct ArchiveConfirmation<'a> {
    publication: RoutePublication,
    deadline: Instant,
    expires: Instant,
    resolver: &'a ArchiveResolver,
}

impl Default for Observer {
    fn default() -> Self {
        Self {
            active: Default::default(),
            writer: Arc::new(Semaphore::new(1)),
            recent: Default::default(),
            firmware_hints: Default::default(),
            replay: Default::default(),
            archive: None,
            archive_pending: AtomicBool::new(true),
        }
    }
}
impl Observer {
    pub(super) fn capture_warm_transport(&self, name: &str) -> Option<FailedRoute> {
        self.observer().ok().flatten()?.capture_warm_transport(name)
    }

    pub(super) fn observe_warm_transport(&self, observation: WarmDnsObservation<'_>) {
        if let Ok(Some(observer)) = self.observer() {
            observer.observe_warm_transport(observation);
        }
    }
    pub(super) fn restore_firmware_hints(&self, stamp: &str, publication: RoutePublication) {
        if let Ok(mut hints) = self.firmware_hints.lock() {
            hints.continue_after_rearm(stamp, publication, Instant::now());
        }
    }

    pub(super) fn park_firmware_hints(&self, old: RoutePublication, stamp: &str) {
        if let Ok(mut hints) = self.firmware_hints.lock() {
            if hints.publication == Some(old) {
                hints.dormant = Some(ParkedFirmwareHints {
                    stamp: stamp.to_owned(),
                    revision: old.revision,
                    records: std::mem::take(&mut hints.records),
                });
                hints.publication = None;
            }
        }
    }

    pub(super) fn dormant_firmware_hints(
        &self,
        request: &nfqws2_awg_rules::kernel::DormantFirmwareDns,
    ) -> io::Result<Option<nfqws2_awg_rules::kernel::DormantFirmwareProof>> {
        use nfqws2_awg_rules::kernel::DormantFirmwareAnswer;
        let (stamp, previous_revision) = request.transfer_stamp();
        let hints = self.firmware_hints.lock().map_err(|_| io::ErrorKind::WouldBlock)?;
        let Some(parked) = hints.dormant.as_ref()
            .filter(|old| old.stamp == stamp && old.revision == previous_revision) else {
            return Ok(None);
        };
        let eligible = parked.records.iter().filter_map(|hint| {
            let query = &hint.query;
            if query.kind != 1 || query.client.is_loopback() || hint.record.managed.is_some() {
                return None;
            }
            Some(DormantFirmwareAnswer {
                name: &query.name,
                client: query.client,
                ingress: query.ingress.as_deref()?,
                addresses: &hint.record.addresses,
                until: hint.policy_expires?.into_std(),
            })
        });
        Ok(Some(request.previous_answers(eligible)))
    }

    pub(super) fn has_live_firmware_hints(&self, publication: RoutePublication) -> bool {
        self.firmware_hints
            .try_lock()
            .is_ok_and(|hints| hints.has_live(publication, Instant::now()))
    }

    pub(super) fn continue_firmware_hints(&self, old: RoutePublication, new: RoutePublication) {
        if let Ok(mut hints) = self.firmware_hints.try_lock() {
            hints.continue_after_refresh(old, new, Instant::now());
        }
    }
    pub(super) fn open(
        store: &nfqws2_store::Store,
        root: &std::path::Path,
        history: Arc<nfqws2_awg_rules::discoveries::Recent>,
    ) -> Self {
        Self {
            recent: Mutex::new(recent::Recent::open(store, root)),
            archive: Some(archive::Source::new(store, root, history)),
            ..Self::default()
        }
    }

    pub(super) fn flush_recent(&self, store: &nfqws2_store::Store) -> io::Result<()> {
        recent::Recent::flush(&self.recent, store)
    }

    pub(super) fn register(&self, observer: Arc<dyn RouteObserver>) {
        *self.active.write().unwrap() = Some(observer);
    }

    pub(super) fn schedule_replay(self: &Arc<Self>, publication: RoutePublication) {
        self.replay_after_publication(publication, false);
    }

    pub(super) fn schedule_restored_replay(self: &Arc<Self>, publication: RoutePublication) {
        self.replay_after_publication(publication, true);
    }

    #[cfg(test)]
    pub(super) async fn finish_replay_for_test(&self) {
        let job = self
            .replay
            .lock()
            .unwrap()
            .take()
            .expect("scheduled replay");
        timeout_at(Instant::now() + Duration::from_secs(5), job)
            .await
            .unwrap()
            .unwrap();
    }

    pub(super) fn replay_after_resolver_start(self: &Arc<Self>) {
        if let Ok(Some(observer)) = self.observer() {
            if let Some(publication) = observer.replay_publication() {
                self.schedule_restored_replay(publication);
            }
        }
    }

    fn replay_after_publication(
        self: &Arc<Self>,
        publication: RoutePublication,
        restored_only: bool,
    ) {
        let Ok(mut slot) = self.replay.lock() else {
            return;
        };
        let Ok(Some(observer)) = self.observer() else {
            return;
        };
        // A delayed dispatch must never displace the newest publication.
        if observer.replay_publication() != Some(publication) {
            return;
        }
        let (scoped, failed_only) = if restored_only {
            let Ok(recent) = self.recent.lock() else {
                return;
            };
            let restored = recent.has_restored();
            (
                restored || recent.has_failed_replies(Instant::now()),
                !restored,
            )
        } else {
            (true, false)
        };
        let archive = self
            .archive
            .as_ref()
            .filter(|_| !restored_only || self.archive_pending.load(Ordering::Relaxed))
            .and_then(|archive| {
                observer
                    .archive_resolver(publication)
                    .map(|resolver| (archive.clone(), resolver))
            });
        if !scoped && archive.is_none() {
            return;
        }
        if let Some(previous) = slot.take() {
            previous.abort();
        }
        let weak = Arc::downgrade(self);
        *slot = Some(tokio::spawn(async move {
            if let Some(routes) = weak.upgrade() {
                if scoped {
                    routes
                        .replay_recent(&observer, publication, failed_only)
                        .await;
                    if observer.replay_publication() == Some(publication) {
                        if let Ok(mut recent) = routes.recent.lock() {
                            recent.finish_restored();
                        }
                    }
                }
                if let Some((archive, resolver)) = archive {
                    if archive
                        .warm_up(&routes, &observer, publication, &resolver)
                        .await
                        && resolver.current(observer.as_ref(), publication)
                    {
                        routes.archive_pending.store(false, Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    pub(super) async fn revalidate_active_replacement(
        &self,
        request: nfqws2_awg_rules::kernel::ActiveDnsReplacement,
        publication: RoutePublication,
        deadline: Instant,
    ) -> io::Result<ActiveDnsRevalidation> {
        let observer = self.observer()?.ok_or(io::ErrorKind::WouldBlock)?;
        let current = || observer.replay_publication() == Some(publication);
        if !current() || publication.revision != request.revision() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        if request.firmware_groups().is_some() {
            return self
                .revalidate_firmware_groups(request, publication, deadline, current)
                .await;
        }
        let expected = request.addresses();
        let select = |records| {
            firmware_rrset_hint(
                records,
                request.bridges(),
                request.client(),
                &expected,
                |name| request.matches_name(name),
                Instant::now(),
            )
        };
        let matched = self
            .firmware_hints
            .lock()
            .map_err(|_| io::ErrorKind::WouldBlock)?
            .snapshot(publication);
        let hint = if let Some(hint) = select(matched)? {
            Some(hint)
        } else if request.client().is_none() {
            let records = {
                let mut recent = self.recent.lock().map_err(|_| io::ErrorKind::WouldBlock)?;
                if recent.has_restored() {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                recent.snapshot(Instant::now())
            };
            select(records)?
        } else {
            None
        };
        let (query, source_expires) = hint
            .ok_or_else(|| io::Error::other("нет полного действующего DNS-ответа активной зоны"))?;
        let Some((answer, response_expires)) = ArchiveResolver::fresh_firmware_ipv4(
            &query.name,
            deadline.min(source_expires),
            current,
        )
        .await?
        else {
            return Err(io::Error::other(
                "не получено свежее DNS-подтверждение зоны",
            ));
        };
        let expires = source_expires.min(response_expires);
        let ttl = expires.saturating_duration_since(Instant::now()).as_secs();
        if !current() || ttl == 0 {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let proof = request.revalidate_from(
            &query.name,
            &answer.addresses,
            u32::try_from(ttl).unwrap_or(u32::MAX),
            DnsOrigin {
                client: Some(query.client),
                ingress: query.ingress.as_deref(),
            },
        )?;
        Ok(ActiveDnsRevalidation {
            proof,
            publication,
            expires,
        })
    }

    async fn revalidate_firmware_groups(
        &self,
        request: nfqws2_awg_rules::kernel::ActiveDnsReplacement,
        publication: RoutePublication,
        deadline: Instant,
        current: impl Fn() -> bool,
    ) -> io::Result<ActiveDnsRevalidation> {
        use nfqws2_awg_rules::kernel::{FirmwareDnsGroupAnswer, FirmwareDnsGroupProof};
        use std::collections::{BTreeMap, BTreeSet};
        enum ResultSet<'a> {
            Warm(&'a [IpAddr]),
            Cold(Vec<IpAddr>, std::time::Instant),
            NxDomain,
        }
        struct SelectedGroup<'a> {
            zone: usize,
            name: String,
            client: Option<IpAddr>,
            ingress: Option<String>,
            answer: ResultSet<'a>,
        }
        let hints = self
            .firmware_hints
            .lock()
            .map_err(|_| io::ErrorKind::WouldBlock)?
            .policy_snapshot(publication);
        let mut selected = Vec::new();
        let mut firmware_archive = None;
        let mut expires = deadline;
        for group in request
            .firmware_groups()
            .ok_or(io::ErrorKind::InvalidInput)?
        {
            let mut witness = None;
            let mut warm = BTreeMap::new();
            let mut seen = BTreeSet::new();
            let mut union = BTreeSet::new();
            let now = Instant::now();
            for hint in &hints {
                if group
                    .client
                    .is_some_and(|client| hint.query.client != client)
                    || !hint
                        .query
                        .ingress
                        .as_ref()
                        .is_some_and(|bridge| request.bridges().contains(bridge))
                    || !request.matches_firmware_group(group.zone, &hint.query.name)?
                    || !seen.insert(hint.query.name.as_str())
                {
                    continue;
                }
                let addresses: BTreeSet<_> = hint.record.addresses.iter().copied().collect();
                if witness.is_none()
                    && addresses
                        .iter()
                        .copied()
                        .eq(group.addresses.iter().copied())
                {
                    witness = Some(hint);
                }
                let Some(until) = hint.policy_expires.filter(|until| *until > now) else {
                    continue;
                };
                if !addresses.is_empty()
                    && addresses
                        .iter()
                        .all(|ip| group.addresses.binary_search(ip).is_ok())
                {
                    union.extend(addresses);
                    warm.insert(hint.query.name.as_str(), (hint, until));
                }
            }
            if union.into_iter().eq(group.addresses.iter().copied()) {
                for (name, (hint, until)) in warm {
                    expires = expires.min(until);
                    selected.push(SelectedGroup {
                        zone: group.zone,
                        name: name.to_owned(),
                        client: Some(hint.query.client),
                        ingress: hint.query.ingress.clone(),
                        answer: ResultSet::Warm(&hint.record.addresses),
                    });
                }
                continue;
            }
            let configured = request.configured_firmware_names(group.zone)?;
            let archived = if configured.is_none() && request.held_profile().is_none() {
                if let (None, Some(source)) = (&firmware_archive, self.archive.as_ref()) {
                    let source = source.clone();
                    firmware_archive = Some(
                        timeout_at(
                            expires,
                            tokio::task::spawn_blocking(move || source.firmware_archive()),
                        )
                        .await
                        .map_err(|_| io::ErrorKind::TimedOut)?
                        .map_err(io::Error::other)??,
                    );
                }
                firmware_archive
                    .as_ref()
                    .map(|archive| request.archived_firmware_names(group.zone, archive))
                    .transpose()?
                    .flatten()
            } else {
                None
            };
            // Fresh queries for an identified group come from the local
            // resolver. An observed wildcard answer keeps its actual ingress.
            let (names, client, ingress) = if let Some(names) = configured.or(archived) {
                (names, group.client, None)
            } else if let Some(hint) = witness {
                ([hint.query.name.clone()].into(), Some(hint.query.client), hint.query.ingress.clone())
            } else {
                return Err(io::ErrorKind::WouldBlock.into());
            };
            for name in names {
                let answer =
                    match ArchiveResolver::fresh_firmware_policy_ipv4(&name, expires, &current)
                        .await?
                    {
                        archive::FirmwarePolicyLookup::Positive(addresses, fresh_until) => {
                            expires = expires.min(fresh_until);
                            ResultSet::Cold(addresses, fresh_until.into_std())
                        }
                        archive::FirmwarePolicyLookup::Negative => ResultSet::NxDomain,
                        archive::FirmwarePolicyLookup::NegativeUntil(until) => {
                            expires = expires.min(until);
                            ResultSet::NxDomain
                        }
                    };
                selected.push(SelectedGroup {
                    zone: group.zone,
                    name,
                    client,
                    ingress: ingress.clone(),
                    answer,
                });
            }
        }
        if !current() || expires <= Instant::now() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let proofs = selected
            .iter()
            .map(|group| FirmwareDnsGroupProof {
                zone: group.zone,
                name: &group.name,
                origin: DnsOrigin {
                    client: group.client,
                    ingress: group.ingress.as_deref(),
                },
                answer: match &group.answer {
                    ResultSet::Warm(addresses) => FirmwareDnsGroupAnswer::Addresses(addresses),
                    ResultSet::Cold(addresses, valid_until) => {
                        FirmwareDnsGroupAnswer::FreshAddresses {
                            addresses,
                            valid_until: *valid_until,
                        }
                    }
                    ResultSet::NxDomain => FirmwareDnsGroupAnswer::NxDomain,
                },
            })
            .collect::<Vec<_>>();
        Ok(ActiveDnsRevalidation {
            proof: request
                .revalidate_firmware_groups_with_archive(&proofs, firmware_archive.as_ref())?,
            publication,
            expires,
        })
    }

    async fn replay_recent(
        &self,
        observer: &Arc<dyn RouteObserver>,
        publication: RoutePublication,
        failed_only: bool,
    ) {
        const BATCH_SIZE: usize = 32;
        let records = {
            let Ok(mut recent) = self.recent.lock() else {
                return;
            };
            recent.snapshot(Instant::now())
        };
        for (index, (query, record)) in records.into_iter().enumerate() {
            if index != 0 && index % BATCH_SIZE == 0 {
                tokio::task::yield_now().await;
            }
            let now = Instant::now();
            if record.expires <= now {
                break; // The snapshot is ordered by descending expiry.
            }
            let failure = record.failure();
            if failed_only && failure.is_none()
                || failure.is_some_and(|failed| !observer.recovered(publication, failed))
            {
                continue;
            }
            let retire = || {
                if let Some(failed) =
                    failure.filter(|&failed| observer.recovered(publication, failed))
                {
                    if let Ok(mut recent) = self.recent.lock() {
                        recent.retire_failed(&query, failed, record.expires);
                    }
                }
            };
            let resolver = match record.managed {
                None => None,
                Some(receipt) => {
                    let Some(resolver) = receipt
                        .resolver()
                        .filter(|resolver| resolver.current(observer.as_ref(), publication))
                    else {
                        retire();
                        continue;
                    };
                    Some(resolver)
                }
            };
            let origin = query.origin();
            let Ok(target) = observer.replay_target(publication, &query.name, origin) else {
                break;
            };
            let Some(target) = target else {
                retire();
                continue;
            };
            let selection = Selection {
                observer: observer.clone(),
                origin,
                target: Some(target),
                kind: SelectionKind::Routed,
            };
            let result = self
                .confirm(
                    &selection,
                    target,
                    &query.name,
                    RouteAnswer {
                        qtype: query.kind,
                        addresses: record.addresses,
                        ttl: 0,
                    },
                    Confirmation::Replay {
                        publication,
                        deadline: now + Duration::from_secs(4),
                        expires: record.expires,
                        resolver: resolver.as_ref(),
                    },
                )
                .await;
            if result.is_ok() {
                retire();
            }
        }
    }
    fn observer(&self) -> io::Result<Option<Arc<dyn RouteObserver>>> {
        self.active
            .read()
            .map(|slot| slot.clone())
            .map_err(|_| io::Error::other("состояние маршрутизации DNS недоступно"))
    }
    pub(super) fn capture_redirect<'a>(
        &self,
        name: &str,
        origin: DnsOrigin<'a>,
    ) -> io::Result<Option<RedirectQuery<'a>>> {
        let Some(observer) = self.observer()? else {
            return Ok(None);
        };
        let (epoch, initial) = observer.capture_redirect(name, origin);
        Ok(Some(RedirectQuery {
            observer,
            origin,
            epoch,
            initial,
        }))
    }

    async fn select_managed<'a>(
        &self,
        name: &str,
        origin: DnsOrigin<'a>,
        deadline: Instant,
    ) -> io::Result<(Option<Selection<'a>>, bool)> {
        let Some(observer) = self.observer()? else {
            return Ok((None, false));
        };
        let (target, waited) = wait_for_delivery(deadline, || {
            observer.select_managed_for_delivery(name, origin)
        })
        .await?;
        Ok((
            Some(Selection {
                observer,
                origin,
                target,
                kind: SelectionKind::Managed,
            }),
            waited,
        ))
    }
    pub(super) async fn suppress_aaaa(
        &self,
        selection: Option<&Selection<'_>>,
        name: &str,
        query: &[u8],
        deadline: Instant,
    ) -> io::Result<Option<Vec<u8>>> {
        let Some(
            selection @ Selection {
                observer,
                target: Some(target),
                ..
            },
        ) = selection
        else {
            return Ok(None);
        };
        if !observer.blocks_aaaa(*target)? {
            return Ok(None);
        }
        let answer = RouteAnswer {
            qtype: 28,
            addresses: Vec::new(),
            ttl: 0,
        };
        // Confirm the current policy and target before returning a locally
        // synthesized answer. Suppression from an older generation is stale.
        let (nodata, target) = self
            .confirm(
                selection,
                *target,
                name,
                answer,
                Confirmation::Query {
                    deadline,
                    expires: None,
                },
            )
            .await?;
        if !nodata {
            return Ok(None);
        }
        let reply = nfqws2_dns::response_error(query, 0);
        observer.record_reply(name, selection.origin, Some(target), &reply, true);
        Ok(Some(reply))
    }
    pub(super) async fn prepare(
        &self,
        name: &str,
        client: Option<IpAddr>,
        query: &[u8],
        reply: &mut Vec<u8>,
        delivery: ManagedDelivery,
    ) -> io::Result<()> {
        let origin = DnsOrigin {
            client,
            ingress: None,
        };
        let managed = delivery.recent.map(|recent| (recent, delivery.ttl_anchor));
        let (selection, waited) = match self.select_managed(name, origin, delivery.deadline).await {
            Ok(selection) => selection,
            Err(error) => {
                if let Some(managed) = managed {
                    self.remember_failed_reply(name, origin, reply, &error, managed);
                }
                return Err(error);
            }
        };
        let timing = RouteTiming {
            deadline: delivery.deadline,
            waited_from: waited.then_some(delivery.ttl_anchor),
            firmware_received: None,
        };
        self.prepare_selected(selection, name, query, reply, timing, managed)
            .await
    }

    fn remember_failed_reply(
        &self,
        name: &str,
        origin: DnsOrigin<'_>,
        reply: &[u8],
        error: &io::Error,
        (mut receipt, anchor): (ManagedRecent, Instant),
    ) {
        let Some(&failure) = error
            .get_ref()
            .and_then(|reason| reason.downcast_ref::<FailedRoute>())
        else {
            return;
        };
        let Ok(Some(observer)) = self.observer() else {
            return;
        };
        let Some(resolver) = receipt.resolver() else {
            return;
        };
        let Ok(Some(answer)) = nfqws2_dns::route_answer(reply) else {
            return;
        };
        if !observer.failed_reply_current(failure, name, origin, &resolver) {
            return;
        }
        receipt.failure = Some(failure);
        if let Ok(mut recent) = self.recent.try_lock() {
            // Empty, negative or expired replies can retire an earlier
            // positive for this peer and family, never seed an address.
            recent.observe_from(name, origin, answer, anchor, Some(receipt));
        }
    }
    pub(super) async fn prepare_selected(
        &self,
        selection: Option<Selection<'_>>,
        name: &str,
        query: &[u8],
        reply: &mut Vec<u8>,
        timing: RouteTiming,
        managed: Option<(ManagedRecent, Instant)>,
    ) -> io::Result<()> {
        if Instant::now() >= timing.deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let Some(selection) = selection else {
            if self.observer()?.is_some() {
                return Err(replaced());
            }
            return Ok(());
        };
        let observer = &selection.observer;
        let current = self.current(&selection, name)?;
        match (selection.target, current) {
            (Some(target), Some(current))
                if target.zone == current.zone && target.generation == current.generation => {}
            (None, None) => (),
            _ => return Err(replaced()),
        }
        let target = current;
        if reply.get(2).is_some_and(|flags| flags & 2 != 0) {
            return Ok(());
        }
        let Some(target) = target else {
            if !matches!(selection.kind, SelectionKind::Managed) || managed.is_some() {
                if let Ok(Some(answer)) = nfqws2_dns::route_answer(reply) {
                    if let Ok(mut recent) = self.recent.try_lock() {
                        if let Some((receipt, anchor)) = managed {
                            recent.observe_from(
                                name,
                                selection.origin,
                                answer,
                                anchor,
                                Some(receipt),
                            );
                        } else {
                            recent.observe(
                                name,
                                selection.origin,
                                answer,
                                timing.waited_from.unwrap_or_else(Instant::now),
                            );
                        }
                    }
                }
            }
            observer.record_reply(name, selection.origin, None, reply, false);
            return Ok(());
        };
        let Some(mut answer) = nfqws2_dns::route_answer(reply)? else {
            observer.record_reply(name, selection.origin, Some(target), reply, false);
            return Ok(());
        };
        // A signed HTTPS/SVCB RRset has to be withheld whole. Inspect every
        // answer hint for this decision, but only learn reachable addresses.
        let suppress_hints = matches!(answer.qtype, 64 | 65)
            && observer.blocks_aaaa(target)?
            && nfqws2_dns::trace_answer(reply)?
                .addresses
                .iter()
                .any(IpAddr::is_ipv6);
        if suppress_hints {
            answer.addresses.clear();
            answer.ttl = 0;
        }
        let ttl = (!answer.addresses.is_empty()).then_some(answer.ttl);
        let expires = timing
            .waited_from
            .zip(ttl)
            .map(|(anchor, ttl)| anchor + Duration::from_secs(ttl.into()));
        if let Some(expires) = expires {
            answer.ttl = remaining_ttl(expires)?;
        }
        let (nodata, target) = self
            .confirm(
                &selection,
                target,
                name,
                answer,
                Confirmation::Query {
                    deadline: timing.deadline,
                    expires,
                },
            )
            .await?;
        let nodata = nodata || suppress_hints;
        if nodata {
            *reply = nfqws2_dns::response_error(query, 0);
        } else if let Some(ttl) = ttl {
            let ttl = expires.map(remaining_ttl).transpose()?.unwrap_or(ttl);
            nfqws2_dns::cap_ttls(reply, ttl)?;
        }
        if !nodata {
            if let Some((received, ttl)) = timing.firmware_received.zip(ttl) {
                let expires = received + Duration::from_secs(ttl.into());
                self.remember_firmware_hint(&selection, target, name, reply, expires, received);
            }
        }
        observer.record_reply(name, selection.origin, Some(target), reply, nodata);
        Ok(())
    }

    fn remember_firmware_hint(
        &self,
        selection: &Selection<'_>,
        target: RouteMatch,
        name: &str,
        reply: &[u8],
        expires: Instant,
        received: Instant,
    ) {
        let origin = selection.origin;
        let now = Instant::now();
        let (Some(client), Some(bridge)) = (origin.client, origin.ingress) else {
            return;
        };
        let client = client.to_canonical();
        if !matches!(selection.kind, SelectionKind::Redirect(_))
            || client.is_loopback()
            || expires <= now
        {
            return;
        }
        let Ok(Some(answer)) = nfqws2_dns::route_answer(reply) else {
            return;
        };
        if answer.qtype != 1
            || answer.ttl == 0
            || answer.addresses.is_empty()
            || answer.addresses.len() > 128
        {
            return;
        }
        let observer = &selection.observer;
        let Some(publication) = observer.firmware_hint_publication(target, name, origin) else {
            return;
        };
        if let Ok(mut hints) = self.firmware_hints.try_lock() {
            if observer.replay_publication() == Some(publication) {
                hints.record(
                    publication,
                    FirmwareHint {
                        query: recent::SourceQuery {
                            name: name.to_owned(),
                            client,
                            ingress: Some(bridge.to_owned()),
                            kind: 1,
                        },
                        record: recent::Record {
                            addresses: answer.addresses,
                            expires,
                            managed: None,
                        },
                        policy_expires: observer
                            .mixed_firmware_policy(publication)
                            .then_some(received + FIRMWARE_POLICY_HINT_LIFETIME),
                    },
                    now,
                );
            }
        }
    }
    fn current(&self, selection: &Selection<'_>, name: &str) -> io::Result<Option<RouteMatch>> {
        let slot = self
            .active
            .read()
            .map_err(|_| io::Error::other("состояние маршрутизации DNS недоступно"))?;
        if !slot
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, &selection.observer))
        {
            return Err(replaced());
        }
        selection.current_target(name)
    }
    async fn acquire_writer(&self, deadline: Instant) -> io::Result<OwnedSemaphorePermit> {
        // An async wait avoids a blocking thread for each simultaneous query.
        let limit = Instant::now() + Duration::from_secs(8);
        timeout_at(deadline.min(limit), self.writer.clone().acquire_owned())
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
            .map_err(io::Error::other)
    }

    async fn execute_write<T: Send + 'static>(
        permit: OwnedSemaphorePermit,
        deadline: Instant,
        write: impl FnOnce() -> io::Result<T> + Send + 'static,
    ) -> io::Result<T> {
        let mut job = tokio::task::spawn_blocking(move || {
            // An in-progress transaction retains the writer slot until it completes.
            let _permit = permit;
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            write()
        });
        let result = match timeout_at(deadline, &mut job).await {
            Ok(result) => result,
            Err(_) => {
                job.abort();
                return Err(io::ErrorKind::TimedOut.into());
            }
        };
        result.map_err(io::Error::other)?
    }

    async fn confirm_history(
        &self,
        observer: &Arc<dyn RouteObserver>,
        name: &str,
        mut answer: RouteAnswer,
        replay: ArchiveConfirmation<'_>,
    ) -> io::Result<()> {
        let deadline = replay.deadline.min(replay.expires);
        let permit = self.acquire_writer(deadline).await?;
        if self
            .observer()?
            .is_none_or(|active| !Arc::ptr_eq(&active, observer))
            || !replay
                .resolver
                .current(observer.as_ref(), replay.publication)
            || !observer.archive_history_matches(replay.publication, name, answer.qtype)?
        {
            return Err(replaced());
        }
        let worker = observer.clone();
        let name = name.to_owned();
        let resolver = replay.resolver.clone();
        let publication = replay.publication;
        let expires = replay.expires;
        Self::execute_write(permit, deadline, move || {
            answer.ttl = remaining_ttl(expires)?;
            worker.install_history(publication, &resolver, &name, &answer)
        })
        .await
    }

    async fn confirm(
        &self,
        selection: &Selection<'_>,
        target: RouteMatch,
        name: &str,
        mut answer: RouteAnswer,
        confirmation: Confirmation<'_>,
    ) -> io::Result<(bool, RouteMatch)> {
        let observer = &selection.observer;
        let (deadline, expires) = match confirmation {
            Confirmation::Query { deadline, expires } => {
                (expires.map_or(deadline, |at| deadline.min(at)), expires)
            }
            Confirmation::Replay {
                deadline, expires, ..
            } => (deadline.min(expires), Some(expires)),
        };
        let cached = || match confirmation {
            Confirmation::Query { .. } => observer.cached(target, name, selection.origin, &answer),
            Confirmation::Replay { .. } => Ok(None),
        };
        let (nodata, revision) = if let Some(cached) = cached()? {
            (cached, target.revision)
        } else {
            let permit = self.acquire_writer(deadline).await?;
            let target = if let Confirmation::Replay {
                publication,
                resolver,
                ..
            } = confirmation
            {
                if self
                    .observer()?
                    .is_none_or(|active| !Arc::ptr_eq(&active, observer))
                {
                    return Err(replaced());
                }
                if resolver
                    .is_some_and(|resolver| !resolver.current(observer.as_ref(), publication))
                {
                    return Err(replaced());
                }
                observer
                    .replay_target(publication, name, selection.origin)?
                    .filter(|current| {
                        current.generation == target.generation && current.zone == target.zone
                    })
                    .ok_or_else(replaced)?
            } else {
                target
            };
            if let Some(cached) = cached()? {
                (cached, target.revision)
            } else {
                let host = name.to_owned();
                let worker = observer.clone();
                let client = selection.origin.client;
                let ingress = selection.origin.ingress.map(str::to_owned);
                let redirected = matches!(selection.kind, SelectionKind::Redirect(_));
                let replay = match confirmation {
                    Confirmation::Query { .. } => None,
                    Confirmation::Replay { resolver, .. } => Some(resolver.cloned()),
                };
                Self::execute_write(permit, deadline, move || {
                    let origin = DnsOrigin {
                        client,
                        ingress: ingress.as_deref(),
                    };
                    loop {
                        if Instant::now() >= deadline {
                            return Err(io::ErrorKind::TimedOut.into());
                        }
                        if let Some(expires) = expires {
                            answer.ttl = remaining_ttl(expires)?;
                        }
                        let result = match &replay {
                            None => worker.install(target, &host, origin, &answer),
                            Some(resolver) => worker.install_replayed(
                                target,
                                &host,
                                origin,
                                &answer,
                                resolver.as_ref(),
                            ),
                        };
                        if !redirected
                            || !result.as_ref().is_err_and(|error| {
                                error
                                    .get_ref()
                                    .is_some_and(|cause| cause.is::<RouteWriterBusy>())
                            })
                        {
                            return result;
                        }
                        // A publication can wake the redirected query just
                        // before the operation lets go of the kernel writer.
                        std::thread::sleep(
                            Duration::from_millis(2)
                                .min(deadline.saturating_duration_since(Instant::now())),
                        );
                    }
                })
                .await?
            }
        };
        let target = RouteMatch { revision, ..target };
        if self.current(selection, name)? != Some(target) {
            return Err(replaced());
        }
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok((nodata, target))
    }
}

fn remaining_ttl(expires: Instant) -> io::Result<u32> {
    let seconds = expires.saturating_duration_since(Instant::now()).as_secs() as u32;
    (seconds != 0)
        .then_some(seconds)
        .ok_or_else(|| io::ErrorKind::TimedOut.into())
}

fn replaced() -> io::Error {
    io::Error::other("политика DNS изменилась до передачи ответа")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Default)]
    struct LiveFirmwareHintGate {
        generation: AtomicU64,
        installed: Mutex<Vec<Instant>>,
        mixed: std::sync::atomic::AtomicBool,
    }

    impl RouteObserver for LiveFirmwareHintGate {
        fn select(&self, _: &str, _: Option<IpAddr>) -> io::Result<Option<RouteMatch>> {
            Ok(Some(RouteMatch {
                revision: 3,
                generation: self.generation.load(Ordering::SeqCst),
                zone: 0,
            }))
        }

        fn capture_redirect(
            &self,
            name: &str,
            origin: DnsOrigin<'_>,
        ) -> (Option<RedirectEpoch>, io::Result<Option<RouteMatch>>) {
            (
                Some(RedirectEpoch {
                    replacement: 3,
                    revision: Some(4),
                    zone: Some(0),
                    suppress_aaaa: false,
                    unavailable: false,
                }),
                self.select_on(name, origin),
            )
        }

        fn install(
            &self,
            target: RouteMatch,
            _: &str,
            _: DnsOrigin<'_>,
            _: &RouteAnswer,
        ) -> io::Result<(bool, u64)> {
            self.installed.lock().unwrap().push(Instant::now());
            std::thread::sleep(Duration::from_millis(12));
            Ok((false, target.revision))
        }

        fn replay_publication(&self) -> Option<RoutePublication> {
            Some(RoutePublication {
                generation: self.generation.load(Ordering::SeqCst),
                revision: 4,
            })
        }

        fn firmware_hint_publication(
            &self,
            target: RouteMatch,
            name: &str,
            origin: DnsOrigin<'_>,
        ) -> Option<RoutePublication> {
            self.replay_publication().filter(|active| {
                target.generation == active.generation
                    && (name == "global.office.test"
                        || (name == "scoped.office.test"
                            && origin.client == Some("192.168.1.25".parse().unwrap())))
            })
        }

        fn mixed_firmware_policy(&self, publication: RoutePublication) -> bool {
            self.mixed.load(Ordering::SeqCst) && self.replay_publication() == Some(publication)
        }
    }

    #[tokio::test]
    async fn mixed_firmware_route_history_does_not_change_delivered_wire_ttl() {
        use tokio::net::UdpSocket;
        let routes = Arc::new(Observer::default());
        let gate = Arc::new(LiveFirmwareHintGate::default());
        gate.mixed.store(true, Ordering::SeqCst);
        routes.register(gate.clone());
        let firmware = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = firmware.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut buf = [0; 512];
            let (n, peer) = firmware.recv_from(&mut buf).await.unwrap();
            let mut reply = nfqws2_dns::response_error(&buf[..n], 0);
            reply[7] = 1;
            reply.extend([192, 12, 0, 1, 0, 1, 0, 0, 0, 4, 0, 4, 192, 0, 2, 19]);
            firmware.send_to(&reply, peer).await.unwrap();
        });
        let query = nfqws2_dns::build_query("scoped.office.test", 1, 71).unwrap();
        let reply = super::super::redirect::forward(
            endpoint,
            &routes,
            "192.168.1.25".parse().unwrap(),
            Some("br0"),
            &query,
        )
        .await
        .unwrap()
        .unwrap();
        server.await.unwrap();
        assert_eq!(nfqws2_dns::route_answer(&reply).unwrap().unwrap().ttl, 4);
        let before = gate.replay_publication().unwrap();
        let next = RoutePublication {
            generation: before.generation + 1,
            ..before
        };
        let mut hints = routes.firmware_hints.lock().unwrap();
        let witness = hints.policy_snapshot(before).pop().unwrap();
        let expires = witness.policy_expires.unwrap();
        assert_eq!(
            expires - witness.record.expires,
            FIRMWARE_POLICY_HINT_LIFETIME - Duration::from_secs(4)
        );
        hints.continue_after_refresh(before, next, expires);
        let candidate = hints.policy_snapshot(next).pop().unwrap();
        assert!(candidate.query == witness.query);
        assert_eq!(candidate.policy_expires, Some(expires));
        assert_eq!(candidate.record.expires, witness.record.expires);
    }

    #[tokio::test]
    async fn matched_transparent_reply_produces_current_source_bound_revalidation_hints() {
        use tokio::net::UdpSocket;
        let routes = Arc::new(Observer::default());
        let gate = Arc::new(LiveFirmwareHintGate::default());
        routes.register(gate.clone());
        let firmware = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream = firmware.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..4 {
                let mut buf = [0; 512];
                let (n, peer) = firmware.recv_from(&mut buf).await.unwrap();
                let mut reply = nfqws2_dns::response_error(&buf[..n], 0);
                reply[7] = 1;
                reply.extend([192, 12, 0, 1, 0, 1, 0, 0, 0, 4, 0, 4, 192, 0, 2, 19]);
                firmware.send_to(&reply, peer).await.unwrap();
            }
        });
        for (name, from) in [
            ("global.office.test", "192.168.1.25"),
            ("scoped.office.test", "192.168.1.25"),
            ("scoped.office.test", "192.168.1.26"),
            ("global.office.test", "127.0.0.1"),
        ] {
            let query = nfqws2_dns::build_query(name, 1, 71).unwrap();
            let reply = super::super::redirect::forward(
                upstream,
                &routes,
                from.parse().unwrap(),
                Some("br0"),
                &query,
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(reply[7], 1);
        }
        server.await.unwrap();
        let publication = gate.replay_publication().unwrap();
        let hints = routes.firmware_hints.lock().unwrap().snapshot(publication);
        assert_eq!(hints.len(), 2);
        assert_eq!(hints[0].0.name, "scoped.office.test");
        assert_eq!(hints[1].0.name, "global.office.test");
        assert_eq!(hints[0].0.client, "192.168.1.25".parse::<IpAddr>().unwrap());
        let expiry = hints[0].1.expires;
        assert!(expiry <= gate.installed.lock().unwrap()[1] + Duration::from_secs(4));
        let expected = ["192.0.2.19".parse().unwrap()];
        let scoped = |name: &str| Ok(name == "scoped.office.test");
        let exact_client = "192.168.1.25".parse::<IpAddr>().unwrap();
        assert!(firmware_rrset_hint(
            hints.clone(),
            &["br0".into()],
            Some(exact_client),
            &expected,
            scoped,
            Instant::now()
        )
        .unwrap()
        .is_some());
        assert!(firmware_rrset_hint(
            hints.clone(),
            &["br-other".into()],
            Some(exact_client),
            &expected,
            scoped,
            Instant::now()
        )
        .unwrap()
        .is_none());
        assert!(firmware_rrset_hint(
            hints.clone(),
            &["br0".into()],
            Some("192.168.1.26".parse().unwrap()),
            &expected,
            scoped,
            Instant::now()
        )
        .unwrap()
        .is_none());
        assert!(firmware_rrset_hint(
            hints,
            &["br0".into()],
            Some(exact_client),
            &expected,
            scoped,
            expiry
        )
        .unwrap()
        .is_none());
        assert!(routes
            .recent
            .lock()
            .unwrap()
            .snapshot(Instant::now())
            .is_empty());
        gate.generation.store(1, Ordering::SeqCst);
        let next = gate.replay_publication().unwrap();
        assert!(routes
            .firmware_hints
            .lock()
            .unwrap()
            .snapshot(next)
            .is_empty());
        routes.continue_firmware_hints(
            publication,
            RoutePublication {
                revision: 5,
                ..next
            },
        );
        assert!(routes.has_live_firmware_hints(publication));
        assert!(!routes.has_live_firmware_hints(next));
        routes.continue_firmware_hints(publication, next);
        assert!(!routes.has_live_firmware_hints(publication));
        {
            let mut stored = routes.firmware_hints.lock().unwrap();
            let carried = stored.snapshot(next);
            assert_eq!(carried.len(), 2);
            assert_eq!(carried[0].0.client, exact_client);
            assert_eq!(carried[0].0.ingress.as_deref(), Some("br0"));
            assert_eq!(carried[0].1.expires, expiry);
            let following = RoutePublication {
                generation: 2,
                ..next
            };
            stored.continue_after_refresh(next, following, expiry);
            assert!(!stored.has_live(following, expiry));
            assert!(stored.snapshot(following).is_empty());
        }
        routes.schedule_replay(next);
        routes.finish_replay_for_test().await;
        assert_eq!(gate.installed.lock().unwrap().len(), 4);
    }

    #[test]
    fn dormant_firmware_hints_keep_original_deadlines_and_newer_held_answers() {
        let observer = Observer::default();
        let start = Instant::now();
        let live = start + Duration::from_secs(50);
        let expired = start + Duration::from_secs(5);
        let resumed = start + Duration::from_secs(10);
        let old = RoutePublication { revision: 31, generation: 9 };
        let held = RoutePublication { revision: 32, generation: 13 };
        let next = RoutePublication { revision: 32, generation: 14 };
        let hint = |name: &str, address: u8, policy_expires| FirmwareHint {
            query: recent::SourceQuery {
                name: name.to_owned(), client: "192.168.1.10".parse().unwrap(),
                ingress: Some("br0".to_owned()), kind: 1,
            },
            record: recent::Record {
                addresses: vec![IpAddr::from([198, 18, 0, address])],
                expires: expired, managed: None,
            },
            policy_expires: Some(policy_expires),
        };
        {
            let mut hints = observer.firmware_hints.lock().unwrap();
            hints.record(old, hint("scoped.test", 1, live), start);
            hints.record(old, hint("held.test", 2, live), start);
            hints.record(old, hint("expired.test", 3, expired), start);
        }
        observer.park_firmware_hints(old, "projection");
        let mut hints = observer.firmware_hints.lock().unwrap();
        hints.record(held, hint("held.test", 4, live), resumed);
        hints.continue_after_rearm("other", next, resumed);
        assert!(hints.policy_snapshot(next).is_empty());
        hints.continue_after_rearm("projection", next, resumed);
        let carried = hints.policy_snapshot(next);
        assert_eq!(carried.len(), 2);
        assert_eq!(carried[0].query.name, "held.test");
        assert_eq!(carried[0].record.addresses, [IpAddr::from([198, 18, 0, 4])]);
        assert_eq!(carried[1].query.name, "scoped.test");
        assert_eq!(carried[1].policy_expires, Some(live));
        assert_eq!(carried[1].record.expires, expired);
        assert!(hints.dormant.is_none());
    }

    #[derive(Default)]
    pub(super) struct ReplayGate {
        pub(super) generation: AtomicU64,
        pub(super) selecting: tokio::sync::Notify,
        pub(super) installs: Mutex<Vec<RouteAnswer>>,
    }

    impl RouteObserver for ReplayGate {
        fn select(&self, name: &str, client: Option<IpAddr>) -> io::Result<Option<RouteMatch>> {
            self.select_on(
                name,
                DnsOrigin {
                    client,
                    ingress: None,
                },
            )
        }

        fn select_on(&self, name: &str, origin: DnsOrigin<'_>) -> io::Result<Option<RouteMatch>> {
            let generation = self.generation.load(Ordering::SeqCst);
            Ok((generation > 0
                && name.ends_with(".office.test")
                && origin.client == Some(IpAddr::from([127, 0, 0, 1]))
                && origin.ingress == Some("br-client"))
            .then_some(RouteMatch {
                revision: 1,
                generation,
                zone: 2,
            }))
        }

        fn replay_publication(&self) -> Option<RoutePublication> {
            Some(RoutePublication {
                generation: self.generation.load(Ordering::SeqCst),
                revision: 4,
            })
        }

        fn replay_target(
            &self,
            publication: RoutePublication,
            name: &str,
            origin: DnsOrigin<'_>,
        ) -> io::Result<Option<RouteMatch>> {
            if self.replay_publication() != Some(publication) {
                return Err(replaced());
            }
            let target = self.select_on(name, origin)?;
            if target.is_some() {
                self.selecting.notify_one();
            }
            Ok(target)
        }

        fn install(
            &self,
            _: RouteMatch,
            _: &str,
            _: DnsOrigin<'_>,
            _: &RouteAnswer,
        ) -> io::Result<(bool, u64)> {
            panic!("replay must not record a live DNS visit")
        }

        fn install_replayed(
            &self,
            _: RouteMatch,
            name: &str,
            origin: DnsOrigin<'_>,
            answer: &RouteAnswer,
            resolver: Option<&ArchiveResolver>,
        ) -> io::Result<(bool, u64)> {
            assert!(resolver.is_none());
            assert!(name.ends_with(".office.test"));
            assert_ne!(name, "expired.office.test");
            assert_eq!(origin.client, Some(IpAddr::from([127, 0, 0, 1])));
            assert_eq!(origin.ingress, Some("br-client"));
            self.installs.lock().unwrap().push(RouteAnswer {
                qtype: answer.qtype,
                addresses: answer.addresses.clone(),
                ttl: answer.ttl,
            });
            Ok((false, 1))
        }
    }

    #[tokio::test]
    async fn recent_unmatched_dns_replays_with_original_source_and_remaining_ttl() {
        use tokio::{net::UdpSocket, time::timeout};
        const V6: [u8; 16] = [32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6];
        let routes = Arc::new(Observer::default());
        let gate = Arc::new(ReplayGate::default());
        routes.register(gate.clone());
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream = server.local_addr().unwrap();
        let firmware = tokio::spawn(async move {
            for (ttl, ip) in [(1, 1), (20, 2), (20, 3), (20, 4), (20, 0)] {
                let mut buf = [0; 512];
                let (n, peer) = server.recv_from(&mut buf).await.unwrap();
                let kind = nfqws2_dns::query_domain(&buf[..n]).unwrap().1;
                let mut reply = nfqws2_dns::response_error(&buf[..n], 0);
                reply[7] = 1;
                reply.extend([192, 12, 0, kind as u8, 0, 1, 0, 0, 0, ttl, 0]);
                if kind == 28 {
                    reply.push(16);
                    reply.extend(V6);
                } else {
                    reply.extend([4, 192, 0, 2, ip]);
                }
                server.send_to(&reply, peer).await.unwrap();
            }
        });
        for (name, client, bridge, kind) in [
            ("expired.office.test", 1, "br-client", 1),
            ("host.office.test", 1, "br-client", 1),
            ("host.office.test", 1, "br-other", 1),
            ("host.office.test", 2, "br-client", 1),
            ("host.office.test", 1, "br-client", 28),
        ] {
            let query = nfqws2_dns::build_query(name, kind, 71).unwrap();
            let answer = super::super::redirect::forward(
                upstream,
                &routes,
                IpAddr::from([127, 0, 0, client]),
                Some(bridge),
                &query,
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(answer[7], 1);
        }
        firmware.await.unwrap();
        assert!(gate.installs.lock().unwrap().is_empty());
        let obsolete = gate.replay_publication().unwrap();
        tokio::time::sleep(Duration::from_millis(1100)).await;
        gate.generation.store(1, Ordering::SeqCst);
        routes.schedule_replay(gate.replay_publication().unwrap());
        routes.schedule_replay(obsolete);
        let job = routes.replay.lock().unwrap().take().unwrap();
        timeout(Duration::from_secs(3), job).await.unwrap().unwrap();

        let mut seen = gate.installs.lock().unwrap();
        seen.sort_by_key(|answer| answer.qtype);
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].qtype, 1);
        assert_eq!(seen[0].addresses, [IpAddr::from([192, 0, 2, 2])]);
        assert_eq!(seen[1].qtype, 28);
        assert_eq!(seen[1].addresses, [IpAddr::from(V6)]);
        assert!(seen.iter().all(|answer| (1..=18).contains(&answer.ttl)));
    }

    #[tokio::test]
    async fn recent_dns_replay_waiting_on_writer_discards_superseded_publication() {
        use tokio::time::timeout;
        let routes = Arc::new(Observer::default());
        let gate = Arc::new(ReplayGate::default());
        routes.register(gate.clone());
        routes.recent.lock().unwrap().observe(
            "host.office.test",
            DnsOrigin {
                client: Some(IpAddr::from([127, 0, 0, 1])),
                ingress: Some("br-client"),
            },
            RouteAnswer {
                qtype: 1,
                addresses: vec![IpAddr::from([192, 0, 2, 2])],
                ttl: 20,
            },
            Instant::now(),
        );
        gate.generation.store(1, Ordering::SeqCst);
        let permit = routes.writer.clone().acquire_owned().await.unwrap();
        routes.schedule_replay(gate.replay_publication().unwrap());
        timeout(Duration::from_secs(2), gate.selecting.notified())
            .await
            .unwrap();
        let old_job = routes.replay.lock().unwrap().take().unwrap();
        gate.generation.store(2, Ordering::SeqCst);
        drop(permit);
        timeout(Duration::from_secs(2), old_job)
            .await
            .unwrap()
            .unwrap();
        assert!(gate.installs.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn recent_dns_replay_crosses_the_yield_batch_boundary() {
        let routes = Arc::new(Observer::default());
        let gate = Arc::new(ReplayGate::default());
        routes.register(gate.clone());
        {
            let now = Instant::now();
            let mut recent = routes.recent.lock().unwrap();
            for address in 1..=64 {
                recent.observe(
                    &format!("host-{address}.office.test"),
                    DnsOrigin {
                        client: Some(IpAddr::from([127, 0, 0, 1])),
                        ingress: Some("br-client"),
                    },
                    RouteAnswer {
                        qtype: 1,
                        addresses: vec![IpAddr::from([192, 0, 2, address])],
                        ttl: 60,
                    },
                    now,
                );
            }
        }
        gate.generation.store(1, Ordering::SeqCst);
        routes.schedule_replay(gate.replay_publication().unwrap());
        let job = routes.replay.lock().unwrap().take().unwrap();
        tokio::time::timeout(Duration::from_secs(4), job)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(gate.installs.lock().unwrap().len(), 64);
    }

    #[tokio::test]
    async fn ipv4_tunnel_withholds_the_whole_service_binding_when_it_carries_ipv6() {
        struct Ipv4Tunnel;
        impl RouteObserver for Ipv4Tunnel {
            fn select(&self, _: &str, client: Option<IpAddr>) -> io::Result<Option<RouteMatch>> {
                Ok(client.filter(IpAddr::is_loopback).map(|_| RouteMatch {
                    revision: 2,
                    generation: 1,
                    zone: 3,
                }))
            }

            fn blocks_aaaa(&self, _: RouteMatch) -> io::Result<bool> {
                Ok(true)
            }

            fn install(
                &self,
                _: RouteMatch,
                _: &str,
                _: DnsOrigin<'_>,
                answer: &RouteAnswer,
            ) -> io::Result<(bool, u64)> {
                assert!(answer.addresses.is_empty());
                assert_eq!(answer.ttl, 0);
                Ok((false, 2))
            }
        }

        let routes = Observer::default();
        routes.register(Arc::new(Ipv4Tunnel));
        for qtype in [64, 65] {
            let query = nfqws2_dns::build_query("office.test", qtype, 3).unwrap();
            let mut response = nfqws2_dns::response_error(&query, 0);
            response[7] = 1;
            // A service-mode binding with both address families. A client
            // whose policy forces IPv4 cannot receive even the IPv4 hint in
            // the filtered response because changing the RRset breaks DNSSEC.
            response.extend_from_slice(&[
                192,
                12,
                0,
                qtype as u8,
                0,
                1,
                0,
                0,
                0,
                60,
                0,
                31,
                0,
                1,
                0,
                0,
                4,
                0,
                4,
                192,
                0,
                2,
                7,
                0,
                6,
                0,
                16,
                32,
                1,
                13,
                184,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                1,
            ]);
            let mut filtered = response.clone();
            routes
                .prepare(
                    "office.test",
                    Some("127.0.0.1".parse().unwrap()),
                    &query,
                    &mut filtered,
                    ManagedDelivery::test_request(),
                )
                .await
                .unwrap();
            assert_eq!(filtered, nfqws2_dns::response_error(&query, 0));
            let original = response.clone();
            routes
                .prepare(
                    "office.test",
                    Some("192.0.2.8".parse().unwrap()),
                    &query,
                    &mut response,
                    ManagedDelivery::test_request(),
                )
                .await
                .unwrap();
            assert_eq!(response, original);
        }
    }

    #[tokio::test]
    async fn confirmed_route_replies_while_a_different_kernel_write_is_pending() {
        struct Confirmed;
        impl RouteObserver for Confirmed {
            fn select(&self, _: &str, _: Option<IpAddr>) -> io::Result<Option<RouteMatch>> {
                Ok(Some(RouteMatch {
                    revision: 7,
                    generation: 1,
                    zone: 2,
                }))
            }
            fn cached(
                &self,
                _: RouteMatch,
                _: &str,
                _: DnsOrigin<'_>,
                answer: &RouteAnswer,
            ) -> io::Result<Option<bool>> {
                assert_eq!(answer.ttl, 300);
                Ok(Some(false))
            }
            fn install(
                &self,
                _: RouteMatch,
                _: &str,
                _: DnsOrigin<'_>,
                _: &RouteAnswer,
            ) -> io::Result<(bool, u64)> {
                panic!("cached confirmation started a kernel writer")
            }
        }
        let routes = Observer::default();
        routes.register(Arc::new(Confirmed));
        let _ongoing = routes.writer.clone().acquire_owned().await.unwrap();
        let query = nfqws2_dns::build_query("office.test", 1, 1).unwrap();
        let mut reply = nfqws2_dns::response_error(&query, 0);
        reply[7] = 1;
        reply.extend_from_slice(&[192, 12, 0, 1, 0, 1, 0, 0, 14, 16, 0, 4, 192, 0, 2, 7]);
        tokio::time::timeout(
            Duration::from_secs(1),
            routes.prepare(
                "office.test",
                None,
                &query,
                &mut reply,
                ManagedDelivery::test_request(),
            ),
        )
        .await
        .expect("a cached reply waited behind the kernel writer")
        .unwrap();
        assert_eq!(
            &reply[query.len() + 6..query.len() + 10],
            &300u32.to_be_bytes()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn waited_managed_route_cannot_extend_original_address_ttl() {
        use futures_util::FutureExt;

        struct PendingRoute {
            applying: AtomicBool,
            published: watch::Sender<()>,
            installed: Mutex<Vec<u32>>,
        }

        impl RouteObserver for PendingRoute {
            fn select(&self, _: &str, _: Option<IpAddr>) -> io::Result<Option<RouteMatch>> {
                Ok(Some(RouteMatch {
                    revision: 7,
                    generation: 1,
                    zone: 0,
                }))
            }

            fn select_managed_for_delivery(
                &self,
                name: &str,
                origin: DnsOrigin<'_>,
            ) -> io::Result<DeliverySelection> {
                if self.applying.load(Ordering::SeqCst) {
                    Ok(DeliverySelection::Pending(self.published.subscribe()))
                } else {
                    self.select(name, origin.client)
                        .map(DeliverySelection::Ready)
                }
            }

            fn install(
                &self,
                target: RouteMatch,
                _: &str,
                _: DnsOrigin<'_>,
                answer: &RouteAnswer,
            ) -> io::Result<(bool, u64)> {
                self.installed.lock().unwrap().push(answer.ttl);
                Ok((false, target.revision))
            }
        }

        let pending = Arc::new(PendingRoute {
            applying: AtomicBool::new(true),
            published: Default::default(),
            installed: Default::default(),
        });
        let complete = || {
            pending.applying.store(false, Ordering::SeqCst);
            pending.published.send_replace(());
        };
        let routes = Observer::default();
        routes.register(pending.clone());
        let query = nfqws2_dns::build_query("ttl.wait.test", 1, 1).unwrap();
        let response = |ttl: u32| {
            let mut reply = nfqws2_dns::response_error(&query, 0);
            reply[7] = 1;
            reply.extend([192, 12, 0, 1, 0, 1]);
            reply.extend(ttl.to_be_bytes());
            reply.extend([0, 4, 192, 0, 2, 18]);
            reply
        };
        let mut reply = response(12);
        let occupy_writer = routes.writer.clone().acquire_owned().await.unwrap();
        {
            let timing = ManagedDelivery::test_request();
            let work = routes.prepare("ttl.wait.test", None, &query, &mut reply, timing);
            tokio::pin!(work);
            assert!(work.as_mut().now_or_never().is_none());
            tokio::time::advance(Duration::from_secs(4)).await;
            complete();
            assert!(work.as_mut().now_or_never().is_none());
            tokio::time::advance(Duration::from_secs(2)).await;
            drop(occupy_writer);
            work.await.unwrap();
        }
        assert_eq!(*pending.installed.lock().unwrap(), [6]);
        assert_eq!(nfqws2_dns::route_answer(&reply).unwrap().unwrap().ttl, 6);

        pending.applying.store(true, Ordering::SeqCst);
        let mut expired = response(2);
        let work = routes.prepare(
            "ttl.wait.test",
            None,
            &query,
            &mut expired,
            ManagedDelivery::test_request(),
        );
        tokio::pin!(work);
        assert!(work.as_mut().now_or_never().is_none());
        tokio::time::advance(Duration::from_secs(3)).await;
        complete();
        assert_eq!(work.await.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(*pending.installed.lock().unwrap(), [6]);
    }
}
