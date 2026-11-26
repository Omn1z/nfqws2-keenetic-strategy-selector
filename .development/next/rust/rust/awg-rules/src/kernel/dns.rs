use super::{
    err,
    plan::{self, Backend, Plan, Prefix},
    Journal, Operation,
};
use crate::Routing;
use nfqws2_store::Store;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::IpAddr,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsRequest {
    pub revision: u64,
    pub names: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dual_stack: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ipv6_only: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsSnapshot {
    pub request: DnsRequest,
    pub answers: BTreeMap<String, Vec<IpAddr>>,
}

/// A static Resolve retry can use only the addresses already authorized by
/// this committed native policy. Resolver provenance and TTL belong to the caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfirmedStaticDnsRetry {
    baseline: super::Snapshot,
}

impl ConfirmedStaticDnsRetry {
    pub fn snapshot(&self) -> &DnsSnapshot {
        &self
            .baseline
            .dns
            .as_ref()
            .expect("confirmed static DNS")
            .snapshot
    }

    fn matches_plan(&self, plan: &Plan) -> bool {
        self.baseline.firewall == plan.firewall
            && self.baseline.fw4_zone == plan.fw4_zone
            && same_static_intent(&self.baseline, plan)
    }

    pub(super) fn verify_candidate(&self, candidate: &Plan) -> io::Result<()> {
        if self.matches_plan(candidate) {
            Ok(())
        } else {
            Err(retry_changed())
        }
    }
}

/// Exact input to a first native static DNS apply with no previous owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ColdStaticDnsDraft {
    request: DnsRequest,
    boot: String,
    input_hash: String,
}

impl ColdStaticDnsDraft {
    pub fn request(&self) -> &DnsRequest {
        &self.request
    }

    pub(super) fn boot(&self) -> &str {
        &self.boot
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ManagedStaticDnsBasis {
    Confirmed(ConfirmedStaticDnsRetry),
    Cold(ColdStaticDnsDraft),
}

/// A complete managed DNS apply whose prior installation was restored after
/// a route writer failure. The panel retains the original DNS deadline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailedStaticDnsApply {
    basis: ManagedStaticDnsBasis,
    before: Journal,
    attempted: super::Snapshot,
}

impl FailedStaticDnsApply {
    pub fn baseline(&self) -> Option<&ConfirmedStaticDnsRetry> {
        match &self.basis {
            ManagedStaticDnsBasis::Confirmed(baseline) => Some(baseline),
            ManagedStaticDnsBasis::Cold(_) => None,
        }
    }

    pub fn cold_draft(&self) -> Option<&ColdStaticDnsDraft> {
        match &self.basis {
            ManagedStaticDnsBasis::Confirmed(_) => None,
            ManagedStaticDnsBasis::Cold(draft) => Some(draft),
        }
    }

    pub fn snapshot(&self) -> &DnsSnapshot {
        &self
            .attempted
            .dns
            .as_ref()
            .expect("managed DNS rotation")
            .snapshot
    }
}

#[derive(Clone, Copy)]
pub enum ManagedStaticDnsApply<'a> {
    Fresh(&'a ConfirmedStaticDnsRetry, &'a DnsSnapshot),
    Cold(&'a ColdStaticDnsDraft, &'a DnsSnapshot),
    Retry(&'a FailedStaticDnsApply),
}

impl<'a> ManagedStaticDnsApply<'a> {
    fn baseline(self) -> Option<&'a ConfirmedStaticDnsRetry> {
        match self {
            Self::Fresh(baseline, _) => Some(baseline),
            Self::Cold(..) => None,
            Self::Retry(failed) => failed.baseline(),
        }
    }

    pub(super) fn cold_draft(self) -> Option<&'a ColdStaticDnsDraft> {
        match self {
            Self::Fresh(..) => None,
            Self::Cold(draft, _) => Some(draft),
            Self::Retry(failed) => failed.cold_draft(),
        }
    }

    pub(super) fn snapshot(self) -> &'a DnsSnapshot {
        match self {
            Self::Fresh(_, snapshot) | Self::Cold(_, snapshot) => snapshot,
            Self::Retry(failed) => failed.snapshot(),
        }
    }

    pub(super) fn intent(self, db: &Store, doc: &Value, journal: &Journal) -> io::Result<Plan> {
        if let Self::Retry(failed) = self {
            if &failed.before != journal {
                return Err(retry_changed());
            }
        }
        let snapshot = self.snapshot();
        let policy = crate::sources::current(db, doc)?;
        if let Some(draft) = self.cold_draft() {
            if cold_static_intent(db, doc, journal, &policy, &snapshot.request, draft.boot())?
                .as_ref()
                != Some(draft)
            {
                return Err(retry_changed());
            }
        } else if let Some(baseline) = self.baseline() {
            recheck_static_dns_retry(db, doc, journal, baseline)?;
            if snapshot.request != baseline.snapshot().request {
                return Err(retry_changed());
            }
            if journal.installed.empty() || !journal.installed.fully_live() {
                return Err(self.off_scope());
            }
        }
        snapshot.validate(doc["routing_revision"].as_u64().ok_or_else(retry_changed)?)?;
        if !snapshot.has_all_positive_families() {
            return Err(self.off_scope());
        }
        let intent = plan::compile_effective(
            doc,
            policy,
            Some(snapshot),
            false,
            &[],
            plan::Layout::default(),
        )?;
        let proposed = intent.dns.as_ref().ok_or_else(retry_changed)?;
        if !static_retry_geometry(&intent)
            || intent.empty()
            || self.cold_draft().is_some() && intent.targets.is_empty()
        {
            return Err(self.off_scope());
        }
        if let Some(previous) = &journal.committed.dns {
            if proposed.source_hash != previous.source_hash {
                return Err(retry_changed());
            }
            if intent.targets != journal.committed.targets
                || intent.source_ranges != journal.committed.source_ranges
                || intent.killswitch != journal.committed.killswitch
                || proposed.snapshot == previous.snapshot
            {
                return Err(self.off_scope());
            }
        }
        if let Self::Retry(failed) = self {
            if !same_static_intent(&failed.attempted, &intent) {
                return Err(retry_changed());
            }
        }
        Ok(intent)
    }

    fn off_scope(self) -> io::Error {
        match self {
            Self::Fresh(..) | Self::Cold(..) => {
                io::Error::new(io::ErrorKind::Unsupported, ProposalOffScope)
            }
            Self::Retry(_) => retry_changed(),
        }
    }

    pub(super) fn verify_candidate(self, candidate: &Plan) -> io::Result<()> {
        if !static_retry_geometry(candidate) {
            return Err(if matches!(self, Self::Cold(..)) {
                self.off_scope()
            } else {
                retry_changed()
            });
        }
        if !candidate.fully_live()
            || self.baseline().is_some_and(|previous| {
                candidate.firewall != previous.baseline.firewall
                    || candidate.fw4_zone != previous.baseline.fw4_zone
            })
        {
            return Err(retry_changed());
        }
        if let Self::Retry(failed) = self {
            if failed.attempted.as_ref() != candidate {
                return Err(retry_changed());
            }
        }
        Ok(())
    }

    pub(super) fn write_failure(
        self,
        original: io::Error,
        old: &Journal,
        new: &Journal,
    ) -> io::Error {
        let basis = match self {
            Self::Fresh(baseline, _) => ManagedStaticDnsBasis::Confirmed(baseline.clone()),
            Self::Cold(draft, _) => ManagedStaticDnsBasis::Cold(draft.clone()),
            Self::Retry(failed) => failed.basis.clone(),
        };
        let retry = FailedStaticDnsApply {
            basis,
            before: old.clone(),
            attempted: new.installed.clone(),
        };
        io::Error::new(original.kind(), CompensatedWrite { original, retry })
    }
}

#[derive(Debug)]
struct ProposalOffScope;

impl std::fmt::Display for ProposalOffScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DNS-снимок требует обычного применения")
    }
}

impl std::error::Error for ProposalOffScope {}

pub fn managed_static_dns_proposal_off_scope(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|cause| cause.is::<ProposalOffScope>())
}

#[derive(Debug)]
struct CompensatedWrite {
    original: io::Error,
    retry: FailedStaticDnsApply,
}

impl std::fmt::Display for CompensatedWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.original.fmt(f)
    }
}

impl std::error::Error for CompensatedWrite {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}

pub fn failed_static_dns_apply(error: &io::Error) -> Option<&FailedStaticDnsApply> {
    error
        .get_ref()?
        .downcast_ref::<CompensatedWrite>()
        .map(|failure| &failure.retry)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Saved {
    pub snapshot: DnsSnapshot,
    /// Binds a rotation to the approved rule order and physical peer identities,
    /// including rules temporarily shadowed by a coincident DNS address.
    pub source_hash: String,
}

fn retry_changed() -> io::Error {
    io::Error::new(
        io::ErrorKind::WouldBlock,
        "изменилась подтверждённая статическая DNS-политика",
    )
}

fn clear_live_state(plan: &mut Plan) {
    plan.mss.clear();
    plan.offline.clear();
    plan.selected.clear();
}

fn same_static_intent(saved: &Plan, current: &Plan) -> bool {
    let mut expected = saved.clone();
    let mut actual = current.clone();
    clear_live_state(&mut expected);
    clear_live_state(&mut actual);
    // The compiler has not selected the platform firewall yet.
    actual.firewall = expected.firewall;
    actual.fw4_zone.clone_from(&expected.fw4_zone);
    expected == actual
}

fn static_retry_geometry(plan: &Plan) -> bool {
    plan.local_sources.is_none()
        && plan.full_endpoints.is_none()
        && plan.legacy_full.is_none()
        && plan.legacy_scope.is_none()
        && !plan.legacy_probe
        && !plan.go_ipv4
        && plan.go_multi_v6_reject.is_none()
        && !plan.ordered_default
        && !plan.packed
        && plan.marks.is_empty()
        && plan.permanent_fences.is_empty()
        && plan.scoped.is_empty()
        && plan.learned.is_none()
        && plan.dns_bridges.is_empty()
        && plan.firewall != Backend::Fw3
}

fn static_retry_intent(
    db: &Store,
    doc: &Value,
    journal: &Journal,
    request: &DnsRequest,
) -> io::Result<Option<Plan>> {
    let committed = &journal.committed;
    let Some(saved) = &committed.dns else {
        return Ok(None);
    };
    let owner = &doc["rust_static_routing"];
    if journal.expires != 0
        || !journal.preparing.is_empty()
        || journal.boot.is_empty()
        || owner["pending_commit"] != false
        || owner["go_trial"] == true
        || owner["legacy_watchdog"] == true
        || owner["boot"].as_str() != Some(&journal.boot)
        || owner["committed_revision"]
            .as_u64()
            .or_else(|| owner["revision"].as_u64())
            != Some(committed.revision)
        || doc["routing_revision"].as_u64() != Some(committed.revision)
        || !static_retry_geometry(committed)
        || &saved.snapshot.request != request
        || !saved.snapshot.has_all_positive_families()
        || super::legacy_active(doc)
        || super::handoff::pending(db)?
        || super::mtu_edit::pending_mtu_edit(db)?
        || super::mtu_edit::saved_profile(doc, journal)?.is_some()
        || doc["servers"].as_array().into_iter().flatten().any(|row| {
            nfqws2_awg_profile::routed_mtu_launch_pending(row)
                && committed
                    .targets
                    .values()
                    .any(|target| row["id"] == target.id)
        })
        || (!journal.installed.empty()
            && (journal.installed.firewall != committed.firewall
                || journal.installed.fw4_zone != committed.fw4_zone
                || !same_static_intent(committed, &journal.installed)))
    {
        return Ok(None);
    }
    let policy = crate::sources::current(db, doc)?;
    if !crate::observed::dynamic(&policy)
        && exact_request(&policy, committed.revision, doc)?.as_ref() == Some(request)
    {
        let intent = plan::compile_effective(
            doc,
            policy,
            Some(&saved.snapshot),
            false,
            &[],
            plan::Layout::default(),
        )?;
        if same_static_intent(committed, &intent) {
            return Ok(Some(intent));
        }
    }
    Ok(None)
}

pub fn confirmed_static_dns_retry(
    db: &Store,
    request: &DnsRequest,
) -> io::Result<Option<ConfirmedStaticDnsRetry>> {
    db.transaction(|_| {
        let journal = Journal::read(db)?;
        let doc = nfqws2_awg_profile::read(db)?;
        if static_retry_intent(db, &doc, &journal, request)?.is_none() {
            return Ok(None);
        }
        let mut baseline = journal.committed;
        clear_live_state(&mut baseline);
        Ok(Some(ConfirmedStaticDnsRetry { baseline }))
    })
}

/// Check the receipt after a successful verified Refresh that supplied this snapshot.
pub fn installed_static_dns_snapshot(db: &Store, expected: &DnsSnapshot) -> io::Result<bool> {
    let journal = Journal::read(db)?;
    let revision = expected.request.revision;
    if journal.boot.is_empty()
        || journal.expires != 0
        || !journal.preparing.is_empty()
        || journal.installed.empty()
        || !journal.installed.fully_live()
        || ![&journal.installed, &journal.committed]
            .into_iter()
            .all(|plan| {
                plan.revision == revision
                    && plan
                        .dns
                        .as_ref()
                        .is_some_and(|dns| &dns.snapshot == expected)
            })
    {
        return Ok(false);
    }
    let doc = nfqws2_awg_profile::read(db)?;
    Ok(doc["routing_revision"].as_u64().unwrap_or_default() == revision)
}

pub(super) fn recheck_static_dns_retry(
    db: &Store,
    doc: &Value,
    journal: &Journal,
    retry: &ConfirmedStaticDnsRetry,
) -> io::Result<Plan> {
    retry.verify_candidate(&journal.committed)?;
    static_retry_intent(db, doc, journal, &retry.snapshot().request)?.ok_or_else(retry_changed)
}

fn cold_static_intent(
    db: &Store,
    doc: &Value,
    journal: &Journal,
    policy: &Routing,
    request: &DnsRequest,
    boot: &str,
) -> io::Result<Option<ColdStaticDnsDraft>> {
    if !journal.cold_empty()
        || !doc["rust_static_routing"].is_null()
        || super::legacy_active(doc)
        || super::handoff::pending(db)?
        || super::acceleration::pending(db)?
        || super::mtu_edit::pending_mtu_edit(db)?
        || doc["routing_revision"].as_u64() != Some(request.revision)
        || crate::observed::dynamic(policy)
        || policy.zones.iter().filter(|zone| zone.enabled).any(|zone| {
            zone.source_key.is_some() || !zone.source_ips.is_empty() || zone.only_catch_all()
        })
        || exact_request(policy, request.revision, doc)?.as_ref() != Some(request)
    {
        return Ok(None);
    }

    let mut hash = SourceHash::default();
    let mut policy = policy.clone();
    policy.active = false;
    hash.add(&policy)?;
    hash.add(&crate::identity::live(doc))?;
    let rows = doc["servers"]
        .as_array()
        .ok_or_else(|| err("нет списка серверов"))?;
    for row in rows {
        if nfqws2_awg_profile::routed_mtu_launch_pending(row)
            || nfqws2_awg_profile::pending_routed_mtu(row)?.is_some()
        {
            return Ok(None);
        }
        let cfg = &row["config"];
        let applied = &row["applied_config"];
        let wire = if applied.is_object() { applied } else { cfg };
        let client = &cfg["client"];
        let peer = nfqws2_awg_profile::client_peer(wire);
        // Bind all potential transport claimants, including unselected reserves.
        // Private keys and runtime health fields are not inputs to this digest.
        hash.add(&(
            &row["id"],
            &cfg["enabled"],
            &cfg["routing"]["mode"],
            &client["enabled"],
            &client["standby"],
            &client["fallback_tunnel_ids"],
            &client["double_tunnel_id"],
            &client["double_tunnel_mode"],
            &wire["enabled"],
            &wire["client"]["enabled"],
            &wire["client"]["endpoint_backups"],
            &wire["client_iface"],
            &wire["public_key"],
            &wire["endpoint"],
            nfqws2_awg_profile::tunnel_mtu(wire, &cfg["routing"]),
            peer.map(|selected| {
                (
                    &selected["id"],
                    &selected["address"],
                    &selected["allowed_ips"],
                )
            }),
        ))?;
    }
    Ok(Some(ColdStaticDnsDraft {
        request: request.clone(),
        boot: boot.to_owned(),
        input_hash: hash.finish(),
    }))
}

pub fn cold_static_dns_draft(
    db: &Store,
    run: &dyn nfqws2_router_command::Runner,
    request: &DnsRequest,
) -> io::Result<Option<ColdStaticDnsDraft>> {
    cold_static_dns_draft_until(db, run, request, Instant::now() + Duration::from_secs(30))
}

pub fn cold_static_dns_draft_until(
    db: &Store,
    run: &dyn nfqws2_router_command::Runner,
    request: &DnsRequest,
    deadline: Instant,
) -> io::Result<Option<ColdStaticDnsDraft>> {
    db.try_transaction(|_| {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let journal = Journal::read(db)?;
        if !journal.cold_empty() {
            return Ok(None);
        }
        let doc = nfqws2_awg_profile::read(db)?;
        let policy = crate::sources::current(db, &doc)?;
        let mut kernel = super::kernel(run);
        kernel.deadline = kernel.deadline.min(deadline);
        let boot = super::boot_id(&kernel)?;
        let draft = cold_static_intent(db, &doc, &journal, &policy, request, &boot)?;
        if draft.is_some() {
            kernel.check_cold_static_empty()?;
        }
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(draft)
    })
}

#[derive(Default)]
pub(super) struct SourceHash(Sha256);
impl std::io::Write for SourceHash {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl SourceHash {
    pub fn add(&mut self, value: &impl Serialize) -> io::Result<()> {
        serde_json::to_writer(&mut *self, value)?;
        self.0.update(b"\n");
        Ok(())
    }
    pub fn finish(self) -> String {
        use std::fmt::Write;
        let mut text = String::with_capacity(64);
        for b in self.0.finalize() {
            write!(&mut text, "{b:02x}").unwrap();
        }
        text
    }
}

pub(super) fn name(raw: &str) -> io::Result<String> {
    nfqws2_awg_profile::exact_route_hostname(raw)
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| err("требуется точное DNS-имя без масок"))
}

pub(super) fn families(doc: &serde_json::Value, z: &crate::Zone) -> (bool, bool) {
    let source4 = z.source_ips.is_empty() || z.source_ips.iter().any(|ip| !ip.contains(':'));
    let source6 = z.source_ips.is_empty() || z.source_ips.iter().any(|ip| ip.contains(':'));
    if z.direction() == "direct" {
        return (source4, source6);
    }
    let rows = doc["servers"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    let reserves = !z.fallback_tunnel_ids.is_empty()
        || rows
            .iter()
            .find(|r| r["id"] == z.tunnel_id)
            .is_some_and(|r| {
                r["config"]["client"]["fallback_tunnel_ids"]
                    .as_array()
                    .is_some_and(|ids| !ids.is_empty())
            });
    let candidates = if reserves {
        nfqws2_awg_profile::FailoverGraph::load(doc)
            .and_then(|g| g.for_rule(&z.tunnel_id, &z.fallback_tunnel_ids))
            .unwrap_or_else(|_| vec![z.tunnel_id.as_str()])
    } else {
        vec![z.tunnel_id.as_str()]
    };
    let mut v4 = false;
    let mut v6 = false;
    for row in rows
        .iter()
        .filter(|r| r["id"].as_str().is_some_and(|id| candidates.contains(&id)))
    {
        let cfg = if row["applied_config"].is_object() {
            &row["applied_config"]
        } else {
            &row["config"]
        };
        if let Some(p) = nfqws2_awg_profile::client_peer(cfg) {
            for addr in p["address"].as_str().unwrap_or("").split([',', ' ', '\t']) {
                if let Ok(ip) = addr.split('/').next().unwrap_or("").parse::<IpAddr>() {
                    let allowed = p["allowed_ips"].as_str().unwrap_or("").trim();
                    let granted = allowed.is_empty()
                        || allowed
                            .split([',', ' ', '\t'])
                            .filter_map(|cidr| cidr.split('/').next()?.parse::<IpAddr>().ok())
                            .any(|a| a.is_ipv4() == ip.is_ipv4());
                    if granted {
                        v4 |= ip.is_ipv4();
                        v6 |= ip.is_ipv6();
                    }
                }
            }
        }
    }
    ((v4 || !v6) && source4, v6 && source6)
}
pub(super) fn request(
    policy: &Routing,
    revision: u64,
    doc: &serde_json::Value,
) -> io::Result<Option<DnsRequest>> {
    if crate::observed::dynamic(policy) {
        return Ok(None);
    }
    exact_request(policy, revision, doc)
}

pub(super) fn exact_request(
    policy: &Routing,
    revision: u64,
    doc: &serde_json::Value,
) -> io::Result<Option<DnsRequest>> {
    if policy.mode == "off" || policy.global_default_zone().is_some() {
        return Ok(None);
    }
    let mut names = BTreeSet::new();
    let mut v4_names = BTreeSet::new();
    let mut v6_names = BTreeSet::new();
    for z in policy.zones.iter().filter(|z| {
        z.enabled
            && z.domains
                .iter()
                .any(|v| !crate::model::ipish(v) && !crate::model::catch_all(v))
    }) {
        if !policy.has_explicit_policy()
            || policy.domain_source != "resolve"
            || z.include_subdomains == Some(true)
            || z.waiting_for_connection
        {
            return Err(err(
                "DNS-зоне нужны точные имена, выключенные поддомены и режим resolve",
            ));
        }
        let (v4, v6) = families(doc, z);
        if !v4 && !v6 {
            return Err(err("семейства адресов источника и туннеля не совпадают"));
        }
        for raw in z
            .domains
            .iter()
            .filter(|v| !crate::model::ipish(v) && !crate::model::catch_all(v))
        {
            let host = name(raw)?;
            if v4 {
                v4_names.insert(host.clone());
            }
            if v6 {
                v6_names.insert(host.clone());
            }
            names.insert(host);
            if names.len() > 32 {
                return Err(err("не более 32 точных DNS-имён на политику"));
            }
        }
    }
    Ok((!names.is_empty()).then(|| DnsRequest {
        revision,
        names: names.into_iter().collect(),
        dual_stack: v6_names.intersection(&v4_names).cloned().collect(),
        ipv6_only: v6_names.difference(&v4_names).cloned().collect(),
    }))
}

impl DnsSnapshot {
    fn has_all_positive_families(&self) -> bool {
        self.request.names.iter().all(|name| {
            let only_v6 = self.request.ipv6_only.binary_search(name).is_ok();
            let dual = self.request.dual_stack.binary_search(name).is_ok();
            self.answers.get(name).is_some_and(|addresses| {
                let present = (
                    addresses.iter().any(IpAddr::is_ipv4),
                    addresses.iter().any(IpAddr::is_ipv6),
                );
                present == (!only_v6, only_v6 || dual)
            })
        })
    }

    pub(super) fn validate(&self, revision: u64) -> io::Result<()> {
        let names = &self.request.names;
        if self.request.revision != revision
            || names.is_empty()
            || names.len() > 32
            || self.answers.keys().ne(names.iter())
            || [&self.request.dual_stack, &self.request.ipv6_only]
                .iter()
                .any(|list| {
                    list.len() > names.len()
                        || list.windows(2).any(|w| w[0] >= w[1])
                        || list.iter().any(|host| names.binary_search(host).is_err())
                })
            || self
                .request
                .dual_stack
                .iter()
                .any(|host| self.request.ipv6_only.binary_search(host).is_ok())
        {
            return Err(err("неполный DNS-снимок или изменилась ревизия политики"));
        }
        let mut total = BTreeSet::new();
        for (host, ips) in &self.answers {
            let dual = self.request.dual_stack.binary_search(host).is_ok();
            let only_v6 = self.request.ipv6_only.binary_search(host).is_ok();
            let v4 = ips.iter().filter(|ip| ip.is_ipv4()).count();
            let v6 = ips.len() - v4;
            if &name(host)? != host
                || ips.is_empty()
                || v4 > 16
                || v6 > 16
                || (only_v6 && v4 != 0)
                || (!dual && !only_v6 && v6 != 0)
                || ips.iter().any(|ip| !Prefix::host(*ip).safe())
            {
                return Err(err("неверный адрес или число DNS-адресов в снимке"));
            }
            total.extend(ips.iter().copied());
        }
        if total.len() > 128 {
            return Err(err("не более 128 различных адресов в DNS-снимке"));
        }
        Ok(())
    }
}

/// Resolve only these names outside the writer transaction. Apply checks its
/// revision again. Recovery and commit use the exact addresses in the receipt.
pub fn dns_request(db: &Store, op: Operation) -> io::Result<Option<DnsRequest>> {
    match op {
        Operation::Apply | Operation::ReloadSources => {
            if op == Operation::Apply && super::handoff::legacy_pending(db)? {
                return Ok(None);
            }
            let doc = nfqws2_awg_profile::read(db)?;
            let r = crate::sources::current(db, &doc)?;
            r.validate(true)?;
            request(
                &r,
                doc["routing_revision"].as_u64().unwrap_or_default(),
                &doc,
            )
        }
        Operation::Refresh => {
            let j = Journal::read(db)?;
            let Some(saved) = &j.committed.dns else {
                return Ok(None);
            };
            if j.expires != 0 || !j.preparing.is_empty() {
                return Ok(None);
            }
            let doc = nfqws2_awg_profile::read(db)?;
            Ok(
                (doc["routing_revision"].as_u64().unwrap_or_default() == j.committed.revision)
                    .then(|| saved.snapshot.request.clone()),
            )
        }
        _ => Ok(None),
    }
}
