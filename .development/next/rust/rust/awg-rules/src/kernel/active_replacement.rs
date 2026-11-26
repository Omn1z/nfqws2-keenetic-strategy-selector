//! A confirmed transfer of one native tunnel's IPv4 routes. Both policies own
//! the same stops until their ordinary route writer and profile save finish.
use self::policy_hint::{
    ConfirmedNegativeName, NamedPositiveObservation, PairPositiveHints, PositiveUntil,
    RetryPositiveHint,
};
use super::{
    boot_id, err, handoff, io, kernel, learning, mtu_edit, objects, plan, profile_rebind, stamp,
    stamp_document, transition, Journal, Kernel, LivePeer, Object, Operation, Plan, Prefix, Runner,
    Snapshot, Store, Transaction, RECEIPT, RECEIPT_LIMIT,
};
use nfqws2_awg_profile::{
    active_replacement_allowed, active_replacement_endpoint, active_replacement_fingerprint,
    active_replacement_nested_mtu, active_replacement_numeric_pool,
    active_replacement_startup_binding, active_replacement_topology,
    active_replacement_transport_stamp, active_replacement_underlay_identity,
    nested_socket_selector, persist_active_replacement_locked,
    read_active_replacement_launch as read_launch, ActiveReplacementLaunchLease,
    ActiveReplacementLaunchMode, ActiveReplacementLaunchPin, ActiveReplacementNumericPool,
    ActiveReplacementPeer, ActiveReplacementStage, ActiveReplacementUnderlay, NativeRemovalSeal,
    ACTIVE_REPLACEMENT_FIELD as FIELD, ACTIVE_REPLACEMENT_LAUNCH_FILE as LAUNCH,
    ACTIVE_REPLACEMENT_LAUNCH_LIMIT as LAUNCH_LIMIT,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    time::Instant,
};

const FILE: &str = "awg-active-replacement.json";
const COLD_NUMERIC_STARTUP: &str = "awg-cold-numeric-startup.json";
const LIMIT: u64 = 64 << 10;
mod disabled;
mod established_name;
mod named;
mod named_rotation;
mod policy_hint;
pub(super) use disabled::{
    confirmed_empty as confirmed_disabled_empty, dormant_target, marked_rearm, rearm,
    rearm_checkpoint, rearm_pending, retain_rearm_lookups, settle_rearm,
    DNS as DISABLED_REPLACEMENT_DNS, TARGETS as DISABLED_REPLACEMENTS,
};
pub use disabled::{
    disabled_replacement_dns_redirects, disabled_replacement_rearm_needs_dns, dormant_firmware_dns,
    replace_active_profile_with_disabled_target, DormantFirmwareAnswer, DormantFirmwareDns,
    DormantFirmwareProof,
};
pub use established_name::{established_warm_client, established_warm_owner};
pub(super) use established_name::{clear as clear_established_name, reassert as reassert_established_name};
use named::SealedTransportPair;
pub(super) use named::TransportClaims as NamedTransportClaims;
pub use named::{
    prepare_named_active_replacement, warm_named_replacement_request, NamedActiveReplacement,
    WarmNamedReplacementRequest,
};
pub use named_rotation::{
    prepare_deferred_named_rotation, resume_deferred_named_rotation, DeferredNamedRotation,
};
pub(super) use named_rotation::{
    reconnect_revision as deferred_named_reconnect_revision,
    validate_reconnect as validate_deferred_named_reconnect,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transfer {
    prior: Journal,
    next: Journal,
    source: NativeRemovalSeal,
    source_fingerprint: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    disabled_target: Option<disabled::Target>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retained_outer: Option<NativeRemovalSeal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    held_direct: Option<HeldDirect>,
    #[serde(
        default,
        rename = "shared_nested_target",
        skip_serializing_if = "Option::is_none"
    )]
    nested_target: Option<NestedTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retiring_nested: Option<RetiringNested>,
    token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    temporary_stop: Option<TemporaryStop>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    retry_runtime: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retry_dns: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retry_projection: Option<RetryDnsProjection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retry_positive_hint: Option<RetryPositiveHint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retry_negative_name: Option<ConfirmedNegativeName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retry_positive_pair: Option<PairPositiveHints>,
    #[serde(default)]
    retired: bool,
}

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct RetryDnsProjection {
    members: Vec<learning::Member>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    withdrawn: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expired_positive_name: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    both_positive: bool,
    stamp: String,
}

impl RetryDnsProjection {
    fn stamp(&self, token: &str) -> io::Result<String> {
        if self.both_positive {
            profile_rebind::digest(&(token, &self.members, "both positive"))
        } else if let Some(name) = &self.expired_positive_name {
            profile_rebind::digest(&(token, &self.members, self.withdrawn, name))
        } else if self.withdrawn {
            profile_rebind::digest(&(token, &self.members, true))
        } else {
            profile_rebind::digest(&(token, &self.members))
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
pub(super) use policy_hint::age_for_test as age_pending_positive_dns_hint;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeldDirect {
    owner: NativeRemovalSeal,
    fingerprint: [u8; 32],
    wan: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NestedTarget {
    owner: NativeRemovalSeal,
    outer: NativeRemovalSeal,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    outer_fingerprint: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_outer: Option<NestedSourceOuter>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NestedSourceOuter {
    owner: NativeRemovalSeal,
    fingerprint: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetiringNested {
    outer: NestedSourceOuter,
    target: NativeRemovalSeal,
}

impl RetiringNested {
    fn binds(&self, source: &NativeRemovalSeal, id: &str, iface: &str) -> bool {
        self.target.valid()
            && self.target.id == id
            && self.target.iface == iface
            && self.target.boot == source.boot
            && self.target.nested.is_none()
            && distinct_owner(source, &self.target)
            && self.outer.fingerprint != [0; 32]
            && binds_direct_outer(&self.outer.owner, source, &self.target)
            && source
                .nested
                .as_ref()
                .is_some_and(|scope| scope.outer_iface == self.outer.owner.iface)
    }
}

fn distinct_owner(a: &NativeRemovalSeal, b: &NativeRemovalSeal) -> bool {
    a.id != b.id && a.iface != b.iface && a.pid != b.pid && a.receipt_sha256 != b.receipt_sha256
}

fn binds_direct_outer(
    outer: &NativeRemovalSeal,
    source: &NativeRemovalSeal,
    target: &NativeRemovalSeal,
) -> bool {
    outer.valid()
        && outer.boot == source.boot
        && outer.nested.is_none()
        && distinct_owner(outer, source)
        && distinct_owner(outer, target)
}

impl NestedTarget {
    fn selected_outer(&self, published: bool) -> (&NativeRemovalSeal, Option<[u8; 32]>) {
        if !published {
            if let Some(outer) = &self.source_outer {
                return (&outer.owner, Some(outer.fingerprint));
            }
        }
        (&self.outer, self.outer_fingerprint)
    }

    fn binds(&self, source: &NativeRemovalSeal, target: &str, iface: &str) -> bool {
        let own_outer = self
            .owner
            .nested
            .as_ref()
            .is_some_and(|scope| scope.outer_iface == self.outer.iface);
        let source_path = match source.nested.as_ref() {
            Some(scope) => {
                scope.outer_iface == self.selected_outer(false).0.iface
                    && nested_socket_selector(&source.iface)
                        .ok()
                        .zip(nested_socket_selector(iface).ok())
                        .is_some_and(|((_, a), (_, b))| a != b)
            }
            None => self.source_outer.is_none(),
        };
        own_outer
            && source_path
            && self.outer_fingerprint != Some([0; 32])
            && (source.nested.is_some() || self.outer_fingerprint.is_some())
            && self.source_outer.as_ref().is_none_or(|outer| {
                self.outer_fingerprint.is_some()
                    && outer.fingerprint != [0; 32]
                    && binds_direct_outer(&outer.owner, source, &self.owner)
                    && distinct_owner(&outer.owner, &self.outer)
            })
            && self.owner.valid()
            && self.owner.id == target
            && self.owner.iface == iface
            && self.owner.boot == source.boot
            && distinct_owner(&self.owner, source)
            && binds_direct_outer(&self.outer, source, &self.owner)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TemporaryStop {
    target_fingerprint: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cold_reserve_primary: Option<SocketAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target_owner: Option<NativeRemovalSeal>,
    wan: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transport_policy: Option<TransportPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    named: Option<SealedTransportPair>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rotation: Option<named_rotation::Rotation>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    deferred_launch: bool,
    #[serde(default)]
    released: bool,
    #[serde(default)]
    teardown: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransportPolicy {
    source: [u8; 32],
    target: [u8; 32],
}

#[derive(Debug, Eq, PartialEq)]
pub struct ActiveReplacementLaunchCleanup {
    pub target: NativeRemovalSeal,
    pub stop: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColdNumericStartup {
    pub owner: NativeRemovalSeal,
    pub binding: [u8; 32],
    committed: String,
}

/// The startup socket can carry its committed IPv4 selectors until its first
/// handshake. It cannot authorize a new policy, revision or process owner.
pub fn cold_numeric_startup(db: &Store, iface: &str) -> io::Result<Option<ColdNumericStartup>> {
    let proof: ColdNumericStartup = match db.read_runtime(COLD_NUMERIC_STARTUP, LAUNCH_LIMIT) {
        Ok(proof) => proof,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if proof.owner.iface != iface {
        return Ok(None);
    }
    let journal = Journal::read(db)?;
    let doc = nfqws2_awg_profile::read(db)?;
    let revision = journal.committed.revision;
    if !proof.owner.valid()
        || proof.owner.nested.is_some()
        || journal.boot != proof.owner.boot
        || journal.expires != 0
        || !journal.preparing.is_empty()
        || journal
            .committed
            .targets
            .get(iface)
            .is_none_or(|target| target.id != proof.owner.id)
        || doc["routing_revision"].as_u64() != Some(revision)
        || !profile_rebind::owner_matches_all(&doc, &journal, [&*proof.owner.id], revision)
        || profile_rebind::digest(&journal.committed)? != proof.committed
    {
        return Ok(None);
    }
    Ok(Some(proof))
}

fn ineligible() -> io::Error {
    err("активный перенос требует двух подтверждённых AWG и непересекающихся IPv4 CIDR")
}

fn packed_ipv4_target(journal: &Journal) -> io::Result<(&str, &plan::Target)> {
    let p = &journal.installed;
    let Some((_, iface)) = p.prefixes.first_key_value() else {
        return Err(ineligible());
    };
    if journal.expires != 0
        || !journal.preparing.is_empty()
        || p != &journal.committed
        || p.targets.len() != 1
        || p.marks.len() != 1
        || !p
            .marks
            .get(iface)
            .is_some_and(|slot| matches!(*slot, 1..=128))
        || p.permanent_fences.iter().any(|owner| owner != iface)
        || p.prefixes.iter().enumerate().any(|(i, (prefix, next))| {
            prefix.any()
                || prefix.family() != plan::Family::V4
                || next != iface
                || p.prefixes
                    .keys()
                    .skip(i + 1)
                    .any(|other| prefix.overlaps(*other))
        })
        || **p
            != (Plan {
                prefixes: p.prefixes.clone(),
                targets: p.targets.clone(),
                mss: p.mss.clone(),
                packed: true,
                marks: p.marks.clone(),
                permanent_fences: p.permanent_fences.clone(),
                revision: p.revision,
                killswitch: p.killswitch,
                ..Plan::default()
            })
    {
        return Err(ineligible());
    }
    Ok((iface, p.targets.get(iface).ok_or_else(ineligible)?))
}

fn replacement_route_target(journal: &Journal) -> io::Result<(&str, &plan::Target)> {
    if journal.installed.learned.is_some() {
        observed_ipv4_target(journal)
    } else if !journal.installed.marks.is_empty() {
        packed_ipv4_target(journal)
    } else if journal.installed.scoped.is_empty() {
        profile_rebind::native_ipv4_prefixes(journal)
    } else {
        scoped_ipv4_target(journal)
    }
}

fn observed_ipv4_target(journal: &Journal) -> io::Result<(&str, &plan::Target)> {
    let p = &journal.installed;
    if p != &journal.committed || p.learned.is_none() {
        return Err(ineligible());
    }
    if let Some(mixed) = mixed_dns_plan(p)? {
        return mixed_dns_target(journal, mixed);
    }
    let members = live_dns_members(p)?;
    let source = observed_dns_source(p)?;
    let mut anchors = p.as_ref().clone();
    anchors.learned = None;
    anchors.dns_bridges.clear();
    if let Some(source) = source {
        anchors.scoped.retain(|(selector, _)| {
            selector.source != source
                || !members
                    .iter()
                    .any(|member| selector.dest == Prefix::host(member.ip))
        });
    }
    let anchor: Snapshot = anchors.into();
    let projected = Journal {
        installed: anchor.clone(),
        committed: anchor,
        ..journal.clone()
    };
    let (iface, _) = if source.is_some() {
        scoped_ipv4_target(&projected)?
    } else {
        profile_rebind::native_ipv4_prefixes(&projected)?
    };
    p.targets
        .get_key_value(iface)
        .map(|(iface, target)| (iface.as_str(), target))
        .ok_or_else(ineligible)
}

/// Detect the exact dynamic owner before its profile callback takes client
/// and Store locks. The route operation holds its existing outer lock.
pub fn active_replacement_dns_redirects(
    db: &Store,
    source: &str,
) -> io::Result<Option<(u64, Vec<String>)>> {
    let journal = Journal::read(db)?;
    if journal.committed.learned.is_none()
        || !journal
            .committed
            .targets
            .values()
            .any(|target| target.id == source)
    {
        return Ok(None);
    }
    observed_ipv4_target(&journal)?;
    if !live_dns_members(&journal.installed)?.is_empty() {
        return Err(ineligible());
    }
    Ok(Some((
        journal.installed.revision,
        journal.installed.dns_bridges.clone(),
    )))
}

fn live_dns_members(plan: &Plan) -> io::Result<&[learning::Member]> {
    let Some(saved) = &plan.learned else {
        return Ok(&[]);
    };
    let Some(first) = saved.members.first() else {
        return Ok(&[]);
    };
    let routing = saved.routing()?;
    if let Some(mixed) = mixed_dns_plan(plan)? {
        valid_mixed_dns_members(plan, &routing, mixed, &saved.members)?;
        return Ok(&saved.members);
    }
    let [zone] = routing.zones.as_slice() else {
        return Err(ineligible());
    };
    let source = observed_dns_source(plan)?;
    if plan.dns_bridges.is_empty()
        || !zone.enabled
        || source.is_none() && !zone.source_ips.is_empty()
        || zone.ips.is_empty()
        || zone.domains.iter().any(|entry| crate::model::ipish(entry))
        || saved.members.len() > 128
    {
        return Err(ineligible());
    }
    let declared = zone
        .ips
        .iter()
        .map(|entry| entry.parse())
        .collect::<io::Result<Vec<Prefix>>>()?;
    if saved.members.iter().any(|member| {
        member.zone != 0
            || !member.ip.is_ipv4()
            || member.until != first.until
            || !learned_host_selector(plan, source, member.ip)
            || declared.iter().any(|prefix| prefix.contains(member.ip))
    }) {
        return Err(ineligible());
    }
    Ok(&saved.members)
}

fn observed_dns_source(plan: &Plan) -> io::Result<Option<Prefix>> {
    if plan.scoped.is_empty() {
        return Ok(None);
    }
    let routing = plan.learned.as_ref().ok_or_else(ineligible)?.routing()?;
    let [zone] = routing.zones.as_slice() else {
        return Err(ineligible());
    };
    let source = exact_ipv4_client(&zone.source_ips).ok_or_else(ineligible)?;
    if !zone.enabled
        || zone.waiting_for_connection
        || zone.ips.is_empty()
        || plan.dns_bridges.is_empty()
        || plan
            .scoped
            .iter()
            .any(|(selector, _)| selector.source != source)
    {
        return Err(ineligible());
    }
    Ok(Some(source))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MixedDnsSources {
    client_zone: usize,
    client: Prefix,
    independent: bool,
}

const RETIRED_FIRMWARE_MEMBER: u64 = 0;
pub(super) const RETAINED_FIRMWARE_MEMBER: u64 = u64::MAX;

fn mixed_dns_plan(plan: &Plan) -> io::Result<Option<MixedDnsSources>> {
    if plan.scoped.is_empty() || plan.learned.is_none() {
        return Ok(None);
    }
    let routing = plan.learned.as_ref().ok_or_else(ineligible)?.routing()?;
    let Some(mixed) = mixed_dns_sources(&routing) else {
        return Ok(None);
    };
    if plan.dns_bridges.is_empty()
        || plan.scoped.iter().any(|(selector, _)| {
            selector.source != mixed.client && selector.source != plan::Family::V4.any()
        })
    {
        return Err(ineligible());
    }
    Ok(Some(mixed))
}

fn dns_zone_target(plan: &Plan, zone: usize) -> io::Result<(&str, &plan::Target)> {
    let routing = plan.learned.as_ref().ok_or_else(ineligible)?.routing()?;
    let id = &routing.zones.get(zone).ok_or_else(ineligible)?.tunnel_id;
    plan.targets
        .iter()
        .find(|(_, target)| &target.id == id)
        .map(|(iface, target)| (iface.as_str(), target))
        .ok_or_else(ineligible)
}

fn independent_dns_peer(plan: &Plan) -> io::Result<Option<(&str, &plan::Target)>> {
    mixed_dns_plan(plan)?
        .filter(|mixed| mixed.independent)
        .map(|mixed| dns_zone_target(plan, 1 - mixed.client_zone))
        .transpose()
}

fn valid_mixed_dns_members(
    plan: &Plan,
    routing: &crate::Routing,
    mixed: MixedDnsSources,
    members: &[learning::Member],
) -> io::Result<()> {
    let declared = routing
        .zones
        .iter()
        .flat_map(|zone| &zone.ips)
        .map(|entry| entry.parse::<Prefix>())
        .collect::<io::Result<Vec<_>>>()?;
    let mut seen = BTreeSet::new();
    if members.len() > 128
        || members.iter().any(|member| {
            member.zone >= routing.zones.len()
                || !member.ip.is_ipv4()
                || !matches!(
                    member.until,
                    RETAINED_FIRMWARE_MEMBER | RETIRED_FIRMWARE_MEMBER
                )
                || !seen.insert(member.ip)
                || declared.iter().any(|prefix| prefix.contains(member.ip))
                || !learned_host_selector(plan, Some(mixed.selector_source(member.zone)), member.ip)
        })
    {
        return Err(ineligible());
    }
    Ok(())
}

fn mixed_dns_target(
    journal: &Journal,
    mixed: MixedDnsSources,
) -> io::Result<(&str, &plan::Target)> {
    let installed = &journal.installed;
    let saved = installed.learned.as_ref().ok_or_else(ineligible)?;
    valid_mixed_dns_members(installed, &saved.routing()?, mixed, &saved.members)?;
    let mut anchors = installed.as_ref().clone();
    anchors.learned = None;
    anchors.dns_bridges.clear();
    anchors.scoped.retain(|(selector, _)| {
        !saved.members.iter().any(|member| {
            selector.source == mixed.selector_source(member.zone)
                && selector.dest == Prefix::host(member.ip)
        })
    });
    if ![mixed.client, plan::Family::V4.any()]
        .into_iter()
        .all(|source| {
            anchors
                .scoped
                .iter()
                .any(|(selector, _)| selector.source == source)
        })
    {
        return Err(ineligible());
    }
    let anchor: Snapshot = anchors.into();
    let projected = Journal {
        installed: anchor.clone(),
        committed: anchor,
        ..journal.clone()
    };
    exact_scoped_ipv4_target(&projected, true, mixed.target_count())?;
    let client = dns_zone_target(installed, mixed.client_zone)?;
    let (global, _) = dns_zone_target(installed, 1 - mixed.client_zone)?;
    if installed.scoped.iter().any(|(selector, iface)| {
        iface
            != if selector.source == mixed.client {
                client.0
            } else {
                global
            }
    }) {
        return Err(ineligible());
    }
    Ok(client)
}

impl MixedDnsSources {
    fn target_count(self) -> usize {
        if self.independent {
            2
        } else {
            1
        }
    }
    fn source(self, zone: usize) -> Option<Prefix> {
        (zone == self.client_zone).then_some(self.client)
    }

    fn selector_source(self, zone: usize) -> Prefix {
        self.source(zone).unwrap_or_else(|| plan::Family::V4.any())
    }
}

fn mixed_dns_sources(routing: &crate::Routing) -> Option<MixedDnsSources> {
    let [first, second] = routing.zones.as_slice() else {
        return None;
    };
    let (client_zone, client) = match (first.source_ips.is_empty(), second.source_ips.is_empty()) {
        (true, false) => (1, exact_ipv4_client(&second.source_ips)?),
        (false, true) => (0, exact_ipv4_client(&first.source_ips)?),
        _ => return None,
    };
    if [first, second].into_iter().any(|zone| {
        !zone.enabled
            || zone.waiting_for_connection
            || zone.direction() != "tunnel"
            || !zone.fallback_tunnel_ids.is_empty()
            || zone.ips.is_empty()
            || zone.domains.is_empty()
            || zone.dns_catch_all()
            || zone.domains.iter().any(|entry| crate::model::ipish(entry))
    }) {
        return None;
    }
    let anchors = |zone: &crate::Zone| {
        zone.ips
            .iter()
            .map(|entry| {
                entry
                    .parse::<Prefix>()
                    .ok()
                    .filter(|p| p.family() == plan::Family::V4)
            })
            .collect::<Option<Vec<_>>>()
    };
    let a = anchors(first)?;
    let b = anchors(second)?;
    (!a.iter().any(|p| b.iter().any(|q| p.overlaps(*q)))).then_some(MixedDnsSources {
        client_zone,
        client,
        independent: first.tunnel_id != second.tunnel_id,
    })
}

pub(super) fn retains_mixed_firmware_member(
    journal: &Journal,
    doc: &Value,
    routing: &crate::Routing,
    answer: &learning::Answer<'_>,
    origin: learning::DnsOrigin<'_>,
    name: Option<&str>,
) -> io::Result<bool> {
    let live = mixed_dns_sources(routing).map(|scopes| (scopes, scopes.target_count()));
    let (Some((scopes, targets)), Some(name), Some(client), Some(bridge)) = (
        live.or_else(|| disabled::parked_dns_scope(doc, journal, routing).map(|scope| (scope, 1))),
        name,
        origin.client,
        origin.ingress,
    ) else {
        return Ok(false);
    };
    let plan = &journal.installed;
    let client = client.to_canonical();
    if answer.qtype != 1
        || answer.ttl == 0
        || client.is_loopback()
        || !client.is_ipv4()
        || journal.expires != 0
        || **plan != *journal.committed
        || !plan.fully_live()
        || !plan.dns_bridges.iter().any(|name| name == bridge)
        || plan.targets.len() != targets
        || !plan.marks.is_empty()
        || answer.zone >= routing.zones.len()
        || scopes
            .source(answer.zone)
            .is_some_and(|source| !source.contains(client))
    {
        return Ok(false);
    }
    let matcher = crate::observed::Policy::compile(routing)?;
    Ok(matcher.matched(name, Some(client)) == Some(answer.zone)
        && matcher.archive_zones(name, 1).eq([answer.zone]))
}

fn exact_ipv4_client(sources: &[String]) -> Option<Prefix> {
    let [source] = sources else {
        return None;
    };
    let source: Prefix = source.parse().ok()?;
    (source.is_host() && source.family() == plan::Family::V4 && source.safe()).then_some(source)
}

fn learned_host_selector(plan: &Plan, source: Option<Prefix>, ip: IpAddr) -> bool {
    let dest = Prefix::host(ip);
    source.map_or_else(
        || plan.prefixes.contains_key(&dest),
        |source| {
            plan.scoped
                .binary_search_by_key(&plan::Selector { source, dest }, |(selector, _)| *selector)
                .is_ok()
        },
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveDnsReplacement {
    prior: Journal,
    source: String,
    client: Option<IpAddr>,
    mixed: Option<MixedDnsSources>,
    held_profile: Option<String>,
}

pub struct FirmwareDnsGroup {
    pub zone: usize,
    pub client: Option<IpAddr>,
    pub addresses: Vec<IpAddr>,
}

#[derive(Default)]
pub struct FirmwareDnsArchive {
    pub discovered: BTreeSet<String>,
    pub replay: std::collections::BTreeMap<String, Vec<IpAddr>>,
}

#[derive(Clone, Copy)]
pub struct FirmwareDnsGroupProof<'a> {
    pub zone: usize,
    pub name: &'a str,
    pub origin: learning::DnsOrigin<'a>,
    pub answer: FirmwareDnsGroupAnswer<'a>,
}

#[derive(Clone, Copy)]
pub enum FirmwareDnsGroupAnswer<'a> {
    Addresses(&'a [IpAddr]),
    FreshAddresses {
        addresses: &'a [IpAddr],
        valid_until: Instant,
    },
    /// The verified cold lookup rejected an exact name for the group.
    NxDomain,
}

impl ActiveDnsReplacement {
    pub fn revision(&self) -> u64 {
        self.prior.installed.revision
    }

    pub fn bridges(&self) -> &[String] {
        &self.prior.installed.dns_bridges
    }

    pub fn client(&self) -> Option<IpAddr> {
        self.client
    }

    pub fn firmware_groups(&self) -> Option<Vec<FirmwareDnsGroup>> {
        let mixed = self.mixed?;
        Some(
            self.members()
                .chunk_by(|a, b| a.zone == b.zone)
                .filter(|members| !mixed.independent || members[0].zone == mixed.client_zone)
                .map(|members| {
                    let zone = members[0].zone;
                    FirmwareDnsGroup {
                        zone,
                        client: mixed.source(zone).map(Prefix::sample),
                        addresses: members.iter().map(|member| member.ip).collect(),
                    }
                })
                .collect(),
        )
    }

    pub fn held_profile(&self) -> Option<&str> {
        self.held_profile.as_deref()
    }

    pub fn addresses(&self) -> Vec<IpAddr> {
        self.members().iter().map(|member| member.ip).collect()
    }

    fn members(&self) -> &[learning::Member] {
        &self
            .prior
            .installed
            .learned
            .as_ref()
            .expect("verified learner")
            .members
    }

    pub fn matches_name(&self, name: &str) -> io::Result<bool> {
        if self.mixed.is_some() {
            return Ok(false);
        }
        let saved = self
            .prior
            .installed
            .learned
            .as_ref()
            .ok_or_else(ineligible)?;
        let matcher = crate::observed::Policy::compile(&saved.routing()?)?;
        Ok(matcher.archive_zones(name, 1).eq([0])
            && self.client.is_none_or(|client| {
                matcher.matched(name, Some(client)) == Some(0)
                    && matcher.matched(name, None).is_none()
            }))
    }

    /// The panel admits only a fresh firmware RRset in the captured source
    /// window. Recheck the complete matching destination set inside Rules.
    pub fn revalidate(
        self,
        name: &str,
        addresses: &[IpAddr],
        ttl: u32,
    ) -> io::Result<ActiveDnsReplacementProof> {
        self.revalidate_from(
            name,
            addresses,
            ttl,
            learning::DnsOrigin {
                client: None,
                ingress: None,
            },
        )
    }

    pub fn revalidate_from(
        self,
        name: &str,
        addresses: &[IpAddr],
        ttl: u32,
        origin: learning::DnsOrigin<'_>,
    ) -> io::Result<ActiveDnsReplacementProof> {
        if self.client.is_some_and(|client| {
            origin.client.map(|address| address.to_canonical()) != Some(client)
                || !origin
                    .ingress
                    .is_some_and(|bridge| self.bridges().iter().any(|allowed| allowed == bridge))
        }) {
            return Err(ineligible());
        }
        let mut addresses = addresses.to_vec();
        addresses.sort_unstable();
        addresses.dedup();
        let now = nfqws2_awg_profile::now();
        let until = self.members()[0]
            .until
            .min(now.saturating_add(u64::from(ttl)));
        if addresses != self.addresses() || until <= now || !self.matches_name(name)? {
            return Err(ineligible());
        }
        let mut renewed = self.members().to_vec();
        for member in &mut renewed {
            member.until = until;
        }
        Ok(ActiveDnsReplacementProof {
            request: self,
            renewed,
            fresh_until: None,
            retry_names: None,
            positive_until: None,
            confirmed_negative: None,
            named_positives: Vec::new(),
        })
    }

    pub fn matches_firmware_group(&self, zone: usize, name: &str) -> io::Result<bool> {
        let Some(mixed) = self.mixed else {
            return Ok(false);
        };
        let saved = self
            .prior
            .installed
            .learned
            .as_ref()
            .ok_or_else(ineligible)?;
        let matcher = crate::observed::Policy::compile(&saved.routing()?)?;
        Ok(Self::firmware_name_matches(&matcher, mixed, zone, name))
    }

    fn firmware_name_matches(
        matcher: &crate::observed::Policy,
        mixed: MixedDnsSources,
        zone: usize,
        name: &str,
    ) -> bool {
        let client = mixed.source(zone).map(Prefix::sample);
        zone < 2
            && matcher.matched(name, client) == Some(zone)
            && matcher.archive_zones(name, 1).eq([zone])
    }

    fn explicit_firmware_name(
        canonical: &str,
        include_subdomains: Option<bool>,
        matcher: &crate::observed::Policy,
        mixed: MixedDnsSources,
        zone: usize,
    ) -> Option<String> {
        let explicit = canonical.strip_prefix("full:");
        let name = explicit.unwrap_or(canonical).trim().trim_end_matches('.');
        let exact =
            include_subdomains == Some(false) || include_subdomains.is_none() && explicit.is_some();
        (exact && Self::valid_firmware_literal(matcher, mixed, zone, name)).then(|| name.to_owned())
    }

    fn valid_firmware_literal(
        matcher: &crate::observed::Policy,
        mixed: MixedDnsSources,
        zone: usize,
        name: &str,
    ) -> bool {
        name.contains('.')
            && crate::model::hostname(name)
            && Self::firmware_name_matches(matcher, mixed, zone, name)
    }

    /// Recover the complete set only when every name in the installed group
    /// is explicit, finite and uniquely matched to that group's source.
    pub fn configured_firmware_names(&self, zone: usize) -> io::Result<Option<BTreeSet<String>>> {
        let Some(mixed) = self.mixed else {
            return Ok(None);
        };
        let saved = self
            .prior
            .installed
            .learned
            .as_ref()
            .ok_or_else(ineligible)?;
        let routing = saved.routing()?;
        let Some(configured) = routing.zones.get(zone) else {
            return Ok(None);
        };
        let matcher = crate::observed::Policy::compile(&routing)?;
        let mut names = BTreeSet::new();
        for raw in &configured.domains {
            let canonical = raw.trim().to_ascii_lowercase();
            let Some(name) = Self::explicit_firmware_name(
                &canonical,
                configured.include_subdomains,
                &matcher,
                mixed,
                zone,
            ) else {
                return Ok(None);
            };
            names.insert(name);
        }
        Ok((!names.is_empty()).then_some(names))
    }

    /// Pre-resolve configured names and discoveries that still match this group.
    /// A legacy suffix supplies its apex. A mask alone supplies no hostname.
    pub fn archived_firmware_names(
        &self,
        zone: usize,
        archive: &FirmwareDnsArchive,
    ) -> io::Result<Option<BTreeSet<String>>> {
        let Some(mixed) = self.mixed.filter(|_| self.held_profile.is_none()) else {
            return Ok(None);
        };
        let saved = self
            .prior
            .installed
            .learned
            .as_ref()
            .ok_or_else(ineligible)?;
        let routing = saved.routing()?;
        let Some(configured) = routing.zones.get(zone) else {
            return Ok(None);
        };
        if archive.discovered.len() > 128 || archive.replay.len() > 4096 {
            return Ok(None);
        }
        let matcher = crate::observed::Policy::compile(&routing)?;
        let legacy_single_suffix =
            configured.domains.len() == 1 && configured.include_subdomains.is_none();
        let mut names = BTreeSet::new();
        let mut uses_discoveries = false;
        for raw in &configured.domains {
            let canonical = raw.trim().to_ascii_lowercase();
            if canonical.starts_with("[re]") || canonical.contains(['*', '#']) {
                uses_discoveries = true;
                continue;
            }
            let name = match Self::explicit_firmware_name(
                &canonical,
                configured.include_subdomains,
                &matcher,
                mixed,
                zone,
            ) {
                Some(name) => name,
                None if legacy_single_suffix => {
                    let Some(apex) = crate::observed::plain_rule_literal(&canonical, None)
                        .filter(|apex| Self::valid_firmware_literal(&matcher, mixed, zone, apex))
                    else {
                        return Ok(None);
                    };
                    uses_discoveries = true;
                    apex.to_owned()
                }
                None => return Ok(None),
            };
            names.insert(name);
        }
        if !uses_discoveries || (!names.is_empty() && mixed.source(zone).is_some()) {
            return Ok(None);
        }
        names.extend(
            archive
                .discovered
                .iter()
                .filter(|name| {
                    crate::model::hostname(name)
                        && Self::firmware_name_matches(&matcher, mixed, zone, name)
                })
                .cloned(),
        );
        Ok((names.len() <= 128).then_some(names))
    }

    fn archived_firmware_addresses(
        &self,
        group: &FirmwareDnsGroup,
        archive: &FirmwareDnsArchive,
    ) -> io::Result<BTreeSet<IpAddr>> {
        let mut addresses = BTreeSet::new();
        if group.client.is_some() {
            return Ok(addresses);
        }
        let mixed = self.mixed.ok_or_else(ineligible)?;
        let saved = self
            .prior
            .installed
            .learned
            .as_ref()
            .ok_or_else(ineligible)?;
        let matcher = crate::observed::Policy::compile(&saved.routing()?)?;
        for (name, replay) in &archive.replay {
            if crate::model::hostname(name)
                && Self::firmware_name_matches(&matcher, mixed, group.zone, name)
            {
                addresses.extend(
                    replay
                        .iter()
                        .copied()
                        .filter(|ip| group.addresses.binary_search(ip).is_ok()),
                );
            }
        }
        Ok(addresses)
    }

    fn revalidated_firmware_union(
        &self,
        group: &FirmwareDnsGroup,
        proofs: &[FirmwareDnsGroupProof<'_>],
        archive: Option<&FirmwareDnsArchive>,
    ) -> io::Result<(Vec<IpAddr>, Option<Instant>)> {
        let names: BTreeSet<_> = proofs.iter().map(|proof| proof.name).collect();
        let warm = !proofs.is_empty()
            && proofs
                .iter()
                .all(|proof| matches!(proof.answer, FirmwareDnsGroupAnswer::Addresses(_)));
        let configured = self.configured_firmware_names(group.zone)?;
        let complete = |configured: &BTreeSet<String>| {
            names
                .iter()
                .copied()
                .eq(configured.iter().map(String::as_str))
        };
        let explicit = configured.as_ref().is_some_and(complete);
        let archived = match archive.filter(|_| !warm && !explicit) {
            Some(archive) => self
                .archived_firmware_names(group.zone, archive)?
                .filter(complete)
                .map(|_| archive),
            None => None,
        };
        let identified = explicit || archived.is_some();
        if proofs.is_empty() && archived.is_none()
            || names.len() != proofs.len()
            || !warm
                && !identified
                && (proofs.len() != 1 || configured.is_some_and(|names| names.len() > 1))
        {
            return Err(ineligible());
        }
        let may_change = group.client.is_some() || self.held_profile.is_none() && identified;
        let mut union = match archived {
            Some(archive) => self.archived_firmware_addresses(group, archive)?,
            None => BTreeSet::new(),
        };
        let mut fresh_until = None::<Instant>;
        for proof in proofs {
            let origin_matches = match proof.origin.client {
                Some(ip) => {
                    let client = ip.to_canonical();
                    client.is_ipv4()
                        && !client.is_loopback()
                        && group.client.is_none_or(|expected| expected == client)
                }
                None => {
                    self.held_profile.is_none() && group.client.is_none() && !warm && identified
                }
            };
            let ingress_matches = proof.origin.ingress.map_or(!warm && identified, |bridge| {
                self.bridges().iter().any(|name| name == bridge)
            });
            if !origin_matches
                || !ingress_matches
                || !identified && !self.matches_firmware_group(group.zone, proof.name)?
            {
                return Err(ineligible());
            }
            match proof.answer {
                FirmwareDnsGroupAnswer::Addresses(addresses) if warm => {
                    union.extend(addresses.iter().copied());
                }
                FirmwareDnsGroupAnswer::Addresses(_) => return Err(ineligible()),
                FirmwareDnsGroupAnswer::FreshAddresses {
                    addresses,
                    valid_until,
                } => {
                    if valid_until <= Instant::now() {
                        return Err(io::ErrorKind::TimedOut.into());
                    }
                    if addresses.is_empty()
                        || addresses.len() > 128
                        || addresses
                            .iter()
                            .any(|&ip| !ip.is_ipv4() || !Prefix::host(ip).safe())
                    {
                        return Err(ineligible());
                    }
                    fresh_until =
                        Some(fresh_until.map_or(valid_until, |previous| previous.min(valid_until)));
                    union.extend(addresses.iter().copied());
                    if union.len() > 128 {
                        return Err(ineligible());
                    }
                }
                FirmwareDnsGroupAnswer::NxDomain if may_change => {}
                FirmwareDnsGroupAnswer::NxDomain => return Err(ineligible()),
            }
        }
        let addresses: Vec<_> = union.into_iter().collect();
        if addresses != group.addresses && (warm || !may_change) {
            return Err(ineligible());
        }
        Ok((addresses, fresh_until))
    }

    pub fn revalidate_firmware_groups(
        self,
        proofs: &[FirmwareDnsGroupProof<'_>],
    ) -> io::Result<ActiveDnsReplacementProof> {
        self.revalidate_firmware_groups_with_archive(proofs, None)
    }

    pub fn revalidate_firmware_groups_with_archive(
        self,
        mut proofs: &[FirmwareDnsGroupProof<'_>],
        archive: Option<&FirmwareDnsArchive>,
    ) -> io::Result<ActiveDnsReplacementProof> {
        let groups = self.firmware_groups().ok_or_else(ineligible)?;
        let retry_names = if self.held_profile.is_some()
            && groups.len() == 1
            && groups[0].client.is_some()
            && proofs
                .iter()
                .any(|proof| !matches!(proof.answer, FirmwareDnsGroupAnswer::Addresses(_)))
        {
            Some(
                proofs
                    .iter()
                    .map(|proof| proof.name.to_owned())
                    .collect::<Vec<_>>(),
            )
        } else {
            None
        };
        let confirmed_negative = match proofs {
            [first, second] if retry_names.is_some() => match (first.answer, second.answer) {
                (
                    FirmwareDnsGroupAnswer::FreshAddresses { .. },
                    FirmwareDnsGroupAnswer::NxDomain,
                ) => Some(second.name.to_owned()),
                (
                    FirmwareDnsGroupAnswer::NxDomain,
                    FirmwareDnsGroupAnswer::FreshAddresses { .. },
                ) => Some(first.name.to_owned()),
                _ => None,
            },
            _ => None,
        };
        let named_positives = if retry_names.as_ref().is_some_and(|names| names.len() == 2) {
            proofs
                .iter()
                .filter_map(|proof| {
                    if matches!(proof.answer, FirmwareDnsGroupAnswer::FreshAddresses { .. }) {
                        NamedPositiveObservation::capture(proof.name)
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            Vec::new()
        };
        let mut renewed = self.members().to_vec();
        let mut fresh_until = None::<Instant>;
        for group in groups {
            let group_end = proofs
                .iter()
                .take_while(|proof| proof.zone == group.zone)
                .count();
            let (group_proofs, rest) = proofs.split_at(group_end);
            proofs = rest;
            let (addresses, until) =
                self.revalidated_firmware_union(&group, group_proofs, archive)?;
            if let Some(until) = until {
                fresh_until = Some(fresh_until.map_or(until, |previous| previous.min(until)));
            }
            for member in renewed
                .iter_mut()
                .filter(|member| member.zone == group.zone)
            {
                if addresses.binary_search(&member.ip).is_err() {
                    member.until = RETIRED_FIRMWARE_MEMBER;
                }
            }
            renewed.extend(
                addresses
                    .into_iter()
                    .filter(|ip| group.addresses.binary_search(ip).is_err())
                    .map(|ip| learning::Member {
                        zone: group.zone,
                        ip,
                        until: RETAINED_FIRMWARE_MEMBER,
                    }),
            );
        }
        renewed.sort_unstable_by_key(|member| (member.zone, member.ip));
        let mut unique = BTreeSet::new();
        if !proofs.is_empty()
            || renewed.len() > 128
            || renewed.iter().any(|member| !unique.insert(member.ip))
        {
            return Err(ineligible());
        }
        let positive_until = if fresh_until.is_some()
            && retry_names.as_ref().is_some_and(|names| names.len() == 1)
        {
            PositiveUntil::capture()
        } else {
            None
        };
        Ok(ActiveDnsReplacementProof {
            request: self,
            renewed,
            fresh_until,
            retry_names,
            positive_until,
            confirmed_negative,
            named_positives,
        })
    }
}

pub struct ActiveDnsReplacementProof {
    request: ActiveDnsReplacement,
    renewed: Vec<learning::Member>,
    fresh_until: Option<Instant>,
    retry_names: Option<Vec<String>>,
    positive_until: Option<PositiveUntil>,
    confirmed_negative: Option<String>,
    named_positives: Vec<NamedPositiveObservation>,
}

impl ActiveDnsReplacementProof {
    pub fn request(&self) -> &ActiveDnsReplacement {
        &self.request
    }
}

pub fn active_replacement_dns_revalidation(
    db: &Store,
    source: &str,
) -> io::Result<Option<ActiveDnsReplacement>> {
    replacement_dns_request(Journal::read(db)?, source)
}

fn replacement_dns_request(
    journal: Journal,
    source: &str,
) -> io::Result<Option<ActiveDnsReplacement>> {
    if journal.committed.learned.is_none()
        || !journal
            .committed
            .targets
            .values()
            .any(|target| target.id == source)
    {
        return Ok(None);
    }
    let (_, owner) = observed_ipv4_target(&journal)?;
    if owner.id != source {
        return Err(ineligible());
    }
    let members = live_dns_members(&journal.installed)?;
    if members.is_empty() {
        return Ok(None);
    }
    if members[0].until <= nfqws2_awg_profile::now() {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    let mixed = mixed_dns_plan(&journal.installed)?;
    let held_profile = independent_dns_peer(&journal.installed)?.map(|(_, peer)| peer.id.clone());
    let client = if mixed.is_none() {
        observed_dns_source(&journal.installed)?.map(Prefix::sample)
    } else {
        None
    };
    Ok(Some(ActiveDnsReplacement {
        prior: journal,
        source: source.to_owned(),
        client,
        mixed,
        held_profile,
    }))
}

fn retry_scope(
    transfer: &Transfer,
    names: &[String],
) -> io::Result<(ActiveDnsReplacement, usize, IpAddr)> {
    let request = replacement_dns_request(transfer.prior.clone(), &transfer.source.id)?
        .ok_or_else(ineligible)?;
    let groups = request.firmware_groups().ok_or_else(ineligible)?;
    let [group] = groups.as_slice() else {
        return Err(ineligible());
    };
    let client = group.client.ok_or_else(ineligible)?;
    let mut unique = BTreeSet::new();
    if request.held_profile().is_none() || names.is_empty() || names.len() > 128 {
        return Err(ineligible());
    }
    for name in names {
        if !crate::model::hostname(name)
            || !unique.insert(name.as_str())
            || !request.matches_firmware_group(group.zone, name)?
        {
            return Err(ineligible());
        }
    }
    Ok((request, group.zone, client))
}

/// Exact still-pending DNS work. The originally confirmed scope and saved
/// draft bind every lookup, independently of how the firmware answers change.
#[derive(Clone, Eq, PartialEq)]
pub struct ActiveReplacementDnsRetry {
    token: String,
    policy: String,
    names: Vec<String>,
    request: ActiveDnsReplacement,
    zone: usize,
    client: IpAddr,
    expected: Vec<learning::Member>,
    positive_hint: Option<RetryPositiveHint>,
    negative_name: Option<ConfirmedNegativeName>,
    positive_pair: Option<PairPositiveHints>,
}

pub struct ActiveReplacementDnsRetryProof {
    basis: ActiveReplacementDnsRetry,
    valid_until: Instant,
    projection: Option<RetryDnsProjection>,
    positive_until: Option<PositiveUntil>,
    invalidate_negative: bool,
    named_positives: Vec<NamedPositiveObservation>,
}

impl ActiveReplacementDnsRetry {
    pub fn names(&self) -> &[String] {
        &self.names
    }
    pub fn bridges(&self) -> &[String] {
        self.request.bridges()
    }

    pub fn revalidate(
        self,
        answers: &[FirmwareDnsGroupAnswer<'_>],
        deadline: Instant,
    ) -> io::Result<ActiveReplacementDnsRetryProof> {
        if Instant::now() >= deadline
            || answers.len() != self.names.len()
            || answers
                .iter()
                .any(|answer| matches!(answer, FirmwareDnsGroupAnswer::Addresses(_)))
        {
            return Err(ineligible());
        }
        let [bridge] = self.bridges() else {
            return Err(ineligible());
        };
        let scoped: Vec<_> = self
            .names
            .iter()
            .zip(answers)
            .map(|(name, answer)| FirmwareDnsGroupProof {
                zone: self.zone,
                name,
                origin: learning::DnsOrigin {
                    client: Some(self.client),
                    ingress: Some(bridge),
                },
                answer: *answer,
            })
            .collect();
        let proof = self.request.clone().revalidate_firmware_groups(&scoped)?;
        let invalidate_negative = self.negative_name.as_ref().is_some_and(|prior| {
            scoped.iter().any(|name| {
                prior.name() == name.name
                    && matches!(name.answer, FirmwareDnsGroupAnswer::FreshAddresses { .. })
            })
        });
        let both_positive = matches!(
            answers,
            [
                FirmwareDnsGroupAnswer::FreshAddresses { .. },
                FirmwareDnsGroupAnswer::FreshAddresses { .. },
            ]
        );
        let projection = if proof.renewed == self.expected {
            None
        } else {
            let expired_positive_name = proof.confirmed_negative.clone().filter(|name| {
                self.positive_pair
                    .as_ref()
                    .is_some_and(|hints| hints.expired(name))
            });
            let withdrawn = match answers {
                [FirmwareDnsGroupAnswer::FreshAddresses { .. }] => false,
                [FirmwareDnsGroupAnswer::NxDomain]
                    if self
                        .positive_hint
                        .as_ref()
                        .is_some_and(RetryPositiveHint::expired) =>
                {
                    true
                }
                [_, _]
                    if both_positive
                        || expired_positive_name.is_some()
                        || self.negative_name.as_ref().is_some_and(|prior| {
                            proof.confirmed_negative.as_deref() == Some(prior.name())
                        }) =>
                {
                    false
                }
                _ => return Err(ineligible()),
            };
            let mut projection = RetryDnsProjection {
                members: proof.renewed,
                withdrawn,
                expired_positive_name,
                both_positive,
                stamp: String::new(),
            };
            projection.stamp = projection.stamp(&self.token)?;
            Some(projection)
        };
        Ok(ActiveReplacementDnsRetryProof {
            projection,
            positive_until: proof.positive_until,
            invalidate_negative,
            named_positives: proof.named_positives,
            basis: self,
            valid_until: proof
                .fresh_until
                .map_or(deadline, |until| until.min(deadline)),
        })
    }
}

impl ActiveReplacementDnsRetryProof {
    pub fn bridges(&self) -> &[String] {
        self.basis.bridges()
    }

    fn check(&self, db: &Store) -> io::Result<()> {
        if Instant::now() >= self.valid_until {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let Some(mut current) = pending_active_replacement_dns_retry(db)? else {
            return Err(io::ErrorKind::Interrupted.into());
        };
        if self.invalidate_negative
            && self
                .projection
                .as_ref()
                .is_none_or(|projection| projection.both_positive)
            && current.negative_name.is_none()
        {
            // The current lookup supplied a positive answer for the prior
            // negative name. Its old negative receipt has been discarded.
            current.negative_name.clone_from(&self.basis.negative_name);
        }
        if current != self.basis {
            return Err(io::ErrorKind::Interrupted.into());
        }
        Ok(())
    }
}

pub fn pending_active_replacement_dns_retry(
    db: &Store,
) -> io::Result<Option<ActiveReplacementDnsRetry>> {
    let Some(transfer) = read(db)? else {
        return Ok(None);
    };
    let Some(names) = transfer.retry_dns.as_deref() else {
        return Ok(None);
    };
    if transfer.retired
        || transfer
            .temporary_stop
            .as_ref()
            .is_none_or(|stop| stop.released || stop.teardown)
    {
        return Ok(None);
    }
    let doc = nfqws2_awg_profile::read(db)?;
    if !committed(&doc, &transfer)
        || doc["routing_revision"].as_u64() != Some(transfer.next.committed.revision)
    {
        return Ok(None);
    }
    let (request, zone, client) = retry_scope(&transfer, names)?;
    Ok(Some(ActiveReplacementDnsRetry {
        token: transfer.token,
        policy: profile_rebind::digest(&crate::policy::current(&doc)?)?,
        names: names.to_vec(),
        request,
        zone,
        client,
        expected: live_dns_members(&transfer.next.installed)?.to_vec(),
        positive_hint: transfer.retry_positive_hint,
        negative_name: transfer.retry_negative_name,
        positive_pair: transfer.retry_positive_pair,
    }))
}

#[derive(Eq, PartialEq)]
pub struct FirmwareRefreshBasis {
    journal: Journal,
    config: String,
}

impl FirmwareRefreshBasis {
    pub fn revision(&self) -> u64 {
        self.journal.installed.revision
    }

    pub fn continue_if_current(&self, db: &Store, carry: impl FnOnce()) -> io::Result<()> {
        db.try_transaction(|_| {
            if firmware_refresh_basis(db)?.as_ref() == Some(self) {
                carry();
            }
            Ok(())
        })
    }
}

/// Only the same installed and confirmed native DNS generation may keep
/// the original source evidence across a successful periodic refresh.
pub fn confirmed_firmware_refresh_basis(db: &Store) -> io::Result<Option<FirmwareRefreshBasis>> {
    db.try_transaction(|_| firmware_refresh_basis(db))
}

fn firmware_refresh_basis(db: &Store) -> io::Result<Option<FirmwareRefreshBasis>> {
    let journal = Journal::read(db)?;
    if journal.boot.is_empty()
        || !journal.installed.fully_live()
        || !live_dns_members(&journal.installed).is_ok_and(|members| {
            members
                .first()
                .is_some_and(|member| member.until > nfqws2_awg_profile::now())
        })
    {
        return Ok(None);
    }
    let Ok((_, target)) = observed_ipv4_target(&journal) else {
        return Ok(None);
    };
    let doc = nfqws2_awg_profile::read(db)?;
    let revision = journal.installed.revision;
    let held = independent_dns_peer(&journal.installed)?.map(|(_, held)| held.id.as_str());
    if doc["routing_revision"].as_u64() != Some(revision)
        || !profile_rebind::owner_matches_all(
            &doc,
            &journal,
            std::iter::once(target.id.as_str()).chain(held),
            revision,
        )
        || profile_rebind::pending(&doc)
        || super::failover_order::pending(&doc)
        || active_replacement_in_progress(db)?
        || super::acceleration::pending(db)?
        || mtu_edit::pending_mtu_edit(db)?
        || mtu_edit::pending_predecessor(db, &doc, &journal)?.is_some()
    {
        return Ok(None);
    }
    Ok(Some(FirmwareRefreshBasis {
        journal,
        config: profile_rebind::digest(&doc)?,
    }))
}

fn scoped_ipv4_target(journal: &Journal) -> io::Result<(&str, &plan::Target)> {
    exact_scoped_ipv4_target(journal, false, 1)
}

fn exact_scoped_ipv4_target(
    journal: &Journal,
    permit_global: bool,
    target_count: usize,
) -> io::Result<(&str, &plan::Target)> {
    let p = &journal.installed;
    let Some((_, iface)) = p.scoped.first() else {
        return Err(ineligible());
    };
    if journal.expires != 0
        || !journal.preparing.is_empty()
        || p != &journal.committed
        || p.targets.len() != target_count
        || p.scoped.iter().enumerate().any(|(i, (selector, target))| {
            (!permit_global && selector.source.any())
                || selector.dest.any()
                || selector.source.family() != plan::Family::V4
                || selector.dest.family() != plan::Family::V4
                || !p.targets.contains_key(target)
                || p.scoped.iter().skip(i + 1).any(|(other, _)| {
                    selector.source.overlaps(other.source) && selector.dest.overlaps(other.dest)
                })
        })
        || **p
            != (Plan {
                scoped: p.scoped.clone(),
                scoped_slots: p.scoped_slots.clone(),
                targets: p.targets.clone(),
                mss: p.mss.clone(),
                revision: p.revision,
                killswitch: p.killswitch,
                ..Plan::default()
            })
    {
        return Err(ineligible());
    }
    Ok((iface, p.targets.get(iface).ok_or_else(ineligible)?))
}

fn unprotected(journal: &Journal) -> bool {
    !journal.installed.killswitch && journal.installed.permanent_fences.is_empty()
}

fn retiring_firmware_members(journal: &Journal) -> bool {
    mixed_dns_plan(&journal.installed).is_ok_and(|mixed| mixed.is_some())
        && journal.installed.learned.as_ref().is_some_and(|saved| {
            saved
                .members
                .iter()
                .any(|member| member.until == RETIRED_FIRMWARE_MEMBER)
        })
}

fn packed_transport_roles(
    prior: &Journal,
    next: &Journal,
    source: &NativeRemovalSeal,
    nested_target: Option<&NestedTarget>,
    retiring_nested: Option<&RetiringNested>,
) -> bool {
    if prior.installed.learned.is_some() || next.installed.learned.is_some() {
        return prior.installed.learned.is_some()
            && next.installed.learned.is_some()
            && source.nested.is_none()
            && nested_target.is_none()
            && retiring_nested.is_none();
    }
    if prior.installed.marks.is_empty() && next.installed.marks.is_empty() {
        return retiring_nested.is_none()
            && (prior.installed.scoped.is_empty() && next.installed.scoped.is_empty()
                || source.nested.is_none() && nested_target.is_none());
    }
    let source_permanent = !prior.installed.permanent_fences.is_empty();
    let target_permanent = !next.installed.permanent_fences.is_empty();
    source.nested.is_some() == source_permanent
        && match (source_permanent, target_permanent) {
            (_, true) => {
                retiring_nested.is_none()
                    && nested_target
                        .is_some_and(|target| target.source_outer.is_some() == source_permanent)
            }
            (true, false) => nested_target.is_none() && retiring_nested.is_some(),
            (false, false) => false,
        }
}

fn added_firmware_stops(
    prior: &Plan,
    next: &Plan,
    pending: &[learning::Member],
) -> io::Result<BTreeSet<Object>> {
    let before = live_dns_members(prior)?;
    let after = live_dns_members(next)?;
    let mixed = mixed_dns_plan(prior)?;
    let merged = receives_held_global(prior, next)?;
    if !merged && mixed != mixed_dns_plan(next)? {
        return Err(ineligible());
    }
    if let Some(layout) = mixed.filter(|layout| layout.independent) {
        let held = |member: &&learning::Member| member.zone != layout.client_zone;
        if before.iter().filter(held).ne(after.iter().filter(held)) {
            return Err(ineligible());
        }
    }
    let mut intact = 0;
    let mut added = BTreeSet::new();
    for member in after {
        if let Ok(index) =
            before.binary_search_by_key(&(member.zone, member.ip), |old| (old.zone, old.ip))
        {
            if before[index].until < member.until {
                return Err(ineligible());
            }
            intact += 1;
        } else {
            let mixed = mixed
                .filter(|_| {
                    member.until == RETAINED_FIRMWARE_MEMBER
                        || member.until == RETIRED_FIRMWARE_MEMBER
                            && pending.iter().any(|old| {
                                old.zone == member.zone
                                    && old.ip == member.ip
                                    && old.until == RETAINED_FIRMWARE_MEMBER
                            })
                })
                .ok_or_else(ineligible)?;
            added.insert(Object::Stop(
                plan::Selector {
                    source: mixed.selector_source(member.zone),
                    dest: Prefix::host(member.ip),
                },
                false,
            ));
        }
    }
    if intact != before.len() {
        return Err(ineligible());
    }
    Ok(added)
}

pub(super) fn held_dns_objects(plan: &Plan, iface: &str) -> BTreeSet<Object> {
    let scopes: BTreeSet<_> = plan
        .flows()
        .filter_map(|(selector, primary)| {
            (selector.source.any() && plan.effective(selector, primary) == Some(iface))
                .then_some(selector)
        })
        .collect();
    objects(plan)
        .into_iter()
        .filter(|object| match object {
            Object::Route(dest, owner, _) => {
                owner == iface && scopes.iter().any(|s| s.dest == *dest)
            }
            Object::Firewall(selector, owner, _) => {
                owner == iface && (object.fixed_mss() || scopes.contains(selector))
            }
            Object::Scoped(selector, ..) | Object::Stop(selector, _) => scopes.contains(selector),
            _ => false,
        })
        .collect()
}

fn receives_held_global(prior: &Plan, next: &Plan) -> io::Result<bool> {
    let (Some(old), Some(new)) = (mixed_dns_plan(prior)?, mixed_dns_plan(next)?) else {
        return Ok(false);
    };
    if !old.independent
        || new.independent
        || old.client_zone != new.client_zone
        || old.client != new.client
        || prior.killswitch != next.killswitch
    {
        return Ok(false);
    }
    let held = dns_zone_target(prior, 1 - old.client_zone)?;
    Ok(dns_zone_target(next, 1 - new.client_zone)? == held
        && dns_zone_target(next, new.client_zone)? == held)
}

fn holds_independent_dns_fib(prior: &Plan, next: &Plan) -> io::Result<bool> {
    let held = independent_dns_peer(prior)?;
    if held != independent_dns_peer(next)? && !receives_held_global(prior, next)? {
        return Ok(false);
    }
    Ok(held
        .is_none_or(|(iface, _)| held_dns_objects(prior, iface) == held_dns_objects(next, iface)))
}

fn stopped_scope(prior: &Journal, next: &Journal) -> bool {
    stopped_scope_with_pending(prior, next, &[])
}

fn stopped_scope_with_pending(
    prior: &Journal,
    next: &Journal,
    pending: &[learning::Member],
) -> bool {
    if prior.installed.killswitch != next.installed.killswitch
        || prior.installed.dns_bridges != next.installed.dns_bridges
        || !prior.installed.temporary_stops.is_empty()
        || !next.installed.temporary_stops.is_empty()
        || !holds_independent_dns_fib(&prior.installed, &next.installed).unwrap_or(false)
    {
        return false;
    }
    let Ok(added) = added_firmware_stops(&prior.installed, &next.installed, pending) else {
        return false;
    };
    let moved = moved_dns_client(prior);
    if !prior.installed.marks.is_empty() || !next.installed.marks.is_empty() {
        let (Ok((source, _)), Ok((target, _))) = (
            replacement_route_target(prior),
            replacement_route_target(next),
        ) else {
            return false;
        };
        let protections = |journal: &Journal, iface: &str| {
            let guarded = objects(&guarded(journal, moved).installed);
            journal.installed.marks.get(iface).map_or_else(
                || {
                    guarded.iter().filter(|object| object.is_stop()).count()
                        == journal.installed.prefixes.len()
                },
                |slot| guarded.contains(&Object::MarkFence(plan::Family::V4, *slot)),
            )
        };
        let (a, b) = (
            prior.installed.marks.get(source),
            next.installed.marks.get(target),
        );
        return a != b
            && prior
                .installed
                .prefixes
                .keys()
                .eq(next.installed.prefixes.keys())
            && protections(prior, source)
            && protections(next, target);
    }
    let covered = guarded(prior, moved);
    let old = objects(&covered.installed);
    let new = objects(&guarded(next, moved).installed);
    let mut stops: BTreeSet<_> = old.into_iter().filter(Object::is_stop).collect();
    let expected_stops = if covered.installed.killswitch {
        prior.installed.flows().count()
    } else {
        covered.installed.temporary_stops.len()
    };
    if expected_stops == 0 || stops.len() != expected_stops {
        return false;
    }
    stops.extend(added);
    stops
        .iter()
        .eq(new.iter().filter(|object| object.is_stop()))
}

fn moved_dns_client(prior: &Journal) -> Option<Prefix> {
    mixed_dns_plan(&prior.installed)
        .ok()
        .flatten()
        .filter(|mixed| mixed.independent)
        .map(|mixed| mixed.client)
}

fn guarded(journal: &Journal, moved: Option<Prefix>) -> Journal {
    let mut result = journal.clone();
    if let Some(client) = moved.filter(|_| !journal.installed.killswitch) {
        result.installed.temporary_stops = journal
            .installed
            .flows()
            .filter_map(|(selector, _)| (selector.source == client).then_some(selector))
            .collect();
    } else {
        result.installed.killswitch = true;
    }
    result
}

fn parked(journal: &Journal, moved: Option<Prefix>) -> Journal {
    let mut result = guarded(journal, moved);
    result.installed = result.installed.guards_only().into();
    result
}

fn supports_runtime_retry(transfer: &Transfer, names: Option<&[String]>) -> bool {
    let retained = |plan: &Plan| {
        plan.learned.as_ref().is_none_or(|learned| {
            learned
                .members
                .iter()
                .all(|member| member.until == RETAINED_FIRMWARE_MEMBER)
        })
    };
    let same_members = || {
        matches!(
            (live_dns_members(&transfer.prior.installed), live_dns_members(&transfer.next.installed)),
            (Ok(prior), Ok(next)) if prior == next
        )
    };
    transfer.source.nested.is_none()
        && transfer.retained_outer.is_none()
        && transfer.nested_target.is_none()
        && transfer.retiring_nested.is_none()
        && retained(&transfer.prior.installed)
        && match names {
            Some(names) => transfer.held_direct.is_some() && retry_scope(transfer, names).is_ok(),
            None => {
                retained(&transfer.next.installed)
                    && transfer.held_direct.as_ref().is_none_or(|_| {
                        moved_dns_client(&transfer.prior).is_some() && same_members()
                    })
            }
        }
}

fn keep_runtime_retry(
    db: &Store,
    tx: &Transaction<'_>,
    run: &dyn Runner,
    transfer: &mut Transfer,
    current: &Journal,
    (before, candidate): (&Value, &mut Value),
    (target, wan, dns): (
        &ActiveReplacementPeer,
        &[String],
        Option<&ActiveDnsReplacementProof>,
    ),
) -> io::Result<Option<String>> {
    let names = dns.and_then(|proof| proof.retry_names.as_deref());
    let checkpoint = if let Some(held) = &transfer.held_direct {
        let source = moved_dns_client(&transfer.prior).ok_or_else(ineligible)?;
        let checkpoint = parked_with_held(&transfer.next, &held.owner.iface, source);
        let global = held_dns_objects(&current.installed, &held.owner.iface);
        if global.is_empty() || global != held_dns_objects(&checkpoint.installed, &held.owner.iface)
        {
            return Err(ineligible());
        }
        checkpoint
    } else {
        parked(&transfer.next, None)
    };
    let mut previous = before.clone();
    stamp_document(&mut previous, current)?;
    if nfqws2_awg_profile::read(db)? != previous {
        return Err(ineligible());
    }
    let k = transfer_kernel(run, db)?;
    if current.boot != boot_id(&k)?
        || k.inventory(&current.claims(), true)? != objects(&current.installed)
    {
        return Err(ineligible());
    }
    k.verify_forward(&current.installed)?;
    let endpoints = plan::endpoints_for(candidate, false, |_| true)?;
    k.guard(&checkpoint.installed, &endpoints)?;

    transfer.retry_runtime = true;
    transfer.retry_dns = names.map(<[String]>::to_vec);
    transfer.temporary_stop = Some(TemporaryStop {
        cold_reserve_primary: None,
        target_fingerprint: target.fingerprint,
        target_owner: Some(target.owner.clone()),
        wan: wan.to_vec(),
        transport_policy: None,
        named: None,
        rotation: None,
        deferred_launch: false,
        released: false,
        teardown: false,
    });
    transfer.token = bind_retry_dns(
        token(
            &transfer.source,
            &transfer.source_fingerprint,
            &transfer.prior,
            &transfer.next,
            transfer.temporary_stop.as_ref(),
            (None, transfer.held_direct.as_ref()),
            (None, None),
        )?,
        names,
    )?;
    transfer.retry_positive_hint = dns
        .and_then(|proof| proof.positive_until.clone())
        .map(|until| RetryPositiveHint::seal(&transfer.token, until))
        .transpose()?;
    transfer.retry_negative_name = dns
        .and_then(|proof| proof.confirmed_negative.clone())
        .map(|name| ConfirmedNegativeName::seal(&transfer.token, name))
        .transpose()?;
    transfer.retry_positive_pair = match dns {
        Some(proof) => PairPositiveHints::seal(&transfer.token, &proof.named_positives)?,
        None => None,
    };
    candidate[FIELD]["token"] = json!(transfer.token);
    stamp_document(&mut previous, &checkpoint)?;
    stamp_document(candidate, &checkpoint)?;
    save(tx, transfer)?;
    transition(db, tx, run, current, &checkpoint, Some(current))?;
    let saved = persist_active_replacement_locked(db, tx, &previous, candidate)?;
    let message = "перенос правил сохранён, применение маршрутов будет повторено";
    Ok(Some(saved.map_or_else(
        || message.to_owned(),
        |old| format!("{old}. {message}"),
    )))
}

fn deferred_launch(transfer: &Transfer) -> bool {
    transfer
        .temporary_stop
        .as_ref()
        .is_some_and(|stop| stop.deferred_launch)
}

fn deferred_launch_checkpoint(next: &Journal, held: Option<&str>) -> Journal {
    if let Some(held) = held {
        let mut result = next.clone();
        if result.installed.killswitch {
            result.installed.offline = result
                .installed
                .targets
                .keys()
                .filter(|iface| iface.as_str() != held)
                .cloned()
                .collect();
        } else {
            let slot = result.installed.scoped_slot(held);
            result.installed.scoped.retain(|(_, iface)| iface == held);
            result.installed.targets.retain(|iface, _| iface == held);
            result.installed.mss.retain(|iface, _| iface == held);
            result.installed.scoped_slots.clear();
            if slot != 0 {
                result.installed.scoped_slots.insert(held.into(), slot);
            }
        }
        return result;
    }
    if next.installed.killswitch {
        parked(next, None)
    } else {
        Journal {
            installed: Snapshot::default(),
            ..next.clone()
        }
    }
}

struct DeferredLaunchScope<'a> {
    fingerprint: [u8; 32],
    wan: &'a [String],
    before_write: &'a dyn Fn() -> io::Result<()>,
    named: Option<SealedTransportPair>,
}

fn persist_deferred_launch(
    db: &Store,
    tx: &Transaction<'_>,
    run: &dyn Runner,
    (before, after): (&Value, &Value),
    (prior, next): (Journal, Journal),
    (source, held): (&ActiveReplacementPeer, Option<&ActiveReplacementPeer>),
    DeferredLaunchScope {
        fingerprint,
        wan,
        before_write,
        named,
    }: DeferredLaunchScope<'_>,
) -> io::Result<Option<String>> {
    let unresolved = named
        .as_ref()
        .is_some_and(|names| names.target_unresolved().is_some());
    let held_direct = held.map(|peer| HeldDirect {
        owner: peer.owner.clone(),
        fingerprint: peer.fingerprint,
        wan: wan.to_vec(),
    });
    let temporary_stop = Some(TemporaryStop {
        cold_reserve_primary: None,
        target_fingerprint: fingerprint,
        target_owner: None,
        wan: wan.to_vec(),
        transport_policy: None,
        named,
        rotation: None,
        deferred_launch: true,
        released: false,
        teardown: false,
    });
    let token = token(
        &source.owner,
        &source.fingerprint,
        &prior,
        &next,
        temporary_stop.as_ref(),
        (None, held_direct.as_ref()),
        (None, None),
    )?;
    let transfer = Transfer {
        prior,
        next,
        source: source.owner.clone(),
        source_fingerprint: source.fingerprint,
        disabled_target: None,
        retained_outer: None,
        held_direct,
        nested_target: None,
        retiring_nested: None,
        token,
        temporary_stop,
        retry_runtime: false,
        retry_dns: None,
        retry_projection: None,
        retry_positive_hint: None,
        retry_negative_name: None,
        retry_positive_pair: None,
        retired: false,
    };
    let checkpoint = deferred_launch_checkpoint(
        &transfer.next,
        transfer
            .held_direct
            .as_ref()
            .map(|held| held.owner.iface.as_str()),
    )
    .validated()?;
    let mut previous = before.clone();
    let mut candidate = after.clone();
    stamp_document(&mut previous, &checkpoint)?;
    candidate[FIELD] = json!({"id": transfer.source.id, "token": transfer.token});
    stamp_document(&mut candidate, &checkpoint)?;
    before_write()?;
    save(tx, &transfer)?;
    transition(
        db,
        tx,
        run,
        &transfer.prior,
        &checkpoint,
        Some(&transfer.prior),
    )?;
    let saved = persist_active_replacement_locked(db, tx, &previous, &candidate)?;
    let message = if unresolved {
        "перенос правил сохранён, не удалось разрешить IPv4-адрес сервера (endpoint)"
    } else {
        "перенос правил сохранён, выбранное подключение пока не запустилось"
    };
    Ok(Some(saved.map_or_else(
        || message.to_owned(),
        |old| format!("{old}. {message}"),
    )))
}

fn parked_with_held(journal: &Journal, iface: &str, client: Prefix) -> Journal {
    let mut result = guarded(journal, Some(client));
    if result.installed.targets.len() == 1 {
        let selectors = result
            .installed
            .flows()
            .filter_map(|(selector, _)| (selector.source == client).then_some(selector))
            .collect::<Vec<_>>();
        result.installed.park(&selectors);
    } else {
        result.installed.offline = result
            .installed
            .targets
            .keys()
            .filter(|&id| id != iface)
            .cloned()
            .collect();
    }
    result
}

fn preflight_stop(k: &Kernel<'_>, prior: &Journal) -> io::Result<()> {
    let current = objects(&prior.installed);
    let proposed = if unprotected(prior) {
        objects(&guarded(prior, moved_dns_client(prior)).installed)
    } else {
        current.clone()
    };
    if k.inventory_for(&prior.claims(), &proposed, true)? != current {
        return Err(ineligible());
    }
    Ok(())
}

fn save(tx: &Transaction<'_>, transfer: &Transfer) -> io::Result<()> {
    tx.save_runtime_bounded(FILE, transfer, LIMIT)
}

fn read(db: &Store) -> io::Result<Option<Transfer>> {
    let saved: Transfer = match db.read_runtime(FILE, LIMIT) {
        Ok(value) => value,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    saved.prior.clone().validated()?;
    saved.next.clone().validated()?;
    if saved.disabled_target.is_some() {
        if saved
            .temporary_stop
            .as_ref()
            .is_some_and(|stop| stop.rotation.is_some())
        {
            return Err(ineligible());
        }
        disabled::validate(&saved)?;
        return Ok(Some(saved));
    }
    let (iface, source) = replacement_route_target(&saved.prior)?;
    let (successor_iface, successor) = replacement_route_target(&saved.next)?;
    let held_dns = independent_dns_peer(&saved.prior.installed)?;
    let merged = receives_held_global(&saved.prior.installed, &saved.next.installed)?;
    if !saved.source.valid()
        || saved.source.boot != saved.prior.boot
        || saved.prior.boot != saved.next.boot
        || saved.source.id != source.id
        || saved.source.iface != iface
        || saved.source_fingerprint == [0; 32]
        || source.id == successor.id
        || held_dns.is_some() != saved.held_direct.is_some()
        || saved.held_direct.as_ref().is_some_and(|held| {
            !held.owner.valid()
                || held.owner.nested.is_some()
                || held.owner.boot != saved.prior.boot
                || !distinct_owner(&held.owner, &saved.source)
                || (held.owner.id == successor.id) != merged
                || (held.owner.iface == successor_iface) != merged
                || held.fingerprint == [0; 32]
                || held_dns.is_none_or(|(iface, target)| {
                    held.owner.iface != iface || held.owner.id != target.id
                })
        })
        || !packed_transport_roles(
            &saved.prior,
            &saved.next,
            &saved.source,
            saved.nested_target.as_ref(),
            saved.retiring_nested.as_ref(),
        )
        || !saved.prior.installed.marks.is_empty() && saved.retained_outer.is_some()
        || saved.nested_target.as_ref().is_some_and(|target| {
            !target.binds(&saved.source, &successor.id, successor_iface)
                || saved.retained_outer.as_ref().is_some_and(|retained| {
                    target
                        .source_outer
                        .as_ref()
                        .is_none_or(|old| &old.owner != retained)
                })
                || saved
                    .temporary_stop
                    .as_ref()
                    .is_some_and(|stop| stop.transport_policy.is_none())
        })
        || saved.retiring_nested.as_ref().is_some_and(|retiring| {
            !retiring.binds(&saved.source, &successor.id, successor_iface)
                || saved
                    .temporary_stop
                    .as_ref()
                    .is_some_and(|stop| stop.transport_policy.is_none())
        })
        || saved.retained_outer.as_ref().is_some_and(|outer| {
            !outer.valid()
                || outer.nested.is_some()
                || outer.boot != saved.source.boot
                || outer.pid == saved.source.pid
                || outer.id == source.id
                || outer.id == successor.id
                || outer.iface == successor_iface
                || saved
                    .source
                    .nested
                    .as_ref()
                    .is_none_or(|scope| scope.outer_iface != outer.iface)
        })
        || saved.prior.committed.revision.checked_add(1) != Some(saved.next.committed.revision)
        || saved.temporary_stop.is_some()
            != (unprotected(&saved.prior)
                || unprotected(&saved.next)
                || retiring_firmware_members(&saved.next)
                || saved.retry_runtime
                || saved
                    .temporary_stop
                    .as_ref()
                    .is_some_and(|stop| stop.cold_reserve_primary.is_some())
                || deferred_launch(&saved)
                || warm_named_receipt(&saved))
        || saved.retry_dns.is_some() && !saved.retry_runtime
        || saved.retry_projection.is_some() && projected_dns(&saved).is_err()
        || saved.retry_positive_hint.as_ref().is_some_and(|hint| {
            !saved.retry_runtime
                || saved
                    .retry_dns
                    .as_ref()
                    .is_none_or(|names| names.len() != 1)
                || !hint.valid(&saved.token)
        })
        || saved.retry_negative_name.as_ref().is_some_and(|prior| {
            !saved.retry_runtime
                || !prior.valid(&saved.token, saved.retry_dns.as_deref().unwrap_or_default())
        })
        || saved.retry_positive_pair.as_ref().is_some_and(|hints| {
            !saved.retry_runtime
                || saved.retry_negative_name.is_some()
                || !hints.valid(&saved.token, saved.retry_dns.as_deref().unwrap_or_default())
        })
        || saved.retry_runtime && !supports_runtime_retry(&saved, saved.retry_dns.as_deref())
        || saved.temporary_stop.as_ref().is_some_and(|stop| {
            stop.target_fingerprint == [0; 32]
                || stop.cold_reserve_primary.is_some_and(|primary| {
                    !primary.is_ipv4()
                        || mtu_edit::canonical_socket(primary) != Some(primary)
                        || stop.deferred_launch
                        || stop.named.is_some()
                        || stop.rotation.is_some()
                        || stop.transport_policy.is_some()
                        || saved.source.nested.is_some()
                        || saved.nested_target.is_some()
                        || saved.retiring_nested.is_some()
                        || saved.retained_outer.is_some()
                        || saved.held_direct.is_some()
                        || saved.retry_runtime
                        || !literal_startup_scope(&saved.prior.installed)
                        || !literal_startup_scope(&saved.next.installed)
                        || saved
                            .prior
                            .installed
                            .overlaps_destination(Prefix::host(primary.ip()))
                        || saved
                            .next
                            .installed
                            .overlaps_destination(Prefix::host(primary.ip()))
                })
                || stop.deferred_launch
                    && (saved.retry_runtime
                        || stop.transport_policy.is_some()
                        || saved.source.nested.is_some()
                        || cold_launch_target(
                            &saved.prior,
                            saved.held_direct.as_ref().map(|held| &held.owner),
                        )
                        .is_err()
                        || cold_launch_target(
                            &saved.next,
                            saved.held_direct.as_ref().map(|held| &held.owner),
                        )
                        .is_err())
                || stop.target_owner.is_some()
                    != (!stop.deferred_launch
                        && (saved.held_direct.is_some()
                            || saved.retry_runtime
                            || stop.named.is_some()))
                || stop.named.as_ref().is_some_and(|named| {
                    saved.held_direct.is_some()
                        || saved.retained_outer.is_some()
                        || saved.nested_target.is_some()
                        || saved.retiring_nested.is_some()
                        || saved.source.nested.is_some()
                        || saved.retry_runtime
                        || stop.transport_policy.is_some()
                        || named.target_unresolved().is_some() && !stop.deferred_launch
                        || named.is_warm_ipv6() && stop.deferred_launch
                        || !named.is_warm_ipv6()
                            && !stop.deferred_launch
                            && (!unprotected(&saved.prior) || !unprotected(&saved.next))
                        || profile_rebind::native_ipv4_prefixes(&saved.prior).is_err()
                        || profile_rebind::native_ipv4_prefixes(&saved.next).is_err()
                        || !named.binds([
                            (&source.id, &saved.source_fingerprint),
                            (&successor.id, &stop.target_fingerprint),
                        ])
                })
                || stop.target_owner.as_ref().is_some_and(|owner| {
                    !owner.valid()
                        || owner.nested.is_some()
                        || owner.boot != saved.prior.boot
                        || owner.id != successor.id
                        || owner.iface != successor_iface
                        || !distinct_owner(owner, &saved.source)
                        || saved.held_direct.as_ref().is_some_and(|held| {
                            if merged {
                                owner != &held.owner
                            } else {
                                !distinct_owner(owner, &held.owner)
                            }
                        })
                })
                || stop
                    .transport_policy
                    .as_ref()
                    .is_some_and(|policy| policy.source == [0; 32] || policy.target == [0; 32])
                || stop
                    .rotation
                    .as_ref()
                    .is_some_and(|rotation| rotation.validate(&saved).is_err())
        })
        || saved.token
            != bind_retry_dns(
                token(
                    &saved.source,
                    &saved.source_fingerprint,
                    &saved.prior,
                    &saved.next,
                    saved.temporary_stop.as_ref(),
                    (saved.retained_outer.as_ref(), saved.held_direct.as_ref()),
                    (saved.nested_target.as_ref(), saved.retiring_nested.as_ref()),
                )?,
                saved.retry_dns.as_deref(),
            )?
        || !stopped_scope(&saved.prior, &saved.next)
    {
        return Err(ineligible());
    }
    Ok(Some(saved))
}

fn bind_retry_dns(token: String, names: Option<&[String]>) -> io::Result<String> {
    match names {
        Some(names) => profile_rebind::digest(&(token, names)),
        None => Ok(token),
    }
}

fn token(
    source: &NativeRemovalSeal,
    fingerprint: &[u8; 32],
    prior: &Journal,
    next: &Journal,
    temporary_stop: Option<&TemporaryStop>,
    (retained_outer, held_direct): (Option<&NativeRemovalSeal>, Option<&HeldDirect>),
    nested: (Option<&NestedTarget>, Option<&RetiringNested>),
) -> io::Result<String> {
    let policy = match temporary_stop {
        Some(stop) if stop.deferred_launch => profile_rebind::digest(&(
            source,
            fingerprint,
            prior,
            next,
            stop.target_fingerprint,
            &stop.wan,
            stop.deferred_launch,
        )),
        Some(stop) if stop.transport_policy.is_some() => profile_rebind::digest(&(
            source,
            fingerprint,
            prior,
            next,
            stop.target_fingerprint,
            &stop.wan,
            &stop.transport_policy,
        )),
        Some(stop) => profile_rebind::digest(&(
            source,
            fingerprint,
            prior,
            next,
            stop.target_fingerprint,
            &stop.wan,
        )),
        None => profile_rebind::digest(&(source, fingerprint, prior, next)),
    }?;
    let policy = match temporary_stop.and_then(|stop| stop.target_owner.as_ref()) {
        Some(owner) => profile_rebind::digest(&(policy, owner)),
        None => Ok(policy),
    }?;
    let policy = match temporary_stop.and_then(|stop| stop.named.as_ref()) {
        Some(named) => profile_rebind::digest(&(policy, named)),
        None => Ok(policy),
    }?;
    let policy = match temporary_stop.and_then(|stop| stop.cold_reserve_primary) {
        Some(primary) => profile_rebind::digest(&(policy, primary)),
        None => Ok(policy),
    }?;
    let policy = match retained_outer {
        Some(outer) => profile_rebind::digest(&(policy, outer)),
        None => Ok(policy),
    }?;
    let policy = match nested.0 {
        Some(target) => profile_rebind::digest(&(policy, target)),
        None => Ok(policy),
    }?;
    let policy = match nested.1 {
        Some(retiring) => profile_rebind::digest(&(policy, retiring)),
        None => Ok(policy),
    }?;
    match held_direct {
        Some(held) => profile_rebind::digest(&(policy, held)),
        None => Ok(policy),
    }
}

pub(super) fn pending(db: &Store) -> io::Result<bool> {
    match db.read_runtime::<Value>(FILE, LIMIT) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

pub(super) fn pending_dns_settlement(db: &Store) -> io::Result<bool> {
    Ok(read(db)?.is_some_and(|transfer| {
        transfer.next.installed.learned.is_some()
            && transfer.temporary_stop.is_some_and(|stop| !stop.released)
    }))
}

pub fn active_replacement_in_progress(db: &Store) -> io::Result<bool> {
    Ok(pending(db)? || launch_pending(db)?)
}

pub fn active_replacement_native_witness_needed(db: &Store, iface: &str) -> io::Result<bool> {
    if read(db)?.is_some_and(|transfer| {
        transfer
            .held_direct
            .as_ref()
            .is_some_and(|held| held.owner.iface == iface)
            || transfer.temporary_stop.is_some_and(|stop| {
                (stop.transport_policy.is_some()
                    || stop.target_owner.is_some()
                    || stop.deferred_launch)
                    && !stop.released
                    && !stop.teardown
            }) && (transfer.source.iface == iface
                || transfer.next.installed.targets.contains_key(iface))
    }) {
        return Ok(true);
    }
    disabled::rearm_witness_needed(db, iface)
}

/// Reuse the exact same-boot native witness if a warm transport transfer
/// was interrupted between durable publication and acknowledgement.
pub fn warm_named_native_owner(
    db: &Store,
    iface: &str,
    endpoint: SocketAddr,
) -> io::Result<Option<NativeRemovalSeal>> {
    Ok(read(db)?
        .filter(warm_named_receipt)
        .and_then(|transfer| transfer.temporary_stop)
        .filter(|stop| !stop.teardown && !stop.released)
        .filter(|stop| stop.named.as_ref().and_then(|names| names.selected(true)) == Some(endpoint))
        .and_then(|stop| stop.target_owner)
        .filter(|owner| owner.iface == iface))
}

fn warm_named_receipt(transfer: &Transfer) -> bool {
    transfer
        .temporary_stop
        .as_ref()
        .and_then(|stop| stop.named.as_ref())
        .is_some_and(SealedTransportPair::is_warm_ipv6)
}

pub(super) fn track_replacement(k: &mut Kernel<'_>, db: &Store) -> io::Result<()> {
    if let Some(transfer) = read(db)? {
        track_transfer_sockets(k, &transfer)?;
        if let Some(held) = transfer.held_direct.as_ref() {
            k.held_dns_lookups.extend(
                held_dns_objects(&transfer.prior.installed, &held.owner.iface)
                    .into_iter()
                    .filter(|object| matches!(object, Object::Scoped(..))),
            );
        }
    }
    Ok(())
}

fn track_transfer_sockets(k: &mut Kernel<'_>, transfer: &Transfer) -> io::Result<()> {
    let source =
        (!transfer.retired && transfer.source.nested.is_some()).then_some(&transfer.source);
    let target = transfer.nested_target.as_ref().map(|v| &v.owner);
    if (source.is_some() || target.is_some()) && transfer.source.boot == boot_id(k)? {
        for seal in source.into_iter().chain(target) {
            let (mark, table) = nested_socket_selector(&seal.iface)?;
            k.nested_sockets.insert(mark, table);
        }
    }
    Ok(())
}

fn transfer_kernel<'a>(run: &'a dyn Runner, db: &Store) -> io::Result<Kernel<'a>> {
    let mut k = kernel(run);
    if let Some(transfer) = read(db)? {
        if transfer.nested_target.is_some() || transfer.retiring_nested.is_some() {
            let doc = nfqws2_awg_profile::read(db)?;
            k.track_sockets(&doc, &transfer.prior.installed);
            k.track_sockets(&doc, &transfer.next.installed);
        }
        track_transfer_sockets(&mut k, &transfer)?;
    }
    Ok(k)
}

pub(super) fn launch_pending(db: &Store) -> io::Result<bool> {
    Ok(read_launch(db)?.is_some())
}

fn row<'a>(doc: &'a Value, id: &str) -> Option<&'a Value> {
    doc["servers"]
        .as_array()?
        .iter()
        .find(|row| row["id"] == id)
}

fn explicit_policy(
    doc: &Value,
    id: &str,
    held: Option<&str>,
) -> io::Result<(crate::Routing, Vec<usize>)> {
    let mut policy = crate::policy::current(doc)?;
    let observed = crate::observed::dynamic(&policy);
    let ranks = policy
        .zones
        .iter()
        .enumerate()
        .filter_map(|(i, z)| z.enabled.then_some(i))
        .collect::<Vec<_>>();
    if observed && policy.zones.iter().any(|zone| !zone.enabled) {
        return Err(ineligible());
    }
    policy.zones.retain(|zone| zone.enabled);
    if !matches!(policy.mode.as_str(), "zones" | "include" | "exclude")
        || policy.sni_routing && !observed
        || policy.zones.is_empty()
    {
        return Err(ineligible());
    }
    let single_zone = policy.zones.len() == 1;
    let mixed = if observed {
        mixed_dns_sources(&policy)
    } else {
        None
    };
    if mixed.is_some_and(|mixed| mixed.independent) != held.is_some() {
        return Err(ineligible());
    }
    for (index, zone) in policy.zones.iter_mut().enumerate() {
        let expected = held
            .filter(|_| mixed.is_some_and(|mixed| mixed.client_zone != index))
            .unwrap_or(id);
        if zone.tunnel_id != expected
            || zone.waiting_for_connection
            || zone.direction() != "tunnel"
            || !zone.fallback_tunnel_ids.is_empty()
            || observed
                && !zone.source_ips.is_empty()
                && mixed.is_none()
                && (!single_zone || exact_ipv4_client(&zone.source_ips).is_none())
            || !observed && !zone.domains.is_empty()
            || zone.ips.is_empty() && zone.domains.is_empty()
            || zone.only_catch_all()
        {
            return Err(ineligible());
        }
        if !observed {
            zone.order = 0;
        }
    }
    Ok((policy, ranks))
}

fn policies(
    before: &Value,
    after: &Value,
    source: &str,
    target: &str,
    held: Option<&str>,
) -> io::Result<(crate::Routing, crate::Routing)> {
    let (old, old_ranks) = explicit_policy(before, source, held)?;
    let (new, new_ranks) = explicit_policy(after, target, held.filter(|&held| held != target))?;
    let mut remapped = old.clone();
    for zone in &mut remapped.zones {
        if zone.tunnel_id == source {
            zone.tunnel_id = target.to_owned();
        }
    }
    if old_ranks != new_ranks || serde_json::to_value(remapped)? != serde_json::to_value(&new)? {
        return Err(ineligible());
    }
    Ok((old, new))
}

pub(super) fn verify_peer(
    doc: &Value,
    peer: &ActiveReplacementPeer,
    plan: &Plan,
) -> io::Result<()> {
    verify_peer_for(doc, peer, plan, None)
}

fn verify_peer_for(
    doc: &Value,
    peer: &ActiveReplacementPeer,
    plan: &Plan,
    affected: Option<&str>,
) -> io::Result<()> {
    verify_peer_bound(doc, peer, plan, affected, (None, false))
}

fn has_endpoint_backups(doc: &Value, id: &str) -> bool {
    row(doc, id).is_some_and(|row| {
        row["config"]["client"]["endpoint_backups"]
            .as_array()
            .is_some_and(|backups| !backups.is_empty())
    })
}

fn durable_endpoint_fingerprint(doc: &Value, peer: &ActiveReplacementPeer) -> io::Result<[u8; 32]> {
    if has_endpoint_backups(doc, &peer.owner.id) {
        return active_replacement_numeric_pool(doc, &peer.owner.id)?
            .binding(peer.endpoint)
            .ok_or_else(ineligible);
    }
    Ok(peer.fingerprint)
}

fn durable_selected_endpoint(
    doc: &Value,
    id: &str,
    fingerprint: [u8; 32],
) -> io::Result<Option<SocketAddr>> {
    if has_endpoint_backups(doc, id) {
        return Ok(active_replacement_numeric_pool(doc, id)?.selected_endpoint(fingerprint));
    }
    if active_replacement_fingerprint(doc, id)? != fingerprint {
        return Ok(None);
    }
    active_replacement_endpoint(doc, id).map(Some)
}

fn verify_peer_bound(
    doc: &Value,
    peer: &ActiveReplacementPeer,
    plan: &Plan,
    affected: Option<&str>,
    (names, allow_backups): (Option<&NamedTransportClaims>, bool),
) -> io::Result<()> {
    let source = row(doc, &peer.owner.id).ok_or_else(ineligible)?;
    let rows = doc["servers"].as_array().ok_or_else(ineligible)?;
    let (_, iface, target) = plan::profile(doc, rows, &peer.owner.id)?;
    if peer.owner.iface != iface
        || peer.owner.nested.is_some() != peer.underlay.is_some()
        || source["config"]["client"]["double_tunnel_mode"] == "permanent"
            && peer.owner.nested.is_none()
        || peer.owner.nested.is_none() && peer.mtu != target.mtu
        || !fits_routes_for(plan, &peer.allowed, peer.endpoint.ip(), affected)?
    {
        return Err(ineligible());
    }
    if let Some(names) = names {
        names.verify_peer(doc, peer)?;
    } else if allow_backups && has_endpoint_backups(doc, &peer.owner.id) {
        let pool = active_replacement_numeric_pool(doc, &peer.owner.id)?;
        if peer.owner.nested.is_some()
            || pool.binding(peer.endpoint).is_none()
            || peer.fingerprint != pool.wire_fingerprint
        {
            return Err(ineligible());
        }
    } else if peer.fingerprint != active_replacement_fingerprint(doc, &peer.owner.id)?
        || source["config"]["endpoint"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .and_then(mtu_edit::canonical_socket)
            != Some(peer.endpoint)
    {
        return Err(ineligible());
    }
    Ok(())
}

pub(super) fn verify_nested_owner<'a>(
    k: &Kernel<'_>,
    doc: &Value,
    peer: &'a ActiveReplacementPeer,
) -> io::Result<&'a ActiveReplacementUnderlay> {
    let scope = peer.owner.nested.as_ref().ok_or_else(ineligible)?;
    let outer = peer.underlay.as_ref().ok_or_else(ineligible)?;
    let row = row(doc, &peer.owner.id).ok_or_else(ineligible)?;
    let id = row["config"]["client"]["double_tunnel_id"]
        .as_str()
        .ok_or_else(ineligible)?;
    let (iface, endpoint, fingerprint) = active_replacement_underlay_identity(doc, id)?;
    let (mark, _) = nested_socket_selector(&peer.owner.iface)?;
    if !outer.owner.valid()
        || outer.owner.nested.is_some()
        || outer.owner.boot != peer.owner.boot
        || outer.owner.id != id
        || outer.owner.pid == peer.owner.pid
        || outer.owner.iface != iface
        || scope.outer_iface != iface
        || scope.endpoint != peer.endpoint.ip()
        || outer.endpoint != endpoint
        || outer.fingerprint != fingerprint
        || peer.socket_mark != mark
        || active_replacement_nested_mtu(doc, &peer.owner.id, outer.mtu)? != peer.mtu
        || !outer
            .allowed
            .iter()
            .map(|network| network.parse::<Prefix>())
            .collect::<io::Result<Vec<_>>>()?
            .iter()
            .any(|network| network.contains(scope.endpoint))
    {
        return Err(ineligible());
    }
    plan::verify_nested_path_with_source(
        k,
        &peer.owner.iface,
        &iface,
        &witnessed_peer(peer, &peer.owner.iface)?,
        Some(scope.source),
    )?;
    Ok(outer)
}

fn verify_nested_peer(
    k: &Kernel<'_>,
    doc: &Value,
    peer: &ActiveReplacementPeer,
    wan: &[String],
    requires_plain_wan: bool,
) -> io::Result<()> {
    let outer = verify_nested_owner(k, doc, peer)?;
    mtu_edit::replacement_wan(k, outer.endpoint, outer.socket_mark, wan)?;
    if requires_plain_wan {
        mtu_edit::replacement_wan(k, peer.endpoint, 0, wan)?;
    }
    Ok(())
}

fn fits_routes_for(
    plan: &Plan,
    allowed: &[String],
    endpoint: IpAddr,
    affected: Option<&str>,
) -> io::Result<bool> {
    let grants = allowed
        .iter()
        .map(|n| n.parse::<Prefix>())
        .collect::<io::Result<Vec<_>>>()?;
    Ok(plan.flows().all(|(selector, iface)| {
        !selector.dest.contains(endpoint)
            && (affected.is_some_and(|affected| affected != iface)
                || grants.iter().any(|grant| grant.covers(selector.dest)))
    }))
}

fn resolve(
    k: &Kernel<'_>,
    doc: &Value,
    policy: crate::Routing,
    peers: (&ActiveReplacementPeer, Option<&ActiveReplacementPeer>),
    layout: plan::Layout,
    nested_only: &BTreeSet<IpAddr>,
    (dns_bridges, members): (&[String], &[learning::Member]),
) -> io::Result<plan::Plan> {
    resolve_with_names(
        k,
        doc,
        policy,
        peers,
        layout,
        nested_only,
        (dns_bridges, members, None),
    )
}

fn resolve_with_names(
    k: &Kernel<'_>,
    doc: &Value,
    policy: crate::Routing,
    (peer, held): (&ActiveReplacementPeer, Option<&ActiveReplacementPeer>),
    layout: plan::Layout,
    nested_only: &BTreeSet<IpAddr>,
    (dns_bridges, members, names): (
        &[String],
        &[learning::Member],
        Option<&NamedTransportClaims>,
    ),
) -> io::Result<plan::Plan> {
    let mut plan = plan::compile_effective(doc, policy, None, true, members, layout)?;
    plan.set_dns_bridges(dns_bridges)?;
    let live = plan::resolve_with_mtu_edit(
        doc,
        plan,
        false,
        None,
        Some(plan::Verification::Read(k)),
        names.map_or(plan::EditContext::None, plan::EditContext::NamedReplacement),
        |_, iface| {
            witnessed_peer(
                held.filter(|held| held.owner.iface == iface)
                    .unwrap_or(peer),
                iface,
            )
        },
    )?;
    if !live.plan.fully_live() {
        return Err(ineligible());
    }
    k.guard(
        &live.plan,
        &live.endpoints.difference(nested_only).copied().collect(),
    )?;
    Ok(live.plan)
}

fn nested_only_endpoints(
    doc: &Value,
    plan: &Plan,
    peers: &[ActiveReplacementPeer; 2],
) -> io::Result<BTreeSet<IpAddr>> {
    if plan.marks.is_empty() || peers.iter().all(|peer| !peer.nested_only) {
        return Ok(BTreeSet::new());
    }
    let claims = super::transport_claims::Claims::read(doc, plan, false, None)?;
    let mut nested_only = BTreeSet::new();
    for peer in peers {
        let ip = peer.endpoint.ip();
        if peer.nested_only
            && peer.owner.nested.is_some()
            && row(doc, &peer.owner.id)
                .is_some_and(|r| r["config"]["client"]["double_tunnel_mode"] == "permanent")
            && claims.sole_primary(&peer.owner.id, peer.endpoint)
            && peers.iter().all(|p| {
                p.underlay
                    .as_ref()
                    .is_some_and(|outer| outer.endpoint.ip() != ip)
            })
        {
            nested_only.insert(ip);
        }
    }
    Ok(nested_only)
}

fn witnessed_peer(peer: &ActiveReplacementPeer, iface: &str) -> io::Result<LivePeer> {
    if peer.owner.iface != iface {
        return Err(ineligible());
    }
    let mut live = LivePeer::from_uapi(
        std::path::Path::new("/"),
        iface,
        peer.endpoint,
        peer.allowed.clone(),
        if peer.owner.nested.is_some() {
            0
        } else {
            peer.socket_mark
        },
        false,
    )?;
    if let Some(underlay) = &peer.underlay {
        live.socket_mark = peer.socket_mark;
        live.nested_mtu = Some(peer.mtu);
        live.nested_transport = Some(nfqws2_awg_profile::RoutedNestedTransport {
            peer: nfqws2_awg_profile::RoutedMtuPeer {
                iface: iface.to_owned(),
                outer_id: underlay.owner.id.clone(),
                outer_iface: underlay.owner.iface.clone(),
                endpoint: peer.endpoint,
                effective_mtu: peer.mtu,
                socket_mark: peer.socket_mark,
            },
            outer_endpoint: underlay.endpoint,
        });
    }
    Ok(live)
}

fn attested_peer(peer: &ActiveReplacementPeer, iface: &str) -> io::Result<LivePeer> {
    Ok(witnessed_peer(peer, iface)?.with_active_replacement_peer(Some(peer.clone())))
}

/// Check the existing protected route before starting a vacant standby.
/// The second pass seals the verified temporary engine before
/// the launcher is allowed to let it outlive the current request.
pub fn prepare_active_replacement_launch(
    db: &Store,
    run: &dyn Runner,
    stage: ActiveReplacementStage<'_>,
    wan: &[String],
    dns: Option<&ActiveDnsReplacementProof>,
) -> io::Result<ActiveReplacementLaunchMode> {
    prepare_cold_replacement(db, run, stage, wan, (dns, None), None).map(|result| result.mode)
}

/// Recheck the off-lock named ticket before launching its temporary client and
/// again before sealing the authenticated process for the route writer.
pub fn prepare_named_active_replacement_launch(
    db: &Store,
    run: &dyn Runner,
    stage: ActiveReplacementStage<'_>,
    wan: &[String],
    names: &NamedActiveReplacement,
) -> io::Result<ActiveReplacementLaunchPin> {
    let pin = names.cold_pin(&Journal::read(db)?, &stage.source.owner.id, stage.target)?;
    prepare_cold_replacement(db, run, stage, wan, (None, Some(names)), None)?;
    Ok(pin)
}

pub fn defer_active_replacement_launch(
    db: &Store,
    run: &dyn Runner,
    stage: ActiveReplacementStage<'_>,
    wan: &[String],
    before_write: &dyn Fn() -> io::Result<()>,
) -> io::Result<Option<String>> {
    prepare_cold_replacement(db, run, stage, wan, (None, None), Some(before_write))
        .map(|result| result.warning)
}

/// Publish an absent named standby as a deferred ordinary transfer. A later
/// native handshake on its recorded socket will authorize route installation.
pub fn defer_named_active_replacement_launch(
    db: &Store,
    run: &dyn Runner,
    stage: ActiveReplacementStage<'_>,
    wan: &[String],
    names: &NamedActiveReplacement,
    before_write: &dyn Fn() -> io::Result<()>,
) -> io::Result<Option<String>> {
    prepare_cold_replacement(db, run, stage, wan, (None, Some(names)), Some(before_write))
        .map(|result| result.warning)
}

fn cold_launch_target<'a>(
    journal: &'a Journal,
    held: Option<&NativeRemovalSeal>,
) -> io::Result<(&'a str, &'a plan::Target)> {
    let independent = independent_dns_peer(&journal.installed)?;
    if journal.installed.targets.len() != 1 + usize::from(held.is_some())
        || !journal.installed.marks.is_empty()
        || independent.map(|(iface, target)| (iface, target.id.as_str()))
            != held.map(|peer| (peer.iface.as_str(), peer.id.as_str()))
    {
        return Err(ineligible());
    }
    replacement_route_target(journal)
}

fn held_layout(
    prior: &Plan,
    source: &str,
    target: &str,
    receiver_holds_global: bool,
) -> plan::Layout {
    let mut layout = prior.layout();
    layout.scoped_slots = prior
        .targets
        .keys()
        .filter(|iface| !receiver_holds_global || iface.as_str() != source)
        .map(|iface| {
            let after_iface = if iface == source { target } else { iface };
            (after_iface.to_owned(), prior.scoped_slot(iface))
        })
        .collect();
    layout
}

struct ColdPreparation {
    mode: ActiveReplacementLaunchMode,
    warning: Option<String>,
}

fn explicit_unreachable_primary(k: &Kernel<'_>, primary: SocketAddr) -> io::Result<bool> {
    if !primary.is_ipv4() {
        return Ok(false);
    }
    let address = primary.ip().to_string();
    let host = format!("{address}/32");
    let exact_destination = |dst: &str| dst == address || dst == host;
    let routes = k.call(
        "ip",
        &["-4", "-o", "route", "show", "table", "main", "exact", &host],
    )?;
    if routes.lines().any(|line| {
        let mut fields = line.split_ascii_whitespace();
        fields.next() == Some("unreachable") && fields.next().is_some_and(exact_destination)
    }) {
        return Ok(true);
    }
    let rules = k.call("ip", &["-4", "-o", "rule", "show"])?;
    Ok(rules.lines().any(|line| {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        matches!(fields.as_slice(), [priority, "from", "all", "to", dst, "unreachable"]
            if priority.strip_suffix(':').is_some_and(|number| number.parse::<u32>().is_ok())
                && exact_destination(dst))
    }))
}

fn next_numeric_cold_endpoint(
    k: &Kernel<'_>,
    pool: &ActiveReplacementNumericPool,
    wan: &[String],
) -> io::Result<SocketAddr> {
    let (primary, _) = pool.primary();
    let error = match mtu_edit::replacement_wan(k, primary, 0, wan) {
        Ok(()) => return Ok(primary),
        Err(error) => error,
    };
    if !nfqws2_router_command::reported_failure(&error)
        || !explicit_unreachable_primary(k, primary)?
    {
        return Err(error);
    }
    pool.reserves()
        .iter()
        .copied()
        .find(|&endpoint| mtu_edit::replacement_wan(k, endpoint, 0, wan).is_ok())
        .ok_or(error)
}

fn sole_dormant_primary(
    before: &Value,
    after: &Value,
    plan: &Plan,
    target: &str,
    primary: SocketAddr,
) -> io::Result<IpAddr> {
    if super::transport_claims::Claims::read(before, plan, false, None)?
        .sole_primary(target, primary)
        && super::transport_claims::Claims::read(after, plan, false, None)?
            .sole_primary(target, primary)
    {
        Ok(primary.ip())
    } else {
        Err(ineligible())
    }
}

fn literal_startup_scope(plan: &Plan) -> bool {
    plan.targets.len() == 1 && plan.marks.is_empty() && plan.learned.is_none() && plan.dns.is_none()
}

fn prepare_cold_replacement(
    db: &Store,
    run: &dyn Runner,
    ActiveReplacementStage {
        before,
        after,
        source,
        held,
        target,
        provisional,
    }: ActiveReplacementStage<'_>,
    wan: &[String],
    (dns, names): (
        Option<&ActiveDnsReplacementProof>,
        Option<&NamedActiveReplacement>,
    ),
    before_write: Option<&dyn Fn() -> io::Result<()>>,
) -> io::Result<ColdPreparation> {
    db.transaction(|tx| {
        let old = Journal::read(db)?;
        let (iface, entry) = cold_launch_target(&old, held.map(|peer| &peer.owner))?;
        let revision = old.committed.revision;
        let target_before = row(before, target).ok_or_else(ineligible)?;
        let target_after = row(after, target).ok_or_else(ineligible)?;
        let unresolved = names.is_some_and(NamedActiveReplacement::target_unresolved);
        let pin = names
            .filter(|_| !unresolved)
            .map(|names| names.cold_pin(&old, &source.owner.id, target))
            .transpose()?;
        let claims = names.map(|names| &names.claims);
        let warm = pin.is_some_and(|pin| pin.warm_ipv6);
        let numeric = has_endpoint_backups(before, target);
        if names.is_some()
            && (held.is_some() || dns.is_some() || before_write.is_some() && provisional.is_some())
            || unresolved && before_write.is_none()
            || warm && before_write.is_some()
        {
            return Err(ineligible());
        }
        if numeric
            && (names.is_some()
                || held.is_some()
                || dns.is_some()
                || before_write.is_some()
                || old.installed.learned.is_some())
        {
            return Err(ineligible());
        }
        if !source.owner.valid()
            || source.owner.nested.is_some()
            || source.owner.id != entry.id
            || source.owner.iface != iface
            || source.owner.boot != old.boot
            || source.owner.id == target
            || row(before, &source.owner.id)
                .is_none_or(|row| row["config"]["routing"]["active"] != true)
            || target_before["config"]["routing"]["active"] == true
            || target_after["config"]["routing"]["active"] != true
            || target_after["config"]["client"]["standby"] != false
            || row(after, &source.owner.id).is_some()
            || !profile_rebind::owner_matches_all(
                before,
                &old,
                std::iter::once(source.owner.id.as_str())
                    .chain(held.map(|peer| peer.owner.id.as_str())),
                revision,
            )
            || before["routing_revision"].as_u64() != Some(revision)
            || revision.checked_add(1) != after["routing_revision"].as_u64()
            || before["rust_static_routing"] != after["rust_static_routing"]
            || before.get(FIELD).is_some()
            || after.get(FIELD).is_some()
            || active_replacement_in_progress(db)?
            || profile_rebind::pending(before)
            || handoff::pending(db)?
            || mtu_edit::pending_mtu_edit(db)?
            || names.is_none()
                && (plan::has_named_endpoint(before) || plan::has_named_endpoint(after))
            || nfqws2_awg_profile::read(db)? != *before
        {
            return Err(ineligible());
        }
        let (prior, next) = policies(
            before,
            after,
            &source.owner.id,
            target,
            held.map(|peer| peer.owner.id.as_str()),
        )?;
        if active_replacement_topology(before, after, &source.owner.id, target)? {
            return Err(ineligible());
        }
        let k = kernel(run);
        let (configured, fingerprint, numeric_pool, reserve) =
            if let Some(names) = names.filter(|_| unresolved) {
                let fingerprint = names.verify_unresolved(&old, before, source, target)?;
                if fingerprint != names.verify_unresolved(&old, after, source, target)? {
                    return Err(ineligible());
                }
                (None, fingerprint, None, None)
            } else if let Some((pin, claims)) = pin.zip(claims) {
                let before_hash = claims.verify_configured(before, target, pin.endpoint)?;
                if claims.verify_configured(after, target, pin.endpoint)? != before_hash {
                    return Err(ineligible());
                }
                (Some(pin.endpoint), before_hash, None, None)
            } else if numeric {
                let previous = active_replacement_numeric_pool(before, target)?;
                let next = active_replacement_numeric_pool(after, target)?;
                let (primary, binding) = previous.primary();
                if next.primary() != (primary, binding)
                    || previous.wire_fingerprint != next.wire_fingerprint
                {
                    return Err(ineligible());
                }
                let endpoint = next_numeric_cold_endpoint(&k, &previous, wan)?;
                let binding = previous.binding(endpoint).ok_or_else(ineligible)?;
                (
                    Some(endpoint),
                    previous.wire_fingerprint,
                    Some(binding),
                    (endpoint != primary).then_some((endpoint, primary)),
                )
            } else {
                let endpoint = active_replacement_endpoint(before, target)?;
                let fingerprint = active_replacement_fingerprint(before, target)?;
                if fingerprint != active_replacement_fingerprint(after, target)?
                    || endpoint != active_replacement_endpoint(after, target)?
                {
                    return Err(ineligible());
                }
                (Some(endpoint), fingerprint, None, None)
            };
        let literal_startup = !numeric
            && names.is_none()
            && dns.is_none()
            && held.is_none()
            && before_write.is_none()
            && literal_startup_scope(&old.installed)
            && active_replacement_startup_binding(before, target).ok() == Some(fingerprint)
            && active_replacement_startup_binding(after, target).ok() == Some(fingerprint);
        let result = ColdPreparation {
            mode: if let Some((endpoint, _)) = reserve {
                ActiveReplacementLaunchMode::Reserve(endpoint)
            } else if numeric || literal_startup {
                ActiveReplacementLaunchMode::ConfiguredPrimary
            } else {
                ActiveReplacementLaunchMode::Authenticate
            },
            warning: None,
        };
        if reserve.is_some() && !literal_startup_scope(&old.installed) {
            return Err(ineligible());
        }
        let excluded = reserve
            .map(|(_, primary)| {
                sole_dormant_primary(before, after, &old.installed, target, primary)
            })
            .transpose()?
            .into_iter()
            .collect::<BTreeSet<_>>();
        let affected = held.map(|_| iface);
        if !fits_routes_for(
            &old.installed,
            &active_replacement_allowed(after, target)?,
            configured.unwrap_or(source.endpoint).ip(),
            affected,
        )? {
            return Err(ineligible());
        }
        let members = live_dns_members(&old.installed)?;
        let mixed = mixed_dns_plan(&old.installed)?.is_some();
        let renewed = match dns {
            Some(proof)
                if proof.request.prior == old
                    && proof.request.source == source.owner.id
                    && proof.request.held_profile() == held.map(|peer| peer.owner.id.as_str()) =>
            {
                if proof
                    .fresh_until
                    .is_some_and(|until| until <= Instant::now())
                    || proof.renewed.iter().any(|member| {
                        (!mixed || member.until != RETIRED_FIRMWARE_MEMBER)
                            && member.until <= nfqws2_awg_profile::now()
                    })
                {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                proof.renewed.as_slice()
            }
            // A failed launch cannot program a new DNS address. Keep the
            // exact installed membership and its original expiration.
            None if before_write.is_some() => members,
            None if members.is_empty() => &[],
            _ => return Err(ineligible()),
        };
        let bridges = &old.installed.dns_bridges;
        let layout = old.installed.layout();
        let rows = after["servers"].as_array().ok_or_else(ineligible)?;
        let (_, target_iface, _) = plan::profile(after, rows, target)?;
        let new_layout = held.map_or_else(
            || layout.clone(),
            |_| held_layout(&old.installed, iface, &target_iface, false),
        );
        let mut projected = plan::compile_effective(after, next, None, true, renewed, new_layout)?;
        projected.set_dns_bridges(bridges)?;
        if let Some(held) = held {
            if let Some(&mss) = old.installed.mss.get(&held.owner.iface) {
                projected.mss.insert(held.owner.iface.clone(), mss);
            }
        }
        let plan: Snapshot = projected.into();
        let mut possible = Journal {
            boot: old.boot.clone(),
            installed: plan.clone(),
            committed: plan,
            ..Default::default()
        };
        let (future_iface, future) = cold_launch_target(&possible, held.map(|peer| &peer.owner))?;
        if future_iface == iface
            || future.id != target
            || !stopped_scope(&old, &possible)
            || reserve.is_some() && !literal_startup_scope(&possible.installed)
        {
            return Err(ineligible());
        }

        if old.boot != boot_id(&k)? {
            return Err(ineligible());
        }
        preflight_stop(&k, &old)?;
        verify_peer_bound(before, source, &old.installed, affected, (claims, numeric))?;
        k.verify_forward(&old.installed)?;
        mtu_edit::replacement_wan(&k, source.endpoint, source.socket_mark, wan)?;
        if let Some(held) = held {
            if !held.owner.valid()
                || held.owner.nested.is_some()
                || held.underlay.is_some()
                || held.owner.boot != old.boot
                || !distinct_owner(&held.owner, &source.owner)
                || row(before, &held.owner.id) != row(after, &held.owner.id)
            {
                return Err(ineligible());
            }
            verify_peer_for(before, held, &old.installed, Some(&held.owner.iface))?;
            mtu_edit::replacement_wan(&k, held.endpoint, held.socket_mark, wan)?;
        }
        if resolve_with_names(
            &k,
            before,
            prior,
            (source, held),
            layout,
            &excluded,
            (bridges, members, claims),
        )? != *old.committed
        {
            return Err(ineligible());
        }
        let mut endpoints = BTreeSet::new();
        plan::visit_transport_endpoints(
            after,
            false,
            (None, claims),
            |_| true,
            |_, _, ip| {
                endpoints.insert(ip);
            },
        )?;
        if numeric {
            plan::visit_transport_endpoints(
                before,
                false,
                (None, None),
                |row| row["id"] == source.owner.id,
                |_, _, ip| {
                    endpoints.insert(ip);
                },
            )?;
        }
        if endpoints.iter().any(|ip| {
            old.installed
                .prefixes
                .keys()
                .any(|prefix| prefix.contains(*ip))
        }) {
            return Err(ineligible());
        }
        k.guard(
            &possible.installed,
            &endpoints.difference(&excluded).copied().collect(),
        )?;
        let Some(peer) = provisional else {
            if let Some(configured) = configured {
                mtu_edit::replacement_wan(&k, configured, 0, wan)?;
            }
            if let Some(names) = names {
                for &address in names.unselected_ipv6() {
                    mtu_edit::replacement_wan(&k, address, 0, wan)?;
                }
                for &address in names.warm_ipv6_addresses() {
                    mtu_edit::replacement_wan(
                        &k,
                        address,
                        nfqws2_awg_profile::DIRECT_SOCKET_MARK,
                        wan,
                    )?;
                }
            }
            if super::routed_disable::link_names(&k)?.contains(future_iface) {
                return Err(ineligible());
            }
            if let Some(names) = names {
                names.check_expiry()?;
            }
            let Some(before_write) = before_write else {
                return Ok(result);
            };
            let mss = future.mtu.checked_sub(40).ok_or_else(ineligible)?;
            let future_iface = future_iface.to_owned();
            possible.installed.mss.insert(future_iface, mss);
            possible.committed = possible.installed.clone();
            let verify = || {
                if let Some(names) = names {
                    names.check_expiry()?;
                }
                before_write()?;
                if let Some(names) = names {
                    names.check_expiry()?;
                }
                Ok(())
            };
            return persist_deferred_launch(
                db,
                tx,
                run,
                (before, after),
                (old, possible),
                (source, held),
                DeferredLaunchScope {
                    fingerprint,
                    wan,
                    before_write: &verify,
                    named: names.map(|names| names.seal_deferred(source, pin)),
                },
            )
            .map(|warning| ColdPreparation {
                mode: ActiveReplacementLaunchMode::Authenticate,
                warning,
            });
        };
        if before_write.is_some() {
            return Err(ineligible());
        }
        if !peer.owner.valid()
            || peer.owner.id != target
            || peer.owner.iface != future_iface
            || peer.owner.boot != old.boot
            || peer.owner.pid == source.owner.pid
            || peer.owner.receipt_sha256 == source.owner.receipt_sha256
            || held.is_some_and(|held| !distinct_owner(&peer.owner, &held.owner))
        {
            return Err(ineligible());
        }
        if Some(peer.endpoint) != configured
            || warm && peer.socket_mark != nfqws2_awg_profile::DIRECT_SOCKET_MARK
        {
            return Err(ineligible());
        }
        verify_peer_bound(
            after,
            peer,
            &possible.installed,
            held.map(|_| future_iface),
            (claims, numeric),
        )?;
        mtu_edit::replacement_wan(&k, peer.endpoint, peer.socket_mark, wan)?;
        if let Some(names) = names {
            names.check_expiry()?;
        }
        tx.save_runtime_bounded(
            LAUNCH,
            &ActiveReplacementLaunchLease {
                prior: profile_rebind::digest(&old)?,
                source: source.owner.clone(),
                target: peer.owner.clone(),
                fingerprint,
                named_endpoint: pin.map(|pin| pin.endpoint),
                warm_ipv6: warm,
                numeric_pool,
                literal_startup,
                target_was_standby: (target_before["config"]["client"]["standby"] != true)
                    .then_some(false),
            },
            LAUNCH_LIMIT,
        )?;
        Ok(result)
    })
}

/// The profile caller holds its operation and Store locks and supplied both
/// authenticated running peers. This callback does not acquire client locks.
pub fn replace_active_profile(
    db: &Store,
    tx: &Transaction<'_>,
    run: &dyn Runner,
    before: &Value,
    after: &Value,
    peers: &[ActiveReplacementPeer; 2],
    wan: &[String],
) -> io::Result<Option<String>> {
    replace_active_profile_checked(db, tx, run, before, after, (peers, wan), || Ok(()))
}

/// Open the DNS publication bracket only after a complete read-only proof.
pub fn replace_active_profile_checked(
    db: &Store,
    tx: &Transaction<'_>,
    run: &dyn Runner,
    before: &Value,
    after: &Value,
    (peers, wan): (&[ActiveReplacementPeer; 2], &[String]),
    before_write: impl FnOnce() -> io::Result<()>,
) -> io::Result<Option<String>> {
    replace_active_profile_with_dns(db, tx, run, before, after, (peers, wan, None), before_write)
}

pub fn replace_active_profile_with_dns(
    db: &Store,
    tx: &Transaction<'_>,
    run: &dyn Runner,
    before: &Value,
    after: &Value,
    (peers, wan, dns): (
        &[ActiveReplacementPeer; 2],
        &[String],
        Option<&ActiveDnsReplacementProof>,
    ),
    before_write: impl FnOnce() -> io::Result<()>,
) -> io::Result<Option<String>> {
    replace_profiles(
        db,
        tx,
        run,
        before,
        after,
        (peers, None, wan, ReplacementProof::Ordinary(dns)),
        before_write,
    )
}

/// Transfer a confirmed IPv4 policy with at least one named transport, using
/// the bounded answers obtained before taking writer locks.
pub fn replace_active_profile_with_names(
    db: &Store,
    tx: &Transaction<'_>,
    run: &dyn Runner,
    before: &Value,
    after: &Value,
    (peers, wan, names): (
        &[ActiveReplacementPeer; 2],
        &[String],
        &NamedActiveReplacement,
    ),
    before_write: impl FnOnce() -> io::Result<()>,
) -> io::Result<Option<String>> {
    replace_profiles(
        db,
        tx,
        run,
        before,
        after,
        (peers, None, wan, ReplacementProof::Named(names, None)),
        before_write,
    )
}

/// Write a previously withheld managed AAAA answer. Each transition
/// revalidates its original resolver and bounded receipt.
pub fn replace_active_profile_with_warm_name(
    db: &Store,
    tx: &Transaction<'_>,
    run: &dyn Runner,
    before: &Value,
    after: &Value,
    (peers, wan, names, verify_origin): (
        &[ActiveReplacementPeer; 2],
        &[String],
        &NamedActiveReplacement,
        &dyn Fn() -> io::Result<()>,
    ),
    before_write: impl FnOnce() -> io::Result<()>,
) -> io::Result<Option<String>> {
    replace_profiles(
        db,
        tx,
        run,
        before,
        after,
        (
            peers,
            None,
            wan,
            ReplacementProof::Named(names, Some(verify_origin)),
        ),
        before_write,
    )
}

pub fn replace_active_profile_with_held_dns(
    db: &Store,
    tx: &Transaction<'_>,
    run: &dyn Runner,
    before: &Value,
    after: &Value,
    (peers, held, wan, dns): (
        &[ActiveReplacementPeer; 2],
        &ActiveReplacementPeer,
        &[String],
        &ActiveDnsReplacementProof,
    ),
    before_write: impl FnOnce() -> io::Result<()>,
) -> io::Result<Option<String>> {
    replace_profiles(
        db,
        tx,
        run,
        before,
        after,
        (
            peers,
            Some(held),
            wan,
            ReplacementProof::Ordinary(Some(dns)),
        ),
        before_write,
    )
}

enum ReplacementProof<'a> {
    Ordinary(Option<&'a ActiveDnsReplacementProof>),
    Named(
        &'a NamedActiveReplacement,
        Option<&'a dyn Fn() -> io::Result<()>>,
    ),
}

fn replace_profiles(
    db: &Store,
    tx: &Transaction<'_>,
    run: &dyn Runner,
    before: &Value,
    after: &Value,
    (peers, held, wan, proof): (
        &[ActiveReplacementPeer; 2],
        Option<&ActiveReplacementPeer>,
        &[String],
        ReplacementProof<'_>,
    ),
    before_write: impl FnOnce() -> io::Result<()>,
) -> io::Result<Option<String>> {
    let (dns, names, verify_origin) = match proof {
        ReplacementProof::Ordinary(dns) => (dns, None, None),
        ReplacementProof::Named(names, verify) => (None, Some(names), verify),
    };
    let claims = names.map(|names| &names.claims);
    let warm = names.is_some_and(|names| !names.warm_ipv6_addresses().is_empty());
    if warm != verify_origin.is_some() {
        return Err(ineligible());
    }
    let [source, target] = peers;
    let prior = Journal::read(db)?;
    if let Some(names) = names {
        names.verify_scope(&prior, peers)?;
        if held.is_some() {
            return Err(ineligible());
        }
    }
    let (iface, current) = replacement_route_target(&prior)?;
    let held_target = independent_dns_peer(&prior.installed)?;
    let moved = moved_dns_client(&prior);
    let receiver_holds_global = held_target.is_some_and(|(_, owner)| owner.id == target.owner.id);
    if held_target.map(|(_, target)| target.id.as_str()) != held.map(|peer| peer.owner.id.as_str())
    {
        return Err(ineligible());
    }
    let revision = prior.committed.revision;
    if !source.owner.valid()
        || !target.owner.valid()
        || source.underlay.as_ref().is_some_and(|outer| {
            outer.owner.pid == target.owner.pid
                || outer.owner.receipt_sha256 == target.owner.receipt_sha256
        })
        || source.owner.id != current.id
        || source.owner.iface != iface
        || source.owner.id == target.owner.id
        || source.owner.iface == target.owner.iface
        || source.owner.pid == target.owner.pid
        || source.owner.boot != prior.boot
        || target.owner.boot != prior.boot
        || source.owner.receipt_sha256 == target.owner.receipt_sha256
        || row(before, &source.owner.id).is_none()
        || row(after, &source.owner.id).is_some()
        || row(before, &target.owner.id).is_none()
        || row(after, &target.owner.id).is_none()
        || row(before, &source.owner.id).unwrap()["config"]["routing"]["active"] != true
        || (row(before, &target.owner.id).unwrap()["config"]["routing"]["active"] == true)
            != receiver_holds_global
        || row(after, &target.owner.id).unwrap()["config"]["routing"]["active"] != true
        || row(after, &target.owner.id).unwrap()["config"]["client"]["standby"] != false
        || !profile_rebind::owner_matches_all(
            before,
            &prior,
            std::iter::once(source.owner.id.as_str())
                .chain(held.map(|peer| peer.owner.id.as_str())),
            revision,
        )
        || before["routing_revision"].as_u64() != Some(revision)
        || revision.checked_add(1) != after["routing_revision"].as_u64()
        || before["rust_static_routing"] != after["rust_static_routing"]
        || before.get(FIELD).is_some()
        || after.get(FIELD).is_some()
        || pending(db)?
        || profile_rebind::pending(before)
        || handoff::pending(db)?
        || mtu_edit::pending_mtu_edit(db)?
        || names.is_none() && (plan::has_named_endpoint(before) || plan::has_named_endpoint(after))
    {
        return Err(ineligible());
    }
    let configured_outer =
        active_replacement_topology(before, after, &source.owner.id, &target.owner.id)?;
    if let Some((held, (held_iface, _))) = held.zip(held_target) {
        if configured_outer
            || source.owner.nested.is_some()
            || target.owner.nested.is_some()
            || !held.owner.valid()
            || held.owner.nested.is_some()
            || held.underlay.is_some()
            || held.owner.boot != prior.boot
            || held.owner.iface != held_iface
            || !distinct_owner(&held.owner, &source.owner)
            || if receiver_holds_global {
                held != target
            } else {
                !distinct_owner(&held.owner, &target.owner)
                    || row(before, &held.owner.id) != row(after, &held.owner.id)
            }
            || row(before, &held.owner.id)
                .is_none_or(|row| row["config"]["routing"]["active"] != true)
            || dns.is_none_or(|proof| proof.request.held_profile() != Some(held.owner.id.as_str()))
        {
            return Err(ineligible());
        }
        verify_peer_for(before, held, &prior.installed, Some(held_iface))?;
        verify_peer_for(after, held, &prior.installed, Some(held_iface))?;
    }
    if (configured_outer || names.is_some()) && nfqws2_awg_profile::read(db)? != *before {
        return Err(ineligible());
    }
    let launch = read_launch(db)?;
    if warm && !launch.as_ref().is_some_and(|launch| launch.warm_ipv6) {
        return Err(ineligible());
    }
    let allow_backups = has_endpoint_backups(before, &source.owner.id)
        || has_endpoint_backups(before, &target.owner.id)
        || has_endpoint_backups(after, &target.owner.id);
    if allow_backups {
        let old = row(before, &target.owner.id).ok_or_else(ineligible)?;
        let new = row(after, &target.owner.id).ok_or_else(ineligible)?;
        if configured_outer
            || source.owner.nested.is_some()
            || target.owner.nested.is_some()
            || names.is_some()
            || dns.is_some()
            || held.is_some()
            || prior.installed.learned.is_some()
            || !prior.installed.marks.is_empty()
            || launch
                .as_ref()
                .is_some_and(|launch| launch.numeric_pool.is_none())
            || old["config"]["client"]["endpoint_backups"]
                != new["config"]["client"]["endpoint_backups"]
        {
            return Err(ineligible());
        }
    }
    let affected = held.map(|_| iface);
    let binding = (claims, allow_backups);
    verify_peer_bound(before, source, &prior.installed, affected, binding)?;
    verify_peer_bound(before, target, &prior.installed, affected, binding)?;
    verify_peer_bound(after, target, &prior.installed, affected, binding)?;
    let (source_fingerprint, target_fingerprint) = if allow_backups {
        (
            durable_endpoint_fingerprint(before, source)?,
            durable_endpoint_fingerprint(after, target)?,
        )
    } else {
        (source.fingerprint, target.fingerprint)
    };
    let nested_target = if let Some(outer) = &target.underlay {
        let sealed = NestedTarget {
            owner: target.owner.clone(),
            outer: outer.owner.clone(),
            outer_fingerprint: Some(outer.fingerprint),
            source_outer: source
                .underlay
                .as_ref()
                .filter(|old| old.owner != outer.owner)
                .map(|old| NestedSourceOuter {
                    owner: old.owner.clone(),
                    fingerprint: old.fingerprint,
                }),
        };
        if !sealed.binds(&source.owner, &target.owner.id, &target.owner.iface)
            || row(before, &outer.owner.id).is_none_or(|r| r["config"]["client"]["standby"] == true)
        {
            return Err(ineligible());
        }
        Some(sealed)
    } else {
        None
    };
    let source_permanent = !prior.installed.permanent_fences.is_empty();
    let retiring_nested = if source_permanent && nested_target.is_none() {
        let outer = source.underlay.as_ref().ok_or_else(ineligible)?;
        let sealed = RetiringNested {
            outer: NestedSourceOuter {
                owner: outer.owner.clone(),
                fingerprint: outer.fingerprint,
            },
            target: target.owner.clone(),
        };
        if !sealed.binds(&source.owner, &target.owner.id, &target.owner.iface)
            || row(before, &outer.owner.id).is_none_or(|r| r["config"]["client"]["standby"] == true)
        {
            return Err(ineligible());
        }
        Some(sealed)
    } else {
        None
    };
    if !prior.installed.marks.is_empty() {
        let old = row(before, &source.owner.id).ok_or_else(ineligible)?;
        let new = row(after, &target.owner.id).ok_or_else(ineligible)?;
        let permanent = |row: &Value| row["config"]["client"]["double_tunnel_mode"] == "permanent";
        if permanent(old) != source_permanent
            || permanent(new) != nested_target.is_some()
            || nested_target
                .as_ref()
                .and_then(|target| target.source_outer.as_ref())
                .is_some_and(|old| {
                    row(before, &old.owner.id)
                        .is_none_or(|r| r["config"]["client"]["standby"] == true)
                })
        {
            return Err(ineligible());
        }
    }
    let (startup, reserve_pool) = if let Some(launch) = launch {
        let named_endpoint = names
            .map(|names| names.cold_pin(&prior, &source.owner.id, &target.owner.id))
            .transpose()?
            .map(|pin| pin.endpoint);
        if configured_outer
            || launch.prior != profile_rebind::digest(&prior)?
            || launch.source != source.owner
            || launch.target != target.owner
            || launch.fingerprint != target.fingerprint
            || launch.named_endpoint != named_endpoint
            || launch.warm_ipv6 != warm
            || launch.numeric_pool
                != has_endpoint_backups(before, &target.owner.id).then_some(target_fingerprint)
            || launch.literal_startup
                && (held.is_some()
                    || names.is_some()
                    || dns.is_some()
                    || !literal_startup_scope(&prior.installed)
                    || active_replacement_startup_binding(before, &target.owner.id)?
                        != launch.fingerprint
                    || active_replacement_startup_binding(after, &target.owner.id)?
                        != launch.fingerprint)
            || named_endpoint.is_some_and(|endpoint| target.endpoint != endpoint)
        {
            return Err(ineligible());
        }
        if let Some(binding) = launch.numeric_pool {
            let pool = active_replacement_numeric_pool(before, &target.owner.id)?;
            if pool.primary().1 == binding {
                (Some(binding), None)
            } else {
                (None, Some(pool))
            }
        } else {
            (launch.literal_startup.then_some(launch.fingerprint), None)
        }
    } else {
        (None, None)
    };
    let (old_policy, new_policy) = policies(
        before,
        after,
        &source.owner.id,
        &target.owner.id,
        held.map(|held| held.owner.id.as_str()),
    )?;
    let mut k = kernel(run);
    if prior.boot != boot_id(&k)? {
        return Err(ineligible());
    }
    if let Some(held) = held {
        mtu_edit::replacement_wan(&k, held.endpoint, held.socket_mark, wan)?;
    }
    let nested_only = nested_only_endpoints(before, &prior.installed, peers)?;
    if source.owner.nested.is_some() {
        verify_nested_peer(
            &k,
            before,
            source,
            wan,
            !nested_only.contains(&source.endpoint.ip()),
        )?;
        let (mark, table) = nested_socket_selector(&source.owner.iface)?;
        k.nested_sockets.insert(mark, table);
    } else {
        mtu_edit::replacement_wan(&k, source.endpoint, source.socket_mark, wan)?;
    }
    if nested_target.is_some() {
        verify_nested_peer(
            &k,
            before,
            target,
            wan,
            !nested_only.contains(&target.endpoint.ip()),
        )?;
        let (mark, table) = nested_socket_selector(&target.owner.iface)?;
        k.nested_sockets.insert(mark, table);
    } else {
        mtu_edit::replacement_wan(&k, target.endpoint, target.socket_mark, wan)?;
    }
    let mut excluded = nested_only;
    if let Some(pool) = &reserve_pool {
        if next_numeric_cold_endpoint(&k, pool, wan)? != target.endpoint {
            return Err(ineligible());
        }
        excluded.insert(sole_dormant_primary(
            before,
            after,
            &prior.installed,
            &target.owner.id,
            pool.primary().0,
        )?);
    }
    if let Some(names) = names {
        for &address in names.warm_ipv6_addresses() {
            mtu_edit::replacement_wan(&k, address, nfqws2_awg_profile::DIRECT_SOCKET_MARK, wan)?;
        }
    }
    preflight_stop(&k, &prior)?;
    k.verify_forward(&prior.installed)?;
    let layout = prior.installed.layout();
    let dns_bridges = &prior.installed.dns_bridges;
    let members = live_dns_members(&prior.installed)?;
    let mixed = mixed_dns_plan(&prior.installed)?.is_some();
    let renewed = match dns {
        Some(proof) if proof.request.prior == prior && proof.request.source == source.owner.id => {
            &proof.renewed[..]
        }
        None if members.is_empty() => &[],
        _ => return Err(ineligible()),
    };
    let verify_expiry = || -> io::Result<()> {
        if renewed.iter().any(|member| {
            (!mixed || member.until != RETIRED_FIRMWARE_MEMBER)
                && member.until <= nfqws2_awg_profile::now()
        }) {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(())
    };
    let verify_freshness = || -> io::Result<()> {
        if let Some(names) = names {
            names.check_expiry()?;
        }
        if let Some(pool) = &reserve_pool {
            if next_numeric_cold_endpoint(&k, pool, wan)? != target.endpoint {
                return Err(ineligible());
            }
            mtu_edit::replacement_wan(&k, target.endpoint, target.socket_mark, wan)?;
        }
        if let Some(verify) = verify_origin {
            verify()?;
        }
        if dns
            .and_then(|proof| proof.fresh_until)
            .is_some_and(|until| until <= Instant::now())
        {
            return Err(io::ErrorKind::TimedOut.into());
        }
        verify_expiry()
    };
    if resolve_with_names(
        &k,
        before,
        old_policy,
        (source, held),
        layout.clone(),
        &excluded,
        (dns_bridges, members, claims),
    )? != *prior.committed
    {
        return Err(ineligible());
    }
    let layout = held.map_or(layout, |_| {
        held_layout(
            &prior.installed,
            iface,
            &target.owner.iface,
            receiver_holds_global,
        )
    });
    let installed: Snapshot = resolve_with_names(
        &k,
        after,
        new_policy,
        (target, held),
        layout,
        &excluded,
        (dns_bridges, renewed, claims),
    )?
    .into();
    let next = Journal {
        boot: prior.boot.clone(),
        installed: installed.clone(),
        committed: installed,
        ..Journal::default()
    };
    replacement_route_target(&next)?;
    if dns.is_some_and(|proof| proof.fresh_until.is_some()) {
        verify_peer_for(
            after,
            target,
            &next.installed,
            held.map(|_| target.owner.iface.as_str()),
        )?;
        if k.inventory_for(
            &prior.claims(),
            &objects(&guarded(&next, moved).installed),
            true,
        )? != objects(&prior.installed)
        {
            return Err(ineligible());
        }
    }
    if !stopped_scope(&prior, &next)
        || !packed_transport_roles(
            &prior,
            &next,
            &source.owner,
            nested_target.as_ref(),
            retiring_nested.as_ref(),
        )
    {
        return Err(ineligible());
    }
    let mut switched_doc = before.clone();
    stamp_document(&mut switched_doc, &next)?;
    let mut candidate = after.clone();
    stamp_document(&mut candidate, &next)?;
    let temporary = unprotected(&prior)
        || unprotected(&next)
        || retiring_firmware_members(&next)
        || reserve_pool.is_some()
        || warm;
    if names.is_some() && profile_rebind::native_ipv4_prefixes(&next).is_err() {
        return Err(ineligible());
    }
    let transport_policy = if configured_outer && temporary {
        Some(TransportPolicy {
            source: active_replacement_transport_stamp(before, &source.owner.id)?,
            target: active_replacement_transport_stamp(after, &target.owner.id)?,
        })
    } else {
        None
    };
    let temporary_stop = temporary.then(|| TemporaryStop {
        target_fingerprint,
        cold_reserve_primary: reserve_pool.as_ref().map(|pool| pool.primary().0),
        target_owner: (held.is_some() || names.is_some()).then(|| target.owner.clone()),
        wan: wan.to_vec(),
        transport_policy,
        named: names.map(|names| names.seal(peers)),
        rotation: None,
        deferred_launch: false,
        released: false,
        teardown: false,
    });
    let retained_outer = source.underlay.as_ref().and_then(|outer| {
        row(before, &outer.owner.id)
            .is_some_and(|r| r["config"]["client"]["standby"] == true)
            .then(|| outer.owner.clone())
    });
    let held_direct = held.map(|held| HeldDirect {
        owner: held.owner.clone(),
        fingerprint: held.fingerprint,
        wan: wan.to_vec(),
    });
    let token = token(
        &source.owner,
        &source_fingerprint,
        &prior,
        &next,
        temporary_stop.as_ref(),
        (retained_outer.as_ref(), held_direct.as_ref()),
        (nested_target.as_ref(), retiring_nested.as_ref()),
    )?;
    candidate[FIELD] = json!({ "id":source.owner.id, "token":token });
    if let Some(outer) = &retained_outer {
        candidate[FIELD]["retained_outer"] = json!(outer);
    }
    let mut transfer = Transfer {
        prior,
        next,
        source: source.owner.clone(),
        source_fingerprint,
        disabled_target: None,
        retained_outer,
        held_direct,
        nested_target,
        retiring_nested,
        token,
        temporary_stop,
        retry_runtime: false,
        retry_dns: None,
        retry_projection: None,
        retry_positive_hint: None,
        retry_negative_name: None,
        retry_positive_pair: None,
        retired: false,
    };
    verify_freshness()?;
    before_write()?;
    verify_freshness()?;
    if let Some(binding) = startup {
        tx.save_runtime_bounded(
            COLD_NUMERIC_STARTUP,
            &ColdNumericStartup {
                owner: target.owner.clone(),
                binding,
                committed: profile_rebind::digest(&transfer.next.committed)?,
            },
            LAUNCH_LIMIT,
        )?;
    }
    save(tx, &transfer)?;
    let covered = |journal: &Journal| {
        if temporary {
            guarded(journal, moved)
        } else {
            journal.clone()
        }
    };
    let covered_prior = covered(&transfer.prior);
    let covered_next = covered(&transfer.next);
    let result = (|| {
        if transfer.temporary_stop.is_some() {
            // Finish installing all stops after an ambiguous partial write.
            // Rolling back a subset could withdraw the shared lookup while
            // another destination still lacks its temporary stop.
            transition(
                db,
                tx,
                run,
                &transfer.prior,
                &covered_prior,
                Some(&covered_prior),
            )?;
        }
        verify_freshness()?;
        transition(db, tx, run, &covered_prior, &covered_next, None)?;
        verify_freshness()?;
        persist_active_replacement_locked(db, tx, &switched_doc, &candidate)
    })();
    let mut warning = match result {
        Ok(warning) => warning,
        Err(error) => {
            // Check both durable outcomes before operating on the old route.
            let mut actual = Journal::read(db)?;
            if actual == covered_next && db.read::<Value>("awg.json").is_ok_and(|v| v == candidate)
            {
                Some("перенос правил подтверждён после ошибки записи".into())
            } else {
                let retry_names = dns.and_then(|proof| proof.retry_names.as_deref());
                if actual == covered_prior
                    && error
                        .get_ref()
                        .is_some_and(|error| error.is::<super::RouteWriteRejected>())
                    && !configured_outer
                    && !allow_backups
                    && names.is_none()
                    && supports_runtime_retry(&transfer, retry_names)
                    && (retry_names.is_some()
                        || dns.is_none_or(|proof| proof.fresh_until.is_none()))
                    && verify_freshness().is_ok()
                {
                    return keep_runtime_retry(
                        db,
                        tx,
                        run,
                        &mut transfer,
                        &actual,
                        (before, &mut candidate),
                        (target, wan, dns),
                    );
                }
                let current = nfqws2_awg_profile::read(db)?;
                if transfer.temporary_stop.is_some() {
                    // The request still holds both native owners. Only the
                    // exact old document or its own FIB stamp can reuse the
                    // source sample, subject to fresh kernel and WAN checks.
                    let mut previous = |_: &Value, iface: &str| {
                        attested_peer(
                            held.filter(|held| held.owner.iface == iface)
                                .unwrap_or(source),
                            iface,
                        )
                    };
                    let witness = (&current == before || current == switched_doc)
                        .then_some(&mut previous as &mut PeerReader<'_>);
                    recover_temporary(
                        db,
                        tx,
                        run,
                        &mut actual,
                        &mut transfer,
                        &current,
                        (witness, None),
                    )?;
                } else {
                    recover_original(tx, db, run, &mut actual, &transfer, &current, |_| {
                        Ok(held.cloned())
                    })?;
                }
                return Err(error);
            }
        }
    };
    if let Some(require_native) = transfer
        .temporary_stop
        .as_ref()
        .map(|stop| stop.transport_policy.is_some() || stop.target_owner.is_some())
    {
        let settled = (|| {
            verify_expiry()?;
            if let Some(names) = names {
                names.check_expiry()?;
            }
            if require_native {
                let mut current_peer = |_: &Value, iface: &str| {
                    attested_peer(
                        held.filter(|held| held.owner.iface == iface)
                            .unwrap_or(target),
                        iface,
                    )
                };
                if !check_temporary_peer(
                    &transfer_kernel(run, db)?,
                    &candidate,
                    &transfer.next,
                    &transfer,
                    true,
                    &mut current_peer,
                )? {
                    return Err(ineligible());
                }
            }
            verify_expiry()?;
            if let Some(verify) = verify_origin {
                verify()?;
            }
            let mut current = covered_next;
            let desired = if retiring_firmware_members(&transfer.next) {
                let desired = without_dns_members(&transfer.next).ok_or_else(ineligible)?;
                let hold = guarded(&desired, moved);
                transition(db, tx, run, &current, &hold, Some(&current))?;
                current = hold;
                desired
            } else {
                transfer.next.clone()
            };
            if current != desired {
                release_temporary_stop(db, tx, run, &current, &desired, (moved, None))?;
            }
            mark_stop_released(tx, &mut transfer)
        })();
        if settled.is_err() {
            let retry = "перенос сохранён, временная защита будет снята после проверки маршрута";
            warning = Some(
                warning.map_or_else(|| retry.to_owned(), |warning| format!("{warning}. {retry}")),
            );
        }
    }
    Ok(warning)
}

fn committed(doc: &Value, transfer: &Transfer) -> bool {
    matches_marker(doc, transfer) && row(doc, &transfer.source.id).is_none()
}

fn matches_marker(doc: &Value, transfer: &Transfer) -> bool {
    doc[FIELD]["id"] == transfer.source.id
        && doc[FIELD]["token"] == transfer.token
        && doc[FIELD]["retained_outer"] == json!(transfer.retained_outer)
        && doc[FIELD]["disabled_target"] == json!(transfer.disabled_target)
}

fn uses_source(journal: &Journal, transfer: &Transfer) -> bool {
    uses_profile(journal, &transfer.source.id)
}

fn uses_profile(journal: &Journal, id: &str) -> bool {
    [&journal.installed, &journal.committed]
        .into_iter()
        .chain(&journal.preparing)
        .any(|plan| plan.targets.values().any(|t| t.id == id))
}

type PeerReader<'a> = dyn FnMut(&Value, &str) -> io::Result<LivePeer> + 'a;
type VerifyRetry<'a> = &'a dyn Fn() -> io::Result<()>;

enum TemporaryProof<'a> {
    Dns(&'a ActiveReplacementDnsRetryProof),
    Named(VerifyRetry<'a>),
}

fn mark_stop_released(tx: &Transaction<'_>, transfer: &mut Transfer) -> io::Result<()> {
    transfer
        .temporary_stop
        .as_mut()
        .ok_or_else(ineligible)?
        .released = true;
    save(tx, transfer)
}

fn release_temporary_stop(
    db: &Store,
    tx: &Transaction<'_>,
    run: &dyn Runner,
    current: &Journal,
    desired: &Journal,
    (moved, retry): (Option<Prefix>, Option<(VerifyRetry<'_>, &Journal)>),
) -> io::Result<()> {
    if *current != guarded(desired, moved) || desired.installed.killswitch {
        return Err(ineligible());
    }
    let k = transfer_kernel(run, db)?;
    if current.boot != boot_id(&k)?
        || k.inventory(&current.claims(), true)? != objects(&current.installed)
    {
        return Err(ineligible());
    }
    k.verify_forward(&current.installed)?;
    // The ordinary writer releases an obsolete Stop only after the complete
    // lookup is back in place. Its compensation retains the guarded route.
    let (verify, fallback) = retry.map_or((None, current), |(verify, fallback)| {
        (Some(verify), fallback)
    });
    transition_with_retry_proof(db, tx, run, current, desired, fallback, verify)
}

fn transition_with_retry_proof(
    db: &Store,
    tx: &Transaction<'_>,
    run: &dyn Runner,
    current: &Journal,
    desired: &Journal,
    fallback: &Journal,
    verify: Option<VerifyRetry<'_>>,
) -> io::Result<()> {
    let Some(verify_current) = verify else {
        return transition(db, tx, run, current, desired, Some(fallback));
    };
    let writer = super::ManagedDnsWriter {
        verify_current,
        cold: false,
        compensated: std::cell::Cell::new(false),
    };
    verify_current()?;
    super::acceleration::transition(db, tx, run, current, desired, || {
        super::switch_routes_checked(db, tx, run, current, desired, Some(fallback), (Some(&writer), None))
    })
}

fn desired_temporary(doc: &Value, transfer: &Transfer) -> io::Result<(bool, Journal)> {
    let published = committed(doc, transfer);
    if !published && (doc.get(FIELD).is_some() || row(doc, &transfer.source.id).is_none()) {
        return Err(ineligible());
    }
    Ok((
        published,
        if published {
            projected_dns(transfer)?.unwrap_or_else(|| transfer.next.clone())
        } else {
            transfer.prior.clone()
        },
    ))
}

fn projected_dns(transfer: &Transfer) -> io::Result<Option<Journal>> {
    transfer
        .retry_projection
        .as_ref()
        .map(|projection| build_dns_projection(transfer, projection))
        .transpose()
}

fn build_dns_projection(
    transfer: &Transfer,
    projection: &RetryDnsProjection,
) -> io::Result<Journal> {
    let held = transfer.held_direct.as_ref().ok_or_else(ineligible)?;
    let names = transfer.retry_dns.as_deref().ok_or_else(ineligible)?;
    let (_, zone, client) = retry_scope(transfer, names)?;
    let eligible_names = match (
        names.len(),
        projection.both_positive,
        projection.expired_positive_name.as_deref(),
    ) {
        (1, false, None) => true,
        (2, true, None) if !projection.withdrawn => true,
        (2, false, None) if !projection.withdrawn => transfer
            .retry_negative_name
            .as_ref()
            .is_some_and(|prior| prior.valid(&transfer.token, names)),
        (2, false, Some(name)) if !projection.withdrawn => transfer
            .retry_positive_pair
            .as_ref()
            .is_some_and(|hints| hints.valid(&transfer.token, names) && hints.contains(name)),
        _ => false,
    };
    if !transfer.retry_runtime
        || !eligible_names
        || projection.stamp != projection.stamp(&transfer.token)?
        || projection.withdrawn && transfer.retry_positive_hint.is_none()
    {
        return Err(ineligible());
    }
    let base = &transfer.next;
    let previous = live_dns_members(&base.installed)?;
    if projection.members == previous
        || projection.withdrawn
            == projection
                .members
                .iter()
                .any(|member| member.zone == zone && member.until == RETAINED_FIRMWARE_MEMBER)
        || !projection
            .members
            .iter()
            .filter(|member| member.zone != zone)
            .eq(previous.iter().filter(|member| member.zone != zone))
    {
        return Err(ineligible());
    }
    let mut known: BTreeSet<_> = projection.members.iter().map(|member| member.ip).collect();
    if known.len() != projection.members.len() {
        return Err(ineligible());
    }
    let mut plan = base.installed.as_ref().clone();
    let mut members = projection.members.clone();
    let source = Prefix::host(client);
    let (iface, _) = replacement_route_target(base)?;
    for member in previous.iter().filter(|member| member.zone == zone) {
        let selector = plan::Selector {
            source,
            dest: Prefix::host(member.ip),
        };
        let index = plan
            .scoped
            .binary_search_by_key(&selector, |row| row.0)
            .map_err(|_| ineligible())?;
        if plan.scoped[index].1 != iface {
            return Err(ineligible());
        }
        plan.scoped.remove(index);
        if known.insert(member.ip) {
            members.push(learning::Member {
                until: RETIRED_FIRMWARE_MEMBER,
                ..member.clone()
            });
        }
    }
    members.sort_unstable_by_key(|member| (member.zone, member.ip));
    for member in members.iter().filter(|member| member.zone == zone) {
        let dest = Prefix::host(member.ip);
        if !dest.safe() {
            return Err(ineligible());
        }
        plan.scoped
            .push((plan::Selector { source, dest }, iface.into()));
    }
    plan.scoped.sort_unstable();
    plan.learned.as_mut().ok_or_else(ineligible)?.members = members;
    live_dns_members(&plan)?;
    if held_dns_objects(&base.installed, &held.owner.iface)
        != held_dns_objects(&plan, &held.owner.iface)
    {
        return Err(ineligible());
    }
    let installed: Snapshot = plan.into();
    let projected = Journal {
        committed: installed.clone(),
        installed,
        ..base.clone()
    };
    if !stopped_scope_with_pending(&transfer.prior, &projected, previous) {
        return Err(ineligible());
    }
    Ok(projected)
}

/// The live transfer owns exactly one uniformly expiring group of separate
/// host routes. Keep the immutable static anchor and its original DNS rule.
fn without_dns_members(journal: &Journal) -> Option<Journal> {
    journal
        .installed
        .learned
        .as_ref()
        .filter(|saved| !saved.members.is_empty())?;
    let mixed = mixed_dns_plan(&journal.installed).ok()?;
    let source = if mixed.is_none() {
        observed_dns_source(&journal.installed).ok()?
    } else {
        None
    };
    let mut plan = journal.installed.as_ref().clone();
    let learned = plan.learned.as_mut()?;
    let (expired, kept): (Vec<_>, Vec<_>) = learned
        .members
        .drain(..)
        .partition(|member| mixed.is_none() || member.until == RETIRED_FIRMWARE_MEMBER);
    if expired.is_empty() {
        return None;
    }
    learned.members = kept;
    for member in expired {
        let dest = Prefix::host(member.ip);
        if let Some(source) =
            source.or_else(|| mixed.map(|mixed| mixed.selector_source(member.zone)))
        {
            plan.scoped
                .retain(|(selector, _)| *selector != plan::Selector { source, dest });
        } else {
            plan.prefixes.remove(&dest);
        }
    }
    let expired: Snapshot = plan.into();
    Some(Journal {
        installed: expired.clone(),
        committed: expired,
        ..journal.clone()
    })
}

fn phases(leg: &Journal, moved: Option<Prefix>) -> [Snapshot; 3] {
    [
        leg.installed.clone(),
        guarded(leg, moved).installed,
        parked(leg, moved).installed,
    ]
}

fn dns_members_expired(journal: &Journal, now: u64) -> bool {
    journal
        .installed
        .learned
        .as_ref()
        .is_some_and(|saved| saved.members.iter().any(|member| member.until <= now))
}

fn expire_during_recovery(
    wanted: Journal,
    current: &Journal,
    now: u64,
    moved: Option<Prefix>,
) -> Journal {
    let Some(pruned) = without_dns_members(&wanted) else {
        return wanted;
    };
    let projected = phases(&pruned, moved);
    let known_pruned = [&current.installed, &current.committed]
        .into_iter()
        .chain(&current.preparing)
        .any(|snapshot| projected.contains(snapshot));
    let due = dns_members_expired(&wanted, now);
    if known_pruned || due {
        pruned
    } else {
        wanted
    }
}

fn known_temporary(journal: &Journal, transfer: &Transfer) -> bool {
    let mut plans = vec![Snapshot::default()];
    let moved = moved_dns_client(&transfer.prior);
    let Ok(projected) = projected_dns(transfer) else {
        return false;
    };
    for leg in [&transfer.prior, &transfer.next]
        .into_iter()
        .chain(projected.as_ref())
    {
        let pruned = without_dns_members(leg);
        for state in std::iter::once(leg).chain(pruned.iter()) {
            plans.extend(phases(state, moved));
            if let Some((held, client)) = transfer.held_direct.as_ref().zip(moved) {
                plans.push(parked_with_held(state, &held.owner.iface, client).installed);
                if deferred_launch(transfer) {
                    plans
                        .push(deferred_launch_checkpoint(state, Some(&held.owner.iface)).installed);
                }
            }
        }
    }
    journal.expires == 0
        && [&journal.installed, &journal.committed]
            .into_iter()
            .chain(&journal.preparing)
            .all(|plan| plans.contains(plan))
}

fn current_temporary(journal: &Journal, desired: &mut Journal, boot: String) -> Journal {
    desired.boot.clone_from(&boot);
    if journal.boot == boot {
        return journal.clone();
    }
    // A former boot supplies no ownership of the current kernel inventory.
    Journal {
        boot,
        committed: desired.committed.clone(),
        ..Default::default()
    }
}

fn check_temporary_peer(
    k: &Kernel<'_>,
    doc: &Value,
    wanted: &Journal,
    transfer: &Transfer,
    published: bool,
    peer: &mut PeerReader<'_>,
) -> io::Result<bool> {
    check_temporary_peer_with_dormant(k, doc, wanted, transfer, (published, None), peer)
}

fn check_temporary_peer_with_dormant(
    k: &Kernel<'_>,
    doc: &Value,
    wanted: &Journal,
    transfer: &Transfer,
    (published, dormant): (bool, Option<IpAddr>),
    peer: &mut PeerReader<'_>,
) -> io::Result<bool> {
    let (iface, target) = replacement_route_target(wanted)?;
    let stop = transfer.temporary_stop.as_ref().ok_or_else(ineligible)?;
    let rotation = stop.rotation.as_ref().filter(|_| published);
    let rotated_names = rotation
        .map(|rotation| rotation.names(stop.named.as_ref().ok_or_else(ineligible)?))
        .transpose()?;
    let named = rotated_names.as_ref().or(stop.named.as_ref());
    let fingerprint = if published {
        stop.target_fingerprint
    } else {
        transfer.source_fingerprint
    };
    let endpoint = match named {
        Some(named) => {
            let Some(endpoint) = named.selected(published) else {
                // A definitive initial resolution failure carries no target
                // address or forwarding authority.
                return Ok(false);
            };
            endpoint
        }
        None if plan::has_named_endpoint(doc) => return Ok(false),
        None => {
            let Some(endpoint) = durable_selected_endpoint(doc, &target.id, fingerprint)? else {
                return Ok(false);
            };
            endpoint
        }
    };
    if stop.transport_policy.as_ref().is_some_and(|policy| {
        let expected = if published {
            policy.target
        } else {
            policy.source
        };
        active_replacement_transport_stamp(doc, &target.id).ok() != Some(expected)
    }) {
        return Ok(false);
    }
    let nested_target = transfer.nested_target.as_ref();
    let retiring_nested = transfer.retiring_nested.as_ref();
    let selected = if published {
        nested_target
            .map(|target| &target.owner)
            .or_else(|| retiring_nested.map(|retiring| &retiring.target))
    } else {
        Some(&transfer.source)
    };
    let nested = selected.and_then(|owner| owner.nested.as_ref());
    let expected_outer = nested_target
        .map(|target| target.selected_outer(published))
        .or_else(|| {
            retiring_nested
                .filter(|_| !published)
                .map(|retiring| (&retiring.outer.owner, Some(retiring.outer.fingerprint)))
        });
    let covered = guarded(wanted, moved_dns_client(&transfer.prior));
    let verify = |row: &Value, name: &str| {
        let live = peer(row, name)?;
        if let Some(held) = transfer
            .held_direct
            .as_ref()
            .filter(|held| held.owner.iface == name)
        {
            let native = live
                .active_replacement_peer
                .as_deref()
                .ok_or_else(ineligible)?;
            let same_boot = wanted.boot == transfer.source.boot;
            if !native.owner.valid()
                || native.owner.id != held.owner.id
                || native.owner.iface != held.owner.iface
                || native.owner.boot != wanted.boot
                || native.owner.nested.is_some()
                || native.fingerprint != held.fingerprint
                || same_boot && native.owner != held.owner
                || native.endpoint != live.endpoint
                || native.socket_mark != live.socket_mark
            {
                return Err(ineligible());
            }
            verify_peer_for(doc, native, &wanted.installed, Some(name))?;
            mtu_edit::replacement_wan(k, native.endpoint, native.socket_mark, &held.wan)?;
            return Ok(live);
        }
        if name != iface || mtu_edit::canonical_socket(live.endpoint) != Some(endpoint) {
            return Err(ineligible());
        }
        if stop.transport_policy.is_some() || stop.target_owner.is_some() || stop.deferred_launch {
            let native = live
                .active_replacement_peer
                .as_deref()
                .ok_or_else(ineligible)?;
            if !native.owner.valid()
                || native.owner.id != target.id
                || native.owner.boot != wanted.boot
                || rotation.is_some_and(|rotation| !rotation.matches(&native.owner))
                || native.endpoint != endpoint
                || native.socket_mark != live.socket_mark
                || native.owner.nested.as_ref() != nested
                || live.nested_mtu != nested.map(|_| native.mtu)
            {
                return Err(ineligible());
            }
            if stop.deferred_launch
                && (native.fingerprint != fingerprint
                    || !published
                        && wanted.boot == transfer.source.boot
                        && native.owner != transfer.source
                    || transfer
                        .held_direct
                        .as_ref()
                        .is_some_and(|held| !distinct_owner(&native.owner, &held.owner)))
            {
                return Err(ineligible());
            }
            if nested_target.is_some() || retiring_nested.is_some() {
                let same_boot = wanted.boot == transfer.source.boot;
                if same_boot && selected != Some(&native.owner) {
                    return Err(ineligible());
                }
                if nested.is_some() {
                    let outer = native.underlay.as_ref().ok_or_else(ineligible)?;
                    let (owner, fingerprint) = expected_outer.ok_or_else(ineligible)?;
                    if outer.owner.id != owner.id
                        || outer.owner.iface != owner.iface
                        || fingerprint.is_some_and(|expect| expect != outer.fingerprint)
                        || same_boot && &outer.owner != owner
                    {
                        return Err(ineligible());
                    }
                }
            }
            if let Some(target_owner) = &stop.target_owner {
                let expected = if published {
                    target_owner
                } else {
                    &transfer.source
                };
                if native.owner.iface != expected.iface
                    || native.fingerprint != fingerprint
                    || wanted.boot == transfer.source.boot && &native.owner != expected
                    || published
                        && warm_named_receipt(transfer)
                        && (&native.owner != target_owner
                            || native.socket_mark != nfqws2_awg_profile::DIRECT_SOCKET_MARK)
                {
                    return Err(ineligible());
                }
            }
            verify_peer_bound(
                doc,
                native,
                &wanted.installed,
                transfer.held_direct.as_ref().map(|_| name),
                (named.map(|named| &named.claims), false),
            )?;
            if nested.is_some() {
                verify_nested_peer(k, doc, native, &stop.wan, true)?;
                return witnessed_peer(native, name);
            }
        }
        mtu_edit::replacement_wan(k, endpoint, live.socket_mark, &stop.wan)?;
        Ok(live)
    };
    let mut resolution = plan::resolve_with_mtu_edit(
        doc,
        (*covered.installed).clone(),
        true,
        None,
        Some(plan::Verification::Read(k)),
        named.map_or(plan::EditContext::None, |named| {
            plan::EditContext::NamedReplacement(&named.claims)
        }),
        verify,
    )?;
    if let Some(ip) = dormant {
        resolution.endpoints.remove(&ip);
    }
    k.guard(&resolution.plan, &resolution.endpoints)?;
    Ok(resolution.plan == *covered.installed && resolution.plan.fully_live())
}

fn dormant_primary_on_reserve_rollback(
    db: &Store,
    k: &Kernel<'_>,
    doc: &Value,
    desired: &Journal,
    transfer: &Transfer,
) -> io::Result<Option<IpAddr>> {
    let Some((stop, primary)) = transfer
        .temporary_stop
        .as_ref()
        .and_then(|stop| stop.cold_reserve_primary.map(|primary| (stop, primary)))
    else {
        return Ok(None);
    };
    let Some(launch) = read_launch(db)? else {
        return Ok(None);
    };
    let Some(binding) = launch.numeric_pool else {
        return Ok(None);
    };
    if launch.source != transfer.source
        || launch.prior != profile_rebind::digest(&transfer.prior)?
        || launch.target.boot != desired.boot
        || stop.target_fingerprint != binding
        || transfer
            .next
            .installed
            .targets
            .get(&launch.target.iface)
            .is_none_or(|target| target.id != launch.target.id)
    {
        return Err(ineligible());
    }
    let pool = active_replacement_numeric_pool(doc, &launch.target.id)?;
    let (configured, primary_binding) = pool.primary();
    if configured != primary
        || primary_binding == binding
        || pool.wire_fingerprint != launch.fingerprint
        || pool.selected_endpoint(binding).is_none()
    {
        return Err(ineligible());
    }
    let Err(error) = mtu_edit::replacement_wan(k, primary, 0, &stop.wan) else {
        return Ok(None);
    };
    if !nfqws2_router_command::reported_failure(&error)
        || !explicit_unreachable_primary(k, primary)?
    {
        return Ok(None);
    }
    if !super::transport_claims::Claims::read(doc, &desired.installed, false, None)?
        .sole_primary(&launch.target.id, primary)
    {
        return Err(ineligible());
    }
    Ok(Some(primary.ip()))
}

fn recover_temporary(
    db: &Store,
    tx: &Transaction<'_>,
    run: &dyn Runner,
    journal: &mut Journal,
    transfer: &mut Transfer,
    doc: &Value,
    (mut peer, proof): (Option<&mut PeerReader<'_>>, Option<TemporaryProof<'_>>),
) -> io::Result<()> {
    let (published, nominal) = desired_temporary(doc, transfer)?;
    if !known_temporary(journal, transfer) {
        return Err(ineligible());
    }
    let moved = moved_dns_client(&transfer.prior);
    let requires_dns = published && transfer.retry_dns.is_some();
    let requires_named = published
        && transfer
            .temporary_stop
            .as_ref()
            .is_some_and(|stop| stop.rotation.is_some());
    let requires_proof = requires_dns || requires_named;
    let verify_retry = || match &proof {
        Some(TemporaryProof::Dns(proof)) if requires_dns => {
            if proof.projection != transfer.retry_projection {
                return Err(io::ErrorKind::Interrupted.into());
            }
            proof.check(db)
        }
        Some(TemporaryProof::Named(verify)) if requires_named => verify(),
        _ => Err(io::ErrorKind::WouldBlock.into()),
    };
    let authorized = || !requires_proof || verify_retry().is_ok();
    let verify = requires_proof.then_some(&verify_retry as &dyn Fn() -> io::Result<()>);
    let mut desired = if authorized() {
        expire_during_recovery(nominal.clone(), journal, nfqws2_awg_profile::now(), moved)
    } else {
        nominal.clone()
    };
    let k = transfer_kernel(run, db)?;
    let current = current_temporary(journal, &mut desired, boot_id(&k)?);
    let dormant = if published {
        None
    } else {
        dormant_primary_on_reserve_rollback(db, &k, doc, &desired, transfer)?
    };
    let mut nominal = nominal;
    nominal.boot.clone_from(&desired.boot);
    let require_native = transfer.temporary_stop.as_ref().is_some_and(|stop| {
        stop.transport_policy.is_some() || stop.target_owner.is_some() || stop.deferred_launch
    });
    let check = |peer: &mut PeerReader<'_>| {
        authorized()
            && check_temporary_peer_with_dormant(
                &k,
                doc,
                &desired,
                transfer,
                (published, dormant),
                peer,
            )
            .unwrap_or(false)
    };
    let mut ready =
        (require_native || requires_proof).then(|| peer.as_deref_mut().is_some_and(check));
    if ready != Some(false)
        && current == desired
        && k.inventory(&current.claims(), true)? == objects(&desired.installed)
        && k.verify_forward(&desired.installed).is_ok()
        && !dns_members_expired(&desired, nfqws2_awg_profile::now())
        && authorized()
    {
        // The original path never changed, or release succeeded before its
        // receipt was acknowledged. Do not write a new Stop in either case.
        stamp(tx, &desired)?;
        return if published {
            mark_stop_released(tx, transfer)
        } else {
            tx.delete_runtime(FILE)
        };
    }

    let mut ready = *ready.get_or_insert_with(|| peer.as_deref_mut().is_some_and(check));
    let parking = if requires_dns { &nominal } else { &desired };
    let deferred = published && deferred_launch(transfer);
    let fallback = if deferred {
        deferred_launch_checkpoint(parking, None)
    } else {
        parked(parking, moved)
    };
    let stop = objects(&fallback.installed);
    let present = k.inventory_for(&current.claims(), &stop, true)?;
    // A same-boot fallback can keep the independent peer's existing objects.
    // This projection never introduces a lookup or route for that peer.
    let fallback = transfer
        .held_direct
        .as_ref()
        .zip(moved)
        .filter(|(held, _)| {
            current.boot == transfer.source.boot
                && held_dns_objects(&parking.installed, &held.owner.iface).is_subset(&present)
        })
        .map_or(fallback, |(held, client)| {
            if deferred {
                deferred_launch_checkpoint(parking, Some(&held.owner.iface))
            } else {
                parked_with_held(parking, &held.owner.iface, client)
            }
        });
    if !stop.is_subset(&present) {
        // Before creating a Stop on a new boot, verify that the originally
        // approved prefix still does not enclose a management or VPN path.
        let claims = transfer
            .temporary_stop
            .as_ref()
            .and_then(|stop| stop.named.as_ref());
        if claims.is_none() && plan::has_named_endpoint(doc) {
            return Err(ineligible());
        }
        let mut endpoints = BTreeSet::new();
        plan::visit_transport_endpoints(
            doc,
            false,
            (None, claims.map(|named| &named.claims)),
            |_| true,
            |_, _, ip| {
                endpoints.insert(ip);
            },
        )?;
        if claims.is_some() {
            desired.installed.check_endpoints(&endpoints)?;
        }
        if let Some(ip) = dormant {
            endpoints.remove(&ip);
        }
        k.guard(&fallback.installed, &endpoints)?;
    }
    // Reconcile a partially written owned generation to its fenced receipt
    // before giving a fresh proof authority on a later attempt.
    ready &= !requires_proof || present == objects(&current.installed);
    let covered = if ready {
        guarded(&desired, moved)
    } else {
        fallback.clone()
    };
    if current != covered || present != objects(&covered.installed) {
        let result = transition_with_retry_proof(
            db,
            tx,
            run,
            &current,
            &covered,
            &fallback,
            if ready { verify } else { None },
        );
        if requires_dns && ready {
            recover_failed_dns_write(db, tx, run, transfer, &fallback, result)?;
        } else {
            result?;
        }
    }
    let ready_to_release = ready
        && (!require_native || peer.is_some_and(check))
        && !dns_members_expired(&desired, nfqws2_awg_profile::now())
        && authorized();
    if ready && !ready_to_release {
        transition(db, tx, run, &covered, &fallback, Some(&fallback))?;
        *journal = fallback;
        return Ok(());
    }
    *journal = covered.clone();
    if ready_to_release {
        if covered != desired {
            let result = release_temporary_stop(
                db,
                tx,
                run,
                &covered,
                &desired,
                (moved, verify.map(|verify| (verify, &fallback))),
            );
            if requires_dns {
                recover_failed_dns_write(db, tx, run, transfer, &fallback, result)?;
            } else {
                result?;
            }
        }
        *journal = desired;
        if published {
            mark_stop_released(tx, transfer)?;
        } else {
            tx.delete_runtime(FILE)?;
        }
    }
    Ok(())
}

fn recover_failed_dns_write(
    db: &Store,
    tx: &Transaction<'_>,
    run: &dyn Runner,
    transfer: &Transfer,
    fallback: &Journal,
    result: io::Result<()>,
) -> io::Result<()> {
    if result.is_err() {
        let actual = Journal::read(db)?;
        if !known_temporary(&actual, transfer) {
            return Err(ineligible());
        }
        transition(db, tx, run, &actual, fallback, Some(fallback))?;
    }
    result
}

fn replace_retry_projection(
    db: &Store,
    tx: &Transaction<'_>,
    run: &dyn Runner,
    current: &mut Journal,
    transfer: &mut Transfer,
    (doc, proof, peer): (&Value, &ActiveReplacementDnsRetryProof, &mut PeerReader<'_>),
) -> io::Result<()> {
    let held = transfer.held_direct.as_ref().ok_or_else(ineligible)?;
    let client = moved_dns_client(&transfer.prior).ok_or_else(ineligible)?;
    let k = transfer_kernel(run, db)?;
    if current.boot != transfer.source.boot || current.boot != boot_id(&k)? {
        return Err(ineligible());
    }
    if proof
        .projection
        .as_ref()
        .is_some_and(|proof| proof.withdrawn)
        && transfer
            .retry_projection
            .as_ref()
            .is_some_and(|installed| !installed.withdrawn)
    {
        // The original receipt says nothing about the age of a newer set.
        return Err(ineligible());
    }
    let desired = proof
        .projection
        .as_ref()
        .map(|projection| build_dns_projection(transfer, projection))
        .transpose()?
        .unwrap_or_else(|| transfer.next.clone());
    let (_, nominal) = desired_temporary(doc, transfer)?;
    let fallback = parked_with_held(&nominal, &held.owner.iface, client);
    let base = parked_with_held(&transfer.next, &held.owner.iface, client);
    // Forget the outgoing projection only after its objects have been removed
    // and the unchanged global leg has been read back under the original seal.
    if !known_temporary(current, transfer)
        || !check_temporary_peer(&k, doc, &desired, transfer, true, peer)?
    {
        return Err(ineligible());
    }
    let present = k.inventory(&current.claims(), true)?;
    let global = held_dns_objects(&base.installed, &held.owner.iface);
    if global.is_empty() || !global.is_subset(&present) {
        return Err(ineligible());
    }
    proof.check(db)?;
    if *current != base || present != objects(&base.installed) {
        transition(db, tx, run, current, &base, Some(&fallback))?;
        *current = base;
    }
    proof.check(db)?;
    transfer.retry_projection = proof.projection.clone();
    if proof.invalidate_negative {
        transfer.retry_negative_name = None;
    }
    save(tx, transfer)
}

pub fn resume_active_replacement_dns_retry(
    db: &Store,
    run: &dyn Runner,
    proof: &ActiveReplacementDnsRetryProof,
    mut peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<()> {
    db.transaction(|tx| {
        proof.check(db)?;
        let Some(mut transfer) = read(db)? else {
            return Err(ineligible());
        };
        let doc = nfqws2_awg_profile::read(db)?;
        let mut current = Journal::read(db)?;
        if transfer.retry_projection != proof.projection {
            replace_retry_projection(
                db,
                tx,
                run,
                &mut current,
                &mut transfer,
                (&doc, proof, &mut peer),
            )?;
        }
        if proof.invalidate_negative && transfer.retry_negative_name.take().is_some() {
            save(tx, &transfer)?;
        }
        let result = recover_temporary(
            db,
            tx,
            run,
            &mut current,
            &mut transfer,
            &doc,
            (Some(&mut peer), Some(TemporaryProof::Dns(proof))),
        );
        if result
            .as_ref()
            .err()
            .and_then(io::Error::get_ref)
            .is_some_and(|error| error.is::<super::RouteWriteRejected>())
            && proof.check(db).is_ok()
        {
            let mut renewed = false;
            if transfer.retry_projection.is_none() {
                if let Some(until) = proof.positive_until.clone() {
                    transfer.retry_positive_hint =
                        Some(RetryPositiveHint::seal(&transfer.token, until)?);
                    renewed = true;
                }
            }
            if let Some(hints) = &mut transfer.retry_positive_pair {
                renewed |= hints.refresh(&transfer.token, &proof.named_positives)?;
            } else if proof.named_positives.len() == 2 {
                transfer.retry_positive_pair =
                    PairPositiveHints::seal(&transfer.token, &proof.named_positives)?;
                renewed |= transfer.retry_positive_pair.is_some();
            }
            if renewed {
                save(tx, &transfer)?;
            }
        }
        result
    })
}

fn teardown_temporary(
    db: &Store,
    tx: &Transaction<'_>,
    run: &dyn Runner,
    journal: &mut Journal,
    transfer: &mut Transfer,
    doc: &Value,
) -> io::Result<()> {
    let (published, mut desired) = desired_temporary(doc, transfer)?;
    if !known_temporary(journal, transfer) {
        return Err(ineligible());
    }
    let current = current_temporary(journal, &mut desired, boot_id(&kernel(run))?);
    let empty = Journal {
        boot: current.boot.clone(),
        ..Default::default()
    };
    let stop = transfer.temporary_stop.as_mut().ok_or_else(ineligible)?;
    if !stop.teardown {
        stop.teardown = true;
        save(tx, transfer)?;
    }
    if current != empty {
        transition(db, tx, run, &current, &empty, None)?;
    }
    *journal = empty;
    if published {
        mark_stop_released(tx, transfer)?;
    } else {
        tx.delete_runtime(FILE)?;
    }
    mtu_edit::clear(tx)
}

/// A temporary Stop may outlive the request, so settle it before an ordinary
/// route writer is allowed to reinterpret the saved unguarded policy.
pub(super) fn recover(
    tx: &Transaction<'_>,
    db: &Store,
    run: &dyn Runner,
    journal: &mut Journal,
    op: Operation,
    peer: &mut PeerReader<'_>,
) -> io::Result<bool> {
    let Some(mut transfer) = read(db)? else {
        return Ok(false);
    };
    let doc = nfqws2_awg_profile::read(db)?;
    if let Some(stop) = transfer
        .temporary_stop
        .as_ref()
        .filter(|stop| !stop.released)
    {
        if stop.teardown {
            teardown_temporary(db, tx, run, journal, &mut transfer, &doc)?;
            return Ok(true);
        }
        match op {
            Operation::Teardown => teardown_temporary(db, tx, run, journal, &mut transfer, &doc)?,
            Operation::Recover | Operation::Refresh | Operation::Suspend => {
                recover_temporary(
                    db,
                    tx,
                    run,
                    journal,
                    &mut transfer,
                    &doc,
                    (Some(peer), None),
                )?;
                if op == Operation::Suspend
                    && read(db)?.is_none_or(|t| t.temporary_stop.is_none_or(|stop| stop.released))
                {
                    return Ok(false);
                }
            }
            Operation::FirewallReload => (),
            _ => return Err(io::ErrorKind::WouldBlock.into()),
        }
        return Ok(true);
    }
    recover_original(tx, db, run, journal, &transfer, &doc, |iface| {
        peer(&doc, iface).map(|live| live.active_replacement_peer.map(|peer| *peer))
    })?;
    Ok(false)
}

fn recover_original(
    tx: &Transaction<'_>,
    db: &Store,
    run: &dyn Runner,
    journal: &mut Journal,
    transfer: &Transfer,
    doc: &Value,
    held_peer: impl FnOnce(&str) -> io::Result<Option<ActiveReplacementPeer>>,
) -> io::Result<()> {
    if transfer.retired {
        return clear_retired(tx, journal, doc, transfer);
    }
    if committed(doc, transfer) {
        if uses_source(journal, transfer) {
            return Err(ineligible());
        }
        return Ok(());
    }
    if doc.get(FIELD).is_some()
        || row(doc, &transfer.source.id).is_none()
        || recover_source_fingerprint(doc, transfer)? != transfer.source_fingerprint
        || journal.boot != transfer.prior.boot
        || journal.expires != 0
    {
        return Err(ineligible());
    }

    let mut parked = transfer.prior.clone();
    let unguarded_disabled = transfer.disabled_target.is_some() && !parked.installed.killswitch;
    if unguarded_disabled {
        // A native literal plan cannot borrow the learned-DNS temporary
        // Stops. Keep the old desired source and the unchanged held FIB
        // until its normal direct peer recovery can restore the source.
        parked.installed = transfer.next.installed.clone();
        parked.installed.revision = transfer.prior.installed.revision;
    } else if transfer.held_direct.is_some() {
        parked
            .installed
            .offline
            .insert(transfer.source.iface.clone());
    } else {
        parked.installed = transfer.prior.committed.guards_only().into();
    }
    if [&journal.installed, &journal.committed]
        .into_iter()
        .chain(&journal.preparing)
        .any(|p| {
            p != &transfer.prior.installed
                && p != &transfer.next.installed
                && p != &parked.installed
        })
    {
        return Err(ineligible());
    }
    let k = transfer_kernel(run, db)?;
    if journal.boot != boot_id(&k)? {
        // These are previous-boot claims. Let standard recovery inspect the
        // empty live tables before restoring the protected original policy.
        stamp(tx, &transfer.prior)?;
        tx.save_runtime_bounded(RECEIPT, &transfer.prior, RECEIPT_LIMIT)?;
        *journal = transfer.prior.clone();
    } else {
        let present = if transfer.held_direct.is_some() || *journal == transfer.prior {
            k.inventory(&journal.claims(), true)?
        } else {
            BTreeSet::new()
        };
        if let Some(held) = &transfer.held_direct {
            let iface = &held.owner.iface;
            let live = held_peer(iface)?.ok_or(io::ErrorKind::WouldBlock)?;
            if live.owner != held.owner
                || live.fingerprint != held.fingerprint
                || !held_dns_objects(&transfer.prior.installed, iface).is_subset(&present)
            {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            verify_peer_for(doc, &live, &transfer.prior.installed, Some(iface))?;
            mtu_edit::replacement_wan(&k, live.endpoint, live.socket_mark, &held.wan)?;
        }
        if *journal == transfer.prior
            && present == objects(&journal.installed)
            && k.verify_forward(&journal.installed).is_ok()
        {
            // The original path still exists and no new forwarding was authorized.
            stamp(tx, journal)?;
        } else {
            transition(db, tx, run, journal, &parked, Some(&parked))?;
            *journal = parked;
            if unguarded_disabled {
                disabled::restore_source_intent(tx, &transfer.source.id)?;
            }
        }
    }
    tx.delete_runtime(FILE)
}

fn recover_source_fingerprint(doc: &Value, transfer: &Transfer) -> io::Result<[u8; 32]> {
    if has_endpoint_backups(doc, &transfer.source.id) {
        return durable_selected_endpoint(doc, &transfer.source.id, transfer.source_fingerprint)?
            .map(|_| transfer.source_fingerprint)
            .ok_or_else(ineligible);
    }
    active_replacement_fingerprint(doc, &transfer.source.id).or_else(|error| {
        if transfer.temporary_stop.is_none()
            && transfer.prior.installed.killswitch
            && profile_rebind::native_ipv4_prefixes(&transfer.prior).is_ok()
        {
            nfqws2_awg_profile::active_named_replacement_fingerprint(doc, &transfer.source.id)
        } else {
            Err(error)
        }
    })
}

pub fn pending_active_replacement_retirement(db: &Store) -> io::Result<Option<NativeRemovalSeal>> {
    if launch_pending(db)? {
        return Ok(None);
    }
    let Some(transfer) = read(db)? else {
        return Ok(None);
    };
    let doc = nfqws2_awg_profile::read(db)?;
    if transfer.retired || !committed(&doc, &transfer) {
        return Ok(None);
    }
    let j = Journal::read(db)?;
    if !retirement_checkpoint(&j, &transfer) {
        return Ok(None);
    }
    if uses_source(&j, &transfer) {
        return Err(ineligible());
    }
    Ok(Some(transfer.source))
}

fn retirement_checkpoint(journal: &Journal, transfer: &Transfer) -> bool {
    transfer.temporary_stop.as_ref().is_none_or(|stop| {
        stop.released
            || stop.deferred_launch
                && !stop.teardown
                && *journal
                    == deferred_launch_checkpoint(
                        &transfer.next,
                        transfer
                            .held_direct
                            .as_ref()
                            .map(|held| held.owner.iface.as_str()),
                    )
    })
}

pub fn active_replacement_launch_cleanup(
    db: &Store,
) -> io::Result<Option<ActiveReplacementLaunchCleanup>> {
    let Some(launch) = read_launch(db)? else {
        return Ok(None);
    };
    let doc = nfqws2_awg_profile::read(db)?;
    let journal = Journal::read(db)?;
    let target = row(&doc, &launch.target.id).ok_or_else(ineligible)?;
    let fingerprint = || match (launch.named_endpoint, launch.numeric_pool) {
        (Some(endpoint), None) => {
            if launch.warm_ipv6 {
                nfqws2_awg_profile::validate_warm_named_ipv6(&doc, &launch.target.id, &[endpoint])?;
            } else {
                nfqws2_awg_profile::validate_active_named_replacement(
                    &doc,
                    &launch.target.id,
                    &[endpoint],
                )?;
            }
            nfqws2_awg_profile::active_named_replacement_fingerprint(&doc, &launch.target.id)
        }
        (None, Some(binding)) => {
            let pool = active_replacement_numeric_pool(&doc, &launch.target.id)?;
            if pool.selected_endpoint(binding).is_none() {
                return Err(ineligible());
            }
            Ok(pool.wire_fingerprint)
        }
        (None, None) if launch.literal_startup => {
            active_replacement_startup_binding(&doc, &launch.target.id)
        }
        (None, None) => active_replacement_fingerprint(&doc, &launch.target.id),
        (Some(_), Some(_)) => Err(ineligible()),
    };
    if let Some(transfer) = read(db)? {
        // A partially applied R75 transaction may still have a FIB claim on
        // the provisional peer. Recover its protected source first.
        if !committed(&doc, &transfer) {
            return Ok(None);
        }
        if transfer.source != launch.source
            || profile_rebind::digest(&transfer.prior)? != launch.prior
            || !transfer
                .next
                .installed
                .targets
                .values()
                .any(|entry| entry.id == launch.target.id)
            || target["config"]["client"]["standby"] != false
            || (launch.named_endpoint.is_some()
                || launch.numeric_pool.is_some()
                || launch.literal_startup)
                && fingerprint()? != launch.fingerprint
        {
            return Err(ineligible());
        }
        return Ok(Some(ActiveReplacementLaunchCleanup {
            target: launch.target,
            stop: false,
        }));
    }
    if row(&doc, &launch.source.id).is_none()
        || uses_profile(&journal, &launch.target.id)
        || (target["config"]["client"]["standby"] == true)
            != launch.target_was_standby.unwrap_or(true)
        || target["config"]["routing"]["active"] == true
        || fingerprint()? != launch.fingerprint
    {
        return Err(ineligible());
    }
    Ok(Some(ActiveReplacementLaunchCleanup {
        target: launch.target,
        stop: true,
    }))
}

pub fn finish_active_replacement_launch_cleanup(
    db: &Store,
    cleanup: &ActiveReplacementLaunchCleanup,
) -> io::Result<()> {
    db.transaction(|tx| {
        if active_replacement_launch_cleanup(db)?.as_ref() != Some(cleanup) {
            return Err(ineligible());
        }
        tx.delete_runtime(LAUNCH)
    })
}

fn clear_retired(
    tx: &Transaction<'_>,
    journal: &Journal,
    doc: &Value,
    transfer: &Transfer,
) -> io::Result<()> {
    if row(doc, &transfer.source.id).is_some()
        || doc.get(FIELD).is_some() && !matches_marker(doc, transfer)
    {
        return Err(ineligible());
    }
    established_name::remember(tx, journal, doc, transfer)?;
    nfqws2_awg_profile::edit_document_locked(tx, |doc| {
        let properties = doc.as_object_mut().ok_or_else(ineligible)?;
        properties.remove(FIELD);
        Ok(())
    })?;
    tx.delete_runtime(FILE)
}

pub fn finish_active_replacement_retirement(
    db: &Store,
    seal: &NativeRemovalSeal,
) -> io::Result<()> {
    db.transaction(|tx| {
        if launch_pending(db)? {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let Some(mut transfer) = read(db)? else {
            return Ok(());
        };
        if transfer.source != *seal {
            return Err(ineligible());
        }
        let journal = Journal::read(db)?;
        if !retirement_checkpoint(&journal, &transfer) || uses_source(&journal, &transfer) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let doc = nfqws2_awg_profile::read(db)?;
        if !transfer.retired {
            if !committed(&doc, &transfer) {
                return Err(ineligible());
            }
            transfer.retired = true;
            save(tx, &transfer)?;
        }
        if transfer
            .temporary_stop
            .as_ref()
            .is_some_and(|stop| !stop.released)
        {
            return Ok(());
        }
        clear_retired(tx, &journal, &doc, &transfer)
    })
}

#[cfg(test)]
mod dns_expiry_tests {
    use super::*;

    #[test]
    fn a_replayed_expired_rrset_is_never_reinstalled_after_clock_changes() {
        let member = "198.18.4.24".parse().unwrap();
        let static_anchor = "203.0.113.0/24".parse().unwrap();
        let plan: Snapshot = Plan {
            revision: 2,
            prefixes: [
                (Prefix::host(member), "awg1".into()),
                (static_anchor, "awg1".into()),
            ]
            .into(),
            learned: Some(
                learning::Saved::new(
                    &crate::Routing::default(),
                    "0".repeat(64),
                    &[learning::Member {
                        zone: 0,
                        ip: member,
                        until: 200,
                    }],
                )
                .unwrap(),
            ),
            dns_bridges: vec!["br0".into()],
            ..Plan::default()
        }
        .into();
        let active = Journal {
            installed: plan.clone(),
            committed: plan,
            ..Journal::default()
        };
        assert_eq!(
            expire_during_recovery(active.clone(), &active, 199, None),
            active
        );
        let expired = expire_during_recovery(active.clone(), &active, 200, None);
        assert_eq!(expired.installed.prefixes.len(), 1);
        assert!(expired.installed.prefixes.contains_key(&static_anchor));
        assert_eq!(expired.installed.dns_bridges, ["br0"]);
        assert_eq!(expired.installed.revision, 2);
        assert!(expired
            .installed
            .learned
            .as_ref()
            .unwrap()
            .members
            .is_empty());
        assert_eq!(
            expire_during_recovery(active, &guarded(&expired, None), 198, None),
            expired
        );
    }

    #[test]
    fn expired_client_rrset_removes_only_its_exact_selectors_after_clock_changes() {
        let source = "192.168.51.40".parse().unwrap();
        let member = "198.18.4.24".parse().unwrap();
        let learned = plan::Selector {
            source,
            dest: Prefix::host(member),
        };
        let anchor = plan::Selector {
            source,
            dest: "203.0.113.0/24".parse().unwrap(),
        };
        let policy = serde_json::from_value(json!({
            "mode":"zones", "domain_source":"dnsproxy", "zones":[{
                "enabled":true,"route":"tunnel","domains":["*.test"],
                "ips":["203.0.113.0/24"],"source_ips":["192.168.51.40"]
            }]
        }))
        .unwrap();
        let plan: Snapshot = Plan {
            revision: 2,
            scoped: vec![(learned, "awg1".into()), (anchor, "awg1".into())],
            learned: Some(
                learning::Saved::new(
                    &policy,
                    "0".repeat(64),
                    &[learning::Member {
                        zone: 0,
                        ip: member,
                        until: 200,
                    }],
                )
                .unwrap(),
            ),
            dns_bridges: vec!["br0".into()],
            ..Plan::default()
        }
        .into();
        let active = Journal {
            installed: plan.clone(),
            committed: plan,
            ..Journal::default()
        };
        assert_eq!(
            expire_during_recovery(active.clone(), &active, 199, None),
            active
        );
        let expired = expire_during_recovery(active.clone(), &active, 200, None);
        assert_eq!(expired.installed.scoped, [(anchor, "awg1".into())]);
        assert_eq!(expired.installed.dns_bridges, ["br0"]);
        assert_eq!(
            expire_during_recovery(active, &guarded(&expired, None), 198, None),
            expired
        );
    }
}
