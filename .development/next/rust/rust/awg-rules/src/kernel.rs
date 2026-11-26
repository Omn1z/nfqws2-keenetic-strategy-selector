//! Owner-scoped IPv4 and IPv6 split routes, backed by a durable intent record.
use super::model::err;
use std::{cell::Cell, io};
mod acceleration;
mod active_replacement;
use active_replacement::NamedTransportClaims;
pub use active_replacement::{
    active_replacement_dns_redirects, active_replacement_dns_revalidation,
    active_replacement_in_progress, active_replacement_launch_cleanup,
    active_replacement_native_witness_needed, cold_numeric_startup,
    confirmed_firmware_refresh_basis, ColdNumericStartup,
    defer_active_replacement_launch, defer_named_active_replacement_launch,
    disabled_replacement_dns_redirects,
    disabled_replacement_rearm_needs_dns, dormant_firmware_dns, DormantFirmwareAnswer,
    DormantFirmwareDns, DormantFirmwareProof,
    finish_active_replacement_launch_cleanup,
    finish_active_replacement_retirement, pending_active_replacement_dns_retry,
    pending_active_replacement_retirement,
    prepare_active_replacement_launch, replace_active_profile, replace_active_profile_checked,
    prepare_deferred_named_rotation, prepare_named_active_replacement,
    prepare_named_active_replacement_launch, replace_active_profile_with_names,
    replace_active_profile_with_warm_name,
    resume_deferred_named_rotation, DeferredNamedRotation, NamedActiveReplacement,
    warm_named_native_owner, warm_named_replacement_request, WarmNamedReplacementRequest,
    established_warm_client, established_warm_owner,
    replace_active_profile_with_disabled_target, replace_active_profile_with_dns,
    replace_active_profile_with_held_dns, resume_active_replacement_dns_retry, ActiveDnsReplacement,
    ActiveDnsReplacementProof, ActiveReplacementDnsRetry, ActiveReplacementDnsRetryProof,
    ActiveReplacementLaunchCleanup, FirmwareDnsArchive, FirmwareDnsGroup, FirmwareDnsGroupAnswer,
    FirmwareDnsGroupProof, FirmwareRefreshBasis,
};
mod packed;
pub use acceleration::{pause_for_engine, EngineChange};
mod prefix;
pub(crate) use prefix::{Family, Prefix};
mod journal;
mod plan;
use journal::{Journal, Snapshot, RECEIPT_LIMIT};
pub use plan::LivePeer;

/// Extra native ownership proof is needed only for the two open peers in an
/// unconfirmed bare full draft that can follow Go's reserve classifier.
pub fn fresh_full_reserve_native_witness_needed(db: &Store, iface: &str) -> io::Result<bool> {
    let doc = nfqws2_awg_profile::read(db)?;
    let Some(zone) = handoff::implicit_multi::native_draft(&doc, &crate::policy::current(&doc)?)
    else {
        return Ok(false);
    };
    if !Journal::read(db)?.idle() {
        return Ok(false);
    }
    let rows = doc["servers"]
        .as_array()
        .ok_or_else(|| err("нет списка серверов AWG"))?;
    for id in std::iter::once(&zone.tunnel_id).chain(&zone.fallback_tunnel_ids) {
        if plan::profile(&doc, rows, id)?.1 == iface {
            return Ok(true);
        }
    }
    Ok(false)
}
mod dns;
pub use dns::{
    cold_static_dns_draft, cold_static_dns_draft_until, confirmed_static_dns_retry, dns_request,
    failed_static_dns_apply, installed_static_dns_snapshot, managed_static_dns_proposal_off_scope,
    ColdStaticDnsDraft, ConfirmedStaticDnsRetry, DnsRequest, DnsSnapshot, FailedStaticDnsApply,
    ManagedStaticDnsApply,
};
mod flow_trace;
pub use flow_trace::{FlowDecision, FlowRoute, FlowSnapshot};
mod full;
mod fw4;
pub mod handoff;
mod inventory;
mod learning;
mod legacy_scope;
mod legacy_sni;
mod legacy_watchdog;
mod marked;
mod mss;
mod mtu_edit;
pub use mtu_edit::{
    legacy_dual_probe_target, named_reconnect_revision, pending_endpoint_launch, pending_endpoint_retry,
    pending_endpoint_retry_with_wan, pending_mtu_edit, prepare_endpoint_retry, prepare_mtu_edit,
    prepare_mtu_edit_with_wan, validate_endpoint_edit,
    validate_endpoint_edit_launch, validate_endpoint_edit_with_backup, validate_named_reconnect,
};
mod nested_endpoint;
mod profile_rebind;
mod routed_disable;
mod failover_order;
pub use failover_order::{finish_routed_failover_order, stage_routed_failover_order};
pub use routed_disable::{disable_routed_profile, routed_profile_is_disabled, routed_profile_needs_rearm};
pub use profile_rebind::{finish_dormant_replacement, stage_dormant_replacement};
mod scopes;
mod transport_claims;
pub(crate) use learning::shared_cdn_address;
pub use learning::{
    learn_answer, learn_archived_answer, learn_client_answer, learn_named_client_answer,
    observation, Answer, ArchiveAnswer, DnsOrigin, Observation,
};
pub use legacy_sni::LegacySni;
pub fn observations(db: &Store) -> io::Result<(Option<Observation>, io::Result<Option<LegacySni>>)> {
    let journal = Journal::read(db)?;
    Ok((
        learning::observation_from_journal(db, &journal)?,
        legacy_sni::read(db, &journal),
    ))
}
pub fn valid_dns_bridge(name: &str) -> bool {
    name.starts_with("br")
        && name.len() < 16
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_'))
}

/// An unfinished transition can own redirects from either generation. Keep
/// their sockets bound until inventory has confirmed the kernel change.
pub fn redirect_bridges(db: &Store, restoring: bool) -> io::Result<Vec<String>> {
    let journal = Journal::read(db)?;
    let bridges: BTreeSet<_> = std::iter::once(&journal.installed)
        .chain(&journal.preparing)
        .chain(restoring.then_some(&journal.committed))
        .flat_map(|plan| plan.dns_bridges.iter().cloned())
        .collect();
    Ok(bridges.into_iter().collect())
}
pub fn needs_dns_listener(db: &Store) -> io::Result<bool> {
    if let Some(bridges) = handoff_dns_bridges(db)? {
        return Ok(!bridges.is_empty());
    }
    Ok(crate::observed::dynamic(&crate::sources::current(
        db,
        &nfqws2_awg_profile::read(db)?,
    )?))
}
pub fn handoff_dns_bridges(db: &Store) -> io::Result<Option<Vec<String>>> {
    handoff::legacy_dns_bridges(db)
}

/// Prebind transparent DNS before a watchdog tick can select a profile with
/// learned client zones. The transaction revalidates this against its plan.
pub fn watchdog_needs_dns_listener(db: &Store) -> io::Result<bool> {
    let j = Journal::read(db)?;
    if j.expires != 0 || !j.preparing.is_empty()
        || !legacy_watchdog::scheduled(&j.committed, &j.installed)
    {
        return Ok(false);
    }
    let doc = nfqws2_awg_profile::read(db)?;
    let Some(selected) = crate::model::selected_profile(&doc) else {
        return Ok(false);
    };
    let config = &selected["config"];
    if doc["routing_revision"].as_u64().unwrap_or_default() != j.committed.revision
        || config["enabled"] != true || config["client"]["enabled"] != true
        || crate::policy::current(&doc)?.mode != "full"
    {
        return Ok(false);
    }
    Ok(legacy_scope::needs_dns(&learning::legacy_policy(db, &doc)?))
}
/// Go clears its legacy confirmation flag after applying an implicit full
/// policy. Keep that public response separate from the installer's commit.
pub fn bare_full_commit_uses_go_response(db: &Store) -> io::Result<bool> {
    let journal = Journal::read(db)?;
    let plan = &journal.installed;
    if journal.expires == 0
        || !journal.preparing.is_empty()
        || !journal.committed.empty()
        || plan.full_endpoints.is_none()
        || !plan.permanent_fences.is_empty()
        || !plan.fully_live()
    {
        return Ok(false);
    }
    let doc = nfqws2_awg_profile::read(db)?;
    let policy = crate::policy::current(&doc)?;
    Ok(doc["rust_static_routing"]["go_trial"] != true
        && doc["routing_revision"].as_u64().unwrap_or_default() == plan.revision
        && policy.mode == "full"
        && policy.zones.is_empty()
        && !policy.sni_routing
        && (plan.targets.len() == 1 && plan.reserves.is_empty()
            || handoff::implicit_multi::reserve_with_separate_intent(&doc, plan).is_some()))
}

#[cfg(test)]
mod tests;
use inventory::{objects, Kernel, Object};
use nfqws2_router_command::Runner;
use nfqws2_store::{Store, Transaction};
use plan::Plan;
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};

const RECEIPT: &str = "awg-static-ipv4.json";
const LEGACY_PREPARATIONS: usize = 4;
const TRIAL: u64 = 90;
impl Journal {
    fn read(db: &Store) -> io::Result<Self> {
        let journal: Self = match db.read_runtime(RECEIPT, RECEIPT_LIMIT) {
            Ok(value) => value,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e),
        };
        journal.validated()
    }
    fn validated(self) -> io::Result<Self> {
        let journal = self;
        if journal.preparing.len() > LEGACY_PREPARATIONS + 1
            || !boot_valid(&journal.boot)
            || !journal.committed.offline.is_empty()
            || !journal.committed.selected.is_empty()
        {
            return Err(err("повреждена запись владения маршрутами"));
        }
        for plan in journal.unique_generations() {
            plan.validate()?;
        }
        if journal.preparing.len() > LEGACY_PREPARATIONS
            && journal.preparing.last().map(Snapshot::as_ref)
                != Some(&journal.committed.guards_only())
        {
            return Err(err("повреждена точка восстановления маршрутных правил"));
        }
        Ok(journal)
    }
    fn claims(&self) -> BTreeSet<Object> {
        let mut set = objects(&self.installed);
        for (i, plan) in self.preparing.iter().enumerate() {
            if plan != &self.installed && !self.preparing[..i].contains(plan) {
                set.extend(objects(plan));
            }
        }
        set
    }
    fn idle(&self) -> bool {
        self.installed.empty()
            && self.committed.empty()
            && self.preparing.is_empty()
            && self.expires == 0
    }
    fn cold_empty(&self) -> bool {
        self.installed.as_ref() == &Plan::default()
            && self.committed.as_ref() == &Plan::default()
            && self.preparing.is_empty()
            && self.expires == 0
    }
}
fn kernel(run: &dyn Runner) -> Kernel<'_> {
    Kernel {
        run,
        deadline: Instant::now() + Duration::from_secs(30),
        ip: Default::default(),
        nested_sockets: Default::default(),
        held_dns_lookups: Default::default(),
    }
}
fn kernel_for_transition<'a>(
    run: &'a dyn Runner,
    db: &Store,
    old: &Journal,
    target: &Plan,
) -> io::Result<Kernel<'a>> {
    let mut k = kernel(run);
    let plans = std::iter::once(old.installed.as_ref())
        .chain(std::iter::once(old.committed.as_ref()))
        .chain(old.preparing.iter().map(Snapshot::as_ref))
        .chain(std::iter::once(target))
        .filter(|p| !p.empty());
    if plans.clone().next().is_some() {
        let doc = nfqws2_awg_profile::read(db)?;
        for plan in plans {
            k.track_sockets(&doc, plan);
        }
        active_replacement::retain_rearm_lookups(&mut k, &doc, old, target)?;
    }
    active_replacement::track_replacement(&mut k, db)?;
    Ok(k)
}
fn boot_valid(v: &str) -> bool {
    v.len() == 36
        && v.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
fn boot_id(k: &Kernel<'_>) -> io::Result<String> {
    let id = k
        .run
        .run("cat", &["/proc/sys/kernel/random/boot_id"], k.deadline)?;
    if !boot_valid(id.trim()) {
        return Err(err("не удалось определить загрузку ядра"));
    }
    Ok(id.trim().into())
}
#[derive(Clone, Copy, Default, Debug)]
pub struct Status {
    pub active: bool,
    pub ready: bool,
    pub pending_commit: bool,
    pub revision: u64,
}
pub fn inspect(db: &Store, run: &dyn Runner) -> io::Result<Status> {
    let j = Journal::read(db)?;
    if j.idle() {
        if active_replacement::confirmed_disabled_empty(db, &j)?
            && kernel_for_transition(run, db, &j, &j.installed)?
                .inventory(&j.claims(), true)?
                .is_empty()
        {
            return Ok(Status {
                revision: j.committed.revision,
                ready: true,
                ..Status::default()
            });
        }
        return Ok(Status::default());
    }
    let pending = j.expires != 0;
    let mut status = Status {
        revision: j.installed.revision,
        pending_commit: pending,
        ..Status::default()
    };
    let k = kernel_for_transition(run, db, &j, &j.installed)?;
    if !j.installed.empty() && j.preparing.is_empty() && j.boot == boot_id(&k)? {
        // A verified zone rename is recoverable drift. Let the periodic
        // worker rebind even when the netlink subscription is unavailable.
        if k.lan_zone(j.installed.firewall)? != j.installed.fw4_zone {
            return Ok(status);
        }
        status.active =
            j.installed.fully_live() && k.inventory(&j.claims(), true)? == objects(&j.installed);
        if status.active {
            let doc = nfqws2_awg_profile::read(db)?;
            status.ready = doc["routing_revision"].as_u64().unwrap_or(0) == j.installed.revision
                && (!pending || nfqws2_awg_profile::now() < j.expires);
        }
    }
    Ok(status)
}
fn synchronize(
    k: &Kernel<'_>,
    present: &BTreeSet<Object>,
    target: &BTreeSet<Object>,
) -> io::Result<()> {
    if present.iter().chain(target).any(marked::owned) {
        return marked::synchronize(k, present, target);
    }
    synchronize_plain(k, present, target)
}
fn synchronize_plain(
    k: &Kernel<'_>,
    present: &BTreeSet<Object>,
    target: &BTreeSet<Object>,
) -> io::Result<()> {
    if present == target {
        return Ok(());
    }
    // Keep both generations of protection until the new lookup rules are in
    // place. A partial replacement or a disappearing device must not open WAN.
    for guard in target.difference(present).filter(|o| o.is_stop()) {
        k.mutate(guard, true)?;
    }
    // Fixed MSS rules have no ipset dependencies. Keep the previous ceiling
    // for both directions until replacement or rollback finishes installing.
    for rule in target.difference(present).filter(|o| o.fixed_mss()) {
        k.mutate(rule, true)?;
    }
    mss::verify_additions(k, present, target)?;
    if let Some((present_keys, target_keys)) = routed_disable::plain_lookup_route_keys(present, target) {
        for rule in target.difference(present).filter(|object| {
            matches!(object, Object::Firewall(..)) && !object.fixed_mss()
        }) {
            k.mutate(rule, true)?;
        }
        for route in target.difference(present) {
            let Object::Route(dest, iface, table) = route else { continue };
            if present_keys.contains(dest) {
                k.call("ip", &[
                    dest.family().flag(), "route", "replace", "table", &table.to_string(),
                    &dest.to_string(), "dev", iface, "proto", inventory::PROTO,
                ])?;
            } else {
                k.mutate(route, true)?;
            }
        }
        for route in present.difference(target).filter(|object| {
            matches!(object, Object::Route(prefix, ..) if !target_keys.contains(prefix))
        }) {
            k.mutate(route, false)?;
        }
        for old in present.difference(target).filter(|object| {
            matches!(object, Object::Firewall(..) | Object::Stop(..) | Object::LegacyV6Reject(_))
        }) {
            k.mutate(old, false)?;
        }
        return Ok(());
    }
    // A DNS answer often only adds a new destination. In that case every
    // installed lookup keeps the same table and the same existing routes.
    // Do not take unrelated clients off their tunnel while adding one IP.
    let keep_lookups = present.difference(target).all(Object::mss_rule);
    let packed = packed::in_use(present) || packed::in_use(target);
    let full = present
        .iter()
        .chain(target)
        .any(|o| matches!(o, Object::FullGuard(..)));
    let scope_families: BTreeSet<_> = present.iter().chain(target).filter_map(|o| {
        match o {
            Object::LegacyLookup(family, _) => Some(*family),
            _ => None,
        }
    }).collect();
    let scope_rule = |o: &Object| match o {
        Object::LegacyLookup(..) => true,
        Object::PackedLookup(family) => scope_families.contains(family),
        _ => false,
    };
    let keep_rule = |rule: &Object| {
        target.contains(rule) && (k.held_dns_lookups.contains(rule) || (packed || full)
            && matches!(rule, Object::PackedLookup(_) | Object::ProbeLookup(_)
                | Object::FullGuard(full::Guard::SourceLookup(_)))
            || full && matches!(rule, Object::FullGuard(full::Guard::Main(_))))
    };
    if !keep_lookups {
        for rule in present
            .iter()
            .filter(|o| o.is_rule() && !keep_rule(o) && !scope_rule(o))
        {
            k.mutate(rule, false)?;
        }
    }
    fw4::update(k, present, target)?;
    if packed {
        packed::create(k, present, target)?;
        if !scope_families.is_empty() {
            packed::routes(k, present, target, true, false)?;
        }
    }
    for r in target.difference(present).filter(|r| scope_rule(r)) {
        k.mutate(r, true)?;
    }
    // Scope rules get their complete sets before the single firewall commit.
    // Both generations of the WAN rejection remain installed during a switch.
    legacy_scope::update(k, present, target)?;
    for r in present.difference(target).filter(|r| scope_rule(r)) {
        k.mutate(r, false)?;
    }
    for o in present
        .difference(target)
        .filter(|x| {
            !x.is_rule()
                && !x.is_stop()
                && !x.fixed_mss()
                && !matches!(x, Object::Native(..) | Object::LegacyClassifier(..))
                && !(packed && packed::batched(x))
        })
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        k.mutate(o, false)?;
    }
    for o in target.difference(present).filter(|x| {
        !x.is_rule()
            && !x.is_stop()
            && !x.fixed_mss()
            && !matches!(x, Object::Native(..) | Object::LegacyClassifier(..))
            && !(packed && packed::batched(x))
    }) {
        k.mutate(o, true)?;
    }
    if packed {
        if !scope_families.is_empty() {
            packed::routes(k, present, target, false, true)?;
            packed::remove_sets(k, present, target)?;
        } else {
            packed::finish(k, present, target)?;
        }
    }
    for rule in target.iter().filter(|o| {
        o.is_rule()
            && !scope_rule(o)
            && (!keep_lookups || !present.contains(o))
            && !(keep_rule(o) && present.contains(o))
    }) {
        k.mutate(rule, true)?;
    }
    for rule in present.difference(target).filter(|o| o.fixed_mss()) {
        k.mutate(rule, false)?;
    }
    for guard in present.difference(target).filter(|o| o.is_stop()) {
        k.mutate(guard, false)?;
    }
    Ok(())
}
fn stamp(tx: &Transaction<'_>, j: &Journal) -> io::Result<()> {
    nfqws2_awg_profile::edit_document_locked(tx, |doc| stamp_document(doc, j))
}

fn stamp_document(doc: &mut Value, j: &Journal) -> io::Result<()> {
    let managed =
        doc["rust_static_routing"].is_object() || !j.installed.empty() || !j.committed.empty();
    if !managed {
        return Ok(());
    }
    let ids = j
        .installed
        .targets
        .values()
        .map(|t| t.id.as_str())
        .collect::<BTreeSet<_>>();
    let committed_ids = j
        .committed
        .targets
        .values()
        .map(|t| t.id.as_str())
        .collect::<BTreeSet<_>>();
    let watchdog = j.expires == 0
        && legacy_watchdog::is_transient(&j.committed, &j.installed);
    let support_disable = j.expires == 0 && routed_disable::supported_intent(doc, &j.committed);
    let previous_watchdog = doc["rust_static_routing"]["legacy_watchdog"] == true;
    let preserve_commit = (j.installed.empty()
        || doc[nfqws2_awg_profile::ACTIVE_REPLACEMENT_FIELD].is_object())
        && doc["routing_revision"].as_u64().unwrap_or_default() == j.committed.revision;
    // Go saves routing.active before it attempts kernel installation. Keep
    // those flags exactly as found until an explicit Rust commit succeeds.
    let go_trial = doc["rust_static_routing"]["go_trial"] == true
        || (j.expires != 0 && !doc["rust_static_routing"].is_object() && legacy_active(doc));
    let preserve_go = go_trial && j.committed.empty();
    let dormant: BTreeSet<String> = doc["rust_static_routing"][active_replacement::DISABLED_REPLACEMENTS]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    let mut prior: BTreeSet<String> = ["targets", "committed_targets"]
        .iter()
        .filter(|&&key| !previous_watchdog || key != "targets")
        .filter_map(|key| doc["rust_static_routing"][*key].as_array())
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    let committed_dormant = !dormant.is_empty()
        && j.committed.revision != 0
        && doc["routing_revision"].as_u64() == Some(j.committed.revision);
    if j.idle() && !committed_dormant {
        prior.extend(dormant.iter().cloned());
    }
    let reserve_plan = if j.expires == 0 && !j.committed.empty() {
        &j.committed
    } else {
        &j.installed
    };
    let connection_only = routed_disable::connection_only_standby(doc, reserve_plan)
        .or_else(|| routed_disable::implicit_full_reserve(reserve_plan))
        .or_else(|| handoff::implicit_multi::reserve_with_separate_intent(doc, reserve_plan));
    for row in doc["servers"]
        .as_array_mut()
        .ok_or_else(|| err("нет серверов AWG"))?
    {
        let id = row["id"].as_str().unwrap_or_default();
        let selected = ids.contains(id) || preserve_commit && committed_ids.contains(id);
        if (!j.idle() || committed_dormant) && !selected && dormant.contains(id) {
            // Keep the dormant target's intent through an interrupted FIB
            // addition until its new receipt has been durably committed.
            continue;
        }
        if support_disable && committed_ids.contains(id) && !ids.contains(id)
            && routed_disable::disabled(&row["config"])
        {
            // Client-down preserves saved active intent; server disable has
            // already explicitly cleared it. Neither has an installed route.
            continue;
        }
        if preserve_go || watchdog || connection_only == Some(id) || !selected && !prior.contains(id) {
            continue;
        }
        for key in ["config", "applied_config"] {
            if row[key].is_object() {
                row[key]["routing"]["active"] = json!(selected);
            }
        }
    }
    if j.idle() && !committed_dormant {
        doc.as_object_mut().unwrap().remove("rust_static_routing");
    } else {
        let pending_failover = doc["rust_static_routing"].get(failover_order::FIELD).cloned();
        let dormant_dns = committed_dormant
            .then(|| doc["rust_static_routing"].get(active_replacement::DISABLED_REPLACEMENT_DNS))
            .flatten()
            .cloned();
        doc["rust_static_routing"] = json!({"revision":j.installed.revision,"pending_commit":j.expires!=0,"boot":j.boot,"targets":ids,"committed_targets":committed_ids});
        if let Some(pending) = pending_failover {
            doc["rust_static_routing"][failover_order::FIELD] = pending;
        }
        if !dormant.is_empty() {
            doc["rust_static_routing"][active_replacement::DISABLED_REPLACEMENTS] = json!(dormant);
        }
        if let Some(dns) = dormant_dns {
            doc["rust_static_routing"][active_replacement::DISABLED_REPLACEMENT_DNS] = dns;
        }
        if !j.committed.empty() || committed_dormant {
            doc["rust_static_routing"]["committed_revision"] = json!(j.committed.revision);
        }
        if watchdog {
            doc["rust_static_routing"]["legacy_watchdog"] = json!(true);
        }
        if preserve_go {
            doc["rust_static_routing"]["go_trial"] = json!(true);
        }
        let routes = if j.installed.empty() || routed_disable::has_confirmed_reserve_transfer(&j.committed) {
            &j.committed
        } else {
            &j.installed
        };
        if !routes.reserves.is_empty() {
            doc["rust_static_routing"]["reserve_chains"] = json!(routes.reserve_chains());
            let mut active = j.installed.active_reserves();
            active.extend(routed_disable::transferred_reserve(&j.committed, &j.installed));
            doc["rust_static_routing"]["active_reserves"] = json!(active);
        }
    }
    Ok(())
}
fn legacy_active(doc: &Value) -> bool {
    doc["servers"].as_array().into_iter().flatten().any(|r| {
        [&r["config"], &r["applied_config"]]
            .into_iter()
            .any(|c| c["routing"]["active"] == true)
            && !["targets", "committed_targets", active_replacement::DISABLED_REPLACEMENTS].iter().any(|k| {
                doc["rust_static_routing"][*k]
                    .as_array()
                    .is_some_and(|a| a.contains(&r["id"]))
            })
    })
}
/// Apply only differences against our private, boot-scoped receipt. Persist intent
/// first, and re-inventory after ambiguous subprocess failures before compensating.
fn transition(
    db: &Store,
    tx: &Transaction<'_>,
    run: &dyn Runner,
    old: &Journal,
    new: &Journal,
    safe_rollback: Option<&Journal>,
) -> io::Result<()> {
    acceleration::transition(db, tx, run, old, new, || {
        switch_routes(db, tx, run, old, new, safe_rollback)
    })
}

struct ManagedDnsWriter<'a> {
    verify_current: &'a dyn Fn() -> io::Result<()>,
    cold: bool,
    compensated: Cell<bool>,
}

fn transition_managed_dns(
    db: &Store,
    tx: &Transaction<'_>,
    run: &dyn Runner,
    old: &Journal,
    new: &Journal,
    (proposal, verify_current): (ManagedStaticDnsApply<'_>, &dyn Fn() -> io::Result<()>),
) -> io::Result<()> {
    let writer = ManagedDnsWriter {
        verify_current,
        cold: proposal.cold_draft().is_some(),
        compensated: Cell::new(false),
    };
    if writer.cold {
        verify_current()?;
    }
    let mut original = None;
    acceleration::transition(db, tx, run, old, new, || {
        let result = switch_routes_checked(db, tx, run, old, new, None, (Some(&writer), None));
        if writer.compensated.get() {
            // Let acceleration finish restoring the previous installation
            // before exposing proof of a fully compensated writer failure.
            original = result.err();
            Ok(())
        } else {
            result
        }
    })?;
    if let Some(original) = original {
        return Err(if Journal::read(db).is_ok_and(|current| current == *old)
            && (!writer.cold || kernel(run).check_cold_static_empty().is_ok())
            && verify_current().is_ok()
        {
            proposal.write_failure(original, old, new)
        } else {
            original
        });
    }
    Ok(())
}

fn switch_routes(
    db: &Store,
    tx: &Transaction<'_>,
    run: &dyn Runner,
    old: &Journal,
    new: &Journal,
    safe_rollback: Option<&Journal>,
) -> io::Result<()> {
    switch_routes_checked(db, tx, run, old, new, safe_rollback, (None, None))
}

type RouteOwnerCheck<'a> = &'a mut dyn FnMut() -> io::Result<()>;

fn reassert_with_owner(
    db: &Store,
    tx: &Transaction<'_>,
    run: &dyn Runner,
    current: &Journal,
    verify_owner: RouteOwnerCheck<'_>,
) -> io::Result<()> {
    let mut parked = current.clone();
    parked.installed = current.installed.guards_only().into();
    acceleration::transition(db, tx, run, current, current, || {
        switch_routes_checked(db, tx, run, current, current, Some(&parked), (None, Some(verify_owner)))
    })
}

#[derive(Debug)]
struct RouteWriteRejected(io::Error);

impl std::fmt::Display for RouteWriteRejected {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(out)
    }
}

impl std::error::Error for RouteWriteRejected {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

fn switch_routes_checked(
    db: &Store,
    tx: &Transaction<'_>,
    run: &dyn Runner,
    old: &Journal,
    new: &Journal,
    safe_rollback: Option<&Journal>,
    (managed, mut verify_owner): (Option<&ManagedDnsWriter<'_>>, Option<RouteOwnerCheck<'_>>),
) -> io::Result<()> {
    new.check_size()?;
    if let Some(rollback) = safe_rollback {
        rollback.check_size()?;
    }
    let started = Instant::now();
    let k = kernel_for_transition(run, db, old, &new.installed)?;
    let mut claims = old.claims();
    let goal = objects(&new.installed);
    if new.installed.firewall == plan::Backend::Fw3 {
        k.check_lan_zone(&new.installed)?;
    }
    let extra_rollback = safe_rollback
        .filter(|fallback| fallback.installed != old.installed && fallback.installed != new.installed)
        .map(|fallback| (&fallback.installed, objects(&fallback.installed)))
        .filter(|(_, objects)| objects.iter().any(|o| !claims.contains(o) && !goal.contains(o)));
    let proposed;
    let proposal = if let Some((_, objects)) = &extra_rollback {
        proposed = goal.union(objects).cloned().collect();
        &proposed
    } else {
        &goal
    };
    let present = k.inventory_for(&claims, proposal, !proposal.is_empty())?;
    if let Some(verify) = verify_owner.as_mut() {
        verify()?;
    }
    if managed.is_some() && present != objects(&old.installed) {
        return Err(err("состав подтверждённых маршрутов изменился"));
    }
    if let Some(writer) = managed.filter(|writer| writer.cold) {
        k.check_cold_static_empty()?;
        (writer.verify_current)()?;
    }
    if old == new && present == goal {
        k.verify_forward(&new.installed)?;
        return stamp(tx, new);
    }
    let mut prepared = old.clone();
    // An existing intent already covers removal of its objects. Never discard
    // a previous claim until inventory confirms the checkpoint or teardown.
    if prepared.preparing.is_empty() || !goal.is_subset(&claims) {
        if prepared.preparing.len() >= LEGACY_PREPARATIONS
            && (prepared.preparing.len() != LEGACY_PREPARATIONS
                || new.installed.as_ref() != &old.committed.guards_only())
        {
            return Err(err(
                "требуется восстановление ранее подготовленных маршрутов",
            ));
        }
        prepared.preparing.push(new.installed.clone());
    }
    if let Some((rollback, objects)) = extra_rollback {
        if prepared.preparing.len() >= LEGACY_PREPARATIONS {
            return Err(err("нет места для защитных правил отката"));
        }
        // A verified fallback can add a fence that neither live route needs.
        // Own it before any writes so recovery can remove it after a crash.
        prepared.preparing.push(rollback.clone());
        claims.extend(objects);
    }
    tx.save_runtime_bounded(RECEIPT, &prepared, RECEIPT_LIMIT)?;
    // During initial install and additive DNS updates the target already
    // contains every claim. Reuse it throughout verification and rollback.
    let claims = if claims.is_subset(&goal) {
        &goal
    } else {
        for object in &goal {
            if !claims.contains(object) {
                claims.insert(object.clone());
            }
        }
        &claims
    };
    let mut route_failure = false;
    let result = (|| {
        if let Some(writer) = managed {
            (writer.verify_current)()?;
        }
        if let Some(verify) = verify_owner.as_mut() {
            verify()?;
        }
        let synced = synchronize(&k, &present, &goal);
        route_failure =
            managed.is_some() && synced.as_ref().is_err_and(|error| !fw4::refused(error));
        synced.map_err(|error| {
            if nfqws2_router_command::reported_failure(&error) {
                io::Error::other(RouteWriteRejected(error))
            } else {
                error
            }
        })?;
        if new.installed.firewall == plan::Backend::Fw3 {
            k.check_lan_zone(&new.installed)?;
        }
        if k.inventory_for(claims, &goal, !goal.is_empty())? != goal {
            return Err(err("ядро не подтвердило полный состав правил"));
        }
        // DNS renewals keep the existing RPDB lookup. The complete FIB and
        // set membership were checked above, probe just the added/changed paths.
        if !new.installed.marks.is_empty() {
            k.verify_forward(&new.installed)?;
        } else if old.installed.packed
            && new.installed.packed
            && new.installed.revision == old.installed.revision
            && old.expires == new.expires
        {
            k.verify_ipv6_reject(&new.installed)?;
            packed::verify(&k, &new.installed, Some(&present))?;
        } else {
            k.verify_forward(&new.installed)?;
        }
        if let Some(writer) = managed {
            (writer.verify_current)()?;
        }
        if let Some(verify) = verify_owner.as_mut() {
            verify()?;
        }
        stamp(tx, new)?;
        // Start the full confirmation window when installation and forwarding
        // verification finish, even for a busy router with many destinations.
        let mut completed;
        let receipt =
            if new.expires != 0 && new.expires != old.expires && started.elapsed().as_secs() > 0 {
                completed = new.clone();
                completed.expires = completed
                    .expires
                    .saturating_add(started.elapsed().as_secs());
                &completed
            } else {
                new
            };
        tx.save_runtime_bounded(RECEIPT, receipt, RECEIPT_LIMIT)
    })();
    if let Err(original) = result {
        let k = Kernel {
            held_dns_lookups: k.held_dns_lookups,
            ..kernel(run)
        };
        let undo = (|| {
            // The fw4 writer explicitly refused before submitting any batch.
            // An externally added exact match for a proposed native rule is
            // still foreign, including during compensation of changed routes.
            let prior;
            let claims = if fw4::refused(&original) {
                prior = claims
                    .iter()
                    .filter(|o| !matches!(o, Object::Native(..)) || present.contains(o))
                    .cloned()
                    .collect();
                &prior
            } else {
                claims
            };
            let protected;
            let mut before = if let Some(safe) = safe_rollback {
                protected = objects(&safe.installed);
                &protected
            } else {
                &present
            };
            let current_zone;
            if claims.iter().any(|o| matches!(o, Object::Fw3Forward(..))) {
                let zone = k.lan_zone(plan::Backend::Fw3)?;
                k.retire_fw3_forward(claims, zone.as_deref())?;
                let chain = inventory::fw3_forward_chain(zone.as_deref());
                current_zone = before
                    .iter()
                    .filter(|o| !matches!(o, Object::Fw3Forward(_, _, owned) if *owned != chain))
                    .cloned()
                    .collect();
                before = &current_zone;
            }
            let current = k.inventory(claims, false)?;
            // A subprocess error by itself cannot prove a kernel mutation.
            let changed_routes = route_failure
                && current.symmetric_difference(&present).any(|object| {
                    matches!(object, Object::Rule(_) | Object::Route(..) | Object::Stop(..))
                });
            synchronize(&k, &current, before)?;
            if &k.inventory(claims, false)? != before {
                return Err(err("неполный откат"));
            }
            let saved = safe_rollback.unwrap_or(old);
            stamp(tx, saved)?;
            tx.save_runtime_bounded(RECEIPT, saved, RECEIPT_LIMIT)?;
            Ok(changed_routes)
        })();
        return match undo {
            Ok(changed_routes) => {
                if let Some(writer) = managed {
                    writer
                        .compensated
                        .set(changed_routes && k.verify_forward(&old.installed).is_ok());
                }
                Err(original)
            }
            Err(e) => Err(err(format!(
                "{original}; требуется повторное снятие или восстановление правил: {e}"
            ))),
        };
    }
    Ok(())
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Operation {
    Apply,
    ReloadSources,
    Commit,
    Teardown,
    Recover,
    Refresh,
    LegacyWatchdog,
    FirewallReload,
    Suspend,
}
pub fn operate(
    db: &Store,
    run: &dyn Runner,
    op: Operation,
    peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<()> {
    operate_with_dns(db, run, op, None, peer)
}
pub fn operate_with_dns(
    db: &Store,
    run: &dyn Runner,
    op: Operation,
    snapshot: Option<&DnsSnapshot>,
    peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<()> {
    operate_with_redirect(db, run, op, snapshot, None, peer)
}
/// A Keenetic apply supplies the complete list of bridges on which both
/// TCP and UDP sockets are already available. Other platforms use panel DNS.
pub fn operate_with_redirect(
    db: &Store,
    run: &dyn Runner,
    op: Operation,
    snapshot: Option<&DnsSnapshot>,
    bridges: Option<&[String]>,
    peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<()> {
    operate_with_redirect_and_mtu(db, run, op, snapshot, bridges, peer, |_, _| Ok(None))
}

/// Recover a routed MTU change with the profile runtime's owned nested peer proof.
/// The verifier performs read-only checks and cannot wait for client locks.
pub fn operate_with_redirect_and_mtu(
    db: &Store,
    run: &dyn Runner,
    op: Operation,
    snapshot: Option<&DnsSnapshot>,
    bridges: Option<&[String]>,
    peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
    prove: impl FnMut(&nfqws2_awg_profile::RoutedMtuChange, &LivePeer) -> io::Result<Option<nfqws2_awg_profile::RoutedMtuPeer>>,
) -> io::Result<()> {
    operate_with_inputs(
        db,
        run,
        op,
        nfqws2_awg_profile::now(),
        (snapshot.map(DnsInput::Fresh), bridges),
        peer,
        (prove, None),
    )
}

pub struct GoFullPrimaryRecovery<'a> {
    pub wan: &'a [String],
    pub probe: &'a dyn Fn(&str) -> io::Result<Option<nfqws2_awg_profile::ActiveReplacementPeer>>,
}

/// Restore a confirmed Go full policy using a separately verified native
/// primary link after its only reserve has been withdrawn.
pub fn operate_with_native_ownership(
    db: &Store,
    run: &dyn Runner,
    op: Operation,
    (snapshot, bridges, firmware_refresh, dormant): (
        Option<&DnsSnapshot>, Option<&[String]>, bool, Option<&DormantFirmwareProof>,
    ),
    peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
    prove: impl FnMut(&nfqws2_awg_profile::RoutedMtuChange, &LivePeer) -> io::Result<Option<nfqws2_awg_profile::RoutedMtuPeer>>,
    go_primary: GoFullPrimaryRecovery<'_>,
) -> io::Result<bool> {
    if firmware_refresh && (op != Operation::Refresh || snapshot.is_some() || dormant.is_some())
        || dormant.is_some() && (snapshot.is_some() || !matches!(op, Operation::Recover | Operation::Refresh)) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let unchanged = Cell::new(false);
    let dns = if firmware_refresh {
        Some(DnsInput::FirmwareRefresh(&unchanged))
    } else if let Some(proof) = dormant {
        Some(DnsInput::DormantRearm(proof))
    } else {
        snapshot.map(DnsInput::Fresh)
    };
    operate_with_inputs(
        db,
        run,
        op,
        nfqws2_awg_profile::now(),
        (dns, bridges),
        peer,
        (prove, Some(go_primary)),
    )?;
    Ok(unchanged.get())
}

/// Refresh through the ordinary writer and report whether its exact installed
/// inventory already matched without repairing or changing the plan.
pub fn operate_firmware_refresh(
    db: &Store,
    run: &dyn Runner,
    bridges: Option<&[String]>,
    peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
    prove: impl FnMut(&nfqws2_awg_profile::RoutedMtuChange, &LivePeer) -> io::Result<Option<nfqws2_awg_profile::RoutedMtuPeer>>,
) -> io::Result<bool> {
    let unchanged = Cell::new(false);
    operate_with_inputs(
        db,
        run,
        Operation::Refresh,
        nfqws2_awg_profile::now(),
        (Some(DnsInput::FirmwareRefresh(&unchanged)), bridges),
        peer,
        (prove, None),
    )?;
    Ok(unchanged.get())
}

/// Reapply a committed static DNS snapshot after the caller verifies the
/// original managed resolution receipt, without accepting any new address.
pub fn apply_confirmed_static_dns_retry(
    db: &Store,
    run: &dyn Runner,
    retry: &ConfirmedStaticDnsRetry,
    peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
    verify_current: impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    operate_with_inputs(
        db,
        run,
        Operation::Apply,
        nfqws2_awg_profile::now(),
        (Some(DnsInput::StaticRetry(retry, &verify_current)), None),
        peer,
        (|_, _| Ok(None), None),
    )
}

/// Apply a complete managed DNS rotation through the ordinary confirmed trial.
/// `verify_current` checks the original resolver, command and TTL before the
/// writer changes the kernel and before it publishes the new trial.
pub fn apply_managed_static_dns_proposal(
    db: &Store,
    run: &dyn Runner,
    proposal: ManagedStaticDnsApply<'_>,
    peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
    verify_current: impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    operate_with_inputs(
        db,
        run,
        Operation::Apply,
        nfqws2_awg_profile::now(),
        (Some(DnsInput::ManagedProposal(proposal, &verify_current)), None),
        peer,
        (|_, _| Ok(None), None),
    )
}

enum DnsInput<'a> {
    Fresh(&'a DnsSnapshot),
    StaticRetry(&'a ConfirmedStaticDnsRetry, &'a dyn Fn() -> io::Result<()>),
    ManagedProposal(ManagedStaticDnsApply<'a>, &'a dyn Fn() -> io::Result<()>),
    FirmwareRefresh(&'a Cell<bool>),
    DormantRearm(&'a DormantFirmwareProof),
}
#[cfg(test)]
fn operate_at(
    db: &Store,
    run: &dyn Runner,
    op: Operation,
    now: u64,
    peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<()> {
    operate_with_dns_at(db, run, op, now, None, peer)
}
#[cfg(test)]
fn operate_with_dns_at(
    db: &Store,
    run: &dyn Runner,
    op: Operation,
    now: u64,
    snapshot: Option<&DnsSnapshot>,
    peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<()> {
    operate_with_inputs_at(db, run, op, now, snapshot, None, peer)
}
#[cfg(test)]
fn operate_with_inputs_at(
    db: &Store,
    run: &dyn Runner,
    op: Operation,
    now: u64,
    snapshot: Option<&DnsSnapshot>,
    bridges: Option<&[String]>,
    peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<()> {
    operate_with_inputs(db, run, op, now, (snapshot.map(DnsInput::Fresh), bridges), peer, (|_, _| Ok(None), None))
}

fn operate_with_inputs(
    db: &Store,
    run: &dyn Runner,
    op: Operation,
    now: u64,
    (dns_input, bridges): (Option<DnsInput<'_>>, Option<&[String]>),
    mut peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
    (mut prove, go_primary): (
        impl FnMut(&nfqws2_awg_profile::RoutedMtuChange, &LivePeer) -> io::Result<Option<nfqws2_awg_profile::RoutedMtuPeer>>,
        Option<GoFullPrimaryRecovery<'_>>,
    ),
) -> io::Result<()> {
    let (snapshot, static_retry, managed, firmware_refresh, dormant) = match dns_input {
        Some(DnsInput::Fresh(snapshot)) => (Some(snapshot), None, None, None, None),
        Some(DnsInput::StaticRetry(retry, verify_current)) => {
            (Some(retry.snapshot()), Some((retry, verify_current)), None, None, None)
        }
        Some(DnsInput::ManagedProposal(proposal, verify_current)) => {
            (Some(proposal.snapshot()), None, Some((proposal, verify_current)), None, None)
        }
        Some(DnsInput::FirmwareRefresh(accepted)) => (None, None, None, Some(accepted), None),
        Some(DnsInput::DormantRearm(proof)) => (None, None, None, None, Some(proof)),
        None => (None, None, None, None, None),
    };
    let verify_freshness = static_retry
        .map(|(_, verify)| verify)
        .or_else(|| managed.map(|(_, verify)| verify));
    let cold_static_draft = managed.and_then(|(proposal, _)| proposal.cold_draft());
    let started = Instant::now();
    let watchdog = op == Operation::LegacyWatchdog;
    if snapshot.is_some()
        && !matches!(
            op,
            Operation::Apply | Operation::ReloadSources | Operation::Refresh
        )
    {
        return Err(err("этой операции не требуется DNS-снимок"));
    }
    let op = if watchdog { Operation::Refresh } else { op };
    db.transaction(|tx| {
        let mut j = Journal::read(db)?;
        let firmware_baseline = firmware_refresh.map(|accepted| (accepted, j.clone()));
        if active_replacement::recover(tx, db, run, &mut j, op, &mut peer)? {
            return Ok(());
        }
        if matches!(op, Operation::Apply | Operation::Commit | Operation::ReloadSources)
            && active_replacement::launch_pending(db)?
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let mut mtu_authority = if op == Operation::Teardown { None } else { mtu_edit::read(db)? };
        if mtu_authority.is_some()
            && (snapshot.is_some() || matches!(op, Operation::Apply | Operation::Commit | Operation::ReloadSources))
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if op == Operation::FirewallReload {
            let k = kernel_for_transition(run, db, &j, &j.installed)?;
            return fw4::reassert(db, tx, &k, &j, now, mtu_authority.as_ref(), peer);
        }
        let armed = handoff::parked_guard::Armed::read(db)?;
        if j.idle()
            && armed.is_none()
            && matches!(
                op,
                Operation::Recover | Operation::Refresh | Operation::Suspend
            )
            && (op == Operation::Suspend
                || j.committed.revision == 0
                || !active_replacement::rearm_pending(&nfqws2_awg_profile::read(db)?, &j))
        {
            return acceleration::restore(db, tx, &kernel(run));
        }
        let mut doc = nfqws2_awg_profile::read(db)?;
        if op != Operation::Teardown && active_replacement::settle_rearm(tx, &doc, &j)? {
            doc = nfqws2_awg_profile::read(db)?;
        }
        if op != Operation::Teardown
            && (profile_rebind::finish(tx, &mut j, &doc)?
                || failover_order::finish(db, tx, run, &mut j, &doc, &mut peer)?)
        {
            doc = nfqws2_awg_profile::read(db)?;
        }
        if failover_order::pending(&doc)
            && matches!(op, Operation::Apply | Operation::Commit | Operation::ReloadSources)
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let predecessor = if mtu_authority.is_none() && matches!(op, Operation::Recover | Operation::Refresh) {
            mtu_edit::pending_predecessor(db, &doc, &j)?
        } else {
            None
        };
        if mtu_authority.is_none() && predecessor.is_none() {
            if matches!(op, Operation::Recover | Operation::Refresh) && snapshot.is_none() {
                mtu_authority = mtu_edit::recover_authority(tx, &doc, &j)?;
            } else if op == Operation::Suspend {
                mtu_edit::preserve_full_ipv6_fence_before_suspend(tx, &doc, &j)?;
            } else if (snapshot.is_some() || matches!(op, Operation::Apply | Operation::Commit | Operation::ReloadSources))
                && mtu_edit::saved_profile(&doc, &j)?.is_some()
            {
                return Err(io::ErrorKind::WouldBlock.into());
            }
        }
        let reload = op == Operation::ReloadSources;
        if reload && (j.expires != 0 || !j.preparing.is_empty() || j.installed.empty()
            || j.committed.local_sources.is_none()
            || doc["routing_revision"].as_u64().unwrap_or_default() != j.committed.revision) {
            return Err(err("изменилась подтверждённая политика источников"));
        }
        if let Some(armed) = &armed {
            armed.verify_native(db, &kernel(run), &doc)?;
            match op {
                Operation::Recover | Operation::Refresh | Operation::Suspend | Operation::LegacyWatchdog => {
                    // The installer owns this protection through its Go
                    // shutdown and the native trial, including rollback.
                    return Ok(());
                }
                Operation::Apply | Operation::Commit => (),
                _ => return Err(io::ErrorKind::WouldBlock.into()),
            }
        }
        let go_active = legacy_active(&doc);
        let dormant_empty = j.idle() && active_replacement::dormant_target(&doc, &j).is_some();
        if j.idle()
            && !dormant_empty
            && (doc["rust_static_routing"].is_object() || go_active && op != Operation::Apply)
        {
            return Err(err(
                "активная политика или её запись владения принадлежит прежней установке",
            ));
        }
        if j.idle() && !dormant_empty && op == Operation::Teardown {
            active_replacement::clear_established_name(tx)?;
            return mtu_edit::clear(tx);
        }
        if j.expires == 0 && op == Operation::Commit {
            return Err(err("нет маршрутов, ожидающих подтверждения"));
        }
        let mut candidate = None;
        if op == Operation::Apply || reload {
            let preflight = kernel(run);
            candidate = Some(if let Some((retry, _)) = static_retry {
                let intent = dns::recheck_static_dns_retry(db, &doc, &j, retry)?;
                let resolved = plan::resolve_on(&doc, intent, false, None, Some(plan::Verification::Read(&preflight)), &mut peer)?;
                (resolved.plan, resolved.endpoints)
            } else if let Some((proposal, _)) = managed {
                let intent = proposal.intent(db, &doc, &j)?;
                let resolved = plan::resolve_on(&doc, intent, false, None, Some(plan::Verification::Read(&preflight)), &mut peer)?;
                (resolved.plan, resolved.endpoints)
            } else if reload {
                let config = crate::sources::current(db, &doc)?;
                let intent = plan::compile_effective(&doc, config, snapshot, false, &[], j.committed.layout())?;
                if !j.committed.local_sources.as_ref().zip(intent.local_sources.as_ref())
                    .is_some_and(|(old, current)| old.can_replace(current)) {
                    return Err(err("снимок источников больше не относится к подтверждённой политике"));
                }
                let resolved = plan::resolve_on(&doc, intent, false, None, Some(plan::Verification::Read(&preflight)), &mut peer)?;
                if resolved.plan.empty() || !resolved.plan.fully_live() {
                    return Err(err("новая политика источников ещё не готова"));
                }
                (resolved.plan, resolved.endpoints)
            } else if j.idle() && go_active {
                match handoff::candidate(db, tx, run, &doc, now, snapshot, &mut peer)? {
                    Some(plan) => plan,
                    None => plan::build(db, &doc, snapshot, false, &preflight, &mut peer)?,
                }
            } else if j.idle() && !go_active {
                plan::build_initial(db, &doc, snapshot, &preflight, &mut peer)?
            } else {
                plan::build(db, &doc, snapshot, false, &preflight, &mut peer)?
            });
        }
        if j.idle() && candidate.as_ref().is_some_and(|(p, _)| p.empty()) {
            if go_active {
                return Err(err(
                    "нет поддерживаемых зон для пробного переноса с прежней панели",
                ));
            }
            return Ok(());
        }
        let mut k = kernel(run);
        k.track_sockets(&doc, &j.installed);
        k.track_sockets(&doc, &j.committed);
        if let Some((plan, _)) = &candidate {
            k.track_sockets(&doc, plan);
        }
        if op == Operation::Apply && go_active
            || op == Operation::Commit && doc["rust_static_routing"]["go_trial"] == true
        {
            if !matches!(crate::policy::current(&doc)?.mode.as_str(),"zones"|"full") {
                return Err(err("для пробного переноса нужна активная политика зон или полного туннеля"));
            }
            if op == Operation::Commit
                && handoff::implicit_multi::reserve_with_separate_intent(&doc, &j.installed).is_some()
            {
                k.check_go_implicit_trial(&j.installed)?;
            } else {
                k.check_go_handoff()?;
            }
        }
        if let Some(armed) = &armed {
            if op == Operation::Apply {
                if !j.idle() || !go_active
                    || candidate.as_ref().is_none_or(|(plan, _)| plan != &armed.plan)
                {
                    return Err(err("временная защита не относится к подготовленной политике AWG"));
                }
                // The exact guard is already in the FIB and separately
                // journaled. Give the standard writer that existing claim.
                j.installed = armed.plan.clone().into();
            } else if j.installed.as_ref() != &armed.plan {
                return Err(err("пробная политика изменила временную защиту AWG"));
            }
        }
        let boot = boot_id(&k)?;
        if let Some(verify_current) = verify_freshness {
            // The normal reboot and fw3 paths may mutate state before the
            // last freshness check. A static retry owns neither transition.
            if cold_static_draft.map_or(j.boot.as_str(), ColdStaticDnsDraft::boot) != boot {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            verify_current()?;
        }
        // A cold draft has no preceding plan to replay. Record its live boot
        // with the apply intent, keeping the missing journal read-only so far.
        let reboot = cold_static_draft.is_none() && j.boot != boot && !j.boot.is_empty();
        if reboot {
            j.installed = Snapshot::default();
            j.preparing.clear();
            // A cold Go AWG2_MULTI start does not replay a FORWARD rule
            // left behind by the original legacy full hook.
            j.committed.go_multi_v6_reject = None;
            if let Some((plan, _)) = &mut candidate {
                plan.go_multi_v6_reject = None;
            }
        }
        j.boot = boot;
        if reboot {
            tx.save_runtime_bounded(RECEIPT, &j, RECEIPT_LIMIT)?;
        }
        if !j.preparing.is_empty() && matches!(op, Operation::Apply | Operation::Commit) {
            return Err(err(
                "сначала восстановите или снимите незавершённые маршруты",
            ));
        }
        if j.installed.firewall == plan::Backend::Fw3
            && !matches!(op, Operation::Teardown | Operation::Suspend)
        {
            let zone = k.lan_zone(plan::Backend::Fw3)?;
            let claims = j.claims();
            k.retire_fw3_forward(&claims, zone.as_deref())?;
            if matches!(op, Operation::Refresh | Operation::Commit)
                && j.expires > now
                && j.preparing.is_empty()
                && !j.installed.empty()
                && (zone != j.installed.fw4_zone || k.inventory(&claims, true)? != claims)
            {
                let mut next = j.clone();
                next.installed.fw4_zone.clone_from(&zone);
                if next.committed.firewall == plan::Backend::Fw3 {
                    next.committed.fw4_zone = zone;
                }
                let live = plan::restore(&doc, &next.installed, None, Some(&k), &mut peer)?;
                if objects(&live.plan) != objects(&next.installed) {
                    return Err(err("fw3: изменилось подтверждённое подключение AWG"));
                }
                k.guard(&live.plan, &live.endpoints)?;
                transition(db, tx, run, &j, &next, None)?;
                j = next;
            }
        }
        if op == Operation::Refresh && j.expires != 0 {
            return Ok(());
        }
        if !watchdog && !reboot && (dns_input.is_none() || dormant.is_some())
            && mtu_authority.is_none() && predecessor.is_none()
            && matches!(op, Operation::Recover | Operation::Refresh)
        {
            if let Some(checkpoint) = active_replacement::rearm_checkpoint(&doc, &j)? {
                transition(db, tx, run, &j, &checkpoint, None)?;
                return Ok(());
            }
            if active_replacement::rearm(db, tx, &k, &doc, &j, (bridges, now, dormant), &mut peer)? {
                return Ok(());
            }
        }
        if watchdog && !reboot && j.preparing.is_empty() && mtu_authority.is_none() && predecessor.is_none() {
            if let Some(candidate) = legacy_watchdog::candidate(db, &k, &doc, &j.committed, &j.installed, bridges, &mut peer)? {
                let mut next = j.clone();
                let mut rollback = j.clone();
                if !candidate.installed.dns_bridges.is_empty()
                    && bridges != Some(candidate.installed.dns_bridges.as_slice())
                {
                    return Err(err("не подтверждены DNS-слушатели выбранного профиля AWG"));
                }
                next.installed = candidate.installed.into();
                rollback.installed = candidate.rollback.into();
                let claims = j.claims();
                if next == j && k.inventory(&claims, true)? == claims {
                    return acceleration::audit(db, tx, &k, &j.installed);
                }
                return transition(db, tx, run, &j, &next, Some(&rollback));
            }
        }
        let upgrading_full = if matches!(op, Operation::Recover | Operation::Refresh) {
            j.committed.upgrade_permanent_full(&doc)?
        } else { None };
        if (!j.preparing.is_empty() || upgrading_full.is_some()) && matches!(op, Operation::Recover | Operation::Refresh) {
            if snapshot.is_some() {
                return Err(err(
                    "перед обновлением DNS требуется завершить восстановление маршрутов",
                ));
            }
            let mut checkpoint = j.clone();
            checkpoint.preparing.clear();
            checkpoint.expires = 0;
            if let Some(fixed) = upgrading_full {
                checkpoint.committed = fixed.into();
            }
            let withdrawn = routed_disable::recovered(&doc, &checkpoint.committed)?;
            let fallback = withdrawn.as_ref().unwrap_or(&checkpoint.committed);
            let full_edit = mtu_authority.as_ref().and_then(|edit| edit.full_edit(&j));
            checkpoint.installed = full_edit.map_or_else(
                || fallback.guards_only(),
                |full| full.recovery_guards(&checkpoint.committed),
            ).into();
            if !checkpoint.installed.empty() {
                // Validate current management and transport paths before adding
                // a missing stop. No peer is selected for this first phase.
                let endpoints = if let Some(full) = full_edit {
                    mtu_edit::FullEdit::verify_legacy_guard(&k, &checkpoint.committed)?;
                    let endpoints = full.retained(&checkpoint.committed, Some(&j.installed))?;
                    checkpoint.installed.full_endpoints = Some(endpoints.clone());
                    endpoints
                } else {
                    let proof = mtu_authority.as_ref().map(|edit| edit.guard_checkpoint_proof(&doc, &j))
                        .transpose()?.flatten();
                    let mut no_peer_proof = |_: &_, _: &_| Ok(None);
                    let idle = routed_disable::withdrawn_mixed(&doc, &checkpoint.committed, fallback)
                        .map_or(plan::EditContext::None, |(id, endpoint)| {
                            plan::EditContext::WithdrawnMixed { id, endpoint }
                        });
                    let edit = proof.as_ref().map_or(idle, |proof| {
                        plan::EditContext::Applying(proof, &mut no_peer_proof)
                    });
                    let topology = plan::resolve_with_mtu_edit(&doc, fallback.clone(),
                        true, None, Some(plan::Verification::Read(&k)), edit, &mut peer)?;
                    if checkpoint.committed.full_endpoints != topology.plan.full_endpoints {
                        checkpoint.committed.full_endpoints.clone_from(&topology.plan.full_endpoints);
                        checkpoint.installed.full_endpoints.clone_from(&topology.plan.full_endpoints);
                    }
                    topology.endpoints
                };
                k.guard(&checkpoint.installed, &endpoints)?;
            }
            // A partial checkpoint can always finish with the same stops.
            // Never compensate by recreating forwarding on an unverified peer.
            transition(db, tx, run, &j, &checkpoint, Some(&checkpoint))?;
            j = checkpoint;
        }
        let mut new = j.clone();
        let mut safe_rollback = None;
        let mut expiry_result = Ok(());
        let mut go_primary_used = None;
        let mut mtu_verified = false;
        new.preparing.clear();
        match op {
            Operation::FirewallReload | Operation::LegacyWatchdog => unreachable!("handled before choosing the transaction"),
            Operation::Apply | Operation::ReloadSources => {
                if j.expires != 0 && j.expires <= now {
                    return Err(err(
                        "срок подтверждения истёк, ожидается автоматический откат",
                    ));
                }
                let (mut plan, endpoints) = candidate.unwrap();
                if !plan.marks.is_empty() {plan.assign_marks(&j.installed.marks)?;}
                k.select_firewall(&mut plan)?;
                if !plan.dns_bridges.is_empty() && bridges != Some(plan.dns_bridges.as_slice()) {
                    return Err(err("не подтверждены DNS-слушатели на мостах снимка Go"));
                }
                if let Some(names) = bridges {
                    if names.is_empty() == plan.learned.is_some() {
                        return Err(err("состав зон DNS изменился или отсутствуют мосты LAN; повторите применение"));
                    }
                    plan.set_dns_bridges(names)?;
                }
                if !plan.empty() {
                    k.guard(&plan, &endpoints)?;
                }
                if let Some((retry, verify_current)) = static_retry {
                    retry.verify_candidate(&plan)?;
                    verify_current()?;
                }
                if let Some((proposal, verify_current)) = managed {
                    proposal.verify_candidate(&plan)?;
                    verify_current()?;
                }
                new.expires = if plan.empty() {
                    0
                } else {
                    now.saturating_add(started.elapsed().as_secs()).saturating_add(TRIAL)
                };
                new.installed = plan.into();
                if reload {
                    new.committed = new.installed.clone();
                    if !new.committed.selected.is_empty() {
                        new.committed.selected.clear();
                    }
                    new.expires = 0;
                }
                if new.installed.empty() {
                    new.committed = Snapshot::default();
                }
            }
            Operation::Commit => {
                if reboot || j.expires <= now || j.installed.empty() {
                    return Err(err("срок подтверждения маршрутов истёк"));
                }
                let saved = j.installed.dns.as_ref().map(|v| &v.snapshot);
                let parked = if doc["rust_static_routing"]["go_trial"] == true {
                    handoff::parked_trial_plan(db, &k, &doc, &j, now)?
                } else {
                    None
                };
                let (mut draft, ends) = if let Some(trial) = &parked {
                    (trial.offline.clone(), trial.endpoints.clone())
                } else if let Some(learned) = &j.installed.learned {
                    let legacy = j.installed.legacy_full.is_some();
                    let mut routing = if legacy { learning::legacy_policy(db, &doc)? }
                        else { crate::sources::current(db, &doc)? };
                    routing.active = false;
                    let draft = plan::compile_effective(
                        &doc,
                        routing,
                        None,
                        false,
                        &learned.members,
                        j.installed.layout(),
                    )?;
                    let resolved = if legacy {
                        plan::resolve_on(&doc, draft, false, None, Some(plan::Verification::Read(&k)), peer)?
                    } else { plan::restore(&doc, &draft, None, Some(&k), peer)? };
                    if !resolved.plan.fully_live() {
                        return Err(err("не все динамические маршруты доступны"));
                    }
                    (resolved.plan, resolved.endpoints)
                } else if j.installed.go_ipv4 || j.installed.legacy_full.is_some() {
                    let intent = plan::compile_effective(&doc, crate::sources::current(db, &doc)?, saved, true, &[], j.installed.layout())?;
                    let live = plan::resolve_on(&doc, intent, false, None, Some(plan::Verification::Read(&k)), peer)?;
                    (live.plan, live.endpoints)
                } else {
                    plan::build(db, &doc, saved, true, &k, peer)?
                };
                if !draft.marks.is_empty() {draft.assign_marks(&j.installed.marks)?;}
                k.select_firewall(&mut draft)?;
                draft.set_dns_bridges(bridges.unwrap_or(&j.installed.dns_bridges))?;
                if &draft != j.installed.as_ref() {
                    return Err(err("сохранённая политика изменилась; примените её снова"));
                }
                k.guard(&draft, &ends)?;
                if k.inventory(&j.claims(), true)? != objects(&j.installed) {
                    return Err(err("состав установленных маршрутов изменился"));
                }
                new.committed = parked.map_or_else(|| j.installed.clone(), |trial| trial.intended.into());
                if !new.committed.selected.is_empty() {
                    new.committed.selected.clear();
                }
                new.expires = 0;
            }
            Operation::Teardown | Operation::Suspend => {
                new.installed = Snapshot::default();
                new.expires = 0;
                if op == Operation::Teardown {
                    new.committed = Snapshot::default();
                } else {
                    // All installed MSS claims are released by this transaction.
                    // Leave the committed intent readable by the preceding binary
                    // after an orderly stop for a package downgrade.
                    new.committed.mss.clear();
                    // No OpenWrt chain remains owned after Suspend. Resolve LAN
                    // again on restart; older binaries can read this intent.
                    new.committed.fw4_zone = None;
                }
            }
            Operation::Recover | Operation::Refresh => {
                if snapshot.is_none()
                    && dormant.is_none()
                    && firmware_refresh.is_none()
                    && !reboot
                    && mtu_authority.is_none()
                    && predecessor.is_none()
                    && active_replacement::reassert_established_name(db, tx, (run, &k), &doc, &j, &mut peer)?
                {
                    return Ok(());
                }
                // Even when the draft's peers no longer authorize pruning a
                // lease, restore the saved ownership and park unavailable peers.
                if mtu_authority.is_none() {
                    expiry_result = learning::expire(&doc, &new.committed, now).map(|fresh| {
                        if let Some(fresh) = fresh {
                            new.committed = fresh.into();
                        }
                    });
                }
                let mtu_proof = mtu_authority.as_ref().map(|edit| edit.proof(&doc, &j)).transpose()?;
                if let Some(snapshot) = snapshot {
                    let saved = j
                        .committed
                        .dns
                        .as_ref()
                        .ok_or_else(|| err("подтверждённая политика DNS отсутствует"))?;
                    if saved.snapshot.request != snapshot.request || !j.preparing.is_empty() {
                        return Err(err("DNS-снимок не соответствует подтверждённой политике"));
                    }
                    if doc["routing_revision"].as_u64().unwrap_or_default()
                        != snapshot.request.revision
                    {
                        return Err(err("черновик политики изменился во время DNS-запроса"));
                    }
                    if &saved.snapshot != snapshot {
                        let fresh = plan::compile_effective(&doc, crate::sources::current(db, &doc)?, Some(snapshot), true, &[], j.committed.layout())?;
                        if fresh
                            .dns
                            .as_ref()
                            .is_none_or(|dns| dns.source_hash != saved.source_hash)
                        {
                            return Err(err(
                                "исходная политика DNS или идентичность туннеля изменились",
                            ));
                        }
                        new.committed = fresh.into();
                    }
                }
                if !new.committed.dns_bridges.is_empty() {
                    if let Some(current) = bridges {
                        if current != new.committed.dns_bridges {
                            new.committed.set_dns_bridges(current)?;
                        }
                    }
                }
                let withdrawn = routed_disable::recovered(&doc, &new.committed)?;
                new.installed = withdrawn.clone().map_or_else(|| new.committed.clone(), Snapshot::from);
                new.expires = 0;
                if !new.installed.empty() {
                    let mut resolving = new.installed.as_ref().clone();
                    if resolving.legacy_full.is_none() {
                        k.select_firewall(&mut resolving)?;
                        if new.committed.fw4_zone != resolving.fw4_zone {
                            new.committed.fw4_zone.clone_from(&resolving.fw4_zone);
                        }
                        if new.committed.firewall != resolving.firewall {
                            new.committed.firewall = resolving.firewall;
                            new.committed.mss.clone_from(&resolving.mss);
                        }
                    }
                    let go_scope = if snapshot.is_none() && j.expires == 0
                        && mtu_proof.is_none() && predecessor.is_none()
                    {
                        withdrawn.as_ref().and_then(|projected| {
                            routed_disable::withdrawn_go_full_primary(&doc, &new.committed, projected)
                        })
                    } else {
                        None
                    };
                    let previous = (j.expires == 0
                        && j.preparing.is_empty()
                        && (mtu_proof.is_some()
                            || predecessor.is_some()
                            || go_scope.is_some()
                            || !j.installed.reserves.is_empty()
                            || resolving.permanent_full_inner(&doc).is_some()
                            || nested_endpoint::has_permanent_target(&doc, &resolving)))
                    .then_some(j.installed.as_ref());
                    let verifiers = if let Some(proof) = &mtu_proof {
                        plan::EditContext::Applying(proof, &mut prove)
                    } else {
                        predecessor.as_ref().map_or_else(
                            || {
                                if let Some((id, endpoint)) =
                                    routed_disable::withdrawn_mixed(&doc, &new.committed, &resolving)
                                {
                                    plan::EditContext::WithdrawnMixed { id, endpoint }
                                } else if j.expires == 0 && !reboot
                                    && routed_disable::rearming(&doc, &resolving, &j.installed)
                                {
                                    plan::EditContext::Rearming(&j.installed)
                                } else {
                                    plan::EditContext::None
                                }
                            },
                            plan::EditContext::Predecessor,
                        )
                    };
                    let awaiting_go_primary = go_primary.as_ref().zip(go_scope);
                    let mut old_attested = false;
                    let route_peer = |cfg: &Value, iface: &str| {
                        let result = peer(cfg, iface);
                        match (&result, awaiting_go_primary) {
                            (Err(_), Some((verify, (id, expected)))) if iface == expected => {
                                let Some(proof) = (verify.probe)(id)? else {
                                    return result;
                                };
                                let live = routed_disable::recovered_go_full_peer(
                                    &k, &doc, &new.committed, iface, &proof, verify.wan,
                                )?;
                                go_primary_used = Some(proof);
                                Ok(live)
                            }
                            _ => result,
                        }
                    };
                    match plan::resolve_with_mtu_edit(&doc, resolving, true, previous, Some(plan::Verification::Refresh(&k)), verifiers, route_peer).and_then(|mut v| {
                        old_attested = v.predecessor_verified;
                        if snapshot.is_some() && predecessor.is_some() && !old_attested {
                            return Err(io::ErrorKind::WouldBlock.into());
                        }
                        if let Some(proof) = mtu_proof.as_ref().filter(|_| v.mtu_verified) {
                            mtu_edit::rebind_dns(db, &doc, &new.committed, &mut v.plan, &proof.change.iface)?;
                            if let Some(sources) = mtu_edit::rebind_local_sources(db, &doc, &new.committed, proof.change)? {
                                v.plan.local_sources = Some(sources);
                            }
                        }
                        if v.plan.legacy_full.is_some() {
                            k.select_firewall(&mut v.plan)?;
                        }
                        if j.committed.dns != new.committed.dns && !v.plan.fully_live() {
                            return Err(err("новый DNS-снимок пока не покрыт действующими пирами"));
                        }
                        k.guard(&v.plan, &v.endpoints)?;
                        Ok(v)
                    }) {
                        Ok(v) => {
                            mtu_verified = v.mtu_verified;
                            if let Some(proof) = mtu_proof.filter(|_| mtu_verified) {
                                let iface = &proof.change.iface;
                                new.committed.targets.get_mut(iface).unwrap().mtu = v.plan.targets[iface].mtu;
                                new.committed.learned.clone_from(&v.plan.learned);
                                new.committed.dns.clone_from(&v.plan.dns);
                                new.committed.local_sources.clone_from(&v.plan.local_sources);
                                if proof.full.is_some() {
                                    new.committed.full_endpoints.clone_from(&v.plan.full_endpoints);
                                }
                            }
                            if !v.unsafe_previous.is_empty() {
                                // A failed handover may restore the previous route only
                                // while its original peer still authenticates and covers it.
                                let mut parked = j.clone();
                                parked.installed.park(&v.unsafe_previous);
                                safe_rollback = Some(parked);
                            }
                            if let (Some(saved),Some(now))=(&mut new.committed.legacy_scope,&v.plan.legacy_scope){
                                saved.remember_bridges(now);
                            }
                            if let Some(withdrawn) = &withdrawn {
                                new.committed.mss.retain(|iface, _| !withdrawn.targets.contains_key(iface));
                                new.committed.mss.extend(v.plan.mss.clone());
                            } else if new.committed.mss != v.plan.mss {
                                new.committed.mss.clone_from(&v.plan.mss);
                            }
                            new.installed = v.plan.into();
                        }
                        Err(e) => {
                            if let Some(held) = &predecessor {
                                if !old_attested {
                                    held.park(db, tx, &k, &j)?;
                                }
                                return Err(e);
                            }
                            // A conflicting management/transport prefix or an
                            // unreadable kernel inventory must not remove a
                            // working guard. Retry when topology is known.
                            if mtu_authority.is_some() || new.committed.has_protection() || new.committed.legacy_full.is_some() || new.committed.go_multi_v6_reject.is_some() || snapshot.is_some() || e.kind() == io::ErrorKind::WouldBlock {
                                return Err(e);
                            }
                            new.installed = Snapshot::default();
                            if !j.installed.empty() || !j.preparing.is_empty() {
                                transition(db, tx, run, &j, &new, None)?;
                            }
                            return Err(e);
                        }
                    }
                }
            }
        }
        // A stable failover audit reads each peer once and inventories the
        // kernel in batches, without probing each selector or writing to flash.
        if op == Operation::Refresh
            && new == j
            && k.inventory(&j.claims(), true)? == objects(&j.installed)
        {
            k.verify_ipv6_reject(&j.installed)?;
            acceleration::audit(db, tx, &k, &j.installed)?;
            if let Some(authority) = mtu_authority.filter(|_| mtu_verified) { authority.finish_verified(tx)?; }
            if let Some((accepted, baseline)) = firmware_baseline {
                accepted.set(baseline == j);
            }
            return expiry_result;
        }
        if let Some(managed) = managed {
            transition_managed_dns(db, tx, run, &j, &new, managed)?;
        } else {
            if let Some((verify, used)) = go_primary.as_ref().zip(go_primary_used.as_ref()) {
                let live = (verify.probe)(&used.owner.id)?.ok_or(io::ErrorKind::WouldBlock)?;
                if live != *used {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                routed_disable::recovered_go_full_peer(
                    &k, &doc, &new.committed, &used.owner.iface, &live, verify.wan,
                )?;
            }
            transition(db, tx, run, &j, &new, safe_rollback.as_ref())?;
        }
        if let Some(authority) = mtu_authority.filter(|_| mtu_verified) {
            authority.finish_verified(tx)?;
        } else if op == Operation::Teardown {
            active_replacement::clear_established_name(tx)?;
            mtu_edit::clear(tx)?;
        }
        expiry_result
    })
}
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Schedule {
    Idle,
    Restore,
    Expires(u64),
    Fw3Trial(u64),
    Audit,
    LegacyWatchdog,
    Failover,
    Dns,
}
pub fn has_local_sources(db: &Store) -> io::Result<bool> {
    let j = Journal::read(db)?;
    Ok(j.expires == 0
        && j.preparing.is_empty()
        && j.committed.local_sources.is_some()
        && j.committed.revision
            == nfqws2_awg_profile::read(db)?["routing_revision"]
                .as_u64()
                .unwrap_or_default())
}
pub fn local_sources_changed(db: &Store) -> io::Result<bool> {
    let j = Journal::read(db)?;
    let Some(old) = j.committed.local_sources.as_ref() else {
        return Ok(false);
    };
    let doc = nfqws2_awg_profile::read(db)?;
    let config = crate::sources::current(db, &doc)?;
    let fresh = crate::sources::Generation::from_policy(&doc, &config)?;
    Ok(j.expires == 0 && j.preparing.is_empty() && fresh.is_some_and(|new| old.can_replace(&new)))
}
pub fn scheduled(db: &Store) -> io::Result<Schedule> {
    Ok(scheduled_with_fw4(db)?.0)
}
pub fn scheduled_with_fw4(db: &Store) -> io::Result<(Schedule, bool)> {
    let (schedule, chain) = schedule_with_fw4_chain(db)?;
    Ok((schedule, chain.is_some()))
}
pub fn schedule_with_fw4_chain(db: &Store) -> io::Result<(Schedule, Option<String>)> {
    let j = Journal::read(db)?;
    let doc = if j.expires == 0 && j.preparing.is_empty() && j.committed.revision != 0 {
        nfqws2_awg_profile::read(db)?
    } else {
        Value::Null
    };
    let watch = (!j.installed.empty() && j.installed.firewall == plan::Backend::Fw4)
        .then(|| fw4::forward_chain(j.installed.fw4_zone.as_deref()));
    let schedule = if active_replacement::active_replacement_in_progress(db)?
        || active_replacement::rearm_pending(&doc, &j)
    {
        Schedule::Restore
    } else if j.idle() {
        if acceleration::pending(db)? {
            Schedule::Restore
        } else {
            Schedule::Idle
        }
    } else if !j.preparing.is_empty()
        || j.installed.empty()
        || profile_rebind::pending(&doc)
        || failover_order::pending(&doc)
    {
        Schedule::Restore
    } else if j.expires > 0 {
        if j.installed.firewall == plan::Backend::Fw3 {
            Schedule::Fw3Trial(j.expires)
        } else {
            Schedule::Expires(j.expires)
        }
    } else if mtu_edit::pending_mtu_edit(db)?
        || mtu_edit::pending_predecessor(db, &doc, &j)?.is_some()
    {
        Schedule::Restore
    } else if legacy_watchdog::scheduled(&j.committed, &j.installed) {
        Schedule::LegacyWatchdog
    } else if j.committed.dns.is_some() {
        Schedule::Dns
    } else if !j.committed.reserves.is_empty()
        || j.committed.learned.is_some()
        || mtu_edit::refresh_fenced_native_full_ipv6(db, &j)?
        || (!j.committed.targets.is_empty()
            && plan::has_named_endpoint(&doc))
    {
        Schedule::Failover
    } else if !j.installed.fully_live() {
        Schedule::Restore
    } else {
        Schedule::Audit
    };
    Ok((schedule, watch))
}
