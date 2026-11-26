use super::{
    boot_id, err, io, kernel_for_transition, objects, plan, stamp_document, transition, Journal,
    Plan, Runner, Store, Transaction,
};
use nfqws2_awg_profile::{
    ActiveReplacementPeer, NativeRemovalSeal, RoutedDirectOutage, RoutedDisable,
    RoutedPermanentHold,
};
use serde_json::Value;
use std::collections::BTreeSet;

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "профиль требует снятия связанной политики AWG",
    )
}

fn plain_intent(committed: &Plan) -> bool {
    !committed.empty()
        && !committed.packed
        && !committed.go_ipv4
        && committed.full_endpoints.is_none()
        && committed.learned.is_none()
        && committed.dns.is_none()
        && committed
            .prefixes
            .keys()
            .all(|p| !p.any() && p.family() == plan::Family::V4)
        && *committed
            == (Plan {
                prefixes: committed.prefixes.clone(),
                targets: committed.targets.clone(),
                mss: committed.mss.clone(),
                revision: committed.revision,
                killswitch: committed.killswitch,
                ..Plan::default()
            })
}

pub(super) fn supported_intent(doc: &Value, plan: &Plan) -> bool {
    plain_intent(plan)
        || full_intent(plan)
        || mixed_intent(plan)
        || reserve_intent(plan).is_some()
        || full_reserve_intent(plan).is_some()
            && (!plan.go_ipv4
                || super::handoff::implicit_multi::reserve_with_separate_intent(doc, plan)
                    .is_some())
}

#[derive(Clone, Copy)]
struct ReserveIntent<'a> {
    primary: &'a str,
    candidates: &'a [String],
}

impl<'a> ReserveIntent<'a> {
    fn selected(self) -> Option<&'a str> {
        (self.candidates.len() == 2).then_some(self.candidates[0].as_str())
    }

    fn standby_without_zone(self, committed: &Plan) -> Option<&'a str> {
        self.selected()
            .filter(|first| !committed.prefixes.values().any(|iface| iface == *first))
    }

    fn departing(self) -> &'a str {
        self.selected().unwrap_or(self.primary)
    }

    fn retained(self) -> &'a str {
        self.candidates.last().unwrap()
    }
}

/// Each explicit selector of the primary has the same ordered candidates.
/// The retained reserve has an independent zone. The retiring first
/// reserve may be a standby reached through the primary connection.
fn reserve_intent(plan: &Plan) -> Option<ReserveIntent<'_>> {
    let (first, candidates) = plan.reserves.first()?;
    let primary = plan.prefixes.get(&first.dest)?;
    if !(1..=2).contains(&candidates.len())
        || plan.targets.len() != 1 + candidates.len()
        || !plan.targets.contains_key(primary)
        || candidates
            .iter()
            .any(|reserve| reserve == primary || !plan.targets.contains_key(reserve))
        || !plan
            .prefixes
            .values()
            .any(|iface| Some(iface) == candidates.last())
        || plan
            .prefixes
            .values()
            .filter(|iface| *iface == primary)
            .count()
            != plan.reserves.len()
        || plan.reserves.iter().any(|(selector, choices)| {
            !selector.source.any()
                || plan.prefixes.get(&selector.dest) != Some(primary)
                || choices != candidates
        })
    {
        return None;
    }
    let mut fixed = plan.clone();
    fixed.reserves.clear();
    plain_intent(&fixed).then_some(ReserveIntent {
        primary,
        candidates,
    })
}

fn select_reserve(projected: &mut Plan, iface: &str) {
    projected.selected = projected
        .reserves
        .iter()
        .map(|(selector, _)| (*selector, Some(iface.to_owned())))
        .collect();
}

pub(super) fn transferred_reserve<'a>(committed: &'a Plan, installed: &Plan) -> Option<&'a str> {
    let intent = reserve_intent(committed)?;
    let primary = intent.primary;
    let reserve = intent.retained();
    let target = &committed.targets[reserve];
    (!installed.targets.contains_key(primary)
        && installed.targets.get(reserve) == Some(target)
        && committed.reserves.iter().any(|(selector, _)| {
            installed
                .prefixes
                .get(&selector.dest)
                .is_some_and(|configured| {
                    installed.effective(*selector, configured) == Some(reserve)
                })
        }))
    .then_some(target.id.as_str())
}

pub(super) fn has_confirmed_reserve_transfer(committed: &Plan) -> bool {
    reserve_intent(committed).is_some()
}

fn mixed_intent(plan: &Plan) -> bool {
    plan.packed
        && plan.permanent_fences.len() == 1
        && plan.targets.len() == 2
        && !plan.prefixes.is_empty()
        && plan
            .prefixes
            .keys()
            .all(|p| !p.any() && p.family() == plan::Family::V4)
        && plan.marks.keys().eq(plan.targets.keys())
        && *plan
            == (Plan {
                prefixes: plan.prefixes.clone(),
                targets: plan.targets.clone(),
                mss: plan.mss.clone(),
                revision: plan.revision,
                killswitch: plan.killswitch,
                packed: true,
                marks: plan.marks.clone(),
                permanent_fences: plan.permanent_fences.clone(),
                ..Plan::default()
            })
}

fn full_intent(committed: &Plan) -> bool {
    single_full_intent(committed, false)
}

fn single_full_intent(committed: &Plan, go_ipv4: bool) -> bool {
    let Some((iface, _)) = committed.targets.first_key_value() else {
        return false;
    };
    let families: &[plan::Family] = if go_ipv4 {
        &[plan::Family::V4]
    } else {
        &[plan::Family::V4, plan::Family::V6]
    };
    committed.targets.len() == 1
        && committed.prefixes.len() == families.len()
        && families
            .iter()
            .all(|family| committed.prefixes.get(&family.any()) == Some(iface))
        && committed
            .full_endpoints
            .as_ref()
            .is_some_and(|endpoints| !endpoints.is_empty())
        && *committed
            == (Plan {
                prefixes: committed.prefixes.clone(),
                targets: committed.targets.clone(),
                full_endpoints: committed.full_endpoints.clone(),
                mss: committed.mss.clone(),
                revision: committed.revision,
                killswitch: committed.killswitch,
                go_ipv4,
                ..Plan::default()
            })
}

fn full_reserve_intent(plan: &Plan) -> Option<ReserveIntent<'_>> {
    let (v4, candidates) = match plan.reserves.as_slice() {
        [(v4, candidates)] if plan.go_ipv4 => (v4, candidates),
        [(v4, candidates), (v6, others)] if !plan.go_ipv4 => {
            let any6 = plan::Family::V6.any();
            if v6.source != any6 || v6.dest != any6 || candidates != others {
                return None;
            }
            (v4, candidates)
        }
        _ => return None,
    };
    let [reserve] = candidates.as_slice() else {
        return None;
    };
    let any4 = plan::Family::V4.any();
    if v4.source != any4 || v4.dest != any4 || plan.targets.len() != 2 {
        return None;
    }
    let primary = plan.prefixes.get(&any4)?;
    if primary == reserve || !plan.targets.contains_key(reserve) {
        return None;
    }
    let mut implicit = plan.clone();
    implicit.reserves.clear();
    implicit.targets.remove(reserve);
    implicit.mss.remove(reserve);
    implicit.go_multi_v6_reject = None;
    single_full_intent(&implicit, plan.go_ipv4).then_some(ReserveIntent {
        primary,
        candidates,
    })
}

/// The implicit full policy owns the blanket, while its connection reserve
/// keeps its independently saved routing flag.
pub(super) fn implicit_full_reserve(plan: &Plan) -> Option<&str> {
    if plan.full_endpoints.is_none() || plan.reserves.len() != 2 {
        return None;
    }
    let mut intent = plan.clone();
    intent.selected.clear();
    intent.offline.clear();
    let reserve = full_reserve_intent(&intent)?.retained();
    Some(plan.targets.get(reserve)?.id.as_str())
}

pub(super) fn disabled(cfg: &Value) -> bool {
    cfg["enabled"].as_bool().is_some()
        && cfg["client"]["enabled"] == false
        && cfg["client"]["rust_managed"] == false
}

fn profile_row<'a>(doc: &'a Value, id: &str) -> Option<&'a Value> {
    doc["servers"]
        .as_array()?
        .iter()
        .find(|row| row["id"] == id)
}

/// Require a stable native literal draft before issuing new withdrawal.
pub(super) fn validate_draft(doc: &Value, committed: &Plan) -> io::Result<()> {
    if !supports_document(doc, committed)
        || !doc["routing"].is_object()
        || doc["routing_revision"].as_u64() != Some(committed.revision)
    {
        return Err(unsupported());
    }

    let policy = crate::policy::current(doc)?;
    if full_intent(committed) || full_reserve_intent(committed).is_some() {
        return validate_full_draft(doc, policy, committed);
    }
    if !matches!(policy.mode.as_str(), "zones" | "include" | "exclude") || policy.sni_routing {
        return Err(unsupported());
    }
    let reserve = reserve_intent(committed);
    let inherit_connection_chain = reserve.is_some_and(|intent| {
        intent.standby_without_zone(committed).is_some()
            && profile_row(doc, &committed.targets[intent.primary].id).is_some_and(|row| {
                row["config"]["client"]["fallback_tunnel_ids"]
                    .as_array()
                    .is_some_and(|ids| !ids.is_empty())
            })
    });
    let mut literal = BTreeSet::<plan::Prefix>::new();
    for zone in policy.zones.iter().filter(|zone| zone.enabled) {
        if zone.waiting_for_connection
            || zone.direction() != "tunnel"
            || !zone_reserves_match(zone, committed, reserve, inherit_connection_chain)
            || !zone.source_ips.is_empty()
            || !zone.domains.is_empty()
            || zone.ips.is_empty()
        {
            return Err(unsupported());
        }
        for raw in &zone.ips {
            let prefix: plan::Prefix = raw.parse()?;
            if prefix.any()
                || prefix.family() != plan::Family::V4
                || literal.iter().any(|existing| prefix.overlaps(*existing))
            {
                return Err(unsupported());
            }
            literal.insert(prefix);
        }
    }
    let mut compiled = plan::compile_effective(doc, policy, None, true, &[], committed.layout())?;
    compiled.mss.clone_from(&committed.mss);
    if compiled != *committed {
        return Err(unsupported());
    }
    Ok(())
}

fn zone_reserves_match(
    zone: &crate::Zone,
    committed: &Plan,
    reserve: Option<ReserveIntent<'_>>,
    inherit_connection_chain: bool,
) -> bool {
    let Some(intent) =
        reserve.filter(|intent| committed.targets[intent.primary].id == zone.tunnel_id)
    else {
        return zone.fallback_tunnel_ids.is_empty();
    };
    // When the exact primary connection chain supplies the standby demand,
    // the zone can inherit it or repeat it in the same order.
    inherit_connection_chain && zone.fallback_tunnel_ids.is_empty()
        || intent
            .candidates
            .iter()
            .map(|iface| &committed.targets[iface].id)
            .eq(&zone.fallback_tunnel_ids)
}

fn connection_reserves_match(
    client: &Value,
    committed: &Plan,
    standby_parent: Option<ReserveIntent<'_>>,
) -> bool {
    let configured = &client["fallback_tunnel_ids"];
    // A zone-only chain owns the same confirmed selector geometry. Any
    // nonempty connection declaration must still match the whole order.
    configured.is_null()
        || configured.as_array().is_some_and(|ids| {
            ids.is_empty()
                || standby_parent.is_some_and(|intent| {
                    ids.iter().map(Value::as_str).eq(intent
                        .candidates
                        .iter()
                        .map(|iface| Some(committed.targets[iface].id.as_str())))
                })
        })
}

fn supports_document(doc: &Value, committed: &Plan) -> bool {
    if let Some(intent) = full_reserve_intent(committed) {
        return supported_intent(doc, committed)
            && profile_row(doc, &committed.targets[intent.retained()].id)
                .is_some_and(|row| row["config"]["routing"]["active"] != true);
    }
    let Some((intent, standby)) = reserve_intent(committed)
        .and_then(|intent| Some((intent, intent.standby_without_zone(committed)?)))
    else {
        return supported_intent(doc, committed);
    };
    profile_row(doc, &committed.targets[standby].id)
        .is_some_and(|row| row["config"]["client"]["standby"] == true)
        && profile_row(doc, &committed.targets[intent.primary].id).is_some_and(|row| {
            connection_reserves_match(&row["config"]["client"], committed, Some(intent))
        })
}

/// A connection-chain selection alone does not activate saved routing on
/// its standby member. Explicit zone references retain the ordinary stamp.
pub(super) fn connection_only_standby<'a>(doc: &Value, plan: &'a Plan) -> Option<&'a str> {
    if plan
        .reserves
        .first()
        .is_none_or(|(_, candidates)| candidates.len() != 2)
    {
        return None;
    }
    let mut intent = plan.clone();
    intent.selected.clear();
    intent.offline.clear();
    let standby = reserve_intent(&intent)?.standby_without_zone(&intent)?;
    let id = plan.targets.get(standby)?.id.as_str();
    if !supports_document(doc, &intent) {
        return None;
    }
    let explicit_zone = doc["routing_revision"].as_u64() == Some(plan.revision)
        && crate::policy::current(doc).is_ok_and(|policy| {
            policy.zones.iter().any(|zone| {
                !zone.waiting_for_connection
                    && zone.direction() == "tunnel"
                    && zone
                        .fallback_tunnel_ids
                        .iter()
                        .any(|fallback| fallback == id)
            })
        });
    (!explicit_zone).then_some(id)
}

fn validate_full_draft(doc: &Value, policy: crate::Routing, committed: &Plan) -> io::Result<()> {
    if policy.mode != "full" || policy.sni_routing || policy.zones.iter().any(|zone| zone.enabled) {
        return Err(unsupported());
    }
    // An already withdrawn whole server still owns its confirmed exception
    // geometry. Reconstruct its historical configured claim without DNS.
    let mut original = doc.clone();
    let primary = committed
        .prefixes
        .get(&plan::Family::V4.any())
        .ok_or_else(unsupported)?;
    let id = &committed.targets.get(primary).ok_or_else(unsupported)?.id;
    if full_reserve_intent(committed).is_some() {
        // Selecting a reserve in the UI changes the target of client/down,
        // not the logical owner of the already-confirmed blanket.
        original["active_id"] = Value::String(id.clone());
    }
    let permanent = committed.permanent_full_inner(doc).is_some();
    let rows = original["servers"].as_array_mut().ok_or_else(unsupported)?;
    for row in rows {
        if row["id"] == *id {
            row["config"]["enabled"] = true.into();
        } else if permanent {
            continue;
        }
        let cfg = &row["config"];
        if cfg["enabled"] != true {
            continue;
        }
        let effective = if row["applied_config"].is_object() {
            &row["applied_config"]
        } else {
            cfg
        };
        let endpoint = effective["endpoint"].as_str().into_iter();
        let backups = cfg["client"]["endpoint_backups"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str);
        if endpoint
            .chain(backups)
            .map(str::trim)
            .filter(|raw| !raw.is_empty())
            .any(|raw| {
                raw.parse::<std::net::SocketAddr>().is_err()
                    && raw.parse::<std::net::IpAddr>().is_err()
            })
        {
            return Err(unsupported());
        }
    }
    let mut projection =
        plan::compile_effective(&original, policy, None, true, &[], committed.layout())?;
    projection.mss.clone_from(&committed.mss);
    if projection != *committed {
        return Err(unsupported());
    }
    Ok(())
}

fn stable_installation(projected: &Plan, installed: &Plan, iface: &str) -> bool {
    if projected == installed {
        return true;
    }
    if let Some(intent) = full_reserve_intent(projected).filter(|intent| intent.primary == iface) {
        // Retire the logical primary even when the same confirmed reserve
        // already owns both installed defaults. No route is moved or added.
        let mut expected = projected.clone();
        select_reserve(&mut expected, intent.retained());
        return &expected == installed;
    }
    if !full_intent(projected) {
        return false;
    }
    let dest = plan::Family::V6.any();
    if installed.selected.as_slice() != [(plan::Selector { source: dest, dest }, None)]
        || installed.prefixes.get(&dest).map(String::as_str) != Some(iface)
    {
        return false;
    }
    let mut installed = installed.clone();
    installed.selected.clear();
    installed == *projected
}

pub(super) fn project(doc: &Value, committed: &Plan) -> io::Result<Plan> {
    let rows = doc["servers"].as_array().ok_or_else(unsupported)?;
    let mut unavailable = BTreeSet::new();
    let full_reserve = full_reserve_intent(committed);
    let full = full_intent(committed) || full_reserve.is_some();
    let mixed = mixed_intent(committed);
    let reserve = reserve_intent(committed);
    let standby = reserve.and_then(|intent| intent.standby_without_zone(committed));
    for (iface, saved) in &committed.targets {
        let row = rows
            .iter()
            .find(|row| row["id"] == saved.id)
            .ok_or_else(unsupported)?;
        let (cfg, actual_iface, actual_target) = plan::profile(doc, rows, &saved.id)?;
        let client = &cfg["client"];
        let is_standby = standby == Some(iface.as_str());
        let connection_parent = reserve
            .filter(|intent| standby.is_some() && intent.primary == iface)
            .or(full_reserve.filter(|intent| intent.primary == iface));
        let outer = client["double_tunnel_id"].as_str().unwrap_or_default();
        let transport = if client["double_tunnel_mode"] == "permanent" {
            (full_reserve.is_none() && full && committed.killswitch
                || mixed && committed.permanent_fences.contains(iface))
                && !outer.is_empty()
                && outer != saved.id
        } else {
            outer.is_empty()
                && matches!(
                    client["double_tunnel_mode"].as_str(),
                    None | Some("" | "off")
                )
                && !committed.permanent_fences.contains(iface)
        };
        if actual_iface != *iface
            || actual_target != *saved
            || row["applied_config"].is_object()
            || cfg["install"] != "imported"
            || if full {
                cfg["routing"]["mode"] != "full"
            } else {
                !matches!(
                    cfg["routing"]["mode"].as_str(),
                    Some("zones" | "include" | "exclude")
                )
            }
            || cfg["endpoint"]
                .as_str()
                .and_then(|raw| raw.parse().ok())
                .and_then(super::mtu_edit::canonical_socket)
                .is_none()
            || (client["standby"] == true) != is_standby
            || (reserve.is_some() || full_reserve.is_some())
                && (!literal(cfg).is_some_and(|endpoint| endpoint.is_ipv4())
                    || client["endpoint_backups"]
                        .as_array()
                        .is_some_and(|items| !items.is_empty()))
            || !transport
            || !connection_reserves_match(client, committed, connection_parent)
            || nfqws2_awg_profile::routed_mtu_launch_pending(row)
            || nfqws2_awg_profile::pending_routed_mtu(row)?.is_some()
        {
            return Err(unsupported());
        }
        match (
            cfg["enabled"].as_bool(),
            client["enabled"].as_bool(),
            client["rust_managed"].as_bool(),
        ) {
            (Some(true), Some(true), Some(true)) => {
                if reserve.is_some_and(|intent| iface == intent.retained())
                    && cfg["routing"]["active"] != true
                    || full_reserve.is_some_and(|intent| iface == intent.retained())
                        && cfg["routing"]["active"] == true
                {
                    return Err(unsupported());
                }
            }
            (Some(_), Some(false), Some(false)) => {
                if reserve.is_some_and(|intent| iface != intent.departing()) {
                    return Err(unsupported());
                }
                if rows.iter().any(|dependent| {
                    let client = &dependent["config"]["client"];
                    let expected = reserve
                        .filter(|_| is_standby)
                        .or(full_reserve.filter(|intent| iface == intent.retained()));
                    let expected_parent = expected.is_some_and(|intent| {
                        dependent["id"] == committed.targets[intent.primary].id
                    });
                    // Do not drop the saved dependency. Only the already
                    // verified originating connection may refer to this reserve.
                    client["double_tunnel_id"] == saved.id
                        || !expected_parent
                            && client["fallback_tunnel_ids"]
                                .as_array()
                                .is_some_and(|ids| ids.iter().any(|id| id == &saved.id))
                }) {
                    return Err(unsupported());
                }
                unavailable.insert(iface.as_str());
            }
            _ => return Err(unsupported()),
        }
    }

    if full_reserve.is_some_and(|intent| unavailable.contains(intent.primary)) {
        // Disabling the originating implicit blanket withdraws it. The
        // connection reserve has no independent blanket to promote here.
        return Ok(Plan::default());
    }
    let mut installed = committed.clone();
    if full_reserve.is_some_and(|intent| unavailable.contains(intent.retained())) {
        installed.reserves.clear();
        installed.go_multi_v6_reject = None;
    }
    if let Some(intent) = reserve.filter(|intent| unavailable.contains(intent.departing())) {
        if let Some(departing) = intent.selected() {
            for (_, candidates) in &mut installed.reserves {
                candidates.retain(|iface| iface != departing);
            }
        } else {
            for iface in installed
                .prefixes
                .values_mut()
                .filter(|iface| *iface == intent.primary)
            {
                *iface = intent.retained().to_owned();
            }
            installed.reserves.clear();
        }
    }
    installed
        .prefixes
        .retain(|_, iface| !unavailable.contains(iface.as_str()));
    installed
        .targets
        .retain(|iface, _| !unavailable.contains(iface.as_str()));
    installed
        .mss
        .retain(|iface, _| !unavailable.contains(iface.as_str()));
    installed
        .marks
        .retain(|iface, _| !unavailable.contains(iface.as_str()));
    installed
        .permanent_fences
        .retain(|iface| !unavailable.contains(iface.as_str()));
    if installed.prefixes.is_empty() {
        installed = Plan::default();
    }
    installed.validate()?;
    Ok(installed)
}

/// A confirmed receipt already bounds the only prefixes recovery may affect.
/// Do not consult a newer unconfirmed draft when honoring persisted intent.
pub(super) fn recovered(doc: &Value, committed: &Plan) -> io::Result<Option<Plan>> {
    if !supports_document(doc, committed)
        || !committed
            .targets
            .values()
            .any(|target| profile_row(doc, &target.id).is_some_and(|row| disabled(&row["config"])))
    {
        return Ok(None);
    }
    project(doc, committed).map(Some)
}

pub(super) fn withdrawn_go_full_primary<'a>(
    doc: &Value,
    committed: &'a Plan,
    projected: &Plan,
) -> Option<(&'a str, &'a str)> {
    if !committed.go_ipv4
        || doc["routing_revision"].as_u64() != Some(committed.revision)
        || !single_full_intent(projected, true)
    {
        return None;
    }
    let intent = full_reserve_intent(committed)?;
    let retired = &committed.targets.get(intent.retained())?.id;
    let primary = &committed.targets.get(intent.primary)?.id;
    (supports_document(doc, committed)
        && !projected.targets.contains_key(intent.retained())
        && projected.targets.get(intent.primary)?.id == *primary
        && disabled(&profile_row(doc, retired)?["config"]))
    .then_some((primary.as_str(), intent.primary))
}

/// A previously withdrawn selector may wait for its new handshake while
/// unrelated confirmed selectors stay live. Existing ownership is still
/// checked by normal resolution, including every remaining profile.
pub(super) fn rearming(doc: &Value, intended: &Plan, previous: &Plan) -> bool {
    if !plain_intent(intended) || previous == intended {
        return false;
    }
    let mut prior = previous.clone();
    if prior.selected.iter().any(|(_, choice)| choice.is_some()) {
        return false;
    }
    prior.selected.clear();
    prior.offline.clear();
    if !prior.empty()
        && (!plain_intent(&prior)
            || prior.revision != intended.revision
            || prior
                .prefixes
                .iter()
                .any(|(prefix, iface)| intended.prefixes.get(prefix) != Some(iface))
            || prior
                .targets
                .iter()
                .any(|(iface, target)| intended.targets.get(iface) != Some(target)))
    {
        return false;
    }
    project(doc, intended).is_ok_and(|projected| projected == *intended)
}

/// One exact saved profile no longer owns a payload selector. Keep its
/// address in collision checks, but do not require its dormant plain path
/// when no independently configured or sampled live peer claims the IP.
pub(super) fn withdrawn_mixed<'a>(
    doc: &'a Value,
    committed: &'a Plan,
    projected: &Plan,
) -> Option<(&'a str, std::net::SocketAddr)> {
    if !mixed_intent(committed) {
        return None;
    }
    committed.targets.iter().find_map(|(iface, target)| {
        if projected.targets.contains_key(iface) {
            return None;
        }
        let row = withdrawn_row(doc, &target.id)?;
        Some((&*target.id, literal(&row["config"])?))
    })
}

fn withdrawn_row<'a>(doc: &'a Value, id: &str) -> Option<&'a Value> {
    let row = profile_row(doc, id)?;
    (disabled(&row["config"])
        && doc["rust_static_routing"]["committed_targets"]
            .as_array()
            .is_some_and(|ids| ids.contains(&row["id"]))
        && doc["rust_static_routing"]["targets"]
            .as_array()
            .is_some_and(|ids| ids.iter().all(|id| id != &row["id"])))
    .then_some(row)
}

fn literal(cfg: &Value) -> Option<std::net::SocketAddr> {
    super::mtu_edit::canonical_socket(cfg["endpoint"].as_str()?.parse().ok()?)
}

pub(super) fn track_withdrawn_socket(k: &mut super::Kernel<'_>, doc: &Value, committed: &Plan) {
    if !mixed_intent(committed) {
        return;
    }
    let iface = committed.permanent_fences.first().unwrap();
    let Some(target) = committed.targets.get(iface) else {
        return;
    };
    let Some(row) = withdrawn_row(doc, &target.id) else {
        return;
    };
    if row["config"]["client"]["double_tunnel_mode"] != "permanent" {
        return;
    }
    // An unproved or partially replaced pair remains foreign to the writer.
    if let Ok((mark, table)) = nfqws2_awg_profile::nested_socket_selector(iface) {
        if nfqws2_awg_profile::owns_withdrawn_permanent_socket(doc, &target.id, iface, k.deadline) {
            k.nested_sockets.insert(mark, table);
        }
    }
}

pub fn routed_profile_is_disabled(db: &Store, id: Option<&str>) -> io::Result<bool> {
    routed_profile_rearm(db, id, false)
}

pub fn routed_profile_needs_rearm(db: &Store, id: Option<&str>) -> io::Result<bool> {
    routed_profile_rearm(db, id, true)
}

fn routed_profile_rearm(db: &Store, id: Option<&str>, include_enabled: bool) -> io::Result<bool> {
    let doc = nfqws2_awg_profile::read(db)?;
    let profile = match id {
        Some(id) => profile_row(&doc, id),
        None => crate::model::selected_profile(&doc),
    };
    let Some((profile, id)) = profile.and_then(|row| row["id"].as_str().map(|id| (row, id))) else {
        return Ok(false);
    };
    let ordinarily_disabled = disabled(&profile["config"]);
    if !ordinarily_disabled
        && !doc["rust_static_routing"][super::active_replacement::DISABLED_REPLACEMENTS].is_array()
    {
        return Ok(false);
    }
    let journal = Journal::read(db)?;
    if super::active_replacement::marked_rearm(&doc, &journal, id, include_enabled)? {
        return Ok(true);
    }
    Ok(ordinarily_disabled
        && journal.expires == 0
        && doc["rust_static_routing"]["committed_targets"]
            .as_array()
            .is_some_and(|targets| targets.contains(&profile["id"]))
        && supports_document(&doc, &journal.committed)
        && journal
            .committed
            .targets
            .values()
            .any(|target| profile["id"] == target.id))
}
type PermanentObserver<'a> = dyn Fn(&str) -> io::Result<RoutedPermanentHold> + 'a;

type DirectObserver<'a> = dyn Fn(&str) -> io::Result<ActiveReplacementPeer> + 'a;
type OutageObserver<'a> = dyn Fn(&str) -> io::Result<RoutedDirectOutage> + 'a;

struct Withdrawal<'a> {
    iface: &'a str,
    id: &'a str,
    owner: Option<&'a NativeRemovalSeal>,
    verify_owner: &'a dyn Fn() -> io::Result<()>,
    retain_permanent: &'a PermanentObserver<'a>,
    retain_direct: &'a DirectObserver<'a>,
    direct_outage: &'a OutageObserver<'a>,
    wan: &'a [String],
}

/// Publish exact native disablement only after the expected FIB withdrawal.
pub fn disable_routed_profile(
    db: &Store,
    run: &dyn Runner,
    request: RoutedDisable<'_>,
    wan: &[String],
) -> io::Result<()> {
    withdraw(
        db,
        run,
        Withdrawal {
            iface: request.iface(),
            id: request.id(),
            owner: request.owner(),
            verify_owner: &|| request.verify_owner(),
            retain_permanent: &|id| request.retain_permanent(id),
            retain_direct: &|id| request.retain_direct(id),
            direct_outage: &|id| request.confirm_direct_outage(id),
            wan,
        },
        |doc| request.prepare(doc),
    )
}

fn tracked_ids(plan: &Plan) -> BTreeSet<&str> {
    plan.targets.values().map(|t| t.id.as_str()).collect()
}

fn check_owner_stamp(doc: &Value, j: &Journal) -> io::Result<()> {
    let stamp = &doc["rust_static_routing"];
    if stamp["boot"] != j.boot
        || stamp["pending_commit"] != false
        || stamp["go_trial"] == true
        || stamp["legacy_watchdog"] == true
        || stamp["revision"] != j.installed.revision
        || stamp["committed_revision"] != j.committed.revision
        || stamp["targets"] != serde_json::json!(tracked_ids(&j.installed))
        || stamp["committed_targets"] != serde_json::json!(tracked_ids(&j.committed))
        || super::legacy_active(doc)
    {
        return Err(unsupported());
    }
    Ok(())
}

/// An existing plain IPv4 lookup can stay active during route replacement,
/// addition or withdrawal if the other RPDB ownership is unchanged.
pub(super) fn plain_lookup_route_keys(
    from: &BTreeSet<super::Object>,
    to: &BTreeSet<super::Object>,
) -> Option<(BTreeSet<plan::Prefix>, BTreeSet<plan::Prefix>)> {
    use super::Object::*;
    let lookup = Rule(plan::Family::V4);
    let ordinary = from.contains(&lookup) && to.contains(&lookup);
    let guarded = [from, to].into_iter().all(|objects| {
        objects.contains(&PackedLookup(plan::Family::V4))
            && objects.contains(&FullGuard(super::full::Guard::Main(plan::Family::V4)))
    });
    if !(ordinary || guarded)
        || !from
            .difference(to)
            .chain(to.difference(from))
            .all(|object| match object {
                Firewall(selector, ..) | Stop(selector, ..) => {
                    selector.dest.family() == plan::Family::V4
                }
                Route(prefix, _, 17842) => prefix.family() == plan::Family::V4,
                LegacyV6Reject(_) => guarded && from.contains(object) && !to.contains(object),
                _ => false,
            })
    {
        return None;
    }
    let keys = |objects: &BTreeSet<super::Object>| {
        objects
            .iter()
            .filter_map(|object| match object {
                Route(prefix, _, 17842) => Some(*prefix),
                _ => None,
            })
            .collect::<BTreeSet<_>>()
    };
    let prior = keys(from);
    let next = keys(to);
    // New route sets with a replacement prefix (such as a DNS answer change)
    // use the ordinary writer's existing publication and rollback ordering.
    let retargeted = to
        .difference(from)
        .any(|object| matches!(object, Route(prefix, _, 17842) if prior.contains(prefix)));
    let unchanged_blanket =
        guarded && prior == BTreeSet::from([plan::Family::V4.any()]) && next == prior && retargeted;
    (unchanged_blanket || ordinary && (prior == next || retargeted)).then_some((prior, next))
}

fn withdrawal_only(before: &BTreeSet<super::Object>, after: &BTreeSet<super::Object>) -> bool {
    after.difference(before).all(|object| {
        let super::Object::Classifier(family, groups) = object else {
            return false;
        };
        before.iter().any(|existing| {
            matches!(existing, super::Object::Classifier(previous, saved)
                if family == previous && groups.iter().all(|group| saved.binary_search(group).is_ok()))
        })
    })
}

fn outage_matches(outage: &RoutedDirectOutage, old: &Journal, primary: &str, cfg: &Value) -> bool {
    let target = &old.committed.targets[primary];
    outage.owner.valid()
        && outage.owner.boot == old.boot
        && outage.owner.id == target.id
        && outage.owner.iface == primary
        && outage.owner.nested.is_none()
        && literal(cfg) == Some(outage.endpoint)
        && outage.mtu == target.mtu
        && matches!(
            outage.socket_mark,
            0 | nfqws2_awg_profile::DIRECT_SOCKET_MARK
        )
}

fn distinct_owner(before: &NativeRemovalSeal, next: &NativeRemovalSeal) -> bool {
    before.pid != next.pid && before.receipt_sha256 != next.receipt_sha256
}

fn verify_reserve(
    k: &super::Kernel<'_>,
    doc: &Value,
    old: &Journal,
    request: &Withdrawal<'_>,
    projection: &Plan,
    holder: &str,
    proof: &ActiveReplacementPeer,
) -> io::Result<()> {
    let target = old.committed.targets.get(holder).ok_or_else(unsupported)?;
    if !proof.owner.valid()
        || proof.owner.boot != old.boot
        || proof.owner.iface != holder
        || proof.owner.id != target.id
        || proof.owner.nested.is_some()
        || proof.underlay.is_some()
        || proof.nested_only
        || request
            .owner
            .is_some_and(|prior| !distinct_owner(prior, &proof.owner))
    {
        return Err(unsupported());
    }
    super::active_replacement::verify_peer(doc, proof, projection)?;
    super::mtu_edit::replacement_wan(k, proof.endpoint, proof.socket_mark, request.wan)
}

fn verify_go_full_primary(
    k: &super::Kernel<'_>,
    doc: &Value,
    committed: &Plan,
    primary: &str,
    proof: &ActiveReplacementPeer,
    wan: &[String],
) -> io::Result<()> {
    let target = committed.targets.get(primary).ok_or_else(unsupported)?;
    let (iface, endpoint, fingerprint) =
        nfqws2_awg_profile::active_replacement_underlay_identity(doc, &target.id)?;
    let grants = proof
        .allowed
        .iter()
        .map(|grant| grant.parse::<plan::Prefix>())
        .collect::<io::Result<BTreeSet<_>>>()?;
    if !proof.owner.valid()
        || proof.owner.boot != boot_id(k)?
        || proof.owner.iface != primary
        || proof.owner.id != target.id
        || proof.owner.nested.is_some()
        || proof.underlay.is_some()
        || proof.nested_only
        || iface != primary
        || proof.endpoint != endpoint
        || proof.fingerprint != fingerprint
        || proof.mtu != target.mtu
        || !committed
            .full_endpoints
            .as_ref()
            .is_some_and(|endpoints| endpoints.contains(&proof.endpoint.ip()))
        || !grants.contains(&plan::Family::V4.any())
    {
        return Err(unsupported());
    }
    super::mtu_edit::replacement_wan(k, proof.endpoint, proof.socket_mark, wan)
}

pub(super) fn recovered_go_full_peer(
    k: &super::Kernel<'_>,
    doc: &Value,
    committed: &Plan,
    primary: &str,
    proof: &ActiveReplacementPeer,
    wan: &[String],
) -> io::Result<plan::LivePeer> {
    super::handoff::implicit_multi::verify_ipv6(k)?;
    if !primary_present(k, primary)? {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    verify_go_full_primary(k, doc, committed, primary, proof, wan)?;
    plan::LivePeer::from_uapi(
        std::path::Path::new("/"),
        primary,
        proof.endpoint,
        proof.allowed.clone(),
        proof.socket_mark,
        false,
    )
}

fn install_go_full_primary(plan: &mut Plan, proof: &ActiveReplacementPeer) -> io::Result<()> {
    let ceiling = proof
        .mtu
        .checked_sub(40)
        .filter(|ceiling| (536..=8960).contains(ceiling))
        .ok_or_else(unsupported)?;
    plan.selected.clear();
    plan.mss.clear();
    plan.mss.insert(proof.owner.iface.clone(), ceiling);
    plan.validate()
}

fn verify_preserved(
    k: &super::Kernel<'_>,
    doc: &Value,
    old: &Journal,
    retiring: &Withdrawal<'_>,
    proof: &RoutedPermanentHold,
) -> io::Result<()> {
    let iface = old
        .committed
        .permanent_fences
        .first()
        .ok_or_else(unsupported)?;
    let target = old.installed.targets.get(iface).ok_or_else(unsupported)?;
    let (outer_id, outer_iface) =
        nfqws2_awg_profile::routed_permanent_disable_outer(doc, &target.id)?
            .ok_or_else(unsupported)?;
    let outer = profile_row(doc, outer_id).ok_or_else(unsupported)?;
    let inner = profile_row(doc, &target.id).ok_or_else(unsupported)?;
    let Some(scope) = &proof.owner.nested else {
        return Err(unsupported());
    };
    if !proof.owner.valid()
        || !proof.outer_owner.valid()
        || proof.owner.boot != old.boot
        || proof.outer_owner.boot != old.boot
        || proof.owner.id != target.id
        || &proof.owner.iface != iface
        || proof.outer_owner.id != outer_id
        || proof.outer_owner.iface != outer_iface
        || proof.outer_owner.nested.is_some()
        || scope.outer_iface != outer_iface
        || retiring.id == outer_id
        || retiring.iface == outer_iface
        || proof.outer_owner.pid == proof.owner.pid
        || proof.outer_owner.receipt_sha256 == proof.owner.receipt_sha256
        || retiring.owner.is_some_and(|owner| {
            [proof.owner.pid, proof.outer_owner.pid].contains(&owner.pid)
                || [proof.owner.receipt_sha256, proof.outer_owner.receipt_sha256]
                    .contains(&owner.receipt_sha256)
        })
        || literal(&inner["config"]) != Some(proof.endpoint)
        || literal(&outer["config"]) != Some(proof.outer_endpoint)
        || scope.endpoint != proof.endpoint.ip()
        || !(576..=target.mtu).contains(&proof.effective_mtu)
        || old.installed.mss.get(iface).copied() != Some(proof.effective_mtu - 40)
    {
        return Err(unsupported());
    }
    plan::verify_nested_socket_path(k, iface, &outer_iface, scope.endpoint, Some(scope.source))
}

fn waive_only_preserved_primary(
    k: &super::Kernel<'_>,
    doc: &Value,
    claims: &super::transport_claims::Claims,
    retiring: &Withdrawal<'_>,
    proof: &RoutedPermanentHold,
) -> io::Result<bool> {
    if proof.endpoint.ip() == proof.outer_endpoint.ip()
        || !claims.sole_primary(&proof.owner.id, proof.endpoint)
        || doc["servers"]
            .as_array()
            .ok_or_else(unsupported)?
            .iter()
            .any(|row| {
                ![retiring.id, &proof.owner.id, &proof.outer_owner.id]
                    .iter()
                    .any(|id| row["id"] == *id)
                    && row["config"]["enabled"] == true
                    && [&row["config"], &row["applied_config"]]
                        .into_iter()
                        .any(|cfg| {
                            cfg["endpoint"]
                                .as_str()
                                .is_some_and(|endpoint| !endpoint.is_empty())
                                || cfg["client"]["endpoint_backups"]
                                    .as_array()
                                    .is_some_and(|a| !a.is_empty())
                                || cfg["client"]["enabled"] == true
                        })
            })
    {
        return Ok(false);
    }
    // The other live tuple has an independent physical WAN. Neither a
    // shared IP nor a fourth unobserved transport can inherit this waiver.
    super::nested_endpoint::require_independent_wan(k, proof.outer_endpoint.ip())?;
    Ok(true)
}

fn park_full(plan: &mut Plan) -> io::Result<()> {
    plan.selected = plan.flows().map(|(selector, _)| (selector, None)).collect();
    plan.mss.clear();
    plan.validate()
}

pub(super) fn link_names(k: &super::Kernel<'_>) -> io::Result<BTreeSet<String>> {
    let links = k.call("ip", &["-o", "link", "show"])?;
    let mut names = BTreeSet::new();
    for line in links.lines() {
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "не удалось проверить список интерфейсов",
            )
        };
        let (index, record) = line.split_once(": ").ok_or_else(invalid)?;
        let (link, _) = record.split_once(": ").ok_or_else(invalid)?;
        let name = link
            .split('@')
            .next()
            .filter(|name| !name.is_empty())
            .ok_or_else(invalid)?;
        if !index.parse::<u32>().is_ok_and(|index| index > 0) {
            return Err(invalid());
        }
        if !names.insert(name.to_owned()) {
            return Err(invalid());
        }
    }
    if names.contains("lo") {
        Ok(names)
    } else {
        Err(io::ErrorKind::InvalidData.into())
    }
}

fn primary_present(k: &super::Kernel<'_>, iface: &str) -> io::Result<bool> {
    Ok(link_names(k)?.contains(iface))
}

fn verify_primary_absent(k: &super::Kernel<'_>, iface: &str) -> io::Result<()> {
    if primary_present(k, iface)? {
        Err(io::ErrorKind::WouldBlock.into())
    } else {
        Ok(())
    }
}

fn withdraw(
    db: &Store,
    run: &dyn Runner,
    request: Withdrawal<'_>,
    prepare: impl FnOnce(&mut Value) -> io::Result<()>,
) -> io::Result<()> {
    db.transaction(|tx| {
        let old = Journal::read(db)?;
        let before = nfqws2_awg_profile::read(db)?;
        let row = profile_row(&before, request.id).ok_or_else(unsupported)?;
        if old.expires != 0
            || !old.preparing.is_empty()
            || !old
                .committed
                .targets
                .get(request.iface)
                .is_some_and(|t| t.id == request.id)
            || super::profile_rebind::pending(&before)
            || super::active_replacement::active_replacement_in_progress(db)?
            || super::mtu_edit::pending_mtu_edit(db)?
            || super::mtu_edit::saved_profile(&before, &old)?.is_some()
        {
            return Err(unsupported());
        }
        check_owner_stamp(&before, &old)?;
        validate_draft(&before, &old.committed)?;
        let absent = disabled(&row["config"]);
        let intent = reserve_intent(&old.committed);
        let retiring_full_reserve =
            full_reserve_intent(&old.committed).filter(|intent| intent.retained() == request.iface);
        let go_full = old.committed.go_ipv4;
        if go_full && retiring_full_reserve.is_none() {
            return Err(unsupported());
        }
        let go_primary = if let Some(intent) = retiring_full_reserve.filter(|_| go_full) {
            if primary_present(&super::kernel(run), intent.primary)? {
                Some((request.retain_direct)(
                    &old.committed.targets[intent.primary].id,
                )?)
            } else {
                None
            }
        } else {
            None
        };
        if intent.is_some_and(|intent| intent.departing() != request.iface) {
            return Err(unsupported());
        }
        let selected = intent.filter(|intent| intent.selected().is_some());
        let mut prior = project(&before, &old.committed)?;
        if let Some(intent) = retiring_full_reserve {
            let primary = &old.committed.targets[intent.primary].id;
            if !prior.targets.contains_key(intent.primary)
                || profile_row(&before, primary)
                    .is_none_or(|row| row["config"]["routing"]["active"] != true)
            {
                return Err(unsupported());
            }
            if absent {
                if let Some(proof) = &go_primary {
                    install_go_full_primary(&mut prior, proof)?;
                } else {
                    park_full(&mut prior)?;
                }
            } else {
                select_reserve(&mut prior, intent.retained());
            }
        }
        if let Some(intent) = selected {
            select_reserve(
                &mut prior,
                if absent {
                    intent.retained()
                } else {
                    intent.departing()
                },
            );
        }
        if !stable_installation(&prior, &old.installed, request.iface) {
            return Err(unsupported());
        }
        let mixed = mixed_intent(&old.committed);
        let reserve = intent.map(ReserveIntent::retained);
        let keeping_permanent = if mixed && !old.committed.permanent_fences.contains(request.iface)
        {
            let iface = old
                .committed
                .permanent_fences
                .first()
                .ok_or_else(unsupported)?;
            let target = old.installed.targets.get(iface).ok_or_else(unsupported)?;
            Some(target.id.as_str())
        } else {
            None
        };
        let scope = if let Some(owner) = request.owner {
            if !owner.valid()
                || owner.boot != old.boot
                || owner.id != request.id
                || owner.iface != request.iface
            {
                return Err(unsupported());
            }
            let expected = nfqws2_awg_profile::routed_permanent_disable_outer(&before, request.id)?;
            match (expected, owner.nested.as_ref()) {
                (None, None) => None,
                (Some((_, outer)), Some(scope)) if mixed || full_intent(&old.committed) => {
                    let endpoint = row["config"]["endpoint"]
                        .as_str()
                        .and_then(|raw| raw.parse().ok())
                        .and_then(super::mtu_edit::canonical_socket)
                        .ok_or_else(unsupported)?;
                    if scope.outer_iface != outer || scope.endpoint != endpoint.ip() {
                        return Err(unsupported());
                    }
                    Some(scope)
                }
                _ => return Err(unsupported()),
            }
        } else if absent {
            None
        } else {
            return Err(unsupported());
        };
        let mut after = before.clone();
        prepare(&mut after)?;
        let mut reduced = project(&after, &old.committed)?;
        if retiring_full_reserve.is_some() {
            if let Some(proof) = &go_primary {
                install_go_full_primary(&mut reduced, proof)?;
            } else {
                park_full(&mut reduced)?;
            }
        }
        if let Some(intent) = selected {
            select_reserve(&mut reduced, intent.retained());
            reduced.validate()?;
        }
        let previous_objects = objects(&old.installed);
        let expected_objects = objects(&reduced);
        if reduced.targets.contains_key(request.iface)
            || if go_primary.is_some() {
                previous_objects != expected_objects
                    && plain_lookup_route_keys(&previous_objects, &expected_objects).is_none()
            } else if retiring_full_reserve.is_some() {
                // Native full already fences unavailable IPv6, including
                // when the operator left the general Kill Switch off.
                expected_objects
                    .difference(&previous_objects)
                    .any(|object| {
                        object
                            != &super::Object::FullGuard(super::full::Guard::Fence(
                                plan::Family::V6,
                            ))
                    })
            } else if reserve.is_some() {
                // Every selector and the sole reserve come from the exact
                // stable committed plan. Only same-table routes may change.
                previous_objects != expected_objects
                    && plain_lookup_route_keys(&previous_objects, &expected_objects).is_none()
            } else if mixed {
                !withdrawal_only(&previous_objects, &expected_objects)
            } else {
                !expected_objects.is_subset(&previous_objects)
            }
        {
            return Err(unsupported());
        }
        let reserve_proof = reserve
            .map(|iface| (request.retain_direct)(&old.committed.targets[iface].id))
            .transpose()?;
        let outage = selected
            .map(|intent| {
                let id = &old.committed.targets[intent.primary].id;
                let down = (request.direct_outage)(id)?;
                let cfg = &profile_row(&before, id).ok_or_else(unsupported)?["config"];
                if !outage_matches(&down, &old, intent.primary, cfg)
                    || request
                        .owner
                        .is_some_and(|retiring| !distinct_owner(retiring, &down.owner))
                    || reserve_proof
                        .as_ref()
                        .is_none_or(|retained| !distinct_owner(&retained.owner, &down.owner))
                {
                    return Err(unsupported());
                }
                Ok(down)
            })
            .transpose()?;
        let mut new = old.clone();
        new.installed = reduced.into();
        if retiring_full_reserve.is_some() && go_full && new.committed.go_multi_v6_reject.is_some() {
            // Go clears the leftover FORWARD rejection on retirement. Keep
            // that release through recovery until the next explicit Apply.
            let mut committed = new.committed.as_ref().clone();
            committed.go_multi_v6_reject = None;
            new.committed = committed.into();
        }
        let mut after_routes_only = before.clone();
        stamp_document(&mut after_routes_only, &new)?;
        stamp_document(&mut after, &new)?;

        let k = kernel_for_transition(run, db, &old, &new.installed)?;
        if boot_id(&k)? != old.boot
            || k.inventory_for(
                &old.claims(),
                &expected_objects,
                !expected_objects.is_empty(),
            )? != previous_objects
        {
            return Err(err("состав подтверждённых маршрутов изменился"));
        }
        let mut current_backend = old.installed.as_ref().clone();
        k.select_firewall(&mut current_backend)?;
        if current_backend.firewall != old.installed.firewall {
            return Err(unsupported());
        }
        k.verify_forward(&old.installed)?;
        let retained = keeping_permanent
            .map(request.retain_permanent)
            .transpose()?;
        if let Some(proof) = &retained {
            verify_preserved(&k, &before, &old, &request, proof)?;
        }
        if !new.installed.empty() {
            let claims =
                super::transport_claims::Claims::read(&before, &new.installed, false, None)?;
            let mut endpoints = claims.addresses();
            let conflicts = if retiring_full_reserve.is_some() {
                new.installed
                    .full_endpoints
                    .as_ref()
                    .is_none_or(|exceptions| !endpoints.is_subset(exceptions))
            } else {
                endpoints
                    .iter()
                    .any(|ip| new.installed.overlaps_destination(plan::Prefix::host(*ip)))
            };
            if conflicts {
                return Err(err("политика перехватывает транспортный адрес VPN"));
            }
            if let Some(proof) = &retained {
                if waive_only_preserved_primary(&k, &before, &claims, &request, proof)? {
                    endpoints.remove(&proof.endpoint.ip());
                }
            }
            k.guard(&new.installed, &endpoints)?;
        }
        let verify_reserve_now = || {
            if let Some((holder, original)) = reserve.zip(reserve_proof.as_ref()) {
                let live = (request.retain_direct)(&original.owner.id)?;
                if live != *original {
                    return Err(unsupported());
                }
                verify_reserve(&k, &before, &old, &request, &new.installed, holder, &live)?;
            }
            Ok(())
        };
        let verify_owner = || {
            (request.verify_owner)()?;
            verify_reserve_now()?;
            if let Some(saved) = &outage {
                if (request.direct_outage)(&saved.owner.id)? != *saved {
                    return Err(unsupported());
                }
                super::mtu_edit::replacement_wan(
                    &k,
                    saved.endpoint,
                    saved.socket_mark,
                    request.wan,
                )?;
            }
            if let Some(proof) = &retained {
                if (request.retain_permanent)(&proof.owner.id)? != *proof {
                    return Err(unsupported());
                }
                verify_preserved(&k, &before, &old, &request, proof)?;
            }
            if let Some(scope) = scope {
                plan::verify_nested_socket_path(
                    &k,
                    request.iface,
                    &scope.outer_iface,
                    scope.endpoint,
                    Some(scope.source),
                )?;
            }
            Ok(())
        };
        let verify_full_primary = |reject: Option<&str>| {
            let Some(intent) = retiring_full_reserve else {
                return Ok(());
            };
            if go_full {
                super::handoff::implicit_multi::verify_ipv6_with_owned_reject(&k, reject)?;
            }
            if let Some(saved) = &go_primary {
                let live = (request.retain_direct)(&saved.owner.id)?;
                if live != *saved
                    || !primary_present(&k, intent.primary)?
                    || request
                        .owner
                        .is_some_and(|old| !distinct_owner(old, &live.owner))
                {
                    return Err(unsupported());
                }
                verify_go_full_primary(
                    &k,
                    &before,
                    &old.committed,
                    intent.primary,
                    &live,
                    request.wan,
                )
            } else {
                verify_primary_absent(&k, intent.primary)
            }
        };
        verify_owner()?;
        verify_full_primary(old.installed.go_multi_v6_reject.as_deref())?;
        let result = (|| {
            transition(db, tx, run, &old, &new, None)?;
            verify_owner()?;
            verify_full_primary(new.installed.go_multi_v6_reject.as_deref())?;
            nfqws2_awg_profile::edit_document_locked(tx, |current| {
                if *current != after_routes_only {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                *current = after;
                Ok(())
            })
        })();
        if let Err(error) = result {
            compensate_publication(db, tx, run, &old, &new, &after_routes_only, || {
                let mut prior = old.clone();
                if let Some(holder) = reserve {
                    let primary_missing = (request.verify_owner)().is_err();
                    let reserve_missing = verify_reserve_now().is_err();
                    let parked = old
                        .installed
                        .flows()
                        .filter_map(|(selector, iface)| {
                            (iface == request.iface && primary_missing
                                || iface == holder && reserve_missing)
                                .then_some(selector)
                        })
                        .collect::<Vec<_>>();
                    prior.installed.park(&parked);
                } else if go_full {
                    // Flags are still enabled. Restore only the directly
                    // verified former carrier, or leave the blanket parked.
                    if (request.verify_owner)().is_err() {
                        park_full(&mut prior.installed)?;
                    }
                } else {
                    verify_owner()?;
                }
                Ok(prior)
            })?;
            return Err(error);
        }
        Ok(())
    })
}

// Route publication belongs to an earlier writer step. Restore it only when
// the disabled flags did not land. A lost authorized reserve is parked
// while restoring any prior selector whose owner still authenticates.
fn compensate_publication(
    db: &Store,
    tx: &Transaction<'_>,
    run: &dyn Runner,
    old: &Journal,
    new: &Journal,
    after_routes_only: &Value,
    prior: impl FnOnce() -> io::Result<Journal>,
) -> io::Result<()> {
    if old == new
        || Journal::read(db)? != *new
        || nfqws2_awg_profile::read(db)? != *after_routes_only
    {
        return Ok(());
    }
    if let Ok(prior) = prior() {
        transition(db, tx, run, new, &prior, None)?;
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn withdraw_fixture(
    db: &Store,
    run: &dyn Runner,
    seal: Option<&NativeRemovalSeal>,
    verify_owner: &dyn Fn() -> io::Result<()>,
    prepare: impl FnOnce(&mut Value) -> io::Result<()>,
) -> io::Result<()> {
    let doc = nfqws2_awg_profile::read(db)?;
    let id = doc["servers"][0]["id"].as_str().ok_or_else(unsupported)?;
    withdraw(
        db,
        run,
        Withdrawal {
            iface: "awg0",
            id,
            owner: seal,
            verify_owner,
            retain_permanent: &|_| Err(unsupported()),
            retain_direct: &|_| Err(unsupported()),
            direct_outage: &|_| Err(unsupported()),
            wan: &[],
        },
        prepare,
    )
}

#[cfg(test)]
pub(super) fn withdraw_mixed_direct_fixture(
    db: &Store,
    run: &dyn Runner,
    seal: &NativeRemovalSeal,
    retain_permanent: &PermanentObserver<'_>,
    prepare: impl FnOnce(&mut Value) -> io::Result<()>,
) -> io::Result<()> {
    withdraw(
        db,
        run,
        Withdrawal {
            iface: "awg1",
            id: "direct",
            owner: Some(seal),
            verify_owner: &|| Ok(()),
            retain_permanent,
            retain_direct: &|_| Err(unsupported()),
            direct_outage: &|_| Err(unsupported()),
            wan: &[],
        },
        prepare,
    )
}

#[cfg(test)]
pub(super) fn withdraw_direct_reserve_fixture(
    db: &Store,
    run: &dyn Runner,
    seal: &NativeRemovalSeal,
    retain_direct: &DirectObserver<'_>,
    prepare: impl FnOnce(&mut Value) -> io::Result<()>,
) -> io::Result<()> {
    withdraw(
        db,
        run,
        Withdrawal {
            iface: &seal.iface,
            id: &seal.id,
            owner: Some(seal),
            verify_owner: &|| Ok(()),
            retain_permanent: &|_| Err(unsupported()),
            retain_direct,
            direct_outage: &|_| Err(unsupported()),
            wan: &["wan0".into()],
        },
        prepare,
    )
}

#[cfg(test)]
pub(super) fn withdraw_selected_reserve_fixture(
    db: &Store,
    run: &dyn Runner,
    seal: &NativeRemovalSeal,
    retain_direct: &DirectObserver<'_>,
    direct_outage: &OutageObserver<'_>,
    prepare: impl FnOnce(&mut Value) -> io::Result<()>,
) -> io::Result<()> {
    withdraw(
        db,
        run,
        Withdrawal {
            iface: &seal.iface,
            id: &seal.id,
            owner: Some(seal),
            verify_owner: &|| Ok(()),
            retain_permanent: &|_| Err(unsupported()),
            retain_direct,
            direct_outage,
            wan: &["wan0".into()],
        },
        prepare,
    )
}
