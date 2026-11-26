use super::{
    boot_id, err, handoff, io, kernel, objects, plan, profile_rebind, Journal, LivePeer, Plan,
    Runner, Store, Transaction, RECEIPT, RECEIPT_LIMIT,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub(super) const FIELD: &str = "failover_reorder";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reorder {
    boot: String,
    before: u64,
    after: u64,
    prior_plan: String,
    next_plan: String,
    settings: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prior_intent: Option<String>,
    reserves: Vec<(plan::Selector, Vec<String>)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    targets: Option<BTreeMap<String, plan::Target>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    marks: Option<BTreeMap<String, u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mss: Option<BTreeMap<String, u16>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    route_update: Option<bool>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LiveEdit {
    Preserve,
    OptionalTransport,
    SetStandby(bool),
}

fn unavailable() -> io::Error {
    err("для изменения резервов требуется подтверждённая политика AWG")
}

fn committed_matches_installation(j: &Journal) -> bool {
    let mut intent = j.installed.clone();
    intent.selected.clear();
    intent == j.committed
}

fn intent_digest(plan: &Plan) -> io::Result<String> {
    let mut intent = plan.clone();
    intent.selected.clear();
    intent.mss.clear();
    profile_rebind::digest(&intent)
}

fn plan_at_current_settings(
    db: &Store,
    doc: &Value,
    journal: &Journal,
    k: &super::Kernel<'_>,
    peer: &mut impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<Plan> {
    let intent = plan::compile_effective(
        doc,
        crate::sources::current(db, doc)?,
        None,
        true,
        &[],
        journal.committed.layout(),
    )?;
    prove_plan(doc, intent, journal, k, peer)
}

fn prove_plan(
    doc: &Value,
    intent: Plan,
    journal: &Journal,
    k: &super::Kernel<'_>,
    peer: &mut impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<Plan> {
    let mut selected = plan::resolve_on(
        doc,
        intent,
        true,
        Some(journal.installed.as_ref()),
        Some(plan::Verification::Read(k)),
        peer,
    )?;
    k.select_firewall(&mut selected.plan)?;
    k.guard(&selected.plan, &selected.endpoints)?;
    Ok(selected.plan)
}

fn verify_failover_edit(
    before: &Value,
    after: &Value,
    id: &str,
    revision: u64,
) -> io::Result<LiveEdit> {
    let mut expected = before.clone();
    let old = expected["servers"]
        .as_array_mut()
        .and_then(|rows| rows.iter_mut().find(|r| r["id"] == id));
    let new = after["servers"]
        .as_array()
        .and_then(|rows| rows.iter().find(|r| r["id"] == id));
    let (Some(old), Some(new)) = (old, new) else {
        return Err(unavailable());
    };
    let mut change_transport = false;
    let mut standby = None;
    for origin in ["config", "applied_config"] {
        if old[origin].is_object() {
            let proposed = &new[origin]["client"]["fallback_tunnel_ids"];
            if !proposed.is_array() {
                return Err(unavailable());
            }
            let current = &mut old[origin]["client"];
            let client = &new[origin]["client"];
            if current["standby"] != client["standby"] {
                let requested = client["standby"].as_bool().ok_or_else(unavailable)?;
                if standby.is_some_and(|value| value != requested) {
                    return Err(unavailable());
                }
                current["standby"] = json!(requested);
                standby = Some(requested);
            }
            let transport_changed = current["double_tunnel_id"] != client["double_tunnel_id"]
                || current["double_tunnel_mode"] != client["double_tunnel_mode"];
            if transport_changed {
                let optional = |value: &Value| {
                    matches!(
                        value.as_str().unwrap_or_default(),
                        "" | "off" | "automatic" | "preferred" | "last_resort"
                    )
                };
                if current["standby"] == true
                    || !optional(&current["double_tunnel_mode"])
                    || !optional(&client["double_tunnel_mode"])
                    || !client["double_tunnel_id"].is_string()
                    || !client["double_tunnel_mode"].is_string()
                {
                    return Err(unavailable());
                }
                current["double_tunnel_id"].clone_from(&client["double_tunnel_id"]);
                current["double_tunnel_mode"].clone_from(&client["double_tunnel_mode"]);
                change_transport = true;
            }
            current["fallback_tunnel_ids"].clone_from(proposed);
        }
    }
    expected["routing_revision"] = json!(revision);
    if &expected != after || change_transport && standby.is_some() {
        return Err(unavailable());
    }
    Ok(if let Some(standby) = standby {
        LiveEdit::SetStandby(standby)
    } else if change_transport {
        LiveEdit::OptionalTransport
    } else {
        LiveEdit::Preserve
    })
}

pub fn stage_routed_failover_order(
    db: &Store,
    run: &dyn Runner,
    before: &Value,
    after: &mut Value,
    id: &str,
    retained_nested: Option<&nfqws2_awg_profile::RoutedNestedTransport>,
    mut peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<()> {
    let j = Journal::read(db)?;
    let mut k = kernel(run);
    k.track_sockets(before, &j.installed);
    let prior = j.installed.revision;
    let revision = prior.checked_add(1).ok_or_else(unavailable)?;
    let owner = &before["rust_static_routing"];
    let live_edit = verify_failover_edit(before, after, id, revision)?;
    let iface = j
        .installed
        .targets
        .iter()
        .find_map(|(iface, target)| (target.id == id).then_some(iface.as_str()))
        .ok_or_else(unavailable)?;
    if j.expires != 0
        || !j.preparing.is_empty()
        || !committed_matches_installation(&j)
        || j.installed.dns.is_some()
        || j.installed.learned.is_some()
        || j.installed.legacy_full.is_some()
        || !j.installed.dns_bridges.is_empty()
        || before["routing_revision"] != prior
        || owner["boot"] != j.boot
        || owner["revision"] != prior
        || owner["committed_revision"] != prior
        || owner["pending_commit"] != false
        || owner.get(FIELD).is_some()
        || owner["go_trial"] == true
        || super::legacy_active(before)
        || handoff::pending(db)?
        || profile_rebind::pending(before)
        || super::mtu_edit::pending_mtu_edit(db)?
        || super::active_replacement::active_replacement_in_progress(db)?
        || j.boot != boot_id(&k)?
        || k.inventory(&j.claims(), true)? != objects(&j.installed)
    {
        return Err(unavailable());
    }
    if let Some(nested) = retained_nested {
        if live_edit != LiveEdit::OptionalTransport || nested.peer.iface != iface {
            return Err(unavailable());
        }
        for doc in [before, &*after] {
            let graph = nfqws2_awg_profile::FailoverGraph::load(doc)?;
            let outer = doc["servers"].as_array().ok_or_else(unavailable)?;
            if graph.nested(id).map(|(outer, _)| outer) != Some(nested.peer.outer_id.as_str())
                || plan::profile(doc, outer, &nested.peer.outer_id)?.1 != nested.peer.outer_iface
            {
                return Err(unavailable());
            }
        }
    }
    if live_edit != LiveEdit::Preserve
        && !j.installed.flows().any(|(selector, primary)| {
            let eligible = match live_edit {
                LiveEdit::SetStandby(false) => true,
                LiveEdit::SetStandby(true) => primary != iface,
                _ => primary == iface,
            };
            eligible && j.installed.effective(selector, primary) == Some(iface)
        })
    {
        return Err(unavailable());
    }
    let mut endpoint = None;
    let mut observations = 0;
    let mut observed = |cfg: &Value, name: &str| {
        let live = peer(cfg, name)?;
        if live_edit != LiveEdit::Preserve && name == iface {
            let matches_transport = if let Some(nested) = retained_nested {
                live.endpoint == nested.peer.endpoint
                    && live.socket_mark == nested.peer.socket_mark
                    && live.nested_mtu == Some(nested.peer.effective_mtu)
            } else {
                matches!(live.socket_mark, 0 | nfqws2_awg_profile::DIRECT_SOCKET_MARK)
                    && live.nested_mtu.is_none()
                    && live.nested_transport.is_none()
            };
            if !matches_transport || endpoint.is_some_and(|address| address != live.endpoint) {
                return Err(unavailable());
            }
            endpoint = Some(live.endpoint);
            observations += 1;
        }
        Ok(live)
    };
    let old = plan_at_current_settings(db, before, &j, &k, &mut observed)?;
    if &old != j.installed.as_ref() {
        return Err(unavailable());
    }
    let next = plan_at_current_settings(db, after, &j, &k, &mut observed)?;
    if live_edit != LiveEdit::Preserve && observations != 2 {
        return Err(unavailable());
    }
    let route_update = same_live_paths(&old, &next).is_err();
    let settings = if route_update {
        if retained_nested.is_some() || live_edit == LiveEdit::SetStandby(true) {
            return Err(unavailable());
        }
        verify_reserve_route_update(&old, &next)?;
        k.verify_forward(&old)?;
        reserve_settings_digest(after)?
    } else {
        profile_rebind::digest(after)?
    };
    after["rust_static_routing"][FIELD] = serde_json::to_value(Reorder {
        boot: j.boot,
        before: prior,
        after: revision,
        prior_plan: profile_rebind::digest(&old)?,
        next_plan: profile_rebind::digest(&next)?,
        prior_intent: route_update.then(|| intent_digest(&old)).transpose()?,
        settings,
        targets: (old.targets != next.targets).then_some(next.targets),
        marks: (old.marks != next.marks).then_some(next.marks),
        mss: (old.mss != next.mss).then_some(next.mss),
        reserves: next.reserves,
        route_update: route_update.then_some(true),
    })?;
    Ok(())
}

pub fn finish_routed_failover_order(
    db: &Store,
    run: &dyn Runner,
    mut peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<bool> {
    db.transaction(|tx| {
        let doc = nfqws2_awg_profile::read(db)?;
        finish(db, tx, run, &mut Journal::read(db)?, &doc, &mut peer)
    })
}

pub(super) fn pending(doc: &Value) -> bool {
    doc["rust_static_routing"].get(FIELD).is_some()
}

pub(super) fn finish(
    db: &Store,
    tx: &Transaction<'_>,
    run: &dyn Runner,
    j: &mut Journal,
    doc: &Value,
    peer: &mut impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<bool> {
    let Some(raw) = doc["rust_static_routing"].get(FIELD) else {
        return Ok(false);
    };
    let marker: Reorder = serde_json::from_value(raw.clone())?;
    if marker.route_update == Some(true) {
        return finish_route_update(db, tx, run, j, doc, &marker, peer);
    }
    let revision = doc["routing_revision"].as_u64().ok_or_else(unavailable)?;
    let recorded = j.installed.revision;
    let digest = profile_rebind::digest(j.installed.as_ref())?;
    if marker.boot != j.boot
        || marker.before.checked_add(1) != Some(marker.after)
        || !committed_matches_installation(j)
        || j.expires != 0
        || !j.preparing.is_empty()
        || revision < marker.after
        || doc["rust_static_routing"]["boot"] != j.boot
        || doc["rust_static_routing"]["revision"] != marker.before
        || !(recorded == marker.before && digest == marker.prior_plan
            || recorded == marker.after && digest == marker.next_plan)
    {
        return Err(unavailable());
    }
    let mut unsigned = doc.clone();
    unsigned["rust_static_routing"]
        .as_object_mut()
        .ok_or_else(unavailable)?
        .remove(FIELD);
    if revision == marker.after && profile_rebind::digest(&unsigned)? != marker.settings {
        return Err(unavailable());
    }
    if recorded == marker.before && revision == marker.after {
        let mut plan = j.installed.as_ref().clone();
        plan.revision = marker.after;
        plan.reserves = marker.reserves;
        if let Some(targets) = marker.targets {
            plan.targets = targets;
        }
        if let Some(marks) = marker.marks {
            plan.marks = marks;
        }
        if let Some(mss) = marker.mss {
            plan.mss = mss;
        }
        same_live_paths(&j.installed, &plan)?;
        if profile_rebind::digest(&plan)? != marker.next_plan {
            return Err(unavailable());
        }
        let mut next = j.clone();
        next.installed = plan.into();
        next.committed = next.installed.clone();
        next.committed.selected.clear();
        tx.save_runtime_bounded(RECEIPT, &next, RECEIPT_LIMIT)?;
        *j = next;
    }
    clear_marker(tx, doc, j)?;
    Ok(true)
}

fn clear_marker(tx: &Transaction<'_>, doc: &Value, j: &Journal) -> io::Result<()> {
    nfqws2_awg_profile::edit_document_locked(tx, |latest| {
        if latest != doc {
            return Err(unavailable());
        }
        latest["rust_static_routing"]
            .as_object_mut()
            .ok_or_else(unavailable)?
            .remove(FIELD);
        super::stamp_document(latest, j)
    })
}

fn reserve_settings_digest(doc: &Value) -> io::Result<String> {
    let mut settings = doc.clone();
    settings
        .as_object_mut()
        .ok_or_else(unavailable)?
        .remove("rust_static_routing");
    for row in settings["servers"].as_array_mut().ok_or_else(unavailable)? {
        for origin in ["config", "applied_config"] {
            if let Some(routing) = row[origin]["routing"].as_object_mut() {
                routing.remove("active");
            }
        }
    }
    profile_rebind::digest(&settings)
}

fn finish_route_update(
    db: &Store,
    tx: &Transaction<'_>,
    run: &dyn Runner,
    j: &mut Journal,
    doc: &Value,
    marker: &Reorder,
    peer: &mut impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<bool> {
    let mut k = kernel(run);
    k.track_sockets(doc, &j.installed);
    if !committed_matches_installation(j) || !j.preparing.is_empty() || j.boot != boot_id(&k)? {
        // The owner first reconciles its existing kernel journal.
        return Ok(false);
    }
    let recorded = j.installed.revision;
    let digest = profile_rebind::digest(j.installed.as_ref())?;
    let owner = &doc["rust_static_routing"];
    let intent = intent_digest(&j.installed)?;
    let prior_matches =
        digest == marker.prior_plan || marker.prior_intent.as_ref() == Some(&intent);
    if j.expires != 0
        || marker.before.checked_add(1) != Some(marker.after)
        || doc["routing_revision"] != marker.after
        || reserve_settings_digest(doc)? != marker.settings
        || owner["boot"] != j.boot
        || owner["revision"] != recorded
        || owner["committed_revision"] != recorded
        || owner["pending_commit"] != false
        || !(recorded == marker.before && prior_matches
            || recorded == marker.after && digest == marker.next_plan)
    {
        return Err(unavailable());
    }
    if recorded == marker.after {
        // The journal already committed the new choice. Re-evaluate changed
        // health through ordinary recovery after clearing the settings marker.
        clear_marker(tx, doc, j)?;
        return Ok(true);
    }
    let prior = prove_plan(doc, j.installed.as_ref().clone(), j, &k, peer)?;
    let next = plan_at_current_settings(db, doc, j, &k, peer)?;
    let candidate = objects(&next);
    if profile_rebind::digest(&next)? != marker.next_plan {
        return Err(unavailable());
    }
    let installed = objects(&j.installed);
    let found = k.inventory_for(&j.claims(), &candidate, true)?;
    let safe_rollback = if &prior == j.installed.as_ref() {
        if found != installed {
            return Err(unavailable());
        }
        k.verify_forward(&j.installed)?;
        None
    } else {
        let confirmed_intent = intent_digest(&prior)?;
        if marker.prior_intent.as_ref() != Some(&confirmed_intent)
            || !prior.fully_live()
            || prior.flows().any(|(selector, primary)| {
                prior.effective(selector, primary) != next.effective(selector, primary)
            })
            || !installed
                .intersection(&candidate)
                .all(|object| found.contains(object))
        {
            return Err(unavailable());
        }
        let mut restore = j.clone();
        restore.committed.mss.clone_from(&prior.mss);
        restore.installed = prior.into();
        Some(restore)
    };
    if same_live_paths(&j.installed, &next).is_err() {
        verify_reserve_route_update(&j.installed, &next)?;
    }
    let mut next_journal = j.clone();
    next_journal.installed = next.into();
    next_journal.committed = next_journal.installed.clone();
    next_journal.committed.selected.clear();
    super::transition(db, tx, run, j, &next_journal, safe_rollback.as_ref())?;
    *j = next_journal;
    clear_marker(tx, &nfqws2_awg_profile::read(db)?, j)?;
    Ok(true)
}

/// A reserve outside the current forwarding paths can be added or removed
/// without writing to the kernel. Still verify all existing peer identities.
fn same_live_paths(installed: &Plan, candidate: &Plan) -> io::Result<()> {
    same_active_forwarding(installed, candidate)?;
    if objects(installed) != objects(candidate) {
        return Err(err("изменение резервов затрагивает действующие маршруты"));
    }
    Ok(())
}

fn verify_reserve_route_update(installed: &Plan, candidate: &Plan) -> io::Result<()> {
    if installed.selected != candidate.selected {
        return verify_reserve_reselection(installed, candidate);
    }
    same_active_forwarding(installed, candidate)?;
    let old = objects(installed);
    let new = objects(candidate);
    if old == new || !old.symmetric_difference(&new).all(super::Object::fixed_mss) {
        return Err(err("изменение резервов затрагивает действующие маршруты"));
    }
    Ok(())
}

fn verify_reserve_reselection(installed: &Plan, candidate: &Plan) -> io::Result<()> {
    let incompatible = || err("изменение меняет состав действующих резервов AWG");
    verify_same_policy(installed, candidate, true)?;
    if !candidate.fully_live()
        || installed.reserves.len() != candidate.reserves.len()
        || installed
            .reserves
            .iter()
            .zip(&candidate.reserves)
            .any(|((s, _), (t, _))| s != t)
    {
        return Err(incompatible());
    }
    for (selector, primary) in installed.flows() {
        let old = installed.effective(selector, primary);
        let new = candidate.effective(selector, primary);
        if old == new {
            continue;
        }
        let prior = installed.reserves_for(selector);
        let updated = candidate.reserves_for(selector);
        let selected = |iface: Option<&str>, pool: &[String]| {
            iface.is_some_and(|iface| pool.iter().any(|reserve| reserve == iface))
        };
        if prior == updated || !selected(old, prior) || !selected(new, updated) {
            return Err(incompatible());
        }
    }
    Ok(())
}

fn same_active_forwarding(installed: &Plan, candidate: &Plan) -> io::Result<()> {
    verify_same_policy(installed, candidate, false)
}

fn verify_same_policy(installed: &Plan, candidate: &Plan, reselection: bool) -> io::Result<()> {
    let changed = || err("изменение резервов затрагивает действующие маршруты");
    candidate.validate()?;
    let mut expected = installed.clone();
    expected.reserves.clone_from(&candidate.reserves);
    expected.targets.clone_from(&candidate.targets);
    expected.marks.clone_from(&candidate.marks);
    expected.mss.clone_from(&candidate.mss);
    expected.revision = candidate.revision;
    if reselection {
        expected.selected.clone_from(&candidate.selected);
    }
    if !installed.fully_live()
        || &expected != candidate
        || installed.marks.is_empty() != candidate.marks.is_empty()
        || installed.targets.iter().any(|(iface, target)| {
            candidate.targets.get(iface).is_some_and(|peer| {
                peer != target
                    || installed.marks.get(iface) != candidate.marks.get(iface)
                    || installed.mss.get(iface) != candidate.mss.get(iface)
            })
        })
    {
        return Err(changed());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::plan::{Selector, Target};
    use super::*;

    #[test]
    fn reserve_edit_preserves_kernel_objects_and_requires_exact_targets() {
        let selector = Selector {
            source: "0.0.0.0/0".parse().unwrap(),
            dest: "203.0.113.0/24".parse().unwrap(),
        };
        let mut old = Plan {
            prefixes: [(selector.dest, "awg0".to_owned())].into(),
            killswitch: true,
            packed: true,
            reserves: vec![(selector, vec!["awg1".into(), "awg2".into()])],
            revision: 11,
            ..Default::default()
        };
        for (slot, iface) in ["awg0", "awg1", "awg2"].into_iter().enumerate() {
            old.marks.insert(iface.to_owned(), slot as u8 + 1);
            old.targets.insert(
                iface.to_owned(),
                Target {
                    id: iface.to_owned(),
                    public_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".to_owned(),
                    mtu: 1420,
                },
            );
        }
        let mut candidate = old.clone();
        candidate.revision = 12;
        candidate.reserves[0].1.reverse();
        same_live_paths(&old, &candidate).unwrap();
        assert!(!objects(&old).is_empty());
        candidate.selected.push((selector, Some("awg2".into())));
        assert!(same_live_paths(&old, &candidate).is_err());
        candidate.selected.clear();
        candidate.reserves[0].1[1] = "awg2".into();
        assert!(same_live_paths(&old, &candidate).is_err());
    }

    #[test]
    fn only_unused_reserve_objects_may_change_under_the_same_forwarding_paths() {
        let scope = super::super::plan::Selector {
            source: "0.0.0.0/0".parse().unwrap(),
            dest: "203.0.113.0/24".parse().unwrap(),
        };
        let old_target = super::super::plan::Target {
            id: "primary".into(),
            public_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into(),
            mtu: 1420,
        };
        let old = Plan {
            prefixes: [(scope.dest, "awg0".into())].into(),
            targets: [("awg0".into(), old_target.clone())].into(),
            marks: [("awg0".into(), 1)].into(),
            mss: [("awg0".into(), 1380)].into(),
            revision: 5,
            packed: true,
            go_ipv4: true,
            ..Default::default()
        };
        let mut next = old.clone();
        let new_target = super::super::plan::Target {
            id: "reserve".into(),
            ..old_target
        };
        next.targets.insert("awg1".into(), new_target);
        next.marks.insert("awg1".into(), 2);
        next.mss.insert("awg1".into(), 1380);
        next.reserves.push((scope, vec!["awg1".into()]));
        next.revision = 6;
        verify_reserve_route_update(&old, &next).unwrap();
        assert_ne!(objects(&old), objects(&next));
        assert!(same_live_paths(&old, &next).is_err());
        let mut cold = next.clone();
        cold.mss.remove("awg1");
        same_live_paths(&old, &cold).unwrap();
        next.selected.push((scope, Some("awg1".into())));
        assert!(same_active_forwarding(&old, &next).is_err());
        next.selected.clear();
        next.marks.insert("awg0".into(), 3);
        assert!(same_active_forwarding(&old, &next).is_err());
    }
}
