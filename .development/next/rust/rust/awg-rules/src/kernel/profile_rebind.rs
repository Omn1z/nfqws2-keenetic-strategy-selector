//! Confirmed revision changes that leave the installed routing policy intact.
use super::{
    boot_id, err, handoff, io, kernel, mtu_edit, objects, plan, Journal, Plan, Runner, Store,
    Transaction, RECEIPT, RECEIPT_LIMIT,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::SocketAddr;

const FIELD: &str = "dormant_replacement";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rebind {
    boot: String,
    prior: u64,
    next: u64,
    removed: String,
    plan: String,
    policy: String,
}

fn ineligible() -> io::Error {
    err("перенос требует неизменной подтверждённой политики AWG")
}

pub(super) fn pending(doc: &Value) -> bool {
    doc["rust_static_routing"].get(FIELD).is_some()
}

pub(super) fn native_prefix(journal: &Journal) -> io::Result<(&str, &plan::Target)> {
    if journal.installed.prefixes.len() != 1 {
        return Err(ineligible());
    }
    native_ipv4_prefixes(journal)
}

pub(super) fn native_ipv4_prefixes(journal: &Journal) -> io::Result<(&str, &plan::Target)> {
    let p = &journal.installed;
    let Some((_, iface)) = p.prefixes.first_key_value() else {
        return Err(ineligible());
    };
    if journal.expires != 0
        || !journal.preparing.is_empty()
        || p != &journal.committed
        || p.targets.len() != 1
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
                revision: p.revision,
                killswitch: p.killswitch,
                ..Plan::default()
            })
    {
        return Err(ineligible());
    }
    Ok((iface, p.targets.get(iface).ok_or_else(ineligible)?))
}

fn revision(doc: &Value) -> Option<u64> {
    doc["routing_revision"].as_u64()
}

pub(super) fn owner_matches(doc: &Value, journal: &Journal, id: &str, revision: u64) -> bool {
    owner_matches_all(doc, journal, [id], revision)
}

pub(super) fn owner_matches_all<'a>(
    doc: &Value,
    journal: &Journal,
    ids: impl IntoIterator<Item = &'a str>,
    revision: u64,
) -> bool {
    let ids = ids.into_iter().collect::<std::collections::BTreeSet<_>>();
    let owner = &doc["rust_static_routing"];
    owner["boot"] == journal.boot
        && owner["pending_commit"] == false
        && owner["go_trial"] != true
        && owner["legacy_watchdog"] != true
        && owner["revision"] == revision
        && owner["committed_revision"] == revision
        && owner["targets"] == json!(ids)
        && owner["committed_targets"] == json!(ids)
        && !super::legacy_active(doc)
}

pub(super) fn digest(data: &impl Serialize) -> io::Result<String> {
    Ok(crate::identity::digest(&serde_json::to_vec(data)?, 32))
}

fn plan_digest(journal: &Journal) -> io::Result<String> {
    let mut unchanged = journal.committed.as_ref().clone();
    unchanged.revision = 0;
    digest(&unchanged)
}

fn policy_digest(doc: &Value, journal: &Journal) -> io::Result<String> {
    let (iface, target) = native_prefix(journal)?;
    let rows = doc["servers"].as_array().ok_or_else(ineligible)?;
    let row = rows
        .iter()
        .find(|r| r["id"] == target.id)
        .ok_or_else(ineligible)?;
    let (wire, inferred, current) = plan::profile(doc, rows, &target.id)?;
    let client = &wire["client"];
    if current != *target
        || inferred != iface
        || !row["applied_config"].is_null()
        || wire["install"] != "imported"
        || wire["enabled"] != true
        || wire["routing"]["active"] != true
        || wire["endpoint"]
            .as_str()
            .and_then(|s| s.parse::<SocketAddr>().ok())
            .and_then(mtu_edit::canonical_socket)
            .is_none()
        || client["enabled"] != true
        || client["rust_managed"] != true
        || client["standby"] == true
        || client["double_tunnel_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty())
        || !matches!(
            client["double_tunnel_mode"].as_str(),
            None | Some("" | "off" | "last_resort")
        )
        || nfqws2_awg_profile::routed_mtu_launch_pending(row)
        || nfqws2_awg_profile::pending_routed_mtu(row)?.is_some()
    {
        return Err(ineligible());
    }
    let mut policy = crate::policy::current(doc)?;
    let trace_index = policy.zones.iter().position(|z| z.enabled);
    policy.zones.retain(|z| z.enabled);
    if !matches!(policy.mode.as_str(), "zones" | "include" | "exclude")
        || policy.zones.len() != 1
        || policy.sni_routing
    {
        return Err(ineligible());
    }
    let zone = &mut policy.zones[0];
    if zone.tunnel_id != target.id
        || zone.waiting_for_connection
        || zone.direction() != "tunnel"
        || !zone.fallback_tunnel_ids.is_empty()
        || !zone.source_ips.is_empty()
        || !zone.domains.is_empty()
        || zone.ips.len() != 1
        || zone.only_catch_all()
    {
        return Err(ineligible());
    }
    zone.order = 0;
    let live = &journal.committed;
    let mut projection =
        plan::compile_effective(doc, policy.clone(), None, true, &[], live.layout())?;
    projection.revision = live.revision;
    projection.mss.clone_from(&live.mss);
    if projection != **live {
        return Err(ineligible());
    }

    // The runtime wire identity and all effective route labels/settings must
    // survive a reordering of the saved profiles and their disabled zones.
    let mut unchanged = wire.clone();
    unchanged["client_iface"] = json!(inferred);
    unchanged["routing"]["zones"] = json!([]);
    digest(&(unchanged, policy, trace_index))
}

/// Certify an unrelated inactive removal while the caller holds the profile
/// and Store locks. Only read the live FIB and add the metadata intent to `after`.
pub fn stage_dormant_replacement(
    db: &Store,
    run: &dyn Runner,
    before: &Value,
    after: &mut Value,
    removed: &str,
    replacement: &str,
) -> io::Result<()> {
    let journal = Journal::read(db)?;
    let (_, target) = native_prefix(&journal)?;
    let row = |doc: &Value, id| {
        doc["servers"]
            .as_array()
            .is_some_and(|rows| rows.iter().any(|r| r["id"] == id))
    };
    let prior = journal.committed.revision;
    let next = prior.checked_add(1).ok_or_else(ineligible)?;
    if removed.is_empty()
        || replacement.is_empty()
        || removed == replacement
        || removed == target.id
        || replacement == target.id
        || !row(before, removed)
        || row(after, removed)
        || !row(before, replacement)
        || !row(after, replacement)
        || revision(before) != Some(prior)
        || revision(after) != Some(next)
        || pending(before)
        || !owner_matches(before, &journal, &target.id, prior)
        || before["rust_static_routing"] != after["rust_static_routing"]
        || handoff::pending(db)?
        || mtu_edit::pending_mtu_edit(db)?
        || super::active_replacement::active_replacement_in_progress(db)?
    {
        return Err(ineligible());
    }
    let policy = policy_digest(before, &journal)?;
    if policy != policy_digest(after, &journal)? {
        return Err(ineligible());
    }
    let k = kernel(run);
    if journal.boot != boot_id(&k)?
        || k.lan_zone(journal.installed.firewall)? != journal.installed.fw4_zone
        || k.inventory(&journal.claims(), true)? != objects(&journal.installed)
    {
        return Err(ineligible());
    }
    k.verify_forward(&journal.installed)?;

    after["rust_static_routing"][FIELD] = serde_json::to_value(Rebind {
        boot: journal.boot.clone(),
        prior,
        next,
        removed: removed.to_owned(),
        plan: plan_digest(&journal)?,
        policy,
    })?;
    Ok(())
}

pub fn finish_dormant_replacement(db: &Store) -> io::Result<bool> {
    db.transaction(|tx| {
        let doc = nfqws2_awg_profile::read(db)?;
        if !pending(&doc) {
            return Ok(false);
        }
        finish(tx, &mut Journal::read(db)?, &doc)
    })
}

pub(super) fn finish(tx: &Transaction<'_>, journal: &mut Journal, doc: &Value) -> io::Result<bool> {
    let Some(raw) = doc["rust_static_routing"].get(FIELD) else {
        return Ok(false);
    };
    let marker: Rebind = serde_json::from_value(raw.clone())?;
    let (_, target) = native_prefix(journal)?;
    let current = revision(doc).ok_or_else(ineligible)?;
    let recorded = journal.committed.revision;
    if marker.boot != journal.boot
        || marker.prior.checked_add(1) != Some(marker.next)
        || ![marker.prior, marker.next].contains(&recorded)
        || current < marker.next
        || marker.removed.is_empty()
        || doc["servers"]
            .as_array()
            .ok_or_else(ineligible)?
            .iter()
            .any(|r| r["id"] == marker.removed)
        || !owner_matches(doc, journal, &target.id, marker.prior)
        || marker.plan != plan_digest(journal)?
        || current == marker.next && marker.policy != policy_digest(doc, journal)?
    {
        return Err(ineligible());
    }

    // If an independent draft was saved after the delete, leave it pending.
    // A previously saved journal revision still needs its matching owner stamp.
    if recorded == marker.prior && current == marker.next {
        let mut next = journal.clone();
        next.installed.revision = marker.next;
        next.committed.revision = marker.next;
        if objects(&next.installed) != objects(&journal.installed) {
            return Err(ineligible());
        }
        tx.save_runtime_bounded(RECEIPT, &next, RECEIPT_LIMIT)?;
        *journal = next;
    }

    nfqws2_awg_profile::edit_document_locked(tx, |latest| {
        if latest != doc {
            return Err(ineligible());
        }
        let owner = latest["rust_static_routing"]
            .as_object_mut()
            .ok_or_else(ineligible)?;
        owner.remove(FIELD);
        owner.insert("revision".into(), json!(journal.installed.revision));
        owner.insert(
            "committed_revision".into(),
            json!(journal.committed.revision),
        );
        Ok(())
    })?;
    Ok(true)
}
