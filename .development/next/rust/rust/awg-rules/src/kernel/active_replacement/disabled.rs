//! Transfer rule intent to an explicitly disabled, absent carrier.
use super::*;
use nfqws2_awg_profile::disabled_active_replacement_target;
use std::collections::BTreeMap;

pub(crate) const TARGETS: &str = "disabled_replacements";
pub(crate) const DNS: &str = "disabled_replacement_dns";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DormantDns {
    policy: String,
    saved_at: u64,
    members: Vec<learning::Member>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    firmware: Vec<learning::Member>,
    #[serde(default)]
    stamp: String,
    #[serde(default)]
    bridges: Vec<String>,
}

fn dns_policy_key(policy: &crate::Routing, revision: u64, id: &str) -> io::Result<String> {
    let mut policy = policy.clone();
    policy.active = false;
    let sources = policy.zones.iter().map(|z| &z.source_key).collect::<Vec<_>>();
    profile_rebind::digest(&(revision, id, &policy, sources))
}

impl DormantDns {
    fn save(doc: &mut Value, transfer: &Transfer, id: &str) -> io::Result<()> {
        let prior = &transfer.prior.installed;
        let held_id = transfer.held_direct.as_ref().map(|held| held.owner.id.as_str());
        let (policy, _) = explicit_policy(doc, id, held_id)?;
        let saved_at = nfqws2_awg_profile::now();
        let (firmware, members) = live_dns_members(prior)?.iter()
            .filter(|m| m.until > saved_at && policy.zones[m.zone].tunnel_id == id)
            .cloned()
            .partition(|m| m.until == RETAINED_FIRMWARE_MEMBER);
        let receipt = Self {
            policy: dns_policy_key(&policy, transfer.next.committed.revision, id)?,
            saved_at,
            members,
            firmware,
            stamp: transfer.token.clone(),
            bridges: prior.dns_bridges.clone(),
        };
        doc["rust_static_routing"][DNS] = serde_json::to_value(receipt)?;
        Ok(())
    }

    fn load(doc: &Value, policy: &crate::Routing, revision: u64, id: &str) -> io::Result<Self> {
        let raw = &doc["rust_static_routing"][DNS];
        let finite = raw["members"].as_array().map_or(129, Vec::len);
        let firmware = raw.get("firmware").map_or(0, |v| v.as_array().map_or(129, Vec::len));
        if finite + firmware > 128 {
            return Err(ineligible());
        }
        let receipt: Self = serde_json::from_value(raw.clone())?;
        if receipt.policy != dns_policy_key(policy, revision, id)?
            || receipt.members.iter().chain(&receipt.firmware).any(|m| {
                m.zone >= policy.zones.len()
                    || !m.ip.is_ipv4()
                    || m.until <= receipt.saved_at
                    || !Prefix::host(m.ip).safe()
            })
            || receipt.members.iter().any(|m| m.until == RETAINED_FIRMWARE_MEMBER)
            || receipt.firmware.iter().any(|m| m.until != RETAINED_FIRMWARE_MEMBER)
            || receipt.members.windows(2).any(|p| (p[0].zone, p[0].ip) >= (p[1].zone, p[1].ip))
            || receipt.firmware.windows(2).any(|p| (p[0].zone, p[0].ip) >= (p[1].zone, p[1].ip))
            || (!receipt.firmware.is_empty() && (receipt.stamp.len() != 64
                || !receipt.members.is_empty()
                || receipt.bridges.is_empty()
                || receipt.bridges.len() > 128
                || receipt.bridges.windows(2).any(|pair| pair[0] >= pair[1])
                || !receipt.bridges.iter().all(|bridge| super::super::valid_dns_bridge(bridge))))
        {
            return Err(ineligible());
        }
        Ok(receipt)
    }
}

pub struct DormantFirmwareDns {
    receipt: DormantDns,
    policy: crate::observed::Policy,
    revision: u64,
    target: String,
}

pub struct DormantFirmwareAnswer<'a> {
    pub name: &'a str,
    pub client: IpAddr,
    pub ingress: &'a str,
    pub addresses: &'a [IpAddr],
    pub until: Instant,
}

pub struct DormantFirmwareProof {
    stamp: String,
    members: BTreeMap<(usize, IpAddr), Instant>,
}

impl DormantFirmwareDns {
    pub fn transfer_stamp(&self) -> (&str, u64) {
        (&self.receipt.stamp, self.revision - 1)
    }

    pub fn restored_revision(&self, db: &Store) -> io::Result<Option<u64>> {
        let doc = nfqws2_awg_profile::read(db)?;
        let j = Journal::read(db)?;
        let restored = j.committed.revision == self.revision
            && j.expires == 0 && j.preparing.is_empty()
            && j.installed == j.committed
            && j.committed.targets.values().any(|owner| owner.id == self.target)
            && doc["routing_revision"].as_u64() == Some(self.revision)
            && doc["rust_static_routing"][TARGETS].is_null()
            && profile_rebind::owner_matches_all(
                &doc, &j, j.committed.targets.values().map(|target| target.id.as_str()), self.revision,
            );
        Ok(restored.then_some(self.revision))
    }

    pub fn previous_answers<'a>(
        &self,
        answers: impl IntoIterator<Item = DormantFirmwareAnswer<'a>>,
    ) -> DormantFirmwareProof {
        let now = Instant::now();
        let mut members = BTreeMap::new();
        for answer in answers.into_iter().take(128) {
            if answer.until <= now || answer.addresses.len() > 128
                || self.receipt.bridges.iter().all(|name| name != answer.ingress)
            {
                continue;
            }
            let Some(zone) = self.policy.matched(answer.name, Some(answer.client)) else {
                continue;
            };
            for member in &self.receipt.firmware {
                if member.zone == zone && answer.addresses.contains(&member.ip) {
                    let until = members.entry((zone, member.ip)).or_insert(answer.until);
                    *until = (*until).max(answer.until);
                }
            }
        }
        DormantFirmwareProof { stamp: self.receipt.stamp.clone(), members }
    }
}

pub fn dormant_firmware_dns(db: &Store) -> io::Result<Option<DormantFirmwareDns>> {
    let doc = nfqws2_awg_profile::read(db)?;
    if doc["rust_static_routing"][DNS]["firmware"].is_null() {
        return Ok(None);
    }
    let j = Journal::read(db)?;
    let Some(profile) = marked_profile(&doc, &j) else {
        return Ok(None);
    };
    let id = profile["id"].as_str().ok_or_else(ineligible)?;
    let held = j.committed.targets.first_key_value().map(|(_, target)| target.id.as_str());
    let (policy, _) = explicit_policy(&doc, id, held)?;
    let receipt = DormantDns::load(&doc, &policy, j.committed.revision, id)?;
    Ok(Some(DormantFirmwareDns {
        receipt,
        policy: crate::observed::Policy::compile(&policy)?,
        revision: j.committed.revision,
        target: id.to_owned(),
    }))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Target {
    id: String,
    iface: String,
}

pub(in crate::kernel) fn confirmed_empty(db: &Store, j: &Journal) -> io::Result<bool> {
    if j.committed.revision == 0 || j.installed != j.committed {
        return Ok(false);
    }
    let doc = nfqws2_awg_profile::read(db)?;
    let Some(target) = dormant_target(&doc, j) else {
        return Ok(false);
    };
    Ok(disabled_active_replacement_target(&doc, target)?.is_some())
}

pub(in crate::kernel) fn dormant_target<'a>(doc: &'a Value, j: &Journal) -> Option<&'a str> {
    let owner = &doc["rust_static_routing"];
    let [target] = owner[TARGETS].as_array()?.as_slice() else {
        return None;
    };
    let target = target.as_str()?;
    let revision = j.committed.revision;
    (j.idle()
        && revision != 0
        && (j.installed == j.committed || j.installed.as_ref() == &Plan::default())
        && doc["routing_revision"].as_u64() == Some(revision)
        && owner["committed_revision"].as_u64() == Some(revision)
        && owner["targets"] == json!([])
        && owner["committed_targets"] == json!([])
        && owner["pending_commit"] == false
        && row(doc, target).is_some_and(|row| row["config"]["routing"]["active"] == true))
    .then_some(target)
}

fn literal_plan(plan: &Plan, held: Option<&str>, targets: usize) -> bool {
    plan.targets.len() == targets
        && held.is_none_or(|held| plan.targets.contains_key(held))
        && plan.flows().all(|(selector, iface)| {
            !selector.dest.any()
                && selector.dest.family() == plan::Family::V4
                && (Some(iface) != held || selector.source.any())
        })
        && *plan
            == (Plan {
                prefixes: plan.prefixes.clone(),
                scoped: plan.scoped.clone(),
                scoped_slots: plan.scoped_slots.clone(),
                targets: plan.targets.clone(),
                mss: plan.mss.clone(),
                killswitch: plan.killswitch,
                revision: plan.revision,
                ..Plan::default()
            })
}

fn withheld(plan: &Plan, held: Option<&str>) -> io::Result<Plan> {
    let mut kept = plan.clone();
    kept.prefixes.retain(|_, i| Some(i.as_str()) == held);
    kept.scoped.retain(|(_, i)| Some(i.as_str()) == held);
    kept.targets.retain(|iface, _| Some(iface.as_str()) == held);
    kept.mss.retain(|iface, _| Some(iface.as_str()) == held);
    kept.scoped_slots.clear();
    if let Some(held) = held.filter(|held| !kept.scoped.is_empty() && plan.scoped_slot(held) != 0) {
        kept.scoped_slots
            .insert(held.into(), plan.scoped_slot(held));
    }
    kept.validate()?;
    if !objects(&kept).is_subset(&objects(plan))
        || held.is_some_and(|held| held_dns_objects(plan, held) != held_dns_objects(&kept, held))
    {
        return Err(ineligible());
    }
    Ok(kept)
}

fn held_dns_policy(mut policy: crate::Routing, held: &str) -> io::Result<crate::Routing> {
    if mixed_dns_sources(&policy).is_none_or(|shape| !shape.independent)
        || policy.zones.iter().filter(|zone| zone.tunnel_id == held).count() != 1
    {
        return Err(ineligible());
    }
    policy.active = false;
    for zone in &mut policy.zones {
        zone.enabled &= zone.tunnel_id == held;
    }
    Ok(policy)
}

fn check_held_dns_projection(
    before: &Plan,
    kept: &Plan,
    source: &str,
    target: &str,
    held: &NativeRemovalSeal,
) -> io::Result<()> {
    let before_saved = before.learned.as_ref().ok_or_else(ineligible)?;
    let kept_saved = kept.learned.as_ref().ok_or_else(ineligible)?;
    let mut expected = before_saved.routing()?;
    let retained = before_saved.members.iter().filter(|member| {
        expected.zones[member.zone].tunnel_id == held.id
    }).eq(&kept_saved.members);
    if !retained {
        return Err(ineligible());
    }
    for zone in &mut expected.zones {
        if zone.tunnel_id == source {
            zone.tunnel_id = target.to_owned();
        }
    }
    let expected = held_dns_policy(expected, &held.id)?;
    if serde_json::to_value(expected)? != serde_json::to_value(kept_saved.routing()?)? {
        return Err(ineligible());
    }
    let mut expected = withheld(before, Some(&held.iface))?;
    expected.revision = before.revision.checked_add(1).ok_or_else(ineligible)?;
    expected.learned = Some(kept_saved.clone());
    if *kept != expected {
        return Err(ineligible());
    }
    Ok(())
}

fn projection(
    prior: &Journal,
    source: &NativeRemovalSeal,
    held: Option<&NativeRemovalSeal>,
    target: &str,
    kept_dns: Option<&Plan>,
) -> io::Result<Journal> {
    let plan = prior.installed.as_ref();
    let learned = plan.learned.is_some();
    let supported = if learned {
        cold_launch_target(prior, held).is_ok()
    } else {
        literal_plan(
            plan,
            held.map(|held| held.iface.as_str()),
            1 + usize::from(held.is_some()),
        )
    };
    if prior.expires != 0
        || !prior.preparing.is_empty()
        || prior.installed != prior.committed
        || !supported
        || source.boot != prior.boot
        || !source.valid()
        || source.nested.is_some()
        || held.is_some_and(|held| {
            held.boot != prior.boot
                || !held.valid()
                || held.nested.is_some()
                || !distinct_owner(source, held)
                || plan
                    .targets
                    .get(&held.iface)
                    .is_none_or(|p| p.id != held.id)
        })
        || plan
            .targets
            .get(&source.iface)
            .is_none_or(|p| p.id != source.id)
    {
        return Err(ineligible());
    }
    let mut kept = if let (true, Some(held)) = (learned, held) {
        let kept = kept_dns.ok_or_else(ineligible)?;
        check_held_dns_projection(plan, kept, &source.id, target, held)?;
        kept.clone()
    } else if learned {
        Plan {
            killswitch: plan.killswitch,
            ..Plan::default()
        }
    } else {
        withheld(plan, held.map(|held| held.iface.as_str()))?
    };
    kept.revision = plan.revision.checked_add(1).ok_or_else(ineligible)?;
    Ok(Journal {
        boot: prior.boot.clone(),
        installed: kept.clone().into(),
        committed: kept.into(),
        ..Journal::default()
    })
}

fn token_for(transfer: &Transfer) -> io::Result<String> {
    profile_rebind::digest(&(
        "disabled-target",
        &transfer.disabled_target,
        &transfer.prior,
        &transfer.next,
        &transfer.source,
        transfer.source_fingerprint,
        &transfer.held_direct,
    ))
}

pub(super) fn validate(transfer: &Transfer) -> io::Result<()> {
    let target = transfer.disabled_target.as_ref().ok_or_else(ineligible)?;
    let held = transfer.held_direct.as_ref();
    if !crate::model::reference(&target.id)
        || !plan::iface_ok(&target.iface)
        || transfer.source.id == target.id
        || transfer.source.iface == target.iface
        || held.is_some_and(|held| {
            held.owner.id == target.id
                || held.owner.iface == target.iface
                || held.fingerprint == [0; 32]
        })
        || transfer.source_fingerprint == [0; 32]
        || transfer.retained_outer.is_some()
        || transfer.nested_target.is_some()
        || transfer.retiring_nested.is_some()
        || transfer.temporary_stop.is_some()
        || transfer.retry_runtime
        || transfer.retry_dns.is_some()
        || transfer.retry_projection.is_some()
        || transfer.retry_positive_hint.is_some()
        || transfer.retry_negative_name.is_some()
        || transfer.retry_positive_pair.is_some()
        || projection(
            &transfer.prior,
            &transfer.source,
            held.map(|held| &held.owner),
            &target.id,
            Some(&transfer.next.installed),
        )? != transfer.next
        || token_for(transfer)? != transfer.token
    {
        return Err(ineligible());
    }
    Ok(())
}

pub(super) fn restore_source_intent(tx: &Transaction<'_>, source: &str) -> io::Result<()> {
    nfqws2_awg_profile::edit_document_locked(tx, |doc| {
        let row = doc["servers"]
            .as_array_mut()
            .and_then(|rows| rows.iter_mut().find(|row| row["id"] == source))
            .ok_or_else(ineligible)?;
        for key in ["config", "applied_config"] {
            if row[key].is_object() {
                row[key]["routing"]["active"] = json!(true);
            }
        }
        Ok(())
    })
}

fn literal_policy(doc: &Value) -> io::Result<crate::Routing> {
    let policy = crate::policy::current(doc)?;
    if !matches!(policy.mode.as_str(), "zones" | "include" | "exclude")
        || policy.sni_routing
        || policy.zones.iter().filter(|z| z.enabled).any(|z| {
            z.waiting_for_connection
                || z.direction() != "tunnel"
                || z.ips.is_empty()
                || !z.domains.is_empty()
                || !z.fallback_tunnel_ids.is_empty()
        })
    {
        return Err(ineligible());
    }
    Ok(policy)
}

fn transfer_policy(
    before: &Value,
    after: &Value,
    source: &str,
    target: &Target,
    (keep_active, learned): (bool, bool),
) -> io::Result<crate::Routing> {
    let old = if learned {
        crate::policy::current(before)?
    } else {
        literal_policy(before)?
    };
    let mut expected = old.clone();
    expected.active &= keep_active;
    for (i, zone) in expected.zones.iter_mut().enumerate() {
        zone.order = i + 1;
        if zone.tunnel_id == source {
            zone.tunnel_id = target.id.clone();
            zone.waiting_for_connection = false;
        }
    }
    let actual = crate::policy::current(after)?;
    let (before_target, after_target) = (
        row(before, &target.id).ok_or_else(ineligible)?,
        row(after, &target.id).ok_or_else(ineligible)?,
    );
    let (before_cfg, after_cfg) = (&before_target["config"], &after_target["config"]);
    if serde_json::to_value(expected)? != serde_json::to_value(actual)?
        || before_cfg["enabled"] != after_cfg["enabled"]
        || before_cfg["client"]["enabled"] != after_cfg["client"]["enabled"]
        || after_cfg["routing"]["active"] != true
        || after_cfg["client"]["standby"] != false
        || row(after, source).is_some()
        || after["active_id"]
            != if before["active_id"] == source {
                json!(target.id)
            } else {
                before["active_id"].clone()
            }
        || disabled_active_replacement_target(after, &target.id)?.as_deref() != Some(&target.iface)
    {
        return Err(ineligible());
    }
    Ok(old)
}

fn marked_id(doc: &Value) -> Option<&str> {
    let [id] = doc["rust_static_routing"][TARGETS].as_array()?.as_slice() else {
        return None;
    };
    id.as_str().filter(|id| crate::model::reference(id))
}

fn marked_profile<'a>(doc: &'a Value, j: &Journal) -> Option<&'a Value> {
    let id = marked_id(doc)?;
    let row = row(doc, id)?;
    let cfg = &row["config"];
    (j.expires == 0
        && doc["routing_revision"].as_u64() == Some(j.committed.revision)
        && j.committed.targets.values().all(|t| t.id != id)
        && row["applied_config"].is_null()
        && cfg["routing"]["active"] == true
        && cfg["client"]["standby"] == false)
        .then_some(row)
}

pub(in crate::kernel) fn marked_rearm(
    doc: &Value,
    j: &Journal,
    id: &str,
    include_enabled: bool,
) -> io::Result<bool> {
    if marked_profile(doc, j).is_none_or(|row| row["id"] != id) {
        return Ok(false);
    }
    Ok((include_enabled && rearm_pending(doc, j))
        || disabled_active_replacement_target(doc, id)?.is_some())
}

fn enabled_profile<'a>(doc: &'a Value, j: &Journal) -> Option<&'a Value> {
    let row = marked_profile(doc, j)?;
    let cfg = &row["config"];
    (cfg["enabled"] == true
        && cfg["client"]["enabled"] == true
        && cfg["client"]["rust_managed"] == true)
        .then_some(row)
}

pub(in crate::kernel) fn rearm_pending(doc: &Value, j: &Journal) -> bool {
    rearm_intent(doc, j).is_some()
        || (j.installed.as_ref() == &Plan::default()
            && dormant_target(doc, j)
                .is_some_and(|id| enabled_profile(doc, j).is_some_and(|row| row["id"] == id))
            && literal_plan(&j.committed, None, 0))
        || rearm_is_committed(doc, j)
}

pub fn disabled_replacement_rearm_needs_dns(db: &Store) -> io::Result<bool> {
    let doc = nfqws2_awg_profile::read(db)?;
    if doc["rust_static_routing"][DNS].is_null() {
        return Ok(false);
    }
    Ok(rearm_pending(&doc, &Journal::read(db)?))
}

pub(super) fn rearm_witness_needed(db: &Store, iface: &str) -> io::Result<bool> {
    let doc = nfqws2_awg_profile::read(db)?;
    if marked_id(&doc).is_none() {
        return Ok(false);
    }
    let j = Journal::read(db)?;
    let Some(intent) = rearm_intent(&doc, &j) else {
        return Ok(false);
    };
    let id = intent.target["id"].as_str().ok_or_else(ineligible)?;
    let rows = doc["servers"].as_array().ok_or_else(ineligible)?;
    let (_, target_iface, _) = plan::profile(&doc, rows, id)?;
    Ok(iface == target_iface || j.committed.targets.contains_key(iface))
}

struct RearmIntent<'a> {
    target: &'a Value,
    held: Option<(&'a str, &'a str)>,
    dns: bool,
}

fn rearm_intent<'a>(doc: &'a Value, j: &'a Journal) -> Option<RearmIntent<'a>> {
    let target = enabled_profile(doc, j)?;
    let held = j
        .committed
        .targets
        .first_key_value()
        .map(|(iface, held)| (iface.as_str(), held.id.as_str()));
    let dns = !doc["rust_static_routing"][DNS].is_null();
    let plan = &j.committed;
    let supported = if let (true, Some((iface, _))) = (dns, held) {
        plan.learned.is_some() && !plan.dns_bridges.is_empty()
            && plan.targets.len() == 1 && plan.prefixes.is_empty()
            && plan.scoped.iter().all(|(scope, owner)| scope.source.any() && owner == iface)
    } else {
        literal_plan(plan, held.map(|(iface, _)| iface), usize::from(held.is_some()))
    };
    (j.installed == j.committed && supported)
    .then_some(RearmIntent { target, held, dns })
}

fn rearm_projection(
    plan: &Plan, dormant: &Plan, id: &str, held: Option<&str>, dns: bool,
) -> io::Result<Plan> {
    if dns {
        if plan.learned.is_none()
            || replacement_route_target(
                &Journal {
                    installed: plan.clone().into(),
                    committed: plan.clone().into(),
                    ..Journal::default()
                },
            )?
            .1
            .id != id
        {
            return Err(ineligible());
        }
        live_dns_members(plan)?;
        if let Some(held) = held {
            let kept = dormant.learned.as_ref().ok_or_else(ineligible)?;
            let saved = plan.learned.as_ref().ok_or_else(ineligible)?;
            let profile = &dormant.targets.get(held).ok_or_else(ineligible)?.id;
            let mut expected = withheld(plan, Some(held))?;
            let policy = saved.routing()?;
            let retained = saved.members.iter().filter(|m| policy.zones[m.zone].tunnel_id == *profile);
            if !retained.eq(&kept.members)
                || serde_json::to_value(held_dns_policy(policy, profile)?)?
                    != serde_json::to_value(kept.routing()?)?
            {
                return Err(ineligible());
            }
            expected.learned = Some(kept.clone());
            return Ok(expected);
        }
        if plan.targets.len() != 1 {
            return Err(ineligible());
        }
        return Ok(Plan {
            killswitch: plan.killswitch,
            revision: plan.revision,
            ..Plan::default()
        });
    }
    if !literal_plan(plan, held, 1 + usize::from(held.is_some()))
        || !plan.targets.values().any(|t| t.id == id)
    {
        return Err(ineligible());
    }
    withheld(plan, held)
}

pub(super) fn parked_dns_scope(
    doc: &Value,
    journal: &Journal,
    routing: &crate::Routing,
) -> Option<MixedDnsSources> {
    let target = marked_profile(doc, journal)?["id"].as_str()?;
    let mut all = routing.clone();
    let held = journal.committed.targets.values().next()?;
    if doc["rust_static_routing"][DNS].is_null() || all.zones.len() != 2
        || journal.committed.targets.len() != 1
        || all.zones.iter().any(|zone| {
            if zone.tunnel_id == target { zone.enabled }
            else { zone.tunnel_id != held.id || !zone.enabled }
        })
    {
        return None;
    }
    for zone in &mut all.zones {
        zone.enabled = true;
    }
    mixed_dns_sources(&all).filter(|scope| scope.independent)
}

/// A cut after the first FIB writes still owns only an additive candidate.
/// Restore the exact old projection before trying the enabled target again.
pub(in crate::kernel) fn rearm_checkpoint(doc: &Value, j: &Journal) -> io::Result<Option<Journal>> {
    let [pending] = j.preparing.as_slice() else {
        return Ok(None);
    };
    let Some(RearmIntent { target, held, dns }) = rearm_intent(doc, j) else {
        return Ok(None);
    };
    let id = target["id"].as_str().ok_or_else(ineligible)?;
    let held_iface = held.map(|(iface, _)| iface);
    let held_id = held.map(|(_, id)| id);
    if !rearm_projection(pending, &j.committed, id, held_iface, dns)
        .is_ok_and(|p| p == *j.committed)
    {
        return Ok(None);
    }
    let mut checkpoint = j.clone();
    checkpoint.preparing.clear();
    let completed = Journal {
        installed: pending.clone(),
        committed: pending.clone(),
        ..checkpoint.clone()
    };
    if !profile_rebind::owner_matches_all(doc, &checkpoint, held_id, j.committed.revision)
        && !profile_rebind::owner_matches_all(
            doc,
            &completed,
            held_id.into_iter().chain([id]),
            j.committed.revision,
        )
    {
        return Ok(None);
    }
    Ok(Some(checkpoint))
}

pub(in crate::kernel) fn retain_rearm_lookups(
    k: &mut Kernel<'_>,
    doc: &Value,
    old: &Journal,
    target: &Plan,
) -> io::Result<()> {
    let Some(RearmIntent {
        target: profile,
        held: Some((held, held_id)),
        dns,
    }) = rearm_intent(doc, old)
    else {
        return Ok(());
    };
    let adding = old.preparing.is_empty()
        && profile_rebind::owner_matches(doc, old, held_id, old.committed.revision)
        && profile["id"].as_str().is_some_and(|id| {
            rearm_projection(target, &old.committed, id, Some(held), dns)
                .is_ok_and(|kept| kept == *old.committed)
        });
    let reverting = target == old.committed.as_ref() && rearm_checkpoint(doc, old)?.is_some();
    if adding || reverting {
        k.held_dns_lookups
            .extend(objects(&old.committed).into_iter().filter(Object::is_rule));
    }
    Ok(())
}

fn rearm_is_committed(doc: &Value, j: &Journal) -> bool {
    let Some(id) = marked_id(doc) else {
        return false;
    };
    j.expires == 0
        && j.preparing.is_empty()
        && j.installed == j.committed
        && j.committed.targets.values().any(|t| t.id == id)
        && profile_rebind::owner_matches_all(
            doc,
            j,
            j.committed.targets.values().map(|t| t.id.as_str()),
            j.committed.revision,
        )
}

pub(in crate::kernel) fn settle_rearm(
    tx: &Transaction<'_>,
    doc: &Value,
    j: &Journal,
) -> io::Result<bool> {
    if !rearm_is_committed(doc, j) {
        return Ok(false);
    }
    nfqws2_awg_profile::edit_document_locked(tx, |doc| {
        let owner = doc["rust_static_routing"]
            .as_object_mut()
            .ok_or_else(ineligible)?;
        owner.remove(TARGETS);
        owner.remove(DNS);
        Ok(())
    })?;
    Ok(true)
}

fn sample_rearm(
    doc: &Value,
    j: &Journal,
    id: &str,
    iface: &str,
    live: LivePeer,
) -> io::Result<ActiveReplacementPeer> {
    let Some(peer) = live.active_replacement_peer else {
        return Err(io::ErrorKind::WouldBlock.into());
    };
    if !peer.owner.valid()
        || peer.owner.boot != j.boot
        || peer.owner.nested.is_some()
        || peer.owner.id != id
        || peer.owner.iface != iface
        || peer.underlay.is_some()
        || peer.nested_only
        || peer.endpoint != live.endpoint
        || peer.socket_mark != live.socket_mark
        || !matches!(peer.socket_mark, 0 | nfqws2_awg_profile::DIRECT_SOCKET_MARK)
        || row(doc, id).is_none_or(|r| r["config"]["client"]["rust_managed"] != true)
    {
        return Err(ineligible());
    }
    Ok(*peer)
}

/// Reapply the unchanged desired revision with authenticated native owners.
/// A missing target handshake leaves the old projection and intent durable.
pub(in crate::kernel) fn rearm(
    db: &Store,
    tx: &Transaction<'_>,
    k: &Kernel<'_>,
    doc: &Value,
    j: &Journal,
    (bridges, now, firmware): (Option<&[String]>, u64, Option<&DormantFirmwareProof>),
    peer: &mut impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<bool> {
    let Some(RearmIntent { target, held, dns }) = rearm_intent(doc, j) else {
        return Ok(false);
    };
    let held_id = held.map(|(_, id)| id);
    if !j.preparing.is_empty()
        || !profile_rebind::owner_matches_all(doc, j, held_id, j.committed.revision)
        || profile_rebind::pending(doc)
        || super::super::failover_order::pending(doc)
    {
        return Ok(false);
    }
    let id = target["id"].as_str().ok_or_else(ineligible)?;
    let rows = doc["servers"].as_array().ok_or_else(ineligible)?;
    let (cfg, iface, _) = plan::profile(doc, rows, id)?;
    let (policy, names, members) = if dns {
        let (policy, _) = explicit_policy(doc, id, held_id)?;
        let names = bridges.filter(|names| !names.is_empty()).ok_or_else(ineligible)?;
        let mut receipt = DormantDns::load(doc, &policy, j.committed.revision, id)?;
        receipt.members.retain(|m| now >= receipt.saved_at && m.until > now);
        if let Some(firmware) = firmware.filter(|f| f.stamp == receipt.stamp && names == receipt.bridges) {
            let now = Instant::now();
            receipt.members.extend(receipt.firmware.into_iter().filter(|member| {
                firmware.members.get(&(member.zone, member.ip)).is_some_and(|until| *until > now)
            }));
        }
        if let Some(learned) = &j.committed.learned {
            receipt.members.extend(learned.members.iter().cloned());
            receipt.members.sort_unstable();
        }
        (policy, names, receipt.members)
    } else {
        (literal_policy(doc)?, &[][..], Vec::new())
    };
    let mut layout = j.committed.layout();
    if let Some((held_iface, _)) = held {
        layout
            .scoped_slots
            .insert(held_iface.to_owned(), j.committed.scoped_slot(held_iface));
    }
    let mut sample = || {
        let target = sample_rearm(doc, j, id, &iface, peer(cfg, &iface)?)?;
        let held = held
            .map(|(iface, id)| {
                let row = row(doc, id).ok_or_else(ineligible)?;
                sample_rearm(doc, j, id, iface, peer(&row["config"], iface)?)
            })
            .transpose()?;
        Ok::<_, io::Error>((target, held))
    };
    let peers = sample()?;
    if peers
        .1
        .as_ref()
        .is_some_and(|held| !distinct_owner(&peers.0.owner, &held.owner))
    {
        return Err(ineligible());
    }
    let plan = resolve(
        k,
        doc,
        policy,
        (&peers.0, peers.1.as_ref()),
        layout,
        &BTreeSet::new(),
        (names, &members),
    )?;
    verify_peer_for(doc, &peers.0, &plan, Some(&iface))?;
    if let Some(held) = &peers.1 {
        verify_peer_for(doc, held, &plan, Some(&held.owner.iface))?;
    }
    let held_iface = held.map(|(iface, _)| iface);
    if plan.targets.get(&iface).is_none_or(|t| t.id != id)
        || rearm_projection(&plan, &j.committed, id, held_iface, dns)? != *j.committed {
        return Err(ineligible());
    }
    if k.inventory_for(&j.claims(), &objects(&plan), true)? != objects(&j.installed) {
        // Ordinary recovery may restore missing held objects, but must not
        // activate the target on an unverified predecessor.
        return Ok(false);
    }
    k.verify_forward(&j.installed)?;
    if sample()? != peers {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    let next = Journal {
        installed: plan.clone().into(),
        committed: plan.into(),
        ..j.clone()
    };
    transition(db, tx, k.run, j, &next, None)?;
    settle_rearm(tx, &nfqws2_awg_profile::read(db)?, &next)?;
    Ok(true)
}

/// Withdraw the confirmed source's routes without a target engine. The held
/// carrier keeps its native FIB and the exact source seal owns retirement.
pub fn replace_active_profile_with_disabled_target(
    db: &Store,
    tx: &Transaction<'_>,
    run: &dyn Runner,
    (before, after): (&Value, &Value),
    (target, peers, wan): (
        &str,
        (&ActiveReplacementPeer, Option<&ActiveReplacementPeer>),
        &[String],
    ),
    verify: &dyn Fn() -> io::Result<()>,
    before_write: impl FnOnce() -> io::Result<()>,
) -> io::Result<Option<String>> {
    let prior = Journal::read(db)?;
    let (source, held) = peers;
    let target = Target {
        id: target.to_owned(),
        iface: disabled_active_replacement_target(before, target)?.ok_or_else(ineligible)?,
    };
    if active_replacement_in_progress(db)?
        || super::super::mtu_edit::pending_mtu_edit(db)?
        || profile_rebind::pending(before)
        || handoff::pending(db)?
        || !profile_rebind::owner_matches_all(
            before,
            &prior,
            std::iter::once(source.owner.id.as_str())
                .chain(held.map(|held| held.owner.id.as_str())),
            prior.committed.revision,
        )
        || !before["rust_static_routing"][TARGETS].is_null()
        || before["rust_static_routing"] != after["rust_static_routing"]
        || active_replacement_topology(before, after, &source.owner.id, &target.id)?
    {
        return Err(ineligible());
    }
    let learned = prior.installed.learned.is_some();
    let policy = transfer_policy(before, after, &source.owner.id, &target, (held.is_some(), learned))?;
    let k = kernel(run);
    let retained = if let Some(held) = held.filter(|_| learned) {
        cold_launch_target(&prior, Some(&held.owner))?;
        let (policy, _) = explicit_policy(after, &target.id, Some(&held.owner.id))?;
        let policy = held_dns_policy(policy, &held.owner.id)?;
        let members = live_dns_members(&prior.installed)?.iter().filter(|member| {
            policy.zones[member.zone].enabled
        }).cloned().collect::<Vec<_>>();
        let mut layout = prior.installed.layout();
        layout.keep_global_scoped = true;
        layout.scoped_slots.insert(held.owner.iface.clone(), prior.installed.scoped_slot(&held.owner.iface));
        Some(resolve(
            &k, after, policy, (held, None), layout, &BTreeSet::new(),
            (&prior.installed.dns_bridges, &members),
        )?)
    } else {
        None
    };
    let next = projection(
        &prior, &source.owner, held.map(|held| &held.owner), &target.id, retained.as_ref(),
    )?;
    if after["routing_revision"].as_u64() != Some(next.committed.revision) {
        return Err(ineligible());
    }
    let target_iface = target.iface.clone();
    let verify = || {
        verify()?;
        if super::super::routed_disable::link_names(&k)?.contains(&target_iface) {
            return Err(ineligible());
        }
        Ok(())
    };
    verify_peer_for(before, source, &prior.installed, Some(&source.owner.iface))?;
    mtu_edit::replacement_wan(&k, source.endpoint, source.socket_mark, wan)?;
    if let Some(held) = held {
        verify_peer_for(before, held, &prior.installed, Some(&held.owner.iface))?;
        mtu_edit::replacement_wan(&k, held.endpoint, held.socket_mark, wan)?;
    }
    if resolve(
        &k,
        before,
        policy,
        (source, held),
        prior.installed.layout(),
        &BTreeSet::new(),
        (&prior.installed.dns_bridges, live_dns_members(&prior.installed)?),
    )? != *prior.committed
        || boot_id(&k)? != prior.boot
        || k.inventory_for(&prior.claims(), &objects(&next.installed), true)?
            != objects(&prior.installed)
    {
        return Err(ineligible());
    }
    k.verify_forward(&prior.installed)?;

    let mut switched = before.clone();
    stamp_document(&mut switched, &next)?;
    let mut candidate = after.clone();
    candidate["rust_static_routing"][TARGETS] = json!([target.id]);
    let mut transfer = Transfer {
        prior,
        next,
        source: source.owner.clone(),
        source_fingerprint: source.fingerprint,
        disabled_target: Some(target),
        retained_outer: None,
        held_direct: held.map(|held| HeldDirect {
            owner: held.owner.clone(),
            fingerprint: held.fingerprint,
            wan: wan.to_vec(),
        }),
        nested_target: None,
        retiring_nested: None,
        temporary_stop: None,
        token: String::new(),
        retry_runtime: false,
        retry_dns: None,
        retry_projection: None,
        retry_positive_hint: None,
        retry_negative_name: None,
        retry_positive_pair: None,
        retired: false,
    };
    transfer.token = token_for(&transfer)?;
    validate(&transfer)?;
    if learned {
        DormantDns::save(&mut candidate, &transfer, &transfer.disabled_target.as_ref().ok_or_else(ineligible)?.id)?;
    }
    stamp_document(&mut candidate, &transfer.next)?;
    candidate[FIELD] = json!({"id": transfer.source.id, "token": transfer.token, "disabled_target": transfer.disabled_target});
    verify()?;
    before_write()?;
    save(tx, &transfer)?;
    let result = (|| {
        transition(db, tx, run, &transfer.prior, &transfer.next, None)?;
        verify()?;
        persist_active_replacement_locked(db, tx, &switched, &candidate)
    })();
    if let Err(error) = result {
        let mut current = Journal::read(db)?;
        let doc = nfqws2_awg_profile::read(db)?;
        if current == transfer.next && doc == candidate {
            return Ok(Some(
                "перенос правил подтверждён после ошибки записи".to_owned(),
            ));
        }
        recover_original(tx, db, run, &mut current, &transfer, &doc, |_| {
            Ok(held.cloned())
        })?;
        return Err(error);
    }
    result
}

/// Confirm the installed learner being withdrawn, with no new DNS results.
pub fn disabled_replacement_dns_redirects(
    db: &Store,
    source: &str,
) -> io::Result<Option<(u64, Vec<String>)>> {
    let journal = Journal::read(db)?;
    if journal.installed.learned.is_none() {
        return Ok(None);
    }
    let (_, owner) = replacement_route_target(&journal)?;
    if owner.id != source {
        return Err(ineligible());
    }
    Ok(Some((
        journal.installed.revision,
        journal.installed.dns_bridges.clone(),
    )))
}
