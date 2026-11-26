//! Read-only authorization for reconnecting an unchanged named direct peer.
use super::*;
use nfqws2_awg_profile::{named_reconnect_profile, NamedReconnectTarget};

/// Classify the exact stored profile before doing bounded DNS work off-lock.
pub fn named_reconnect_revision(
    db: &Store,
    id: &str,
    iface: &str,
    raw: &str,
) -> io::Result<Option<u64>> {
    db.transaction(|_| {
        let journal = Journal::read(db)?;
        let doc = nfqws2_awg_profile::read(db)?;
        revision(db, &doc, &journal, id, iface, raw)
    })
}

fn revision(
    db: &Store,
    doc: &Value,
    journal: &Journal,
    id: &str,
    iface: &str,
    raw: &str,
) -> io::Result<Option<u64>> {
    if let Some(revision) =
        active_replacement::deferred_named_reconnect_revision(db, doc, journal, (id, iface, raw))?
    {
        return Ok(Some(revision));
    }
    let owns = |plan: &Plan| plan.targets.values().any(|target| target.id == id);
    if !address::explicit(journal)
        || !std::iter::once(&journal.committed)
            .chain(std::iter::once(&journal.installed))
            .chain(&journal.preparing)
            .any(|plan| owns(plan))
    {
        return Ok(None);
    }
    let changed = || io::Error::from(io::ErrorKind::WouldBlock);
    let saved = journal.committed.revision;
    let meta = &doc["rust_static_routing"];
    if journal.expires != 0
        || !journal.preparing.is_empty()
        || journal.boot.is_empty()
        || journal.installed.revision != saved
        || journal.committed.local_sources != journal.installed.local_sources
        || doc["routing_revision"].as_u64().unwrap_or_default() != saved
        || meta["revision"].as_u64() != Some(saved)
        || meta["committed_revision"]
            .as_u64()
            .or_else(|| meta["revision"].as_u64())
            != Some(saved)
        || meta["pending_commit"] != false
        || meta["go_trial"] == true
        || read(db)?.is_some()
        || saved_profile(doc, journal)?.is_some()
    {
        return Err(changed());
    }
    let rows = doc["servers"].as_array().ok_or_else(changed)?;
    let row = rows
        .iter()
        .find(|row| row["id"] == id)
        .ok_or_else(changed)?;
    if !named_reconnect_profile(row, raw) {
        return Err(changed());
    }
    let (_, expected_iface, target) = plan::profile(doc, rows, id)?;
    if expected_iface != iface
        || target.public_key.is_empty()
        || journal.committed.targets.get(iface) != Some(&target)
        || journal.installed.targets.get(iface) != Some(&target)
    {
        return Err(changed());
    }
    Ok(Some(saved))
}

/// Check the fixed DNS answer against both route generations and the actual
/// WAN while the routing operation still holds the previous process in place.
pub fn validate_named_reconnect(
    db: &Store,
    run: &dyn Runner,
    target: NamedReconnectTarget<'_>,
    wan: &[String],
) -> io::Result<()> {
    target.validate()?;
    db.transaction(|_| {
        let j = Journal::read(db)?;
        let doc = nfqws2_awg_profile::read(db)?;
        if active_replacement::validate_deferred_named_reconnect(db, run, &doc, &j, &target, wan)? {
            return Ok(());
        }
        if revision(db, &doc, &j, target.id, target.iface, target.raw)? != Some(target.revision) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if let Some(saved) = &j.committed.local_sources {
            let effective = crate::sources::current(db, &doc)?;
            if crate::sources::Generation::from_policy(&doc, &effective)?.as_ref() != Some(saved) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
        }
        // Compare the new IPs with static, source-scoped, learned, and eager
        // destinations without resolving this or any unrelated endpoint again.
        for address in target.addresses {
            address::check_plans(&j, address.ip())?;
        }
        let k = kernel_for_transition(run, db, &j, &j.installed)?;
        if j.boot != boot_id(&k)? || k.inventory(&j.claims(), true)? != objects(&j.installed) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        address::verify_wan(&k, target.selected.ip(), wan)
    })
}
