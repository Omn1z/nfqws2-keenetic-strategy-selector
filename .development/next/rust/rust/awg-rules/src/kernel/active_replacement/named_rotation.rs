//! A new transport address does not change the deferred profile or route ownership.
use super::*;
use nfqws2_awg_profile::{
    active_named_replacement_fingerprint, resolve_active_named_replacement,
    validate_active_named_replacement, NamedReconnectTarget,
};
use std::time::Duration;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Rotation {
    answers: Vec<SocketAddr>,
    owner: NativeRemovalSeal,
    stamp: String,
}

impl Rotation {
    fn stamp(&self, token: &str) -> io::Result<String> {
        profile_rebind::digest(&(
            token,
            &self.owner,
            &self.answers,
            "deferred named transport",
        ))
    }

    pub(super) fn validate(&self, transfer: &Transfer) -> io::Result<()> {
        let scope = scope(transfer).ok_or_else(ineligible)?;
        scope.names.rotated_target(&self.answers)?;
        if !self.owner.valid()
            || self.owner.id != scope.id
            || self.owner.iface != scope.iface
            || self.owner.nested.is_some()
            || self.owner.boot == transfer.source.boot
                && !distinct_owner(&self.owner, &transfer.source)
            || self.stamp != self.stamp(&transfer.token)?
        {
            return Err(ineligible());
        }
        Ok(())
    }

    pub(super) fn names(&self, original: &SealedTransportPair) -> io::Result<SealedTransportPair> {
        original.rotated_target(&self.answers)
    }

    pub(super) fn matches(&self, owner: &NativeRemovalSeal) -> bool {
        self.owner == *owner
    }
}

struct Scope<'a> {
    id: &'a str,
    iface: &'a str,
    raw: &'a str,
    stop: &'a TemporaryStop,
    names: &'a SealedTransportPair,
}

fn scope(transfer: &Transfer) -> Option<Scope<'_>> {
    let stop = transfer.temporary_stop.as_ref()?;
    if !stop.deferred_launch
        || stop.target_owner.is_some()
        || stop.transport_policy.is_some()
        || transfer.disabled_target.is_some()
        || transfer.held_direct.is_some()
        || transfer.nested_target.is_some()
        || transfer.retained_outer.is_some()
        || transfer.retiring_nested.is_some()
        || transfer.retry_runtime
        || transfer.retry_dns.is_some()
        || profile_rebind::native_ipv4_prefixes(&transfer.prior).is_err()
    {
        return None;
    }
    let (iface, target) = profile_rebind::native_ipv4_prefixes(&transfer.next).ok()?;
    let names = stop.named.as_ref()?;
    Some(Scope {
        id: &target.id,
        iface,
        raw: names.target_name()?,
        stop,
        names,
    })
}

fn saved_checkpoint(
    doc: &Value,
    journal: &Journal,
    transfer: &Transfer,
    scope: &Scope<'_>,
) -> io::Result<()> {
    let pending = &doc["rust_static_routing"];
    let revision = journal.committed.revision;
    let mut checkpoint = deferred_launch_checkpoint(&transfer.next, None);
    checkpoint.boot.clone_from(&journal.boot);
    if scope.stop.released
        || scope.stop.teardown
        || !committed(doc, transfer)
        || *journal != checkpoint
        || journal.boot.is_empty()
        || doc["routing_revision"].as_u64() != Some(revision)
        || pending["committed_revision"].as_u64() != Some(revision)
        || pending["pending_commit"] != false
        || pending["go_trial"] == true
        || row(doc, scope.id).and_then(|row| row["config"]["endpoint"].as_str()) != Some(scope.raw)
        || active_named_replacement_fingerprint(doc, scope.id).ok()
            != Some(scope.stop.target_fingerprint)
    {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    Ok(())
}

/// Preserve the normal two-pass reconnect for the deliberately empty KS-off
/// checkpoint, as well as the guard-only KS-on checkpoint.
pub(in crate::kernel) fn reconnect_revision(
    db: &Store,
    doc: &Value,
    journal: &Journal,
    (id, iface, raw): (&str, &str, &str),
) -> io::Result<Option<u64>> {
    let Some(transfer) = read(db)? else {
        return Ok(None);
    };
    let Some(scope) = scope(&transfer).filter(|scope| {
        scope.id == id && scope.iface == iface && scope.raw == raw && !scope.stop.released
    }) else {
        return Ok(None);
    };
    saved_checkpoint(doc, journal, &transfer, &scope)?;
    if mtu_edit::pending_mtu_edit(db)? {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    Ok(Some(journal.committed.revision))
}

fn verify_inventory(k: &Kernel<'_>, journal: &Journal) -> io::Result<()> {
    if journal.boot != boot_id(k)?
        || k.inventory(&journal.claims(), true)? != objects(&journal.installed)
    {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    k.verify_forward(&journal.installed)
}

fn check_claims(
    k: &Kernel<'_>,
    doc: &Value,
    journal: &Journal,
    transfer: &Transfer,
    names: &SealedTransportPair,
) -> io::Result<()> {
    let mut endpoints = BTreeSet::new();
    plan::visit_transport_endpoints(
        doc,
        false,
        (None, Some(&names.claims)),
        |_| true,
        |_, _, ip| {
            endpoints.insert(ip);
        },
    )?;
    transfer.prior.committed.check_endpoints(&endpoints)?;
    transfer.next.committed.check_endpoints(&endpoints)?;
    k.guard(&journal.installed, &endpoints)
}

/// A launch only checks paths while the payload stays parked. A fresh native
/// handshake and a second complete lookup authorize any new forwarding.
pub(in crate::kernel) fn validate_reconnect(
    db: &Store,
    run: &dyn Runner,
    doc: &Value,
    journal: &Journal,
    target: &NamedReconnectTarget<'_>,
    wan: &[String],
) -> io::Result<bool> {
    let Some(transfer) = read(db)? else {
        return Ok(false);
    };
    let Some(scope) = scope(&transfer).filter(|scope| {
        scope.id == target.id
            && scope.iface == target.iface
            && scope.raw == target.raw
            && !scope.stop.released
    }) else {
        return Ok(false);
    };
    saved_checkpoint(doc, journal, &transfer, &scope)?;
    let names = scope.names.rotated_target(target.addresses)?;
    if target.revision != journal.committed.revision
        || Some(target.selected) != names.selected(true)
        || scope.stop.wan != wan
        || mtu_edit::pending_mtu_edit(db)?
    {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    let k = transfer_kernel(run, db)?;
    verify_inventory(&k, journal)?;
    check_claims(&k, doc, journal, &transfer, &names)?;
    mtu_edit::replacement_wan(&k, target.selected, 0, wan)?;
    Ok(true)
}

/// An off-lock fresh lookup for the exact deferred profile and its current
/// native owner. Only verified recovery can turn it into a durable witness.
pub struct DeferredNamedRotation {
    token: String,
    owner: NativeRemovalSeal,
    answers: Vec<SocketAddr>,
    until: Instant,
}

pub fn prepare_deferred_named_rotation(
    db: &Store,
    peer: impl FnOnce(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<Option<DeferredNamedRotation>> {
    prepare(db, peer, resolve_active_named_replacement)
}

fn prepare(
    db: &Store,
    peer: impl FnOnce(&Value, &str) -> io::Result<LivePeer>,
    resolve: impl FnOnce(&Value, &str, Instant) -> io::Result<Vec<SocketAddr>>,
) -> io::Result<Option<DeferredNamedRotation>> {
    let Some(transfer) = read(db)? else {
        return Ok(None);
    };
    let Some(scope) = scope(&transfer).filter(|scope| !scope.stop.released && !scope.stop.teardown)
    else {
        return Ok(None);
    };
    let doc = nfqws2_awg_profile::read(db)?;
    let journal = Journal::read(db)?;
    if saved_checkpoint(&doc, &journal, &transfer, &scope).is_err() {
        return Ok(None);
    }
    let configured = &row(&doc, scope.id).ok_or_else(ineligible)?["config"];
    let Some(live) = peer(configured, scope.iface).ok() else {
        return Ok(None);
    };
    let Some(native) = live.active_replacement_peer.as_deref() else {
        return Ok(None);
    };
    if native.owner.id != scope.id
        || native.owner.iface != scope.iface
        || native.owner.boot != journal.boot
        || native.fingerprint != scope.stop.target_fingerprint
        || native.endpoint != live.endpoint
        || native.socket_mark != live.socket_mark
        || native.owner.nested.is_some()
        || native.underlay.is_some()
        || native.nested_only
    {
        return Ok(None);
    }
    if scope.stop.rotation.is_none() && scope.names.selected(true) == Some(native.endpoint) {
        return Ok(None);
    }
    let until = Instant::now() + Duration::from_secs(12);
    let answers = resolve(&doc, scope.id, until)?;
    validate_active_named_replacement(&doc, scope.id, &answers)?;
    if scope.names.rotated_target(&answers)?.selected(true) != Some(native.endpoint) {
        return Ok(None);
    }
    let proof = DeferredNamedRotation {
        token: transfer.token,
        owner: native.owner.clone(),
        answers,
        until,
    };
    proof.check_expiry()?;
    Ok(Some(proof))
}

impl DeferredNamedRotation {
    fn check_expiry(&self) -> io::Result<()> {
        if Instant::now() >= self.until {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(())
    }
}

pub fn resume_deferred_named_rotation(
    db: &Store,
    run: &dyn Runner,
    proof: &DeferredNamedRotation,
    wan: &[String],
    mut peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<()> {
    db.transaction(|tx| {
        proof.check_expiry()?;
        let mut transfer = read(db)?.ok_or_else(ineligible)?;
        let doc = nfqws2_awg_profile::read(db)?;
        let mut journal = Journal::read(db)?;
        let scope = scope(&transfer).ok_or_else(ineligible)?;
        saved_checkpoint(&doc, &journal, &transfer, &scope)?;
        if proof.token != transfer.token || scope.stop.wan != wan || mtu_edit::pending_mtu_edit(db)?
        {
            return Err(io::ErrorKind::Interrupted.into());
        }
        validate_active_named_replacement(&doc, scope.id, &proof.answers)?;
        let k = transfer_kernel(run, db)?;
        verify_inventory(&k, &journal)?;
        let mut rotation = Rotation {
            answers: proof.answers.clone(),
            owner: proof.owner.clone(),
            stamp: String::new(),
        };
        rotation.stamp = rotation.stamp(&transfer.token)?;
        rotation.validate(&transfer)?;
        let names = rotation.names(scope.names)?;
        check_claims(&k, &doc, &journal, &transfer, &names)?;
        transfer
            .temporary_stop
            .as_mut()
            .ok_or_else(ineligible)?
            .rotation = Some(rotation);
        let mut wanted = transfer.next.clone();
        wanted.boot.clone_from(&journal.boot);
        if !check_temporary_peer(&k, &doc, &wanted, &transfer, true, &mut peer)? {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        proof.check_expiry()?;
        // The earlier token remains the only profile publication marker. This
        // supplemental receipt binds the newly selected address to one exact
        // live native engine; a replacement owner needs another fresh lookup.
        save(tx, &transfer)?;
        recover_temporary(
            db,
            tx,
            run,
            &mut journal,
            &mut transfer,
            &doc,
            (
                Some(&mut peer),
                Some(TemporaryProof::Named(&|| proof.check_expiry())),
            ),
        )
    })
}
