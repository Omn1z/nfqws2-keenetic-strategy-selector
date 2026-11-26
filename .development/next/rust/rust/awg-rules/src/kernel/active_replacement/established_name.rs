//! Reassert an already committed native route using its exact live transport.
//! The recorded addresses are collision claims. They cannot launch a client.
use super::named::SealedTransportPair;
use super::{
    attested_peer, boot_id, ineligible, mtu_edit, objects, plan, profile_rebind, row,
    verify_peer_bound, Journal, Kernel, LivePeer, NativeRemovalSeal, Runner, Store, Transaction,
    Transfer, LAUNCH_LIMIT,
};
use nfqws2_awg_profile::{active_named_replacement_fingerprint, DIRECT_SOCKET_MARK};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{io, net::SocketAddr};

const FILE: &str = "awg-established-warm-name.json";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attachment {
    source: String,
    source_fingerprint: [u8; 32],
    owner: NativeRemovalSeal,
    fingerprint: [u8; 32],
    transport: SealedTransportPair,
    wan: Vec<String>,
    committed: String,
}

impl Attachment {
    fn matches(
        &self,
        journal: &Journal,
        (iface, id, fingerprint): (&str, &str, [u8; 32]),
    ) -> io::Result<bool> {
        Ok(journal.boot == self.owner.boot
            && iface == self.owner.iface
            && id == self.owner.id
            && self.owner.valid()
            && self.owner.nested.is_none()
            && self.fingerprint != [0; 32]
            && self.fingerprint == fingerprint
            && self.transport.is_warm_ipv6()
            && self.transport.binds([
                (&self.source, &self.source_fingerprint),
                (&self.owner.id, &self.fingerprint),
            ])
            && profile_rebind::digest(&journal.committed)? == self.committed)
    }

    fn owned_live(&self, live: &LivePeer) -> bool {
        live.active_replacement_peer
            .as_deref()
            .is_some_and(|native| {
                native.owner == self.owner
                    && native.fingerprint == self.fingerprint
                    && native.underlay.is_none()
                    && Some(native.endpoint) == self.transport.selected(true)
                    && native.endpoint == live.endpoint
                    && native.socket_mark == DIRECT_SOCKET_MARK
                    && native.socket_mark == live.socket_mark
            })
    }
}

fn geometry<'a>(journal: &'a Journal, doc: &Value) -> Option<(&'a str, &'a str, [u8; 32])> {
    let (iface, target) = profile_rebind::native_ipv4_prefixes(journal).ok()?;
    let revision = journal.committed.revision;
    if doc["active_id"] != target.id
        || !doc["servers"]
            .as_array()
            .is_some_and(|rows| rows.len() == 1)
        || doc["routing_revision"] != revision
        || profile_rebind::pending(doc)
        || super::super::failover_order::pending(doc)
        || !profile_rebind::owner_matches(doc, journal, &target.id, revision)
    {
        return None;
    }
    let fingerprint = active_named_replacement_fingerprint(doc, &target.id).ok()?;
    Some((iface, &target.id, fingerprint))
}

pub(super) fn remember(
    tx: &Transaction<'_>,
    journal: &Journal,
    doc: &Value,
    transfer: &Transfer,
) -> io::Result<()> {
    let Some(stop) = transfer
        .temporary_stop
        .as_ref()
        .filter(|stop| stop.released && !stop.teardown)
    else {
        return Ok(());
    };
    let (Some(owner), Some(transport)) = (&stop.target_owner, &stop.named) else {
        return Ok(());
    };
    if !transport.is_warm_ipv6() || journal.committed != transfer.next.committed {
        return Ok(());
    }
    let Some(geometry) = geometry(journal, doc) else {
        return Ok(());
    };
    let attachment = Attachment {
        source: transfer.source.id.clone(),
        source_fingerprint: transfer.source_fingerprint,
        owner: owner.clone(),
        fingerprint: stop.target_fingerprint,
        transport: transport.clone(),
        wan: stop.wan.clone(),
        committed: profile_rebind::digest(&journal.committed)?,
    };
    if attachment.matches(journal, geometry)? {
        // The transfer can still be replayed if publication of the attachment
        // or the later removal of the transfer receipt is interrupted.
        tx.save_runtime_bounded(FILE, &attachment, LAUNCH_LIMIT)?;
    }
    Ok(())
}

fn read(db: &Store, journal: &Journal, doc: &Value) -> io::Result<Option<Attachment>> {
    if doc.get(super::FIELD).is_some() {
        return Ok(None);
    }
    let Some(geometry) = geometry(journal, doc) else {
        return Ok(None);
    };
    let attachment: Attachment = match db.read_runtime(FILE, LAUNCH_LIMIT) {
        Ok(attachment) => attachment,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::InvalidData
            ) =>
        {
            return Ok(None)
        }
        Err(error) => return Err(error),
    };
    Ok(attachment.matches(journal, geometry)?.then_some(attachment))
}

pub fn established_warm_owner(
    db: &Store,
    iface: &str,
    endpoint: SocketAddr,
    wan: &[String],
) -> io::Result<Option<NativeRemovalSeal>> {
    let mut journal = Journal::read(db)?;
    match journal.preparing.as_slice() {
        [] => {}
        [same] if same == &journal.installed => journal.preparing.clear(),
        [same, fallback]
            if same == &journal.installed
                && fallback.as_ref() == &journal.installed.guards_only() =>
        {
            journal.preparing.clear()
        }
        _ => return Ok(None),
    }
    // The authorized writer rechecks its live owner after saving one exact
    // intent. Merely reading the owner here confers no route authority.
    let doc = nfqws2_awg_profile::read(db)?;
    Ok(read(db, &journal, &doc)?
        .filter(|attachment| {
            attachment.owner.iface == iface
                && attachment.wan == wan
                && attachment.transport.selected(true) == Some(endpoint)
        })
        .map(|attachment| attachment.owner))
}

pub fn established_warm_client(db: &Store, server: Option<&str>) -> io::Result<bool> {
    Ok(
        read(db, &Journal::read(db)?, &nfqws2_awg_profile::read(db)?)?
            .is_some_and(|attachment| server.is_none_or(|id| attachment.owner.id == id)),
    )
}

pub(in crate::kernel) fn clear(tx: &Transaction<'_>) -> io::Result<()> {
    tx.delete_runtime(FILE)
}

pub(in crate::kernel) fn reassert(
    db: &Store,
    tx: &Transaction<'_>,
    (run, k): (&dyn Runner, &Kernel<'_>),
    doc: &Value,
    journal: &Journal,
    mut peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<bool> {
    let Some(attachment) = read(db, journal, doc)? else {
        return Ok(false);
    };
    if boot_id(k)? != attachment.owner.boot {
        return Ok(false);
    }
    let iface = &attachment.owner.iface;
    let config = &row(doc, &attachment.owner.id).ok_or_else(ineligible)?["config"];
    let Ok(live) = peer(config, iface) else {
        return Ok(false);
    };
    if !attachment.owned_live(&live) {
        return Ok(false);
    }
    let native = live
        .active_replacement_peer
        .as_deref()
        .ok_or_else(ineligible)?;
    verify_peer_bound(
        doc,
        native,
        &journal.committed,
        None,
        (Some(&attachment.transport.claims), false),
    )?;
    for &endpoint in attachment.transport.warm_target_addresses() {
        mtu_edit::replacement_wan(k, endpoint, DIRECT_SOCKET_MARK, &attachment.wan)?;
    }
    let resolution = plan::resolve_with_mtu_edit(
        doc,
        journal.committed.as_ref().clone(),
        true,
        None,
        Some(plan::Verification::Refresh(k)),
        plan::EditContext::NamedReplacement(&attachment.transport.claims),
        |_, requested| {
            if requested != iface {
                return Err(ineligible());
            }
            attested_peer(native, requested)
        },
    )?;
    if resolution.plan != *journal.committed {
        return Err(ineligible());
    }
    k.guard(&resolution.plan, &resolution.endpoints)?;
    if k.inventory(&journal.claims(), true)? != objects(&journal.installed) {
        super::super::reassert_with_owner(db, tx, run, journal, &mut || {
            let current = peer(config, iface)?;
            if !attachment.owned_live(&current)
                || current.active_replacement_peer != live.active_replacement_peer
            {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            mtu_edit::replacement_wan(k, current.endpoint, DIRECT_SOCKET_MARK, &attachment.wan)
        })?;
    } else {
        k.verify_ipv6_reject(&journal.installed)?;
        super::super::acceleration::audit(db, tx, k, &journal.installed)?;
    }
    Ok(true)
}
