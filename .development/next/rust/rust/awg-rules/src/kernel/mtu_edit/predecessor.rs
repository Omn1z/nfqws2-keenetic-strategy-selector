//! The previous owned daemon can retain confirmed routes before the first park.
use super::*;
use nfqws2_awg_profile::DIRECT_SOCKET_MARK;
use std::net::IpAddr;

pub(in super::super) struct Predecessor {
    pub change: RoutedMtuChange,
    endpoints: BTreeSet<SocketAddr>,
    pub future: BTreeSet<IpAddr>,
}

pub(in super::super) fn pending_predecessor(
    db: &Store,
    doc: &Value,
    journal: &Journal,
) -> io::Result<Option<Predecessor>> {
    if journal.expires != 0
        || !journal.preparing.is_empty()
        || !address::explicit(journal)
        || read(db)?.is_some()
    {
        return Ok(None);
    }
    let Some(authority) = saved_profile(doc, journal)? else {
        return Ok(None);
    };
    let change = authority.change;
    let Some((before, after)) = edit_endpoints(&change) else {
        return Ok(None);
    };
    let row = doc["servers"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|row| row["id"] == change.id)
        .ok_or_else(invalid)?;
    if change.nested_outer.is_some()
        || change.legacy_predecessor.is_some()
        || change.combines_endpoint_mtu()
        || named(&change)
        || nfqws2_awg_profile::routed_endpoint_predecessor_change(doc, row)?.as_ref()
            != Some(&change)
    {
        return Ok(None);
    }
    let Some(candidates) = nfqws2_awg_profile::routing_direct_literal_pool(row)? else {
        return Ok(None);
    };
    if candidates.first().copied() != Some(after) {
        return Err(invalid());
    }
    let mut previous = row.clone();
    previous["config"]["endpoint"] =
        json!(change.endpoint_edit.as_ref().ok_or_else(invalid)?.before);
    let candidates_before =
        nfqws2_awg_profile::routing_direct_literal_pool(&previous)?.ok_or_else(invalid)?;
    if candidates_before.first().copied() != Some(before) {
        return Err(invalid());
    }
    let future: BTreeSet<_> = candidates
        .into_iter()
        .map(|endpoint| endpoint.ip())
        .collect();
    for &ip in &future {
        address::check_plans(journal, ip)?;
    }
    Ok(Some(Predecessor {
        change,
        endpoints: candidates_before.into_iter().collect(),
        future,
    }))
}

impl Predecessor {
    pub fn verify(&self, live: &LivePeer, iface: &str, mtu: u16) -> io::Result<()> {
        let witness = live.endpoint_predecessor.as_ref().ok_or_else(invalid)?;
        let peer = &witness.peer;
        let endpoint = canonical_socket(live.endpoint)
            .filter(|endpoint| self.endpoints.contains(endpoint))
            .ok_or_else(invalid)?;
        if witness.edit != self.change
            || peer.iface != iface
            || canonical_socket(peer.endpoint) != Some(endpoint)
            || peer.socket_mark != live.socket_mark
            || !matches!(live.socket_mark, 0 | DIRECT_SOCKET_MARK)
            || live.nested_mtu.is_some()
            || !peer.outer_id.is_empty()
            || !peer.outer_iface.is_empty()
            || peer.effective_mtu != mtu
            || mtu != self.change.before
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub fn park(
        &self,
        db: &Store,
        tx: &Transaction<'_>,
        k: &Kernel<'_>,
        journal: &Journal,
    ) -> io::Result<()> {
        if !journal.installed.empty() {
            return park_target(db, tx, k, journal, &self.change.iface, None);
        }
        if journal.committed.has_protection() {
            let mut plan = journal.committed.guards_only();
            if !plan.empty() {
                k.select_firewall(&mut plan)?;
                k.guard(&plan, &BTreeSet::new())?;
                let mut next = journal.clone();
                next.installed = plan.into();
                transition(db, tx, k.run, journal, &next, None)?;
            }
        }
        Ok(())
    }
}
