//! Distinguish sole literal primaries from addresses with other transport claims.
use super::{mtu_edit::canonical_socket, plan, LivePeer, Plan};
use nfqws2_awg_profile::DIRECT_SOCKET_MARK;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::{IpAddr, SocketAddr},
};

#[derive(Default)]
pub(super) struct Claims(BTreeMap<IpAddr, Claim>);

struct Claim {
    owner: Option<String>,
    primary: Option<SocketAddr>,
    multiple: bool,
}

impl Claims {
    pub fn read(
        doc: &Value,
        plan: &Plan,
        resolve_names: bool,
        active: Option<&nfqws2_awg_profile::RoutedMtuChange>,
    ) -> io::Result<Self> {
        Self::read_with_names(doc, plan, resolve_names, (active, None))
    }

    pub fn read_with_names(
        doc: &Value,
        plan: &Plan,
        resolve_names: bool,
        pins: (
            Option<&nfqws2_awg_profile::RoutedMtuChange>,
            Option<&super::NamedTransportClaims>,
        ),
    ) -> io::Result<Self> {
        let mut ips = BTreeMap::new();
        let explicit = explicit(plan);
        plan::visit_transport_endpoints(
            doc,
            resolve_names,
            pins,
            |_| true,
            |row, primary, ip| {
                let owner = row["id"].as_str().filter(|_| explicit);
                ips.entry(ip)
                    .and_modify(|claim: &mut Claim| {
                        claim.primary = None;
                        claim.multiple = true;
                        if claim.owner.as_deref() != owner {
                            claim.owner = None;
                        }
                    })
                    .or_insert_with(|| Claim {
                        owner: owner.map(str::to_owned),
                        primary: primary.filter(|_| explicit).and_then(canonical_socket),
                        multiple: false,
                    });
            },
        )?;
        Ok(Self(ips))
    }

    pub fn addresses(&self) -> BTreeSet<IpAddr> {
        self.0.keys().copied().collect()
    }

    pub fn sole_primary(&self, id: &str, endpoint: SocketAddr) -> bool {
        self.0.get(&endpoint.ip()).is_some_and(|claim| {
            claim.owner.as_deref() == Some(id) && claim.primary == Some(endpoint)
        })
    }

    pub fn solely_owned_by(&self, ip: IpAddr, id: &str) -> bool {
        self.0
            .get(&ip)
            .is_some_and(|claim| claim.owner.as_deref() == Some(id))
    }

    pub fn sole_claim_by(&self, ip: IpAddr, id: &str) -> bool {
        self.0
            .get(&ip)
            .is_some_and(|claim| !claim.multiple && claim.owner.as_deref() == Some(id))
    }
}

pub(super) fn explicit(plan: &Plan) -> bool {
    plan.full_endpoints.is_none() && plan.legacy_full.is_none() && !plan.ordered_default
}

/// Verify the selected reserve against the current row and sampled peer. The
/// native witness owns the daemon fingerprint and the selected marked WAN.
pub(super) fn dormant_direct_primary(
    row: &Value,
    iface: &str,
    live: &LivePeer,
    mtu: u16,
) -> Option<SocketAddr> {
    let witness = live.direct_backup.as_ref()?;
    let endpoint = canonical_socket(live.endpoint)?;
    let primary = canonical_socket(witness.primary)?;
    let peer = &witness.peer;
    if endpoint.ip() == primary.ip()
        || !matches!(live.socket_mark, 0 | DIRECT_SOCKET_MARK)
        || live.nested_mtu.is_some()
        || canonical_socket(peer.endpoint) != Some(endpoint)
        || peer.iface != iface
        || peer.socket_mark != live.socket_mark
        || peer.effective_mtu != mtu
        || !peer.outer_id.is_empty()
        || !peer.outer_iface.is_empty()
    {
        return None;
    }
    let pool = nfqws2_awg_profile::routing_direct_backup_pool(row).ok()?;
    (pool.first().copied() == Some(primary) && pool[1..].contains(&endpoint)).then_some(primary)
}
