//! Durable routing authorization for a saved MTU or endpoint edit.
use super::*;
use nfqws2_awg_profile::{RoutedEndpointLaunch, RoutedMtuChange, RoutedMtuPeer};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
mod address;
mod dual;
mod predecessor;
mod reconnect;
mod retry;
pub use dual::legacy_dual_probe_target;
pub(super) use dual::{dual_probe_phase, legacy_dual_reject_wan};
pub(super) use predecessor::{pending_predecessor, Predecessor};
pub use reconnect::{named_reconnect_revision, validate_named_reconnect};
pub use retry::{
    pending_endpoint_launch, pending_endpoint_retry, pending_endpoint_retry_with_wan,
    prepare_endpoint_retry,
};

const FILE: &str = "awg-routed-mtu.json";
const LIMIT: u64 = 4096;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Authority {
    change: RoutedMtuChange,
    public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    outer_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recorded_nested_primary: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    endpoint_committed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retry_endpoint: Option<SocketAddr>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    full_endpoint_staged: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    keep_full_ipv6_fenced: bool,
}

struct Profile {
    mtu: u16,
    marker: Option<RoutedMtuChange>,
    launch_pending: bool,
    native: bool,
    endpoint: Option<SocketAddr>,
    dormant_primary: Option<SocketAddr>,
    nested_primary: Option<SocketAddr>,
    forward: bool,
}

impl Profile {
    fn checked_ip(
        &self,
        journal: &Journal,
        change: &RoutedMtuChange,
        endpoint: Option<SocketAddr>,
        forward: bool,
    ) -> io::Result<Option<IpAddr>> {
        if let Some(primary) = self.dormant_primary.or(self.nested_primary) {
            // An unused primary can lack WAN, but it is still part of policy geometry.
            address::check_plans(journal, primary.ip())?;
        }
        address::checked_ip(journal, change, endpoint, forward)
    }
}

pub(super) struct Proof<'a> {
    pub change: &'a RoutedMtuChange,
    pub wanted: Option<u16>,
    endpoint: Option<SocketAddr>,
    nested_reserve: bool,
    pub dormant_primary: Option<SocketAddr>,
    pub parked_dormant_primary: Option<SocketAddr>,
    pub parked_named_primary: Option<IpAddr>,
    pub forward: bool,
    pub full: Option<FullEdit>,
}

#[derive(Clone, Copy)]
pub(super) struct FullEdit {
    before: IpAddr,
    after: IpAddr,
    staged: bool,
    nested_fixed: bool,
    pub dual: bool,
    pub keep_ipv6_fenced: bool,
}

impl FullEdit {
    pub fn recovery_guards(self, confirmed: &Plan) -> Plan {
        let guards = confirmed.guards_only();
        if !self.keep_ipv6_fenced || !guards.empty() {
            return guards;
        }
        // Full tunnel IPv6 fences are independent from the IPv4 kill switch.
        let mut fenced = confirmed.clone();
        let selectors: Vec<_> = confirmed.flows().map(|(selector, _)| selector).collect();
        fenced.park(&selectors);
        fenced.mss.clear();
        fenced
    }

    pub fn retained(
        self,
        confirmed: &Plan,
        previous: Option<&Plan>,
    ) -> io::Result<BTreeSet<IpAddr>> {
        let mut endpoints = confirmed.full_endpoints.clone().unwrap_or_default();
        endpoints.extend(
            previous
                .and_then(|plan| plan.full_endpoints.as_ref())
                .into_iter()
                .flatten(),
        );
        if self.staged {
            endpoints.insert(self.after);
        }
        Self::check_capacity(&endpoints)?;
        Ok(endpoints)
    }

    fn check_capacity(endpoints: &BTreeSet<IpAddr>) -> io::Result<()> {
        if endpoints.len() > plan::MAX_FULL_ENDPOINTS {
            return Err(err("превышен предел транспортов полного туннеля AWG"));
        }
        Ok(())
    }

    fn check_staging(self, journal: &Journal, candidate: IpAddr) -> io::Result<()> {
        let mut endpoints = self.retained(&journal.committed, Some(&journal.installed))?;
        endpoints.insert(candidate);
        Self::check_capacity(&endpoints)
    }

    fn check_nested_transports(k: &Kernel<'_>, committed: &Plan) -> io::Result<()> {
        // Keep the full policy's existing independently guarded throw set.
        // The selected nested socket still needs its own marked-outer proof.
        k.guard(
            committed,
            committed.full_endpoints.as_ref().ok_or_else(invalid)?,
        )
    }

    pub fn verify_legacy_guard(k: &Kernel<'_>, plan: &Plan) -> io::Result<()> {
        if let Some(plan::LegacyFull::ForwardReject {
            wan,
            ipv6_endpoint: false,
        }) = &plan.legacy_full
        {
            if !k.ipv6_stack()? || k.legacy_wan(false)? != *wan {
                return Err(err(
                    "изменился WAN подтверждённой защиты IPv6 полного туннеля AWG",
                ));
            }
        }
        Ok(())
    }

    pub fn verify_legacy_transport(k: &Kernel<'_>, plan: &Plan, live: &LivePeer) -> io::Result<()> {
        let wan = match &plan.legacy_full {
            Some(plan::LegacyFull::ForwardReject { wan, .. }) => Some(wan.clone()),
            Some(plan::LegacyFull::Dual) => Some(k.legacy_wan(false)?),
            _ => None,
        };
        if let Some(wan) = wan {
            address::verify_wan_on(
                k,
                live.endpoint.ip().to_canonical(),
                std::slice::from_ref(&wan),
                live.socket_mark == nfqws2_awg_profile::DIRECT_SOCKET_MARK,
                Some(&wan),
            )?;
        }
        Ok(())
    }

    pub fn retire(
        self,
        endpoints: &mut BTreeSet<IpAddr>,
        current: &BTreeSet<IpAddr>,
        forward: bool,
    ) {
        let (selected, retiring) = if forward {
            (self.after, self.before)
        } else {
            (self.before, self.after)
        };
        endpoints.insert(selected);
        if retiring != selected && !current.contains(&retiring) {
            endpoints.remove(&retiring);
        }
    }
}

pub(super) type Prover<'a> =
    dyn FnMut(&RoutedMtuChange, &LivePeer) -> io::Result<Option<RoutedMtuPeer>> + 'a;

impl Proof<'_> {
    pub fn verified_retiring_nested_path(&self, k: &Kernel<'_>, live: &LivePeer) -> bool {
        let Some(outer) = self.change.nested_outer.as_ref() else {
            return false;
        };
        let Some((before, after)) = edit_endpoints(self.change) else {
            return false;
        };
        let (retiring, selected) = if self.forward {
            (before, after)
        } else {
            (after, before)
        };
        self.change.combines_endpoint_mtu()
            && self.wanted.is_some()
            && self.endpoint == Some(selected)
            && retiring.ip() != selected.ip()
            && canonical_socket(live.endpoint) == Some(retiring)
            && live.nested_mtu.is_some()
            && plan::verify_nested_path(k, &self.change.iface, &outer.iface, live).is_ok()
    }

    pub fn effective_mtu(
        &self,
        k: &Kernel<'_>,
        live: &LivePeer,
        prove: &mut Prover<'_>,
    ) -> io::Result<u16> {
        let wanted = self.wanted.ok_or_else(invalid)?;
        let iface = &self.change.iface;
        let endpoint = canonical_socket(live.endpoint).ok_or_else(invalid)?;
        if self.endpoint.is_some_and(|saved| saved != endpoint) {
            return Err(invalid());
        }
        let effective = if self.change.requires_peer_proof() {
            let proof = prove(self.change, live)?.ok_or_else(invalid)?;
            if proof.iface != *iface
                || canonical_socket(proof.endpoint) != Some(endpoint)
                || proof.socket_mark != live.socket_mark
            {
                return Err(invalid());
            }
            if let Some(outer) = &self.change.nested_outer {
                if proof.outer_id != outer.id
                    || proof.outer_iface != outer.iface
                    || !(576..=wanted).contains(&proof.effective_mtu)
                    || live
                        .nested_mtu
                        .is_some_and(|mtu| mtu != proof.effective_mtu)
                {
                    return Err(invalid());
                }
                plan::verify_nested_path(k, iface, &outer.iface, live)?;
                if self.nested_reserve {
                    nested_endpoint::require_independent_wan(k, endpoint.ip())?;
                }
                proof.effective_mtu
            } else {
                if live.socket_mark >> 28 == 0xa
                    || (self.full.is_some()
                        || self.change.legacy_predecessor.is_some()
                        || self.change.native_mtu_endpoint.is_some()
                        || self.change.combines_endpoint_mtu())
                        && !matches!(live.socket_mark, 0 | nfqws2_awg_profile::DIRECT_SOCKET_MARK)
                    || !proof.outer_id.is_empty()
                    || !proof.outer_iface.is_empty()
                    || proof.effective_mtu != wanted
                {
                    return Err(invalid());
                }
                wanted
            }
        } else if live.socket_mark >> 28 == 0xa {
            return Err(invalid());
        } else {
            wanted
        };
        let file = format!("/sys/class/net/{iface}/mtu");
        if k.call("cat", &[&file])?.trim().parse::<u16>().ok() != Some(effective) {
            return Err(invalid());
        }
        Ok(effective)
    }
}

fn invalid() -> io::Error {
    err("сохранённая правка подключения не соответствует подтверждённым маршрутам AWG")
}

pub(super) fn canonical_socket(value: SocketAddr) -> Option<SocketAddr> {
    (value.port() != 0
        && !matches!(value, SocketAddr::V6(v6) if v6.scope_id() != 0 || v6.flowinfo() != 0))
    .then(|| SocketAddr::new(value.ip().to_canonical(), value.port()))
}

fn edit_endpoints(change: &RoutedMtuChange) -> Option<(SocketAddr, SocketAddr)> {
    change.endpoint_edit.as_ref()?.sockets().ok()
}

fn named(change: &RoutedMtuChange) -> bool {
    change
        .endpoint_edit
        .as_ref()
        .is_some_and(|edit| edit.has_hostname())
}

fn fixed_legacy_endpoint(change: &RoutedMtuChange) -> Option<SocketAddr> {
    change
        .legacy_predecessor
        .as_ref()
        .filter(|_| change.endpoint_edit.is_none())
        .map(|sealed| sealed.endpoint)
}

fn fixed_mtu_endpoint(change: &RoutedMtuChange) -> Option<SocketAddr> {
    change
        .native_mtu_endpoint
        .or_else(|| fixed_legacy_endpoint(change))
        .or_else(|| fixed_nested_mtu_endpoint(change))
}

fn fixed_nested_mtu_endpoint(change: &RoutedMtuChange) -> Option<SocketAddr> {
    if !change.nested_mtu_before_recorded {
        return None;
    }
    let raw = change.nested_endpoint.as_deref()?;
    canonical_socket(raw.parse().ok()?)
}

fn nested_reserve_primary<'a>(
    row: &'a Value,
    change: &RoutedMtuChange,
) -> io::Result<Option<&'a str>> {
    let Some(pin) = fixed_nested_mtu_endpoint(change) else {
        return Ok(None);
    };
    let raw = row["config"]["endpoint"].as_str().ok_or_else(invalid)?;
    let primary = raw
        .parse()
        .ok()
        .and_then(canonical_socket)
        .ok_or_else(invalid)?;
    if primary == pin {
        return Ok(None);
    }
    if !nfqws2_awg_profile::routing_permanent_nested_reserve(row, pin)? {
        return Err(invalid());
    }
    Ok(Some(raw))
}

fn recorded_native_mtu(change: &RoutedMtuChange) -> bool {
    change.native_mtu_endpoint.is_some() || change.nested_mtu_before_recorded
}

fn authorized_endpoints(change: &RoutedMtuChange) -> Option<(SocketAddr, SocketAddr)> {
    edit_endpoints(change)
        .or_else(|| fixed_mtu_endpoint(change).map(|endpoint| (endpoint, endpoint)))
}

fn can_restore_mtu(change: &RoutedMtuChange) -> bool {
    (change.legacy_mtu_before_recorded || recorded_native_mtu(change))
        && (1280..=1500).contains(&change.before)
}

fn native_full_fence_edit(change: &RoutedMtuChange) -> bool {
    fixed_nested_mtu_endpoint(change).is_some()
        || change.legacy_predecessor.is_none()
            && change.nested_outer.is_none()
            && !named(change)
            && (change.native_mtu_endpoint.is_some()
                || edit_endpoints(change).is_some_and(|(before, after)| {
                    before.is_ipv4() == after.is_ipv4()
                        && (change.combines_endpoint_mtu() || before.ip() != after.ip())
                }))
}

fn valid(change: &RoutedMtuChange) -> bool {
    nfqws2_store::valid_name(&change.id)
        && plan::iface_ok(&change.iface)
        && (!change.legacy_mtu_before_recorded || fixed_legacy_endpoint(change).is_some())
        && (change.implicit_before_mtu.is_none()
            || change.combines_endpoint_mtu()
            || change.legacy_mtu_before_recorded
            || recorded_native_mtu(change))
        && (!change.nested_mtu_before_recorded
            || change.endpoint_edit.is_none()
                && change.native_mtu_endpoint.is_none()
                && change.legacy_predecessor.is_none()
                && change
                    .nested_outer
                    .as_ref()
                    .is_some_and(|outer| outer.peer_key_sha256 != [0; 32])
                && fixed_nested_mtu_endpoint(change).is_some()
                && [change.before, change.after]
                    .into_iter()
                    .all(|mtu| (1280..=1500).contains(&mtu)))
        && change.native_mtu_endpoint.is_none_or(|pin| {
            canonical_socket(pin) == Some(pin)
                && change.endpoint_edit.is_none()
                && change.nested_outer.is_none()
                && change.nested_endpoint.is_none()
                && change.legacy_predecessor.is_none()
                && (1280..=1500).contains(&change.after)
        })
        && if change.endpoint_edit.is_some() {
            (change.before == change.after || valid_combined(change))
                && change.nested_endpoint.is_none()
                && (change.nested_outer.is_none() || !named(change))
                && edit_endpoints(change).is_some()
        } else {
            change.before != change.after
        }
        && change.nested_outer.as_ref().is_none_or(|outer| {
            nfqws2_store::valid_name(&outer.id)
                && plan::iface_ok(&outer.iface)
                && outer.id != change.id
                && outer.iface != change.iface
        })
        && change.legacy_predecessor.as_ref().is_none_or(|old| {
            change.nested_outer.is_none()
                && change.nested_endpoint.is_none()
                && (!named(change)
                    || change.endpoint_edit.as_ref().is_some_and(|edit| {
                        change.before == change.after
                            && edit.previous_reserve.is_none()
                            && (edit.resolved_before == [old.endpoint]
                                && edit.resolved_after.is_empty()
                                || edit.resolved_before.is_empty()
                                    && !edit.resolved_after.is_empty())
                    }))
                && old.receipt_sha256 != [0; 32]
                && authorized_endpoints(change).is_some_and(|(before, after)| {
                    old.endpoint == before && before.is_ipv4() == after.is_ipv4()
                })
                && (change.endpoint_edit.is_some()
                    || canonical_socket(old.endpoint) == Some(old.endpoint)
                        && (1280..=1500).contains(&change.after))
        })
        && [change.before, change.after]
            .into_iter()
            .all(|mtu| (576..=9000).contains(&mtu))
}

fn valid_combined(change: &RoutedMtuChange) -> bool {
    change.combines_endpoint_mtu()
        && !named(change)
        && [change.before, change.after]
            .into_iter()
            .all(|mtu| (1280..=1500).contains(&mtu))
        && edit_endpoints(change).is_some_and(|(before, after)| match &change.nested_outer {
            Some(outer) => outer.peer_key_sha256 != [0; 32] && before != after,
            None => change.legacy_predecessor.is_none() || before.is_ipv4() == after.is_ipv4(),
        })
}

fn direct_cross_family_pair(change: &RoutedMtuChange) -> bool {
    change.combines_endpoint_mtu()
        && change.nested_outer.is_none()
        && change.legacy_predecessor.is_none()
        && !named(change)
        && edit_endpoints(change).is_some_and(|(before, after)| before.is_ipv4() != after.is_ipv4())
}

pub(super) fn read(db: &Store) -> io::Result<Option<Authority>> {
    match db.read_runtime::<Authority>(FILE, LIMIT) {
        Ok(authority)
            if valid(&authority.change)
                && (!authority.keep_full_ipv6_fenced
                    || native_full_fence_edit(&authority.change))
                && authority.outer_key.is_some() == authority.change.nested_outer.is_some()
                && authority
                    .recorded_nested_primary
                    .as_deref()
                    .is_none_or(|raw| {
                        fixed_nested_mtu_endpoint(&authority.change).is_some_and(|pin| {
                            raw.parse()
                                .ok()
                                .and_then(canonical_socket)
                                .is_some_and(|primary| primary != pin)
                        })
                    })
                && (!authority.endpoint_committed || authority.change.endpoint_edit.is_some())
                && authority
                    .retry_endpoint
                    .is_none_or(|endpoint| retry::valid(&authority.change, endpoint)) =>
        {
            Ok(Some(authority))
        }
        Ok(_) => Err(invalid()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub(super) fn clear(tx: &Transaction<'_>) -> io::Result<()> {
    tx.delete_runtime(FILE)
}

pub fn pending_mtu_edit(db: &Store) -> io::Result<bool> {
    Ok(read(db)?.is_some())
}

pub(super) fn replacement_wan(k: &Kernel<'_>, endpoint: SocketAddr, mark: u32, wan: &[String]) -> io::Result<()> {
    match mark {
        0 => address::verify_wan(k, endpoint.ip(), wan),
        nfqws2_awg_profile::DIRECT_SOCKET_MARK => address::verify_consistent_wan(k, endpoint.ip(), wan),
        _ => Err(err("прямое подключение AWG использует неподтверждённую метку")),
    }
}

fn native_full_profile(row: &Value, id: &str) -> bool {
    let cfg = &row["config"];
    row["id"] == id
        && cfg["enabled"] == true
        && cfg["install"] == "imported"
        && cfg["client"]["enabled"] == true
        && cfg["client"]["rust_managed"] == true
        && cfg["client"]["standby"] != true
        && cfg["client"]["double_tunnel_mode"] != "permanent"
        && !row["applied_config"].is_object()
}

fn native_mtu_at_primary(row: &Value, change: &RoutedMtuChange) -> bool {
    change.native_mtu_endpoint.is_some_and(|pin| {
        row["config"]["endpoint"]
            .as_str()
            .and_then(|raw| raw.parse().ok())
            .and_then(canonical_socket)
            == Some(pin)
    })
}

fn nested_mtu_at_primary(row: &Value, change: &RoutedMtuChange) -> bool {
    change.nested_mtu_before_recorded
        && change
            .nested_endpoint
            .as_deref()
            .is_some_and(|pin| row["config"]["endpoint"].as_str() == Some(pin))
}

pub(super) fn refresh_fenced_native_full_ipv6(db: &Store, journal: &Journal) -> io::Result<bool> {
    let Some(iface) = address::native_full_fenced_ipv6(&journal.installed) else {
        return Ok(false);
    };
    let Some(target) = journal.installed.targets.get(iface).filter(|target| {
        journal.committed.targets.get(iface) == Some(*target)
            && journal.installed.revision == journal.committed.revision
            && address::native_single_full(&journal.committed)
    }) else {
        return Ok(false);
    };
    let doc = nfqws2_awg_profile::read(db)?;
    Ok(doc["servers"].as_array().into_iter().flatten().any(|row| {
        native_full_profile(row, &target.id)
            && row["config"]["client"]["double_tunnel_id"]
                .as_str()
                .unwrap_or_default()
                .is_empty()
    }))
}

impl Authority {
    pub(super) fn has_named_endpoint(&self) -> bool {
        named(&self.change)
    }

    pub(super) fn full_edit(&self, journal: &Journal) -> Option<FullEdit> {
        let (before, after) = address::full_pair(journal, &self.change)?;
        if self.keep_full_ipv6_fenced
            && (!address::native_single_full(&journal.committed)
                || !journal.installed.empty() && !address::native_single_full(&journal.installed))
        {
            return None;
        }
        Some(FullEdit {
            before,
            after,
            staged: self.full_endpoint_staged,
            nested_fixed: self.change.nested_mtu_before_recorded,
            dual: journal.committed.legacy_full == Some(plan::LegacyFull::Dual),
            keep_ipv6_fenced: self.keep_full_ipv6_fenced,
        })
    }

    fn full_profile(&self, doc: &Value) -> bool {
        let Some(rows) = doc["servers"].as_array() else {
            return false;
        };
        if self.change.nested_mtu_before_recorded {
            return rows.iter().any(|row| {
                row["id"] == self.change.id
                    && nested_mtu_at_primary(row, &self.change)
                    && nfqws2_awg_profile::routed_nested_mtu_edit_profile(row, &self.change)
            }) && self.change.nested_outer.as_ref().is_some_and(|outer| {
                rows.iter().any(|row| {
                    let client = &row["config"]["client"];
                    row["id"] == outer.id
                        && (client["standby"] != true || client["rust_managed"] == true)
                })
            });
        }
        rows.iter().any(|row| {
            native_full_profile(row, &self.change.id)
                && (self.change.native_mtu_endpoint.is_none()
                    || native_mtu_at_primary(row, &self.change))
        })
    }
    fn outer_key(
        doc: &Value,
        rows: &[Value],
        change: &RoutedMtuChange,
    ) -> io::Result<Option<String>> {
        let Some(outer) = &change.nested_outer else {
            return Ok(None);
        };
        let graph = nfqws2_awg_profile::FailoverGraph::load(doc)?;
        let paired = change.combines_endpoint_mtu();
        if graph.nested(&change.id).is_none_or(|(id, mode)| {
            id != outer.id || (paired || change.nested_mtu_before_recorded) && mode != "permanent"
        }) || !rows.iter().any(|row| {
            let client = &row["config"]["client"];
            row["id"] == outer.id
                && row["config"]["enabled"] == true
                && client["enabled"] == true
                && (!paired || client["standby"] != true || client["rust_managed"] == true)
        }) {
            return Err(invalid());
        }
        let (_, iface, target) = plan::profile(doc, rows, &outer.id)?;
        if iface != outer.iface || target.public_key.is_empty() {
            return Err(invalid());
        }
        Ok(Some(target.public_key))
    }

    fn committed<'a>(&self, journal: &'a Journal) -> io::Result<&'a plan::Target> {
        if journal.expires != 0 || journal.committed.revision != self.change.revision {
            return Err(invalid());
        }
        journal
            .committed
            .targets
            .get(&self.change.iface)
            .filter(|target| {
                target.id == self.change.id
                    && target.public_key == self.public_key
                    && [self.change.before, self.change.after].contains(&target.mtu)
            })
            .ok_or_else(invalid)
    }

    fn needs_stable_generations(&self) -> bool {
        self.change.legacy_predecessor.is_some()
            || recorded_native_mtu(&self.change)
            || self.change.combines_endpoint_mtu()
            || self.keep_full_ipv6_fenced
    }

    fn stable_generations(&self, doc: &Value, journal: &Journal) -> bool {
        if !self.needs_stable_generations() {
            return true;
        }
        let meta = &doc["rust_static_routing"];
        (address::explicit(journal)
            || (self.change.combines_endpoint_mtu()
                || recorded_native_mtu(&self.change)
                || self.keep_full_ipv6_fenced)
                && self.full_edit(journal).is_some())
            && meta["go_trial"] != true
            && meta["pending_commit"] == false
            && meta["committed_revision"]
                .as_u64()
                .or_else(|| meta["revision"].as_u64())
                == Some(self.change.revision)
            && meta["committed_targets"]
                .as_array()
                .is_some_and(|ids| ids.iter().any(|id| id == &self.change.id))
            && (journal.installed.empty()
                || journal.installed.revision == self.change.revision
                    && journal.installed.targets.get(&self.change.iface)
                        == journal.committed.targets.get(&self.change.iface)
                    && journal.installed.local_sources == journal.committed.local_sources)
    }

    fn profile(&self, doc: &Value) -> io::Result<Profile> {
        let rows = doc["servers"].as_array().ok_or_else(invalid)?;
        let row = rows
            .iter()
            .find(|r| r["id"] == self.change.id)
            .ok_or_else(invalid)?;
        if named(&self.change)
            && !nfqws2_awg_profile::routed_endpoint_named_allowed(row, &self.change)
        {
            return Err(invalid());
        }
        if self.change.legacy_predecessor.is_some()
            && !nfqws2_awg_profile::routed_legacy_edit_profile(row, &self.change)
        {
            return Err(invalid());
        }
        if self.change.nested_mtu_before_recorded
            && (!nfqws2_awg_profile::routed_nested_mtu_edit_profile(row, &self.change)
                || nested_reserve_primary(row, &self.change)?
                    != self.recorded_nested_primary.as_deref())
        {
            return Err(invalid());
        }
        let dormant_primary = if let Some(endpoint) = self.change.native_mtu_endpoint {
            if !nfqws2_awg_profile::routed_native_mtu_edit_profile(row, &self.change) {
                return Err(invalid());
            }
            nfqws2_awg_profile::routing_direct_backup_pool(row)?
                .first()
                .copied()
                .filter(|primary| primary.ip() != endpoint.ip())
        } else {
            None
        };
        if self.change.combines_endpoint_mtu()
            && !nfqws2_awg_profile::routed_combined_endpoint_mtu_profile(row, &self.change)
        {
            return Err(invalid());
        }
        let (wire, iface, target) = plan::profile(doc, rows, &self.change.id)?;
        if iface != self.change.iface
            || target.public_key != self.public_key
            || ![self.change.before, self.change.after].contains(&target.mtu)
            || Self::outer_key(doc, rows, &self.change)? != self.outer_key
        {
            return Err(invalid());
        }
        let marker = nfqws2_awg_profile::pending_routed_mtu(row)?;
        if marker.as_ref().is_some_and(|value| value != &self.change) {
            return Err(invalid());
        }
        let (endpoint, forward) = if let Some(edit) = &self.change.endpoint_edit {
            let (before, after) = edit.sockets()?;
            let raw = wire["endpoint"].as_str().ok_or_else(invalid)?;
            if raw == edit.before {
                (Some(before), false)
            } else if raw == edit.after {
                (Some(after), true)
            } else if marker.is_none()
                && !edit.has_hostname()
                && self.change.legacy_predecessor.is_none()
                && !self.change.combines_endpoint_mtu()
                && !self.keep_full_ipv6_fenced
            {
                let current = raw
                    .parse()
                    .ok()
                    .and_then(canonical_socket)
                    .ok_or_else(invalid)?;
                if ![before, after].contains(&current) {
                    return Err(invalid());
                }
                (Some(current), current == after)
            } else {
                return Err(invalid());
            }
        } else if let Some(endpoint) = fixed_mtu_endpoint(&self.change) {
            let forward = target.mtu == self.change.after;
            if !forward && marker.is_some() && !can_restore_mtu(&self.change) {
                return Err(invalid());
            }
            (Some(endpoint), forward)
        } else {
            (None, false)
        };
        Ok(Profile {
            mtu: target.mtu,
            marker,
            launch_pending: nfqws2_awg_profile::routed_mtu_launch_pending(row),
            native: row["config"]["client"]["rust_managed"] == true,
            endpoint,
            dormant_primary,
            nested_primary: self
                .recorded_nested_primary
                .as_deref()
                .and_then(|raw| raw.parse().ok().and_then(canonical_socket)),
            forward,
        })
    }

    fn proof_endpoint(
        &self,
        doc: &Value,
        journal: &Journal,
        profile: &Profile,
    ) -> io::Result<Option<SocketAddr>> {
        profile.checked_ip(journal, &self.change, profile.endpoint, profile.forward)?;
        if let Some(endpoint) = self.retry_endpoint.filter(|_| profile.forward) {
            retry::check_candidate(doc, journal, &self.change, endpoint)?;
            return Ok(Some(endpoint));
        }
        Ok(profile.endpoint)
    }

    pub(super) fn proof(&self, doc: &Value, journal: &Journal) -> io::Result<Proof<'_>> {
        let saved = self.committed(journal)?;
        let full = self.full_edit(journal);
        if (self.full_endpoint_staged || self.keep_full_ipv6_fenced) && full.is_none() {
            return Err(invalid());
        }
        // A replaced/corrupt profile cannot authorize forwarding. The
        // existing confirmed selectors remain parked until explicitly removed.
        let profile = self
            .profile(doc)
            .ok()
            .filter(|_| self.stable_generations(doc, journal));
        let parked_dormant_primary = profile.as_ref().and_then(|profile| {
            profile.dormant_primary.filter(|_| {
                profile.marker.is_some() && self.proof_endpoint(doc, journal, profile).is_ok()
            })
        });
        let parked_named_primary = profile
            .as_ref()
            .filter(|profile| {
                profile.marker.is_some()
                    && profile.forward
                    && self.change.legacy_predecessor.is_some()
                    && self
                        .change
                        .endpoint_edit
                        .as_ref()
                        .is_some_and(|edit| !edit.resolved_after.is_empty())
            })
            .and_then(|profile| self.proof_endpoint(doc, journal, profile).ok().flatten())
            .map(|selected| selected.ip());
        let ready = profile
            .filter(|profile| {
                if self.needs_stable_generations() && !profile.native {
                    return false;
                }
                if full
                    .is_some_and(|edit| !self.full_profile(doc) || profile.forward && !edit.staged)
                {
                    return false;
                }
                if !self.change.requires_peer_proof() {
                    return profile.marker.is_none();
                }
                if profile.launch_pending {
                    return false;
                }
                if profile.marker.is_some() {
                    return true;
                }
                if self.change.endpoint_edit.is_some() {
                    // A cancelled edit may restore the previous endpoint. At
                    // equal MTU, the journal alone cannot prove the new endpoint.
                    if self.change.combines_endpoint_mtu()
                        && self.change.legacy_predecessor.is_some()
                        && saved.mtu != profile.mtu
                    {
                        return false;
                    }
                    return self.endpoint_committed || !profile.forward;
                }
                // The old configuration or a crash after acknowledgement is
                // readable when it still matches the committed MTU generation.
                saved.mtu == profile.mtu
            })
            .and_then(|profile| {
                self.proof_endpoint(doc, journal, &profile)
                    .ok()
                    .map(|endpoint| {
                        let dormant = profile.dormant_primary.or_else(|| {
                            profile.endpoint.filter(|configured| {
                                endpoint.is_some_and(|selected| configured.ip() != selected.ip())
                            })
                        });
                        (profile.mtu, endpoint, dormant, profile.forward)
                    })
            });
        Ok(Proof {
            change: &self.change,
            wanted: ready.map(|(mtu, _, _, _)| mtu),
            endpoint: ready.and_then(|(_, endpoint, _, _)| endpoint),
            nested_reserve: self.recorded_nested_primary.is_some(),
            dormant_primary: ready.and_then(|(_, _, dormant, _)| dormant),
            parked_dormant_primary,
            parked_named_primary,
            forward: ready.is_some_and(|(_, _, _, forward)| forward),
            full,
        })
    }

    pub(super) fn guard_checkpoint_proof(
        &self,
        doc: &Value,
        journal: &Journal,
    ) -> io::Result<Option<Proof<'_>>> {
        let sealed_hostname = self.change.legacy_predecessor.is_some() && named(&self.change);
        if self.change.native_mtu_endpoint.is_none() && !sealed_hostname {
            return Ok(None);
        }
        let mut proof = self.proof(doc, journal)?;
        proof.wanted = None;
        let pinned_name =
            sealed_hostname && self.stable_generations(doc, journal) && self.profile(doc).is_ok();
        Ok((pinned_name || proof.parked_dormant_primary.is_some()).then_some(proof))
    }

    pub(super) fn parked_fw4_proof(
        &self,
        doc: &Value,
        journal: &Journal,
    ) -> io::Result<Option<Proof<'_>>> {
        let installed = &journal.installed;
        if installed.firewall != plan::Backend::Fw4
            || journal.expires != 0
            || !journal.preparing.is_empty()
            || !address::explicit(journal)
            || !self.stable_generations(doc, journal)
            || installed.flows().any(|(selector, primary)| {
                installed.effective(selector, primary) == Some(self.change.iface.as_str())
            })
        {
            return Ok(None);
        }
        let Ok(target) = self.committed(journal) else {
            return Ok(None);
        };
        let matching = self.profile(doc).is_ok_and(|profile| {
            profile.marker.as_ref() == Some(&self.change)
                && self.proof_endpoint(doc, journal, &profile).is_ok()
        });
        if !matching || installed.targets.get(&self.change.iface) != Some(target) {
            return Ok(None);
        }
        self.guard_checkpoint_proof(doc, journal)
    }

    fn bind(
        doc: &Value,
        journal: &Journal,
        change: &RoutedMtuChange,
        previous: Option<&Self>,
    ) -> io::Result<Self> {
        if !valid(change)
            || !journal
                .committed
                .flows()
                .any(|(_, primary)| primary == change.iface)
                && !journal
                    .committed
                    .reserves
                    .iter()
                    .any(|(_, names)| names.contains(&change.iface))
        {
            return Err(invalid());
        }
        let saved = journal
            .committed
            .targets
            .get(&change.iface)
            .ok_or_else(invalid)?;
        let rows = doc["servers"].as_array().ok_or_else(invalid)?;
        let recorded_nested_primary = if change.nested_mtu_before_recorded {
            let row = rows
                .iter()
                .find(|row| row["id"] == change.id)
                .ok_or_else(invalid)?;
            nested_reserve_primary(row, change)?.map(str::to_owned)
        } else {
            None
        };
        if previous.is_some_and(|saved| saved.recorded_nested_primary != recorded_nested_primary) {
            return Err(invalid());
        }
        let authority = Self {
            change: change.clone(),
            public_key: saved.public_key.clone(),
            outer_key: Self::outer_key(doc, rows, change)?,
            recorded_nested_primary,
            endpoint_committed: previous.is_some_and(|saved| saved.endpoint_committed),
            retry_endpoint: previous.and_then(|saved| saved.retry_endpoint),
            full_endpoint_staged: previous.is_some_and(|saved| saved.full_endpoint_staged),
            keep_full_ipv6_fenced: previous.map_or_else(
                || {
                    native_full_fence_edit(change)
                        && journal.preparing.is_empty()
                        && address::full_pair(journal, change).is_some()
                        && address::native_single_full(&journal.committed)
                        && address::native_full_fenced_ipv6(&journal.installed)
                            == Some(change.iface.as_str())
                },
                |saved| saved.keep_full_ipv6_fenced,
            ),
        };
        authority.committed(journal)?;
        if !authority.stable_generations(doc, journal) {
            return Err(invalid());
        }
        let full = authority.full_edit(journal);
        if (authority.full_endpoint_staged || authority.keep_full_ipv6_fenced) && full.is_none() {
            return Err(invalid());
        }
        if let Some(full) = full {
            if !authority.full_profile(doc)
                || previous.is_none()
                    && ![&journal.committed, &journal.installed].iter().all(|plan| {
                        plan.empty()
                            || plan
                                .full_endpoints
                                .as_ref()
                                .is_some_and(|set| set.contains(&full.before))
                    })
            {
                return Err(invalid());
            }
        }
        let meta = &doc["rust_static_routing"];
        if saved.mtu != change.before && previous != Some(&authority)
            || (!journal.installed.empty() && meta["revision"] != change.revision)
            || meta["pending_commit"] != false
        {
            return Err(invalid());
        }
        Ok(authority)
    }

    fn for_change(
        doc: &Value,
        journal: &Journal,
        change: &RoutedMtuChange,
        previous: Option<&Self>,
    ) -> io::Result<(Self, Option<std::net::IpAddr>)> {
        let authority = Self::bind(doc, journal, change, previous)?;
        let profile = authority.profile(doc)?;
        let wanted =
            if !profile.forward && (change.combines_endpoint_mtu() || can_restore_mtu(change)) {
                change.before
            } else {
                change.after
            };
        if profile.mtu != wanted || profile.marker.as_ref() != Some(change) {
            return Err(invalid());
        }
        let address = profile.checked_ip(journal, change, profile.endpoint, profile.forward)?;
        Ok((authority, address))
    }

    fn save(&self, tx: &Transaction<'_>) -> io::Result<()> {
        tx.save_runtime_bounded(FILE, self, LIMIT)
    }

    pub(super) fn finish_verified(mut self, tx: &Transaction<'_>) -> io::Result<()> {
        if self.change.requires_peer_proof() {
            nfqws2_awg_profile::edit_document_locked(tx, |doc| {
                let profile = self.profile(doc)?;
                if profile.marker.is_some() {
                    if self.change.endpoint_edit.is_some() {
                        let endpoint_committed = profile.forward;
                        if self.endpoint_committed != endpoint_committed {
                            self.endpoint_committed = endpoint_committed;
                            self.save(tx)?;
                        }
                    }
                    let row = doc["servers"]
                        .as_array_mut()
                        .ok_or_else(invalid)?
                        .iter_mut()
                        .find(|row| row["id"] == self.change.id)
                        .ok_or_else(invalid)?;
                    nfqws2_awg_profile::finish_routed_mtu(row, &self.change)?;
                }
                Ok(())
            })?;
        }
        clear(tx)
    }
}

pub(super) fn saved_profile(doc: &Value, journal: &Journal) -> io::Result<Option<Authority>> {
    let mut pending = None;
    for row in doc["servers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|row| {
            journal
                .committed
                .targets
                .values()
                .any(|target| row["id"] == target.id)
        })
    {
        if let Some(change) = nfqws2_awg_profile::pending_routed_mtu(row)? {
            if pending.is_some() {
                return Err(invalid());
            }
            pending = Some(Authority::for_change(doc, journal, &change, None)?.0);
        }
    }
    Ok(pending)
}

pub(super) fn recover_authority(
    tx: &Transaction<'_>,
    doc: &Value,
    journal: &Journal,
) -> io::Result<Option<Authority>> {
    let pending = saved_profile(doc, journal)?;
    if let Some(authority) = &pending {
        authority.save(tx)?;
    }
    Ok(pending)
}

pub(super) fn preserve_full_ipv6_fence_before_suspend(
    tx: &Transaction<'_>,
    doc: &Value,
    journal: &Journal,
) -> io::Result<()> {
    if address::native_full_fenced_ipv6(&journal.installed).is_some() {
        if let Some(authority) = saved_profile(doc, journal)?.filter(|a| a.keep_full_ipv6_fenced) {
            authority.save(tx)?;
        }
    }
    Ok(())
}

/// Rebind the confirmed DNS identity after proof. Its hash includes each
/// candidate's MTU. Rebuild that hash twice against the saved policy and change
/// nothing else, proving that the old value covers the same policy and peers.
pub(super) fn rebind_dns(
    db: &Store,
    doc: &Value,
    confirmed: &Plan,
    current: &mut Plan,
    iface: &str,
) -> io::Result<()> {
    let before = &confirmed.targets[iface];
    if before.mtu == current.targets[iface].mtu || confirmed.legacy_full.is_some() {
        return Ok(());
    }
    let (policy, snapshot, members, hash) = if let Some(saved) = &confirmed.learned {
        (
            saved.routing()?,
            None,
            saved.members.as_slice(),
            saved.hash.as_str(),
        )
    } else if let Some(saved) = &confirmed.dns {
        if doc["routing_revision"] != confirmed.revision {
            // Eager answers never rotate against a different draft revision.
            return Ok(());
        }
        (
            crate::sources::current(db, doc)?,
            Some(&saved.snapshot),
            &[][..],
            saved.source_hash.as_str(),
        )
    } else {
        return Ok(());
    };
    let mut original = doc.clone();
    let row = original["servers"]
        .as_array_mut()
        .ok_or_else(invalid)?
        .iter_mut()
        .find(|r| r["id"] == before.id)
        .ok_or_else(invalid)?;
    row["config"]["mtu"] = json!(before.mtu);
    if row["applied_config"].is_object() {
        row["applied_config"]["mtu"] = json!(before.mtu);
    }
    let compile = |source, policy| {
        plan::compile_saved_policy(
            source,
            policy,
            confirmed.revision,
            snapshot,
            members,
            snapshot.is_some(),
            confirmed.layout(),
        )
    };
    let read_hash = |plan: Plan| {
        plan.learned
            .map(|saved| saved.hash)
            .or_else(|| plan.dns.map(|saved| saved.source_hash))
    };
    if read_hash(compile(&original, policy.clone())?).as_deref() != Some(hash) {
        return Err(invalid());
    }
    let new = read_hash(compile(doc, policy)?).ok_or_else(invalid)?;
    if let Some(learned) = &mut current.learned {
        learned.hash = new;
    } else if let Some(dns) = &mut current.dns {
        dns.source_hash = new;
    }
    Ok(())
}

/// Only change the connection identity in the source stamp. Prove the saved
/// content against the previous endpoint before accepting the current one.
pub(super) fn rebind_local_sources(
    db: &Store,
    doc: &Value,
    confirmed: &Plan,
    change: &RoutedMtuChange,
) -> io::Result<Option<crate::sources::Generation>> {
    let Some(saved) = confirmed.local_sources.as_ref().filter(|_| {
        change.combines_endpoint_mtu()
            || change.legacy_predecessor.is_some()
            || recorded_native_mtu(change)
    }) else {
        return Ok(None);
    };
    let changed = || err("изменилась подтверждённая политика локальных источников AWG");
    if doc["routing_revision"].as_u64().unwrap_or_default() != confirmed.revision {
        return Err(changed());
    }
    let material = crate::sources::current(db, doc)?;
    let rebound = crate::sources::Generation::from_policy(doc, &material)?.ok_or_else(changed)?;
    if (change.legacy_predecessor.is_some() || recorded_native_mtu(change)) && &rebound == saved {
        return Ok(Some(rebound));
    }
    let mut prior = doc.clone();
    let row = prior["servers"]
        .as_array_mut()
        .ok_or_else(invalid)?
        .iter_mut()
        .find(|row| row["id"] == change.id)
        .ok_or_else(invalid)?;
    if change.combines_endpoint_mtu() {
        let target = confirmed.targets.get(&change.iface).ok_or_else(invalid)?;
        let forward = if target.mtu == change.before {
            false
        } else if target.mtu == change.after {
            true
        } else {
            return Err(invalid());
        };
        change.rewrite_combined_endpoint_mtu(row, forward)?;
    } else {
        let edit = change.endpoint_edit.as_ref().ok_or_else(changed)?;
        let endpoint = &mut row["config"]["endpoint"];
        *endpoint = if *endpoint == edit.before {
            json!(edit.after)
        } else if *endpoint == edit.after {
            json!(edit.before)
        } else {
            return Err(invalid());
        };
    }
    if crate::sources::Generation::from_policy(&prior, &material)?.as_ref() != Some(saved) {
        return Err(changed());
    }
    Ok(Some(rebound))
}

/// Park selectors using the exact confirmed target before the client releases
/// its live TUN. This operation invokes no AWG process callbacks.
pub fn prepare_mtu_edit(db: &Store, run: &dyn Runner, change: &RoutedMtuChange) -> io::Result<()> {
    prepare_edit(db, run, change, None)
}

pub fn prepare_mtu_edit_with_wan(
    db: &Store,
    run: &dyn Runner,
    change: &RoutedMtuChange,
    wan: &[String],
) -> io::Result<()> {
    prepare_edit(db, run, change, Some(wan))
}

/// Prove an endpoint edit or its reverse against the confirmed policy before
/// saving. An exact pending forward row authorizes checking the old tuple.
pub fn validate_endpoint_edit(
    db: &Store,
    run: &dyn Runner,
    change: &RoutedMtuChange,
    wan: &[String],
) -> io::Result<()> {
    validate_endpoint_edit_inner(db, run, change, wan, false).map(drop)
}

/// Validate the forward edit before saving. A direct split edit can nominate
/// an exact usable configured reserve when the primary has no usable WAN.
pub fn validate_endpoint_edit_with_backup(
    db: &Store,
    run: &dyn Runner,
    change: &RoutedMtuChange,
    wan: &[String],
) -> io::Result<Option<SocketAddr>> {
    retry::legacy_choice(validate_endpoint_edit_launch(db, run, change, wan)?)
}

pub fn validate_endpoint_edit_launch(
    db: &Store,
    run: &dyn Runner,
    change: &RoutedMtuChange,
    wan: &[String],
) -> io::Result<RoutedEndpointLaunch> {
    validate_endpoint_edit_inner(db, run, change, wan, true)
}

fn validate_unrecorded_mtu(
    doc: &Value,
    journal: &Journal,
    change: &RoutedMtuChange,
) -> io::Result<()> {
    let mut unrecorded = change.clone();
    unrecorded.native_mtu_endpoint = None;
    unrecorded.nested_mtu_before_recorded = false;
    unrecorded.implicit_before_mtu = None;
    let baseline = Authority::bind(doc, journal, &unrecorded, None)?;
    let profile = baseline.profile(doc)?;
    let row = doc["servers"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|row| row["id"] == change.id)
        .ok_or_else(invalid)?;
    if !profile.native
        || profile.marker.is_some()
        || profile.launch_pending
        || profile.mtu != change.before
        || doc["routing_revision"].as_u64().unwrap_or_default() != change.revision
        || journal.installed.empty()
        || journal.installed.revision != change.revision
        || journal.installed.targets.get(&change.iface)
            != journal.committed.targets.get(&change.iface)
        || if change.nested_mtu_before_recorded {
            !nfqws2_awg_profile::routed_nested_mtu_edit_profile(row, change)
        } else {
            !nfqws2_awg_profile::routed_native_mtu_edit_profile(row, change)
        }
    {
        return Err(invalid());
    }
    Ok(())
}

fn validate_endpoint_edit_inner(
    db: &Store,
    run: &dyn Runner,
    change: &RoutedMtuChange,
    wan: &[String],
    allow_backup: bool,
) -> io::Result<RoutedEndpointLaunch> {
    if !valid(change) {
        return Err(invalid());
    }
    let Some((before, after)) = authorized_endpoints(change) else {
        return Ok(RoutedEndpointLaunch::Primary);
    };
    let launch = db
        .transaction(|_| {
            let journal = Journal::read(db)?;
            let doc = nfqws2_awg_profile::read(db)?;
            let saved_authority = read(db)?;
            if !journal.preparing.is_empty() {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            if recorded_native_mtu(change)
                && !address::explicit(&journal)
                && !(address::native_single_full(&journal.committed)
                    && doc["servers"].as_array().into_iter().flatten().any(|row| {
                        row["id"] == change.id
                            && (native_mtu_at_primary(row, change)
                                || nested_mtu_at_primary(row, change))
                    }))
            {
                if saved_authority.is_some() {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                validate_unrecorded_mtu(&doc, &journal, change)?;
                let k = kernel_for_transition(run, db, &journal, &journal.installed)?;
                if journal.boot != boot_id(&k)?
                    || k.inventory(&journal.claims(), true)? != objects(&journal.installed)
                {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                return Ok(None);
            }
            let expected = Authority::bind(&doc, &journal, change, saved_authority.as_ref())?;
            if saved_authority
                .as_ref()
                .is_some_and(|saved| saved != &expected)
            {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let profile = expected.profile(&doc)?;
            let saved_mtu = if profile.forward {
                change.after
            } else {
                change.before
            };
            if profile.mtu != saved_mtu {
                return Err(invalid());
            }
            let reverting = match (profile.marker.as_ref(), profile.forward) {
                (Some(saved), true)
                    if saved == change
                        && (change.endpoint_edit.is_some() || can_restore_mtu(change)) =>
                {
                    true
                }
                (None, false)
                    if profile.endpoint == Some(before)
                        && !profile.launch_pending
                        && saved_authority.is_none()
                        && doc["routing_revision"].as_u64().unwrap_or_default()
                            == change.revision =>
                {
                    false
                }
                _ => return Err(invalid()),
            };
            if change.legacy_predecessor.is_some() && !reverting && profile.native {
                return Err(invalid());
            }
            if reverting
                && change
                    .endpoint_edit
                    .as_ref()
                    .is_some_and(|edit| edit.previous_reserve.is_some())
            {
                let row = doc["servers"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|row| row["id"] == change.id)
                    .ok_or_else(invalid)?;
                if !nfqws2_awg_profile::routed_endpoint_previous_reserve_allowed(row, change) {
                    return Err(invalid());
                }
            }
            let selected = if reverting { before } else { after };
            let ip = profile.checked_ip(&journal, change, Some(selected), !reverting)?;
            rebind_local_sources(db, &doc, &journal.committed, change)?;
            let k = kernel_for_transition(run, db, &journal, &journal.installed)?;
            let installed = !journal.installed.empty() && journal.boot == boot_id(&k)?;
            if !installed && !reverting
                || installed && k.inventory(&journal.claims(), true)? != objects(&journal.installed)
            {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let full = expected.full_edit(&journal);
            let nested_full = full.is_some_and(|full| full.nested_fixed);
            if !reverting
                && (change.combines_endpoint_mtu() || recorded_native_mtu(change))
                && full.is_some()
                && journal.installed.flows().any(|(selector, primary)| {
                    !(expected.keep_full_ipv6_fenced && selector.dest.family() == plan::Family::V6)
                        && journal.installed.effective(selector, primary)
                            != Some(change.iface.as_str())
                })
            {
                return Err(err(
                    "не подтверждены действующий IPv4 и защита IPv6 полного туннеля AWG",
                ));
            }
            if !reverting && (expected.keep_full_ipv6_fenced || nested_full) {
                k.verify_forward(&journal.installed)?;
            }
            if allow_backup
                && !reverting
                && change.endpoint_edit.is_some()
                && change.nested_outer.is_none()
                && change.legacy_predecessor.is_none()
                && !change.combines_endpoint_mtu()
                && address::explicit(&journal)
                && !named(change)
            {
                let candidates = retry::projected_pool(&doc, change)?;
                if !candidates.is_empty() {
                    address::check_plans(&journal, after.ip())?;
                    if address::has_wan(&k, after.ip(), wan)? {
                        return Ok(Some(RoutedEndpointLaunch::Primary));
                    }
                    let complete = retry::projected_literal_pool(&doc, change)?;
                    return retry::backup_or_wait(
                        &k,
                        &journal,
                        &candidates,
                        complete.as_deref(),
                        wan,
                    )
                    .map(Some);
                }
            }
            if let Some(ip) = ip {
                if let Some(full) = full {
                    full.check_staging(&journal, ip)?;
                    FullEdit::verify_legacy_guard(&k, &journal.committed)?;
                    if installed {
                        k.verify_ipv6_reject(&journal.installed)?;
                    }
                    let dual_wan = full
                        .dual
                        .then(|| legacy_dual_reject_wan(&k, &change.iface))
                        .transpose()?;
                    let expected = dual_wan
                        .as_deref()
                        .or_else(|| journal.committed.ipv6_reject_wan());
                    if dual_wan.is_some() && !reverting {
                        address::verify_wan_on(&k, full.before, wan, true, expected)?;
                    }
                    if nested_full {
                        FullEdit::check_nested_transports(&k, &journal.committed)?;
                    } else if change.native_mtu_endpoint.is_some() {
                        address::verify_consistent_wan(&k, ip, wan)?;
                    } else {
                        address::verify_wan_on(&k, ip, wan, true, expected)?;
                    }
                } else if address::checks_consistent_wan(change) {
                    address::verify_consistent_wan(&k, ip, wan)?;
                } else if expected.recorded_nested_primary.is_some()
                    || !nested_endpoint::edit_has_no_direct_claim(
                        &doc,
                        &journal.committed,
                        change,
                        ip,
                    )?
                {
                    address::verify_wan(&k, ip, wan)?;
                }
            }
            Ok(Some(RoutedEndpointLaunch::Primary))
        })
        .map_err(|error| {
            if recorded_native_mtu(change) && error.kind() == io::ErrorKind::Unsupported {
                io::Error::other(error)
            } else {
                error
            }
        })?;
    // Only a positively identified off-scope policy may use the unrecorded forward path.
    launch.ok_or_else(|| io::ErrorKind::Unsupported.into())
}

fn prepare_edit(
    db: &Store,
    run: &dyn Runner,
    change: &RoutedMtuChange,
    wan: Option<&[String]>,
) -> io::Result<()> {
    if !valid(change) {
        return Err(invalid());
    }
    db.transaction(|tx| {
        let journal = Journal::read(db)?;
        let doc = nfqws2_awg_profile::read(db)?;
        let saved_authority = read(db)?;
        let (mut authority, ip) =
            Authority::for_change(&doc, &journal, change, saved_authority.as_ref())?;
        rebind_local_sources(db, &doc, &journal.committed, change)?;
        if !journal.preparing.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if saved_authority
            .as_ref()
            .is_some_and(|old| old != &authority)
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if authority.retry_endpoint.is_some() && authority.profile(&doc)?.forward {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let k = kernel_for_transition(run, db, &journal, &journal.installed)?;
        if saved_authority.is_none()
            && authority.keep_full_ipv6_fenced
            && journal.boot == boot_id(&k)?
        {
            if k.inventory(&journal.claims(), true)? != objects(&journal.installed) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            k.verify_forward(&journal.installed)?;
        }
        let full = authority.full_edit(&journal);
        let dual_wan = if full.is_some_and(|edit| edit.dual) {
            Some(legacy_dual_reject_wan(&k, &change.iface)?)
        } else {
            None
        };
        let expected = dual_wan
            .as_deref()
            .or_else(|| journal.committed.ipv6_reject_wan());
        let check_consistent_wan = address::checks_consistent_wan(change);
        let mut check_wan_after_park = false;
        if let Some(ip) = ip {
            let wan = wan.ok_or_else(invalid)?;
            if let Some(edit) = full {
                edit.check_staging(&journal, ip)?;
                FullEdit::verify_legacy_guard(&k, &journal.committed)?;
                if !journal.installed.empty() && journal.boot == boot_id(&k)? {
                    k.verify_ipv6_reject(&journal.installed)?;
                }
                if edit.dual && ip == edit.after {
                    address::verify_wan_on(&k, edit.before, wan, true, expected)?;
                }
                if edit.nested_fixed {
                    FullEdit::check_nested_transports(&k, &journal.committed)?;
                } else if change.native_mtu_endpoint.is_some() {
                    address::verify_consistent_wan(&k, ip, wan)?;
                } else {
                    address::verify_wan_on(&k, ip, wan, true, expected)?;
                }
                // An exact restore need only have its previous WAN. Keep a
                // forward exception if it was authorized before the restore.
                authority.full_endpoint_staged |= ip == edit.after;
            } else if check_consistent_wan {
                address::verify_consistent_wan(&k, ip, wan)?;
            } else if authority.recorded_nested_primary.is_some()
                || !nested_endpoint::edit_has_no_direct_claim(&doc, &journal.committed, change, ip)?
            {
                address::verify_wan(&k, ip, wan)?;
                check_wan_after_park = authority.recorded_nested_primary.is_some()
                    || change.nested_outer.is_some() && change.combines_endpoint_mtu();
            }
        }
        if saved_authority.as_ref() != Some(&authority) {
            // Keep authorization even if the process exits before the kernel
            // transaction starts or the profile restart acknowledgement arrives.
            authority.save(tx)?;
        }
        let staged = ip.filter(|_| full.is_some());
        park_target(db, tx, &k, &journal, &change.iface, staged)?;
        if let Some((ip, edit)) = staged.zip(full) {
            FullEdit::verify_legacy_guard(&k, &journal.committed)?;
            let wan = wan.ok_or_else(invalid)?;
            if edit.nested_fixed {
                FullEdit::check_nested_transports(&k, &journal.committed)?;
            } else if change.native_mtu_endpoint.is_some() {
                address::verify_consistent_wan(&k, ip, wan)?;
            } else {
                address::verify_wan_on(&k, ip, wan, false, expected)?;
            }
        } else if let Some(ip) = ip.filter(|_| check_consistent_wan) {
            address::verify_consistent_wan(&k, ip, wan.ok_or_else(invalid)?)?;
        } else if let Some(ip) = ip.filter(|_| check_wan_after_park) {
            address::verify_wan(&k, ip, wan.ok_or_else(invalid)?)?;
        }
        Ok(())
    })
}

fn park_target(
    db: &Store,
    tx: &Transaction<'_>,
    k: &Kernel<'_>,
    journal: &Journal,
    iface: &str,
    endpoint: Option<IpAddr>,
) -> io::Result<()> {
    if journal.installed.empty() || journal.boot != boot_id(k)? {
        return Ok(());
    }
    let mut affected = journal
        .installed
        .flows()
        .filter_map(|(selector, primary)| {
            (journal.installed.effective(selector, primary) == Some(iface)).then_some(selector)
        })
        .collect::<Vec<_>>();
    let mut parked = journal.clone();
    if let Some(endpoint) = endpoint {
        if parked.committed.legacy_full == Some(plan::LegacyFull::Dual)
            && matches!(
                parked.installed.legacy_full,
                Some(plan::LegacyFull::ForwardReject { .. })
            )
        {
            // A previous attempt can end in Go's IPv4 fallback. Reinstate
            // the confirmed IPv6 fence before releasing this generation.
            let v6 = plan::Family::V6.any();
            let primary = parked
                .committed
                .prefixes
                .get(&v6)
                .ok_or_else(invalid)?
                .clone();
            parked.installed.prefixes.insert(v6, primary);
            parked.installed.legacy_full = Some(plan::LegacyFull::Dual);
            parked.installed.go_ipv4 = false;
            affected.push(plan::Selector {
                source: v6,
                dest: v6,
            });
        }
        parked
            .installed
            .full_endpoints
            .as_mut()
            .ok_or_else(invalid)?
            .insert(endpoint);
    }
    parked.installed.park(&affected);
    parked.installed.mss.remove(iface);
    if parked == *journal && k.inventory(&journal.claims(), true)? == journal.claims() {
        return Ok(());
    }
    transition(db, tx, k.run, journal, &parked, None)
}
