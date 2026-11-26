use super::*;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

pub(super) const PENDING_PROFILE: &str = "rust_pending_client_profile";
pub(super) const PENDING_ROUTED_MTU: &str = "rust_pending_routed_mtu";
const TRANSPORT_REFRESH: &str = "transport_refresh";
const MAX_HOST_ADDRESSES: usize = 16;

/// A saved link-only edit bound to an already confirmed routing revision.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoutedMtuChange {
    pub id: String,
    pub iface: String,
    pub revision: u64,
    pub before: u16,
    pub after: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nested_outer: Option<RoutedMtuOuter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nested_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_edit: Option<RoutedEndpointEdit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_predecessor: Option<RoutedLegacyPredecessor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implicit_before_mtu: Option<RoutedImplicitMtu>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub legacy_mtu_before_recorded: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub nested_mtu_before_recorded: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_mtu_endpoint: Option<SocketAddr>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutedImplicitMtu {
    Missing,
    Zero,
    Null,
}

impl RoutedImplicitMtu {
    fn from_saved(raw: Option<&Value>) -> Option<Self> {
        match raw {
            None => Some(Self::Missing),
            Some(Value::Null) => Some(Self::Null),
            Some(value) if value.as_u64() == Some(0) => Some(Self::Zero),
            _ => None,
        }
    }

    fn write(self, cfg: &mut serde_json::Map<String, Value>) {
        match self {
            Self::Missing => {
                cfg.remove("mtu");
            }
            Self::Zero => {
                cfg.insert("mtu".into(), json!(0));
            }
            Self::Null => {
                cfg.insert("mtu".into(), Value::Null);
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoutedLegacyPredecessor {
    pub receipt_sha256: [u8; 32],
    pub endpoint: SocketAddr,
}

impl RoutedMtuChange {
    pub fn requires_peer_proof(&self) -> bool {
        self.nested_outer.is_some()
            || self.endpoint_edit.is_some()
            || self.legacy_predecessor.is_some()
            || self.native_mtu_endpoint.is_some()
    }

    pub fn combines_endpoint_mtu(&self) -> bool {
        self.endpoint_edit.is_some() && self.before != self.after
    }

    pub(super) fn combines_nested_endpoint_mtu(&self) -> bool {
        self.nested_outer.is_some() && self.combines_endpoint_mtu()
    }

    fn combines_direct_cross_family_mtu(&self) -> bool {
        self.combines_endpoint_mtu()
            && self.nested_outer.is_none()
            && self.legacy_predecessor.is_none()
            && self.endpoint_edit.as_ref().is_some_and(|edit| {
                !edit.has_hostname()
                    && edit
                        .sockets()
                        .is_ok_and(|(before, after)| before.is_ipv4() != after.is_ipv4())
            })
    }

    pub(super) fn inherits_named_endpoint(&self) -> bool {
        self.legacy_predecessor.is_some()
            && self
                .endpoint_edit
                .as_ref()
                .is_some_and(RoutedEndpointEdit::has_hostname)
    }

    fn legacy_mtu_only(&self) -> bool {
        self.legacy_predecessor.is_some() && self.endpoint_edit.is_none()
    }

    fn records_mtu_before(&self) -> bool {
        self.legacy_mtu_before_recorded
            || self.nested_mtu_before_recorded
            || self.native_mtu_endpoint.is_some()
    }

    fn fixed_mtu_endpoint(&self) -> Option<SocketAddr> {
        self.native_mtu_endpoint.or_else(|| {
            self.legacy_predecessor
                .as_ref()
                .map(|legacy| legacy.endpoint)
        })
    }

    fn fixed_nested_mtu_endpoint(&self) -> Option<SocketAddr> {
        self.nested_endpoint
            .as_deref()
            .filter(|_| self.nested_mtu_before_recorded)
            .and_then(literal_transport)
    }

    fn valid_mtu_provenance(&self) -> bool {
        (!self.legacy_mtu_before_recorded || self.legacy_mtu_only())
            && (!self.nested_mtu_before_recorded
                || self.endpoint_edit.is_none()
                    && self.legacy_predecessor.is_none()
                    && self.native_mtu_endpoint.is_none()
                    && self.nested_outer.is_some()
                    && self.fixed_nested_mtu_endpoint().is_some()
                    && self.before != self.after)
            && (self.native_mtu_endpoint.is_none()
                || self.endpoint_edit.is_none()
                    && self.legacy_predecessor.is_none()
                    && self.nested_outer.is_none()
                    && self.nested_endpoint.is_none()
                    && self.before != self.after)
            && (self.implicit_before_mtu.is_none()
                || self.combines_endpoint_mtu()
                || self.records_mtu_before())
    }

    fn matches_saved_mtu(&self, row: &Value, mtu: u16) -> bool {
        let raw = row["config"].get("mtu");
        if let Some(implicit) = self.implicit_before_mtu.filter(|_| mtu == self.before) {
            RoutedImplicitMtu::from_saved(raw) == Some(implicit)
                && effective_mtu(row).is_ok_and(|effective| effective == mtu)
        } else {
            raw.and_then(Value::as_u64) == Some(mtu.into())
        }
    }

    fn write_mtu(&self, cfg: &mut serde_json::Map<String, Value>, mtu: u16) {
        if let Some(implicit) = self.implicit_before_mtu.filter(|_| mtu == self.before) {
            implicit.write(cfg);
        } else {
            cfg.insert("mtu".into(), json!(mtu));
        }
    }

    /// Rebuild either saved pair, retaining the original representation of a legacy MTU.
    pub fn rewrite_combined_endpoint_mtu(&self, row: &mut Value, forward: bool) -> io::Result<()> {
        let edit = self
            .endpoint_edit
            .as_ref()
            .ok_or(io::ErrorKind::WouldBlock)?;
        if !self.combines_endpoint_mtu() || row["id"] != self.id {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let cfg = row["config"]
            .as_object_mut()
            .ok_or(io::ErrorKind::WouldBlock)?;
        cfg.insert(
            "endpoint".into(),
            json!(if forward { &edit.after } else { &edit.before }),
        );
        self.write_mtu(cfg, if forward { self.after } else { self.before });
        if !routed_combined_endpoint_mtu_profile(row, self) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        Ok(())
    }

    fn saved_mtu(&self, row: &Value) -> Option<u16> {
        if self.records_mtu_before() {
            return [self.before, self.after]
                .into_iter()
                .find(|&mtu| self.matches_saved_mtu(row, mtu));
        }
        let Some(edit) = &self.endpoint_edit else {
            return Some(self.after);
        };
        let raw = s(&row["config"], "endpoint");
        if raw == edit.after {
            Some(self.after)
        } else if raw == edit.before {
            Some(self.before)
        } else {
            None
        }
    }

    fn endpoint_selection(&self, row: &Value) -> io::Result<Option<EndpointSelection<'_>>> {
        let Some(edit) = &self.endpoint_edit else {
            return Ok(None);
        };
        let (before, after) = edit.sockets()?;
        let selected = s(&row["config"], "endpoint");
        let refresh_port = edit.has_hostname()
            || self.legacy_predecessor.is_some()
            || self.combines_endpoint_mtu();
        let selection = if selected == edit.after {
            EndpointSelection {
                retiring: before,
                chosen: after,
                previous_config: &edit.before,
                restoring: false,
                refresh_port,
            }
        } else if selected == edit.before {
            EndpointSelection {
                retiring: after,
                chosen: before,
                previous_config: &edit.after,
                restoring: true,
                refresh_port,
            }
        } else {
            return Err(invalid(
                "ожидающая правка endpoint не соответствует профилю AWG",
            ));
        };
        Ok(Some(selection))
    }
}

struct EndpointSelection<'a> {
    retiring: SocketAddr,
    chosen: SocketAddr,
    previous_config: &'a str,
    restoring: bool,
    refresh_port: bool,
}

impl EndpointSelection<'_> {
    fn refreshes_transport(&self) -> bool {
        self.refresh_port || self.restoring || self.retiring.ip() != self.chosen.ip()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoutedEndpointEdit {
    pub before: String,
    pub after: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved_before: Vec<SocketAddr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved_after: Vec<SocketAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_reserve: Option<SocketAddr>,
}

impl RoutedEndpointEdit {
    pub fn has_hostname(&self) -> bool {
        !self.resolved_before.is_empty()
            || !self.resolved_after.is_empty()
            || self.previous_reserve.is_some()
    }

    /// Addresses admitted for the given exact spelling of the named endpoint.
    pub fn pinned_addresses(&self, raw: &str) -> Option<&[SocketAddr]> {
        if raw == self.before
            && (!self.resolved_before.is_empty() || self.previous_reserve.is_some())
        {
            Some(&self.resolved_before)
        } else if raw == self.after && !self.resolved_after.is_empty() {
            Some(&self.resolved_after)
        } else {
            None
        }
    }

    /// Parse the immutable old and new launch tuples without a DNS lookup.
    pub fn sockets(&self) -> io::Result<(SocketAddr, SocketAddr)> {
        let bad = || invalid("неверная сохранённая правка endpoint AWG");
        if self.before == self.after {
            return Err(bad());
        }
        let before = if let Some(reserve) = self.previous_reserve {
            let port = hostname_port(&self.before).ok_or_else(bad)?;
            validate_named_addresses(&self.before, &self.resolved_before)?;
            if supervisor::canonical_transport(reserve) != Some(reserve)
                || reserve.port() == port && self.resolved_before.is_empty()
                || self.resolved_before.contains(&reserve)
            {
                return Err(bad());
            }
            reserve
        } else if let Some(&active) = self.resolved_before.first() {
            validate_named_addresses(&self.before, &self.resolved_before)?;
            active
        } else {
            literal_transport(&self.before).ok_or_else(bad)?
        };
        let after = if self.resolved_after.is_empty() {
            literal_transport(&self.after).ok_or_else(bad)?
        } else {
            selected_named_address(&self.after, &self.resolved_after)?
        };
        if before == after && !self.has_hostname() {
            return Err(bad());
        }
        Ok((before, after))
    }
}

pub(in crate::client) fn hostname_port(endpoint: &str) -> Option<u16> {
    let (host, port) = conf::endpoint(endpoint).ok()?;
    host.parse::<IpAddr>().is_err().then_some(port)
}

pub(in crate::client) fn validate_named_addresses(raw: &str, addresses: &[SocketAddr]) -> io::Result<()> {
    let bad = || invalid("неверные записанные адреса имени endpoint AWG");
    let port = hostname_port(raw).ok_or_else(bad)?;
    if addresses.len() > MAX_HOST_ADDRESSES {
        return Err(bad());
    }
    let mut unique = std::collections::BTreeSet::new();
    for &ip in addresses {
        if ip.port() != port
            || supervisor::canonical_transport(ip) != Some(ip)
            || !unique.insert(ip)
        {
            return Err(bad());
        }
    }
    Ok(())
}

pub(in crate::client) fn selected_named_address(
    raw: &str,
    addresses: &[SocketAddr],
) -> io::Result<SocketAddr> {
    validate_named_addresses(raw, addresses)?;
    addresses
        .iter()
        .copied()
        .find(SocketAddr::is_ipv4)
        .ok_or_else(|| invalid("имя endpoint AWG не разрешилось в IPv4"))
}

/// DNS answers prepared outside operation locks for one exact profile edit.
pub struct PreparedRoutedEndpointEdit {
    id: String,
    iface: String,
    revision: u64,
    previous: [u8; 32],
    before: String,
    after: String,
    resolved_after: Vec<SocketAddr>,
    previous_reserve: Option<(SocketAddr, Vec<SocketAddr>)>,
}

#[derive(Default)]
struct NamedPredecessor {
    addresses: Vec<SocketAddr>,
    reserve: Option<SocketAddr>,
}

pub(super) fn literal_transport(text: &str) -> Option<SocketAddr> {
    if text.contains('%') {
        return None;
    }
    supervisor::canonical_transport(text.parse().ok()?)
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoutedMtuOuter {
    pub id: String,
    pub iface: String,
    pub peer_key_sha256: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutedMtuPeer {
    pub iface: String,
    pub outer_id: String,
    pub outer_iface: String,
    pub endpoint: SocketAddr,
    pub effective_mtu: u16,
    pub socket_mark: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutedNestedTransport {
    pub peer: RoutedMtuPeer,
    pub outer_endpoint: SocketAddr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutedDirectBackup {
    pub primary: SocketAddr,
    pub peer: RoutedMtuPeer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutedEndpointLaunch {
    Primary,
    Alternate(SocketAddr),
    Waiting,
}

impl RoutedEndpointLaunch {
    pub(super) fn from_pin(pin: Option<SocketAddr>) -> Self {
        pin.map_or(Self::Primary, Self::Alternate)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutedEndpointPredecessor {
    pub edit: RoutedMtuChange,
    pub peer: RoutedMtuPeer,
}

pub(super) struct RoutedMtuSample {
    pub endpoint: SocketAddr,
    pub effective_mtu: u16,
    pub socket_mark: u32,
    pub connected: bool,
    pub outer_endpoint: Option<SocketAddr>,
}

pub(super) type ParkRoutedMtu<'a> = dyn Fn(&RoutedMtuChange) -> io::Result<()> + 'a;
type ValidateRoutedEdit<'a> = dyn Fn(&RoutedMtuChange, &Spec, SocketAddr) -> io::Result<()> + 'a;
type ChooseRoutedLaunch<'a> =
    dyn Fn(&RoutedMtuChange, &Spec, SocketAddr) -> io::Result<RoutedEndpointLaunch> + 'a;
type ReadRoutedRetry<'a> = dyn Fn(&RoutedMtuChange) -> io::Result<RoutedEndpointLaunch> + 'a;
type PrepareRoutedRetry<'a> = dyn Fn(&RoutedMtuChange, SocketAddr) -> io::Result<()> + 'a;
type VerifyDirectWan<'a> = dyn Fn(SocketAddr, u32) -> bool + 'a;
type AdoptLegacy<'a> = dyn Fn(&Spec) -> io::Result<Option<Box<dyn Tunnel>>> + 'a;

#[derive(Clone, Copy)]
pub(super) struct RoutedRetryHooks<'a> {
    pub read: &'a ReadRoutedRetry<'a>,
    pub prepare: &'a PrepareRoutedRetry<'a>,
}

#[derive(Clone, Copy)]
struct RoutedEditHooks<'a> {
    validate: Option<&'a ValidateRoutedEdit<'a>>,
    park: &'a ParkRoutedMtu<'a>,
    initial: Option<InitialRoutedEditHooks<'a>>,
}

#[derive(Clone, Copy)]
struct InitialRoutedEditHooks<'a> {
    choose: &'a ChooseRoutedLaunch<'a>,
    prepare: &'a PrepareRoutedRetry<'a>,
    can_wait: bool,
    prepared: Option<&'a PreparedRoutedEndpointEdit>,
    verify_previous: &'a VerifyDirectWan<'a>,
    adopt_legacy: Option<&'a AdoptLegacy<'a>>,
}

#[derive(Clone, Copy)]
struct InitialRoutedLaunch<'a> {
    endpoint: SocketAddr,
    prepare: &'a PrepareRoutedRetry<'a>,
}

pub fn pending_routed_mtu(row: &Value) -> io::Result<Option<RoutedMtuChange>> {
    row.get(PENDING_ROUTED_MTU)
        .map(|saved| {
            serde_json::from_value(saved.clone())
                .map_err(|_| invalid("неверная запись ожидающей правки MTU"))
        })
        .transpose()
}

/// The successor might still need to acquire its interface or refresh its UDP exclusions.
pub fn routed_mtu_launch_pending(row: &Value) -> bool {
    row.get(PENDING_PROFILE).is_some()
}

/// The staged direct edit still has an original predecessor to retire.
pub fn routed_endpoint_initial_pending(row: &Value) -> io::Result<bool> {
    Ok(pending_routed_mtu(row)?
        .as_ref()
        .and_then(|change| direct_forward_endpoint(row, change))
        .is_some_and(|edit| !edit.has_hostname())
        && previous_fingerprint(row)?.is_some())
}

/// Verify the saved predecessor fingerprint against the confirmed direct edit.
pub fn routed_endpoint_predecessor_change(
    doc: &Value,
    row: &Value,
) -> io::Result<Option<RoutedMtuChange>> {
    if !routed_endpoint_initial_pending(row)? {
        return Ok(None);
    }
    check_saved_edit(doc, row)
}

/// Whether the exact saved hostname edit belongs to a directly managed profile.
pub fn routed_endpoint_named_allowed(row: &Value, change: &RoutedMtuChange) -> bool {
    change.endpoint_edit.as_ref().is_some_and(|edit| {
        let profile = if change.legacy_predecessor.is_some() {
            routed_legacy_edit_profile(row, change)
        } else {
            direct_endpoint_profile(row)
        };
        edit.has_hostname()
            && edit.sockets().is_ok()
            && row["id"] == change.id
            && (row["config"]["endpoint"] == edit.before || row["config"]["endpoint"] == edit.after)
            && change.before == change.after
            && change.nested_outer.is_none()
            && change.nested_endpoint.is_none()
            && profile
            && (row["config"]["endpoint"] != edit.before
                || edit.previous_reserve.is_none()
                || routed_endpoint_previous_reserve_allowed(row, change))
    })
}

fn legacy_edit_candidate(row: &Value) -> bool {
    let cfg = &row["config"];
    let client = &cfg["client"];
    cfg_is_imported(cfg)
        && cfg["enabled"] == true
        && row["applied_config"].is_null()
        && client["enabled"] == true
        && client["standby"] != true
        && client["double_tunnel_mode"] != "permanent"
        && s(client, "double_tunnel_id").is_empty()
}

fn legacy_endpoint_change(before: SocketAddr, after: SocketAddr, named: bool) -> bool {
    before.is_ipv4() == after.is_ipv4() && (named || before != after)
}

fn unambiguous_legacy_named_transport(
    row: &Value,
    raw: &str,
    endpoint: SocketAddr,
) -> io::Result<bool> {
    if hostname_port(raw) != Some(endpoint.port()) {
        return Ok(false);
    }
    // The retiring name is pinned from the owner, without a fresh DNS lookup.
    // Any unresolved reserve or share of its IP would make that claim ambiguous.
    Ok(configured_endpoint_backups(row, raw)?
        .iter()
        .all(|backup| literal_transport(backup).is_some_and(|backup| backup.ip() != endpoint.ip())))
}

/// Scope and exact saved endpoint for a confirmed Go predecessor handover.
pub fn routed_legacy_edit_profile(row: &Value, change: &RoutedMtuChange) -> bool {
    let Some(previous) = &change.legacy_predecessor else {
        return false;
    };
    let cfg = &row["config"];
    legacy_edit_candidate(row)
        && (cfg["client"].get("rust_managed").is_none() || cfg["client"]["rust_managed"] == true)
        && row["id"] == change.id
        && change.nested_outer.is_none()
        && change.nested_endpoint.is_none()
        && change.valid_mtu_provenance()
        && previous.receipt_sha256 != [0; 32]
        && match &change.endpoint_edit {
            Some(edit) => {
                (cfg["endpoint"] == edit.before || cfg["endpoint"] == edit.after)
                    && edit.sockets().is_ok_and(|(before, after)| {
                        before == previous.endpoint
                            && legacy_endpoint_change(before, after, edit.has_hostname())
                    })
                    && if edit.has_hostname() {
                        change.before == change.after
                            && edit.previous_reserve.is_none()
                            && if edit.resolved_after.is_empty() {
                                edit.resolved_before == [previous.endpoint]
                                    && unambiguous_legacy_named_transport(
                                        row,
                                        &edit.before,
                                        previous.endpoint,
                                    )
                                    .is_ok_and(|unambiguous| unambiguous)
                            } else {
                                edit.resolved_before.is_empty()
                                    && literal_transport(&edit.before) == Some(previous.endpoint)
                            }
                    } else {
                        change.before == change.after || matches_paired_mtu(row, change)
                    }
            }
            None => {
                change.before != change.after
                    && (576..=9000).contains(&change.before)
                    && (1280..=1500).contains(&change.after)
                    && literal_transport(s(cfg, "endpoint")) == Some(previous.endpoint)
                    && if change.legacy_mtu_before_recorded {
                        change.saved_mtu(row).is_some()
                    } else {
                        effective_mtu(row)
                            .is_ok_and(|mtu| [change.before, change.after].contains(&mtu))
                    }
            }
        }
}

/// A fixed literal primary or reserve and exact MTU on either side of a native edit.
pub fn routed_native_mtu_edit_profile(row: &Value, change: &RoutedMtuChange) -> bool {
    change.valid_mtu_provenance()
        && row["id"] == change.id
        && direct_endpoint_profile(row)
        && change.native_mtu_endpoint.is_some_and(|endpoint| {
            let configured = s(&row["config"], "endpoint");
            literal_transport(configured).is_some_and(|primary| {
                primary == endpoint
                    || has_configured_backup(row, configured, endpoint).is_ok_and(|found| found)
            })
        })
        && [change.before, change.after]
            .into_iter()
            .all(|mtu| (1280..=1500).contains(&mtu))
        && change.saved_mtu(row).is_some()
}

/// An unchanged permanent inner transport and selected outer across an exact MTU edit.
pub fn routed_nested_mtu_edit_profile(row: &Value, change: &RoutedMtuChange) -> bool {
    let Some(primary) = permanent_nested_primary(row) else {
        return false;
    };
    let cfg = &row["config"];
    let client = &cfg["client"];
    change.valid_mtu_provenance()
        && change.nested_mtu_before_recorded
        && row["id"] == change.id
        && client["standby"] != true
        && change
            .nested_outer
            .as_ref()
            .is_some_and(|outer| client["double_tunnel_id"] == outer.id)
        && change.fixed_nested_mtu_endpoint().is_some_and(|pin| {
            if pin == primary {
                change.nested_endpoint.as_deref() == cfg["endpoint"].as_str()
            } else {
                change.nested_endpoint.as_deref() == Some(pin.to_string().as_str())
                    && routing_permanent_nested_reserve(row, pin).is_ok_and(|configured| configured)
            }
        })
        && [change.before, change.after]
            .into_iter()
            .all(|mtu| (1280..=1500).contains(&mtu))
        && change.saved_mtu(row).is_some()
}

/// Bind the exact numeric endpoint, raw setting and effective MTU for either side.
pub fn routed_combined_endpoint_mtu_profile(row: &Value, change: &RoutedMtuChange) -> bool {
    if !change.combines_endpoint_mtu() {
        return false;
    }
    if change.legacy_predecessor.is_some() {
        return routed_legacy_edit_profile(row, change);
    }
    let nested = change.nested_outer.as_ref();
    let eligible = if let Some(outer) = nested {
        let client = &row["config"]["client"];
        permanent_nested_primary(row).is_some()
            && client["standby"] != true
            && client["double_tunnel_id"] == outer.id
            && outer.peer_key_sha256 != [0; 32]
    } else {
        direct_endpoint_profile(row)
    };
    row["id"] == change.id
        && eligible
        && change.valid_mtu_provenance()
        && change.nested_endpoint.is_none()
        && matches_paired_mtu(row, change)
        && change
            .endpoint_edit
            .as_ref()
            .is_some_and(|edit| !edit.has_hostname() && edit.sockets().is_ok())
}

fn matches_paired_mtu(row: &Value, change: &RoutedMtuChange) -> bool {
    [change.before, change.after]
        .into_iter()
        .all(|mtu| (1280..=1500).contains(&mtu))
        && change
            .saved_mtu(row)
            .is_some_and(|mtu| change.matches_saved_mtu(row, mtu))
}

/// Check the old explicit reserve using the old name's port and current saved pool.
pub fn routed_endpoint_previous_reserve_allowed(row: &Value, change: &RoutedMtuChange) -> bool {
    change.endpoint_edit.as_ref().is_some_and(|edit| {
        edit.previous_reserve.is_some_and(|reserve| {
            row["id"] == change.id
                && (row["config"]["endpoint"] == edit.before
                    || row["config"]["endpoint"] == edit.after)
                && direct_endpoint_profile(row)
                && edit.sockets().is_ok()
                && has_configured_backup(row, &edit.before, reserve).unwrap_or(false)
        })
    })
}

/// Return the admitted addresses for the currently selected raw hostname.
pub fn routed_hostname_addresses(doc: &Value, row: &Value) -> io::Result<Option<Vec<SocketAddr>>> {
    let Some(change) = pending_routed_mtu(row)? else {
        return Ok(None);
    };
    let raw = s(&row["config"], "endpoint");
    let Some(addresses) = change
        .endpoint_edit
        .as_ref()
        .and_then(|edit| edit.pinned_addresses(raw))
    else {
        return Ok(None);
    };
    if !routed_endpoint_named_allowed(row, &change)
        || check_saved_edit(doc, row)?.as_ref() != Some(&change)
    {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    Ok(Some(addresses.to_vec()))
}

/// The current configured numeric pool of a launched direct forward edit.
/// Routing must still authorize the policy and each selected address.
pub fn routed_endpoint_retry_pool(
    row: &Value,
    change: &RoutedMtuChange,
) -> io::Result<Vec<SocketAddr>> {
    let Some(edit) = direct_forward_endpoint(row, change) else {
        return Ok(Vec::new());
    };
    if edit.has_hostname()
        || routed_mtu_launch_pending(row)
        || pending_routed_mtu(row)?.is_some_and(|saved| saved != *change)
    {
        return Ok(Vec::new());
    }
    edit.sockets()?;
    routing_direct_backup_pool(row)
}

/// The current numeric primary and configured direct reserves in saved order.
pub fn routing_direct_backup_pool(row: &Value) -> io::Result<Vec<SocketAddr>> {
    let Some((primary, backups)) = direct_endpoint_pool(row)? else {
        return Ok(Vec::new());
    };
    Ok(std::iter::once(primary)
        .chain(backups.iter().filter_map(|value| literal_transport(value)))
        .collect())
}

/// The entire direct pool when every configured tuple is a numeric literal.
pub fn routing_direct_literal_pool(row: &Value) -> io::Result<Option<Vec<SocketAddr>>> {
    if !direct_endpoint_profile(row) {
        return Ok(None);
    }
    configured_literal_endpoint_pool(row)
}

pub(super) fn configured_literal_endpoint_pool(row: &Value) -> io::Result<Option<Vec<SocketAddr>>> {
    let Some((primary, backups)) = configured_endpoint_pool(row)? else {
        return Ok(None);
    };
    Ok(std::iter::once(Some(primary))
        .chain(backups.iter().map(|value| literal_transport(value)))
        .collect())
}

fn direct_endpoint_pool(row: &Value) -> io::Result<Option<(SocketAddr, Vec<String>)>> {
    if !direct_endpoint_profile(row) {
        return Ok(None);
    }
    configured_endpoint_pool(row)
}

fn configured_endpoint_pool(row: &Value) -> io::Result<Option<(SocketAddr, Vec<String>)>> {
    let configured = s(&row["config"], "endpoint");
    let Some(primary) = literal_transport(configured) else {
        return Ok(None);
    };
    let backups = configured_endpoint_backups(row, configured)?;
    Ok(Some((primary, backups)))
}

fn configured_endpoint_backups(row: &Value, configured: &str) -> io::Result<Vec<String>> {
    if let Some(backups) = row["config"]["client"]
        .get("endpoint_backups")
        .filter(|v| !v.is_null())
    {
        let backups: Vec<String> = serde_json::from_value(backups.clone())
            .map_err(|_| invalid("неверный список резервных endpoint AWG"))?;
        supervisor::normalize(configured, &backups)
    } else {
        Ok(Vec::new())
    }
}

fn has_configured_backup(row: &Value, configured: &str, endpoint: SocketAddr) -> io::Result<bool> {
    Ok(configured_endpoint_backups(row, configured)?
        .iter()
        .any(|candidate| literal_transport(candidate) == Some(endpoint)))
}

pub(super) fn permanent_nested_primary(row: &Value) -> Option<SocketAddr> {
    let cfg = &row["config"];
    let client = &cfg["client"];
    if cfg["enabled"] != true
        || !cfg_is_imported(cfg)
        || client["enabled"] != true
        || client["rust_managed"] != true
        || client["double_tunnel_mode"] != "permanent"
        || !row["applied_config"].is_null()
    {
        return None;
    }
    literal_transport(s(cfg, "endpoint"))
}

/// A normalized numeric reserve of an eligible permanent nested profile.
pub fn routing_permanent_nested_reserve(row: &Value, endpoint: SocketAddr) -> io::Result<bool> {
    let Some(primary) = permanent_nested_primary(row) else {
        return Ok(false);
    };
    if primary == endpoint {
        return Ok(false);
    }
    has_configured_backup(row, s(&row["config"], "endpoint"), endpoint)
}

fn verified_permanent_nested_transport(
    doc: &Value,
    row: &Value,
    managed: &Managed,
    endpoint: SocketAddr,
    socket_mark: u32,
) -> io::Result<Option<RoutedNestedTransport>> {
    let Some(primary) = permanent_nested_primary(row) else {
        return Ok(None);
    };
    if managed.tunnel.inherited()
        || routed_mtu_launch_pending(row)
        || socket_mark >> 28 != 0xa
        || nested_socket_selector(&managed.iface)?.0 != socket_mark
        || endpoint != primary && !routing_permanent_nested_reserve(row, endpoint)?
    {
        return Ok(None);
    }
    verified_owned_nested_transport(doc, row, managed, endpoint, socket_mark)
}

fn verified_owned_nested_transport(
    doc: &Value,
    row: &Value,
    managed: &Managed,
    endpoint: SocketAddr,
    socket_mark: u32,
) -> io::Result<Option<RoutedNestedTransport>> {
    let iface = &managed.iface;
    let spec = specification(doc, row)?;
    let fingerprint: [u8; 32] = Sha256::digest(spec.conf.as_bytes()).into();
    if &spec.iface != iface || managed.fingerprint != fingerprint {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    let (selected, outer) = routed_outer(doc, &spec.id)?;
    let sample = managed
        .tunnel
        .verified_routed_mtu(&spec, Some(&outer), true)?;
    if !sample.connected || sample.endpoint != endpoint || sample.socket_mark != socket_mark {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    Ok(Some(RoutedNestedTransport {
        outer_endpoint: sample.outer_endpoint.ok_or(io::ErrorKind::WouldBlock)?,
        peer: RoutedMtuPeer {
            iface: spec.iface,
            outer_id: selected.id,
            outer_iface: selected.iface,
            endpoint,
            effective_mtu: sample.effective_mtu,
            socket_mark,
        },
    }))
}

pub(super) fn verify_retained_optional_nested(
    doc: &Value,
    row: &Value,
    managed: &Managed,
) -> io::Result<Option<RoutedNestedTransport>> {
    let cfg = &row["config"];
    let client = &cfg["client"];
    if managed.tunnel.inherited()
        || managed.tunnel.nested_iface().is_none()
        || routed_mtu_launch_pending(row)
        || cfg["enabled"] != true
        || client["enabled"] != true
        || client["rust_managed"] != true
        || client["standby"] == true
        || client["double_tunnel_mode"] == "permanent"
        || !cfg_is_imported(cfg)
        || !row["applied_config"].is_null()
    {
        return Ok(None);
    }
    let endpoint = literal_transport(s(cfg, "endpoint")).ok_or(io::ErrorKind::WouldBlock)?;
    let (mark, _) = nested_socket_selector(&managed.iface)?;
    verified_owned_nested_transport(doc, row, managed, endpoint, mark)
}

pub(super) fn verified_permanent_nested_resume<'a>(
    doc: &Value,
    row: &Value,
    managed: &Managed,
    snapshot: &'a Value,
) -> Option<&'a Value> {
    if !managed.tunnel.resumed() || snapshot["connected"] != true {
        return None;
    }
    let endpoint = supervisor::live_transport_endpoint(snapshot)?;
    let mark = u32::try_from(snapshot["socket_mark"].as_u64()?).ok()?;
    verified_permanent_nested_transport(doc, row, managed, endpoint, mark).ok()??;
    Some(snapshot)
}

pub(super) fn direct_forward_endpoint<'a>(
    row: &Value,
    change: &'a RoutedMtuChange,
) -> Option<&'a RoutedEndpointEdit> {
    let edit = change.endpoint_edit.as_ref()?;
    (row["id"] == change.id
        && row["config"]["endpoint"] == edit.after
        && change.nested_outer.is_none()
        && change.nested_endpoint.is_none()
        && change.legacy_predecessor.is_none()
        && !change.combines_endpoint_mtu()
        && direct_endpoint_profile(row))
    .then_some(edit)
}

pub(in crate::client) fn direct_endpoint_profile(row: &Value) -> bool {
    let cfg = &row["config"];
    let client = &cfg["client"];
    cfg_is_imported(cfg)
        && row["applied_config"].is_null()
        && cfg["enabled"] == true
        && client["enabled"] == true
        && client["rust_managed"] == true
        && client["standby"] != true
        && client["double_tunnel_mode"] != "permanent"
        && s(client, "double_tunnel_id").is_empty()
}

/// The routing transaction calls this after it binds the verified new peer.
pub fn finish_routed_mtu(row: &mut Value, expected: &RoutedMtuChange) -> io::Result<()> {
    if routed_mtu_launch_pending(row) || pending_routed_mtu(row)?.as_ref() != Some(expected) {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    row.as_object_mut().unwrap().remove(PENDING_ROUTED_MTU);
    Ok(())
}

pub(in crate::client) fn confirmed_routing_revision(doc: &Value, id: &str) -> Option<u64> {
    let routing = &doc["rust_static_routing"];
    let revision = routing["committed_revision"]
        .as_u64()
        .or_else(|| routing["revision"].as_u64())?;
    (routing["pending_commit"] == false
        && routing["go_trial"] != true
        && routing["committed_targets"]
            .as_array()
            .is_some_and(|ids| ids.iter().any(|v| v == id)))
    .then_some(revision)
}

fn routed_mtu_admission(doc: &Value, id: &str) -> Option<u64> {
    let revision = confirmed_routing_revision(doc, id)?;
    let pending = doc["servers"]
        .as_array()?
        .iter()
        .any(|row| row.get(PENDING_ROUTED_MTU).is_some());
    (doc["rust_static_routing"]["revision"].as_u64() == Some(revision)
        && revision == doc["routing_revision"].as_u64().unwrap_or_default()
        && !pending)
        .then_some(revision)
}

fn effective_mtu(row: &Value) -> io::Result<u16> {
    let profile = wire(row);
    u16::try_from(crate::tunnel_mtu(profile, &profile["routing"]))
        .ok()
        .filter(|n| (576..=9000).contains(n))
        .ok_or_else(|| invalid("неверный MTU работающего профиля AWG"))
}

fn routed_mtu_change(
    doc: &Value,
    original: &Value,
    proposed: &Value,
    prepared: Option<&PreparedRoutedEndpointEdit>,
    predecessor: NamedPredecessor,
    legacy_predecessor: Option<RoutedLegacyPredecessor>,
    nested_outer: Option<RoutedMtuOuter>,
) -> io::Result<RoutedMtuChange> {
    let id = s(original, "id");
    let invalid_edit = || {
        invalid("для применённой политики AWG доступна отдельная правка MTU или endpoint импортированного профиля")
    };
    if !cfg_is_imported(&original["config"])
        || original["config"]["enabled"] != true
        || original["config"]["client"]["enabled"] != true
        || original["config"]["client"]["rust_managed"] != true && legacy_predecessor.is_none()
        || !original["applied_config"].is_null()
        || original.get(PENDING_PROFILE).is_some()
        || original.get(PENDING_ROUTED_MTU).is_some()
    {
        return Err(invalid_edit());
    }
    let before = effective_mtu(original)?;
    let after = effective_mtu(proposed)?;
    let old_endpoint = s(&original["config"], "endpoint");
    let new_endpoint = s(&proposed["config"], "endpoint");
    let (fields, endpoint_edit): (&[&str], _) = if old_endpoint != new_endpoint {
        let mut edit = RoutedEndpointEdit {
            before: old_endpoint.into(),
            after: new_endpoint.into(),
            resolved_before: predecessor.addresses,
            resolved_after: Vec::new(),
            previous_reserve: predecessor.reserve,
        };
        if let Some(prepared) = prepared {
            let old = specification(doc, original)?;
            let fingerprint: [u8; 32] = Sha256::digest(old.conf.as_bytes()).into();
            if prepared.id != id
                || prepared.iface != old.iface
                || prepared.previous != fingerprint
                || routed_mtu_admission(doc, id) != Some(prepared.revision)
                || prepared.before != old_endpoint
                || prepared.after != new_endpoint
            {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            edit.resolved_after.clone_from(&prepared.resolved_after);
        }
        edit.sockets()?;
        let fields: &[&str] = if before == after {
            &["endpoint"]
        } else {
            &["endpoint", "mtu"]
        };
        (fields, Some(edit))
    } else if before != after {
        (&["mtu"], None)
    } else {
        return Err(invalid_edit());
    };
    let mut same = proposed.clone();
    let cfg = same["config"].as_object_mut().unwrap();
    for &field in fields {
        if let Some(old) = original["config"].get(field) {
            cfg.insert(field.into(), old.clone());
        } else {
            cfg.remove(field);
        }
    }
    if same != *original {
        return Err(invalid_edit());
    }
    let legacy_mtu_before_recorded = legacy_predecessor.is_some() && endpoint_edit.is_none();
    let implicit_before_mtu =
        if endpoint_edit.is_some() && before != after || legacy_mtu_before_recorded {
            RoutedImplicitMtu::from_saved(original["config"].get("mtu"))
        } else {
            None
        };
    let change = RoutedMtuChange {
        id: id.to_owned(),
        iface: iface(original, doc)?,
        revision: routed_mtu_admission(doc, id).ok_or_else(invalid_edit)?,
        before,
        after,
        nested_outer,
        nested_endpoint: None,
        endpoint_edit,
        legacy_predecessor,
        implicit_before_mtu,
        legacy_mtu_before_recorded,
        nested_mtu_before_recorded: false,
        native_mtu_endpoint: None,
    };
    if change
        .endpoint_edit
        .as_ref()
        .is_some_and(RoutedEndpointEdit::has_hostname)
        && !routed_endpoint_named_allowed(proposed, &change)
    {
        return Err(invalid_edit());
    }
    if change.legacy_predecessor.is_some()
        && (!routed_legacy_edit_profile(proposed, &change)
            || !routed_legacy_edit_profile(original, &change))
    {
        return Err(invalid_edit());
    }
    if change.combines_endpoint_mtu()
        && (!routed_combined_endpoint_mtu_profile(original, &change)
            || !routed_combined_endpoint_mtu_profile(proposed, &change))
    {
        return Err(invalid_edit());
    }
    Ok(change)
}

fn routed_outer(doc: &Value, id: &str) -> io::Result<(RoutedMtuOuter, NestedOuter)> {
    let graph = FailoverGraph::load(doc)?;
    let (id, _) = graph
        .nested(id)
        .ok_or_else(|| invalid("внешний туннель правки MTU изменился"))?;
    let row = find(doc, id)?;
    let cfg = &row["config"];
    if cfg["enabled"] != true || cfg["client"]["enabled"] != true {
        return Err(invalid("внешний туннель правки MTU выключен"));
    }
    let outer = NestedOuter::from_spec(&specification(doc, row)?)?;
    let selected = RoutedMtuOuter {
        id: id.to_owned(),
        iface: outer.iface.clone(),
        peer_key_sha256: Sha256::digest(outer.peer_hex.as_bytes()).into(),
    };
    Ok((selected, outer))
}

fn expected_routed_outer(doc: &Value, change: &RoutedMtuChange) -> io::Result<Option<NestedOuter>> {
    change
        .nested_outer
        .as_ref()
        .map(|saved| {
            let (selected, outer) = routed_outer(doc, &change.id)?;
            if &selected != saved {
                return Err(invalid("владелец внешнего туннеля правки MTU изменился"));
            }
            if (change.nested_mtu_before_recorded || change.combines_nested_endpoint_mtu())
                && !recoverable_mtu_outer(find(doc, &saved.id)?)
            {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            Ok(outer)
        })
        .transpose()
}

fn recoverable_mtu_outer(row: &Value) -> bool {
    let client = &row["config"]["client"];
    client["standby"] != true || client["rust_managed"] == true
}

pub(super) fn previous_fingerprint(row: &Value) -> io::Result<Option<[u8; 32]>> {
    row.get(PENDING_PROFILE)
        .filter(|saved| *saved != TRANSPORT_REFRESH)
        .map(|value| {
            serde_json::from_value(value.clone())
                .map_err(|_| invalid("неверная запись ожидающей правки AWG"))
        })
        .transpose()
}

fn transport_refresh_pending(row: &Value) -> bool {
    row[PENDING_PROFILE] == TRANSPORT_REFRESH
}

fn source<'a>(obj: &'a Value, key: &str) -> io::Result<Option<&'a str>> {
    obj.get(key)
        .filter(|v| !v.is_null())
        .map(|v| {
            v.as_str()
                .ok_or_else(|| invalid("ожидается текстовое поле конфигурации AWG"))
        })
        .transpose()
}
fn text_fields(dst: &mut Value, src: &Value, fields: &[&str]) -> io::Result<()> {
    for name in fields {
        if let Some(v) = source(src, name)? {
            if v.chars().any(char::is_control) || v.len() > 4096 {
                return Err(invalid("недопустимый текст в конфигурации AWG"));
            }
            dst[*name] = json!(v.trim());
        }
    }
    Ok(())
}
fn number(
    dst: &mut Value,
    src: &Value,
    key: &str,
    range: std::ops::RangeInclusive<u64>,
    default: u64,
) -> io::Result<()> {
    if let Some(v) = src.get(key) {
        let n = v
            .as_u64()
            .filter(|v| *v == 0 || range.contains(v))
            .ok_or_else(|| invalid(&format!("параметр {key} вне диапазона")))?;
        dst[key] = json!(if n == 0 { default } else { n });
    }
    Ok(())
}
fn endpoint_for_host(host: &str, port: u16) -> String {
    if let Ok(ip) = host.parse::<IpAddr>() {
        SocketAddr::new(ip, port).to_string()
    } else {
        format!("{host}:{port}")
    }
}
fn connection(cfg: &mut Value, input: &Value, old: &Value) -> io::Result<()> {
    let c = &mut cfg["conn"];
    let submitted = &input["conn"];
    if cfg_is_imported(old) {
        return Ok(());
    }
    if !submitted.is_null() && !submitted.is_object() {
        return Err(invalid("неверные реквизиты SSH"));
    }
    if source(submitted, "expected_known_key")?
        .is_some_and(|expected| expected != s(c, "known_key"))
    {
        return Err(invalid("ключ SSH-хоста изменился во время редактирования"));
    }
    text_fields(c, submitted, &["host", "user", "auth_kind", "known_key"])?;
    number(c, submitted, "port", 1..=65535, 22)?;
    for key in ["password", "key_pem", "key_pass"] {
        if let Some(secret) = source(submitted, key)?.filter(|s| !s.trim().is_empty()) {
            if secret.len() > 64 * 1024 || secret.contains('\0') {
                return Err(invalid("неверное значение реквизитов SSH"));
            }
            c[key] = json!(secret);
        }
    }
    let host = s(c, "host");
    if !conf::hostname(host) && host.parse::<IpAddr>().is_err() {
        return Err(invalid("неверный адрес сервера SSH"));
    }
    if s(c, "user").is_empty() {
        c["user"] = json!("root");
    }
    if s(c, "auth_kind").is_empty() {
        c["auth_kind"] = json!("password");
    }
    let user = s(c, "user");
    if user.len() > 64
        || user.starts_with('-')
        || !user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        || !matches!(s(c, "auth_kind"), "password" | "key")
    {
        return Err(invalid("неверные реквизиты SSH"));
    }
    if ["host", "port", "user", "auth_kind"]
        .iter()
        .any(|k| c[*k] != old["conn"][*k])
    {
        c["known_key"] = json!("");
    }
    Ok(())
}
fn cfg_is_imported(cfg: &Value) -> bool {
    cfg["install"] == "imported"
}
fn valid_iface(v: &str) -> bool {
    !v.is_empty()
        && v.len() < 16
        && !v.starts_with('-')
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}
fn initialize_header_protection(cfg: &mut Value) -> io::Result<()> {
    use base64ct::{Base64, Encoding};
    let o = &mut cfg["obf"];
    if conf::EXTENSIONS
        .iter()
        .skip(16)
        .any(|(_, k)| o[*k] == true || o[*k].as_str().is_some_and(|v| !v.is_empty()))
    {
        return Ok(());
    }
    o["header_protection_key"] = json!(Base64::encode_string(&crate::peers::random()?));
    for k in ["s1", "s2", "s3", "s4"] {
        o[k] = json!(o[k].as_u64().unwrap_or(0).max(12));
    }
    for (k, v) in [
        ("rekey_after_time", "100-120"),
        ("rekey_timeout", "3-7"),
        ("reject_after_time", "150-180"),
        ("keepalive_timeout", "5-15"),
        ("max_handshake_attempts", "15-20"),
    ] {
        o[k] = json!(v);
    }
    o["random_trailers"] = json!(true);
    o["disable_cookies"] = json!(true);
    for peer in cfg["peers"].as_array_mut().into_iter().flatten() {
        if s(peer, "keepalive_range").is_empty() {
            peer["keepalive_range"] = json!("25-35");
        }
    }
    Ok(())
}
fn obf(cfg: &mut Value, input: &Value) -> io::Result<()> {
    let submitted = &input["obf"];
    if !submitted.is_null() && !submitted.is_object() {
        return Err(invalid("неверные поля формата AWG"));
    }
    for &(wire, field) in conf::EXTENSIONS {
        let Some(value) = submitted.get(field) else {
            continue;
        };
        let text = match value {
            Value::Number(v) => v.to_string(),
            Value::Bool(v) => v.to_string(),
            Value::String(v) => v.trim().into(),
            _ => return Err(invalid("неверное поле формата AWG")),
        };
        if text.len() > 8192 || text.chars().any(char::is_control) {
            return Err(invalid("неверное поле формата AWG"));
        }
        if text.is_empty() {
            if field != "header_protection_key" {
                cfg["obf"][field] = json!("");
            }
        } else {
            cfg["obf"][field] = conf::extension(wire, &text)?;
        }
    }
    if cfg["protocol"] != "wireguard" && cfg["traffic_obfuscation"] != false {
        conf::validate_obf(&cfg["obf"])?;
    }
    Ok(())
}
fn changed_wire(old: &Value, new: &Value) -> bool {
    let fields = [
        "install",
        "interface",
        "protocol",
        "protocol_version",
        "listen_port",
        "address",
        "subnet",
        "dns",
        "wan_iface",
        "endpoint",
    ];
    let active = |c: &Value| c["protocol"] != "wireguard" && c["traffic_obfuscation"] != false;
    let has_value = |v: &Value| !v.is_null() && v != "" && v != false;
    let format_changed = active(old) != active(new)
        || active(new)
            && conf::EXTENSIONS.iter().any(|(_, k)| {
                let a = &old["obf"][*k];
                let b = &new["obf"][*k];
                a != b && (has_value(a) || has_value(b))
            });
    fields.iter().any(|k| old[*k] != new[*k])
        || old["conn"]["host"] != new["conn"]["host"]
        || format_changed
}
fn proposal(row: &Value, input: &Value) -> io::Result<Value> {
    if !input.is_object() {
        return Err(invalid("ожидается объект конфигурации AWG"));
    }
    let old = &row["config"];
    let mut cfg = old.clone();
    text_fields(
        &mut cfg,
        input,
        &[
            "install",
            "interface",
            "address",
            "subnet",
            "dns",
            "wan_iface",
            "endpoint",
        ],
    )?;
    if !matches!(s(&cfg, "install"), "imported" | "userspace" | "apt")
        || cfg_is_imported(old) != cfg_is_imported(&cfg)
    {
        return Err(invalid("несовместимый тип подключения AWG"));
    }
    for key in ["protocol", "protocol_version"] {
        if let Some(v) = source(input, key)?.filter(|s| !s.is_empty()) {
            cfg[key] = json!(v);
        }
    }
    if !matches!(s(&cfg, "protocol"), "awg" | "wireguard")
        || !matches!(
            s(&cfg, "protocol_version"),
            "" | "1.0" | "1.5" | "2" | "2.0" | "3.1"
        )
    {
        return Err(invalid("неверный протокол или версия AWG"));
    }
    for key in ["enabled", "traffic_obfuscation"] {
        if let Some(v) = input.get(key).filter(|v| !v.is_null()) {
            let value = v
                .as_bool()
                .ok_or_else(|| invalid("ожидается логический параметр AWG"))?;
            if key != "enabled" || value || old["enabled"] != true {
                cfg[key] = json!(value);
            }
        }
    }
    number(&mut cfg, input, "listen_port", 1..=65535, 51820)?;
    number(&mut cfg, input, "mtu", 1280..=1500, 1420)?;
    connection(&mut cfg, input, old)?;
    if !valid_iface(s(&cfg, "interface"))
        || (!s(&cfg, "wan_iface").is_empty() && !valid_iface(s(&cfg, "wan_iface")))
    {
        return Err(invalid("неверное имя сетевого интерфейса"));
    }
    for k in ["address", "subnet"] {
        if s(&cfg, k).contains(',') {
            return Err(invalid("ожидается один адрес/префикс"));
        }
        conf::cidrs(s(&cfg, k), true)?;
    }
    let dns = s(&cfg, "dns");
    if !dns.is_empty()
        && dns
            .split(',')
            .map(str::trim)
            .any(|d| d.parse::<IpAddr>().is_err() && !conf::hostname(d))
    {
        return Err(invalid("неверный адрес DNS"));
    }
    if !cfg_is_imported(&cfg) && s(&cfg, "endpoint").is_empty() {
        cfg["endpoint"] = json!(endpoint_for_host(
            s(&cfg["conn"], "host"),
            cfg["listen_port"].as_u64().unwrap_or(51820) as u16
        ));
    }
    conf::endpoint(s(&cfg, "endpoint"))?;
    if let Some(backups) = cfg["client"]["endpoint_backups"].as_array() {
        let list = backups
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| invalid("неверный резервный endpoint"))
            })
            .collect::<io::Result<Vec<_>>>()?;
        super::supervisor::normalize(s(&cfg, "endpoint"), &list)?;
    }
    obf(&mut cfg, input)?;
    if !cfg_is_imported(&cfg)
        && input["traffic_obfuscation"] == true
        && cfg["protocol"] == "awg"
        && cfg["protocol_version"] == "3.1"
        && (old["deployed_at"].as_u64().unwrap_or(0) == 0
            || cfg["protocol_version"] != old["protocol_version"]
            || old["traffic_obfuscation"] == false)
    {
        initialize_header_protection(&mut cfg)?;
    }
    let mut result = row.clone();
    if !cfg_is_imported(old)
        && row["applied_config"].is_null()
        && old["deployed_at"].as_u64().unwrap_or(0) > 0
        && changed_wire(old, &cfg)
    {
        result["applied_config"] = old.clone();
    }
    result["config"] = cfg;
    Ok(result)
}
impl Runtime {
    /// Attest an active configured direct reserve without changing its runtime choice.
    pub fn routing_direct_backup(
        &self,
        db: &Store,
        iface: &str,
        endpoint: SocketAddr,
        socket_mark: u32,
        wan: &[String],
    ) -> io::Result<Option<RoutedDirectBackup>> {
        self.routing_direct_backup_inner(db, iface, endpoint, socket_mark, |endpoint, mark| {
            self.verifies_live_wan(endpoint, mark, wan)
        })
    }

    fn routing_direct_backup_inner(
        &self,
        db: &Store,
        iface: &str,
        endpoint: SocketAddr,
        socket_mark: u32,
        verify_wan: impl FnOnce(SocketAddr, u32) -> bool,
    ) -> io::Result<Option<RoutedDirectBackup>> {
        if !matches!(socket_mark, 0 | crate::DIRECT_SOCKET_MARK) {
            return Ok(None);
        }
        let Some(endpoint) = supervisor::canonical_transport(endpoint) else {
            return Ok(None);
        };
        let owned = self
            .clients
            .0
            .try_lock()
            .map_err(|_| io::ErrorKind::WouldBlock)?;
        let mut owners = owned.iter().filter(|(_, managed)| managed.iface == iface);
        let Some((id, managed)) = owners.next() else {
            return Ok(None);
        };
        if owners.next().is_some()
            || managed.tunnel.inherited()
            || managed.tunnel.nested_iface().is_some()
        {
            return Ok(None);
        }
        let doc = read(db)?;
        let row = find(&doc, id)?;
        if routed_mtu_launch_pending(row) || pending_routed_mtu(row)?.is_some() {
            return Ok(None);
        }
        let pool = routing_direct_backup_pool(row)?;
        let [primary, backups @ ..] = pool.as_slice() else {
            return Ok(None);
        };
        if primary.ip() == endpoint.ip() || !backups.contains(&endpoint) {
            return Ok(None);
        }
        let spec = specification(&doc, row)?;
        let peer = owned_direct_witness(
            &spec,
            managed,
            endpoint,
            socket_mark,
            effective_mtu(row)?,
            verify_wan,
        )?;
        Ok(Some(RoutedDirectBackup {
            primary: *primary,
            peer,
        }))
    }

    /// Read the still-owned configuration awaiting replacement. Routing must
    /// independently confirm that no retirement authorization exists.
    pub fn routing_endpoint_predecessor(
        &self,
        db: &Store,
        iface: &str,
        endpoint: SocketAddr,
        socket_mark: u32,
        wan: &[String],
    ) -> io::Result<Option<RoutedEndpointPredecessor>> {
        self.routing_endpoint_predecessor_inner(
            db,
            iface,
            endpoint,
            socket_mark,
            |endpoint, mark| self.verifies_live_wan(endpoint, mark, wan),
        )
    }

    fn routing_endpoint_predecessor_inner(
        &self,
        db: &Store,
        iface: &str,
        endpoint: SocketAddr,
        socket_mark: u32,
        verify_wan: impl FnOnce(SocketAddr, u32) -> bool,
    ) -> io::Result<Option<RoutedEndpointPredecessor>> {
        if !matches!(socket_mark, 0 | crate::DIRECT_SOCKET_MARK) {
            return Ok(None);
        }
        let Some(endpoint) = supervisor::canonical_transport(endpoint) else {
            return Ok(None);
        };
        let owned = self
            .clients
            .0
            .try_lock()
            .map_err(|_| io::ErrorKind::WouldBlock)?;
        let mut owners = owned.iter().filter(|(_, managed)| managed.iface == iface);
        let Some((id, managed)) = owners.next() else {
            return Ok(None);
        };
        if owners.next().is_some()
            || managed.tunnel.inherited()
            || managed.tunnel.nested_iface().is_some()
        {
            return Ok(None);
        }
        let doc = read(db)?;
        let row = find(&doc, id)?;
        let Some(edit) = routed_endpoint_predecessor_change(&doc, row)? else {
            return Ok(None);
        };
        let before = &edit
            .endpoint_edit
            .as_ref()
            .ok_or(io::ErrorKind::WouldBlock)?
            .before;
        let mut predecessor = row.clone();
        predecessor["config"]["endpoint"] = json!(before);
        if !routing_direct_backup_pool(&predecessor)?.contains(&endpoint) {
            return Ok(None);
        }
        let spec = specification(&doc, &predecessor)?;
        let peer = owned_direct_witness(
            &spec,
            managed,
            endpoint,
            socket_mark,
            edit.before,
            verify_wan,
        )?;
        Ok(Some(RoutedEndpointPredecessor { edit, peer }))
    }

    /// Attest one active permanent nested transport without admitting a direct path.
    pub fn routing_nested_transport(
        &self,
        db: &Store,
        iface: &str,
        endpoint: SocketAddr,
        socket_mark: u32,
    ) -> io::Result<Option<RoutedNestedTransport>> {
        if socket_mark >> 28 != 0xa || nested_socket_selector(iface)?.0 != socket_mark {
            return Ok(None);
        }
        let Some(endpoint) = supervisor::canonical_transport(endpoint) else {
            return Ok(None);
        };
        let owned = self
            .clients
            .0
            .try_lock()
            .map_err(|_| io::ErrorKind::WouldBlock)?;
        let mut owners = owned.iter().filter(|(_, managed)| managed.iface == iface);
        let Some((id, managed)) = owners.next() else {
            return Ok(None);
        };
        if owners.next().is_some() || managed.tunnel.inherited() {
            return Ok(None);
        }
        let doc = read(db)?;
        let row = find(&doc, id)?;
        verified_permanent_nested_transport(&doc, row, managed, endpoint, socket_mark)
    }

    /// Verify an owned daemon while routing reads its Store transaction.
    /// Nonblocking client ownership avoids inversion with a concurrent save.
    pub fn routed_mtu_peer(
        &self,
        db: &Store,
        change: &RoutedMtuChange,
    ) -> io::Result<Option<RoutedMtuPeer>> {
        self.routed_mtu_peer_inner(db, change, None, |_, _| false)
    }

    /// Attest the exact tuple authorized by the routing journal for this edit.
    pub fn routed_mtu_peer_at(
        &self,
        db: &Store,
        change: &RoutedMtuChange,
        endpoint: SocketAddr,
        wan: &[String],
    ) -> io::Result<Option<RoutedMtuPeer>> {
        let check_marked_legacy_wan = change.legacy_predecessor.is_some()
            && (change.combines_endpoint_mtu()
                || change.endpoint_edit.as_ref().is_some_and(|edit| {
                    edit.has_hostname()
                        || edit
                            .sockets()
                            .is_ok_and(|(before, after)| before.ip() != after.ip())
                }));
        self.routed_mtu_peer_inner(db, change, Some(endpoint), |endpoint, mark| {
            self.verifies_live_wan_path(
                endpoint,
                mark,
                wan,
                check_marked_legacy_wan
                    || change.records_mtu_before()
                    || change.combines_direct_cross_family_mtu(),
            )
        })
    }

    fn routed_mtu_peer_inner(
        &self,
        db: &Store,
        change: &RoutedMtuChange,
        expected: Option<SocketAddr>,
        verify_wan: impl FnOnce(SocketAddr, u32) -> bool,
    ) -> io::Result<Option<RoutedMtuPeer>> {
        if !change.requires_peer_proof() {
            return Ok(None);
        }
        let owned = self
            .clients
            .0
            .try_lock()
            .map_err(|_| io::ErrorKind::WouldBlock)?;
        let doc = read(db)?;
        let row = find(&doc, &change.id)?;
        let mtu = effective_mtu(row)?;
        let cfg = &row["config"];
        let marker = pending_routed_mtu(row)?;
        let saved_mtu = change.saved_mtu(row);
        let combined = change.combines_endpoint_mtu();
        let combined_nested = change.combines_nested_endpoint_mtu();
        if routed_mtu_launch_pending(row)
            || !change.valid_mtu_provenance()
            || marker
                .as_ref()
                .is_some_and(|saved| saved != change || saved_mtu != Some(mtu))
            || ![change.before, change.after].contains(&mtu)
            || confirmed_routing_revision(&doc, &change.id) != Some(change.revision)
            || cfg["enabled"] != true
            || cfg["client"]["enabled"] != true
            || cfg["client"]["rust_managed"] != true
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let selection = change.endpoint_selection(row)?;
        let endpoint = selection
            .as_ref()
            .map(|endpoint| endpoint.chosen)
            .or_else(|| change.fixed_mtu_endpoint());
        if endpoint.is_some()
            && (saved_mtu != Some(mtu)
                || combined && !routed_combined_endpoint_mtu_profile(row, change)
                || change.nested_endpoint.is_some()
                || !cfg_is_imported(cfg)
                || !row["applied_config"].is_null()
                || change.legacy_predecessor.is_some() && !routed_legacy_edit_profile(row, change)
                || change.native_mtu_endpoint.is_some()
                    && !routed_native_mtu_edit_profile(row, change)
                || change.endpoint_edit.as_ref().is_some_and(|edit| {
                    edit.has_hostname() && !routed_endpoint_named_allowed(row, change)
                })
                || marker.is_some() && check_saved_edit(&doc, row)?.as_ref() != Some(change))
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let outer = expected_routed_outer(&doc, change)?;
        let spec = specification(&doc, row)?;
        let managed = owned.get(&change.id).ok_or(io::ErrorKind::WouldBlock)?;
        let sample = owned_routed_sample(&spec, managed, &change.iface, outer.as_ref())?;
        let nested_pin = change.fixed_nested_mtu_endpoint();
        if let Some(pin) = nested_pin {
            if !routed_nested_mtu_edit_profile(row, change)
                || marker.is_some() && check_saved_edit(&doc, row)?.as_ref() != Some(change)
                || expected
                    .is_some_and(|wanted| supervisor::canonical_transport(wanted) != Some(pin))
                || !matches_nested_mtu_sample(&sample, &spec.iface, pin, mtu)
            {
                return Err(io::ErrorKind::WouldBlock.into());
            }
        }
        if combined_nested
            && !endpoint
                .is_some_and(|pin| matches_nested_mtu_sample(&sample, &spec.iface, pin, mtu))
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if (combined && !combined_nested || change.fixed_mtu_endpoint().is_some())
            && !endpoint.is_some_and(|endpoint| matches_direct_mtu_sample(&sample, endpoint, mtu))
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let reserve = endpoint.filter(|endpoint| *endpoint != sample.endpoint);
        if let Some(primary) = reserve {
            if expected == Some(primary)
                || expected.and_then(supervisor::canonical_transport) != Some(sample.endpoint)
                || !routed_endpoint_retry_pool(row, change)?.contains(&sample.endpoint)
            {
                return Err(io::ErrorKind::WouldBlock.into());
            }
        } else if endpoint.is_some()
            && expected.is_some_and(|selected| {
                supervisor::canonical_transport(selected) != Some(sample.endpoint)
            })
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        // A same-family numeric move can replace a full policy's exact WAN
        // exception, so confirm the new peer's actual marked path before FIB acknowledgement.
        let same_family_move = expected.is_some()
            && outer.is_none()
            && change.endpoint_edit.as_ref().is_some_and(|edit| {
                !edit.has_hostname()
                    && edit.sockets().is_ok_and(|(before, after)| {
                        before.is_ipv4() == after.is_ipv4() && before.ip() != after.ip()
                    })
            });
        let restored_reserve = expected.is_some()
            && selection
                .as_ref()
                .is_some_and(|endpoint| endpoint.restoring)
            && change
                .endpoint_edit
                .as_ref()
                .is_some_and(|edit| edit.previous_reserve.is_some());
        let wan_path = if let Some(pin) =
            nested_pin.filter(|pin| permanent_nested_primary(row) != Some(*pin))
        {
            // The reserve additionally remains an ordinary transport claim.
            Some((pin, 0))
        } else if reserve.is_some()
            || same_family_move
            || restored_reserve
            || change.fixed_mtu_endpoint().is_some()
            || combined && !combined_nested
        {
            Some((sample.endpoint, sample.socket_mark))
        } else {
            None
        };
        if wan_path.is_some_and(|(endpoint, mark)| !verify_wan(endpoint, mark)) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        Ok(Some(RoutedMtuPeer {
            iface: change.iface.clone(),
            outer_id: change
                .nested_outer
                .as_ref()
                .map_or_else(String::new, |selected| selected.id.clone()),
            outer_iface: change
                .nested_outer
                .as_ref()
                .map_or_else(String::new, |selected| selected.iface.clone()),
            endpoint: sample.endpoint,
            effective_mtu: sample.effective_mtu,
            socket_mark: sample.socket_mark,
        }))
    }

    pub fn save_config(&self, db: &Store, input: &Value, wan: &[String]) -> io::Result<()> {
        self.save_config_inner(db, input, wan, None, None).map(drop)
    }

    /// Resolve just the pending hostname request before routing takes its locks.
    pub fn prepare_routed_endpoint_edit(
        &self,
        db: &Store,
        input: &Value,
    ) -> io::Result<Option<PreparedRoutedEndpointEdit>> {
        prepare_routed_endpoint_edit_with(
            db,
            input,
            |raw, deadline, fresh| {
                if fresh {
                    crate::endpoint::resolve_fresh_endpoint_addresses(raw, deadline)
                } else {
                    crate::resolve_endpoint_addresses(raw, deadline)
                }
            },
            |spec| {
                let owned = match self.clients.0.try_lock() {
                    Ok(owned) => owned,
                    Err(std::sync::TryLockError::WouldBlock) => return Ok(None),
                    Err(std::sync::TryLockError::Poisoned(_)) => {
                        return Err(invalid("менеджер AWG недоступен"));
                    }
                };
                Ok(owned.get(&spec.id).and_then(|managed| {
                    owned_routed_sample(spec, managed, &spec.iface, None)
                        .ok()
                        .map(|sample| sample.endpoint)
                }))
            },
        )
    }

    pub fn save_config_with_transport(
        &self,
        db: &Store,
        input: &Value,
        wan: &[String],
        refresh: impl Fn(TransportBypassProof<'_>) -> io::Result<()>,
    ) -> io::Result<()> {
        self.save_config_inner(db, input, wan, Some(&refresh), None)
            .map(drop)
    }

    /// The caller holds the routing-operation lock and parks the exact saved
    /// change without reentering this runtime's deployment or client locks.
    pub fn save_config_with_routing(
        &self,
        db: &Store,
        input: &Value,
        wan: &[String],
        refresh: impl Fn(TransportBypassProof<'_>) -> io::Result<()>,
        park: impl Fn(&RoutedMtuChange) -> io::Result<()>,
    ) -> io::Result<()> {
        self.save_config_with_routing_report(db, input, wan, refresh, park)
            .map(drop)
    }

    /// Report a deferred runtime apply only after the new settings are saved.
    pub fn save_config_with_routing_report(
        &self,
        db: &Store,
        input: &Value,
        wan: &[String],
        refresh: impl Fn(TransportBypassProof<'_>) -> io::Result<()>,
        park: impl Fn(&RoutedMtuChange) -> io::Result<()>,
    ) -> io::Result<Option<String>> {
        self.save_config_inner(
            db,
            input,
            wan,
            Some(&refresh),
            Some(RoutedEditHooks {
                initial: None,
                validate: None,
                park: &park,
            }),
        )
    }

    /// The routing operation must prove an IP edit can preserve its confirmed policy.
    pub fn save_config_with_routing_preflight(
        &self,
        db: &Store,
        input: &Value,
        wan: &[String],
        refresh: impl Fn(TransportBypassProof<'_>) -> io::Result<()>,
        validate: impl Fn(&RoutedMtuChange) -> io::Result<()>,
        park: impl Fn(&RoutedMtuChange) -> io::Result<()>,
    ) -> io::Result<Option<String>> {
        let preflight = |change: &RoutedMtuChange, spec: &Spec, endpoint: SocketAddr| {
            self.preflight_saved_endpoint(change, spec, endpoint, wan)?;
            validate(change)
        };
        self.save_config_inner(
            db,
            input,
            wan,
            Some(&refresh),
            Some(RoutedEditHooks {
                initial: None,
                validate: Some(&preflight),
                park: &park,
            }),
        )
    }

    /// The routing operation may admit a viable direct reserve for the initial launch.
    pub fn save_config_with_routing_initial_retry(
        &self,
        db: &Store,
        input: &Value,
        wan: &[String],
        refresh: impl Fn(TransportBypassProof<'_>) -> io::Result<()>,
        validate: impl Fn(&RoutedMtuChange) -> io::Result<Option<SocketAddr>>,
        park: impl Fn(&RoutedMtuChange, Option<SocketAddr>) -> io::Result<()>,
    ) -> io::Result<Option<String>> {
        self.save_config_with_routing_launch(
            db,
            input,
            wan,
            &refresh,
            &|change| validate(change).map(RoutedEndpointLaunch::from_pin),
            &park,
            (false, None),
        )
    }

    /// Save a confirmed endpoint edit even while its entire direct pool awaits WAN.
    pub fn save_config_with_routing_endpoint_launch(
        &self,
        db: &Store,
        input: &Value,
        wan: &[String],
        refresh: impl Fn(TransportBypassProof<'_>) -> io::Result<()>,
        validate: impl Fn(&RoutedMtuChange) -> io::Result<RoutedEndpointLaunch>,
        park: impl Fn(&RoutedMtuChange, Option<SocketAddr>) -> io::Result<()>,
    ) -> io::Result<Option<String>> {
        self.save_config_with_routing_launch(
            db,
            input,
            wan,
            &refresh,
            &validate,
            &park,
            (true, None),
        )
    }

    pub fn save_config_with_prepared_routed_endpoint<F, P>(
        &self,
        db: &Store,
        input: &Value,
        wan: &[String],
        prepared: Option<&PreparedRoutedEndpointEdit>,
        refresh: impl Fn(TransportBypassProof<'_>) -> io::Result<()>,
        (validate, park): (F, P),
    ) -> io::Result<Option<String>>
    where
        F: Fn(&RoutedMtuChange) -> io::Result<RoutedEndpointLaunch>,
        P: Fn(&RoutedMtuChange, Option<SocketAddr>) -> io::Result<()>,
    {
        self.save_config_with_routing_launch(
            db,
            input,
            wan,
            &refresh,
            &validate,
            &park,
            (true, prepared),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn save_config_with_routing_launch(
        &self,
        db: &Store,
        input: &Value,
        wan: &[String],
        refresh: &RefreshTransport<'_>,
        validate: &ReadRoutedRetry<'_>,
        park: &dyn Fn(&RoutedMtuChange, Option<SocketAddr>) -> io::Result<()>,
        (can_wait, prepared): (bool, Option<&PreparedRoutedEndpointEdit>),
    ) -> io::Result<Option<String>> {
        let choose = |change: &RoutedMtuChange, spec: &Spec, endpoint: SocketAddr| {
            self.preflight_saved_endpoint(change, spec, endpoint, wan)?;
            validate(change)
        };
        self.save_config_inner(
            db,
            input,
            wan,
            Some(refresh),
            Some(RoutedEditHooks {
                validate: None,
                park: &|change| park(change, None),
                initial: Some(InitialRoutedEditHooks {
                    choose: &choose,
                    prepare: &|change, selected| park(change, Some(selected)),
                    can_wait,
                    prepared,
                    verify_previous: &|endpoint, mark| self.verifies_live_wan(endpoint, mark, wan),
                    adopt_legacy: Some(&|spec| self.adopt_legacy_edit(db, spec)),
                }),
            }),
        )
    }

    fn preflight_saved_endpoint(
        &self,
        change: &RoutedMtuChange,
        spec: &Spec,
        endpoint: SocketAddr,
        wan: &[String],
    ) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        if spec.outer.is_some() {
            let changing_ip = change.endpoint_edit.as_ref().is_some_and(|edit| {
                edit.sockets()
                    .is_ok_and(|(before, after)| before.ip() != after.ip())
            });
            let shared_wan = (spec.permanent
                && (changing_ip
                    || change.nested_mtu_before_recorded
                    || change.combines_nested_endpoint_mtu()))
            .then_some(wan);
            linux::preflight_nested_mtu(self, spec, endpoint, shared_wan)?;
        }
        #[cfg(not(target_os = "linux"))]
        let _ = (change, spec, endpoint, wan);
        Ok(())
    }

    fn save_config_inner(
        &self,
        db: &Store,
        input: &Value,
        wan: &[String],
        refresh: Option<&RefreshTransport<'_>>,
        routing: Option<RoutedEditHooks<'_>>,
    ) -> io::Result<Option<String>> {
        let _deployment = self.deployment_guard()?;
        self.clients.save_config(
            db,
            input,
            |spec| self.start_saved_edit(spec, wan),
            |name| self.present(name),
            |doc, owned, next, phase| {
                self.prepare_saved_edit(doc, owned, next, wan, refresh, phase)
            },
            routing,
        )
    }

    fn prepare_saved_edit(
        &self,
        doc: &Value,
        owned: &HashMap<String, Managed>,
        spec: &mut Spec,
        wan: &[String],
        refresh: Option<&RefreshTransport<'_>>,
        phase: EditPreparation,
    ) -> io::Result<()> {
        if let EditPreparation::VerifyDirectBeforeRetiring(endpoint, mark) = phase {
            return self
                .verifies_live_wan_path(endpoint, mark, wan, true)
                .then_some(())
                .ok_or_else(|| io::ErrorKind::WouldBlock.into());
        }
        if phase == EditPreparation::VerifyBeforeRetiring {
            let endpoint = literal_transport(&spec.endpoint)
                .ok_or_else(|| invalid("не подтверждён числовой endpoint вложенного AWG"))?;
            #[cfg(target_os = "linux")]
            linux::preflight_nested_mtu(self, spec, endpoint, Some(wan))?;
            #[cfg(not(target_os = "linux"))]
            let _ = endpoint;
            return Ok(());
        }
        let refresh = refresh.filter(|_| !spec.permanent || spec.outer.is_some());
        if refresh.is_some() || spec.outer.is_some() {
            let endpoint = resolve_endpoint(&spec.endpoint)?;
            #[cfg(target_os = "linux")]
            if spec.outer.is_some() {
                linux::preflight_nested_mtu(self, spec, endpoint, None)?;
            }
            if let Some(refresh) = refresh {
                self.capture_inherited_transport(doc, owned, wan)
                    .prepare(refresh, endpoint)?;
            }
            spec.endpoint = endpoint.to_string();
        }
        Ok(())
    }

    fn start_saved_edit(&self, spec: Spec, wan: &[String]) -> io::Result<Box<dyn Tunnel>> {
        self.record_nested(&spec.iface, false);
        self.start_local(spec, wan)
    }

    pub(super) fn recover_saved_edits(
        &self,
        db: &Store,
        wan: &[String],
        refresh: Option<&RefreshTransport<'_>>,
        park: Option<&ParkRoutedMtu<'_>>,
        retry: Option<RoutedRetryHooks<'_>>,
    ) -> io::Result<Vec<String>> {
        let mut owned = self
            .clients
            .0
            .lock()
            .map_err(|_| invalid("менеджер AWG недоступен"))?;
        let doc = read(db)?;
        let now = crate::now();
        let settings = crate::recovery_settings(&doc["recovery_settings"]);
        let mut warnings = Vec::new();
        for row in doc["servers"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|r| wants_saved_edit(r))
        {
            let id = s(row, "id");
            let mut cycling = false;
            let result = (|| {
                let spec = specification(&doc, row)?;
                let standby = row["config"]["client"]["standby"] == true;
                let routed_mtu = row.get(PENDING_ROUTED_MTU).is_some();
                if !standby || routed_mtu {
                    owned
                        .entry(id.into())
                        .or_insert_with(|| stopped_edit(&spec));
                }
                #[cfg(target_os = "linux")]
                if owned.get(id).is_none_or(|m| m.tunnel.is_stopped()) {
                    if let Some(managed) =
                        linux::resume_after_edit(self, &spec, previous_fingerprint(row)?)?
                    {
                        owned.insert(id.into(), managed);
                    } else if row["config"]["client"].get("rust_managed").is_none() {
                        if let Some(change) = check_saved_edit(&doc, row)? {
                            if let Some(legacy) = &change.legacy_predecessor {
                                let before = legacy_predecessor_spec(&doc, row, &change)?;
                                if let Some(managed) =
                                    self.replay_legacy_edit(db, &before, legacy)?
                                {
                                    owned.insert(id.into(), managed);
                                }
                            }
                        }
                    }
                }
                // A dormant backup belongs to the failover demand manager.
                if standby && !routed_mtu && owned.get(id).is_none_or(|m| m.tunnel.is_stopped()) {
                    return Ok(());
                }
                let mut initial = None;
                if let Some((hooks, change)) = retry.zip(pending_routed_mtu(row)?) {
                    if routed_mtu_launch_pending(row)
                        && direct_forward_endpoint(row, &change)
                            .is_some_and(|edit| !edit.has_hostname())
                        && check_saved_edit(&doc, row)?.as_ref() == Some(&change)
                    {
                        match (hooks.read)(&change) {
                            Ok(RoutedEndpointLaunch::Primary) => {}
                            Ok(RoutedEndpointLaunch::Alternate(endpoint)) => {
                                initial = Some(InitialRoutedLaunch {
                                    endpoint,
                                    prepare: hooks.prepare,
                                });
                            }
                            Ok(RoutedEndpointLaunch::Waiting) => {
                                if !routed_endpoint_initial_pending(row)?
                                    || routing_direct_literal_pool(row)?.is_none()
                                {
                                    return Err(io::ErrorKind::WouldBlock.into());
                                }
                                if owned
                                    .get(id)
                                    .is_some_and(|m| m.recovery.retry_at(&settings) > now)
                                {
                                    return Ok(());
                                }
                                return Err(waiting_for_wan());
                            }
                            Err(error) if error.kind() == io::ErrorKind::Unsupported => {}
                            Err(error) => {
                                cycling = true;
                                return Err(error);
                            }
                        }
                    }
                    let candidates = routed_endpoint_retry_pool(row, &change)?;
                    if !candidates.is_empty()
                        && check_saved_edit(&doc, row)?.as_ref() == Some(&change)
                    {
                        let authorized = match (hooks.read)(&change) {
                            Ok(RoutedEndpointLaunch::Primary) => Some(None),
                            Ok(RoutedEndpointLaunch::Alternate(endpoint)) => Some(Some(endpoint)),
                            Ok(RoutedEndpointLaunch::Waiting) => {
                                return Err(io::ErrorKind::WouldBlock.into())
                            }
                            Err(error) if error.kind() == io::ErrorKind::Unsupported => None,
                            Err(error) => {
                                cycling = true;
                                return Err(error);
                            }
                        };
                        if let Some(authorized) =
                            authorized.filter(|selected| candidates.len() > 1 || selected.is_some())
                        {
                            cycling = true;
                            let inherited = refresh
                                .map(|_| self.capture_inherited_transport(&doc, &owned, wan));
                            let transport = refresh.zip(inherited.as_ref());
                            let prepare = |selected: SocketAddr| {
                                if !candidates.contains(&selected)
                                    || check_saved_edit(&read(db)?, row)?.as_ref() != Some(&change)
                                {
                                    return Err(io::ErrorKind::WouldBlock.into());
                                }
                                supervisor::prepare_transport(transport, selected)?;
                                if check_saved_edit(&read(db)?, row)?.as_ref() != Some(&change) {
                                    return Err(io::ErrorKind::WouldBlock.into());
                                }
                                if authorized.is_some() || selected != candidates[0] {
                                    (hooks.prepare)(&change, selected)?;
                                }
                                Ok(())
                            };
                            return supervisor::retry_routed_endpoint(
                                supervisor::RoutedRetryCycle {
                                    candidates: &candidates,
                                    authorized,
                                    settings: &settings,
                                    now,
                                    tick: std::time::Instant::now(),
                                },
                                owned.get_mut(id).ok_or(io::ErrorKind::WouldBlock)?,
                                spec,
                                prepare,
                                |spec| self.start_saved_edit(spec, wan),
                                |candidates| self.routed_retry_hints(candidates, wan),
                            );
                        }
                    }
                }
                if owned
                    .get(id)
                    .is_some_and(|m| m.recovery.retry_at(&settings) > now)
                {
                    return Ok(());
                }
                apply_saved_edit_at(
                    SavedEdit { db, doc: &doc, row },
                    &mut owned,
                    spec,
                    |doc, known, spec, phase| {
                        self.prepare_saved_edit(doc, known, spec, wan, refresh, phase)
                    },
                    |spec| self.start_saved_edit(spec, wan),
                    park,
                    initial,
                )?;
                if pending_routed_mtu(row)?.is_some_and(|change| change.nested_outer.is_some()) {
                    if let Some(managed) = owned.get_mut(id) {
                        self.check_saved_nested(managed);
                    }
                }
                Ok(())
            })();
            if let Err(e) = result {
                if !cycling {
                    remember_failed_edit(&mut owned, row, now, &e);
                }
                warnings.push(format!(
                    "{id}: сохранённая правка AWG ожидает применения: {e}"
                ));
            }
        }
        Ok(warnings)
    }
}

fn prepare_routed_endpoint_edit_with(
    db: &Store,
    input: &Value,
    resolve: impl Fn(&str, Instant, bool) -> io::Result<Vec<SocketAddr>>,
    observe_previous: impl FnOnce(&Spec) -> io::Result<Option<SocketAddr>>,
) -> io::Result<Option<PreparedRoutedEndpointEdit>> {
    let doc = read(db)?;
    let original = active(&doc)?;
    let id = s(original, "id");
    if !routes_use(&doc, id) || has_saved_edit(original) {
        return Ok(None);
    }
    let proposed = proposal(original, input)?;
    let before = s(&original["config"], "endpoint");
    let after = s(&proposed["config"], "endpoint");
    if before == after {
        return Ok(None);
    }
    let resolve_after = hostname_port(after).is_some();
    let old_port = hostname_port(before);
    let direct = direct_endpoint_profile(original);
    let inspect_previous =
        old_port.is_some() && direct && !configured_endpoint_backups(original, before)?.is_empty();
    if !resolve_after && !inspect_previous {
        return Ok(None);
    }
    let prior_literal = literal_transport(before);
    let inherited_literal = if resolve_after
        && legacy_edit_candidate(original)
        && original["config"]["client"].get("rust_managed").is_none()
        && effective_mtu(original)? == effective_mtu(&proposed)?
    {
        prior_literal.filter(SocketAddr::is_ipv4)
    } else {
        None
    };
    if inherited_literal.is_none() && (!direct || prior_literal.is_none() && old_port.is_none()) {
        return Err(invalid(
            "имя endpoint требует работающий прямой импортированный профиль AWG",
        ));
    }
    let revision = routed_mtu_admission(&doc, id).ok_or(io::ErrorKind::WouldBlock)?;
    let spec = specification(&doc, original)?;
    let mut previous_reserve = None;
    if inspect_previous {
        if let Some(previous) = observe_previous(&spec)? {
            if Some(previous.port()) == old_port
                && has_configured_backup(original, before, previous)?
            {
                let addresses =
                    resolve_named_addresses(before, |raw, deadline| resolve(raw, deadline, true))?;
                if addresses.is_empty() || addresses.contains(&previous) {
                    return Err(invalid(
                        "нельзя отличить резервный endpoint от адресов прежнего имени AWG",
                    ));
                }
                previous_reserve = Some((previous, addresses));
            }
        }
    }
    if !resolve_after && previous_reserve.is_none() {
        return Ok(None);
    }
    let resolved_after = if resolve_after {
        let addresses = resolve_named_addresses(after, |raw, deadline| {
            resolve(raw, deadline, inherited_literal.is_some())
        })?;
        let selected = selected_named_address(after, &addresses)?;
        if inherited_literal.is_some_and(|before| !legacy_endpoint_change(before, selected, true)) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        addresses
    } else {
        Vec::new()
    };
    Ok(Some(PreparedRoutedEndpointEdit {
        id: id.to_owned(),
        iface: spec.iface,
        revision,
        previous: Sha256::digest(spec.conf.as_bytes()).into(),
        before: before.into(),
        after: after.into(),
        resolved_after,
        previous_reserve,
    }))
}

fn resolve_named_addresses(
    raw: &str,
    resolve: impl Fn(&str, Instant) -> io::Result<Vec<SocketAddr>>,
) -> io::Result<Vec<SocketAddr>> {
    let mut addresses = Vec::new();
    for address in resolve(raw, Instant::now() + Duration::from_secs(5))? {
        let address = supervisor::canonical_transport(address)
            .ok_or_else(|| invalid("DNS вернул недопустимый адрес endpoint AWG"))?;
        if !addresses.contains(&address) {
            if addresses.len() == MAX_HOST_ADDRESSES {
                return Err(invalid("DNS вернул слишком много адресов endpoint AWG"));
            }
            addresses.push(address);
        }
    }
    validate_named_addresses(raw, &addresses)?;
    Ok(addresses)
}

pub(in crate::client) fn owned_routed_sample(
    spec: &Spec,
    managed: &Managed,
    iface: &str,
    outer: Option<&NestedOuter>,
) -> io::Result<RoutedMtuSample> {
    let fingerprint: [u8; 32] = Sha256::digest(spec.conf.as_bytes()).into();
    if managed.iface != iface
        || spec.iface != iface
        || managed.fingerprint != fingerprint
        || managed.tunnel.inherited()
    {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    managed.tunnel.verified_routed_mtu(spec, outer, true)
}

fn matches_direct_mtu_sample(sample: &RoutedMtuSample, endpoint: SocketAddr, mtu: u16) -> bool {
    sample.effective_mtu == mtu && matches_direct_sample_endpoint(sample, endpoint)
}

fn matches_nested_mtu_sample(
    sample: &RoutedMtuSample,
    iface: &str,
    endpoint: SocketAddr,
    configured_mtu: u16,
) -> bool {
    sample.endpoint == endpoint
        && (576..=configured_mtu).contains(&sample.effective_mtu)
        && crate::nested_socket_selector(iface).is_ok_and(|(mark, _)| sample.socket_mark == mark)
}

fn matches_direct_sample_endpoint(sample: &RoutedMtuSample, endpoint: SocketAddr) -> bool {
    sample.endpoint == endpoint
        && matches!(sample.socket_mark, 0 | crate::DIRECT_SOCKET_MARK)
        && sample.outer_endpoint.is_none()
}

fn owned_direct_witness(
    spec: &Spec,
    managed: &Managed,
    endpoint: SocketAddr,
    socket_mark: u32,
    mtu: u16,
    verify_wan: impl FnOnce(SocketAddr, u32) -> bool,
) -> io::Result<RoutedMtuPeer> {
    let sample = owned_routed_sample(spec, managed, &spec.iface, None)?;
    if !sample.connected
        || sample.endpoint != endpoint
        || sample.socket_mark != socket_mark
        || sample.effective_mtu != mtu
        || !verify_wan(endpoint, socket_mark)
    {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    Ok(RoutedMtuPeer {
        iface: spec.iface.clone(),
        outer_id: String::new(),
        outer_iface: String::new(),
        endpoint,
        effective_mtu: sample.effective_mtu,
        socket_mark,
    })
}

fn verified_named_predecessor(
    row: &Value,
    spec: &Spec,
    managed: &Managed,
    verify_wan: &VerifyDirectWan<'_>,
    prepared: Option<&PreparedRoutedEndpointEdit>,
) -> io::Result<NamedPredecessor> {
    let unproved = || invalid("не подтверждён действующий адрес имени endpoint AWG");
    if !direct_endpoint_profile(row) || managed.tunnel.nested_iface().is_some() {
        return Err(unproved());
    }
    let port = hostname_port(&spec.endpoint).ok_or_else(unproved)?;
    let sample = owned_routed_sample(spec, managed, &spec.iface, None)?;
    if !sample.connected
        || supervisor::canonical_transport(sample.endpoint) != Some(sample.endpoint)
        || !matches!(sample.socket_mark, 0 | crate::DIRECT_SOCKET_MARK)
        || sample.effective_mtu != effective_mtu(row)?
        || !verify_wan(sample.endpoint, sample.socket_mark)
    {
        return Err(unproved());
    }
    let endpoint = sample.endpoint;
    if has_configured_backup(row, &spec.endpoint, endpoint)? {
        let addresses = if endpoint.port() == port {
            let (_, addresses) = prepared
                .and_then(|prepared| prepared.previous_reserve.as_ref())
                .filter(|(candidate, _)| *candidate == endpoint)
                .ok_or_else(unproved)?;
            addresses.clone()
        } else {
            Vec::new()
        };
        Ok(NamedPredecessor {
            addresses,
            reserve: Some(endpoint),
        })
    } else if endpoint.port() == port {
        Ok(NamedPredecessor {
            addresses: vec![endpoint],
            reserve: None,
        })
    } else {
        Err(unproved())
    }
}

pub(super) fn has_saved_edit(row: &Value) -> bool {
    row.get(PENDING_PROFILE).is_some() || row.get(PENDING_ROUTED_MTU).is_some()
}

pub(super) fn pending_fixed_nested_outer<'a>(doc: &Value, row: &'a Value) -> Option<&'a str> {
    if row[PENDING_ROUTED_MTU]["nested_outer"].is_null() {
        return None;
    }
    let saved = check_saved_edit(doc, row).ok()??;
    if !saved.nested_mtu_before_recorded && !saved.combines_nested_endpoint_mtu() {
        return None;
    }
    let outer = saved.nested_outer.as_ref()?;
    row["config"]["client"]["double_tunnel_id"]
        .as_str()
        .filter(|id| *id == outer.id)
}

pub(super) fn awaiting_legacy_edit(row: &Value) -> bool {
    row["config"]["client"].get("rust_managed").is_none()
        && previous_fingerprint(row).ok().flatten().is_some()
        && pending_routed_mtu(row)
            .ok()
            .flatten()
            .is_some_and(|change| routed_legacy_edit_profile(row, &change))
}

fn wants_saved_edit(row: &Value) -> bool {
    let config = &row["config"];
    has_saved_edit(row)
        && config["enabled"] == true
        && config["client"]["enabled"] == true
        && (config["client"]["rust_managed"] == true || awaiting_legacy_edit(row))
}

fn stopped_edit(spec: &Spec) -> Managed {
    Managed {
        tunnel: Box::new(supervisor::Stopped),
        iface: spec.iface.clone(),
        fingerprint: Sha256::digest(spec.conf.as_bytes()).into(),
        recovery: Default::default(),
    }
}

fn remember_failed_edit(
    owned: &mut HashMap<String, Managed>,
    row: &Value,
    now: u64,
    error: &io::Error,
) {
    let id = s(row, "id");
    let standby = row["config"]["client"]["standby"] == true;
    if let Some(m) = owned.get_mut(id) {
        if standby && row.get(PENDING_ROUTED_MTU).is_none() && !m.tunnel.alive() {
            owned.remove(id);
        } else {
            m.recovery.note_edit_failure(now, error);
        }
    }
}

fn waiting_for_wan() -> io::Error {
    io::Error::new(
        io::ErrorKind::NetworkUnreachable,
        "для основного и резервных endpoint AWG пока нет маршрута через WAN",
    )
}

fn check_saved_edit(doc: &Value, expected: &Value) -> io::Result<Option<RoutedMtuChange>> {
    let id = s(expected, "id");
    if find(doc, id)? != expected {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    standalone(doc, wire(expected))?;
    let routed = routes_use(doc, id);
    let Some(change) = pending_routed_mtu(expected)? else {
        return if routed || transport_refresh_pending(expected) {
            Err(io::ErrorKind::WouldBlock.into())
        } else {
            Ok(None)
        };
    };
    let endpoint_edit = change.endpoint_edit.as_ref();
    if change.id != id
        || change.iface != iface(expected, doc)?
        || !change.valid_mtu_provenance()
        || change.saved_mtu(expected) != Some(effective_mtu(expected)?)
        || endpoint_edit.is_none() && change.before == change.after
        || change.combines_endpoint_mtu()
            && !routed_combined_endpoint_mtu_profile(expected, &change)
        || !(576..=9000).contains(&change.before)
        || endpoint_edit.is_none() && !(1280..=1500).contains(&change.after)
        || !cfg_is_imported(&expected["config"])
        || !expected["applied_config"].is_null()
        || change.legacy_predecessor.is_some() && !routed_legacy_edit_profile(expected, &change)
        || change.native_mtu_endpoint.is_some()
            && !routed_native_mtu_edit_profile(expected, &change)
        || change.nested_mtu_before_recorded && !routed_nested_mtu_edit_profile(expected, &change)
        || change.legacy_predecessor.is_some()
            && transport_refresh_pending(expected)
            && expected["config"]["client"]["rust_managed"] != true
        || endpoint_edit.is_some_and(|edit| {
            edit.has_hostname() && !routed_endpoint_named_allowed(expected, &change)
        })
        || change.nested_endpoint.as_ref().is_some_and(|endpoint| {
            change.nested_outer.is_none() || !supervisor::mtu_endpoint_in_pool(expected, endpoint)
        })
    {
        return Err(invalid("ожидающая правка MTU не соответствует профилю"));
    }
    let selection = change.endpoint_selection(expected)?;
    if selection.is_some() && change.nested_endpoint.is_some() {
        return Err(invalid(
            "ожидающая правка endpoint не соответствует профилю AWG",
        ));
    }
    let old = superseded_routed_spec(doc, expected, &change, selection.as_ref())?;
    let fingerprint: [u8; 32] = Sha256::digest(old.conf.as_bytes()).into();
    let prior = previous_fingerprint(expected)?;
    if prior.is_some_and(|hash| hash != fingerprint)
        || prior.is_none() && !change.requires_peer_proof()
        || transport_refresh_pending(expected)
            && change.fixed_mtu_endpoint().is_none()
            && !change.nested_mtu_before_recorded
            && !selection.is_some_and(|endpoint| endpoint.refreshes_transport())
    {
        return Err(invalid("владелец ожидающей правки MTU изменился"));
    }
    expected_routed_outer(doc, &change)?;
    if routed && confirmed_routing_revision(doc, id) != Some(change.revision) {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    Ok(routed.then_some(change))
}

fn superseded_routed_spec(
    doc: &Value,
    row: &Value,
    change: &RoutedMtuChange,
    selection: Option<&EndpointSelection<'_>>,
) -> io::Result<Spec> {
    let mut previous = row.clone();
    match selection {
        Some(endpoint) if change.combines_endpoint_mtu() => {
            change.rewrite_combined_endpoint_mtu(&mut previous, endpoint.restoring)?;
        }
        Some(endpoint) => {
            previous["config"]["endpoint"] = json!(endpoint.previous_config);
        }
        None if change.records_mtu_before() => {
            let selected = change.saved_mtu(row).ok_or(io::ErrorKind::WouldBlock)?;
            let previous_mtu = if selected == change.before {
                change.after
            } else {
                change.before
            };
            change.write_mtu(
                previous["config"]
                    .as_object_mut()
                    .ok_or(io::ErrorKind::WouldBlock)?,
                previous_mtu,
            );
        }
        None => previous["config"]["mtu"] = json!(change.before),
    }
    specification(doc, &previous)
}

fn legacy_predecessor_spec(doc: &Value, row: &Value, change: &RoutedMtuChange) -> io::Result<Spec> {
    if !routed_legacy_edit_profile(row, change) {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    let mut predecessor = row.clone();
    if change.combines_endpoint_mtu() {
        change.rewrite_combined_endpoint_mtu(&mut predecessor, false)?;
    } else if let Some(edit) = &change.endpoint_edit {
        predecessor["config"]["endpoint"] = json!(edit.before);
    } else {
        change.write_mtu(
            predecessor["config"]
                .as_object_mut()
                .ok_or(io::ErrorKind::WouldBlock)?,
            change.before,
        );
    }
    specification(doc, &predecessor)
}

/// Preserve the previously configured tuple until the owned daemon has retired.
pub(super) fn retiring_routed_transport(doc: &Value, row: &Value) -> Option<SocketAddr> {
    let change = pending_routed_mtu(row).ok()??;
    let endpoint = change.endpoint_selection(row).ok()??;
    if !endpoint.refreshes_transport() || previous_fingerprint(row).ok()?.is_none() {
        return None;
    }
    check_saved_edit(doc, row).ok().map(|_| endpoint.retiring)
}

fn begin_transport_refresh(db: &Store, row: &Value) -> io::Result<Value> {
    let mut pending = row.clone();
    pending[PENDING_PROFILE] = json!(TRANSPORT_REFRESH);
    let legacy = pending_routed_mtu(row)?.is_some_and(|edit| edit.legacy_predecessor.is_some());
    if legacy {
        pending["config"]["client"]["rust_managed"] = json!(true);
    }
    if &pending != row {
        edit_document(db, |doc| {
            check_saved_edit(doc, row)?;
            let current = doc["servers"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|r| r["id"] == row["id"])
                .unwrap();
            current[PENDING_PROFILE] = json!(TRANSPORT_REFRESH);
            if legacy {
                current["config"]["client"]["rust_managed"] = json!(true);
            }
            Ok(())
        })?;
    }
    Ok(pending)
}

fn finish_saved_edit(db: &Store, row: &Value) -> io::Result<()> {
    edit_document(db, |doc| {
        let keep_route_proof =
            check_saved_edit(doc, row)?.is_some_and(|change| change.requires_peer_proof());
        let current = doc["servers"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|r| r["id"] == row["id"])
            .unwrap();
        let fields = current.as_object_mut().unwrap();
        fields.remove(PENDING_PROFILE);
        if !keep_route_proof {
            fields.remove(PENDING_ROUTED_MTU);
        }
        Ok(())
    })
}

pub(super) struct SavedEdit<'a> {
    pub db: &'a Store,
    pub doc: &'a Value,
    pub row: &'a Value,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum EditPreparation {
    Transport,
    VerifyBeforeRetiring,
    VerifyDirectBeforeRetiring(SocketAddr, u32),
}

#[cfg(test)]
pub(super) fn apply_saved_edit(
    edit: SavedEdit<'_>,
    owned: &mut HashMap<String, Managed>,
    spec: Spec,
    prepare: impl Fn(&Value, &HashMap<String, Managed>, &mut Spec, EditPreparation) -> io::Result<()>,
    start: impl FnOnce(Spec) -> io::Result<Box<dyn Tunnel>>,
    park: Option<&ParkRoutedMtu<'_>>,
) -> io::Result<()> {
    apply_saved_edit_at(edit, owned, spec, prepare, start, park, None)
}

fn apply_saved_edit_at(
    edit: SavedEdit<'_>,
    owned: &mut HashMap<String, Managed>,
    mut spec: Spec,
    prepare: impl Fn(&Value, &HashMap<String, Managed>, &mut Spec, EditPreparation) -> io::Result<()>,
    start: impl FnOnce(Spec) -> io::Result<Box<dyn Tunnel>>,
    park: Option<&ParkRoutedMtu<'_>>,
    initial: Option<InitialRoutedLaunch<'_>>,
) -> io::Result<()> {
    let SavedEdit { db, doc, row } = edit;
    let previous = previous_fingerprint(row)?;
    let fingerprint: [u8; 32] = Sha256::digest(spec.conf.as_bytes()).into();
    let id = spec.id.clone();
    let saved = pending_routed_mtu(row)?;
    if previous.is_none() && saved.as_ref().is_none_or(|c| !c.requires_peer_proof()) {
        return Err(invalid("нет ожидающей правки AWG"));
    }
    let change = check_saved_edit(&read(db)?, row)?;
    let legacy = saved
        .as_ref()
        .and_then(|edit| edit.legacy_predecessor.as_ref());
    let combined = saved
        .as_ref()
        .is_some_and(RoutedMtuChange::combines_endpoint_mtu);
    let combined_nested = saved
        .as_ref()
        .is_some_and(RoutedMtuChange::combines_nested_endpoint_mtu);
    let combined_direct = combined && !combined_nested;
    if legacy.is_some() && change.is_none() {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    let verify_old = |managed: &Managed| -> io::Result<()> {
        let (saved, legacy) = saved
            .as_ref()
            .zip(legacy)
            .ok_or(io::ErrorKind::WouldBlock)?;
        if row["config"]["client"].get("rust_managed").is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let predecessor = legacy_predecessor_spec(doc, row, saved)?;
        if managed.fingerprint != <[u8; 32]>::from(Sha256::digest(predecessor.conf.as_bytes()))
            || managed.tunnel.verified_legacy_predecessor(
                &predecessor,
                legacy.endpoint,
                saved.before,
                false,
            )? != *legacy
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        Ok(())
    };
    if change.is_some() && park.is_none() && initial.is_none() {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    let selection = saved
        .as_ref()
        .map(|saved| saved.endpoint_selection(row))
        .transpose()?
        .flatten();
    if let Some(initial) = initial {
        if !routed_mtu_launch_pending(row)
            || change
                .as_ref()
                .and_then(|change| direct_forward_endpoint(row, change))
                .is_none_or(RoutedEndpointEdit::has_hostname)
            || !routing_direct_backup_pool(row)?.contains(&initial.endpoint)
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
    }
    let nested_mtu = saved.as_ref().and_then(|change| {
        change
            .fixed_nested_mtu_endpoint()
            .map(|endpoint| (change.iface.as_str(), endpoint))
    });
    let endpoint = initial
        .map(|initial| initial.endpoint)
        .or_else(|| selection.as_ref().map(|endpoint| endpoint.chosen))
        .or_else(|| saved.as_ref().and_then(RoutedMtuChange::fixed_mtu_endpoint))
        .or_else(|| nested_mtu.map(|(_, endpoint)| endpoint));
    let native_pair = endpoint.zip(saved.as_ref().and_then(|saved| saved.saved_mtu(row)));
    let native_mtu_endpoint = saved.as_ref().and_then(|change| change.native_mtu_endpoint);
    let nested_iface = saved
        .as_ref()
        .filter(|_| combined_nested || nested_mtu.is_some())
        .map(|change| change.iface.as_str());
    let strict_native =
        legacy.is_some() || combined || native_mtu_endpoint.is_some() || nested_mtu.is_some();
    let fixed_mtu_inverse = saved.as_ref().is_some_and(|change| {
        change.records_mtu_before() && change.saved_mtu(row) == Some(change.before)
    });
    let verify_retiring_wan =
        fixed_mtu_inverse && nested_mtu.is_none() || native_mtu_endpoint.is_some();
    let verify_replaced_native = |managed: &Managed| -> io::Result<RoutedMtuSample> {
        let saved = saved.as_ref().ok_or(io::ErrorKind::WouldBlock)?;
        let predecessor = superseded_routed_spec(doc, row, saved, selection.as_ref())?;
        let sample = managed
            .tunnel
            .verified_routed_mtu(&predecessor, None, false)?;
        let valid = if fixed_mtu_inverse {
            saved
                .fixed_mtu_endpoint()
                .is_some_and(|endpoint| matches_direct_sample_endpoint(&sample, endpoint))
        } else if let Some(endpoint) = native_mtu_endpoint {
            matches_direct_mtu_sample(&sample, endpoint, saved.before)
        } else {
            selection.as_ref().is_some_and(|selected| {
                if selected.restoring && legacy.is_some() {
                    return matches_direct_sample_endpoint(&sample, selected.retiring);
                }
                let mtu = if selected.restoring {
                    saved.after
                } else {
                    saved.before
                };
                matches_direct_mtu_sample(&sample, selected.retiring, mtu)
            })
        };
        if !valid {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        Ok(sample)
    };
    let verify_native = |sample: &RoutedMtuSample| -> io::Result<()> {
        if strict_native
            && !native_pair.is_some_and(|(endpoint, mtu)| {
                if let Some(iface) = nested_iface {
                    matches_nested_mtu_sample(sample, iface, endpoint, mtu)
                } else {
                    matches_direct_mtu_sample(sample, endpoint, mtu)
                }
            })
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        Ok(())
    };
    let restoring = fixed_mtu_inverse
        || selection
            .as_ref()
            .is_some_and(|endpoint| endpoint.restoring);
    let restored_reserve = saved
        .as_ref()
        .and_then(|change| change.endpoint_edit.as_ref())
        .and_then(|edit| edit.previous_reserve)
        .filter(|_| restoring)
        .map(|endpoint| endpoint.to_string());
    let fixed_reserve = native_mtu_endpoint
        .or_else(|| nested_mtu.map(|(_, endpoint)| endpoint))
        .filter(|endpoint| literal_transport(s(&row["config"], "endpoint")) != Some(*endpoint))
        .map(|endpoint| endpoint.to_string());
    let configured_recovery = || {
        restored_reserve
            .as_deref()
            .or(fixed_reserve.as_deref())
            .unwrap_or_else(|| s(&row["config"], "endpoint"))
    };
    let refresh_transport = routed_mtu_launch_pending(row)
        && (legacy.is_some()
            || native_mtu_endpoint.is_some()
            || nested_mtu.is_some()
            || selection
                .as_ref()
                .is_some_and(EndpointSelection::refreshes_transport));
    let park_edit = || -> io::Result<()> {
        if let Some(change) = change.as_ref() {
            if let Some(initial) = initial {
                (initial.prepare)(change, initial.endpoint)?;
            } else {
                park.ok_or(io::ErrorKind::WouldBlock)?(change)?;
            }
            if check_saved_edit(&read(db)?, row)?.as_ref() != Some(change) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
        }
        Ok(())
    };
    let finish = |owned: &HashMap<String, Managed>, spec: &mut Spec| {
        if !refresh_transport {
            return finish_saved_edit(db, row);
        }
        let pending = begin_transport_refresh(db, row)?;
        let current = read(db)?;
        check_saved_edit(&current, &pending)?;
        prepare(&current, owned, spec, EditPreparation::Transport)?;
        finish_saved_edit(db, &pending)
    };
    if let Some(saved) = &saved {
        spec.outer = expected_routed_outer(doc, saved)?;
        if let Some(pin) = endpoint {
            spec.endpoint = pin.to_string();
        } else if let Some(pin) = &saved.nested_endpoint {
            spec.endpoint.clone_from(pin);
        }
        if spec.permanent && spec.outer.is_none() {
            return Err(invalid("не подтверждён внешний профиль правки MTU"));
        }
    }
    let mut probe = None;
    if let Some(managed) = owned.get_mut(&id) {
        let inherited = managed.tunnel.inherited();
        if managed.iface != spec.iface
            || managed.fingerprint != fingerprint && previous != Some(managed.fingerprint)
        {
            return Err(invalid("владелец ожидающей правки AWG изменился"));
        }
        if inherited {
            verify_old(managed)?;
        }
        let running = managed.tunnel.alive();
        if (combined_direct || verify_retiring_wan)
            && !inherited
            && running
            && managed.fingerprint != fingerprint
        {
            verify_replaced_native(managed)?;
        }
        if saved.is_some()
            && running
            && managed.tunnel.nested_iface()
                != spec.outer.as_ref().map(|outer| outer.iface.as_str())
        {
            return Err(invalid("действующий внешний туннель правки MTU изменился"));
        }
        if managed.fingerprint == fingerprint && running && !inherited {
            if saved
                .as_ref()
                .is_some_and(RoutedMtuChange::requires_peer_proof)
            {
                let sample = managed
                    .tunnel
                    .verified_routed_mtu(&spec, spec.outer.as_ref(), false);
                if let Ok(sample) = sample {
                    verify_native(&sample)?;
                    if endpoint.is_some_and(|expected| expected != sample.endpoint) {
                        if !restoring && initial.is_none() {
                            return Err(io::ErrorKind::WouldBlock.into());
                        }
                        // Reverting or replaying an authorized reserve requires the exact pin.
                    } else if sample.connected || refresh_transport {
                        if restoring && routed_mtu_launch_pending(row) {
                            park_edit()?;
                            managed
                                .recovery
                                .remember_routed_mtu_endpoint(configured_recovery());
                        } else if let Some(initial) = initial {
                            managed
                                .recovery
                                .remember_routed_mtu_endpoint(&initial.endpoint.to_string());
                        } else if let Some(endpoint) = &fixed_reserve {
                            managed.recovery.remember_routed_mtu_endpoint(endpoint);
                        }
                        return finish(owned, &mut spec);
                    } else {
                        spec.endpoint = sample.endpoint.to_string();
                        probe = Some(sample.endpoint);
                    }
                } else if strict_native {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
            } else {
                finish_saved_edit(db, row)?;
                managed.recovery = Default::default();
                return Ok(());
            }
        }
        if let Some(outer_iface) = managed.tunnel.nested_iface().filter(|_| saved.is_none()) {
            let graph = FailoverGraph::load(doc)?;
            let (outer_id, _) = graph
                .nested(&id)
                .ok_or_else(|| invalid("внешний туннель ожидающей правки AWG изменился"))?;
            let outer = specification(doc, find(doc, outer_id)?)?;
            if outer.iface != outer_iface {
                return Err(invalid("внешний интерфейс ожидающей правки AWG изменился"));
            }
            spec.outer = Some(NestedOuter::from_spec(&outer)?);
        }
    }
    prepare(doc, owned, &mut spec, EditPreparation::Transport)?;
    if check_saved_edit(&read(db)?, row)? != change {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    if let Some(endpoint) = probe {
        owned
            .get_mut(&id)
            .ok_or(io::ErrorKind::WouldBlock)?
            .tunnel
            .probe_at(endpoint)?;
        return finish_saved_edit(db, row);
    }
    park_edit()?;
    if change.is_some()
        && spec.permanent
        && (nested_iface.is_some()
            || selection
                .as_ref()
                .is_some_and(|endpoint| endpoint.retiring.ip() != endpoint.chosen.ip()))
    {
        prepare(doc, owned, &mut spec, EditPreparation::VerifyBeforeRetiring)?;
        if check_saved_edit(&read(db)?, row)? != change {
            return Err(io::ErrorKind::WouldBlock.into());
        }
    }
    let mut retiring_path = None;
    if let Some(managed) = owned.get_mut(&id) {
        if managed.tunnel.inherited() {
            verify_old(managed)?;
            if fixed_mtu_inverse && managed.tunnel.alive() {
                retiring_path = legacy.map(|legacy| (legacy.endpoint, 0));
            }
        } else if (combined_direct || verify_retiring_wan) && managed.tunnel.alive() {
            let sample = verify_replaced_native(managed)?;
            if verify_retiring_wan {
                retiring_path = Some((sample.endpoint, sample.socket_mark));
            }
        }
    }
    if let Some((endpoint, mark)) = retiring_path {
        prepare(
            doc,
            owned,
            &mut spec,
            EditPreparation::VerifyDirectBeforeRetiring(endpoint, mark),
        )?;
        if check_saved_edit(&read(db)?, row)? != change {
            return Err(io::ErrorKind::WouldBlock.into());
        }
    }
    if let Some(managed) = owned.get_mut(&id) {
        managed.tunnel.stop()?;
    }
    owned.insert(id.clone(), stopped_edit(&spec));
    let expected_outer = spec.outer.as_ref().map(|outer| outer.iface.clone());
    let mut refresh_spec = refresh_transport.then(|| spec.clone());
    let mut tunnel = start(spec)?;
    if saved.is_some() && tunnel.nested_iface() != expected_outer.as_deref() {
        if tunnel.resumed() {
            tunnel.detach()?;
        } else {
            tunnel.stop()?;
        }
        return Err(invalid(
            "движок AWG не подтвердил внешний туннель правки MTU",
        ));
    }
    if let Err(e) = read(db).and_then(|current| check_saved_edit(&current, row)) {
        if tunnel.resumed() {
            tunnel.detach()?;
        } else {
            tunnel.stop()?;
        }
        return Err(e);
    }
    let managed = owned.get_mut(&id).unwrap();
    managed.tunnel = tunnel;
    if strict_native {
        let native = refresh_spec.as_ref().ok_or(io::ErrorKind::WouldBlock)?;
        if managed.tunnel.inherited() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        verify_native(&managed.tunnel.verified_routed_mtu(
            native,
            native.outer.as_ref(),
            false,
        )?)?;
    }
    if let Some(initial) = initial {
        managed
            .recovery
            .remember_routed_mtu_endpoint(&initial.endpoint.to_string());
    } else if let Some(endpoint) = selection
        .map(|_| configured_recovery())
        .or(fixed_reserve.as_deref())
        .or_else(|| {
            saved
                .as_ref()
                .and_then(|edit| edit.nested_endpoint.as_deref())
        })
    {
        managed.recovery.remember_routed_mtu_endpoint(endpoint);
    }
    match &mut refresh_spec {
        Some(spec) => finish(owned, spec),
        None => finish_saved_edit(db, row),
    }
}
impl Clients {
    fn save_config(
        &self,
        db: &Store,
        input: &Value,
        start: impl FnOnce(Spec) -> io::Result<Box<dyn Tunnel>>,
        present: impl FnOnce(&str) -> io::Result<bool>,
        prepare: impl Fn(
            &Value,
            &HashMap<String, Managed>,
            &mut Spec,
            EditPreparation,
        ) -> io::Result<()>,
        routing: Option<RoutedEditHooks<'_>>,
    ) -> io::Result<Option<String>> {
        let mut owned = self
            .0
            .lock()
            .map_err(|_| io::Error::other("менеджер AWG недоступен"))?;
        let doc = read(db)?;
        let original = active(&doc)?;
        let id = s(original, "id");
        let mut proposed = proposal(original, input)?;
        if &proposed == original {
            return Ok(None);
        }
        let pending = pending_routed_mtu(original)?;
        let restoring = pending.is_some();
        let mut adopted = None;
        let before = wire(original);
        let after = wire(&proposed);
        let live_change = changed_wire(before, after) || before["mtu"] != after["mtu"];
        if live_change
            && doc["servers"].as_array().into_iter().flatten().any(|row| {
                row.get(PENDING_ROUTED_MTU)
                    .is_some_and(|saved| saved["nested_outer"]["id"] == id)
            })
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let routed = if let Some(change) = pending {
            let mut restored = original.clone();
            if let Some(edit) = &change.endpoint_edit {
                if original["config"]["endpoint"] != edit.after
                    || (edit.previous_reserve.is_some()
                        && !routed_endpoint_previous_reserve_allowed(original, &change))
                {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                restored["config"]["endpoint"] = json!(edit.before);
            } else if !change.records_mtu_before()
                || change.saved_mtu(original) != Some(change.after)
            {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            if change.combines_endpoint_mtu() || change.records_mtu_before() {
                restored["config"]["mtu"] = json!(change.before);
            }
            if routing.is_none_or(|hooks| hooks.validate.is_none() && hooks.initial.is_none())
                || proposed != restored
                || check_saved_edit(&doc, original)?.as_ref() != Some(&change)
                || original["config"]["enabled"] != true
                || original["config"]["client"]["enabled"] != true
            {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            if change.combines_endpoint_mtu() {
                change.rewrite_combined_endpoint_mtu(&mut proposed, false)?;
            } else if change.records_mtu_before() {
                change.write_mtu(
                    proposed["config"]
                        .as_object_mut()
                        .ok_or(io::ErrorKind::WouldBlock)?,
                    change.before,
                );
                let valid = if change.nested_mtu_before_recorded {
                    routed_nested_mtu_edit_profile(&proposed, &change)
                } else if change.native_mtu_endpoint.is_some() {
                    routed_native_mtu_edit_profile(&proposed, &change)
                } else {
                    routed_legacy_edit_profile(&proposed, &change)
                };
                if !valid {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
            }
            Some(change)
        } else if live_change && routes_use(&doc, id) {
            if routing.is_none() {
                return Err(invalid("сначала снимите маршруты этого подключения"));
            }
            let initial = routing.and_then(|hooks| hooks.initial);
            let prepared = initial.and_then(|hooks| hooks.prepared);
            let old = specification(&doc, original)?;
            let previous: [u8; 32] = Sha256::digest(old.conf.as_bytes()).into();
            let next_endpoint = s(&proposed["config"], "endpoint");
            let retiring_hostname =
                old.endpoint != next_endpoint && hostname_port(&old.endpoint).is_some();
            let mut inherited_endpoint = None;
            let mut inherited_named = None;
            if legacy_edit_candidate(original)
                && original["config"]["client"].get("rust_managed").is_none()
            {
                let mtu_changed = effective_mtu(original)? != effective_mtu(&proposed)?;
                let next_literal = literal_transport(next_endpoint);
                let before_literal = literal_transport(&old.endpoint);
                let named_after = if before_literal.is_some()
                    && !mtu_changed
                    && hostname_port(next_endpoint).is_some()
                {
                    prepared
                        .map(|prepared| {
                            selected_named_address(next_endpoint, &prepared.resolved_after)
                        })
                        .transpose()?
                } else {
                    None
                };
                inherited_endpoint = before_literal.filter(|before| {
                    old.endpoint == next_endpoint && mtu_changed
                        || next_literal.or(named_after).is_some_and(|after| {
                            legacy_endpoint_change(*before, after, named_after.is_some())
                        })
                });
                inherited_named = next_literal.filter(|_| retiring_hostname && !mtu_changed);
            }
            if !owned.contains_key(id)
                && (inherited_endpoint.is_some() || inherited_named.is_some())
            {
                if let Some(adopt) = initial.and_then(|hooks| hooks.adopt_legacy) {
                    adopted = adopt(&old)?.map(|tunnel| Managed {
                        tunnel,
                        iface: old.iface.clone(),
                        fingerprint: previous,
                        recovery: Default::default(),
                    });
                }
            }
            let managed = owned
                .get_mut(id)
                .or(adopted.as_mut())
                .ok_or_else(|| invalid("ожидается подтверждённый процесс работающего AWG"))?;
            if managed.iface != old.iface
                || managed.fingerprint != previous
                || !managed.tunnel.alive()
            {
                return Err(invalid(
                    "владелец правки MTU не соответствует сохранённому профилю",
                ));
            }
            let (legacy, predecessor) = if managed.tunnel.inherited() {
                let (endpoint, predecessor) = if let Some(after) = inherited_named {
                    let live = managed.tunnel.snapshot()?;
                    let before = supervisor::live_transport_endpoint(&live)
                        .filter(|before| legacy_endpoint_change(*before, after, true))
                        .ok_or(io::ErrorKind::WouldBlock)?;
                    if live["connected"] != true
                        || live["socket_mark"].as_u64().unwrap_or_default() != 0
                        || !unambiguous_legacy_named_transport(original, &old.endpoint, before)?
                    {
                        return Err(io::ErrorKind::WouldBlock.into());
                    }
                    (
                        before,
                        NamedPredecessor {
                            addresses: vec![before],
                            reserve: None,
                        },
                    )
                } else {
                    (
                        inherited_endpoint.ok_or(io::ErrorKind::WouldBlock)?,
                        NamedPredecessor::default(),
                    )
                };
                let verify = initial.ok_or(io::ErrorKind::WouldBlock)?.verify_previous;
                let proof = managed.tunnel.verified_legacy_predecessor(
                    &old,
                    endpoint,
                    effective_mtu(original)?,
                    true,
                )?;
                if proof.endpoint != endpoint || !verify(endpoint, 0) {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                (Some(proof), predecessor)
            } else if retiring_hostname {
                let verify = initial.ok_or(io::ErrorKind::WouldBlock)?.verify_previous;
                (
                    None,
                    verified_named_predecessor(original, &old, managed, verify, prepared)?,
                )
            } else {
                (None, NamedPredecessor::default())
            };
            let active_outer = managed
                .tunnel
                .nested_iface()
                .map(|iface| -> io::Result<_> {
                    let (selected, outer) = routed_outer(&doc, id)?;
                    if selected.iface != iface {
                        return Err(invalid("изменился внешний интерфейс правки MTU"));
                    }
                    Ok((selected, outer))
                })
                .transpose()?;
            let mut change = routed_mtu_change(
                &doc,
                original,
                &proposed,
                prepared,
                predecessor,
                legacy,
                active_outer.as_ref().map(|(selected, _)| selected.clone()),
            )?;
            if let Some((selected, outer)) = active_outer {
                let combined = change.combines_nested_endpoint_mtu();
                let sample = managed
                    .tunnel
                    .verified_routed_mtu(&old, Some(&outer), combined)?;
                let recoverable = recoverable_mtu_outer(find(&doc, &selected.id)?);
                if combined {
                    let prior = change
                        .endpoint_selection(original)?
                        .ok_or(io::ErrorKind::WouldBlock)?;
                    if !recoverable
                        || !sample.connected
                        || !matches_nested_mtu_sample(
                            &sample,
                            &old.iface,
                            prior.chosen,
                            change.before,
                        )
                    {
                        return Err(io::ErrorKind::WouldBlock.into());
                    }
                }
                if change.endpoint_edit.is_none() {
                    change.nested_endpoint =
                        supervisor::routed_mtu_endpoint(original, managed, sample.endpoint);
                }
                if let Some(hooks) = initial
                    .filter(|_| recoverable && sample.connected && change.endpoint_edit.is_none())
                {
                    let pin = sample.endpoint;
                    let mut candidate = change.clone();
                    candidate.nested_endpoint = if permanent_nested_primary(original) == Some(pin) {
                        Some(old.endpoint.clone())
                    } else {
                        routing_permanent_nested_reserve(original, pin)
                            .is_ok_and(|configured| configured)
                            .then(|| pin.to_string())
                    };
                    candidate.nested_mtu_before_recorded = true;
                    candidate.implicit_before_mtu =
                        RoutedImplicitMtu::from_saved(original["config"].get("mtu"));
                    if routed_nested_mtu_edit_profile(original, &candidate)
                        && routed_nested_mtu_edit_profile(&proposed, &candidate)
                    {
                        if !matches_nested_mtu_sample(&sample, &old.iface, pin, change.before) {
                            return Err(io::ErrorKind::WouldBlock.into());
                        }
                        let mut next = specification(&doc, &proposed)?;
                        next.outer = Some(outer);
                        match (hooks.choose)(&candidate, &next, pin) {
                            Ok(RoutedEndpointLaunch::Primary) => change = candidate,
                            Err(error) if error.kind() == io::ErrorKind::Unsupported => {}
                            Err(error) => return Err(error),
                            Ok(_) => return Err(io::ErrorKind::WouldBlock.into()),
                        }
                    }
                }
            } else if old.permanent {
                return Err(invalid(
                    "ожидается работающий постоянный двойной туннель AWG",
                ));
            } else if let Some(edit) = change
                .endpoint_edit
                .as_ref()
                .filter(|_| !retiring_hostname && change.legacy_predecessor.is_none())
            {
                let sample = managed.tunnel.verified_routed_mtu(
                    &old,
                    None,
                    change.combines_direct_cross_family_mtu(),
                )?;
                if change.combines_endpoint_mtu() {
                    let (before, _) = edit.sockets()?;
                    if !matches_direct_mtu_sample(&sample, before, change.before)
                        || initial.is_some_and(|hooks| {
                            !(hooks.verify_previous)(before, sample.socket_mark)
                        })
                    {
                        return Err(io::ErrorKind::WouldBlock.into());
                    }
                }
            }
            let primary = literal_transport(&old.endpoint).zip(initial).filter(|_| {
                change.endpoint_edit.is_none()
                    && change.legacy_predecessor.is_none()
                    && change.nested_outer.is_none()
                    && direct_endpoint_profile(original)
                    && (1280..=1500).contains(&change.before)
            });
            if let Some((endpoint, initial)) = primary {
                let mut candidate = change.clone();
                candidate.native_mtu_endpoint = Some(endpoint);
                candidate.implicit_before_mtu =
                    RoutedImplicitMtu::from_saved(original["config"].get("mtu"));
                if routed_native_mtu_edit_profile(original, &candidate)
                    && routed_native_mtu_edit_profile(&proposed, &candidate)
                {
                    let sample = managed.tunnel.verified_routed_mtu(&old, None, false);
                    let verifies = |sample: &RoutedMtuSample, selected| {
                        matches_direct_mtu_sample(sample, selected, change.before)
                            && (initial.verify_previous)(selected, sample.socket_mark)
                    };
                    let mut selected = endpoint;
                    if let Ok(observed) = &sample {
                        if observed.connected
                            && observed.endpoint != endpoint
                            && has_configured_backup(original, &old.endpoint, observed.endpoint)?
                        {
                            selected = observed.endpoint;
                            candidate.native_mtu_endpoint = Some(selected);
                        }
                    }
                    let quiet_primary = sample
                        .as_ref()
                        .is_ok_and(|sample| sample.endpoint == endpoint && !sample.connected);
                    if quiet_primary || selected != endpoint {
                        // Prove the actual transport even when the saved primary has no WAN.
                        if !sample
                            .as_ref()
                            .is_ok_and(|sample| verifies(sample, selected))
                        {
                            return Err(io::ErrorKind::WouldBlock.into());
                        }
                    }
                    if !quiet_primary {
                        let next = specification(&doc, &proposed)?;
                        match (initial.choose)(&candidate, &next, selected) {
                            Ok(RoutedEndpointLaunch::Primary) => {
                                let sample = sample?;
                                if !sample.connected
                                    || (selected == endpoint && !verifies(&sample, selected))
                                {
                                    return Err(io::ErrorKind::WouldBlock.into());
                                }
                                change = candidate;
                            }
                            Err(error) if error.kind() == io::ErrorKind::Unsupported => {}
                            Err(error) => return Err(error),
                            Ok(_) => return Err(io::ErrorKind::WouldBlock.into()),
                        }
                    }
                }
            }
            Some(change)
        } else {
            None
        };
        let save = |proposed: &Value| {
            edit_document(db, |d| {
                if active(d)? != original {
                    return Err(invalid("подключение изменилось во время редактирования"));
                }
                if let Some(change) = &routed {
                    let valid = if restoring {
                        check_saved_edit(d, original)?.as_ref() == Some(change)
                    } else {
                        routed_mtu_admission(d, id) == Some(change.revision)
                    };
                    if !valid {
                        return Err(io::ErrorKind::WouldBlock.into());
                    }
                    expected_routed_outer(d, change)?;
                } else if live_change && routes_use(d, id) {
                    return Err(invalid("сначала снимите маршруты этого подключения"));
                }
                let row = d["servers"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|r| r["id"] == id)
                    .unwrap();
                *row = proposed.clone();
                Ok(())
            })
        };
        if !live_change {
            return save(&proposed).map(|()| None);
        }
        let managed = owned.get(id).or(adopted.as_ref());
        if managed.is_none() && !restoring {
            if routed.is_some() {
                return Err(invalid("ожидается подтверждённый процесс работающего AWG"));
            }
            if present(&iface(original, &doc)?)? {
                return Err(invalid("активный интерфейс управляется другим процессом"));
            }
            return save(&proposed).map(|()| None);
        }
        if (managed.is_some_and(|managed| managed.tunnel.inherited())
            || original["config"]["client"]["rust_managed"] != true)
            && routed
                .as_ref()
                .is_none_or(|change| !routed_legacy_edit_profile(original, change))
        {
            return Err(invalid(
                "управление работающим профилем AWG ещё не передано",
            ));
        }
        let mut spec = specification(&doc, &proposed)?;
        if managed.is_some_and(|managed| managed.iface != spec.iface) {
            return Err(invalid("интерфейс работающего профиля AWG изменился"));
        }
        let previous = if restoring {
            let superseded = specification(&doc, original)?;
            let superseded_fingerprint = Sha256::digest(superseded.conf.as_bytes()).into();
            let wanted_fingerprint: [u8; 32] = Sha256::digest(spec.conf.as_bytes()).into();
            if managed.is_some_and(|managed| {
                managed.fingerprint != superseded_fingerprint
                    && managed.fingerprint != wanted_fingerprint
            }) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            superseded_fingerprint
        } else {
            managed.unwrap().fingerprint
        };
        let mut initial_launch = None;
        let mut wait_for_wan = false;
        if let Some(change) = &routed {
            let validated_endpoint = change
                .endpoint_selection(&proposed)?
                .map(|selected| (selected.chosen, selected.refreshes_transport()))
                .or_else(|| {
                    change
                        .legacy_predecessor
                        .as_ref()
                        .map(|legacy| (legacy.endpoint, true))
                })
                .or_else(|| {
                    change
                        .native_mtu_endpoint
                        .or_else(|| change.fixed_nested_mtu_endpoint())
                        .filter(|_| restoring)
                        .map(|endpoint| (endpoint, true))
                });
            if let Some((endpoint, refreshes_transport)) = validated_endpoint {
                let initial = routing.and_then(|hooks| hooks.initial);
                let pool = if initial.is_some()
                    && direct_forward_endpoint(&proposed, change)
                        .is_some_and(|edit| !edit.has_hostname())
                {
                    routing_direct_backup_pool(&proposed)?
                } else {
                    Vec::new()
                };
                if refreshes_transport
                    || pool.len() > 1
                    || !pool.is_empty() && initial.is_some_and(|initial| initial.can_wait)
                {
                    spec.outer = expected_routed_outer(&doc, change)?;
                    if let Some(initial) = initial {
                        match (initial.choose)(change, &spec, endpoint)? {
                            RoutedEndpointLaunch::Primary => {}
                            RoutedEndpointLaunch::Alternate(pin) => {
                                if !pool.get(1..).is_some_and(|backups| backups.contains(&pin)) {
                                    return Err(io::ErrorKind::WouldBlock.into());
                                }
                                initial_launch = Some(InitialRoutedLaunch {
                                    endpoint: pin,
                                    prepare: initial.prepare,
                                });
                            }
                            RoutedEndpointLaunch::Waiting => {
                                if !initial.can_wait
                                    || pool.is_empty()
                                    || routing_direct_literal_pool(&proposed)?.is_none()
                                {
                                    return Err(io::ErrorKind::WouldBlock.into());
                                }
                                wait_for_wan = true;
                            }
                        }
                    } else {
                        let validate =
                            routing.and_then(|hooks| hooks.validate).ok_or_else(|| {
                                invalid("правка AWG требует проверки применённых маршрутов")
                            })?;
                        validate(change, &spec, endpoint)?;
                    }
                }
            }
            proposed[PENDING_ROUTED_MTU] = json!(change);
        }
        proposed[PENDING_PROFILE] = json!(previous);
        save(&proposed)?;
        if let Some(adopted) = adopted {
            owned.insert(id.to_owned(), adopted);
        }
        // Go acknowledges a saved edit even if its live application must retry.
        let apply = if wait_for_wan {
            Err(waiting_for_wan())
        } else {
            read(db).and_then(|doc| {
                apply_saved_edit_at(
                    SavedEdit {
                        db,
                        doc: &doc,
                        row: &proposed,
                    },
                    &mut owned,
                    spec,
                    prepare,
                    start,
                    routing.map(|hooks| hooks.park),
                    initial_launch,
                )
            })
        };
        if let Err(e) = apply {
            remember_failed_edit(&mut owned, &proposed, crate::now(), &e);
            return Ok(Some(
                "Конфигурация AWG сохранена. Туннель будет восстановлен автоматически".into(),
            ));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, AtomicU16, Ordering},
        Arc,
    };

    struct NamedEngine {
        fingerprint: [u8; 32],
        endpoint: SocketAddr,
        running: Arc<AtomicBool>,
    }
    impl Tunnel for NamedEngine {
        fn alive(&mut self) -> bool {
            self.running.load(Ordering::SeqCst)
        }
        fn stop(&mut self) -> io::Result<()> {
            self.running.store(false, Ordering::SeqCst);
            Ok(())
        }
        fn probe(&mut self) -> io::Result<()> {
            unreachable!()
        }
        fn snapshot(&self) -> io::Result<Value> {
            unreachable!()
        }
        fn verified_routed_mtu(
            &self,
            spec: &Spec,
            outer: Option<&NestedOuter>,
            _: bool,
        ) -> io::Result<RoutedMtuSample> {
            let fingerprint: [u8; 32] = Sha256::digest(spec.conf.as_bytes()).into();
            if outer.is_some()
                || fingerprint != self.fingerprint
                || !self.running.load(Ordering::SeqCst)
            {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            Ok(RoutedMtuSample {
                endpoint: self.endpoint,
                effective_mtu: 1420,
                socket_mark: 0,
                connected: true,
                outer_endpoint: None,
            })
        }
    }

    #[test]
    fn routed_combined_endpoint_and_mtu_replays_and_undoes_the_exact_pair() {
        routed_combined_endpoint_and_mtu(None, None);
    }

    #[test]
    fn routed_combined_implicit_mtu_preserves_saved_shape_and_live_previous_value() {
        for implicit in [
            RoutedImplicitMtu::Missing,
            RoutedImplicitMtu::Zero,
            RoutedImplicitMtu::Null,
        ] {
            routed_combined_endpoint_and_mtu(Some(implicit), None);
        }
    }

    #[test]
    fn routed_combined_direct_cross_family_edit_pins_selected_wan_and_exact_inverse() {
        let ipv4 = "192.0.2.92:2408".parse().unwrap();
        let ipv6 = "[2001:db8:92::1]:443".parse().unwrap();
        for pair in [(ipv4, ipv6), (ipv6, ipv4)] {
            routed_combined_endpoint_and_mtu(Some(RoutedImplicitMtu::Missing), Some(pair));
        }
    }

    fn routed_combined_endpoint_and_mtu(
        implicit_before_mtu: Option<RoutedImplicitMtu>,
        pair: Option<(SocketAddr, SocketAddr)>,
    ) {
        struct Engine {
            owner: NamedEngine,
            mtu: Arc<AtomicU16>,
            authenticated: Arc<AtomicBool>,
        }
        impl Tunnel for Engine {
            fn alive(&mut self) -> bool {
                self.owner.alive()
            }
            fn stop(&mut self) -> io::Result<()> {
                self.owner.stop()
            }
            fn probe(&mut self) -> io::Result<()> {
                unreachable!()
            }
            fn snapshot(&self) -> io::Result<Value> {
                unreachable!()
            }
            fn verified_routed_mtu(
                &self,
                spec: &Spec,
                outer: Option<&NestedOuter>,
                connected: bool,
            ) -> io::Result<RoutedMtuSample> {
                let mut sample = self.owner.verified_routed_mtu(spec, outer, connected)?;
                sample.effective_mtu = self.mtu.load(Ordering::SeqCst);
                sample.socket_mark = crate::DIRECT_SOCKET_MARK;
                sample.connected = self.authenticated.load(Ordering::SeqCst);
                if connected && !sample.connected {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                Ok(sample)
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        let rt = Runtime::new(dir.path(), dir.path().join("no-engine"));
        crate::import(&db, &crate::tests::input(), "imported").unwrap();
        let (before, after) = pair.unwrap_or_else(|| {
            (
                "192.0.2.92:2408".parse().unwrap(),
                "192.0.2.92:443".parse().unwrap(),
            )
        });
        let cross_family = before.is_ipv4() != after.is_ipv4();
        let reserve: SocketAddr = "192.0.2.93:2408".parse().unwrap();
        let old_mtu = match implicit_before_mtu {
            None => 1420,
            Some(RoutedImplicitMtu::Missing) => 1280,
            Some(_) => 1388,
        };
        let new_mtu = 1320;
        let id = s(active(&read(&db).unwrap()).unwrap(), "id").to_owned();
        let row_mut = |doc: &mut Value, update: &dyn Fn(&mut Value)| {
            let row = doc["servers"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|row| row["id"] == id)
                .unwrap();
            update(row);
        };
        edit_document(&db, |doc| {
            row_mut(doc, &|row| {
                row["config"]["endpoint"] = json!(before);
                row["config"]["mtu"] = json!(old_mtu);
                if let Some(implicit) = implicit_before_mtu {
                    implicit.write(row["config"].as_object_mut().unwrap());
                    let routing = &mut row["config"]["routing"];
                    if implicit == RoutedImplicitMtu::Missing {
                        routing.as_object_mut().unwrap().remove("mtu");
                    } else {
                        routing["mtu"] = json!(old_mtu);
                    }
                }
                row["config"]["client"]["endpoint_backups"] = json!([reserve]);
            });
            Ok(())
        })
        .unwrap();
        let old_running = Arc::new(AtomicBool::new(true));
        let authenticated = Arc::new(AtomicBool::new(true));
        let build = |spec: Spec,
                     endpoint: SocketAddr,
                     configured_mtu: u16,
                     mtu,
                     running|
         -> io::Result<Box<dyn Tunnel>> {
            assert_eq!(spec.endpoint, endpoint.to_string());
            assert_eq!(conf::parse(&spec.conf, 0)?["mtu"], configured_mtu);
            Ok(Box::new(Engine {
                owner: NamedEngine {
                    fingerprint: Sha256::digest(spec.conf.as_bytes()).into(),
                    endpoint,
                    running,
                },
                mtu,
                authenticated: authenticated.clone(),
            }))
        };
        rt.clients
            .up(&db, Some(&id), |spec| {
                build(
                    spec,
                    before,
                    old_mtu,
                    Arc::new(AtomicU16::new(old_mtu)),
                    old_running.clone(),
                )
            })
            .unwrap();
        let previous = rt.clients.0.lock().unwrap()[&id].fingerprint;
        edit_document(&db, |doc| {
            doc["routing_revision"] = json!(7);
            doc["rust_static_routing"] = json!({"revision":7,"pending_commit":false,"targets":[id],"committed_targets":[id]});
            Ok(())
        }).unwrap();

        let measured = Arc::new(AtomicU16::new(new_mtu + 10));
        let new_running = Arc::new(AtomicBool::new(true));
        let old_wan = AtomicBool::new(true);
        let new_wan = AtomicBool::new(true);
        let park = |saved: &RoutedMtuChange| {
            let doc = read(&db)?;
            let row = active(&doc)?;
            assert_eq!(pending_routed_mtu(row)?.as_ref(), Some(saved));
            assert!(routed_combined_endpoint_mtu_profile(row, saved));
            let endpoints = crate::transport_endpoints(&db)?;
            assert!(endpoints.contains(&before) && endpoints.contains(&after));
            Ok(())
        };
        let validate = |change: &RoutedMtuChange, spec: &Spec, endpoint: SocketAddr| {
            assert!(change.combines_endpoint_mtu());
            assert_eq!(change.combines_direct_cross_family_mtu(), cross_family);
            assert_eq!((change.before, change.after), (old_mtu, new_mtu));
            assert_eq!(
                change.endpoint_edit.as_ref().unwrap().sockets()?,
                (before, after)
            );
            assert_eq!(spec.endpoint, endpoint.to_string());
            assert_eq!(
                conf::parse(&spec.conf, 0)?["mtu"],
                if endpoint == before { old_mtu } else { new_mtu }
            );
            assert!(routed_combined_endpoint_mtu_profile(
                active(&read(&db)?)?,
                change
            ));
            (if endpoint == before {
                &old_wan
            } else {
                &new_wan
            })
            .load(Ordering::SeqCst)
            .then_some(())
            .ok_or_else(|| io::ErrorKind::NetworkUnreachable.into())
        };
        let expected = json!({"endpoint":after,"mtu":new_mtu});
        let forward = |decision| {
            rt.clients.save_config(
                &db,
                &expected,
                |spec| {
                    assert!(!old_running.load(Ordering::SeqCst));
                    build(spec, after, new_mtu, measured.clone(), new_running.clone())
                },
                |_| unreachable!(),
                |_, _, _, _| Ok(()),
                Some(RoutedEditHooks {
                    validate: None,
                    park: &park,
                    initial: Some(InitialRoutedEditHooks {
                        choose: &|change, spec, endpoint| {
                            validate(change, spec, endpoint)?;
                            Ok(decision)
                        },
                        prepare: &|_, _| unreachable!(),
                        can_wait: true,
                        prepared: None,
                        verify_previous: &|endpoint, mark| {
                            endpoint == before
                                && mark == crate::DIRECT_SOCKET_MARK
                                && old_wan.load(Ordering::SeqCst)
                        },
                        adopt_legacy: None,
                    }),
                }),
            )
        };
        for decision in [
            RoutedEndpointLaunch::Waiting,
            RoutedEndpointLaunch::Alternate(reserve),
        ] {
            assert!(forward(decision).is_err());
            assert!(old_running.load(Ordering::SeqCst));
            assert!(pending_routed_mtu(active(&read(&db).unwrap()).unwrap())
                .unwrap()
                .is_none());
        }
        if cross_family {
            let original = read(&db).unwrap();
            for evidence in [&*authenticated, &old_wan, &new_wan] {
                evidence.store(false, Ordering::SeqCst);
                assert!(forward(RoutedEndpointLaunch::Primary).is_err());
                assert_eq!(read(&db).unwrap(), original);
                assert!(old_running.load(Ordering::SeqCst));
                evidence.store(true, Ordering::SeqCst);
            }
            let mut spec = specification(&original, active(&original).unwrap()).unwrap();
            spec.endpoint = reserve.to_string();
            let wanted = build(
                spec,
                reserve,
                old_mtu,
                Arc::new(AtomicU16::new(old_mtu)),
                old_running.clone(),
            )
            .unwrap();
            let previous = std::mem::replace(
                &mut rt.clients.0.lock().unwrap().get_mut(&id).unwrap().tunnel,
                wanted,
            );
            assert!(forward(RoutedEndpointLaunch::Primary).is_err());
            assert_eq!(read(&db).unwrap(), original);
            assert!(old_running.load(Ordering::SeqCst));
            rt.clients.0.lock().unwrap().get_mut(&id).unwrap().tunnel = previous;
        }
        assert!(forward(RoutedEndpointLaunch::Primary).unwrap().is_some());

        let doc = read(&db).unwrap();
        let row = active(&doc).unwrap();
        let change = pending_routed_mtu(row).unwrap().unwrap();
        assert_eq!(change.implicit_before_mtu, implicit_before_mtu);
        let encoded = serde_json::to_value(&change).unwrap();
        if let Some(implicit) = implicit_before_mtu {
            assert_eq!(encoded["implicit_before_mtu"], json!(implicit));
            let mut stale = doc.clone();
            row_mut(&mut stale, &|row| {
                row["config"]["routing"]["mtu"] = json!(old_mtu + 10)
            });
            assert!(check_saved_edit(&stale, active(&stale).unwrap()).is_err());
        } else {
            assert!(encoded.get("implicit_before_mtu").is_none());
        }
        assert_eq!(
            serde_json::from_value::<RoutedMtuChange>(encoded).unwrap(),
            change
        );
        let successor = specification(&doc, row).unwrap();
        assert_eq!(previous_fingerprint(row).unwrap(), Some(previous));
        assert!(!transport_refresh_pending(row));
        assert!(!routed_endpoint_initial_pending(row).unwrap());
        assert!(routed_endpoint_retry_pool(row, &change).unwrap().is_empty());
        assert!(rt.routed_mtu_peer(&db, &change).is_err());
        let before_spec = superseded_routed_spec(
            &doc,
            row,
            &change,
            change.endpoint_selection(row).unwrap().as_ref(),
        )
        .unwrap();
        assert_eq!(
            previous,
            <[u8; 32]>::from(Sha256::digest(before_spec.conf.as_bytes()))
        );
        for invalid in [json!(old_mtu), Value::Null] {
            let mut mixed = doc.clone();
            row_mut(&mut mixed, &|row| row["config"]["mtu"] = invalid.clone());
            assert!(check_saved_edit(&mixed, active(&mixed).unwrap()).is_err());
        }

        measured.store(new_mtu, Ordering::SeqCst);
        let reopened = Store::open(dir.path()).unwrap();
        assert_eq!(
            apply_saved_edit(
                SavedEdit {
                    db: &reopened,
                    doc: &doc,
                    row
                },
                &mut rt.clients.0.lock().unwrap(),
                successor.clone(),
                |doc, _, _, _| {
                    assert!(transport_refresh_pending(active(doc)?));
                    let endpoints = crate::transport_endpoints(&db)?;
                    assert!(!endpoints.contains(&before) && endpoints.contains(&after));
                    Err(io::ErrorKind::TimedOut.into())
                },
                |_| unreachable!("native successor already owns the interface"),
                Some(&|_| unreachable!("forward already parked")),
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::TimedOut
        );
        assert!(new_running.load(Ordering::SeqCst));
        assert!(transport_refresh_pending(
            active(&read(&db).unwrap()).unwrap()
        ));

        if cross_family {
            let doc = read(&reopened).unwrap();
            let row = active(&doc).unwrap();
            apply_saved_edit(
                SavedEdit {
                    db: &reopened,
                    doc: &doc,
                    row,
                },
                &mut rt.clients.0.lock().unwrap(),
                successor.clone(),
                |_, _, spec, _| {
                    assert_eq!(spec.endpoint, after.to_string());
                    Ok(())
                },
                |_| unreachable!("native successor already owns the interface"),
                Some(&|_| unreachable!("forward already parked")),
            )
            .unwrap();
            let peer = |pin| {
                rt.routed_mtu_peer_inner(&reopened, &change, Some(pin), |selected, mark| {
                    selected == after
                        && mark == crate::DIRECT_SOCKET_MARK
                        && new_wan.load(Ordering::SeqCst)
                })
            };
            assert!(peer(before).is_err());
            assert_eq!(peer(after).unwrap().unwrap().effective_mtu, new_mtu);
            new_wan.store(false, Ordering::SeqCst);
            assert!(peer(after).is_err());
        }
        for input in [
            json!({"endpoint":before}),
            json!({"mtu":old_mtu}),
            json!({"endpoint":before,"mtu":new_mtu+1}),
        ] {
            assert!(rt
                .clients
                .save_config(
                    &db,
                    &input,
                    |_| unreachable!(),
                    |_| unreachable!(),
                    |_, _, _, _| unreachable!(),
                    Some(RoutedEditHooks {
                        initial: None,
                        park: &park,
                        validate: Some(&validate)
                    }),
                )
                .is_err());
        }
        let inverse = rt
            .clients
            .save_config(
                &db,
                &json!({"endpoint":before,"mtu":old_mtu}),
                |spec| {
                    assert!(!new_running.load(Ordering::SeqCst));
                    build(
                        spec,
                        before,
                        old_mtu,
                        Arc::new(AtomicU16::new(old_mtu)),
                        Arc::new(AtomicBool::new(true)),
                    )
                },
                |_| unreachable!(),
                |doc, _, _, _| {
                    let row = active(doc)?;
                    if !transport_refresh_pending(row) {
                        assert_eq!(
                            previous_fingerprint(row)?,
                            Some(Sha256::digest(successor.conf.as_bytes()).into())
                        );
                    }
                    Ok(())
                },
                Some(RoutedEditHooks {
                    initial: None,
                    park: &park,
                    validate: Some(&validate),
                }),
            )
            .unwrap();
        assert!(inverse.is_none());
        let disk = read(&db).unwrap();
        let reverted = active(&disk).unwrap();
        assert_eq!(reverted["config"]["endpoint"], before.to_string());
        assert_eq!(
            reverted["config"]["client"]["endpoint_backups"],
            json!([reserve])
        );
        let raw = reverted["config"].get("mtu");
        match implicit_before_mtu {
            None => assert_eq!(raw, Some(&json!(old_mtu))),
            Some(RoutedImplicitMtu::Missing) => assert!(raw.is_none()),
            Some(RoutedImplicitMtu::Zero) => assert_eq!(raw, Some(&json!(0))),
            Some(RoutedImplicitMtu::Null) => assert_eq!(raw, Some(&Value::Null)),
        }
        assert_eq!(effective_mtu(reverted).unwrap(), old_mtu);
        if implicit_before_mtu.is_some() {
            let mut materialized = reverted.clone();
            materialized["config"]["mtu"] = json!(old_mtu);
            assert_eq!(effective_mtu(&materialized).unwrap(), old_mtu);
            assert!(!routed_combined_endpoint_mtu_profile(
                &materialized,
                &change
            ));
        }
        assert_eq!(rt.clients.0.lock().unwrap()[&id].fingerprint, previous);
        assert!(rt
            .routed_mtu_peer_inner(&db, &change, Some(before), |_, _| false)
            .is_err());
        let proof = rt
            .routed_mtu_peer_inner(&db, &change, Some(before), |endpoint, mark| {
                endpoint == before && mark == crate::DIRECT_SOCKET_MARK
            })
            .unwrap()
            .unwrap();
        assert_eq!((proof.endpoint, proof.effective_mtu), (before, old_mtu));
        assert!(rt
            .routed_mtu_peer_inner(&db, &change, Some(after), |_, _| true)
            .is_err());
    }

    #[test]
    fn routed_inherited_port_edit_replays_before_park_and_after_native_start() {
        routed_inherited_endpoint_edit(
            "192.0.2.87:2408",
            "192.0.2.87:443",
            InheritedEdit::Forward,
            None,
        );
    }

    #[test]
    fn routed_inherited_port_edit_reverses_through_the_same_sealed_predecessor() {
        routed_inherited_endpoint_edit(
            "192.0.2.87:2408",
            "192.0.2.87:443",
            InheritedEdit::UndoBeforePromotion,
            None,
        );
    }

    #[test]
    fn routed_inherited_ip_edit_replays_ipv4_at_the_same_udp_port() {
        for operation in [InheritedEdit::Forward, InheritedEdit::UndoBeforePromotion] {
            routed_inherited_endpoint_edit("192.0.2.87:2408", "192.0.2.88:2408", operation, None);
        }
    }

    #[test]
    fn routed_inherited_ip_edit_undoes_ipv6_after_native_promotion() {
        routed_inherited_endpoint_edit(
            "[2001:db8::87]:2408",
            "[2001:db8::88]:2408",
            InheritedEdit::UndoAfterPromotion,
            None,
        );
    }

    #[test]
    fn routed_inherited_hostname_edit_replays_and_restores_raw_name_without_dns() {
        for operation in [
            InheritedEdit::Forward,
            InheritedEdit::UndoBeforePromotion,
            InheritedEdit::UndoAfterPromotion,
        ] {
            routed_inherited_endpoint_edit_at(
                "Original.Example:2408",
                "192.0.2.87:2408".parse().unwrap(),
                "192.0.2.88:2408",
                operation,
                None,
                None,
            );
        }
        routed_inherited_endpoint_edit_at(
            "Original.Example:2408",
            "[2001:db8::87]:2408".parse().unwrap(),
            "[2001:db8::87]:443",
            InheritedEdit::UndoAfterPromotion,
            None,
            None,
        );
    }

    #[test]
    fn routed_inherited_numeric_edit_prepares_fresh_hostname_and_undoes_without_dns() {
        for (selected, operation) in [
            ("192.0.2.88:443", InheritedEdit::Forward),
            ("192.0.2.88:443", InheritedEdit::UndoBeforePromotion),
            ("192.0.2.87:443", InheritedEdit::UndoAfterPromotion),
        ] {
            routed_inherited_endpoint_edit_at(
                "192.0.2.87:2408",
                "192.0.2.87:2408".parse().unwrap(),
                "Fresh.Example:443",
                operation,
                None,
                Some(&[
                    "[2001:db8::88]:443".parse().unwrap(),
                    selected.parse().unwrap(),
                    "192.0.2.89:443".parse().unwrap(),
                ]),
            );
        }
    }

    #[test]
    fn routed_inherited_name_alias_requires_the_exact_new_owner_at_the_same_socket() {
        let literal = "192.0.2.87:2408";
        let actual = literal.parse().unwrap();
        let name = "Alias.Example:2408";
        for operation in [
            InheritedEdit::Forward,
            InheritedEdit::UndoBeforePromotion,
            InheritedEdit::UndoAfterPromotion,
        ] {
            routed_inherited_endpoint_edit_at(name, actual, literal, operation, None, None);
            routed_inherited_endpoint_edit_at(
                literal,
                actual,
                name,
                operation,
                None,
                Some(&[actual]),
            );
        }
    }

    #[test]
    fn routed_inherited_combined_edit_replays_ipv4_and_restores_both_fields_before_promotion() {
        routed_inherited_endpoint_edit(
            "192.0.2.87:2408",
            "192.0.2.88:2408",
            InheritedEdit::Forward,
            Some((1320, Some(RoutedImplicitMtu::Missing))),
        );
        routed_inherited_endpoint_edit(
            "192.0.2.87:2408",
            "192.0.2.88:443",
            InheritedEdit::UndoBeforePromotion,
            Some((1320, Some(RoutedImplicitMtu::Null))),
        );
    }

    #[test]
    fn routed_inherited_combined_edit_undoes_ipv6_port_and_mtu_after_promotion() {
        routed_inherited_endpoint_edit(
            "[2001:db8::87]:2408",
            "[2001:db8::87]:443",
            InheritedEdit::UndoAfterPromotion,
            Some((1320, Some(RoutedImplicitMtu::Zero))),
        );
    }

    #[test]
    fn routed_native_mtu_inverse_reuses_old_owner_or_retires_exact_successor() {
        routed_native_mtu_edit(Ok(RoutedEndpointLaunch::Primary), MtuReplay::OldOwner, None);
        routed_native_mtu_edit(Ok(RoutedEndpointLaunch::Primary), MtuReplay::Promoted, None);
    }

    #[test]
    fn routed_native_mtu_pins_authenticated_numeric_reserve_when_primary_has_no_wan() {
        routed_native_mtu_edit(
            Ok(RoutedEndpointLaunch::Primary),
            MtuReplay::OldOwner,
            Some("192.0.2.125:443"),
        );
        routed_native_mtu_edit(
            Ok(RoutedEndpointLaunch::Primary),
            MtuReplay::Promoted,
            Some("[2001:db8::125]:443"),
        );
        routed_native_mtu_edit(
            Ok(RoutedEndpointLaunch::Primary),
            MtuReplay::Cold,
            Some("192.0.2.123:443"),
        );
    }

    #[test]
    fn routed_native_mtu_scope_fallback_keeps_old_forward_only_transaction() {
        routed_native_mtu_edit(Err(io::ErrorKind::Unsupported), MtuReplay::OldOwner, None);
    }

    #[test]
    fn routed_native_mtu_forward_accepts_only_proved_reserve_or_quiet_primary() {
        for connected in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let db = Store::open(dir.path()).unwrap();
            let runtime = Runtime::new(dir.path(), dir.path().join("no-engine"));
            crate::import(&db, &crate::tests::input(), "owned").unwrap();
            let id = s(active(&read(&db).unwrap()).unwrap(), "id").to_owned();
            let primary: SocketAddr = "192.0.2.124:2408".parse().unwrap();
            let reserve: SocketAddr = "192.0.2.125:443".parse().unwrap();
            let observed = if connected { reserve } else { primary };
            let update = |doc: &mut Value, edit: &dyn Fn(&mut Value)| {
                let row = doc["servers"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|row| row["id"] == id)
                    .unwrap();
                edit(&mut row["config"]);
            };
            edit_document(&db, |doc| {
                update(doc, &|cfg| cfg["endpoint"] = json!(primary));
                Ok(())
            })
            .unwrap();
            let running = Arc::new(AtomicBool::new(true));
            let measured = Arc::new(AtomicU16::new(1420));
            runtime
                .clients
                .up(&db, Some(&id), |spec| {
                    Ok(Box::new(NativeEngine(
                        NamedEngine {
                            fingerprint: Sha256::digest(spec.conf.as_bytes()).into(),
                            endpoint: observed,
                            running: running.clone(),
                        },
                        measured.clone(),
                        connected,
                    )))
                })
                .unwrap();
            edit_document(&db, |doc| {
                doc["routing_revision"] = json!(7);
                doc["rust_static_routing"] = json!({"revision":7,"pending_commit":false,"targets":[id],"committed_targets":[id]});
                Ok(())
            }).unwrap();
            let checks = std::cell::Cell::new(0);
            let stage = |wan: bool| {
                runtime.clients.save_config(
                    &db,
                    &json!({"mtu":1320}),
                    |_| unreachable!("the working owner has not been parked"),
                    |_| unreachable!(),
                    |_, _, _, _| Ok(()),
                    Some(RoutedEditHooks {
                        validate: None,
                        park: &|change| {
                            assert!(
                                change.native_mtu_endpoint.is_none()
                                    && !change.requires_peer_proof()
                            );
                            Err(io::ErrorKind::TimedOut.into())
                        },
                        initial: Some(InitialRoutedEditHooks {
                            choose: &|change, _, selected| {
                                checks.set(checks.get() + 1);
                                assert_eq!(change.native_mtu_endpoint, Some(selected));
                                if selected == reserve {
                                    Err(io::ErrorKind::Unsupported.into())
                                } else {
                                    Ok(RoutedEndpointLaunch::Primary)
                                }
                            },
                            prepare: &|_, _| unreachable!(),
                            can_wait: true,
                            prepared: None,
                            verify_previous: &|selected, mark| {
                                wan && selected == observed && mark == crate::DIRECT_SOCKET_MARK
                            },
                            adopt_legacy: None,
                        }),
                    }),
                )
            };
            if connected {
                assert!(stage(true).is_err());
                assert_eq!(checks.replace(0), 1);
                edit_document(&db, |doc| {
                    update(doc, &|cfg| {
                        cfg["client"]["endpoint_backups"] = json!([reserve])
                    });
                    Ok(())
                })
                .unwrap();
            }
            measured.store(1410, Ordering::SeqCst);
            assert!(stage(true).is_err());
            measured.store(1420, Ordering::SeqCst);
            assert!(stage(false).is_err());
            assert!(pending_routed_mtu(active(&read(&db).unwrap()).unwrap())
                .unwrap()
                .is_none());
            assert!(stage(true).unwrap().is_some());
            assert_eq!(checks.get(), usize::from(connected));
            assert!(running.load(Ordering::SeqCst));
            let doc = read(&db).unwrap();
            let row = active(&doc).unwrap();
            assert_eq!(row["config"]["endpoint"], primary.to_string());
            assert_eq!(row["config"]["mtu"], 1320);
            assert!(pending_routed_mtu(row)
                .unwrap()
                .unwrap()
                .native_mtu_endpoint
                .is_none());
            if connected {
                assert_eq!(
                    row["config"]["client"]["endpoint_backups"],
                    json!([reserve])
                );
            }
        }
    }

    #[derive(PartialEq, Eq)]
    enum MtuReplay {
        OldOwner,
        Promoted,
        Cold,
    }

    fn routed_native_mtu_edit(
        layout: Result<RoutedEndpointLaunch, io::ErrorKind>,
        replay: MtuReplay,
        reserve: Option<&str>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        let runtime = Runtime::new(dir.path(), dir.path().join("no-engine"));
        crate::import(&db, &crate::tests::input(), "owned").unwrap();
        let id = s(active(&read(&db).unwrap()).unwrap(), "id").to_owned();
        let primary: SocketAddr = "192.0.2.123:2408".parse().unwrap();
        let endpoint = reserve.map_or(primary, |reserve| reserve.parse().unwrap());
        let before = 1390;
        let after = 1300;
        edit_document(&db, |doc| {
            let row = doc["servers"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|row| row["id"] == id)
                .unwrap();
            row["config"]["endpoint"] = json!(primary);
            if reserve.is_some() {
                row["config"]["client"]["endpoint_backups"] = json!([endpoint]);
            }
            row["config"]["mtu"] = Value::Null;
            row["config"]["routing"]["mtu"] = json!(before);
            Ok(())
        })
        .unwrap();
        let measured = Arc::new(AtomicU16::new(before));
        let old_running = Arc::new(AtomicBool::new(true));
        runtime
            .clients
            .up(&db, Some(&id), |spec| {
                Ok(Box::new(NativeEngine(
                    NamedEngine {
                        fingerprint: Sha256::digest(spec.conf.as_bytes()).into(),
                        endpoint,
                        running: old_running.clone(),
                    },
                    measured.clone(),
                    true,
                )))
            })
            .unwrap();
        edit_document(&db, |doc| {
            doc["routing_revision"] = json!(7);
            doc["rust_static_routing"] = json!({"revision":7,"pending_commit":false,"targets":[id],"committed_targets":[id]});
            Ok(())
        }).unwrap();
        let original = read(&db).unwrap();
        let old_row = active(&original).unwrap();
        let old_spec = specification(&original, old_row).unwrap();
        let old_fingerprint: [u8; 32] = Sha256::digest(old_spec.conf.as_bytes()).into();
        let tuple_list = crate::transport_endpoints(&db).unwrap();
        let stage = |result: Result<RoutedEndpointLaunch, io::ErrorKind>, wan: bool| {
            let validations = std::cell::Cell::new(0);
            let staged = runtime.clients.save_config(
                &db,
                &json!({"mtu":after}),
                |_| unreachable!("unable to park the working route in this phase"),
                |_| unreachable!(),
                |_, _, _, _| Ok(()),
                Some(RoutedEditHooks {
                    validate: None,
                    park: &|_| Err(io::ErrorKind::TimedOut.into()),
                    initial: Some(InitialRoutedEditHooks {
                        choose: &|change, spec, selected| {
                            validations.set(validations.get() + 1);
                            assert_eq!(selected, endpoint);
                            assert_eq!(
                                conf::parse(&spec.conf, 0)?["endpoint"],
                                primary.to_string()
                            );
                            assert_eq!(conf::parse(&spec.conf, 0)?["mtu"], after);
                            assert_eq!(change.native_mtu_endpoint, Some(endpoint));
                            assert_eq!(change.implicit_before_mtu, Some(RoutedImplicitMtu::Null));
                            assert!(routed_native_mtu_edit_profile(old_row, change));
                            assert!(active(&read(&db)?)?.get(PENDING_PROFILE).is_none());
                            result.map_err(io::Error::from)
                        },
                        prepare: &|_, _| unreachable!(),
                        can_wait: true,
                        prepared: None,
                        verify_previous: &|selected, mark| {
                            wan && selected == endpoint && mark == crate::DIRECT_SOCKET_MARK
                        },
                        adopt_legacy: None,
                    }),
                }),
            );
            assert_eq!(
                validations.get(),
                usize::from(reserve.is_none() || wan && measured.load(Ordering::SeqCst) == before)
            );
            staged
        };
        for denial in [
            Err(io::ErrorKind::WouldBlock),
            Err(io::ErrorKind::NetworkUnreachable),
            Ok(RoutedEndpointLaunch::Waiting),
        ] {
            assert!(stage(denial, true).is_err());
            assert_eq!(read(&db).unwrap(), original);
        }
        measured.store(before + 1, Ordering::SeqCst);
        assert!(stage(Ok(RoutedEndpointLaunch::Primary), true).is_err());
        measured.store(before, Ordering::SeqCst);
        assert!(stage(Ok(RoutedEndpointLaunch::Primary), false).is_err());
        assert_eq!(read(&db).unwrap(), original);

        let reversible = layout.is_ok();
        assert!(stage(layout, reversible).unwrap().is_some());
        let reopened = Store::open(dir.path()).unwrap();
        let doc = read(&reopened).unwrap();
        let row = active(&doc).unwrap();
        let change = pending_routed_mtu(row).unwrap().unwrap();
        assert_eq!(previous_fingerprint(row).unwrap(), Some(old_fingerprint));
        assert_eq!(change.native_mtu_endpoint, reversible.then_some(endpoint));
        if !reversible {
            assert!(change.implicit_before_mtu.is_none() && !change.requires_peer_proof());
            assert!(runtime
                .clients
                .save_config(
                    &reopened,
                    &json!({"mtu":before}),
                    |_| unreachable!(),
                    |_| unreachable!(),
                    |_, _, _, _| unreachable!(),
                    Some(RoutedEditHooks {
                        initial: None,
                        park: &|_| unreachable!(),
                        validate: Some(&|_, _, _| unreachable!())
                    }),
                )
                .is_err());
            assert!(old_running.load(Ordering::SeqCst));
            return;
        }

        if reserve.is_some() {
            let mut wrong_port = endpoint;
            wrong_port.set_port(endpoint.port() + 1);
            assert_eq!(
                runtime
                    .set_backups(&reopened, &id, &[wrong_port.to_string()], &[])
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::WouldBlock,
            );
            runtime
                .set_backups(&reopened, &id, &[endpoint.to_string()], &[])
                .unwrap();
            assert!(old_running.load(Ordering::SeqCst));
        }

        let successor_running = Arc::new(AtomicBool::new(false));
        let successor_mtu = Arc::new(AtomicU16::new(after));
        let park = |saved: &RoutedMtuChange| {
            assert_eq!(saved, &change);
            Ok(())
        };
        if replay == MtuReplay::Cold {
            runtime.clients.0.lock().unwrap().remove(&id).unwrap();
            old_running.store(false, Ordering::SeqCst);
        }
        let promoted = replay != MtuReplay::OldOwner;
        if promoted {
            assert_eq!(
                apply_saved_edit(
                    SavedEdit {
                        db: &reopened,
                        doc: &doc,
                        row
                    },
                    &mut runtime.clients.0.lock().unwrap(),
                    specification(&doc, row).unwrap(),
                    |current, _, _, phase| {
                        if let EditPreparation::VerifyDirectBeforeRetiring(selected, mark) = phase {
                            assert!(replay != MtuReplay::Cold);
                            assert_eq!((selected, mark), (endpoint, crate::DIRECT_SOCKET_MARK));
                            assert!(old_running.load(Ordering::SeqCst));
                        }
                        if transport_refresh_pending(active(current)?) {
                            Err(io::ErrorKind::TimedOut.into())
                        } else {
                            Ok(())
                        }
                    },
                    |spec| {
                        assert!(!old_running.load(Ordering::SeqCst));
                        assert_eq!(spec.endpoint, endpoint.to_string());
                        successor_running.store(true, Ordering::SeqCst);
                        Ok(Box::new(NativeEngine(
                            NamedEngine {
                                fingerprint: Sha256::digest(spec.conf.as_bytes()).into(),
                                endpoint,
                                running: successor_running.clone(),
                            },
                            successor_mtu.clone(),
                            true,
                        )))
                    },
                    Some(&park),
                )
                .unwrap_err()
                .kind(),
                io::ErrorKind::TimedOut
            );
            if reserve.is_some() {
                let resumed = read(&reopened).unwrap();
                let row = active(&resumed).unwrap();
                assert!(transport_refresh_pending(row));
                let mut owned = runtime.clients.0.lock().unwrap();
                owned.get_mut(&id).unwrap().recovery = Default::default();
                apply_saved_edit(
                    SavedEdit {
                        db: &reopened,
                        doc: &resumed,
                        row,
                    },
                    &mut owned,
                    specification(&resumed, row).unwrap(),
                    |_, _, spec, _| {
                        assert_eq!(spec.endpoint, endpoint.to_string());
                        Ok(())
                    },
                    |_| unreachable!("the exact native generation is already running"),
                    Some(&park),
                )
                .unwrap();
                assert_eq!(owned[&id].recovery.selected(), reserve);
                drop(owned);
                assert!(runtime
                    .routed_mtu_peer_inner(&reopened, &change, Some(primary), |_, _| true)
                    .is_err());
                let proof = runtime
                    .routed_mtu_peer_inner(&reopened, &change, Some(endpoint), |selected, mark| {
                        selected == endpoint && mark == crate::DIRECT_SOCKET_MARK
                    })
                    .unwrap()
                    .unwrap();
                assert_eq!((proof.endpoint, proof.effective_mtu), (endpoint, after));
            }
            successor_mtu.store(after + 1, Ordering::SeqCst);
        }

        let replay = Runtime::new(dir.path(), dir.path().join("no-engine"));
        let owner = runtime.clients.0.lock().unwrap().remove(&id).unwrap();
        replay.clients.0.lock().unwrap().insert(id.clone(), owner);
        let seen_live_wan = std::cell::Cell::new(false);
        let response = replay
            .clients
            .save_config(
                &reopened,
                &json!({"mtu":before}),
                |spec| {
                    assert!(promoted && seen_live_wan.get());
                    assert!(!successor_running.load(Ordering::SeqCst));
                    assert_eq!(spec.endpoint, endpoint.to_string());
                    assert_eq!(spec.conf, old_spec.conf);
                    Ok(Box::new(NativeEngine(
                        NamedEngine {
                            fingerprint: old_fingerprint,
                            endpoint,
                            running: Arc::new(AtomicBool::new(true)),
                        },
                        measured.clone(),
                        true,
                    )))
                },
                |_| unreachable!(),
                |_, _, _, phase| {
                    assert_eq!(crate::transport_endpoints(&reopened)?, tuple_list);
                    if let EditPreparation::VerifyDirectBeforeRetiring(selected, mark) = phase {
                        assert_eq!((selected, mark), (endpoint, crate::DIRECT_SOCKET_MARK));
                        assert!(promoted && successor_running.load(Ordering::SeqCst));
                        seen_live_wan.set(true);
                    }
                    Ok(())
                },
                Some(RoutedEditHooks {
                    initial: None,
                    park: &park,
                    validate: Some(&|saved, spec, selected| {
                        assert_eq!(saved, &change);
                        assert_eq!(selected, endpoint);
                        assert_eq!(spec.conf, old_spec.conf);
                        Ok(())
                    }),
                }),
            )
            .unwrap();
        assert!(response.is_none());
        assert_eq!(old_running.load(Ordering::SeqCst), !promoted);
        assert_eq!(seen_live_wan.get(), promoted);
        let disk = read(&reopened).unwrap();
        let saved = active(&disk).unwrap();
        assert_eq!(saved["config"].get("mtu"), Some(&Value::Null));
        assert_eq!(saved["config"]["endpoint"], old_spec.endpoint);
        if reserve.is_some() {
            assert_eq!(
                saved["config"]["client"]["endpoint_backups"],
                json!([endpoint])
            );
            assert_eq!(
                replay.clients.0.lock().unwrap()[&id].recovery.selected(),
                reserve
            );
        }
        assert!(replay
            .routed_mtu_peer_inner(&reopened, &change, Some(endpoint), |_, _| false)
            .is_err());
        let peer = replay
            .routed_mtu_peer_inner(&reopened, &change, Some(endpoint), |selected, mark| {
                selected == endpoint && mark == crate::DIRECT_SOCKET_MARK
            })
            .unwrap()
            .unwrap();
        assert_eq!((peer.endpoint, peer.effective_mtu), (endpoint, before));
    }

    #[test]
    fn routed_inherited_mtu_edit_replays_the_sealed_owner_at_the_same_tuple() {
        routed_inherited_mtu_edit(Some(RoutedImplicitMtu::Missing), InheritedEdit::Forward);
    }

    #[test]
    fn routed_inherited_mtu_inverse_preserves_raw_shape_before_and_after_promotion() {
        for implicit in [
            None,
            Some(RoutedImplicitMtu::Missing),
            Some(RoutedImplicitMtu::Zero),
            Some(RoutedImplicitMtu::Null),
        ] {
            for operation in [
                InheritedEdit::UndoBeforePromotion,
                InheritedEdit::UndoAfterPromotion,
            ] {
                routed_inherited_mtu_edit(implicit, operation);
            }
        }
    }

    fn routed_inherited_mtu_edit(implicit: Option<RoutedImplicitMtu>, operation: InheritedEdit) {
        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        let runtime = Runtime::new(dir.path(), dir.path().join("no-engine"));
        crate::import(&db, &crate::tests::input(), "inherited").unwrap();
        let id = s(active(&read(&db).unwrap()).unwrap(), "id").to_owned();
        let endpoint: SocketAddr = "[2001:db8::71]:2408".parse().unwrap();
        let reserve: SocketAddr = "192.0.2.72:443".parse().unwrap();
        let before = 1388;
        let after = 1320;
        let proof = RoutedLegacyPredecessor {
            receipt_sha256: [25; 32],
            endpoint,
        };
        edit_document(&db, |doc| {
            doc["routing_revision"] = json!(7);
            doc["rust_static_routing"] = json!({"revision":7,"pending_commit":false,"targets":[id],"committed_targets":[id]});
            let row = doc["servers"].as_array_mut().unwrap().iter_mut().find(|row| row["id"] == id).unwrap();
            let cfg = &mut row["config"];
            cfg["endpoint"] = json!(endpoint);
            cfg["enabled"] = json!(true);
            cfg["client"]["enabled"] = json!(true);
            cfg["client"]["endpoint_backups"] = json!([reserve]);
            cfg["client"].as_object_mut().unwrap().remove("rust_managed");
            cfg["mtu"] = json!(before);
            if let Some(implicit) = implicit {
                implicit.write(cfg.as_object_mut().unwrap());
            }
            cfg["routing"]["mtu"] = json!(before);
            Ok(())
        }).unwrap();
        let original = read(&db).unwrap();
        let original_row = active(&original).unwrap();
        let old_spec = specification(&original, original_row).unwrap();
        let old_fingerprint: [u8; 32] = Sha256::digest(old_spec.conf.as_bytes()).into();
        let transports = crate::transport_endpoints(&db).unwrap();
        assert!(transports.contains(&endpoint) && transports.contains(&reserve));
        assert_eq!(effective_mtu(original_row).unwrap(), before);
        let old_running = Arc::new(AtomicBool::new(true));
        let parked = Arc::new(AtomicBool::new(false));
        let stage = |decision, old_wan: bool| {
            runtime.clients.save_config(
                &db,
                &json!({"mtu":after}),
                |_| unreachable!("must keep the old engine until park succeeds"),
                |_| unreachable!(),
                |_, _, _, _| Ok(()),
                Some(RoutedEditHooks {
                    validate: None,
                    park: &|_| Err(io::ErrorKind::TimedOut.into()),
                    initial: Some(InitialRoutedEditHooks {
                        choose: &|change, spec, selected| {
                            assert!(old_wan && old_running.load(Ordering::SeqCst));
                            assert_eq!(active(&read(&db)?)?, original_row);
                            assert_eq!(change.legacy_predecessor.as_ref(), Some(&proof));
                            assert!(change.endpoint_edit.is_none() && change.requires_peer_proof());
                            assert_eq!((change.before, change.after), (before, after));
                            assert_eq!(selected, endpoint);
                            assert_eq!(spec.endpoint, endpoint.to_string());
                            assert_eq!(conf::parse(&spec.conf, 0)?["mtu"], after);
                            Ok(decision)
                        },
                        prepare: &|_, _| unreachable!("no alternate can be authorized"),
                        can_wait: true,
                        prepared: None,
                        verify_previous: &|selected, mark| {
                            old_wan && selected == endpoint && mark == 0
                        },
                        adopt_legacy: Some(&|spec| {
                            assert_eq!(spec.conf, old_spec.conf);
                            Ok(Some(Box::new(InheritedEngine {
                                fingerprint: old_fingerprint,
                                proof: proof.clone(),
                                mtu: before,
                                running: old_running.clone(),
                                parked: parked.clone(),
                            })))
                        }),
                    }),
                }),
            )
        };
        for (decision, old_wan) in [
            (RoutedEndpointLaunch::Primary, false),
            (RoutedEndpointLaunch::Waiting, true),
            (RoutedEndpointLaunch::Alternate(reserve), true),
        ] {
            assert!(stage(decision, old_wan).is_err());
            assert_eq!(active(&read(&db).unwrap()).unwrap(), original_row);
            assert!(old_running.load(Ordering::SeqCst));
        }
        assert!(stage(RoutedEndpointLaunch::Primary, true)
            .unwrap()
            .is_some());
        let reopened = Store::open(dir.path()).unwrap();
        let doc = read(&reopened).unwrap();
        let row = active(&doc).unwrap();
        let change = pending_routed_mtu(row).unwrap().unwrap();
        assert!(awaiting_legacy_edit(row));
        assert!(change.legacy_mtu_before_recorded);
        assert_eq!(change.implicit_before_mtu, implicit);
        assert_eq!(previous_fingerprint(row).unwrap(), Some(old_fingerprint));
        assert_eq!(
            legacy_predecessor_spec(&doc, row, &change).unwrap().conf,
            old_spec.conf
        );
        assert_eq!(crate::transport_endpoints(&reopened).unwrap(), transports);
        assert_eq!(
            row["config"]["client"]["endpoint_backups"],
            json!([reserve])
        );
        assert!(old_running.load(Ordering::SeqCst));
        assert!(runtime.routed_mtu_peer(&reopened, &change).is_err());
        assert!(runtime
            .clients
            .save_config(
                &reopened,
                &json!({"mtu":after + 1}),
                |_| unreachable!(),
                |_| unreachable!(),
                |_, _, _, _| unreachable!(),
                Some(RoutedEditHooks {
                    initial: None,
                    park: &|_| unreachable!(),
                    validate: Some(&|_, _, _| unreachable!())
                }),
            )
            .is_err());

        if operation == InheritedEdit::Forward {
            let mut historical = change.clone();
            historical.legacy_mtu_before_recorded = false;
            historical.implicit_before_mtu = None;
            let mut old_doc = doc.clone();
            let historical_row = old_doc["servers"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|row| row["id"] == id)
                .unwrap();
            historical_row[PENDING_ROUTED_MTU] = json!(historical);
            let encoded = &historical_row[PENDING_ROUTED_MTU];
            assert!(encoded.get("legacy_mtu_before_recorded").is_none());
            assert_eq!(
                check_saved_edit(&old_doc, active(&old_doc).unwrap()).unwrap(),
                Some(historical.clone())
            );
            edit_document(&reopened, |doc| {
                let row = doc["servers"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|row| row["id"] == id)
                    .unwrap();
                row[PENDING_ROUTED_MTU] = json!(historical);
                Ok(())
            })
            .unwrap();
            assert!(runtime
                .clients
                .save_config(
                    &reopened,
                    &json!({"mtu":before}),
                    |_| unreachable!(),
                    |_| unreachable!(),
                    |_, _, _, _| unreachable!(),
                    Some(RoutedEditHooks {
                        initial: None,
                        park: &|_| unreachable!(),
                        validate: Some(&|_, _, _| unreachable!())
                    }),
                )
                .is_err());
            edit_document(&reopened, |doc| {
                let row = doc["servers"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|row| row["id"] == id)
                    .unwrap();
                row[PENDING_ROUTED_MTU] = json!(change);
                Ok(())
            })
            .unwrap();
        }

        let successor_running = Arc::new(AtomicBool::new(false));
        let undo = |owner: &Runtime, promoted: bool| {
            let mark = if promoted {
                crate::DIRECT_SOCKET_MARK
            } else {
                0
            };
            let retiring_running = if promoted {
                &successor_running
            } else {
                &old_running
            };
            let superseded = specification(&doc, row).unwrap();
            let superseded_fingerprint: [u8; 32] =
                Sha256::digest(superseded.conf.as_bytes()).into();
            let check_restore = |row: &Value| {
                assert_eq!(row["config"].get("mtu"), original_row["config"].get("mtu"));
                assert_eq!(row["config"]["endpoint"], endpoint.to_string());
                assert_eq!(pending_routed_mtu(row).unwrap().as_ref(), Some(&change));
            };
            let park_inverse = |saved: &RoutedMtuChange| {
                assert_eq!(saved, &change);
                assert!(retiring_running.load(Ordering::SeqCst));
                let current = read(&reopened)?;
                let row = active(&current)?;
                check_restore(row);
                assert_eq!(previous_fingerprint(row)?, Some(superseded_fingerprint));
                assert_eq!(row["config"]["client"]["rust_managed"] == true, promoted);
                parked.store(true, Ordering::SeqCst);
                Ok(())
            };
            let verify = |phase, wan: bool| {
                if let EditPreparation::VerifyDirectBeforeRetiring(selected, actual_mark) = phase {
                    assert_eq!((selected, actual_mark), (endpoint, mark));
                    assert!(retiring_running.load(Ordering::SeqCst));
                    return wan
                        .then_some(())
                        .ok_or_else(|| io::ErrorKind::WouldBlock.into());
                }
                assert_eq!(crate::transport_endpoints(&reopened).unwrap(), transports);
                Ok(())
            };
            let warning = owner
                .clients
                .save_config(
                    &reopened,
                    &json!({"mtu":before}),
                    |_| unreachable!("incorrect WAN must keep the current owner"),
                    |_| unreachable!(),
                    |_, _, _, phase| verify(phase, false),
                    Some(RoutedEditHooks {
                        initial: None,
                        park: &park_inverse,
                        validate: Some(&|saved, spec, selected| {
                            assert_eq!(saved, &change);
                            assert_eq!(selected, endpoint);
                            assert_eq!(spec.conf, old_spec.conf);
                            assert_eq!(active(&read(&reopened)?)?["config"]["mtu"], after);
                            Ok(())
                        }),
                    }),
                )
                .unwrap();
            assert!(warning.is_some() && retiring_running.load(Ordering::SeqCst));

            let replay = Runtime::new(dir.path(), dir.path().join("no-engine"));
            let attached = owner.clients.0.lock().unwrap().remove(&id).unwrap();
            replay
                .clients
                .0
                .lock()
                .unwrap()
                .insert(id.clone(), attached);
            let current = read(&reopened).unwrap();
            let row = active(&current).unwrap();
            check_restore(row);
            assert_eq!(change.saved_mtu(row), Some(before));
            assert!(replay.routed_mtu_peer(&reopened, &change).is_err());
            apply_saved_edit(
                SavedEdit {
                    db: &reopened,
                    doc: &current,
                    row,
                },
                &mut replay.clients.0.lock().unwrap(),
                specification(&current, row).unwrap(),
                |_, _, _, phase| verify(phase, true),
                |spec| {
                    assert_eq!(spec.conf, old_spec.conf);
                    assert!(!retiring_running.load(Ordering::SeqCst));
                    Ok(Box::new(NativeEngine(
                        NamedEngine {
                            fingerprint: old_fingerprint,
                            endpoint,
                            running: Arc::new(AtomicBool::new(true)),
                        },
                        Arc::new(AtomicU16::new(before)),
                        true,
                    )))
                },
                Some(&park_inverse),
            )
            .unwrap();
            let current = read(&reopened).unwrap();
            let row = active(&current).unwrap();
            check_restore(row);
            assert_eq!(row["config"]["client"]["rust_managed"], true);
            let attested = replay
                .routed_mtu_peer_inner(&reopened, &change, Some(endpoint), |ip, mark| {
                    ip == endpoint && mark == crate::DIRECT_SOCKET_MARK
                })
                .unwrap()
                .unwrap();
            assert_eq!(
                (attested.endpoint, attested.effective_mtu),
                (endpoint, before)
            );
            assert_eq!(crate::transport_endpoints(&reopened).unwrap(), transports);
        };
        if operation == InheritedEdit::UndoBeforePromotion {
            undo(&runtime, false);
            return;
        }

        let resumed = Runtime::new(dir.path(), dir.path().join("no-engine"));
        let old = runtime.clients.0.lock().unwrap().remove(&id).unwrap();
        resumed.clients.0.lock().unwrap().insert(id.clone(), old);
        let measured = Arc::new(AtomicU16::new(before));
        assert_eq!(
            apply_saved_edit(
                SavedEdit {
                    db: &reopened,
                    doc: &doc,
                    row
                },
                &mut resumed.clients.0.lock().unwrap(),
                specification(&doc, row).unwrap(),
                |_, _, _, _| Ok(()),
                |spec| {
                    assert!(!old_running.load(Ordering::SeqCst));
                    assert_eq!(spec.endpoint, endpoint.to_string());
                    successor_running.store(true, Ordering::SeqCst);
                    Ok(Box::new(NativeEngine(
                        NamedEngine {
                            fingerprint: Sha256::digest(spec.conf.as_bytes()).into(),
                            endpoint,
                            running: successor_running.clone(),
                        },
                        measured.clone(),
                        true,
                    )))
                },
                Some(&|saved| {
                    assert_eq!(saved, &change);
                    assert!(old_running.load(Ordering::SeqCst));
                    parked.store(true, Ordering::SeqCst);
                    Ok(())
                }),
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(awaiting_legacy_edit(
            active(&read(&reopened).unwrap()).unwrap()
        ));

        measured.store(after, Ordering::SeqCst);
        let recover = |fail_refresh: bool| {
            let current = read(&reopened)?;
            let row = active(&current)?;
            apply_saved_edit(
                SavedEdit {
                    db: &reopened,
                    doc: &current,
                    row,
                },
                &mut resumed.clients.0.lock().unwrap(),
                specification(&current, row)?,
                |updated, _, _, _| {
                    assert!(transport_refresh_pending(active(updated)?));
                    assert_eq!(crate::transport_endpoints(&reopened)?, transports);
                    if fail_refresh {
                        Err(io::ErrorKind::TimedOut.into())
                    } else {
                        Ok(())
                    }
                },
                |_| unreachable!("the same native receipt must resume without restart"),
                Some(&|_| unreachable!("the tunnel has already been parked")),
            )
        };
        assert_eq!(recover(true).unwrap_err().kind(), io::ErrorKind::TimedOut);
        let current = read(&reopened).unwrap();
        let current_row = active(&current).unwrap();
        assert!(transport_refresh_pending(current_row));
        assert_eq!(current_row["config"]["client"]["rust_managed"], true);
        assert!(resumed.routed_mtu_peer(&reopened, &change).is_err());
        if operation == InheritedEdit::UndoAfterPromotion {
            measured.store(after + 1, Ordering::SeqCst);
            undo(&resumed, true);
            return;
        }
        recover(false).unwrap();

        let witness = |selected, wan: bool| {
            resumed.routed_mtu_peer_inner(&reopened, &change, Some(selected), |live, mark| {
                wan && live == endpoint && mark == crate::DIRECT_SOCKET_MARK
            })
        };
        assert!(witness(endpoint, false).is_err());
        assert!(witness(reserve, true).is_err());
        let attested = witness(endpoint, true).unwrap().unwrap();
        assert_eq!(
            (attested.endpoint, attested.effective_mtu),
            (endpoint, after)
        );
        measured.store(before, Ordering::SeqCst);
        assert!(witness(endpoint, true).is_err());
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum InheritedEdit {
        Forward,
        UndoBeforePromotion,
        UndoAfterPromotion,
    }

    struct InheritedEngine {
        fingerprint: [u8; 32],
        proof: RoutedLegacyPredecessor,
        mtu: u16,
        running: Arc<AtomicBool>,
        parked: Arc<AtomicBool>,
    }
    impl Tunnel for InheritedEngine {
        fn inherited(&self) -> bool {
            true
        }
        fn alive(&mut self) -> bool {
            self.running.load(Ordering::SeqCst)
        }
        fn stop(&mut self) -> io::Result<()> {
            assert!(self.parked.load(Ordering::SeqCst));
            assert!(self.running.swap(false, Ordering::SeqCst));
            Ok(())
        }
        fn probe(&mut self) -> io::Result<()> {
            unreachable!()
        }
        fn snapshot(&self) -> io::Result<Value> {
            let running = self.running.load(Ordering::SeqCst);
            Ok(json!({"running":running, "connected":running, "endpoint":self.proof.endpoint}))
        }
        fn verified_legacy_predecessor(
            &self,
            spec: &Spec,
            endpoint: SocketAddr,
            mtu: u16,
            _: bool,
        ) -> io::Result<RoutedLegacyPredecessor> {
            assert!(self.running.load(Ordering::SeqCst));
            assert_eq!(
                self.fingerprint,
                <[u8; 32]>::from(Sha256::digest(spec.conf.as_bytes()))
            );
            assert_eq!(endpoint, self.proof.endpoint);
            assert_eq!(mtu, self.mtu);
            Ok(self.proof.clone())
        }
    }
    struct NativeEngine(NamedEngine, Arc<AtomicU16>, bool);
    impl Tunnel for NativeEngine {
        fn alive(&mut self) -> bool {
            self.0.alive()
        }
        fn stop(&mut self) -> io::Result<()> {
            self.0.stop()
        }
        fn probe(&mut self) -> io::Result<()> {
            unreachable!()
        }
        fn snapshot(&self) -> io::Result<Value> {
            unreachable!()
        }
        fn verified_routed_mtu(
            &self,
            spec: &Spec,
            outer: Option<&NestedOuter>,
            connected: bool,
        ) -> io::Result<RoutedMtuSample> {
            if connected && !self.2 {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let mut sample = self.0.verified_routed_mtu(spec, outer, connected)?;
            sample.socket_mark = crate::DIRECT_SOCKET_MARK;
            sample.effective_mtu = self.1.load(Ordering::SeqCst);
            sample.connected = self.2;
            Ok(sample)
        }
    }

    fn routed_inherited_endpoint_edit(
        before: &str,
        after: &str,
        operation: InheritedEdit,
        mtu_edit: Option<(u16, Option<RoutedImplicitMtu>)>,
    ) {
        routed_inherited_endpoint_edit_at(
            before,
            before.parse().unwrap(),
            after,
            operation,
            mtu_edit,
            None,
        );
    }

    fn routed_inherited_endpoint_edit_at(
        before_raw: &str,
        before: SocketAddr,
        after_raw: &str,
        operation: InheritedEdit,
        mtu_edit: Option<(u16, Option<RoutedImplicitMtu>)>,
        resolved_after: Option<&[SocketAddr]>,
    ) {
        let reverse = operation == InheritedEdit::UndoBeforePromotion;
        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        let runtime = Runtime::new(dir.path(), dir.path().join("no-engine"));
        crate::import(&db, &crate::tests::input(), "inherited").unwrap();
        let id = s(active(&read(&db).unwrap()).unwrap(), "id").to_owned();
        let after: SocketAddr = resolved_after.map_or_else(
            || after_raw.parse().unwrap(),
            |addresses| selected_named_address(after_raw, addresses).unwrap(),
        );
        let named = hostname_port(before_raw).is_some();
        let implicit_mtu = mtu_edit.and_then(|(_, raw)| raw);
        let before_mtu = if implicit_mtu.is_some() { 1388 } else { 1420 };
        let after_mtu = mtu_edit.map_or(before_mtu, |(mtu, _)| mtu);
        let input = |endpoint: &str, mtu| {
            if mtu_edit.is_some() {
                json!({"endpoint":endpoint,"mtu":mtu})
            } else {
                json!({"endpoint":endpoint})
            }
        };
        let proof = RoutedLegacyPredecessor {
            receipt_sha256: [21; 32],
            endpoint: before,
        };
        edit_document(&db, |doc| {
            doc["routing_revision"] = json!(7);
            doc["rust_static_routing"] = json!({"revision":7,"pending_commit":false,"targets":[id],"committed_targets":[id]});
            let row = doc["servers"].as_array_mut().unwrap().iter_mut().find(|row| row["id"] == id).unwrap();
            row["config"]["endpoint"] = json!(before_raw);
            row["config"]["enabled"] = json!(true);
            row["config"]["client"]["enabled"] = json!(true);
            row["config"]["client"].as_object_mut().unwrap().remove("rust_managed");
            if let Some(raw) = implicit_mtu {
                raw.write(row["config"].as_object_mut().unwrap());
                row["config"]["routing"]["mtu"] = json!(before_mtu);
            }
            Ok(())
        }).unwrap();
        let original = read(&db).unwrap();
        let original_row = active(&original).unwrap();
        let old = specification(&original, original_row).unwrap();
        let running = Arc::new(AtomicBool::new(true));
        let parked = Arc::new(AtomicBool::new(false));
        let adopt = |spec: &Spec| -> io::Result<Option<Box<dyn Tunnel>>> {
            assert_eq!(spec.endpoint, before_raw);
            assert_eq!(spec.conf, old.conf);
            Ok(Some(Box::new(InheritedEngine {
                fingerprint: Sha256::digest(spec.conf.as_bytes()).into(),
                proof: proof.clone(),
                mtu: before_mtu,
                running: running.clone(),
                parked: parked.clone(),
            })))
        };
        let mut prepared = resolved_after.map(|addresses| {
            let prepare = |selected_name: &str, answers: &[SocketAddr]| {
                prepare_routed_endpoint_edit_with(
                    &db,
                    &input(selected_name, after_mtu),
                    |raw, deadline, fresh| {
                        assert_eq!(raw, selected_name);
                        assert!(fresh && deadline > Instant::now());
                        Ok(answers.to_vec())
                    },
                    |_| unreachable!("old numeric endpoint needs no named observation"),
                )
            };
            let ticket = prepare(after_raw, addresses).unwrap().unwrap();
            assert_eq!(ticket.resolved_after, addresses);
            ticket
        });
        let stage = |old_wan: bool, accept: bool, prepared: Option<&PreparedRoutedEndpointEdit>| {
            runtime.clients.save_config(
                &db,
                &input(after_raw, after_mtu),
                |_| unreachable!("cannot start before park"),
                |_| unreachable!(),
                |_, _, _, _| Ok(()),
                Some(RoutedEditHooks {
                    validate: None,
                    park: &|_| Err(io::ErrorKind::TimedOut.into()),
                    initial: Some(InitialRoutedEditHooks {
                        choose: &|change, _, selected| {
                            assert!(old_wan);
                            assert_eq!(change.legacy_predecessor.as_ref(), Some(&proof));
                            assert_eq!(selected, after);
                            assert_eq!((change.before, change.after), (before_mtu, after_mtu));
                            if named {
                                assert_eq!(
                                    change.endpoint_edit.as_ref().unwrap().resolved_before,
                                    [before]
                                );
                            }
                            if let Some(addresses) = resolved_after {
                                assert_eq!(
                                    change.endpoint_edit.as_ref().unwrap().resolved_after,
                                    addresses
                                );
                            }
                            assert!(active(&read(&db)?)?.get(PENDING_PROFILE).is_none());
                            if accept {
                                Ok(RoutedEndpointLaunch::Primary)
                            } else {
                                Err(io::ErrorKind::WouldBlock.into())
                            }
                        },
                        prepare: &|_, _| unreachable!(),
                        can_wait: false,
                        prepared,
                        verify_previous: &|endpoint, mark| {
                            old_wan && endpoint == before && mark == 0
                        },
                        adopt_legacy: Some(&adopt),
                    }),
                }),
            )
        };
        if let Some(ticket) = &mut prepared {
            assert!(stage(true, true, None).is_err());
            ticket.revision += 1;
            assert_eq!(
                stage(true, true, Some(ticket)).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            ticket.revision -= 1;
            assert_eq!(read(&db).unwrap(), original);
        }
        assert_eq!(
            stage(false, true, prepared.as_ref()).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            stage(true, false, prepared.as_ref()).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(runtime.clients.0.lock().unwrap().is_empty());
        assert!(running.load(Ordering::SeqCst));
        if named {
            assert!(runtime
                .prepare_routed_endpoint_edit(&db, &input(after_raw, after_mtu))
                .unwrap()
                .is_none());
            let mut same_ip_reserve = before;
            same_ip_reserve.set_port(before.port() + 1);
            let set_test_backups = |backups: Value| {
                edit_document(&db, |doc| {
                    let row = doc["servers"]
                        .as_array_mut()
                        .unwrap()
                        .iter_mut()
                        .find(|row| row["id"] == id)
                        .unwrap();
                    row["config"]["client"]["endpoint_backups"] = backups.clone();
                    Ok(())
                })
                .unwrap();
            };
            for (backup, error) in [
                (same_ip_reserve.to_string(), io::ErrorKind::WouldBlock),
                (
                    "unresolved.example:2408".to_owned(),
                    io::ErrorKind::InvalidInput,
                ),
            ] {
                set_test_backups(json!([backup]));
                assert_eq!(
                    stage(true, true, prepared.as_ref()).unwrap_err().kind(),
                    error
                );
                assert!(pending_routed_mtu(active(&read(&db).unwrap()).unwrap())
                    .unwrap()
                    .is_none());
            }
            set_test_backups(json!([]));
        }
        assert!(stage(true, true, prepared.as_ref()).unwrap().is_some());
        let db = Store::open(dir.path()).unwrap();
        if named || resolved_after.is_some() {
            assert!(runtime
                .prepare_routed_endpoint_edit(&db, &input(before_raw, before_mtu))
                .unwrap()
                .is_none());
        }
        if named {
            let mut same_ip_reserve = before;
            same_ip_reserve.set_port(before.port() + 1);
            assert_eq!(
                runtime
                    .set_backups(&db, &id, &[same_ip_reserve.to_string()], &[])
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::WouldBlock
            );
            runtime
                .set_backups(&db, &id, &["203.0.113.29:443".into()], &[])
                .unwrap();
            assert!(running.load(Ordering::SeqCst));
        }
        let doc = read(&db).unwrap();
        let row = active(&doc).unwrap();
        if let Some(addresses) = resolved_after {
            assert_eq!(
                routed_hostname_addresses(&doc, row).unwrap().as_deref(),
                Some(addresses)
            );
            let transports = crate::transport_endpoints(&db).unwrap();
            assert!(addresses
                .iter()
                .all(|endpoint| transports.contains(endpoint)));
        }
        assert!(awaiting_legacy_edit(row));
        assert!(!transport_refresh_pending(row));
        assert!(running.load(Ordering::SeqCst));
        let change = pending_routed_mtu(row).unwrap().unwrap();
        assert_eq!(change.legacy_predecessor.as_ref(), Some(&proof));
        assert_eq!(change.implicit_before_mtu, implicit_mtu);
        assert_eq!(
            legacy_predecessor_spec(&doc, row, &change).unwrap().conf,
            old.conf
        );
        if mtu_edit.is_some() {
            for partial in [json!({"endpoint":before}), json!({"mtu":before_mtu})] {
                assert!(runtime
                    .clients
                    .save_config(
                        &db,
                        &partial,
                        |_| unreachable!(),
                        |_| unreachable!(),
                        |_, _, _, _| unreachable!(),
                        Some(RoutedEditHooks {
                            initial: None,
                            park: &|_| unreachable!(),
                            validate: Some(&|_, _, _| unreachable!())
                        }),
                    )
                    .is_err());
            }
        }
        assert!(!routed_endpoint_initial_pending(row).unwrap());
        let mut mixed = change.clone();
        mixed.endpoint_edit.as_mut().unwrap().after = if before.is_ipv4() {
            "[2001:db8::2]:2408"
        } else {
            "192.0.2.2:2408"
        }
        .into();
        let mut mixed_row = row.clone();
        mixed_row["config"]["endpoint"] = json!(mixed.endpoint_edit.as_ref().unwrap().after);
        assert!(!routed_legacy_edit_profile(&mixed_row, &mixed));
        mixed.endpoint_edit.as_mut().unwrap().after = if before.is_ipv4() {
            "[::ffff:192.0.2.87]:2408"
        } else {
            "[2001:0db8:0:0:0:0:0:87]:2408"
        }
        .into();
        if named {
            mixed_row["config"]["endpoint"] = json!(mixed.endpoint_edit.as_ref().unwrap().after);
            assert!(routed_legacy_edit_profile(&mixed_row, &mixed));
        } else {
            assert!(mixed.endpoint_edit.as_ref().unwrap().sockets().is_err());
        }
        assert!(runtime
            .routed_mtu_peer_inner(&db, &change, Some(after), |_, _| true)
            .is_err());
        let endpoints = crate::transport_endpoints(&db).unwrap();
        for selected in [before, after] {
            assert_eq!(
                endpoints
                    .iter()
                    .filter(|&&endpoint| endpoint == selected)
                    .count(),
                1
            );
        }

        // Emulate re-opening the same exact Go receipt after a pre-park interruption.
        let replay = Runtime::new(dir.path(), dir.path().join("no-engine"));
        let managed = runtime.clients.0.lock().unwrap().remove(&id).unwrap();
        replay.clients.0.lock().unwrap().insert(id.clone(), managed);
        let selected = if reverse { before } else { after };
        let selected_raw = if reverse { before_raw } else { after_raw };
        let retiring = if reverse { after } else { before };
        let selected_mtu = if reverse { before_mtu } else { after_mtu };
        let prune = |doc: &Value, _: &HashMap<String, Managed>, _: &mut Spec, _| {
            let current = active(doc)?;
            let ports = crate::transport_endpoints(&db)?;
            assert!(ports.contains(&selected));
            if transport_refresh_pending(current) {
                assert_eq!(current["config"]["client"]["rust_managed"], true);
                assert_eq!(ports.contains(&retiring), retiring == selected);
                return Err(io::ErrorKind::TimedOut.into());
            }
            assert!(ports.contains(&retiring));
            assert!(current["config"]["client"].get("rust_managed").is_none());
            Ok(())
        };
        let park = |saved: &RoutedMtuChange| {
            assert_eq!(saved, &change);
            assert!(awaiting_legacy_edit(active(&read(&db)?)?));
            parked.store(true, Ordering::SeqCst);
            Ok(())
        };
        let successor_running = Arc::new(AtomicBool::new(true));
        let successor_mtu = Arc::new(AtomicU16::new(selected_mtu));
        let start = |spec: Spec| -> io::Result<Box<dyn Tunnel>> {
            assert!(parked.load(Ordering::SeqCst));
            assert!(!running.load(Ordering::SeqCst));
            assert_eq!(spec.endpoint, selected.to_string());
            let parsed = conf::parse(&spec.conf, 0)?;
            assert_eq!(parsed["endpoint"], selected_raw);
            assert_eq!(parsed["mtu"], selected_mtu);
            assert_eq!(spec.conf == old.conf, reverse);
            assert!(active(&read(&db)?)?["config"]["client"]
                .get("rust_managed")
                .is_none());
            Ok(Box::new(NativeEngine(
                NamedEngine {
                    fingerprint: Sha256::digest(spec.conf.as_bytes()).into(),
                    endpoint: selected,
                    running: successor_running.clone(),
                },
                successor_mtu.clone(),
                true,
            )))
        };
        if reverse {
            assert!(replay
                .clients
                .save_config(
                    &db,
                    &input(before_raw, before_mtu),
                    start,
                    |_| unreachable!(),
                    prune,
                    Some(RoutedEditHooks {
                        initial: None,
                        park: &park,
                        validate: Some(&|saved, _, endpoint| {
                            assert_eq!(saved, &change);
                            assert_eq!(endpoint, before);
                            Ok(())
                        })
                    }),
                )
                .unwrap()
                .is_some());
        } else {
            assert_eq!(
                apply_saved_edit(
                    SavedEdit {
                        db: &db,
                        doc: &doc,
                        row
                    },
                    &mut replay.clients.0.lock().unwrap(),
                    specification(&doc, row).unwrap(),
                    prune,
                    start,
                    Some(&park),
                )
                .unwrap_err()
                .kind(),
                io::ErrorKind::TimedOut
            );
        }
        let doc = read(&db).unwrap();
        let row = active(&doc).unwrap();
        assert_eq!(row["config"]["endpoint"], selected_raw);
        assert!(transport_refresh_pending(row));
        assert_eq!(row["config"]["client"]["rust_managed"], true);
        assert!(replay
            .routed_mtu_peer_inner(&db, &change, Some(selected), |_, _| true)
            .is_err());
        let (owner, selected) = if operation == InheritedEdit::UndoAfterPromotion {
            // The native owner survives a panel interruption before the retiring UDP tuple is removed.
            let resumed = Runtime::new(dir.path(), dir.path().join("no-engine"));
            let native = replay.clients.0.lock().unwrap().remove(&id).unwrap();
            resumed.clients.0.lock().unwrap().insert(id.clone(), native);
            if mtu_edit.is_some() {
                successor_mtu.store(after_mtu + 1, Ordering::SeqCst);
            }
            let parked_inverse = AtomicBool::new(false);
            let undo = resumed
                .clients
                .save_config(
                    &db,
                    &input(before_raw, before_mtu),
                    |spec| {
                        assert!(parked_inverse.load(Ordering::SeqCst));
                        assert!(!successor_running.load(Ordering::SeqCst));
                        assert_eq!(spec.endpoint, before.to_string());
                        assert_eq!(spec.conf, old.conf);
                        assert_eq!(
                            active(&read(&db)?)?["config"]["client"]["rust_managed"],
                            true
                        );
                        Ok(Box::new(NativeEngine(
                            NamedEngine {
                                fingerprint: Sha256::digest(spec.conf.as_bytes()).into(),
                                endpoint: before,
                                running: Arc::new(AtomicBool::new(true)),
                            },
                            Arc::new(AtomicU16::new(before_mtu)),
                            true,
                        )))
                    },
                    |_| unreachable!(),
                    |doc, _, _, _| {
                        let current = active(doc)?;
                        let endpoints = crate::transport_endpoints(&db)?;
                        assert!(endpoints.contains(&before));
                        assert_eq!(
                            endpoints.contains(&after),
                            before == after || !transport_refresh_pending(current)
                        );
                        Ok(())
                    },
                    Some(RoutedEditHooks {
                        initial: None,
                        park: &|saved| {
                            let doc = read(&db)?;
                            let current = active(&doc)?;
                            assert!(successor_running.load(Ordering::SeqCst));
                            assert_eq!(current["config"]["endpoint"], before_raw);
                            assert_eq!(pending_routed_mtu(current)?.as_ref(), Some(saved));
                            assert_eq!(saved.legacy_predecessor.as_ref(), Some(&proof));
                            parked_inverse.store(true, Ordering::SeqCst);
                            Ok(())
                        },
                        validate: Some(&|saved, _, endpoint| {
                            assert_eq!(saved, &change);
                            assert_eq!(endpoint, before);
                            Ok(())
                        }),
                    }),
                )
                .unwrap();
            assert!(undo.is_none());
            (resumed, before)
        } else {
            apply_saved_edit(
                SavedEdit {
                    db: &db,
                    doc: &doc,
                    row,
                },
                &mut replay.clients.0.lock().unwrap(),
                specification(&doc, row).unwrap(),
                |_, _, _, _| Ok(()),
                |_| unreachable!("verified native receipt already owns the interface"),
                Some(&|saved| {
                    assert!(reverse);
                    assert_eq!(saved, &change);
                    assert!(transport_refresh_pending(active(&read(&db)?)?));
                    Ok(())
                }),
            )
            .unwrap();
            (replay, selected)
        };
        if before == after {
            let doc = read(&db).unwrap();
            let row = active(&doc).unwrap();
            let selection = change.endpoint_selection(row).unwrap();
            let stale = superseded_routed_spec(&doc, row, &change, selection.as_ref()).unwrap();
            let stale_fingerprint = Sha256::digest(stale.conf.as_bytes()).into();
            let mut owned = owner.clients.0.lock().unwrap();
            let current = &mut owned.get_mut(&id).unwrap().fingerprint;
            assert_ne!(*current, stale_fingerprint);
            let valid_fingerprint = std::mem::replace(current, stale_fingerprint);
            drop(owned);
            assert!(owner
                .routed_mtu_peer_inner(&db, &change, Some(selected), |_, _| true)
                .is_err());
            owner
                .clients
                .0
                .lock()
                .unwrap()
                .get_mut(&id)
                .unwrap()
                .fingerprint = valid_fingerprint;
        }
        assert!(owner
            .routed_mtu_peer_inner(&db, &change, Some(selected), |_, _| false)
            .is_err());
        let attested = owner
            .routed_mtu_peer_inner(&db, &change, Some(selected), |endpoint, mark| {
                endpoint == selected && mark == crate::DIRECT_SOCKET_MARK
            })
            .unwrap()
            .unwrap();
        assert_eq!(attested.endpoint, selected);
        let current = read(&db).unwrap();
        let row = active(&current).unwrap();
        let restored = operation != InheritedEdit::Forward;
        assert_eq!(
            row["config"]["endpoint"],
            if restored { before_raw } else { after_raw }
        );
        assert_eq!(
            attested.effective_mtu,
            if restored { before_mtu } else { after_mtu }
        );
        if restored {
            assert_eq!(row["config"].get("mtu"), original_row["config"].get("mtu"));
        }
        assert_eq!(
            pending_routed_mtu(active(&read(&db).unwrap()).unwrap())
                .unwrap()
                .as_ref(),
            Some(&change)
        );
    }

    #[test]
    fn routed_hostname_alias_replays_saved_answers_and_undoes_by_raw_endpoint() {
        routed_hostname_alias(false);
    }

    #[test]
    fn routed_two_hostname_aliases_change_generation_and_undo_without_lookup() {
        routed_hostname_alias(true);
    }

    fn routed_hostname_alias(retiring_name: bool) {
        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        let rt = Runtime::new(dir.path(), dir.path().join("no-engine"));
        crate::import(&db, &crate::tests::input(), "imported").unwrap();
        let before: SocketAddr = "192.0.2.51:2408".parse().unwrap();
        let before_raw = if retiring_name {
            "Previous.Example.:2408".to_owned()
        } else {
            before.to_string()
        };
        let name = "VPN.Example.:2408";
        let aaaa: SocketAddr = "[2001:db8::51]:2408".parse().unwrap();
        let secondary: SocketAddr = "192.0.2.52:2408".parse().unwrap();
        let id = s(active(&read(&db).unwrap()).unwrap(), "id").to_owned();
        edit_document(&db, |doc| {
            let row = doc["servers"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|row| row["id"] == id)
                .unwrap();
            row["config"]["endpoint"] = json!(before_raw);
            Ok(())
        })
        .unwrap();
        let old_running = Arc::new(AtomicBool::new(true));
        rt.clients
            .up(&db, Some(&id), |spec| {
                Ok(Box::new(NamedEngine {
                    fingerprint: Sha256::digest(spec.conf.as_bytes()).into(),
                    endpoint: before,
                    running: old_running.clone(),
                }))
            })
            .unwrap();
        let revision = |rev| {
            edit_document(&db, |doc| {
                doc["routing_revision"] = json!(rev);
                doc["rust_static_routing"] = json!({"revision":rev,"pending_commit":false,"targets":[id],"committed_targets":[id]});
                Ok(())
            })
        };
        revision(9).unwrap();
        let input = json!({"endpoint":name});
        let prepared = prepare_routed_endpoint_edit_with(
            &db,
            &input,
            |raw, _, previous| {
                assert!(!previous);
                assert_eq!(raw, name);
                assert!(rt.clients.0.try_lock().is_ok());
                db.try_transaction(|_| Ok(()))?;
                Ok(vec![aaaa, before, secondary, before])
            },
            |_| unreachable!(),
        )
        .unwrap()
        .unwrap();
        let expected_edit = RoutedEndpointEdit {
            before: before_raw.clone(),
            after: name.into(),
            resolved_before: if retiring_name {
                vec![before]
            } else {
                Vec::new()
            },
            resolved_after: vec![aaaa, before, secondary],
            previous_reserve: None,
        };
        assert_eq!(expected_edit.sockets().unwrap(), (before, before));
        assert_eq!(prepared.resolved_after, expected_edit.resolved_after);
        revision(10).unwrap();
        assert!(rt
            .save_config_with_prepared_routed_endpoint(
                &db,
                &input,
                &[],
                Some(&prepared),
                |_| unreachable!(),
                (
                    |_: &RoutedMtuChange| unreachable!("prepared revision changed"),
                    |_: &RoutedMtuChange, _| unreachable!(),
                ),
            )
            .is_err());
        revision(9).unwrap();

        let running = Arc::new(AtomicBool::new(true));
        let report = rt
            .clients
            .save_config(
                &db,
                &input,
                |spec| {
                    assert!(!old_running.load(Ordering::SeqCst));
                    assert_eq!(spec.endpoint, before.to_string());
                    assert!(spec
                        .conf
                        .lines()
                        .any(|line| line == format!("Endpoint = {name}")));
                    let fingerprint = Sha256::digest(spec.conf.as_bytes()).into();
                    assert_ne!(prepared.previous, fingerprint);
                    Ok(Box::new(NamedEngine {
                        fingerprint,
                        endpoint: before,
                        running: running.clone(),
                    }))
                },
                |_| unreachable!(),
                |doc, _, _, _| {
                    let row = active(doc)?;
                    assert_eq!(
                        routed_hostname_addresses(doc, row)?.unwrap(),
                        [aaaa, before, secondary]
                    );
                    if transport_refresh_pending(row) {
                        return Err(io::ErrorKind::TimedOut.into());
                    }
                    assert_eq!(previous_fingerprint(row)?, Some(prepared.previous));
                    assert!(old_running.load(Ordering::SeqCst));
                    Ok(())
                },
                Some(RoutedEditHooks {
                    validate: None,
                    park: &|_| {
                        assert!(old_running.load(Ordering::SeqCst));
                        Ok(())
                    },
                    initial: Some(InitialRoutedEditHooks {
                        choose: &|change, _, selected| {
                            assert_eq!(change.endpoint_edit.as_ref(), Some(&expected_edit));
                            assert_eq!(selected, before);
                            Ok(RoutedEndpointLaunch::Primary)
                        },
                        prepare: &|_, _| unreachable!("named endpoint has one selected primary"),
                        can_wait: true,
                        prepared: Some(&prepared),
                        verify_previous: &|endpoint, mark| {
                            assert!(retiring_name);
                            endpoint == before && mark == 0
                        },
                        adopt_legacy: None,
                    }),
                }),
            )
            .unwrap();
        assert!(report.is_some());
        let db = Store::open(dir.path()).unwrap();
        let doc = read(&db).unwrap();
        let row = active(&doc).unwrap();
        let change = pending_routed_mtu(row).unwrap().unwrap();
        assert!(transport_refresh_pending(row));
        assert_eq!(row["config"]["endpoint"], name);
        assert!(rt.routed_mtu_peer(&db, &change).is_err());

        let recovered = Runtime::new(dir.path(), dir.path().join("no-engine"));
        let mut prior = rt.clients.0.lock().unwrap().remove(&id).unwrap();
        prior.recovery = Default::default();
        recovered
            .clients
            .0
            .lock()
            .unwrap()
            .insert(id.clone(), prior);
        recovered
            .recover_saved_edits(
                &db,
                &[],
                Some(&|proof| {
                    assert_eq!(proof.endpoint, before);
                    let all = crate::transport_endpoints(&db)?;
                    assert!(all.contains(&secondary) && all.contains(&aaaa));
                    Ok(())
                }),
                Some(&|_| unreachable!("the exact same native owner already launched")),
                Some(RoutedRetryHooks {
                    read: &|_| unreachable!("replay uses the admitted named pin"),
                    prepare: &|_, _| unreachable!(),
                }),
            )
            .unwrap();
        assert_eq!(
            recovered
                .routed_mtu_peer(&db, &change)
                .unwrap()
                .unwrap()
                .endpoint,
            before
        );
        let new_fingerprint = {
            let mut owned = recovered.clients.0.lock().unwrap();
            std::mem::replace(
                &mut owned.get_mut(&id).unwrap().fingerprint,
                prepared.previous,
            )
        };
        assert!(recovered.routed_mtu_peer(&db, &change).is_err());
        recovered
            .clients
            .0
            .lock()
            .unwrap()
            .get_mut(&id)
            .unwrap()
            .fingerprint = new_fingerprint;

        let undo = json!({"endpoint":before_raw});
        assert!(prepare_routed_endpoint_edit_with(
            &db,
            &undo,
            |_, _, _| unreachable!(),
            |_| unreachable!()
        )
        .unwrap()
        .is_none());
        let report = recovered
            .clients
            .save_config(
                &db,
                &undo,
                |spec| {
                    assert!(!running.load(Ordering::SeqCst));
                    let fingerprint = Sha256::digest(spec.conf.as_bytes()).into();
                    assert_eq!(prepared.previous, fingerprint);
                    Ok(Box::new(NamedEngine {
                        fingerprint,
                        endpoint: before,
                        running: Arc::new(AtomicBool::new(true)),
                    }))
                },
                |_| unreachable!(),
                |doc, _, spec, _| {
                    assert_eq!(spec.endpoint, before.to_string());
                    assert_eq!(active(doc)?["config"]["endpoint"], before_raw);
                    assert_eq!(
                        routed_hostname_addresses(doc, active(doc)?)?,
                        retiring_name.then_some(vec![before])
                    );
                    Ok(())
                },
                Some(RoutedEditHooks {
                    validate: Some(&|same, _, selected| {
                        assert_eq!(same, &change);
                        assert_eq!(selected, before);
                        assert!(running.load(Ordering::SeqCst));
                        Ok(())
                    }),
                    park: &|same| {
                        assert_eq!(same, &change);
                        Ok(())
                    },
                    initial: None,
                }),
            )
            .unwrap();
        assert!(report.is_none());
        assert_eq!(
            recovered
                .routed_mtu_peer(&db, &change)
                .unwrap()
                .unwrap()
                .endpoint,
            before
        );
    }

    #[test]
    fn routed_named_predecessor_uses_owned_ipv6_tuple_for_undo_without_dns() {
        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        let rt = Runtime::new(dir.path(), dir.path().join("no-engine"));
        crate::import(&db, &crate::tests::input(), "imported").unwrap();
        let name = "Previously.Named.:2408";
        let previous: SocketAddr = "[2001:db8::57]:2408".parse().unwrap();
        let replacement: SocketAddr = "192.0.2.57:2408".parse().unwrap();
        let reserve: SocketAddr = "192.0.2.58:2408".parse().unwrap();
        let id = s(active(&read(&db).unwrap()).unwrap(), "id").to_owned();
        let update = |f: &dyn Fn(&mut Value)| {
            edit_document(&db, |doc| {
                let row = doc["servers"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|row| row["id"] == id)
                    .unwrap();
                f(row);
                Ok(())
            })
        };
        update(&|row| row["config"]["endpoint"] = json!(name)).unwrap();
        let old_running = Arc::new(AtomicBool::new(true));
        rt.clients
            .up(&db, Some(&id), |spec| {
                Ok(Box::new(NamedEngine {
                    fingerprint: Sha256::digest(spec.conf.as_bytes()).into(),
                    endpoint: previous,
                    running: old_running.clone(),
                }))
            })
            .unwrap();
        let old_hash = rt.clients.0.lock().unwrap()[&id].fingerprint;
        edit_document(&db, |doc| {
            doc["routing_revision"] = json!(13);
            doc["rust_static_routing"] = json!({"revision":13,"pending_commit":false,"targets":[id],"committed_targets":[id]});
            Ok(())
        }).unwrap();
        let input = json!({"endpoint":replacement});
        assert!(prepare_routed_endpoint_edit_with(
            &db,
            &input,
            |_, _, _| unreachable!("the live named owner is the old address evidence"),
            |_| unreachable!()
        )
        .unwrap()
        .is_none());
        for (backups, wan, decision) in [
            (json!([previous]), true, RoutedEndpointLaunch::Primary),
            (json!([reserve]), false, RoutedEndpointLaunch::Primary),
            (
                json!([reserve]),
                true,
                RoutedEndpointLaunch::Alternate(reserve),
            ),
            (json!([reserve]), true, RoutedEndpointLaunch::Waiting),
        ] {
            update(&|row| row["config"]["client"]["endpoint_backups"] = backups.clone()).unwrap();
            assert!(rt
                .clients
                .save_config(
                    &db,
                    &input,
                    |_| unreachable!(),
                    |_| unreachable!(),
                    |_, _, _, _| unreachable!(),
                    Some(RoutedEditHooks {
                        validate: None,
                        park: &|_| unreachable!(),
                        initial: Some(InitialRoutedEditHooks {
                            choose: &|_, _, _| Ok(decision),
                            prepare: &|_, _| unreachable!(),
                            can_wait: true,
                            prepared: None,
                            verify_previous: &|endpoint, mark| wan
                                && endpoint == previous
                                && mark == 0,
                            adopt_legacy: None,
                        }),
                    }),
                )
                .is_err());
            assert_eq!(
                active(&read(&db).unwrap()).unwrap()["config"]["endpoint"],
                name
            );
            assert!(old_running.load(Ordering::SeqCst));
        }

        let new_running = Arc::new(AtomicBool::new(true));
        let report = rt
            .clients
            .save_config(
                &db,
                &input,
                |spec| {
                    assert!(!old_running.load(Ordering::SeqCst));
                    assert_eq!(spec.endpoint, replacement.to_string());
                    Ok(Box::new(NamedEngine {
                        fingerprint: Sha256::digest(spec.conf.as_bytes()).into(),
                        endpoint: replacement,
                        running: new_running.clone(),
                    }))
                },
                |_| unreachable!(),
                |doc, _, _, _| {
                    let row = active(doc)?;
                    let all = crate::transport_endpoints(&db)?;
                    if transport_refresh_pending(row) {
                        assert!(!all.contains(&previous));
                        return Err(io::ErrorKind::TimedOut.into());
                    }
                    assert!(all.contains(&previous) && all.contains(&replacement));
                    assert_eq!(previous_fingerprint(row)?, Some(old_hash));
                    Ok(())
                },
                Some(RoutedEditHooks {
                    validate: None,
                    park: &|_| {
                        assert!(old_running.load(Ordering::SeqCst));
                        Ok(())
                    },
                    initial: Some(InitialRoutedEditHooks {
                        choose: &|change, _, selected| {
                            let edit = change.endpoint_edit.as_ref().unwrap();
                            assert_eq!(edit.before, name);
                            assert_eq!(edit.resolved_before, [previous]);
                            assert_eq!(selected, replacement);
                            Ok(RoutedEndpointLaunch::Primary)
                        },
                        prepare: &|_, _| unreachable!(),
                        can_wait: true,
                        prepared: None,
                        verify_previous: &|endpoint, mark| endpoint == previous && mark == 0,
                        adopt_legacy: None,
                    }),
                }),
            )
            .unwrap();
        assert!(report.is_some());
        let db = Store::open(dir.path()).unwrap();
        let doc = read(&db).unwrap();
        let edit = pending_routed_mtu(active(&doc).unwrap()).unwrap().unwrap();
        assert!(!routed_endpoint_initial_pending(active(&doc).unwrap()).unwrap());
        assert!(routed_endpoint_retry_pool(active(&doc).unwrap(), &edit)
            .unwrap()
            .is_empty());
        let recovered = Runtime::new(dir.path(), dir.path().join("no-engine"));
        let mut owner = rt.clients.0.lock().unwrap().remove(&id).unwrap();
        owner.recovery = Default::default();
        recovered.clients.0.lock().unwrap().insert(id, owner);
        recovered
            .recover_saved_edits(
                &db,
                &[],
                Some(&|proof| {
                    assert_eq!(proof.endpoint, replacement);
                    Ok(())
                }),
                Some(&|_| unreachable!("the same successor is still active")),
                Some(RoutedRetryHooks {
                    read: &|_| {
                        unreachable!("a hostname transaction cannot fall into ordinary retry")
                    },
                    prepare: &|_, _| unreachable!(),
                }),
            )
            .unwrap();
        assert_eq!(
            recovered
                .routed_mtu_peer(&db, &edit)
                .unwrap()
                .unwrap()
                .endpoint,
            replacement
        );

        let undo = json!({"endpoint":name});
        assert!(prepare_routed_endpoint_edit_with(
            &db,
            &undo,
            |_, _, _| unreachable!(),
            |_| unreachable!()
        )
        .unwrap()
        .is_none());
        let report = recovered
            .clients
            .save_config(
                &db,
                &undo,
                |spec| {
                    assert!(!new_running.load(Ordering::SeqCst));
                    assert_eq!(spec.endpoint, previous.to_string());
                    let fingerprint = Sha256::digest(spec.conf.as_bytes()).into();
                    assert_eq!(old_hash, fingerprint);
                    Ok(Box::new(NamedEngine {
                        fingerprint,
                        endpoint: previous,
                        running: Arc::new(AtomicBool::new(true)),
                    }))
                },
                |_| unreachable!(),
                |doc, _, spec, _| {
                    let row = active(doc)?;
                    assert_eq!(spec.endpoint, previous.to_string());
                    assert_eq!(routed_hostname_addresses(doc, row)?.unwrap(), [previous]);
                    let all = crate::transport_endpoints(&db)?;
                    assert!(all.contains(&previous));
                    assert_eq!(all.contains(&replacement), !transport_refresh_pending(row));
                    Ok(())
                },
                Some(RoutedEditHooks {
                    validate: Some(&|same, _, selected| {
                        assert_eq!(same, &edit);
                        assert_eq!(selected, previous);
                        Ok(())
                    }),
                    park: &|_| Ok(()),
                    initial: None,
                }),
            )
            .unwrap();
        assert!(report.is_none());
        assert_eq!(
            recovered
                .routed_mtu_peer(&db, &edit)
                .unwrap()
                .unwrap()
                .endpoint,
            previous
        );
    }

    #[test]
    fn routed_named_previous_reserve_restores_its_different_port_without_lookup() {
        routed_named_previous_reserve(4433);
    }

    #[test]
    fn routed_named_previous_reserve_same_port_needs_unambiguous_dns_claims() {
        routed_named_previous_reserve(2408);
    }

    fn routed_named_previous_reserve(port: u16) {
        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        let runtime = Runtime::new(dir.path(), dir.path().join("no-engine"));
        crate::import(&db, &crate::tests::input(), "imported").unwrap();
        let old_name = "Original.Profile.:2408";
        let reserve = SocketAddr::new("192.0.2.59".parse().unwrap(), port);
        let replacement = if port == 2408 {
            reserve
        } else {
            "192.0.2.60:2408".parse().unwrap()
        };
        let old_dns = "[2001:db8::59]:2408".parse::<SocketAddr>().unwrap();
        let doc = read(&db).unwrap();
        let id = s(active(&doc).unwrap(), "id").to_owned();
        let index = doc["servers"]
            .as_array()
            .unwrap()
            .iter()
            .position(|row| row["id"] == id)
            .unwrap();
        edit_document(&db, |doc| {
            doc["servers"][index]["config"]["endpoint"] = json!(old_name);
            doc["servers"][index]["config"]["client"]["endpoint_backups"] = json!([reserve]);
            Ok(())
        })
        .unwrap();
        let old_running = Arc::new(AtomicBool::new(true));
        runtime
            .clients
            .up(&db, Some(&id), |spec| {
                Ok(Box::new(NamedEngine {
                    fingerprint: Sha256::digest(spec.conf.as_bytes()).into(),
                    endpoint: reserve,
                    running: old_running.clone(),
                }))
            })
            .unwrap();
        let old_hash = runtime.clients.0.lock().unwrap()[&id].fingerprint;
        edit_document(&db, |doc| {
            doc["routing_revision"] = json!(14);
            doc["rust_static_routing"] = json!({"revision":14,"pending_commit":false,"targets":[id],"committed_targets":[id]});
            Ok(())
        }).unwrap();
        let input = json!({"endpoint":replacement});
        let observe = |spec: &Spec| {
            let owned = runtime.clients.0.try_lock().unwrap();
            Ok(Some(
                owned_routed_sample(spec, &owned[&id], &spec.iface, None)?.endpoint,
            ))
        };
        if port == 2408 {
            let ambiguous = prepare_routed_endpoint_edit_with(
                &db,
                &input,
                |raw, _, previous| {
                    assert!(previous);
                    assert_eq!(raw, old_name);
                    Ok(vec![reserve])
                },
                observe,
            );
            assert!(ambiguous.is_err());
        }
        let prepared = prepare_routed_endpoint_edit_with(
            &db,
            &input,
            |raw, _, previous| {
                assert!(previous);
                assert_eq!(port, 2408);
                assert_eq!(raw, old_name);
                assert!(runtime.clients.0.try_lock().is_ok());
                db.try_transaction(|_| Ok(()))?;
                Ok(vec![old_dns])
            },
            observe,
        )
        .unwrap();
        assert_eq!(prepared.is_some(), port == 2408);
        let pins = if port == 2408 {
            vec![old_dns]
        } else {
            Vec::new()
        };
        let running = Arc::new(AtomicBool::new(true));
        let result = runtime
            .clients
            .save_config(
                &db,
                &input,
                |spec| {
                    assert!(!old_running.load(Ordering::SeqCst));
                    assert_eq!(spec.endpoint, replacement.to_string());
                    let fingerprint = Sha256::digest(spec.conf.as_bytes()).into();
                    assert_ne!(old_hash, fingerprint);
                    Ok(Box::new(NamedEngine {
                        fingerprint,
                        endpoint: replacement,
                        running: running.clone(),
                    }))
                },
                |_| unreachable!(),
                |doc, _, _, _| {
                    let row = active(doc)?;
                    assert_eq!(routed_hostname_addresses(doc, row)?, None);
                    assert!(crate::transport_endpoints(&db)?.contains(&replacement));
                    Ok(())
                },
                Some(RoutedEditHooks {
                    validate: None,
                    park: &|_| {
                        assert!(old_running.load(Ordering::SeqCst));
                        Ok(())
                    },
                    initial: Some(InitialRoutedEditHooks {
                        choose: &|change, _, selected| {
                            let edit = change.endpoint_edit.as_ref().unwrap();
                            assert_eq!(edit.previous_reserve, Some(reserve));
                            assert_eq!(edit.pinned_addresses(old_name), Some(pins.as_slice()));
                            assert_eq!(edit.sockets()?, (reserve, replacement));
                            assert_eq!(selected, replacement);
                            Ok(RoutedEndpointLaunch::Primary)
                        },
                        prepare: &|_, _| unreachable!(),
                        can_wait: true,
                        prepared: prepared.as_ref(),
                        verify_previous: &|endpoint, mark| endpoint == reserve && mark == 0,
                        adopt_legacy: None,
                    }),
                }),
            )
            .unwrap();
        assert!(result.is_none());
        let db = Store::open(dir.path()).unwrap();
        let doc = read(&db).unwrap();
        let change = pending_routed_mtu(active(&doc).unwrap()).unwrap().unwrap();
        assert_eq!(
            runtime
                .routed_mtu_peer(&db, &change)
                .unwrap()
                .unwrap()
                .endpoint,
            replacement
        );

        let set_backups = |backups: &[String]| {
            runtime.set_backups_with_transport(&db, &id, backups, &[], |_| unreachable!())
        };
        let undo = json!({"endpoint":old_name});
        if replacement != reserve {
            set_backups(&[]).unwrap();
            assert!(runtime
                .clients
                .save_config(
                    &db,
                    &undo,
                    |_| unreachable!(),
                    |_| unreachable!(),
                    |_, _, _, _| unreachable!(),
                    Some(RoutedEditHooks {
                        validate: Some(&|_, _, _| unreachable!()),
                        park: &|_| unreachable!(),
                        initial: None
                    }),
                )
                .is_err());
            set_backups(&[reserve.to_string()]).unwrap();
        }
        assert!(prepare_routed_endpoint_edit_with(
            &db,
            &undo,
            |_, _, _| unreachable!(),
            |_| unreachable!()
        )
        .unwrap()
        .is_none());
        let result = runtime
            .clients
            .save_config(
                &db,
                &undo,
                |spec| {
                    assert!(!running.load(Ordering::SeqCst));
                    assert_eq!(spec.endpoint, reserve.to_string());
                    let fingerprint = Sha256::digest(spec.conf.as_bytes()).into();
                    assert_eq!(fingerprint, old_hash);
                    Ok(Box::new(NamedEngine {
                        fingerprint,
                        endpoint: reserve,
                        running: Arc::new(AtomicBool::new(true)),
                    }))
                },
                |_| unreachable!(),
                |doc, _, _, _| {
                    assert_eq!(
                        routed_hostname_addresses(doc, active(doc)?)?,
                        Some(pins.clone())
                    );
                    assert!(crate::transport_endpoints(&db)?.contains(&reserve));
                    Ok(())
                },
                Some(RoutedEditHooks {
                    validate: Some(&|saved, _, endpoint| {
                        assert_eq!(saved, &change);
                        assert_eq!(endpoint, reserve);
                        Ok(())
                    }),
                    park: &|_| Ok(()),
                    initial: None,
                }),
            )
            .unwrap();
        assert!(result.is_none());
        assert_eq!(
            runtime.clients.0.lock().unwrap()[&id].recovery.selected(),
            Some(reserve.to_string().as_str())
        );
        assert!(set_backups(&[]).is_err());
        let verify = |wan| {
            runtime.routed_mtu_peer_inner(&db, &change, Some(reserve), |endpoint, mark| {
                endpoint == reserve && mark == 0 && wan
            })
        };
        assert!(verify(false).is_err());
        assert_eq!(verify(true).unwrap().unwrap().endpoint, reserve);
    }

    #[test]
    fn routed_endpoint_wait_keeps_the_exact_predecessor_until_a_successor_is_ready() {
        struct Prior {
            endpoint: SocketAddr,
            connected: Arc<AtomicBool>,
            stopped: Arc<AtomicBool>,
        }
        impl Tunnel for Prior {
            fn alive(&mut self) -> bool {
                !self.stopped.load(Ordering::SeqCst)
            }
            fn stop(&mut self) -> io::Result<()> {
                self.stopped.store(true, Ordering::SeqCst);
                Ok(())
            }
            fn probe(&mut self) -> io::Result<()> {
                unreachable!()
            }
            fn snapshot(&self) -> io::Result<Value> {
                unreachable!()
            }
            fn verified_routed_mtu(
                &self,
                spec: &Spec,
                outer: Option<&NestedOuter>,
                connected: bool,
            ) -> io::Result<RoutedMtuSample> {
                if spec.endpoint != self.endpoint.to_string()
                    || outer.is_some()
                    || self.stopped.load(Ordering::SeqCst)
                    || connected && !self.connected.load(Ordering::SeqCst)
                {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                Ok(RoutedMtuSample {
                    endpoint: self.endpoint,
                    effective_mtu: 1420,
                    socket_mark: crate::DIRECT_SOCKET_MARK,
                    connected: self.connected.load(Ordering::SeqCst),
                    outer_endpoint: None,
                })
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        let rt = Runtime::new(dir.path(), dir.path().join("no-engine"));
        crate::import(&db, &crate::tests::input(), "imported").unwrap();
        let old: SocketAddr = "192.0.2.31:2408".parse().unwrap();
        let new: SocketAddr = "[2001:db8::31]:443".parse().unwrap();
        let reserve: SocketAddr = "[2001:db8::32]:3200".parse().unwrap();
        let id = s(active(&read(&db).unwrap()).unwrap(), "id").to_owned();
        let update = |doc: &mut Value, f: &dyn Fn(&mut Value)| {
            let row = doc["servers"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|row| row["id"] == id)
                .unwrap();
            f(row);
        };
        let set_backups = |backups: Value| -> io::Result<()> {
            edit_document(&db, |doc| {
                update(doc, &|row| {
                    row["config"]["client"]["endpoint_backups"] = backups.clone();
                });
                Ok(())
            })
        };
        edit_document(&db, |doc| {
            update(doc, &|row| row["config"]["endpoint"] = json!(old));
            Ok(())
        })
        .unwrap();
        let connected = Arc::new(AtomicBool::new(true));
        let stopped = Arc::new(AtomicBool::new(false));
        rt.clients
            .up(&db, Some(&id), |_| {
                Ok(Box::new(Prior {
                    endpoint: old,
                    connected: connected.clone(),
                    stopped: stopped.clone(),
                }))
            })
            .unwrap();
        edit_document(&db, |doc| {
            doc["routing_revision"] = json!(7);
            doc["rust_static_routing"] = json!({"revision":7,"pending_commit":false,"targets":[id],"committed_targets":[id]});
            Ok(())
        })
        .unwrap();
        let input = json!({"endpoint":new});
        let save_waiting = || {
            rt.save_config_with_routing_endpoint_launch(
                &db,
                &input,
                &[],
                |_| unreachable!("waiting never changes transport exclusions"),
                |_| Ok(RoutedEndpointLaunch::Waiting),
                |_, _| unreachable!("waiting never parks the prior owner"),
            )
        };
        set_backups(json!(["standby.invalid:443", reserve])).unwrap();
        assert!(save_waiting().is_err());
        let doc = read(&db).unwrap();
        let row = active(&doc).unwrap();
        assert_eq!(row["config"]["endpoint"], old.to_string());
        assert!(routing_direct_backup_pool(row).is_err());
        assert!(routing_direct_literal_pool(row).is_err());

        set_backups(json!([reserve])).unwrap();
        assert!(save_waiting().unwrap().is_some());
        assert!(!stopped.load(Ordering::SeqCst));
        let db = Store::open(dir.path()).unwrap();
        let doc = read(&db).unwrap();
        let row = active(&doc).unwrap();
        assert_eq!(row["config"]["endpoint"], new.to_string());
        assert_eq!(
            routing_direct_literal_pool(row).unwrap().unwrap(),
            [new, reserve]
        );
        assert!(routed_endpoint_initial_pending(row).unwrap());
        let edit = pending_routed_mtu(row).unwrap().unwrap();
        let witness = |runtime: &Runtime, endpoint, wan| {
            runtime.routing_endpoint_predecessor_inner(
                &db,
                &edit.iface,
                endpoint,
                crate::DIRECT_SOCKET_MARK,
                |actual, mark| wan && actual == old && mark == crate::DIRECT_SOCKET_MARK,
            )
        };
        let previous = witness(&rt, old, true).unwrap().unwrap();
        assert_eq!(previous.edit, edit);
        assert_eq!(previous.peer.endpoint, old);
        assert!(witness(&rt, old, false).is_err());
        assert!(witness(&rt, new, true).unwrap().is_none());
        assert!(rt
            .routed_mtu_peer_inner(&db, &edit, Some(old), |_, _| true)
            .is_err());
        connected.store(false, Ordering::SeqCst);
        assert!(witness(&rt, old, true).is_err());
        connected.store(true, Ordering::SeqCst);

        let recovered = Runtime::new(dir.path(), dir.path().join("no-engine"));
        let keep_waiting = || {
            recovered.recover_saved_edits(
                &db,
                &[],
                Some(&|_| unreachable!("waiting cannot change transport")),
                Some(&|_| unreachable!("waiting cannot park")),
                Some(RoutedRetryHooks {
                    read: &|saved| {
                        assert_eq!(saved, &edit);
                        Ok(RoutedEndpointLaunch::Waiting)
                    },
                    prepare: &|_, _| unreachable!("waiting cannot prepare a retry"),
                }),
            )
        };
        assert_eq!(keep_waiting().unwrap().len(), 1);
        assert!(witness(&recovered, old, true).is_err());
        let managed = rt.clients.0.lock().unwrap().remove(&id).unwrap();
        recovered
            .clients
            .0
            .lock()
            .unwrap()
            .insert(id.clone(), managed);
        keep_waiting().unwrap();
        assert!(witness(&recovered, old, true).unwrap().is_some());
        let spec = specification(&doc, row).unwrap();
        let successor: [u8; 32] = Sha256::digest(spec.conf.as_bytes()).into();
        let mut owned = recovered.clients.0.lock().unwrap();
        assert_ne!(owned[&id].fingerprint, successor);
        let saved = std::mem::replace(&mut owned.get_mut(&id).unwrap().fingerprint, successor);
        drop(owned);
        assert!(witness(&recovered, old, true).is_err());
        let mut owned = recovered.clients.0.lock().unwrap();
        owned.get_mut(&id).unwrap().fingerprint = saved;
        let parked = AtomicBool::new(false);
        apply_saved_edit_at(
            SavedEdit {
                db: &db,
                doc: &doc,
                row,
            },
            &mut owned,
            spec,
            |_, _, spec, _| {
                assert_eq!(spec.endpoint, new.to_string());
                Ok(())
            },
            |spec| {
                assert!(parked.load(Ordering::SeqCst));
                assert!(stopped.load(Ordering::SeqCst));
                assert_eq!(spec.endpoint, new.to_string());
                Ok(Box::new(Prior {
                    endpoint: new,
                    connected: Arc::new(AtomicBool::new(true)),
                    stopped: Arc::new(AtomicBool::new(false)),
                }))
            },
            Some(&|change| {
                assert_eq!(change, &edit);
                assert!(!stopped.load(Ordering::SeqCst));
                parked.store(true, Ordering::SeqCst);
                Ok(())
            }),
            None,
        )
        .unwrap();
        drop(owned);
        assert!(witness(&recovered, old, true).unwrap().is_none());
    }

    #[test]
    fn initial_wan_loss_launches_the_authorized_reserve_and_replays_transport_refresh() {
        struct Engine {
            endpoint: SocketAddr,
            running: Arc<AtomicBool>,
        }
        impl Tunnel for Engine {
            fn alive(&mut self) -> bool {
                self.running.load(Ordering::SeqCst)
            }
            fn stop(&mut self) -> io::Result<()> {
                self.running.store(false, Ordering::SeqCst);
                Ok(())
            }
            fn probe(&mut self) -> io::Result<()> {
                unreachable!()
            }
            fn snapshot(&self) -> io::Result<Value> {
                unreachable!()
            }
            fn verified_routed_mtu(
                &self,
                _: &Spec,
                outer: Option<&NestedOuter>,
                _: bool,
            ) -> io::Result<RoutedMtuSample> {
                assert!(outer.is_none());
                if !self.running.load(Ordering::SeqCst) {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                Ok(RoutedMtuSample {
                    endpoint: self.endpoint,
                    effective_mtu: 1420,
                    socket_mark: crate::DIRECT_SOCKET_MARK,
                    connected: true,
                    outer_endpoint: None,
                })
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        let rt = Runtime::new(dir.path(), dir.path().join("no-engine"));
        crate::import(&db, &crate::tests::input(), "imported").unwrap();
        let before: SocketAddr = "192.0.2.16:2408".parse().unwrap();
        let after: SocketAddr = "[2001:db8::16]:443".parse().unwrap();
        let reserve: SocketAddr = "198.51.100.16:3200".parse().unwrap();
        let id = s(active(&read(&db).unwrap()).unwrap(), "id").to_owned();
        edit_document(&db, |doc| {
            let row = doc["servers"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|row| row["id"] == id)
                .unwrap();
            row["config"]["endpoint"] = json!(before);
            row["config"]["client"]["endpoint_backups"] = json!([reserve]);
            Ok(())
        })
        .unwrap();
        let old_running = Arc::new(AtomicBool::new(true));
        rt.clients
            .up(&db, Some(&id), |_| {
                Ok(Box::new(Engine {
                    endpoint: reserve,
                    running: old_running.clone(),
                }))
            })
            .unwrap();
        let old_fingerprint = rt.clients.0.lock().unwrap()[&id].fingerprint;
        edit_document(&db, |doc| {
            doc["routing_revision"] = json!(7);
            doc["rust_static_routing"] = json!({"revision":7,"pending_commit":false,"targets":[id],"committed_targets":[id]});
            Ok(())
        })
        .unwrap();
        let input = json!({"endpoint":after});
        for result in [
            Err(io::ErrorKind::InvalidData.into()),
            Ok(RoutedEndpointLaunch::Alternate(before)),
        ] {
            let choose = |_: &RoutedMtuChange, _: &Spec, _: SocketAddr| {
                result
                    .as_ref()
                    .copied()
                    .map_err(|error: &io::Error| io::Error::from(error.kind()))
            };
            assert!(rt
                .clients
                .save_config(
                    &db,
                    &input,
                    |_| unreachable!(),
                    |_| unreachable!(),
                    |_, _, _, _| unreachable!(),
                    Some(RoutedEditHooks {
                        validate: None,
                        park: &|_| unreachable!(),
                        initial: Some(InitialRoutedEditHooks {
                            choose: &choose,
                            prepare: &|_, _| unreachable!(),
                            can_wait: false,
                            prepared: None,
                            verify_previous: &|_, _| unreachable!(),
                            adopt_legacy: None,
                        }),
                    }),
                )
                .is_err());
            let doc = read(&db).unwrap();
            assert_eq!(
                active(&doc).unwrap()["config"]["endpoint"],
                before.to_string()
            );
            assert!(old_running.load(Ordering::SeqCst));
        }
        let report = rt
            .clients
            .save_config(
                &db,
                &input,
                |_| unreachable!("no process can start before durable authority"),
                |_| unreachable!(),
                |_, _, spec, _| {
                    assert_eq!(spec.endpoint, reserve.to_string());
                    Ok(())
                },
                Some(RoutedEditHooks {
                    validate: None,
                    park: &|_| unreachable!("the primary has no WAN route"),
                    initial: Some(InitialRoutedEditHooks {
                        choose: &|_, spec, selected| {
                            assert_eq!(spec.endpoint, after.to_string());
                            assert_eq!(selected, after);
                            assert_eq!(
                                active(&read(&db)?)?["config"]["endpoint"],
                                before.to_string()
                            );
                            Ok(RoutedEndpointLaunch::Alternate(reserve))
                        },
                        prepare: &|change, selected| {
                            assert_eq!(selected, reserve);
                            let doc = read(&db)?;
                            let row = active(&doc)?;
                            assert_eq!(pending_routed_mtu(row)?.as_ref(), Some(change));
                            assert!(routed_endpoint_initial_pending(row)?);
                            assert_eq!(previous_fingerprint(row)?, Some(old_fingerprint));
                            assert!(old_running.load(Ordering::SeqCst));
                            Err(io::ErrorKind::TimedOut.into())
                        },
                        can_wait: false,
                        prepared: None,
                        verify_previous: &|_, _| unreachable!(),
                        adopt_legacy: None,
                    }),
                }),
            )
            .unwrap();
        assert!(report.is_some());

        let db = Store::open(dir.path()).unwrap();
        let doc = read(&db).unwrap();
        let row = active(&doc).unwrap();
        let change = pending_routed_mtu(row).unwrap().unwrap();
        let spec = specification(&doc, row).unwrap();
        let new_fingerprint: [u8; 32] = Sha256::digest(spec.conf.as_bytes()).into();
        assert_ne!(new_fingerprint, old_fingerprint);
        assert!(rt
            .routed_mtu_peer_inner(&db, &change, Some(reserve), |_, _| true)
            .is_err());
        let parked = AtomicBool::new(false);
        let prepare = |saved: &RoutedMtuChange, selected: SocketAddr| {
            assert_eq!(saved, &change);
            assert_eq!(selected, reserve);
            assert!(old_running.load(Ordering::SeqCst));
            parked.store(true, Ordering::SeqCst);
            Ok(())
        };
        let launch = InitialRoutedLaunch {
            endpoint: reserve,
            prepare: &prepare,
        };
        let error = apply_saved_edit_at(
            SavedEdit {
                db: &db,
                doc: &doc,
                row,
            },
            &mut rt.clients.0.lock().unwrap(),
            spec.clone(),
            |doc, _, spec, _| {
                assert_eq!(spec.endpoint, reserve.to_string());
                let row = active(doc)?;
                let bypass = crate::transport_endpoints(&db)?;
                assert!(bypass.contains(&reserve));
                if transport_refresh_pending(row) {
                    assert!(!bypass.contains(&before));
                    assert!(!routed_endpoint_initial_pending(row)?);
                    return Err(io::ErrorKind::TimedOut.into());
                }
                assert!(bypass.contains(&before));
                Ok(())
            },
            |actual| {
                assert!(parked.load(Ordering::SeqCst));
                assert!(!old_running.load(Ordering::SeqCst));
                assert_eq!(actual.endpoint, reserve.to_string());
                assert_eq!(actual.conf, spec.conf);
                Ok(Box::new(Engine {
                    endpoint: reserve,
                    running: Arc::new(AtomicBool::new(true)),
                }))
            },
            None,
            Some(launch),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(rt
            .routed_mtu_peer_inner(&db, &change, Some(reserve), |_, _| true)
            .is_err());
        assert_eq!(
            rt.clients.0.lock().unwrap()[&id].fingerprint,
            new_fingerprint
        );

        let reopened = Store::open(dir.path()).unwrap();
        let recovered = Runtime::new(dir.path(), dir.path().join("no-engine"));
        recovered.clients.0.lock().unwrap().insert(
            id.clone(),
            rt.clients.0.lock().unwrap().remove(&id).unwrap(),
        );
        let retried = recovered
            .recover_saved_edits(
                &reopened,
                &[],
                Some(&|proof| {
                    assert_eq!(proof.endpoint, reserve);
                    assert!(!crate::transport_endpoints(&reopened)?.contains(&before));
                    Ok(())
                }),
                None,
                Some(RoutedRetryHooks {
                    read: &|saved| {
                        assert_eq!(saved, &change);
                        Ok(RoutedEndpointLaunch::Alternate(reserve))
                    },
                    prepare: &|_, _| unreachable!("the same owned reserve already launched"),
                }),
            )
            .unwrap();
        assert!(retried.is_empty());
        let doc = read(&reopened).unwrap();
        let row = active(&doc).unwrap();
        assert_eq!(row["config"]["endpoint"], after.to_string());
        assert!(!routed_mtu_launch_pending(row));
        assert_eq!(pending_routed_mtu(row).unwrap().as_ref(), Some(&change));
        let peer = recovered
            .routed_mtu_peer_inner(&reopened, &change, Some(reserve), |endpoint, mark| {
                endpoint == reserve && mark == crate::DIRECT_SOCKET_MARK
            })
            .unwrap()
            .unwrap();
        assert_eq!(peer.endpoint, reserve);
    }

    #[test]
    fn routed_endpoint_undo_restarts_old_reserve_after_unparked_save() {
        routed_endpoint_undo(false);
    }

    #[test]
    fn routed_endpoint_undo_replays_failed_prune_after_unreachable_launch() {
        routed_endpoint_undo(true);
    }

    fn routed_endpoint_undo(launched: bool) {
        struct Engine {
            alive: Arc<AtomicBool>,
            configured: SocketAddr,
            endpoint: SocketAddr,
            connected: Arc<AtomicBool>,
        }
        impl Tunnel for Engine {
            fn alive(&mut self) -> bool {
                self.alive.load(Ordering::SeqCst)
            }
            fn stop(&mut self) -> io::Result<()> {
                self.alive.store(false, Ordering::SeqCst);
                Ok(())
            }
            fn probe(&mut self) -> io::Result<()> {
                unreachable!("never probe a superseded peer")
            }
            fn snapshot(&self) -> io::Result<Value> {
                unreachable!()
            }
            fn verified_routed_mtu(
                &self,
                spec: &Spec,
                outer: Option<&NestedOuter>,
                require_connected: bool,
            ) -> io::Result<RoutedMtuSample> {
                let connected = self.connected.load(Ordering::SeqCst);
                if outer.is_some()
                    || spec.endpoint.parse().ok() != Some(self.configured)
                    || !self.alive.load(Ordering::SeqCst)
                    || require_connected && !connected
                {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                Ok(RoutedMtuSample {
                    endpoint: self.endpoint,
                    effective_mtu: 1420,
                    socket_mark: 0,
                    connected,
                    outer_endpoint: None,
                })
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        let rt = Runtime::new(dir.path(), dir.path().join("no-engine"));
        crate::import(&db, &crate::tests::input(), "imported").unwrap();
        let before: SocketAddr = "192.0.2.6:2408".parse().unwrap();
        let after: SocketAddr = if launched {
            "[2001:db8::7]:443"
        } else {
            "192.0.2.6:443"
        }
        .parse()
        .unwrap();
        let reserve: SocketAddr = "198.51.100.6:3200".parse().unwrap();
        let id = s(active(&read(&db).unwrap()).unwrap(), "id").to_owned();
        let update = |doc: &mut Value, f: &dyn Fn(&mut Value)| {
            let row = doc["servers"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|row| row["id"] == id)
                .unwrap();
            f(row);
        };
        edit_document(&db, |doc| {
            update(doc, &|row| {
                row["config"]["endpoint"] = json!(before);
                row["config"]["client"]["endpoint_backups"] = json!([reserve]);
            });
            Ok(())
        })
        .unwrap();
        let old_running = Arc::new(AtomicBool::new(true));
        rt.clients
            .up(&db, Some(&id), |_| {
                Ok(Box::new(Engine {
                    alive: old_running.clone(),
                    configured: before,
                    endpoint: reserve,
                    connected: Arc::new(AtomicBool::new(true)),
                }))
            })
            .unwrap();
        let old_fingerprint = rt.clients.0.lock().unwrap()[&id].fingerprint;
        edit_document(&db, |doc| {
            doc["routing_revision"] = json!(7);
            doc["rust_static_routing"] = json!({"revision":7,"pending_commit":false,"targets":[id],"committed_targets":[id]});
            Ok(())
        }).unwrap();
        let new_running = Arc::new(AtomicBool::new(launched));
        let forward = rt
            .clients
            .save_config(
                &db,
                &json!({"endpoint":after}),
                |spec| {
                    assert!(launched);
                    assert_eq!(spec.endpoint, after.to_string());
                    Ok(Box::new(Engine {
                        alive: new_running.clone(),
                        configured: after,
                        endpoint: after,
                        connected: Arc::new(AtomicBool::new(false)),
                    }))
                },
                |_| unreachable!(),
                |doc, _, _, _| {
                    if !launched || transport_refresh_pending(active(doc)?) {
                        Err(io::ErrorKind::TimedOut.into())
                    } else {
                        Ok(())
                    }
                },
                Some(RoutedEditHooks {
                    initial: None,
                    validate: Some(&|_, _, endpoint| {
                        assert_eq!(endpoint, after);
                        Ok(())
                    }),
                    park: &|_| {
                        assert!(launched);
                        Ok(())
                    },
                }),
            )
            .unwrap();
        assert!(forward.is_some());
        assert_eq!(old_running.load(Ordering::SeqCst), !launched);
        let current = read(&db).unwrap();
        let row = active(&current).unwrap();
        let change = pending_routed_mtu(row).unwrap().unwrap();
        let superseded_fingerprint: [u8; 32] =
            Sha256::digest(specification(&current, row).unwrap().conf.as_bytes()).into();
        assert!(rt.routed_mtu_peer(&db, &change).is_err());
        assert_eq!(transport_refresh_pending(row), launched);

        let db = Store::open(dir.path()).unwrap();
        for input in [
            json!({"endpoint":"192.0.2.9:2500"}),
            json!({"endpoint":before,"mtu":1490}),
        ] {
            assert!(rt
                .clients
                .save_config(
                    &db,
                    &input,
                    |_| unreachable!(),
                    |_| unreachable!(),
                    |_, _, _, _| unreachable!(),
                    Some(RoutedEditHooks {
                        initial: None,
                        validate: Some(&|_, _, _| unreachable!()),
                        park: &|_| unreachable!()
                    }),
                )
                .is_err());
        }
        let ready = Arc::new(AtomicBool::new(false));
        let parked = AtomicBool::new(false);
        let park_restore = |saved: &RoutedMtuChange| {
            assert_eq!(saved, &change);
            let doc = read(&db)?;
            let row = active(&doc)?;
            assert_eq!(row["config"]["endpoint"], before.to_string());
            assert_eq!(pending_routed_mtu(row)?.as_ref(), Some(saved));
            assert_eq!(doc["routing_revision"], 7);
            assert!(routed_mtu_launch_pending(row));
            parked.store(true, Ordering::SeqCst);
            Ok(())
        };
        let undo = rt
            .clients
            .save_config(
                &db,
                &json!({"endpoint":before}),
                |spec| {
                    assert!(parked.load(Ordering::SeqCst));
                    assert_eq!(spec.endpoint, before.to_string());
                    assert!(
                        !old_running.load(Ordering::SeqCst) && !new_running.load(Ordering::SeqCst)
                    );
                    Ok(Box::new(Engine {
                        alive: Arc::new(AtomicBool::new(true)),
                        configured: before,
                        endpoint: before,
                        connected: ready.clone(),
                    }))
                },
                |_| unreachable!(),
                |doc, _, spec, _| {
                    let row = active(doc)?;
                    assert_eq!(spec.endpoint, before.to_string());
                    let endpoints = crate::transport_endpoints(&db)?;
                    assert!(endpoints.contains(&before));
                    if transport_refresh_pending(row) {
                        assert!(!endpoints.contains(&after));
                        if launched {
                            return Err(io::ErrorKind::TimedOut.into());
                        }
                    } else {
                        assert!(endpoints.contains(&after));
                        assert_eq!(previous_fingerprint(row)?, Some(superseded_fingerprint));
                    }
                    Ok(())
                },
                Some(RoutedEditHooks {
                    initial: None,
                    validate: Some(&|saved, _, endpoint| {
                        assert_eq!(saved, &change);
                        assert_eq!(endpoint, before);
                        assert_eq!(
                            active(&read(&db)?)?["config"]["endpoint"],
                            after.to_string()
                        );
                        Ok(())
                    }),
                    park: &park_restore,
                }),
            )
            .unwrap();
        assert_eq!(undo.is_some(), launched);

        let reopened = Store::open(dir.path()).unwrap();
        assert!(rt.routed_mtu_peer(&reopened, &change).is_err());
        let recovered = Runtime::new(dir.path(), dir.path().join("no-engine"));
        let receipt = rt.clients.0.lock().unwrap().remove(&id).unwrap();
        assert_eq!(receipt.fingerprint, old_fingerprint);
        recovered
            .clients
            .0
            .lock()
            .unwrap()
            .insert(id.clone(), receipt);
        if launched {
            let doc = read(&reopened).unwrap();
            let row = active(&doc).unwrap();
            assert!(transport_refresh_pending(row));
            assert_eq!(pending_routed_mtu(row).unwrap().as_ref(), Some(&change));
            apply_saved_edit(
                SavedEdit {
                    db: &reopened,
                    doc: &doc,
                    row,
                },
                &mut recovered.clients.0.lock().unwrap(),
                specification(&doc, row).unwrap(),
                |_, _, spec, _| {
                    assert_eq!(spec.endpoint, before.to_string());
                    assert!(!crate::transport_endpoints(&reopened)?.contains(&after));
                    Ok(())
                },
                |_| unreachable!("the proved previous process already owns the interface"),
                Some(&park_restore),
            )
            .unwrap();
        }
        assert!(recovered.routed_mtu_peer(&reopened, &change).is_err());
        ready.store(true, Ordering::SeqCst);
        let proof = recovered
            .routed_mtu_peer(&reopened, &change)
            .unwrap()
            .unwrap();
        assert_eq!(proof.endpoint, before);
        let doc = read(&reopened).unwrap();
        assert_eq!(
            active(&doc).unwrap()["config"]["client"]["endpoint_backups"],
            json!([reserve])
        );
        edit_document(&reopened, |doc| {
            let row = doc["servers"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|row| row["id"] == id)
                .unwrap();
            finish_routed_mtu(row, &change)
        })
        .unwrap();
        assert_eq!(
            recovered.routed_mtu_peer(&reopened, &change).unwrap(),
            Some(proof)
        );
    }

    #[test]
    fn routed_endpoint_edit_validates_canonical_literal_addresses() {
        let edit = |before: &str, after: &str| RoutedEndpointEdit {
            before: before.into(),
            after: after.into(),
            resolved_before: Vec::new(),
            resolved_after: Vec::new(),
            previous_reserve: None,
        };
        assert_eq!(
            edit("[::ffff:192.0.2.6]:2408", "192.0.2.6:443")
                .sockets()
                .unwrap(),
            (
                "192.0.2.6:2408".parse().unwrap(),
                "192.0.2.6:443".parse().unwrap()
            )
        );
        assert_eq!(
            edit("192.0.2.6:2408", "[2001:db8::6]:2408")
                .sockets()
                .unwrap(),
            (
                "192.0.2.6:2408".parse().unwrap(),
                "[2001:db8::6]:2408".parse().unwrap()
            )
        );
        for after in ["vpn.test:443", "192.0.2.6:0", "[::ffff:192.0.2.6]:2408"] {
            assert!(edit("192.0.2.6:2408", after).sockets().is_err());
        }
        assert!(edit("[2001:db8::6%1]:2408", "[2001:db8::6%1]:443")
            .sockets()
            .is_err());
    }

    #[test]
    fn routed_hostname_codec_preserves_historical_forms_and_rejects_equal_raw_names() {
        let v4: SocketAddr = "192.0.2.9:2408".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::9]:2408".parse().unwrap();
        let old_name = "Old.Example.:2408";
        let new_name = "New.Example.:2408";
        let cases = [
            (json!({"before":v4,"after":v6}), (v4, v6)),
            (
                json!({"before":v6,"after":new_name,"resolved_after":[v6,v4]}),
                (v6, v4),
            ),
            (
                json!({"before":old_name,"after":v4,"resolved_before":[v6]}),
                (v6, v4),
            ),
            (
                json!({"before":old_name,"after":new_name,"resolved_before":[v4],"resolved_after":[v6,v4]}),
                (v4, v4),
            ),
        ];
        for (saved, expected) in cases {
            let edit: RoutedEndpointEdit = serde_json::from_value(saved.clone()).unwrap();
            assert_eq!(edit.sockets().unwrap(), expected);
            assert_eq!(json!(edit), saved);
        }
        let forged: RoutedEndpointEdit = serde_json::from_value(json!({
            "before": old_name,
            "after": old_name,
            "resolved_before": [v6],
            "resolved_after": [v4]
        }))
        .unwrap();
        assert!(forged.sockets().is_err());
    }

    #[test]
    fn routed_endpoint_edit_replays_new_primary_without_opening_routes_for_old_peer() {
        routed_endpoint_edit_replay("192.0.2.6:2408", "192.0.2.6:443");
    }

    #[test]
    fn routed_endpoint_ip_edit_keeps_old_exemption_until_launch_then_retries_prune() {
        routed_endpoint_edit_replay("192.0.2.6:2408", "192.0.2.7:2408");
        routed_endpoint_edit_replay("[2001:db8::6]:2408", "[2001:db8::7]:8443");
    }

    #[test]
    fn direct_routed_endpoint_cross_family_replays_with_ipv4_only_payload() {
        routed_endpoint_edit_replay("192.0.2.6:2408", "[2001:db8::7]:2408");
        routed_endpoint_edit_replay("[2001:db8::6]:2408", "192.0.2.7:8443");
    }

    fn routed_endpoint_edit_replay(before: &str, after: &str) {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        struct Engine {
            alive: Arc<AtomicBool>,
            configured: SocketAddr,
            peer: Arc<Mutex<SocketAddr>>,
        }
        impl Tunnel for Engine {
            fn alive(&mut self) -> bool {
                self.alive.load(Ordering::SeqCst)
            }
            fn stop(&mut self) -> io::Result<()> {
                self.alive.store(false, Ordering::SeqCst);
                Ok(())
            }
            fn probe(&mut self) -> io::Result<()> {
                unreachable!()
            }
            fn snapshot(&self) -> io::Result<Value> {
                unreachable!()
            }
            fn verified_routed_mtu(
                &self,
                spec: &Spec,
                outer: Option<&NestedOuter>,
                _: bool,
            ) -> io::Result<RoutedMtuSample> {
                let cfg = conf::parse(&spec.conf, 0)?;
                if outer.is_some() || cfg["endpoint"] != self.configured.to_string() {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                assert_eq!(cfg["peers"][0]["allowed_ips"], "0.0.0.0/0");
                assert_eq!(cfg["peers"][0]["address"], "192.0.2.8/32");
                Ok(RoutedMtuSample {
                    endpoint: *self.peer.lock().unwrap(),
                    effective_mtu: 1420,
                    socket_mark: 0,
                    connected: true,
                    outer_endpoint: None,
                })
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        let rt = Runtime::new(dir.path(), dir.path().join("no-engine"));
        let config = crate::tests::input()
            .replace(", fd00::8/128", "")
            .replace(", ::/0", "");
        crate::import(&db, &config, "imported").unwrap();
        let id = s(active(&read(&db).unwrap()).unwrap(), "id").to_owned();
        let before: SocketAddr = before.parse().unwrap();
        let after: SocketAddr = after.parse().unwrap();
        let address_changed = before.ip() != after.ip();
        let reserve: SocketAddr = "198.51.100.6:3200".parse().unwrap();
        let backups = json!([reserve, "[2001:db8::15]:2580"]);
        let index = read(&db).unwrap()["servers"]
            .as_array()
            .unwrap()
            .iter()
            .position(|row| row["id"] == id)
            .unwrap();
        edit_document(&db, |doc| {
            let cfg = &mut doc["servers"][index]["config"];
            cfg["endpoint"] = json!(before);
            cfg["client"]["endpoint_backups"] = backups.clone();
            Ok(())
        })
        .unwrap();
        let old_running = Arc::new(AtomicBool::new(true));
        rt.clients
            .up(&db, Some(&id), |_| {
                Ok(Box::new(Engine {
                    alive: old_running.clone(),
                    configured: before,
                    peer: Arc::new(Mutex::new(reserve)),
                }))
            })
            .unwrap();
        let prior_fp = {
            let mut owned = rt.clients.0.lock().unwrap();
            let current = owned.get_mut(&id).unwrap();
            current
                .recovery
                .remember_routed_mtu_endpoint(&reserve.to_string());
            current.fingerprint
        };
        edit_document(&db, |doc| {
            doc["routing_revision"] = json!(7);
            doc["rust_static_routing"] = json!({"revision":7,"pending_commit":false,"targets":[id],"committed_targets":[id]});
            Ok(())
        }).unwrap();
        for input in [
            json!({"endpoint":if before.is_ipv4() { "192.0.2.8:443" } else { "[2001:db8::8]:443" }}),
            json!({"endpoint":if before.is_ipv4() { "[2001:db8::8]:443" } else { "192.0.2.8:443" }}),
            json!({"endpoint":"vpn.test:443"}),
            json!({"endpoint":after,"mtu":1490}),
            json!({"endpoint":after,"dns":"192.0.2.2"}),
        ] {
            assert!(rt
                .clients
                .save_config(
                    &db,
                    &input,
                    |_| unreachable!(),
                    |_| unreachable!(),
                    |_, _, _, _| unreachable!(),
                    Some(RoutedEditHooks {
                        initial: None,
                        validate: None,
                        park: &|_| unreachable!()
                    }),
                )
                .is_err());
        }
        assert!(old_running.load(Ordering::SeqCst));
        let parked = |change: &RoutedMtuChange| {
            assert_eq!(change.before, 1420);
            assert_eq!(change.after, change.before);
            assert_eq!(
                change.endpoint_edit.as_ref().unwrap().sockets()?,
                (before, after)
            );
            assert!(change.nested_outer.is_none());
            assert!(change.nested_endpoint.is_none());
            assert_eq!(
                pending_routed_mtu(active(&read(&db)?)?)?.as_ref(),
                Some(change)
            );
            if address_changed && old_running.load(Ordering::SeqCst) {
                let independent = Store::open(dir.path())?;
                let endpoints = crate::transport_endpoints(&independent)?;
                assert!(endpoints.contains(&before) && endpoints.contains(&after));
            }
            Ok(())
        };
        let validate = |change: &RoutedMtuChange, spec: &Spec, endpoint: SocketAddr| {
            assert_eq!(
                change.endpoint_edit.as_ref().unwrap().sockets()?,
                (before, after)
            );
            assert_eq!(endpoint, after);
            assert_eq!(spec.endpoint, after.to_string());
            let doc = read(&db)?;
            let row = active(&doc)?;
            assert_eq!(row["config"]["endpoint"], before.to_string());
            assert!(pending_routed_mtu(row)?.is_none());
            assert!(old_running.load(Ordering::SeqCst));
            Ok(())
        };
        if address_changed {
            let reject = |change: &RoutedMtuChange, spec: &Spec, endpoint: SocketAddr| {
                validate(change, spec, endpoint)?;
                Err(io::ErrorKind::PermissionDenied.into())
            };
            let error = rt
                .clients
                .save_config(
                    &db,
                    &json!({"endpoint":after}),
                    |_| unreachable!(),
                    |_| unreachable!(),
                    |_, _, _, _| unreachable!(),
                    Some(RoutedEditHooks {
                        initial: None,
                        validate: Some(&reject),
                        park: &|_| unreachable!(),
                    }),
                )
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            let doc = read(&db).unwrap();
            let row = active(&doc).unwrap();
            assert_eq!(row["config"]["endpoint"], before.to_string());
            assert!(pending_routed_mtu(row).unwrap().is_none());
            assert!(old_running.load(Ordering::SeqCst));
        }
        let validation: &ValidateRoutedEdit<'_> = if address_changed {
            &validate
        } else {
            &|_, _, _| unreachable!()
        };
        let warning = rt
            .clients
            .save_config(
                &db,
                &json!({"endpoint":after}),
                |spec| {
                    assert_eq!(spec.endpoint, after.to_string());
                    let message = uapi_message(&spec.conf, after)?;
                    let expected = format!("endpoint={after}");
                    assert!(message.lines().any(|line| line == expected));
                    assert_eq!(
                        message
                            .lines()
                            .filter_map(|line| line.strip_prefix("allowed_ip="))
                            .collect::<Vec<_>>(),
                        ["0.0.0.0/0"]
                    );
                    assert!(!old_running.load(Ordering::SeqCst));
                    Err(io::Error::other("private implementation error"))
                },
                |_| unreachable!(),
                |_, _, _, _| Ok(()),
                Some(RoutedEditHooks {
                    initial: None,
                    validate: Some(validation),
                    park: &parked,
                }),
            )
            .unwrap()
            .unwrap();
        assert!(!warning.contains("private implementation error"));

        let reopened = Store::open(dir.path()).unwrap();
        let rt = Runtime::new(dir.path(), dir.path().join("no-engine"));
        let doc = read(&reopened).unwrap();
        let row = active(&doc).unwrap();
        let change = pending_routed_mtu(row).unwrap().unwrap();
        assert_eq!(row["config"]["endpoint"], after.to_string());
        assert_eq!(row["config"]["client"]["endpoint_backups"], backups);
        assert_eq!(previous_fingerprint(row).unwrap(), Some(prior_fp));
        assert!(rt.routed_mtu_peer(&reopened, &change).is_err());
        let peer = Arc::new(Mutex::new(before));
        {
            let mut owned = rt.clients.0.lock().unwrap();
            let result = apply_saved_edit(
                SavedEdit {
                    db: &reopened,
                    doc: &doc,
                    row,
                },
                &mut owned,
                specification(&doc, row).unwrap(),
                |doc, _, _, _| {
                    if transport_refresh_pending(active(doc)?) {
                        let endpoints = crate::transport_endpoints(&reopened)?;
                        assert!(!endpoints.contains(&before));
                        assert!(endpoints.contains(&after));
                        Err(io::ErrorKind::TimedOut.into())
                    } else {
                        Ok(())
                    }
                },
                |spec| {
                    assert_eq!(spec.endpoint, after.to_string());
                    Ok(Box::new(Engine {
                        alive: Arc::new(AtomicBool::new(true)),
                        configured: after,
                        peer: peer.clone(),
                    }))
                },
                Some(&parked),
            );
            if address_changed {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
            } else {
                result.unwrap();
            }
            assert_eq!(
                owned[&id].recovery.selected(),
                Some(after.to_string().as_str())
            );
        }
        if address_changed {
            let disk = Store::open(dir.path()).unwrap();
            let doc = read(&disk).unwrap();
            let row = active(&doc).unwrap();
            assert!(transport_refresh_pending(row));
            assert!(routed_mtu_launch_pending(row));
            assert_eq!(previous_fingerprint(row).unwrap(), None);
            assert_eq!(pending_routed_mtu(row).unwrap().as_ref(), Some(&change));
            *peer.lock().unwrap() = after;
            assert!(rt.routed_mtu_peer(&disk, &change).is_err());
            let mut owned = rt.clients.0.lock().unwrap();
            apply_saved_edit(
                SavedEdit {
                    db: &disk,
                    doc: &doc,
                    row,
                },
                &mut owned,
                specification(&doc, row).unwrap(),
                |doc, _, _, _| {
                    assert!(transport_refresh_pending(active(doc)?));
                    assert!(!crate::transport_endpoints(&disk)?.contains(&before));
                    Ok(())
                },
                |_| unreachable!("the verified successor must be retained"),
                Some(&|_| unreachable!("the saved route is already parked")),
            )
            .unwrap();
            *peer.lock().unwrap() = before;
        }
        let current = read(&reopened).unwrap();
        let row = active(&current).unwrap();
        assert!(!routed_mtu_launch_pending(row));
        assert_eq!(pending_routed_mtu(row).unwrap().as_ref(), Some(&change));
        assert!(rt.routed_mtu_peer(&reopened, &change).is_err());
        let proof_at = |endpoint| {
            rt.routed_mtu_peer_inner(&reopened, &change, Some(endpoint), |actual, mark| {
                assert_eq!(actual, endpoint);
                assert_eq!(mark, 0);
                true
            })
        };
        assert!(proof_at(before).is_err());
        let set_backups = |endpoints: &[String]| {
            assert!(rt
                .set_backups_with_transport(&reopened, &id, endpoints, &[], |_| {
                    unreachable!("the pending route operation owns the restart")
                })
                .unwrap()
                .is_none());
        };
        set_backups(&[before.to_string()]);
        assert_eq!(proof_at(before).unwrap().unwrap().endpoint, before);
        let current_fingerprint = {
            let mut owned = rt.clients.0.lock().unwrap();
            std::mem::replace(&mut owned.get_mut(&id).unwrap().fingerprint, prior_fp)
        };
        assert!(proof_at(before).is_err());
        rt.clients
            .0
            .lock()
            .unwrap()
            .get_mut(&id)
            .unwrap()
            .fingerprint = current_fingerprint;
        let mut wrong_port = before;
        wrong_port.set_port(1);
        assert!(proof_at(wrong_port).is_err());
        set_backups(&[reserve.to_string(), "[2001:db8::15]:2580".into()]);
        assert!(proof_at(before).is_err());
        *peer.lock().unwrap() = after;
        let proof = rt.routed_mtu_peer(&reopened, &change).unwrap().unwrap();
        assert_eq!(proof.endpoint, after);
        assert!(proof.outer_id.is_empty() && proof.outer_iface.is_empty());
        if address_changed && before.is_ipv4() == after.is_ipv4() {
            let wrong_wan =
                rt.routed_mtu_peer_inner(&reopened, &change, Some(after), |actual, mark| {
                    assert_eq!(actual, after);
                    assert_eq!(mark, 0);
                    false
                });
            assert_eq!(wrong_wan.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        }
        assert_eq!(proof_at(after).unwrap().unwrap().endpoint, after);
        let witness = |endpoint, mark, wan| {
            rt.routing_direct_backup_inner(
                &reopened,
                &change.iface,
                endpoint,
                mark,
                |observed, socket_mark| {
                    assert_eq!(observed, endpoint);
                    assert_eq!(socket_mark, mark);
                    wan
                },
            )
        };
        *peer.lock().unwrap() = reserve;
        assert!(witness(reserve, 0, true).unwrap().is_none());
        edit_document(&reopened, |d| {
            finish_routed_mtu(&mut d["servers"][index], &change)
        })
        .unwrap();
        let backup = witness(reserve, 0, true).unwrap().unwrap();
        assert_eq!(backup.primary, after);
        assert_eq!(backup.peer.endpoint, reserve);
        assert_eq!(backup.peer.effective_mtu, 1420);
        assert!(witness(reserve, 0, false).is_err());
        assert!(witness(reserve, crate::DIRECT_SOCKET_MARK, true).is_err());
        let mut wrong_port = reserve;
        wrong_port.set_port(1);
        assert!(witness(wrong_port, 0, true).unwrap().is_none());
        let mut shared_ip = after;
        shared_ip.set_port(1);
        edit_document(&reopened, |doc| {
            doc["servers"][index]["config"]["client"]["endpoint_backups"] =
                json!([reserve, shared_ip]);
            Ok(())
        })
        .unwrap();
        *peer.lock().unwrap() = shared_ip;
        assert!(witness(shared_ip, 0, true).unwrap().is_none());
        *peer.lock().unwrap() = reserve;
        let old = {
            let mut owned = rt.clients.0.lock().unwrap();
            let selected = owned.get_mut(&id).unwrap();
            selected.fingerprint = prior_fp;
            std::mem::replace(
                &mut selected.tunnel,
                Box::new(Engine {
                    alive: Arc::new(AtomicBool::new(true)),
                    configured: before,
                    peer: peer.clone(),
                }),
            )
        };
        assert!(witness(reserve, 0, true).is_err());
        let mut owned = rt.clients.0.lock().unwrap();
        owned.get_mut(&id).unwrap().fingerprint = current_fingerprint;
        drop(owned);
        assert!(witness(reserve, 0, true).is_err());
        rt.clients.0.lock().unwrap().get_mut(&id).unwrap().tunnel = old;
        edit_document(&reopened, |doc| {
            doc["servers"][index]["config"]["client"]["endpoint_backups"] = json!([]);
            Ok(())
        })
        .unwrap();
        assert!(witness(reserve, 0, true).unwrap().is_none());
        *peer.lock().unwrap() = after;
        assert_eq!(rt.routed_mtu_peer(&reopened, &change).unwrap(), Some(proof));

        edit_document(&reopened, |doc| {
            doc["servers"][index]["config"]["endpoint"] = json!(before);
            Ok(())
        })
        .unwrap();
        *peer.lock().unwrap() = before;
        assert!(rt.routed_mtu_peer(&reopened, &change).is_err());
        {
            let mut owned = rt.clients.0.lock().unwrap();
            let managed = owned.get_mut(&id).unwrap();
            managed.fingerprint = prior_fp;
            managed.tunnel = Box::new(Engine {
                alive: Arc::new(AtomicBool::new(true)),
                configured: before,
                peer,
            });
        }
        assert_eq!(
            rt.routed_mtu_peer(&reopened, &change)
                .unwrap()
                .unwrap()
                .endpoint,
            before
        );
    }

    #[test]
    fn nested_mtu_edit_preserves_reserve_and_rejects_old_owned_generation_at_same_clamp() {
        nested_routed_edit_replay("[2001:db8::1]:51820", None);
    }

    #[test]
    fn permanent_nested_reserve_witness_checks_current_pool_and_warm_owner() {
        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        let rt = Runtime::new(dir.path(), dir.path().join("no-engine"));
        crate::import(&db, &crate::tests::input(), "outer").unwrap();
        let outer_id = s(active(&read(&db).unwrap()).unwrap(), "id").to_owned();
        crate::import(&db, &crate::tests::input(), "inner").unwrap();
        let id = s(active(&read(&db).unwrap()).unwrap(), "id").to_owned();
        let primary: SocketAddr = "192.0.2.31:443".parse().unwrap();
        let reserve = SocketAddr::new(primary.ip(), 2443);
        edit_document(&db, |doc| {
            for row in doc["servers"].as_array_mut().unwrap() {
                if row["id"] == outer_id {
                    row["config"]["client"]["enabled"] = json!(true);
                    row["config"]["client"]["rust_managed"] = json!(true);
                } else if row["id"] == id {
                    row["config"]["endpoint"] = json!(primary);
                    row["config"]["client"]["double_tunnel_id"] = json!(outer_id);
                    row["config"]["client"]["double_tunnel_mode"] = json!("permanent");
                    row["config"]["client"]["endpoint_backups"] = json!([reserve]);
                }
            }
            Ok(())
        })
        .unwrap();
        let (_, outer) = routed_outer(&read(&db).unwrap(), &id).unwrap();
        let engine = |resumed, outer| -> Box<dyn Tunnel> {
            Box::new(NestedEditEngine {
                resumed,
                running: Arc::new(AtomicBool::new(true)),
                outer,
                configured: 1420,
                endpoint: reserve,
                outer_mtu: 1360,
            })
        };
        rt.clients
            .up(&db, Some(&id), |_| Ok(engine(true, outer.clone())))
            .unwrap();
        let doc = read(&db).unwrap();
        let row = active(&doc).unwrap();
        let name = iface(row, &doc).unwrap();
        let mark = nested_socket_selector(&name).unwrap().0;
        let witness = rt
            .routing_nested_transport(&db, &name, reserve, mark)
            .unwrap()
            .unwrap();
        assert_eq!(witness.peer.endpoint, reserve);
        assert_eq!(witness.peer.outer_id, outer_id);
        assert_eq!(witness.peer.effective_mtu, 1300);
        assert_eq!(witness.peer.socket_mark, mark);
        assert!(!routing_permanent_nested_reserve(row, primary).unwrap());
        assert!(routing_permanent_nested_reserve(row, reserve).unwrap());
        assert!(rt
            .routing_nested_transport(&db, &name, primary, mark)
            .is_err());
        let snapshot =
            json!({"running":true,"connected":true,"endpoint":reserve,"socket_mark":mark});
        {
            let mut owned = rt.clients.0.lock().unwrap();
            let managed = owned.get_mut(&id).unwrap();
            assert_eq!(
                verified_permanent_nested_resume(&doc, row, managed, &snapshot),
                Some(&snapshot)
            );
            let mut denied = snapshot.clone();
            denied["connected"] = false.into();
            assert!(verified_permanent_nested_resume(&doc, row, managed, &denied).is_none());
            denied = snapshot.clone();
            denied["socket_mark"] = crate::DIRECT_SOCKET_MARK.into();
            assert!(verified_permanent_nested_resume(&doc, row, managed, &denied).is_none());
            denied = snapshot.clone();
            denied["endpoint"] = json!(SocketAddr::new(primary.ip(), 4433));
            assert!(verified_permanent_nested_resume(&doc, row, managed, &denied).is_none());
            let mut foreign = outer.clone();
            foreign.peer_hex = "aa".repeat(32);
            managed.tunnel = engine(true, foreign);
            assert!(verified_permanent_nested_resume(&doc, row, managed, &snapshot).is_none());
            managed.tunnel = engine(false, outer.clone());
            assert!(verified_permanent_nested_resume(&doc, row, managed, &snapshot).is_none());
        }
        assert!(rt
            .routing_nested_transport(&db, &name, reserve, mark)
            .unwrap()
            .is_some());
        edit_document(&db, |doc| {
            let row = doc["servers"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|row| row["id"] == id)
                .unwrap();
            row["config"]["client"]["endpoint_backups"] = json!([]);
            Ok(())
        })
        .unwrap();
        assert!(rt
            .routing_nested_transport(&db, &name, reserve, mark)
            .unwrap()
            .is_none());
    }

    #[test]
    fn nested_recorded_mtu_inverse_preserves_raw_shape_and_exact_generation() {
        for implicit in [
            None,
            Some(RoutedImplicitMtu::Missing),
            Some(RoutedImplicitMtu::Zero),
            Some(RoutedImplicitMtu::Null),
        ] {
            for replay in [NestedMtuReplay::OldOwner, NestedMtuReplay::Promoted] {
                nested_recorded_mtu_edit(implicit, replay, true, true, None, None, None);
            }
        }
    }

    #[test]
    fn nested_recorded_mtu_inverse_keeps_exact_authenticated_reserve() {
        for (replay, reserve) in [
            (NestedMtuReplay::OldOwner, "192.0.2.32:443"),
            (NestedMtuReplay::Promoted, "192.0.2.31:2443"),
            (NestedMtuReplay::Cold, "[2001:db8::32]:443"),
        ] {
            nested_recorded_mtu_edit(
                Some(RoutedImplicitMtu::Null),
                replay,
                true,
                true,
                Some(reserve),
                None,
                None,
            );
        }
    }

    #[test]
    fn nested_recorded_mtu_unsupported_layout_keeps_forward_only_legacy_marker() {
        nested_recorded_mtu_edit(
            Some(RoutedImplicitMtu::Missing),
            NestedMtuReplay::OldOwner,
            false,
            true,
            None,
            None,
            None,
        );
        nested_recorded_mtu_edit(
            Some(RoutedImplicitMtu::Missing),
            NestedMtuReplay::OldOwner,
            false,
            false,
            None,
            None,
            None,
        );
    }

    #[test]
    fn permanent_nested_port_and_mtu_replay_and_undo_preserve_exact_pair() {
        let old = "192.0.2.31:443".parse().unwrap();
        let new = "192.0.2.31:2443".parse().unwrap();
        for replay in [
            NestedMtuReplay::OldOwner,
            NestedMtuReplay::Promoted,
            NestedMtuReplay::Cold,
        ] {
            nested_recorded_mtu_edit(
                Some(RoutedImplicitMtu::Missing),
                replay,
                true,
                true,
                None,
                Some((old, new)),
                None,
            );
        }
    }

    #[test]
    fn permanent_nested_ipv6_endpoint_and_mtu_edit_rechecks_outer_before_saving() {
        let old = "[2001:db8:31::1]:443".parse().unwrap();
        let new = "[2001:db8:32::1]:2443".parse().unwrap();
        for replay in [
            NestedMtuReplay::OldOwner,
            NestedMtuReplay::Promoted,
            NestedMtuReplay::Cold,
        ] {
            nested_recorded_mtu_edit(
                Some(RoutedImplicitMtu::Missing),
                replay,
                true,
                true,
                None,
                Some((old, new)),
                None,
            );
        }
    }

    #[test]
    fn permanent_nested_cross_family_endpoint_and_mtu_edit_has_directional_clamp() {
        let v4 = "192.0.2.31:443".parse().unwrap();
        let v6 = "[2001:db8:32::1]:2443".parse().unwrap();
        for pair in [(v4, v6), (v6, v4)] {
            for replay in [
                NestedMtuReplay::OldOwner,
                NestedMtuReplay::Promoted,
                NestedMtuReplay::Cold,
            ] {
                nested_recorded_mtu_edit(
                    Some(RoutedImplicitMtu::Missing),
                    replay,
                    true,
                    true,
                    None,
                    Some(pair),
                    None,
                );
            }
        }
    }

    #[test]
    fn permanent_full_fixed_mtu_preserves_native_outer_and_raw_inverse() {
        for (replay, raw_mtu, outer_mtu) in [
            (NestedMtuReplay::OldOwner, RoutedImplicitMtu::Zero, 1340),
            (NestedMtuReplay::Promoted, RoutedImplicitMtu::Null, 1340),
            (NestedMtuReplay::Cold, RoutedImplicitMtu::Missing, 1330),
        ] {
            nested_recorded_mtu_edit(
                Some(raw_mtu),
                replay,
                true,
                true,
                None,
                None,
                Some(outer_mtu),
            );
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum NestedMtuReplay {
        OldOwner,
        Promoted,
        Cold,
    }

    fn nested_recorded_mtu_edit(
        implicit: Option<RoutedImplicitMtu>,
        replay_mode: NestedMtuReplay,
        reversible: bool,
        outer_native: bool,
        reserve: Option<&str>,
        pair: Option<(SocketAddr, SocketAddr)>,
        full_outer_mtu: Option<u64>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        let rt = Runtime::new(dir.path(), dir.path().join("no-engine"));
        crate::import(&db, &crate::tests::input(), "outer").unwrap();
        let outer_id = s(active(&read(&db).unwrap()).unwrap(), "id").to_owned();
        crate::import(&db, &crate::tests::input(), "inner").unwrap();
        let id = s(active(&read(&db).unwrap()).unwrap(), "id").to_owned();
        let primary = pair.map_or_else(|| "192.0.2.31:443".parse().unwrap(), |(old, _)| old);
        let endpoint = reserve.map_or(primary, |reserve| reserve.parse().unwrap());
        let forward = pair.map_or(endpoint, |(_, new)| new);
        let paired = pair.is_some();
        let cross_family_pair = paired && endpoint.is_ipv4() != forward.is_ipv4();
        let full = full_outer_mtu.is_some();
        let outer_mtu = full_outer_mtu.unwrap_or(if cross_family_pair { 1350 } else { 1360 });
        let expected_effective =
            |endpoint: SocketAddr| (outer_mtu - if endpoint.is_ipv4() { 60 } else { 80 }) as u16;
        let stale_reserve = "198.51.100.32:443";
        let promoted = replay_mode != NestedMtuReplay::OldOwner;
        let before = 1420u16;
        let after = 1360u16;
        let full_policy = json!({"mode":"full","killswitch":false});
        edit_document(&db, |doc| {
            if full {
                doc["routing"] = full_policy.clone();
            }
            for row in doc["servers"].as_array_mut().unwrap() {
                if row["id"] == outer_id {
                    row["config"]["enabled"] = json!(true);
                    let client = &mut row["config"]["client"];
                    *client = json!({"enabled":true,"standby":true});
                    if outer_native {
                        client["rust_managed"] = true.into();
                    }
                } else if row["id"] == id {
                    let cfg = &mut row["config"];
                    cfg["mtu"] = json!(before);
                    if full {
                        cfg["routing"] = full_policy.clone();
                    }
                    cfg["routing"]["mtu"] = json!(before);
                    cfg["endpoint"] = json!(primary);
                    cfg["client"]["double_tunnel_id"] = json!(outer_id);
                    cfg["client"]["double_tunnel_mode"] = json!("permanent");
                    if reserve.is_some() {
                        cfg["client"]["endpoint_backups"] =
                            json!([endpoint.to_string(), stale_reserve]);
                    } else if paired {
                        cfg["client"]["endpoint_backups"] = json!([stale_reserve]);
                    }
                    if let Some(raw) = implicit {
                        raw.write(cfg.as_object_mut().unwrap());
                    }
                }
            }
            Ok(())
        })
        .unwrap();
        let (selected, outer) = routed_outer(&read(&db).unwrap(), &id).unwrap();
        let engine = |running, configured, endpoint| -> Box<dyn Tunnel> {
            Box::new(NestedEditEngine {
                resumed: false,
                running,
                outer: outer.clone(),
                configured,
                endpoint,
                outer_mtu,
            })
        };
        let old = Arc::new(AtomicBool::new(true));
        rt.clients
            .up(&db, Some(&id), |_| {
                Ok(engine(old.clone(), before, endpoint))
            })
            .unwrap();
        if reserve.is_some() || paired {
            let primary = primary.to_string();
            rt.clients
                .0
                .lock()
                .unwrap()
                .get_mut(&id)
                .unwrap()
                .recovery
                .remember_routed_mtu_endpoint(if paired { &primary } else { stale_reserve });
        }
        edit_document(&db, |doc| {
            doc["routing_revision"] = json!(7);
            doc["rust_static_routing"] = json!({"revision":7,"pending_commit":false,"targets":[id],"committed_targets":[id]});
            Ok(())
        }).unwrap();
        let original = read(&db).unwrap();
        let original_row = active(&original).unwrap();
        let old_spec = specification(&original, original_row).unwrap();
        let mark = nested_socket_selector(&old_spec.iface).unwrap().0;
        let input = if paired {
            json!({"endpoint":forward,"mtu":after})
        } else {
            json!({"mtu":after})
        };
        let stage = |result: Result<RoutedEndpointLaunch, io::ErrorKind>,
                     outer_evidence: Option<(&str, &str)>| {
            rt.clients.save_config(
                &db,
                &input,
                |_| unreachable!("cannot start before park"),
                |_| unreachable!(),
                |_, _, _, _| Ok(()),
                Some(RoutedEditHooks {
                    validate: None,
                    park: &|change| {
                        assert_eq!(change.nested_mtu_before_recorded, reversible && !paired);
                        Err(io::ErrorKind::TimedOut.into())
                    },
                    initial: Some(InitialRoutedEditHooks {
                        choose: &|change, spec, pin| {
                            assert!(outer_native);
                            assert!(old.load(Ordering::SeqCst));
                            assert_eq!(change.implicit_before_mtu, implicit);
                            if paired {
                                assert!(routed_combined_endpoint_mtu_profile(original_row, change));
                            } else {
                                assert!(routed_nested_mtu_edit_profile(original_row, change));
                            }
                            assert_eq!(change.nested_outer.as_ref(), Some(&selected));
                            assert_eq!(spec.outer.as_ref(), Some(&outer));
                            assert_eq!(pin, forward);
                            assert_eq!((change.before, change.after), (before, after));
                            if let Some((uapi, addresses)) = outer_evidence {
                                nested::check_outer_peer(
                                    uapi.as_bytes(),
                                    &outer.peer_hex,
                                    pin.ip(),
                                    100,
                                )?;
                                nested::source(addresses, pin.ip())?;
                            }
                            result.map_err(io::Error::from)
                        },
                        prepare: &|_, _| unreachable!(),
                        can_wait: false,
                        prepared: None,
                        verify_previous: &|_, _| unreachable!("the inner uses its marked outer"),
                        adopt_legacy: None,
                    }),
                }),
            )
        };
        if paired {
            rt.clients.0.lock().unwrap().get_mut(&id).unwrap().tunnel =
                engine(old.clone(), before, SocketAddr::new(primary.ip(), 4444));
            assert_eq!(
                stage(Ok(RoutedEndpointLaunch::Primary), None)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::WouldBlock
            );
            assert_eq!(read(&db).unwrap(), original);
            rt.clients.0.lock().unwrap().get_mut(&id).unwrap().tunnel =
                engine(old.clone(), before, endpoint);
        }
        if outer_native {
            assert!(stage(Err(io::ErrorKind::WouldBlock), None).is_err());
            assert_eq!(read(&db).unwrap(), original);
        }
        let outer_evidence = (paired && primary.ip() != forward.ip()).then(|| {
            let width = |endpoint: SocketAddr| if endpoint.is_ipv4() { 32 } else { 128 };
            let old_only = format!(
                "public_key={}\nendpoint=198.51.100.50:4010\nlast_handshake_time_sec=99\nallowed_ip={}/{}\n",
                outer.peer_hex, primary.ip(), width(primary),
            );
            let both = format!(
                "{old_only}allowed_ip={}/{}\nerrno=0\n\n",
                forward.ip(),
                width(forward)
            );
            let old_only = format!("{old_only}errno=0\n\n");
            let v4 = "1: awg0 inet 192.0.2.30/24 scope global";
            let v6 = "1: awg0 inet6 2001:db8:33::10/64 scope global";
            let addresses = format!("{v4}\n{v6}");
            let without_candidate_source = if forward.is_ipv4() {
                v6
            } else {
                "1: awg0 inet 192.0.2.30/24 scope global\n1: awg0 inet6 2001:db8:33::10/64 tentative"
            };
            nested::check_outer_peer(old_only.as_bytes(), &outer.peer_hex, primary.ip(), 100)
                .unwrap();
            nested::source(&addresses, primary.ip()).unwrap();
            for (uapi, links, expected) in [
                (
                    old_only.as_str(),
                    addresses.as_str(),
                    "внешний AWG не подтвердил рукопожатие, публичный ключ и AllowedIPs",
                ),
                (
                    both.as_str(),
                    without_candidate_source,
                    "нет исходного адреса внешнего туннеля",
                ),
            ] {
                let err =
                    stage(Ok(RoutedEndpointLaunch::Primary), Some((uapi, links))).unwrap_err();
                assert_eq!(err.to_string(), expected);
                assert_eq!(read(&db).unwrap(), original);
                assert!(old.load(Ordering::SeqCst));
            }
            (both, addresses)
        });
        let scope = if reversible {
            Ok(RoutedEndpointLaunch::Primary)
        } else {
            Err(io::ErrorKind::Unsupported)
        };
        assert!(stage(
            scope,
            outer_evidence
                .as_ref()
                .map(|(uapi, addresses)| (uapi.as_str(), addresses.as_str())),
        )
        .unwrap()
        .is_some());
        let reopened = Store::open(dir.path()).unwrap();
        let doc = read(&reopened).unwrap();
        let row = active(&doc).unwrap();
        if full {
            assert_eq!(doc["routing"], full_policy);
            assert_eq!(row["config"]["routing"], original_row["config"]["routing"]);
        }
        let change = check_saved_edit(&doc, row).unwrap().unwrap();
        let undo_input = if paired {
            json!({"endpoint":primary,"mtu":before})
        } else {
            json!({"mtu":before})
        };
        if !reversible {
            assert!(row[PENDING_ROUTED_MTU]
                .get("nested_mtu_before_recorded")
                .is_none());
            assert!(change.implicit_before_mtu.is_none());
            assert!(rt
                .clients
                .save_config(
                    &reopened,
                    &undo_input,
                    |_| unreachable!(),
                    |_| unreachable!(),
                    |_, _, _, _| unreachable!(),
                    Some(RoutedEditHooks {
                        validate: Some(&|_, _, _| unreachable!()),
                        park: &|_| unreachable!(),
                        initial: None,
                    })
                )
                .is_err());
            assert!(old.load(Ordering::SeqCst));
            return;
        }
        if paired {
            assert!(!change.nested_mtu_before_recorded);
            assert_eq!(change.fixed_nested_mtu_endpoint(), None);
            assert_eq!(
                change.endpoint_edit.as_ref().unwrap().sockets().unwrap(),
                (endpoint, forward)
            );
            assert_eq!(row["config"]["endpoint"], forward.to_string());
            rt.set_backups(&reopened, &id, &[stale_reserve.into()], &[])
                .unwrap();
            assert!(active(&read(&reopened).unwrap())
                .unwrap()
                .get("rust_pending_endpoint_restart")
                .is_none());
        } else {
            assert!(change.nested_mtu_before_recorded);
            assert_eq!(change.fixed_nested_mtu_endpoint(), Some(endpoint));
            assert_eq!(row["config"]["endpoint"], primary.to_string());
        }
        assert_eq!(
            previous_fingerprint(row).unwrap(),
            Some(Sha256::digest(old_spec.conf.as_bytes()).into())
        );
        if reserve.is_some() {
            assert_eq!(
                rt.set_backups(&reopened, &id, &[stale_reserve.into()], &[])
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::WouldBlock
            );
        }
        assert_eq!(
            pending_fixed_nested_outer(&doc, row),
            Some(outer_id.as_str())
        );
        assert!(rt
            .routed_mtu_peer_inner(&reopened, &change, Some(endpoint), |_, _| true)
            .is_err());
        let desired = specification(&doc, row).unwrap();
        assert_ne!(old_spec.conf, desired.conf);
        if implicit == Some(RoutedImplicitMtu::Missing)
            && (!promoted || full && replay_mode == NestedMtuReplay::Cold)
        {
            let settings = crate::recovery_settings(&doc["recovery_settings"]);
            let mut cold = if full && replay_mode == NestedMtuReplay::Cold {
                let recovery = Runtime::new(dir.path(), dir.path().join("no-engine"));
                recovery
                    .recover_saved_edits(
                        &reopened,
                        &[],
                        None,
                        Some(&|saved| {
                            assert_eq!(saved, &change);
                            Err(io::ErrorKind::NotConnected.into())
                        }),
                        None,
                    )
                    .unwrap();
                let clients = std::mem::take(&mut *recovery.clients.0.lock().unwrap());
                assert!(clients[&id].tunnel.is_stopped());
                clients
            } else {
                HashMap::from([(id.clone(), stopped_edit(&desired))])
            };
            let mut events = Vec::new();
            let mut wrong = doc.clone();
            let row = wrong["servers"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|row| row["id"] == id)
                .unwrap();
            let byte = &mut row[PENDING_ROUTED_MTU]["nested_outer"]["peer_key_sha256"][0];
            *byte = json!(byte.as_u64().unwrap() ^ 1);
            failover::reconcile(
                &wrong,
                &mut cold,
                crate::now(),
                &settings,
                &mut events,
                None,
                |_| unreachable!("foreign outer must not be demanded"),
            )
            .unwrap();
            assert!(!cold.contains_key(&outer_id));
            failover::reconcile(
                &doc,
                &mut cold,
                crate::now(),
                &settings,
                &mut events,
                None,
                |spec| {
                    assert_eq!(spec.id, outer_id);
                    assert!(spec.outer.is_none());
                    Ok(Box::new(supervisor::Stopped))
                },
            )
            .unwrap();
            assert!(cold.contains_key(&outer_id));
        }
        let successor = Arc::new(AtomicBool::new(false));
        if replay_mode == NestedMtuReplay::Cold {
            rt.clients.0.lock().unwrap().remove(&id).unwrap();
            old.store(false, Ordering::SeqCst);
        }
        if promoted {
            let expected = apply_saved_edit(
                SavedEdit {
                    db: &reopened,
                    doc: &doc,
                    row,
                },
                &mut rt.clients.0.lock().unwrap(),
                desired.clone(),
                |current, _, spec, phase| {
                    assert_eq!(spec.outer.as_ref(), Some(&outer));
                    assert_eq!(spec.endpoint, forward.to_string());
                    if phase == EditPreparation::VerifyBeforeRetiring {
                        assert_eq!(
                            old.load(Ordering::SeqCst),
                            replay_mode != NestedMtuReplay::Cold
                        );
                    }
                    if transport_refresh_pending(active(current)?) {
                        return Err(io::ErrorKind::TimedOut.into());
                    }
                    Ok(())
                },
                |spec| {
                    assert!(!old.load(Ordering::SeqCst));
                    assert_eq!(spec.conf, desired.conf);
                    successor.store(true, Ordering::SeqCst);
                    Ok(engine(successor.clone(), after, forward))
                },
                Some(&|saved| {
                    assert_eq!(saved, &change);
                    Ok(())
                }),
            );
            assert_eq!(expected.unwrap_err().kind(), io::ErrorKind::TimedOut);
            if reserve.is_some() || paired || full {
                let current = read(&reopened).unwrap();
                let row = active(&current).unwrap();
                let mut owned = rt.clients.0.lock().unwrap();
                owned.get_mut(&id).unwrap().recovery = Default::default();
                apply_saved_edit(
                    SavedEdit {
                        db: &reopened,
                        doc: &current,
                        row,
                    },
                    &mut owned,
                    specification(&current, row).unwrap(),
                    |_, _, spec, _| {
                        assert_eq!(spec.endpoint, forward.to_string());
                        assert_eq!(spec.outer.as_ref(), Some(&outer));
                        Ok(())
                    },
                    |_| unreachable!("already-verified successor keeps its owner"),
                    Some(&|_| Ok(())),
                )
                .unwrap();
                if reserve.is_some() {
                    assert_eq!(owned[&id].recovery.selected(), reserve);
                }
            }
            if paired || full {
                let peer = |pin| {
                    rt.routed_mtu_peer_inner(&reopened, &change, Some(pin), |_, _| {
                        unreachable!("the nested primary uses its marked path")
                    })
                };
                if paired {
                    assert!(peer(endpoint).is_err());
                }
                if full {
                    let previous = Sha256::digest(old_spec.conf.as_bytes()).into();
                    let current = std::mem::replace(
                        &mut rt
                            .clients
                            .0
                            .lock()
                            .unwrap()
                            .get_mut(&id)
                            .unwrap()
                            .fingerprint,
                        previous,
                    );
                    assert!(peer(endpoint).is_err());
                    rt.clients
                        .0
                        .lock()
                        .unwrap()
                        .get_mut(&id)
                        .unwrap()
                        .fingerprint = current;
                }
                let peer = peer(forward).unwrap().unwrap();
                assert_eq!(
                    (peer.endpoint, peer.effective_mtu, peer.socket_mark),
                    (forward, expected_effective(forward), mark)
                );
            }
        }
        let replay = Runtime::new(dir.path(), dir.path().join("no-engine"));
        let managed = rt.clients.0.lock().unwrap().remove(&id).unwrap();
        replay.clients.0.lock().unwrap().insert(id.clone(), managed);
        let parked = AtomicBool::new(false);
        let undo = replay
            .clients
            .save_config(
                &reopened,
                &undo_input,
                |spec| {
                    assert!(promoted && parked.load(Ordering::SeqCst));
                    assert!(!successor.load(Ordering::SeqCst));
                    assert_eq!(spec.outer.as_ref(), Some(&outer));
                    assert_eq!(spec.conf, old_spec.conf);
                    Ok(engine(Arc::new(AtomicBool::new(true)), before, endpoint))
                },
                |_| unreachable!(),
                |_, _, spec, phase| {
                    assert_eq!(spec.outer.as_ref(), Some(&outer));
                    assert_eq!(spec.endpoint, endpoint.to_string());
                    assert!(!matches!(
                        phase,
                        EditPreparation::VerifyDirectBeforeRetiring(..)
                    ));
                    Ok(())
                },
                Some(RoutedEditHooks {
                    validate: Some(&|saved, spec, pin| {
                        assert_eq!(saved, &change);
                        assert_eq!(pin, endpoint);
                        assert_eq!(spec.outer.as_ref(), Some(&outer));
                        assert_eq!(spec.conf, old_spec.conf);
                        Ok(())
                    }),
                    park: &|saved| {
                        assert_eq!(saved, &change);
                        parked.store(true, Ordering::SeqCst);
                        Ok(())
                    },
                    initial: None,
                }),
            )
            .unwrap();
        assert!(undo.is_none() && parked.load(Ordering::SeqCst));
        assert_eq!(old.load(Ordering::SeqCst), !promoted);
        let final_doc = read(&reopened).unwrap();
        let row = active(&final_doc).unwrap();
        assert_eq!(row["config"], original_row["config"]);
        assert_eq!(final_doc["routing"], original["routing"]);
        assert_eq!(pending_routed_mtu(row).unwrap().as_ref(), Some(&change));
        let stale = Sha256::digest(desired.conf.as_bytes()).into();
        let fingerprint = Sha256::digest(old_spec.conf.as_bytes()).into();
        replay
            .clients
            .0
            .lock()
            .unwrap()
            .get_mut(&id)
            .unwrap()
            .fingerprint = stale;
        let peer = |pin, wan_ok| {
            replay.routed_mtu_peer_inner(&reopened, &change, Some(pin), |_, _| {
                assert!(reserve.is_some(), "only a nested reserve needs plain WAN");
                wan_ok
            })
        };
        assert!(peer(endpoint, true).is_err());
        replay
            .clients
            .0
            .lock()
            .unwrap()
            .get_mut(&id)
            .unwrap()
            .fingerprint = fingerprint;
        let mut wrong_port = endpoint;
        wrong_port.set_port(endpoint.port() + 1);
        assert!(peer(wrong_port, true).is_err());
        if reserve.is_some() {
            assert!(peer(endpoint, false).is_err());
            assert_eq!(
                replay.clients.0.lock().unwrap()[&id].recovery.selected(),
                reserve
            );
        }
        let attested = replay
            .routed_mtu_peer_inner(&reopened, &change, Some(endpoint), |pin, mark| {
                assert!(reserve.is_some());
                (pin, mark) == (endpoint, 0)
            })
            .unwrap()
            .unwrap();
        assert_eq!(
            (
                attested.endpoint,
                attested.effective_mtu,
                attested.socket_mark
            ),
            (endpoint, expected_effective(endpoint), mark)
        );
        assert_eq!(
            (attested.outer_id, attested.outer_iface),
            (outer_id, outer.iface)
        );
    }

    #[test]
    fn nested_routed_endpoint_ip_edit_pins_primary_under_the_original_outer() {
        nested_routed_edit_replay("[2001:db8::1]:51820", Some("[2001:db8::23]:8443"));
    }

    #[test]
    fn nested_routed_endpoint_cross_family_recomputes_and_restores_effective_mtu() {
        nested_routed_edit_replay("192.0.2.11:51820", Some("[2001:db8::23]:8443"));
        nested_routed_edit_replay("[2001:db8::1]:51820", Some("192.0.2.12:8443"));
    }

    struct NestedEditEngine {
        resumed: bool,
        running: Arc<AtomicBool>,
        outer: NestedOuter,
        configured: u16,
        endpoint: SocketAddr,
        outer_mtu: u64,
    }
    impl Tunnel for NestedEditEngine {
        fn resumed(&self) -> bool {
            self.resumed
        }

        fn alive(&mut self) -> bool {
            self.running.load(Ordering::SeqCst)
        }
        fn stop(&mut self) -> io::Result<()> {
            self.running.store(false, Ordering::SeqCst);
            Ok(())
        }
        fn probe(&mut self) -> io::Result<()> {
            unreachable!()
        }
        fn snapshot(&self) -> io::Result<Value> {
            unreachable!()
        }
        fn nested_iface(&self) -> Option<&str> {
            Some(&self.outer.iface)
        }
        fn verified_routed_mtu(
            &self,
            spec: &Spec,
            outer: Option<&NestedOuter>,
            _: bool,
        ) -> io::Result<RoutedMtuSample> {
            let cfg = conf::parse(&spec.conf, 0)?;
            if outer != Some(&self.outer) || cfg["mtu"] != self.configured {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            Ok(RoutedMtuSample {
                endpoint: self.endpoint,
                effective_mtu: nested::mtu(&cfg, self.outer_mtu, self.endpoint.ip())? as u16,
                socket_mark: nested_socket_selector(&spec.iface)?.0,
                connected: true,
                outer_endpoint: Some("198.51.100.50:4010".parse().unwrap()),
            })
        }
    }

    fn nested_routed_edit_replay(primary: &str, replacement: Option<&str>) {
        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        let rt = Runtime::new(dir.path(), dir.path().join("no-engine"));
        crate::import(&db, &crate::tests::input(), "outer").unwrap();
        let outer_id = s(active(&read(&db).unwrap()).unwrap(), "id").to_owned();
        crate::import(&db, &crate::tests::input(), "inner").unwrap();
        let id = s(active(&read(&db).unwrap()).unwrap(), "id").to_owned();
        let primary: SocketAddr = primary.parse().unwrap();
        let reserve: SocketAddr = if primary.is_ipv4() {
            "192.0.2.22:2443"
        } else {
            "[2001:db8::22]:2443"
        }
        .parse()
        .unwrap();
        let address_changed = replacement.is_some();
        let before = 1420u16;
        let (after, endpoint, input) = if let Some(replacement) = replacement {
            let endpoint: SocketAddr = replacement.parse().unwrap();
            (before, endpoint, json!({"endpoint":endpoint}))
        } else {
            (1490, reserve, json!({"mtu":1490}))
        };
        let cross_family = primary.is_ipv4() != endpoint.is_ipv4();
        let outer_mtu = if cross_family { 1350 } else { 1400 };
        let effective = |endpoint: SocketAddr| match (cross_family, endpoint.is_ipv4()) {
            (true, true) => 1290,
            (true, false) => 1270,
            (false, _) => 1320,
        };
        edit_document(&db, |doc| {
            for row in doc["servers"].as_array_mut().unwrap() {
                let is_outer = row["id"] == outer_id;
                let is_inner = row["id"] == id;
                let cfg = &mut row["config"];
                if is_outer {
                    cfg["client"]["enabled"] = json!(true);
                    cfg["client"]["rust_managed"] = json!(true);
                    cfg["enabled"] = json!(true);
                } else if is_inner {
                    cfg["mtu"] = json!(before);
                    cfg["endpoint"] = json!(primary);
                    cfg["client"]["double_tunnel_id"] = json!(outer_id);
                    cfg["client"]["double_tunnel_mode"] = json!("permanent");
                    cfg["client"]["endpoint_backups"] = json!([reserve]);
                }
            }
            Ok(())
        })
        .unwrap();
        let (outer_claim, outer) = routed_outer(&read(&db).unwrap(), &id).unwrap();
        let old = Arc::new(AtomicBool::new(true));
        rt.clients
            .up(&db, Some(&id), |_| {
                Ok(Box::new(NestedEditEngine {
                    resumed: false,
                    running: old.clone(),
                    outer: outer.clone(),
                    configured: before,
                    endpoint: reserve,
                    outer_mtu,
                }))
            })
            .unwrap();
        let prior_fp = rt.clients.0.lock().unwrap()[&id].fingerprint;
        let original = read(&db).unwrap();
        let spec = specification(&original, active(&original).unwrap()).unwrap();
        let mark = nested_socket_selector(&spec.iface).unwrap().0;
        let sample = rt.clients.0.lock().unwrap()[&id]
            .tunnel
            .verified_routed_mtu(&spec, Some(&outer), true)
            .unwrap();
        assert_eq!(sample.effective_mtu, effective(primary));
        assert!(rt
            .routing_nested_transport(&db, &spec.iface, primary, mark)
            .is_err());
        let witness = rt
            .routing_nested_transport(&db, &spec.iface, reserve, mark)
            .unwrap()
            .unwrap();
        assert_eq!(witness.peer.endpoint, reserve);
        edit_document(&db, |doc| {
            doc["routing_revision"] = json!(7);
            doc["rust_static_routing"] = json!({"revision":7,"pending_commit":false,"targets":[id],"committed_targets":[id]});
            Ok(())
        }).unwrap();
        let parked_checked = AtomicBool::new(false);
        let parked = |change: &RoutedMtuChange| {
            assert_eq!(change.before, before);
            assert_eq!(change.after, after);
            assert_eq!(change.nested_outer.as_ref(), Some(&outer_claim));
            if address_changed {
                assert!(change.nested_endpoint.is_none());
                assert_eq!(
                    change.endpoint_edit.as_ref().unwrap().sockets()?,
                    (primary, endpoint)
                );
            } else {
                assert!(change.endpoint_edit.is_none());
                assert_eq!(
                    change.nested_endpoint.as_deref(),
                    Some(reserve.to_string().as_str())
                );
            }
            assert_eq!(
                pending_routed_mtu(active(&read(&db)?)?)?.as_ref(),
                Some(change)
            );
            parked_checked.store(true, Ordering::SeqCst);
            Ok(())
        };
        let start = |spec: Spec| {
            assert_eq!(spec.outer.as_ref(), Some(&outer));
            assert_eq!(spec.endpoint.parse::<SocketAddr>().unwrap(), endpoint);
            assert!(spec.permanent);
            assert!(!old.load(Ordering::SeqCst));
            Ok(Box::new(NestedEditEngine {
                resumed: false,
                running: Arc::new(AtomicBool::new(true)),
                outer: outer.clone(),
                configured: after,
                endpoint,
                outer_mtu,
            }) as Box<dyn Tunnel>)
        };
        let validate = |change: &RoutedMtuChange, spec: &Spec, addr: SocketAddr| {
            assert!(address_changed);
            assert_eq!(change.nested_outer.as_ref(), Some(&outer_claim));
            assert_eq!(addr, endpoint);
            assert_eq!(spec.outer.as_ref(), Some(&outer));
            assert!(old.load(Ordering::SeqCst));
            Ok(())
        };
        assert!(rt
            .clients
            .save_config(
                &db,
                &json!({"endpoint":"192.0.2.90:443","mtu":1450}),
                |_| unreachable!(),
                |_| unreachable!(),
                |_, _, _, _| unreachable!(),
                Some(RoutedEditHooks {
                    initial: None,
                    validate: Some(&|_, _, _| unreachable!()),
                    park: &|_| unreachable!(),
                }),
            )
            .is_err());
        assert!(old.load(Ordering::SeqCst));
        rt.clients
            .save_config(
                &db,
                &input,
                |_| {
                    assert!(!address_changed);
                    Err(io::ErrorKind::ConnectionRefused.into())
                },
                |_| Ok(false),
                |_, _, spec, phase| {
                    if phase == EditPreparation::VerifyBeforeRetiring {
                        assert!(address_changed);
                        assert!(parked_checked.load(Ordering::SeqCst));
                        assert_eq!(spec.outer.as_ref(), Some(&outer));
                        assert_eq!(spec.endpoint, endpoint.to_string());
                        assert!(old.load(Ordering::SeqCst));
                        return Err(io::ErrorKind::HostUnreachable.into());
                    }
                    Ok(())
                },
                Some(RoutedEditHooks {
                    initial: None,
                    validate: Some(&validate),
                    park: &parked,
                }),
            )
            .unwrap();
        assert_eq!(old.load(Ordering::SeqCst), address_changed);
        let prior_owner =
            address_changed.then(|| rt.clients.0.lock().unwrap().remove(&id).unwrap());
        let reopened = Store::open(dir.path()).unwrap();
        let rt = Runtime::new(dir.path(), dir.path().join("no-engine"));
        assert!(rt
            .routing_nested_transport(&reopened, &spec.iface, endpoint, mark)
            .unwrap()
            .is_none());
        if let Some(owner) = prior_owner {
            rt.clients.0.lock().unwrap().insert(id.clone(), owner);
        }
        // The first retry starts the desired daemon. A subsequent cold
        // restart still uses the same pinned outer while routes await proof.
        for replay in 0..2 {
            let doc = read(&reopened).unwrap();
            let row = active(&doc).unwrap();
            let change = pending_routed_mtu(row).unwrap().unwrap();
            if address_changed {
                let mut wrong_journal = doc.clone();
                let row = wrong_journal["servers"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|row| row["id"] == id)
                    .unwrap();
                let mut wrong_change = change.clone();
                wrong_change.nested_outer.as_mut().unwrap().peer_key_sha256[0] ^= 1;
                row[PENDING_ROUTED_MTU] = json!(wrong_change);
                let row = active(&wrong_journal).unwrap();
                assert!(check_saved_edit(&wrong_journal, row).is_err());
            }
            assert!(rt.routed_mtu_peer(&reopened, &change).is_err());
            assert!(rt
                .routing_nested_transport(&reopened, &spec.iface, endpoint, mark)
                .unwrap()
                .is_none());
            let mut owned = rt.clients.0.lock().unwrap();
            assert!(rt.routed_mtu_peer(&reopened, &change).is_err());
            assert!(rt
                .routing_nested_transport(&reopened, &spec.iface, endpoint, mark)
                .is_err());
            apply_saved_edit(
                SavedEdit {
                    db: &reopened,
                    doc: &doc,
                    row,
                },
                &mut owned,
                specification(&doc, row).unwrap(),
                |_, _, _, _| Ok(()),
                start,
                Some(&parked),
            )
            .unwrap();
            let current = read(&reopened).unwrap();
            let row = active(&current).unwrap();
            assert!(!routed_mtu_launch_pending(row));
            assert_eq!(pending_routed_mtu(row).unwrap().as_ref(), Some(&change));
            let current_fp = owned[&id].fingerprint;
            owned.get_mut(&id).unwrap().fingerprint = prior_fp;
            drop(owned);
            assert!(rt.routed_mtu_peer(&reopened, &change).is_err());
            assert!(rt
                .routing_nested_transport(&reopened, &spec.iface, endpoint, mark)
                .is_err());
            rt.clients
                .0
                .lock()
                .unwrap()
                .get_mut(&id)
                .unwrap()
                .fingerprint = current_fp;
            let proof = rt.routed_mtu_peer(&reopened, &change).unwrap().unwrap();
            assert_eq!(proof.endpoint, endpoint);
            assert_eq!(proof.effective_mtu, effective(endpoint));
            let witness =
                |peer, mark| rt.routing_nested_transport(&reopened, &spec.iface, peer, mark);
            let attested = witness(endpoint, mark).unwrap().unwrap();
            assert_eq!(attested.peer, proof);
            assert_eq!(
                attested.outer_endpoint,
                "198.51.100.50:4010".parse().unwrap()
            );
            assert!(witness(endpoint, crate::DIRECT_SOCKET_MARK)
                .unwrap()
                .is_none());
            let mut other_port = endpoint;
            other_port.set_port(1);
            assert!(witness(other_port, mark).unwrap().is_none());
            let mut wrong = change.clone();
            wrong.nested_outer.as_mut().unwrap().peer_key_sha256[0] ^= 1;
            assert!(rt.routed_mtu_peer(&reopened, &wrong).is_err());
            if replay == 0 || !cross_family {
                rt.clients.0.lock().unwrap().clear();
            }
        }
        if cross_family {
            let current = read(&reopened).unwrap();
            let change = pending_routed_mtu(active(&current).unwrap())
                .unwrap()
                .unwrap();
            let mut foreign = outer.clone();
            foreign.peer_hex = "aa".repeat(32);
            let set_engine = |engine: Box<dyn Tunnel>| {
                let mut owned = rt.clients.0.lock().unwrap();
                std::mem::replace(&mut owned.get_mut(&id).unwrap().tunnel, engine)
            };
            let current_engine = set_engine(Box::new(NestedEditEngine {
                resumed: false,
                running: Arc::new(AtomicBool::new(true)),
                outer: foreign,
                configured: after,
                endpoint,
                outer_mtu,
            }));
            assert!(rt.routed_mtu_peer(&reopened, &change).is_err());
            assert!(rt
                .routing_nested_transport(&reopened, &spec.iface, endpoint, mark)
                .is_err());
            set_engine(current_engine);
            let edit_mode = |mode| {
                edit_document(&reopened, |doc| {
                    let row = doc["servers"]
                        .as_array_mut()
                        .unwrap()
                        .iter_mut()
                        .find(|row| row["id"] == id)
                        .unwrap();
                    row["config"]["client"]["double_tunnel_mode"] = json!(mode);
                    Ok(())
                })
                .unwrap()
            };
            for mode in ["automatic", "last_resort", "off"] {
                edit_mode(mode);
                assert!(rt
                    .routing_nested_transport(&reopened, &spec.iface, endpoint, mark)
                    .unwrap()
                    .is_none());
            }
            edit_mode("permanent");
            let undo = rt
                .clients
                .save_config(
                    &reopened,
                    &json!({"endpoint":primary}),
                    |spec| {
                        assert_eq!(spec.outer.as_ref(), Some(&outer));
                        assert_eq!(spec.endpoint, primary.to_string());
                        Ok(Box::new(NestedEditEngine {
                            resumed: false,
                            running: Arc::new(AtomicBool::new(true)),
                            outer: outer.clone(),
                            configured: before,
                            endpoint: primary,
                            outer_mtu,
                        }))
                    },
                    |_| unreachable!(),
                    |_, _, spec, _| {
                        assert_eq!(spec.outer.as_ref(), Some(&outer));
                        assert_eq!(spec.endpoint, primary.to_string());
                        Ok(())
                    },
                    Some(RoutedEditHooks {
                        initial: None,
                        validate: Some(&|saved, spec, selected| {
                            assert_eq!(saved, &change);
                            assert_eq!(spec.outer.as_ref(), Some(&outer));
                            assert_eq!(selected, primary);
                            assert_eq!(
                                active(&read(&reopened)?)?["config"]["endpoint"],
                                endpoint.to_string()
                            );
                            Ok(())
                        }),
                        park: &|saved| {
                            let current = read(&reopened)?;
                            let row = active(&current)?;
                            assert_eq!(saved, &change);
                            assert_eq!(pending_routed_mtu(row)?.as_ref(), Some(&change));
                            assert_eq!(row["config"]["endpoint"], primary.to_string());
                            assert_eq!(row["config"]["mtu"], before);
                            assert_eq!(current["routing_revision"], 7);
                            Ok(())
                        },
                    }),
                )
                .unwrap();
            assert!(undo.is_none());
            let proof = rt.routed_mtu_peer(&reopened, &change).unwrap().unwrap();
            assert_eq!(proof.endpoint, primary);
            assert_eq!(proof.effective_mtu, effective(primary));
            assert_eq!(proof.outer_id, outer_id);
            assert_eq!(proof.outer_iface, outer.iface);
        }
        edit_document(&reopened, |doc| {
            let row = doc["servers"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|row| row["id"] == id)
                .unwrap();
            let change = pending_routed_mtu(row)?.unwrap();
            finish_routed_mtu(row, &change)
        })
        .unwrap();
        assert!(
            pending_routed_mtu(active(&read(&reopened).unwrap()).unwrap())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn stale_ssh_form_preserves_enrolled_pin_and_reset_compares_previous_pin() {
        let old = json!({"conn":{"host":"vpn.test","user":"admin","auth_kind":"key","port":22,"known_key":"enrolled"}});
        let mut cfg = old.clone();
        connection(&mut cfg, &json!({"conn":{"port":22}}), &old).unwrap();
        assert_eq!(cfg["conn"]["known_key"], "enrolled");
        assert!(connection(
            &mut cfg,
            &json!({"conn":{"known_key":"","expected_known_key":"stale"}}),
            &old
        )
        .is_err());
        assert_eq!(cfg["conn"]["known_key"], "enrolled");
        connection(
            &mut cfg,
            &json!({"conn":{"known_key":"","expected_known_key":"enrolled"}}),
            &old,
        )
        .unwrap();
        assert_eq!(cfg["conn"]["known_key"], "");
    }
}
