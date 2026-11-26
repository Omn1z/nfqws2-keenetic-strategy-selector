//! Separate genuinely nested-only primaries from ordinary transport claims.
use super::{
    active_replacement::verify_nested_owner,
    boot_id, err,
    mtu_edit::canonical_socket,
    plan,
    transport_claims::{explicit, Claims},
    Kernel, LivePeer, Plan,
};
use nfqws2_awg_profile::{active_replacement_fingerprint, FailoverGraph, RoutedMtuChange};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    io,
    net::{IpAddr, SocketAddr},
};

pub(super) struct Primary {
    id: String,
    pub endpoint: SocketAddr,
    outer_id: String,
    outer_iface: String,
    outer_enabled: bool,
}

pub(super) fn has_permanent_target(doc: &Value, plan: &Plan) -> bool {
    explicit(plan)
        && doc["servers"].as_array().into_iter().flatten().any(|row| {
            row["config"]["client"]["double_tunnel_mode"] == "permanent"
                && plan.targets.values().any(|target| row["id"] == target.id)
        })
}

fn permanent(
    doc: &Value,
    rows: &[Value],
    graph: &FailoverGraph<'_>,
    id: &str,
    iface: &str,
    peer_key: &str,
) -> Option<Primary> {
    let row = rows.iter().find(|row| row["id"] == id)?;
    let cfg = &row["config"];
    if cfg["install"] != "imported"
        || !row["applied_config"].is_null()
        || cfg["enabled"] != true
        || cfg["client"]["enabled"] != true
        || cfg["client"]["rust_managed"] != true
    {
        return None;
    }
    let (outer_id, "permanent") = graph.nested(id)? else {
        return None;
    };
    let outer_enabled = rows.iter().any(|row| {
        row["id"] == outer_id
            && row["config"]["enabled"] == true
            && row["config"]["client"]["enabled"] == true
    });
    let (wire, current_iface, target) = plan::profile(doc, rows, id).ok()?;
    let (_, outer_iface, outer) = plan::profile(doc, rows, outer_id).ok()?;
    if current_iface != iface
        || outer_iface == iface
        || target.public_key != peer_key
        || peer_key.is_empty()
        || outer.public_key.is_empty()
    {
        return None;
    }
    let raw = wire["endpoint"].as_str()?;
    if raw.contains('%') {
        return None;
    }
    let endpoint = canonical_socket(raw.parse().ok()?)?;
    Some(Primary {
        id: id.to_owned(),
        endpoint,
        outer_id: outer_id.to_owned(),
        outer_iface,
        outer_enabled,
    })
}

fn matches_primary(primary: &Primary, row: &Value, socket: Option<SocketAddr>) -> bool {
    row["id"] == primary.id && socket.and_then(canonical_socket) == Some(primary.endpoint)
}

pub(super) fn permanent_primaries(doc: &Value, plan: &Plan) -> BTreeMap<String, Primary> {
    let Some(rows) = doc["servers"].as_array().filter(|_| explicit(plan)) else {
        return BTreeMap::new();
    };
    let Ok(graph) = FailoverGraph::load(doc) else {
        return BTreeMap::new();
    };
    plan.targets
        .iter()
        .filter_map(|(iface, target)| {
            permanent(doc, rows, &graph, &target.id, iface, &target.public_key)
                .map(|primary| (iface.clone(), primary))
        })
        .collect()
}

/// A verified permanent socket may be alive before its first policy owns a
/// payload route. Its marked path is never an authorization for a new flow.
pub(super) fn unselected_permanent_transports(
    k: &Kernel<'_>,
    doc: &Value,
    plan: &Plan,
    claims: &Claims,
    mut peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> Vec<(IpAddr, IpAddr)> {
    let Some(rows) = doc["servers"]
        .as_array()
        .filter(|_| explicit(plan) && !plan.marks.is_empty())
    else {
        return Vec::new();
    };
    let Ok(graph) = FailoverGraph::load(doc) else {
        return Vec::new();
    };
    rows.iter()
        .filter_map(|row| {
            if row["config"]["client"]["double_tunnel_mode"] != "permanent"
                || row["config"]["routing"]["active"] == true
                || row["config"]["enabled"] != true
                || row["config"]["client"]["enabled"] != true
                || row["config"]["client"]["rust_managed"] != true
            {
                return None;
            }
            let id = row["id"].as_str()?;
            let (wire, iface, target) = plan::profile(doc, rows, id).ok()?;
            if plan.targets.contains_key(&iface)
                || plan.targets.values().any(|p| p.id == id)
                || rows.iter().enumerate().any(|(index, other)| {
                    other["id"] != id
                        && ["config", "applied_config"].into_iter().any(|origin| {
                            let config = &other[origin];
                            config.is_object()
                                && config["client_iface"]
                                    .as_str()
                                    .filter(|name| !name.is_empty())
                                    .map_or_else(
                                        || iface == format!("awg{index}"),
                                        |name| name == iface,
                                    )
                        })
                })
            {
                return None;
            }
            let primary = permanent(doc, rows, &graph, id, &iface, &target.public_key)?;
            let ip = primary.endpoint.ip();
            if !primary.outer_enabled
                || !claims.sole_primary(id, primary.endpoint)
                || require_independent_wan(k, ip).is_ok()
            {
                return None;
            }
            let live = peer(wire, &iface).ok()?;
            let native = live.active_replacement_peer.as_deref()?;
            let witnessed = live.nested_transport.as_ref()?;
            if !native.nested_only
                || !native.owner.valid()
                || native.owner.id != id
                || native.owner.iface != iface
                || native.owner.boot != boot_id(k).ok()?
                || native.fingerprint != active_replacement_fingerprint(doc, id).ok()?
                || native.endpoint != primary.endpoint
                || canonical_socket(live.endpoint) != Some(primary.endpoint)
                || canonical_socket(witnessed.peer.endpoint) != Some(primary.endpoint)
                || witnessed.peer.outer_id != primary.outer_id
                || witnessed.peer.outer_iface != primary.outer_iface
                || native.socket_mark != live.socket_mark
                || witnessed.peer.socket_mark != live.socket_mark
                || witnessed.peer.effective_mtu != native.mtu
                || live.nested_mtu != Some(native.mtu)
            {
                return None;
            }
            let outer = verify_nested_owner(k, doc, native).ok()?;
            if outer.endpoint.ip() == ip
                || canonical_socket(witnessed.outer_endpoint) != Some(outer.endpoint)
            {
                return None;
            }
            require_independent_wan(k, outer.endpoint.ip()).ok()?;
            Some((ip, outer.endpoint.ip()))
        })
        .collect()
}

/// The profile manager separately proves this pinned outer before saving and
/// again before releasing the old daemon. This check only classifies claims.
pub(super) fn edit_has_no_direct_claim(
    doc: &Value,
    plan: &Plan,
    change: &RoutedMtuChange,
    selected: IpAddr,
) -> io::Result<bool> {
    let Some(outer) = change.nested_outer.as_ref().filter(|_| explicit(plan)) else {
        return Ok(false);
    };
    let Some(target) = plan
        .targets
        .get(&change.iface)
        .filter(|target| target.id == change.id)
    else {
        return Ok(false);
    };
    let rows = doc["servers"]
        .as_array()
        .ok_or_else(|| err("нет списка серверов AWG"))?;
    let graph = FailoverGraph::load(doc)?;
    let Some(primary) = permanent(
        doc,
        rows,
        &graph,
        &change.id,
        &change.iface,
        &target.public_key,
    ) else {
        return Ok(false);
    };
    if !primary.outer_enabled || primary.outer_id != outer.id || primary.outer_iface != outer.iface
    {
        return Ok(false);
    }
    let mut shared = false;
    plan::visit_endpoints(
        doc,
        true,
        |_| true,
        |row, socket, ip| {
            if ip == selected && !matches_primary(&primary, row, socket) {
                shared = true;
            }
        },
    )?;
    Ok(!shared)
}

impl Primary {
    pub fn verify(
        &self,
        k: &Kernel<'_>,
        row: &Value,
        iface: &str,
        live: &LivePeer,
        configured_mtu: u16,
        requires_ordinary_path: bool,
    ) -> io::Result<u16> {
        let waiting = || err("основной вложенный AWG ожидает подтверждения внешнего маршрута");
        let transport = live.nested_transport.as_ref().ok_or_else(waiting)?;
        let witness = &transport.peer;
        let endpoint = canonical_socket(live.endpoint).ok_or_else(waiting)?;
        let reserve = endpoint != self.endpoint;
        if !self.outer_enabled
            || reserve && !nfqws2_awg_profile::routing_permanent_nested_reserve(row, endpoint)?
            || canonical_socket(witness.endpoint) != Some(endpoint)
            || witness.iface != iface
            || witness.outer_id != self.outer_id
            || witness.outer_iface != self.outer_iface
            || witness.socket_mark != live.socket_mark
            || live.nested_mtu != Some(witness.effective_mtu)
            || !(576..=configured_mtu).contains(&witness.effective_mtu)
            || canonical_socket(transport.outer_endpoint).is_none()
        {
            return Err(waiting());
        }
        plan::verify_nested_path(k, iface, &self.outer_iface, live)?;
        if reserve || requires_ordinary_path {
            require_independent_wan(k, endpoint.ip())?;
        }
        Ok(witness.effective_mtu)
    }
}

pub(super) fn require_independent_wan(k: &Kernel<'_>, address: IpAddr) -> io::Result<()> {
    let family = plan::Family::of(address);
    let route = k.call("ip", &[family.flag(), "route", "get", &address.to_string()])?;
    let device = route
        .lines()
        .next()
        .into_iter()
        .flat_map(str::split_ascii_whitespace)
        .skip_while(|word| *word != "dev")
        .nth(1)
        .ok_or_else(|| err("не подтверждён WAN общего транспортного адреса AWG"))?;
    if nfqws2_awg_profile::physical_wan(&route, address, &[device.to_owned()], None).is_none() {
        return Err(err("не подтверждён WAN общего транспортного адреса AWG"));
    }
    Ok(())
}
