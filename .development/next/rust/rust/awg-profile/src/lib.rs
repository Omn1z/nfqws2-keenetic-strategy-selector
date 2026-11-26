//! Local WireGuard/AmneziaWG profile import and export.
mod client;
pub use client::run_launcher;
pub use client::{
    native_full_reserve_draft,
    active_named_replacement_fingerprint, resolve_active_named_replacement,
    resolve_initial_named_active_replacement,
    validate_active_named_replacement, validate_warm_named_ipv6, verify_warm_named_ipv4_failure,
    active_client_iface,
    active_replacement_allowed, active_replacement_endpoint, active_replacement_fingerprint,
    active_replacement_numeric_pool, active_replacement_startup_binding, ActiveReplacementNumericPool,
    active_replacement_nested_mtu, active_replacement_source, active_replacement_topology,
    active_replacement_transport_stamp, active_replacement_underlay_identity, client_peer,
    disabled_active_replacement_target,
    exact_route_hostname, finish_routed_mtu, inspect_physical_wan, named_reconnect_profile,
    nested_socket_selector, owns_unselected_nested_socket, owns_withdrawn_permanent_socket, pending_routed_mtu,
    persist_active_replacement_locked, physical_wan, read_active_replacement_launch,
    routed_combined_endpoint_mtu_profile, routed_endpoint_initial_pending,
    routed_endpoint_named_allowed, routed_endpoint_predecessor_change,
    routed_endpoint_previous_reserve_allowed, routed_endpoint_retry_pool,
    routed_hostname_addresses, routed_legacy_edit_profile, routed_mtu_launch_pending,
    routed_native_mtu_edit_profile, routed_nested_mtu_edit_profile, routed_permanent_disable_outer, routing_direct_backup_pool,
    routing_direct_literal_pool, routing_permanent_nested_reserve, transport_endpoints,
    ActiveReplacementLaunchLease, ActiveReplacementLaunchMode, ActiveReplacementLaunchPin,
    ActiveReplacementPeer, ActiveReplacementPreparation,
    ActiveReplacementStage, ActiveReplacementUnderlay, ClientRecoveryPass,
    DeleteReplacementPersistenceUncertain, EndpointBackupsPersistenceUncertain, Failover,
    FailoverGraph, NamedReconnectInput, NamedReconnectRequest, NamedReconnectTarget,
    NativeNestedRemovalScope, NativeRemovalSeal, PreparedRoutedEndpointEdit,
    ResolvedNamedReconnect, RoutedDirectBackup, RoutedDirectOutage, RoutedDisable, RoutedEndpointEdit, RoutedEndpointLaunch,
    RoutedEndpointPredecessor, RoutedImplicitMtu, RoutedLegacyPredecessor, RoutedMtuChange,
    RoutedMtuOuter, RoutedMtuPeer, RoutedNestedTransport, RoutedPermanentHold, TransportBypassProof,
    ACTIVE_REPLACEMENT_FIELD, ACTIVE_REPLACEMENT_LAUNCH_FILE, ACTIVE_REPLACEMENT_LAUNCH_LIMIT,
};
mod conf;
pub use conf::effective_protocol_version;
mod deploy;
mod endpoint;
pub use endpoint::resolve_endpoint_addresses;
mod peers;
mod recovery;
mod remote;
pub use peers::{add_peer, add_server, remove_peer, PeerInput};
pub use recovery::{recovery_settings, save_recovery, RecoveryUpdate};
pub mod runtime;
#[cfg(test)]
mod tests;
mod view;
mod vpn;
mod warp;
use nfqws2_store::{new_id, ConfigFile, Store};
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    io,
    time::{SystemTime, UNIX_EPOCH},
};
pub use view::{
    dashboard, dns_routes, fallback_servers, status, status_with_public_refs, DnsRoute,
    FallbackServer,
};
/// A direct AWG UDP socket may use this bit to bypass the packed AWG lookup.
pub const DIRECT_SOCKET_MARK: u32 = 0x2000_0000;
pub use warp::WarpEnrollment;

/// MTU used by Go's local tunnel, including profiles predating the per-server setting.
pub fn tunnel_mtu(profile: &Value, routing: &Value) -> u64 {
    [profile, routing]
        .into_iter()
        .filter_map(|settings| settings["mtu"].as_u64())
        .find(|&mtu| mtu > 0)
        .unwrap_or(1280)
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}
fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or_default()
}
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn defaults() -> Value {
    json!({"active_id":"awg0","servers":[{"id":"awg0","name":"","config":conf::base()}]})
}
const FILE: ConfigFile<Value> = ConfigFile::new("awg.json", defaults, validate);
fn validate_profile(v: &Value) -> io::Result<()> {
    if !v["endpoint"].is_string()
        || !(v["peers"].is_array() || v["conn"].is_object() || v["install"].is_string())
    {
        return Err(invalid("неизвестный формат конфигурации AWG"));
    }
    for key in ["conn", "client", "routing", "obf"] {
        if v.get(key).is_some() && !v[key].is_object() {
            return Err(invalid("неверная структура конфигурации AWG"));
        }
    }
    if !matches!(s(v, "install"), "" | "apt" | "userspace" | "imported")
        || !matches!(s(v, "protocol"), "" | "awg" | "wireguard")
    {
        return Err(invalid("неизвестный тип профиля AWG"));
    }
    Ok(())
}
fn validate(doc: &Value) -> io::Result<()> {
    let Some(servers) = doc.get("servers") else {
        return validate_profile(doc);
    };
    let servers = servers
        .as_array()
        .ok_or_else(|| invalid("неверный список серверов AWG"))?;
    if servers.is_empty()
        && !(doc["routing"].is_object()
            && doc["pending_rules"]
                .as_array()
                .is_some_and(|v| !v.is_empty()))
    {
        return Err(invalid("пустой список подключений AWG"));
    }
    let mut ids = HashSet::new();
    for row in servers {
        if !ids.insert(s(row, "id")) || s(row, "id").is_empty() {
            return Err(invalid("некорректный идентификатор сервера AWG"));
        }
        validate_profile(&row["config"])?;
        if !row["applied_config"].is_null() {
            validate_profile(&row["applied_config"])?;
        }
    }
    Ok(())
}
fn modern(doc: &mut Value) {
    if doc.get("servers").is_none() {
        let legacy = doc.take();
        *doc = json!({"active_id":"awg0","servers":[{"id":"awg0","name":"","config":legacy}]});
    }
}
/// Edit the complete, normalized document under the store's writer lock.
pub fn edit_document<T>(
    db: &Store,
    edit: impl FnOnce(&mut Value) -> io::Result<T>,
) -> io::Result<T> {
    FILE.edit(db, |doc| {
        modern(doc);
        edit(doc)
    })
}
pub fn read(db: &Store) -> io::Result<Value> {
    let (mut v, _) = FILE.inspect(db)?;
    modern(&mut v);
    Ok(v)
}
pub fn edit_document_locked<T>(
    tx: &nfqws2_store::Transaction<'_>,
    edit: impl FnOnce(&mut Value) -> io::Result<T>,
) -> io::Result<T> {
    FILE.edit_locked(tx, |doc| {
        modern(doc);
        edit(doc)
    })
}
fn active(doc: &Value) -> io::Result<&Value> {
    let rows = doc["servers"]
        .as_array()
        .ok_or_else(|| invalid("неверный список серверов AWG"))?;
    rows.iter()
        .find(|r| r["id"] == doc["active_id"])
        .or_else(|| rows.first())
        .ok_or_else(|| invalid("нет выбранного сервера AWG"))
}

/// Use the committed legacy connection when a saved document predates shared routing.
pub fn routing_settings_source(doc: &Value) -> &Value {
    if doc["routing"].is_object() {
        return &doc["routing"];
    }
    let selected = active(doc).ok().map(|row| &row["config"]["routing"]);
    let sources = selected.into_iter().chain(
        doc["servers"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|row| &row["config"]["routing"]),
    );
    sources
        .clone()
        .find(|v| v["active"] == true && v["mode"] != "off")
        .or_else(|| {
            sources.clone().find(|v| {
                v["zones"].as_array().is_some_and(|a| !a.is_empty())
                    || v["mode"]
                        .as_str()
                        .is_some_and(|m| m != "off" && !m.is_empty())
                    || v["killswitch"] == true
                    || v["trace_enabled"] == true
                    || v["sni_routing"] == true
                    || v["domain_source"] == "dnsproxy"
                    || v["mtu"].as_u64().is_some_and(|m| m != 1420 && m > 0)
            })
        })
        .or(selected)
        .unwrap_or(&Value::Null)
}

fn shared_routing_settings(doc: &Value) -> Value {
    let source = routing_settings_source(doc);
    let mode = match s(source, "mode") {
        "" => "off",
        "include" | "exclude" => "zones",
        mode => mode,
    };
    let mtu = source["mtu"].as_u64().filter(|mtu| *mtu > 0).unwrap_or(1420);
    json!({
        "mode": mode,
        "mtu": mtu,
        "killswitch": source["killswitch"] == true,
        "domain_source": if source["domain_source"] == "dnsproxy" { "dnsproxy" } else { "resolve" },
        "sni_routing": source["sni_routing"] == true,
        "trace_enabled": source["trace_enabled"] == true,
    })
}

fn routing_settings_for_profile(doc: &Value) -> Value {
    let mut settings = shared_routing_settings(doc);
    if let Some(saved) = doc["routing"].as_object() {
        // Early Rust files could save only a subset of the global fields.
        // A missing field still belongs to the connection in those files.
        settings
            .as_object_mut()
            .unwrap()
            .retain(|key, _| saved.contains_key(key));
    }
    settings
}

fn apply_shared_routing(cfg: &mut Value, mut settings: Value) {
    let routing = &mut cfg["routing"];
    if routing["mode"] == "exclude" {
        if let Some(zones) = routing["zones"].as_array_mut() {
            for zone in zones {
                if s(zone, "mode").is_empty() && s(zone, "route").is_empty() {
                    zone["mode"] = json!("exclude");
                }
            }
        }
    }
    if let Some(routing) = routing.as_object_mut() {
        routing.append(settings.as_object_mut().unwrap());
    } else {
        *routing = settings;
    }
}

pub fn import(db: &Store, text: &str, name: &str) -> io::Result<()> {
    add_config(db, vpn::parse(text, now())?, name)
}
fn add_config(db: &Store, mut cfg: Value, name: &str) -> io::Result<()> {
    if name.chars().any(char::is_control) || name.len() > 512 {
        return Err(invalid("неверное имя подключения"));
    }
    FILE.edit(db, move |doc| {
        modern(doc);
        apply_shared_routing(&mut cfg, routing_settings_for_profile(doc));
        let rows = doc["servers"].as_array_mut().unwrap();
        let mut used = HashSet::new();
        for (index, row) in rows.iter().enumerate() {
            let iface = s(&row["config"], "client_iface");
            if iface.is_empty() {
                used.insert(format!("awg{index}"));
            } else {
                used.insert(iface.into());
            }
            if let Some(iface) = row["applied_config"]["client_iface"].as_str() {
                used.insert(iface.into());
            }
        }
        let iface = (0u32..)
            .map(|i| format!("awg{i}"))
            .find(|v| !used.contains(v))
            .unwrap();
        cfg["client_iface"] = json!(iface);
        let id = format!("awg-{}", new_id()?);
        rows.push(json!({"id":id,"name":name.trim(),"config":cfg}));
        doc["active_id"] = json!(id);
        Ok(())
    })
}
pub fn select(db: &Store, id: &str) -> io::Result<()> {
    let id = id.trim();
    FILE.edit(db, |doc| {
        modern(doc);
        let shared = routing_settings_for_profile(doc);
        let previous = doc["active_id"].clone();
        let row = doc["servers"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|row| row["id"] == id)
            .ok_or_else(|| invalid("подключение не найдено"))?;
        if previous != id {
            apply_shared_routing(&mut row["config"], shared);
            doc["active_id"] = json!(id);
        }
        Ok(())
    })
}
pub fn rename(db: &Store, id: &str, name: &str) -> io::Result<()> {
    if name.len() > 512 || name.chars().any(char::is_control) {
        return Err(invalid("неверное имя подключения"));
    }
    FILE.edit(db, |doc| {
        modern(doc);
        let row = doc["servers"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|r| r["id"] == id)
            .ok_or_else(|| invalid("подключение не найдено"))?;
        row["name"] = json!(name.trim());
        Ok(())
    })
}
fn wire(row: &Value) -> &Value {
    if row["applied_config"].is_object() {
        &row["applied_config"]
    } else {
        &row["config"]
    }
}
pub fn peer_export(db: &Store, id: &str, format: &str) -> io::Result<(String, String)> {
    let doc = read(db)?;
    let row = active(&doc)?;
    let cfg = wire(row);
    let peer = cfg["peers"]
        .as_array()
        .and_then(|v| v.iter().find(|p| p["id"] == id))
        .ok_or_else(|| invalid("пир не найден"))?;
    let mut stem = String::new();
    let mut separator = false;
    for c in s(peer, "name").chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
            stem.push(c);
            separator = false;
        } else if !separator {
            stem.push('_');
            separator = true;
        }
        if stem.len() >= 100 {
            break;
        }
    }
    let stem = stem.trim_matches(['.', '-', '_']);
    let stem = if stem.is_empty() { "peer" } else { stem };
    let text = conf::export(cfg, peer)?;
    match format.trim().to_ascii_lowercase().as_str() {
        "" | "conf" => Ok((text, format!("{stem}.conf"))),
        "vpn" => {
            let mtu = tunnel_mtu(cfg, &row["config"]["routing"]);
            Ok((vpn::encode(cfg, peer, text, stem, mtu)?, format!("{stem}.vpn")))
        }
        _ => Err(invalid("неизвестный формат экспорта")),
    }
}
