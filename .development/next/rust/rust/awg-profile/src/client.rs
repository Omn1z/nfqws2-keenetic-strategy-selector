//! Local userspace tunnels. Hold a handle only for the foreground engine
//! started by this panel; foreign interfaces and their routing stay upstream.
use super::{active, conf, edit_document, invalid, read, runtime::Runtime, s, view, wire};
use nfqws2_store::Store;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};
use std::{collections::HashMap, io, sync::Mutex};

mod connection_check;
/// Go and Rust reserve a single fwmark and a 72-table range for nested
/// transport sockets. The entire mark must match for both RPDB rules.
pub fn nested_socket_selector(iface: &str) -> io::Result<(u32, u32)> {
    let slot = iface
        .strip_prefix("awg")
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|n| *n < 1 << 28 && iface == format!("awg{n}"))
        .ok_or_else(|| invalid("неверный интерфейс вложенного туннеля"))?;
    Ok((0xa000_0000 | slot, 828 + slot % 72))
}

fn nested_usable(ip: IpAddr) -> bool {
    !ip.is_loopback()
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && match ip {
            IpAddr::V4(v) => !v.is_link_local() && !v.is_broadcast(),
            IpAddr::V6(v) => !v.is_unicast_link_local(),
        }
}

fn validate_nested_scope(
    iface: &str,
    outer: &str,
    endpoint: IpAddr,
    source: IpAddr,
) -> io::Result<()> {
    nested_socket_selector(iface)?;
    nested_socket_selector(outer)?;
    if iface == outer
        || !nested_usable(endpoint)
        || !nested_usable(source)
        || endpoint == source
        || endpoint.is_ipv4() != source.is_ipv4()
    {
        return Err(invalid("повреждена запись маршрутов вложенного AWG"));
    }
    Ok(())
}

pub(in crate::client) fn nested_mtu(cfg: &Value, outer: u64, endpoint: IpAddr) -> io::Result<u64> {
    NestedMtu::from_config(cfg, endpoint)?.effective(outer)
}

#[derive(Clone, Copy)]
struct NestedMtu {
    limit: u64,
    overhead: u64,
}

impl NestedMtu {
    fn from_config(cfg: &Value, endpoint: IpAddr) -> io::Result<Self> {
        let mut overhead = if endpoint.is_ipv4() { 60u64 } else { 80 };
        if cfg["protocol"] != "wireguard" && cfg["traffic_obfuscation"] != false {
            let obf = &cfg["obf"];
            overhead = overhead.saturating_add(obf["s4"].as_u64().unwrap_or_default());
            let padding = obf["content_padding_addition"]
                .as_str()
                .unwrap_or("")
                .trim();
            if !padding.is_empty() {
                overhead = overhead.saturating_add(u64::from(
                    padding
                        .rsplit('-')
                        .next()
                        .unwrap()
                        .trim()
                        .parse::<u16>()
                        .map_err(|_| invalid("неверный ContentPaddingAddition"))?,
                ));
            }
        }
        Ok(Self {
            limit: cfg["mtu"].as_u64().unwrap_or(1420),
            overhead,
        })
    }

    fn effective(self, outer: u64) -> io::Result<u64> {
        let n = outer.saturating_sub(self.overhead).min(self.limit);
        (n >= 576)
            .then_some(n)
            .ok_or_else(|| invalid("недостаточный MTU внешнего туннеля"))
    }
}

pub(in crate::client) struct NestedOuterPeer {
    pub endpoint: Option<SocketAddr>,
    pub socket_mark: u32,
}
mod failover;
mod legacy;
#[cfg(any(target_os = "linux", test))]
mod nested;
pub use failover::{Failover, Graph as FailoverGraph};
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::run_launcher;
#[cfg(not(target_os = "linux"))]
pub fn run_launcher(_: &std::path::Path, _: &str) -> io::Result<()> {
    Err(io::ErrorKind::Unsupported.into())
}
mod removal;
pub use removal::{
    active_named_replacement_fingerprint, resolve_active_named_replacement,
    resolve_initial_named_active_replacement,
    validate_active_named_replacement, validate_warm_named_ipv6, verify_warm_named_ipv4_failure,
    active_replacement_allowed, active_replacement_endpoint, active_replacement_fingerprint,
    active_replacement_numeric_pool, active_replacement_startup_binding, ActiveReplacementNumericPool,
    active_replacement_nested_mtu, active_replacement_source, active_replacement_topology,
    active_replacement_transport_stamp, active_replacement_underlay_identity,
    disabled_active_replacement_target,
    native_full_reserve_draft,
    owns_unselected_nested_socket, persist_active_replacement_locked,
    read_active_replacement_launch, ActiveReplacementLaunchLease, ActiveReplacementLaunchMode,
    ActiveReplacementLaunchPin, ActiveReplacementPeer,
    ActiveReplacementPreparation, ActiveReplacementStage, ActiveReplacementUnderlay,
    DeleteReplacementPersistenceUncertain, NativeNestedRemovalScope, NativeRemovalSeal,
    ACTIVE_REPLACEMENT_FIELD, ACTIVE_REPLACEMENT_LAUNCH_FILE, ACTIVE_REPLACEMENT_LAUNCH_LIMIT,
};
mod settings;
pub use settings::{
    finish_routed_mtu, pending_routed_mtu, routed_combined_endpoint_mtu_profile,
    routed_endpoint_initial_pending, routed_endpoint_named_allowed,
    routed_endpoint_predecessor_change, routed_endpoint_previous_reserve_allowed,
    routed_endpoint_retry_pool, routed_hostname_addresses, routed_legacy_edit_profile,
    routed_mtu_launch_pending, routed_native_mtu_edit_profile, routed_nested_mtu_edit_profile,
    routing_direct_backup_pool, routing_direct_literal_pool, routing_permanent_nested_reserve,
    PreparedRoutedEndpointEdit, RoutedDirectBackup, RoutedEndpointEdit, RoutedEndpointLaunch,
    RoutedEndpointPredecessor, RoutedImplicitMtu, RoutedLegacyPredecessor, RoutedMtuChange,
    RoutedMtuOuter, RoutedMtuPeer, RoutedNestedTransport,
};
mod supervisor;
#[cfg(any(target_os = "linux", test))]
mod transport;
mod wan;
pub use supervisor::{
    named_reconnect_profile, transport_endpoints, ClientRecoveryPass,
    EndpointBackupsPersistenceUncertain, NamedReconnectInput, NamedReconnectRequest,
    NamedReconnectTarget, ResolvedNamedReconnect, TransportBypassProof,
};
pub use wan::{inspect_physical_wan, physical_wan};

type RouteWithdrawal<'a> = dyn Fn(RoutedDisable<'_>) -> io::Result<()> + 'a;

pub(crate) type RefreshTransport<'a> = dyn Fn(TransportBypassProof<'_>) -> io::Result<()> + 'a;

fn resolve_endpoint(text: &str) -> io::Result<std::net::SocketAddr> {
    use std::time::{Duration, Instant};
    crate::endpoint::resolve_client_endpoint(text, Instant::now() + Duration::from_secs(5))
}

#[derive(Default)]
pub(crate) struct Clients(
    Mutex<HashMap<String, Managed>>,
    Mutex<legacy::Pending>,
    Mutex<HashMap<String, (u64, u64, u32)>>,
);
struct Managed {
    tunnel: Box<dyn Tunnel>,
    iface: String,
    fingerprint: [u8; 32],
    recovery: supervisor::Recovery,
}
trait Tunnel: Send {
    fn resumed(&self) -> bool {
        false
    }
    fn is_stopped(&self) -> bool {
        false
    }
    /// Release the panel's handle while preserving the verified running engine.
    fn detach(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn inherited(&self) -> bool {
        false
    }
    #[cfg_attr(not(unix), allow(dead_code))]
    fn matches_response(&self, _: &[u8]) -> bool {
        true
    }
    fn alive(&mut self) -> bool;
    fn stop(&mut self) -> io::Result<()>;
    fn probe(&mut self) -> io::Result<()>;
    fn probe_at(&mut self, endpoint: std::net::SocketAddr) -> io::Result<()> {
        if supervisor::live_transport_endpoint(&self.snapshot()?) != Some(endpoint) {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        self.probe()
    }
    fn snapshot(&self) -> io::Result<Value>;
    fn active_replacement_peer(
        &self,
        _: &Spec,
        _: &Value,
        _: bool,
        _: Option<&NestedOuter>,
    ) -> io::Result<(ActiveReplacementPeer, Option<NestedOuterPeer>)> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn configured_cold_replacement_peer(
        &self,
        _: &Spec,
        _: &Value,
        _: bool,
        _: bool,
    ) -> io::Result<ActiveReplacementPeer> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn go_full_primary_peer(&self, _: &Spec, _: &Value) -> io::Result<ActiveReplacementPeer> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn commit_temporary_replacement(&mut self, _: &NativeRemovalSeal) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn native_removal_seal(&self) -> io::Result<NativeRemovalSeal> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn nested_iface(&self) -> Option<&str> {
        None
    }
    fn verified_routed_mtu(
        &self,
        _: &Spec,
        _: Option<&NestedOuter>,
        _: bool,
    ) -> io::Result<settings::RoutedMtuSample> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn verified_legacy_predecessor(
        &self,
        _: &Spec,
        _: std::net::SocketAddr,
        _: u16,
        _: bool,
    ) -> io::Result<settings::RoutedLegacyPredecessor> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn repair_nested(&mut self) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct NestedOuter {
    iface: String,
    peer_hex: String,
}
impl NestedOuter {
    fn from_spec(spec: &Spec) -> io::Result<Self> {
        use std::fmt::Write;
        let key = spec
            .conf
            .lines()
            .find_map(|l| l.strip_prefix("PublicKey = "))
            .ok_or_else(|| invalid("отсутствует публичный ключ внешнего туннеля"))?;
        let mut peer_hex = String::with_capacity(64);
        for b in conf::key(key, false)? {
            write!(peer_hex, "{b:02x}").unwrap();
        }
        Ok(Self {
            iface: spec.iface.clone(),
            peer_hex,
        })
    }
}
#[derive(Clone)]
struct Spec {
    id: String,
    iface: String,
    conf: String,
    endpoint: String,
    outer: Option<NestedOuter>,
    permanent: bool,
}
#[cfg(any(target_os = "linux", test))]
fn uapi_message(text: &str, endpoint: std::net::SocketAddr) -> io::Result<String> {
    use std::fmt::Write;
    let hex = |v: &str, zero: bool| -> io::Result<String> {
        let mut out = String::with_capacity(64);
        for b in conf::key(v, zero)? {
            write!(&mut out, "{b:02x}").unwrap();
        }
        Ok(out)
    };
    // This text is produced by conf::export and checked by conf::parse;
    // never send configuration hooks, addresses or resolvers to the engine.
    let mut out = String::from("set=1\n");
    for line in text.lines() {
        if line == "[Peer]" {
            out.push_str("replace_peers=true\n");
        }
        let Some((k, v)) = line.split_once(" = ") else {
            continue;
        };
        match k {
            "PrivateKey" | "PublicKey" | "PresharedKey" | "HeaderProtectionKey" => {
                let name = match k {
                    "PrivateKey" => "private_key",
                    "PublicKey" => "public_key",
                    "PresharedKey" => "preshared_key",
                    _ => "header_protection_key",
                };
                writeln!(
                    out,
                    "{name}={}",
                    hex(v, matches!(k, "PresharedKey" | "HeaderProtectionKey"))?
                )
                .unwrap();
            }
            "Endpoint" => writeln!(out, "endpoint={endpoint}").unwrap(),
            "ListenPort" => writeln!(out, "listen_port={v}").unwrap(),
            "PersistentKeepalive" => writeln!(out, "persistent_keepalive_interval={v}").unwrap(),
            "AllowedIPs" => {
                out.push_str("replace_allowed_ips=true\n");
                for ip in v.split(',').map(str::trim) {
                    writeln!(out, "allowed_ip={ip}").unwrap();
                }
            }
            _ => {
                if let Some((_, field)) = conf::EXTENSIONS.iter().find(|(key, _)| *key == k) {
                    let v = if matches!(k, "RandomTrailers" | "DisableCookies") {
                        if v == "on" {
                            "true"
                        } else {
                            "false"
                        }
                    } else {
                        v
                    };
                    writeln!(out, "{field}={v}").unwrap();
                }
            }
        }
    }
    out.push('\n');
    Ok(out)
}
/// Validate an exact route name, preserving case and dropping the optional
/// rule prefix and a single root dot. DNS wire names must never contain ':'.
pub fn exact_route_hostname(raw: &str) -> Option<&str> {
    let raw = match raw.split_once(':') {
        Some((kind, host))
            if kind.eq_ignore_ascii_case("full") || kind.eq_ignore_ascii_case("domain") =>
        {
            host
        }
        Some(_) => return None,
        None => raw,
    };
    let host = raw.strip_suffix('.').unwrap_or(raw);
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    let mut numeric = true;
    for label in host.split('.') {
        let bytes = label.as_bytes();
        if bytes.len() > 63
            || !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
            || !bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return None;
        }
        numeric &= bytes.iter().all(u8::is_ascii_digit)
            || label
                .strip_prefix("0x")
                .or_else(|| label.strip_prefix("0X"))
                .is_some_and(|hex| !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()));
    }
    (!numeric).then_some(host)
}

fn dormant_replacement_id(doc: &Value) -> Option<&str> {
    let owner = &doc["rust_static_routing"];
    let [id] = owner["disabled_replacements"].as_array()?.as_slice() else {
        return None;
    };
    let id = id.as_str()?;
    let revision = doc["routing_revision"].as_u64().filter(|&n| n != 0)?;
    let installed = owner["targets"].as_array()?;
    let committed = owner["committed_targets"].as_array()?;
    let profile = find(doc, id).ok()?;
    (owner["pending_commit"] == false
        && owner["committed_revision"] == revision
        && owner["go_trial"] != true
        && owner["legacy_watchdog"] != true
        && committed.len() <= 1
        && committed.iter().all(|v| v.as_str().is_some_and(|v| v != id))
        && installed.iter().all(|v| committed.contains(v))
        && profile["applied_config"].is_null()
        && profile["config"]["routing"]["active"] == true
        && profile["config"]["client"]["standby"] == false)
        .then_some(id)
}

fn standalone(doc: &Value, cfg: &Value) -> io::Result<()> {
    let routed = |v: &Value, managed: bool| {
        if v["active"] == true && !managed {
            return true;
        }
        match s(v, "mode") {
            "" | "off" | "full" => false,
            "zones" | "include" | "exclude" => v["zones"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|z| z["enabled"] == true)
                .any(|z| {
                    let names = z["domains"].as_array().filter(|a| !a.is_empty());
                    z["waiting_for_connection"] == true
                        || names.is_some_and(|a| {
                            a.iter().any(|s| s.as_str().is_none_or(str::is_empty))
                                || [&doc["routing"], v].iter().any(|c| {
                                    !matches!(
                                        c["domain_source"].as_str(),
                                        None | Some("" | "resolve" | "dnsproxy")
                                    )
                                })
                        })
                        || names.is_none() && z["ips"].as_array().is_none_or(Vec::is_empty)
                        || ["ips", "source_ips"]
                            .iter()
                            .filter_map(|k| z[*k].as_array())
                            .flatten()
                            .any(|address| {
                                address.as_str().is_none_or(|v| {
                                    v.contains(',') || conf::cidrs(v, false).is_err()
                                })
                            })
                }),
            _ => true,
        }
    };
    let dormant = dormant_replacement_id(doc);
    if routed(&doc["routing"], doc["rust_static_routing"].is_object())
        || doc["servers"].as_array().into_iter().flatten().any(|r| {
            let id = s(r, "id");
            // The saved target keeps its intent while its independent
            // carrier is absent. Only the kernel receipt owns payload routes.
            let owns = routes_use(doc, id) || dormant == Some(id);
            routed(&r["config"]["routing"], owns) || routed(&r["applied_config"]["routing"], owns)
        })
    {
        return Err(invalid(
            "этому подключению требуется управление политиками маршрутизации",
        ));
    }
    let c = &cfg["client"];
    if view::warp(cfg) && !(cfg["warp_standard"] == true && cfg["protocol"] == "wireguard") {
        return Err(invalid(
            "этому профилю требуется управление резервными или вложенными туннелями",
        ));
    }
    if !s(c, "double_tunnel_id").is_empty()
        || !matches!(s(c, "double_tunnel_mode"), "" | "off" | "last_resort")
    {
        failover::Graph::load(doc)?;
    }
    Ok(())
}
fn routes_use(doc: &Value, id: &str) -> bool {
    ["targets", "committed_targets"].iter().any(|k| {
        doc["rust_static_routing"][*k]
            .as_array()
            .is_some_and(|ids| ids.iter().any(|v| v == id))
    })
}
pub(crate) fn find<'a>(doc: &'a Value, id: &str) -> io::Result<&'a Value> {
    doc["servers"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|v| v["id"] == id)
        .ok_or_else(|| invalid("подключение не найдено"))
}
fn iface(row: &Value, doc: &Value) -> io::Result<String> {
    configured_iface(row, doc, &row["config"])
}

/// The local device of the selected saved profile.
pub fn active_client_iface(db: &Store) -> io::Result<String> {
    let doc = read(db)?;
    match active(&doc) {
        Ok(row) => iface(row, &doc),
        Err(_) => Ok("awg0".into()),
    }
}

fn configured_iface(row: &Value, doc: &Value, config: &Value) -> io::Result<String> {
    let v = s(config, "client_iface");
    let v = if v.is_empty() {
        let i = doc["servers"]
            .as_array()
            .unwrap()
            .iter()
            .position(|r| r["id"] == row["id"])
            .unwrap();
        format!("awg{i}")
    } else {
        v.to_owned()
    };
    if !v
        .strip_prefix("awg")
        .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        || v.len() >= 16
    {
        return Err(invalid("неверный AWG-интерфейс"));
    }
    Ok(v)
}
pub fn client_peer(cfg: &Value) -> Option<&Value> {
    let peers = cfg["peers"].as_array()?;
    peers
        .iter()
        .find(|p| p["id"] == cfg["client"]["peer_id"])
        .or_else(|| peers.iter().find(|p| p["is_router"] == true))
}
fn specification(doc: &Value, row: &Value) -> io::Result<Spec> {
    saved_specification(doc, row, true)
}
fn enabled_spec_for_release(doc: &Value, row: &Value) -> io::Result<Spec> {
    let mut original = row.clone();
    for key in ["config", "applied_config"] {
        if original[key].is_object() {
            original[key]["enabled"] = true.into();
        }
    }
    saved_specification(doc, &original, false)
}

fn saved_specification(doc: &Value, row: &Value, check_routing: bool) -> io::Result<Spec> {
    let cfg = wire(row);
    // Go's RuntimeConfig overlays the saved local client on the last applied
    // server config. Pending server edits must not replace deployed keys.
    let mut applied;
    let cfg = if row["applied_config"].is_object() {
        applied = cfg.clone();
        for key in ["enabled", "client", "client_iface", "routing"] {
            applied[key] = row["config"][key].clone();
        }
        &applied
    } else {
        cfg
    };
    if check_routing {
        standalone(doc, cfg)?;
    }
    if cfg["enabled"] == false {
        return Err(invalid("подключение выключено"));
    }
    let peer = client_peer(cfg).ok_or_else(|| invalid("сначала добавьте роутер как пир"))?;
    let mtu = crate::tunnel_mtu(cfg, &cfg["routing"]);
    let text = conf::export_with_mtu(cfg, peer, Some(mtu))?;
    // Validate old configuration and all extension combinations before any
    // firmware call, including legacy documents not written by this panel.
    conf::parse(&text, 0)?;
    Ok(Spec {
        id: s(row, "id").to_owned(),
        iface: iface(row, doc)?,
        conf: text,
        endpoint: s(cfg, "endpoint").to_owned(),
        outer: None,
        permanent: cfg["client"]["double_tunnel_mode"] == "permanent",
    })
}
/// Validate the independently enabled direct underlay for a permanent native
/// withdrawal. This pure check does not confer process or socket ownership.
pub fn routed_permanent_disable_outer<'a>(
    doc: &'a Value,
    inner: &str,
) -> io::Result<Option<(&'a str, String)>> {
    let inner_row = find(doc, inner)?;
    let inner_cfg = &inner_row["config"];
    let inner_client = &inner_cfg["client"];
    if inner_client["double_tunnel_mode"] != "permanent" {
        return Ok(None);
    }
    let unsupported = || {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "не подтверждён независимый внешний AWG",
        )
    };
    let rows = doc["servers"].as_array().ok_or_else(unsupported)?;
    let (id, mode) = FailoverGraph::load(doc)?
        .nested(inner)
        .ok_or_else(unsupported)?;
    let outer_row = find(doc, id)?;
    let outer_cfg = &outer_row["config"];
    let outer_client = &outer_cfg["client"];
    let fixed_imported = |row: &Value| -> io::Result<bool> {
        let cfg = &row["config"];
        let client = &cfg["client"];
        Ok(cfg["install"] == "imported"
            && row["applied_config"].is_null()
            && client["standby"] != true
            && client["fallback_tunnel_ids"]
                .as_array()
                .is_none_or(Vec::is_empty)
            && (client["endpoint_backups"].is_null()
                || client["endpoint_backups"]
                    .as_array()
                    .is_some_and(Vec::is_empty))
            && settings::literal_transport(s(cfg, "endpoint")).is_some()
            && !settings::has_saved_edit(row)
            && supervisor::pending_endpoint_restart(row)?.is_none())
    };
    if mode != "permanent"
        || !matches!(s(&inner_cfg["routing"], "mode"), "full" | "zones" | "include" | "exclude")
        || !fixed_imported(inner_row)?
        || !fixed_imported(outer_row)?
        || outer_cfg["enabled"] != true
        || outer_client["enabled"] != true
        || outer_client["rust_managed"] != true
        || !matches!(s(outer_client, "double_tunnel_mode"), "" | "off")
        || !s(outer_client, "double_tunnel_id").is_empty()
        || rows.iter().any(|candidate| {
            candidate["id"] != inner
                && ["config", "applied_config"]
                    .into_iter()
                    .any(|field| candidate[field]["client"]["double_tunnel_id"] == id)
        })
    {
        return Err(unsupported());
    }
    let outer_iface = iface(outer_row, doc)?;
    if outer_iface == iface(inner_row, doc)? {
        return Err(unsupported());
    }
    Ok(Some((id, outer_iface)))
}

/// Recognize a still-live companion between the verified payload withdrawal
/// and exact socket cleanup. This only reads the current native receipt.
pub fn owns_withdrawn_permanent_socket(doc: &Value, id: &str, iface: &str, until: std::time::Instant) -> bool {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (doc, id, iface, until);
        false
    }
    #[cfg(target_os = "linux")]
    {
        let verify = || -> io::Result<bool> {
            let row = find(doc, id)?;
            let client = &row["config"]["client"];
            if client["enabled"] != false || client["rust_managed"] != false {
                return Ok(false);
            }
            let Some((outer, _)) = routed_permanent_disable_outer(doc, id)? else {
                return Ok(false);
            };
            let spec = enabled_spec_for_release(doc, row)?;
            let outer = NestedOuter::from_spec(&specification(doc, find(doc, outer)?)?)?;
            let endpoint = settings::literal_transport(&spec.endpoint)
                .ok_or_else(|| invalid("изменился адрес вложенного AWG"))?;
            if spec.iface != iface {
                return Ok(false);
            }
            linux::owns_nested_socket(std::path::Path::new("/"), &spec, &outer, endpoint, until)
        };
        verify().unwrap_or(false)
    }
}

fn verify_routed_disable_owner(
    managed: &Managed,
    spec: &Spec,
    seal: &NativeRemovalSeal,
    outer: Option<&NestedOuter>,
    connected: bool,
) -> io::Result<settings::RoutedMtuSample> {
    let changed = || invalid("личность отключаемого AWG не подтверждена");
    let fingerprint: [u8; 32] = Sha256::digest(spec.conf.as_bytes()).into();
    if !seal.valid()
        || seal.id != spec.id
        || seal.iface != spec.iface
        || managed.iface != spec.iface
        || managed.fingerprint != fingerprint
        || managed.tunnel.native_removal_seal()? != *seal
    {
        return Err(changed());
    }
    let endpoint = settings::literal_transport(&spec.endpoint).ok_or_else(changed)?;
    let sample = managed.tunnel.verified_routed_mtu(spec, outer, connected)?;
    if sample.endpoint != endpoint || (connected && !sample.connected) {
        return Err(changed());
    }
    let transport = match (&seal.nested, outer) {
        (None, None) => {
            sample.outer_endpoint.is_none()
                && matches!(sample.socket_mark, 0 | super::DIRECT_SOCKET_MARK)
        }
        (Some(saved), Some(outer)) => {
            saved.outer_iface == outer.iface
                && saved.endpoint == endpoint.ip()
                && sample.outer_endpoint.is_some()
                && sample.socket_mark == nested_socket_selector(&spec.iface)?.0
        }
        _ => false,
    };
    if !transport {
        return Err(changed());
    }
    Ok(sample)
}

struct RoutedOuterHold<'a> {
    managed: &'a Managed,
    spec: Spec,
    seal: NativeRemovalSeal,
    configured: NestedOuter,
}

fn routed_outer_hold<'a>(
    doc: &Value,
    owned: &'a HashMap<String, Managed>,
    inner: &NativeRemovalSeal,
) -> io::Result<Option<RoutedOuterHold<'a>>> {
    routed_permanent_disable_outer(doc, &inner.id)?
        .map(|(id, name)| {
            let changed = || invalid("личность внешнего AWG не подтверждена");
            let spec = enabled_spec_for_release(doc, find(doc, id)?)?;
            let managed = owned.get(id).ok_or_else(changed)?;
            let seal = managed.tunnel.native_removal_seal()?;
            if spec.iface != name
                || seal.nested.is_some()
                || inner.boot != seal.boot
                || inner.pid == seal.pid
                || inner.receipt_sha256 == seal.receipt_sha256
            {
                return Err(changed());
            }
            let configured = NestedOuter::from_spec(&spec)?;
            Ok(RoutedOuterHold {
                managed,
                spec,
                seal,
                configured,
            })
        })
        .transpose()
}

fn verify_routed_outer(
    sample: &settings::RoutedMtuSample,
    outer: &RoutedOuterHold<'_>,
) -> io::Result<SocketAddr> {
    let proved = verify_routed_disable_owner(outer.managed, &outer.spec, &outer.seal, None, true)?;
    if sample.outer_endpoint != Some(proved.endpoint) {
        return Err(invalid("внешний транспорт AWG изменился"));
    }
    Ok(proved.endpoint)
}

/// Authenticated surviving native inner and its independently enabled outer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutedPermanentHold {
    pub owner: NativeRemovalSeal,
    pub outer_owner: NativeRemovalSeal,
    pub endpoint: SocketAddr,
    pub outer_endpoint: SocketAddr,
    pub effective_mtu: u16,
}

fn retain_permanent(
    doc: &Value,
    owned: &HashMap<String, Managed>,
    id: &str,
) -> io::Result<RoutedPermanentHold> {
    let unavailable = || invalid("оставшийся вложенный AWG не подтверждён");
    let row = find(doc, id)?;
    let config = &row["config"];
    if config["enabled"] != true
        || config["client"]["enabled"] != true
        || config["client"]["rust_managed"] != true
    {
        return Err(unavailable());
    }
    let managed = owned.get(id).ok_or_else(unavailable)?;
    let spec = enabled_spec_for_release(doc, row)?;
    let owner = managed.tunnel.native_removal_seal()?;
    let outer = routed_outer_hold(doc, owned, &owner)?.ok_or_else(unavailable)?;
    let sample =
        verify_routed_disable_owner(managed, &spec, &owner, Some(&outer.configured), true)?;
    let outer_endpoint = verify_routed_outer(&sample, &outer)?;
    Ok(RoutedPermanentHold {
        owner,
        outer_owner: outer.seal,
        endpoint: sample.endpoint,
        outer_endpoint,
        effective_mtu: sample.effective_mtu,
    })
}

fn retain_direct(
    doc: &Value,
    owned: &HashMap<String, Managed>,
    id: &str,
) -> io::Result<ActiveReplacementPeer> {
    let unavailable = || invalid("не подтверждён независимый резерв AWG");
    let row = find(doc, id)?;
    let config = &row["config"];
    if config["routing"]["active"] != true || config["client"]["standby"] == true {
        return Err(unavailable());
    }
    if s(&config["routing"], "mode") == "full" {
        return retain_go_full_primary(doc, owned, id);
    }
    let expected = active_replacement_fingerprint(doc, id)?;
    let managed = owned.get(id).ok_or_else(unavailable)?;
    let spec = enabled_spec_for_release(doc, row)?;
    let (sample, outer) = managed.tunnel.active_replacement_peer(&spec, config, false, None)?;
    if outer.is_some() || sample.owner.nested.is_some() || sample.fingerprint != expected {
        return Err(unavailable());
    }
    Ok(sample)
}

fn retain_go_full_primary(
    doc: &Value,
    owned: &HashMap<String, Managed>,
    id: &str,
) -> io::Result<ActiveReplacementPeer> {
    let unavailable = || invalid("не подтверждён основной владелец полного туннеля AWG");
    let row = find(doc, id)?;
    let config = &row["config"];
    let client = &config["client"];
    let backups = &client["endpoint_backups"];
    if config["routing"]["mode"] != "full"
        || config["routing"]["active"] != true
        || config["install"] != "imported"
        || client["standby"] == true
        || !s(client, "double_tunnel_id").is_empty()
        || !matches!(s(client, "double_tunnel_mode"), "" | "off")
        || !(backups.is_null() || backups.as_array().is_some_and(Vec::is_empty))
    {
        return Err(unavailable());
    }
    let (iface, endpoint, fingerprint) = active_replacement_underlay_identity(doc, id)?;
    if !endpoint.is_ipv4() {
        return Err(unavailable());
    }
    let managed = owned.get(id).ok_or_else(unavailable)?;
    let spec = enabled_spec_for_release(doc, row)?;
    if !spec.conf.lines().find_map(|line| line.strip_prefix("AllowedIPs = ")).is_some_and(|ips| {
        ips.split(',').map(str::trim).any(|ip| ip == "0.0.0.0/0")
    }) {
        return Err(unavailable());
    }
    let peer = managed.tunnel.go_full_primary_peer(&spec, config)?;
    if peer.owner.iface != iface
        || peer.fingerprint != fingerprint
        || peer.endpoint != endpoint
        || peer.owner.nested.is_some()
        || peer.underlay.is_some()
        || !peer.allowed.iter().any(|grant| grant == "0.0.0.0/0")
    {
        return Err(unavailable());
    }
    Ok(peer)
}

impl Runtime {
    /// Read a known native link without requiring a fresh handshake. The
    /// rule writer independently checks the confirmed Go generation and WAN.
    pub fn routing_go_full_primary(
        &self,
        db: &Store,
        id: &str,
    ) -> io::Result<Option<ActiveReplacementPeer>> {
        let owned = self.clients.0.try_lock().map_err(|_| io::ErrorKind::WouldBlock)?;
        if !owned.contains_key(id) {
            return Ok(None);
        }
        let doc = read(db)?;
        retain_go_full_primary(&doc, &owned, id).map(Some)
    }
}

/// Independently owned primary whose configured peer has no fresh handshake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutedDirectOutage {
    pub owner: NativeRemovalSeal,
    pub endpoint: SocketAddr,
    pub socket_mark: u32,
    pub mtu: u16,
}

fn direct_outage(doc: &Value, owned: &HashMap<String, Managed>, id: &str) -> io::Result<RoutedDirectOutage> {
    let unavailable = || invalid("не подтверждено состояние основного AWG");
    let row = find(doc, id)?;
    let config = &row["config"];
    let client = &config["client"];
    if config["install"] != "imported"
        || config["enabled"] != true
        || client["enabled"] != true
        || client["rust_managed"] != true
        || client["standby"] == true
        || config["routing"]["active"] != true
        || !matches!(s(&config["routing"], "mode"), "zones" | "include" | "exclude")
        || !row["applied_config"].is_null()
        || settings::has_saved_edit(row)
        || supervisor::pending_endpoint_restart(row)?.is_some()
        || !s(client, "double_tunnel_id").is_empty()
        || !matches!(s(client, "double_tunnel_mode"), "" | "off")
        || client["endpoint_backups"].as_array().is_some_and(|items| !items.is_empty())
    {
        return Err(unavailable());
    }
    // The caller has matched the confirmed route dependency chain. This
    // witness is about the original direct engine and its current handshake.
    let managed = owned.get(id).ok_or_else(unavailable)?;
    let spec = enabled_spec_for_release(doc, row)?;
    let owner = managed.tunnel.native_removal_seal()?;
    let observed = verify_routed_disable_owner(managed, &spec, &owner, None, false)?;
    if observed.connected {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    Ok(RoutedDirectOutage {
        owner, endpoint: observed.endpoint, socket_mark: observed.socket_mark, mtu: observed.effective_mtu,
    })
}

/// Exact native lifecycle request. It is issued while the client and
/// deployment guards are held and can only publish the captured row.
pub struct RoutedDisable<'a> {
    row: &'a Value,
    iface: &'a str,
    disable_server: bool,
    owner: Option<NativeRemovalSeal>,
    verify: &'a dyn Fn() -> io::Result<()>,
    retain_permanent: &'a dyn Fn(&str) -> io::Result<RoutedPermanentHold>,
    retain_direct: &'a dyn Fn(&str) -> io::Result<ActiveReplacementPeer>,
    direct_outage: &'a dyn Fn(&str) -> io::Result<RoutedDirectOutage>,
}

impl RoutedDisable<'_> {
    pub fn id(&self) -> &str {
        s(self.row, "id")
    }

    pub fn iface(&self) -> &str {
        self.iface
    }

    pub fn owner(&self) -> Option<&NativeRemovalSeal> {
        self.owner.as_ref()
    }

    pub fn verify_owner(&self) -> io::Result<()> {
        (self.verify)()
    }

    pub fn retain_permanent(&self, id: &str) -> io::Result<RoutedPermanentHold> {
        (self.retain_permanent)(id)
    }

    pub fn retain_direct(&self, id: &str) -> io::Result<ActiveReplacementPeer> {
        (self.retain_direct)(id)
    }

    pub fn confirm_direct_outage(&self, id: &str) -> io::Result<RoutedDirectOutage> {
        (self.direct_outage)(id)
    }

    pub fn prepare(&self, doc: &mut Value) -> io::Result<()> {
        write_enablement(doc, self.id(), self.row, false, self.disable_server.then_some(false))
    }
}

fn set_enabled(
    db: &Store,
    id: &str,
    expected: &Value,
    enabled: bool,
    server: Option<bool>,
) -> io::Result<()> {
    edit_document(db, |doc| write_enablement(doc, id, expected, enabled, server))
}

fn write_enablement(
    doc: &mut Value,
    id: &str,
    expected: &Value,
    enabled: bool,
    server: Option<bool>,
) -> io::Result<()> {
    let current = find(doc, id)?;
    if current != expected {
        return Err(invalid("профиль изменился во время операции"));
    }
    standalone(doc, wire(current))?;
    let row = doc["servers"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|r| r["id"] == id)
        .unwrap();
    for k in ["config", "applied_config"] {
        if row[k].is_object() {
            if let Some(on) = server {
                row[k]["enabled"] = json!(on);
                if !on {
                    row[k]["routing"]["active"] = json!(false);
                }
            }
            row[k]["client"]["enabled"] = json!(enabled);
            row[k]["client"]["rust_managed"] = json!(enabled);
        }
    }
    Ok(())
}
impl Clients {
    fn reconcile_deployed(
        &self,
        db: &Store,
        id: &str,
        start: impl FnOnce(Spec, &Value, &HashMap<String, Managed>) -> io::Result<Box<dyn Tunnel>>,
    ) -> io::Result<()> {
        let mut owned = self
            .0
            .lock()
            .map_err(|_| io::Error::other("менеджер туннелей недоступен"))?;
        let doc = read(db)?;
        let row = find(&doc, id)?;
        if row.get(settings::PENDING_ROUTED_MTU).is_some() && routes_use(&doc, id) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let client = &row["config"]["client"];
        if client["enabled"] != true
            || client["rust_managed"] != true
            || (client["standby"] == true && !owned.contains_key(id))
        {
            return Ok(());
        }
        let spec = specification(&doc, row)?;
        let fingerprint = Sha256::digest(spec.conf.as_bytes()).into();
        let managed = owned.entry(id.to_owned()).or_insert_with(|| Managed {
            tunnel: Box::new(supervisor::Stopped),
            iface: spec.iface.clone(),
            fingerprint,
            recovery: Default::default(),
        });
        if managed.tunnel.alive() {
            if managed.fingerprint == fingerprint && managed.iface == spec.iface {
                return Ok(());
            }
            managed.tunnel.stop()?;
        }
        // The VPS has already switched. Recovery must now retry the confirmed
        // local specification even if the foreground engine cannot start yet.
        managed.tunnel = Box::new(supervisor::Stopped);
        managed.fingerprint = fingerprint;
        managed.iface = spec.iface.clone();
        managed.recovery = Default::default();
        let tunnel = start(spec, &doc, &owned)?;
        owned.get_mut(id).unwrap().tunnel = tunnel;
        Ok(())
    }
    fn up(
        &self,
        db: &Store,
        id: Option<&str>,
        start: impl FnOnce(Spec) -> io::Result<Box<dyn Tunnel>>,
    ) -> io::Result<()> {
        self.up_profile(db, id, false, None, start)
    }
    fn up_profile(
        &self,
        db: &Store,
        id: Option<&str>,
        server: bool,
        expected: Option<&Value>,
        start: impl FnOnce(Spec) -> io::Result<Box<dyn Tunnel>>,
    ) -> io::Result<()> {
        let mut owned = self
            .0
            .lock()
            .map_err(|_| io::Error::other("менеджер туннелей недоступен"))?;
        let doc = read(db)?;
        let row = match id {
            Some(id) => find(&doc, id)?,
            None => active(&doc)?,
        };
        if expected.is_some_and(|previous| previous != row) {
            return Err(invalid("профиль изменился во время восстановления"));
        }
        if row.get(settings::PENDING_ROUTED_MTU).is_some() && routes_use(&doc, s(row, "id")) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let mut candidate = row.clone();
        if server {
            if s(wire(row), "endpoint").is_empty()
                || (wire(row)["install"] != "imported"
                    && wire(row)["deployed_at"].as_u64().unwrap_or(0) == 0)
            {
                return set_enabled(db, s(row, "id"), row, false, Some(true));
            }
            for k in ["config", "applied_config"] {
                if candidate[k].is_object() {
                    candidate[k]["enabled"] = json!(true);
                }
            }
        }
        let spec = specification(&doc, &candidate)?;
        if candidate["config"]["client"]["standby"] == true {
            // Explicitly arm a standby without bringing its TUN up before demand.
            failover::Graph::load(&doc)?;
            return set_enabled(db, &spec.id, row, true, server.then_some(true));
        }
        if candidate["config"]["client"]["fallback_tunnel_ids"]
            .as_array()
            .is_some_and(|v| !v.is_empty())
        {
            failover::Graph::load(&doc)?;
        }
        let fingerprint = Sha256::digest(spec.conf.as_bytes()).into();
        if let Some(running) = owned.get_mut(&spec.id) {
            if running.tunnel.alive() {
                return if running.iface == spec.iface && running.fingerprint == fingerprint {
                    let disabled_native = !running.tunnel.inherited()
                        && row["config"]["client"]["enabled"] == false
                        && row["config"]["client"]["rust_managed"] == false;
                    if server && row["config"]["enabled"] != true || disabled_native {
                        set_enabled(db, &spec.id, row, true, server.then_some(true))
                    } else {
                        Ok(())
                    }
                } else {
                    Err(invalid("активный профиль изменён: сначала отключите его"))
                };
            }
        }
        owned.remove(&spec.id);
        let id = spec.id.clone();
        let iface = spec.iface.clone();
        let mut tunnel = start(spec)?;
        let result = if expected.is_some()
            && !server
            && row["config"]["client"]["rust_managed"] == true
            && row["config"]["client"]["enabled"] == true
        {
            read(db).and_then(|doc| {
                if find(&doc, &id)? == row {
                    Ok(())
                } else {
                    Err(invalid("профиль изменился во время восстановления"))
                }
            })
        } else {
            set_enabled(db, &id, row, true, server.then_some(true))
        };
        if let Err(e) = result {
            if tunnel.resumed() {
                tunnel.detach()?;
            } else {
                tunnel.stop()?;
            }
            return Err(e);
        }
        owned.insert(
            id,
            Managed {
                tunnel,
                iface,
                fingerprint,
                recovery: Default::default(),
            },
        );
        Ok(())
    }
    fn down(&self, db: &Store, present: impl FnOnce(&str) -> io::Result<bool>) -> io::Result<()> {
        self.down_profile(db, None, false, present)
    }
    fn down_profile(
        &self,
        db: &Store,
        id: Option<&str>,
        server: bool,
        present: impl FnOnce(&str) -> io::Result<bool>,
    ) -> io::Result<()> {
        self.down_profile_with_routes(db, id, server, present, None)
    }

    fn down_profile_with_routes(
        &self,
        db: &Store,
        id: Option<&str>,
        server: bool,
        present: impl FnOnce(&str) -> io::Result<bool>,
        withdraw: Option<&RouteWithdrawal<'_>>,
    ) -> io::Result<()> {
        let mut owned = self
            .0
            .lock()
            .map_err(|_| io::Error::other("менеджер туннелей недоступен"))?;
        let doc = read(db)?;
        let row = match id {
            Some(v) => find(&doc, v)?,
            None => active(&doc)?,
        };
        let id = s(row, "id");
        let routed = routes_use(&doc, id);
        if routed && withdraw.is_none() {
            return Err(invalid("сначала снимите маршруты этого подключения"));
        }
        standalone(&doc, wire(row))?;
        let name = iface(row, &doc)?;
        let alive = owned.get_mut(id).is_some_and(|t| t.tunnel.alive());
        if !alive && present(&name)? {
            return Err(invalid("интерфейс управляется другим процессом"));
        }
        if let Some(withdraw) = withdraw.filter(|_| routed) {
            let live = alive.then(|| &owned[id]);
            let client = &row["config"]["client"];
            let disabled = client["enabled"] == false && client["rust_managed"] == false;
            if live.is_none() && !disabled {
                return Err(invalid("не подтверждён работающий владелец AWG"));
            }
            let owner = live
                .map(|current| current.tunnel.native_removal_seal())
                .transpose()?;
            let outer = owner
                .as_ref()
                .map(|inner| routed_outer_hold(&doc, &owned, inner))
                .transpose()?
                .flatten();
            let verify = || {
                let Some((live, owner)) = live.zip(owner.as_ref()) else {
                    return Ok(());
                };
                let spec = enabled_spec_for_release(&doc, row)?;
                let expected_outer = outer.as_ref().map(|hold| &hold.configured);
                let sample =
                    verify_routed_disable_owner(live, &spec, owner, expected_outer, false)?;
                if let Some(outer) = &outer {
                    verify_routed_outer(&sample, outer)?;
                }
                Ok(())
            };
            verify()?;
            withdraw(RoutedDisable {
                row,
                iface: &name,
                disable_server: server,
                owner: owner.clone(),
                verify: &verify,
                retain_permanent: &|selected| retain_permanent(&doc, &owned, selected),
                retain_direct: &|selected| retain_direct(&doc, &owned, selected),
                direct_outage: &|primary| direct_outage(&doc, &owned, primary),
            })?;
            let saved = read(db)?;
            let mut expected = doc.clone();
            write_enablement(&mut expected, id, row, false, server.then_some(false))?;
            if find(&saved, id)? != find(&expected, id)?
                || !saved["rust_static_routing"]["targets"]
                    .as_array()
                    .is_some_and(|ids| ids.iter().all(|value| value != id))
            {
                return Err(invalid(
                    "снятие маршрутов и отключение клиента AWG не подтверждены",
                ));
            }
            verify()?;
        } else {
            set_enabled(db, id, row, false, server.then_some(false))?;
        }
        if let Some(owned) = owned.get_mut(id) {
            owned.tunnel.stop()?;
        }
        owned.remove(id);
        Ok(())
    }

}
impl Runtime {
    pub(crate) fn reconcile_deployed(
        &self,
        db: &Store,
        id: &str,
        wan: &[String],
        refresh: Option<&RefreshTransport<'_>>,
    ) -> io::Result<()> {
        self.clients.reconcile_deployed(db, id, |spec, doc, owned| {
            let inherited = refresh.map(|_| self.capture_inherited_transport(doc, owned, wan));
            self.start_local_prepared(spec, wan, refresh.zip(inherited.as_ref()))
        })
    }
    fn start_local(&self, spec: Spec, wan: &[String]) -> io::Result<Box<dyn Tunnel>> {
        self.start_local_prepared(spec, wan, None)
    }
    fn start_local_prepared(
        &self,
        spec: Spec,
        wan: &[String],
        transport: Option<supervisor::TransportPreparation<'_>>,
    ) -> io::Result<Box<dyn Tunnel>> {
        #[cfg(target_os = "linux")]
        if let Some(tunnel) = linux::resume(self, &spec)? {
            return Ok(tunnel);
        }
        if spec.permanent && spec.outer.is_none() {
            return Ok(Box::new(supervisor::Stopped));
        }
        #[cfg(target_os = "linux")]
        {
            linux::start(self, spec, wan, false, false, transport)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (spec.iface, spec.conf, spec.endpoint, wan, transport);
            Err(invalid(
                "клиент AWG2 поддерживается только на Linux-роутере",
            ))
        }
    }
    /// Serialize a watchdog's peer verification and FIB handoff with local
    /// client changes and deployment. A busy client defers the current tick.
    pub fn with_idle_routing_clients(
        &self,
        update: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        use std::sync::TryLockError;

        let unavailable = || invalid("состояние VPN-клиентов недоступно");
        let _deployment = match self.deployment.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => return Ok(()),
            Err(TryLockError::Poisoned(_)) => return Err(unavailable()),
        };
        let _clients = match self.clients.0.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => return Ok(()),
            Err(TryLockError::Poisoned(_)) => return Err(unavailable()),
        };
        update()
    }

    pub fn client_up(&self, db: &Store, wan: &[String]) -> io::Result<()> {
        self.clients
            .up(db, None, |spec| self.start_local(spec, wan))
    }
    pub fn client_up_with_transport(
        &self,
        db: &Store,
        wan: &[String],
        refresh: impl Fn(TransportBypassProof<'_>) -> io::Result<()>,
    ) -> io::Result<()> {
        let refresh: &RefreshTransport<'_> = &refresh;
        let inherited = self.collect_transport(db, wan, Some(refresh))?;
        self.clients.up(db, None, |spec| {
            self.start_local_prepared(spec, wan, Some(refresh).zip(inherited.as_ref()))
        })
    }
    fn start_temporary(
        &self,
        spec: Spec,
        wan: &[String],
        require_direct_mark: bool,
        transport: Option<supervisor::TransportPreparation<'_>>,
    ) -> io::Result<Box<dyn Tunnel>> {
        if spec.permanent && spec.outer.is_none() {
            return Ok(Box::new(supervisor::Stopped));
        }
        #[cfg(target_os = "linux")]
        {
            linux::start(self, spec, wan, true, require_direct_mark, transport)
        }
        #[cfg(not(target_os = "linux"))]
        {
            if require_direct_mark {
                return Err(io::ErrorKind::Unsupported.into());
            }
            self.start_local_prepared(spec, wan, transport)
        }
    }
    pub fn client_down(&self, db: &Store) -> io::Result<()> {
        self.clients.down(db, |iface| self.present(iface))
    }

    /// The panel holds the route operation gate before lifecycle/store locks.
    /// Only the routed path delegates publication to the verified FIB writer.
    pub fn disable_with_routing(
        &self,
        db: &Store,
        server: Option<&str>,
        withdraw: impl Fn(RoutedDisable<'_>) -> io::Result<()>,
    ) -> io::Result<()> {
        let _deployment = self.deployment_guard()?;
        self.clients.down_profile_with_routes(
            db, server, server.is_some(), |iface| self.present(iface), Some(&withdraw),
        )
    }
    fn present(&self, iface: &str) -> io::Result<bool> {
        for path in [
            self.root.join("sys/class/net").join(iface),
            self.root
                .join("var/run/amneziawg")
                .join(format!("{iface}.sock")),
        ] {
            match path.symlink_metadata() {
                Ok(_) => return Ok(true),
                Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                Err(e) => return Err(e),
            }
        }
        Ok(false)
    }
    pub fn server_enabled(
        &self,
        db: &Store,
        id: &str,
        enabled: bool,
        wan: &[String],
    ) -> io::Result<()> {
        self.server_enabled_inner(db, id, enabled, wan, None)
    }

    pub fn server_enabled_with_transport(
        &self,
        db: &Store,
        id: &str,
        enabled: bool,
        wan: &[String],
        refresh: impl Fn(TransportBypassProof<'_>) -> io::Result<()>,
    ) -> io::Result<()> {
        self.server_enabled_inner(db, id, enabled, wan, Some(&refresh))
    }

    fn server_enabled_inner(
        &self,
        db: &Store,
        id: &str,
        enabled: bool,
        wan: &[String],
        refresh: Option<&RefreshTransport<'_>>,
    ) -> io::Result<()> {
        let _deployment = self.deployment_guard()?;
        if enabled {
            let inherited = self.collect_transport(db, wan, refresh)?;
            self.clients.up_profile(db, Some(id), true, None, |spec| {
                self.start_local_prepared(spec, wan, refresh.zip(inherited.as_ref()))
            })
        } else {
            self.clients
                .down_profile(db, Some(id), true, |iface| self.present(iface))
        }
    }
    pub fn restore_clients(&self, db: &Store, wan: &[String]) -> io::Result<()> {
        self.restore_clients_inner(db, wan, None, None, None)
    }

    pub fn restore_clients_with_transport(
        &self,
        db: &Store,
        wan: &[String],
        refresh: impl Fn(TransportBypassProof<'_>) -> io::Result<()>,
    ) -> io::Result<()> {
        self.restore_clients_inner(db, wan, Some(&refresh), None, None)
    }

    /// Restore durable edits after the caller obtains the routing lock.
    pub fn restore_clients_with_routing(
        &self,
        db: &Store,
        wan: &[String],
        refresh: impl Fn(TransportBypassProof<'_>) -> io::Result<()>,
        park: impl Fn(&RoutedMtuChange) -> io::Result<()>,
    ) -> io::Result<()> {
        let _deployment = self.deployment_guard()?;
        self.restore_clients_inner(db, wan, Some(&refresh), Some(&park), None)
    }

    pub fn restore_clients_with_routing_retry(
        &self,
        db: &Store,
        wan: &[String],
        refresh: impl Fn(TransportBypassProof<'_>) -> io::Result<()>,
        park: impl Fn(&RoutedMtuChange) -> io::Result<()>,
        read_retry: impl Fn(&RoutedMtuChange) -> io::Result<Option<std::net::SocketAddr>>,
        prepare_retry: impl Fn(&RoutedMtuChange, std::net::SocketAddr) -> io::Result<()>,
    ) -> io::Result<()> {
        self.restore_clients_with_routing_endpoint_launch(
            db,
            wan,
            refresh,
            park,
            |change| read_retry(change).map(RoutedEndpointLaunch::from_pin),
            prepare_retry,
        )
    }

    pub fn restore_clients_with_routing_endpoint_launch(
        &self,
        db: &Store,
        wan: &[String],
        refresh: impl Fn(TransportBypassProof<'_>) -> io::Result<()>,
        park: impl Fn(&RoutedMtuChange) -> io::Result<()>,
        read_retry: impl Fn(&RoutedMtuChange) -> io::Result<RoutedEndpointLaunch>,
        prepare_retry: impl Fn(&RoutedMtuChange, std::net::SocketAddr) -> io::Result<()>,
    ) -> io::Result<()> {
        let _deployment = self.deployment_guard()?;
        self.restore_clients_inner(
            db,
            wan,
            Some(&refresh),
            Some(&park),
            Some(settings::RoutedRetryHooks {
                read: &read_retry,
                prepare: &prepare_retry,
            }),
        )
    }

    fn restore_clients_inner(
        &self,
        db: &Store,
        wan: &[String],
        refresh: Option<&RefreshTransport<'_>>,
        park: Option<&settings::ParkRoutedMtu<'_>>,
        retry: Option<settings::RoutedRetryHooks<'_>>,
    ) -> io::Result<()> {
        let mut failures = self.recover_saved_edits(db, wan, refresh, park, retry)?;
        let doc = read(db)?;
        let inherited = self.collect_transport(db, wan, refresh)?;
        let start = |spec| self.start_local_prepared(spec, wan, refresh.zip(inherited.as_ref()));
        if cfg!(target_os = "linux") && self.root == std::path::Path::new("/") {
            self.restore_legacy(
                db,
                &doc,
                true,
                |spec| self.legacy_presence(spec),
                start,
                &mut failures,
            )?;
        }
        for row in doc["servers"].as_array().into_iter().flatten() {
            let client = &row["config"]["client"];
            #[cfg(target_os = "linux")]
            if row["config"]["enabled"] != true || client["enabled"] != true {
                if let Err(e) = self.stop_disabled_receipt(&doc, row) {
                    failures.push(e.to_string());
                }
                continue;
            }
            if client["rust_managed"] == true
                && row["config"]["enabled"] == true
                && client["enabled"] == true
            {
                if settings::has_saved_edit(row) {
                    continue;
                }
                if client["standby"] == true {
                    #[cfg(target_os = "linux")]
                    if let Err(e) = self.resume_standby(&doc, row) {
                        failures.push(e.to_string());
                    }
                    continue;
                }
                if let Err(e) =
                    self.clients
                        .up_profile(db, Some(s(row, "id")), false, Some(row), start)
                {
                    self.retry_restore(&doc, row, &e);
                    failures.push(e.to_string());
                }
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(invalid(&failures.join(". ")))
        }
    }
    #[cfg(target_os = "linux")]
    fn stop_disabled_receipt(&self, doc: &Value, row: &Value) -> io::Result<()> {
        let name = iface(row, doc)?;
        if !linux::has_receipt(&self.root, &name, s(row, "id"))? {
            return Ok(());
        }
        let spec = Self::spec_for_release(doc, row)?;
        let previous = settings::previous_fingerprint(row)?;
        if let Some(mut managed) = linux::resume_after_edit(self, &spec, previous)? {
            managed.tunnel.stop()?;
        }
        Ok(())
    }
    fn spec_for_release(doc: &Value, row: &Value) -> io::Result<Spec> {
        enabled_spec_for_release(doc, row)
    }
    /// Explicit installer rollback or uninstall, after the HTTP service exited.
    pub fn release_detached_clients(&self, db: &Store) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let claims = linux::owned_interfaces(&self.root)?;
            if claims.is_empty() {
                return Ok(());
            }
            let doc = read(db)?;
            let mut specs = Vec::new();
            for (id, iface) in claims {
                let row = find(&doc, &id)?;
                let spec = Self::spec_for_release(&doc, row)?;
                if spec.iface != iface {
                    return Err(invalid("профиль сохранённого AWG-процесса изменился"));
                }
                let previous = settings::previous_fingerprint(row)?;
                if let Some(mut managed) = linux::resume_after_edit(self, &spec, previous)? {
                    managed.tunnel.detach()?;
                    specs.push((spec, previous));
                }
            }
            for (spec, previous) in specs {
                if let Some(mut managed) = linux::resume_after_edit(self, &spec, previous)? {
                    managed.tunnel.stop()?;
                }
            }
            if !linux::owned_interfaces(&self.root)?.is_empty() {
                return Err(invalid("остались занятые процессы AWG"));
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = db;
        Ok(())
    }
    #[cfg(target_os = "linux")]
    fn resume_standby(&self, doc: &Value, row: &Value) -> io::Result<()> {
        let spec = saved_specification(doc, row, false)?;
        let mut managed = self
            .clients
            .0
            .lock()
            .map_err(|_| invalid("менеджер туннелей недоступен"))?;
        if let std::collections::hash_map::Entry::Vacant(slot) = managed.entry(spec.id.clone()) {
            if let Some(tunnel) = linux::resume(self, &spec)? {
                slot.insert(Managed {
                    tunnel,
                    iface: spec.iface,
                    fingerprint: Sha256::digest(spec.conf.as_bytes()).into(),
                    recovery: Default::default(),
                });
            }
        }
        Ok(())
    }
    /// Keep verified engines and their current handshakes across panel restarts.
    pub fn shutdown_clients(&self) -> io::Result<()> {
        let mut owned = self
            .clients
            .0
            .lock()
            .map_err(|_| io::Error::other("менеджер туннелей недоступен"))?;
        let mut first = None;
        for (_, mut managed) in owned.drain() {
            if let Err(e) = managed.tunnel.detach() {
                first.get_or_insert(e);
            }
        }
        drop(owned);
        let remote = self.remote.join();
        first.map_or(remote, Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    struct Mock(Arc<AtomicBool>);
    impl Tunnel for Mock {
        fn alive(&mut self) -> bool {
            self.0.load(Ordering::SeqCst)
        }
        fn stop(&mut self) -> io::Result<()> {
            self.0.store(false, Ordering::SeqCst);
            Ok(())
        }
        fn probe(&mut self) -> io::Result<()> {
            Ok(())
        }
        fn snapshot(&self) -> io::Result<Value> {
            Ok(json!({}))
        }
    }

    #[test]
    fn routed_disable_stops_only_the_sealed_native_owner_after_disabled_commit() {
        struct Retiring {
            owner: NativeRemovalSeal,
            endpoint: SocketAddr,
            db: Store,
            stopped: Arc<AtomicBool>,
        }
        impl Tunnel for Retiring {
            fn alive(&mut self) -> bool {
                !self.stopped.load(Ordering::SeqCst)
            }
            fn stop(&mut self) -> io::Result<()> {
                let saved = read(&self.db)?;
                assert_eq!(find(&saved, &self.owner.id)?["config"]["client"]["enabled"], false);
                self.stopped.store(true, Ordering::SeqCst);
                Ok(())
            }
            fn probe(&mut self) -> io::Result<()> {
                panic!("disable must not initiate transport")
            }
            fn snapshot(&self) -> io::Result<Value> {
                Ok(Value::Null)
            }
            fn native_removal_seal(&self) -> io::Result<NativeRemovalSeal> {
                Ok(self.owner.clone())
            }
            fn verified_routed_mtu(
                &self, spec: &Spec, outer: Option<&NestedOuter>, connected: bool,
            ) -> io::Result<settings::RoutedMtuSample> {
                assert_eq!(spec.id, self.owner.id);
                assert_eq!(spec.iface, self.owner.iface);
                assert!(outer.is_none() && !connected);
                Ok(settings::RoutedMtuSample {
                    endpoint: self.endpoint,
                    effective_mtu: 1280,
                    socket_mark: 0,
                    connected: false,
                    outer_endpoint: None,
                })
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        crate::import(&db, &crate::tests::input(), "branch").unwrap();
        let rt = Runtime::new(dir.path(), dir.path().join("unused"));
        let stopped = Arc::new(AtomicBool::new(false));
        rt.clients.up(&db, None, |spec| {
            Ok(Box::new(Retiring {
                owner: NativeRemovalSeal {
                    id: spec.id,
                    iface: spec.iface,
                    boot: "12121212-1212-1212-1212-121212121212".into(),
                    pid: 4242,
                    started: 7,
                    receipt_sha256: [0xb4; 32],
                    nested: None,
                },
                endpoint: spec.endpoint.parse().unwrap(),
                db: db.clone(),
                stopped: stopped.clone(),
            }))
        }).unwrap();
        let id = edit_document(&db, |doc| {
            let id = s(active(doc)?, "id").to_string();
            doc["rust_static_routing"] = json!({"targets":[id], "committed_targets":[id]});
            Ok(id)
        }).unwrap();
        let verify = |request: RoutedDisable<'_>| -> io::Result<()> {
            assert_eq!(request.id(), id);
            assert_eq!(request.owner().unwrap().pid, 4242);
            assert_eq!(active(&read(&db)?)?["config"]["client"]["enabled"], true);
            assert!(!stopped.load(Ordering::SeqCst));
            Err(io::ErrorKind::BrokenPipe.into())
        };
        assert_eq!(rt.disable_with_routing(&db, None, verify).unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert!(!stopped.load(Ordering::SeqCst));
        assert_eq!(active(&read(&db).unwrap()).unwrap()["config"]["client"]["enabled"], true);
        assert!(rt.disable_with_routing(&db, None, |_| Ok(())).is_err());
        assert!(!stopped.load(Ordering::SeqCst));
        rt.disable_with_routing(&db, None, |request| {
            request.verify_owner()?;
            assert!(rt.clients.0.try_lock().is_err());
            db.transaction(|tx| crate::edit_document_locked(tx, |doc| {
                request.prepare(doc)?;
                doc["rust_static_routing"]["targets"] = json!([]);
                Ok(())
            }))
        }).unwrap();
        assert!(stopped.load(Ordering::SeqCst));
        rt.disable_with_routing(&db, Some(&id), |request| {
            assert!(request.owner().is_none());
            db.transaction(|tx| crate::edit_document_locked(tx, |doc| request.prepare(doc)))
        }).unwrap();
        assert_eq!(active(&read(&db).unwrap()).unwrap()["config"]["enabled"], false);
    }


    #[test]
    fn routed_permanent_full_disable_retires_inner_owner_without_stopping_outer() {
        struct Native {
            seal: NativeRemovalSeal,
            endpoint: SocketAddr,
            outer_sample: Option<SocketAddr>,
            live: Arc<AtomicBool>,
            db: Store,
        }
        impl Tunnel for Native {
            fn alive(&mut self) -> bool {
                self.live.load(Ordering::SeqCst)
            }
            fn stop(&mut self) -> io::Result<()> {
                assert!(self.seal.nested.is_some(), "independent outer was stopped");
                let doc = read(&self.db)?;
                assert_eq!(
                    find(&doc, &self.seal.id)?["config"]["client"]["enabled"],
                    false
                );
                self.live.store(false, Ordering::SeqCst);
                Ok(())
            }
            fn probe(&mut self) -> io::Result<()> {
                panic!("retirement began new traffic")
            }
            fn snapshot(&self) -> io::Result<Value> {
                Ok(Value::Null)
            }
            fn native_removal_seal(&self) -> io::Result<NativeRemovalSeal> {
                Ok(self.seal.clone())
            }
            fn verified_routed_mtu(
                &self,
                spec: &Spec,
                outer: Option<&NestedOuter>,
                connected: bool,
            ) -> io::Result<settings::RoutedMtuSample> {
                assert_eq!(spec.iface, self.seal.iface);
                assert_eq!(spec.id, self.seal.id);
                if !self.live.load(Ordering::SeqCst) {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                let socket_mark = if let Some(expected) = outer {
                    assert_eq!(
                        self.seal.nested.as_ref().unwrap().outer_iface,
                        expected.iface
                    );
                    nested_socket_selector(&spec.iface)?.0
                } else {
                    assert!(connected && self.seal.nested.is_none());
                    0
                };
                Ok(settings::RoutedMtuSample {
                    endpoint: self.endpoint,
                    effective_mtu: 1290,
                    socket_mark,
                    connected: true,
                    outer_endpoint: self.outer_sample,
                })
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        crate::import(&db, &crate::tests::input(), "inner").unwrap();
        crate::import(&db, &crate::tests::input(), "outer").unwrap();
        let inner_endpoint: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let outer_endpoint: SocketAddr = "192.0.2.44:443".parse().unwrap();
        let (inner, outer) = edit_document(&db, |doc| {
            let rows = doc["servers"].as_array_mut().unwrap();
            let inner = rows.iter().find(|r| r["name"] == "inner").unwrap()["id"]
                .as_str()
                .unwrap()
                .to_string();
            let outer = rows.iter().find(|r| r["name"] == "outer").unwrap()["id"]
                .as_str()
                .unwrap()
                .to_string();
            for row in rows {
                if row["id"] == inner {
                    row["config"]["endpoint"] = inner_endpoint.to_string().into();
                    row["config"]["routing"] = json!({"mode":"full"});
                    row["config"]["client"]["double_tunnel_mode"] = "permanent".into();
                    row["config"]["client"]["double_tunnel_id"] = json!(outer);
                } else if row["id"] == outer {
                    row["config"]["endpoint"] = outer_endpoint.to_string().into();
                    row["config"]["routing"] = json!({"mode":"off"});
                }
            }
            doc["routing"] = json!({"mode":"full"});
            doc["active_id"] = json!(inner);
            Ok((inner, outer))
        })
        .unwrap();
        let rt = Runtime::new(dir.path(), dir.path().join("unused"));
        let outer_live = Arc::new(AtomicBool::new(true));
        let inner_live = Arc::new(AtomicBool::new(true));
        let outer_iface = iface(
            find(&read(&db).unwrap(), &outer).unwrap(),
            &read(&db).unwrap(),
        )
        .unwrap();
        for (id, nested, endpoint, live, pid) in [
            (&outer, None, outer_endpoint, outer_live.clone(), 4243),
            (
                &inner,
                Some(NativeNestedRemovalScope {
                    outer_iface: outer_iface.clone(),
                    endpoint: inner_endpoint.ip(),
                    source: "198.18.92.2".parse().unwrap(),
                }),
                inner_endpoint,
                inner_live.clone(),
                4244,
            ),
        ] {
            rt.clients
                .up(&db, Some(id), |spec| {
                    Ok(Box::new(Native {
                        seal: NativeRemovalSeal {
                            id: spec.id,
                            iface: spec.iface,
                            boot: "12121212-1212-1212-1212-121212121212".into(),
                            pid,
                            started: 7,
                            receipt_sha256: [pid as u8; 32],
                            nested,
                        },
                        endpoint,
                        outer_sample: (id == &inner).then_some(outer_endpoint),
                        live,
                        db: db.clone(),
                    }))
                })
                .unwrap();
        }
        edit_document(&db, |doc| {
            doc["rust_static_routing"] = json!({"targets":[inner], "committed_targets":[inner]});
            Ok(())
        })
        .unwrap();
        outer_live.store(false, Ordering::SeqCst);
        assert!(rt
            .disable_with_routing(&db, None, |_| panic!("unproved outer reached writer"))
            .is_err());
        assert!(inner_live.load(Ordering::SeqCst));
        outer_live.store(true, Ordering::SeqCst);
        {
            let doc = read(&db).unwrap();
            let owned = rt.clients.0.lock().unwrap();
            let proof = retain_permanent(&doc, &owned, &inner).unwrap();
            assert_eq!(proof.owner.id, inner);
            assert_eq!(proof.outer_owner.id, outer);
            assert_eq!(proof.outer_endpoint, outer_endpoint);
        }
        let outer_before = find(&read(&db).unwrap(), &outer).unwrap().clone();
        rt.disable_with_routing(&db, Some(&inner), |request| {
            request.verify_owner()?;
            assert_eq!(
                request
                    .owner()
                    .unwrap()
                    .nested
                    .as_ref()
                    .unwrap()
                    .outer_iface,
                outer_iface
            );
            assert!(outer_live.load(Ordering::SeqCst));
            db.transaction(|tx| {
                crate::edit_document_locked(tx, |doc| {
                    request.prepare(doc)?;
                    doc["rust_static_routing"]["targets"] = json!([]);
                    Ok(())
                })
            })
        })
        .unwrap();
        assert!(!inner_live.load(Ordering::SeqCst));
        assert!(outer_live.load(Ordering::SeqCst));
        assert_eq!(find(&read(&db).unwrap(), &outer).unwrap(), &outer_before);
    }

    #[test]
    fn routing_watchdog_defers_while_a_client_or_deployment_operation_is_running() {
        let dir = tempfile::tempdir().unwrap();
        let rt = Runtime::new(dir.path(), dir.path().join("missing"));
        let must_not_run = || -> io::Result<()> { panic!("watchdog raced a client operation") };
        {
            let _busy = rt.deployment_guard().unwrap();
            rt.with_idle_routing_clients(must_not_run).unwrap();
        }
        {
            let _busy = rt.clients.0.lock().unwrap();
            rt.with_idle_routing_clients(must_not_run).unwrap();
        }
        rt.with_idle_routing_clients(|| {
            assert!(rt.deployment.try_lock().is_err());
            assert!(rt.clients.0.try_lock().is_err());
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn exact_a_record_routing_allows_owned_clients_for_bare_and_full_names() {
        assert_eq!(
            exact_route_hostname("fUlL:VPN_app.Keenetic."),
            Some("VPN_app.Keenetic")
        );
        assert_eq!(
            exact_route_hostname("DoMaIn:VPN_app.Keenetic."),
            Some("VPN_app.Keenetic")
        );
        assert_eq!(
            exact_route_hostname("vpn-app.branch"),
            Some("vpn-app.branch")
        );
        let mut doc = json!({"routing":{"mode":"zones","domain_source":"resolve"},"rust_static_routing":{"targets":["p"]},"servers":[{"id":"p","config":{"routing":{"mode":"zones","active":true,"zones":[{"enabled":true,"domains":["FULL:EXAMPLE.TEST.","example.test"],"include_subdomains":false}]}}}]});
        assert!(standalone(&doc, &doc["servers"][0]["config"]).is_ok());
        doc["routing"]["domain_source"] = json!("dnsproxy");
        doc["servers"][0]["config"]["routing"]["zones"][0]["domains"] = json!(["*.example.test"]);
        doc["servers"][0]["config"]["routing"]["zones"][0]["ips"] = json!(["2001:db8::/48"]);
        doc["servers"][0]["config"]["routing"]["zones"][0]["source_ips"] = json!(["fd12:3456::c"]);
        assert!(standalone(&doc, &doc["servers"][0]["config"]).is_ok());
        doc["servers"][0]["config"]["routing"]["zones"][0]["ips"] = json!(["2001:db8::/129"]);
        assert!(standalone(&doc, &doc["servers"][0]["config"]).is_err());
        for entry in [
            "*.example.test",
            "regexp:example.test",
            "127.0.1",
            "0x7f000001",
            "bad.test..",
            "-bad.test",
            "bad-.test",
            "_bad.test",
            "bad_.test",
            " app.test",
            "full:full:app.test",
        ] {
            assert!(exact_route_hostname(entry).is_none());
        }
    }
    #[test]
    fn dormant_replacement_allows_a_native_start_without_claiming_routes() {
        let doc = json!({
            "routing_revision": 5,
            "routing":{"mode":"zones"},
            "rust_static_routing":{
                "targets":["held"],"committed_targets":["held"],"pending_commit":false,
                "committed_revision":5,"disabled_replacements":["target"]
            },
            "servers":[{"id":"target","config":{
                "client":{"enabled":false,"standby":false},
                "routing":{"mode":"zones","active":true,"zones":[{"enabled":true,"ips":["192.0.2.5/32"]}]}
             }},{"id":"held","config":{"routing":{"mode":"zones","active":true}}}]
        });
        let run = |doc: &Value| standalone(doc, &doc["servers"][0]["config"]);
        assert!(run(&doc).is_ok());
        assert!(!routes_use(&doc, "target"));
        let mut suspended = doc.clone();
        suspended["rust_static_routing"]["targets"] = json!([]);
        assert!(run(&suspended).is_ok());
        let mut stale = doc.clone();
        stale["routing_revision"] = json!(6);
        assert!(run(&stale).is_err());
        let mut foreign = doc.clone();
        foreign["rust_static_routing"]["disabled_replacements"] = json!(["other"]);
        assert!(run(&foreign).is_err());
        let mut pending = doc;
        pending["rust_static_routing"]["pending_commit"] = json!(true);
        assert!(run(&pending).is_err());
    }

    #[test]
    fn local_client_can_start_under_owned_static_policy_and_rejects_foreign_active_routes() {
        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        crate::import(&db, &crate::tests::input(), "branch").unwrap();
        edit_document(&db, |d| {
            let id = active(d)?["id"].clone();
            d["rust_static_routing"] = json!({"targets":[id]});
            d["routing"] = json!({"mode":"zones","killswitch":true,"sni_routing":true});
            d["servers"][1]["config"]["routing"] = json!({"mode":"zones","active":true,"sni_routing":true,"zones":[
                {"route":"direct","enabled":true,"ips":["10.0.0.2"]},
                {"route":"tunnel","enabled":true,"ips":["10.0.0.0/24"],"source_ips":["192.168.1.0/24"],"fallback_tunnel_ids":["backup"]}
            ]});
            Ok(())
        }).unwrap();
        Clients::default()
            .up(&db, None, |_| {
                Ok(Box::new(Mock(Arc::new(AtomicBool::new(true)))))
            })
            .unwrap();
        let mut doc = read(&db).unwrap();
        doc["rust_static_routing"] = Value::Null;
        assert!(standalone(&doc, wire(active(&doc).unwrap())).is_err());
    }
    #[test]
    fn uapi_sets_exact_wire_values_and_separates_interface_metadata() {
        let conf = crate::tests::input().replace("DNS =", "RandomTrailers = on\nS3 = 16\nDNS =");
        let cfg = crate::conf::parse(&conf, 0).unwrap();
        let text = crate::conf::export(&cfg, &cfg["peers"][0]).unwrap();
        let req = uapi_message(&text, "192.0.2.70:77".parse().unwrap()).unwrap();
        assert!(req.starts_with(&format!("set=1\nprivate_key={}\n", "07".repeat(32))));
        assert!(req.contains(&format!("public_key={}\n", "0b".repeat(32))));
        assert!(req.contains("random_trailers=true\n"));
        assert!(req.contains("s3=16\n"));
        assert!(req.contains("endpoint=192.0.2.70:77\n"));
        assert!(req.contains("persistent_keepalive_interval=0\n"));
        assert!(req.contains("allowed_ip=0.0.0.0/0\nallowed_ip=::/0\n"));
        assert!(req.ends_with("\n\n"));
        assert!(!req.contains("DNS") && !req.contains("Address"));
    }
    #[test]
    fn up_down_are_owned_serialized_and_save_only_after_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        crate::import(&db, &crate::tests::input(), "one").unwrap();
        let clients = Clients::default();
        let live = Arc::new(AtomicBool::new(true));
        assert!(clients
            .up(&db, None, |_| Err(invalid("mock failure")))
            .is_err());
        let doc = read(&db).unwrap();
        assert_eq!(active(&doc).unwrap()["config"]["client"]["enabled"], false);
        clients
            .up(&db, None, |s| {
                assert_eq!(s.iface, "awg1");
                Ok(Box::new(Mock(live.clone())))
            })
            .unwrap();
        clients
            .up(&db, None, |_| panic!("already running"))
            .unwrap();
        let doc = read(&db).unwrap();
        assert_eq!(active(&doc).unwrap()["config"]["client"]["enabled"], true);
        clients.down(&db, |_| panic!("owned")).unwrap();
        assert!(!live.load(Ordering::SeqCst));
        assert!(clients.down(&db, |_| Ok(true)).is_err());
        let before = read(&db).unwrap();
        live.store(true, Ordering::SeqCst);
        assert!(clients
            .up(&db, None, |_| {
                crate::rename(&db, s(active(&before).unwrap(), "id"), "moved")?;
                Ok(Box::new(Mock(live.clone())))
            })
            .is_err());
        assert!(!live.load(Ordering::SeqCst));
        let after = read(&db).unwrap();
        assert_eq!(
            active(&after).unwrap()["config"]["client"]["enabled"],
            false
        );
        edit_document(&db, |d| {
            d["servers"][1]["config"]["routing"]["active"] = json!(true);
            Ok(())
        })
        .unwrap();
        assert!(clients
            .up(&db, None, |_| panic!("standalone guard"))
            .is_err());
    }
    #[test]
    fn confirmed_server_edit_restarts_only_the_owned_changed_client() {
        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        crate::import(&db, &crate::tests::input(), "deploy fixture").unwrap();
        let clients = Clients::default();
        let id = s(active(&read(&db).unwrap()).unwrap(), "id").to_owned();
        clients
            .reconcile_deployed(&db, &id, |_, _, _| panic!("inactive client"))
            .unwrap();
        let old = Arc::new(AtomicBool::new(true));
        clients
            .up(&db, Some(&id), |_| Ok(Box::new(Mock(old.clone()))))
            .unwrap();
        clients
            .reconcile_deployed(&db, &id, |_, _, _| panic!("unchanged client"))
            .unwrap();
        edit_document(&db, |d| {
            d["servers"][1]["config"]["mtu"] = json!(1300);
            d["servers"][1]["config"]["client"]["standby"] = json!(true);
            Ok(())
        })
        .unwrap();
        clients
            .reconcile_deployed(&db, &id, |_, _, _| Err(invalid("fixture start failure")))
            .unwrap_err();
        assert!(!old.load(Ordering::SeqCst));
        let new = Arc::new(AtomicBool::new(true));
        clients
            .reconcile_deployed(&db, &id, |spec, _, _| {
                assert!(spec.conf.contains("MTU = 1300"));
                Ok(Box::new(Mock(new.clone())))
            })
            .unwrap();
        clients
            .reconcile_deployed(&db, &id, |_, _, _| panic!("already recovered"))
            .unwrap();
        assert!(new.load(Ordering::SeqCst));
    }
    #[test]
    fn imported_edit_commits_before_refresh_and_retries_the_saved_candidate_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        crate::import(&db, &crate::tests::input(), "one").unwrap();
        let runtime = Runtime::new(dir.path(), dir.path().join("no-engine"));
        let clients = &runtime.clients;
        let live = Arc::new(AtomicBool::new(true));
        clients
            .up(&db, None, |_| Ok(Box::new(Mock(live.clone()))))
            .unwrap();
        let change =
            json!({"endpoint":"192.0.2.1:444","mtu":1350,"routing":{"active":true},"peers":[]});
        let old = read(&db).unwrap();
        runtime
            .save_config_with_transport(&db, &change, &[], |proof| {
                assert_eq!(proof.endpoint.to_string(), "192.0.2.1:444");
                assert!(live.load(Ordering::SeqCst));
                let saved = read(&db)?;
                assert_eq!(active(&saved)?["config"]["mtu"], 1350);
                assert!(settings::previous_fingerprint(active(&saved)?)?.is_some());
                Err(io::ErrorKind::WouldBlock.into())
            })
            .unwrap();
        assert!(live.load(Ordering::SeqCst));
        let pending = read(&db).unwrap();
        let row = active(&pending).unwrap();
        assert_eq!(row["config"]["endpoint"], "192.0.2.1:444");
        assert!(!crate::status(&db, &runtime)
            .unwrap()
            .to_string()
            .contains(settings::PENDING_PROFILE));
        let spec = || specification(&pending, row).unwrap();
        {
            let mut owned = clients.0.lock().unwrap();
            let fail = settings::apply_saved_edit(
                settings::SavedEdit {
                    db: &db,
                    doc: &pending,
                    row,
                },
                &mut owned,
                spec(),
                |_, _, _, _| Ok(()),
                |spec| {
                    assert_eq!(spec.endpoint, "192.0.2.1:444");
                    assert!(!live.load(Ordering::SeqCst));
                    Err(invalid("simulated start failure"))
                },
                None,
            );
            assert!(fail.is_err());
        }
        assert!(!live.load(Ordering::SeqCst));
        assert_eq!(read(&db).unwrap(), pending);

        let reopened = Store::open(dir.path()).unwrap();
        let mut restarted = HashMap::new();
        settings::apply_saved_edit(
            settings::SavedEdit {
                db: &reopened,
                doc: &pending,
                row,
            },
            &mut restarted,
            spec(),
            |_, _, _, _| Ok(()),
            |spec| {
                assert_eq!(spec.endpoint, "192.0.2.1:444");
                assert!(spec.conf.contains("MTU = 1350"));
                live.store(true, Ordering::SeqCst);
                Ok(Box::new(Mock(live.clone())))
            },
            None,
        )
        .unwrap();
        assert!(live.load(Ordering::SeqCst));
        let new = read(&db).unwrap();
        assert_eq!(
            settings::previous_fingerprint(active(&new).unwrap()).unwrap(),
            None
        );
        let before = &active(&old).unwrap()["config"];
        let after = &active(&new).unwrap()["config"];
        assert_eq!(before["peers"], after["peers"]);
        assert_eq!(before["routing"], after["routing"]);
        assert_eq!(after["mtu"], 1350);
    }

    #[test]
    fn routed_mtu_edit_parks_before_stop_and_retries_after_a_later_draft() {
        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        crate::import(&db, &crate::tests::input(), "routed").unwrap();
        let runtime = Runtime::new(dir.path(), dir.path().join("no-engine"));
        let live = Arc::new(AtomicBool::new(true));
        runtime
            .clients
            .up(&db, None, |_| Ok(Box::new(Mock(live.clone()))))
            .unwrap();
        let before = read(&db).unwrap();
        let row = active(&before).unwrap();
        let mtu = crate::tunnel_mtu(wire(row), &wire(row)["routing"]) as u16;
        let new_mtu = if mtu == 1350 { 1370 } else { 1350 };
        let id = s(row, "id");
        let claim = RoutedMtuChange {
            id: id.into(),
            iface: iface(row, &before).unwrap(),
            revision: 7,
            before: mtu,
            after: new_mtu,
            nested_outer: None,
            nested_endpoint: None,
            endpoint_edit: None,
            legacy_predecessor: None,
            implicit_before_mtu: None,
            legacy_mtu_before_recorded: false,
            nested_mtu_before_recorded: false,
            native_mtu_endpoint: None,
        };
        crate::import(&db, &crate::tests::input(), "second routed tunnel").unwrap();
        let second_doc = read(&db).unwrap();
        let second = active(&second_doc).unwrap();
        let other_id = s(second, "id");
        let other_mtu = second["config"]["mtu"].clone();
        let other_live = Arc::new(AtomicBool::new(true));
        runtime
            .clients
            .up(&db, Some(other_id), |_| {
                Ok(Box::new(Mock(other_live.clone())))
            })
            .unwrap();
        edit_document(&db, |d| {
            d["active_id"] = json!(id);
            d["routing_revision"] = json!(7);
            d["rust_static_routing"] =
                json!({"revision":7,"pending_commit":true,"targets":[id,other_id],"committed_targets":[id,other_id]});
            let primary = d["servers"].as_array_mut().unwrap().iter_mut().find(|r| r["id"] == id).unwrap();
            primary["config"]["client"]["standby"] = json!(true);
            Ok(())
        })
        .unwrap();
        let skip = |_: TransportBypassProof<'_>| -> io::Result<()> {
            panic!("unexpected transport preflight")
        };
        let no_park =
            |_: &RoutedMtuChange| -> io::Result<()> { panic!("unexpected route preflight") };
        let input = json!({"mtu":new_mtu});
        assert!(runtime
            .save_config_with_routing(&db, &input, &[], skip, no_park)
            .is_err());
        edit_document(&db, |d| {
            d["rust_static_routing"]["pending_commit"] = json!(false);
            Ok(())
        })
        .unwrap();
        let not_mtu_only = json!({"mtu":new_mtu,"endpoint":"192.0.2.5:5555"});
        assert!(runtime
            .save_config_with_routing(&db, &not_mtu_only, &[], skip, no_park)
            .is_err());
        assert!(runtime
            .save_config_with_transport(&db, &input, &[], skip)
            .is_err());
        assert!(pending_routed_mtu(active(&read(&db).unwrap()).unwrap())
            .unwrap()
            .is_none());
        runtime
            .save_config_with_routing(
                &db,
                &input,
                &[],
                |_| Ok(()),
                |actual| {
                    assert_eq!(actual, &claim);
                    assert!(live.load(Ordering::SeqCst));
                    let committed = read(&db)?;
                    let saved = active(&committed)?;
                    assert_eq!(saved["config"]["mtu"], new_mtu);
                    assert_eq!(pending_routed_mtu(saved)?, Some(claim.clone()));
                    Err(io::ErrorKind::WouldBlock.into())
                },
            )
            .unwrap();
        assert!(live.load(Ordering::SeqCst));
        assert!(runtime.client_up(&db, &[]).is_err());

        edit_document(&db, |d| {
            d["active_id"] = json!(other_id);
            Ok(())
        })
        .unwrap();
        assert!(runtime
            .save_config_with_routing(&db, &input, &[], skip, no_park)
            .is_err());
        let second_attempt = read(&db).unwrap();
        let other = find(&second_attempt, other_id).unwrap();
        assert!(pending_routed_mtu(other).unwrap().is_none());
        assert_eq!(other["config"]["mtu"], other_mtu);
        assert!(other_live.load(Ordering::SeqCst));

        edit_document(&db, |d| {
            d["active_id"] = json!(id);
            d["routing_revision"] = json!(8);
            Ok(())
        })
        .unwrap();
        let pending = read(&db).unwrap();
        let row = active(&pending).unwrap();
        let spec = || specification(&pending, row).unwrap();
        let park = |actual: &RoutedMtuChange| {
            assert_eq!(actual, &claim);
            assert!(live.load(Ordering::SeqCst));
            Ok(())
        };
        {
            let mut owned = runtime.clients.0.lock().unwrap();
            let failed = settings::apply_saved_edit(
                settings::SavedEdit {
                    db: &db,
                    doc: &pending,
                    row,
                },
                &mut owned,
                spec(),
                |_, _, _, _| Ok(()),
                |_| {
                    assert!(!live.load(Ordering::SeqCst));
                    Err(io::ErrorKind::ConnectionRefused.into())
                },
                Some(&park),
            );
            assert_eq!(failed.unwrap_err().kind(), io::ErrorKind::ConnectionRefused);
        }
        assert_eq!(read(&db).unwrap(), pending);
        let reopened = Store::open(dir.path()).unwrap();
        edit_document(&reopened, |d| {
            d["rust_static_routing"]["committed_revision"] = json!(7);
            d["rust_static_routing"]["revision"] = json!(0);
            d["rust_static_routing"]["targets"] = json!([]);
            Ok(())
        })
        .unwrap();
        let pending = read(&reopened).unwrap();
        let row = active(&pending).unwrap();
        let spec = || specification(&pending, row).unwrap();
        let restarted_runtime = Runtime::new(dir.path(), dir.path().join("no-engine"));
        let invoked = AtomicBool::new(false);
        assert!(restarted_runtime
            .restore_clients_with_routing(
                &reopened,
                &[],
                |_| Ok(()),
                |actual| {
                    assert_eq!(actual, &claim);
                    invoked.store(true, Ordering::SeqCst);
                    Err(io::ErrorKind::WouldBlock.into())
                }
            )
            .is_err());
        assert!(invoked.load(Ordering::SeqCst));
        let owners = restarted_runtime.clients.0.lock().unwrap();
        assert!(owners[id].tunnel.is_stopped());
        drop(owners);
        assert_eq!(read(&reopened).unwrap(), pending);
        let mut restarted = HashMap::new();
        let apply = |owned: &mut _, park| {
            settings::apply_saved_edit(
                settings::SavedEdit {
                    db: &reopened,
                    doc: &pending,
                    row,
                },
                owned,
                spec(),
                |_, _, _, _| Ok(()),
                |next| {
                    assert!(next.conf.contains(&format!("MTU = {new_mtu}")));
                    live.store(true, Ordering::SeqCst);
                    Ok(Box::new(Mock(live.clone())))
                },
                park,
            )
        };
        assert_eq!(
            apply(&mut restarted, None).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let parked = |actual: &RoutedMtuChange| {
            assert_eq!(actual, &claim);
            assert!(!live.load(Ordering::SeqCst));
            Ok(())
        };
        apply(&mut restarted, Some(&parked)).unwrap();
        let final_doc = read(&db).unwrap();
        assert!(live.load(Ordering::SeqCst));
        assert_eq!(final_doc["routing_revision"], 8);
        assert_eq!(
            final_doc["rust_static_routing"],
            pending["rust_static_routing"]
        );
        let saved = active(&final_doc).unwrap();
        assert_eq!(saved["config"]["mtu"], new_mtu);
        assert!(pending_routed_mtu(saved).unwrap().is_none());
        assert!(settings::previous_fingerprint(saved).unwrap().is_none());
    }
}
