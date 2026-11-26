use super::*;
use nfqws2_store::new_id;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

pub const ACTIVE_REPLACEMENT_FIELD: &str = "rust_active_replacement";
pub const ACTIVE_REPLACEMENT_LAUNCH_FILE: &str = "awg-active-replacement-launch.json";
pub const ACTIVE_REPLACEMENT_LAUNCH_LIMIT: u64 = 4096;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeNestedRemovalScope {
    pub outer_iface: String,
    pub endpoint: IpAddr,
    pub source: IpAddr,
}

impl NativeNestedRemovalScope {
    #[cfg(target_os = "linux")]
    pub(super) fn routes(&self, iface: &str) -> nested::Routes {
        nested::Routes {
            iface: iface.to_owned(),
            outer: self.outer_iface.clone(),
            endpoint: self.endpoint,
            source: self.source,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRemovalSeal {
    pub id: String,
    pub iface: String,
    pub boot: String,
    pub pid: u32,
    pub started: u64,
    pub receipt_sha256: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nested: Option<NativeNestedRemovalScope>,
}

impl NativeRemovalSeal {
    pub fn valid(&self) -> bool {
        nfqws2_store::valid_name(&self.id)
            && self.iface.len() < 16
            && self
                .iface
                .strip_prefix("awg")
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
            && self.boot.len() == 36
            && self.boot.bytes().enumerate().all(|(i, b)| {
                if matches!(i, 8 | 13 | 18 | 23) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            })
            && (2..=i32::MAX as u32).contains(&self.pid)
            && self.started > 0
            && self.receipt_sha256 != [0; 32]
            && self.nested.as_ref().is_none_or(|scope| {
                validate_nested_scope(
                    &self.iface,
                    &scope.outer_iface,
                    scope.endpoint,
                    scope.source,
                )
                .is_ok()
            })
    }
}

pub(super) fn retained_replacement_outer(
    doc: &Value,
    owned: &mut HashMap<String, Managed>,
) -> Option<String> {
    let marker = &doc[ACTIVE_REPLACEMENT_FIELD];
    let source = marker["id"]
        .as_str()
        .filter(|id| nfqws2_store::valid_name(id))?;
    if find(doc, source).is_ok()
        || !marker["token"]
            .as_str()
            .is_some_and(|token| token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return None;
    }
    let outer: NativeRemovalSeal = serde_json::from_value(marker["retained_outer"].clone()).ok()?;
    if !outer.valid() || outer.nested.is_some() || outer.id == source {
        return None;
    }
    let row = find(doc, &outer.id).ok()?;
    let client = &row["config"]["client"];
    if row["config"]["enabled"] != true
        || client["enabled"] != true
        || client["rust_managed"] != true
        || client["standby"] != true
    {
        return None;
    }
    let current = owned.get_mut(&outer.id)?;
    (current.iface == outer.iface
        && current.tunnel.alive()
        && current
            .tunnel
            .native_removal_seal()
            .is_ok_and(|seal| seal == outer))
    .then_some(outer.id)
}

#[derive(Clone, Eq, PartialEq)]
pub struct ActiveReplacementPeer {
    pub owner: NativeRemovalSeal,
    pub fingerprint: [u8; 32],
    pub endpoint: SocketAddr,
    pub socket_mark: u32,
    pub mtu: u16,
    pub allowed: Vec<String>,
    pub underlay: Option<ActiveReplacementUnderlay>,
    pub nested_only: bool,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ActiveReplacementUnderlay {
    pub owner: NativeRemovalSeal,
    pub fingerprint: [u8; 32],
    pub endpoint: SocketAddr,
    pub socket_mark: u32,
    pub mtu: u16,
    pub allowed: Vec<String>,
}

pub struct ActiveReplacementStage<'a> {
    pub before: &'a Value,
    pub after: &'a Value,
    pub source: &'a ActiveReplacementPeer,
    pub held: Option<&'a ActiveReplacementPeer>,
    pub target: &'a str,
    pub provisional: Option<&'a ActiveReplacementPeer>,
}

type NamedReplacementCheck<'a> =
    dyn Fn(ActiveReplacementStage<'_>) -> io::Result<ActiveReplacementLaunchPin> + 'a;

pub struct ActiveReplacementPreparation<'a> {
    pub check: &'a dyn Fn(ActiveReplacementStage<'_>) -> io::Result<ActiveReplacementLaunchMode>,
    pub named: Option<&'a NamedReplacementCheck<'a>>,
    pub defer_unresolved_name: bool,
    pub defer: &'a dyn Fn(ActiveReplacementStage<'_>) -> io::Result<Option<String>>,
    pub refresh: &'a dyn Fn(TransportBypassProof<'_>) -> io::Result<()>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActiveReplacementLaunchMode {
    Authenticate,
    ConfiguredPrimary,
    Reserve(SocketAddr),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ActiveReplacementLaunchPin {
    pub endpoint: SocketAddr,
    pub deadline: std::time::Instant,
    pub warm_ipv6: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveReplacementLaunchLease {
    pub prior: String,
    pub source: NativeRemovalSeal,
    pub target: NativeRemovalSeal,
    pub fingerprint: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub named_endpoint: Option<SocketAddr>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub warm_ipv6: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub numeric_pool: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub literal_startup: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_was_standby: Option<bool>,
}

pub fn read_active_replacement_launch(
    db: &Store,
) -> io::Result<Option<ActiveReplacementLaunchLease>> {
    let launch: ActiveReplacementLaunchLease = match db.read_runtime(
        ACTIVE_REPLACEMENT_LAUNCH_FILE,
        ACTIVE_REPLACEMENT_LAUNCH_LIMIT,
    ) {
        Ok(launch) => launch,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if !launch.source.valid()
        || !launch.target.valid()
        || launch.source.nested.is_some()
        || launch.target.nested.is_some()
        || launch.source.boot != launch.target.boot
        || launch.source.id == launch.target.id
        || launch.source.iface == launch.target.iface
        || launch.source.pid == launch.target.pid
        || launch.source.receipt_sha256 == launch.target.receipt_sha256
        || launch.fingerprint == [0; 32]
        || launch.numeric_pool == Some([0; 32])
        || launch.numeric_pool.is_some() && launch.named_endpoint.is_some()
        || launch.literal_startup
            && (launch.numeric_pool.is_some() || launch.named_endpoint.is_some())
        || launch.warm_ipv6 && launch.named_endpoint.is_none()
        || launch.named_endpoint.is_some_and(|endpoint| {
            endpoint.is_ipv6() != launch.warm_ipv6
                || supervisor::canonical_transport(endpoint) != Some(endpoint)
        })
        || launch.prior.len() != 64
        || !launch.prior.bytes().all(|c| c.is_ascii_hexdigit())
    {
        return Err(invalid("неверная запись запуска резервного AWG"));
    }
    Ok(Some(launch))
}

#[derive(Debug)]
pub struct DeleteReplacementPersistenceUncertain {
    save: io::Error,
    restore: io::Error,
}

impl std::fmt::Display for DeleteReplacementPersistenceUncertain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "не удалось подтвердить перенос правил или восстановить прежнее состояние: {}. {}",
            self.save, self.restore
        )
    }
}

impl std::error::Error for DeleteReplacementPersistenceUncertain {}

fn drain_rules(value: &mut Value) -> io::Result<Vec<Value>> {
    match value {
        Value::Array(rules) => Ok(std::mem::take(rules)),
        Value::Null => Ok(vec![]),
        _ => Err(invalid("неверный список правил AWG")),
    }
}

fn fallbacks(list: &Value) -> io::Result<Vec<&str>> {
    if list.is_null() {
        return Ok(Vec::new());
    }
    list.as_array()
        .ok_or_else(|| invalid("неверный список резервов"))?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::trim)
                .ok_or_else(|| invalid("неверный идентификатор резерва"))
        })
        .collect()
}

fn remap_fallbacks<'a>(
    owner: &str,
    list: impl IntoIterator<Item = &'a str>,
    from: &str,
    to: &'a str,
) -> Vec<&'a str> {
    let mut seen = HashSet::new();
    list.into_iter()
        .map(|id| if id == from { to } else { id })
        .filter(|id| !id.is_empty() && *id != owner && seen.insert(*id))
        .collect()
}

fn dependent(row: &Value, source: &str, allow_outgoing_outer: bool) -> io::Result<bool> {
    for origin in ["config", "applied_config"] {
        let client = &row[origin]["client"];
        let outer = s(client, "double_tunnel_id").trim();
        let backups = fallbacks(&client["fallback_tunnel_ids"])?;
        if outer == source
            || backups.contains(&source)
            || row["id"] == source
                && (!backups.is_empty() || !allow_outgoing_outer && !outer.is_empty())
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn detach_client_dependency(client: &mut Value, id: &str) -> io::Result<()> {
    fallbacks(&client["fallback_tunnel_ids"])?;
    if let Some(backups) = client
        .get_mut("fallback_tunnel_ids")
        .and_then(Value::as_array_mut)
    {
        backups.retain(|value| value.as_str().unwrap_or_default().trim() != id);
    }
    if s(client, "double_tunnel_id").trim() == id {
        client["double_tunnel_id"] = "".into();
    }
    Ok(())
}

fn replace_client_controls(
    row: &mut Value,
    source: &str,
    target: &str,
    source_backups: &[&str],
) -> io::Result<()> {
    let id = s(row, "id").to_owned();
    let cfg = &row["config"]["client"];
    let mut backups = fallbacks(&cfg["fallback_tunnel_ids"])?;
    if id == target {
        backups.extend_from_slice(source_backups);
    }
    let mapped = remap_fallbacks(&id, backups, source, target);
    let replace_outer = s(cfg, "double_tunnel_id").trim() == source;
    if cfg.get("fallback_tunnel_ids").is_some_and(Value::is_array) || !mapped.is_empty() {
        row["config"]["client"]["fallback_tunnel_ids"] = json!(mapped);
    }
    if replace_outer {
        row["config"]["client"]["double_tunnel_id"] = json!(if id == target { "" } else { target });
    }
    if row["applied_config"].is_object() {
        // The four client controls and routing take effect locally, even if
        // the remote server changes in config have not been deployed.
        for key in [
            "fallback_tunnel_ids",
            "standby",
            "double_tunnel_id",
            "double_tunnel_mode",
        ] {
            let desired = row["config"]["client"].get(key).cloned();
            if let Some(value) = desired {
                row["applied_config"]["client"][key] = value;
            } else if let Some(client) = row["applied_config"]["client"].as_object_mut() {
                client.remove(key);
            }
        }
        row["applied_config"]["routing"] = row["config"]["routing"].clone();
    }
    Ok(())
}

fn active_policy(doc: &Value) -> bool {
    doc["rust_static_routing"].is_object()
        || doc["routing"]["active"] == true
        || doc["servers"].as_array().into_iter().flatten().any(|row| {
            ["config", "applied_config"]
                .iter()
                .any(|cfg| row[*cfg]["routing"]["active"] == true)
        })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TransferPolicy {
    Dormant,
    UnroutedPlain,
    UnrelatedActive,
    Active,
}

struct PlainDeleteDependent<'a> {
    row: &'a Value,
    iface: String,
    direct: Option<SocketAddr>,
}

impl PlainDeleteDependent<'_> {
    fn optional_standby(&self) -> bool {
        let cfg = &self.row["config"]["client"];
        cfg["standby"] == true && cfg["double_tunnel_mode"] != "permanent"
    }
}

fn remove(
    doc: &mut Value,
    id: &str,
    to: Option<&str>,
    reference: Value,
    policy: TransferPolicy,
) -> io::Result<()> {
    let unrouted_plain = policy == TransferPolicy::UnroutedPlain;
    if unrouted_plain && active_policy(doc) {
        return Err(invalid("сначала отключите активную маршрутизацию"));
    }
    if policy != TransferPolicy::Active && routes_use(doc, id) {
        return Err(invalid("сначала снимите маршруты этого подключения"));
    }
    if let Some(to) = to {
        if to == id || to.is_empty() {
            return Err(invalid("выберите другое подключение для переноса правил"));
        }
        find(doc, to)?;
    }
    let source = find(doc, id)?;
    if !doc["connection_refs"].is_null() && !doc["connection_refs"].is_object() {
        return Err(invalid("неверный список ссылок AWG"));
    }
    let prior_selection = crate::active(doc)?["id"].clone();
    let source_backups = to
        .map(|_| source["config"]["client"]["fallback_tunnel_ids"].clone())
        .unwrap_or_default();
    let source_backups = fallbacks(&source_backups)?;
    // A legacy row without client_iface used its old position as identity.
    // Removing a row must not renumber interfaces of surviving profiles.
    let mut prior_ifaces = HashMap::new();
    if to.is_some() || unrouted_plain {
        for (index, row) in doc["servers"].as_array().unwrap().iter().enumerate() {
            if row["id"] != id {
                prior_ifaces.insert(s(row, "id").to_owned(), format!("awg{index}"));
            }
        }
    }
    let shared = doc["routing"].clone();
    let mut zones = Vec::new();
    let mut ids = HashSet::new();
    for row in doc["servers"].as_array_mut().unwrap() {
        let owner = s(row, "id").to_owned();
        ids.insert(owner.clone());
        for cfg in ["config", "applied_config"] {
            if !row[cfg].is_object() {
                continue;
            }
            let client = &row[cfg]["client"];
            if to.is_none()
                && cfg == "applied_config"
                && row[cfg]["routing"]["zones"]
                    .as_array()
                    .is_some_and(|a| !a.is_empty())
            {
                return Err(invalid(
                    "сначала завершите изменение применённой конфигурации",
                ));
            }
            if policy == TransferPolicy::Dormant && row[cfg]["routing"]["active"] == true
                || (to.is_none()
                    && !unrouted_plain
                    && (s(client, "double_tunnel_id") == id
                        || client["fallback_tunnel_ids"]
                            .as_array()
                            .is_some_and(|v| v.iter().any(|s| s == id))
                        || owner == id
                            && (!s(client, "double_tunnel_id").is_empty()
                                || client["fallback_tunnel_ids"]
                                    .as_array()
                                    .is_some_and(|v| !v.is_empty()))))
            {
                return Err(invalid(
                    "сначала отключите активную маршрутизацию и отвяжите резервные туннели",
                ));
            }
        }
        for mut z in drain_rules(&mut row["config"]["routing"]["zones"])? {
            if !z.is_object() {
                return Err(invalid("неверное правило AWG"));
            }
            let primary = s(&z, "tunnel_id");
            if to.is_some() && primary != primary.trim() {
                z["tunnel_id"] = json!(primary.trim());
            }
            if s(&z, "tunnel_id").is_empty()
                && (to.is_none() || z["waiting_for_connection"] != true)
            {
                z["tunnel_id"] = json!(owner);
            }
            zones.push(z);
        }
    }
    if policy == TransferPolicy::Dormant && doc["routing"]["active"] == true {
        return Err(invalid("сначала отключите активную маршрутизацию"));
    }
    for mut z in drain_rules(&mut doc["pending_rules"])? {
        if !z.is_object() {
            return Err(invalid("неверное ожидающее правило AWG"));
        }
        let primary = s(&z, "tunnel_id");
        if to.is_some() && primary != primary.trim() {
            z["tunnel_id"] = json!(primary.trim());
        }
        z["waiting_for_connection"] = json!(true);
        zones.push(z);
    }
    zones.sort_by_key(|z| z["order"].as_u64().filter(|n| *n > 0).unwrap_or(u64::MAX));
    let rows = doc["servers"].as_array_mut().unwrap();
    rows.retain(|r| r["id"] != id);
    ids.remove(id);
    let mut pending = Vec::new();
    let mut by_owner: HashMap<String, Vec<Value>> = HashMap::new();
    for (i, mut z) in zones.into_iter().enumerate() {
        z["order"] = json!(i + 1);
        if z["tunnel_id"] == id {
            if let Some(to) = to {
                z["tunnel_id"] = json!(to);
                z["waiting_for_connection"] = json!(false);
            } else {
                z["waiting_for_connection"] = json!(true);
            }
        }
        let primary = s(&z, "tunnel_id").to_owned();
        if let Some(to) = to.filter(|_| !z["fallback_tunnel_ids"].is_null()) {
            let fallbacks = fallbacks(&z["fallback_tunnel_ids"])?;
            z["fallback_tunnel_ids"] = json!(remap_fallbacks(&primary, fallbacks, id, to));
        }
        if z["waiting_for_connection"] == true || !ids.contains(&primary) {
            z["waiting_for_connection"] = json!(true);
            pending.push(z);
        } else {
            by_owner.entry(primary).or_default().push(z);
        }
    }
    for row in rows.iter_mut() {
        let owner = s(row, "id").to_owned();
        row["config"]["routing"]["zones"] = json!(by_owner.remove(&owner).unwrap_or_default());
        if to.is_some() || unrouted_plain {
            for cfg in ["config", "applied_config"] {
                if row[cfg].is_object() && s(&row[cfg], "client_iface").is_empty() {
                    row[cfg]["client_iface"] = json!(prior_ifaces[&owner]);
                }
            }
        }
        if let Some(to) = to {
            if policy == TransferPolicy::Active && owner == to {
                row["config"]["routing"]["active"] = json!(true);
                row["config"]["client"]["standby"] = json!(false);
            }
            replace_client_controls(row, id, to, &source_backups)?;
        } else if unrouted_plain {
            for cfg in ["config", "applied_config"] {
                if let Some(client) = row.get_mut(cfg).and_then(|saved| saved.get_mut("client")) {
                    detach_client_dependency(client, id)?;
                }
            }
        }
    }
    if rows.is_empty() {
        let fresh = format!("awg-{}", new_id()?);
        let mut cfg = conf::base();
        // A blank manager inherits the shared policy knobs on recreation.
        for k in [
            "mode",
            "mtu",
            "killswitch",
            "domain_source",
            "sni_routing",
            "trace_enabled",
        ] {
            if let Some(v) = shared.get(k) {
                cfg["routing"][k] = v.clone();
            }
        }
        rows.push(json!({"id":fresh,"name":"","config":cfg}));
    }
    let first = rows[0]["id"].clone();
    if prior_selection == id {
        doc["active_id"] = to.map_or(first, |s| json!(s));
    } else if to.is_some() && doc["active_id"] != prior_selection {
        doc["active_id"] = prior_selection;
    }
    doc["pending_rules"] = json!(pending);
    doc["connection_refs"][id] = reference;
    doc["connection_refs"] = Value::Object(crate::view::retained_connection_refs(doc));
    if to.is_some() {
        failover::Graph::validate_replacement(doc)?;
        doc["routing_revision"] = json!(doc["routing_revision"]
            .as_u64()
            .unwrap_or(0)
            .saturating_add(1));
    } else if unrouted_plain {
        failover::Graph::load(doc)?;
    }
    Ok(())
}

fn finish_replacement_save(
    before: &Value,
    after: &Value,
    read: impl Fn() -> io::Result<Value>,
    write: impl Fn(&Value, &Value) -> io::Result<()>,
) -> io::Result<Option<String>> {
    let Err(save) = write(before, after) else {
        return Ok(None);
    };
    // An error from directory sync can occur after the atomic rename.
    let restored = read().and_then(|current| {
        if current == *before {
            Ok(())
        } else {
            write(after, before)
        }
    });
    let Err(restore) = restored else {
        return Err(save);
    };
    match read() {
        Ok(current) if current == *before => Err(save),
        Ok(current) if current == *after => Ok(Some(format!(
            "перенос правил сохранён после ошибки записи: {save}"
        ))),
        _ => Err(io::Error::other(DeleteReplacementPersistenceUncertain {
            save,
            restore,
        })),
    }
}

pub fn persist_active_replacement_locked(
    db: &Store,
    tx: &nfqws2_store::Transaction<'_>,
    before: &Value,
    after: &Value,
) -> io::Result<Option<String>> {
    finish_replacement_save(
        before,
        after,
        || db.read("awg.json"),
        |expected, next| {
            crate::edit_document_locked(tx, |doc| {
                if doc != expected {
                    return Err(invalid("подключения изменились во время переноса"));
                }
                doc.clone_from(next);
                Ok(())
            })
        },
    )
}

fn configured_replacement_outer<'a>(doc: &Value, row: &'a Value) -> io::Result<Option<&'a str>> {
    let client = &row["config"]["client"];
    let outer = s(client, "double_tunnel_id");
    let mode = s(client, "double_tunnel_mode");
    if outer.is_empty() {
        return if mode == "permanent" {
            Err(invalid("не подтверждён внешний профиль постоянного AWG"))
        } else {
            Ok(None)
        };
    }
    if !nfqws2_store::valid_name(outer)
        || row["id"] == outer
        || !matches!(
            mode,
            "" | "off" | "last_resort" | "automatic" | "preferred" | "permanent"
        )
        || find(doc, outer)?["config"]["client"]["double_tunnel_mode"] == "permanent"
    {
        return Err(invalid("не подтверждён внешний профиль AWG"));
    }
    Ok(Some(outer))
}

/// Validate the dependency graph and report whether any participant has a configured outer.
pub fn active_replacement_topology(
    before: &Value,
    after: &Value,
    source: &str,
    target: &str,
) -> io::Result<bool> {
    let old_outer = configured_replacement_outer(before, find(before, source)?)?;
    let new_outer = configured_replacement_outer(before, find(before, target)?)?;
    let saved_outer = configured_replacement_outer(after, find(after, target)?)?;
    let changed = || invalid("активный перенос изменяет внешний профиль AWG");
    if new_outer != saved_outer {
        return Err(changed());
    }
    let has_outer = old_outer.is_some() || new_outer.is_some();
    let rows = before["servers"].as_array().unwrap();
    for row in rows {
        if dependent(row, source, has_outer)? || dependent(row, target, has_outer)? {
            return Err(invalid(
                "активный перенос изменяет резервный или двойной туннель",
            ));
        }
    }
    if !has_outer {
        return Ok(false);
    }
    if after["servers"].as_array().map(|rows| rows.len() + 1) != Some(rows.len()) {
        return Err(changed());
    }
    for row in rows.iter().filter(|row| row["id"] != source) {
        let id = s(row, "id");
        let saved = find(after, id)?;
        let is_outer = old_outer == Some(id) || new_outer == Some(id);
        for origin in ["config", "applied_config"] {
            let mut client = row[origin]["client"].clone();
            if id == target && origin == "config" {
                client["standby"] = json!(false);
            }
            if saved[origin]["client"] != client {
                return Err(changed());
            }
            if is_outer {
                let (old, new) = (&row[origin], &saved[origin]);
                let compare = |config: &Value| {
                    let mut config = config.clone();
                    if let Some(values) = config.as_object_mut() {
                        values.remove("routing");
                        values.remove("client_iface");
                    }
                    config
                };
                if compare(old) != compare(new)
                    || old.is_object()
                        && configured_iface(row, before, old)?
                            != configured_iface(saved, after, new)?
                {
                    return Err(changed());
                }
            }
        }
    }
    for outer in [old_outer, new_outer].into_iter().flatten() {
        if outer == source || outer == target || find(after, outer).is_err() {
            return Err(changed());
        }
    }
    Ok(true)
}

fn direct_replacement_profile(doc: &Value, row: &Value, allow_backups: bool) -> io::Result<()> {
    let cfg = &row["config"];
    let client = &cfg["client"];
    let unsupported =
        || invalid("для активного переноса требуются два работающих прямых подключения AWG");
    if cfg["install"] != "imported"
        || cfg["enabled"] != true
        || client["enabled"] != true
        || client["rust_managed"] != true
        || !matches!(s(&cfg["routing"], "mode"), "zones" | "include" | "exclude")
        || !row["applied_config"].is_null()
        || !matches!(
            s(client, "double_tunnel_mode"),
            "" | "off" | "last_resort" | "automatic" | "preferred" | "permanent"
        )
        || !fallbacks(&client["fallback_tunnel_ids"])?.is_empty()
        || !allow_backups && !fallbacks(&client["endpoint_backups"])?.is_empty()
        || settings::has_saved_edit(row)
        || supervisor::pending_endpoint_restart(row)?.is_some()
    {
        return Err(unsupported());
    }
    configured_replacement_outer(doc, row)?;
    Ok(())
}

fn direct_endpoint(doc: &Value, row: &Value) -> io::Result<SocketAddr> {
    direct_replacement_profile(doc, row, false)?;
    configured_direct_endpoint(row)
}

fn configured_direct_endpoint(row: &Value) -> io::Result<SocketAddr> {
    let unsupported = || invalid("неподтверждённый адрес переносимого профиля AWG");
    let cfg = &row["config"];
    let endpoint = s(cfg, "endpoint")
        .parse::<SocketAddr>()
        .map_err(|_| unsupported())?;
    let ip = endpoint.ip().to_canonical();
    if endpoint.port() == 0
        || ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || matches!(endpoint, SocketAddr::V6(v6) if v6.scope_id() != 0 || v6.flowinfo() != 0)
    {
        return Err(unsupported());
    }
    Ok(SocketAddr::new(ip, endpoint.port()))
}

/// The raw native draft for an unqualified full connection and its single
/// independently enabled reserve. Route rules and live leases are checked separately.
pub fn native_full_reserve_draft(doc: &Value) -> Option<[&Value; 2]> {
    if doc["routing"]["mode"] != "full" || doc["rust_static_routing"].is_object() {
        return None;
    }
    let rows = doc["servers"].as_array()?;
    let [first, second] = rows.as_slice() else {
        return None;
    };
    let [owner, reserve] = if first["id"] == doc["active_id"] {
        [first, second]
    } else if second["id"] == doc["active_id"] {
        [second, first]
    } else {
        return None;
    };
    let id = owner["id"]
        .as_str()
        .filter(|id| nfqws2_store::valid_name(id))?;
    let reserve_id = reserve["id"]
        .as_str()
        .filter(|reserve| *reserve != id && nfqws2_store::valid_name(reserve))?;
    if fallbacks(&owner["config"]["client"]["fallback_tunnel_ids"]).ok()? != [reserve_id]
        || !fallbacks(&reserve["config"]["client"]["fallback_tunnel_ids"])
            .ok()?
            .is_empty()
    {
        return None;
    }
    [owner, reserve]
        .into_iter()
        .all(|row| {
            let cfg = &row["config"];
            let client = &cfg["client"];
            cfg["install"] == "imported"
                && cfg["enabled"] == true
                && client["enabled"] == true
                && client["rust_managed"] == true
                && client["standby"] != true
                && cfg["routing"]["mode"] == "full"
                && cfg["routing"]["active"] != true
                && row["applied_config"].is_null()
                && matches!(s(client, "double_tunnel_mode"), "" | "off")
                && s(client, "double_tunnel_id").is_empty()
                && fallbacks(&client["endpoint_backups"]).is_ok_and(|pool| pool.is_empty())
                && !settings::has_saved_edit(row)
                && supervisor::pending_endpoint_restart(row).is_ok_and(|pin| pin.is_none())
                && configured_direct_endpoint(row).is_ok_and(|endpoint| endpoint.is_ipv4())
        })
        .then_some([owner, reserve])
}

fn named_endpoint<'a>(doc: &Value, row: &'a Value) -> io::Result<(&'a str, u16)> {
    direct_replacement_profile(doc, row, false)?;
    let cfg = &row["config"];
    let raw = s(cfg, "endpoint");
    let (host, port) = conf::endpoint(raw)?;
    if raw.trim() != raw
        || host.contains(':')
        || host.parse::<IpAddr>().is_ok()
        || super::exact_route_hostname(host).is_none()
        || !matches!(s(&cfg["client"], "double_tunnel_mode"), "" | "off")
        || configured_replacement_outer(doc, row)?.is_some()
    {
        return Err(invalid("неподтверждённое имя прямого транспорта AWG"));
    }
    Ok((raw, port))
}

fn enroll_deferred_named(
    db: &Store,
    owned: &mut HashMap<String, Managed>,
    (source, target): (&str, &str),
    iface: String,
    fingerprint: [u8; 32],
    error: &io::Error,
) {
    if read(db).is_ok_and(|doc| {
        doc[ACTIVE_REPLACEMENT_FIELD]["id"] == source
            && find(&doc, source).is_err()
            && active_named_replacement_fingerprint(&doc, target).ok() == Some(fingerprint)
    }) {
        // A stopped candidate keeps the saved hostname eligible for the
        // ordinary watchdog after the original owner has retired.
        owned.insert(
            target.to_owned(),
            Managed {
                iface,
                fingerprint,
                tunnel: Box::new(super::supervisor::Stopped),
                recovery: super::supervisor::Recovery::failed_start(crate::now(), error),
            },
        );
    }
}

/// Match the raw named native configuration without resolving it.
pub fn active_named_replacement_fingerprint(doc: &Value, id: &str) -> io::Result<[u8; 32]> {
    let row = find(doc, id)?;
    named_endpoint(doc, row)?;
    let spec = saved_specification(doc, row, false)?;
    Ok(Sha256::digest(spec.conf.as_bytes()).into())
}

/// Resolve a bounded complete named endpoint for a later active replacement.
pub fn resolve_active_named_replacement(
    doc: &Value,
    id: &str,
    deadline: std::time::Instant,
) -> io::Result<Vec<SocketAddr>> {
    let (raw, _) = named_endpoint(doc, find(doc, id)?)?;
    let addresses = crate::endpoint::resolve_fresh_endpoint_addresses(raw, deadline)?;
    validate_active_named_replacement(doc, id, &addresses)?;
    Ok(addresses)
}

/// Classify a fresh full-family lookup before initial named replacement.
/// A parked target requires a definitive result with no IPv4 address.
pub fn resolve_initial_named_active_replacement(
    doc: &Value,
    id: &str,
    deadline: std::time::Instant,
) -> io::Result<Option<Vec<SocketAddr>>> {
    let (raw, _) = named_endpoint(doc, find(doc, id)?)?;
    let addresses = crate::endpoint::resolve_initial_replacement(raw, deadline)?;
    if let Some(addresses) = &addresses {
        settings::validate_named_addresses(raw, addresses)?;
    }
    Ok(addresses)
}

/// Validate accepted resolver answers again at the replacement boundary.
pub fn validate_active_named_replacement(
    doc: &Value,
    id: &str,
    addresses: &[SocketAddr],
) -> io::Result<()> {
    let (raw, _) = named_endpoint(doc, find(doc, id)?)?;
    settings::selected_named_address(raw, addresses).map(|_| ())
}

pub fn validate_warm_named_ipv6(doc: &Value, id: &str, addresses: &[SocketAddr]) -> io::Result<()> {
    let (raw, _) = named_endpoint(doc, find(doc, id)?)?;
    if addresses.is_empty() || addresses.iter().any(SocketAddr::is_ipv4) {
        return Err(io::ErrorKind::Unsupported.into());
    }
    settings::validate_named_addresses(raw, addresses)
}

pub fn verify_warm_named_ipv4_failure(
    doc: &Value,
    id: &str,
    deadline: std::time::Instant,
) -> io::Result<()> {
    let (raw, _) = named_endpoint(doc, find(doc, id)?)?;
    crate::endpoint::verify_warm_replacement_ipv4_failure(raw, deadline)
}

pub fn active_replacement_fingerprint(doc: &Value, id: &str) -> io::Result<[u8; 32]> {
    let row = find(doc, id)?;
    direct_endpoint(doc, row)?;
    let spec = saved_specification(doc, row, false)?;
    Ok(Sha256::digest(spec.conf.as_bytes()).into())
}

#[derive(Clone, Copy)]
enum ReplacementSample {
    Provisional(Option<SocketAddr>),
    WarmNamedIpv6 {
        endpoint: SocketAddr,
        provisional: bool,
    },
    ColdConfigured {
        provisional: bool,
        before_first_handshake: bool,
    },
    ColdReserve {
        provisional: bool,
        endpoint: SocketAddr,
    },
    RunningPrimary,
    RunningFullReserveDraft,
    RunningWithNumericBackups,
}

fn numeric_backup_pool(doc: &Value, row: &Value) -> io::Result<Vec<SocketAddr>> {
    direct_replacement_profile(doc, row, true)?;
    let unavailable = || invalid("не подтверждён числовой резервный endpoint AWG");
    let raw = fallbacks(&row["config"]["client"]["endpoint_backups"])?;
    let primary = configured_direct_endpoint(row)?;
    if raw.is_empty()
        || raw.iter().any(|address| address.is_empty())
        || !matches!(
            s(&row["config"]["client"], "double_tunnel_mode"),
            "" | "off"
        )
        || configured_replacement_outer(doc, row)?.is_some()
    {
        return Err(unavailable());
    }
    settings::configured_literal_endpoint_pool(row)?
        .filter(|pool| pool.first() == Some(&primary))
        .ok_or_else(unavailable)
}

pub struct ActiveReplacementNumericPool {
    endpoints: Vec<SocketAddr>,
    pub wire_fingerprint: [u8; 32],
    pool_fingerprint: [u8; 32],
}

impl ActiveReplacementNumericPool {
    /// Return the configured initial transport and its binding to the complete raw pool.
    pub fn primary(&self) -> (SocketAddr, [u8; 32]) {
        (self.endpoints[0], self.pool_fingerprint)
    }

    pub fn reserves(&self) -> &[SocketAddr] {
        &self.endpoints[1..]
    }

    pub fn binding(&self, selected: SocketAddr) -> Option<[u8; 32]> {
        let index = self
            .endpoints
            .iter()
            .position(|&endpoint| endpoint == selected)?;
        if index == 0 {
            return Some(self.pool_fingerprint);
        }
        let mut binding = Sha256::new();
        binding.update(self.pool_fingerprint);
        binding.update(selected.to_string());
        Some(binding.finalize().into())
    }

    pub fn selected_endpoint(&self, binding: [u8; 32]) -> Option<SocketAddr> {
        self.endpoints
            .iter()
            .copied()
            .find(|&endpoint| self.binding(endpoint) == Some(binding))
    }
}

/// Bind an already authenticated direct socket to its complete saved numeric pool.
pub fn active_replacement_numeric_pool(
    doc: &Value,
    id: &str,
) -> io::Result<ActiveReplacementNumericPool> {
    let row = find(doc, id)?;
    let endpoints = numeric_backup_pool(doc, row)?;
    let spec = saved_specification(doc, row, false)?;
    let wire_fingerprint = Sha256::digest(spec.conf.as_bytes()).into();
    let pool = &row["config"]["client"]["endpoint_backups"];
    let pool_fingerprint = Sha256::digest(serde_json::to_vec(&(wire_fingerprint, pool))?).into();
    Ok(ActiveReplacementNumericPool {
        endpoints,
        wire_fingerprint,
        pool_fingerprint,
    })
}

fn configured_startup_literal(doc: &Value, row: &Value) -> io::Result<SocketAddr> {
    if !matches!(
        s(&row["config"]["client"], "double_tunnel_mode"),
        "" | "off"
    ) || configured_replacement_outer(doc, row)?.is_some()
    {
        return Err(invalid("не подтверждён прямой запуск AWG"));
    }
    direct_endpoint(doc, row)
}

/// Bind an eligible configured startup to its saved wire identity, including
/// all raw backup entries when the profile has a numeric pool.
pub fn active_replacement_startup_binding(doc: &Value, id: &str) -> io::Result<[u8; 32]> {
    let row = find(doc, id)?;
    if fallbacks(&row["config"]["client"]["endpoint_backups"])?.is_empty() {
        configured_startup_literal(doc, row)?;
        let spec = saved_specification(doc, row, false)?;
        Ok(Sha256::digest(spec.conf.as_bytes()).into())
    } else {
        Ok(active_replacement_numeric_pool(doc, id)?.primary().1)
    }
}

fn replacement_underlay_spec(doc: &Value, id: &str) -> io::Result<(Spec, SocketAddr)> {
    let row = find(doc, id)?;
    let cfg = &row["config"];
    let client = &cfg["client"];
    let unavailable = || invalid("не подтверждён независимый внешний AWG");
    if cfg["enabled"] != true
        || client["enabled"] != true
        || client["rust_managed"] != true
        || !row["applied_config"].is_null()
        || settings::has_saved_edit(row)
        || supervisor::pending_endpoint_restart(row)?.is_some()
    {
        return Err(unavailable());
    }
    let endpoint = settings::literal_transport(s(cfg, "endpoint")).ok_or_else(unavailable)?;
    Ok((saved_specification(doc, row, false)?, endpoint))
}

pub fn active_replacement_underlay_identity(
    doc: &Value,
    id: &str,
) -> io::Result<(String, SocketAddr, [u8; 32])> {
    let (spec, endpoint) = replacement_underlay_spec(doc, id)?;
    Ok((
        spec.iface,
        endpoint,
        Sha256::digest(spec.conf.as_bytes()).into(),
    ))
}

pub fn active_replacement_nested_mtu(doc: &Value, id: &str, outer_mtu: u16) -> io::Result<u16> {
    let row = find(doc, id)?;
    let endpoint = direct_endpoint(doc, row)?;
    let spec = saved_specification(doc, row, false)?;
    let cfg = conf::parse(&spec.conf, 0)?;
    u16::try_from(nested_mtu(&cfg, u64::from(outer_mtu), endpoint.ip())?)
        .map_err(|_| invalid("неверный MTU вложенного AWG"))
}

pub fn active_replacement_endpoint(doc: &Value, id: &str) -> io::Result<SocketAddr> {
    direct_endpoint(doc, find(doc, id)?)
}

/// Read the independent socket owner without taking the clients lock or
/// requiring a fresh handshake. This proves a selector pair, not a data path.
pub fn owns_unselected_nested_socket(
    doc: &Value,
    id: &str,
    iface: &str,
    deadline: std::time::Instant,
) -> bool {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (doc, id, iface, deadline);
        false
    }
    #[cfg(target_os = "linux")]
    {
        let verify = || -> io::Result<bool> {
            let row = find(doc, id)?;
            let cfg = &row["config"];
            if cfg["routing"]["active"] == true {
                return Ok(false);
            }
            let endpoint = direct_endpoint(doc, row)?;
            let spec = saved_specification(doc, row, false)?;
            if spec.iface != iface {
                return Ok(false);
            }
            let Some(outer) = configured_replacement_outer(doc, row)? else {
                return Ok(false);
            };
            let (outer, _) = replacement_underlay_spec(doc, outer)?;
            super::linux::owns_nested_socket(
                std::path::Path::new("/"),
                &spec,
                &NestedOuter::from_spec(&outer)?,
                endpoint,
                deadline,
            )
        };
        verify().unwrap_or(false)
    }
}

/// Bind the saved optional transport policy separately from the direct daemon's configuration.
pub fn active_replacement_transport_stamp(doc: &Value, id: &str) -> io::Result<[u8; 32]> {
    let row = find(doc, id)?;
    let client = &row["config"]["client"];
    let outer = configured_replacement_outer(doc, row)?;
    let identity = if let Some(id) = outer {
        let row = find(doc, id)?;
        let cfg = &row["config"];
        Some((
            id,
            configured_iface(row, doc, cfg)?,
            &cfg["endpoint"],
            &cfg["enabled"],
            &cfg["client"],
        ))
    } else {
        None
    };
    let policy = (
        id,
        &client["double_tunnel_mode"],
        &client["double_tunnel_id"],
        identity,
    );
    Ok(Sha256::digest(serde_json::to_vec(&policy)?).into())
}

pub fn active_replacement_allowed(doc: &Value, id: &str) -> io::Result<Vec<String>> {
    let spec = saved_specification(doc, find(doc, id)?, false)?;
    let allowed = spec
        .conf
        .lines()
        .find_map(|line| line.strip_prefix("AllowedIPs = "))
        .ok_or_else(|| invalid("нет AllowedIPs для переноса маршрутов"))?;
    Ok(allowed
        .split(',')
        .map(str::trim)
        .map(str::to_owned)
        .collect())
}

pub fn active_replacement_source(doc: &Value, id: &str) -> bool {
    routes_use(doc, id)
}

pub fn disabled_active_replacement_target(doc: &Value, id: &str) -> io::Result<Option<String>> {
    let row = find(doc, id)?;
    let cfg = &row["config"];
    match (cfg["enabled"].as_bool(), cfg["client"]["enabled"].as_bool()) {
        (Some(false), Some(_)) | (Some(_), Some(false)) => iface(row, doc).map(Some),
        _ => Ok(None),
    }
}

fn wait_standby_handshake(
    tunnel: &mut dyn Tunnel,
    endpoint: SocketAddr,
    timeout: std::time::Duration,
    named: Option<(ActiveReplacementLaunchPin, u64)>,
) -> io::Result<()> {
    use std::time::{Duration, Instant};
    let deadline = named.map_or(Instant::now() + timeout, |(pin, _)| {
        pin.deadline.min(Instant::now() + timeout)
    });
    if Instant::now() >= deadline {
        return Err(io::ErrorKind::TimedOut.into());
    }
    tunnel.probe_at(endpoint)?;
    loop {
        let status = tunnel.snapshot()?;
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "резервный AWG не подтвердил рукопожатие",
            ));
        }
        let last = status["last_handshake"].as_u64().unwrap_or(0);
        if status["connected"] == true
            && last > 0
            && named.is_none_or(|(pin, started)| {
                last >= started
                    && last <= crate::now()
                    && supervisor::live_transport_endpoint(&status) == Some(pin.endpoint)
            })
        {
            return Ok(());
        }
        std::thread::sleep(left.min(Duration::from_millis(200)));
    }
}

fn unchanged_replacement(db: &Store, before: &Value) -> io::Result<()> {
    if read(db)? == *before {
        Ok(())
    } else {
        Err(invalid("подключения изменились во время запуска резерва"))
    }
}

impl Runtime {
    fn check_plain_delete_owner(
        &self,
        doc: &Value,
        row: &Value,
        name: &str,
        owner: Option<&Managed>,
    ) -> io::Result<()> {
        if let Some(owner) = owner {
            let spec = Self::spec_for_release(doc, row)?;
            let fingerprint: [u8; 32] = Sha256::digest(spec.conf.as_bytes()).into();
            if owner.iface != name || owner.fingerprint != fingerprint {
                return Err(invalid("сохранённый профиль работающего AWG изменился"));
            }
        } else if self.present(name)? {
            return Err(invalid("интерфейс управляется другим процессом"));
        }
        Ok(())
    }

    fn retire_plain_delete_owner(
        &self,
        doc: &Value,
        row: &Value,
        name: &str,
        owner: Option<&mut Managed>,
    ) -> io::Result<()> {
        if let Some(owner) = owner {
            owner.tunnel.stop()?;
        }
        if self.present(name)? {
            return Err(invalid("интерфейс управляется другим процессом"));
        }
        #[cfg(target_os = "linux")]
        linux::retire_vacant_plain_delete(self, doc, row, name)?;
        #[cfg(not(target_os = "linux"))]
        let _ = (doc, row);
        Ok(())
    }

    fn verify_plain_delete_direct(&self, endpoint: SocketAddr, wan: &[String]) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        if self.root == std::path::Path::new("/") {
            return linux::verify_direct_wan(self, endpoint, wan);
        }
        let _ = (endpoint, wan);
        Err(io::ErrorKind::Unsupported.into())
    }

    fn delete_unrouted_profile(
        &self,
        db: &Store,
        before: &Value,
        id: &str,
        reference: impl FnOnce(&Value, &str) -> io::Result<Value>,
        owned: &mut HashMap<String, Managed>,
        transport: Option<(&[String], &RefreshTransport<'_>)>,
    ) -> io::Result<Option<String>> {
        let row = find(before, id)?;
        let name = iface(row, before)?;
        let check_pending = |row: &Value| {
            if settings::has_saved_edit(row) || supervisor::pending_endpoint_restart(row)?.is_some()
            {
                return Err(invalid(
                    "сначала завершите изменение локального подключения",
                ));
            }
            Ok(())
        };
        self.check_plain_delete_owner(before, row, &name, owned.get(id))?;
        check_pending(row)?;
        let mut dependents = Vec::new();
        let unavailable = || invalid("не подтверждено снятие зависимого вложенного AWG");
        for other in before["servers"].as_array().unwrap() {
            let other_id = s(other, "id");
            if other_id == id {
                continue;
            }
            let owner = owned.get(other_id);
            let installed = owner.and_then(|m| m.tunnel.nested_iface());
            let config = &other["config"]["client"];
            let nested = ["config", "applied_config"]
                .iter()
                .any(|cfg| s(&other[*cfg]["client"], "double_tunnel_id").trim() == id);
            if !nested && installed != Some(name.as_str()) {
                if dependent(other, id, false)? {
                    check_pending(other)?;
                }
                continue;
            }
            check_pending(other)?;
            let iface = iface(other, before)?;
            let permanent = config["double_tunnel_mode"] == "permanent";
            if installed == Some(name.as_str()) {
                if s(config, "double_tunnel_id").trim() != id {
                    return Err(unavailable());
                }
                self.check_plain_delete_owner(before, other, &iface, owner)?;
                let standby = config["standby"] == true;
                if !permanent && (config["enabled"] != true || other["config"]["enabled"] != true) {
                    return Err(unavailable());
                }
                let direct = if permanent || standby {
                    None
                } else {
                    if transport.is_none() {
                        return Err(unavailable());
                    }
                    let spec = specification(before, other)?;
                    Some(resolve_endpoint(&spec.endpoint)?)
                };
                dependents.push(PlainDeleteDependent {
                    row: other,
                    iface,
                    direct,
                });
                continue;
            }
            let present = self.present(&iface)?;
            if installed.is_some() || present && (owner.is_none() || permanent) {
                return Err(unavailable());
            }
            if !present {
                #[cfg(target_os = "linux")]
                linux::ensure_plain_delete_scope_vacant(self, &iface)?;
            }
        }
        if owned.iter().any(|(other, m)| {
            m.tunnel.nested_iface().is_some_and(|outer| {
                dependents.iter().any(|d| outer == d.iface)
                    || other != id
                        && outer == name
                        && !dependents.iter().any(|d| d.row["id"] == *other)
            })
        }) {
            return Err(unavailable());
        }
        let tombstone = reference(before, id)?;
        let mut after = before.clone();
        remove(
            &mut after,
            id,
            None,
            tombstone,
            TransferPolicy::UnroutedPlain,
        )?;
        let mut shared_standbys = Vec::new();
        for retiring in dependents.iter_mut().filter(|d| d.optional_standby()) {
            let consumer_id = s(retiring.row, "id");
            for row in after["servers"].as_array().unwrap() {
                if row["id"] != consumer_id && dependent(row, consumer_id, false)? {
                    shared_standbys.push(retiring);
                    break;
                }
            }
        }
        let unconfirmed_demand =
            || invalid("не подтверждена потребность другого подключения во вложенном резерве");
        let shared_ids: Vec<_> = shared_standbys.iter().map(|d| s(d.row, "id")).collect();
        let mut standby_plan = Default::default();
        if !shared_ids.is_empty() {
            standby_plan = failover::unrouted_standby_plan(self, &after, owned, &shared_ids)?;
            for (retiring, id) in shared_standbys.into_iter().zip(&shared_ids) {
                match standby_plan.get(id) {
                    Some(failover::UnroutedStandby::Cold) => {}
                    Some(failover::UnroutedStandby::Direct) if transport.is_some() => {
                        let spec = specification(before, retiring.row)?;
                        retiring.direct = Some(resolve_endpoint(&spec.endpoint)?);
                    }
                    _ => return Err(unconfirmed_demand()),
                }
            }
        }
        for retiring in &dependents {
            let consumer_id = s(retiring.row, "id");
            if owned.get(consumer_id).is_some_and(|m| m.tunnel.inherited())
                || retiring.direct.is_some()
            {
                let successor = after["servers"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|candidate| candidate["id"] == consumer_id)
                    .ok_or_else(unavailable)?;
                for cfg in ["config", "applied_config"] {
                    if successor[cfg]["client"]["enabled"] == true {
                        successor[cfg]["client"]["rust_managed"] = true.into();
                    }
                }
            }
        }
        if let Some((wan, refresh)) =
            transport.filter(|_| dependents.iter().any(|d| d.direct.is_some()))
        {
            let inherited = self.capture_inherited_transport(before, owned, wan);
            for endpoint in dependents.iter().filter_map(|d| d.direct) {
                // The firewall refresh takes its own Store writer lock.
                supervisor::prepare_transport(Some((refresh, &inherited)), endpoint)?;
                self.verify_plain_delete_direct(endpoint, wan)?;
            }
        }
        let mut warning = db.transaction(|tx| {
            if read(db)? != *before {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            if !shared_ids.is_empty()
                && failover::unrouted_standby_plan(self, &after, owned, &shared_ids)?
                    != standby_plan
            {
                return Err(unconfirmed_demand());
            }
            if let Some((wan, _)) = transport {
                for endpoint in dependents.iter().filter_map(|d| d.direct) {
                    self.verify_plain_delete_direct(endpoint, wan)?;
                }
            }
            for dependent in &dependents {
                let owner = owned
                    .get_mut(s(dependent.row, "id"))
                    .ok_or_else(unavailable)?;
                self.retire_plain_delete_owner(
                    before,
                    dependent.row,
                    &dependent.iface,
                    Some(owner),
                )?;
            }
            self.retire_plain_delete_owner(before, row, &name, owned.get_mut(id))?;
            // Startup restores active direct clients. The watchdog rechecks
            // live demand before restoring a standby.
            persist_active_replacement_locked(db, tx, before, &after)
        })?;
        owned.remove(id);
        for dependent in dependents {
            let consumer_id = s(dependent.row, "id");
            self.record_nested(&dependent.iface, false);
            if dependent.optional_standby() && dependent.direct.is_none() {
                owned.remove(consumer_id);
                continue;
            }
            let launch = (|| {
                let (Some(endpoint), Some((wan, refresh))) = (dependent.direct, transport) else {
                    return Ok(None);
                };
                let row = find(&after, consumer_id)?;
                let mut spec = specification(&after, row)?;
                supervisor::check_recovery_row(db, row)?;
                let inherited = self.capture_inherited_transport(&after, owned, wan);
                supervisor::prepare_transport(Some((refresh, &inherited)), endpoint)?;
                self.verify_plain_delete_direct(endpoint, wan)?;
                supervisor::check_recovery_row(db, row)?;
                spec.endpoint = endpoint.to_string();
                let fingerprint: [u8; 32] = Sha256::digest(spec.conf.as_bytes()).into();
                let mut tunnel = self.start_local_prepared(spec, wan, None)?;
                if let Err(error) = supervisor::check_recovery_row(db, row) {
                    tunnel.stop()?;
                    return Err(error);
                }
                Ok(Some((tunnel, fingerprint)))
            })();
            if let Some(owner) = owned.get_mut(consumer_id) {
                owner.tunnel = Box::new(supervisor::Stopped);
                owner.recovery = Default::default();
                match launch {
                    Ok(Some((tunnel, fingerprint))) => {
                        owner.tunnel = tunnel;
                        owner.fingerprint = fingerprint;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        let message = if dependent.optional_standby() {
                            owned.remove(consumer_id);
                            format!(
                                "повторный запуск резерва AWG {consumer_id} ожидает проверки: {error}"
                            )
                        } else {
                            owner.recovery =
                                supervisor::Recovery::failed_start(crate::now(), &error);
                            format!("зависимый AWG {consumer_id} будет подключён повторно: {error}")
                        };
                        warning = Some(
                            warning
                                .map_or_else(|| message.clone(), |old| format!("{old}. {message}")),
                        );
                    }
                }
            }
        }
        Ok(warning)
    }

    pub fn delete_profile(
        &self,
        db: &Store,
        id: &str,
        to: Option<&str>,
        reference: impl FnOnce(&Value, &str) -> io::Result<Value>,
    ) -> io::Result<Option<String>> {
        self.delete_profile_with_route_check(db, id, to, reference, |_, _| {
            Err(invalid("сначала отключите активную маршрутизацию"))
        })
    }

    /// The route callback runs under the Store and client locks. It may inspect
    /// the candidate and the kernel, without using the client manager or Store writer.
    pub fn delete_profile_with_route_check(
        &self,
        db: &Store,
        id: &str,
        to: Option<&str>,
        reference: impl FnOnce(&Value, &str) -> io::Result<Value>,
        check_routes: impl FnOnce(&Value, &mut Value) -> io::Result<()>,
    ) -> io::Result<Option<String>> {
        self.delete_profile_inner(db, id, to, reference, check_routes, None)
    }

    pub fn delete_profile_with_transport(
        &self,
        db: &Store,
        id: &str,
        to: Option<&str>,
        reference: impl FnOnce(&Value, &str) -> io::Result<Value>,
        check_routes: impl FnOnce(&Value, &mut Value) -> io::Result<()>,
        (wan, refresh): (
            &[String],
            impl Fn(TransportBypassProof<'_>) -> io::Result<()>,
        ),
    ) -> io::Result<Option<String>> {
        self.delete_profile_inner(db, id, to, reference, check_routes, Some((wan, &refresh)))
    }

    fn delete_profile_inner(
        &self,
        db: &Store,
        id: &str,
        to: Option<&str>,
        reference: impl FnOnce(&Value, &str) -> io::Result<Value>,
        check_routes: impl FnOnce(&Value, &mut Value) -> io::Result<()>,
        transport: Option<(&[String], &RefreshTransport<'_>)>,
    ) -> io::Result<Option<String>> {
        let _deployment = self.deployment_guard()?;
        let mut owned = self
            .clients
            .0
            .lock()
            .map_err(|_| io::Error::other("менеджер туннелей недоступен"))?;
        let check_source = |doc: &Value, owned: &mut HashMap<String, Managed>| {
            let row = find(doc, id)?;
            let iface = iface(row, doc)?;
            if !owned.get_mut(id).is_some_and(|v| v.tunnel.alive()) && self.present(&iface)? {
                return Err(invalid("интерфейс управляется другим процессом"));
            }
            Ok(())
        };
        if to.is_none() {
            let before = read(db)?;
            if !active_policy(&before) {
                return self
                    .delete_unrouted_profile(db, &before, id, reference, &mut owned, transport);
            }
        }
        let saved_warning = if let Some(target) = to {
            db.transaction(|tx| {
                let before = read(db)?;
                check_source(&before, &mut owned)?;
                let check_unrelated_policy = active_policy(&before);
                let rows = before["servers"].as_array().unwrap();
                let mut dependents = HashSet::new();
                for row in rows {
                    if dependent(row, id, false)? {
                        dependents.insert(s(row, "id"));
                    }
                }
                for row in rows {
                    let owner = s(row, "id");
                    let participant = owner == id || owner == target || dependents.contains(owner);
                    if !participant && !(check_unrelated_policy && routes_use(&before, owner)) {
                        continue;
                    }
                    if settings::has_saved_edit(row)
                        || supervisor::pending_endpoint_restart(row)?.is_some()
                    {
                        return Err(invalid(
                            "сначала завершите изменение локального подключения",
                        ));
                    }
                    if participant
                        && (check_unrelated_policy || !dependents.is_empty())
                        && (routes_use(&before, owner)
                            || owned.get_mut(owner).is_some_and(|v| v.tunnel.alive())
                            || self.present(&iface(row, &before)?)?
                            || check_unrelated_policy
                                && row["applied_config"].is_object()
                                && self.present(&configured_iface(
                                    row,
                                    &before,
                                    &row["applied_config"],
                                )?)?)
                    {
                        return Err(invalid(
                            "сначала отключите подключения с изменяемым резервированием",
                        ));
                    }
                }
                let tombstone = reference(&before, id)?;
                let mut after = before.clone();
                let policy = if check_unrelated_policy {
                    TransferPolicy::UnrelatedActive
                } else {
                    TransferPolicy::Dormant
                };
                remove(&mut after, id, to, tombstone, policy)?;
                if check_unrelated_policy {
                    check_routes(&before, &mut after)?;
                }
                persist_active_replacement_locked(db, tx, &before, &after)
            })?
        } else {
            edit_document(db, |doc| {
                check_source(doc, &mut owned)?;
                let tombstone = reference(doc, id)?;
                remove(doc, id, None, tombstone, TransferPolicy::Dormant)
            })?;
            None
        };
        let stop_warning = owned
            .remove(id)
            .and_then(|mut v| v.tunnel.stop().err())
            .map(|e| format!("подключение удалено, ошибка остановки локального клиента: {e}"));
        Ok(match (saved_warning, stop_warning) {
            (Some(save), Some(stop)) => Some(format!("{save}. {stop}")),
            (save, stop) => save.or(stop),
        })
    }

    pub fn delete_active_profile_with_routes(
        &self,
        db: &Store,
        id: &str,
        target: &str,
        wan: &[String],
        reference: impl FnOnce(&Value, &str) -> io::Result<Value>,
        transfer: impl FnOnce(
            &nfqws2_store::Transaction<'_>,
            &Value,
            &Value,
            &[ActiveReplacementPeer; 2],
        ) -> io::Result<Option<String>>,
    ) -> io::Result<Option<String>> {
        self.delete_active_profile(
            db,
            id,
            target,
            wan,
            reference,
            (None, None, |tx, before, after, peers, _| {
                transfer(tx, before, after, peers)
            }),
        )
    }

    pub fn delete_active_profile_with_standby(
        &self,
        db: &Store,
        id: &str,
        target: &str,
        wan: &[String],
        reference: impl FnOnce(&Value, &str) -> io::Result<Value>,
        (prepare, transfer): (
            ActiveReplacementPreparation<'_>,
            impl FnOnce(
                &nfqws2_store::Transaction<'_>,
                &Value,
                &Value,
                &[ActiveReplacementPeer; 2],
            ) -> io::Result<Option<String>>,
        ),
    ) -> io::Result<Option<String>> {
        self.delete_active_profile(
            db,
            id,
            target,
            wan,
            reference,
            (Some(prepare), None, |tx, before, after, peers, _| {
                transfer(tx, before, after, peers)
            }),
        )
    }

    pub fn delete_active_profile_with_held_peer(
        &self,
        db: &Store,
        id: &str,
        target: &str,
        wan: &[String],
        reference: impl FnOnce(&Value, &str) -> io::Result<Value>,
        (held, prepare, transfer): (
            &str,
            ActiveReplacementPreparation<'_>,
            impl FnOnce(
                &nfqws2_store::Transaction<'_>,
                &Value,
                &Value,
                &[ActiveReplacementPeer; 2],
                &ActiveReplacementPeer,
            ) -> io::Result<Option<String>>,
        ),
    ) -> io::Result<Option<String>> {
        self.delete_active_profile(
            db,
            id,
            target,
            wan,
            reference,
            (
                Some(prepare),
                Some(held),
                |tx, before, after, peers, held| {
                    transfer(
                        tx,
                        before,
                        after,
                        peers,
                        held.ok_or(io::ErrorKind::WouldBlock)?,
                    )
                },
            ),
        )
    }

    pub fn delete_active_profile_with_disabled_target(
        &self,
        db: &Store,
        id: &str,
        target: &str,
        wan: &[String],
        reference: impl FnOnce(&Value, &str) -> io::Result<Value>,
        transfer: impl FnOnce(
            &nfqws2_store::Transaction<'_>,
            &Value,
            &Value,
            (&ActiveReplacementPeer, Option<&ActiveReplacementPeer>),
            &dyn Fn() -> io::Result<()>,
        ) -> io::Result<Option<String>>,
    ) -> io::Result<Option<String>> {
        let _deployment = self.deployment_guard()?;
        let mut owned = self
            .clients
            .0
            .lock()
            .map_err(|_| io::ErrorKind::WouldBlock)?;
        let before = read(db)?;
        let unavailable = || invalid("не подтверждён перенос правил на отключённое подключение");
        let target_iface =
            disabled_active_replacement_target(&before, target)?.ok_or_else(unavailable)?;
        let holder = before["rust_static_routing"]["committed_targets"]
            .as_array()
            .ok_or_else(unavailable)?;
        let held = match holder.as_slice() {
            [source] if source == id => None,
            [source, held] if source == id => Some(held.as_str().ok_or_else(unavailable)?),
            [held, source] if source == id => Some(held.as_str().ok_or_else(unavailable)?),
            _ => return Err(unavailable()),
        };
        let target_row = find(&before, target)?;
        if id == target
            || held == Some(target)
            || routes_use(&before, target)
            || target_row["applied_config"].is_object()
            || target_row["config"]["routing"]["mode"] == "off"
            || owned.get_mut(target).is_some_and(|v| v.tunnel.alive())
        {
            return Err(unavailable());
        }
        for name in [id, target].into_iter().chain(held) {
            let row = find(&before, name)?;
            if settings::has_saved_edit(row) || supervisor::pending_endpoint_restart(row)?.is_some()
            {
                return Err(unavailable());
            }
        }
        let mut after = before.clone();
        remove(
            &mut after,
            id,
            Some(target),
            reference(&before, id)?,
            TransferPolicy::Active,
        )?;
        if active_replacement_topology(&before, &after, id, target)? {
            return Err(unavailable());
        }
        let sample = |name| {
            self.active_replacement_sample(
                &before,
                name,
                owned.get(name).ok_or_else(unavailable)?,
                wan,
                ReplacementSample::RunningPrimary,
                Some(&owned),
            )
        };
        let source = sample(id)?;
        let other = held.map(sample).transpose()?;
        let verify = || {
            if self.present(&target_iface)?
                || sample(id)? != source
                || held.map(sample).transpose()? != other
            {
                return Err(unavailable());
            }
            Ok(())
        };
        db.transaction(|tx| {
            unchanged_replacement(db, &before)?;
            verify()?;
            transfer(tx, &before, &after, (&source, other.as_ref()), &verify)
        })
    }

    fn active_replacement_sample(
        &self,
        before: &Value,
        name: &str,
        current: &Managed,
        wan: &[String],
        sample: ReplacementSample,
        source_owners: Option<&HashMap<String, Managed>>,
    ) -> io::Result<ActiveReplacementPeer> {
        let row = find(before, name)?;
        let warm = matches!(sample, ReplacementSample::WarmNamedIpv6 { .. });
        let (provisional, pinned) = match sample {
            ReplacementSample::RunningPrimary
            | ReplacementSample::RunningFullReserveDraft
            | ReplacementSample::RunningWithNumericBackups => (false, None),
            ReplacementSample::Provisional(endpoint) => (true, endpoint),
            ReplacementSample::WarmNamedIpv6 {
                endpoint,
                provisional,
            } => (provisional, Some(endpoint)),
            ReplacementSample::ColdConfigured { provisional, .. }
            | ReplacementSample::ColdReserve { provisional, .. } => (provisional, None),
        };
        let numeric_pool = if matches!(
            sample,
            ReplacementSample::RunningWithNumericBackups
                | ReplacementSample::ColdConfigured { .. }
                | ReplacementSample::ColdReserve { .. }
        ) && !fallbacks(&row["config"]["client"]["endpoint_backups"])?
            .is_empty()
        {
            Some(numeric_backup_pool(before, row)?)
        } else {
            None
        };
        let literal = if matches!(sample, ReplacementSample::RunningFullReserveDraft) {
            configured_direct_endpoint(row)
        } else {
            numeric_pool
                .as_ref()
                .map_or_else(|| direct_endpoint(before, row), |pool| Ok(pool[0]))
        };
        if let ReplacementSample::ColdReserve { endpoint, .. } = sample {
            if numeric_pool
                .as_ref()
                .is_none_or(|pool| !pool[1..].contains(&endpoint))
            {
                return Err(invalid("не подтверждён выбранный резервный endpoint AWG"));
            }
        }
        let (literal, port) = match literal {
            Ok(endpoint) => (Some(endpoint), endpoint.port()),
            Err(_)
                if (!provisional || pinned.is_some())
                    && current.tunnel.nested_iface().is_none() =>
            {
                (None, named_endpoint(before, row)?.1)
            }
            Err(error) => return Err(error),
        };
        let spec = saved_specification(before, row, false)?;
        let unavailable = || invalid("не подтверждён внешний AWG переносимого профиля");
        let outer = if let Some(iface) = current.tunnel.nested_iface() {
            let owners = source_owners.ok_or_else(unavailable)?;
            let id = configured_replacement_outer(before, row)?.ok_or_else(unavailable)?;
            let owner = owners.get(id).ok_or_else(unavailable)?;
            let (spec, endpoint) = replacement_underlay_spec(before, id)?;
            let (live, nested) = owner.tunnel.active_replacement_peer(
                &spec,
                &find(before, id)?["config"],
                false,
                None,
            )?;
            if nested.is_some()
                || owner.iface != iface
                || spec.iface != iface
                || live.owner.id != id
                || live.owner.iface != iface
                || live.fingerprint != owner.fingerprint
                || live.endpoint != endpoint
                || !self.verifies_live_wan_path(endpoint, live.socket_mark, wan, true)
            {
                return Err(unavailable());
            }
            Some((NestedOuter::from_spec(&spec)?, live))
        } else {
            None
        };
        if spec.permanent && outer.is_none() {
            return Err(unavailable());
        }
        let (mut peer, observed_outer) = if let ReplacementSample::ColdConfigured {
            before_first_handshake,
            ..
        } = sample
        {
            if outer.is_some() {
                return Err(unavailable());
            }
            if numeric_pool.is_none() {
                configured_startup_literal(before, row)?;
            }
            (
                current.tunnel.configured_cold_replacement_peer(
                    &spec,
                    &row["config"],
                    provisional,
                    before_first_handshake,
                )?,
                None,
            )
        } else {
            current.tunnel.active_replacement_peer(
                &spec,
                &row["config"],
                provisional,
                outer.as_ref().map(|(expected, _)| expected),
            )?
        };
        let endpoint = if let Some(pool) = numeric_pool {
            if !pool.contains(&peer.endpoint) {
                return Err(unavailable());
            }
            match sample {
                ReplacementSample::ColdConfigured { .. } => pool[0],
                ReplacementSample::ColdReserve { endpoint, .. } => endpoint,
                _ => peer.endpoint,
            }
        } else if let Some(endpoint) = literal {
            endpoint
        } else {
            if peer.endpoint.is_ipv6() != warm
                || peer.endpoint.port() != port
                || pinned.is_some_and(|endpoint| peer.endpoint != endpoint)
            {
                return Err(unavailable());
            }
            peer.endpoint
        };
        match (outer, observed_outer) {
            (Some((_, native)), Some(observed))
                if observed.endpoint == Some(native.endpoint)
                    && observed.socket_mark == native.socket_mark =>
            {
                peer.underlay = Some(ActiveReplacementUnderlay {
                    owner: native.owner,
                    fingerprint: native.fingerprint,
                    endpoint: native.endpoint,
                    socket_mark: native.socket_mark,
                    mtu: native.mtu,
                    allowed: native.allowed,
                });
            }
            (None, None) => (),
            _ => return Err(unavailable()),
        }
        let fingerprint: [u8; 32] = Sha256::digest(spec.conf.as_bytes()).into();
        let transport_mark = if peer.underlay.is_some() {
            0
        } else {
            peer.socket_mark
        };
        let on_wan = self.verifies_live_wan_path(endpoint, transport_mark, wan, true);
        peer.nested_only = !on_wan
            && spec.permanent
            && peer.underlay.is_some()
            && source_owners.is_some_and(|owners| {
                self.no_live_direct_claim(before, owners, endpoint.ip())
                    .unwrap_or(false)
            });
        if peer.fingerprint != fingerprint
            || current.fingerprint != fingerprint
            || current.iface != spec.iface
            || peer.owner.iface != spec.iface
            || peer.owner.id != spec.id
            || peer.endpoint != endpoint
            || warm && peer.socket_mark != crate::DIRECT_SOCKET_MARK
            || !on_wan && !peer.nested_only
        {
            return Err(invalid("не подтверждён работающий прямой транспорт AWG"));
        }
        Ok(peer)
    }

    fn no_live_direct_claim(
        &self,
        doc: &Value,
        owners: &HashMap<String, Managed>,
        ip: std::net::IpAddr,
    ) -> io::Result<bool> {
        let rows = doc["servers"]
            .as_array()
            .ok_or_else(|| invalid("нет списка AWG"))?;
        for row in rows {
            let recorded = owners.get(s(row, "id"));
            let cfg = iface(row, doc)?;
            if recorded.is_none_or(|owner| owner.iface != cfg) && self.present(&cfg)? {
                return Ok(false);
            }
            if row["applied_config"].is_object() {
                let applied = configured_iface(row, doc, &row["applied_config"])?;
                if applied != cfg
                    && recorded.is_none_or(|owner| owner.iface != applied)
                    && self.present(&applied)?
                {
                    return Ok(false);
                }
            }
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        for owner in owners.values() {
            if std::time::Instant::now() >= deadline || owner.tunnel.inherited() {
                return Ok(false);
            }
            let live = owner.tunnel.snapshot()?;
            let mark = live["socket_mark"]
                .as_u64()
                .and_then(|v| u32::try_from(v).ok());
            if matches!(mark, Some(0 | crate::DIRECT_SOCKET_MARK)) {
                if supervisor::live_transport_endpoint(&live)
                    .is_none_or(|address| address.ip() == ip)
                {
                    return Ok(false);
                }
            } else if owner.tunnel.nested_iface().is_none()
                || mark != Some(super::nested_socket_selector(&owner.iface)?.0)
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Confirm a current direct native owner without waiting on client operations.
    pub fn routing_active_replacement_peer(
        &self,
        db: &Store,
        iface: &str,
        endpoint: SocketAddr,
        socket_mark: u32,
        wan: &[String],
    ) -> io::Result<Option<ActiveReplacementPeer>> {
        if !matches!(socket_mark, 0 | crate::DIRECT_SOCKET_MARK) {
            return Ok(None);
        }
        self.routing_replacement_peer(db, iface, endpoint, wan, (socket_mark, false))
    }

    /// Recheck only the exact previously authorized same-boot named IPv6 owner.
    pub fn routing_warm_named_ipv6_peer(
        &self,
        db: &Store,
        owner: &NativeRemovalSeal,
        endpoint: SocketAddr,
        wan: &[String],
    ) -> io::Result<ActiveReplacementPeer> {
        let doc = read(db)?;
        validate_warm_named_ipv6(&doc, &owner.id, &[endpoint])?;
        #[cfg(target_os = "linux")]
        {
            let row = find(&doc, &owner.id)?;
            let spec = saved_specification(&doc, row, false)?;
            let peer = linux::observed_warm_direct_peer(self, &spec, &row["config"], owner)?;
            if peer.endpoint != endpoint || !self.verifies_live_wan_path(endpoint, peer.socket_mark, wan, true) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            Ok(peer)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = wan;
            Err(io::ErrorKind::Unsupported.into())
        }
    }

    /// Confirm the exact daemon and configured socket during a cold numeric transfer,
    /// while the installed transport has yet to produce its first handshake.
    pub fn routing_cold_numeric_replacement_peer(
        &self,
        db: &Store,
        owner: &NativeRemovalSeal,
        binding: [u8; 32],
        wan: &[String],
    ) -> io::Result<ActiveReplacementPeer> {
        let doc = read(db)?;
        let row = find(&doc, &owner.id)?;
        let observed = active_replacement_startup_binding(&doc, &owner.id)?;
        if row["config"]["client"]["standby"] != false
            || row["config"]["routing"]["active"] != true
            || observed != binding
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let owned = self
            .clients
            .0
            .try_lock()
            .map_err(|_| io::ErrorKind::WouldBlock)?;
        let current = owned.get(&owner.id).ok_or(io::ErrorKind::NotFound)?;
        let peer = self.active_replacement_sample(
            &doc,
            &owner.id,
            current,
            wan,
            ReplacementSample::ColdConfigured {
                provisional: false,
                before_first_handshake: true,
            },
            None,
        )?;
        if &peer.owner != owner {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        Ok(peer)
    }

    /// Confirm the currently selected marked source and its independent outer owner.
    pub fn routing_nested_active_replacement_peer(
        &self,
        db: &Store,
        iface: &str,
        endpoint: SocketAddr,
        socket_mark: u32,
        wan: &[String],
    ) -> io::Result<Option<ActiveReplacementPeer>> {
        if socket_mark >> 28 != 0xa || super::nested_socket_selector(iface)?.0 != socket_mark {
            return Ok(None);
        }
        self.routing_replacement_peer(db, iface, endpoint, wan, (socket_mark, true))
    }

    fn routing_replacement_peer(
        &self,
        db: &Store,
        iface: &str,
        endpoint: SocketAddr,
        wan: &[String],
        (socket_mark, nested): (u32, bool),
    ) -> io::Result<Option<ActiveReplacementPeer>> {
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
            || managed.tunnel.nested_iface().is_some() != nested
        {
            return Ok(None);
        }
        let doc = read(db)?;
        let full_draft = !nested
            && native_full_reserve_draft(&doc)
                .is_some_and(|rows| rows.iter().any(|row| row["id"] == id.as_str()));
        let peer = self.active_replacement_sample(
            &doc,
            id,
            managed,
            wan,
            if full_draft {
                ReplacementSample::RunningFullReserveDraft
            } else {
                ReplacementSample::RunningPrimary
            },
            nested.then_some(&*owned),
        )?;
        Ok((peer.endpoint == endpoint && peer.socket_mark == socket_mark).then_some(peer))
    }

    fn delete_active_profile(
        &self,
        db: &Store,
        id: &str,
        target: &str,
        wan: &[String],
        reference: impl FnOnce(&Value, &str) -> io::Result<Value>,
        (prepare, held, transfer): (
            Option<ActiveReplacementPreparation<'_>>,
            Option<&str>,
            impl FnOnce(
                &nfqws2_store::Transaction<'_>,
                &Value,
                &Value,
                &[ActiveReplacementPeer; 2],
                Option<&ActiveReplacementPeer>,
            ) -> io::Result<Option<String>>,
        ),
    ) -> io::Result<Option<String>> {
        let _deployment = self.deployment_guard()?;
        let mut owned = self
            .clients
            .0
            .lock()
            .map_err(|_| io::Error::other("менеджер туннелей недоступен"))?;
        let before = read(db)?;
        if id == target
            || !routes_use(&before, id)
            || routes_use(&before, target) && held != Some(target)
        {
            return Err(invalid("нужно выбрать другое работающее подключение"));
        }
        let tombstone = reference(&before, id)?;
        let mut after = before.clone();
        remove(
            &mut after,
            id,
            Some(target),
            tombstone,
            TransferPolicy::Active,
        )?;
        let has_outer = active_replacement_topology(&before, &after, id, target)?;
        if held.is_some_and(|held| held == id || has_outer || !routes_use(&before, held)) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let target_running = owned
            .get_mut(target)
            .is_some_and(|peer| peer.tunnel.alive());
        let target_row = find(&before, target)?;
        let cold_numeric = if !target_running
            && !has_outer
            && held.is_none()
            && !fallbacks(&target_row["config"]["client"]["endpoint_backups"])?.is_empty()
        {
            Some(numeric_backup_pool(&before, target_row)?[0])
        } else {
            None
        };
        let warm_target = std::cell::Cell::new(None);
        let ready = |owners: &HashMap<String, Managed>, name| {
            let sample = if let Some(endpoint) = warm_target.get().filter(|_| name == target) {
                ReplacementSample::WarmNamedIpv6 {
                    endpoint,
                    provisional: false,
                }
            } else if (target_running || cold_numeric.is_some()) && !has_outer && held.is_none() {
                ReplacementSample::RunningWithNumericBackups
            } else {
                ReplacementSample::RunningPrimary
            };
            self.active_replacement_sample(
                &before,
                name,
                owners.get(name).ok_or(io::ErrorKind::WouldBlock)?,
                wan,
                sample,
                Some(owners),
            )
        };
        let launch_mode = if !target_running {
            if has_outer {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let prepare = prepare.ok_or(io::ErrorKind::WouldBlock)?;
            let row = target_row;
            let literal = cold_numeric.map_or_else(|| direct_endpoint(&before, row), Ok);
            let named = if literal.is_err() && held.is_none() {
                prepare
                    .named
                    .map(|check| named_endpoint(&before, row).map(|_| check))
                    .transpose()?
            } else {
                None
            };
            if named.is_none() && literal.is_err() {
                return literal.map(|_| None);
            }
            let mut spec = saved_specification(&before, row, false)?;
            if self.present(&spec.iface)?
                || owned
                    .get(id)
                    .is_some_and(|source| source.iface == spec.iface)
            {
                return Err(invalid("интерфейс выбранного подключения занят"));
            }
            let fingerprint = Sha256::digest(spec.conf.as_bytes()).into();
            let iface = spec.iface.clone();
            if prepare.defer_unresolved_name {
                if named.is_none() || owned.contains_key(target) {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                let source = ready(&owned, id)?;
                let saved = (prepare.defer)(ActiveReplacementStage {
                    before: &before,
                    after: &after,
                    source: &source,
                    held: None,
                    target,
                    provisional: None,
                })?;
                if saved.is_some() {
                    enroll_deferred_named(
                        db,
                        &mut owned,
                        (id, target),
                        iface,
                        fingerprint,
                        &io::ErrorKind::NotFound.into(),
                    );
                }
                return Ok(saved);
            }
            let stage = |owners: &HashMap<String, Managed>,
                         provisional: Option<&ActiveReplacementPeer>| {
                let source = ready(owners, id)?;
                let held = held.map(|held| ready(owners, held)).transpose()?;
                let stage = ActiveReplacementStage {
                    before: &before,
                    after: &after,
                    source: &source,
                    held: held.as_ref(),
                    target,
                    provisional,
                };
                match named {
                    Some(check) => check(stage)
                        .map(|pin| (Some(pin), ActiveReplacementLaunchMode::Authenticate)),
                    None => (prepare.check)(stage).map(|mode| (None, mode)),
                }
            };
            let (pin, launch_mode) = stage(&owned, None)?;
            if launch_mode != ActiveReplacementLaunchMode::Authenticate && held.is_some() {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let endpoint = match pin {
                Some(pin) => {
                    if pin.warm_ipv6 {
                        validate_warm_named_ipv6(&before, target, &[pin.endpoint])?;
                        warm_target.set(Some(pin.endpoint));
                    } else {
                        validate_active_named_replacement(&before, target, &[pin.endpoint])?;
                    }
                    if std::time::Instant::now() >= pin.deadline {
                        return Err(io::ErrorKind::TimedOut.into());
                    }
                    pin.endpoint
                }
                None => match launch_mode {
                    ActiveReplacementLaunchMode::Reserve(endpoint) => {
                        if !active_replacement_numeric_pool(&before, target)?
                            .reserves()
                            .contains(&endpoint)
                        {
                            return Err(invalid("не подтверждён выбранный резервный endpoint AWG"));
                        }
                        endpoint
                    }
                    _ => literal?,
                },
            };
            if let Some(old) = owned.get_mut(target) {
                old.tunnel.stop()?;
                owned.remove(target);
            }
            let inherited = self.capture_inherited_transport(&before, &owned, wan);
            let refresh = |mut proof: TransportBypassProof<'_>| {
                if let Some(pin) = pin {
                    proof.deadline = proof.deadline.min(pin.deadline);
                    if std::time::Instant::now() >= proof.deadline {
                        return Err(io::ErrorKind::TimedOut.into());
                    }
                }
                unchanged_replacement(db, &before)?;
                (prepare.refresh)(proof)?;
                unchanged_replacement(db, &before)
            };
            spec.endpoint = endpoint.to_string();
            let launched = (|| -> io::Result<_> {
                let fresh = pin.map(|pin| (pin, crate::now()));
                let tunnel = self.start_temporary(
                    spec,
                    wan,
                    pin.is_some_and(|pin| pin.warm_ipv6),
                    Some((&refresh, &inherited)),
                )?;
                let mut provisional = Managed {
                    tunnel,
                    iface: iface.clone(),
                    fingerprint,
                    recovery: Default::default(),
                };
                let settings = crate::recovery_settings(&before["recovery_settings"]);
                if launch_mode == ActiveReplacementLaunchMode::ConfiguredPrimary {
                    provisional.tunnel.probe_at(endpoint)?;
                } else {
                    wait_standby_handshake(
                        provisional.tunnel.as_mut(),
                        endpoint,
                        std::time::Duration::from_secs(
                            settings["handshake_timeout_seconds"].as_u64().unwrap_or(20),
                        ),
                        fresh,
                    )?;
                }
                Ok(provisional)
            })();
            let mut provisional = match launched {
                Ok(provisional) => provisional,
                Err(error) => {
                    let named_uncertain = pin.is_some_and(|pin| {
                        pin.warm_ipv6
                            || std::time::Instant::now() >= pin.deadline
                            || matches!(
                                error.kind(),
                                io::ErrorKind::Interrupted | io::ErrorKind::PermissionDenied
                            )
                    });
                    if named_uncertain
                        || cold_numeric.is_some()
                        || error.kind() == io::ErrorKind::WouldBlock
                        || self.present(&iface)?
                    {
                        return Err(error);
                    }
                    unchanged_replacement(db, &before)?;
                    let source = ready(&owned, id)?;
                    let held = held.map(|held| ready(&owned, held)).transpose()?;
                    let saved = (prepare.defer)(ActiveReplacementStage {
                        before: &before,
                        after: &after,
                        source: &source,
                        held: held.as_ref(),
                        target,
                        provisional: None,
                    })?;
                    if pin.is_some() && saved.is_some() {
                        enroll_deferred_named(
                            db,
                            &mut owned,
                            (id, target),
                            iface,
                            fingerprint,
                            &error,
                        );
                    }
                    return Ok(saved);
                }
            };
            let phase = match launch_mode {
                ActiveReplacementLaunchMode::ConfiguredPrimary => {
                    ReplacementSample::ColdConfigured {
                        provisional: true,
                        before_first_handshake: false,
                    }
                }
                ActiveReplacementLaunchMode::Reserve(endpoint) => ReplacementSample::ColdReserve {
                    provisional: true,
                    endpoint,
                },
                ActiveReplacementLaunchMode::Authenticate => match warm_target.get() {
                    Some(endpoint) => ReplacementSample::WarmNamedIpv6 {
                        endpoint,
                        provisional: true,
                    },
                    None => ReplacementSample::Provisional(pin.map(|pin| pin.endpoint)),
                },
            };
            let peer =
                self.active_replacement_sample(&before, target, &provisional, wan, phase, None)?;
            if stage(&owned, Some(&peer))? != (pin, launch_mode) {
                return Err(invalid("подтверждение запуска AWG изменилось"));
            }
            // The durable cleanup lease precedes guardian detachment.
            provisional
                .tunnel
                .commit_temporary_replacement(&peer.owner)?;
            if let ActiveReplacementLaunchMode::Reserve(endpoint) = launch_mode {
                provisional.recovery = super::supervisor::Recovery::at_numeric_reserve(endpoint);
            }
            owned.insert(target.to_owned(), provisional);
            launch_mode
        } else {
            ActiveReplacementLaunchMode::Authenticate
        };
        db.transaction(|tx| {
            unchanged_replacement(db, &before)?;
            let sample = match launch_mode {
                ActiveReplacementLaunchMode::ConfiguredPrimary => {
                    Some(ReplacementSample::ColdConfigured {
                        provisional: false,
                        before_first_handshake: false,
                    })
                }
                ActiveReplacementLaunchMode::Reserve(endpoint) => {
                    Some(ReplacementSample::ColdReserve {
                        provisional: false,
                        endpoint,
                    })
                }
                ActiveReplacementLaunchMode::Authenticate => None,
            };
            let receiver = if let Some(sample) = sample {
                self.active_replacement_sample(
                    &before,
                    target,
                    owned.get(target).ok_or(io::ErrorKind::WouldBlock)?,
                    wan,
                    sample,
                    None,
                )?
            } else {
                ready(&owned, target)?
            };
            let peers = [ready(&owned, id)?, receiver];
            let independent = held
                .filter(|&held| held != target)
                .map(|held| ready(&owned, held))
                .transpose()?;
            let held = if held == Some(target) {
                Some(&peers[1])
            } else {
                independent.as_ref()
            };
            // Keep the original owner registered until both the FIB and saved
            // candidate are confirmed. A durable lease handles its retirement.
            transfer(tx, &before, &after, &peers, held)
        })
    }

    pub fn retire_active_replacement(&self, seal: &NativeRemovalSeal) -> io::Result<()> {
        if !seal.valid() {
            return Err(invalid("неверная запись удаления AWG"));
        }
        let _deployment = self.deployment_guard()?;
        let mut owned = self
            .clients
            .0
            .lock()
            .map_err(|_| io::Error::other("менеджер туннелей недоступен"))?;
        if let Some(current) = owned.get_mut(&seal.id) {
            if current.iface != seal.iface || current.tunnel.native_removal_seal()?.ne(seal) {
                return Err(invalid("личность удаляемого AWG не подтверждена"));
            }
            current.tunnel.stop()?;
            owned.remove(&seal.id);
            return Ok(());
        }
        #[cfg(target_os = "linux")]
        return linux::retire_sealed(self, seal);
        #[cfg(not(target_os = "linux"))]
        Err(io::ErrorKind::Unsupported.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires the isolated Linux guest and a dummy WAN"]
    fn disabled_target_uses_only_the_existing_source_and_held_receipts() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering::Relaxed},
            Arc,
        };
        assert_eq!(
            std::fs::read_to_string("/synthetic-guest").unwrap().trim(),
            "ea1-qemu-airgap"
        );
        let current = std::fs::read_link("/proc/self/ns/net").unwrap();
        let parent = std::env::var("N2S_PARENT_NET").unwrap();
        assert_ne!(current, std::path::Path::new(&parent));

        struct Witness(ActiveReplacementPeer, Arc<AtomicUsize>);
        impl Tunnel for Witness {
            fn alive(&mut self) -> bool {
                true
            }
            fn stop(&mut self) -> io::Result<()> {
                self.1.fetch_add(1, Relaxed);
                Ok(())
            }
            fn probe(&mut self) -> io::Result<()> {
                unreachable!()
            }
            fn snapshot(&self) -> io::Result<Value> {
                unreachable!()
            }
            fn native_removal_seal(&self) -> io::Result<NativeRemovalSeal> {
                Ok(self.0.owner.clone())
            }
            fn active_replacement_peer(
                &self,
                spec: &Spec,
                _: &Value,
                provisional: bool,
                outer: Option<&NestedOuter>,
            ) -> io::Result<(ActiveReplacementPeer, Option<super::super::NestedOuterPeer>)>
            {
                assert!(!provisional && outer.is_none());
                assert!(spec.id == self.0.owner.id && spec.iface == self.0.owner.iface);
                Ok((self.0.clone(), None))
            }
        }

        for server_disabled in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let db = Store::open(dir.path()).unwrap();
            crate::import(&db, &crate::tests::input(), "fixture").unwrap();
            edit_document(&db, |doc| {
                let mut source = doc["servers"].as_array().unwrap().last().unwrap().clone();
                source["id"] = json!("source");
                source["config"]["client_iface"] = json!("awg0");
                source["config"]["endpoint"] = json!("198.51.100.10:443");
                source["config"]["client"]["enabled"] = json!(true);
                source["config"]["client"]["rust_managed"] = json!(true);
                source["config"]["routing"] = json!({"mode":"zones", "active":true,
                    "zones":[{"enabled":true,"order":1,"ips":["203.0.113.90/32"]}]});
                let mut target = source.clone();
                target["id"] = json!("target");
                target["config"]["client_iface"] = json!("awg91");
                target["config"]["enabled"] = json!(!server_disabled);
                target["config"]["client"]["enabled"] = json!(server_disabled);
                target["config"]["client"]["standby"] = json!(true);
                target["config"]["routing"] = json!({"mode":"zones", "active":false, "zones":[]});
                let mut held = source.clone();
                held["id"] = json!("held");
                held["config"]["client_iface"] = json!("awg2");
                held["config"]["endpoint"] = json!("198.51.100.12:443");
                held["config"]["routing"]["zones"] =
                    json!([{"enabled":true,"order":2,"tunnel_id":"held","ips":["203.0.113.92/32"]}]);
                doc["servers"] = json!([source, target, held]);
                doc["active_id"] = json!("source");
                doc["rust_static_routing"] =
                    json!({"targets":["held", "source"], "committed_targets":["held", "source"]});
                Ok(())
            })
            .unwrap();
            let before = read(&db).unwrap();
            let runtime = Runtime::new(std::path::Path::new("/"), dir.path().join("no-engine"));
            let stopped = [Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0))];
            let [source, held] =
                [("source", "awg0", 0), ("held", "awg2", 1)].map(|(id, iface, n)| {
                    let row = find(&before, id).unwrap();
                    let spec = saved_specification(&before, row, false).unwrap();
                    let fingerprint = Sha256::digest(spec.conf.as_bytes()).into();
                    let owner = NativeRemovalSeal {
                        id: id.into(),
                        iface: iface.into(),
                        boot: "12121212-1212-1212-1212-121212121212".into(),
                        pid: 200 + n as u32,
                        started: 300 + n as u64,
                        receipt_sha256: [n as u8 + 1; 32],
                        nested: None,
                    };
                    let attested = ActiveReplacementPeer {
                        owner: owner.clone(),
                        fingerprint,
                        endpoint: direct_endpoint(&before, row).unwrap(),
                        socket_mark: crate::DIRECT_SOCKET_MARK,
                        mtu: 1420,
                        allowed: vec!["0.0.0.0/0".into()],
                        underlay: None,
                        nested_only: false,
                    };
                    runtime.clients.0.lock().unwrap().insert(
                        id.into(),
                        Managed {
                            iface: iface.into(),
                            fingerprint,
                            recovery: Default::default(),
                            tunnel: Box::new(Witness(attested, stopped[n].clone())),
                        },
                    );
                    owner
                });
            runtime
                .delete_active_profile_with_disabled_target(
                    &db,
                    "source",
                    "target",
                    &["wan0".into()],
                    |_, id| Ok(json!({"id":id})),
                    |tx, before, after, pair, still_current| {
                        still_current()?;
                        assert_eq!(pair.0.owner, source);
                        assert_eq!(pair.1.map(|peer| &peer.owner), Some(&held));
                        let target = &find(after, "target")?["config"];
                        assert!(
                            target["routing"]["active"] == true
                                && target["client"]["standby"] == false
                        );
                        assert_eq!(target["enabled"], !server_disabled);
                        assert_eq!(target["client"]["enabled"], server_disabled);
                        assert_eq!(target["routing"]["zones"][0]["tunnel_id"], "target");
                        assert!(find(after, "held")? == find(before, "held")?);
                        persist_active_replacement_locked(&db, tx, before, after)
                    },
                )
                .unwrap();
            assert!(!runtime.present("awg91").unwrap());
            assert_eq!(stopped[0].load(Relaxed), 0);
            assert_eq!(stopped[1].load(Relaxed), 0);
            runtime.retire_active_replacement(&source).unwrap();
            assert_eq!(stopped[0].load(Relaxed), 1);
            assert_eq!(stopped[1].load(Relaxed), 0);
            assert_eq!(read(&db).unwrap()["active_id"], "target");
        }
    }

    #[test]
    fn nested_only_claim_rejects_roamed_direct_peers_and_untracked_interfaces() {
        struct Direct(SocketAddr);
        impl Tunnel for Direct {
            fn alive(&mut self) -> bool {
                true
            }
            fn stop(&mut self) -> io::Result<()> {
                panic!("claim proof stopped a peer")
            }
            fn probe(&mut self) -> io::Result<()> {
                panic!("claim proof probed a peer")
            }
            fn snapshot(&self) -> io::Result<Value> {
                Ok(json!({
                    "running":true,
                    "endpoint":self.0.to_string(),
                    "socket_mark":crate::DIRECT_SOCKET_MARK
                }))
            }
        }
        let root = tempfile::tempdir().unwrap();
        let runtime = Runtime::new(root.path(), root.path().join("engine"));
        let doc = json!({"servers":[
            {"id":"other","config":{"client_iface":"awg0","endpoint":"198.51.100.42:443"}},
            {"id":"vacant","config":{"client_iface":"awg1","endpoint":"198.51.100.43:443"}}
        ]});
        let primary = "198.51.100.11".parse().unwrap();
        let peer = |socket: &str| Managed {
            iface: "awg0".into(),
            fingerprint: [0; 32],
            recovery: Default::default(),
            tunnel: Box::new(Direct(socket.parse().unwrap())),
        };
        let mut owners = HashMap::from([("other".into(), peer("198.51.100.42:443"))]);
        assert!(runtime
            .no_live_direct_claim(&doc, &owners, primary)
            .unwrap());
        owners.insert("other".into(), peer("198.51.100.11:8443"));
        assert!(!runtime
            .no_live_direct_claim(&doc, &owners, primary)
            .unwrap());
        owners.insert("other".into(), peer("198.51.100.42:443"));
        std::fs::create_dir_all(root.path().join("sys/class/net/awg1")).unwrap();
        assert!(!runtime
            .no_live_direct_claim(&doc, &owners, primary)
            .unwrap());
    }

    #[test]
    fn retiring_outer_hold_preserves_only_the_exact_live_standby_without_starting() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        struct Standby(NativeRemovalSeal, Arc<AtomicUsize>);
        impl Tunnel for Standby {
            fn alive(&mut self) -> bool {
                true
            }
            fn stop(&mut self) -> io::Result<()> {
                self.1.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            fn probe(&mut self) -> io::Result<()> {
                panic!("standby hold probed owner")
            }
            fn snapshot(&self) -> io::Result<Value> {
                Ok(json!({"connected": false}))
            }
            fn native_removal_seal(&self) -> io::Result<NativeRemovalSeal> {
                Ok(self.0.clone())
            }
        }

        let outer = NativeRemovalSeal {
            id: "outer".into(),
            iface: "awg3".into(),
            boot: "12121212-1212-1212-1212-121212121212".into(),
            pid: 123,
            started: 456,
            receipt_sha256: [1; 32],
            nested: None,
        };
        let stops = Arc::new(AtomicUsize::new(0));
        let mut owned = HashMap::from([(
            outer.id.clone(),
            Managed {
                iface: outer.iface.clone(),
                fingerprint: [0; 32],
                recovery: Default::default(),
                tunnel: Box::new(Standby(outer.clone(), stops.clone())),
            },
        )]);
        let mut doc = json!({ "servers": [{ "id":"outer", "config": {
                "enabled":true, "client":{"enabled":true,"rust_managed":true,"standby":true}
            }}], "rust_active_replacement":{
                "id":"removed", "token":"12".repeat(32), "retained_outer": outer
            }
        });
        let settings = crate::recovery_settings(&Value::Null);
        let mut events = vec![];
        let mut empty = HashMap::new();
        assert!(retained_replacement_outer(&doc, &mut empty).is_none());
        failover::reconcile(&doc, &mut empty, 100, &settings, &mut events, None, |_| {
            panic!("held standby launched")
        })
        .unwrap();

        let saved = doc[ACTIVE_REPLACEMENT_FIELD].clone();
        doc[ACTIVE_REPLACEMENT_FIELD]["retained_outer"]["started"] = json!(outer.started + 1);
        assert!(retained_replacement_outer(&doc, &mut owned).is_none());
        doc[ACTIVE_REPLACEMENT_FIELD] = saved;
        let held = retained_replacement_outer(&doc, &mut owned);
        assert_eq!(held.as_deref(), Some("outer"));
        failover::reconcile(
            &doc,
            &mut owned,
            100,
            &settings,
            &mut events,
            held.as_deref(),
            |_| panic!("held standby relaunched"),
        )
        .unwrap();
        assert_eq!(stops.load(Ordering::Relaxed), 0);

        doc.as_object_mut()
            .unwrap()
            .remove(ACTIVE_REPLACEMENT_FIELD);
        assert!(retained_replacement_outer(&doc, &mut owned).is_none());
        failover::reconcile(&doc, &mut owned, 100, &settings, &mut events, None, |_| {
            panic!("released standby relaunched")
        })
        .unwrap();
        assert!(owned.is_empty());
        assert_eq!(stops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn replacement_replay_skips_nested_and_never_waits_for_native_ownership() {
        let root = tempfile::tempdir().unwrap();
        let db = Store::open(root.path()).unwrap();
        let runtime = Runtime::new(root.path(), root.path().join("engine"));
        let endpoint = "198.51.100.31:51820".parse().unwrap();
        let owned = runtime.clients.0.lock().unwrap();
        assert!(runtime
            .routing_active_replacement_peer(&db, "awg3", endpoint, 0xa021_0000, &[])
            .unwrap()
            .is_none());
        let busy = runtime.routing_active_replacement_peer(&db, "awg3", endpoint, 0, &[]);
        assert_eq!(busy.err().unwrap().kind(), io::ErrorKind::WouldBlock);
        drop(owned);
        assert!(runtime
            .routing_active_replacement_peer(&db, "awg3", endpoint, 0, &[])
            .unwrap()
            .is_none());
    }

    #[test]
    fn cold_replacement_waits_for_real_handshake_and_preserves_timeout() {
        use std::time::Duration;
        struct Provisional {
            ready: bool,
            probed: bool,
        }
        impl Tunnel for Provisional {
            fn alive(&mut self) -> bool {
                true
            }
            fn stop(&mut self) -> io::Result<()> {
                unreachable!()
            }
            fn probe(&mut self) -> io::Result<()> {
                unreachable!()
            }
            fn probe_at(&mut self, endpoint: SocketAddr) -> io::Result<()> {
                assert_eq!(endpoint.to_string(), "198.51.100.31:51820");
                self.probed = true;
                Ok(())
            }
            fn snapshot(&self) -> io::Result<Value> {
                assert!(self.probed);
                Ok(json!({"connected":self.ready,"last_handshake":if self.ready {42} else {0}}))
            }
        }
        let endpoint = "198.51.100.31:51820".parse().unwrap();
        let mut good = Provisional {
            ready: true,
            probed: false,
        };
        wait_standby_handshake(&mut good, endpoint, Duration::from_millis(500), None).unwrap();
        assert!(good.probed);
        let mut unready = Provisional {
            ready: false,
            probed: false,
        };
        assert_eq!(
            wait_standby_handshake(&mut unready, endpoint, Duration::from_millis(5), None)
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert!(unready.probed);
    }

    #[test]
    fn cold_named_replacement_requires_a_fresh_handshake_on_the_pinned_udp_tuple() {
        use std::time::{Duration, Instant};
        struct Sample(Value, bool);
        impl Tunnel for Sample {
            fn alive(&mut self) -> bool {
                true
            }
            fn stop(&mut self) -> io::Result<()> {
                Ok(())
            }
            fn probe(&mut self) -> io::Result<()> {
                unreachable!()
            }
            fn probe_at(&mut self, endpoint: SocketAddr) -> io::Result<()> {
                assert_eq!(endpoint.to_string(), "198.51.100.31:51820");
                self.1 = true;
                Ok(())
            }
            fn snapshot(&self) -> io::Result<Value> {
                assert!(self.1);
                Ok(self.0.clone())
            }
        }
        let endpoint = "198.51.100.31:51820".parse().unwrap();
        let now = crate::now();
        for (address, handshake, success) in [
            ("198.51.100.31:51820", now, true),
            ("198.51.100.32:51820", now, false),
            ("198.51.100.31:443", now, false),
            ("198.51.100.31:51820", now - 1, false),
            ("198.51.100.31:51820", now + 60, false),
        ] {
            let mut peer = Sample(
                json!({
                    "running":true, "connected":true, "last_handshake":handshake, "endpoint":address
                }),
                false,
            );
            let pin = ActiveReplacementLaunchPin {
                endpoint,
                deadline: Instant::now() + Duration::from_millis(if success { 500 } else { 5 }),
                warm_ipv6: false,
            };
            let result = wait_standby_handshake(
                &mut peer,
                endpoint,
                Duration::from_secs(1),
                Some((pin, now)),
            );
            if success {
                result.unwrap();
            } else {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
            }
        }
    }

    #[test]
    fn retirement_signals_only_the_original_managed_receipt() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        struct Owner(NativeRemovalSeal, Arc<AtomicUsize>);
        impl Tunnel for Owner {
            fn alive(&mut self) -> bool {
                true
            }
            fn stop(&mut self) -> io::Result<()> {
                self.1.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            fn probe(&mut self) -> io::Result<()> {
                unreachable!()
            }
            fn snapshot(&self) -> io::Result<Value> {
                unreachable!()
            }
            fn native_removal_seal(&self) -> io::Result<NativeRemovalSeal> {
                Ok(self.0.clone())
            }
        }

        let root = tempfile::tempdir().unwrap();
        let runtime = Runtime::new(root.path(), root.path().join("engine"));
        let original = NativeRemovalSeal {
            id: "source".into(),
            iface: "awg3".into(),
            boot: "12121212-1212-1212-1212-121212121212".into(),
            pid: 123,
            started: 456,
            receipt_sha256: [1; 32],
            nested: None,
        };
        let stops = Arc::new(AtomicUsize::new(0));
        runtime.clients.0.lock().unwrap().insert(
            original.id.clone(),
            Managed {
                iface: original.iface.clone(),
                fingerprint: [0; 32],
                recovery: Default::default(),
                tunnel: Box::new(Owner(original.clone(), stops.clone())),
            },
        );
        let mut same_pid = original.clone();
        same_pid.started += 1;
        let mut same_iface = original.clone();
        same_iface.receipt_sha256 = [2; 32];
        assert!(runtime.retire_active_replacement(&same_pid).is_err());
        assert!(runtime.retire_active_replacement(&same_iface).is_err());
        assert_eq!(stops.load(Ordering::Relaxed), 0);
        runtime.retire_active_replacement(&original).unwrap();
        assert_eq!(stops.load(Ordering::Relaxed), 1);
        assert!(runtime.clients.0.lock().unwrap().is_empty());
    }

    fn source() -> Value {
        let mut a = conf::base();
        a["routing"]["zones"] = json!([{"name":"a","order":3,"future":9}]);
        let mut b = conf::base();
        b["routing"]["zones"] =
            json!([{"name":"b","order":1,"tunnel_id":"b","fallback_tunnel_ids":["a","b"]}]);
        json!({"active_id":"a","servers":[{"id":"a","config":a},{"id":"b","config":b}],"pending_rules":[{"name":"prev","tunnel_id":"missing","order":2,"future":13}],"top_future":true})
    }
    #[test]
    fn transfers_dormant_rules_or_keeps_waiting_and_preserves_unknown_fields() {
        let mut a = source();
        let mark = json!({"ref":"a","label":"old"});
        remove(
            &mut a,
            "a",
            Some("b"),
            mark.clone(),
            TransferPolicy::Dormant,
        )
        .unwrap();
        assert_eq!(a["active_id"], "b");
        assert!(a["connection_refs"].get("a").is_none());
        assert_eq!(a["connection_refs"]["missing"]["label"], "missing");
        assert_eq!(a["connection_refs"]["missing"]["fingerprint"], "");
        assert_eq!(a["pending_rules"][0]["future"], 13);
        let z = &a["servers"][0]["config"]["routing"]["zones"];
        assert_eq!(z[0]["fallback_tunnel_ids"], json!([]));
        assert_eq!(z[1]["future"], 9);
        assert_eq!(z[1]["order"], 3);
        assert_eq!(z[1]["tunnel_id"], "b");
        assert_eq!(a["top_future"], true);
        let mut b = source();
        remove(&mut b, "a", None, mark.clone(), TransferPolicy::Dormant).unwrap();
        assert_eq!(b["pending_rules"][1]["tunnel_id"], "a");
        assert_eq!(b["pending_rules"][1]["waiting_for_connection"], true);
        assert_eq!(b["connection_refs"]["a"]["label"], "old");
        remove(&mut b, "b", None, mark, TransferPolicy::Dormant).unwrap();
        assert_ne!(b["active_id"], "a");
        assert_ne!(b["active_id"], "b");
        assert_eq!(b["servers"].as_array().unwrap().len(), 1);
    }
    #[test]
    fn unrouted_plain_delete_retries_stop_before_removing_the_profile() {
        struct Owner {
            stop_attempts: usize,
        }
        impl Tunnel for Owner {
            fn alive(&mut self) -> bool {
                self.stop_attempts < 2
            }
            fn stop(&mut self) -> io::Result<()> {
                self.stop_attempts += 1;
                if self.stop_attempts == 1 {
                    return Err(io::Error::other("cleanup needs retry"));
                }
                Ok(())
            }
            fn probe(&mut self) -> io::Result<()> {
                panic!("deletion probed the peer")
            }
            fn snapshot(&self) -> io::Result<Value> {
                panic!("deletion queried peer status")
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        let rt = Runtime::new(dir.path(), dir.path().join("engine"));
        let mut main = conf::parse(&crate::tests::input(), 0).unwrap();
        main["enabled"] = true.into();
        main["client"]["enabled"] = true.into();
        main["client"]["rust_managed"] = true.into();
        main["client"]["fallback_tunnel_ids"] = json!(["b"]);
        main["client"]["double_tunnel_id"] = "b".into();
        let mut standby = conf::base();
        standby["client_iface"] = "".into();
        standby["client"]["standby"] = true.into();
        let original = json!({
            "active_id": "a",
            "routing": {"active": false},
            "servers": [{"id": "a", "config": main}, {"id": "b", "config": standby}],
        });
        edit_document(&db, |doc| {
            *doc = original.clone();
            Ok(())
        })
        .unwrap();
        let spec = saved_specification(&original, &original["servers"][0], false).unwrap();
        rt.clients.0.lock().unwrap().insert(
            "a".into(),
            Managed {
                iface: spec.iface,
                fingerprint: Sha256::digest(spec.conf.as_bytes()).into(),
                recovery: Default::default(),
                tunnel: Box::new(Owner { stop_attempts: 0 }),
            },
        );
        let delete = || rt.delete_profile(&db, "a", None, |_, id| Ok(json!({"ref":id})));
        assert!(delete().is_err());
        assert_eq!(read(&db).unwrap(), original);
        assert!(rt.clients.0.lock().unwrap().contains_key("a"));
        assert!(delete().unwrap().is_none());
        assert!(rt.clients.0.lock().unwrap().is_empty());
        let removed = read(&db).unwrap();
        assert!(find(&removed, "a").is_err());
        assert_eq!(removed["active_id"], "b");
        assert_eq!(removed["servers"][0]["config"]["client_iface"], "awg1");
        assert_eq!(removed["servers"][0]["config"]["client"], standby["client"]);
    }

    #[test]
    fn plain_delete_prunes_client_reserve_without_stopping_direct_consumer() {
        struct Untouched;
        impl Tunnel for Untouched {
            fn alive(&mut self) -> bool {
                true
            }
            fn stop(&mut self) -> io::Result<()> {
                panic!("direct reserve consumer restarted")
            }
            fn probe(&mut self) -> io::Result<()> {
                panic!("direct reserve consumer probed")
            }
            fn snapshot(&self) -> io::Result<Value> {
                panic!("direct reserve consumer sampled")
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        let rt = Runtime::new(dir.path(), dir.path().join("engine"));
        let mut doc = source();
        let rows = doc["servers"].as_array_mut().unwrap();
        rows[1]["config"]["client_iface"] = "awg1".into();
        rows[1]["config"]["client"]["fallback_tunnel_ids"] = json!(["a", "c"]);
        rows[1]["applied_config"] = rows[1]["config"].clone();
        rows[1]["applied_config"]["routing"]["zones"] = json!([]);
        let mut unrelated = conf::base();
        unrelated["client_iface"] = "awg2".into();
        rows.push(json!({"id":"c","config":unrelated}));
        edit_document(&db, |saved| {
            *saved = doc.clone();
            Ok(())
        })
        .unwrap();
        rt.clients.0.lock().unwrap().insert(
            "b".into(),
            Managed {
                iface: "awg1".into(),
                fingerprint: [0; 32],
                tunnel: Box::new(Untouched),
                recovery: Default::default(),
            },
        );
        rt.delete_profile(&db, "a", None, |_, id| {
            Ok(json!({"ref":id,"label":"previous"}))
        })
        .unwrap();
        assert!(rt.clients.0.lock().unwrap().contains_key("b"));
        let removed = read(&db).unwrap();
        let consumer = find(&removed, "b").unwrap();
        assert_eq!(
            consumer["config"]["client"]["fallback_tunnel_ids"],
            json!(["c"])
        );
        assert_eq!(
            consumer["applied_config"]["client"]["fallback_tunnel_ids"],
            json!(["c"])
        );
        assert_eq!(
            consumer["config"]["routing"]["zones"][0]["fallback_tunnel_ids"],
            json!(["a", "b"])
        );
        assert_eq!(removed["connection_refs"]["a"]["label"], "previous");
        assert_eq!(
            find(&removed, "c").unwrap()["config"]["client"],
            unrelated["client"]
        );
        assert!(find(&removed, "c").unwrap().get("applied_config").is_none());
    }

    #[test]
    fn protects_foreign_interfaces_and_unsupported_active_dependencies_before_commit() {
        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        let mut d = source();
        d["servers"][1]["config"]["client"]["double_tunnel_id"] = json!("a");
        d["routing"]["active"] = json!(true);
        db.transaction(|tx| tx.save("awg.json", &d)).unwrap();
        let rt = Runtime::new(dir.path(), dir.path().join("engine"));
        assert!(rt
            .delete_profile(&db, "a", None, |_, _| Ok(json!({"ref":"a"})))
            .is_err());
        assert_eq!(read(&db).unwrap(), d);
        d["servers"][1]["config"]["client"]["double_tunnel_id"] = json!("");
        d["routing"]["active"] = json!(false);
        db.transaction(|tx| tx.save("awg.json", &d)).unwrap();
        std::fs::create_dir_all(dir.path().join("sys/class/net/awg0")).unwrap();
        assert!(rt
            .delete_profile(&db, "a", None, |_, _| panic!("foreign iface"))
            .is_err());
        assert_eq!(read(&db).unwrap(), d);
    }

    #[test]
    fn replaces_dormant_dependencies_and_preserves_applied_wire_and_interface_aliases() {
        let mut d = source();
        d.as_object_mut().unwrap().remove("active_id");
        d["routing_revision"] = json!(16);
        let rows = d["servers"].as_array_mut().unwrap();
        rows[0]["config"]["routing"]["zones"][0]["order"] = json!(1);
        rows[0]["config"]["client"]["fallback_tunnel_ids"] = json!(["c", "d", "missing"]);
        rows[1]["config"]["client"] = json!({
            "fallback_tunnel_ids":[" a ", "c"], "double_tunnel_id":"a",
            "double_tunnel_mode":"off", "standby":true, "enabled":false, "peer_id":"draft"
        });
        rows[1]["config"]["endpoint"] = json!("192.0.2.8:50");
        rows[1]["config"]
            .as_object_mut()
            .unwrap()
            .remove("client_iface");
        rows[1]["applied_config"] = rows[1]["config"].clone();
        rows[1]["applied_config"]["endpoint"] = json!("deployed.example:40");
        rows[1]["applied_config"]["client"]["peer_id"] = json!("applied");
        rows[1]["applied_config"]["client"]["enabled"] = json!(true);
        rows[1]["applied_config"]["future_wire"] = json!(17);
        rows.push(json!({"id":"c","config":conf::base()}));
        rows.push(json!({"id":"d","config":conf::base()}));
        rows[3]["config"]
            .as_object_mut()
            .unwrap()
            .remove("client_iface");
        rows[3]["config"]["client"]["double_tunnel_id"] = json!("a");
        rows[3]["config"]["client"]["double_tunnel_mode"] = json!("automatic");
        rows[3]["config"]["routing"]["zones"] = json!([{"name":"zero","order":0}]);
        // Keep the resulting graph acyclic: an outer and an ordinary reserve
        // may legitimately form opposite edges in their independent graphs.
        rows[2]["config"]["client"]["double_tunnel_id"] = json!("a");

        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        db.transaction(|tx| tx.save("awg.json", &d)).unwrap();
        let rt = Runtime::new(dir.path(), dir.path().join("engine"));
        assert_eq!(
            rt.delete_profile(&db, "a", Some("b"), |_, _| Ok(json!({"ref":"a"})))
                .unwrap(),
            None
        );
        let next = read(&db).unwrap();
        assert_eq!(next["active_id"], "b");
        assert_eq!(next["routing_revision"], 17);
        let row = find(&next, "b").unwrap();
        assert_eq!(row["config"]["client_iface"], "awg1");
        assert_eq!(find(&next, "d").unwrap()["config"]["client_iface"], "awg3");
        let client = &row["config"]["client"];
        assert_eq!(client["fallback_tunnel_ids"], json!(["c", "d", "missing"]));
        assert_eq!(client["standby"], true);
        assert_eq!(client["enabled"], false);
        assert_eq!(client["double_tunnel_id"], "");
        assert_eq!(client["double_tunnel_mode"], "off");
        assert_eq!(
            find(&next, "d").unwrap()["config"]["client"]["double_tunnel_id"],
            "b"
        );
        let applied = &row["applied_config"];
        assert_eq!(applied["client_iface"], "awg1");
        assert_eq!(applied["endpoint"], "deployed.example:40");
        assert_eq!(applied["client"]["peer_id"], "applied");
        assert_eq!(applied["client"]["enabled"], true);
        assert_eq!(applied["future_wire"], 17);
        assert_eq!(applied["routing"], row["config"]["routing"]);
        let zones = &applied["routing"]["zones"];
        assert_eq!(zones[0]["name"], "a");
        assert_eq!(zones[0]["order"], 1);
        assert_eq!(zones[1]["name"], "b");
        assert_eq!(zones[1]["order"], 2);
        assert_eq!(next["pending_rules"][0]["order"], 3);
        assert_eq!(
            find(&next, "d").unwrap()["config"]["routing"]["zones"][0]["order"],
            4
        );
        assert!(rt.clients.0.lock().unwrap().is_empty());
    }

    #[test]
    fn replacement_cycle_and_occupied_dependents_leave_disk_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        let rt = Runtime::new(dir.path(), dir.path().join("engine"));
        let mut d = source();
        d["routing_revision"] = json!(11);
        d["servers"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id":"c","config":conf::base()}));
        d["servers"][0]["config"]["client"]["fallback_tunnel_ids"] = json!(["c"]);
        d["servers"][2]["config"]["client"]["fallback_tunnel_ids"] = json!(["a"]);
        d["servers"][1]["config"]["client_iface"] = json!("awg1");
        let attempt = || rt.delete_profile(&db, "a", Some("b"), |_, _| Ok(json!({"ref":"a"})));
        db.transaction(|tx| tx.save("awg.json", &d)).unwrap();
        assert!(attempt().unwrap_err().to_string().contains("цикл"));
        assert_eq!(read(&db).unwrap(), d);
        d["servers"][2]["config"]["client"]["fallback_tunnel_ids"] = json!([]);
        db.transaction(|tx| tx.save("awg.json", &d)).unwrap();
        std::fs::create_dir_all(dir.path().join("sys/class/net/awg1")).unwrap();
        assert!(attempt().is_err());
        assert_eq!(read(&db).unwrap(), d);
    }

    #[test]
    fn compensates_failed_replacement_write_and_distinguishes_unconfirmed_readback() {
        use std::{cell::RefCell, io::Error};
        let before = json!({"old":true});
        let after = json!({"new":true});
        for (rollback_writes, observed, result_is_committed) in [
            (true, before.clone(), false),
            (false, after.clone(), true),
            (false, json!({"unknown":true}), false),
        ] {
            let disk = RefCell::new(before.clone());
            let result = finish_replacement_save(
                &before,
                &after,
                || Ok(disk.borrow().clone()),
                |expected, next| {
                    assert_eq!(*disk.borrow(), *expected);
                    if expected == &before {
                        disk.replace(next.clone());
                        return Err(Error::other("write after rename"));
                    }
                    disk.replace(observed.clone());
                    if rollback_writes {
                        Ok(())
                    } else {
                        Err(Error::other("restore"))
                    }
                },
            );
            assert_eq!(*disk.borrow(), observed);
            if result_is_committed {
                assert!(result.unwrap().is_some());
            } else {
                let error = result.unwrap_err();
                assert_eq!(
                    error
                        .get_ref()
                        .is_some_and(|err| err.is::<DeleteReplacementPersistenceUncertain>()),
                    !rollback_writes
                );
            }
        }
    }
}
