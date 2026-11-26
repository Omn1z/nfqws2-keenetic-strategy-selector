use super::{active, modern, runtime::Runtime, s, wire, FILE};
use nfqws2_store::Store;
use serde_json::{json, Map, Value};
use std::{
    collections::HashSet,
    io,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
pub(crate) fn router_address(cfg: &Value) -> &str {
    cfg["peers"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|p| {
            p["is_router"] == true
                || cfg["client"]["peer_id"].is_string() && p["id"] == cfg["client"]["peer_id"]
        })
        .map(|p| s(p, "address"))
        .unwrap_or_default()
}
struct Profile {
    id: String,
    label: String,
    endpoint: String,
    iface: String,
    address: String,
    mtu: u64,
    permanent: bool,
}
pub(super) fn server_label(row: &Value, cfg: &Value) -> String {
    let id = s(row, "id");
    [s(row, "name"), s(cfg, "endpoint"), s(&cfg["conn"], "host")]
        .into_iter()
        .find(|s| !s.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| {
            if id == "awg0" {
                "AWG2".into()
            } else {
                format!("AWG2 {}", id.trim_start_matches("awg-"))
            }
        })
}
impl Profile {
    fn new(row: &Value, i: usize) -> Self {
        let cfg = wire(row);
        let id = s(row, "id");
        let endpoint = s(cfg, "endpoint");
        let label = server_label(row, cfg);
        let iface = cfg["client_iface"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("awg{i}"));
        Self {
            id: id.into(),
            label,
            endpoint: endpoint.into(),
            iface,
            address: router_address(cfg).into(),
            mtu: cfg["mtu"].as_u64().unwrap_or(1420),
            permanent: row["config"]["client"]["double_tunnel_mode"] == "permanent",
        }
    }
}
struct CachedProfiles {
    modified: Option<(u64, std::time::SystemTime)>,
    loaded: Instant,
    profiles: Arc<Vec<Profile>>,
}
#[derive(serde::Serialize)]
pub struct FallbackServer {
    pub id: String,
    pub label: String,
    pub client_iface: String,
    pub connected: bool,
}
/// Non-secret DNS route information. Reuse one physical observation across
/// logical profiles whose active reserve is the same local tunnel.
#[derive(Clone)]
pub struct DnsRoute {
    pub id: String,
    pub label: String,
    pub iface: String,
    pub ifindex: Option<u32>,
    pub dns: Vec<std::net::IpAddr>,
}
pub fn dns_routes(db: &Store, runtime: &Runtime) -> io::Result<Vec<DnsRoute>> {
    use std::collections::HashMap;
    let doc = super::read(db)?;
    let rows = doc["servers"]
        .as_array()
        .ok_or_else(|| io::Error::other("нет списка AWG"))?;
    let effective = runtime.failover_view(&doc);
    let end = Instant::now() + Duration::from_millis(900);
    let mut out = Vec::new();
    let mut checked = HashMap::new();
    for (i, row) in rows.iter().enumerate() {
        let c = &row["config"];
        if c["enabled"] != true
            || c["client"]["enabled"] != true
            || s(wire(row), "endpoint").is_empty()
        {
            continue;
        }
        let p = Profile::new(row, i);
        let managed = c["client"]["standby"] == true
            || c["client"]["fallback_tunnel_ids"]
                .as_array()
                .is_some_and(|a| !a.is_empty());
        let physical = if managed {
            effective
                .get(&p.id)
                .and_then(|st| st["active_tunnel_id"].as_str())
                .and_then(|id| rows.iter().enumerate().find(|(_, r)| r["id"] == id))
        } else {
            Some((i, row))
        };
        let mut route = DnsRoute {
            id: p.id,
            label: p.label,
            iface: p.iface,
            ifindex: None,
            dns: vec![],
        };
        if let Some((idx, r)) = physical {
            let physical = Profile::new(r, idx);
            let cfg = wire(r);
            route.iface = physical.iface;
            if (!s(&r["config"]["client"], "double_tunnel_id").is_empty()
                || r["config"]["client"]["double_tunnel_mode"] == "permanent")
                && crate::FailoverGraph::load(&doc).is_err()
            {
                out.push(route);
                continue;
            }
            let value = checked
                .entry((route.iface.clone(), s(cfg, "public_key")))
                .or_insert_with(|| {
                    let time = end
                        .saturating_duration_since(Instant::now())
                        .min(Duration::from_millis(300));
                    if !route.iface.strip_prefix("awg").is_some_and(|n| {
                        !n.is_empty()
                            && route.iface.len() < 16
                            && n.bytes().all(|b| b.is_ascii_digit())
                    }) {
                        return None;
                    }
                    if time.is_zero() {
                        return None;
                    }
                    let index = || {
                        std::fs::read_to_string(
                            runtime
                                .root
                                .join("sys/class/net")
                                .join(&route.iface)
                                .join("ifindex"),
                        )
                        .ok()?
                        .trim()
                        .parse::<u32>()
                        .ok()
                        .filter(|i| *i != 0)
                    };
                    let before = index()?;
                    runtime
                        .routing_peer_with_budget(cfg, &route.iface, time)
                        .ok()?;
                    (index() == Some(before)).then_some(before)
                });
            route.ifindex = *value;
            route.dns = s(cfg, "dns")
                .split([',', ' ', ';'])
                .filter_map(|ip| ip.parse::<std::net::IpAddr>().ok())
                .filter(|ip| !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast())
                .take(4)
                .collect();
        }
        out.push(route);
    }
    Ok(out)
}
/// Read only the public identity and live tunnel status needed by Telegram.
pub fn fallback_servers(
    db: &Store,
    runtime: &Runtime,
    only: Option<&str>,
) -> io::Result<Vec<FallbackServer>> {
    let doc = super::read(db)?;
    let effective = only
        .map(|_| runtime.failover_view(&doc))
        .unwrap_or_default();
    let deadline = Instant::now() + Duration::from_millis(900);
    let mut out = Vec::new();
    for (i, row) in doc["servers"].as_array().into_iter().flatten().enumerate() {
        let cfg = wire(row);
        if cfg["enabled"] != true
            || s(cfg, "endpoint").trim().is_empty()
            || only.is_some_and(|id| id != s(row, "id"))
        {
            continue;
        }
        let p = Profile::new(row, i);
        let client = &row["config"]["client"];
        if only.is_some()
            && (client["standby"] == true
                || p.permanent
                || client["fallback_tunnel_ids"]
                    .as_array()
                    .is_some_and(|a| !a.is_empty()))
        {
            let selected = effective
                .get(&p.id)
                .and_then(|v| v["active_tunnel_id"].as_str())
                .and_then(|id| {
                    doc["servers"]
                        .as_array()?
                        .iter()
                        .enumerate()
                        .find(|(_, r)| r["id"] == id)
                });
            let actual = selected.and_then(|(index, r)| {
                let physical = Profile::new(r, index);
                runtime
                    .routing_peer(wire(r), &physical.iface)
                    .ok()
                    .map(|_| physical.iface)
            });
            out.push(FallbackServer {
                id: p.id,
                label: p.label,
                connected: actual.is_some(),
                client_iface: actual.unwrap_or(p.iface),
            });
            continue;
        }
        let (live, _) = runtime.client_detail(
            p.mtu,
            &p.address,
            &p.iface,
            deadline.saturating_duration_since(Instant::now()),
        );
        out.push(FallbackServer {
            id: p.id,
            label: p.label,
            client_iface: p.iface,
            connected: live["iface_present"] == true
                && live["running"] == true
                && (!p.permanent || live["nested_transport"] == true)
                && live["connected"] == true,
        });
    }
    Ok(out)
}
#[derive(Default)]
pub(crate) struct DashboardCache(Option<CachedProfiles>);
pub fn dashboard(db: &Store, dir: &Path, runtime: &Runtime) -> io::Result<Vec<Value>> {
    let modified = dir
        .join("awg.json")
        .symlink_metadata()
        .ok()
        .and_then(|m| m.modified().ok().map(|t| (m.len(), t)));
    let profiles = {
        let mut cached = runtime
            .dashboard_cache
            .lock()
            .map_err(|_| io::Error::other("кеш статуса AWG недоступен"))?;
        // No key material is retained between polls. Periodically refresh even
        // where the firmware filesystem has coarse timestamps or recovery data.
        if let Some(hit) = cached
            .0
            .as_ref()
            .filter(|v| v.modified == modified && v.loaded.elapsed() < Duration::from_secs(10))
        {
            hit.profiles.clone()
        } else {
            let doc = super::read(db)?;
            let profiles: Arc<Vec<_>> = Arc::new(
                doc["servers"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .enumerate()
                    .map(|(i, row)| Profile::new(row, i))
                    .collect(),
            );
            cached.0 = Some(CachedProfiles {
                modified,
                loaded: Instant::now(),
                profiles: profiles.clone(),
            });
            profiles
        }
    };
    let end = Instant::now() + Duration::from_millis(1500);
    let mut out = Vec::new();
    for p in profiles.iter() {
        let (live, _) = runtime.client_detail(
            p.mtu,
            &p.address,
            &p.iface,
            end.saturating_duration_since(Instant::now()),
        );
        let running = live["running"] == true;
        let connected =
            live["connected"] == true && (!p.permanent || live["nested_transport"] == true);
        if p.endpoint.is_empty() && !running {
            continue;
        }
        let state = if connected {
            "connected"
        } else if running {
            "stale"
        } else if live.is_null() {
            "off"
        } else {
            "down"
        };
        let mut item = json!({"id":p.id,"label":p.label,"endpoint":p.endpoint,"state":state,"connected":connected,"running":running,
            "last_handshake":live["last_handshake"].as_u64().unwrap_or(0),"rx_bytes":live["rx_bytes"].as_u64().unwrap_or(0),
            "tx_bytes":live["tx_bytes"].as_u64().unwrap_or(0),"mtu":p.mtu,"address":p.address});
        for field in ["checking_peer", "last_peer_activity"] {
            if let Some(value) = live.get(field) {
                item[field] = value.clone();
            }
        }
        out.push(item);
    }
    Ok(out)
}

// Persist unknown fields intact; expose only explicitly public scalars and
// string lists, even when a foreign version adds private extension objects.
fn fields(v: &Value, keys: &str) -> Value {
    let mut out = json!({});
    for key in keys.split_ascii_whitespace() {
        if let Some(val) = v.get(key) {
            if val.is_string()
                || val.is_number()
                || val.is_boolean()
                || val
                    .as_array()
                    .is_some_and(|a| a.iter().all(Value::is_string))
            {
                out[key] = val.clone();
            }
        }
    }
    out
}
fn zone(v: &Value, routing_mode: &str) -> Value {
    let mut out=fields(v,"waiting_for_connection name tunnel_id fallback_tunnel_ids order route mode enabled domains ips source_ips");
    if let Some(include) = v["include_subdomains"].as_bool() {
        out["include_subdomains"] = json!(include);
    }
    for name in ["domains", "ips", "source_ips"] {
        if !out[name].is_array() {
            out[name] = json!([]);
        }
    }
    if !matches!(s(&out, "mode"), "include" | "exclude") {
        out["mode"] = json!(if routing_mode == "exclude" {
            "exclude"
        } else {
            "include"
        });
    }
    if !matches!(s(&out, "route"), "tunnel" | "direct") {
        out["route"] = json!(if out["mode"] == "exclude" {
            "direct"
        } else {
            "tunnel"
        });
    }
    out
}
fn routing(cfg: &Value) -> Value {
    let mut rc = fields(
        cfg,
        "mode mtu killswitch domain_source sni_routing trace_enabled active",
    );
    for (key, value) in [
        ("mode", json!("off")),
        ("mtu", json!(1420)),
        ("domain_source", json!("resolve")),
    ] {
        if rc[key].is_null() {
            rc[key] = value;
        }
    }
    rc["zones"] = json!(cfg["zones"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|rule| zone(rule, s(cfg, "mode")))
        .collect::<Vec<_>>());
    rc
}
fn redacted(cfg: &Value) -> Value {
    let mut v=fields(cfg,"enabled protocol protocol_version traffic_obfuscation install public_key listen_port address subnet mtu dns wan_iface endpoint interface client_iface deployed_at");
    v["private_key"] = json!("");
    v["conn"] = fields(&cfg["conn"], "host port user auth_kind known_key");
    v["client"]=fields(&cfg["client"],"enabled peer_id listen_port standby fallback_tunnel_ids double_tunnel_id double_tunnel_mode endpoint_backups");
    if let Some(client) = v["client"].as_object_mut() {
        if client.get("endpoint_backups").is_some_and(|backups| {
            backups.is_null() || backups.as_array().is_some_and(Vec::is_empty)
        }) {
            client.remove("endpoint_backups");
        }
    }
    v["routing"] = routing(&cfg["routing"]);
    v["obf"]=fields(&cfg["obf"],"jc jmin jmax s1 s2 s3 s4 h1 h2 h3 h4 i1 i2 i3 i4 i5 content_padding_addition rekey_after_time rekey_timeout reject_after_time keepalive_timeout max_handshake_attempts random_trailers disable_cookies");
    v["obf"]["has_header_protection_key"] =
        json!(!s(&cfg["obf"], "header_protection_key").is_empty());
    v["peers"]=json!(cfg["peers"].as_array().into_iter().flatten().map(|p|{
        let mut peer=fields(p,"id name public_key address allowed_ips keepalive keepalive_range is_router created_at");
        peer["has_private"]=json!(!s(p,"private_key").is_empty());peer["private_key"]=json!("");peer["psk"]=json!("");peer
    }).collect::<Vec<_>>());
    v
}
pub(crate) fn warp(cfg: &Value) -> bool {
    if cfg["install"] != "imported" {
        return false;
    }
    if cfg["warp_standard"] == true {
        return true;
    }
    if s(cfg, "public_key").trim() == "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=" {
        return true;
    }
    let endpoint = s(cfg, "endpoint");
    let host = endpoint.rsplit_once(':').map_or(endpoint, |(h, _)| h);
    host.eq_ignore_ascii_case("engage.cloudflareclient.com")
        || host.parse::<std::net::Ipv4Addr>().is_ok_and(|a| {
            matches!(
                a.octets(),
                [162, 159, 192 | 193 | 195, _] | [188, 114, 96 | 97, _]
            )
        })
}
fn rules(doc: &Value) -> Value {
    let mut rules = Vec::new();
    for r in doc["servers"].as_array().into_iter().flatten() {
        let routing = &r["config"]["routing"];
        for z in routing["zones"].as_array().into_iter().flatten() {
            let mut z = zone(z, s(routing, "mode"));
            let owner = s(&z, "tunnel_id").trim();
            if z["waiting_for_connection"] != true {
                let owner = if owner.is_empty() { s(r, "id") } else { owner };
                let mut seen = HashSet::from([owner]);
                let backups: Vec<_> = z["fallback_tunnel_ids"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::trim)
                    .filter(|id| z["route"] == "tunnel" && !id.is_empty() && seen.insert(id))
                    .map(str::to_owned)
                    .collect();
                z["tunnel_id"] = json!(owner);
                if backups.is_empty() {
                    z.as_object_mut().unwrap().remove("fallback_tunnel_ids");
                } else {
                    z["fallback_tunnel_ids"] = json!(backups);
                }
            } else if !owner.is_empty() {
                z["tunnel_id"] = json!(owner);
            }
            rules.push(z);
        }
    }
    for item in doc["pending_rules"].as_array().into_iter().flatten() {
        let mut z = zone(item, "");
        z["waiting_for_connection"] = json!(true);
        rules.push(z);
    }
    rules.sort_by_key(|z| z["order"].as_u64().filter(|v| *v > 0).unwrap_or(u64::MAX));
    for (i, z) in rules.iter_mut().enumerate() {
        if !z["order"].as_u64().is_some_and(|n| n > 0) {
            z["order"] = json!(i + 1);
        }
    }
    json!(rules)
}

fn saved_routing_active(doc: &Value, routing: &Value) -> bool {
    if routing["mode"] == "off" {
        return false;
    }
    let usable: HashSet<_> = doc["servers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|row| {
            let cfg = &row["config"];
            cfg["enabled"] == true
                && cfg["client"]["enabled"] == true
                && cfg["routing"]["active"] == true
                && !matches!(s(&cfg["routing"], "mode"), "" | "off")
        })
        .map(|row| s(row, "id"))
        .collect();
    if usable.is_empty() || routing["mode"] == "full" {
        return !usable.is_empty();
    }
    let failovers = std::cell::OnceCell::new();
    routing["zones"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|zone| zone["enabled"] == true && zone["waiting_for_connection"] != true)
        .any(|zone| {
            let primary = s(zone, "tunnel_id");
            if usable.contains(primary) {
                return true;
            }
            if zone["route"] != "tunnel" {
                return false;
            }
            let backups: Vec<_> = zone["fallback_tunnel_ids"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
            failovers
                .get_or_init(|| super::FailoverGraph::load(doc).ok())
                .as_ref()
                .and_then(|graph| graph.for_rule(primary, &backups).ok())
                .is_some_and(|candidates| candidates.into_iter().any(|id| usable.contains(id)))
        })
}

pub(crate) fn retained_connection_refs(doc: &Value) -> Map<String, Value> {
    let servers = doc["servers"].as_array().into_iter().flatten();
    let live: HashSet<_> = servers.clone().map(|row| s(row, "id")).collect();
    let mut retained = Map::new();
    let mut retain_missing = |raw: &Value| {
        let Some(id) = raw.as_str().map(str::trim) else {
            return;
        };
        if id.is_empty() || live.contains(id) || retained.contains_key(id) {
            return;
        }
        let saved = &doc["connection_refs"][id];
        let mut public = json!({
            "ref": id,
            "label": saved["label"].as_str().unwrap_or(id),
            "endpoint": s(saved, "endpoint"),
            "client_iface": s(saved, "client_iface"),
            "protocol": s(saved, "protocol"),
            "fingerprint": s(saved, "fingerprint"),
        });
        if let Some(key) = saved["server_public_key"]
            .as_str()
            .filter(|s| !s.is_empty())
        {
            public["server_public_key"] = json!(key);
        }
        retained.insert(id.to_owned(), public);
    };
    for rule in doc["pending_rules"].as_array().into_iter().flatten() {
        retain_missing(&rule["tunnel_id"]);
        for backup in rule["fallback_tunnel_ids"].as_array().into_iter().flatten() {
            retain_missing(backup);
        }
    }
    for row in servers {
        for rule in row["config"]["routing"]["zones"]
            .as_array()
            .into_iter()
            .flatten()
        {
            for backup in rule["fallback_tunnel_ids"].as_array().into_iter().flatten() {
                retain_missing(backup);
            }
        }
    }
    retained
}

fn status_endpoint<'a>(wire: &'a Value, client: &'a Value) -> &'a str {
    client["endpoint_candidate"]
        .as_str()
        .filter(|endpoint| {
            !endpoint.is_empty()
                && client["endpoint_index"]
                    .as_u64()
                    .is_some_and(|index| index > 0)
        })
        .unwrap_or_else(|| s(wire, "endpoint"))
}

pub fn status(db: &Store, runtime: &Runtime) -> io::Result<Value> {
    status_with_public_refs(db, runtime, |_| Map::new())
}

pub fn status_with_public_refs(
    db: &Store,
    runtime: &Runtime,
    current: impl FnOnce(&Value) -> Map<String, Value>,
) -> io::Result<Value> {
    let (mut doc, recovered) = FILE.inspect(db)?;
    modern(&mut doc);
    let mut failovers = runtime.failover_view(&doc);
    let empty = json!({"id":"","config":super::conf::base()});
    let row = active(&doc).unwrap_or(&empty);
    let cfg = &row["config"];
    let mut safe = redacted(cfg);
    let zones = rules(&doc);
    let mut global = routing(&super::routing_settings_for_profile(&doc));
    global["zones"] = zones.clone();
    for k in [
        "mode",
        "mtu",
        "killswitch",
        "domain_source",
        "sni_routing",
        "trace_enabled",
    ] {
        if !global[k].is_null() {
            safe["routing"][k] = global[k].clone();
        }
    }
    let deadline = Instant::now() + Duration::from_millis(1500);
    let recovery = super::recovery_settings(&doc["recovery_settings"]);
    let mut servers = Vec::new();
    let mut active_client = Value::Null;
    for (i, entry) in doc["servers"].as_array().into_iter().flatten().enumerate() {
        let conf = &entry["config"];
        let wire = wire(entry);
        let id = s(entry, "id");
        let host = s(&conf["conn"], "host");
        let Profile { label, iface, .. } = Profile::new(entry, i);
        let (mut client, endpoint_verified) = runtime.client_observation(
            wire,
            &iface,
            deadline.saturating_duration_since(Instant::now()),
        );
        runtime.supplement_client(entry, &mut client, &recovery, endpoint_verified);
        let endpoint = status_endpoint(wire, &client).trim();
        let chosen = entry["id"] == row["id"];
        if chosen {
            active_client = client.clone();
        }
        let warp = warp(wire);
        let remote = runtime.remote.status(entry);
        let mut summary = json!({"id":id,"label":label,"host":host,"endpoint":endpoint,"client_iface":iface,"enabled":conf["enabled"].as_bool().unwrap_or(false),
            "imported":conf["install"]=="imported","protocol":wire["protocol"].as_str().unwrap_or("awg"),"protocol_version":super::effective_protocol_version(wire),
            "traffic_obfuscation":wire["protocol"]!="wireguard"&&wire["traffic_obfuscation"]!=false,"deployment_pending":entry["applied_config"].is_object(),"is_warp":warp,
            "active":chosen,"deployed":conf["deployed_at"].as_u64().unwrap_or(0)>0,"connected":client["connected"]==true,"reachable":client["connected"]==true||remote.as_ref().is_some_and(|st|st["reachable"]==true),
            "has_password":!s(&conf["conn"],"password").is_empty(),"has_key":!s(&conf["conn"],"key_pem").is_empty(),"has_server_key":!s(conf,"private_key").is_empty()});
        if !client.is_null() {
            summary["client"] = client;
        }
        if let Some(e) = remote.as_ref().and_then(|st| st["error"].as_str()) {
            summary["last_error"] = json!(e);
        }
        if let Some(f) = failovers.remove(id) {
            summary["failover"] = f;
        }
        servers.push(summary);
    }
    global["active"] =
        json!(!doc["rust_static_routing"].is_object() && saved_routing_active(&doc, &global));
    let mut refs = retained_connection_refs(&doc);
    refs.extend(current(&doc));
    let revision = doc["routing_revision"].as_u64().unwrap_or(0);
    let routing_state = if doc["rust_static_routing"].is_object() {
        let mut info=runtime.routing(db,revision).unwrap_or_else(||json!({"active":false,"ready":false,"error":"Состояние маршрутов ещё не проверено."}));
        global["active"] = json!(info["active"] == true);
        info["revision"] = json!(revision);
        info["applying"] = json!(false);
        info
    } else if revision > 0 {
        json!({"revision":revision,"applying":false,"ready":false,"error":"Настройки сохранены. Маршруты ещё не применены."})
    } else if global["active"] == true {
        json!({"revision":0,"applying":false,"ready":false,"error":"состояние применения маршрутов недоступно в этой сборке"})
    } else {
        json!({"revision":0,"applying":false,"ready":true})
    };
    Ok(
        json!({"config":safe,"active_server_id":row["id"],"servers":servers,"routing_rules":zones,"routing_config":global,"routing_state":routing_state,
        "warp_protocol":"wireguard","server_deployment":"wireguard","ssh_host_key_enrollment":true,"mtu_only_edit":true,"primary_endpoint_edit":true,"config_recovered":recovered,"connection_refs":refs,"has_password":!s(&cfg["conn"],"password").is_empty(),"has_key":!s(&cfg["conn"],"key_pem").is_empty(),
        "has_server_key":!s(cfg,"private_key").is_empty(),"deployed":cfg["deployed_at"].as_u64().unwrap_or(0)>0,"last_deploy":runtime.deploy_history.status(row),"status":runtime.remote.status(row),
        "endpoint":status_endpoint(wire(row), &active_client),"engine":runtime.engine(),"client":active_client,"deployment_pending":row["applied_config"].is_object(),"recovery_settings":recovery}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_endpoint_uses_only_the_current_configured_pool_selection() {
        let wire = json!({"endpoint":"192.0.2.2:51820"});
        let mut client = json!({
            "endpoint":"192.0.2.5:51820",
            "endpoint_candidate":"192.0.2.3:51820",
            "endpoint_index":1,
        });
        assert_eq!(status_endpoint(&wire, &client), "192.0.2.3:51820");
        client["endpoint_index"] = json!(-1);
        assert_eq!(status_endpoint(&wire, &client), "192.0.2.2:51820");
        assert_eq!(status_endpoint(&wire, &Value::Null), "192.0.2.2:51820");
    }
}
