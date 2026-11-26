use super::{
    identity::{digest, Ref, Refs},
    model::{domain, err},
    Routing, Zone,
};
use nfqws2_awg_profile::{edit_document, routing_settings_source};
use nfqws2_store::Store;
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    io,
};
pub(crate) fn decode(v: &Value) -> io::Result<Routing> {
    if v.is_null() {
        return Ok(Routing::default());
    }
    serde_json::from_value(v.clone()).map_err(|e| err(e.to_string()))
}
pub(crate) fn current(doc: &Value) -> io::Result<Routing> {
    let rows = doc["servers"]
        .as_array()
        .ok_or_else(|| err("неверный список серверов"))?;
    let mut r = decode(routing_settings_source(doc))?;
    r.zones.clear();
    r.normalize();
    r.active = false;
    let ids: HashSet<_> = rows.iter().filter_map(|v| v["id"].as_str()).collect();
    for row in rows {
        let mut part = decode(&row["config"]["routing"])?;
        part.normalize();
        r.active |= r.mode != "off"
            && part.active
            && row["config"]["enabled"] == true
            && row["config"]["client"]["enabled"] == true;
        for mut z in part.zones {
            if !z.waiting_for_connection {
                if z.tunnel_id.is_empty() {
                    z.tunnel_id = row["id"].as_str().unwrap_or_default().into();
                } else if !ids.contains(z.tunnel_id.as_str()) {
                    z.waiting_for_connection = true;
                }
            }
            r.zones.push(z);
        }
    }
    if !doc["pending_rules"].is_null() {
        for mut z in serde_json::from_value::<Vec<Zone>>(doc["pending_rules"].clone())? {
            z.waiting_for_connection = true;
            z.normalize();
            r.zones.push(z);
        }
    }
    r.zones
        .sort_by_key(|z| if z.order == 0 { usize::MAX } else { z.order });
    for (i, z) in r.zones.iter_mut().enumerate() {
        if z.order == 0 {
            z.order = i + 1;
        }
    }
    Ok(r)
}
pub(crate) fn policy_hash(r: &Routing, refs: &Refs) -> String {
    let mut routing = r.clone();
    routing.normalize();
    routing.active = false;
    let mut connections = Refs::new();
    for (i, z) in routing.zones.iter_mut().enumerate() {
        z.order = i + 1;
        for id in std::iter::once(&z.tunnel_id).chain(&z.fallback_tunnel_ids) {
            let mut public = refs.get(id).cloned().unwrap_or_default();
            public.id.clone_from(id);
            public.label.clear();
            connections.insert(id.clone(), public);
        }
    }
    #[derive(Serialize)]
    struct Hash<'a> {
        routing: &'a Routing,
        connections: &'a Refs,
    }
    let wire = serde_json::to_string(&Hash {
        routing: &routing,
        connections: &connections,
    })
    .unwrap()
    .replace('&', "\\u0026")
    .replace('<', "\\u003c")
    .replace('>', "\\u003e")
    .replace('\u{2028}', "\\u2028")
    .replace('\u{2029}', "\\u2029");
    digest(wire.as_bytes(), 32)
}
fn settings(r: &Routing) -> Value {
    json!({"mode":r.mode,"mtu":r.mtu,"killswitch":r.killswitch,"domain_source":r.domain_source,"sni_routing":r.sni_routing,"trace_enabled":r.trace_enabled})
}
pub(crate) fn bump(doc: &mut Value) -> u64 {
    let revision = doc["routing_revision"]
        .as_u64()
        .unwrap_or(0)
        .saturating_add(1);
    doc["routing_revision"] = json!(revision);
    revision
}
pub(crate) fn write(doc: &mut Value, mut r: Routing, refs: &Refs) -> io::Result<()> {
    r.validate(true)?;
    if r.mtu == 0 {
        r.mtu = current(doc)?.mtu;
    }
    if r.mode.is_empty() {
        r.mode = "zones".into();
    }
    r.normalize();
    let ids: HashSet<String> = doc["servers"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s["id"].as_str().map(str::to_owned))
        .collect();
    let selected = doc["active_id"]
        .as_str()
        .filter(|id| ids.contains(*id))
        .or_else(|| {
            doc["servers"]
                .as_array()
                .and_then(|s| s.first())?
                .get("id")?
                .as_str()
        })
        .unwrap_or("")
        .to_owned();
    let mut parts: HashMap<String, Vec<Zone>> = HashMap::new();
    let mut pending = Vec::new();
    let mut retained = Refs::new();
    for (i, mut z) in std::mem::take(&mut r.zones).into_iter().enumerate() {
        z.order = i + 1;
        if z.tunnel_id.is_empty() && !z.waiting_for_connection {
            z.tunnel_id.clone_from(&selected);
        }
        if !z.waiting_for_connection && !ids.contains(&z.tunnel_id) {
            return Err(err("туннель для правила не найден"));
        }
        for id in std::iter::once(&z.tunnel_id).chain(&z.fallback_tunnel_ids) {
            if !id.is_empty() && !ids.contains(id) {
                if !z.waiting_for_connection && !refs.contains_key(id) {
                    return Err(err("резервный туннель не найден"));
                }
                retained.insert(
                    id.clone(),
                    refs.get(id).cloned().unwrap_or_else(|| Ref::blank(id)),
                );
            }
        }
        if z.waiting_for_connection {
            pending.push(z);
        } else {
            parts.entry(z.tunnel_id.clone()).or_default().push(z);
        }
    }
    doc["routing"] = settings(&r);
    doc["pending_rules"] = json!(pending);
    doc["connection_refs"] = json!(retained);
    for row in doc["servers"].as_array_mut().unwrap() {
        let id = row["id"].as_str().unwrap_or_default();
        let active = row["config"]["routing"]["active"] == true && r.mode != "off";
        let mut cfg = settings(&r);
        cfg["zones"] = json!(parts.remove(id).unwrap_or_default());
        cfg["active"] = json!(active);
        row["config"]["routing"] = cfg;
    }
    bump(doc);
    Ok(())
}
pub fn save(db: &Store, r: Routing) -> io::Result<()> {
    edit_document(db, |doc| {
        let refs = super::identity::refs(doc, &super::identity::live(doc))?;
        write(doc, r, &refs)
    })
}
pub fn save_settings(db: &Store, mut r: Routing) -> io::Result<()> {
    r.validate(true)?;
    edit_document(db, |doc| {
        if r.mtu == 0 {
            r.mtu = current(doc)?.mtu;
        }
        r.normalize();
        let settings = settings(&r);
        let selected = doc["active_id"].clone();
        doc["routing"] = settings.clone();
        for row in doc["servers"].as_array_mut().unwrap() {
            let active = row["config"]["routing"]["active"] == true && r.mode != "off";
            let zones = if row["id"] == selected {
                json!(r.zones)
            } else {
                row["config"]["routing"]["zones"].clone()
            };
            row["config"]["routing"] = settings.clone();
            row["config"]["routing"]["active"] = json!(active);
            row["config"]["routing"]["zones"] = zones;
        }
        bump(doc);
        Ok(())
    })
}
pub fn insert_top(db: &Store, name: &str, host: &str, route: &str) -> io::Result<()> {
    let host = host.trim();
    domain(host, true)?;
    if !matches!(route, "direct" | "tunnel") {
        return Err(err("направление должно быть direct или tunnel"));
    }
    edit_document(db, |doc| {
        let mut routing = current(doc)?;
        if routing.mode == "off" {
            routing.mode = "zones".into();
        }
        let label = if name.is_empty() {
            format!("trace:{host}")
        } else {
            name.into()
        };
        routing.zones.insert(
            0,
            Zone {
                name: label,
                route: route.into(),
                domains: vec![host.into()],
                include_subdomains: Some(true),
                enabled: true,
                ..Default::default()
            },
        );
        let refs = super::identity::refs(doc, &super::identity::live(doc))?;
        write(doc, routing, &refs)
    })
}
pub fn copy(db: &Store, source: &str) -> io::Result<usize> {
    edit_document(db, |doc| {
        let active = doc["active_id"].clone();
        let rows = doc["servers"].as_array_mut().unwrap();
        let src = rows
            .iter()
            .find(|r| r["id"] == source)
            .ok_or_else(|| err("сервер-источник не найден"))?;
        let zones = decode(&src["config"]["routing"])?.zones;
        let count = zones.len();
        let dst = rows
            .iter_mut()
            .find(|r| r["id"] == active)
            .ok_or_else(|| err("сервер не выбран"))?;
        dst["config"]["routing"]["zones"] = json!(zones);
        bump(doc);
        Ok(count)
    })
}
