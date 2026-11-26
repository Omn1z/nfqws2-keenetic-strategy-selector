use super::parse::Topology;
use serde::Serialize;
use std::{collections::BTreeMap, net::IpAddr};

#[derive(Clone, Serialize, Default)]
pub(super) struct Client {
    pub mac: String,
    pub ip: String,
    pub hostname: String,
    pub segment: String,
    pub ap: String,
}
fn mac(s: &str) -> Option<String> {
    let (separator, width) = match (s.len(), s.as_bytes().get(2)) {
        (17, Some(b':')) => (':', 2),
        (17, Some(b'-')) => ('-', 2),
        (14, _) => ('.', 4),
        _ => return None,
    };
    let mut bytes = [0; 6];
    let mut next = 0;
    for group in s.split(separator) {
        if group.len() != width || !group.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        for index in (0..width).step_by(2) {
            *bytes.get_mut(next)? = u8::from_str_radix(&group[index..index + 2], 16).ok()?;
            next += 1;
        }
    }
    let [a, b, c, d, e, f] = bytes;
    if next != bytes.len() || a & 1 != 0 || bytes == [0; 6] {
        return None;
    }
    Some(format!("{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}"))
}
fn records<'a>(text: &'a str, marker: &str) -> Vec<BTreeMap<&'a str, &'a str>> {
    let mut rows = Vec::<BTreeMap<&str, &str>>::new();
    let mut column = None;
    for (key, value) in text.lines().filter_map(|l| l.split_once(':')) {
        let i = key.len();
        let key = key.trim();
        let value = value.trim();
        if key == marker && value.is_empty() {
            rows.push(Default::default());
            column = None;
            continue;
        }
        let Some(row) = rows.last_mut() else { continue };
        if *column.get_or_insert(i) != i {
            continue;
        }
        if matches!(key, "mac" | "ip" | "hostname" | "ap") && row.insert(key, value).is_some() {
            row.insert("mac", "invalid");
        }
    }
    rows
}
pub(super) fn clients(cfg: &Topology, assoc: &str, leases: &str) -> Vec<Client> {
    let mut inventory = BTreeMap::new();
    for row in records(leases, "lease") {
        if let Some(mac) = row.get("mac").and_then(|x| mac(x)) {
            inventory.insert(
                mac,
                Client {
                    ip: row
                        .get("ip")
                        .filter(|s| s.parse::<IpAddr>().is_ok())
                        .unwrap_or(&"")
                        .to_string(),
                    hostname: row.get("hostname").unwrap_or(&"").to_string(),
                    ..Default::default()
                },
            );
        }
    }
    let mut clients = BTreeMap::new();
    for row in records(assoc, "station") {
        let Some(mac) = row.get("mac").and_then(|x| mac(x)) else {
            continue;
        };
        if clients.contains_key(&mac) {
            continue;
        }
        let ap = row.get("ap").copied().unwrap_or("");
        let alias = cfg
            .aps
            .iter()
            .find(|i| i.id == ap)
            .map(|i| i.alias.as_str())
            .unwrap_or("");
        let mut client = inventory.remove(&mac).unwrap_or_default();
        client.mac.clone_from(&mac);
        client.ap = ap.into();
        if let Some(bridge) = cfg.bridges.iter().find(|b| {
            b.members
                .iter()
                .any(|m| m == ap || !alias.is_empty() && m == alias)
        }) {
            client.segment.clone_from(&bridge.id);
        }
        clients.insert(mac, client);
    }
    clients.into_values().collect()
}
