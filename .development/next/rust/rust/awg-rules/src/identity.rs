use crate::model::{err, hostname, reference, text};
use base64ct::{Base64, Encoding};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt::Write, io};
pub(crate) fn digest(data: &[u8], n: usize) -> String {
    let mut hex = String::with_capacity(2 * n);
    for b in &Sha256::digest(data)[..n] {
        write!(hex, "{b:02x}").unwrap();
    }
    hex
}
#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ref {
    #[serde(rename = "ref")]
    pub id: String,
    pub label: String,
    pub endpoint: String,
    pub client_iface: String,
    pub protocol: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub server_public_key: String,
    pub fingerprint: String,
}
pub(crate) type Refs = BTreeMap<String, Ref>;
fn iface(s: &str) -> bool {
    s.len() <= 15
        && s.strip_prefix("awg")
            .is_some_and(|v| !v.is_empty() && v.bytes().all(|c| c.is_ascii_digit()))
}
fn protocol(s: &str) -> bool {
    matches!(s, "wireguard" | "awg/1.0" | "awg/1.5" | "awg/2" | "awg/3.1")
}
fn endpoint(s: &str) -> Option<String> {
    let (host, port) = s.trim().rsplit_once(':')?;
    let port = port.parse::<u16>().ok().filter(|p| *p > 0)?;
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.starts_with('[') && host.ends_with(']') {
        return Some(format!(
            "[{}]:{port}",
            host[1..host.len() - 1].parse::<std::net::Ipv6Addr>().ok()?
        ));
    }
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return Some(format!("{ip}:{port}"));
    }
    hostname(&host).then(|| format!("{host}:{port}"))
}
fn public_key(s: &str) -> Option<String> {
    let raw = Base64::decode_vec(s.trim()).ok()?;
    (raw.len() == 32).then(|| Base64::encode_string(&raw))
}
impl Ref {
    pub(crate) fn blank(id: &str) -> Self {
        Self {
            id: id.into(),
            label: id.into(),
            ..Default::default()
        }
    }
    fn fingerprint(&self) -> String {
        if !protocol(&self.protocol) || !iface(&self.client_iface) {
            return String::new();
        }
        match (
            endpoint(&self.endpoint),
            public_key(&self.server_public_key),
        ) {
            (Some(ep), Some(key)) => digest(
                [self.protocol.as_str(), &ep, &key, &self.client_iface]
                    .join("\0")
                    .as_bytes(),
                16,
            ),
            _ => String::new(),
        }
    }
    pub fn validate(&self) -> io::Result<()> {
        if !reference(&self.id)
            || !text(&self.label, 512)
            || !self.endpoint.is_empty() && endpoint(&self.endpoint).is_none()
            || !self.server_public_key.is_empty() && public_key(&self.server_public_key).is_none()
            || !self.client_iface.is_empty() && !iface(&self.client_iface)
            || !self.protocol.is_empty() && !protocol(&self.protocol)
            || self.fingerprint != self.fingerprint()
        {
            return Err(err("ошибочная идентичность или отпечаток подключения"));
        }
        Ok(())
    }
    pub(crate) fn detached(&self, live: &Refs, retained: &Refs, extra: &Refs) -> Self {
        let data = [
            &self.id,
            &self.fingerprint,
            &self.endpoint,
            &self.server_public_key,
            &self.protocol,
            &self.client_iface,
        ]
        .map(String::as_str)
        .join("\0");
        let base = format!("pending-import-{}", digest(data.as_bytes(), 16));
        for i in 0.. {
            let id = if i == 0 {
                base.clone()
            } else {
                format!("{base}-{i}")
            };
            let mut v = self.clone();
            v.id.clone_from(&id);
            if !live.contains_key(&id)
                && [retained, extra].iter().all(|map| {
                    map.get(&id).is_none_or(|r| {
                        r.fingerprint == v.fingerprint
                            && r.endpoint == v.endpoint
                            && r.protocol == v.protocol
                            && r.client_iface == v.client_iface
                            && r.server_public_key == v.server_public_key
                    })
                })
            {
                return v;
            }
        }
        unreachable!()
    }
}
pub(crate) fn live(doc: &Value) -> Refs {
    let mut used = std::collections::HashSet::new();
    let mut next = 0;
    doc["servers"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|row| {
            let c = &row["config"];
            let get = |k: &str| c[k].as_str().unwrap_or("");
            let id = row["id"].as_str().unwrap_or_default();
            let name = row["name"].as_str().unwrap_or("");
            let p = wire_protocol(c);
            let iface_name = get("client_iface").trim();
            let client_iface = if iface(iface_name) && used.insert(iface_name.to_owned()) {
                iface_name.into()
            } else {
                loop {
                    let v = format!("awg{next}");
                    next += 1;
                    if used.insert(v.clone()) {
                        break v;
                    }
                }
            };
            let ep = get("endpoint").trim();
            let legacy_ep;
            let ep = if ep.is_empty() && get("install") != "imported" {
                legacy_ep = format!(
                    "{}:{}",
                    c["conn"]["host"].as_str().unwrap_or_default().trim(),
                    c["listen_port"]
                        .as_u64()
                        .filter(|p| *p != 0)
                        .unwrap_or(51820)
                );
                &legacy_ep
            } else {
                ep
            };
            let mut r = Ref {
                id: id.into(),
                label: name.trim().into(),
                endpoint: endpoint(ep).unwrap_or_default(),
                server_public_key: public_key(get("public_key")).unwrap_or_default(),
                client_iface,
                protocol: if protocol(&p) { p } else { String::new() },
                fingerprint: String::new(),
            };
            r.fingerprint = r.fingerprint();
            (id.to_owned(), r)
        })
        .collect()
}
fn wire_protocol(c: &Value) -> String {
    if c["protocol"] == "wireguard" {
        return "wireguard".into();
    }
    let version = nfqws2_awg_profile::effective_protocol_version(c);
    format!("awg/{version}")
}
pub(crate) fn refs(doc: &Value, live: &Refs) -> io::Result<Refs> {
    let mut out = if doc["connection_refs"].is_null() {
        Refs::default()
    } else {
        serde_json::from_value(doc["connection_refs"].clone()).map_err(io::Error::other)?
    };
    out.extend(live.clone());
    Ok(out)
}
