use super::{active, add_config, conf, invalid, modern, now, s, FILE};
use base64ct::{Base64, Encoding};
use curve25519_dalek::montgomery::MontgomeryPoint;
use nfqws2_store::{new_id, Store};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    io,
    net::{IpAddr, Ipv4Addr},
};

#[derive(Deserialize, Serialize, Default)]
#[serde(default)]
pub struct PeerInput {
    pub is_router: bool,
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub private_key: String,
    pub psk: String,
    pub address: String,
    pub allowed_ips: String,
    pub keepalive: u16,
    pub keepalive_range: String,
}
pub(crate) fn random() -> io::Result<[u8; 32]> {
    let mut b = [0; 32];
    getrandom::getrandom(&mut b).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(b)
}
pub(crate) fn pair() -> io::Result<(String, String)> {
    let mut raw = random()?;
    raw[0] &= 248;
    raw[31] &= 127;
    raw[31] |= 64;
    Ok((
        Base64::encode_string(&raw),
        Base64::encode_string(MontgomeryPoint::mul_base_clamped(raw).as_bytes()),
    ))
}
fn addresses(v: &str) -> impl Iterator<Item = IpAddr> + '_ {
    v.split(',')
        .filter_map(|t| t.trim().split('/').next()?.parse::<IpAddr>().ok())
}
pub(crate) fn append(cfg: &mut Value, incoming: PeerInput, router: bool) -> io::Result<Value> {
    let id = if incoming.id.is_empty() {
        new_id()?
    } else {
        incoming.id
    };
    if id.len() > 100
        || id
            .chars()
            .any(|c| c.is_control() || matches!(c, '/' | '\\'))
        || incoming.name.len() > 512
        || incoming.name.chars().any(char::is_control)
    {
        return Err(invalid("неверный ID или имя пира"));
    }
    let (private, public) = if !incoming.private_key.is_empty() {
        let raw = conf::key(&incoming.private_key, false)?;
        let public = Base64::encode_string(MontgomeryPoint::mul_base_clamped(raw).as_bytes());
        if !incoming.public_key.is_empty() && public != incoming.public_key {
            return Err(invalid("публичный и приватный ключи не соответствуют"));
        }
        (incoming.private_key, public)
    } else if incoming.public_key.is_empty() {
        pair()?
    } else {
        conf::key(&incoming.public_key, false)?;
        (String::new(), incoming.public_key)
    };
    let psk = if incoming.psk.is_empty() {
        Base64::encode_string(&random()?)
    } else {
        conf::key(&incoming.psk, true)?;
        incoming.psk
    };
    let subnet = s(cfg, "address").to_owned();
    let needs_range = cfg["protocol_version"] == "3.1"
        && cfg["traffic_obfuscation"] != false
        && cfg["protocol"] != "wireguard";
    if cfg["peers"].is_null() {
        cfg["peers"] = json!([]);
    }
    let peers = cfg["peers"]
        .as_array_mut()
        .ok_or_else(|| invalid("неверный список пиров"))?;
    if router && (private.is_empty() || peers.iter().any(|p| p["is_router"] == true)) {
        return Err(invalid("нужен единственный роутер-пир с приватным ключом"));
    }
    if peers
        .iter()
        .any(|p| p["id"] == id || p["public_key"] == public)
    {
        return Err(invalid("пир с таким ключом или ID уже существует"));
    }
    let used: HashSet<_> = peers
        .iter()
        .flat_map(|p| addresses(s(p, "address")))
        .chain(addresses(&subnet))
        .collect();
    let address = if !incoming.address.is_empty() {
        conf::cidrs(&incoming.address, false)?;
        if addresses(&incoming.address).any(|ip| used.contains(&ip)) {
            return Err(invalid("адрес пира уже занят"));
        }
        incoming.address
    } else {
        let (ip, bits) = subnet
            .split_once('/')
            .ok_or_else(|| invalid("требуется IPv4-подсеть сервера"))?;
        let ip = ip
            .parse::<Ipv4Addr>()
            .map_err(|_| invalid("требуется IPv4-подсеть сервера"))?;
        let bits = bits
            .parse::<u8>()
            .ok()
            .filter(|b| *b <= 30)
            .ok_or_else(|| invalid("в подсети нет свободного адреса"))?;
        let mask = u32::MAX.checked_shl(u32::from(32 - bits)).unwrap_or(0);
        let network = u32::from(ip) & mask;
        let last = network | !mask;
        let ip = (network.saturating_add(2)..last)
            .take(used.len() + 2)
            .map(Ipv4Addr::from)
            .find(|ip| !used.contains(&IpAddr::V4(*ip)))
            .ok_or_else(|| invalid("в подсети нет свободного адреса"))?;
        format!("{ip}/32")
    };
    let allowed = if incoming.allowed_ips.is_empty() {
        "0.0.0.0/0, ::/0".into()
    } else {
        incoming.allowed_ips
    };
    conf::cidrs(&allowed, true)?;
    let name = if incoming.name.trim().is_empty() {
        format!("peer-{}", id.chars().take(4).collect::<String>())
    } else {
        incoming.name.trim().into()
    };
    let mut peer = json!({"id":id,"name":name,"public_key":public,"private_key":private,"psk":psk,"address":address,"allowed_ips":allowed,"keepalive":if incoming.keepalive==0{25}else{incoming.keepalive},
        "created_at":now(),"has_private":!private.is_empty(),"is_router":router});
    if !incoming.keepalive_range.is_empty() {
        peer["keepalive_range"] = json!(conf::range(&incoming.keepalive_range, 65535)?);
    } else if needs_range {
        peer["keepalive_range"] = json!("25-35");
    }
    peers.push(peer.clone());
    if router {
        cfg["client"]["peer_id"] = json!(id);
    }
    Ok(redacted(peer))
}
pub(crate) fn redacted(mut peer: Value) -> Value {
    peer["private_key"] = json!("");
    peer["psk"] = json!("");
    peer
}
pub fn add_server(db: &Store, name: &str) -> io::Result<()> {
    let mut cfg = conf::base();
    let (private, public) = pair()?;
    cfg["private_key"] = json!(private);
    cfg["public_key"] = json!(public);
    append(
        &mut cfg,
        PeerInput {
            name: "Keenetic".into(),
            ..Default::default()
        },
        true,
    )?;
    add_config(db, cfg, name)
}
fn edit<R>(db: &Store, f: impl FnOnce(&mut Value) -> io::Result<R>) -> io::Result<R> {
    FILE.edit(db, |doc| {
        modern(doc);
        let id = active(doc)?["id"].clone();
        let row = doc["servers"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|r| r["id"] == id)
            .unwrap();
        if row["config"]["install"] == "imported" {
            return Err(invalid("imported-профиль не управляет удалённым сервером"));
        }
        if row["applied_config"].is_object()
            || row["config"]["deployed_at"].as_u64().unwrap_or(0) > 0
        {
            return Err(invalid(
                "для развёрнутого сервера нужна синхронизация пиров через SSH",
            ));
        }
        f(&mut row["config"])
    })
}
pub fn add_peer(db: &Store, v: PeerInput) -> io::Result<Value> {
    let router = v.is_router;
    edit(db, |cfg| append(cfg, v, router))
}
pub fn remove_peer(db: &Store, id: &str) -> io::Result<()> {
    edit(db, |cfg| discard(cfg, id))
}
pub(crate) fn discard(cfg: &mut Value, id: &str) -> io::Result<()> {
    let selected = s(&cfg["client"], "peer_id") == id;
    let peers = cfg["peers"]
        .as_array_mut()
        .ok_or_else(|| invalid("пир не найден"))?;
    let i = peers
        .iter()
        .position(|p| p["id"] == id)
        .ok_or_else(|| invalid("пир не найден"))?;
    peers.remove(i);
    if selected {
        cfg["client"]["peer_id"] = json!("");
    }
    Ok(())
}
