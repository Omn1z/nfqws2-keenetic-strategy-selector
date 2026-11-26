use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
pub fn domain(raw: &str) -> std::io::Result<String> {
    let bad = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "некорректный домен сервиса",
        )
    };
    let text = raw.trim();
    let text = text.strip_prefix("*.").unwrap_or(text);
    let text = text.strip_prefix('.').unwrap_or(text);
    let text = text.strip_suffix('.').unwrap_or(text);
    let ascii = idna::domain_to_ascii(text)
        .map_err(|_| bad())?
        .to_ascii_lowercase();
    if ascii.len() > 253
        || !ascii.contains('.')
        || ascii.parse::<std::net::IpAddr>().is_ok()
        || ascii.split('.').any(|l| {
            l.is_empty()
                || l.len() > 63
                || l.starts_with('-')
                || l.ends_with('-')
                || !l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(bad());
    }
    Ok(ascii)
}

fn list<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Vec<T>, D::Error> {
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, deserialize_with = "list")]
    pub groups: Vec<Group>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub kind: String,
    #[serde(default, deserialize_with = "list")]
    pub entries: Vec<String>,
    #[serde(default)]
    pub strategy: String,
}
#[derive(Deserialize, Serialize)]
pub struct Request {
    #[serde(default, deserialize_with = "list")]
    pub services: Vec<Service>,
    pub source: String,
    pub lists_dir: String,
}
#[derive(Deserialize, Serialize)]
pub struct Compiled {
    pub services: Vec<Service>,
    pub lists: BTreeMap<String, String>,
    pub config: String,
    pub args: String,
    pub tcp_ports: String,
    pub udp_ports: String,
    pub profiles: usize,
    pub warnings: Vec<String>,
}
#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    #[serde(default, deserialize_with = "list")]
    pub services: Vec<Service>,
    #[serde(default)]
    pub restart_required: bool,
}
