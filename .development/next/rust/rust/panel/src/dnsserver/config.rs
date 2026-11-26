use axum::http::Uri;
use nfqws2_store::ConfigFile;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    io,
    net::IpAddr,
};

pub fn invalid(s: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, s.into())
}
pub fn defaults() -> Value {
    serde_json::from_str(include_str!("default.json")).expect("Go DNS defaults")
}
pub const FILE: ConfigFile<Value> = ConfigFile::new("dnsserver.json", defaults, |v| {
    Config::from_value(v).map(|_| ())
});
pub fn hash(v: &Value) -> String {
    document_hash(v, true)
}
pub(super) fn document_hash(v: &Value, form: bool) -> String {
    // Field order and Go's HTML escapes are part of the optimistic-edit token
    // returned by the previous server. Its cloneConfig canonicalizes nil slices.
    let mut cfg = Config::from_value(v).expect("validated DNS config");
    if form {
        cfg.dns_port = 0;
        cfg.logging_enabled = false;
        cfg.disabled_methods.clear();
    }
    cfg.extra.clear();
    let raw = serde_json::to_string(&cfg)
        .unwrap()
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029");
    use std::fmt::Write;
    let mut hex = String::with_capacity(64);
    for b in Sha256::digest(raw.as_bytes()) {
        write!(hex, "{b:02x}").expect("string writer");
    }
    hex
}
pub fn domain(raw: &str) -> io::Result<String> {
    let raw = raw.trim();
    let ascii = idna::domain_to_ascii(raw.strip_suffix('.').unwrap_or(raw))
        .map_err(|_| invalid("некорректный домен"))?
        .to_ascii_lowercase();
    if ascii.len() > 253
        || ascii.split('.').any(|l| {
            l.is_empty()
                || l.len() > 63
                || l.starts_with('-')
                || l.ends_with('-')
                || !l
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        })
    {
        return Err(invalid("некорректный домен"));
    }
    Ok(ascii)
}
pub fn local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_private() || v.is_loopback(),
        IpAddr::V6(v) => v.is_unique_local() || v.is_loopback(),
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub struct Upstream {
    pub address: String,
    #[serde(default, deserialize_with = "read_ips")]
    pub bootstrap_ips: Vec<IpAddr>,
}
fn read_ips<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<IpAddr>, D::Error> {
    let values = Option::<Vec<String>>::deserialize(d)?.unwrap_or_default();
    if values.len() > 16 {
        return Err(serde::de::Error::custom("не более 16 bootstrap IP"));
    }
    values
        .into_iter()
        .map(|s| s.trim().parse().map_err(serde::de::Error::custom))
        .collect()
}
pub(super) fn display_upstream(address: &str) -> String {
    // Custom DoH URLs can contain credentials in the query or in a provider's path.
    let Ok(uri) = address.parse::<Uri>() else {
        return String::new();
    };
    let Some(authority) = uri.authority() else {
        return String::new();
    };
    format!(
        "https://{authority}{}",
        if uri.path() == "/dns-query" {
            "/dns-query"
        } else {
            "/…"
        }
    )
}
impl Upstream {
    fn normalize(&mut self) -> io::Result<()> {
        let raw = self.address.trim();
        let (authority, suffix) = raw
            .strip_prefix("https://")
            .map(|v| v.find(['/', '?']).map_or((v, ""), |i| v.split_at(i)))
            .ok_or_else(|| invalid("требуется DoH https://…"))?;
        if raw.len() > 2048 || raw.contains('#') || authority.contains('@') || authority.is_empty()
        {
            return Err(invalid("неверный адрес DoH"));
        }
        let (host, port) = if let Some(v) = authority.strip_prefix('[') {
            let (ip, tail) = v
                .split_once(']')
                .ok_or_else(|| invalid("неверный IPv6 адрес DoH"))?;
            let ip: std::net::Ipv6Addr =
                ip.parse().map_err(|_| invalid("неверный IPv6 адрес DoH"))?;
            (
                match IpAddr::V6(ip).to_canonical() {
                    IpAddr::V4(ip) => ip.to_string(),
                    IpAddr::V6(ip) => format!("[{ip}]"),
                },
                if tail.is_empty() {
                    None
                } else {
                    Some(
                        tail.strip_prefix(':')
                            .ok_or_else(|| invalid("неверный порт DoH"))?,
                    )
                },
            )
        } else {
            let (name, port) = authority
                .split_once(':')
                .map_or((authority, None), |(a, p)| (a, Some(p)));
            (domain(name)?, port)
        };
        let port = port
            .map(|p| {
                p.parse::<u16>()
                    .ok()
                    .filter(|p| *p > 0)
                    .ok_or_else(|| invalid("неверный порт DoH"))
            })
            .transpose()?
            .unwrap_or(443);
        self.address = format!(
            "https://{host}{}{}{}",
            if port == 443 {
                String::new()
            } else {
                format!(":{port}")
            },
            if suffix.starts_with('/') {
                ""
            } else {
                "/dns-query"
            },
            suffix
        );
        self.address
            .parse::<Uri>()
            .map_err(|_| invalid("неверный адрес DoH"))?;
        for ip in &mut self.bootstrap_ips {
            *ip = ip.to_canonical();
        }
        if self.bootstrap_ips.len() > 16
            || self
                .bootstrap_ips
                .iter()
                .any(|ip| ip.is_unspecified() || ip.is_multicast())
        {
            return Err(invalid("неверные bootstrap IP"));
        }
        let mut seen = HashSet::new();
        self.bootstrap_ips.retain(|ip| seen.insert(*ip));
        Ok(())
    }
}
fn pool(primary: &mut Upstream, others: &mut Vec<Upstream>) -> io::Result<()> {
    if others.len() >= 8 {
        return Err(invalid("не более 8 DoH-серверов в одном пуле"));
    }
    primary.normalize()?;
    let mut seen = HashSet::from([primary.address.clone()]);
    for u in others.iter_mut() {
        u.normalize()?;
    }
    others.retain(|u| seen.insert(u.address.clone()));
    Ok(())
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Rule {
    #[serde(default)]
    pub id: String,
    pub enabled: bool,
    pub domain: String,
    #[serde(default)]
    pub include_subdomains: bool,
    pub upstream: Upstream,
    #[serde(default)]
    pub pool: Vec<Upstream>,
}
fn implicit_rule_id(index: usize) -> String {
    format!("rule-{}", index + 1)
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub struct Method {
    pub upstream: String,
    pub route: String,
}
impl Method {
    pub(super) fn normalize(&mut self) -> io::Result<()> {
        let mut u = Upstream {
            address: std::mem::take(&mut self.upstream),
            bootstrap_ips: vec![],
        };
        u.normalize()?;
        self.upstream = u.address;
        self.route = self.route.trim().to_owned();
        if self.route != "nfqws"
            && !self.route.strip_prefix("awg:").is_some_and(|id| {
                !id.is_empty()
                    && id.len() <= 96
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            })
        {
            return Err(invalid("метод DNS: маршрут должен быть nfqws или awg:ID"));
        }
        Ok(())
    }
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Config {
    #[serde(serialize_with = "serialize_shadow")]
    pub shadow_dns: Value,
    pub enabled: bool,
    pub listen_host: String,
    pub dns_port: u16,
    pub default_upstream: Upstream,
    pub default_pool: Vec<Upstream>,
    pub logging_enabled: bool,
    pub fast_dns: bool,
    pub scheduler_enabled: bool,
    pub awg_fallback: String,
    pub route_mode: String,
    #[serde(serialize_with = "serialize_filtering")]
    pub filtering: Value,
    pub timeout_seconds: u64,
    pub cache_size: usize,
    pub cache_ttl_seconds: u32,
    pub rules: Vec<Rule>,
    pub disabled_methods: Vec<Method>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}
fn serialize_shadow<S: serde::Serializer>(value: &Value, s: S) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct Shadow<'a> {
        enabled: &'a Value,
        servers: &'a Value,
        domains: &'a Value,
    }
    Shadow {
        enabled: &value["enabled"],
        servers: &value["servers"],
        domains: &value["domains"],
    }
    .serialize(s)
}
fn serialize_filtering<S: serde::Serializer>(value: &Value, s: S) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct Rule<'a> {
        domain: &'a Value,
        category: &'a Value,
    }
    #[derive(Serialize)]
    struct Filtering<'a> {
        enabled: &'a Value,
        lists: &'a Value,
        custom_rules: Vec<Rule<'a>>,
        allowlist: &'a Value,
    }
    Filtering {
        enabled: &value["enabled"],
        lists: &value["lists"],
        custom_rules: value["custom_rules"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|r| Rule {
                domain: &r["domain"],
                category: &r["category"],
            })
            .collect(),
        allowlist: &value["allowlist"],
    }
    .serialize(s)
}
impl Config {
    pub fn from_value(v: &Value) -> io::Result<Self> {
        let src = v
            .as_object()
            .ok_or_else(|| invalid("параметры DNS должны быть объектом"))?;
        let mut base = defaults();
        if src.is_empty()
            || !src.contains_key("default_upstream")
            || !src.contains_key("timeout_seconds")
        {
            return Err(invalid("в настройках DNS отсутствуют обязательные поля"));
        }
        base["rules"] = Value::Array(vec![]);
        base["cache_size"] = Value::from(0);
        base.as_object_mut().unwrap().extend(src.clone());
        for k in ["shadow_dns", "filtering"] {
            if base[k].is_null() {
                base[k] = defaults()[k].take();
            }
        }
        for name in ["rules", "default_pool", "disabled_methods"] {
            if base[name].is_null() {
                base[name] = Value::Array(vec![]);
            }
        }
        if let Some(rules) = base["rules"].as_array_mut() {
            for r in rules {
                if !r.is_object() {
                    return Err(invalid("неверное правило DNS"));
                }
                if r["enabled"].is_null() {
                    r["enabled"] = Value::Bool(false);
                }
                if r["pool"].is_null() {
                    r["pool"] = Value::Array(vec![]);
                }
            }
        }
        let mut c: Config = serde_json::from_value(base).map_err(|e| invalid(e.to_string()))?;
        c.listen_host = match c.listen_host.trim() {
            "" | "auto" => "auto".into(),
            host => host
                .parse::<IpAddr>()
                .ok()
                .map(|addr| addr.to_canonical())
                .filter(|addr| local(*addr))
                .ok_or_else(|| invalid("укажите локальный IP LAN или auto"))?
                .to_string(),
        };
        if c.dns_port == 0
            || !(1..=10).contains(&c.timeout_seconds)
            || c.cache_size > 4096
            || !(1..=86400).contains(&c.cache_ttl_seconds)
        {
            return Err(invalid("порт, таймаут или размер DNS-кэша вне диапазона"));
        }
        c.route_mode = match c.route_mode.trim() {
            "" => "auto".into(),
            mode => mode.to_owned(),
        };
        if c.awg_fallback.is_empty() {
            c.awg_fallback = "auto".into();
        }
        if let Some(id) = c.awg_fallback.strip_prefix("awg:") {
            c.awg_fallback = id.to_owned();
        }
        if !matches!(c.route_mode.as_str(), "auto" | "vpn_only")
            || (c.route_mode == "vpn_only" && c.awg_fallback == "off")
            || c.awg_fallback.len() > 100
        {
            return Err(invalid("неверная политика маршрутизации DNS"));
        }
        for policy in [&mut c.shadow_dns, &mut c.filtering] {
            if policy.is_object() && policy["enabled"].is_null() {
                policy["enabled"] = Value::Bool(false);
            } else if !policy["enabled"].is_boolean() {
                return Err(invalid("неверная политика DNS"));
            }
        }
        for (policy, arrays) in [
            (
                &mut c.shadow_dns,
                &[("domains", 4096usize), ("servers", 4096)][..],
            ),
            (
                &mut c.filtering,
                &[("custom_rules", 2000), ("allowlist", 2000), ("lists", 2000)][..],
            ),
        ] {
            for &(field, limit) in arrays {
                if policy[field].is_null() {
                    policy[field] = Value::Array(Vec::new());
                }
                if !policy[field].as_array().is_some_and(|a| a.len() <= limit) {
                    return Err(invalid("неверный размер списка DNS"));
                }
            }
        }
        if c.disabled_methods.len() > 2048 {
            return Err(invalid("не более 2048 отключённых методов DNS"));
        }
        super::filtering::normalize(&mut c.filtering)?;
        super::shadow::normalize(&mut c.shadow_dns)?;
        let mut seen = HashSet::new();
        for method in &mut c.disabled_methods {
            method.normalize()?;
        }
        c.disabled_methods.retain(|m| seen.insert(m.clone()));
        pool(&mut c.default_upstream, &mut c.default_pool)?;
        if c.rules.len() > 512 {
            return Err(invalid("не более 512 правил DNS"));
        }
        let (mut ids, mut domains) = (HashSet::new(), HashSet::new());
        for (i, r) in c.rules.iter_mut().enumerate() {
            if r.id.is_empty() {
                r.id = implicit_rule_id(i);
            }
            r.domain = domain(&r.domain)?;
            if !ids.insert(r.id.clone()) || r.enabled && !domains.insert(r.domain.clone()) {
                return Err(invalid("повторяется правило DNS"));
            }
            pool(&mut r.upstream, &mut r.pool)?;
        }
        Ok(c)
    }
    pub fn check_runtime(&self) -> io::Result<()> {
        if !cfg!(target_os = "linux") && self.route_mode == "vpn_only" {
            return Err(invalid(
                "режим DNS «только VPN» требует Linux для привязки сокетов к AWG",
            ));
        }
        Ok(())
    }
    pub fn servers(&self, name: &str) -> (&str, &Upstream, &[Upstream]) {
        let rule = self
            .rules
            .iter()
            .filter(|r| {
                r.enabled
                    && (r.domain == name
                        || r.include_subdomains
                            && name
                                .strip_suffix(&r.domain)
                                .is_some_and(|p| p.ends_with('.')))
            })
            .max_by_key(|r| r.domain.len());
        rule.map_or(
            (
                "default",
                &self.default_upstream,
                self.default_pool.as_slice(),
            ),
            |r| (r.domain.as_str(), &r.upstream, r.pool.as_slice()),
        )
    }
}
pub fn merged(current: &Value, mut edit: Value) -> io::Result<Value> {
    let form = edit
        .as_object_mut()
        .ok_or_else(|| invalid("ожидался объект DNS"))?;
    form.remove("base_hash");
    for k in ["dns_port", "logging_enabled", "disabled_methods"] {
        form.remove(k);
    }
    // The Go settings form treats nil pointers and a nil default pool as omitted.
    // An explicit false or empty array still replaces the saved value.
    for k in [
        "cache_ttl_seconds",
        "fast_dns",
        "scheduler_enabled",
        "route_mode",
        "filtering",
        "shadow_dns",
        "default_pool",
    ] {
        if form.get(k).is_some_and(Value::is_null) {
            form.remove(k);
        }
    }
    if let Some(rules) = form.get_mut("rules").and_then(Value::as_array_mut) {
        // The form echoes the IDs returned by status, including IDs assigned on load.
        let pools: HashMap<_, _> = current["rules"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
            .filter_map(|(i, old)| {
                let pool = old["pool"].as_array().filter(|pool| !pool.is_empty())?;
                let id = match old["id"].as_str() {
                    Some(id) if !id.is_empty() => Cow::Borrowed(id),
                    _ => Cow::Owned(implicit_rule_id(i)),
                };
                Some((id, pool))
            })
            .collect();
        for rule in rules {
            if !rule.is_object() {
                return Err(invalid("неверное правило DNS"));
            }
            if rule["pool"].is_null() {
                if let Some(pool) = rule["id"].as_str().and_then(|id| pools.get(id)) {
                    rule["pool"] = Value::Array((*pool).clone());
                }
            }
        }
    }
    let mut next = current.clone();
    next.as_object_mut().unwrap().extend(std::mem::take(form));
    let normalized = Config::from_value(&next)?;
    let mut value = serde_json::to_value(&normalized).map_err(io::Error::other)?;
    value["filtering"] = normalized.filtering;
    value["shadow_dns"] = normalized.shadow_dns;
    Ok(value)
}
