use serde::{Deserialize, Serialize};
use std::{collections::HashSet, io, net::IpAddr};
pub(crate) const ROUTING_ENTRY_LIMIT: usize = 4 * 65_536;
pub(crate) fn err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}
pub(crate) fn empty(v: &bool) -> bool {
    !*v
}
fn zero(v: &usize) -> bool {
    *v == 0
}
fn list<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Vec<T>, D::Error> {
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Zone {
    /// Internal identity of a zone before local list/Geo references expand.
    #[serde(skip)]
    pub(crate) source_key: Option<String>,
    #[serde(skip_serializing_if = "empty")]
    pub waiting_for_connection: bool,
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tunnel_id: String,
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "list")]
    pub fallback_tunnel_ids: Vec<String>,
    #[serde(skip_serializing_if = "zero")]
    pub order: usize,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub route: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub mode: String,
    #[serde(deserialize_with = "list")]
    pub domains: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_subdomains: Option<bool>,
    #[serde(deserialize_with = "list")]
    pub ips: Vec<String>,
    #[serde(deserialize_with = "list")]
    pub source_ips: Vec<String>,
    pub enabled: bool,
}
impl Zone {
    pub(crate) fn only_catch_all(&self) -> bool {
        // Go's StaticOK deliberately keeps an empty rule. With no destination
        // set its match consists solely of its source (or every source).
        self.ips.iter().chain(&self.domains).all(|s| catch_all(s))
    }
    // DNS answers match the blanket even when the packet classifier retains
    // an ipset for additional explicit destinations in the same zone.
    pub(crate) fn dns_catch_all(&self) -> bool {
        self.only_catch_all()
            || self.domains.iter().any(|s| s.trim() == "*")
            || self
                .ips
                .iter()
                .any(|s| matches!(s.trim(), "0.0.0.0/0" | "::/0"))
    }
    pub fn direction(&self) -> &str {
        if self.route == "direct" || self.route.is_empty() && self.mode == "exclude" {
            "direct"
        } else {
            "tunnel"
        }
    }
    pub fn normalize(&mut self) {
        if self.route.is_empty() {
            self.route = self.direction().to_owned();
        }
        if self.mode.is_empty() {
            self.mode = if self.route == "direct" {
                "exclude"
            } else {
                "include"
            }
            .into();
        }
        if self.route == "direct" && !self.waiting_for_connection {
            self.fallback_tunnel_ids.clear();
        } else {
            let mut seen = HashSet::new();
            self.fallback_tunnel_ids
                .retain(|id| !id.is_empty() && id != &self.tunnel_id && seen.insert(id.clone()));
        }
    }
}
pub(crate) fn catch_all(value: &str) -> bool {
    matches!(value.trim(), "*" | "0.0.0.0/0" | "::/0")
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Routing {
    pub mode: String,
    #[serde(deserialize_with = "list")]
    pub zones: Vec<Zone>,
    pub mtu: u16,
    pub killswitch: bool,
    pub domain_source: String,
    pub sni_routing: bool,
    pub trace_enabled: bool,
    pub active: bool,
}
impl Routing {
    /// A bare destination wildcard is an unconditional IPv4 AWG2_MULTI jump.
    /// A wildcard accompanied by actual entries retains its destination set.
    pub(crate) fn global_default_zone(&self) -> Option<&Zone> {
        if !matches!(self.mode.as_str(), "zones" | "full") {
            return None;
        }
        let mut enabled = self
            .zones
            .iter()
            .filter(|z| z.enabled && !z.waiting_for_connection);
        let zone = enabled.next_back()?;
        (zone.source_ips.iter().all(|s| !s.contains(':'))
            && zone.direction() == "tunnel"
            && zone.only_catch_all()
            && enabled.all(|z| {
                z.direction() == "direct"
                    && z.source_ips.is_empty()
                    && z.ips
                        .iter()
                        .chain(&z.domains)
                        .all(|p| ipish(p) && !catch_all(p))
            }))
        .then_some(zone)
    }
    /// Go's multi-policy owns the final firewall when a full profile also
    /// supplies explicit rules. It does not append an implicit default zone.
    pub(crate) fn has_explicit_policy(&self) -> bool {
        self.mode == "zones"
            || self.mode == "full"
                && self
                    .zones
                    .iter()
                    .any(|z| z.enabled && !z.waiting_for_connection)
    }
    /// Go's watchdog also restores its single full tunnel when every active
    /// rule was discarded by the IPv4-only multi-policy builder. An empty
    /// destination list, an explicit default, and IPv4-mapped IPv6 addresses
    /// all survive that builder when their connection can route them.
    pub(crate) fn go_watchdog_full(&self, doc: &serde_json::Value) -> bool {
        self.mode == "full"
            && self
                .zones
                .iter()
                .filter(|z| z.enabled && !z.waiting_for_connection)
                .all(|z| {
                    z.source_key.is_none()
                        && z.domains.is_empty()
                        && !z.ips.is_empty()
                        && z.ips.iter().all(|net| {
                            let net = net.trim();
                            let (ip, length) = net.split_once('/').unwrap_or((net, "128"));
                            length.parse::<u8>().is_ok_and(|n| n > 0 && n <= 128)
                                && ip
                                    .parse::<std::net::Ipv6Addr>()
                                    .is_ok_and(|v| v.to_ipv4_mapped().is_none())
                        })
                        || skipped_copy(z, doc)
                })
    }
    pub fn normalize(&mut self) {
        for z in &mut self.zones {
            if z.mode.is_empty() && z.route.is_empty() && self.mode == "exclude" {
                z.mode = "exclude".into();
            }
            z.normalize();
        }
        self.mode = match self.mode.as_str() {
            "" => "off",
            "include" | "exclude" => "zones",
            m => m,
        }
        .into();
        if self.mtu == 0 {
            self.mtu = 1420;
        }
        if self.domain_source.is_empty() {
            self.domain_source = "resolve".into();
        }
    }
    pub fn validate(&self, deps: bool) -> io::Result<()> {
        if !matches!(
            self.mode.as_str(),
            "" | "off" | "zones" | "full" | "include" | "exclude"
        ) || !matches!(self.domain_source.as_str(), "" | "resolve" | "dnsproxy")
            || self.mtu != 0 && !(68..=9000).contains(&self.mtu)
            || self.zones.len() > 2048
        {
            return Err(err("неверные параметры маршрутизации"));
        }
        let mut entries = 0;
        for z in &self.zones {
            if !text(&z.name, 512)
                || z.order > 2048
                || !z.tunnel_id.is_empty() && !reference(&z.tunnel_id)
                || !matches!(z.route.as_str(), "" | "tunnel" | "direct")
                || !matches!(z.mode.as_str(), "" | "include" | "exclude")
                || z.fallback_tunnel_ids.len() > 256
            {
                return Err(err("неверное правило маршрутизации"));
            }
            let mut seen = HashSet::new();
            for id in &z.fallback_tunnel_ids {
                if !reference(id) || !seen.insert(id) {
                    return Err(err("неверная ссылка резервного подключения"));
                }
            }
            entries += z.domains.len() + z.ips.len() + z.source_ips.len();
            if entries > ROUTING_ENTRY_LIMIT {
                return Err(err("слишком много записей в правилах"));
            }
            for value in &z.domains {
                domain(value, deps)?;
            }
            if z.ips.iter().chain(&z.source_ips).any(|v| !ipish(v)) {
                return Err(err("неверный IP/CIDR"));
            }
        }
        Ok(())
    }
}

pub(crate) fn selected_profile(doc: &serde_json::Value) -> Option<&serde_json::Value> {
    doc["servers"]
        .as_array()?
        .iter()
        .find(|r| r["id"] == doc["active_id"])
}

fn skipped_copy(z: &Zone, doc: &serde_json::Value) -> bool {
    if z.domains.is_empty() || z.dns_catch_all() {
        return false;
    }
    let Some(owner) = selected_profile(doc).map(|row| &row["config"]) else {
        return false;
    };
    let profile = &owner["routing"];
    if owner["enabled"] != true
        || owner["client"]["enabled"] != true
        || profile["active"] != true
        || profile["mode"] != "full"
        || doc["active_id"] == z.tunnel_id
    {
        return false;
    }
    // Go's copy keeps the old TunnelID. The shared multi-policy discards a
    // directly addressed disabled connection. A tunnel zone may still reach
    // an enabled backup, so only accept that case with no reserves to walk.
    doc["servers"].as_array().into_iter().flatten().any(|row| {
        let config = &row["config"];
        row["id"] == z.tunnel_id
            && (config["enabled"] == false || config["client"]["enabled"] == false)
            && (z.direction() == "direct"
                || z.fallback_tunnel_ids.is_empty()
                    && config["client"]["fallback_tunnel_ids"]
                        .as_array()
                        .is_none_or(Vec::is_empty))
    })
}
pub(crate) fn text(s: &str, max: usize) -> bool {
    s.len() <= max && !s.chars().any(|c| c < ' ' || c == '\u{7f}')
}
pub(crate) fn reference(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c))
}
pub(crate) fn ipish(raw: &str) -> bool {
    if let Some((host, bits)) = raw.split_once('/') {
        return host.parse::<IpAddr>().is_ok_and(|ip| {
            bits.parse::<u8>()
                .is_ok_and(|n| n <= if ip.is_ipv4() { 32 } else { 128 })
        });
    }
    raw.parse::<IpAddr>().is_ok()
}
pub(crate) fn hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.parse::<IpAddr>().is_err()
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        })
}
pub(crate) fn dependency(v: &str) -> Option<(&'static str, &str)> {
    let (kind, value) = v.split_once(':')?;
    ["list", "geosite", "geoip"]
        .into_iter()
        .find(|p| kind.eq_ignore_ascii_case(p))
        .map(|k| (k, value))
}
pub(crate) fn domain(s: &str, deps: bool) -> io::Result<()> {
    if s.is_empty() || s.trim() != s || !text(s, 4096) {
        return Err(err("неверная запись домена"));
    }
    if let Some((_, id)) = dependency(s) {
        return if deps && reference(id) {
            Ok(())
        } else {
            Err(err("ссылка на локальную базу требует снимка"))
        };
    }
    let lower = s.to_ascii_lowercase();
    if let Some(pattern) = lower
        .strip_prefix("regexp:")
        .or_else(|| s.starts_with("[re]").then(|| &lower[4..]))
    {
        if pattern.is_empty() {
            return Err(err("пустое регулярное выражение"));
        }
        regex_syntax::ast::parse::Parser::new()
            .parse(pattern)
            .map_err(|_| err("некорректное регулярное выражение"))?;
        return Ok(());
    }
    if let Some(keyword) = lower.strip_prefix("keyword:") {
        return if keyword.is_empty() || keyword.chars().any(|c| "/\\\"'\u{60};$|&<> ".contains(c)) {
            Err(err("неверное ключевое слово"))
        } else {
            Ok(())
        };
    }
    let value = lower
        .strip_prefix("domain:")
        .or_else(|| lower.strip_prefix("full:"))
        .unwrap_or(&lower);
    let plain = value.strip_prefix('.').unwrap_or(value);
    if ipish(value)
        || hostname(plain.strip_suffix('.').unwrap_or(plain))
        || (value.contains(['*', '#'])
            && value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".-_*#".contains(&c)))
    {
        Ok(())
    } else {
        Err(err("неверный домен или маска"))
    }
}
