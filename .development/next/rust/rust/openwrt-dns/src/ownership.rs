use super::{
    err,
    uci::{valid_id, valid_instance, Configuration, OptionValue, Options, Section},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io,
    net::{IpAddr, Ipv4Addr},
};

// Go encoding/json escapes HTML-sensitive characters; these bytes are part of
// the on-disk identity and of the revision displayed by existing Go panels.
pub(crate) fn go_json(value: &impl Serialize) -> io::Result<String> {
    Ok(serde_json::to_string(value)?
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029"))
}
fn non_scoped(key: &str) -> bool {
    matches!(
        key,
        "cachesize"
            | "logqueries"
            | "logfacility"
            | "logdhcp"
            | "quietdhcp"
            | "quietdhcp6"
            | "logasync"
    )
}
fn identity(section: &Section, scope: bool) -> io::Result<String> {
    let settings: BTreeMap<_, _> = section
        .options
        .iter()
        .filter(|(k, _)| !matches!(k.as_str(), "server" | "noresolv") && !(scope && non_scoped(k)))
        .collect();
    Ok(super::hex(&Sha256::digest(go_json(&settings)?)))
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}
impl Endpoint {
    pub fn address(&self) -> io::Result<IpAddr> {
        let ip: IpAddr = self
            .host
            .parse()
            .map_err(|_| err("invalid DNS listener address"))?;
        let ip = ip.to_canonical();
        if self.port == 0
            || self.port == 53
            || ip.is_loopback()
            || ip.is_multicast()
            || ip.is_unspecified()
            || match ip {
                IpAddr::V4(v) => v.is_link_local() || v == Ipv4Addr::BROADCAST,
                IpAddr::V6(v) => v.is_unicast_link_local(),
            }
        {
            return Err(err(
                "expected a unicast LAN listener and a port other than 53",
            ));
        }
        Ok(ip)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Binding {
    pub interface: String,
    pub instance: String,
    pub endpoint: Endpoint,
}
impl Binding {
    pub fn validate(&self) -> io::Result<()> {
        self.endpoint.address()?;
        if !valid_id(&self.interface)
            || self.interface == "loopback"
            || !valid_instance(&self.instance)
        {
            return Err(err("invalid DNS binding"));
        }
        Ok(())
    }
    pub fn keys(&self) -> [String; 4] {
        [
            format!("network.{}.peerdns", self.interface),
            format!("network.{}.dns", self.interface),
            format!("dhcp.{}.noresolv", self.instance),
            format!("dhcp.{}.server", self.instance),
        ]
    }
    pub(crate) fn options(
        &self,
        network: &Configuration,
        dhcp: &Configuration,
    ) -> io::Result<Options> {
        let n = network.find(&self.interface, "interface")?;
        let d = dhcp.find(&self.instance, "dnsmasq")?;
        Ok(self
            .keys()
            .into_iter()
            .zip([(n, "peerdns"), (n, "dns"), (d, "noresolv"), (d, "server")])
            .map(|(k, (s, opt))| (k, s.options.get(opt).cloned().unwrap_or_default()))
            .collect())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) struct Snapshot {
    pub version: u8,
    pub binding: Binding,
    pub original: Options,
    pub applied: Options,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pending: bool,
    #[serde(default, skip_serializing_if = "Options::is_empty")]
    pub before: Options,
    #[serde(
        default,
        rename = "instanceIdentity",
        skip_serializing_if = "String::is_empty"
    )]
    pub identity: String,
    #[serde(
        default,
        rename = "instanceScope",
        skip_serializing_if = "String::is_empty"
    )]
    pub scope: String,
}
impl Snapshot {
    pub fn validate(&self) -> io::Result<()> {
        self.binding.validate()?;
        let hash = |v: &str| v.len() == 64 && v.bytes().all(|c| c.is_ascii_hexdigit());
        if self.version != 1
            || (self.binding.instance.starts_with('@') && !hash(&self.identity))
            || (!self.scope.is_empty() && !hash(&self.scope))
        {
            return Err(err("invalid DNS snapshot identity/version"));
        }
        let keys = self.binding.keys();
        let valid = |opts: &Options| {
            opts.len() == 4
                && keys
                    .iter()
                    .all(|k| opts.get(k).is_some_and(OptionValue::valid))
        };
        if !valid(&self.original)
            || !valid(&self.applied)
            || if self.pending {
                !valid(&self.before)
            } else {
                !self.before.is_empty()
            }
        {
            return Err(err("invalid managed UCI fields in snapshot"));
        }
        Ok(())
    }
    fn rekey(&self, id: &str) -> Self {
        let mut s = self.clone();
        if id != s.binding.instance {
            let old = format!("dhcp.{}.", s.binding.instance);
            for opts in [&mut s.original, &mut s.applied, &mut s.before] {
                *opts = std::mem::take(opts)
                    .into_iter()
                    .map(|(k, v)| {
                        (
                            k.strip_prefix(&old)
                                .map_or_else(|| k.clone(), |suffix| format!("dhcp.{id}.{suffix}")),
                            v,
                        )
                    })
                    .collect();
            }
            s.binding.instance = id.into();
        }
        s
    }
    fn owns(&self, s: &Section) -> bool {
        ["noresolv", "server"].iter().all(|key| {
            let v = s.options.get(*key).cloned().unwrap_or_default();
            self.applied
                .get(&format!("dhcp.{}.{key}", self.binding.instance))
                == Some(&v)
        })
    }
    pub fn resolve(&self, dhcp: &Configuration) -> io::Result<Option<Self>> {
        if !self.binding.instance.starts_with('@') {
            return Ok(Some(self.clone()));
        }
        for scope in [false, true] {
            if scope && (self.pending || self.scope.is_empty()) {
                break;
            }
            let mut found = None;
            for s in &dhcp.sections {
                if s.kind != "dnsmasq" || !s.id.starts_with('@') || scope && !self.owns(s) {
                    continue;
                }
                if identity(s, scope)?
                    == if scope {
                        self.scope.as_str()
                    } else {
                        self.identity.as_str()
                    }
                {
                    if found.is_some() {
                        return Err(err("ambiguous dnsmasq instance"));
                    }
                    found = Some(&s.id);
                }
            }
            if let Some(id) = found {
                return Ok(Some(self.rekey(id)));
            }
        }
        Ok(None)
    }
    pub fn rebind_candidate(&self, network: &Configuration, dhcp: &Configuration) -> Option<Self> {
        if self.pending || !self.scope.is_empty() {
            return None;
        }
        let mut found = dhcp
            .sections
            .iter()
            .filter(|s| s.kind == "dnsmasq" && self.owns(s));
        let s = found.next()?;
        if !s.enabled() || !s.id.starts_with('@') || found.next().is_some() {
            return None;
        }
        let candidate = self.rekey(&s.id);
        candidate
            .check(&candidate.binding.options(network, dhcp).ok()?)
            .ok()?;
        Some(candidate)
    }
    pub fn capture(&mut self, dhcp: &Configuration) -> io::Result<()> {
        if self.binding.instance.starts_with('@') {
            let s = dhcp.find(&self.binding.instance, "dnsmasq")?;
            self.identity = identity(s, false)?;
            self.scope = identity(s, true)?;
            self.check_identity(dhcp)?;
        }
        Ok(())
    }
    pub fn check_identity(&self, dhcp: &Configuration) -> io::Result<()> {
        if !self.binding.instance.starts_with('@') {
            return Ok(());
        }
        let mut selected = false;
        for s in dhcp
            .sections
            .iter()
            .filter(|s| s.kind == "dnsmasq" && s.id.starts_with('@'))
        {
            if identity(s, false)? == self.identity {
                if s.id != self.binding.instance {
                    return Err(err("dnsmasq instance moved or has ambiguous identity"));
                }
                selected = true;
            }
        }
        if !selected {
            return Err(err("managed dnsmasq instance changed during transaction"));
        }
        Ok(())
    }
    pub fn check(&self, current: &Options) -> io::Result<()> {
        for (key, v) in current {
            let applied = &self.applied[key];
            if v == applied {
                continue;
            }
            if self.pending {
                let before = &self.before[key];
                if v == before || v.kind.is_empty() || v.prefix_of(applied) || v.prefix_of(before) {
                    continue;
                }
            }
            return Err(err(format!("параметр {key} изменён вне приложения")));
        }
        Ok(())
    }
}
