use super::{
    discovery::{native, usable, wan},
    leases,
};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr},
};
use time::OffsetDateTime;

pub(super) fn device(name: &str) -> bool {
    name.strip_prefix("ppp").is_some_and(|n| {
        n.parse::<u32>().is_ok() && !n.starts_with('+') && (n == "0" || !n.starts_with('0'))
    }) && wan(name)
}
#[derive(Debug, PartialEq)]
pub(super) struct Uplink {
    native: String,
    dev: String,
    client: Ipv4Addr,
    session: u16,
    uptime: u32,
}
impl Uplink {
    fn from_fields(
        name: &str,
        fields: &HashMap<&str, &str>,
        hosts: &[(String, IpAddr)],
        configured: &[String],
        main: &HashSet<String>,
    ) -> Option<Self> {
        let get = |k| fields.get(k).copied();
        let id = get("id").unwrap_or(name);
        if !native(name)
            || !native(id)
            || get("type") != Some("PPPoE")
            || get("connected") != Some("yes")
            || get("global") != Some("yes")
            || get("defaultgw") != Some("yes")
            || get("security-level") != Some("public")
        {
            return None;
        }
        let client = ipv4(get("address")?)?;
        let (dev, _) = hosts.iter().find(|(d, ip)| {
            device(d) && main.contains(d) && configured.contains(d) && *ip == IpAddr::V4(client)
        })?;
        Some(Self {
            native: id.into(),
            dev: dev.clone(),
            client,
            session: get("session-id")?.parse::<u16>().ok().filter(|n| *n != 0)?,
            uptime: get("uptime")?.parse().ok()?,
        })
    }
}

pub(super) fn active(
    text: &str,
    hosts: &[(String, IpAddr)],
    configured: &[String],
    main: &HashSet<String>,
) -> Vec<Uplink> {
    interface_records(text, |name, fields| Uplink::from_fields(name, fields, hosts, configured, main))
}

pub(crate) fn interface_records<T>(
    text: &str,
    mut select: impl FnMut(&str, &HashMap<&str, &str>) -> Option<T>,
) -> Vec<T> {
    let mut results = Vec::new();
    let mut name = String::new();
    let mut fields = HashMap::<&str, &str>::new();
    let mut scalar = None;
    let mut nested = false;
    let mut invalid = false;
    for raw in text.lines().chain(["Interface, name = \"\""]) {
        let raw = raw.trim_start_matches("\x1b[K");
        let line = raw.trim();
        if let Some(label) = line.strip_prefix("Interface, name = ") {
            if !invalid {
                if let Some(link) = select(&name, &fields) {
                    if results.len() >= 32 {
                        return Vec::new();
                    }
                    results.push(link);
                }
            }
            name = serde_json::from_str(label.trim_end_matches(':')).unwrap_or_default();
            fields.clear();
            scalar = None;
            nested = false;
            invalid = false;
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let column = raw.find(':');
        if nested && column != scalar {
            continue;
        }
        if scalar.is_none() {
            scalar = column;
        }
        let key = key.trim();
        nested = matches!(key, "ipv6" | "summary" | "addresses") || key.starts_with("port,");
        if matches!(
            key,
            "id" | "type"
                | "address"
                | "connected"
                | "global"
                | "defaultgw"
                | "security-level"
                | "session-id"
                | "uptime"
        ) && fields.insert(key, value.trim()).is_some()
        {
            invalid = true;
        }
    }
    results
}

#[derive(Default)]
enum Link {
    #[default]
    Idle,
    Session,
    Interface,
    Connected,
    Assigned,
}
#[derive(Default)]
struct Negotiation {
    stage: Link,
    stamp: Option<OffsetDateTime>,
    id: u16,
    dev: String,
    client: Option<Ipv4Addr>,
    names: Vec<Ipv4Addr>,
    malformed: bool,
}
impl Negotiation {
    fn reset(&mut self, pid: u32, owners: &mut HashMap<String, u32>) {
        if owners.get(&self.dev) == Some(&pid) {
            owners.remove(&self.dev);
        }
        *self = Self::default();
    }
}
fn ipv4(v: &str) -> Option<Ipv4Addr> {
    v.parse::<Ipv4Addr>().ok().filter(|ip| usable((*ip).into()))
}
fn states(log: &str, now: OffsetDateTime) -> Vec<Negotiation> {
    let mut states = HashMap::<u32, Negotiation>::new();
    let mut owners = HashMap::<String, u32>::new();
    let mut overflow = false;
    leases::records(log, |line| {
        if overflow {
            return;
        }
        if line.is_empty() {
            states.clear();
            owners.clear();
            return;
        }
        let Some((stamp, msg)) = line.get(3..).and_then(|s| s.split_once("] ")) else {
            return;
        };
        let Some(raw) = msg.strip_prefix("pppd[") else {
            return;
        };
        let Some((rawpid, msg)) = raw.split_once("]: ") else {
            states.clear();
            owners.clear();
            return;
        };
        let Some(pid) = rawpid
            .parse::<u32>()
            .ok()
            .filter(|n| *n != 0 && n.to_string() == rawpid)
        else {
            states.clear();
            owners.clear();
            return;
        };
        if !states.contains_key(&pid) && states.len() >= 64 {
            overflow = true;
            return;
        }
        let st = states.entry(pid).or_default();
        let mut words = msg.split_ascii_whitespace();
        let [a, b, c, d, e] = std::array::from_fn(|_| words.next().unwrap_or(""));
        match a {
            "PPP" if b == "session" => {
                st.reset(pid, &mut owners);
                if c == "is" && e.is_empty() {
                    if let Some(id) = d.parse::<u16>().ok().filter(|n| *n != 0) {
                        st.stamp = leases::observed_at(stamp, now);
                        st.id = id;
                        st.stage = Link::Session;
                    }
                }
            }
            "Using" if b == "interface" => {
                let keep = matches!(st.stage, Link::Session);
                if !keep {
                    st.reset(pid, &mut owners);
                }
                if device(c) && d.is_empty() {
                    owners.insert(c.into(), pid);
                    st.dev = c.into();
                    if keep {
                        st.stage = Link::Interface;
                    }
                } else {
                    st.reset(pid, &mut owners);
                }
            }
            "Connect:" => {
                let keep = matches!(st.stage, Link::Interface)
                    && st.dev == b
                    && owners.get(b) == Some(&pid);
                if !keep {
                    st.reset(pid, &mut owners);
                }
                if device(b) && c == "<-->" && wan(d) && e.is_empty() {
                    owners.insert(b.into(), pid);
                    st.dev = b.into();
                    if keep {
                        st.stage = Link::Connected;
                    }
                } else {
                    st.reset(pid, &mut owners);
                }
            }
            "local" if b != "LL" => {
                st.client = None;
                st.names.clear();
                st.malformed = false;
                if matches!(st.stage, Link::Connected | Link::Assigned) {
                    st.stage = Link::Connected;
                    if b == "IP" && c == "address" && e.is_empty() {
                        st.client = ipv4(d);
                        if st.client.is_some() {
                            st.stage = Link::Assigned;
                        }
                    }
                }
            }
            "primary" | "secondary" if matches!(st.stage, Link::Assigned) => {
                let ip = ipv4(d);
                if b != "DNS" || c != "address" || !e.is_empty() || ip.is_none() {
                    st.names.clear();
                    st.malformed = true;
                    return;
                }
                if !st.malformed {
                    if a == "primary" {
                        st.names.clear();
                    }
                    if let Some(ip) = ip.filter(|ip| st.names.len() < 2 && !st.names.contains(ip)) {
                        st.names.push(ip);
                    }
                }
            }
            _ if [
                "Connection terminated",
                "Modem hangup",
                "LCP terminated",
                "IPCP terminated",
                "Terminating on signal",
                "No network protocols running",
                "Exit",
                "pppd ",
                "Plugin ",
            ]
            .iter()
            .any(|s| msg.starts_with(s)) =>
            {
                st.reset(pid, &mut owners)
            }
            _ => (),
        }
        if owners.len() > 64 {
            overflow = true;
        }
    });
    if overflow {
        return vec![];
    }
    states
        .into_iter()
        .filter_map(|(pid, st)| {
            (!st.malformed && !st.names.is_empty() && owners.get(&st.dev) == Some(&pid))
                .then_some(st)
        })
        .collect()
}

// Current native state must bracket the log read. Session IDs and addresses
// can recur after a reconnect, so also compare the session start and uptime.
pub(super) fn current<'a>(
    log: &str,
    now: OffsetDateTime,
    before: &[Uplink],
    after: &'a [Uplink],
) -> Vec<(&'a str, Ipv4Addr)> {
    let sessions = states(log, now);
    let mut peers = Vec::new();
    for link in after {
        if !before.iter().any(|old| {
            old.native == link.native
                && old.dev == link.dev
                && old.session == link.session
                && old.client == link.client
                && old.uptime <= link.uptime
        }) {
            continue;
        }
        for st in &sessions {
            if st.id != link.session || st.dev != link.dev || st.client != Some(link.client) {
                continue;
            }
            if st
                .stamp
                .is_some_and(|t| ((now - t).whole_seconds() - i64::from(link.uptime)).abs() <= 30)
            {
                peers.extend(st.names.iter().map(|ip| (link.dev.as_str(), *ip)));
            }
        }
    }
    peers
}
