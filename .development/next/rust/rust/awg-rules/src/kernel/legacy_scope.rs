//! Per-client exceptions from the Go full-tunnel watchdog. A confirmed LAN
//! bridge scopes IPv4 sources. IPv6 also uses the device's link identity.
use super::{
    err,
    inventory::{Kernel, Object},
    learning::{Member, Saved},
    plan::{Family, LegacyFull, Plan},
    Prefix,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write,
    io,
    net::IpAddr,
};

const MAC_TAG: &str = "n2s-awg-mac";
const SOURCE_TAG: &str = "n2s-awg-src";
// Slots 0..=128 belong to ordinary marked policy and can still be active
// during a transactional transition. Keep both MAC decisions disjoint.
pub(super) const DIRECT: &str = "0x1fe00000/0x1ff00000";
pub(super) const TUNNEL: &str = "0x1ff00000/0x1ff00000";
pub(super) const DEFAULT: &str = "0/0x30000000";
const LIMIT: usize = 2048;
fn invalid() -> io::Error {
    err("не подтверждены наборы, MAC или порядок старых правил AWG")
}

#[derive(Clone, Default, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Scope {
    zones: Vec<Zone>,
    #[serde(default)]
    bridges: BTreeMap<String, String>,
    // Rebuilt from an authenticated peer before a down-state tunnel lookup.
    #[serde(default)]
    pub tunnel_route: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Zone {
    index: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rule: Option<usize>,
    tunnel: bool,
    sources: Vec<String>,
    v4: bool,
    v6: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    all_destinations: bool,
    networks: Vec<Prefix>,
    devices: BTreeMap<String, Device>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    addresses: BTreeMap<String, String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Device {
    bridge: String,
    mac: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct Rule {
    pub token: String,
    source: Source,
    tunnel: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Source {
    Address { bridge: String, prefix: Prefix },
    Ethernet(Device),
}

fn mac(s: &str) -> Option<String> {
    let a: Vec<_> = s
        .split(':')
        .map(|p| {
            (p.len() == 2)
                .then(|| u8::from_str_radix(p, 16).ok())
                .flatten()
        })
        .collect::<Option<_>>()?;
    (a.len() == 6 && a[0] & 1 == 0 && a.iter().any(|v| *v != 0)).then(|| s.to_ascii_lowercase())
}
pub(super) fn owner(doc: &Value) -> io::Result<crate::Routing> {
    let row = doc["servers"]
        .as_array()
        .and_then(|rows| rows.iter().find(|r| r["id"] == doc["active_id"]))
        .ok_or_else(invalid)?;
    let mut cfg = crate::policy::decode(&row["config"]["routing"])?;
    cfg.normalize();
    Ok(cfg)
}
fn scoped(zone: &crate::Zone) -> bool {
    zone.enabled && !zone.waiting_for_connection && !zone.source_ips.is_empty()
}
fn named(zone: &crate::Zone) -> bool {
    zone.domains.iter().any(|s| !crate::model::ipish(s))
}
fn any_destination(zone: &crate::Zone) -> bool {
    zone.domains.is_empty() && zone.ips.is_empty()
}
pub(super) fn needs_dns(routing: &crate::Routing) -> bool {
    if !routing.zones.iter().any(|zone| scoped(zone) && named(zone)) {
        return false;
    }
    let mut global_finished = false;
    for zone in routing
        .zones
        .iter()
        .filter(|z| z.enabled && !z.waiting_for_connection)
    {
        let global = zone.source_ips.is_empty();
        if global && global_finished {
            continue;
        }
        if zone
            .domains
            .iter()
            .any(|s| !crate::model::catch_all(s) && !crate::model::ipish(s))
        {
            return true;
        }
        global_finished |= global && zone.dns_catch_all();
    }
    false
}
fn networks(zone: &crate::Zone) -> io::Result<BTreeSet<Prefix>> {
    zone.ips
        .iter()
        .chain(
            zone.domains
                .iter()
                .filter(|s| crate::model::ipish(s.trim())),
        )
        .map(|s| s.trim().parse())
        .collect()
}
pub(super) fn intent(doc: &Value, scope: Option<&Scope>) -> io::Result<()> {
    let cfg = owner(doc)?;
    let zones = cfg.zones.iter().enumerate().filter(|(_, z)| scoped(z));
    let persisted = scope.map(|s| s.zones.as_slice()).unwrap_or_default();
    if zones.clone().count() != persisted.len() {
        return Err(invalid());
    }
    for ((index, z), p) in zones.zip(persisted) {
        let nets = networks(z)?;
        if z.source_ips != p.sources
            || (z.direction() == "tunnel") != p.tunnel
            || any_destination(z) != p.all_destinations
            || (named(z) && p.rule != Some(index))
            || !nets.iter().all(|n| p.networks.binary_search(n).is_ok())
            || !named(z) && (p.rule.is_some() || !nets.iter().eq(&p.networks))
        {
            return Err(invalid());
        }
    }
    Ok(())
}
fn bridges(k: &Kernel<'_>) -> io::Result<BTreeSet<String>> {
    let bridges=k.call("sh",&["-c","for d in /sys/class/net/br*/bridge; do test -d \"$d\" || continue; n=${d%/bridge}; echo \"${n##*/}\"; done"])?;
    Ok(bridges
        .lines()
        .filter(|n| super::valid_dns_bridge(n))
        .map(str::to_owned)
        .collect())
}
fn neighbours(
    k: &Kernel<'_>,
    bridges: &BTreeSet<String>,
) -> io::Result<BTreeMap<IpAddr, Option<Device>>> {
    let mut entries = BTreeMap::<IpAddr, Option<Device>>::new();
    for f in [Family::V4, Family::V6] {
        for row in k.call("ip", &[f.flag(), "neigh", "show"])?.lines() {
            let w: Vec<_> = row.split_ascii_whitespace().collect();
            let Some(ip) = w.first() else { continue };
            let Ok(ip) = ip.parse::<IpAddr>() else {
                continue;
            };
            if Family::of(ip) != f {
                continue;
            }
            let field = |key| w.windows(2).find(|p| p[0] == key).map(|p| p[1]);
            let dev = field("dev")
                .filter(|n| bridges.contains(*n))
                .zip(field("lladdr").and_then(mac))
                .map(|(n, mac)| Device {
                    bridge: n.into(),
                    mac,
                });
            entries
                .entry(ip)
                .and_modify(|old| {
                    if old.as_ref() != dev.as_ref() {
                        *old = None
                    }
                })
                .or_insert(dev);
        }
    }
    Ok(entries)
}
fn set(
    k: &Kernel<'_>,
    existing: &BTreeSet<&str>,
    name: &str,
    f: Family,
    want: &BTreeSet<Prefix>,
    rule: Option<usize>,
    now: u64,
) -> io::Result<Option<Vec<Member>>> {
    if !existing.contains(name) {
        return Ok(None);
    }
    // A full set of /128 strings exceeds the ordinary command-output budget.
    let save = k
        .run
        .run_bounded("ipset", &["save", name], k.deadline, 8 << 20)?;
    let mut rows = save.lines();
    if !rows.next().is_some_and(|s| set_header(s, name, f)) {
        return Err(invalid());
    }
    let mut found = BTreeSet::new();
    let mut warm = Vec::new();
    for row in rows {
        let w: Vec<_> = row.split_ascii_whitespace().collect();
        let ["add", key, address, rest @ ..] = w.as_slice() else {
            return Err(invalid());
        };
        let prefix: Prefix = address.parse()?;
        let expiry = super::handoff::member_expiry(rest, now)?;
        if *key != name
            || prefix.family() != f
            || !found.insert(prefix)
            || found.len() > super::packed::ZONE_LIMIT
        {
            return Err(invalid());
        }
        if want.contains(&prefix) {
            if expiry != u64::MAX {
                return Err(invalid());
            }
            continue;
        }
        let zone = rule.ok_or_else(invalid)?;
        if !prefix.is_host() || !prefix.safe() {
            return Err(invalid());
        }
        warm.push(Member {
            zone,
            ip: prefix.sample(),
            until: expiry,
        });
    }
    if !want.is_subset(&found) {
        return Err(invalid());
    }
    Ok(Some(warm))
}
fn set_header(line: &str, name: &str, family: Family) -> bool {
    let mut words = line.split_ascii_whitespace();
    let mut base = String::new();
    let mut counters = false;
    let mut timeout = false;
    while let Some(word) = words.next() {
        match word {
            "timeout" if !timeout => {
                if words.next().and_then(|v| v.parse::<u32>().ok()).is_none() {
                    return false;
                }
                timeout = true;
            }
            "counters" if !counters => counters = true,
            _ => write!(base, "{word} ").unwrap(),
        }
    }
    super::packed::check_header(&base, name, family)
}
pub(super) fn capture(
    k: &Kernel<'_>,
    db: &nfqws2_store::Store,
    doc: &Value,
    state: &LegacyFull,
    now: u64,
) -> io::Result<(Option<Scope>, Vec<Member>)> {
    let config = super::learning::legacy_policy(db, doc)?;
    let rows: Vec<_> = config
        .zones
        .iter()
        .enumerate()
        .filter(|(_, z)| scoped(z))
        .collect();
    if rows.is_empty() {
        return Ok((None, Vec::new()));
    }
    if !owner(doc)?.go_watchdog_full(doc) {
        return Err(invalid());
    }
    let names = k.call("ipset", &["list", "-name"])?;
    let existing = names.lines().collect();
    let mut scope = Scope::default();
    let mut warm = Vec::new();
    for (index, (rule_index, z)) in rows.into_iter().enumerate() {
        let networks = networks(z)?;
        let rule = named(z).then_some(rule_index);
        let name = format!("awg2_z{index}");
        let mut read = |f: Family, name: &str| -> io::Result<bool> {
            let static_nets = networks
                .iter()
                .copied()
                .filter(|net| net.family() == f)
                .collect();
            let Some(sample) = set(k, &existing, name, f, &static_nets, rule, now)? else {
                return Ok(false);
            };
            if warm.len() + sample.len() > super::packed::LIMIT {
                return Err(invalid());
            }
            warm.extend(sample);
            Ok(true)
        };
        let v4 = read(Family::V4, &name)?;
        let v6 = *state != LegacyFull::Ipv4Only && read(Family::V6, &format!("{name}_6"))?;
        if rule.is_some()
            && (!v4
                && z.source_ips
                    .iter()
                    .any(|s| s.parse::<Prefix>().is_ok_and(|p| p.family() == Family::V4))
                || *state != LegacyFull::Ipv4Only && !v6)
        {
            return Err(err(
                "нет действующего IP-набора DNS-зоны старого полного туннеля Go",
            ));
        }
        scope.zones.push(Zone {
            index,
            rule,
            tunnel: z.direction() == "tunnel",
            sources: z.source_ips.clone(),
            v4,
            v6,
            all_destinations: false,
            networks: networks.into_iter().collect(),
            devices: Default::default(),
            addresses: Default::default(),
        });
    }
    scope.refresh(k, *state != LegacyFull::Ipv4Only)?;
    scope.verify_v4_sources()?;
    if *state != LegacyFull::Ipv4Only {
        // The Go hook is a rendered file: a device that appeared since its
        // last rewrite need not have a live MAC rule yet.
        let show = k.call("ip6tables", &["-t", "mangle", "-S", "AWG2_MARK6"])?;
        let mut enrolled = BTreeSet::new();
        for row in show.lines() {
            let w = row.split_ascii_whitespace().collect::<Vec<_>>();
            if let (Some(m), Some(set)) = (
                w.windows(2)
                    .find(|w| w[0] == "--mac-source")
                    .and_then(|w| mac(w[1])),
                w.windows(2).find(|w| w[0] == "--match-set"),
            ) {
                enrolled.insert((set[1].to_owned(), m));
            }
        }
        for z in &mut scope.zones {
            let key = format!("awg2_z{}_6", z.index);
            z.devices
                .retain(|_, d| enrolled.contains(&(key.clone(), d.mac.clone())));
        }
    }
    scope.valid()?;
    warm.sort_unstable();
    Ok((Some(scope), warm))
}

/// Construct the selected profile's source classifier from its configuration
/// and current LAN evidence, without reading unrelated live firewall sets.
pub(super) fn rebuild(
    k: &Kernel<'_>,
    db: &nfqws2_store::Store,
    doc: &Value,
    previous: &Plan,
) -> io::Result<(Option<Scope>, Option<Saved>)> {
    let raw = owner(doc)?;
    let routing = super::learning::legacy_policy(db, doc)?;
    routing.validate(true)?;
    let dns = needs_dns(&routing);
    let scoped = routing
        .zones
        .iter()
        .enumerate()
        .filter(|(_, zone)| scoped(zone));
    if scoped.clone().next().is_none() {
        return Ok((None, None));
    }
    let v6 = k.ipv6_stack()?;
    let mut scope = Scope::default();
    for (index, (rule_index, zone)) in scoped.enumerate() {
        scope.zones.push(Zone {
            index,
            rule: (dns && named(zone)).then_some(rule_index),
            tunnel: zone.direction() == "tunnel",
            sources: zone.source_ips.clone(),
            v4: true,
            v6,
            all_destinations: any_destination(&raw.zones[rule_index]),
            networks: networks(zone)?.into_iter().collect(),
            devices: BTreeMap::new(),
            addresses: BTreeMap::new(),
        });
    }
    scope.refresh(k, v6)?;
    scope.verify_v4_sources()?;
    let learner = if dns {
        let members = transferred_members(&scope, &routing, previous)?;
        Some(super::learning::legacy_saved(&routing, &members)?)
    } else {
        None
    };
    Ok((Some(scope), learner))
}

fn transferred_members(
    scope: &Scope,
    routing: &crate::Routing,
    previous: &Plan,
) -> io::Result<Vec<Member>> {
    let (Some(prior_scope), Some(prior)) = (&previous.legacy_scope, &previous.learned) else {
        return Ok(Vec::new());
    };
    let prior_routing = prior.routing()?;
    let mut eligible = BTreeMap::new();
    for current in &scope.zones {
        let Some(index) = current.rule else { continue };
        let (Some(a), Some(b)) = (prior_routing.zones.get(index), routing.zones.get(index)) else {
            continue;
        };
        let Some(old) = prior_scope
            .zones
            .get(current.index)
            .filter(|zone| zone.rule == Some(index))
        else {
            continue;
        };
        if old.tunnel != current.tunnel
            || old.sources != current.sources
            || old.networks != current.networks
            || a.domains != b.domains
            || a.include_subdomains != b.include_subdomains
            || a.source_key != b.source_key
        {
            continue;
        }
        let v4 =
            old.v4 && current.v4 && !old.addresses.is_empty() && old.addresses == current.addresses;
        let v6 = old.v6 && current.v6 && !old.devices.is_empty() && old.devices == current.devices;
        eligible.insert(index, (v4, v6));
    }
    let now = nfqws2_awg_profile::now();
    Ok(prior
        .members
        .iter()
        .filter(|member| {
            member.until > now
                && eligible.get(&member.zone).is_some_and(|(v4, v6)| {
                    if member.ip.is_ipv4() {
                        *v4
                    } else {
                        *v6
                    }
                })
        })
        .cloned()
        .collect())
}

impl Scope {
    fn verify_v4_sources(&self) -> io::Result<()> {
        if self.zones.iter().any(|zone| {
            zone.v4
                && (zone.all_destinations
                    || zone.rule.is_some()
                    || zone.networks.iter().any(|n| n.family() == Family::V4))
                && zone.sources.iter().any(|source| {
                    source
                        .parse::<Prefix>()
                        .is_ok_and(|p| p.family() == Family::V4)
                        && !zone.addresses.contains_key(source)
                })
        }) {
            return Err(err(
                "не подтверждён LAN-мост IPv4-источника старого полного туннеля",
            ));
        }
        Ok(())
    }
    pub(super) fn learner_wanted(&self) -> bool {
        self.zones.iter().any(|z| z.rule.is_some())
    }
    pub(super) fn tracks_members(&self, members: &[Member]) -> bool {
        let families = self
            .zones
            .iter()
            .filter_map(|z| Some((z.rule?, (z.v4, z.v6))))
            .collect::<BTreeMap<_, _>>();
        members.iter().all(|m| {
            families
                .get(&m.zone)
                .is_some_and(|(v4, v6)| if m.ip.is_ipv4() { *v4 } else { *v6 })
        })
    }
    pub(super) fn permits_source_member(
        &self,
        rule: usize,
        source: IpAddr,
        destination: IpAddr,
    ) -> bool {
        let source = source.to_canonical();
        self.zones.iter().any(|zone| {
            if zone.rule != Some(rule) {
                return false;
            }
            let contains = |configured: &String| {
                configured
                    .parse::<Prefix>()
                    .is_ok_and(|p| p.contains(source))
            };
            if destination.is_ipv4() {
                zone.addresses.keys().any(contains)
            } else {
                zone.devices.keys().any(contains)
            }
        })
    }
    pub(super) fn accepts_client(&self, source: IpAddr, bridge: &str) -> bool {
        let source = source.to_canonical();
        let contains = |configured: &str| {
            configured
                .parse::<Prefix>()
                .is_ok_and(|p| p.contains(source))
        };
        self.zones.iter().any(|z| {
            z.addresses
                .iter()
                .any(|(net, input)| input == bridge && contains(net))
                || z.devices
                    .iter()
                    .any(|(net, dev)| dev.bridge == bridge && contains(net))
        })
    }
    pub(super) fn ingress_bindings(&self) -> io::Result<Vec<(Prefix, Option<String>)>> {
        let mut bindings = BTreeMap::<Prefix, Option<String>>::new();
        for zone in &self.zones {
            for source in &zone.sources {
                let prefix = source.parse::<Prefix>()?;
                let proof = zone
                    .addresses
                    .get(source)
                    .or_else(|| zone.devices.get(source).map(|d| &d.bridge));
                let current = bindings.entry(prefix).or_default();
                if let Some(proof) = proof {
                    if current.as_ref().is_some_and(|name| name != proof) {
                        return Err(invalid());
                    }
                    if current.is_none() {
                        *current = Some(proof.clone());
                    }
                }
            }
        }
        Ok(bindings.into_iter().collect())
    }
    pub(super) fn rows(&self) -> usize {
        self.zones
            .iter()
            .map(|z| 1 + z.networks.len() + z.sources.len() + z.devices.len() + z.addresses.len())
            .sum()
    }
    pub(super) fn valid(&self) -> io::Result<()> {
        if self.zones.is_empty()
            || self.bridges.iter().any(|(s, b)| {
                !super::valid_dns_bridge(b) || !self.zones.iter().any(|z| z.sources.contains(s))
            })
            || self.rows() > super::packed::LIMIT
            || !self
                .zones
                .iter()
                .filter_map(|z| z.rule)
                .is_sorted_by(|a, b| a < b)
            || self.zones.iter().enumerate().any(|(i, z)| {
                i != z.index
                    || z.rule.is_some_and(|r| r < i || r >= 2048)
                    || z.sources.is_empty()
                    || z.sources
                        .iter()
                        .any(|s| s.parse::<Prefix>().ok().is_none_or(Prefix::any))
                    || z.all_destinations && (!z.networks.is_empty() || z.rule.is_some())
                    || z.networks.len() > super::packed::ZONE_LIMIT
                    || z.networks.windows(2).any(|w| w[0] >= w[1])
                    || z.networks.iter().any(|n| n.any())
                    || z.addresses.iter().any(|(s, b)| {
                        !z.v4
                            || !z.sources.contains(s)
                            || s.parse::<Prefix>()
                                .ok()
                                .is_none_or(|p| p.family() != Family::V4)
                            || self.bridges.get(s) != Some(b)
                    })
                    || z.devices.iter().any(|(s, d)| {
                        !z.v6
                            || !z.sources.contains(s)
                            || !super::valid_dns_bridge(&d.bridge)
                            || self.bridges.get(s) != Some(&d.bridge)
                            || mac(&d.mac).as_ref() != Some(&d.mac)
                    })
            })
            || self.zones.iter().map(|z| z.devices.len()).sum::<usize>() > LIMIT
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub(super) fn refresh(&mut self, k: &Kernel<'_>, ipv6_stack: bool) -> io::Result<()> {
        let v4 = self.zones.iter().any(|z| z.v4);
        let v6 = ipv6_stack && self.zones.iter().any(|z| z.v6);
        if !v4 && !v6 {
            return Ok(());
        }
        let bridges = bridges(k)?;
        let entries = if v6 {
            neighbours(k, &bridges)?
        } else {
            BTreeMap::new()
        };
        let mut subnets = Vec::new();
        for family in [Family::V4, Family::V6]
            .into_iter()
            .filter(|f| v6 || *f == Family::V4)
        {
            for row in k
                .call("ip", &["-o", family.flag(), "addr", "show"])?
                .lines()
            {
                let words = row.split_ascii_whitespace().collect::<Vec<_>>();
                if let [_, dev, kind, net, ..] = words.as_slice() {
                    let name = dev.split('@').next().unwrap_or(dev);
                    if *kind == family.inet() && bridges.contains(name) {
                        subnets.push((net.parse::<Prefix>()?, name.to_owned()));
                    }
                }
            }
        }
        for z in &mut self.zones {
            z.devices.clear();
            z.addresses.clear();
            for s in &z.sources {
                let source = s.parse::<Prefix>()?;
                let mut local = subnets
                    .iter()
                    .filter(|(net, _)| net.covers(source))
                    .map(|(_, dev)| dev);
                let Some(bridge) = local.next() else { continue };
                if local.any(|name| name != bridge) {
                    continue;
                }
                let pinned = self
                    .bridges
                    .entry(s.clone())
                    .or_insert_with(|| bridge.clone());
                if pinned != bridge {
                    continue;
                }
                if z.v4 && source.family() == Family::V4 {
                    z.addresses.insert(s.clone(), bridge.clone());
                }
                if v6 && z.v6 && source.is_host() {
                    if let Some(Some(dev)) = entries.get(&source.sample()) {
                        if dev.bridge == *pinned {
                            z.devices.insert(s.clone(), dev.clone());
                        }
                    }
                }
            }
        }
        self.valid()
    }
    pub(super) fn remember_bridges(&mut self, now: &Self) {
        self.bridges.clone_from(&now.bridges);
    }
    pub(super) fn go_rules(&self, f: Family) -> Vec<Vec<String>> {
        let mut result = Vec::new();
        for z in &self.zones {
            let name = format!(
                "awg2_z{}{}",
                z.index,
                if f == Family::V6 { "_6" } else { "" }
            );
            for src in &z.sources {
                let mut w: Vec<String> = if f == Family::V4 && z.v4 {
                    let Ok(p) = src.trim().parse::<Prefix>() else {
                        continue;
                    };
                    if p.family() != f {
                        continue;
                    }
                    vec!["-s".into(), p.to_string()]
                } else if f == Family::V6 && z.v6 {
                    let Some(d) = z.devices.get(src) else {
                        continue;
                    };
                    vec![
                        "-m".into(),
                        "mac".into(),
                        "--mac-source".into(),
                        d.mac.clone(),
                    ]
                } else {
                    continue;
                };
                if !z.all_destinations {
                    w.extend(["-m", "set", "--match-set", &name, "dst"].map(str::to_owned));
                }
                w.push("-j".into());
                if z.tunnel {
                    w.extend(["MARK", "--set-xmark", "0x10000000/0x10000000"].map(str::to_owned));
                } else {
                    w.push("RETURN".into())
                }
                result.push(w);
            }
        }
        result
    }
    pub(super) fn needs_tunnel(&self) -> bool {
        self.zones.iter().any(|z| z.tunnel && !z.devices.is_empty())
    }
    pub(super) fn verify_paths(&self, k: &Kernel<'_>, plan: &Plan) -> io::Result<()> {
        let mut objs = BTreeSet::new();
        self.objects(plan, &mut objs);
        for f in [Family::V4, Family::V6] {
            self.verify_family_paths(k, plan, &objs, f)?;
        }
        Ok(())
    }
    fn verify_family_paths(
        &self,
        k: &Kernel<'_>,
        plan: &Plan,
        objs: &BTreeSet<Object>,
        f: Family,
    ) -> io::Result<()> {
        let mut tested = BTreeSet::new();
        for rule in generation(objs, f) {
            if !tested.insert(rule.tunnel) {
                continue;
            }
            let Some(sample) = objs.iter().find_map(|o| match o {
                Object::SetMember(net, name) if name.as_ref() == rule.token => Some(net.sample()),
                _ => None,
            }) else {
                return Err(invalid());
            };
            let sample = sample.to_string();
            let get = |mark: &str| k.call("ip", &[f.flag(), "route", "get", &sample, "mark", mark]);
            let mark = if rule.tunnel {
                "0x1ff00000"
            } else {
                "0x1fe00000"
            };
            let route = get(mark);
            if !rule.tunnel {
                // The original unclassified path is allowed to be unavailable.
                if let Ok(row) = &route {
                    if row
                        .split_ascii_whitespace()
                        .collect::<Vec<_>>()
                        .windows(2)
                        .any(|p| p[0] == "dev" && plan.targets.contains_key(p[1]))
                    {
                        return Err(invalid());
                    }
                } else if get("0x20000000").is_ok() {
                    return Err(invalid());
                }
                continue;
            }
            let via = if let Some(iface) = plan.prefixes.get(&f.any()) {
                plan.effective(
                    super::plan::Selector {
                        source: f.any(),
                        dest: f.any(),
                    },
                    iface,
                )
            } else {
                self.tunnel_route.then(|| plan.probe_iface()).flatten()
            };
            if let Some(iface) = via {
                if !route?
                    .split_ascii_whitespace()
                    .collect::<Vec<_>>()
                    .windows(2)
                    .any(|p| p == ["dev", iface])
                {
                    return Err(invalid());
                }
            } else if route.is_ok() {
                return Err(invalid());
            }
        }
        Ok(())
    }
    pub(super) fn tunnel_covered(
        &self,
        members: &[Member],
        allows: impl Fn(Prefix) -> bool,
    ) -> bool {
        self.zones
            .iter()
            .filter(|z| z.tunnel && !z.devices.is_empty())
            .all(|z| addresses(z, Family::V6, members).all(&allows))
    }
    pub(super) fn objects(&self, plan: &Plan, out: &mut BTreeSet<Object>) {
        if plan.legacy_full.is_none() {
            return;
        }
        self.family_objects(plan, out, Family::V4);
        if plan.legacy_full != Some(LegacyFull::Ipv4Only) {
            self.family_objects(plan, out, Family::V6);
        }
    }
    fn family_objects(&self, plan: &Plan, out: &mut BTreeSet<Object>, family: Family) {
        let members = plan
            .learned
            .as_ref()
            .map_or(&[][..], |saved| &saved.members);
        let mut rules = Vec::new();
        for z in &self.zones {
            let mut sources = BTreeSet::new();
            for src in &z.sources {
                let origin = match family {
                    Family::V4 => z.addresses.get(src).map(|bridge| Source::Address {
                        bridge: bridge.clone(),
                        prefix: src.parse().expect("validated source scope"),
                    }),
                    Family::V6 => z.devices.get(src).cloned().map(Source::Ethernet),
                };
                if let Some(origin) = origin {
                    sources.insert(origin);
                }
            }
            if sources.is_empty() {
                continue;
            }
            let mut nets = Prefix::compact(addresses(z, family, members).collect());
            // Go returns for the active endpoints and management prefixes
            // before it evaluates source-bound rules in either family.
            let excluded = match family {
                Family::V4 => super::full::excluded_v4().collect::<Vec<_>>(),
                Family::V6 => [
                    "::/96",
                    "::ffff:0:0/96",
                    "fc00::/7",
                    "fe80::/10",
                    "ff00::/8",
                ]
                .map(|s| s.parse::<Prefix>().unwrap())
                .to_vec(),
            };
            for ex in excluded.into_iter().chain(
                plan.full_endpoints
                    .iter()
                    .flatten()
                    .copied()
                    .filter(|ip| Family::of(*ip) == family)
                    .map(Prefix::host),
            ) {
                if let Some(parent) = ex.ancestors().find(|p| nets.contains(p)) {
                    nets.remove(&parent);
                    parent.outside(ex, |piece| {
                        nets.insert(piece);
                    });
                } else {
                    let inside = nets
                        .range(ex..)
                        .take_while(|p| ex.covers(**p))
                        .copied()
                        .collect::<Vec<_>>();
                    for subnet in inside {
                        nets.remove(&subnet);
                    }
                }
            }
            let nets = nets.into_iter().collect::<Vec<_>>();
            if nets.is_empty() {
                continue;
            }
            for chunk in nets.chunks(16_384) {
                let mut key = super::marked::token(chunk);
                key.replace_range(..1, "l");
                if out.insert(Object::Set(family, key.clone())) {
                    let tag: std::sync::Arc<str> = key.as_str().into();
                    out.extend(chunk.iter().map(|p| Object::SetMember(*p, tag.clone())));
                }
                rules.extend(sources.iter().cloned().map(|source| Rule {
                    token: key.clone(),
                    source,
                    tunnel: z.tunnel,
                }));
            }
        }
        if rules.is_empty() {
            return;
        }
        if plan.prefixes.contains_key(&family.any()) {
            out.remove(&Object::PackedLookup(family));
            out.insert(Object::LegacyLookup(family, false));
        }
        if rules.iter().any(|r| r.tunnel) {
            out.insert(Object::LegacyLookup(family, true));
            if family == Family::V6
                && matches!(plan.legacy_full, Some(LegacyFull::ForwardReject { .. }))
            {
                out.insert(Object::FullGuard(super::full::Guard::Fence(Family::V6)));
                if self.tunnel_route {
                    if let Some(iface) = plan.probe_iface() {
                        let any = Family::V6.any();
                        out.insert(Object::Route(any, iface.into(), 17842));
                        for &fw in super::inventory::Firewall::legacy_rules(plan) {
                            out.insert(Object::Firewall(
                                super::plan::Selector {
                                    source: any,
                                    dest: any,
                                },
                                iface.into(),
                                fw,
                            ));
                        }
                    }
                }
            }
        }
        out.insert(Object::LegacyClassifier(family, rules));
    }

    pub(super) fn v4_dns_mark(
        &self,
        plan: &Plan,
        client: IpAddr,
        bridge: &str,
        dst: IpAddr,
    ) -> io::Result<Option<&'static str>> {
        if !client.is_ipv4() || !dst.is_ipv4() || !super::valid_dns_bridge(bridge) {
            return Err(invalid());
        }
        if !self.accepts_client(client, bridge) {
            return Ok(None);
        }
        let mut out = BTreeSet::new();
        self.family_objects(plan, &mut out, Family::V4);
        Ok(generation(&out, Family::V4).iter().find_map(|r| {
            let Source::Address { bridge: input, prefix } = &r.source else {return None};
            (input == bridge && prefix.contains(client) && out.iter().any(|o| {
                matches!(o,Object::SetMember(net,key) if key.as_ref() == r.token && net.contains(dst))
            })).then_some(if r.tunnel {"0x1ff00000"} else {"0x1fe00000"})
        }))
    }
}
fn addresses<'a>(
    z: &'a Zone,
    family: Family,
    members: &'a [Member],
) -> impl Iterator<Item = Prefix> + 'a {
    let matching = z.rule.map_or(&[][..], |i| {
        let lo = members.partition_point(|m| m.zone < i);
        let hi = members.partition_point(|m| m.zone <= i);
        &members[lo..hi]
    });
    z.networks
        .iter()
        .copied()
        .chain(matching.iter().map(|m| Prefix::host(m.ip)))
        .chain(z.all_destinations.then(|| family.any()))
        .filter(move |n| n.family() == family)
}
pub(super) fn tag(family: Family) -> &'static str {
    if family == Family::V4 {
        SOURCE_TAG
    } else {
        MAC_TAG
    }
}
fn rules(family: Family, items: &[Rule]) -> Vec<String> {
    items.iter().map(|r| {
        let source = match &r.source {
            Source::Address { bridge, prefix } => format!("-i {bridge} -s {prefix}"),
            Source::Ethernet(dev) => format!("-i {} -m mac --mac-source {}",dev.bridge,dev.mac.to_ascii_uppercase()),
        };
        format!("PREROUTING {source} -m set --match-set {} dst -m mark --mark 0x0/0x30000000 -m comment --comment {} -j MARK --set-xmark {}",
            super::packed::name(family,&r.token),tag(family),if r.tunnel{TUNNEL}else{DIRECT})
    }).collect()
}
fn generation(objects: &BTreeSet<Object>, family: Family) -> &[Rule] {
    objects
        .iter()
        .find_map(|o| match o {
            Object::LegacyClassifier(f, r) if *f == family => Some(r.as_slice()),
            _ => None,
        })
        .unwrap_or_default()
}
pub(super) fn update(
    k: &Kernel<'_>,
    old: &BTreeSet<Object>,
    new: &BTreeSet<Object>,
) -> io::Result<()> {
    for family in [Family::V4, Family::V6] {
        update_family(k, generation(old, family), generation(new, family), family)?;
    }
    Ok(())
}
fn update_family(k: &Kernel<'_>, old: &[Rule], new: &[Rule], family: Family) -> io::Result<()> {
    if old == new {
        return Ok(());
    }
    let mut prog = String::from("*mangle\n");
    for r in rules(family, old) {
        writeln!(prog, "-D {r}").unwrap();
    }
    for r in rules(family, new).into_iter().rev() {
        let (_, spec) = r.split_once(' ').unwrap();
        writeln!(prog, "-I PREROUTING 1 {spec}").unwrap();
    }
    prog.push_str("COMMIT\n");
    k.run
        .run_input(
            if family == Family::V4 {
                "iptables-restore"
            } else {
                "ip6tables-restore"
            },
            &["--noflush"],
            prog.as_bytes(),
            k.deadline,
        )
        .map(drop)
}
pub(super) fn inventory(
    k: &Kernel<'_>,
    claims: &BTreeSet<Object>,
    proposed: &BTreeSet<Object>,
    go: bool,
) -> io::Result<Vec<Object>> {
    let mut found = Vec::new();
    for family in [Family::V4, Family::V6] {
        found.extend(inventory_family(k, claims, proposed, go, family)?);
    }
    Ok(found)
}
fn inventory_family(
    k: &Kernel<'_>,
    claims: &BTreeSet<Object>,
    proposed: &BTreeSet<Object>,
    go: bool,
    family: Family,
) -> io::Result<Option<Object>> {
    if !claims.iter().chain(proposed).any(
        |o| matches!(o, Object::LegacyClassifier(f,..) | Object::LegacyLookup(f,_) if *f==family),
    ) {
        return Ok(None);
    }
    let rpdb = k.listing(family, &["rule", "show"])?;
    let rpdb = rpdb
        .lines()
        .filter(|l| {
            let w = l.split_ascii_whitespace().collect::<Vec<_>>();
            !matches!(
                w.as_slice(),
                [
                    "68:",
                    "from",
                    "all",
                    "fwmark",
                    DEFAULT | "0x0/0x30000000" | TUNNEL,
                    "lookup",
                    "17842"
                ]
            ) && !(go
                && matches!(
                    w.as_slice(),
                    [
                        _,
                        "from",
                        "all",
                        "fwmark",
                        "0x10000000/0x10000000",
                        "lookup",
                        "998"
                    ]
                ))
        })
        .collect::<Vec<_>>()
        .join("\n");
    super::marked::check_rpdb(&rpdb, &BTreeSet::from([254, 255]), false)?;
    let marked = claims
        .iter()
        .any(|o| matches!(o, Object::Classifier(f, _) if *f==family));
    let tag = tag(family);
    let xt = if family == Family::V4 {
        "iptables"
    } else {
        "ip6tables"
    };
    let go_chain = if family == Family::V4 {
        "AWG2_MARK"
    } else {
        "AWG2_MARK6"
    };
    let mut found = Vec::new();
    let mut foreign_first = false;
    for row in k.call(xt, &["-w", "-t", "mangle", "-S"])?.lines() {
        let w: Vec<_> = row.split_ascii_whitespace().collect();
        if w.iter().any(|s| s.trim_matches('"') == tag) {
            if !row.starts_with("-A PREROUTING ") || foreign_first {
                return Err(invalid());
            }
            let key = if family == Family::V4 {
                "-s"
            } else {
                "--mac-source"
            };
            let raw = w
                .windows(2)
                .find(|p| p[0] == key)
                .map(|p| p[1])
                .ok_or_else(invalid)?;
            let canonical = match family {
                Family::V4 => raw.parse::<Prefix>()?.to_string(),
                Family::V6 => mac(raw).ok_or_else(invalid)?.to_ascii_uppercase(),
            };
            found.push(
                row[3..]
                    .replace(&format!("{key} {raw}"), &format!("{key} {canonical}"))
                    .replace(&format!("\"{tag}\""), tag)
                    .replace("--mark 0/0x30000000", "--mark 0x0/0x30000000"),
            );
        } else {
            if marked && w.iter().any(|s| s.trim_matches('"') == super::marked::TAG) {
                // marked::inventory independently verifies the entire other
                // generation, including both chains and their ordering.
                continue;
            }
            foreign_first |= row.starts_with("-A PREROUTING ");
            if go && w.get(1) == Some(&go_chain) {
                continue;
            }
            for arg in w.windows(2).filter(|p| {
                matches!(
                    p[0],
                    "--set-xmark" | "--set-mark" | "--or-mark" | "--xor-mark"
                )
            }) {
                let raw = arg[1].split('/').next().unwrap_or_default();
                let num = raw
                    .strip_prefix("0x")
                    .and_then(|n| u32::from_str_radix(n, 16).ok())
                    .or_else(|| raw.parse::<u32>().ok());
                if num.is_none_or(|n| n & 0x10000000 != 0) {
                    return Err(invalid());
                }
            }
        }
    }
    if found.is_empty() {
        return Ok(None);
    }
    claims
        .iter()
        .find(
            |o| matches!(o,Object::LegacyClassifier(f,rs) if *f==family && rules(family,rs)==found),
        )
        .cloned()
        .map(Some)
        .ok_or_else(invalid)
}
